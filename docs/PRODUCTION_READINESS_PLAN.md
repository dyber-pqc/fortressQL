# FortressQL Production Readiness Plan

**Version:** v1.0.1 → v1.1.0 (Beta) → v2.0.0 (Production)
**Date:** March 16, 2026
**Author:** Zachary Kleckner

---

## Current State (v1.0.1 — Alpha)

| Feature | Status | Notes |
|---------|--------|-------|
| ML-KEM / ML-DSA / SLH-DSA engine | Done | All FIPS 203/204/205 variants |
| SQL functions (pgcrypto_pqc) | Done | keygen, encrypt, decrypt, sign, verify |
| TDE (AES-256 + ML-KEM-768 wrapping) | Done | Survives restart, key unwrap from env var |
| WAL segment signing (ML-DSA-65) | Done | Deferred signing, no crit-section crash |
| CI (Ubuntu, macOS, Windows) | Done | E2E TDE, WAL signing, crash recovery |
| SECURITY.md | Done | Vulnerability disclosure policy |

---

## Phase 1: Beta Readiness (v1.1.0)

### Task 1 — WAL Signing Key Auto-Load on Primary Startup

**Problem:** On the primary server, `pqc_wal_load_signing_keys()` is never called at startup. It's only called from `walreceiver.c` (standby side) and via the `pqc_rotate_wal_signing_keys()` SQL function. When `wal_pqc_signing = on` and a WAL segment completes, `pqc_wal_sign_data()` finds `wal_keys_loaded = false` and silently skips signing.

**Solution:** Load WAL signing keys during `pqc_preflight_check()` and call that function from the postmaster startup path.

**Files to modify:**
- `src/backend/crypto/pqc/pqc_preflight.c` — After existing key file checks, call `pqc_wal_load_signing_keys()` inside a `PG_TRY` block (WARNING on failure, not FATAL)
- `src/backend/postmaster/postmaster.c` — Add `pqc_preflight_check()` call after GUCs and shared memory are initialized, before `ServerLoop`

**Risks:**
- `pqc_wal_load_signing_keys` uses `palloc` — acceptable in postmaster context (small allocations, ~4KB for ML-DSA-65 keys)
- Forked backends (including WAL writer) inherit loaded keys via `fork()` — same model as walreceiver
- Windows `EXEC_BACKEND` emulates fork — may need separate key loading in child startup

**Priority:** Highest — unblocks real WAL signing on the primary server
**Effort:** Small (< 50 lines changed)

---

### Task 2 — PQC/Hybrid TLS Key Exchange

**Problem:** Data in transit uses classical-only TLS. Need hybrid ML-KEM + X25519 key exchange for quantum-safe connections.

**Current state:** Server-side TLS is largely done:
- `src/backend/libpq/be-secure-openssl.c` already loads oqs-provider (OpenSSL 3.0-3.4) or uses native support (OpenSSL 3.5+)
- `ssl_pqc_mode` GUC exists with values `off`, `preferred`, `required`
- `ssl_pqc_groups` GUC configures group list (e.g., `X25519MLKEM768:x25519`)
- PQC signature algorithms configured via `SSL_CTX_set1_sigalgs_list()`

**What's missing:** Client-side PQC TLS in libpq.

**Files to modify:**
- `src/interfaces/libpq/fe-secure-openssl.c` — Add oqs-provider loading and PQC group configuration (mirror server-side logic)
- `src/backend/utils/misc/guc_tables.c` — Verify `ssl_pqc_groups` default includes `X25519MLKEM768:x25519`
- `src/backend/utils/misc/postgresql.conf.sample` — Document hybrid group configuration

**Risks:**
- Client-side changes affect all libpq consumers (psql, pg_dump, application drivers)
- If client's OpenSSL lacks PQC support, must fall back gracefully to classical-only
- oqs-provider availability varies across distros

**Priority:** High — completes the encryption story (at-rest + in-transit)
**Effort:** Medium (~200 lines, mostly mirroring existing server-side code)

---

### Task 3 — Security Audit Document

**Problem:** No comprehensive self-audit exists. Third-party firms need a threat model and code path analysis to scope their work.

**Current state:** `docs/SECURITY_AUDIT.md` exists with basic content. Needs major expansion.

**Sections to write:**

1. **Threat model** — What FortressQL protects against:
   - Harvest-now-decrypt-later (HNDL) attacks on stored data
   - WAL tampering in transit/at rest
   - Data-at-rest extraction from stolen disks
   - What it does NOT protect against: authorized DBA access, SQL injection, side-channel attacks on shared hosts

2. **Cryptographic code path analysis** — For each subsystem:
   - TDE: key wrapping flow (ML-KEM-768 encaps → shared secret → AES-256-GCM encrypt master key), page encryption (AES-256-CTR), IV derivation (HKDF from master key + block number)
   - WAL signing: key loading, deferred signing on segment completion, verification on receive
   - TLS: hybrid group negotiation, oqs-provider vs native OpenSSL 3.5
   - Column encryption: `pqc_encrypt`/`pqc_decrypt` flow through pgcrypto_pqc

3. **Key material lifecycle** — Where each key lives in memory, when it's zeroed (`explicit_bzero`/`OQS_MEM_cleanse`), what survives in core dumps

4. **Known limitations** — HSM not yet integrated, no formal fuzz testing, EXEC_BACKEND key inheritance, liboqs dependency for side-channel resistance

**File:** `docs/SECURITY_AUDIT.md` — expand existing document
**Priority:** High — required for any enterprise evaluation
**Effort:** Medium (documentation only, no code)

---

## Phase 2: Production Readiness (v2.0.0)

### Task 4 — HSM/KMS Key Provider Interface

**Problem:** TDE key retrieval is hardcoded to `getenv("FORTRESSQL_KEM_SECRET_KEY")` at line 474 of `tde_keymanage.c`. Production deployments need keys from HSM, AWS KMS, Azure Key Vault, or HashiCorp Vault.

**Design:** Abstract key provider interface with pluggable backends.

```c
/* src/include/crypto/tde/tde_key_provider.h */

typedef enum TdeKeyProviderType {
    TDE_KEY_PROVIDER_ENV,       /* environment variable (current default) */
    TDE_KEY_PROVIDER_FILE,      /* read hex from file path */
    TDE_KEY_PROVIDER_COMMAND,   /* execute command, read hex from stdout */
} TdeKeyProviderType;
```

**New GUCs:**
- `tde_key_provider` — `env` (default), `file`, `command`
- `tde_key_file` — path to file containing hex-encoded secret key
- `tde_key_command` — command to execute (follows `ssl_passphrase_command` pattern)

**Files to create/modify:**
- New: `src/include/crypto/tde/tde_key_provider.h` — interface definition
- New: `src/backend/crypto/tde/tde_key_provider.c` — implementations (env, file, command)
- `src/backend/crypto/tde/tde_keymanage.c` — replace `getenv()` with `tde_key_provider_fetch()`
- `src/backend/utils/misc/guc_tables.c` — register new GUCs
- `src/backend/crypto/tde/meson.build` — add new source file

**Risks:**
- `command` provider runs external process during startup — needs timeout, must be outside critical sections
- Follow `ssl_passphrase_command` pattern from `be-secure-openssl.c` for safe subprocess execution
- Key material from command stdout must be wiped immediately after use

**Priority:** High for production — enterprises won't deploy with env var key management
**Effort:** Large (~400 lines new code + GUC registration)

---

### Task 5 — Replication Testing in CI

**Problem:** No CI test validates WAL signing across primary → standby replication. The existing TAP test `src/test/pqc/t/010_replication_pqc.pl` exists but has bugs and isn't in the CI workflow.

**Known bug:** Test writes key files as `wal_sign_pub.bin` / `wal_sign_sec.bin`, but the server expects `wal_signing.pub` / `wal_signing.key` (defined in `pqc_wal_keys.c` lines 49-50).

**Files to modify:**
- `src/test/pqc/t/010_replication_pqc.pl` — Fix key filenames, verify test logic
- `.github/workflows/pqc-ci.yml` — Add replication test step:
  ```yaml
  - name: Replication with WAL signing verification
    run: |
      cd build
      meson test pqc/010_replication_pqc --timeout-multiplier 6 --print-errorlogs
  ```
- `src/test/pqc/meson.build` — Verify test is registered in the suite

**Test flow:**
1. Start primary with `wal_pqc_signing = on` + signing keys
2. Start standby streaming from primary
3. Insert data on primary
4. Verify data appears on standby
5. Verify `.sig` files exist in primary's `pg_wal/`
6. (Optional) Verify standby validated signatures on receive

**Risks:** Replication tests are time-sensitive in CI — use generous timeout (6x multiplier)
**Priority:** Medium — validates the complete signing pipeline
**Effort:** Medium (~100 lines test fixes + CI config)

---

### Task 6 — Performance Baselines (pgbench)

**Problem:** No quantitative data on PQC overhead vs standard PostgreSQL. Enterprises need to know the performance cost of enabling TDE and WAL signing.

**Design:** Run pgbench with and without PQC features, emit structured results.

**Benchmark matrix:**

| Configuration | What it measures |
|--------------|-----------------|
| Baseline (PQC compiled but disabled) | Standard PostgreSQL throughput |
| WAL signing enabled | Overhead of ML-DSA-65 signing per WAL segment |
| TDE enabled | Overhead of AES-256 page encryption + ML-KEM key unwrap |
| WAL signing + TDE | Combined overhead |
| PQC SQL operations | Throughput of keygen/sign/verify/encrypt/decrypt |

**Files to modify:**
- `.github/workflows/pqc-ci.yml` — Add pgbench comparison step (30s runs, output TPS)
- `src/test/pqc/t/012_tde_benchmark.pl` — Extend to run with TDE enabled
- `contrib/pgcrypto_pqc/sql/ci_benchmark.sql` — Add wall-clock timing comparisons

**Output format:** Structured markdown table in CI logs (informational, no pass/fail thresholds — CI runners have variable performance)

**Priority:** Medium — important for enterprise sales, but not a blocker
**Effort:** Medium (~150 lines CI + test changes)

---

## Implementation Order

```
Phase 1 (Beta — v1.1.0):
  1. WAL key auto-load .............. [small]  ← do first, unblocks everything
  2. Security audit document ........ [medium] ← can parallel with #1
  3. PQC/hybrid TLS (client-side) ... [medium] ← after #1

Phase 2 (Production — v2.0.0):
  4. HSM/KMS key provider ........... [large]  ← biggest code change
  5. Replication CI test ............ [medium] ← depends on #1
  6. Performance baselines .......... [medium] ← run last, after everything stable
```

**Estimated total:** ~1000 lines of code changes + ~500 lines of documentation

---

## Success Criteria

### Beta (v1.1.0)
- [x] WAL signing keys auto-load on primary startup — segments get `.sig` files without manual SQL
- [x] PQC TLS works end-to-end (server + libpq client with oqs-provider or OpenSSL 3.5+)
- [x] Comprehensive security audit document suitable for enterprise review
- [ ] All CI green

### Production (v2.0.0)
- [x] TDE keys can be fetched from file or external command (HSM/KMS integration path)
- [x] Primary → standby replication with WAL signing verified in CI
- [x] Published performance baselines (pgbench TPS with/without PQC)
- [ ] All CI green including replication tests
- [x] Ready for third-party security audit engagement
