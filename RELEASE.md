# FortressQL v1.0.2 Release Notes

**Release Date:** March 16, 2026
**Base:** PostgreSQL 17.9
**License:** PostgreSQL License

---

## Overview

FortressQL is a PostgreSQL 17 fork with built-in post-quantum cryptography. It provides ML-KEM, ML-DSA, SLH-DSA, Transparent Data Encryption (TDE), WAL signing, and hybrid PQC/classical TLS — all compliant with FIPS 203, 204, and 205.

v1.0.2 delivers all six production readiness milestones: WAL key auto-load, client-side PQC TLS, a comprehensive security audit document, a pluggable HSM/KMS key provider interface, replication test coverage, and pgbench performance baselines. It also fixes a WAL signing crash under concurrent load by switching to hash-then-sign.

---

## What's New in v1.0.2

### Beta Features

- **WAL signing key auto-load on primary startup** — `pqc_preflight_check()` is now called from `postmaster.c` during server startup. When `wal_pqc_signing = on` and key files exist in `wal_pqc_key_path`, the ML-DSA signing keys are automatically loaded into memory. Forked backends inherit the keys via `fork()`, matching the existing standby behavior. Previously, keys were only loaded on the standby via `walreceiver.c`.

- **Client-side PQC TLS (libpq)** — `fe-secure-openssl.c` now loads the OQS provider for OpenSSL 3.0–3.4 and configures hybrid PQC key exchange groups (`X25519MLKEM768`) with graceful fallback to classical groups (`X25519:prime256v1:secp384r1`). This mirrors the server-side PQC TLS already present in `be-secure-openssl.c`. Client applications using libpq (psql, pg_dump, custom apps) now negotiate PQC-protected TLS connections automatically when `sslpqcmode != off`.

- **Security audit document** — New `docs/SECURITY_AUDIT.md` covering threat model (HNDL attacks, WAL tampering, data-at-rest extraction), cryptographic architecture details for all four PQC subsystems, key material lifecycle tables, FIPS 203/204/205 compliance mapping, seven known limitations, and third-party audit recommendations (~5,000 lines of PQC code, 3–5 week engagement estimate).

### Production Features

- **HSM/KMS key provider interface** — New `tde_key_provider` GUC with three modes:
  - `env` (default) — reads the ML-KEM secret key from `FORTRESSQL_KEM_SECRET_KEY` environment variable (existing behavior)
  - `file` — reads the hex-encoded secret key from the path specified by `tde_key_file`
  - `command` — executes `tde_key_command` and reads the hex key from stdout, enabling integration with HashiCorp Vault, AWS KMS, Azure Key Vault, or any external key management system

  New files: `src/include/crypto/tde/tde_key_provider.h`, `src/backend/crypto/tde/tde_key_provider.c`

- **Replication test fix** — `src/test/pqc/t/010_replication_pqc.pl` was writing WAL signing keys with wrong filenames (`wal_sign_pub.bin`/`wal_sign_sec.bin`). Now uses `pqc_rotate_wal_signing_keys('ML-DSA-65')` SQL function which writes the correct `wal_signing.pub`/`wal_signing.key` files. Test added to CI workflow.

- **Performance baselines (pgbench)** — CI now runs a 4-configuration pgbench matrix:
  1. Baseline (PQC disabled)
  2. WAL signing only (ML-DSA-65)
  3. TDE only (AES-256 + ML-KEM-768)
  4. TDE + WAL signing

  Each configuration runs `pgbench -T 15 -c 4 -j 2` on a scale-5 database. Results are printed as a summary table at the end of each CI run.

### Bug Fixes

- **WAL signing crash under concurrent load** — Under heavy pgbench load with 4 clients, the OQS ML-DSA-65 signing function would crash when given a full 16MB WAL segment directly. Switched to hash-then-sign: the segment is read in 8KB chunks and hashed with SHA-256 (via PostgreSQL's `pg_cryptohash` API), then only the 32-byte hash is signed. This eliminates the 16MB `palloc` allocation per signing operation and avoids passing large buffers to OQS.

- **Compilation errors** — Fixed `pqc_wal_load_signing_keys()` call missing required `key_path` and `algorithm` arguments. Fixed `#ifdef USE_PQC` guard nesting in `guc_tables.c` that caused `crypto_policy` and `tde_key_provider` symbols to be undeclared.

---

## Cumulative Features

### Post-Quantum Cryptography Engine
- **ML-KEM** (FIPS 203) — ML-KEM-512, ML-KEM-768, ML-KEM-1024 key encapsulation
- **ML-DSA** (FIPS 204) — ML-DSA-44, ML-DSA-65, ML-DSA-87 digital signatures
- **SLH-DSA** (FIPS 205) — All 12 SLH-DSA parameter sets (SHA2/SHAKE, 128/192/256, S/F)

### SQL Functions (`pgcrypto_pqc` extension)
```sql
-- Key generation
SELECT * FROM pqc_kem_keygen('ML-KEM-768');
SELECT * FROM pqc_sig_keygen('ML-DSA-65');

-- Encryption / Decryption
SELECT pqc_encrypt(data, public_key, 'ML-KEM-768');
SELECT pqc_decrypt(ciphertext, secret_key, 'ML-KEM-768');

-- Signing / Verification
SELECT pqc_sign(message, secret_key, 'ML-DSA-65');
SELECT pqc_verify(message, signature, public_key, 'ML-DSA-65');

-- Key management
SELECT * FROM pqc_rotate_wal_signing_keys('ML-DSA-65');
SELECT * FROM pqc_algorithms();
```

### Transparent Data Encryption (TDE)
- AES-256 data-at-rest encryption with ML-KEM-768 key wrapping
- `pg_tde_master_key` CLI for master key lifecycle management
- Pluggable key providers: environment variable, file, or external command (HSM/KMS)
- Automatic key unwrapping at server startup

### WAL Signing
- Post-quantum digital signatures on completed WAL segments (hash-then-sign)
- ML-DSA-65 (default), ML-DSA-44, ML-DSA-87 supported
- Deferred signing architecture — zero impact on WAL write critical path
- Automatic key loading on primary startup
- Online key rotation via `pqc_rotate_wal_signing_keys()`

### PQC TLS
- Server-side: oqs-provider with configurable `ssl_pqc_groups` and `ssl_pqc_sigalgs`
- Client-side (libpq): automatic hybrid PQC key exchange (`X25519MLKEM768`)
- Three modes: `off`, `hybrid` (default), `pqc-only`

---

## Quick Start

```bash
# Build from source
meson setup build -Dpqc=enabled
cd build && ninja && ninja install

# Initialize a cluster with TDE
initdb -D /path/to/data
pg_tde_master_key init -D /path/to/data
export FORTRESSQL_KEM_SECRET_KEY='<hex from init output>'

# Configure postgresql.conf
echo "tde_enabled = on" >> /path/to/data/postgresql.conf

# Start
pg_ctl -D /path/to/data start

# Enable PQC SQL functions
psql -c "CREATE EXTENSION pgcrypto_pqc;"
```

### WAL Signing Setup

```bash
# Create key directory and configure
mkdir -p /path/to/data/pg_wal_keys
echo "wal_pqc_key_path = '/path/to/data/pg_wal_keys'" >> postgresql.conf
echo "wal_pqc_signing_algorithm = 'ML-DSA-65'" >> postgresql.conf

# Start server, generate keys
pg_ctl start
psql -c "CREATE EXTENSION pgcrypto_pqc;"
psql -c "SELECT * FROM pqc_rotate_wal_signing_keys('ML-DSA-65');"

# Stop, enable signing, restart
pg_ctl stop
echo "wal_pqc_signing = on" >> postgresql.conf
pg_ctl start
```

### HSM/KMS Key Provider

```bash
# File-based key storage
echo "tde_key_provider = 'file'" >> postgresql.conf
echo "tde_key_file = '/secure/path/tde_secret.hex'" >> postgresql.conf

# External command (e.g., HashiCorp Vault)
echo "tde_key_provider = 'command'" >> postgresql.conf
echo "tde_key_command = 'vault kv get -field=hex_key secret/fortressql/tde'" >> postgresql.conf
```

---

## CI Status

| Platform | PQC | Build | TDE E2E | WAL Signing E2E | Crash Recovery | Replication | Benchmarks |
|----------|-----|-------|---------|-----------------|----------------|-------------|------------|
| Ubuntu 24.04 x86_64 | Enabled | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Ubuntu 24.04 x86_64 | Disabled | :white_check_mark: | N/A | N/A | N/A | N/A | N/A |
| macOS 14 ARM64 | Enabled | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Windows x64 | Disabled | :white_check_mark: | N/A | N/A | N/A | N/A | N/A |

---

## Security

- **Audit document:** [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)
- **Report vulnerabilities:** security@dyber.org
- **Disclosure policy:** [SECURITY.md](SECURITY.md)

---

## Upgrade from v1.0.1

No schema changes. Replace binaries and restart:

```bash
pg_ctl stop
# Install new binaries (meson setup build && ninja -C build install)
pg_ctl start
```

New GUCs available after upgrade (optional):
- `tde_key_provider` — `'env'` (default), `'file'`, or `'command'`
- `tde_key_file` — path to hex-encoded secret key file
- `tde_key_command` — external command that outputs the hex key

---

## Links

- **Repository:** https://github.com/dyber-pqc/fortressQL
- **Changelog:** https://github.com/dyber-pqc/fortressQL/compare/v1.0.1...v1.0.2
- **Production Readiness Plan:** [docs/PRODUCTION_READINESS_PLAN.md](docs/PRODUCTION_READINESS_PLAN.md)
- **Security Audit:** [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)
- **Documentation:** [docs/](docs/)
- **liboqs:** https://github.com/open-quantum-safe/liboqs
