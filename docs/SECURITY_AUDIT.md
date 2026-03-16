# FortressQL Security Audit Document

**Product:** FortressQL (PostgreSQL 17 fork with post-quantum cryptography)
**Document Version:** 2.0
**Date:** 2026-03-16
**Classification:** Internal / Pre-Audit

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Cryptographic Architecture](#2-cryptographic-architecture)
3. [Key Material Lifecycle](#3-key-material-lifecycle)
4. [FIPS Compliance](#4-fips-compliance)
5. [Known Limitations and Open Items](#5-known-limitations-and-open-items)
6. [Recommendations for Third-Party Audit](#6-recommendations-for-third-party-audit)

---

## 1. Threat Model

### 1.1 Threats FortressQL Protects Against

#### Harvest-Now-Decrypt-Later (HNDL) Attacks on Stored Data

Nation-state and advanced persistent threat actors are known to collect encrypted
traffic and data stores today with the intent of decrypting them once
cryptographically relevant quantum computers become available. FortressQL
addresses this by applying post-quantum key encapsulation (ML-KEM-768) to all
key wrapping operations and offering hybrid PQC+classical TLS for data in
transit. Data encrypted under FortressQL's TDE subsystem is protected against
future quantum decryption of the key material, because the master key wrapping
uses a KEM whose security assumptions are based on the hardness of the
Module-LWE problem rather than integer factorization or discrete logarithms.

#### WAL Tampering in Transit and at Rest

Write-ahead log segments are critical to database integrity and replication
correctness. FortressQL signs completed WAL segments using ML-DSA-65
(Module-Lattice Digital Signature Algorithm, security level 2). This ensures
that:

- A compromised network path between primary and standby cannot inject
  fabricated WAL records without detection.
- An attacker with filesystem access to archived WAL segments cannot modify
  them undetected.
- Replication integrity is cryptographically verifiable, not just
  checksum-based.

#### Data-at-Rest Extraction from Stolen Disks

If physical storage media (disks, SSDs, backup tapes) are stolen or improperly
decommissioned, FortressQL's Transparent Data Encryption (TDE) ensures that
tablespace data pages are encrypted with AES-256-CTR. The encryption key
hierarchy means that raw page data is unreadable without the ML-KEM secret key,
which is never stored on the same media as the encrypted data.

### 1.2 Threats FortressQL Does NOT Protect Against

The following threats are explicitly outside the scope of FortressQL's
cryptographic protections. Deployments must address these through operational
controls, network security, and application-layer measures:

- **Authorized DBA access.** A database administrator with valid credentials
  and the decryption key material can read all data. TDE protects data at rest,
  not data in use. Row-level security, audit logging, and privilege separation
  are complementary controls that remain the deployer's responsibility.

- **SQL injection and application-layer vulnerabilities.** FortressQL does not
  alter PostgreSQL's SQL parser or query execution in ways that prevent
  injection attacks. Applications must continue to use parameterized queries and
  input validation.

- **Side-channel attacks on shared hosts.** Timing attacks, cache-line attacks,
  power analysis, and other side-channel vectors on shared or virtualized
  infrastructure are not mitigated by FortressQL at the database layer.
  Side-channel resistance of the underlying PQC primitives depends on the liboqs
  implementation (see Section 5).

- **Compromise of the host operating system.** If an attacker gains root or
  SYSTEM-level access to the database server, they can read process memory,
  extract decrypted key material, and bypass all cryptographic controls.

---

## 2. Cryptographic Architecture

### 2.1 Transparent Data Encryption (TDE)

#### Key Wrapping Flow

The TDE master key is protected using ML-KEM-768 (NIST FIPS 203) key
encapsulation:

1. During initial setup (`pg_tde_master_key` utility), an ML-KEM-768 keypair is
   generated. The secret key is exported to the operator (via
   `FORTRESSQL_KEM_SECRET_KEY` environment variable). The public key is used
   immediately for encapsulation.
2. A random AES-256 master key is generated using the system CSPRNG.
3. ML-KEM-768 `Encaps(pk)` produces a shared secret and a ciphertext.
4. The shared secret is used as the key for AES-256-GCM to encrypt the master
   key. The resulting bundle (KEM ciphertext || GCM nonce || GCM ciphertext ||
   GCM tag) is written to disk.
5. At server startup, the server reads the wrapped master key file, performs
   ML-KEM-768 `Decaps(sk, ct)` using the secret key from the environment
   variable, recovers the shared secret, and decrypts the master key with
   AES-256-GCM.

```
┌──────────────────────────────────────────────────────┐
│                  Key Wrapping Flow                    │
│                                                      │
│  ML-KEM-768 Encaps(pk) ──► shared_secret + ct       │
│                              │                       │
│                              ▼                       │
│              AES-256-GCM Encrypt(shared_secret,      │
│                               master_key)            │
│                              │                       │
│                              ▼                       │
│              Disk: ct || nonce || ciphertext || tag   │
│                                                      │
│  At startup:                                         │
│  ML-KEM-768 Decaps(sk, ct) ──► shared_secret        │
│              AES-256-GCM Decrypt ──► master_key      │
└──────────────────────────────────────────────────────┘
```

#### Page Encryption

Individual data pages are encrypted using AES-256-CTR. This mode is chosen for
its ability to support random-access reads and writes to individual pages
without requiring re-encryption of adjacent pages.

#### IV Derivation

Initialization vectors for page encryption are derived deterministically using
HKDF (HMAC-based Key Derivation Function) with the following inputs:

- The TDE master key as the input keying material
- A context string composed of the block number, tablespace OID, and relation
  OID

This ensures that each page has a unique, deterministic IV without requiring
per-page IV storage, while preventing IV reuse across different pages,
tablespaces, or relations. The deterministic derivation also means that the same
page written with the same content produces the same ciphertext, which is an
acceptable trade-off for the operational simplicity it provides.

### 2.2 WAL Signing

#### Signing Algorithm

Completed WAL segments are signed using ML-DSA-65 (NIST FIPS 204), which
provides NIST security level 2 (roughly equivalent to 128-bit classical
security). ML-DSA-65 was selected for its balance between signature size
(~3,300 bytes), verification speed, and security margin.

#### Deferred Signing Queue Architecture

WAL signing is implemented with a deferred queue to avoid introducing latency
in the critical WAL write path:

1. When a WAL segment file is completed (filled and ready for archival), it is
   enqueued for signing rather than signed synchronously.
2. A background worker processes the signing queue, computing ML-DSA-65
   signatures over the full segment contents.
3. The signature is stored alongside the segment file (or appended as metadata).
4. This architecture ensures that WAL write throughput is not gated by the
   signing operation, which involves a ~3,300-byte signature computation.

#### Verification on Standby

When a standby server receives a WAL segment (via streaming replication or
archive recovery), it verifies the ML-DSA-65 signature against the configured
public key before applying the segment. Segments that fail verification are
rejected and an error is logged. This provides end-to-end integrity from primary
WAL generation through standby application.

### 2.3 Column-Level Encryption (pgcrypto_pqc Extension)

The `pgcrypto_pqc` extension provides SQL-callable functions for column-level
encryption and decryption:

- **`pqc_encrypt(plaintext bytea, public_key bytea)`** -- Performs ML-KEM-768
  encapsulation against the provided public key, derives a shared secret, and
  encrypts the plaintext with AES-256-GCM. Returns the concatenation of the KEM
  ciphertext and the GCM-encrypted payload.

- **`pqc_decrypt(ciphertext bytea, secret_key bytea)`** -- Performs ML-KEM-768
  decapsulation to recover the shared secret and decrypts the AES-256-GCM
  payload.

This extension allows applications to encrypt sensitive columns (e.g., PII,
credentials, health records) with post-quantum security at the SQL level,
independent of TDE. Key management for column encryption is the application's
responsibility.

### 2.4 TLS (Post-Quantum Key Exchange)

FortressQL supports hybrid post-quantum TLS key exchange combining ML-KEM with
X25519:

- **Provider mechanism:** The `oqs-provider` for OpenSSL 3.x supplies hybrid
  key exchange algorithms (e.g., `x25519_mlkem768`). OpenSSL 3.5+ also supports
  ML-KEM natively.
- **GUC parameter:** The `ssl_pqc_mode` server parameter controls PQC TLS
  behavior:
  - `off` -- Standard classical TLS only.
  - `preferred` -- Offer hybrid PQC key exchange; fall back to classical if the
    client does not support it.
  - `required` -- Reject connections that do not negotiate a PQC key exchange.
- **Ephemeral keys:** PQC key exchange keys are ephemeral and generated
  per-connection by OpenSSL. No long-term PQC key material is stored for TLS.
- **Hybrid design rationale:** The hybrid approach (ML-KEM + X25519) ensures
  that security is maintained even if one of the two algorithms is broken,
  providing defense-in-depth during the transition period.

---

## 3. Key Material Lifecycle

### 3.1 TDE Master Key

| Property | Detail |
|---|---|
| **Storage location** | `$PGDATA/global/pg_encryption/master.key` |
| **On-disk format** | ML-KEM-768 ciphertext \|\| AES-256-GCM nonce \|\| encrypted master key \|\| GCM authentication tag |
| **Protection** | Encrypted under ML-KEM-768 shared secret; requires the corresponding secret key to unwrap |
| **In-memory form** | Unwrapped into process memory at server startup; stored in shared memory for access by all backends |
| **Wiping** | Registered via `on_proc_exit` callback; memory is zeroed using `explicit_bzero` to prevent compiler optimization from eliding the wipe |
| **Rotation** | Manual; requires re-encrypting all tablespaces with a new master key (tooling provided but no automated schedule enforcement) |

### 3.2 TDE ML-KEM Secret Key

| Property | Detail |
|---|---|
| **Storage location** | Configurable via `tde_key_provider` GUC: environment variable (`env`), file (`file`), or external command (`command`). Never written to disk by the server process itself. |
| **In-memory form** | Hex-decoded into a `palloc`-allocated buffer during startup decapsulation |
| **Wiping** | Buffer is `explicit_bzero`-wiped and freed immediately after decapsulation completes; the secret key exists in process memory only for the duration of the `Decaps` operation |
| **Operational guidance** | For `env` provider: the environment variable should be set via a secrets manager, systemd credential, or container orchestration secret. For `file` provider: restrict permissions to 0600. For `command` provider: use a script that retrieves the key from an HSM/KMS. The key must not appear in shell history, process listings, or log files. |

### 3.3 WAL Signing Keys

| Property | Detail |
|---|---|
| **Storage location** | Directory specified by `wal_pqc_key_path` GUC; files are `wal_signing.key` (secret key) and `wal_signing.pub` (public key) |
| **On-disk protection** | File permissions (0600); no additional encryption wrapping currently applied |
| **In-memory form** | Loaded into static buffers in `pqc_wal_keys.c` at server startup; remain in memory for the lifetime of the server process |
| **Distribution** | The public key must be distributed to all standby servers for verification. The secret key must exist only on the primary server. |
| **Rotation** | Manual; requires generating a new keypair, distributing the new public key to standbys, and restarting the primary |

### 3.4 TLS Keys

| Property | Detail |
|---|---|
| **Management** | Handled entirely by OpenSSL; FortressQL configures the provider and cipher suites but does not directly manage PQC TLS key material |
| **Lifetime** | Ephemeral; ML-KEM keypairs are generated per-connection during the TLS handshake and discarded after key exchange completes |
| **Long-term keys** | Server certificate and classical private key are managed per standard PostgreSQL TLS configuration (`ssl_cert_file`, `ssl_key_file`) |

---

## 4. FIPS Compliance

### 4.1 Applicable FIPS Standards

FortressQL's post-quantum algorithms align with the following NIST standards:

| Algorithm | FIPS Standard | Usage in FortressQL | Security Level |
|---|---|---|---|
| ML-KEM-768 | FIPS 203 (Aug 2024) | TDE key wrapping, column encryption, TLS key exchange | NIST Level 3 |
| ML-DSA-65 | FIPS 204 (Aug 2024) | WAL segment signing | NIST Level 2 |
| SLH-DSA | FIPS 205 (Aug 2024) | Reserved for future use (stateless hash-based signatures) | Configurable |
| AES-256-GCM | FIPS 197 / SP 800-38D | Key encryption, column encryption payload | -- |
| AES-256-CTR | FIPS 197 / SP 800-38A | TDE page encryption | -- |

### 4.2 liboqs Dependency

FortressQL's PQC primitives are implemented via the **Open Quantum Safe (OQS)**
project's `liboqs` library.

**Critical caveat:** liboqs is **not FIPS-certified**. It is an open-source
research and prototyping library. While it implements the algorithms specified in
FIPS 203, 204, and 205, the library itself has not undergone FIPS 140-3
validation. This means:

- FortressQL **cannot claim FIPS 140-3 compliance** for its PQC operations in
  its current form.
- Organizations with strict FIPS requirements should treat FortressQL's PQC
  layer as implementing FIPS-specified algorithms via a non-validated module.
- As FIPS 140-3 validated implementations of ML-KEM and ML-DSA become available
  from commercial cryptographic module vendors, FortressQL will evaluate
  migration to a validated provider.

### 4.3 Classical Cryptography

The AES-256-GCM and AES-256-CTR operations used for actual data encryption can
leverage a FIPS-validated OpenSSL module (OpenSSL 3.x FIPS provider) when
configured appropriately. This means the symmetric encryption layer can
independently satisfy FIPS requirements even while the PQC key management layer
uses a non-validated implementation.

---

## 5. Known Limitations and Open Items

### 5.1 Key Provider Interface (v1.1.0+)

As of v1.1.0, the TDE ML-KEM secret key retrieval is abstracted through a
pluggable key provider interface (`tde_key_provider` GUC):

- **`env`** (default) -- Reads from `FORTRESSQL_KEM_SECRET_KEY` environment
  variable. Backward-compatible with v1.0.x behavior.
- **`file`** -- Reads hex-encoded key from a file specified by `tde_key_file`.
  Warns if file permissions are too permissive (not 0600).
- **`command`** -- Executes `tde_key_command` and reads hex key from stdout,
  following the same subprocess pattern as PostgreSQL's
  `ssl_passphrase_command`. This enables integration with HashiCorp Vault,
  AWS KMS, Azure Key Vault, or any external secrets manager.

**Remaining limitations:**
- No direct PKCS#11/HSM integration (requires a wrapper command).
- No hardware-backed key attestation.
- Key material from the command provider transits through process memory
  (wiped with `explicit_bzero` after use, but briefly present in plaintext).

### 5.2 No Formal Fuzz Testing on PQC Input Paths

The PQC-specific code paths (KEM decapsulation, signature verification,
pgcrypto_pqc extension input parsing) have not been subjected to formal fuzz
testing. Malformed inputs to these paths could potentially trigger unexpected
behavior in liboqs or in FortressQL's wrapper code. Coverage with tools such as
AFL++, libFuzzer, or OSS-Fuzz is recommended.

### 5.3 Windows EXEC_BACKEND Key Inheritance

On Windows, PostgreSQL uses the `EXEC_BACKEND` model where child processes are
created via `CreateProcess` rather than `fork`. Environment variable and
in-memory state inheritance behaves differently under this model. WAL signing
keys loaded into static buffers in the postmaster may not be correctly inherited
by child backends. This is a known issue requiring platform-specific testing and
potentially explicit key re-loading in the child process initialization path.

### 5.4 Side-Channel Resistance

FortressQL delegates all PQC primitive operations to liboqs. The side-channel
resistance of these operations (constant-time execution, protection against
cache-timing attacks, protection against power analysis) is entirely dependent
on the liboqs implementation and the compiler's treatment of the generated code.
FortressQL does not add additional side-channel mitigations beyond what liboqs
provides. Deployments on shared or multi-tenant infrastructure should evaluate
this risk independently.

### 5.5 No Key Expiration or Rotation Enforcement

There is no automated mechanism to enforce key expiration or rotation schedules.
All key rotation (TDE master key, WAL signing keys) is manual and
operator-initiated. There are no warnings, alerts, or policy checks for key age.
Organizations with compliance requirements for key rotation periods must
implement external monitoring and operational procedures.

### 5.6 pgcrypto_pqc Extension Concurrency

The `pgcrypto_pqc` extension (providing `pqc_encrypt` and `pqc_decrypt` SQL
functions) has not been tested under high-concurrency workloads. Potential
concerns include:

- Thread safety of liboqs calls when invoked from multiple parallel backends.
- Memory allocation patterns under sustained concurrent encryption/decryption.
- Performance degradation characteristics under load.

Load testing with realistic concurrency levels is recommended before production
use of column-level encryption.

### 5.7 Client-Side PQC TLS (libpq)

As of v1.1.0, the `libpq` client library includes PQC TLS support:

- Automatic loading of the `oqs-provider` for OpenSSL 3.0-3.4.
- PQC group configuration via the `sslpqcmode` and `sslpqcgroups` connection
  parameters.
- Graceful fallback to classical groups if PQC is not available in the client's
  OpenSSL installation.

**Remaining limitations:**
- All libpq consumers (psql, pg_dump, application drivers) are affected by the
  PQC group configuration.
- The `oqs-provider` must be installed on the client system if using
  OpenSSL < 3.5.
- No mechanism to enforce PQC-only connections from the client side (the server's
  `ssl_pqc_mode = required` provides this enforcement).

---

## 6. Recommendations for Third-Party Audit

### 6.1 Suggested Audit Scope

A third-party security audit should focus on the PQC-specific code introduced
by FortressQL, which is concentrated in the following areas:

| Code Area | Approximate Size | Description |
|---|---|---|
| `src/backend/crypto/` | ~2,000 lines | TDE key wrapping, page encryption, HKDF IV derivation, key cache management |
| `contrib/pgcrypto_pqc/` | ~1,500 lines | Column-level encryption extension (pqc_encrypt, pqc_decrypt), liboqs bindings |
| `src/bin/pg_tde_master_key/` | ~800 lines | Master key generation and wrapping utility |
| WAL signing integration | ~700 lines | ML-DSA-65 signing/verification in WAL subsystem, deferred queue, key loading (`pqc_wal_keys.c`) |

**Total estimated PQC-specific code: approximately 5,000 lines.**

### 6.2 Priority Focus Areas

The following areas carry the highest risk and should receive the deepest
scrutiny:

1. **TDE page encryption correctness.** Verify that IV derivation produces
   unique IVs for all valid combinations of block number, tablespace OID, and
   relation OID. Confirm that AES-256-CTR encryption and decryption are
   correctly applied to page boundaries. Test edge cases: maximum block numbers,
   tablespace migration, relation truncation and re-creation.

2. **Key material handling and zeroing.** Audit all code paths where secret key
   material is allocated, used, and freed. Verify that `explicit_bzero` is
   called on all buffers containing secret keys before deallocation. Check for
   compiler optimizations that might elide zeroing. Verify that no secret key
   material is written to logs, core dumps, or error messages.

3. **WAL signing in critical paths.** Verify that the deferred signing queue
   cannot be bypassed (e.g., by a crash between segment completion and signing).
   Confirm that signature verification on standby is mandatory when configured
   and cannot be silently skipped. Assess the integrity guarantees if the
   primary crashes before signing a completed segment.

4. **OpenSSL integration.** Review the configuration of the oqs-provider and
   hybrid key exchange. Verify that `ssl_pqc_mode = required` correctly rejects
   non-PQC connections. Confirm that fallback behavior in `preferred` mode does
   not introduce downgrade attack vectors.

5. **liboqs API usage.** Verify that all calls to liboqs functions check return
   codes. Confirm that buffer sizes match liboqs expectations. Check for
   potential memory leaks in error paths.

### 6.3 Suggested Audit Activities

- **Code review:** Manual review of all PQC-specific code paths listed above.
- **Fuzz testing:** Targeted fuzzing of KEM decapsulation inputs, signature
  verification inputs, and pgcrypto_pqc function arguments.
- **Key lifecycle testing:** Attempt to recover key material from process
  memory, core dumps, swap partitions, and filesystem after key wiping.
- **Integration testing:** End-to-end testing of TDE encryption/decryption
  across server restart, crash recovery, and point-in-time recovery scenarios.
- **Downgrade testing:** Attempt to force classical-only TLS when
  `ssl_pqc_mode = required`. Attempt to bypass WAL signature verification.

### 6.4 Estimated Engagement

Based on the code volume (~5,000 lines of PQC-specific code) and the scope
described above, a thorough security audit by a qualified cryptographic
engineering firm is estimated to require 3-5 consultant-weeks, assuming
familiarity with PostgreSQL internals and post-quantum cryptography.

---

*This document is intended for internal use and as a briefing document for
prospective third-party auditors. It reflects the state of FortressQL as of
the date listed above and will be updated as the cryptographic subsystems
evolve.*

## Contact

For security-related inquiries, see [SECURITY.md](../SECURITY.md).
