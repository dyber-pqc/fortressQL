# FortressQL v1.0.1 Release Notes

**Release Date:** March 16, 2026
**Base:** PostgreSQL 17.9
**License:** PostgreSQL License

---

## Overview

FortressQL is a PostgreSQL 17 fork with built-in post-quantum cryptography. It provides ML-KEM, ML-DSA, SLH-DSA, Transparent Data Encryption (TDE), WAL signing, and hybrid PQC/classical TLS — all compliant with FIPS 203, 204, and 205.

v1.0.1 is a patch release fixing critical bugs in TDE master key initialization and WAL segment signing discovered during end-to-end CI validation.

---

## What's New in v1.0.1

### Bug Fixes

- **TDE master key file format mismatch** — `pg_tde_master_key init` was producing files incompatible with the server. The tool wrote magic `FQMK` with only a header and public key, but the server expected magic `TDE1` with the full encrypted payload (header + public key + ML-KEM-768 ciphertext + AES-256-GCM IV + encrypted master key + GCM tag). The tool now generates a random AES-256 master key, wraps it via ML-KEM-768 encapsulation and AES-256-GCM encryption, and writes the complete server-compatible blob.

- **TDE key cache never initialized at startup** — `tde_keycache_shmem_init()` and `tde_unwrap_master_key()` were defined but never wired into the PostgreSQL shared memory startup path. Added initialization to `ipci.c` so the key cache is allocated in shared memory and the master key is unwrapped automatically when the server starts with `tde_enabled = on`.

- **WAL signing PANIC in critical section** — `XLogPqcSignSegment` was called directly inside `XLogWrite`, which runs in a PostgreSQL critical section. Any `palloc` call inside a critical section triggers an immediate `PANIC` and server crash. Replaced with a deferred signing queue: segment metadata is recorded inside `XLogWrite`, and the actual signing (file I/O, cryptographic operations) runs after `END_CRIT_SECTION()` in `XLogFlush` and the WAL writer.

- **WAL signing test missing ML-DSA keys** — WAL signing requires ML-DSA digital signature keypairs (separate from TDE's ML-KEM keys), loaded from the `wal_pqc_key_path` directory. CI tests now properly generate keys via `pqc_rotate_wal_signing_keys('ML-DSA-65')` before enabling `wal_pqc_signing`.

### CI/Testing Improvements

- End-to-end TDE test covering full lifecycle: `initdb` → `pg_tde_master_key init` → start with `tde_enabled=on` → create database/table → insert → restart → verify data survives
- End-to-end WAL signing test: generate ML-DSA-65 keys → enable `wal_pqc_signing` → insert data → `pg_switch_wal()` → restart → verify WAL replay integrity
- Crash recovery test: insert → checkpoint → insert more → `pg_ctl stop -m immediate` (simulate crash) → restart → verify all rows survive
- Server log capture on all test failures for faster debugging

---

## Features (since v1.0.0)

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
- Automatic key unwrapping at server startup via `FORTRESSQL_KEM_SECRET_KEY` environment variable

### WAL Signing
- Post-quantum digital signatures on completed WAL segments
- ML-DSA-65 (default), ML-DSA-44, ML-DSA-87 supported
- Deferred signing architecture — zero impact on WAL write critical path
- Online key rotation via `pqc_rotate_wal_signing_keys()`

### Performance
- CI benchmark suite: ML-KEM-768 keygen+encaps+decaps, ML-DSA-65 keygen+sign+verify, column-level encryption round-trip

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

# Start server, generate keys
pg_ctl start
psql -c "CREATE EXTENSION pgcrypto_pqc;"
psql -c "SELECT * FROM pqc_rotate_wal_signing_keys('ML-DSA-65');"

# Stop, enable signing, restart
pg_ctl stop
echo "wal_pqc_signing = on" >> postgresql.conf
pg_ctl start
```

---

## CI Status

| Platform | PQC | Build | Smoke Tests | TDE E2E | WAL Signing E2E | Crash Recovery | Benchmarks |
|----------|-----|-------|-------------|---------|-----------------|----------------|------------|
| Ubuntu 24.04 x86_64 | Enabled | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Ubuntu 24.04 x86_64 | Disabled | :white_check_mark: | N/A | N/A | N/A | N/A | N/A |
| macOS 14 ARM64 | Enabled | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Windows x64 | Disabled | :white_check_mark: | N/A | N/A | N/A | N/A | N/A |

---

## Security

Report vulnerabilities to **security@dyber.org**. See [SECURITY.md](SECURITY.md) for the full disclosure policy.

---

## Links

- **Repository:** https://github.com/dyber-pqc/fortressQL
- **Changelog:** https://github.com/dyber-pqc/fortressQL/compare/v1.0.0...v1.0.1
- **Documentation:** [docs/](docs/)
- **liboqs:** https://github.com/open-quantum-safe/liboqs
