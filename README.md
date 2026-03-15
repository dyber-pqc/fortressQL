<p align="center">
  <img src="logo.svg" alt="FortressQL Logo" width="200" height="200">
</p>

<h1 align="center">FortressQL</h1>

<p align="center">
  <strong>Post-Quantum Cryptography for PostgreSQL</strong>
</p>

<p align="center">
  A hardened fork of PostgreSQL 17 with NIST-standardized post-quantum cryptography<br>
  integrated across TLS transport, authentication, and application-level encryption.
</p>

---

## Why FortressQL?

Quantum computers threaten current cryptographic standards. The **"harvest now, decrypt later"** attack means data encrypted today with classical algorithms can be stored and decrypted once quantum computers mature. NIST has finalized three post-quantum cryptographic standards to address this threat.

FortressQL integrates these standards directly into PostgreSQL, providing quantum-resistant protection across every layer of the database stack.

## NIST PQC Algorithms

| Algorithm | Standard | Purpose | Variants |
|-----------|----------|---------|----------|
| **ML-KEM** | FIPS 203 | Key Encapsulation | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| **ML-DSA** | FIPS 204 | Digital Signatures | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| **SLH-DSA** | FIPS 205 | Hash-Based Signatures | 12 variants (SHA-2 and SHAKE) |

## Features

### PQC TLS Transport
Hybrid key exchange combining classical and post-quantum algorithms for defense-in-depth.

```
# postgresql.conf
ssl_pqc_mode = 'hybrid'                              # off | hybrid | pqc-only
ssl_pqc_groups = 'X25519MLKEM768:X25519:prime256v1'   # key exchange groups
ssl_pqc_sigalgs = 'mldsa65:ed25519'                   # certificate signature algorithms
```

```bash
# Client connection with PQC TLS
psql "host=localhost sslmode=require sslpqcgroups=X25519MLKEM768"
```

Monitor negotiated PQC groups via `pg_stat_ssl`:
```sql
SELECT pid, ssl_version, ssl_cipher, pqc_group FROM pg_stat_ssl;
```

### PQC Authentication

Two new authentication methods in `pg_hba.conf`:

```
# PQC certificate authentication (ML-DSA / SLH-DSA certificates)
hostssl all all 0.0.0.0/0 pqc-cert

# SCRAM-SHA-384 (NIST Level 3 aligned)
hostssl all all 0.0.0.0/0 pqc-scram-sha-384
```

- **`pqc-cert`** — Verifies client certificates use post-quantum signature algorithms
- **`pqc-scram-sha-384`** — SCRAM authentication with SHA-384 (48-byte keys)

### pgcrypto_pqc Extension

SQL-callable PQC functions for application-level encryption:

```sql
CREATE EXTENSION pgcrypto_pqc;

-- Key Encapsulation (ML-KEM)
SELECT * FROM pqc_kem_keygen('ML-KEM-768');
SELECT * FROM pqc_kem_encapsulate(public_key, 'ML-KEM-768');
SELECT pqc_kem_decapsulate(ciphertext, secret_key, 'ML-KEM-768');

-- Digital Signatures (ML-DSA, SLH-DSA)
SELECT * FROM pqc_sig_keygen('ML-DSA-65');
SELECT pqc_sign('message'::bytea, secret_key, 'ML-DSA-65');
SELECT pqc_verify('message'::bytea, signature, public_key, 'ML-DSA-65');

-- Hybrid Encryption (ML-KEM + AES-256-GCM)
SELECT * FROM pqc_encrypt('sensitive data'::bytea, 'ML-KEM-768');
SELECT pqc_decrypt(encrypted_data, encapsulated_key, secret_key, 'ML-KEM-768');

-- Algorithm Discovery
SELECT * FROM pqc_algorithms();
```

### PQC Cluster Communication

Streaming replication inherits PQC TLS automatically:
```
# postgresql.conf on standby
primary_conninfo = 'host=primary sslmode=verify-full sslpqcmode=hybrid sslpqcgroups=X25519MLKEM768'
```

## Architecture

```
+--------------------------------------------------+
|              FortressQL Server                    |
|                                                   |
|  +--------------------------------------------+  |
|  |  PQC TLS Transport (OpenSSL 3.x)           |  |
|  |  - Hybrid key exchange (X25519MLKEM768)     |  |
|  |  - PQC certificate verification             |  |
|  +--------------------------------------------+  |
|                                                   |
|  +--------------------------------------------+  |
|  |  PQC Authentication                         |  |
|  |  - pqc-cert (ML-DSA/SLH-DSA certificates)  |  |
|  |  - pqc-scram-sha-384 (NIST Level 3)        |  |
|  +--------------------------------------------+  |
|                                                   |
|  +--------------------------------------------+  |
|  |  pgcrypto_pqc Extension                     |  |
|  |  - ML-KEM key encapsulation                 |  |
|  |  - ML-DSA / SLH-DSA signatures              |  |
|  |  - Hybrid encryption (ML-KEM + AES-256-GCM) |  |
|  +--------------------------------------------+  |
|                                                   |
|  +--------------------------------------------+  |
|  |  PQC Abstraction Layer (liboqs)             |  |
|  |  - Unified C API for all NIST PQC algos     |  |
|  |  - Secure memory management                 |  |
|  +--------------------------------------------+  |
+--------------------------------------------------+
```

## Building

### Prerequisites

- **OpenSSL** 3.0 or later (3.5+ recommended for native PQC support)
- **liboqs** (Open Quantum Safe) — required for PQC features
- **oqs-provider** — required for PQC TLS on OpenSSL < 3.5
- Standard PostgreSQL build dependencies

### Build liboqs

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON ..
ninja && sudo ninja install && sudo ldconfig
```

### Build oqs-provider (OpenSSL < 3.5)

```bash
git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -Dliboqs_DIR=/usr/local/lib/cmake/liboqs ..
ninja && sudo ninja install
```

### Build FortressQL

```bash
# With PQC enabled (default if liboqs is found)
meson setup build -Dssl=openssl -Dpqc=enabled
meson compile -C build
sudo meson install -C build

# Without PQC (vanilla PostgreSQL compatible)
meson setup build -Dssl=openssl -Dpqc=disabled
meson compile -C build
```

### Build Options

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `-Dpqc` | `enabled`, `disabled`, `auto` | `auto` | PQC support (auto-detects liboqs) |
| `-Dssl` | `openssl` | — | Required for TLS features |

### Run Tests

```bash
cd build
meson test --suite pqc --print-errorlogs    # PQC-specific tests
meson test --suite regress --print-errorlogs # Core regression tests
```

## Compatibility

- **PQC disabled**: Produces binaries identical to vanilla PostgreSQL 17
- **All PQC code** is guarded by `#ifdef USE_PQC` compile flags
- **Hybrid-first defaults**: Classical algorithms always included as fallback
- **Client compatibility**: Non-PQC clients connect normally via classical TLS

## Configuration Reference

### Server (postgresql.conf)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ssl_pqc_mode` | enum | `hybrid` | `off`, `hybrid`, or `pqc-only` |
| `ssl_pqc_groups` | string | `X25519MLKEM768:X25519:prime256v1` | Key exchange groups |
| `ssl_pqc_sigalgs` | string | *(empty)* | TLS signature algorithms |

### Client (connection string)

| Parameter | Description |
|-----------|-------------|
| `sslpqcmode` | PQC mode: `off`, `hybrid`, `pqc-only` |
| `sslpqcgroups` | Key exchange groups (colon-separated) |

## License

FortressQL is released under the [PostgreSQL License](COPYRIGHT), the same permissive open-source license as PostgreSQL.

Portions Copyright (c) 2024-2026, FortressQL Contributors
Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group

## Acknowledgments

- [PostgreSQL](https://www.postgresql.org/) — The foundation
- [Open Quantum Safe (liboqs)](https://openquantumsafe.org/) — PQC algorithm implementations
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) — Standards
