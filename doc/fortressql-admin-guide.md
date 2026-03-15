# FortressQL Administrator's Guide

This guide covers installation, configuration, key management, backup, monitoring, and troubleshooting for FortressQL -- a hardened fork of PostgreSQL 17 with NIST-standardized post-quantum cryptography.

---

## Table of Contents

1. [Installation](#installation)
2. [Initial Configuration](#initial-configuration)
3. [pg_hba.conf Configuration](#pg_hbaconf-configuration)
4. [postgresql.conf Reference](#postgresqlconf-reference)
5. [Key Management](#key-management)
6. [Backup and Restore](#backup-and-restore)
7. [Monitoring](#monitoring)
8. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

| Dependency | Minimum Version | Recommended Version | Purpose |
|------------|----------------|---------------------|---------|
| OpenSSL | 3.0 | 3.5+ | TLS, cryptographic primitives |
| liboqs | 0.9+ | Latest stable | PQC algorithm implementations (ML-KEM, ML-DSA, SLH-DSA) |
| oqs-provider | Latest | Latest | OpenSSL provider for PQC TLS (not needed with OpenSSL 3.5+) |
| meson | 1.1+ | Latest stable | Build system |
| ninja | 1.10+ | Latest stable | Build backend |
| pkg-config | Any | Any | Dependency detection |
| flex | 2.5.35+ | Any | Lexer generator |
| bison | 2.3+ | Any | Parser generator |
| Python 3 | 3.6+ | 3.10+ | Meson dependency |

### Building from Source on Ubuntu 24.04

#### 1. Install system dependencies

```bash
sudo apt update
sudo apt install -y \
    build-essential pkg-config meson ninja-build \
    flex bison python3 python3-pip \
    libreadline-dev zlib1g-dev libxml2-dev libxslt1-dev \
    libssl-dev libicu-dev liblz4-dev libzstd-dev \
    cmake git
```

#### 2. Build and install liboqs

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    ..
ninja
sudo ninja install
sudo ldconfig
```

#### 3. Build and install oqs-provider (OpenSSL < 3.5 only)

If your system has OpenSSL 3.5 or later, skip this step -- native PQC support is built in.

```bash
git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider && mkdir build && cd build
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -Dliboqs_DIR=/usr/local/lib/cmake/liboqs \
    ..
ninja
sudo ninja install
```

Verify oqs-provider is loadable:

```bash
openssl list -providers -provider oqsprovider
```

#### 4. Build FortressQL

```bash
cd /path/to/sql-pqc

meson setup build \
    -Dpqc=enabled \
    -Dssl=openssl \
    -Dcassert=true \
    --prefix=/usr/local/fortressql

meson compile -C build
sudo meson install -C build
sudo ldconfig
```

#### 5. Verify installation

```bash
/usr/local/fortressql/bin/postgres --version
# Should output: postgres (FortressQL) 17.x
```

#### 6. Initialize database cluster

```bash
sudo -u postgres /usr/local/fortressql/bin/initdb \
    -D /var/lib/fortressql/data \
    --encoding=UTF8 \
    --locale=en_US.UTF-8
```

### Building from Source on RHEL/Rocky 9

#### 1. Install system dependencies

```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y \
    openssl-devel readline-devel zlib-devel libxml2-devel libxslt-devel \
    libicu-devel lz4-devel libzstd-devel \
    flex bison python3 python3-pip cmake ninja-build git pkg-config

# Install meson (RHEL 9 repos may have an older version)
pip3 install --user meson
export PATH="$HOME/.local/bin:$PATH"
```

#### 2. Build and install liboqs

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    ..
ninja
sudo ninja install
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/liboqs.conf
sudo ldconfig
```

#### 3. Build and install oqs-provider (OpenSSL < 3.5 only)

```bash
git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider && mkdir build && cd build
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -Dliboqs_DIR=/usr/local/lib/cmake/liboqs \
    ..
ninja
sudo ninja install
```

#### 4. Build FortressQL

```bash
cd /path/to/sql-pqc

meson setup build \
    -Dpqc=enabled \
    -Dssl=openssl \
    -Dcassert=true \
    --prefix=/usr/local/fortressql

meson compile -C build
sudo meson install -C build
sudo ldconfig
```

#### 5. SELinux configuration (if enforcing)

```bash
# Allow FortressQL to bind to non-standard ports if needed
sudo semanage port -a -t postgresql_port_t -p tcp 5432

# Allow access to PQC key files
sudo semanage fcontext -a -t postgresql_etc_t '/etc/fortressql(/.*)?'
sudo restorecon -Rv /etc/fortressql
```

#### 6. Firewall configuration

```bash
sudo firewall-cmd --permanent --add-port=5432/tcp
sudo firewall-cmd --reload
```

### Meson Build Options

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `-Dpqc` | `enabled`, `disabled`, `auto` | `auto` | Enable PQC support. `auto` detects liboqs at build time. |
| `-Dssl` | `openssl` | *(none)* | SSL library. Required for TLS features. |
| `-Dcassert` | `true`, `false` | `false` | Enable C assertion checks. Recommended for testing, not production. |
| `--prefix` | path | `/usr/local/pgsql` | Installation prefix. |
| `--buildtype` | `release`, `debug`, `debugoptimized` | `debugoptimized` | Build optimization level. Use `release` for production. |

### Running Tests

```bash
cd build

# Run PQC-specific tests
meson test --suite pqc --print-errorlogs

# Run core PostgreSQL regression tests
meson test --suite regress --print-errorlogs

# Run all tests
meson test --print-errorlogs
```

---

## Initial Configuration

### TDE (Transparent Data Encryption) Setup

TDE encrypts heap pages, indexes, and WAL at rest using ML-KEM-derived keys with AES-256-CTR.

#### Step 1: Initialize the master key

```bash
pg_tde_master_key init -D /var/lib/fortressql/data
```

This generates a master key and wraps it with ML-KEM. The wrapped key is stored in `$PGDATA/global/pg_tde_master.key`.

#### Step 2: Set the KEM secret key environment variable

The KEM secret key is used to unwrap the master key at server startup. Store this securely (for example, in a secrets manager or HSM).

```bash
export FORTRESSQL_KEM_SECRET_KEY=/etc/fortressql/kem_secret.key
```

Alternatively, use a wrapper script that retrieves the key from a vault and writes it to the path specified by `FORTRESSQL_KEM_SECRET_KEY`:

```bash
#!/bin/bash
# /usr/local/bin/fetch-kem-key.sh
vault read -field=key secret/fortressql/master > "$FORTRESSQL_KEM_SECRET_KEY"
chmod 600 "$FORTRESSQL_KEM_SECRET_KEY"
```

Run this script before starting the server (for example, in a systemd `ExecStartPre` directive).

#### Step 3: Enable TDE in postgresql.conf

```ini
tde_enabled = on
# The KEM algorithm defaults to ML-KEM-768 and is not currently a configurable GUC.
# It is set at master key initialization time by pg_tde_master_key init.
```

#### Step 4: Restart the server

```bash
sudo systemctl restart fortressql
```

#### Step 5: Verify TDE is active

Once the server starts with TDE enabled, all heap pages, indexes, and WAL are encrypted transparently. There is no separate `CREATE ENCRYPTION KEY` SQL command. Verify TDE status:

```sql
SELECT * FROM pg_stat_pqc WHERE tde_pages_encrypted > 0;
```

To create a tablespace whose data is stored in a separate directory (all tablespaces are encrypted when TDE is enabled):

```sql
CREATE TABLESPACE secure_data LOCATION '/data/secure';
CREATE TABLE sensitive_records (id int, data text) TABLESPACE secure_data;
```

### WAL Signing Setup

WAL signing ensures every completed WAL segment is digitally signed with ML-DSA. Standbys verify signatures before applying WAL, providing tamper detection across the replication chain.

#### Step 1: Generate WAL signing keys

```sql
SELECT pqc_rotate_wal_signing_keys();
```

This generates an ML-DSA keypair and stores it in the directory specified by `wal_pqc_key_path`. If `wal_pqc_key_path` is not yet set, set it first:

```bash
sudo mkdir -p /etc/fortressql/wal_keys
sudo chown postgres:postgres /etc/fortressql/wal_keys
sudo chmod 700 /etc/fortressql/wal_keys
```

#### Step 2: Configure WAL signing in postgresql.conf

```ini
wal_pqc_signing = on
wal_pqc_signing_algorithm = 'ML-DSA-65'   # ML-DSA-44, ML-DSA-65, or ML-DSA-87
wal_pqc_key_path = '/etc/fortressql/wal_keys'
wal_pqc_verify_on_receive = on             # verify on standbys
```

#### Step 3: Restart the server

```bash
sudo systemctl restart fortressql
```

WAL segments will now have `.sig` sidecar files alongside them. Standbys with `wal_pqc_verify_on_receive = on` will reject WAL that fails signature verification.

### PQC TLS Setup

PQC TLS adds quantum-resistant key exchange and certificate verification to all client-server and replication connections.

#### Step 1: Install oqs-provider (or use OpenSSL 3.5+)

See the [installation section](#building-from-source-on-ubuntu-2404) for oqs-provider build instructions. On OpenSSL 3.5+, PQC algorithms are available natively.

#### Step 2: Set PQC mode in postgresql.conf

```ini
ssl = on
ssl_pqc_mode = 'hybrid'     # 'hybrid' recommended; uses both classical + PQC
```

The `hybrid` mode is strongly recommended. It combines classical key exchange (X25519 or ECDH) with post-quantum key exchange (ML-KEM), so security is maintained even if one algorithm is broken.

#### Step 3: Generate ML-DSA certificates

```bash
# Generate CA key and certificate with ML-DSA-65
openssl genpkey -algorithm mldsa65 -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 \
    -subj "/CN=FortressQL CA"

# Generate server key and certificate
openssl genpkey -algorithm mldsa65 -out server.key
openssl req -new -key server.key -out server.csr \
    -subj "/CN=db.example.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 365

# Set permissions
chmod 600 server.key
chown postgres:postgres server.key server.crt ca.crt
```

#### Step 4: Configure TLS certificate paths

```ini
ssl_cert_file = '/etc/fortressql/server.crt'
ssl_key_file = '/etc/fortressql/server.key'
ssl_ca_file = '/etc/fortressql/ca.crt'
ssl_pqc_groups = 'X25519MLKEM768:X25519:prime256v1'
ssl_pqc_sigalgs = 'mldsa65:ed25519'
```

#### Step 5: Restart the server

```bash
sudo systemctl restart fortressql
```

#### Step 6: Test PQC TLS connection

```bash
psql "host=db.example.com sslmode=verify-full sslrootcert=ca.crt sslpqcgroups=X25519MLKEM768"
```

Verify the negotiated PQC group:

```sql
SELECT pid, ssl_version, ssl_cipher, pqc_group FROM pg_stat_ssl WHERE pid = pg_backend_pid();
```

---

## pg_hba.conf Configuration

### PQC Certificate Authentication

Requires clients to present certificates signed with a post-quantum algorithm (ML-DSA or SLH-DSA).

```
# TYPE    DATABASE    USER    ADDRESS         METHOD
hostssl   all         all     0.0.0.0/0       pqc-cert
hostssl   all         all     ::/0            pqc-cert
```

The server verifies that the client certificate's signature algorithm is a recognized PQC algorithm. Classical certificates (RSA, ECDSA) are rejected.

Client connection:

```bash
psql "host=db.example.com sslmode=verify-full \
      sslcert=client.crt sslkey=client.key sslrootcert=ca.crt \
      sslpqcgroups=X25519MLKEM768"
```

### PQC SCRAM-SHA-384 Authentication

SCRAM authentication using SHA-384 (48-byte keys), aligned with NIST Level 3 security.

```
# TYPE    DATABASE    USER    ADDRESS         METHOD
hostssl   all         all     10.0.0.0/8      pqc-scram-sha-384
```

Users must have their passwords stored with SHA-384-based SCRAM:

```sql
SET password_encryption = 'scram-sha-384';
CREATE ROLE analyst LOGIN PASSWORD 'strong-password-here';
```

### Combined PQC TLS + Authentication

For maximum security, combine PQC TLS transport with PQC authentication:

```
# Require PQC certificates for admin users
hostssl   all         admin_role    0.0.0.0/0   pqc-cert clientcert=verify-full

# Require PQC SCRAM for application users over PQC TLS
hostssl   appdb       app_role      10.0.0.0/8  pqc-scram-sha-384

# Allow classical SCRAM for legacy clients on internal network only
hostssl   all         all           192.168.0.0/16  scram-sha-256
```

With `ssl_pqc_mode = 'hybrid'`, even connections using `scram-sha-256` benefit from PQC key exchange at the TLS layer.

### Authentication Method Comparison

| Method | Password Stored | Hash Strength | PQC TLS Required |
|--------|----------------|---------------|-------------------|
| `scram-sha-256` | SCRAM verifier | SHA-256 (128-bit quantum) | No |
| `pqc-scram-sha-384` | SCRAM verifier | SHA-384 (192-bit quantum) | Yes (hostssl) |
| `pqc-cert` | N/A (certificate) | Depends on cert algorithm | Yes (hostssl) |

---

## postgresql.conf Reference

### Crypto Policy

| Parameter | Type | Default | Reload | Description |
|-----------|------|---------|--------|-------------|
| `crypto_policy` | enum | `custom` | Yes | Cryptographic policy profile. Sets a coordinated group of PQC parameters. |

Available `crypto_policy` values:

| Policy | `password_encryption` | `ssl_pqc_mode` | `ssl_pqc_groups` | `ssl_pqc_sigalgs` | Use Case |
|--------|-----------------------|----------------|------------------|--------------------|----|
| `legacy` | `scram-sha-256` | `off` | *(classical only)* | *(empty)* | Backward compatibility, no PQC |
| `transitional` | `scram-sha-256` | `hybrid` | `X25519MLKEM768:X25519:prime256v1` | *(empty)* | Migration period, PQC optional |
| `fips-pqc-level3` | `scram-sha-384` | `hybrid` | `X25519MLKEM768:X25519:prime256v1` | `mldsa65:mldsa87` | NIST Level 3 compliance |
| `fips-pqc-level5` | `scram-sha-384` | `hybrid` | `MLKEM1024:X25519MLKEM768` | `mldsa87` | NIST Level 5 compliance |
| `custom` | *(manual)* | *(manual)* | *(manual)* | *(manual)* | Fine-grained control |

**Recommended:** Start with `transitional` and progress to `fips-pqc-level3` once all clients support PQC.

### PQC TLS

| Parameter | Type | Default | Reload | Description |
|-----------|------|---------|--------|-------------|
| `ssl_pqc_mode` | enum | `hybrid` | Yes | PQC mode for TLS. `off` = classical only, `hybrid` = classical + PQC, `pqc-only` = PQC only (rejects classical clients). |
| `ssl_pqc_groups` | string | `X25519MLKEM768:X25519:prime256v1` | Yes | Colon-separated list of key exchange groups in preference order. |
| `ssl_pqc_sigalgs` | string | *(empty)* | Yes | Colon-separated list of TLS signature algorithms. Empty = accept defaults from OpenSSL. |

**Recommended values for production:**

```ini
ssl_pqc_mode = 'hybrid'
ssl_pqc_groups = 'X25519MLKEM768:X25519:prime256v1'
ssl_pqc_sigalgs = 'mldsa65:ed25519'
```

### Transparent Data Encryption

| Parameter | Type | Default | Reload | Description |
|-----------|------|---------|--------|-------------|
| `tde_enabled` | bool | `off` | No (restart) | Enable transparent data encryption for heap, index, and WAL pages. |

The master key is unwrapped at server startup using the KEM secret key referenced by the `FORTRESSQL_KEM_SECRET_KEY` environment variable (set to the file path of the KEM secret key). There is no GUC for this -- it must be set in the server environment before startup.

The KEM algorithm defaults to ML-KEM-768 and is determined at master key initialization time (`pg_tde_master_key init`). It is not currently a configurable GUC.

**Recommended values for production:**

```ini
tde_enabled = on
```

Set `FORTRESSQL_KEM_SECRET_KEY` in your systemd unit or startup script:

```ini
# /etc/systemd/system/fortressql.service.d/tde.conf
[Service]
Environment="FORTRESSQL_KEM_SECRET_KEY=/etc/fortressql/kem_secret.key"
```

### WAL Signing

| Parameter | Type | Default | Reload | Description |
|-----------|------|---------|--------|-------------|
| `wal_pqc_signing` | bool | `off` | No (restart) | Enable ML-DSA signing of completed WAL segments. |
| `wal_pqc_signing_algorithm` | string | `ML-DSA-65` | No (restart) | Signature algorithm. Options: `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`. |
| `wal_pqc_key_path` | string | *(empty)* | No (restart) | Directory containing WAL signing keypair (`wal_sign.key`, `wal_sign.pub`). |
| `wal_pqc_verify_on_receive` | bool | `on` | Yes | Verify PQC signatures on WAL segments received by standbys. |

**Recommended values for production:**

```ini
wal_pqc_signing = on
wal_pqc_signing_algorithm = 'ML-DSA-65'
wal_pqc_key_path = '/etc/fortressql/wal_keys'
wal_pqc_verify_on_receive = on
```

### Hybrid Proof Logging (Audit)

| Parameter | Type | Default | Reload | Description |
|-----------|------|---------|--------|-------------|
| `pqc_audit.enabled` | bool | `off` | Yes | Enable hybrid proof audit logging with dual signatures and hash chains. |
| `pqc_audit.events` | string | `ddl,auth,policy,grant` | Yes | Comma-separated list of event categories to audit. |

Available event categories: `ddl`, `auth`, `policy`, `grant`, `dml`, `system`, `all`.

### Authentication

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password_encryption` | enum | `scram-sha-256` | Hash method for `CREATE ROLE ... PASSWORD`. Add `scram-sha-384` for NIST Level 3. |

---

## Key Management

### Master Key Initialization and Rotation

The TDE master key is the root of the encryption hierarchy. It wraps tablespace data encryption keys (DEKs).

**Initialize:**

```bash
pg_tde_master_key init -D /var/lib/fortressql/data
```

**Rotate the master key** (re-wraps all DEKs with a new master key; does not re-encrypt data pages):

```sql
SELECT pqc_rotate_tde_master_key();
```

This operation:
1. Generates a new ML-KEM keypair
2. Decrypts all tablespace DEKs with the old master key
3. Re-encrypts all tablespace DEKs with the new master key
4. Atomically replaces `$PGDATA/global/pg_tde_master.key`

**Recommended rotation schedule:** Every 90 days, or immediately if compromise is suspected.

### WAL Signing Key Rotation

```sql
SELECT pqc_rotate_wal_signing_keys();
```

This generates a new ML-DSA keypair in `wal_pqc_key_path`. The old key remains available for verification of previously signed WAL segments. A server restart is required after rotation.

**Recommended rotation schedule:** Every 30 days for high-security environments.

**Distribute keys to standbys:** After rotation, copy the new public key to all standby servers:

```bash
scp /etc/fortressql/wal_keys/wal_sign.pub standby:/etc/fortressql/wal_keys/
```

### Backup Key Escrow (Shamir's Secret Sharing)

For disaster recovery, the master key can be split into shares using Shamir's Secret Sharing:

```sql
-- Split master key into 5 shares, requiring 3 to reconstruct
SELECT * FROM pqc_escrow_create(
    key_id := 'master',
    total_shares := 5,
    threshold := 3
);
```

Each share should be stored by a different key custodian in a physically separate location (for example, sealed envelopes in different safes, or separate HSM partitions).

**Reconstruct the key:**

```sql
SELECT pqc_escrow_recover(
    shares := ARRAY['share1_hex', 'share2_hex', 'share3_hex']
);
```

### Key Recovery Procedures

If the master key is lost or corrupted:

1. **From escrow shares:** Gather the required threshold of shares and use `pqc_escrow_recover()`.

2. **From backup:** If you backed up `$PGDATA/global/pg_tde_master.key` along with the KEM secret key, restore both files.

3. **Last resort:** If neither escrow shares nor backups are available, encrypted data cannot be recovered. This is by design -- there is no backdoor.

**Prevention checklist:**
- Always create escrow shares before going to production
- Store the KEM secret key in at least two independent locations
- Include `$PGDATA/global/pg_tde_master.key` in your backup procedures
- Test key recovery procedures quarterly

### Upgrading with pg_upgrade

When upgrading between FortressQL major versions, `pg_upgrade` handles TDE key migration automatically:

```bash
pg_upgrade \
    -b /usr/local/fortressql-old/bin \
    -B /usr/local/fortressql-new/bin \
    -d /var/lib/fortressql/data-old \
    -D /var/lib/fortressql/data-new
```

**Key points:**

- **Automatic TDE key migration.** `pg_upgrade` detects the TDE master key in the old data directory and copies it to the new data directory. No manual key copying is needed.
- **KEM secret key must be accessible.** Ensure `FORTRESSQL_KEM_SECRET_KEY` is set in the environment when running `pg_upgrade`, as it needs to verify the master key can be unwrapped.
- **Migration validation.** `pg_upgrade` validates the TDE key migration by performing a test decryption of a sample page from the old cluster. If validation fails, the upgrade is aborted and no data is modified.
- **WAL signing keys** are also migrated automatically if `wal_pqc_signing` was enabled in the old cluster.

---

## Backup and Restore

### Encrypted and Signed Backups with pg_dump

```bash
# Generate backup encryption and signing keys
openssl genpkey -algorithm mldsa65 -out signer.key
openssl pkey -in signer.key -pubout -out signer.pub

# The recipient's ML-KEM keys (generated earlier or via pqc_kem_keygen)
# recipient.pub = ML-KEM public key
# recipient.key = ML-KEM secret key

# Create an encrypted + signed backup
pg_dump \
    --pqc-encrypt \
    --pqc-encrypt-key=recipient.pub \
    --pqc-encrypt-algorithm=ML-KEM-768 \
    --pqc-sign \
    --pqc-sign-key=signer.key \
    --pqc-sign-algorithm=ML-DSA-65 \
    mydb > backup.dump
```

### Restore with Decryption and Verification

```bash
pg_restore \
    --pqc-decrypt-key=recipient.key \
    --pqc-verify-key=signer.pub \
    -d mydb \
    backup.dump
```

If signature verification fails, `pg_restore` exits with an error and does not apply any data. This protects against tampered backups.

### Key Management for Encrypted Backups

**Best practices:**

1. **Separate backup keys from server keys.** Generate dedicated ML-KEM keypairs for backup encryption. Do not reuse the TDE master key.

2. **Rotate backup keys independently.** Generate new keypairs periodically. Old secret keys must be retained as long as any backup encrypted with the corresponding public key exists.

3. **Store secret keys separately from backups.** Never store `recipient.key` alongside the encrypted backup.

4. **Label backups with key identifiers.** Include the public key fingerprint in the backup filename or metadata so you know which secret key to use for restore.

5. **Test restores regularly.** Verify that you can decrypt and restore from your oldest retained backup.

### Backup Without Encryption

Standard `pg_dump` without PQC flags works identically to vanilla PostgreSQL:

```bash
pg_dump mydb > backup.sql
```

### Physical Backups with pg_basebackup

When TDE is enabled, `pg_basebackup` supports the `--tde-key-handling` option to control how TDE keys are included in the backup:

```bash
pg_basebackup -D /backups/base -Fp -Xs --tde-key-handling=include
```

**Available modes:**

| Mode | Description | Use Case |
|------|-------------|----------|
| `include` | Copies the TDE master key file into the backup. The backup can be restored and started directly. | Standbys, fast disaster recovery where the backup storage is trusted. |
| `exclude` | Omits the TDE master key file. The backup cannot be started without manually providing the key. | Offsite or cloud backups where key and data should be stored separately. |
| `verify-only` | Validates that TDE keys are consistent but does not include them in the backup. | Audit and verification workflows; confirms data pages can be decrypted before backup completes. |

**Security implications:**

- **`include` mode** means anyone with access to the backup and the KEM secret key can read all data. Only use this when the backup destination has the same security posture as the primary server.
- **`exclude` mode** provides defense in depth: a stolen backup is useless without the master key. You must ensure the master key file (`$PGDATA/global/pg_tde_master.key`) and the KEM secret key are available when restoring. Store them separately from the backup.
- **`verify-only` mode** is useful for scheduled integrity checks. It confirms the backup process can read all encrypted pages without actually transferring key material.

**Example: secure offsite backup**

```bash
# Take a backup without keys
pg_basebackup -D /backups/base -Fp -Xs --tde-key-handling=exclude

# Separately back up the master key to a different secure location
cp /var/lib/fortressql/data/global/pg_tde_master.key /secure-key-storage/
```

---

## Monitoring

### pg_stat_pqc View

The `pg_stat_pqc` view provides aggregate statistics about PQC operations.

| Column | Type | Description |
|--------|------|-------------|
| `tde_pages_encrypted` | bigint | Total pages encrypted since server start |
| `tde_pages_decrypted` | bigint | Total pages decrypted since server start |
| `tde_encryption_errors` | bigint | TDE encryption failures |
| `tde_decryption_errors` | bigint | TDE decryption failures (possible corruption) |
| `wal_segments_signed` | bigint | WAL segments signed since server start |
| `wal_signatures_verified` | bigint | WAL signatures verified on receive |
| `wal_signature_failures` | bigint | WAL signature verification failures |
| `pqc_tls_handshakes` | bigint | TLS handshakes using PQC key exchange |
| `classical_tls_handshakes` | bigint | TLS handshakes using classical key exchange only |
| `kem_operations` | bigint | Total KEM encapsulate/decapsulate operations |
| `sig_operations` | bigint | Total sign/verify operations |
| `pqc_auth_successes` | bigint | Successful PQC authentications |
| `pqc_auth_failures` | bigint | Failed PQC authentications |

```sql
SELECT * FROM pg_stat_pqc;
```

### pg_pqc_compliance_status View

Reports whether the current configuration meets various compliance targets.

| Column | Type | Description |
|--------|------|-------------|
| `check_name` | text | Name of the compliance check |
| `status` | text | `pass`, `fail`, or `warning` |
| `current_value` | text | Current setting value |
| `required_value` | text | Required value for compliance |
| `policy` | text | Which policy requires this check |
| `detail` | text | Human-readable explanation |

```sql
SELECT * FROM pg_pqc_compliance_status;

-- Filter for failures only
SELECT * FROM pg_pqc_compliance_status WHERE status = 'fail';
```

### What to Alert On

Configure monitoring alerts for these conditions:

| Metric | Threshold | Severity | Action |
|--------|-----------|----------|--------|
| `tde_decryption_errors > 0` | Any non-zero | Critical | Possible data corruption or key mismatch. Stop writes, investigate immediately. |
| `wal_signature_failures > 0` | Any non-zero | Critical | Possible WAL tampering. Investigate replication chain and network. |
| `pqc_auth_failures` | Rapid increase | Warning | Possible brute-force attack. Check client IP addresses. |
| `classical_tls_handshakes > 0` | Any (in pqc-only mode) | Warning | Clients connecting without PQC. Review `ssl_pqc_mode` and client configuration. |
| `pg_pqc_compliance_status` has `fail` | Any | Warning | Configuration drift from target policy. Review and remediate. |

**Example Prometheus alert rule:**

```yaml
groups:
  - name: fortressql_pqc
    rules:
      - alert: TDEDecryptionErrors
        expr: pg_stat_pqc_tde_decryption_errors > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "TDE decryption errors detected on {{ $labels.instance }}"

      - alert: WALSignatureFailure
        expr: pg_stat_pqc_wal_signature_failures > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "WAL signature verification failure on {{ $labels.instance }}"
```

---

## Troubleshooting

### Common Errors and Solutions

#### "PQC support not available: liboqs not found"

**Cause:** FortressQL was compiled without PQC support, or liboqs is not installed.

**Solution:**
```bash
# Verify liboqs is installed
ldconfig -p | grep liboqs

# If missing, install liboqs and rebuild
# See the Installation section

# Verify FortressQL was built with PQC
pg_config --configure | grep pqc
```

#### "oqs-provider not available"

**Cause:** oqs-provider is not installed or not configured in OpenSSL.

**Solution:**
```bash
# Check if oqs-provider is loadable
openssl list -providers -provider oqsprovider

# If not found, verify the provider is in OpenSSL's provider path
openssl version -d
ls $(openssl version -d | cut -d'"' -f2)/oqsprovider.*
```

#### "crypto_policy conflict: cannot set ssl_pqc_mode when crypto_policy is not 'custom'"

**Cause:** You are trying to set individual PQC parameters while `crypto_policy` is set to a named profile.

**Solution:** Either set `crypto_policy = 'custom'` to manage parameters individually, or change the policy level rather than individual parameters.

### TDE Page Decryption Failures

**Symptoms:**
- ERROR messages containing "could not decrypt page" or "TDE decryption failed"
- `tde_decryption_errors` counter incrementing in `pg_stat_pqc`

**Diagnostic steps:**

1. **Verify the master key is accessible:**
   ```bash
   # Check that the KEM secret key file exists and is readable
   ls -la "$FORTRESSQL_KEM_SECRET_KEY"
   ```

2. **Check for key mismatch:** If the database was restored from a backup made with a different master key, the current key will not decrypt the pages.
   ```sql
   SELECT * FROM pg_stat_pqc WHERE tde_decryption_errors > 0;
   ```

3. **Check for page corruption:** Run a checksum verification:
   ```bash
   pg_checksums --check -D /var/lib/fortressql/data
   ```

4. **Recovery:** If the master key was rotated but the old key is needed:
   - Restore the old `pg_tde_master.key` file from backup
   - Set `FORTRESSQL_KEM_SECRET_KEY` to the old KEM secret key
   - Restart the server
   - Rotate to a new master key once data is accessible

### WAL Signature Verification Failures

**Symptoms:**
- Standby logs: "WAL signature verification failed for segment XXXX"
- `wal_signature_failures` counter incrementing in `pg_stat_pqc`
- Replication stalls

**Diagnostic steps:**

1. **Check key synchronization:** Verify the standby has the current WAL signing public key:
   ```bash
   md5sum /etc/fortressql/wal_keys/wal_sign.pub  # on primary
   md5sum /etc/fortressql/wal_keys/wal_sign.pub  # on standby
   ```

2. **Check for key rotation timing:** If keys were recently rotated on the primary, the standby may be receiving WAL signed with the new key while still holding the old public key.

3. **Check for network corruption:** Compare WAL segment checksums between primary and standby.

4. **Temporary workaround** (use with caution):
   ```ini
   # On standby -- disables verification, NOT recommended for production
   wal_pqc_verify_on_receive = off
   ```
   Re-enable verification after resolving the key synchronization issue.

### PQC TLS Negotiation Issues

**Symptoms:**
- Client connection errors: "SSL error: no shared cipher" or "no suitable key exchange"
- `classical_tls_handshakes` incrementing when expecting PQC

**Diagnostic steps:**

1. **Check client support:** Verify the client's OpenSSL supports PQC:
   ```bash
   openssl list -kem-algorithms 2>/dev/null | grep -i mlkem
   ```

2. **Check group negotiation:** Connect with verbose SSL logging:
   ```bash
   psql "host=db.example.com sslmode=require sslpqcgroups=X25519MLKEM768" 2>&1 | grep -i pqc
   ```

3. **Check server configuration:**
   ```sql
   SHOW ssl_pqc_mode;
   SHOW ssl_pqc_groups;
   ```

4. **Test with classical fallback:** If `ssl_pqc_mode = 'pqc-only'`, clients without PQC support cannot connect. Switch to `hybrid` to allow fallback:
   ```sql
   ALTER SYSTEM SET ssl_pqc_mode = 'hybrid';
   SELECT pg_reload_conf();
   ```

### Slow TLS Handshakes

**Cause:** PQC key exchange and signature verification are computationally more expensive than classical algorithms. ML-KEM-1024 and ML-DSA-87 have the highest overhead.

**Solutions:**
- Use `ML-KEM-768` and `ML-DSA-65` (NIST Level 3) instead of Level 5 variants unless required by policy
- Enable TLS session resumption on clients to avoid repeated handshakes
- Use connection pooling (for example, PgBouncer) to reduce handshake frequency

### Audit Chain Verification Failures

```sql
SELECT * FROM pqc_audit_verify_chain();
```

If the chain verification reports gaps or invalid signatures:

1. Check whether the server experienced an unclean shutdown (crash recovery may skip audit entries)
2. Check disk integrity for the audit log files
3. A broken chain does not necessarily indicate tampering -- it may indicate an operational issue -- but it should be investigated and documented
