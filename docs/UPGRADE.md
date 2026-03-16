# FortressQL Upgrade Guide

This document covers upgrading from PostgreSQL 17 to FortressQL, upgrading between
FortressQL releases, and enabling post-quantum cryptographic features on existing
clusters.

---

## Table of Contents

1. [Upgrading from PostgreSQL 17 to FortressQL](#upgrading-from-postgresql-17-to-fortressql)
2. [Upgrading Between FortressQL Versions](#upgrading-between-fortressql-versions)
3. [pg_upgrade Compatibility](#pg_upgrade-compatibility)
4. [Enabling PQC Features on an Existing Cluster](#enabling-pqc-features-on-an-existing-cluster)
5. [TDE Enablement](#tde-enablement)
6. [PQC TLS Migration](#pqc-tls-migration)
7. [WAL Signing Enablement](#wal-signing-enablement)
8. [Rollback Procedures](#rollback-procedures)

---

## Upgrading from PostgreSQL 17 to FortressQL

FortressQL is a source-compatible fork of PostgreSQL 17. The on-disk format is
identical when PQC features are disabled, so upgrading follows the standard
PostgreSQL major-version upgrade process.

### Prerequisites

- FortressQL binaries built and installed (see the
  [Administrator's Guide](../doc/fortressql-admin-guide.md))
- liboqs installed on the target system
- A full backup of the existing PostgreSQL cluster

### In-Place Binary Upgrade

If you are running PostgreSQL 17 at the exact base version that FortressQL
tracks, you can replace the binaries directly:

```bash
# 1. Stop the existing PostgreSQL cluster
pg_ctl -D /var/lib/postgresql/17/main stop

# 2. Install FortressQL binaries (overwrites pg binaries in prefix)
cd /path/to/sql-pqc
meson setup build -Dpqc=enabled -Dssl=openssl --prefix=/usr/local/fortressql
meson compile -C build
sudo meson install -C build
sudo ldconfig

# 3. Start with FortressQL binaries
/usr/local/fortressql/bin/pg_ctl -D /var/lib/postgresql/17/main start
```

At this point the cluster runs as vanilla PostgreSQL 17 with PQC capabilities
available but not yet enabled. No data migration is needed.

### Using pg_upgrade

For clusters where a clean data directory is preferred:

```bash
# 1. Initialize a new FortressQL data directory
/usr/local/fortressql/bin/initdb -D /var/lib/fortressql/data

# 2. Run pg_upgrade
/usr/local/fortressql/bin/pg_upgrade \
    -b /usr/lib/postgresql/17/bin \
    -B /usr/local/fortressql/bin \
    -d /var/lib/postgresql/17/main \
    -D /var/lib/fortressql/data
```

After upgrade, enable PQC features incrementally as described in the sections
below.

---

## Upgrading Between FortressQL Versions

### Minor Version Upgrades

Minor releases (e.g., 0.2.0 to 0.2.1) are binary-compatible. Replace the
binaries and restart:

```bash
pg_ctl -D /var/lib/fortressql/data stop
# Install new FortressQL binaries
meson compile -C build && sudo meson install -C build
pg_ctl -D /var/lib/fortressql/data start
```

If the release includes extension updates, run after restart:

```sql
ALTER EXTENSION pgcrypto_pqc UPDATE;
```

### Major Version Upgrades

Major version upgrades follow the same `pg_upgrade` process described above.
TDE encryption keys are migrated automatically (see
[pg_upgrade Compatibility](#pg_upgrade-compatibility)).

---

## pg_upgrade Compatibility

FortressQL's `pg_upgrade` is fully compatible with both vanilla PostgreSQL 17 and
previous FortressQL releases. It includes additional logic for TDE-enabled
clusters:

- **TDE key migration** -- `pg_upgrade` detects `master.key` and `master.pub` in
  the old data directory and copies them to the new data directory with
  restrictive permissions (`0600`) and `fsync` for durability.
- **No manual key copying required** -- the upgrade process validates that master
  key files were successfully transferred.
- **Tablespace key re-wrapping** is not performed during upgrade; existing
  wrapped keys remain valid.

```bash
# Standard pg_upgrade with TDE -- no extra flags needed
pg_upgrade \
    -b /old/fortressql/bin \
    -B /new/fortressql/bin \
    -d /old/data \
    -D /new/data
```

Verify key presence after upgrade:

```bash
ls -la /new/data/master.key /new/data/master.pub
```

---

## Enabling PQC Features on an Existing Cluster

PQC features can be enabled independently and incrementally. There is no
requirement to enable all features at once. The recommended order is:

1. **PQC TLS** -- protects data in transit immediately
2. **WAL Signing** -- adds tamper detection to replication
3. **TDE** -- encrypts data at rest (requires key infrastructure)

Each feature is controlled by GUC parameters in `postgresql.conf` and can be
enabled with a configuration reload or restart as noted below.

---

## TDE Enablement

Enabling Transparent Data Encryption requires a server restart. Plan a
maintenance window.

### Step 1: Generate the ML-KEM Master Key

```bash
# Generate the ML-KEM keypair for the master key
export FORTRESSQL_KEM_SECRET_KEY=/etc/fortressql/kem_secret.key

pg_tde_master_key init \
    --algorithm=ML-KEM-768 \
    --data-dir=/var/lib/fortressql/data
```

This creates two files in the data directory:
- `master.key` -- the ML-KEM public key (used to wrap tablespace keys)
- `master.pub` -- public component

And the secret key at the path specified by `FORTRESSQL_KEM_SECRET_KEY`.

### Step 2: Secure the Secret Key

```bash
# Set restrictive permissions
chmod 0400 /etc/fortressql/kem_secret.key
chown postgres:postgres /etc/fortressql/kem_secret.key
```

Store a backup of the secret key in a secure, offline location. Without this
key, encrypted data cannot be recovered. See
[BACKUP_RESTORE.md](BACKUP_RESTORE.md) for key backup procedures.

### Step 3: Enable TDE

Add to `postgresql.conf`:

```
tde_enabled = on
```

Set the environment variable before starting the server:

```bash
export FORTRESSQL_KEM_SECRET_KEY=/etc/fortressql/kem_secret.key
pg_ctl -D /var/lib/fortressql/data restart
```

### Step 4: Create Encrypted Tablespaces

```sql
CREATE ENCRYPTION KEY production_key ALGORITHM 'ML-KEM-768';
CREATE TABLESPACE encrypted_ts LOCATION '/data/encrypted' ENCRYPTION KEY production_key;

-- Move existing tables to encrypted storage
ALTER TABLE sensitive_data SET TABLESPACE encrypted_ts;
```

Existing data is re-written encrypted when moved to the encrypted tablespace.
The original tablespace retains unencrypted data until vacuumed.

---

## PQC TLS Migration

PQC TLS can be enabled without a server restart via `pg_reload_conf()`. The
recommended migration path is a phased transition:

### Phase 1: Hybrid Mode (Recommended Starting Point)

Hybrid mode uses both classical and post-quantum key exchange. All existing
clients continue to work; PQC-capable clients negotiate quantum-resistant
sessions.

```
# postgresql.conf
ssl_pqc_mode = 'hybrid'
ssl_pqc_groups = 'X25519MLKEM768:X25519:prime256v1'
```

```sql
SELECT pg_reload_conf();
```

Verify with:

```sql
SELECT pid, ssl_version, ssl_cipher, pqc_group FROM pg_stat_ssl;
```

### Phase 2: Audit Client Compatibility

Before moving to PQC-only, verify that all clients can negotiate PQC key
exchange:

```sql
-- Identify connections not using PQC
SELECT pid, client_addr, pqc_group
FROM pg_stat_ssl
WHERE pqc_group IS NULL AND ssl IS TRUE;
```

Update client connection strings to request PQC:

```
psql "host=db sslmode=require sslpqcgroups=X25519MLKEM768"
```

### Phase 3: PQC-Only Mode

Once all clients support PQC key exchange:

```
# postgresql.conf
ssl_pqc_mode = 'pqc-only'
ssl_pqc_groups = 'X25519MLKEM768'
ssl_pqc_sigalgs = 'mldsa65'
```

```sql
SELECT pg_reload_conf();
```

Clients that cannot negotiate PQC key exchange will be rejected.

### Rollback

To revert to hybrid mode at any time:

```
ssl_pqc_mode = 'hybrid'
```

```sql
SELECT pg_reload_conf();
```

---

## WAL Signing Enablement

WAL signing requires a server restart.

### Step 1: Generate Signing Keys

```bash
# Generate ML-DSA keypair for WAL signing
mkdir -p /etc/fortressql/wal_keys

pg_tde_master_key gensig \
    --algorithm=ML-DSA-65 \
    --output=/etc/fortressql/wal_keys

chmod 0400 /etc/fortressql/wal_keys/*
chown postgres:postgres /etc/fortressql/wal_keys/*
```

### Step 2: Configure WAL Signing

Add to `postgresql.conf`:

```
wal_pqc_signing = on
wal_pqc_signing_algorithm = 'ML-DSA-65'
wal_pqc_key_path = '/etc/fortressql/wal_keys'
```

Restart the server:

```bash
pg_ctl -D /var/lib/fortressql/data restart
```

### Step 3: Configure Standbys for Verification

On each standby, add:

```
wal_pqc_verify_on_receive = on
wal_pqc_key_path = '/etc/fortressql/wal_keys'
```

Copy the **public key only** to standbys. The secret signing key should remain
on the primary.

### Step 4: Verify

Completed WAL segments will have `.sig` sidecar files:

```bash
ls /var/lib/fortressql/data/pg_wal/*.sig
```

---

## Rollback Procedures

### Reverting PQC TLS

PQC TLS can be disabled without a restart:

```
ssl_pqc_mode = 'off'
```

```sql
SELECT pg_reload_conf();
```

Existing connections retain their negotiated parameters until they disconnect.

### Reverting WAL Signing

1. Set `wal_pqc_signing = off` in `postgresql.conf`.
2. Restart the server.
3. Unsigned WAL segments are produced immediately.
4. Standbys will accept unsigned WAL regardless of `wal_pqc_verify_on_receive`
   when the incoming segment has no signature.

### Reverting TDE

TDE cannot be disabled in place for data that has already been written to
encrypted tablespaces. To remove TDE:

1. Move all tables out of encrypted tablespaces to unencrypted ones:

   ```sql
   ALTER TABLE sensitive_data SET TABLESPACE pg_default;
   ```

2. Drop the encrypted tablespace and encryption keys:

   ```sql
   DROP TABLESPACE encrypted_ts;
   DROP ENCRYPTION KEY production_key;
   ```

3. Set `tde_enabled = off` in `postgresql.conf` and restart.

Data that was written to encrypted tablespaces is decrypted when moved to an
unencrypted tablespace. WAL records written while TDE was enabled remain
encrypted in the WAL archive.

### Full Rollback to PostgreSQL 17

If you need to revert entirely to vanilla PostgreSQL 17:

1. Ensure no encrypted tablespaces remain (move all data to `pg_default`).
2. Disable all PQC features (`ssl_pqc_mode = 'off'`, `wal_pqc_signing = off`,
   `tde_enabled = off`).
3. Stop the server.
4. Replace FortressQL binaries with PostgreSQL 17 binaries.
5. Remove PQC-specific GUC entries from `postgresql.conf` (PostgreSQL will
   report errors for unknown parameters).
6. Start with PostgreSQL 17 binaries.

Alternatively, use `pg_dump` / `pg_restore` to migrate to a clean PostgreSQL 17
cluster.
