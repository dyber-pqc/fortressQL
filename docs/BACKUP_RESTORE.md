# FortressQL Backup and Restore

This document covers backup and restore procedures for FortressQL clusters,
with particular attention to Transparent Data Encryption (TDE), WAL signing,
and PQC-encrypted backups.

---

## Table of Contents

1. [Overview](#overview)
2. [Logical Backups (pg_dump / pg_restore)](#logical-backups-pg_dump--pg_restore)
3. [Physical Backups (pg_basebackup)](#physical-backups-pg_basebackup)
4. [Key Backup Procedures](#key-backup-procedures)
5. [Point-in-Time Recovery with TDE](#point-in-time-recovery-with-tde)
6. [WAL Archiving with Signed WAL](#wal-archiving-with-signed-wal)
7. [Key Rotation During Backup Windows](#key-rotation-during-backup-windows)
8. [Disaster Recovery Checklist](#disaster-recovery-checklist)

---

## Overview

FortressQL's encryption architecture affects backup and restore in two ways:

- **TDE encrypts data at rest.** Physical backups contain encrypted files.
  Logical backups (pg_dump) export decrypted data.
- **PQC-encrypted backups** add an additional encryption layer using ML-KEM,
  independent of TDE. This protects backup files stored in untrusted locations.

These are orthogonal features. You can use either, both, or neither.

---

## Logical Backups (pg_dump / pg_restore)

### Standard pg_dump

`pg_dump` connects to the running server and reads data through the normal SQL
interface. TDE decryption is handled transparently by the server -- the dump
output contains **plaintext data**.

```bash
pg_dump -Fc mydb > mydb.dump
pg_restore -d mydb_restored mydb.dump
```

No special flags or key material are needed for TDE-enabled clusters.

### PQC-Encrypted Backups

To protect dump files at rest, use the `--pqc-encrypt` and `--pqc-sign` flags:

```bash
# Create an encrypted and signed backup
pg_dump -Fc --pqc-encrypt --pqc-encrypt-key=/keys/recipient.pub \
        --pqc-sign --pqc-sign-key=/keys/signer.key \
        mydb > mydb.dump.pqc

# Restore with decryption and signature verification
pg_restore --pqc-decrypt-key=/keys/recipient.key \
           --pqc-verify-key=/keys/signer.pub \
           -d mydb_restored mydb.dump.pqc
```

The backup is encrypted to the recipient's ML-KEM public key and signed with
the signer's ML-DSA secret key. The recipient needs their ML-KEM secret key to
decrypt. The verifier needs the signer's ML-DSA public key to confirm
authenticity.

**Key points:**

- PQC encryption uses ML-KEM-768 by default (override with
  `--pqc-encrypt-algorithm`).
- PQC signing uses ML-DSA-65 by default (override with
  `--pqc-sign-algorithm`).
- Encryption and signing are independent -- you can use either or both.
- The recipient and signer can be different entities.

---

## Physical Backups (pg_basebackup)

### How TDE Affects Physical Backups

`pg_basebackup` copies the raw data directory files. When TDE is enabled, the
copied files **remain encrypted**. To restore from a physical backup, you need
the same master key that was used when the backup was taken.

### Standard Physical Backup

```bash
# Include TDE keys in backup (default behavior)
pg_basebackup -D /backup/base -Fp -Xs -P \
    --tde-key-handling=include
```

This copies `master.key` and `master.pub` into the backup. The backup is
self-contained -- it can be restored with only the KEM secret key.

### Excluding Keys from Backup

For backup storage locations with lower security guarantees:

```bash
pg_basebackup -D /backup/base -Fp -Xs -P \
    --tde-key-handling=exclude
```

When restoring a backup taken with `--tde-key-handling=exclude`, you must
manually place `master.key` and `master.pub` into the data directory before
starting the server.

### Verifying Key Presence

```bash
pg_basebackup -D /backup/base -Fp -Xs -P \
    --tde-key-handling=verify-only
```

This mode checks that key files are present in the source cluster but does not
copy them into the backup.

### Restoring a Physical Backup

```bash
# 1. Copy the backup to the target location
cp -a /backup/base /var/lib/fortressql/data

# 2. Ensure the KEM secret key is available
export FORTRESSQL_KEM_SECRET_KEY=/etc/fortressql/kem_secret.key

# 3. Set ownership and permissions
chown -R postgres:postgres /var/lib/fortressql/data
chmod 0700 /var/lib/fortressql/data

# 4. Start the server
pg_ctl -D /var/lib/fortressql/data start
```

If the backup was taken with `--tde-key-handling=exclude`, copy the master key
files before starting:

```bash
cp /secure-storage/master.key /var/lib/fortressql/data/master.key
cp /secure-storage/master.pub /var/lib/fortressql/data/master.pub
chmod 0600 /var/lib/fortressql/data/master.key
chmod 0600 /var/lib/fortressql/data/master.pub
```

---

## Key Backup Procedures

Key material loss is **unrecoverable**. If the KEM secret key is lost, all data
encrypted with TDE is permanently inaccessible. Key backup is the single most
critical operational procedure for TDE-enabled clusters.

### What to Back Up

| File | Location | Purpose | Criticality |
|------|----------|---------|-------------|
| KEM secret key | `FORTRESSQL_KEM_SECRET_KEY` path | Decrypts tablespace keys | **CRITICAL** -- loss means permanent data loss |
| `master.key` | `$PGDATA/master.key` | ML-KEM public key (wraps tablespace keys) | High -- can be regenerated from secret key |
| `master.pub` | `$PGDATA/master.pub` | Public component | High -- can be regenerated from secret key |
| WAL signing keys | `wal_pqc_key_path` directory | Signs/verifies WAL segments | Medium -- loss prevents WAL verification, not data access |
| PQC backup keys | Operator-managed | Encrypts/signs pg_dump output | Medium -- loss prevents decryption of PQC-encrypted backups |

### KEM Secret Key Backup Procedure

```bash
# 1. Create an encrypted copy for offline storage
cp /etc/fortressql/kem_secret.key /secure-media/kem_secret.key.bak
chmod 0400 /secure-media/kem_secret.key.bak

# 2. Verify the copy
sha384sum /etc/fortressql/kem_secret.key
sha384sum /secure-media/kem_secret.key.bak
# Both hashes must match.

# 3. Store the backup offline
# Transfer to a hardware security module, encrypted USB drive, or
# air-gapped secure storage. Follow your organization's key management
# policy.
```

### Key Backup Rules

1. **Never store the KEM secret key in the same location as the database
   backup.** If both are compromised, TDE provides no protection.
2. **Never store the KEM secret key in the data directory.** The data directory
   is included in physical backups by default.
3. **Test key restoration regularly.** Restore a physical backup to a test
   server using the backed-up key to verify recoverability.
4. **Maintain at least two geographically separated copies** of the KEM secret
   key.
5. **Document the key custodian chain.** Record who has access to key backups
   and when keys were last verified.

---

## Point-in-Time Recovery with TDE

PITR works normally with TDE-enabled clusters. WAL records for encrypted
tablespaces contain encrypted page data. Recovery replays encrypted WAL and the
server decrypts transparently at read time.

### Prerequisites

- A base backup taken with `pg_basebackup` (with TDE keys included or available
  separately)
- Archived WAL segments covering the desired recovery window
- The KEM secret key that was active when the base backup was taken

### Recovery Steps

```bash
# 1. Restore the base backup
cp -a /backup/base /var/lib/fortressql/recovery
chown -R postgres:postgres /var/lib/fortressql/recovery

# 2. Ensure the KEM secret key is available
export FORTRESSQL_KEM_SECRET_KEY=/etc/fortressql/kem_secret.key

# 3. Configure recovery
cat >> /var/lib/fortressql/recovery/postgresql.conf <<EOF
restore_command = 'cp /archive/wal/%f %p'
recovery_target_time = '2026-03-15 14:30:00'
EOF

# 4. Create the recovery signal file
touch /var/lib/fortressql/recovery/recovery.signal

# 5. Start the server
pg_ctl -D /var/lib/fortressql/recovery start
```

### Key Rotation and PITR

If the master key was rotated between the base backup and the recovery target,
both the old and new KEM secret keys must be available. The server uses the key
embedded in each WAL record's header to select the correct decryption key.

---

## WAL Archiving with Signed WAL

When `wal_pqc_signing = on`, each completed WAL segment produces a `.sig`
sidecar file containing the ML-DSA signature.

### Archive Configuration

Your `archive_command` must archive both the WAL segment and its signature:

```bash
# postgresql.conf
archive_mode = on
archive_command = 'cp %p /archive/wal/%f && cp %p.sig /archive/wal/%f.sig'
```

### Restore Configuration

The `restore_command` should restore both files:

```bash
restore_command = 'cp /archive/wal/%f %p && cp /archive/wal/%f.sig %p.sig'
```

### Signature Verification During Recovery

If `wal_pqc_verify_on_receive = on` on the recovery target, each restored WAL
segment is verified against its `.sig` file before being applied. If a
signature is missing or invalid, recovery halts with an error.

To recover WAL segments that predate WAL signing enablement (which have no
`.sig` files), temporarily set:

```
wal_pqc_verify_on_receive = off
```

---

## Key Rotation During Backup Windows

Key rotation replaces the active master key while preserving access to
previously encrypted data. Schedule key rotation during a maintenance window
that includes a fresh base backup.

### Recommended Procedure

```bash
# 1. Take a pre-rotation base backup
pg_basebackup -D /backup/pre-rotation -Fp -Xs -P \
    --tde-key-handling=include

# 2. Rotate the master key
pg_tde_master_key rotate \
    --algorithm=ML-KEM-768 \
    --data-dir=/var/lib/fortressql/data

# The server re-wraps all tablespace keys with the new master key.
# Existing encrypted data does not need to be re-encrypted.

# 3. Restart the server to load the new key
export FORTRESSQL_KEM_SECRET_KEY=/etc/fortressql/kem_secret_new.key
pg_ctl -D /var/lib/fortressql/data restart

# 4. Take a post-rotation base backup
pg_basebackup -D /backup/post-rotation -Fp -Xs -P \
    --tde-key-handling=include

# 5. Back up the new KEM secret key
cp /etc/fortressql/kem_secret_new.key /secure-media/kem_secret_new.key.bak
chmod 0400 /secure-media/kem_secret_new.key.bak

# 6. Retain the old KEM secret key
# Keep the old key accessible until all base backups that used it have
# expired from your retention policy.
```

### Key Retention Policy

- **Never delete an old KEM secret key** until all backups encrypted with that
  key have been retired.
- Maintain a key-to-backup mapping: record which KEM secret key corresponds to
  which base backup.
- After rotation, the old key is needed only for restoring old base backups. It
  is not needed for normal server operation.

---

## Disaster Recovery Checklist

Use this checklist to verify your disaster recovery readiness.

### Preparation (Verify Regularly)

- [ ] KEM secret key is backed up to at least two geographically separated
      secure locations
- [ ] KEM secret key backup has been verified (hash comparison with the active
      key)
- [ ] WAL signing keys are backed up (public key distributed to standbys)
- [ ] PQC backup encryption/signing keys are backed up separately from the
      encrypted backups
- [ ] Base backup schedule is active and monitored
- [ ] WAL archiving is active (`archive_mode = on`) and monitored
- [ ] Archive destination has sufficient storage for the retention period
- [ ] `archive_command` copies both WAL segments and `.sig` sidecar files
- [ ] A test restore has been performed within the last 30 days
- [ ] Key-to-backup mapping is documented and current

### Recovery Procedure

1. **Identify the failure** -- determine what was lost (data files, WAL
   archive, key material, or all).
2. **Retrieve the KEM secret key** from secure offline storage.
3. **Restore the most recent base backup** to the target data directory.
4. **Place key files** -- if the backup was taken with
   `--tde-key-handling=exclude`, copy `master.key` and `master.pub` into the
   data directory.
5. **Set the environment** -- `export FORTRESSQL_KEM_SECRET_KEY=<path>`.
6. **Configure recovery** -- set `restore_command` and `recovery_target_*`
   parameters.
7. **Create recovery signal** -- `touch $PGDATA/recovery.signal`.
8. **Start the server** and monitor recovery progress in the server log.
9. **Verify data integrity** after recovery completes:
   ```sql
   -- Check that encrypted tablespaces are accessible
   SELECT schemaname, tablename, tablespace
   FROM pg_tables
   WHERE tablespace IS NOT NULL;

   -- Run application-level integrity checks
   ```
10. **Reconfigure replication** -- standbys will need a fresh base backup from
    the recovered primary.

### If the KEM Secret Key Is Lost

If the KEM secret key is permanently lost and no backup exists:

- **Encrypted data is unrecoverable.** This is by design -- TDE provides
  strong at-rest encryption.
- Unencrypted tablespaces (including `pg_default`) remain accessible.
- Logical backups (pg_dump) taken before the loss contain plaintext data and
  can be restored normally.
- PQC-encrypted backup files (pg_dump `--pqc-encrypt`) require their own
  separate decryption key, which is independent of the TDE master key.

Prevention is the only mitigation. Follow the key backup procedures above.
