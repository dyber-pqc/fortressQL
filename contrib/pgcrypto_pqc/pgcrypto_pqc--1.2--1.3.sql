/* contrib/pgcrypto_pqc/pgcrypto_pqc--1.2--1.3.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pgcrypto_pqc UPDATE TO '1.3'" to load this file. \quit

-- ============================================================
-- Escrow Metadata Table
-- ============================================================

CREATE TABLE IF NOT EXISTS pqc_escrow_metadata (
    escrow_id       serial PRIMARY KEY,
    escrow_name     text NOT NULL,
    algorithm       text NOT NULL,
    num_shares      int NOT NULL,
    threshold       int NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pqc_escrow_metadata_name
    ON pqc_escrow_metadata (escrow_name);

-- ============================================================
-- Audit Compliance Extensions
-- ============================================================

-- Add compliance metadata columns to pqc_audit_log
ALTER TABLE pqc_audit_log ADD COLUMN IF NOT EXISTS
    compliance_framework text DEFAULT NULL;

ALTER TABLE pqc_audit_log ADD COLUMN IF NOT EXISTS
    data_classification text DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_pqc_audit_compliance_framework
    ON pqc_audit_log (compliance_framework)
    WHERE compliance_framework IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_pqc_audit_data_classification
    ON pqc_audit_log (data_classification)
    WHERE data_classification IS NOT NULL;

-- Compliance report function
CREATE OR REPLACE FUNCTION pqc_audit_compliance_report(
    framework text DEFAULT 'SOC2'
) RETURNS TABLE (
    report_section   text,
    requirement      text,
    status           text,
    detail           text
) AS $$
DECLARE
    v_crypto_policy    text;
    v_tde_enabled      boolean;
    v_wal_signing      boolean;
    v_audit_count      bigint;
    v_chain_valid      boolean;
    v_oldest_entry     timestamptz;
    v_newest_entry     timestamptz;
BEGIN
    -- Gather current system state
    BEGIN
        v_crypto_policy := current_setting('crypto_policy', true);
    EXCEPTION WHEN OTHERS THEN
        v_crypto_policy := 'unknown';
    END;

    BEGIN
        v_tde_enabled := current_setting('pqc_tde.enabled', true)::boolean;
    EXCEPTION WHEN OTHERS THEN
        v_tde_enabled := false;
    END;

    BEGIN
        v_wal_signing := current_setting('wal_pqc_signing', true)::boolean;
    EXCEPTION WHEN OTHERS THEN
        v_wal_signing := false;
    END;

    SELECT count(*), min(event_time), max(event_time)
    INTO v_audit_count, v_oldest_entry, v_newest_entry
    FROM pqc_audit_log;

    -- Check hash chain integrity (sample last 100 entries)
    v_chain_valid := true;
    IF v_audit_count > 0 THEN
        PERFORM 1 FROM pqc_audit_verify_chain(
            greatest(1, v_audit_count - 100), NULL
        ) WHERE NOT chain_valid LIMIT 1;
        IF FOUND THEN
            v_chain_valid := false;
        END IF;
    END IF;

    -- Encryption at Rest
    report_section := 'Encryption at Rest';
    requirement := 'Data must be encrypted at rest using approved algorithms';
    IF v_tde_enabled THEN
        status := 'PASS';
        detail := 'TDE is enabled with PQC key wrapping';
    ELSE
        status := 'FAIL';
        detail := 'TDE is not enabled';
    END IF;
    RETURN NEXT;

    -- Cryptographic Policy
    report_section := 'Cryptographic Policy';
    requirement := 'System must enforce post-quantum cryptographic policy';
    IF v_crypto_policy IN ('pqc-only', 'hybrid', 'transitional') THEN
        status := 'PASS';
        detail := format('Crypto policy: %s', v_crypto_policy);
    ELSE
        status := 'WARN';
        detail := format('Crypto policy is "%s" - consider "hybrid" or "pqc-only"',
                         coalesce(v_crypto_policy, 'not set'));
    END IF;
    RETURN NEXT;

    -- WAL Integrity
    report_section := 'WAL Integrity';
    requirement := 'WAL segments must be signed for tamper detection';
    IF v_wal_signing THEN
        status := 'PASS';
        detail := 'WAL PQC signing is enabled';
    ELSE
        status := 'FAIL';
        detail := 'WAL PQC signing is not enabled';
    END IF;
    RETURN NEXT;

    -- Audit Logging
    report_section := 'Audit Logging';
    requirement := 'Security events must be logged with non-repudiation';
    IF v_audit_count > 0 THEN
        status := 'PASS';
        detail := format('%s audit entries from %s to %s',
                         v_audit_count, v_oldest_entry, v_newest_entry);
    ELSE
        status := 'FAIL';
        detail := 'No audit log entries found';
    END IF;
    RETURN NEXT;

    -- Audit Chain Integrity
    report_section := 'Audit Chain Integrity';
    requirement := 'Audit log hash chain must be intact';
    IF v_chain_valid THEN
        status := 'PASS';
        detail := 'Hash chain integrity verified';
    ELSE
        status := 'FAIL';
        detail := 'Hash chain integrity check failed - possible tampering';
    END IF;
    RETURN NEXT;

    -- Framework-specific checks
    IF upper(framework) = 'HIPAA' THEN
        report_section := 'HIPAA Access Controls';
        requirement := 'Access to ePHI must be authenticated and audited';
        IF v_audit_count > 0 AND v_crypto_policy IN ('pqc-only', 'hybrid') THEN
            status := 'PASS';
            detail := 'Audit logging active with PQC cryptographic controls';
        ELSE
            status := 'WARN';
            detail := 'Review audit and crypto settings for HIPAA compliance';
        END IF;
        RETURN NEXT;
    ELSIF upper(framework) = 'FEDRAMP' THEN
        report_section := 'FedRAMP FIPS 140-3';
        requirement := 'Cryptographic modules must meet FIPS 140-3 standards';
        IF v_crypto_policy = 'pqc-only' THEN
            status := 'PASS';
            detail := 'PQC-only policy with NIST-approved algorithms';
        ELSIF v_crypto_policy = 'hybrid' THEN
            status := 'PASS';
            detail := 'Hybrid mode with NIST-approved PQC algorithms';
        ELSE
            status := 'FAIL';
            detail := 'FedRAMP requires NIST-approved cryptographic algorithms';
        END IF;
        RETURN NEXT;
    ELSIF upper(framework) = 'SOC2' THEN
        report_section := 'SOC2 CC6.1 - Logical Access';
        requirement := 'Encryption controls must protect data confidentiality';
        IF v_tde_enabled AND v_wal_signing THEN
            status := 'PASS';
            detail := 'TDE and WAL signing provide data protection controls';
        ELSE
            status := 'WARN';
            detail := 'Enable TDE and WAL signing for full SOC2 coverage';
        END IF;
        RETURN NEXT;
    END IF;

    RETURN;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION pqc_audit_compliance_report(text) IS
'Generate a compliance report for the specified framework (SOC2, HIPAA, FedRAMP)';

-- Compliance status view
CREATE OR REPLACE VIEW pg_pqc_compliance_status AS
SELECT
    current_setting('crypto_policy', true) AS crypto_policy,
    coalesce(current_setting('pqc_tde.enabled', true), 'off') AS tde_status,
    coalesce(current_setting('wal_pqc_signing', true), 'off') AS wal_signing_status,
    (SELECT count(*) FROM pqc_audit_log) AS audit_entry_count,
    CASE
        WHEN (SELECT count(*) FROM pqc_audit_log) = 0 THEN 'N/A'
        WHEN NOT EXISTS (
            SELECT 1 FROM pqc_audit_verify_chain(
                greatest(1, (SELECT max(log_id) - 100 FROM pqc_audit_log)),
                NULL
            ) WHERE NOT chain_valid
        ) THEN 'INTACT'
        ELSE 'BROKEN'
    END AS hash_chain_status,
    CASE
        WHEN current_setting('crypto_policy', true) IN ('pqc-only', 'hybrid')
             AND coalesce(current_setting('pqc_tde.enabled', true), 'off') = 'on'
             AND coalesce(current_setting('wal_pqc_signing', true), 'off') = 'on'
             AND (SELECT count(*) FROM pqc_audit_log) > 0
        THEN 'COMPLIANT'
        ELSE 'NOT COMPLIANT'
    END AS compliance_readiness;

COMMENT ON VIEW pg_pqc_compliance_status IS
'Shows current PQC compliance status including crypto policy, TDE, WAL signing, audit, and readiness';

-- ============================================================
-- Online Key Rotation Functions
-- ============================================================

-- Rotate WAL signing keys online
CREATE OR REPLACE FUNCTION pqc_rotate_wal_signing_keys(
    algorithm text DEFAULT 'ML-DSA-65'
) RETURNS TABLE (
    status      text,
    old_key_id  text,
    new_key_id  text,
    algorithm_used text,
    rotated_at  timestamptz
) AS 'MODULE_PATHNAME', 'pqc_rotate_wal_signing_keys'
LANGUAGE C VOLATILE;

COMMENT ON FUNCTION pqc_rotate_wal_signing_keys(text) IS
'Generate new WAL signing keypair and atomically swap. No restart required.';

-- Rotate TDE master key
CREATE OR REPLACE FUNCTION pqc_rotate_tde_master_key()
RETURNS TABLE (
    status              text,
    tablespaces_rewrapped int,
    rotated_at          timestamptz
) AS 'MODULE_PATHNAME', 'pqc_rotate_tde_master_key'
LANGUAGE C VOLATILE;

COMMENT ON FUNCTION pqc_rotate_tde_master_key() IS
'Re-wrap all tablespace keys with a new master key. Online operation.';

-- Key rotation status
CREATE OR REPLACE FUNCTION pqc_key_rotation_status()
RETURNS TABLE (
    key_type           text,
    key_id             text,
    algorithm          text,
    created_at         timestamptz,
    age_days           int,
    rotation_recommended boolean
) AS 'MODULE_PATHNAME', 'pqc_key_rotation_status'
LANGUAGE C STABLE;

COMMENT ON FUNCTION pqc_key_rotation_status() IS
'Show last rotation timestamp, key age, and whether rotation is recommended';

-- ============================================================
-- Backup Key Escrow (Shamir Secret Sharing)
-- ============================================================

-- Create key escrow shares using Shamir's Secret Sharing
CREATE OR REPLACE FUNCTION pqc_escrow_create(
    escrow_name text,
    num_shares  int DEFAULT 5,
    threshold   int DEFAULT 3
) RETURNS TABLE (
    share_index int,
    share_data  bytea
) AS 'MODULE_PATHNAME', 'pqc_escrow_create'
LANGUAGE C VOLATILE;

COMMENT ON FUNCTION pqc_escrow_create(text, int, int) IS
'Split the KEM secret key into Shamir Secret Sharing shares (GF(256) scheme)';

-- Recover key from escrow shares
CREATE OR REPLACE FUNCTION pqc_escrow_recover(
    shares bytea[]
) RETURNS TABLE (
    status         text,
    recovered_key  bytea
) AS 'MODULE_PATHNAME', 'pqc_escrow_recover'
LANGUAGE C VOLATILE;

COMMENT ON FUNCTION pqc_escrow_recover(bytea[]) IS
'Reconstruct the KEM secret key from threshold Shamir Secret Sharing shares';

-- Show backup key metadata
CREATE OR REPLACE FUNCTION pqc_backup_key_info()
RETURNS TABLE (
    key_type    text,
    algorithm   text,
    key_id      text,
    created_at  timestamptz,
    escrow_name text,
    num_shares  int,
    threshold   int
) AS 'MODULE_PATHNAME', 'pqc_backup_key_info'
LANGUAGE C STABLE;

COMMENT ON FUNCTION pqc_backup_key_info() IS
'Show current backup encryption key metadata and escrow information';
