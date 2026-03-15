/* contrib/pgcrypto_pqc/pgcrypto_pqc--1.0--1.1.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pgcrypto_pqc UPDATE TO '1.1'" to load this file. \quit

--
-- FortressQL: Hybrid Proof Logging - dual classical+PQC audit signatures
--

-- ============================================================
-- Audit Log Tables
-- ============================================================

-- Hybrid proof audit log table
CREATE TABLE IF NOT EXISTS pqc_audit_log (
    log_id          bigserial PRIMARY KEY,
    event_time      timestamptz NOT NULL DEFAULT now(),
    session_id      text NOT NULL,
    user_name       name NOT NULL,
    database_name   name NOT NULL,
    event_type      text NOT NULL,
    event_detail    jsonb NOT NULL,
    classical_sig_alg  text NOT NULL,
    classical_signature bytea NOT NULL,
    pqc_sig_alg     text NOT NULL,
    pqc_signature   bytea NOT NULL,
    prev_hash       bytea,
    entry_hash      bytea NOT NULL
);

CREATE INDEX ON pqc_audit_log (event_time);
CREATE INDEX ON pqc_audit_log (event_type);

-- Audit signing keys
CREATE TABLE IF NOT EXISTS pqc_audit_keys (
    key_id          serial PRIMARY KEY,
    key_purpose     text NOT NULL,
    algorithm       text NOT NULL,
    public_key      bytea NOT NULL,
    encrypted_secret_key bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    is_active       boolean NOT NULL DEFAULT true
);

-- ============================================================
-- Audit Key Management
-- ============================================================

-- Initialize audit keys
CREATE FUNCTION pqc_audit_init_keys(
    classical_alg text DEFAULT 'Ed25519',
    pqc_alg text DEFAULT 'ML-DSA-65'
) RETURNS void AS 'MODULE_PATHNAME', 'pqc_audit_init_keys' LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_audit_init_keys(text, text) IS
'Initialize hybrid audit signing keys (classical Ed25519 + post-quantum ML-DSA)';

-- ============================================================
-- Dual-Signature Functions
-- ============================================================

-- Dual-sign a message
CREATE FUNCTION pqc_audit_sign(
    message bytea
) RETURNS TABLE(classical_sig bytea, pqc_sig bytea, classical_alg text, pqc_alg text)
AS 'MODULE_PATHNAME', 'pqc_audit_sign' LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_audit_sign(bytea) IS
'Sign a message with both classical (Ed25519) and post-quantum keys for hybrid non-repudiation';

-- Verify dual signatures
CREATE FUNCTION pqc_audit_verify(
    message bytea,
    classical_sig bytea,
    classical_alg text,
    pqc_sig bytea,
    pqc_alg text
) RETURNS TABLE(classical_valid boolean, pqc_valid boolean)
AS 'MODULE_PATHNAME', 'pqc_audit_verify' LANGUAGE C STRICT STABLE;

COMMENT ON FUNCTION pqc_audit_verify(bytea, bytea, text, bytea, text) IS
'Verify both classical and post-quantum signatures on a message';

-- ============================================================
-- Hash Chain Verification
-- ============================================================

-- Verify the hash chain integrity
CREATE FUNCTION pqc_audit_verify_chain(
    start_id bigint DEFAULT 1,
    end_id bigint DEFAULT NULL
) RETURNS TABLE(log_id bigint, chain_valid boolean, classical_sig_valid boolean, pqc_sig_valid boolean)
AS 'MODULE_PATHNAME', 'pqc_audit_verify_chain' LANGUAGE C STABLE;

COMMENT ON FUNCTION pqc_audit_verify_chain(bigint, bigint) IS
'Verify the integrity of the audit log hash chain and all dual signatures';

-- ============================================================
-- Credential Migration
-- ============================================================

-- Credential migration
CREATE FUNCTION pqc_migrate_credentials(
    mode text DEFAULT 'report'
) RETURNS TABLE(rolname name, current_type text, action text)
AS 'MODULE_PATHNAME', 'pqc_migrate_credentials' LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_migrate_credentials(text) IS
'Report or force-reset SCRAM-SHA-256 credentials for PQC migration';
