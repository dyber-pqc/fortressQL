/* contrib/pgcrypto_pqc/pgcrypto_pqc--1.1--1.2.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pgcrypto_pqc UPDATE TO '1.2'" to load this file. \quit

--
-- FortressQL v1.2: Column-level PQC encryption
--
-- Provides per-value encryption using ML-KEM key encapsulation with
-- AES-256-GCM symmetric encryption.  Each encrypted value gets a fresh
-- KEM encapsulation, so compromising one value's key does not affect others.
--

-- ============================================================
-- Column-Level Encryption Functions
-- ============================================================

-- Encrypt arbitrary bytea data with PQC key wrapping
CREATE FUNCTION pqc_encrypt_column(
    data bytea,
    public_key bytea,
    algorithm text DEFAULT 'ML-KEM-768'
) RETURNS bytea
AS 'MODULE_PATHNAME', 'pqc_encrypt_column'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_encrypt_column(bytea, bytea, text) IS
'Encrypt a column value using ML-KEM key encapsulation + AES-256-GCM. '
'Each call generates a fresh per-value symmetric key via KEM encapsulation. '
'Output contains the KEM ciphertext, IV, AES ciphertext, and GCM authentication tag.';

-- Decrypt data encrypted with pqc_encrypt_column
CREATE FUNCTION pqc_decrypt_column(
    encrypted_data bytea,
    secret_key bytea,
    algorithm text DEFAULT 'ML-KEM-768'
) RETURNS bytea
AS 'MODULE_PATHNAME', 'pqc_decrypt_column'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_decrypt_column(bytea, bytea, text) IS
'Decrypt a column value that was encrypted with pqc_encrypt_column(). '
'Decapsulates the KEM ciphertext to recover the AES key, then decrypts with AES-256-GCM.';

-- ============================================================
-- Convenience Text Wrappers
-- ============================================================

-- Encrypt text data (convenience wrapper)
CREATE FUNCTION pqc_encrypt_text(
    plaintext text,
    public_key bytea,
    algorithm text DEFAULT 'ML-KEM-768'
) RETURNS bytea
AS 'MODULE_PATHNAME', 'pqc_encrypt_text'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_encrypt_text(text, bytea, text) IS
'Convenience wrapper: encrypts a text value using PQC column encryption (ML-KEM + AES-256-GCM). '
'Equivalent to pqc_encrypt_column(plaintext::bytea, public_key, algorithm).';

-- Decrypt to text (convenience wrapper)
CREATE FUNCTION pqc_decrypt_text(
    encrypted_data bytea,
    secret_key bytea,
    algorithm text DEFAULT 'ML-KEM-768'
) RETURNS text
AS 'MODULE_PATHNAME', 'pqc_decrypt_text'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_decrypt_text(bytea, bytea, text) IS
'Convenience wrapper: decrypts data encrypted with pqc_encrypt_text() and returns the original text. '
'Equivalent to convert_from(pqc_decrypt_column(encrypted_data, secret_key, algorithm), ''UTF8'').';
