/* contrib/pgcrypto_pqc/pgcrypto_pqc--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgcrypto_pqc" to load this file. \quit

--
-- FortressQL: Post-Quantum Cryptography SQL Functions
--
-- FIPS 203: ML-KEM (Key Encapsulation Mechanism)
-- FIPS 204: ML-DSA (Digital Signature Algorithm)
-- FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature)
--

-- ============================================================
-- Key Encapsulation Mechanism (KEM) Functions
-- ============================================================

-- Generate a KEM key pair
-- Returns (public_key bytea, secret_key bytea)
CREATE FUNCTION pqc_kem_keygen(algorithm text DEFAULT 'ML-KEM-768',
    OUT public_key bytea, OUT secret_key bytea)
RETURNS record
AS 'MODULE_PATHNAME', 'pqc_kem_keygen'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_kem_keygen(text) IS
'Generate a post-quantum KEM key pair. Algorithms: ML-KEM-512, ML-KEM-768 (default), ML-KEM-1024';

-- Encapsulate: generate shared secret from a public key
-- Returns (ciphertext bytea, shared_secret bytea)
CREATE FUNCTION pqc_kem_encapsulate(public_key bytea,
    algorithm text DEFAULT 'ML-KEM-768',
    OUT ciphertext bytea, OUT shared_secret bytea)
RETURNS record
AS 'MODULE_PATHNAME', 'pqc_kem_encapsulate'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_kem_encapsulate(bytea, text) IS
'Encapsulate: generate a ciphertext and shared secret using a public key';

-- Decapsulate: recover shared secret from ciphertext using secret key
CREATE FUNCTION pqc_kem_decapsulate(ciphertext bytea, secret_key bytea,
    algorithm text DEFAULT 'ML-KEM-768')
RETURNS bytea
AS 'MODULE_PATHNAME', 'pqc_kem_decapsulate'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_kem_decapsulate(bytea, bytea, text) IS
'Decapsulate: recover the shared secret from a ciphertext using the secret key';

-- ============================================================
-- Digital Signature Functions
-- ============================================================

-- Generate a signature key pair
-- Returns (public_key bytea, secret_key bytea)
CREATE FUNCTION pqc_sig_keygen(algorithm text DEFAULT 'ML-DSA-65',
    OUT public_key bytea, OUT secret_key bytea)
RETURNS record
AS 'MODULE_PATHNAME', 'pqc_sig_keygen'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_sig_keygen(text) IS
'Generate a post-quantum signature key pair. Algorithms: ML-DSA-44, ML-DSA-65 (default), ML-DSA-87, SLH-DSA-*';

-- Sign a message
CREATE FUNCTION pqc_sign(message bytea, secret_key bytea,
    algorithm text DEFAULT 'ML-DSA-65')
RETURNS bytea
AS 'MODULE_PATHNAME', 'pqc_sign'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_sign(bytea, bytea, text) IS
'Sign a message using a post-quantum secret key';

-- Verify a signature
CREATE FUNCTION pqc_verify(message bytea, signature bytea, public_key bytea,
    algorithm text DEFAULT 'ML-DSA-65')
RETURNS boolean
AS 'MODULE_PATHNAME', 'pqc_verify'
LANGUAGE C STRICT STABLE;

COMMENT ON FUNCTION pqc_verify(bytea, bytea, bytea, text) IS
'Verify a post-quantum signature. Returns true if valid, false otherwise';

-- ============================================================
-- Hybrid Encryption (ML-KEM + AES-256-GCM)
-- ============================================================

-- Encrypt data using hybrid PQC+AES encryption
-- Generates an ephemeral KEM key pair, encapsulates to derive AES key,
-- then encrypts with AES-256-GCM.
-- Returns (encrypted_data bytea, encapsulated_key bytea, public_key bytea)
CREATE FUNCTION pqc_encrypt(plaintext bytea,
    algorithm text DEFAULT 'ML-KEM-768',
    OUT encrypted_data bytea, OUT encapsulated_key bytea,
    OUT public_key bytea, OUT secret_key bytea)
RETURNS record
AS 'MODULE_PATHNAME', 'pqc_encrypt'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_encrypt(bytea, text) IS
'Hybrid PQC encryption: ML-KEM key encapsulation + AES-256-GCM. Returns encrypted data, KEM ciphertext, and key pair';

-- Decrypt data using hybrid PQC+AES decryption
CREATE FUNCTION pqc_decrypt(encrypted_data bytea, encapsulated_key bytea,
    secret_key bytea, algorithm text DEFAULT 'ML-KEM-768')
RETURNS bytea
AS 'MODULE_PATHNAME', 'pqc_decrypt'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION pqc_decrypt(bytea, bytea, bytea, text) IS
'Hybrid PQC decryption: ML-KEM decapsulation + AES-256-GCM decrypt';

-- ============================================================
-- Algorithm Discovery
-- ============================================================

-- List all available PQC algorithms with their properties
CREATE FUNCTION pqc_algorithms(
    OUT name text,
    OUT type text,
    OUT nist_level int,
    OUT public_key_size int,
    OUT secret_key_size int,
    OUT ciphertext_or_sig_size int)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pqc_algorithms'
LANGUAGE C STRICT STABLE;

COMMENT ON FUNCTION pqc_algorithms() IS
'List all available FortressQL PQC algorithms with their properties';
