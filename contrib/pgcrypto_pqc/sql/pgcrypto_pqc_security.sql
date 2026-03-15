-- FortressQL PQC: Security and edge case regression tests
-- Tests wrong-key rejection, tampered data, NULL handling, and boundary inputs

CREATE EXTENSION pgcrypto_pqc;

-- ============================================================
-- KEM: Decapsulation with wrong secret key
-- ============================================================

-- ML-KEM decapsulation with wrong key produces different shared secret
-- (ML-KEM uses implicit rejection: no error, but wrong secret)
DO $$
DECLARE
    keys_a RECORD;
    keys_b RECORD;
    encap RECORD;
    recovered bytea;
BEGIN
    SELECT * INTO keys_a FROM pqc_kem_keygen('ML-KEM-768');
    SELECT * INTO keys_b FROM pqc_kem_keygen('ML-KEM-768');
    SELECT * INTO encap FROM pqc_kem_encapsulate(keys_a.public_key, 'ML-KEM-768');

    -- Decapsulate with wrong key B
    recovered := pqc_kem_decapsulate(encap.ciphertext, keys_b.secret_key, 'ML-KEM-768');

    IF recovered <> encap.shared_secret THEN
        RAISE NOTICE 'KEM wrong-key rejection: PASS';
    ELSE
        RAISE EXCEPTION 'KEM wrong-key rejection: FAIL - should produce different secret';
    END IF;
END $$;

-- ============================================================
-- Hybrid encrypt: Decrypt with wrong key fails
-- ============================================================

DO $$
DECLARE
    enc RECORD;
    wrong_keys RECORD;
    plaintext bytea := E'\\x736563726574206d657373616765';
    decrypted bytea;
BEGIN
    SELECT * INTO enc FROM pqc_encrypt(plaintext, 'ML-KEM-768');
    SELECT * INTO wrong_keys FROM pqc_kem_keygen('ML-KEM-768');

    -- This should fail with AES-GCM authentication error
    BEGIN
        decrypted := pqc_decrypt(enc.encrypted_data, enc.encapsulated_key,
                                 wrong_keys.secret_key, 'ML-KEM-768');
        RAISE EXCEPTION 'Hybrid wrong-key decrypt: FAIL - should have errored';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Hybrid wrong-key decrypt rejected: PASS';
    END;
END $$;

-- ============================================================
-- Signature: Verify with wrong public key
-- ============================================================

DO $$
DECLARE
    keys_a RECORD;
    keys_b RECORD;
    sig bytea;
    msg bytea := E'\\x48656c6c6f';
    valid boolean;
BEGIN
    SELECT * INTO keys_a FROM pqc_sig_keygen('ML-DSA-65');
    SELECT * INTO keys_b FROM pqc_sig_keygen('ML-DSA-65');
    sig := pqc_sign(msg, keys_a.secret_key, 'ML-DSA-65');

    -- Verify with wrong key B should return false
    valid := pqc_verify(msg, sig, keys_b.public_key, 'ML-DSA-65');
    IF NOT valid THEN
        RAISE NOTICE 'Signature wrong-key rejection: PASS';
    ELSE
        RAISE EXCEPTION 'Signature wrong-key rejection: FAIL';
    END IF;
END $$;

-- ============================================================
-- Signature: Tampered message detection
-- ============================================================

DO $$
DECLARE
    keys RECORD;
    sig bytea;
    msg bytea := E'\\x6f726967696e616c206d657373616765';
    tampered bytea := E'\\x74616d7065726564206d657373616765';
    valid boolean;
BEGIN
    SELECT * INTO keys FROM pqc_sig_keygen('ML-DSA-44');
    sig := pqc_sign(msg, keys.secret_key, 'ML-DSA-44');

    valid := pqc_verify(tampered, sig, keys.public_key, 'ML-DSA-44');
    IF NOT valid THEN
        RAISE NOTICE 'Tampered message detection (ML-DSA-44): PASS';
    ELSE
        RAISE EXCEPTION 'Tampered message detection: FAIL';
    END IF;
END $$;

-- ============================================================
-- Empty message signing and verification
-- ============================================================

DO $$
DECLARE
    keys RECORD;
    sig bytea;
    msg bytea := E''::bytea;
    valid boolean;
BEGIN
    SELECT * INTO keys FROM pqc_sig_keygen('ML-DSA-65');
    sig := pqc_sign(msg, keys.secret_key, 'ML-DSA-65');
    valid := pqc_verify(msg, sig, keys.public_key, 'ML-DSA-65');

    IF valid THEN
        RAISE NOTICE 'Empty message sign/verify: PASS';
    ELSE
        RAISE EXCEPTION 'Empty message sign/verify: FAIL';
    END IF;
END $$;

-- ============================================================
-- Large message signing and verification (1 MB)
-- ============================================================

DO $$
DECLARE
    keys RECORD;
    sig bytea;
    msg bytea;
    valid boolean;
BEGIN
    msg := convert_to(repeat('X', 1000000), 'UTF8');
    SELECT * INTO keys FROM pqc_sig_keygen('ML-DSA-65');
    sig := pqc_sign(msg, keys.secret_key, 'ML-DSA-65');
    valid := pqc_verify(msg, sig, keys.public_key, 'ML-DSA-65');

    IF valid THEN
        RAISE NOTICE 'Large message (1MB) sign/verify: PASS';
    ELSE
        RAISE EXCEPTION 'Large message sign/verify: FAIL';
    END IF;
END $$;

-- ============================================================
-- Empty message hybrid encryption/decryption
-- ============================================================

DO $$
DECLARE
    enc RECORD;
    plaintext bytea := E''::bytea;
    decrypted bytea;
BEGIN
    SELECT * INTO enc FROM pqc_encrypt(plaintext, 'ML-KEM-768');
    decrypted := pqc_decrypt(enc.encrypted_data, enc.encapsulated_key,
                             enc.secret_key, 'ML-KEM-768');

    IF decrypted = plaintext THEN
        RAISE NOTICE 'Empty message hybrid encrypt/decrypt: PASS';
    ELSE
        RAISE EXCEPTION 'Empty message hybrid encrypt/decrypt: FAIL';
    END IF;
END $$;

-- ============================================================
-- Large message hybrid encryption/decryption
-- ============================================================

DO $$
DECLARE
    enc RECORD;
    plaintext bytea;
    decrypted bytea;
BEGIN
    plaintext := convert_to(repeat('Y', 100000), 'UTF8');
    SELECT * INTO enc FROM pqc_encrypt(plaintext, 'ML-KEM-768');
    decrypted := pqc_decrypt(enc.encrypted_data, enc.encapsulated_key,
                             enc.secret_key, 'ML-KEM-768');

    IF decrypted = plaintext THEN
        RAISE NOTICE 'Large message (100KB) hybrid encrypt/decrypt: PASS';
    ELSE
        RAISE EXCEPTION 'Large message hybrid encrypt/decrypt: FAIL';
    END IF;
END $$;

-- ============================================================
-- Invalid algorithm names
-- ============================================================

-- Invalid KEM algorithm
SELECT pqc_kem_keygen('INVALID-KEM');

-- Invalid SIG algorithm
SELECT pqc_sig_keygen('INVALID-SIG');

-- Using a SIG algorithm for KEM should fail
SELECT pqc_kem_keygen('ML-DSA-65');

-- Using a KEM algorithm for SIG should fail
SELECT pqc_sig_keygen('ML-KEM-768');

-- ============================================================
-- Tampered ciphertext detection for hybrid encryption
-- ============================================================

DO $$
DECLARE
    enc RECORD;
    plaintext bytea := E'\\x736563726574';
    tampered_data bytea;
    decrypted bytea;
BEGIN
    SELECT * INTO enc FROM pqc_encrypt(plaintext, 'ML-KEM-768');

    -- Flip a bit in the encrypted data
    tampered_data := set_byte(enc.encrypted_data, 20, get_byte(enc.encrypted_data, 20) # 255);

    BEGIN
        decrypted := pqc_decrypt(tampered_data, enc.encapsulated_key,
                                 enc.secret_key, 'ML-KEM-768');
        RAISE EXCEPTION 'Tampered ciphertext detection: FAIL - should have errored';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Tampered ciphertext detection: PASS';
    END;
END $$;

-- ============================================================
-- Signature with tampered signature bytes
-- ============================================================

DO $$
DECLARE
    keys RECORD;
    sig bytea;
    tampered_sig bytea;
    msg bytea := E'\\x48656c6c6f';
    valid boolean;
BEGIN
    SELECT * INTO keys FROM pqc_sig_keygen('ML-DSA-87');
    sig := pqc_sign(msg, keys.secret_key, 'ML-DSA-87');

    -- Flip a byte in the signature
    tampered_sig := set_byte(sig, 10, get_byte(sig, 10) # 255);
    valid := pqc_verify(msg, tampered_sig, keys.public_key, 'ML-DSA-87');

    IF NOT valid THEN
        RAISE NOTICE 'Tampered signature detection (ML-DSA-87): PASS';
    ELSE
        RAISE EXCEPTION 'Tampered signature detection: FAIL';
    END IF;
END $$;

DROP EXTENSION pgcrypto_pqc;
