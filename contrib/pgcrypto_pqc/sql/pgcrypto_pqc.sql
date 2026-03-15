-- FortressQL PQC Extension regression tests

CREATE EXTENSION pgcrypto_pqc;

-- List all available algorithms
SELECT name, type, nist_level FROM pqc_algorithms() ORDER BY name;

-- Test ML-KEM-768 key generation
SELECT
    length(public_key) AS pk_len,
    length(secret_key) AS sk_len
FROM pqc_kem_keygen('ML-KEM-768');

-- Test ML-KEM-768 encapsulate/decapsulate round-trip
DO $$
DECLARE
    keys RECORD;
    encap RECORD;
    recovered_secret bytea;
BEGIN
    SELECT * INTO keys FROM pqc_kem_keygen('ML-KEM-768');
    SELECT * INTO encap FROM pqc_kem_encapsulate(keys.public_key, 'ML-KEM-768');
    recovered_secret := pqc_kem_decapsulate(encap.ciphertext, keys.secret_key, 'ML-KEM-768');

    IF recovered_secret = encap.shared_secret THEN
        RAISE NOTICE 'ML-KEM-768 KEM round-trip: PASS';
    ELSE
        RAISE EXCEPTION 'ML-KEM-768 KEM round-trip: FAIL - shared secrets do not match';
    END IF;
END $$;

-- Test ML-DSA-65 key generation
SELECT
    length(public_key) AS pk_len,
    length(secret_key) AS sk_len
FROM pqc_sig_keygen('ML-DSA-65');

-- Test ML-DSA-65 sign/verify round-trip
DO $$
DECLARE
    keys RECORD;
    sig bytea;
    msg bytea := E'\\x48656c6c6f20466f72747265737351';
    valid boolean;
BEGIN
    SELECT * INTO keys FROM pqc_sig_keygen('ML-DSA-65');
    sig := pqc_sign(msg, keys.secret_key, 'ML-DSA-65');
    valid := pqc_verify(msg, sig, keys.public_key, 'ML-DSA-65');

    IF valid THEN
        RAISE NOTICE 'ML-DSA-65 sign/verify: PASS';
    ELSE
        RAISE EXCEPTION 'ML-DSA-65 sign/verify: FAIL';
    END IF;

    -- Verify tampered message fails
    valid := pqc_verify(E'\\x00'::bytea, sig, keys.public_key, 'ML-DSA-65');
    IF NOT valid THEN
        RAISE NOTICE 'ML-DSA-65 tamper detection: PASS';
    ELSE
        RAISE EXCEPTION 'ML-DSA-65 tamper detection: FAIL - should have rejected';
    END IF;
END $$;

-- Test hybrid encryption/decryption round-trip
DO $$
DECLARE
    enc RECORD;
    plaintext bytea := E'\\x5468697320697320746f702073656372657420646174612070726f746563746564206279204d4c2d4b454d2d373638';
    decrypted bytea;
BEGIN
    SELECT * INTO enc FROM pqc_encrypt(plaintext, 'ML-KEM-768');
    decrypted := pqc_decrypt(enc.encrypted_data, enc.encapsulated_key,
                             enc.secret_key, 'ML-KEM-768');

    IF decrypted = plaintext THEN
        RAISE NOTICE 'Hybrid encryption (ML-KEM-768 + AES-256-GCM) round-trip: PASS';
    ELSE
        RAISE EXCEPTION 'Hybrid encryption round-trip: FAIL';
    END IF;
END $$;

-- Test invalid algorithm name
SELECT pqc_kem_keygen('INVALID-ALGO');  -- should error

DROP EXTENSION pgcrypto_pqc;
