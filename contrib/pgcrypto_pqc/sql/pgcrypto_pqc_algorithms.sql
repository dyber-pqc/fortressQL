-- FortressQL PQC: Algorithm variants regression tests
-- Tests all ML-KEM, ML-DSA, and SLH-DSA variants with key size verification

CREATE EXTENSION pgcrypto_pqc;

-- ============================================================
-- ML-KEM Key Size Verification
-- ============================================================

-- ML-KEM-512 key sizes
SELECT
    length(public_key) AS pk_len,
    length(secret_key) AS sk_len
FROM pqc_kem_keygen('ML-KEM-512');

-- ML-KEM-768 key sizes
SELECT
    length(public_key) AS pk_len,
    length(secret_key) AS sk_len
FROM pqc_kem_keygen('ML-KEM-768');

-- ML-KEM-1024 key sizes
SELECT
    length(public_key) AS pk_len,
    length(secret_key) AS sk_len
FROM pqc_kem_keygen('ML-KEM-1024');

-- ============================================================
-- ML-KEM Round-Trip Tests
-- ============================================================

-- ML-KEM-512 encapsulate/decapsulate round-trip
DO $$
DECLARE
    keys RECORD;
    encap RECORD;
    recovered bytea;
BEGIN
    SELECT * INTO keys FROM pqc_kem_keygen('ML-KEM-512');
    SELECT * INTO encap FROM pqc_kem_encapsulate(keys.public_key, 'ML-KEM-512');
    recovered := pqc_kem_decapsulate(encap.ciphertext, keys.secret_key, 'ML-KEM-512');

    IF recovered = encap.shared_secret THEN
        RAISE NOTICE 'ML-KEM-512 round-trip: PASS';
    ELSE
        RAISE EXCEPTION 'ML-KEM-512 round-trip: FAIL';
    END IF;
END $$;

-- ML-KEM-768 encapsulate/decapsulate round-trip
DO $$
DECLARE
    keys RECORD;
    encap RECORD;
    recovered bytea;
BEGIN
    SELECT * INTO keys FROM pqc_kem_keygen('ML-KEM-768');
    SELECT * INTO encap FROM pqc_kem_encapsulate(keys.public_key, 'ML-KEM-768');
    recovered := pqc_kem_decapsulate(encap.ciphertext, keys.secret_key, 'ML-KEM-768');

    IF recovered = encap.shared_secret THEN
        RAISE NOTICE 'ML-KEM-768 round-trip: PASS';
    ELSE
        RAISE EXCEPTION 'ML-KEM-768 round-trip: FAIL';
    END IF;
END $$;

-- ML-KEM-1024 encapsulate/decapsulate round-trip
DO $$
DECLARE
    keys RECORD;
    encap RECORD;
    recovered bytea;
BEGIN
    SELECT * INTO keys FROM pqc_kem_keygen('ML-KEM-1024');
    SELECT * INTO encap FROM pqc_kem_encapsulate(keys.public_key, 'ML-KEM-1024');
    recovered := pqc_kem_decapsulate(encap.ciphertext, keys.secret_key, 'ML-KEM-1024');

    IF recovered = encap.shared_secret THEN
        RAISE NOTICE 'ML-KEM-1024 round-trip: PASS';
    ELSE
        RAISE EXCEPTION 'ML-KEM-1024 round-trip: FAIL';
    END IF;
END $$;

-- ============================================================
-- ML-DSA Key Size Verification
-- ============================================================

-- ML-DSA-44 key sizes
SELECT
    length(public_key) AS pk_len,
    length(secret_key) AS sk_len
FROM pqc_sig_keygen('ML-DSA-44');

-- ML-DSA-65 key sizes
SELECT
    length(public_key) AS pk_len,
    length(secret_key) AS sk_len
FROM pqc_sig_keygen('ML-DSA-65');

-- ML-DSA-87 key sizes
SELECT
    length(public_key) AS pk_len,
    length(secret_key) AS sk_len
FROM pqc_sig_keygen('ML-DSA-87');

-- ============================================================
-- ML-DSA Round-Trip Tests
-- ============================================================

-- ML-DSA-44 sign/verify round-trip
DO $$
DECLARE
    keys RECORD;
    sig bytea;
    msg bytea := E'\\x48656c6c6f20466f72747265737351';
    valid boolean;
BEGIN
    SELECT * INTO keys FROM pqc_sig_keygen('ML-DSA-44');
    sig := pqc_sign(msg, keys.secret_key, 'ML-DSA-44');
    valid := pqc_verify(msg, sig, keys.public_key, 'ML-DSA-44');

    IF valid THEN
        RAISE NOTICE 'ML-DSA-44 sign/verify: PASS';
    ELSE
        RAISE EXCEPTION 'ML-DSA-44 sign/verify: FAIL';
    END IF;
END $$;

-- ML-DSA-65 sign/verify round-trip
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
END $$;

-- ML-DSA-87 sign/verify round-trip
DO $$
DECLARE
    keys RECORD;
    sig bytea;
    msg bytea := E'\\x48656c6c6f20466f72747265737351';
    valid boolean;
BEGIN
    SELECT * INTO keys FROM pqc_sig_keygen('ML-DSA-87');
    sig := pqc_sign(msg, keys.secret_key, 'ML-DSA-87');
    valid := pqc_verify(msg, sig, keys.public_key, 'ML-DSA-87');

    IF valid THEN
        RAISE NOTICE 'ML-DSA-87 sign/verify: PASS';
    ELSE
        RAISE EXCEPTION 'ML-DSA-87 sign/verify: FAIL';
    END IF;
END $$;

-- ============================================================
-- SLH-DSA Variants
-- ============================================================

-- SLH-DSA-SHA2-128f key generation and sizes
SELECT
    length(public_key) AS pk_len,
    length(secret_key) AS sk_len
FROM pqc_sig_keygen('SLH-DSA-SHA2-128f');

-- SLH-DSA-SHA2-128f sign/verify round-trip
DO $$
DECLARE
    keys RECORD;
    sig bytea;
    msg bytea := E'\\x504f53542d5155414e54554d';
    valid boolean;
BEGIN
    SELECT * INTO keys FROM pqc_sig_keygen('SLH-DSA-SHA2-128f');
    sig := pqc_sign(msg, keys.secret_key, 'SLH-DSA-SHA2-128f');
    valid := pqc_verify(msg, sig, keys.public_key, 'SLH-DSA-SHA2-128f');

    IF valid THEN
        RAISE NOTICE 'SLH-DSA-SHA2-128f sign/verify: PASS';
    ELSE
        RAISE EXCEPTION 'SLH-DSA-SHA2-128f sign/verify: FAIL';
    END IF;
END $$;

-- SLH-DSA-SHAKE-256f key generation and sizes
SELECT
    length(public_key) AS pk_len,
    length(secret_key) AS sk_len
FROM pqc_sig_keygen('SLH-DSA-SHAKE-256f');

-- SLH-DSA-SHAKE-256f sign/verify round-trip
DO $$
DECLARE
    keys RECORD;
    sig bytea;
    msg bytea := E'\\x504f53542d5155414e54554d';
    valid boolean;
BEGIN
    SELECT * INTO keys FROM pqc_sig_keygen('SLH-DSA-SHAKE-256f');
    sig := pqc_sign(msg, keys.secret_key, 'SLH-DSA-SHAKE-256f');
    valid := pqc_verify(msg, sig, keys.public_key, 'SLH-DSA-SHAKE-256f');

    IF valid THEN
        RAISE NOTICE 'SLH-DSA-SHAKE-256f sign/verify: PASS';
    ELSE
        RAISE EXCEPTION 'SLH-DSA-SHAKE-256f sign/verify: FAIL';
    END IF;
END $$;

-- ============================================================
-- Verify shared secret length is consistent across KEM variants
-- ============================================================

-- All ML-KEM variants produce 32-byte shared secrets
DO $$
DECLARE
    keys RECORD;
    encap RECORD;
BEGIN
    SELECT * INTO keys FROM pqc_kem_keygen('ML-KEM-512');
    SELECT * INTO encap FROM pqc_kem_encapsulate(keys.public_key, 'ML-KEM-512');
    IF length(encap.shared_secret) = 32 THEN
        RAISE NOTICE 'ML-KEM-512 shared secret length (32): PASS';
    ELSE
        RAISE EXCEPTION 'ML-KEM-512 shared secret length: FAIL (got %)', length(encap.shared_secret);
    END IF;

    SELECT * INTO keys FROM pqc_kem_keygen('ML-KEM-768');
    SELECT * INTO encap FROM pqc_kem_encapsulate(keys.public_key, 'ML-KEM-768');
    IF length(encap.shared_secret) = 32 THEN
        RAISE NOTICE 'ML-KEM-768 shared secret length (32): PASS';
    ELSE
        RAISE EXCEPTION 'ML-KEM-768 shared secret length: FAIL (got %)', length(encap.shared_secret);
    END IF;

    SELECT * INTO keys FROM pqc_kem_keygen('ML-KEM-1024');
    SELECT * INTO encap FROM pqc_kem_encapsulate(keys.public_key, 'ML-KEM-1024');
    IF length(encap.shared_secret) = 32 THEN
        RAISE NOTICE 'ML-KEM-1024 shared secret length (32): PASS';
    ELSE
        RAISE EXCEPTION 'ML-KEM-1024 shared secret length: FAIL (got %)', length(encap.shared_secret);
    END IF;
END $$;

-- ============================================================
-- Verify algorithm type classification
-- ============================================================

-- KEM algorithms should not be usable for signing
SELECT pqc_sig_keygen('ML-KEM-768');

-- SIG algorithms should not be usable for KEM
SELECT pqc_kem_keygen('ML-DSA-65');

DROP EXTENSION pgcrypto_pqc;
