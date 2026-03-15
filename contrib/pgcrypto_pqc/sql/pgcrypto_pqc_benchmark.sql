-- FortressQL PQC: Performance benchmark regression tests
-- Measures timing of KEM keygen, encapsulate/decapsulate, and sign/verify.
-- Note: timing values will vary by hardware; this test verifies operations
-- complete successfully and reports elapsed time via NOTICE.

CREATE EXTENSION pgcrypto_pqc;

-- ============================================================
-- Benchmark 1: ML-KEM-768 key generation (100 ops)
-- ============================================================

DO $$
DECLARE
  start_time timestamptz;
  elapsed interval;
  i int;
  keys RECORD;
BEGIN
  start_time := clock_timestamp();
  FOR i IN 1..100 LOOP
    SELECT * INTO keys FROM pqc_kem_keygen('ML-KEM-768');
  END LOOP;
  elapsed := clock_timestamp() - start_time;
  RAISE NOTICE 'ML-KEM-768 keygen: 100 ops in % ms', extract(milliseconds from elapsed)::int;
END $$;

-- ============================================================
-- Benchmark 2: ML-KEM-768 encapsulate/decapsulate (100 ops)
-- ============================================================

DO $$
DECLARE
  start_time timestamptz;
  elapsed interval;
  i int;
  keys RECORD;
  encap RECORD;
  recovered bytea;
BEGIN
  SELECT * INTO keys FROM pqc_kem_keygen('ML-KEM-768');
  start_time := clock_timestamp();
  FOR i IN 1..100 LOOP
    SELECT * INTO encap FROM pqc_kem_encapsulate(keys.public_key, 'ML-KEM-768');
    recovered := pqc_kem_decapsulate(encap.ciphertext, keys.secret_key, 'ML-KEM-768');
  END LOOP;
  elapsed := clock_timestamp() - start_time;
  RAISE NOTICE 'ML-KEM-768 encap/decap: 100 ops in % ms', extract(milliseconds from elapsed)::int;
END $$;

-- ============================================================
-- Benchmark 3: ML-DSA-65 key generation (100 ops)
-- ============================================================

DO $$
DECLARE
  start_time timestamptz;
  elapsed interval;
  i int;
  keys RECORD;
BEGIN
  start_time := clock_timestamp();
  FOR i IN 1..100 LOOP
    SELECT * INTO keys FROM pqc_sig_keygen('ML-DSA-65');
  END LOOP;
  elapsed := clock_timestamp() - start_time;
  RAISE NOTICE 'ML-DSA-65 keygen: 100 ops in % ms', extract(milliseconds from elapsed)::int;
END $$;

-- ============================================================
-- Benchmark 4: ML-DSA-65 sign/verify (100 ops)
-- ============================================================

DO $$
DECLARE
  start_time timestamptz;
  elapsed interval;
  i int;
  keys RECORD;
  sig bytea;
  msg bytea := convert_to('Benchmark message for sign/verify timing', 'UTF8');
  valid boolean;
BEGIN
  SELECT * INTO keys FROM pqc_sig_keygen('ML-DSA-65');
  start_time := clock_timestamp();
  FOR i IN 1..100 LOOP
    sig := pqc_sign(msg, keys.secret_key, 'ML-DSA-65');
    valid := pqc_verify(msg, sig, keys.public_key, 'ML-DSA-65');
  END LOOP;
  elapsed := clock_timestamp() - start_time;
  RAISE NOTICE 'ML-DSA-65 sign/verify: 100 ops in % ms', extract(milliseconds from elapsed)::int;
END $$;

-- ============================================================
-- Benchmark 5: Hybrid encrypt/decrypt (50 ops)
-- ============================================================

DO $$
DECLARE
  start_time timestamptz;
  elapsed interval;
  i int;
  enc RECORD;
  plaintext bytea := convert_to('Benchmark plaintext for hybrid encryption timing test', 'UTF8');
  decrypted bytea;
BEGIN
  start_time := clock_timestamp();
  FOR i IN 1..50 LOOP
    SELECT * INTO enc FROM pqc_encrypt(plaintext, 'ML-KEM-768');
    decrypted := pqc_decrypt(enc.encrypted_data, enc.encapsulated_key,
                             enc.secret_key, 'ML-KEM-768');
  END LOOP;
  elapsed := clock_timestamp() - start_time;
  RAISE NOTICE 'Hybrid encrypt/decrypt: 50 ops in % ms', extract(milliseconds from elapsed)::int;
END $$;

-- Report completion
SELECT 'PQC benchmark suite completed' AS status;

-- ============================================================
-- Cleanup
-- ============================================================

DROP EXTENSION pgcrypto_pqc;
