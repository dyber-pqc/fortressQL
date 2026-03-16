-- FortressQL PQC Performance Benchmark (CI)
-- Produces timing data for key PQC operations

\timing on

-- ML-KEM-768 keygen (10 iterations)
DO $$
DECLARE
  i int;
  t_start timestamp;
  t_end timestamp;
BEGIN
  t_start := clock_timestamp();
  FOR i IN 1..10 LOOP
    PERFORM pqc_kem_keygen('ML-KEM-768');
  END LOOP;
  t_end := clock_timestamp();
  RAISE NOTICE 'ML-KEM-768 keygen x10: % ms', extract(milliseconds from t_end - t_start);
END $$;

-- ML-KEM-768 encapsulate+decapsulate (10 iterations)
DO $$
DECLARE
  i int;
  keys record;
  enc record;
  t_start timestamp;
  t_end timestamp;
BEGIN
  SELECT * INTO keys FROM pqc_kem_keygen('ML-KEM-768');
  t_start := clock_timestamp();
  FOR i IN 1..10 LOOP
    SELECT * INTO enc FROM pqc_kem_encapsulate(keys.public_key, 'ML-KEM-768');
    PERFORM pqc_kem_decapsulate(enc.ciphertext, keys.secret_key, 'ML-KEM-768');
  END LOOP;
  t_end := clock_timestamp();
  RAISE NOTICE 'ML-KEM-768 encap+decap x10: % ms', extract(milliseconds from t_end - t_start);
END $$;

-- ML-DSA-65 keygen (10 iterations)
DO $$
DECLARE
  i int;
  t_start timestamp;
  t_end timestamp;
BEGIN
  t_start := clock_timestamp();
  FOR i IN 1..10 LOOP
    PERFORM pqc_sig_keygen('ML-DSA-65');
  END LOOP;
  t_end := clock_timestamp();
  RAISE NOTICE 'ML-DSA-65 keygen x10: % ms', extract(milliseconds from t_end - t_start);
END $$;

-- ML-DSA-65 sign+verify (10 iterations)
DO $$
DECLARE
  i int;
  keys record;
  sig bytea;
  msg bytea := 'FortressQL benchmark message for CI testing'::bytea;
  t_start timestamp;
  t_end timestamp;
BEGIN
  SELECT * INTO keys FROM pqc_sig_keygen('ML-DSA-65');
  t_start := clock_timestamp();
  FOR i IN 1..10 LOOP
    SELECT pqc_sign(msg, keys.secret_key, 'ML-DSA-65') INTO sig;
    PERFORM pqc_verify(msg, sig, keys.public_key, 'ML-DSA-65');
  END LOOP;
  t_end := clock_timestamp();
  RAISE NOTICE 'ML-DSA-65 sign+verify x10: % ms', extract(milliseconds from t_end - t_start);
END $$;

-- Column encryption (10 iterations with 1KB data)
DO $$
DECLARE
  i int;
  enc record;
  t_start timestamp;
  t_end timestamp;
  test_data bytea := repeat('X', 1024)::bytea;
BEGIN
  t_start := clock_timestamp();
  FOR i IN 1..10 LOOP
    SELECT * INTO enc FROM pqc_encrypt_column(test_data, 'ML-KEM-768');
    PERFORM pqc_decrypt_column(enc.encrypted_data, enc.encapsulated_key, enc.secret_key, 'ML-KEM-768');
  END LOOP;
  t_end := clock_timestamp();
  RAISE NOTICE 'Column encrypt+decrypt (1KB) x10: % ms', extract(milliseconds from t_end - t_start);
END $$;
