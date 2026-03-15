/*-------------------------------------------------------------------------
 *
 * pqc_kem.h
 *	  FortressQL Post-Quantum Key Encapsulation Mechanism (KEM) API.
 *
 * Provides a clean PostgreSQL-native interface over liboqs KEM operations.
 * Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024 (FIPS 203).
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/include/crypto/pqc/pqc_kem.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PQC_KEM_H
#define PQC_KEM_H

#include "crypto/pqc/pqc_common.h"

/* Opaque KEM context - wraps OQS_KEM internally */
typedef struct PqcKemContext PqcKemContext;

/*
 * Create a new KEM context for the specified algorithm.
 * Raises ERROR on invalid algorithm or initialization failure.
 */
extern PqcKemContext *pqc_kem_new(PqcAlgorithm alg);

/*
 * Free a KEM context. Securely wipes internal state.
 */
extern void pqc_kem_free(PqcKemContext *ctx);

/*
 * Generate a KEM key pair.
 *
 * Allocates public_key and secret_key via palloc(). Caller is responsible
 * for freeing public_key with pfree() and secret_key with pqc_secure_free().
 *
 * Returns PQC_SUCCESS on success, PQC_ERROR_CRYPTO_FAILURE on failure.
 */
extern PqcStatus pqc_kem_keygen(PqcKemContext *ctx,
								uint8 **public_key, size_t *public_key_len,
								uint8 **secret_key, size_t *secret_key_len);

/*
 * Encapsulate: generate a shared secret using a public key.
 *
 * Produces a ciphertext (to send to the key holder) and a shared secret
 * (to use for symmetric encryption). Both are palloc'd.
 *
 * Returns PQC_SUCCESS on success, PQC_ERROR_CRYPTO_FAILURE on failure.
 */
extern PqcStatus pqc_kem_encaps(PqcKemContext *ctx,
								const uint8 *public_key, size_t public_key_len,
								uint8 **ciphertext, size_t *ciphertext_len,
								uint8 **shared_secret, size_t *shared_secret_len);

/*
 * Decapsulate: recover the shared secret from a ciphertext.
 *
 * Uses the secret key to recover the same shared secret that was produced
 * by pqc_kem_encaps(). The shared_secret is palloc'd.
 *
 * Returns PQC_SUCCESS on success, PQC_ERROR_CRYPTO_FAILURE on failure.
 */
extern PqcStatus pqc_kem_decaps(PqcKemContext *ctx,
								const uint8 *ciphertext, size_t ciphertext_len,
								const uint8 *secret_key, size_t secret_key_len,
								uint8 **shared_secret, size_t *shared_secret_len);

/*
 * Size queries - get key/ciphertext sizes without creating a full context.
 * Returns 0 if the algorithm is not a valid KEM.
 */
extern size_t pqc_kem_public_key_len(PqcAlgorithm alg);
extern size_t pqc_kem_secret_key_len(PqcAlgorithm alg);
extern size_t pqc_kem_ciphertext_len(PqcAlgorithm alg);
extern size_t pqc_kem_shared_secret_len(PqcAlgorithm alg);

#endif							/* PQC_KEM_H */
