/*-------------------------------------------------------------------------
 *
 * pqc_sig.h
 *	  FortressQL Post-Quantum Digital Signature API.
 *
 * Provides a clean PostgreSQL-native interface over liboqs signature
 * operations. Supports ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/include/crypto/pqc/pqc_sig.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PQC_SIG_H
#define PQC_SIG_H

#include "crypto/pqc/pqc_common.h"

/* Opaque signature context - wraps OQS_SIG internally */
typedef struct PqcSigContext PqcSigContext;

/*
 * Create a new signature context for the specified algorithm.
 * Raises ERROR on invalid algorithm or initialization failure.
 */
extern PqcSigContext *pqc_sig_new(PqcAlgorithm alg);

/*
 * Free a signature context. Securely wipes internal state.
 */
extern void pqc_sig_free(PqcSigContext *ctx);

/*
 * Generate a signature key pair.
 *
 * Allocates public_key and secret_key via palloc(). Caller is responsible
 * for freeing public_key with pfree() and secret_key with pqc_secure_free().
 *
 * Returns PQC_SUCCESS on success, PQC_ERROR_CRYPTO_FAILURE on failure.
 */
extern PqcStatus pqc_sig_keygen(PqcSigContext *ctx,
								uint8 **public_key, size_t *public_key_len,
								uint8 **secret_key, size_t *secret_key_len);

/*
 * Sign a message.
 *
 * Produces a signature over the given message using the secret key.
 * The signature is palloc'd; signature_len is set to the actual length.
 *
 * Returns PQC_SUCCESS on success, PQC_ERROR_CRYPTO_FAILURE on failure.
 */
extern PqcStatus pqc_sig_sign(PqcSigContext *ctx,
							  const uint8 *message, size_t message_len,
							  const uint8 *secret_key, size_t secret_key_len,
							  uint8 **signature, size_t *signature_len);

/*
 * Verify a signature.
 *
 * Returns PQC_SUCCESS if the signature is valid, PQC_ERROR_CRYPTO_FAILURE
 * if verification fails (invalid signature).
 */
extern PqcStatus pqc_sig_verify(PqcSigContext *ctx,
								const uint8 *message, size_t message_len,
								const uint8 *signature, size_t signature_len,
								const uint8 *public_key, size_t public_key_len);

/*
 * Size queries - get key/signature sizes without creating a full context.
 * Returns 0 if the algorithm is not a valid signature algorithm.
 */
extern size_t pqc_sig_public_key_len(PqcAlgorithm alg);
extern size_t pqc_sig_secret_key_len(PqcAlgorithm alg);
extern size_t pqc_sig_max_signature_len(PqcAlgorithm alg);

#endif							/* PQC_SIG_H */
