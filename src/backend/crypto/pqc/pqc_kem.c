/*-------------------------------------------------------------------------
 *
 * pqc_kem.c
 *	  FortressQL Post-Quantum Key Encapsulation Mechanism implementation.
 *
 * Wraps liboqs OQS_KEM operations with PostgreSQL memory management
 * and error handling. Supports ML-KEM-512/768/1024 (FIPS 203).
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/pqc/pqc_kem.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "crypto/pqc/pqc_kem.h"

#ifdef USE_PQC
#include <oqs/oqs.h>

/*
 * Internal KEM context structure.
 */
struct PqcKemContext
{
	OQS_KEM    *oqs_kem;
	PqcAlgorithm alg;
};

/*
 * pqc_kem_new
 *
 * Create a KEM context for the specified algorithm.
 */
PqcKemContext *
pqc_kem_new(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info;
	OQS_KEM    *oqs_kem;
	PqcKemContext *ctx;

	info = pqc_get_algorithm_info(alg);
	if (info == NULL || info->type != PQC_TYPE_KEM)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid KEM algorithm: %d", (int) alg),
				 errhint("Valid algorithms: ML-KEM-512, ML-KEM-768, ML-KEM-1024")));

	/* Ensure PQC subsystem is initialized */
	if (!pqc_is_available())
	{
		if (pqc_init() != PQC_SUCCESS)
			ereport(ERROR,
					(errcode(ERRCODE_SYSTEM_ERROR),
					 errmsg("failed to initialize FortressQL PQC subsystem")));
	}

	oqs_kem = OQS_KEM_new(info->oqs_name);
	if (oqs_kem == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("liboqs failed to initialize KEM algorithm \"%s\"",
						info->name),
				 errhint("Ensure liboqs was compiled with support for %s.",
						 info->name)));

	ctx = (PqcKemContext *) palloc(sizeof(PqcKemContext));
	ctx->oqs_kem = oqs_kem;
	ctx->alg = alg;

	return ctx;
}

/*
 * pqc_kem_free
 *
 * Free a KEM context and its liboqs resources.
 */
void
pqc_kem_free(PqcKemContext *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->oqs_kem)
		OQS_KEM_free(ctx->oqs_kem);

	pfree(ctx);
}

/*
 * pqc_kem_keygen
 *
 * Generate a KEM key pair. Allocates output buffers with palloc().
 */
PqcStatus
pqc_kem_keygen(PqcKemContext *ctx,
			   uint8 **public_key, size_t *public_key_len,
			   uint8 **secret_key, size_t *secret_key_len)
{
	OQS_KEM    *kem = ctx->oqs_kem;

	*public_key_len = kem->length_public_key;
	*secret_key_len = kem->length_secret_key;
	*public_key = (uint8 *) palloc(kem->length_public_key);
	*secret_key = (uint8 *) palloc(kem->length_secret_key);

	if (OQS_KEM_keypair(kem, *public_key, *secret_key) != OQS_SUCCESS)
	{
		pfree(*public_key);
		pqc_secure_free(*secret_key, kem->length_secret_key);
		*public_key = NULL;
		*secret_key = NULL;
		return PQC_ERROR_CRYPTO_FAILURE;
	}

	return PQC_SUCCESS;
}

/*
 * pqc_kem_encaps
 *
 * Encapsulate: generate shared secret and ciphertext from a public key.
 */
PqcStatus
pqc_kem_encaps(PqcKemContext *ctx,
			   const uint8 *public_key, size_t public_key_len,
			   uint8 **ciphertext, size_t *ciphertext_len,
			   uint8 **shared_secret, size_t *shared_secret_len)
{
	OQS_KEM    *kem = ctx->oqs_kem;

	/* Validate public key length */
	if (public_key_len != kem->length_public_key)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid public key length for %s: got %zu, expected %zu",
						pqc_algorithm_name(ctx->alg),
						public_key_len,
						kem->length_public_key)));

	*ciphertext_len = kem->length_ciphertext;
	*shared_secret_len = kem->length_shared_secret;
	*ciphertext = (uint8 *) palloc(kem->length_ciphertext);
	*shared_secret = (uint8 *) palloc(kem->length_shared_secret);

	if (OQS_KEM_encaps(kem, *ciphertext, *shared_secret, public_key) != OQS_SUCCESS)
	{
		pfree(*ciphertext);
		pqc_secure_free(*shared_secret, kem->length_shared_secret);
		*ciphertext = NULL;
		*shared_secret = NULL;
		return PQC_ERROR_CRYPTO_FAILURE;
	}

	return PQC_SUCCESS;
}

/*
 * pqc_kem_decaps
 *
 * Decapsulate: recover shared secret from ciphertext using secret key.
 */
PqcStatus
pqc_kem_decaps(PqcKemContext *ctx,
			   const uint8 *ciphertext, size_t ciphertext_len,
			   const uint8 *secret_key, size_t secret_key_len,
			   uint8 **shared_secret, size_t *shared_secret_len)
{
	OQS_KEM    *kem = ctx->oqs_kem;

	/* Validate input lengths */
	if (ciphertext_len != kem->length_ciphertext)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid ciphertext length for %s: got %zu, expected %zu",
						pqc_algorithm_name(ctx->alg),
						ciphertext_len,
						kem->length_ciphertext)));

	if (secret_key_len != kem->length_secret_key)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid secret key length for %s: got %zu, expected %zu",
						pqc_algorithm_name(ctx->alg),
						secret_key_len,
						kem->length_secret_key)));

	*shared_secret_len = kem->length_shared_secret;
	*shared_secret = (uint8 *) palloc(kem->length_shared_secret);

	if (OQS_KEM_decaps(kem, *shared_secret, ciphertext, secret_key) != OQS_SUCCESS)
	{
		pqc_secure_free(*shared_secret, kem->length_shared_secret);
		*shared_secret = NULL;
		return PQC_ERROR_CRYPTO_FAILURE;
	}

	return PQC_SUCCESS;
}

/*
 * Size query functions.
 */
size_t
pqc_kem_public_key_len(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info = pqc_get_algorithm_info(alg);
	return (info && info->type == PQC_TYPE_KEM) ? info->public_key_len : 0;
}

size_t
pqc_kem_secret_key_len(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info = pqc_get_algorithm_info(alg);
	return (info && info->type == PQC_TYPE_KEM) ? info->secret_key_len : 0;
}

size_t
pqc_kem_ciphertext_len(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info = pqc_get_algorithm_info(alg);
	return (info && info->type == PQC_TYPE_KEM) ? info->ciphertext_len : 0;
}

size_t
pqc_kem_shared_secret_len(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info = pqc_get_algorithm_info(alg);
	return (info && info->type == PQC_TYPE_KEM) ? info->shared_secret_len : 0;
}

#else							/* !USE_PQC */

/*
 * Stub implementations when PQC is not compiled in.
 */
PqcKemContext *
pqc_kem_new(PqcAlgorithm alg)
{
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in"),
			 errhint("Rebuild with -Dpqc=enabled and liboqs installed.")));
	return NULL;				/* unreachable */
}

void
pqc_kem_free(PqcKemContext *ctx)
{
}

PqcStatus
pqc_kem_keygen(PqcKemContext *ctx,
			   uint8 **public_key, size_t *public_key_len,
			   uint8 **secret_key, size_t *secret_key_len)
{
	return PQC_ERROR_NOT_SUPPORTED;
}

PqcStatus
pqc_kem_encaps(PqcKemContext *ctx,
			   const uint8 *public_key, size_t public_key_len,
			   uint8 **ciphertext, size_t *ciphertext_len,
			   uint8 **shared_secret, size_t *shared_secret_len)
{
	return PQC_ERROR_NOT_SUPPORTED;
}

PqcStatus
pqc_kem_decaps(PqcKemContext *ctx,
			   const uint8 *ciphertext, size_t ciphertext_len,
			   const uint8 *secret_key, size_t secret_key_len,
			   uint8 **shared_secret, size_t *shared_secret_len)
{
	return PQC_ERROR_NOT_SUPPORTED;
}

size_t pqc_kem_public_key_len(PqcAlgorithm alg)   { return 0; }
size_t pqc_kem_secret_key_len(PqcAlgorithm alg)   { return 0; }
size_t pqc_kem_ciphertext_len(PqcAlgorithm alg)   { return 0; }
size_t pqc_kem_shared_secret_len(PqcAlgorithm alg) { return 0; }

#endif							/* USE_PQC */
