/*-------------------------------------------------------------------------
 *
 * pqc_sig.c
 *	  FortressQL Post-Quantum Digital Signature implementation.
 *
 * Wraps liboqs OQS_SIG operations with PostgreSQL memory management
 * and error handling. Supports ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/pqc/pqc_sig.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "crypto/pqc/pqc_sig.h"

#ifdef USE_PQC
#include <oqs/oqs.h>

/*
 * Internal signature context structure.
 */
struct PqcSigContext
{
	OQS_SIG    *oqs_sig;
	PqcAlgorithm alg;
};

/*
 * pqc_sig_new
 *
 * Create a signature context for the specified algorithm.
 */
PqcSigContext *
pqc_sig_new(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info;
	OQS_SIG    *oqs_sig;
	PqcSigContext *ctx;

	info = pqc_get_algorithm_info(alg);
	if (info == NULL || info->type != PQC_TYPE_SIG)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid signature algorithm: %d", (int) alg),
				 errhint("Valid algorithms: ML-DSA-44, ML-DSA-65, ML-DSA-87, "
						 "SLH-DSA-SHA2-*, SLH-DSA-SHAKE-*")));

	/* Ensure PQC subsystem is initialized */
	if (!pqc_is_available())
	{
		if (pqc_init() != PQC_SUCCESS)
			ereport(ERROR,
					(errcode(ERRCODE_SYSTEM_ERROR),
					 errmsg("failed to initialize FortressQL PQC subsystem")));
	}

	oqs_sig = OQS_SIG_new(info->oqs_name);
	if (oqs_sig == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("liboqs failed to initialize signature algorithm \"%s\"",
						info->name),
				 errhint("Ensure liboqs was compiled with support for %s.",
						 info->name)));

	ctx = (PqcSigContext *) palloc(sizeof(PqcSigContext));
	ctx->oqs_sig = oqs_sig;
	ctx->alg = alg;

	return ctx;
}

/*
 * pqc_sig_free
 *
 * Free a signature context and its liboqs resources.
 */
void
pqc_sig_free(PqcSigContext *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->oqs_sig)
		OQS_SIG_free(ctx->oqs_sig);

	pfree(ctx);
}

/*
 * pqc_sig_keygen
 *
 * Generate a signature key pair. Allocates output buffers with palloc().
 */
PqcStatus
pqc_sig_keygen(PqcSigContext *ctx,
			   uint8 **public_key, size_t *public_key_len,
			   uint8 **secret_key, size_t *secret_key_len)
{
	OQS_SIG    *sig = ctx->oqs_sig;

	*public_key_len = sig->length_public_key;
	*secret_key_len = sig->length_secret_key;
	*public_key = (uint8 *) palloc(sig->length_public_key);
	*secret_key = (uint8 *) palloc(sig->length_secret_key);

	if (OQS_SIG_keypair(sig, *public_key, *secret_key) != OQS_SUCCESS)
	{
		pfree(*public_key);
		pqc_secure_free(*secret_key, sig->length_secret_key);
		*public_key = NULL;
		*secret_key = NULL;
		return PQC_ERROR_CRYPTO_FAILURE;
	}

	return PQC_SUCCESS;
}

/*
 * pqc_sig_sign
 *
 * Sign a message using the secret key. Allocates signature with palloc().
 */
PqcStatus
pqc_sig_sign(PqcSigContext *ctx,
			 const uint8 *message, size_t message_len,
			 const uint8 *secret_key, size_t secret_key_len,
			 uint8 **signature, size_t *signature_len)
{
	OQS_SIG    *sig = ctx->oqs_sig;

	/* Validate secret key length */
	if (secret_key_len != sig->length_secret_key)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid secret key length for %s: got %zu, expected %zu",
						pqc_algorithm_name(ctx->alg),
						secret_key_len,
						sig->length_secret_key)));

	/* Allocate max signature size; actual size returned in signature_len */
	*signature = (uint8 *) palloc(sig->length_signature);

	if (OQS_SIG_sign(sig, *signature, signature_len,
					 message, message_len,
					 secret_key) != OQS_SUCCESS)
	{
		pfree(*signature);
		*signature = NULL;
		*signature_len = 0;
		return PQC_ERROR_CRYPTO_FAILURE;
	}

	pqc_stat_count_sig_sign();
	return PQC_SUCCESS;
}

/*
 * pqc_sig_verify
 *
 * Verify a signature over a message using the public key.
 *
 * Returns PQC_SUCCESS if valid, PQC_ERROR_CRYPTO_FAILURE if invalid.
 */
PqcStatus
pqc_sig_verify(PqcSigContext *ctx,
			   const uint8 *message, size_t message_len,
			   const uint8 *signature, size_t signature_len,
			   const uint8 *public_key, size_t public_key_len)
{
	OQS_SIG    *sig = ctx->oqs_sig;

	/* Validate public key length */
	if (public_key_len != sig->length_public_key)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid public key length for %s: got %zu, expected %zu",
						pqc_algorithm_name(ctx->alg),
						public_key_len,
						sig->length_public_key)));

	if (OQS_SIG_verify(sig, message, message_len,
					   signature, signature_len,
					   public_key) != OQS_SUCCESS)
		return PQC_ERROR_CRYPTO_FAILURE;

	pqc_stat_count_sig_verify();
	return PQC_SUCCESS;
}

/*
 * Size query functions.
 */
size_t
pqc_sig_public_key_len(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info = pqc_get_algorithm_info(alg);
	return (info && info->type == PQC_TYPE_SIG) ? info->public_key_len : 0;
}

size_t
pqc_sig_secret_key_len(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info = pqc_get_algorithm_info(alg);
	return (info && info->type == PQC_TYPE_SIG) ? info->secret_key_len : 0;
}

size_t
pqc_sig_max_signature_len(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info = pqc_get_algorithm_info(alg);
	return (info && info->type == PQC_TYPE_SIG) ? info->signature_len : 0;
}

#else							/* !USE_PQC */

/*
 * Stub implementations when PQC is not compiled in.
 */
PqcSigContext *
pqc_sig_new(PqcAlgorithm alg)
{
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in"),
			 errhint("Rebuild with -Dpqc=enabled and liboqs installed.")));
	return NULL;
}

void pqc_sig_free(PqcSigContext *ctx) {}

PqcStatus
pqc_sig_keygen(PqcSigContext *ctx,
			   uint8 **public_key, size_t *public_key_len,
			   uint8 **secret_key, size_t *secret_key_len)
{
	return PQC_ERROR_NOT_SUPPORTED;
}

PqcStatus
pqc_sig_sign(PqcSigContext *ctx,
			 const uint8 *message, size_t message_len,
			 const uint8 *secret_key, size_t secret_key_len,
			 uint8 **signature, size_t *signature_len)
{
	return PQC_ERROR_NOT_SUPPORTED;
}

PqcStatus
pqc_sig_verify(PqcSigContext *ctx,
			   const uint8 *message, size_t message_len,
			   const uint8 *signature, size_t signature_len,
			   const uint8 *public_key, size_t public_key_len)
{
	return PQC_ERROR_NOT_SUPPORTED;
}

size_t pqc_sig_public_key_len(PqcAlgorithm alg)       { return 0; }
size_t pqc_sig_secret_key_len(PqcAlgorithm alg)       { return 0; }
size_t pqc_sig_max_signature_len(PqcAlgorithm alg)    { return 0; }

#endif							/* USE_PQC */
