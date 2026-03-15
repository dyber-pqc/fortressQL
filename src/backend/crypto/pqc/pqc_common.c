/*-------------------------------------------------------------------------
 *
 * pqc_common.c
 *	  FortressQL Post-Quantum Cryptography common infrastructure.
 *
 * Implements the algorithm registry, initialization, and secure memory
 * management for the PQC abstraction layer.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/pqc/pqc_common.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "crypto/pqc/pqc_common.h"
#include "utils/memutils.h"

#ifdef USE_PQC
#include <oqs/oqs.h>
#endif

#include <string.h>

/* Initialization state */
static bool pqc_initialized = false;

/*
 * Static algorithm registry.
 *
 * Maps PqcAlgorithm enum values to their liboqs names and metadata.
 * Sizes are populated at init time from liboqs to ensure accuracy.
 */
static PqcAlgorithmInfo pqc_algorithms[] = {
	/* ML-KEM (FIPS 203) - Key Encapsulation */
	{PQC_ALG_ML_KEM_512,  "ML-KEM-512",  "ML-KEM-512",  PQC_TYPE_KEM, 1, 0, 0, 0, 0, 0},
	{PQC_ALG_ML_KEM_768,  "ML-KEM-768",  "ML-KEM-768",  PQC_TYPE_KEM, 3, 0, 0, 0, 0, 0},
	{PQC_ALG_ML_KEM_1024, "ML-KEM-1024", "ML-KEM-1024", PQC_TYPE_KEM, 5, 0, 0, 0, 0, 0},

	/* ML-DSA (FIPS 204) - Digital Signatures */
	{PQC_ALG_ML_DSA_44, "ML-DSA-44", "ML-DSA-44", PQC_TYPE_SIG, 2, 0, 0, 0, 0, 0},
	{PQC_ALG_ML_DSA_65, "ML-DSA-65", "ML-DSA-65", PQC_TYPE_SIG, 3, 0, 0, 0, 0, 0},
	{PQC_ALG_ML_DSA_87, "ML-DSA-87", "ML-DSA-87", PQC_TYPE_SIG, 5, 0, 0, 0, 0, 0},

	/* SLH-DSA (FIPS 205) - Hash-Based Signatures */
	{PQC_ALG_SLH_DSA_SHA2_128S,  "SLH-DSA-SHA2-128s",  "SLH-DSA-SHA2-128s",  PQC_TYPE_SIG, 1, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHA2_128F,  "SLH-DSA-SHA2-128f",  "SLH-DSA-SHA2-128f",  PQC_TYPE_SIG, 1, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHA2_192S,  "SLH-DSA-SHA2-192s",  "SLH-DSA-SHA2-192s",  PQC_TYPE_SIG, 3, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHA2_192F,  "SLH-DSA-SHA2-192f",  "SLH-DSA-SHA2-192f",  PQC_TYPE_SIG, 3, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHA2_256S,  "SLH-DSA-SHA2-256s",  "SLH-DSA-SHA2-256s",  PQC_TYPE_SIG, 5, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHA2_256F,  "SLH-DSA-SHA2-256f",  "SLH-DSA-SHA2-256f",  PQC_TYPE_SIG, 5, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHAKE_128S, "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s", PQC_TYPE_SIG, 1, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHAKE_128F, "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f", PQC_TYPE_SIG, 1, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHAKE_192S, "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s", PQC_TYPE_SIG, 3, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHAKE_192F, "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192f", PQC_TYPE_SIG, 3, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHAKE_256S, "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s", PQC_TYPE_SIG, 5, 0, 0, 0, 0, 0},
	{PQC_ALG_SLH_DSA_SHAKE_256F, "SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256f", PQC_TYPE_SIG, 5, 0, 0, 0, 0, 0},
};

StaticAssertDecl(lengthof(pqc_algorithms) == PQC_ALG_COUNT,
				 "pqc_algorithms array must match PqcAlgorithm enum count");

#ifdef USE_PQC
/*
 * Populate KEM algorithm sizes from liboqs at init time.
 */
static void
pqc_populate_kem_info(PqcAlgorithmInfo *info)
{
	OQS_KEM    *kem;

	kem = OQS_KEM_new(info->oqs_name);
	if (kem == NULL)
	{
		elog(WARNING, "FortressQL: liboqs does not support KEM algorithm \"%s\"",
			 info->oqs_name);
		return;
	}

	info->public_key_len = kem->length_public_key;
	info->secret_key_len = kem->length_secret_key;
	info->ciphertext_len = kem->length_ciphertext;
	info->shared_secret_len = kem->length_shared_secret;

	OQS_KEM_free(kem);
}

/*
 * Populate signature algorithm sizes from liboqs at init time.
 */
static void
pqc_populate_sig_info(PqcAlgorithmInfo *info)
{
	OQS_SIG    *sig;

	sig = OQS_SIG_new(info->oqs_name);
	if (sig == NULL)
	{
		elog(WARNING, "FortressQL: liboqs does not support signature algorithm \"%s\"",
			 info->oqs_name);
		return;
	}

	info->public_key_len = sig->length_public_key;
	info->secret_key_len = sig->length_secret_key;
	info->signature_len = sig->length_signature;

	OQS_SIG_free(sig);
}
#endif							/* USE_PQC */

/*
 * pqc_init
 *
 * Initialize the PQC subsystem. Must be called before any PQC operations.
 * Safe to call multiple times; subsequent calls are no-ops.
 */
PqcStatus
pqc_init(void)
{
#ifdef USE_PQC
	int			i;

	if (pqc_initialized)
		return PQC_SUCCESS;

	/* Initialize liboqs */
	OQS_init();

	/* Populate algorithm sizes from liboqs */
	for (i = 0; i < PQC_ALG_COUNT; i++)
	{
		if (pqc_algorithms[i].type == PQC_TYPE_KEM)
			pqc_populate_kem_info(&pqc_algorithms[i]);
		else
			pqc_populate_sig_info(&pqc_algorithms[i]);
	}

	pqc_initialized = true;
	elog(LOG, "FortressQL: Post-Quantum Cryptography initialized (liboqs)");
	return PQC_SUCCESS;
#else
	return PQC_ERROR_NOT_SUPPORTED;
#endif
}

/*
 * pqc_cleanup
 *
 * Shut down the PQC subsystem and release liboqs resources.
 */
void
pqc_cleanup(void)
{
#ifdef USE_PQC
	if (!pqc_initialized)
		return;

	OQS_destroy();
	pqc_initialized = false;
#endif
}

/*
 * pqc_is_available
 *
 * Returns true if PQC support is compiled in and initialized.
 */
bool
pqc_is_available(void)
{
#ifdef USE_PQC
	return pqc_initialized;
#else
	return false;
#endif
}

/*
 * pqc_get_algorithm_info
 *
 * Returns metadata for the specified algorithm, or NULL if invalid.
 */
const PqcAlgorithmInfo *
pqc_get_algorithm_info(PqcAlgorithm alg)
{
	if (alg < 0 || alg >= PQC_ALG_COUNT)
		return NULL;
	return &pqc_algorithms[alg];
}

/*
 * pqc_algorithm_name
 *
 * Returns the display name for the algorithm, or "unknown".
 */
const char *
pqc_algorithm_name(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info = pqc_get_algorithm_info(alg);

	return info ? info->name : "unknown";
}

/*
 * pqc_algorithm_from_name
 *
 * Looks up an algorithm by name (case-insensitive).
 * Returns PQC_ALG_COUNT if not found.
 */
PqcAlgorithm
pqc_algorithm_from_name(const char *name)
{
	int			i;

	if (name == NULL)
		return PQC_ALG_COUNT;

	for (i = 0; i < PQC_ALG_COUNT; i++)
	{
		if (pg_strcasecmp(pqc_algorithms[i].name, name) == 0)
			return pqc_algorithms[i].alg_id;
	}

	return PQC_ALG_COUNT;
}

/*
 * pqc_algorithm_is_kem / pqc_algorithm_is_sig
 *
 * Type predicates for algorithm classification.
 */
bool
pqc_algorithm_is_kem(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info = pqc_get_algorithm_info(alg);

	return info && info->type == PQC_TYPE_KEM;
}

bool
pqc_algorithm_is_sig(PqcAlgorithm alg)
{
	const PqcAlgorithmInfo *info = pqc_get_algorithm_info(alg);

	return info && info->type == PQC_TYPE_SIG;
}

/*
 * pqc_secure_free
 *
 * Securely zeroes memory before freeing it. Essential for secret key
 * material that must not persist in freed memory pages.
 */
void
pqc_secure_free(void *ptr, size_t len)
{
	if (ptr == NULL)
		return;

	/* Use explicit_bzero where available, otherwise volatile memset */
#ifdef HAVE_EXPLICIT_BZERO
	explicit_bzero(ptr, len);
#else
	{
		volatile uint8 *p = (volatile uint8 *) ptr;

		while (len--)
			*p++ = 0;
	}
#endif

	pfree(ptr);
}
