/*-------------------------------------------------------------------------
 *
 * pqc_common.h
 *	  FortressQL Post-Quantum Cryptography common types and declarations.
 *
 * This header defines the core types, algorithm registry, and utility
 * functions for the PQC abstraction layer that wraps liboqs.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/include/crypto/pqc/pqc_common.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PQC_COMMON_H
#define PQC_COMMON_H

#include "postgres.h"

/*
 * PQC Algorithm identifiers.
 *
 * These map 1:1 to NIST-standardized algorithms in liboqs.
 * FIPS 203: ML-KEM (Module-Lattice Key Encapsulation Mechanism)
 * FIPS 204: ML-DSA (Module-Lattice Digital Signature Algorithm)
 * FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
 */
typedef enum PqcAlgorithm
{
	/* ML-KEM variants (FIPS 203) - Key Encapsulation */
	PQC_ALG_ML_KEM_512 = 0,
	PQC_ALG_ML_KEM_768,			/* NIST Level 3 - recommended default */
	PQC_ALG_ML_KEM_1024,

	/* ML-DSA variants (FIPS 204) - Digital Signatures */
	PQC_ALG_ML_DSA_44,
	PQC_ALG_ML_DSA_65,				/* NIST Level 3 - recommended default */
	PQC_ALG_ML_DSA_87,

	/* SLH-DSA variants (FIPS 205) - Hash-Based Signatures */
	PQC_ALG_SLH_DSA_SHA2_128S,
	PQC_ALG_SLH_DSA_SHA2_128F,
	PQC_ALG_SLH_DSA_SHA2_192S,
	PQC_ALG_SLH_DSA_SHA2_192F,
	PQC_ALG_SLH_DSA_SHA2_256S,
	PQC_ALG_SLH_DSA_SHA2_256F,
	PQC_ALG_SLH_DSA_SHAKE_128S,
	PQC_ALG_SLH_DSA_SHAKE_128F,
	PQC_ALG_SLH_DSA_SHAKE_192S,
	PQC_ALG_SLH_DSA_SHAKE_192F,
	PQC_ALG_SLH_DSA_SHAKE_256S,
	PQC_ALG_SLH_DSA_SHAKE_256F,

	PQC_ALG_COUNT					/* must be last */
} PqcAlgorithm;

/* Status codes for PQC operations */
typedef enum PqcStatus
{
	PQC_SUCCESS = 0,
	PQC_ERROR = -1,
	PQC_ERROR_NOT_SUPPORTED = -2,
	PQC_ERROR_INVALID_PARAM = -3,
	PQC_ERROR_MEMORY = -4,
	PQC_ERROR_CRYPTO_FAILURE = -5,
} PqcStatus;

/* Algorithm type classification */
typedef enum PqcAlgType
{
	PQC_TYPE_KEM = 0,
	PQC_TYPE_SIG,
} PqcAlgType;

/* Algorithm metadata - populated from liboqs at init time */
typedef struct PqcAlgorithmInfo
{
	PqcAlgorithm alg_id;
	const char *name;				/* display name, e.g. "ML-KEM-768" */
	const char *oqs_name;			/* liboqs identifier */
	PqcAlgType	type;				/* KEM or SIG */
	int			nist_level;			/* NIST security level: 1, 2, 3, or 5 */
	size_t		public_key_len;
	size_t		secret_key_len;

	/* KEM-specific */
	size_t		ciphertext_len;
	size_t		shared_secret_len;

	/* SIG-specific */
	size_t		signature_len;		/* max signature length */
} PqcAlgorithmInfo;

/*
 * Initialization and lifecycle.
 *
 * pqc_init() must be called before any PQC operations. It initializes
 * the liboqs library and populates the algorithm registry. Safe to call
 * multiple times.
 */
extern PqcStatus pqc_init(void);
extern void pqc_cleanup(void);
extern bool pqc_is_available(void);

/*
 * Algorithm registry - query available algorithms.
 */
extern const PqcAlgorithmInfo *pqc_get_algorithm_info(PqcAlgorithm alg);
extern const char *pqc_algorithm_name(PqcAlgorithm alg);
extern PqcAlgorithm pqc_algorithm_from_name(const char *name);
extern bool pqc_algorithm_is_kem(PqcAlgorithm alg);
extern bool pqc_algorithm_is_sig(PqcAlgorithm alg);

/*
 * Secure memory management.
 *
 * pqc_secure_free() zeroes memory before freeing it, preventing
 * secret key material from lingering in freed pages.
 */
extern void pqc_secure_free(void *ptr, size_t len);

#endif							/* PQC_COMMON_H */
