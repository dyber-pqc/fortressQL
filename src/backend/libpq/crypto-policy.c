/*-------------------------------------------------------------------------
 *
 * crypto-policy.c
 *	  FortressQL: Crypto Agility Engine - policy-based configuration.
 *
 *	  Implements the crypto_policy GUC, which cascades settings for
 *	  password_encryption, ssl_pqc_mode, ssl_pqc_groups, and
 *	  ssl_pqc_sigalgs based on a chosen policy profile.
 *
 * Copyright (c) 2024, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/libpq/crypto-policy.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#ifdef USE_PQC

#include "libpq/libpq.h"
#include "utils/guc.h"

/* Global variable backing the crypto_policy GUC */
int crypto_policy = CRYPTO_POLICY_CUSTOM;

/*
 * check_crypto_policy
 *
 * Validate that the requested crypto policy can be applied.  Non-legacy
 * and non-custom policies require PQC support to be available (which it
 * is, since this file is only compiled when liboqs is found).
 */
bool
check_crypto_policy(int *newval, void **extra, GucSource source)
{
	switch ((CryptoPolicy) *newval)
	{
		case CRYPTO_POLICY_CUSTOM:
		case CRYPTO_POLICY_LEGACY:
			/* Always valid */
			return true;

		case CRYPTO_POLICY_TRANSITIONAL:
		case CRYPTO_POLICY_FIPS_PQC_LEVEL3:
		case CRYPTO_POLICY_FIPS_PQC_LEVEL5:
			/*
			 * These policies require PQC support.  Since this file is only
			 * compiled when USE_PQC is defined (liboqs found), PQC is
			 * available.  If we ever need runtime detection, add it here.
			 */
			return true;

		default:
			GUC_check_errdetail("Unrecognized crypto policy value: %d.", *newval);
			return false;
	}
}

/*
 * assign_crypto_policy
 *
 * Cascade dependent GUC settings based on the selected policy.  Uses
 * SetConfigOption() so that the cascaded values are applied with
 * PGC_S_OVERRIDE source, ensuring the policy takes precedence.
 */
void
assign_crypto_policy(int newval, void *extra)
{
	switch ((CryptoPolicy) newval)
	{
		case CRYPTO_POLICY_CUSTOM:
			/* No cascading - administrator manages individual settings */
			break;

		case CRYPTO_POLICY_LEGACY:
			SetConfigOption("password_encryption", "md5",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			SetConfigOption("ssl_pqc_mode", "off",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			break;

		case CRYPTO_POLICY_TRANSITIONAL:
			SetConfigOption("password_encryption", "scram-sha-256",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			SetConfigOption("ssl_pqc_mode", "hybrid",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			SetConfigOption("ssl_pqc_groups", "X25519MLKEM768:X25519:prime256v1",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			SetConfigOption("ssl_pqc_sigalgs", "",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			break;

		case CRYPTO_POLICY_FIPS_PQC_LEVEL3:
			SetConfigOption("password_encryption", "scram-sha-384",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			SetConfigOption("ssl_pqc_mode", "hybrid",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			SetConfigOption("ssl_pqc_groups", "MLKEM768",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			SetConfigOption("ssl_pqc_sigalgs", "MLDSA65",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			break;

		case CRYPTO_POLICY_FIPS_PQC_LEVEL5:
			SetConfigOption("password_encryption", "scram-sha-384",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			SetConfigOption("ssl_pqc_mode", "pqc-only",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			SetConfigOption("ssl_pqc_groups", "MLKEM1024",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			SetConfigOption("ssl_pqc_sigalgs", "MLDSA87",
							PGC_SIGHUP, PGC_S_OVERRIDE);
			break;
	}
}

#endif							/* USE_PQC */
