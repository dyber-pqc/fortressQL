/*-------------------------------------------------------------------------
 *
 * pqc_preflight.c
 *	  FortressQL Post-Quantum Cryptography startup preflight checks
 *	  and GUC validation hooks.
 *
 * Validates PQC configuration at server startup, ensuring that
 * required key files, master key infrastructure, and algorithm
 * settings are consistent before the server begins accepting
 * connections.
 *
 * Also provides GUC check hooks for PQC-related configuration
 * parameters.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/backend/crypto/pqc/pqc_preflight.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "miscadmin.h"
#include "utils/guc.h"
#include "utils/guc_hooks.h"

#ifdef USE_PQC
#include "crypto/pqc/pqc_common.h"
#include "crypto/pqc/pqc_wal_keys.h"
#include "crypto/tde/tde.h"
#include "libpq/libpq.h"
#include <sys/stat.h>

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#include <openssl/err.h>
#endif

void
pqc_preflight_check(void)
{
	/* Check TDE configuration */
	if (tde_enabled)
	{
		struct stat mk_st;
		char		mk_path[MAXPGPATH];

		elog(LOG, "FortressQL: TDE enabled, verifying master key configuration");

		/* Verify master key file exists */
		snprintf(mk_path, MAXPGPATH, "%s/global/pg_encryption/master.key", DataDir);
		if (stat(mk_path, &mk_st) != 0)
			ereport(WARNING,
					(errmsg("TDE enabled but master key file not found: %s", mk_path),
					 errhint("Run pg_tde_master_key init to create the master key.")));
		else if (mk_st.st_size < (off_t) sizeof(int) * 6)
			ereport(WARNING,
					(errmsg("TDE master key file appears truncated: %s", mk_path)));
	}

	/* Check WAL signing configuration */
	if (wal_pqc_signing)
	{
		if (wal_pqc_key_path == NULL || wal_pqc_key_path[0] == '\0')
		{
			ereport(WARNING,
					(errmsg("WAL PQC signing enabled but wal_pqc_key_path is not set"),
					 errhint("Set wal_pqc_key_path to the directory containing signing keys.")));
		}
		else
		{
			struct stat st;
			char		keypath[MAXPGPATH];

			snprintf(keypath, MAXPGPATH, "%s/wal_signing.key", wal_pqc_key_path);
			if (stat(keypath, &st) != 0)
				ereport(WARNING,
						(errmsg("WAL PQC signing enabled but key file not found: %s", keypath),
						 errhint("Generate keys with pg_tde_master_key or pqc_rotate_wal_signing_keys().")));
			else if (st.st_size == 0)
				ereport(WARNING,
						(errmsg("WAL PQC signing key file is empty: %s", keypath)));

			/* Also check the public key file */
			snprintf(keypath, MAXPGPATH, "%s/wal_signing.pub", wal_pqc_key_path);
			if (stat(keypath, &st) != 0)
				ereport(WARNING,
						(errmsg("WAL PQC signing enabled but public key file not found: %s", keypath)));
			else
			{
				/*
				 * Both key files exist — load them now so that WAL
				 * signing works on the primary without requiring a
				 * manual SQL call.  Use PG_TRY so a load failure is
				 * reported as WARNING, not FATAL.  Forked backends
				 * (including the WAL writer) inherit loaded keys via
				 * fork(), same as walreceiver on the standby.
				 */
				PG_TRY();
				{
					pqc_wal_load_signing_keys();
					elog(LOG, "FortressQL: WAL signing keys loaded at startup");
				}
				PG_CATCH();
				{
					FlushErrorState();
					ereport(WARNING,
							(errmsg("WAL PQC signing enabled but could not load signing keys"),
							 errhint("Check key files in \"%s\" and verify they are valid.",
									 wal_pqc_key_path)));
				}
				PG_END_TRY();
			}
		}
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	/* Check if oqs-provider is available for PQC TLS */
	if (ssl_pqc_mode != PQC_TLS_OFF)
	{
		OSSL_PROVIDER *test_prov = OSSL_PROVIDER_load(NULL, "oqsprovider");
		if (test_prov != NULL)
		{
			OSSL_PROVIDER_unload(test_prov);
			elog(LOG, "FortressQL: oqs-provider available for PQC TLS");
		}
		else
		{
			ereport(LOG,
					(errmsg("FortressQL: oqs-provider not found; PQC TLS requires OpenSSL 3.5+ native support"),
					 errhint("Install oqs-provider or upgrade to OpenSSL 3.5+ for PQC key exchange.")));
			ERR_clear_error();
		}
	}
#endif

	/* Log PQC subsystem status */
	elog(LOG, "FortressQL: PQC subsystem initialized (liboqs available: %s)",
		 pqc_is_available() ? "yes" : "no");
}

/*
 * GUC check hook for wal_pqc_key_path.
 *
 * When wal_pqc_signing is enabled, the key path must not be empty.
 */
bool
check_wal_pqc_key_path(char **newval, void **extra, GucSource source)
{
	if (wal_pqc_signing && (*newval == NULL || (*newval)[0] == '\0'))
	{
		GUC_check_errdetail("wal_pqc_key_path must be set when wal_pqc_signing is enabled.");
		return false;
	}
	return true;
}

#else							/* !USE_PQC */

void
pqc_preflight_check(void)
{
	/* no-op when PQC is not compiled in */
}

/*
 * Stub check hook for wal_pqc_key_path when PQC is not compiled in.
 * This should never be called since the GUC is only registered under
 * USE_PQC, but we provide it to satisfy the linker.
 */
bool
check_wal_pqc_key_path(char **newval, void **extra, GucSource source)
{
	return true;
}

#endif							/* USE_PQC */

/*
 * GUC check hook for ssl_pqc_groups.
 *
 * Basic validation that the string is not empty. This GUC is registered
 * regardless of USE_PQC, so the hook must be available unconditionally.
 */
bool
check_ssl_pqc_groups(char **newval, void **extra, GucSource source)
{
	/* An empty string is only acceptable as a reset-to-default */
	if (*newval != NULL && (*newval)[0] == '\0' && source > PGC_S_DEFAULT)
	{
		GUC_check_errdetail("ssl_pqc_groups must not be empty when explicitly set.");
		return false;
	}
	return true;
}
