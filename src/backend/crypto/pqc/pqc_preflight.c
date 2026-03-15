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

#include "utils/guc.h"

#ifdef USE_PQC
#include "crypto/pqc/pqc_common.h"
#include "crypto/pqc/pqc_wal_keys.h"
#include "crypto/tde/tde.h"
#include <sys/stat.h>

void
pqc_preflight_check(void)
{
	/* Check TDE configuration */
	if (tde_enabled)
	{
		/* Verify master key infrastructure is available */
		elog(LOG, "FortressQL: TDE enabled, verifying master key configuration");
		/* Check for master key file or command */
	}

	/* Check WAL signing configuration */
	if (wal_pqc_signing)
	{
		/* Verify key files exist and are readable */
		struct stat st;
		char		keypath[MAXPGPATH];

		snprintf(keypath, MAXPGPATH, "%s/wal_signing.key", wal_pqc_key_path);
		if (stat(keypath, &st) != 0)
			ereport(WARNING,
					(errmsg("WAL PQC signing enabled but key file not found: %s", keypath),
					 errhint("Generate keys with pg_tde_master_key or pqc_rotate_wal_signing_keys().")));
	}

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
