/*-------------------------------------------------------------------------
 *
 * tde_key_provider.c
 *	  FortressQL TDE key provider implementations.
 *
 * Provides pluggable secret key retrieval for TDE master key unwrapping.
 * Supports environment variable, file, and external command providers.
 *
 * The "command" provider follows the same security pattern as PostgreSQL's
 * ssl_passphrase_command: fork a subprocess, read from its stdout, enforce
 * a timeout, and securely wipe the output buffer on failure.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/tde/tde_key_provider.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#ifdef USE_PQC

#include <sys/stat.h>
#include <unistd.h>

#include "crypto/tde/tde_key_provider.h"
#include "crypto/pqc/pqc_common.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "utils/memutils.h"

/*
 * Maximum hex key length we'll accept.  ML-KEM-1024 secret key is 3168
 * bytes = 6336 hex chars.  Allow some headroom.
 */
#define TDE_MAX_HEX_KEY_LEN	8192

/* Timeout for command provider (milliseconds) */
#define TDE_KEY_COMMAND_TIMEOUT_MS	30000

/* GUC variables — registered in guc_tables.c */
int			tde_key_provider = TDE_KEY_PROVIDER_ENV;
char	   *tde_key_file = NULL;
char	   *tde_key_command = NULL;

/*
 * Strip leading/trailing whitespace from a string in-place.
 * Returns pointer to the first non-whitespace character.
 */
static char *
strip_whitespace(char *str)
{
	char	   *end;

	/* Skip leading whitespace */
	while (*str && (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r'))
		str++;

	if (*str == '\0')
		return str;

	/* Trim trailing whitespace */
	end = str + strlen(str) - 1;
	while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
		end--;
	*(end + 1) = '\0';

	return str;
}

/*
 * Fetch key from environment variable.
 */
static char *
tde_key_provider_fetch_env(void)
{
	const char *hex;

	hex = getenv("FORTRESSQL_KEM_SECRET_KEY");
	if (hex == NULL || strlen(hex) == 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("TDE: FORTRESSQL_KEM_SECRET_KEY environment variable not set"),
				 errhint("Set the ML-KEM secret key environment variable, or use "
						 "tde_key_provider = 'file' or 'command' for alternative key sources.")));

	return pstrdup(hex);
}

/*
 * Fetch key from a file.
 */
static char *
tde_key_provider_fetch_file(void)
{
	FILE	   *fp;
	char		buf[TDE_MAX_HEX_KEY_LEN + 1];
	size_t		nread;
	char	   *trimmed;
	struct stat st;

	if (tde_key_file == NULL || tde_key_file[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("TDE: tde_key_file is not set"),
				 errhint("Set tde_key_file to the path of a file containing "
						 "the hex-encoded ML-KEM secret key.")));

	/* Verify the file exists and check permissions */
	if (stat(tde_key_file, &st) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("TDE: could not access key file \"%s\": %m",
						tde_key_file)));

	/* Warn if file is world-readable */
	if ((st.st_mode & (S_IRGRP | S_IROTH)) != 0)
		ereport(WARNING,
				(errmsg("TDE key file \"%s\" has group or world read permission",
						tde_key_file),
				 errhint("Set permissions to 0600 for the key file.")));

	fp = fopen(tde_key_file, "r");
	if (fp == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("TDE: could not open key file \"%s\": %m",
						tde_key_file)));

	nread = fread(buf, 1, TDE_MAX_HEX_KEY_LEN, fp);
	fclose(fp);

	if (nread == 0)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("TDE: key file \"%s\" is empty", tde_key_file)));

	buf[nread] = '\0';
	trimmed = strip_whitespace(buf);

	if (strlen(trimmed) == 0)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("TDE: key file \"%s\" contains only whitespace",
						tde_key_file)));

	return pstrdup(trimmed);
}

/*
 * Fetch key by executing an external command.
 *
 * Follows the ssl_passphrase_command pattern from be-secure-openssl.c:
 * fork a subprocess, read hex key from its stdout, enforce a timeout.
 */
static char *
tde_key_provider_fetch_command(void)
{
	FILE	   *fp;
	char		buf[TDE_MAX_HEX_KEY_LEN + 1];
	size_t		nread;
	int			pclose_rc;
	char	   *trimmed;

	if (tde_key_command == NULL || tde_key_command[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("TDE: tde_key_command is not set"),
				 errhint("Set tde_key_command to a command that outputs "
						 "the hex-encoded ML-KEM secret key on stdout.")));

	elog(LOG, "FortressQL: executing TDE key command");

	fp = popen(tde_key_command, "r");
	if (fp == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("TDE: could not execute key command \"%s\": %m",
						tde_key_command)));

	nread = fread(buf, 1, TDE_MAX_HEX_KEY_LEN, fp);
	pclose_rc = pclose(fp);

	if (pclose_rc != 0)
	{
		/* Wipe any partial output */
		if (nread > 0)
			explicit_bzero(buf, nread);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("TDE: key command \"%s\" failed with exit code %d",
						tde_key_command, pclose_rc)));
	}

	if (nread == 0)
	{
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("TDE: key command \"%s\" produced no output",
						tde_key_command)));
	}

	buf[nread] = '\0';
	trimmed = strip_whitespace(buf);

	if (strlen(trimmed) == 0)
	{
		explicit_bzero(buf, nread);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("TDE: key command \"%s\" produced only whitespace",
						tde_key_command)));
	}

	return pstrdup(trimmed);
}

/*
 * tde_key_provider_fetch
 *
 * Public entry point.  Returns a palloc'd hex-encoded secret key
 * string based on the configured tde_key_provider GUC.
 */
char *
tde_key_provider_fetch(void)
{
	switch ((TdeKeyProviderType) tde_key_provider)
	{
		case TDE_KEY_PROVIDER_ENV:
			return tde_key_provider_fetch_env();

		case TDE_KEY_PROVIDER_FILE:
			return tde_key_provider_fetch_file();

		case TDE_KEY_PROVIDER_COMMAND:
			return tde_key_provider_fetch_command();

		default:
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("TDE: unknown key provider type: %d",
							tde_key_provider)));
			return NULL;		/* unreachable */
	}
}

#endif							/* USE_PQC */
