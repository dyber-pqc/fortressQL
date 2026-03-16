/*-------------------------------------------------------------------------
 *
 * tde_key_provider.h
 *	  FortressQL TDE key provider interface.
 *
 * Abstracts the retrieval of the ML-KEM secret key used to unwrap the
 * TDE master key.  Three providers are supported:
 *
 *   - env:     Read from FORTRESSQL_KEM_SECRET_KEY environment variable
 *              (default, backward-compatible).
 *   - file:    Read hex-encoded key from a file specified by tde_key_file.
 *   - command: Execute a command and read hex key from its stdout,
 *              following the ssl_passphrase_command pattern.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/include/crypto/tde/tde_key_provider.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TDE_KEY_PROVIDER_H
#define TDE_KEY_PROVIDER_H

#include "postgres.h"

#ifdef USE_PQC

/* Key provider types */
typedef enum TdeKeyProviderType
{
	TDE_KEY_PROVIDER_ENV = 0,		/* environment variable (default) */
	TDE_KEY_PROVIDER_FILE,			/* read hex from file path */
	TDE_KEY_PROVIDER_COMMAND,		/* execute command, read hex from stdout */
} TdeKeyProviderType;

/* GUC variables */
extern int tde_key_provider;
extern char *tde_key_file;
extern char *tde_key_command;

/*
 * Fetch the ML-KEM secret key (hex-encoded) using the configured provider.
 *
 * Returns a palloc'd string containing the hex-encoded secret key.
 * The caller is responsible for securely freeing the returned string
 * (use pqc_secure_free or explicit_bzero + pfree).
 *
 * Raises ERROR on failure (missing key, command failure, etc.).
 */
extern char *tde_key_provider_fetch(void);

#endif							/* USE_PQC */

#endif							/* TDE_KEY_PROVIDER_H */
