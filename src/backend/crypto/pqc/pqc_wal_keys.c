/*-------------------------------------------------------------------------
 *
 * pqc_wal_keys.c
 *	  FortressQL Post-Quantum WAL Signing Key Management.
 *
 * Manages generation, loading, and use of post-quantum digital signature
 * keys for WAL segment signing.  Keys are stored on disk and loaded into
 * static memory at server startup.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/pqc/pqc_wal_keys.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#ifdef USE_PQC

#include <sys/stat.h>
#include <unistd.h>

#include "crypto/pqc/pqc_wal_keys.h"
#include "crypto/pqc/pqc_common.h"
#include "crypto/pqc/pqc_sig.h"
#include "common/file_perm.h"
#include "miscadmin.h"
#include "storage/fd.h"

/* GUC variables */
bool		wal_pqc_signing = false;
int			wal_pqc_signing_algorithm = 0;
char	   *wal_pqc_signing_algorithm_string = NULL;
char	   *wal_pqc_key_path = NULL;
bool		wal_pqc_verify_on_receive = true;

/* Static key material - loaded once at startup */
static uint8 *wal_secret_key = NULL;
static size_t wal_secret_key_len = 0;
static uint8 *wal_public_key = NULL;
static size_t wal_public_key_len = 0;
static PqcAlgorithm wal_sig_algorithm = PQC_ALG_ML_DSA_65;
static bool wal_keys_loaded = false;

#define WAL_SIGNING_KEY_FILE	"wal_signing.key"
#define WAL_SIGNING_PUB_FILE	"wal_signing.pub"

/*
 * Helper: resolve the PqcAlgorithm enum from a string name.
 */
static PqcAlgorithm
pqc_wal_resolve_algorithm(const char *algorithm)
{
	PqcAlgorithm alg;

	alg = pqc_algorithm_from_name(algorithm);
	if (!pqc_algorithm_is_sig(alg))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid WAL signing algorithm: \"%s\"", algorithm),
				 errhint("Use a signature algorithm such as ML-DSA-44, "
						 "ML-DSA-65, or ML-DSA-87.")));
	return alg;
}

/*
 * Helper: read an entire file into a palloc'd buffer.
 *
 * Returns the buffer and sets *len.  Raises ERROR on failure.
 */
static uint8 *
read_key_file(const char *filepath, size_t *len)
{
	FILE	   *fp;
	struct stat st;
	uint8	   *buf;
	size_t		nread;

	if (stat(filepath, &st) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not stat WAL signing key file \"%s\": %m",
						filepath)));

	*len = (size_t) st.st_size;
	if (*len == 0)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("WAL signing key file \"%s\" is empty", filepath)));

	buf = (uint8 *) palloc(*len);

	fp = AllocateFile(filepath, "rb");
	if (fp == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open WAL signing key file \"%s\": %m",
						filepath)));

	nread = fread(buf, 1, *len, fp);
	if (nread != *len)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read WAL signing key file \"%s\": %m",
						filepath)));

	FreeFile(fp);
	return buf;
}

/*
 * Helper: write data to a file with restrictive permissions.
 */
static void
write_key_file(const char *filepath, const uint8 *data, size_t len,
			   int filemode)
{
	FILE	   *fp;
	size_t		nwritten;

	fp = AllocateFile(filepath, "wb");
	if (fp == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not create WAL signing key file \"%s\": %m",
						filepath)));

	nwritten = fwrite(data, 1, len, fp);
	if (nwritten != len)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not write WAL signing key file \"%s\": %m",
						filepath)));

	if (FreeFile(fp) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not close WAL signing key file \"%s\": %m",
						filepath)));

#ifndef WIN32
	if (chmod(filepath, filemode) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not set permissions on \"%s\": %m",
						filepath)));
#endif
}

/*
 * pqc_wal_load_signing_keys
 *
 * Read the secret and public key files from key_path into static buffers.
 */
void
pqc_wal_load_signing_keys(const char *key_path, const char *algorithm)
{
	char		sk_path[MAXPGPATH];
	char		pk_path[MAXPGPATH];

	if (key_path == NULL || key_path[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("wal_pqc_key_path must be set when wal_pqc_signing is enabled")));

	/* Resolve algorithm */
	wal_sig_algorithm = pqc_wal_resolve_algorithm(algorithm);

	/* Build file paths */
	snprintf(sk_path, MAXPGPATH, "%s/%s", key_path, WAL_SIGNING_KEY_FILE);
	snprintf(pk_path, MAXPGPATH, "%s/%s", key_path, WAL_SIGNING_PUB_FILE);

	/* Free any previously loaded keys */
	if (wal_secret_key != NULL)
	{
		pqc_secure_free(wal_secret_key, wal_secret_key_len);
		wal_secret_key = NULL;
		wal_secret_key_len = 0;
	}
	if (wal_public_key != NULL)
	{
		pfree(wal_public_key);
		wal_public_key = NULL;
		wal_public_key_len = 0;
	}

	/* Read key files */
	wal_secret_key = read_key_file(sk_path, &wal_secret_key_len);
	wal_public_key = read_key_file(pk_path, &wal_public_key_len);

	/* Validate key sizes against algorithm expectations */
	{
		size_t		expected_sk = pqc_sig_secret_key_len(wal_sig_algorithm);
		size_t		expected_pk = pqc_sig_public_key_len(wal_sig_algorithm);

		if (expected_sk > 0 && wal_secret_key_len != expected_sk)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("WAL signing secret key has wrong size: "
							"got %zu, expected %zu for %s",
							wal_secret_key_len, expected_sk, algorithm)));

		if (expected_pk > 0 && wal_public_key_len != expected_pk)
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("WAL signing public key has wrong size: "
							"got %zu, expected %zu for %s",
							wal_public_key_len, expected_pk, algorithm)));
	}

	wal_keys_loaded = true;

	ereport(LOG,
			(errmsg("FortressQL: loaded PQC WAL signing keys (%s) from \"%s\"",
					algorithm, key_path)));
}

/*
 * pqc_wal_generate_signing_keys
 *
 * Generate a fresh key pair using liboqs and write to disk.
 */
void
pqc_wal_generate_signing_keys(const char *key_path, const char *algorithm)
{
	PqcSigContext *ctx;
	char		sk_path[MAXPGPATH];
	char		pk_path[MAXPGPATH];
	uint8	   *sk = NULL;
	size_t		sk_len = 0;
	uint8	   *pk = NULL;
	size_t		pk_len = 0;
	PqcStatus	status;

	if (key_path == NULL || key_path[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("wal_pqc_key_path must be set for key generation")));

	wal_sig_algorithm = pqc_wal_resolve_algorithm(algorithm);

	/* Generate key pair */
	ctx = pqc_sig_new(wal_sig_algorithm);
	status = pqc_sig_keygen(ctx, &pk, &pk_len, &sk, &sk_len);
	if (status != PQC_SUCCESS)
	{
		pqc_sig_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("failed to generate PQC WAL signing key pair")));
	}
	pqc_sig_free(ctx);

	/* Write key files */
	snprintf(sk_path, MAXPGPATH, "%s/%s", key_path, WAL_SIGNING_KEY_FILE);
	snprintf(pk_path, MAXPGPATH, "%s/%s", key_path, WAL_SIGNING_PUB_FILE);

	/* Secret key: owner-read only (0600) */
	write_key_file(sk_path, sk, sk_len, 0600);

	/* Public key: owner-read + group/other-read (0644) */
	write_key_file(pk_path, pk, pk_len, 0644);

	ereport(LOG,
			(errmsg("FortressQL: generated PQC WAL signing keys (%s) in \"%s\"",
					algorithm, key_path)));

	/* Load the newly generated keys into memory */
	if (wal_secret_key != NULL)
		pqc_secure_free(wal_secret_key, wal_secret_key_len);
	if (wal_public_key != NULL)
		pfree(wal_public_key);

	wal_secret_key = sk;
	wal_secret_key_len = sk_len;
	wal_public_key = pk;
	wal_public_key_len = pk_len;
	wal_keys_loaded = true;
}

/*
 * pqc_wal_sign_data
 *
 * Sign arbitrary data using the loaded WAL signing secret key.
 *
 * The caller must provide a sig_out buffer large enough for the maximum
 * signature length (use pqc_sig_max_signature_len()).
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_wal_sign_data(const uint8 *data, size_t data_len,
				  uint8 *sig_out, size_t *sig_len)
{
	PqcSigContext *ctx;
	PqcStatus	status;
	uint8	   *sig = NULL;
	size_t		actual_sig_len = 0;

	if (!wal_keys_loaded)
	{
		ereport(WARNING,
				(errmsg("PQC WAL signing keys not loaded, cannot sign")));
		return -1;
	}

	ctx = pqc_sig_new(wal_sig_algorithm);
	status = pqc_sig_sign(ctx, data, data_len,
						  wal_secret_key, wal_secret_key_len,
						  &sig, &actual_sig_len);
	pqc_sig_free(ctx);

	if (status != PQC_SUCCESS)
	{
		ereport(WARNING,
				(errmsg("PQC WAL segment signing failed")));
		return -1;
	}

	memcpy(sig_out, sig, actual_sig_len);
	*sig_len = actual_sig_len;
	pfree(sig);

	return 0;
}

/*
 * pqc_wal_verify_data
 *
 * Verify a signature against data using an externally provided public key.
 *
 * Returns 0 on success (valid signature), -1 on failure.
 */
int
pqc_wal_verify_data(const uint8 *data, size_t data_len,
					const uint8 *sig, size_t sig_len,
					const uint8 *pubkey, size_t pubkey_len)
{
	PqcSigContext *ctx;
	PqcStatus	status;

	ctx = pqc_sig_new(wal_sig_algorithm);
	status = pqc_sig_verify(ctx, data, data_len,
							sig, sig_len,
							pubkey, pubkey_len);
	pqc_sig_free(ctx);

	if (status != PQC_SUCCESS)
		return -1;

	return 0;
}

/*
 * pqc_wal_get_public_key
 *
 * Return a pointer to the currently loaded public key.
 */
void
pqc_wal_get_public_key(uint8 **pubkey, size_t *pubkey_len)
{
	if (!wal_keys_loaded)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("PQC WAL signing keys have not been loaded")));

	*pubkey = wal_public_key;
	*pubkey_len = wal_public_key_len;
}

#endif							/* USE_PQC */
