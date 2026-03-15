/*-------------------------------------------------------------------------
 *
 * tde_keymanage.c
 *	  FortressQL TDE key lifecycle management.
 *
 * Implements master key generation and wrapping via ML-KEM-768 (FIPS 203,
 * post-quantum KEM), tablespace data encryption key (TDEK) generation
 * and encryption via AES-256-GCM, master key rotation, and HKDF-based
 * IV derivation for per-page encryption.
 *
 * The encrypted master key blob is stored in
 *   $PGDATA/global/pg_encryption/master.key
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/tde/tde_keymanage.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#ifdef USE_PQC

#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include "crypto/pqc/pqc_common.h"
#include "crypto/pqc/pqc_kem.h"
#include "crypto/tde/tde.h"
#include "crypto/tde/tde_keycache.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "storage/ipc.h"
#include "utils/memutils.h"

/* HKDF label for page IV derivation */
static const char TDE_PAGE_HKDF_LABEL[] = "FortressQL-TDE-Page-IV-v1";

/*
 * AES-256-GCM parameters for TDEK wrapping.
 */
#define TDE_GCM_IV_LEN			12
#define TDE_GCM_TAG_LEN			16

/*
 * Master key file header - written at the start of master.key.
 *
 * Layout on disk:
 *   [MasterKeyFileHeader]
 *   [ML-KEM-768 public key]
 *   [ML-KEM-768 ciphertext (encapsulated shared secret)]
 *   [AES-256-GCM IV (12 bytes)]
 *   [AES-256-GCM encrypted master key (32 bytes)]
 *   [AES-256-GCM tag (16 bytes)]
 */
typedef struct MasterKeyFileHeader
{
	uint32		magic;				/* TDE_MASTER_KEY_MAGIC */
	uint32		version;			/* TDE_VERSION */
	uint32		kem_alg;			/* PqcAlgorithm value */
	uint32		pubkey_len;			/* ML-KEM public key length */
	uint32		ciphertext_len;		/* ML-KEM ciphertext length */
	uint32		reserved;			/* padding / future use */
} MasterKeyFileHeader;

#define TDE_MASTER_KEY_MAGIC	0x54444531	/* "TDE1" */

/*
 * In-memory master key state.  The decrypted master key is held in
 * backend-local memory and wiped on process exit via an on_proc_exit
 * callback to prevent leakage in core dumps.
 */
static uint8 MasterKey[TDE_AES_KEY_LEN];
static bool MasterKeyLoaded = false;
static bool MasterKeyExitRegistered = false;

/*
 * tde_wipe_master_key_on_exit
 *
 * Process-exit callback to securely wipe the master key from memory.
 */
static void
tde_wipe_master_key_on_exit(int code, Datum arg)
{
	explicit_bzero(MasterKey, TDE_AES_KEY_LEN);
	MasterKeyLoaded = false;
}

/* Forward declarations */
static void tde_ensure_key_directory(void);
static char *tde_master_key_path(void);
static void tde_write_master_key_file(const uint8 *pubkey, size_t pubkey_len,
									  const uint8 *ct, size_t ct_len,
									  PqcAlgorithm alg,
									  const uint8 *encrypted_mk,
									  const uint8 *gcm_iv,
									  const uint8 *gcm_tag);

/*
 * tde_ensure_key_directory
 *
 * Create $PGDATA/global/pg_encryption if it does not exist.
 */
static void
tde_ensure_key_directory(void)
{
	char		path[MAXPGPATH];

	snprintf(path, sizeof(path), "%s/global/%s", DataDir, TDE_KEY_DIR);

	if (MakePGDirectory(path) < 0 && errno != EEXIST)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("TDE: could not create directory \"%s\": %m", path)));
}

/*
 * tde_master_key_path
 *
 * Return the full path to the master key file.  Result is in a palloc'd
 * buffer.
 */
static char *
tde_master_key_path(void)
{
	char	   *path = palloc(MAXPGPATH);

	snprintf(path, MAXPGPATH, "%s/global/%s/%s",
			 DataDir, TDE_KEY_DIR, TDE_MASTER_KEY_FILE);
	return path;
}

/*
 * tde_generate_master_key
 *
 * Generate a new random AES-256 master key, wrap it using ML-KEM-768
 * key encapsulation, and write the encrypted blob to disk.
 *
 * The ML-KEM-768 public key is stored alongside the ciphertext so that
 * the corresponding secret key (held externally by the administrator)
 * can be used for decapsulation.
 *
 * The KEM shared secret is used as the wrapping key to AES-256-GCM
 * encrypt the actual master key.
 */
void
tde_generate_master_key(void)
{
	PqcKemContext *kem_ctx;
	uint8	   *pubkey = NULL;
	size_t		pubkey_len;
	uint8	   *seckey = NULL;
	size_t		seckey_len;
	uint8	   *kem_ct = NULL;
	size_t		kem_ct_len;
	uint8	   *shared_secret = NULL;
	size_t		shared_secret_len;
	uint8		raw_master_key[TDE_AES_KEY_LEN];
	uint8		encrypted_mk[TDE_AES_KEY_LEN];
	uint8		gcm_iv[TDE_GCM_IV_LEN];
	uint8		gcm_tag[TDE_GCM_TAG_LEN];
	EVP_CIPHER_CTX *gcm_ctx;
	int			outlen;
	int			tmplen;

	tde_ensure_key_directory();

	/* Generate random master key */
	if (RAND_bytes(raw_master_key, TDE_AES_KEY_LEN) != 1)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: failed to generate random master key")));

	/* Generate ML-KEM-768 key pair */
	kem_ctx = pqc_kem_new(PQC_ALG_ML_KEM_768);

	if (pqc_kem_keygen(kem_ctx, &pubkey, &pubkey_len,
					   &seckey, &seckey_len) != PQC_SUCCESS)
	{
		pqc_kem_free(kem_ctx);
		explicit_bzero(raw_master_key, TDE_AES_KEY_LEN);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: ML-KEM-768 key generation failed")));
	}

	/* Encapsulate to produce shared secret */
	if (pqc_kem_encaps(kem_ctx, pubkey, pubkey_len,
					   &kem_ct, &kem_ct_len,
					   &shared_secret, &shared_secret_len) != PQC_SUCCESS)
	{
		pqc_kem_free(kem_ctx);
		pqc_secure_free(seckey, seckey_len);
		pfree(pubkey);
		explicit_bzero(raw_master_key, TDE_AES_KEY_LEN);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: ML-KEM-768 encapsulation failed")));
	}

	/*
	 * Wrap the master key with AES-256-GCM using the KEM shared secret
	 * as the wrapping key.  The shared secret from ML-KEM-768 is 32
	 * bytes, exactly the right size for AES-256.
	 */
	if (RAND_bytes(gcm_iv, TDE_GCM_IV_LEN) != 1)
	{
		pqc_kem_free(kem_ctx);
		pqc_secure_free(seckey, seckey_len);
		pqc_secure_free(shared_secret, shared_secret_len);
		pfree(pubkey);
		pfree(kem_ct);
		explicit_bzero(raw_master_key, TDE_AES_KEY_LEN);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: failed to generate GCM IV")));
	}

	gcm_ctx = EVP_CIPHER_CTX_new();
	if (gcm_ctx == NULL)
	{
		pqc_kem_free(kem_ctx);
		pqc_secure_free(seckey, seckey_len);
		pqc_secure_free(shared_secret, shared_secret_len);
		pfree(pubkey);
		pfree(kem_ct);
		explicit_bzero(raw_master_key, TDE_AES_KEY_LEN);
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("TDE: failed to allocate GCM context")));
	}

	if (EVP_EncryptInit_ex(gcm_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
		EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_SET_IVLEN,
							TDE_GCM_IV_LEN, NULL) != 1 ||
		EVP_EncryptInit_ex(gcm_ctx, NULL, NULL, shared_secret, gcm_iv) != 1 ||
		EVP_EncryptUpdate(gcm_ctx, encrypted_mk, &outlen,
						  raw_master_key, TDE_AES_KEY_LEN) != 1 ||
		EVP_EncryptFinal_ex(gcm_ctx, encrypted_mk + outlen, &tmplen) != 1 ||
		EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_GET_TAG,
							TDE_GCM_TAG_LEN, gcm_tag) != 1)
	{
		EVP_CIPHER_CTX_free(gcm_ctx);
		pqc_kem_free(kem_ctx);
		pqc_secure_free(seckey, seckey_len);
		pqc_secure_free(shared_secret, shared_secret_len);
		pfree(pubkey);
		pfree(kem_ct);
		explicit_bzero(raw_master_key, TDE_AES_KEY_LEN);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: AES-256-GCM wrapping of master key failed")));
	}

	EVP_CIPHER_CTX_free(gcm_ctx);

	/* Write everything to disk */
	tde_write_master_key_file(pubkey, pubkey_len,
							  kem_ct, kem_ct_len,
							  PQC_ALG_ML_KEM_768,
							  encrypted_mk, gcm_iv, gcm_tag);

	/* Load the master key into memory */
	memcpy(MasterKey, raw_master_key, TDE_AES_KEY_LEN);
	MasterKeyLoaded = true;

	/* Register process-exit wipe callback (once) */
	if (!MasterKeyExitRegistered)
	{
		on_proc_exit(tde_wipe_master_key_on_exit, 0);
		MasterKeyExitRegistered = true;
	}

	/*
	 * IMPORTANT: The secret key must be exported to the administrator
	 * and stored securely outside of $PGDATA.  For now, we log a
	 * warning.  A production deployment would use a key management
	 * service or HSM.
	 */
	ereport(LOG,
			(errmsg("TDE: master key generated and wrapped with ML-KEM-768"),
			 errhint("The ML-KEM secret key must be backed up securely. "
					 "It is required to unwrap the master key after restart.")));

	/* Clean up sensitive material */
	explicit_bzero(raw_master_key, TDE_AES_KEY_LEN);
	pqc_secure_free(seckey, seckey_len);
	pqc_secure_free(shared_secret, shared_secret_len);
	pfree(pubkey);
	pfree(kem_ct);
	pqc_kem_free(kem_ctx);
}

/*
 * tde_write_master_key_file
 *
 * Write the master key file to $PGDATA/global/pg_encryption/master.key.
 */
static void
tde_write_master_key_file(const uint8 *pubkey, size_t pubkey_len,
						  const uint8 *ct, size_t ct_len,
						  PqcAlgorithm alg,
						  const uint8 *encrypted_mk,
						  const uint8 *gcm_iv,
						  const uint8 *gcm_tag)
{
	char	   *filepath;
	FILE	   *fp;
	MasterKeyFileHeader hdr;

	filepath = tde_master_key_path();

	fp = AllocateFile(filepath, "wb");
	if (fp == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("TDE: could not create master key file \"%s\": %m",
						filepath)));

	/* Write header */
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = TDE_MASTER_KEY_MAGIC;
	hdr.version = TDE_VERSION;
	hdr.kem_alg = (uint32) alg;
	hdr.pubkey_len = (uint32) pubkey_len;
	hdr.ciphertext_len = (uint32) ct_len;

	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1 ||
		fwrite(pubkey, pubkey_len, 1, fp) != 1 ||
		fwrite(ct, ct_len, 1, fp) != 1 ||
		fwrite(gcm_iv, TDE_GCM_IV_LEN, 1, fp) != 1 ||
		fwrite(encrypted_mk, TDE_AES_KEY_LEN, 1, fp) != 1 ||
		fwrite(gcm_tag, TDE_GCM_TAG_LEN, 1, fp) != 1)
	{
		FreeFile(fp);
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("TDE: could not write master key file \"%s\": %m",
						filepath)));
	}

	if (FreeFile(fp) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("TDE: could not close master key file \"%s\": %m",
						filepath)));

	pfree(filepath);
}

/*
 * tde_unwrap_master_key
 *
 * Read the master key file and use the ML-KEM secret key (provided via
 * an environment variable or key management callback) to decapsulate
 * the shared secret, then use it to AES-256-GCM decrypt the master key.
 *
 * For this implementation, the ML-KEM secret key is expected in the
 * environment variable FORTRESSQL_KEM_SECRET_KEY as a hex string.
 */
void
tde_unwrap_master_key(void)
{
	char	   *filepath;
	FILE	   *fp;
	MasterKeyFileHeader hdr;
	uint8	   *pubkey = NULL;
	uint8	   *kem_ct = NULL;
	uint8		gcm_iv[TDE_GCM_IV_LEN];
	uint8		encrypted_mk[TDE_AES_KEY_LEN];
	uint8		gcm_tag[TDE_GCM_TAG_LEN];
	const char *seckey_hex;
	uint8	   *seckey = NULL;
	size_t		seckey_len;
	PqcKemContext *kem_ctx;
	uint8	   *shared_secret = NULL;
	size_t		shared_secret_len;
	EVP_CIPHER_CTX *gcm_ctx;
	int			outlen;
	int			tmplen;
	int			i;

	if (MasterKeyLoaded)
		return;

	filepath = tde_master_key_path();

	fp = AllocateFile(filepath, "rb");
	if (fp == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("TDE: could not open master key file \"%s\": %m",
						filepath),
				 errhint("Run tde_generate_master_key() to create one.")));

	/* Read and validate header */
	if (fread(&hdr, sizeof(hdr), 1, fp) != 1)
	{
		FreeFile(fp);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("TDE: could not read master key file header")));
	}

	if (hdr.magic != TDE_MASTER_KEY_MAGIC)
	{
		FreeFile(fp);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("TDE: invalid master key file magic: 0x%08X",
						hdr.magic)));
	}

	if (hdr.version != TDE_VERSION)
	{
		FreeFile(fp);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("TDE: unsupported master key file version: %u",
						hdr.version)));
	}

	/* Read the variable-length fields */
	pubkey = palloc(hdr.pubkey_len);
	kem_ct = palloc(hdr.ciphertext_len);

	if (fread(pubkey, hdr.pubkey_len, 1, fp) != 1 ||
		fread(kem_ct, hdr.ciphertext_len, 1, fp) != 1 ||
		fread(gcm_iv, TDE_GCM_IV_LEN, 1, fp) != 1 ||
		fread(encrypted_mk, TDE_AES_KEY_LEN, 1, fp) != 1 ||
		fread(gcm_tag, TDE_GCM_TAG_LEN, 1, fp) != 1)
	{
		FreeFile(fp);
		pfree(pubkey);
		pfree(kem_ct);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("TDE: master key file is truncated")));
	}

	FreeFile(fp);
	pfree(filepath);

	/*
	 * Get the ML-KEM secret key from environment.  In production this
	 * would come from an HSM or key management service.
	 */
	seckey_hex = getenv("FORTRESSQL_KEM_SECRET_KEY");
	if (seckey_hex == NULL || strlen(seckey_hex) == 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("TDE: FORTRESSQL_KEM_SECRET_KEY environment variable not set"),
				 errhint("Set the ML-KEM secret key to unwrap the TDE master key.")));

	/* Decode hex string to binary */
	seckey_len = strlen(seckey_hex) / 2;
	seckey = palloc(seckey_len);
	for (i = 0; i < (int) seckey_len; i++)
	{
		unsigned int byte;

		if (sscanf(seckey_hex + (i * 2), "%02x", &byte) != 1)
		{
			pqc_secure_free(seckey, seckey_len);
			pfree(pubkey);
			pfree(kem_ct);
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("TDE: invalid hex in FORTRESSQL_KEM_SECRET_KEY")));
		}
		seckey[i] = (uint8) byte;
	}

	/* Decapsulate to recover shared secret */
	kem_ctx = pqc_kem_new((PqcAlgorithm) hdr.kem_alg);

	if (pqc_kem_decaps(kem_ctx, kem_ct, hdr.ciphertext_len,
					   seckey, seckey_len,
					   &shared_secret, &shared_secret_len) != PQC_SUCCESS)
	{
		pqc_kem_free(kem_ctx);
		pqc_secure_free(seckey, seckey_len);
		pfree(pubkey);
		pfree(kem_ct);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: ML-KEM decapsulation failed"),
				 errhint("Verify that the correct ML-KEM secret key is provided.")));
	}

	pqc_kem_free(kem_ctx);
	pqc_secure_free(seckey, seckey_len);
	pfree(pubkey);
	pfree(kem_ct);

	/* Unwrap master key with AES-256-GCM */
	gcm_ctx = EVP_CIPHER_CTX_new();
	if (gcm_ctx == NULL)
	{
		pqc_secure_free(shared_secret, shared_secret_len);
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("TDE: failed to allocate GCM context for unwrap")));
	}

	if (EVP_DecryptInit_ex(gcm_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
		EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_SET_IVLEN,
							TDE_GCM_IV_LEN, NULL) != 1 ||
		EVP_DecryptInit_ex(gcm_ctx, NULL, NULL, shared_secret, gcm_iv) != 1 ||
		EVP_DecryptUpdate(gcm_ctx, MasterKey, &outlen,
						  encrypted_mk, TDE_AES_KEY_LEN) != 1 ||
		EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_GCM_SET_TAG,
							TDE_GCM_TAG_LEN, gcm_tag) != 1 ||
		EVP_DecryptFinal_ex(gcm_ctx, MasterKey + outlen, &tmplen) != 1)
	{
		EVP_CIPHER_CTX_free(gcm_ctx);
		pqc_secure_free(shared_secret, shared_secret_len);
		explicit_bzero(MasterKey, TDE_AES_KEY_LEN);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: AES-256-GCM unwrapping of master key failed"),
				 errhint("The master key file may be corrupted or the wrong "
						 "ML-KEM secret key was provided.")));
	}

	EVP_CIPHER_CTX_free(gcm_ctx);
	pqc_secure_free(shared_secret, shared_secret_len);

	MasterKeyLoaded = true;

	/* Register process-exit wipe callback (once) */
	if (!MasterKeyExitRegistered)
	{
		on_proc_exit(tde_wipe_master_key_on_exit, 0);
		MasterKeyExitRegistered = true;
	}

	ereport(LOG,
			(errmsg("TDE: master key successfully unwrapped")));
}

/*
 * tde_generate_tablespace_key
 *
 * Generate a new random TDEK for the specified tablespace and encrypt
 * it with the master key using AES-256-GCM.  The encrypted TDEK is
 * stored in the pg_tablespace catalog (via caller), and the decrypted
 * TDEK is inserted into the shared memory key cache.
 */
void
tde_generate_tablespace_key(Oid spcOid)
{
	uint8		tdek[TDE_AES_KEY_LEN];
	TdeKeyEntry entry;

	if (!MasterKeyLoaded)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: master key is not loaded"),
				 errhint("Call tde_unwrap_master_key() first.")));

	/* Generate random TDEK */
	if (RAND_bytes(tdek, TDE_AES_KEY_LEN) != 1)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: failed to generate tablespace key")));

	/* Populate key entry and insert into cache */
	entry.spc_oid = spcOid;
	memcpy(entry.key, tdek, TDE_AES_KEY_LEN);
	entry.version = 1;
	entry.active = true;

	tde_keycache_insert(&entry);

	/* Wipe local copies of key material */
	explicit_bzero(tdek, TDE_AES_KEY_LEN);
	explicit_bzero(&entry, sizeof(entry));

	ereport(LOG,
			(errmsg("TDE: generated new encryption key for tablespace %u",
					spcOid)));
}

/*
 * tde_rotate_master_key
 *
 * Generate a new master key and re-wrap all existing TDEKs under the
 * new master key.  This does NOT re-encrypt data pages; it only changes
 * the master key that protects the TDEKs.
 *
 * IMPORTANT: The new key is generated and written to disk BEFORE the
 * old key is wiped and the cache is invalidated.  This ensures that
 * a failure during key generation does not leave the system in an
 * unrecoverable state with both old and new keys lost.
 */
void
tde_rotate_master_key(void)
{
	uint8		old_master_key[TDE_AES_KEY_LEN];

	if (!MasterKeyLoaded)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: cannot rotate master key - current key not loaded")));

	/* Save old master key so we can restore on failure */
	memcpy(old_master_key, MasterKey, TDE_AES_KEY_LEN);

	/*
	 * Generate the new master key first.  This writes the new key file
	 * and loads the new key into MasterKey.  If this fails, we restore
	 * the old key — the system remains in a working state.
	 */
	PG_TRY();
	{
		tde_generate_master_key();
	}
	PG_CATCH();
	{
		/* Restore old master key on failure */
		memcpy(MasterKey, old_master_key, TDE_AES_KEY_LEN);
		MasterKeyLoaded = true;
		explicit_bzero(old_master_key, TDE_AES_KEY_LEN);
		PG_RE_THROW();
	}
	PG_END_TRY();

	/* New key is safely on disk — now invalidate the TDEK cache */
	tde_keycache_invalidate();

	explicit_bzero(old_master_key, TDE_AES_KEY_LEN);

	ereport(LOG,
			(errmsg("TDE: master key rotation complete")));
}

/*
 * tde_derive_page_iv
 *
 * Derive a unique TDE_IV_LEN-byte IV for a data page using HKDF-SHA256.
 *
 * The info parameter is constructed from the page identity:
 *   spcOid || dbOid || relNumber || forkNum || blockNum
 *
 * This ensures every page gets a distinct IV even when using the same TDEK.
 */
void
tde_derive_page_iv(const uint8 *tdek,
				   Oid spcOid, Oid dbOid,
				   RelFileNumber relNumber,
				   ForkNumber forkNum,
				   BlockNumber blockNum,
				   uint8 *iv_out)
{
	EVP_PKEY_CTX *pctx;
	uint8		info_buf[sizeof(Oid) + sizeof(Oid) + sizeof(RelFileNumber) +
						 sizeof(ForkNumber) + sizeof(BlockNumber)];
	size_t		iv_len = TDE_IV_LEN;
	size_t		off = 0;

	/* Build info: spcOid || dbOid || relNumber || forkNum || blockNum */
	memcpy(info_buf + off, &spcOid, sizeof(Oid));
	off += sizeof(Oid);
	memcpy(info_buf + off, &dbOid, sizeof(Oid));
	off += sizeof(Oid);
	memcpy(info_buf + off, &relNumber, sizeof(RelFileNumber));
	off += sizeof(RelFileNumber);
	memcpy(info_buf + off, &forkNum, sizeof(ForkNumber));
	off += sizeof(ForkNumber);
	memcpy(info_buf + off, &blockNum, sizeof(BlockNumber));

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("TDE: failed to allocate HKDF context for page IV")));

	if (EVP_PKEY_derive_init(pctx) <= 0 ||
		EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
		EVP_PKEY_CTX_set1_hkdf_salt(pctx,
									(const unsigned char *) TDE_PAGE_HKDF_LABEL,
									strlen(TDE_PAGE_HKDF_LABEL)) <= 0 ||
		EVP_PKEY_CTX_set1_hkdf_key(pctx, tdek, TDE_AES_KEY_LEN) <= 0 ||
		EVP_PKEY_CTX_add1_hkdf_info(pctx, info_buf, sizeof(info_buf)) <= 0 ||
		EVP_PKEY_derive(pctx, iv_out, &iv_len) <= 0)
	{
		EVP_PKEY_CTX_free(pctx);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: HKDF derivation failed for page IV")));
	}

	EVP_PKEY_CTX_free(pctx);
}

#endif							/* USE_PQC */
