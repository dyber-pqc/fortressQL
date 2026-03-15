/*-------------------------------------------------------------------------
 *
 * compress_pqc.c
 *		PQC encryption/decryption and signing/verification wrapper for
 *		pg_dump/pg_restore data streams.
 *
 * This implements streaming encryption using KEM-derived AES-256-GCM keys,
 * and signing/verification using PQC signature schemes via liboqs.
 *
 * Each data chunk is encrypted with AES-256-GCM using a unique nonce
 * derived from a base IV and a monotonically increasing counter.
 * The encrypted output format per chunk is:
 *     [4-byte big-endian ciphertext length][ciphertext][16-byte GCM tag]
 *
 * FortressQL
 *
 * Portions Copyright (c) 2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/bin/pg_dump/compress_pqc.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres_fe.h"

#include "compress_pqc.h"

#ifdef USE_PQC

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "common/logging.h"

/*
 * derive_aes_key
 *		Derive a 32-byte AES-256 key from the KEM shared secret using
 *		SHA-256.  The shared secret may be larger than 32 bytes depending
 *		on the KEM algorithm.
 */
static void
derive_aes_key(const uint8_t *shared_secret, size_t ss_len,
			   uint8_t *aes_key)
{
	EVP_MD_CTX *mdctx;
	unsigned int md_len;

	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL)
		pg_fatal("out of memory");

	if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
		EVP_DigestUpdate(mdctx, shared_secret, ss_len) != 1 ||
		EVP_DigestFinal_ex(mdctx, aes_key, &md_len) != 1)
	{
		EVP_MD_CTX_free(mdctx);
		pg_fatal("could not derive AES key from shared secret");
	}

	EVP_MD_CTX_free(mdctx);
}

/*
 * make_chunk_iv
 *		Construct a per-chunk IV by XORing the chunk counter into the
 *		last 8 bytes of the base IV.  This ensures each chunk uses a
 *		unique nonce.
 */
static void
make_chunk_iv(const uint8_t *base_iv, uint64_t counter, uint8_t *out_iv)
{
	int			i;

	memcpy(out_iv, base_iv, PQC_AES_IV_LEN);

	/* XOR counter into the last 8 bytes, big-endian */
	for (i = 0; i < 8; i++)
	{
		out_iv[PQC_AES_IV_LEN - 1 - i] ^=
			(uint8_t) ((counter >> (i * 8)) & 0xFF);
	}
}


/* ----------------------------------------------------------------
 * Encryption functions
 * ----------------------------------------------------------------
 */

/*
 * pqc_encrypt_init
 *		Initialize PQC encryption for a dump.
 *
 * Loads the recipient's KEM public key, performs encapsulation to produce
 * a shared secret, and derives an AES-256-GCM key.
 *
 * Returns the encryptor state, or exits via pg_fatal on error.
 */
PqcEncryptorState *
pqc_encrypt_init(const char *pubkey_path, const char *algorithm)
{
	PqcEncryptorState *state;

	state = malloc(sizeof(PqcEncryptorState));
	if (state == NULL)
		pg_fatal("out of memory");
	memset(state, 0, sizeof(PqcEncryptorState));

	/* Create KEM context */
	state->kem_ctx = pqc_kem_ctx_new(algorithm);
	if (state->kem_ctx == NULL)
		pg_fatal("could not create KEM context for algorithm \"%s\"",
				 algorithm);

	/* Validate key file is readable and has correct size */
	{
		FILE	   *key_fp;
		long		key_fsize;

		key_fp = fopen(pubkey_path, "rb");
		if (key_fp == NULL)
			pg_fatal("could not open PQC public key file \"%s\": %m",
					 pubkey_path);
		if (fseek(key_fp, 0, SEEK_END) != 0 || (key_fsize = ftell(key_fp)) < 0)
		{
			fclose(key_fp);
			pg_fatal("could not determine size of PQC public key file \"%s\"",
					 pubkey_path);
		}
		fclose(key_fp);

		if (key_fsize == 0)
			pg_fatal("PQC public key file \"%s\" is empty", pubkey_path);

		if (state->kem_ctx->public_key_len > 0 &&
			(size_t) key_fsize != state->kem_ctx->public_key_len)
			pg_fatal("PQC public key file \"%s\" has wrong size: "
					 "got %ld bytes, expected %zu for %s",
					 pubkey_path, key_fsize,
					 state->kem_ctx->public_key_len, algorithm);
	}

	/* Load public key */
	if (pqc_kem_load_public_key(state->kem_ctx, pubkey_path) != 0)
		pg_fatal("could not load PQC public key from \"%s\"", pubkey_path);

	/* Encapsulate to get shared secret */
	if (pqc_kem_encapsulate(state->kem_ctx) != 0)
		pg_fatal("PQC KEM encapsulation failed");

	/* Derive AES-256 key from shared secret */
	derive_aes_key(state->kem_ctx->shared_secret,
				   state->kem_ctx->shared_secret_len,
				   state->aes_key);

	/* Generate random base IV */
	if (RAND_bytes(state->aes_iv, PQC_AES_IV_LEN) != 1)
		pg_fatal("could not generate random IV");

	state->chunk_counter = 0;

	/* Initialize running hash for optional signing */
	state->hash_ctx = EVP_MD_CTX_new();
	if (state->hash_ctx == NULL)
		pg_fatal("out of memory");
	if (EVP_DigestInit_ex(state->hash_ctx, EVP_sha256(), NULL) != 1)
		pg_fatal("could not initialize SHA-256 hash context");

	return state;
}

/*
 * pqc_encrypt_data
 *		Encrypt a chunk of data using AES-256-GCM.
 *
 * Output format: [4-byte BE ciphertext length][ciphertext][16-byte tag]
 * The caller must free *output.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_encrypt_data(PqcEncryptorState *state,
				 const uint8_t *input, size_t input_len,
				 uint8_t **output, size_t *output_len)
{
	uint8_t		chunk_iv[PQC_AES_IV_LEN];
	uint8_t    *ct_buf;
	size_t		ct_len;
	uint8_t		tag[PQC_AES_TAG_LEN];
	size_t		total_len;
	uint8_t    *out;

	if (state == NULL || input == NULL || input_len == 0)
		return -1;

	/* Update running hash with plaintext */
	if (EVP_DigestUpdate(state->hash_ctx, input, input_len) != 1)
		return -1;

	/* Construct per-chunk IV */
	make_chunk_iv(state->aes_iv, state->chunk_counter, chunk_iv);
	state->chunk_counter++;

	/* Allocate buffer for ciphertext (same size as plaintext for GCM) */
	ct_buf = malloc(input_len + 16);	/* extra space for safety */
	if (ct_buf == NULL)
		return -1;

	if (pqc_aes256gcm_encrypt(state->aes_key, chunk_iv, PQC_AES_IV_LEN,
							  input, input_len,
							  ct_buf, &ct_len,
							  tag, PQC_AES_TAG_LEN) != 0)
	{
		free(ct_buf);
		return -1;
	}

	/* Pack output: [4-byte ct_len][ciphertext][tag] */
	total_len = 4 + ct_len + PQC_AES_TAG_LEN;
	out = malloc(total_len);
	if (out == NULL)
	{
		free(ct_buf);
		return -1;
	}

	/* Write ciphertext length as 4-byte big-endian */
	out[0] = (uint8_t) ((ct_len >> 24) & 0xFF);
	out[1] = (uint8_t) ((ct_len >> 16) & 0xFF);
	out[2] = (uint8_t) ((ct_len >> 8) & 0xFF);
	out[3] = (uint8_t) (ct_len & 0xFF);

	memcpy(out + 4, ct_buf, ct_len);
	memcpy(out + 4 + ct_len, tag, PQC_AES_TAG_LEN);

	free(ct_buf);

	*output = out;
	*output_len = total_len;
	return 0;
}

/*
 * pqc_encrypt_finish
 *		Finalize encryption and return the KEM ciphertext.
 *
 * The KEM ciphertext must be stored in the archive header so the
 * recipient can decapsulate it with their secret key.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_encrypt_finish(PqcEncryptorState *state,
				   uint8_t **kem_ciphertext, size_t *kem_ct_len)
{
	if (state == NULL || state->kem_ctx == NULL)
		return -1;

	/* Return a copy of the KEM ciphertext */
	*kem_ct_len = state->kem_ctx->ciphertext_len;
	*kem_ciphertext = malloc(*kem_ct_len);
	if (*kem_ciphertext == NULL)
		return -1;

	memcpy(*kem_ciphertext, state->kem_ctx->ciphertext, *kem_ct_len);
	return 0;
}

/*
 * pqc_encrypt_free
 *		Free all resources associated with an encryptor state.
 */
void
pqc_encrypt_free(PqcEncryptorState *state)
{
	if (state == NULL)
		return;

	pqc_kem_ctx_free(state->kem_ctx);

	OQS_MEM_cleanse(state->aes_key, PQC_AES_KEY_LEN);
	OQS_MEM_cleanse(state->aes_iv, PQC_AES_IV_LEN);

	if (state->hash_ctx)
		EVP_MD_CTX_free(state->hash_ctx);

	OQS_MEM_cleanse(state, sizeof(PqcEncryptorState));
	free(state);
}


/* ----------------------------------------------------------------
 * Decryption functions
 * ----------------------------------------------------------------
 */

/*
 * pqc_decrypt_init
 *		Initialize PQC decryption for a restore.
 *
 * Loads the recipient's KEM secret key, decapsulates the ciphertext from
 * the archive header to recover the shared secret, and derives the
 * AES-256-GCM key.
 *
 * Returns the decryptor state, or exits via pg_fatal on error.
 */
PqcDecryptorState *
pqc_decrypt_init(const char *seckey_path, const char *algorithm,
				 const uint8_t *ciphertext, size_t ct_len)
{
	PqcDecryptorState *state;

	state = malloc(sizeof(PqcDecryptorState));
	if (state == NULL)
		pg_fatal("out of memory");
	memset(state, 0, sizeof(PqcDecryptorState));

	/* Create KEM context */
	state->kem_ctx = pqc_kem_ctx_new(algorithm);
	if (state->kem_ctx == NULL)
		pg_fatal("could not create KEM context for algorithm \"%s\"",
				 algorithm);

	/* Load secret key */
	if (pqc_kem_load_secret_key(state->kem_ctx, seckey_path) != 0)
		pg_fatal("could not load PQC secret key from \"%s\"", seckey_path);

	/* Decapsulate to recover shared secret */
	if (pqc_kem_decapsulate(state->kem_ctx, ciphertext, ct_len) != 0)
		pg_fatal("PQC KEM decapsulation failed: the secret key may not match "
				 "the public key used for encryption, or the encrypted backup "
				 "header is corrupted");

	/* Derive AES-256 key from shared secret */
	derive_aes_key(state->kem_ctx->shared_secret,
				   state->kem_ctx->shared_secret_len,
				   state->aes_key);

	state->chunk_counter = 0;

	/* Initialize running hash for optional verification */
	state->hash_ctx = EVP_MD_CTX_new();
	if (state->hash_ctx == NULL)
		pg_fatal("out of memory");
	if (EVP_DigestInit_ex(state->hash_ctx, EVP_sha256(), NULL) != 1)
		pg_fatal("could not initialize SHA-256 hash context");

	return state;
}

/*
 * pqc_decrypt_data
 *		Decrypt a chunk of data.
 *
 * Input format: [4-byte BE ciphertext length][ciphertext][16-byte tag]
 * The caller must free *output.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_decrypt_data(PqcDecryptorState *state,
				 const uint8_t *input, size_t input_len,
				 uint8_t **output, size_t *output_len)
{
	uint8_t		chunk_iv[PQC_AES_IV_LEN];
	size_t		ct_len;
	const uint8_t *ct_data;
	const uint8_t *tag;
	uint8_t    *pt_buf;
	size_t		pt_len;

	if (state == NULL || input == NULL)
		return -1;

	/* Parse input: [4-byte ct_len][ciphertext][tag] */
	if (input_len < 4 + PQC_AES_TAG_LEN)
		return -1;

	ct_len = ((size_t) input[0] << 24) |
		((size_t) input[1] << 16) |
		((size_t) input[2] << 8) |
		(size_t) input[3];

	if (input_len != 4 + ct_len + PQC_AES_TAG_LEN)
		return -1;

	ct_data = input + 4;
	tag = input + 4 + ct_len;

	/* Construct per-chunk IV */
	make_chunk_iv(state->aes_iv, state->chunk_counter, chunk_iv);
	state->chunk_counter++;

	/* Allocate buffer for plaintext */
	pt_buf = malloc(ct_len + 16);	/* extra space for safety */
	if (pt_buf == NULL)
		return -1;

	if (pqc_aes256gcm_decrypt(state->aes_key, chunk_iv, PQC_AES_IV_LEN,
							  ct_data, ct_len,
							  tag, PQC_AES_TAG_LEN,
							  pt_buf, &pt_len) != 0)
	{
		free(pt_buf);
		pg_log_error("AES-256-GCM decryption failed at chunk " UINT64_FORMAT ": "
					 "encrypted backup may be tampered with or wrong key used",
					 state->chunk_counter - 1);
		return -1;
	}

	/* Update running hash with decrypted plaintext */
	if (EVP_DigestUpdate(state->hash_ctx, pt_buf, pt_len) != 1)
	{
		free(pt_buf);
		return -1;
	}

	*output = pt_buf;
	*output_len = pt_len;
	return 0;
}

/*
 * pqc_decrypt_finish
 *		Finalize decryption.
 *
 * Returns 0 on success.
 */
int
pqc_decrypt_finish(PqcDecryptorState *state)
{
	if (state == NULL)
		return -1;

	return 0;
}

/*
 * pqc_decrypt_free
 *		Free all resources associated with a decryptor state.
 */
void
pqc_decrypt_free(PqcDecryptorState *state)
{
	if (state == NULL)
		return;

	pqc_kem_ctx_free(state->kem_ctx);

	OQS_MEM_cleanse(state->aes_key, PQC_AES_KEY_LEN);
	OQS_MEM_cleanse(state->aes_iv, PQC_AES_IV_LEN);

	if (state->hash_ctx)
		EVP_MD_CTX_free(state->hash_ctx);

	OQS_MEM_cleanse(state, sizeof(PqcDecryptorState));
	free(state);
}


/* ----------------------------------------------------------------
 * Signing functions
 * ----------------------------------------------------------------
 */

/*
 * pqc_sign_init
 *		Initialize PQC signing for a dump.
 *
 * Loads the signer's secret key.  Data is fed via pqc_sign_update()
 * and the final signature is produced by pqc_sign_finish().
 *
 * Returns the sign state, or exits via pg_fatal on error.
 */
PqcSignState *
pqc_sign_init(const char *seckey_path, const char *algorithm)
{
	PqcSignState *state;

	state = malloc(sizeof(PqcSignState));
	if (state == NULL)
		pg_fatal("out of memory");
	memset(state, 0, sizeof(PqcSignState));

	state->sig_ctx = pqc_sig_ctx_new(algorithm);
	if (state->sig_ctx == NULL)
		pg_fatal("could not create signature context for algorithm \"%s\"",
				 algorithm);

	if (pqc_sig_load_keys(state->sig_ctx, NULL, seckey_path) != 0)
		pg_fatal("could not load PQC signing key from \"%s\"", seckey_path);

	/* Initialize running hash */
	state->hash_ctx = EVP_MD_CTX_new();
	if (state->hash_ctx == NULL)
		pg_fatal("out of memory");
	if (EVP_DigestInit_ex(state->hash_ctx, EVP_sha256(), NULL) != 1)
		pg_fatal("could not initialize SHA-256 hash context");

	return state;
}

/*
 * pqc_sign_update
 *		Feed data into the running hash for signing.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_sign_update(PqcSignState *state, const uint8_t *data, size_t len)
{
	if (state == NULL || data == NULL)
		return -1;

	if (EVP_DigestUpdate(state->hash_ctx, data, len) != 1)
		return -1;

	return 0;
}

/*
 * pqc_sign_finish
 *		Finalize the hash and produce a PQC signature.
 *
 * The caller must free *sig_out.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_sign_finish(PqcSignState *state, uint8_t **sig_out, size_t *sig_len)
{
	uint8_t		hash[SHA256_DIGEST_LENGTH];
	unsigned int hash_len;

	if (state == NULL)
		return -1;

	/* Finalize the hash */
	if (EVP_DigestFinal_ex(state->hash_ctx, hash, &hash_len) != 1)
	{
		pg_log_error("could not finalize SHA-256 hash for backup signing");
		return -1;
	}

	/* Sign the hash */
	if (pqc_common_sign(state->sig_ctx, hash, hash_len, sig_out, sig_len) != 0)
	{
		pg_log_error("PQC signature generation failed for backup: "
					 "signing key may be corrupted or algorithm mismatch");
		OQS_MEM_cleanse(hash, SHA256_DIGEST_LENGTH);
		return -1;
	}

	OQS_MEM_cleanse(hash, SHA256_DIGEST_LENGTH);
	return 0;
}

/*
 * pqc_sign_free
 *		Free all resources associated with a sign state.
 */
void
pqc_sign_free(PqcSignState *state)
{
	if (state == NULL)
		return;

	pqc_sig_ctx_free(state->sig_ctx);
	if (state->hash_ctx)
		EVP_MD_CTX_free(state->hash_ctx);

	free(state);
}


/* ----------------------------------------------------------------
 * Verification functions
 * ----------------------------------------------------------------
 */

/*
 * pqc_verify_init
 *		Initialize PQC verification for a restore.
 *
 * Loads the signer's public key.
 *
 * Returns the verify state, or exits via pg_fatal on error.
 */
PqcVerifyState *
pqc_verify_init(const char *pubkey_path, const char *algorithm)
{
	PqcVerifyState *state;

	state = malloc(sizeof(PqcVerifyState));
	if (state == NULL)
		pg_fatal("out of memory");
	memset(state, 0, sizeof(PqcVerifyState));

	state->sig_ctx = pqc_sig_ctx_new(algorithm);
	if (state->sig_ctx == NULL)
		pg_fatal("could not create signature context for algorithm \"%s\"",
				 algorithm);

	if (pqc_sig_load_keys(state->sig_ctx, pubkey_path, NULL) != 0)
		pg_fatal("could not load PQC verification key from \"%s\"",
				 pubkey_path);

	/* Initialize running hash */
	state->hash_ctx = EVP_MD_CTX_new();
	if (state->hash_ctx == NULL)
		pg_fatal("out of memory");
	if (EVP_DigestInit_ex(state->hash_ctx, EVP_sha256(), NULL) != 1)
		pg_fatal("could not initialize SHA-256 hash context");

	return state;
}

/*
 * pqc_verify_update
 *		Feed data into the running hash for verification.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_verify_update(PqcVerifyState *state, const uint8_t *data, size_t len)
{
	if (state == NULL || data == NULL)
		return -1;

	if (EVP_DigestUpdate(state->hash_ctx, data, len) != 1)
		return -1;

	return 0;
}

/*
 * pqc_verify_finish
 *		Finalize the hash and verify the PQC signature.
 *
 * Returns 0 if the signature is valid, -1 on failure.
 */
int
pqc_verify_finish(PqcVerifyState *state,
				  const uint8_t *sig, size_t sig_len)
{
	uint8_t		hash[SHA256_DIGEST_LENGTH];
	unsigned int hash_len;

	if (state == NULL || sig == NULL)
		return -1;

	/* Finalize the hash */
	if (EVP_DigestFinal_ex(state->hash_ctx, hash, &hash_len) != 1)
	{
		pg_log_error("could not finalize SHA-256 hash for backup verification");
		return -1;
	}

	/* Verify the signature over the hash */
	if (pqc_common_verify(state->sig_ctx, hash, hash_len, sig, sig_len) != 0)
	{
		pg_log_error("PQC signature verification failed: backup may have been "
					 "tampered with, or the wrong verification key was used");
		OQS_MEM_cleanse(hash, SHA256_DIGEST_LENGTH);
		return -1;
	}

	OQS_MEM_cleanse(hash, SHA256_DIGEST_LENGTH);
	return 0;
}

/*
 * pqc_verify_free
 *		Free all resources associated with a verify state.
 */
void
pqc_verify_free(PqcVerifyState *state)
{
	if (state == NULL)
		return;

	pqc_sig_ctx_free(state->sig_ctx);
	if (state->hash_ctx)
		EVP_MD_CTX_free(state->hash_ctx);

	free(state);
}

#endif							/* USE_PQC */
