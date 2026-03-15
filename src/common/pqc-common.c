/*-------------------------------------------------------------------------
 *
 * pqc-common.c
 *		Shared frontend/backend code for PQC (Post-Quantum Cryptography)
 *		operations used in encrypted and signed database backups.
 *
 * This contains KEM and signature operations via liboqs, plus AES-256-GCM
 * encryption via OpenSSL EVP.  It uses malloc/free (not palloc) so it can
 * be used in both frontend and backend contexts.
 *
 * FortressQL
 *
 * Portions Copyright (c) 2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/common/pqc-common.c
 *
 *-------------------------------------------------------------------------
 */
#ifndef FRONTEND
#include "postgres.h"
#else
#include "postgres_fe.h"
#endif

#include "common/pqc-common.h"

#ifdef USE_PQC

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

/*
 * pqc_kem_ctx_new
 *		Create a new KEM context for the given algorithm name.
 *
 * Returns NULL on failure.
 */
PqcKemContext *
pqc_kem_ctx_new(const char *algorithm)
{
	PqcKemContext *ctx;
	OQS_KEM    *kem;

	/* Verify the algorithm is supported */
	kem = OQS_KEM_new(algorithm);
	if (kem == NULL)
		return NULL;

	ctx = malloc(sizeof(PqcKemContext));
	if (ctx == NULL)
	{
		OQS_KEM_free(kem);
		return NULL;
	}
	memset(ctx, 0, sizeof(PqcKemContext));

	ctx->algorithm = strdup(algorithm);
	if (ctx->algorithm == NULL)
	{
		OQS_KEM_free(kem);
		free(ctx);
		return NULL;
	}

	ctx->public_key_len = kem->length_public_key;
	ctx->secret_key_len = kem->length_secret_key;
	ctx->shared_secret_len = kem->length_shared_secret;
	ctx->ciphertext_len = kem->length_ciphertext;

	OQS_KEM_free(kem);
	return ctx;
}

/*
 * pqc_kem_ctx_free
 *		Free a KEM context and all its associated memory.
 */
void
pqc_kem_ctx_free(PqcKemContext *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->algorithm)
		free(ctx->algorithm);
	if (ctx->public_key)
	{
		OQS_MEM_cleanse(ctx->public_key, ctx->public_key_len);
		free(ctx->public_key);
	}
	if (ctx->secret_key)
	{
		OQS_MEM_cleanse(ctx->secret_key, ctx->secret_key_len);
		free(ctx->secret_key);
	}
	if (ctx->shared_secret)
	{
		OQS_MEM_cleanse(ctx->shared_secret, ctx->shared_secret_len);
		free(ctx->shared_secret);
	}
	if (ctx->ciphertext)
		free(ctx->ciphertext);

	OQS_MEM_cleanse(ctx, sizeof(PqcKemContext));
	free(ctx);
}

/*
 * pqc_kem_generate_keypair
 *		Generate a KEM keypair.  Allocates public_key and secret_key
 *		in the context.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_kem_generate_keypair(PqcKemContext *ctx)
{
	OQS_KEM    *kem;
	OQS_STATUS	rc;

	if (ctx == NULL)
		return -1;

	kem = OQS_KEM_new(ctx->algorithm);
	if (kem == NULL)
		return -1;

	ctx->public_key = malloc(ctx->public_key_len);
	ctx->secret_key = malloc(ctx->secret_key_len);
	if (ctx->public_key == NULL || ctx->secret_key == NULL)
	{
		OQS_KEM_free(kem);
		return -1;
	}

	rc = OQS_KEM_keypair(kem, ctx->public_key, ctx->secret_key);
	OQS_KEM_free(kem);

	return (rc == OQS_SUCCESS) ? 0 : -1;
}

/*
 * pqc_kem_encapsulate
 *		Perform KEM encapsulation using the public key stored in ctx.
 *		Produces a ciphertext and shared secret.
 *
 * The public key must already be loaded via pqc_kem_load_public_key()
 * or pqc_kem_generate_keypair().
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_kem_encapsulate(PqcKemContext *ctx)
{
	OQS_KEM    *kem;
	OQS_STATUS	rc;

	if (ctx == NULL || ctx->public_key == NULL)
		return -1;

	kem = OQS_KEM_new(ctx->algorithm);
	if (kem == NULL)
		return -1;

	ctx->ciphertext = malloc(ctx->ciphertext_len);
	ctx->shared_secret = malloc(ctx->shared_secret_len);
	if (ctx->ciphertext == NULL || ctx->shared_secret == NULL)
	{
		OQS_KEM_free(kem);
		return -1;
	}

	rc = OQS_KEM_encaps(kem, ctx->ciphertext, ctx->shared_secret,
						 ctx->public_key);
	OQS_KEM_free(kem);

	return (rc == OQS_SUCCESS) ? 0 : -1;
}

/*
 * pqc_kem_decapsulate
 *		Perform KEM decapsulation using the secret key stored in ctx.
 *		Recovers the shared secret from the given ciphertext.
 *
 * The secret key must already be loaded via pqc_kem_load_secret_key().
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_kem_decapsulate(PqcKemContext *ctx,
					const uint8_t *ciphertext, size_t ct_len)
{
	OQS_KEM    *kem;
	OQS_STATUS	rc;

	if (ctx == NULL || ctx->secret_key == NULL)
		return -1;

	kem = OQS_KEM_new(ctx->algorithm);
	if (kem == NULL)
		return -1;

	if (ct_len != kem->length_ciphertext)
	{
		OQS_KEM_free(kem);
		return -1;
	}

	ctx->shared_secret = malloc(ctx->shared_secret_len);
	if (ctx->shared_secret == NULL)
	{
		OQS_KEM_free(kem);
		return -1;
	}

	rc = OQS_KEM_decaps(kem, ctx->shared_secret, ciphertext, ctx->secret_key);
	OQS_KEM_free(kem);

	return (rc == OQS_SUCCESS) ? 0 : -1;
}

/*
 * read_file_contents
 *		Helper to read the entire contents of a binary file.
 *
 * Returns 0 on success, -1 on failure.  On success, *buf and *len are set.
 */
static int
read_file_contents(const char *path, uint8_t **buf, size_t *len)
{
	FILE	   *fp;
	long		fsize;

	fp = fopen(path, "rb");
	if (fp == NULL)
		return -1;

	if (fseek(fp, 0, SEEK_END) != 0)
	{
		fclose(fp);
		return -1;
	}

	fsize = ftell(fp);
	if (fsize < 0)
	{
		fclose(fp);
		return -1;
	}

	if (fseek(fp, 0, SEEK_SET) != 0)
	{
		fclose(fp);
		return -1;
	}

	*buf = malloc((size_t) fsize);
	if (*buf == NULL)
	{
		fclose(fp);
		return -1;
	}

	if (fread(*buf, 1, (size_t) fsize, fp) != (size_t) fsize)
	{
		free(*buf);
		*buf = NULL;
		fclose(fp);
		return -1;
	}

	fclose(fp);
	*len = (size_t) fsize;
	return 0;
}

/*
 * pqc_kem_load_public_key
 *		Load a KEM public key from a file.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_kem_load_public_key(PqcKemContext *ctx, const char *path)
{
	uint8_t    *data;
	size_t		data_len;

	if (ctx == NULL || path == NULL)
		return -1;

	if (read_file_contents(path, &data, &data_len) != 0)
		return -1;

	if (data_len != ctx->public_key_len)
	{
		free(data);
		return -1;
	}

	/* Free any existing key */
	if (ctx->public_key)
		free(ctx->public_key);

	ctx->public_key = data;
	return 0;
}

/*
 * pqc_kem_load_secret_key
 *		Load a KEM secret key from a file.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_kem_load_secret_key(PqcKemContext *ctx, const char *path)
{
	uint8_t    *data;
	size_t		data_len;

	if (ctx == NULL || path == NULL)
		return -1;

	if (read_file_contents(path, &data, &data_len) != 0)
		return -1;

	if (data_len != ctx->secret_key_len)
	{
		free(data);
		return -1;
	}

	/* Free any existing key */
	if (ctx->secret_key)
	{
		OQS_MEM_cleanse(ctx->secret_key, ctx->secret_key_len);
		free(ctx->secret_key);
	}

	ctx->secret_key = data;
	return 0;
}

/*
 * pqc_sig_ctx_new
 *		Create a new signature context for the given algorithm name.
 *
 * Returns NULL on failure.
 */
PqcSigContext *
pqc_sig_ctx_new(const char *algorithm)
{
	PqcSigContext *ctx;
	OQS_SIG    *sig;

	/* Verify the algorithm is supported */
	sig = OQS_SIG_new(algorithm);
	if (sig == NULL)
		return NULL;

	ctx = malloc(sizeof(PqcSigContext));
	if (ctx == NULL)
	{
		OQS_SIG_free(sig);
		return NULL;
	}
	memset(ctx, 0, sizeof(PqcSigContext));

	ctx->algorithm = strdup(algorithm);
	if (ctx->algorithm == NULL)
	{
		OQS_SIG_free(sig);
		free(ctx);
		return NULL;
	}

	ctx->public_key_len = sig->length_public_key;
	ctx->secret_key_len = sig->length_secret_key;

	OQS_SIG_free(sig);
	return ctx;
}

/*
 * pqc_sig_ctx_free
 *		Free a signature context and all its associated memory.
 */
void
pqc_sig_ctx_free(PqcSigContext *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->algorithm)
		free(ctx->algorithm);
	if (ctx->public_key)
	{
		OQS_MEM_cleanse(ctx->public_key, ctx->public_key_len);
		free(ctx->public_key);
	}
	if (ctx->secret_key)
	{
		OQS_MEM_cleanse(ctx->secret_key, ctx->secret_key_len);
		free(ctx->secret_key);
	}

	OQS_MEM_cleanse(ctx, sizeof(PqcSigContext));
	free(ctx);
}

/*
 * pqc_sig_load_keys
 *		Load signature public and/or secret keys from files.
 *		Either path may be NULL to skip loading that key.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_sig_load_keys(PqcSigContext *ctx,
				  const char *pub_path, const char *sec_path)
{
	if (ctx == NULL)
		return -1;

	if (pub_path != NULL)
	{
		uint8_t    *data;
		size_t		data_len;

		if (read_file_contents(pub_path, &data, &data_len) != 0)
			return -1;

		if (data_len != ctx->public_key_len)
		{
			free(data);
			return -1;
		}

		if (ctx->public_key)
			free(ctx->public_key);
		ctx->public_key = data;
	}

	if (sec_path != NULL)
	{
		uint8_t    *data;
		size_t		data_len;

		if (read_file_contents(sec_path, &data, &data_len) != 0)
			return -1;

		if (data_len != ctx->secret_key_len)
		{
			free(data);
			return -1;
		}

		if (ctx->secret_key)
		{
			OQS_MEM_cleanse(ctx->secret_key, ctx->secret_key_len);
			free(ctx->secret_key);
		}
		ctx->secret_key = data;
	}

	return 0;
}

/*
 * pqc_common_sign
 *		Sign a message using the secret key in the context.
 *
 * On success, *sig is allocated with malloc and must be freed by the caller.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_common_sign(PqcSigContext *ctx,
				const uint8_t *msg, size_t msg_len,
				uint8_t **sig, size_t *sig_len)
{
	OQS_SIG    *oqs_sig;
	OQS_STATUS	rc;

	if (ctx == NULL || ctx->secret_key == NULL || msg == NULL)
		return -1;

	oqs_sig = OQS_SIG_new(ctx->algorithm);
	if (oqs_sig == NULL)
		return -1;

	*sig = malloc(oqs_sig->length_signature);
	if (*sig == NULL)
	{
		OQS_SIG_free(oqs_sig);
		return -1;
	}

	rc = OQS_SIG_sign(oqs_sig, *sig, sig_len, msg, msg_len, ctx->secret_key);
	OQS_SIG_free(oqs_sig);

	if (rc != OQS_SUCCESS)
	{
		free(*sig);
		*sig = NULL;
		*sig_len = 0;
		return -1;
	}

	return 0;
}

/*
 * pqc_common_verify
 *		Verify a signature using the public key in the context.
 *
 * Returns 0 on success (valid signature), -1 on failure.
 */
int
pqc_common_verify(PqcSigContext *ctx,
				  const uint8_t *msg, size_t msg_len,
				  const uint8_t *sig, size_t sig_len)
{
	OQS_SIG    *oqs_sig;
	OQS_STATUS	rc;

	if (ctx == NULL || ctx->public_key == NULL || msg == NULL || sig == NULL)
		return -1;

	oqs_sig = OQS_SIG_new(ctx->algorithm);
	if (oqs_sig == NULL)
		return -1;

	rc = OQS_SIG_verify(oqs_sig, msg, msg_len, sig, sig_len, ctx->public_key);
	OQS_SIG_free(oqs_sig);

	return (rc == OQS_SUCCESS) ? 0 : -1;
}

/*
 * pqc_aes256gcm_encrypt
 *		Encrypt data with AES-256-GCM using the OpenSSL EVP interface.
 *
 * key must be 32 bytes.  iv is the nonce (typically 12 bytes).
 * tag must point to a buffer of tag_len bytes (typically 16).
 * ciphertext buffer must be at least pt_len + 16 bytes.
 * *ct_len is set to the actual ciphertext length on return.
 *
 * Returns 0 on success, -1 on failure.
 */
int
pqc_aes256gcm_encrypt(const uint8_t *key,
					  const uint8_t *iv, size_t iv_len,
					  const uint8_t *plaintext, size_t pt_len,
					  uint8_t *ciphertext, size_t *ct_len,
					  uint8_t *tag, size_t tag_len)
{
	EVP_CIPHER_CTX *evp_ctx;
	int			outlen;
	int			tmplen;

	evp_ctx = EVP_CIPHER_CTX_new();
	if (evp_ctx == NULL)
		return -1;

	if (EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto err;

	/* Set IV length */
	if (EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN,
							(int) iv_len, NULL) != 1)
		goto err;

	/* Set key and IV */
	if (EVP_EncryptInit_ex(evp_ctx, NULL, NULL, key, iv) != 1)
		goto err;

	/* Encrypt */
	if (EVP_EncryptUpdate(evp_ctx, ciphertext, &outlen,
						  plaintext, (int) pt_len) != 1)
		goto err;

	/* Finalize */
	if (EVP_EncryptFinal_ex(evp_ctx, ciphertext + outlen, &tmplen) != 1)
		goto err;

	outlen += tmplen;
	*ct_len = (size_t) outlen;

	/* Get the authentication tag */
	if (EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG,
							(int) tag_len, tag) != 1)
		goto err;

	EVP_CIPHER_CTX_free(evp_ctx);
	return 0;

err:
	EVP_CIPHER_CTX_free(evp_ctx);
	return -1;
}

/*
 * pqc_aes256gcm_decrypt
 *		Decrypt data with AES-256-GCM using the OpenSSL EVP interface.
 *
 * key must be 32 bytes.  iv is the nonce (typically 12 bytes).
 * tag is the authentication tag (typically 16 bytes).
 * plaintext buffer must be at least ct_len bytes.
 * *pt_len is set to the actual plaintext length on return.
 *
 * Returns 0 on success, -1 on failure (including authentication failure).
 */
int
pqc_aes256gcm_decrypt(const uint8_t *key,
					  const uint8_t *iv, size_t iv_len,
					  const uint8_t *ciphertext, size_t ct_len,
					  const uint8_t *tag, size_t tag_len,
					  uint8_t *plaintext, size_t *pt_len)
{
	EVP_CIPHER_CTX *evp_ctx;
	int			outlen;
	int			tmplen;

	evp_ctx = EVP_CIPHER_CTX_new();
	if (evp_ctx == NULL)
		return -1;

	if (EVP_DecryptInit_ex(evp_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto err;

	/* Set IV length */
	if (EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN,
							(int) iv_len, NULL) != 1)
		goto err;

	/* Set key and IV */
	if (EVP_DecryptInit_ex(evp_ctx, NULL, NULL, key, iv) != 1)
		goto err;

	/* Decrypt */
	if (EVP_DecryptUpdate(evp_ctx, plaintext, &outlen,
						  ciphertext, (int) ct_len) != 1)
		goto err;

	/* Set the expected tag */
	if (EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG,
							(int) tag_len, (void *) tag) != 1)
		goto err;

	/* Finalize and verify tag */
	if (EVP_DecryptFinal_ex(evp_ctx, plaintext + outlen, &tmplen) != 1)
		goto err;

	outlen += tmplen;
	*pt_len = (size_t) outlen;

	EVP_CIPHER_CTX_free(evp_ctx);
	return 0;

err:
	EVP_CIPHER_CTX_free(evp_ctx);
	return -1;
}

#endif							/* USE_PQC */
