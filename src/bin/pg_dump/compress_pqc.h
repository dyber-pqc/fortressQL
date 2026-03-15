/*-------------------------------------------------------------------------
 *
 * compress_pqc.h
 *		PQC encryption/decryption and signing/verification wrapper for
 *		pg_dump/pg_restore data streams.
 *
 * FortressQL: Post-Quantum Cryptography support for backup encryption
 * and signing.
 *
 * Portions Copyright (c) 2024, PostgreSQL Global Development Group
 *
 * src/bin/pg_dump/compress_pqc.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef COMPRESS_PQC_H
#define COMPRESS_PQC_H

#ifdef USE_PQC

#include <openssl/evp.h>

#include "common/pqc-common.h"

/* AES-256-GCM constants */
#define PQC_AES_KEY_LEN		32
#define PQC_AES_IV_LEN		12
#define PQC_AES_TAG_LEN		16

/* Chunk size for streaming encryption/decryption */
#define PQC_CHUNK_SIZE		(64 * 1024)

/*
 * State for PQC encryption during dump.
 */
typedef struct PqcEncryptorState
{
	PqcKemContext *kem_ctx;		/* KEM context with shared secret */
	uint8_t		aes_key[PQC_AES_KEY_LEN];	/* derived AES-256 key */
	uint8_t		aes_iv[PQC_AES_IV_LEN];	/* current IV/nonce */
	uint64_t	chunk_counter;	/* incremented per chunk for unique nonce */
	EVP_MD_CTX *hash_ctx;		/* running SHA-256 hash for signing */
} PqcEncryptorState;

/*
 * State for PQC decryption during restore.
 */
typedef struct PqcDecryptorState
{
	PqcKemContext *kem_ctx;		/* KEM context with shared secret */
	uint8_t		aes_key[PQC_AES_KEY_LEN];	/* derived AES-256 key */
	uint8_t		aes_iv[PQC_AES_IV_LEN];	/* base IV/nonce */
	uint64_t	chunk_counter;	/* incremented per chunk */
	EVP_MD_CTX *hash_ctx;		/* running SHA-256 hash for verification */
} PqcDecryptorState;

/*
 * State for PQC signing during dump.
 */
typedef struct PqcSignState
{
	PqcSigContext *sig_ctx;		/* signature context with secret key */
	EVP_MD_CTX *hash_ctx;		/* running SHA-256 hash */
} PqcSignState;

/*
 * State for PQC verification during restore.
 */
typedef struct PqcVerifyState
{
	PqcSigContext *sig_ctx;		/* signature context with public key */
	EVP_MD_CTX *hash_ctx;		/* running SHA-256 hash */
} PqcVerifyState;

/* Encryption functions */
extern PqcEncryptorState *pqc_encrypt_init(const char *pubkey_path,
										   const char *algorithm);
extern int	pqc_encrypt_data(PqcEncryptorState *state,
							 const uint8_t *input, size_t input_len,
							 uint8_t **output, size_t *output_len);
extern int	pqc_encrypt_finish(PqcEncryptorState *state,
							   uint8_t **kem_ciphertext,
							   size_t *kem_ct_len,
							   uint8_t *base_iv_out);
extern void pqc_encrypt_free(PqcEncryptorState *state);

/* Decryption functions */
extern PqcDecryptorState *pqc_decrypt_init(const char *seckey_path,
										   const char *algorithm,
										   const uint8_t *ciphertext,
										   size_t ct_len,
										   const uint8_t *base_iv);
extern int	pqc_decrypt_data(PqcDecryptorState *state,
							 const uint8_t *input, size_t input_len,
							 uint8_t **output, size_t *output_len);
extern int	pqc_decrypt_finish(PqcDecryptorState *state);
extern void pqc_decrypt_free(PqcDecryptorState *state);

/* Signing functions */
extern PqcSignState *pqc_sign_init(const char *seckey_path,
								   const char *algorithm);
extern int	pqc_sign_update(PqcSignState *state,
							const uint8_t *data, size_t len);
extern int	pqc_sign_finish(PqcSignState *state,
							uint8_t **sig_out, size_t *sig_len);
extern void pqc_sign_free(PqcSignState *state);

/* Verification functions */
extern PqcVerifyState *pqc_verify_init(const char *pubkey_path,
									   const char *algorithm);
extern int	pqc_verify_update(PqcVerifyState *state,
							  const uint8_t *data, size_t len);
extern int	pqc_verify_finish(PqcVerifyState *state,
							  const uint8_t *sig, size_t sig_len);
extern void pqc_verify_free(PqcVerifyState *state);

#endif							/* USE_PQC */
#endif							/* COMPRESS_PQC_H */
