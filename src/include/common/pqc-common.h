/*-------------------------------------------------------------------------
 *
 * pqc-common.h
 *		Declarations for PQC (Post-Quantum Cryptography) common functions
 *		shared between frontend and backend.
 *
 * FortressQL: This provides KEM and signature operations using liboqs,
 * plus AES-256-GCM encryption using OpenSSL EVP, for encrypted and
 * signed database backups.
 *
 * Portions Copyright (c) 2024, PostgreSQL Global Development Group
 *
 * src/include/common/pqc-common.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PQC_COMMON_H
#define PQC_COMMON_H

#ifdef USE_PQC
#include <oqs/oqs.h>

/* KEM operations for dump encryption */
typedef struct PqcKemContext
{
	char	   *algorithm;
	uint8_t    *public_key;
	size_t		public_key_len;
	uint8_t    *secret_key;
	size_t		secret_key_len;
	uint8_t    *shared_secret;
	size_t		shared_secret_len;
	uint8_t    *ciphertext;
	size_t		ciphertext_len;
} PqcKemContext;

/* Signature operations for dump signing */
typedef struct PqcSigContext
{
	char	   *algorithm;
	uint8_t    *public_key;
	size_t		public_key_len;
	uint8_t    *secret_key;
	size_t		secret_key_len;
} PqcSigContext;

extern PqcKemContext *pqc_kem_ctx_new(const char *algorithm);
extern void pqc_kem_ctx_free(PqcKemContext *ctx);
extern int pqc_kem_generate_keypair(PqcKemContext *ctx);
extern int pqc_kem_encapsulate(PqcKemContext *ctx);
extern int pqc_kem_decapsulate(PqcKemContext *ctx,
							   const uint8_t *ciphertext, size_t ct_len);
extern int pqc_kem_load_public_key(PqcKemContext *ctx, const char *path);
extern int pqc_kem_load_secret_key(PqcKemContext *ctx, const char *path);

extern PqcSigContext *pqc_sig_ctx_new(const char *algorithm);
extern void pqc_sig_ctx_free(PqcSigContext *ctx);
extern int pqc_sig_load_keys(PqcSigContext *ctx,
							 const char *pub_path, const char *sec_path);
extern int pqc_common_sign(PqcSigContext *ctx,
						   const uint8_t *msg, size_t msg_len,
						   uint8_t **sig, size_t *sig_len);
extern int pqc_common_verify(PqcSigContext *ctx,
							 const uint8_t *msg, size_t msg_len,
							 const uint8_t *sig, size_t sig_len);

/* AES-256-GCM encryption using shared secret */
extern int pqc_aes256gcm_encrypt(const uint8_t *key,
								 const uint8_t *iv, size_t iv_len,
								 const uint8_t *plaintext, size_t pt_len,
								 uint8_t *ciphertext, size_t *ct_len,
								 uint8_t *tag, size_t tag_len);
extern int pqc_aes256gcm_decrypt(const uint8_t *key,
								 const uint8_t *iv, size_t iv_len,
								 const uint8_t *ciphertext, size_t ct_len,
								 const uint8_t *tag, size_t tag_len,
								 uint8_t *plaintext, size_t *pt_len);

#endif							/* USE_PQC */
#endif							/* PQC_COMMON_H */
