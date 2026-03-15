/*-------------------------------------------------------------------------
 *
 * pgcrypto_pqc.c
 *	  FortressQL: SQL-callable Post-Quantum Cryptography functions.
 *
 * Provides KEM (key encapsulation), digital signatures, hybrid
 * encryption (ML-KEM + AES-256-GCM), and hybrid proof audit logging
 * with dual classical+PQC signatures through SQL functions.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  contrib/pgcrypto_pqc/pgcrypto_pqc.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "catalog/pg_authid.h"
#include "commands/dbcommands.h"
#include "crypto/pqc/pqc_common.h"
#include "crypto/pqc/pqc_kem.h"
#include "crypto/pqc/pqc_sig.h"
#include "crypto/pqc/pqc_wal_keys.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "nodes/parsenodes.h"
#include "tcop/utility.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "port/pg_bswap.h"
#include "utils/jsonb.h"
#include "utils/snapmgr.h"
#include "utils/timestamp.h"

#ifdef USE_PQC
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#endif

PG_MODULE_MAGIC;

/* ------------------------------------------------------------ */
/*			 GUC variables									     */
/* ------------------------------------------------------------ */

static bool pqc_audit_enabled = false;
static char *pqc_audit_events = NULL;

/* ------------------------------------------------------------ */
/*			 ProcessUtility hook                                 */
/* ------------------------------------------------------------ */

static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/* Forward declarations */
static void pqc_audit_process_utility(PlannedStmt *pstmt,
									  const char *queryString,
									  bool readOnlyTree,
									  ProcessUtilityContext context,
									  ParamListInfo params,
									  QueryEnvironment *queryEnv,
									  DestReceiver *dest,
									  QueryCompletion *qc);

#ifdef USE_PQC
static void audit_log_ddl_event(const char *event_type,
								const char *object_name,
								const char *query_string);
static bool audit_event_is_enabled(const char *event_type);
#endif

/* ------------------------------------------------------------ */
/*			 Module init / fini                                  */
/* ------------------------------------------------------------ */

void		_PG_init(void);

void
_PG_init(void)
{
	DefineCustomBoolVariable("pqc_audit.enabled",
							 "Enable hybrid proof audit logging.",
							 NULL,
							 &pqc_audit_enabled,
							 false,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomStringVariable("pqc_audit.events",
							   "Comma-separated list of event categories to audit.",
							   NULL,
							   &pqc_audit_events,
							   "ddl,auth,policy,grant",
							   PGC_SUSET,
							   0,
							   NULL,
							   NULL,
							   NULL);

	MarkGUCPrefixReserved("pqc_audit");

	/* Install ProcessUtility hook */
	prev_ProcessUtility = ProcessUtility_hook;
	ProcessUtility_hook = pqc_audit_process_utility;
}

/* ------------------------------------------------------------ */
/*			 Helper functions								     */
/* ------------------------------------------------------------ */

/*
 * Parse algorithm name from SQL text argument.
 */
static PqcAlgorithm
parse_algorithm(text *alg_text)
{
	char	   *alg_name = text_to_cstring(alg_text);
	PqcAlgorithm alg = pqc_algorithm_from_name(alg_name);

	if (alg >= PQC_ALG_COUNT)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("unknown PQC algorithm: \"%s\"", alg_name),
				 errhint("Use SELECT * FROM pqc_algorithms() to list available algorithms.")));

	pfree(alg_name);
	return alg;
}

/*
 * Create a bytea datum from raw bytes.
 */
static bytea *
make_bytea(const uint8 *data, size_t len)
{
	bytea	   *result = (bytea *) palloc(VARHDRSZ + len);

	SET_VARSIZE(result, VARHDRSZ + len);
	memcpy(VARDATA(result), data, len);
	return result;
}

/* ------------------------------------------------------------ */
/*			 KEM Functions									     */
/* ------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(pgcrypto_pqc_kem_keygen);

Datum
pgcrypto_pqc_kem_keygen(PG_FUNCTION_ARGS)
{
	text	   *alg_text = PG_GETARG_TEXT_PP(0);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcKemContext *ctx;
	uint8	   *pk,
			   *sk;
	size_t		pk_len,
				sk_len;
	TupleDesc	tupdesc;
	Datum		values[2];
	bool		nulls[2] = {false, false};
	HeapTuple	tuple;

	if (!pqc_algorithm_is_kem(alg))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("\"%s\" is not a KEM algorithm", pqc_algorithm_name(alg))));

	ctx = pqc_kem_new(alg);

	if (pqc_kem_keygen(ctx, &pk, &pk_len, &sk, &sk_len) != PQC_SUCCESS)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("PQC KEM key generation failed for %s",
						pqc_algorithm_name(alg))));

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupdesc = BlessTupleDesc(tupdesc);

	values[0] = PointerGetDatum(make_bytea(pk, pk_len));
	values[1] = PointerGetDatum(make_bytea(sk, sk_len));

	pfree(pk);
	pqc_secure_free(sk, sk_len);
	pqc_kem_free(ctx);

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

PG_FUNCTION_INFO_V1(pqc_kem_encapsulate);

Datum
pqc_kem_encapsulate(PG_FUNCTION_ARGS)
{
	bytea	   *pk_bytea = PG_GETARG_BYTEA_PP(0);
	text	   *alg_text = PG_GETARG_TEXT_PP(1);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcKemContext *ctx;
	uint8	   *ct,
			   *ss;
	size_t		ct_len,
				ss_len;
	TupleDesc	tupdesc;
	Datum		values[2];
	bool		nulls[2] = {false, false};
	HeapTuple	tuple;

	ctx = pqc_kem_new(alg);

	if (pqc_kem_encaps(ctx,
					   (uint8 *) VARDATA_ANY(pk_bytea),
					   VARSIZE_ANY_EXHDR(pk_bytea),
					   &ct, &ct_len, &ss, &ss_len) != PQC_SUCCESS)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("PQC KEM encapsulation failed")));

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupdesc = BlessTupleDesc(tupdesc);

	values[0] = PointerGetDatum(make_bytea(ct, ct_len));
	values[1] = PointerGetDatum(make_bytea(ss, ss_len));

	pfree(ct);
	pqc_secure_free(ss, ss_len);
	pqc_kem_free(ctx);

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

PG_FUNCTION_INFO_V1(pqc_kem_decapsulate);

Datum
pqc_kem_decapsulate(PG_FUNCTION_ARGS)
{
	bytea	   *ct_bytea = PG_GETARG_BYTEA_PP(0);
	bytea	   *sk_bytea = PG_GETARG_BYTEA_PP(1);
	text	   *alg_text = PG_GETARG_TEXT_PP(2);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcKemContext *ctx;
	uint8	   *ss;
	size_t		ss_len;
	bytea	   *result;

	ctx = pqc_kem_new(alg);

	if (pqc_kem_decaps(ctx,
					   (uint8 *) VARDATA_ANY(ct_bytea),
					   VARSIZE_ANY_EXHDR(ct_bytea),
					   (uint8 *) VARDATA_ANY(sk_bytea),
					   VARSIZE_ANY_EXHDR(sk_bytea),
					   &ss, &ss_len) != PQC_SUCCESS)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("PQC KEM decapsulation failed")));

	result = make_bytea(ss, ss_len);
	pqc_secure_free(ss, ss_len);
	pqc_kem_free(ctx);

	PG_RETURN_BYTEA_P(result);
}

/* ------------------------------------------------------------ */
/*			 Signature Functions							     */
/* ------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(pgcrypto_pqc_sig_keygen);

Datum
pgcrypto_pqc_sig_keygen(PG_FUNCTION_ARGS)
{
	text	   *alg_text = PG_GETARG_TEXT_PP(0);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcSigContext *ctx;
	uint8	   *pk,
			   *sk;
	size_t		pk_len,
				sk_len;
	TupleDesc	tupdesc;
	Datum		values[2];
	bool		nulls[2] = {false, false};
	HeapTuple	tuple;

	if (!pqc_algorithm_is_sig(alg))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("\"%s\" is not a signature algorithm",
						pqc_algorithm_name(alg))));

	ctx = pqc_sig_new(alg);

	if (pqc_sig_keygen(ctx, &pk, &pk_len, &sk, &sk_len) != PQC_SUCCESS)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("PQC signature key generation failed for %s",
						pqc_algorithm_name(alg))));

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupdesc = BlessTupleDesc(tupdesc);

	values[0] = PointerGetDatum(make_bytea(pk, pk_len));
	values[1] = PointerGetDatum(make_bytea(sk, sk_len));

	pfree(pk);
	pqc_secure_free(sk, sk_len);
	pqc_sig_free(ctx);

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

PG_FUNCTION_INFO_V1(pqc_sign);

Datum
pqc_sign(PG_FUNCTION_ARGS)
{
	bytea	   *msg_bytea = PG_GETARG_BYTEA_PP(0);
	bytea	   *sk_bytea = PG_GETARG_BYTEA_PP(1);
	text	   *alg_text = PG_GETARG_TEXT_PP(2);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcSigContext *ctx;
	uint8	   *sig;
	size_t		sig_len;
	bytea	   *result;

	ctx = pqc_sig_new(alg);

	if (pqc_sig_sign(ctx,
					 (uint8 *) VARDATA_ANY(msg_bytea),
					 VARSIZE_ANY_EXHDR(msg_bytea),
					 (uint8 *) VARDATA_ANY(sk_bytea),
					 VARSIZE_ANY_EXHDR(sk_bytea),
					 &sig, &sig_len) != PQC_SUCCESS)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("PQC signature generation failed")));

	result = make_bytea(sig, sig_len);
	pfree(sig);
	pqc_sig_free(ctx);

	PG_RETURN_BYTEA_P(result);
}

PG_FUNCTION_INFO_V1(pqc_verify);

Datum
pqc_verify(PG_FUNCTION_ARGS)
{
	bytea	   *msg_bytea = PG_GETARG_BYTEA_PP(0);
	bytea	   *sig_bytea = PG_GETARG_BYTEA_PP(1);
	bytea	   *pk_bytea = PG_GETARG_BYTEA_PP(2);
	text	   *alg_text = PG_GETARG_TEXT_PP(3);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcSigContext *ctx;
	PqcStatus	status;

	ctx = pqc_sig_new(alg);

	status = pqc_sig_verify(ctx,
							(uint8 *) VARDATA_ANY(msg_bytea),
							VARSIZE_ANY_EXHDR(msg_bytea),
							(uint8 *) VARDATA_ANY(sig_bytea),
							VARSIZE_ANY_EXHDR(sig_bytea),
							(uint8 *) VARDATA_ANY(pk_bytea),
							VARSIZE_ANY_EXHDR(pk_bytea));

	pqc_sig_free(ctx);

	PG_RETURN_BOOL(status == PQC_SUCCESS);
}

/* ------------------------------------------------------------ */
/*			 Hybrid Encryption (ML-KEM + AES-256-GCM)		     */
/* ------------------------------------------------------------ */

#ifdef USE_PQC

/*
 * AES-256-GCM constants
 */
#define AES_GCM_KEY_LEN		32
#define AES_GCM_IV_LEN		12
#define AES_GCM_TAG_LEN		16

/* SHA-384 digest length for audit hash chain */
#define AUDIT_HASH_LEN		48

/*
 * Derive AES-256 key from KEM shared secret using HKDF-SHA256.
 */
static void
derive_aes_key(const uint8 *shared_secret, size_t ss_len,
			   uint8 *aes_key)
{
	EVP_PKEY_CTX *pctx;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("HKDF initialization failed")));

	if (EVP_PKEY_derive_init(pctx) <= 0 ||
		EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
		EVP_PKEY_CTX_set1_hkdf_salt(pctx,
									(const unsigned char *) "FortressQL-PQC-v1",
									17) <= 0 ||
		EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, ss_len) <= 0 ||
		EVP_PKEY_CTX_add1_hkdf_info(pctx,
									(const unsigned char *) "aes-256-gcm",
									11) <= 0)
	{
		EVP_PKEY_CTX_free(pctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("HKDF parameter setup failed")));
	}

	{
		size_t		keylen = AES_GCM_KEY_LEN;

		if (EVP_PKEY_derive(pctx, aes_key, &keylen) <= 0)
		{
			EVP_PKEY_CTX_free(pctx);
			ereport(ERROR,
					(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
					 errmsg("HKDF key derivation failed")));
		}
	}

	EVP_PKEY_CTX_free(pctx);
}

/*
 * AES-256-GCM encrypt.
 *
 * Output format: [12-byte IV] [ciphertext] [16-byte GCM tag]
 */
static bytea *
aes_gcm_encrypt(const uint8 *plaintext, size_t pt_len,
				const uint8 *key)
{
	EVP_CIPHER_CTX *ctx;
	uint8		iv[AES_GCM_IV_LEN];
	int			outlen,
				tmplen;
	size_t		total_len;
	bytea	   *result;
	uint8	   *out;

	/* Generate random IV */
	if (RAND_bytes(iv, AES_GCM_IV_LEN) != 1)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("failed to generate random IV")));

	/* Output: IV + ciphertext + tag */
	total_len = AES_GCM_IV_LEN + pt_len + AES_GCM_TAG_LEN;
	result = (bytea *) palloc(VARHDRSZ + total_len);
	SET_VARSIZE(result, VARHDRSZ + total_len);
	out = (uint8 *) VARDATA(result);

	/* Copy IV to output */
	memcpy(out, iv, AES_GCM_IV_LEN);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("failed to create cipher context")));

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
		EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
		EVP_EncryptUpdate(ctx, out + AES_GCM_IV_LEN, &outlen,
						  plaintext, pt_len) != 1 ||
		EVP_EncryptFinal_ex(ctx, out + AES_GCM_IV_LEN + outlen, &tmplen) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("AES-256-GCM encryption failed")));
	}

	outlen += tmplen;

	/* Append GCM authentication tag */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN,
							out + AES_GCM_IV_LEN + outlen) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("failed to get GCM authentication tag")));
	}

	EVP_CIPHER_CTX_free(ctx);
	return result;
}

/*
 * AES-256-GCM decrypt.
 *
 * Input format: [12-byte IV] [ciphertext] [16-byte GCM tag]
 */
static bytea *
aes_gcm_decrypt(const uint8 *data, size_t data_len,
				const uint8 *key)
{
	EVP_CIPHER_CTX *ctx;
	const uint8 *iv;
	const uint8 *ciphertext;
	size_t		ct_len;
	const uint8 *tag;
	int			outlen,
				tmplen;
	bytea	   *result;

	if (data_len < AES_GCM_IV_LEN + AES_GCM_TAG_LEN)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("encrypted data too short")));

	iv = data;
	ct_len = data_len - AES_GCM_IV_LEN - AES_GCM_TAG_LEN;
	ciphertext = data + AES_GCM_IV_LEN;
	tag = data + AES_GCM_IV_LEN + ct_len;

	result = (bytea *) palloc(VARHDRSZ + ct_len);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("failed to create cipher context")));

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
		EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
		EVP_DecryptUpdate(ctx, (uint8 *) VARDATA(result), &outlen,
						  ciphertext, ct_len) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("AES-256-GCM decryption failed")));
	}

	/* Set expected tag for verification */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN,
							(void *) tag) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("failed to set GCM tag for verification")));
	}

	if (EVP_DecryptFinal_ex(ctx, (uint8 *) VARDATA(result) + outlen,
							&tmplen) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("AES-256-GCM authentication failed: data has been tampered with")));
	}

	outlen += tmplen;
	SET_VARSIZE(result, VARHDRSZ + outlen);
	EVP_CIPHER_CTX_free(ctx);

	return result;
}

/* ------------------------------------------------------------ */
/*			 Ed25519 Classical Signature Helpers                 */
/* ------------------------------------------------------------ */

/*
 * Generate an Ed25519 key pair via OpenSSL EVP.
 *
 * Caller must free *pk with pfree() and *sk with
 * explicit_bzero + pfree.
 */
static void
ed25519_keygen(uint8 **pk, size_t *pk_len, uint8 **sk, size_t *sk_len)
{
	EVP_PKEY	   *pkey = NULL;
	EVP_PKEY_CTX   *pctx;
	unsigned char  *raw_pub = NULL;
	unsigned char  *raw_priv = NULL;
	size_t			pub_len = 0;
	size_t			priv_len = 0;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	if (pctx == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("Ed25519 context creation failed")));

	if (EVP_PKEY_keygen_init(pctx) <= 0 ||
		EVP_PKEY_keygen(pctx, &pkey) <= 0)
	{
		EVP_PKEY_CTX_free(pctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("Ed25519 key generation failed")));
	}
	EVP_PKEY_CTX_free(pctx);

	/* Extract raw public key */
	if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len) != 1)
	{
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("failed to get Ed25519 public key length")));
	}
	raw_pub = palloc(pub_len);
	if (EVP_PKEY_get_raw_public_key(pkey, raw_pub, &pub_len) != 1)
	{
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("failed to extract Ed25519 public key")));
	}

	/* Extract raw private key */
	if (EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len) != 1)
	{
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("failed to get Ed25519 private key length")));
	}
	raw_priv = palloc(priv_len);
	if (EVP_PKEY_get_raw_private_key(pkey, raw_priv, &priv_len) != 1)
	{
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("failed to extract Ed25519 private key")));
	}

	EVP_PKEY_free(pkey);

	*pk = raw_pub;
	*pk_len = pub_len;
	*sk = raw_priv;
	*sk_len = priv_len;
}

/*
 * Sign a message with Ed25519 using the one-shot EVP_DigestSign API.
 *
 * Returns a palloc'd signature; sets *sig_len.
 */
static uint8 *
ed25519_sign(const uint8 *message, size_t message_len,
			 const uint8 *secret_key, size_t secret_key_len,
			 size_t *sig_len)
{
	EVP_PKEY	   *pkey;
	EVP_MD_CTX	   *mdctx;
	uint8		   *sig;
	size_t			slen;

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
										secret_key, secret_key_len);
	if (pkey == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("failed to load Ed25519 private key")));

	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL)
	{
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("failed to create digest context")));
	}

	if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1)
	{
		EVP_MD_CTX_free(mdctx);
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("Ed25519 sign init failed")));
	}

	/* Determine signature size */
	if (EVP_DigestSign(mdctx, NULL, &slen, message, message_len) != 1)
	{
		EVP_MD_CTX_free(mdctx);
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("Ed25519 sign size query failed")));
	}

	sig = palloc(slen);

	if (EVP_DigestSign(mdctx, sig, &slen, message, message_len) != 1)
	{
		EVP_MD_CTX_free(mdctx);
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("Ed25519 signature generation failed")));
	}

	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);

	*sig_len = slen;
	return sig;
}

/*
 * Verify an Ed25519 signature using the one-shot EVP_DigestVerify API.
 *
 * Returns true if the signature is valid.
 */
static bool
ed25519_verify(const uint8 *message, size_t message_len,
			   const uint8 *signature, size_t signature_len,
			   const uint8 *public_key, size_t public_key_len)
{
	EVP_PKEY   *pkey;
	EVP_MD_CTX *mdctx;
	int			rc;

	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
									   public_key, public_key_len);
	if (pkey == NULL)
		return false;

	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL)
	{
		EVP_PKEY_free(pkey);
		return false;
	}

	if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) != 1)
	{
		EVP_MD_CTX_free(mdctx);
		EVP_PKEY_free(pkey);
		return false;
	}

	rc = EVP_DigestVerify(mdctx, signature, signature_len,
						  message, message_len);

	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);

	return (rc == 1);
}

/*
 * Compute SHA-384 hash of the given data.
 *
 * Returns a palloc'd buffer of AUDIT_HASH_LEN bytes.
 */
static uint8 *
compute_sha384(const uint8 *data, size_t data_len)
{
	EVP_MD_CTX *mdctx;
	uint8	   *hash;
	unsigned int hash_len;

	hash = palloc(AUDIT_HASH_LEN);

	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("failed to create SHA-384 digest context")));

	if (EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL) != 1 ||
		EVP_DigestUpdate(mdctx, data, data_len) != 1 ||
		EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
	{
		EVP_MD_CTX_free(mdctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("SHA-384 hash computation failed")));
	}

	EVP_MD_CTX_free(mdctx);
	return hash;
}

/*
 * Compute the entry hash for an audit log row.
 *
 * The hash covers: event_type || event_detail_json || classical_sig ||
 *                  pqc_sig || prev_hash
 *
 * Returns a palloc'd SHA-384 digest.
 */
static uint8 *
compute_entry_hash(const char *event_type,
				   const char *event_detail_json,
				   const uint8 *classical_sig, size_t classical_sig_len,
				   const uint8 *pqc_sig, size_t pqc_sig_len,
				   const uint8 *prev_hash, size_t prev_hash_len)
{
	EVP_MD_CTX *mdctx;
	uint8	   *hash;
	unsigned int hash_len;

	hash = palloc(AUDIT_HASH_LEN);

	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("failed to create digest context for entry hash")));

	if (EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL) != 1)
	{
		EVP_MD_CTX_free(mdctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("SHA-384 init failed for entry hash")));
	}

	EVP_DigestUpdate(mdctx, event_type, strlen(event_type));
	EVP_DigestUpdate(mdctx, event_detail_json, strlen(event_detail_json));
	EVP_DigestUpdate(mdctx, classical_sig, classical_sig_len);
	EVP_DigestUpdate(mdctx, pqc_sig, pqc_sig_len);
	if (prev_hash != NULL && prev_hash_len > 0)
		EVP_DigestUpdate(mdctx, prev_hash, prev_hash_len);

	if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
	{
		EVP_MD_CTX_free(mdctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("SHA-384 finalize failed for entry hash")));
	}

	EVP_MD_CTX_free(mdctx);
	return hash;
}

/*
 * Check whether a given event category is enabled in pqc_audit.events.
 */
static bool
audit_event_is_enabled(const char *event_type)
{
	const char *p;
	size_t		etype_len;

	if (pqc_audit_events == NULL || pqc_audit_events[0] == '\0')
		return false;

	etype_len = strlen(event_type);
	p = pqc_audit_events;

	while (*p != '\0')
	{
		const char *start;
		size_t		token_len;

		/* Skip leading whitespace and commas */
		while (*p == ' ' || *p == ',')
			p++;

		if (*p == '\0')
			break;

		start = p;
		while (*p != '\0' && *p != ',')
			p++;

		token_len = p - start;

		/* Trim trailing whitespace */
		while (token_len > 0 && start[token_len - 1] == ' ')
			token_len--;

		if (token_len == etype_len &&
			pg_strncasecmp(start, event_type, etype_len) == 0)
			return true;
	}

	return false;
}

/*
 * Load active audit keys from pqc_audit_keys via SPI.
 *
 * Fetches the active key for the given purpose.  Returns true if found,
 * with output parameters set.  Caller must pfree the output buffers.
 */
static bool
load_audit_key(const char *purpose,
			   char **out_algorithm,
			   uint8 **out_public_key, size_t *out_pk_len,
			   uint8 **out_secret_key, size_t *out_sk_len)
{
	int			ret;
	bool		found = false;
	Oid			argtypes[1] = {TEXTOID};
	Datum		argvals[1];

	/* Use parameterized query to prevent SQL injection */
	argvals[0] = CStringGetTextDatum(purpose);

	ret = SPI_execute_with_args(
		"SELECT algorithm, public_key, encrypted_secret_key "
		"FROM pqc_audit_keys "
		"WHERE key_purpose = $1 AND is_active = true "
		"ORDER BY key_id DESC LIMIT 1",
		1, argtypes, argvals, NULL, true, 1);

	if (ret == SPI_OK_SELECT && SPI_processed > 0)
	{
		bool		isnull;
		Datum		alg_datum;
		Datum		pk_datum;
		Datum		sk_datum;
		bytea	   *pk_bytea;
		bytea	   *sk_bytea;

		alg_datum = SPI_getbinval(SPI_tuptable->vals[0],
								 SPI_tuptable->tupdesc, 1, &isnull);
		if (!isnull)
		{
			*out_algorithm = pstrdup(TextDatumGetCString(alg_datum));

			pk_datum = SPI_getbinval(SPI_tuptable->vals[0],
									 SPI_tuptable->tupdesc, 2, &isnull);
			pk_bytea = DatumGetByteaPP(pk_datum);
			*out_pk_len = VARSIZE_ANY_EXHDR(pk_bytea);
			*out_public_key = palloc(*out_pk_len);
			memcpy(*out_public_key, VARDATA_ANY(pk_bytea), *out_pk_len);

			sk_datum = SPI_getbinval(SPI_tuptable->vals[0],
									 SPI_tuptable->tupdesc, 3, &isnull);
			sk_bytea = DatumGetByteaPP(sk_datum);
			*out_sk_len = VARSIZE_ANY_EXHDR(sk_bytea);
			*out_secret_key = palloc(*out_sk_len);
			memcpy(*out_secret_key, VARDATA_ANY(sk_bytea), *out_sk_len);

			found = true;
		}
	}

	return found;
}

/*
 * Get the previous entry hash from the last audit log row.
 *
 * Must be called inside an SPI session.  Returns a palloc'd copy of the
 * entry_hash, or NULL if the table is empty.
 */
static uint8 *
get_prev_hash(size_t *prev_hash_len)
{
	int		ret;
	uint8  *result = NULL;

	ret = SPI_execute("SELECT entry_hash FROM pqc_audit_log "
					  "ORDER BY log_id DESC LIMIT 1",
					  true, 1);

	if (ret == SPI_OK_SELECT && SPI_processed > 0)
	{
		bool	isnull;
		Datum	datum;
		bytea  *hash_bytea;

		datum = SPI_getbinval(SPI_tuptable->vals[0],
							 SPI_tuptable->tupdesc, 1, &isnull);
		if (!isnull)
		{
			hash_bytea = DatumGetByteaPP(datum);
			*prev_hash_len = VARSIZE_ANY_EXHDR(hash_bytea);
			result = palloc(*prev_hash_len);
			memcpy(result, VARDATA_ANY(hash_bytea), *prev_hash_len);
		}
	}

	if (result == NULL)
		*prev_hash_len = 0;

	return result;
}

/*
 * Insert a signed audit log entry via SPI.
 *
 * This performs the dual-sign, hash-chain computation, and INSERT in
 * one operation.  Must be called inside an SPI session.
 */
static void
audit_log_ddl_event(const char *event_type,
					const char *object_name,
					const char *query_string)
{
	char	   *classical_alg = NULL;
	uint8	   *classical_pk = NULL;
	uint8	   *classical_sk = NULL;
	size_t		classical_pk_len = 0;
	size_t		classical_sk_len = 0;
	char	   *pqc_alg_name = NULL;
	uint8	   *pqc_pk = NULL;
	uint8	   *pqc_sk = NULL;
	size_t		pqc_pk_len = 0;
	size_t		pqc_sk_len = 0;
	uint8	   *classical_sig = NULL;
	size_t		classical_sig_len = 0;
	uint8	   *pqc_sig = NULL;
	size_t		pqc_sig_len = 0;
	uint8	   *prev_hash = NULL;
	size_t		prev_hash_len = 0;
	uint8	   *entry_hash;
	uint8	   *message_hash;
	StringInfoData event_json;
	StringInfoData insert_query;
	char	   *session_id;
	const char *user_name;
	char	   *db_name;
	Oid			user_id;
	PqcAlgorithm pqc_alg;
	PqcSigContext *sig_ctx;
	Datum		values[12];
	Oid			argtypes[12];
	char		nulls_str[13];
	int			nargs;

	/* Ensure PQC is initialized */
	if (!pqc_is_available())
		pqc_init();

	/* Load audit signing keys */
	if (!load_audit_key("classical",
						&classical_alg,
						&classical_pk, &classical_pk_len,
						&classical_sk, &classical_sk_len))
	{
		ereport(WARNING,
				(errmsg("pqc_audit: no active classical signing key found, skipping audit")));
		return;
	}

	if (!load_audit_key("pqc",
						&pqc_alg_name,
						&pqc_pk, &pqc_pk_len,
						&pqc_sk, &pqc_sk_len))
	{
		pqc_secure_free(classical_sk, classical_sk_len);
		pfree(classical_pk);
		pfree(classical_alg);
		ereport(WARNING,
				(errmsg("pqc_audit: no active PQC signing key found, skipping audit")));
		return;
	}

	/* Build session identifier */
	session_id = psprintf("%d.%lx", MyProcPid,
						  (unsigned long) MyStartTimestamp);

	/* Get user and database names */
	user_id = GetUserId();
	user_name = GetUserNameFromId(user_id, false);
	db_name = get_database_name(MyDatabaseId);

	/*
	 * Build event detail as JSON with proper escaping to prevent
	 * JSON injection from crafted object names or query strings.
	 * Use SPI to call jsonb_build_object() safely.
	 */
	{
		Oid			argtypes_json[2] = {TEXTOID, TEXTOID};
		Datum		argvals_json[2];
		int			json_ret;

		argvals_json[0] = CStringGetTextDatum(object_name ? object_name : "");
		argvals_json[1] = CStringGetTextDatum(query_string ? query_string : "");

		json_ret = SPI_execute_with_args(
			"SELECT jsonb_build_object('object', $1, 'query', $2)::text",
			2, argtypes_json, argvals_json, NULL, true, 1);

		initStringInfo(&event_json);
		if (json_ret == SPI_OK_SELECT && SPI_processed > 0)
		{
			bool		isnull;
			Datum		d = SPI_getbinval(SPI_tuptable->vals[0],
										 SPI_tuptable->tupdesc, 1, &isnull);

			if (!isnull)
				appendStringInfoString(&event_json,
									   TextDatumGetCString(d));
			else
				appendStringInfoString(&event_json, "{}");
		}
		else
			appendStringInfoString(&event_json, "{}");
	}

	/* Compute message hash for signing (SHA-384 of event detail) */
	message_hash = compute_sha384((uint8 *) event_json.data,
								  event_json.len);

	/* Classical signature (Ed25519) */
	classical_sig = ed25519_sign(message_hash, AUDIT_HASH_LEN,
								 classical_sk, classical_sk_len,
								 &classical_sig_len);

	/* PQC signature (ML-DSA) */
	pqc_alg = pqc_algorithm_from_name(pqc_alg_name);
	if (pqc_alg >= PQC_ALG_COUNT)
	{
		pqc_secure_free(classical_sk, classical_sk_len);
		pqc_secure_free(pqc_sk, pqc_sk_len);
		pfree(classical_pk);
		pfree(pqc_pk);
		ereport(WARNING,
				(errmsg("pqc_audit: unknown PQC algorithm \"%s\", skipping audit",
						pqc_alg_name)));
		return;
	}

	sig_ctx = pqc_sig_new(pqc_alg);
	if (pqc_sig_sign(sig_ctx,
					 message_hash, AUDIT_HASH_LEN,
					 pqc_sk, pqc_sk_len,
					 &pqc_sig, &pqc_sig_len) != PQC_SUCCESS)
	{
		pqc_sig_free(sig_ctx);
		pqc_secure_free(classical_sk, classical_sk_len);
		pqc_secure_free(pqc_sk, pqc_sk_len);
		pfree(classical_pk);
		pfree(pqc_pk);
		ereport(WARNING,
				(errmsg("pqc_audit: PQC signature generation failed, skipping audit")));
		return;
	}
	pqc_sig_free(sig_ctx);

	/* Get previous hash for chain */
	prev_hash = get_prev_hash(&prev_hash_len);

	/* Compute entry hash */
	entry_hash = compute_entry_hash(event_type, event_json.data,
									classical_sig, classical_sig_len,
									pqc_sig, pqc_sig_len,
									prev_hash, prev_hash_len);

	/* Insert via parameterized SPI query */
	nargs = 0;
	initStringInfo(&insert_query);
	appendStringInfoString(&insert_query,
		"INSERT INTO pqc_audit_log "
		"(session_id, user_name, database_name, event_type, event_detail, "
		" classical_sig_alg, classical_signature, "
		" pqc_sig_alg, pqc_signature, prev_hash, entry_hash) "
		"VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11)");

	argtypes[0] = TEXTOID;		/* session_id */
	argtypes[1] = NAMEOID;		/* user_name */
	argtypes[2] = NAMEOID;		/* database_name */
	argtypes[3] = TEXTOID;		/* event_type */
	argtypes[4] = TEXTOID;		/* event_detail (cast to jsonb) */
	argtypes[5] = TEXTOID;		/* classical_sig_alg */
	argtypes[6] = BYTEAOID;	/* classical_signature */
	argtypes[7] = TEXTOID;		/* pqc_sig_alg */
	argtypes[8] = BYTEAOID;	/* pqc_signature */
	argtypes[9] = BYTEAOID;	/* prev_hash */
	argtypes[10] = BYTEAOID;	/* entry_hash */

	values[0] = CStringGetTextDatum(session_id);
	values[1] = DirectFunctionCall1(namein, CStringGetDatum(user_name));
	values[2] = DirectFunctionCall1(namein, CStringGetDatum(db_name));
	values[3] = CStringGetTextDatum(event_type);
	values[4] = CStringGetTextDatum(event_json.data);
	values[5] = CStringGetTextDatum(classical_alg);
	values[6] = PointerGetDatum(make_bytea(classical_sig, classical_sig_len));
	values[7] = CStringGetTextDatum(pqc_alg_name);
	values[8] = PointerGetDatum(make_bytea(pqc_sig, pqc_sig_len));
	values[9] = PointerGetDatum(prev_hash ?
								make_bytea(prev_hash, prev_hash_len) :
								NULL);
	values[10] = PointerGetDatum(make_bytea(entry_hash, AUDIT_HASH_LEN));

	/* Handle nullable prev_hash */
	memset(nulls_str, ' ', 11);
	nulls_str[11] = '\0';
	if (prev_hash == NULL)
		nulls_str[9] = 'n';

	nargs = 11;

	SPI_execute_with_args(insert_query.data,
						  nargs, argtypes, values, nulls_str,
						  false, 0);

	/* Clean up sensitive material */
	pqc_secure_free(classical_sk, classical_sk_len);
	pqc_secure_free(pqc_sk, pqc_sk_len);
	pfree(classical_pk);
	pfree(pqc_pk);
	pfree(classical_sig);
	pfree(pqc_sig);
	pfree(message_hash);
	pfree(entry_hash);
	if (prev_hash)
		pfree(prev_hash);
	pfree(event_json.data);
	pfree(insert_query.data);
	pfree(session_id);
	pfree(classical_alg);
	pfree(pqc_alg_name);
	pfree(db_name);
}

#endif							/* USE_PQC */

PG_FUNCTION_INFO_V1(pqc_encrypt);

Datum
pqc_encrypt(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	bytea	   *pt_bytea = PG_GETARG_BYTEA_PP(0);
	text	   *alg_text = PG_GETARG_TEXT_PP(1);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcKemContext *ctx;
	uint8	   *pk,
			   *sk,
			   *ct,
			   *ss;
	size_t		pk_len,
				sk_len,
				ct_len,
				ss_len;
	uint8		aes_key[AES_GCM_KEY_LEN];
	bytea	   *encrypted;
	TupleDesc	tupdesc;
	Datum		values[4];
	bool		nulls[4] = {false, false, false, false};
	HeapTuple	tuple;

	ctx = pqc_kem_new(alg);

	/* Generate ephemeral KEM key pair */
	if (pqc_kem_keygen(ctx, &pk, &pk_len, &sk, &sk_len) != PQC_SUCCESS)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("KEM key generation failed")));

	/* Encapsulate to get shared secret */
	if (pqc_kem_encaps(ctx, pk, pk_len, &ct, &ct_len, &ss, &ss_len) != PQC_SUCCESS)
	{
		pfree(pk);
		pqc_secure_free(sk, sk_len);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("KEM encapsulation failed")));
	}

	/* Derive AES-256 key from shared secret via HKDF */
	derive_aes_key(ss, ss_len, aes_key);
	pqc_secure_free(ss, ss_len);

	/* Encrypt plaintext with AES-256-GCM */
	encrypted = aes_gcm_encrypt((uint8 *) VARDATA_ANY(pt_bytea),
								VARSIZE_ANY_EXHDR(pt_bytea),
								aes_key);

	/* Securely clear AES key */
	explicit_bzero(aes_key, AES_GCM_KEY_LEN);

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupdesc = BlessTupleDesc(tupdesc);

	values[0] = PointerGetDatum(encrypted);
	values[1] = PointerGetDatum(make_bytea(ct, ct_len));
	values[2] = PointerGetDatum(make_bytea(pk, pk_len));
	values[3] = PointerGetDatum(make_bytea(sk, sk_len));

	pfree(ct);
	pfree(pk);
	pqc_secure_free(sk, sk_len);
	pqc_kem_free(ctx);

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_decrypt);

Datum
pqc_decrypt(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	bytea	   *enc_bytea = PG_GETARG_BYTEA_PP(0);
	bytea	   *ct_bytea = PG_GETARG_BYTEA_PP(1);
	bytea	   *sk_bytea = PG_GETARG_BYTEA_PP(2);
	text	   *alg_text = PG_GETARG_TEXT_PP(3);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcKemContext *ctx;
	uint8	   *ss;
	size_t		ss_len;
	uint8		aes_key[AES_GCM_KEY_LEN];
	bytea	   *result;

	ctx = pqc_kem_new(alg);

	/* Decapsulate to recover shared secret */
	if (pqc_kem_decaps(ctx,
					   (uint8 *) VARDATA_ANY(ct_bytea),
					   VARSIZE_ANY_EXHDR(ct_bytea),
					   (uint8 *) VARDATA_ANY(sk_bytea),
					   VARSIZE_ANY_EXHDR(sk_bytea),
					   &ss, &ss_len) != PQC_SUCCESS)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("KEM decapsulation failed")));

	/* Derive same AES-256 key from shared secret */
	derive_aes_key(ss, ss_len, aes_key);
	pqc_secure_free(ss, ss_len);

	/* Decrypt with AES-256-GCM */
	result = aes_gcm_decrypt((uint8 *) VARDATA_ANY(enc_bytea),
							 VARSIZE_ANY_EXHDR(enc_bytea),
							 aes_key);

	explicit_bzero(aes_key, AES_GCM_KEY_LEN);
	pqc_kem_free(ctx);

	PG_RETURN_BYTEA_P(result);
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

/* ------------------------------------------------------------ */
/*			 Algorithm Discovery							     */
/* ------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(pqc_algorithms);

Datum
pqc_algorithms(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	int			call_cntr;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext oldcontext;
		TupleDesc	tupdesc;
		int		   *available_algs;
		int			num_available = 0;
		int			i;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);

		/* Ensure PQC is initialized for accurate sizes */
		if (!pqc_is_available())
			pqc_init();

		/*
		 * Build a list of available algorithm indices, skipping any that
		 * liboqs doesn't support (indicated by all sizes being 0).
		 */
		available_algs = palloc(sizeof(int) * PQC_ALG_COUNT);
		for (i = 0; i < PQC_ALG_COUNT; i++)
		{
			const PqcAlgorithmInfo *info = pqc_get_algorithm_info((PqcAlgorithm) i);

			if (info == NULL)
				continue;

			/* Skip algorithms where liboqs did not populate sizes */
			if (info->public_key_len == 0 && info->secret_key_len == 0)
				continue;

			available_algs[num_available++] = i;
		}

		funcctx->max_calls = num_available;
		funcctx->user_fctx = available_algs;

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();
	call_cntr = funcctx->call_cntr;

	if (call_cntr < funcctx->max_calls)
	{
		int		   *available_algs = (int *) funcctx->user_fctx;
		const PqcAlgorithmInfo *info;
		Datum		values[6];
		bool		nulls[6] = {false, false, false, false, false, false};
		HeapTuple	tuple;

		info = pqc_get_algorithm_info((PqcAlgorithm) available_algs[call_cntr]);
		if (info == NULL)
			SRF_RETURN_DONE(funcctx);

		values[0] = CStringGetTextDatum(info->name);
		values[1] = CStringGetTextDatum(info->type == PQC_TYPE_KEM ? "KEM" : "SIG");
		values[2] = Int32GetDatum(info->nist_level);
		values[3] = Int32GetDatum((int32) info->public_key_len);
		values[4] = Int32GetDatum((int32) info->secret_key_len);
		values[5] = Int32GetDatum((int32) (info->type == PQC_TYPE_KEM ?
										   info->ciphertext_len :
										   info->signature_len));

		tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
	}

	SRF_RETURN_DONE(funcctx);
}

/* ------------------------------------------------------------ */
/*			 Hybrid Proof Audit Functions (v1.1)                 */
/* ------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(pqc_audit_init_keys);

/*
 * pqc_audit_init_keys(classical_alg text, pqc_alg text)
 *
 * Generate Ed25519 + ML-DSA key pairs and store them in pqc_audit_keys.
 */
Datum
pqc_audit_init_keys(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	text	   *classical_alg_text = PG_GETARG_TEXT_PP(0);
	text	   *pqc_alg_text = PG_GETARG_TEXT_PP(1);
	char	   *classical_alg_name = text_to_cstring(classical_alg_text);
	char	   *pqc_alg_name = text_to_cstring(pqc_alg_text);
	PqcAlgorithm pqc_alg;
	PqcSigContext *sig_ctx;
	uint8	   *ed_pk,
			   *ed_sk;
	size_t		ed_pk_len,
				ed_sk_len;
	uint8	   *pqc_pk,
			   *pqc_sk;
	size_t		pqc_pk_len,
				pqc_sk_len;
	StringInfoData query;
	Datum		values[5];
	Oid			argtypes[5];
	int			ret;

	/* Validate classical algorithm */
	if (pg_strcasecmp(classical_alg_name, "Ed25519") != 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("unsupported classical algorithm: \"%s\"",
						classical_alg_name),
				 errhint("Currently only \"Ed25519\" is supported.")));

	/* Validate PQC algorithm */
	pqc_alg = pqc_algorithm_from_name(pqc_alg_name);
	if (pqc_alg >= PQC_ALG_COUNT || !pqc_algorithm_is_sig(pqc_alg))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("unsupported PQC signature algorithm: \"%s\"",
						pqc_alg_name)));

	/* Ensure PQC is initialized */
	if (!pqc_is_available())
		pqc_init();

	/* Generate Ed25519 key pair */
	ed25519_keygen(&ed_pk, &ed_pk_len, &ed_sk, &ed_sk_len);

	/* Generate PQC key pair */
	sig_ctx = pqc_sig_new(pqc_alg);
	if (pqc_sig_keygen(sig_ctx, &pqc_pk, &pqc_pk_len,
					   &pqc_sk, &pqc_sk_len) != PQC_SUCCESS)
	{
		pqc_sig_free(sig_ctx);
		explicit_bzero(ed_sk, ed_sk_len);
		pfree(ed_sk);
		pfree(ed_pk);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("PQC signature key generation failed for %s",
						pqc_alg_name)));
	}
	pqc_sig_free(sig_ctx);

	/* Store keys via SPI */
	SPI_connect();

	/* Deactivate any existing keys first */
	SPI_execute("UPDATE pqc_audit_keys SET is_active = false "
				"WHERE is_active = true", false, 0);

	/* Insert classical key */
	initStringInfo(&query);
	appendStringInfoString(&query,
		"INSERT INTO pqc_audit_keys "
		"(key_purpose, algorithm, public_key, encrypted_secret_key) "
		"VALUES ($1, $2, $3, $4)");

	argtypes[0] = TEXTOID;
	argtypes[1] = TEXTOID;
	argtypes[2] = BYTEAOID;
	argtypes[3] = BYTEAOID;

	values[0] = CStringGetTextDatum("classical");
	values[1] = CStringGetTextDatum(classical_alg_name);
	values[2] = PointerGetDatum(make_bytea(ed_pk, ed_pk_len));
	values[3] = PointerGetDatum(make_bytea(ed_sk, ed_sk_len));

	ret = SPI_execute_with_args(query.data, 4, argtypes, values, NULL,
								false, 0);
	if (ret != SPI_OK_INSERT)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("failed to insert classical audit key")));

	/* Insert PQC key */
	values[0] = CStringGetTextDatum("pqc");
	values[1] = CStringGetTextDatum(pqc_alg_name);
	values[2] = PointerGetDatum(make_bytea(pqc_pk, pqc_pk_len));
	values[3] = PointerGetDatum(make_bytea(pqc_sk, pqc_sk_len));

	ret = SPI_execute_with_args(query.data, 4, argtypes, values, NULL,
								false, 0);
	if (ret != SPI_OK_INSERT)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("failed to insert PQC audit key")));

	SPI_finish();

	/* Clean up sensitive key material */
	explicit_bzero(ed_sk, ed_sk_len);
	pfree(ed_sk);
	pfree(ed_pk);
	pqc_secure_free(pqc_sk, pqc_sk_len);
	pfree(pqc_pk);
	pfree(query.data);
	pfree(classical_alg_name);
	pfree(pqc_alg_name);

	PG_RETURN_VOID();
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_VOID();
#endif
}

PG_FUNCTION_INFO_V1(pqc_audit_sign);

/*
 * pqc_audit_sign(message bytea)
 *
 * Dual-sign a message with the active classical + PQC keys.
 * Returns: (classical_sig bytea, pqc_sig bytea, classical_alg text, pqc_alg text)
 */
Datum
pqc_audit_sign(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	bytea	   *msg_bytea = PG_GETARG_BYTEA_PP(0);
	uint8	   *msg;
	size_t		msg_len;
	char	   *classical_alg = NULL;
	uint8	   *classical_pk = NULL;
	uint8	   *classical_sk = NULL;
	size_t		classical_pk_len;
	size_t		classical_sk_len;
	char	   *pqc_alg_name = NULL;
	uint8	   *pqc_pk = NULL;
	uint8	   *pqc_sk = NULL;
	size_t		pqc_pk_len;
	size_t		pqc_sk_len;
	uint8	   *classical_sig;
	size_t		classical_sig_len;
	uint8	   *pqc_sig;
	size_t		pqc_sig_len;
	PqcAlgorithm pqc_alg;
	PqcSigContext *sig_ctx;
	TupleDesc	tupdesc;
	Datum		values[4];
	bool		nulls[4] = {false, false, false, false};
	HeapTuple	tuple;

	if (!pqc_is_available())
		pqc_init();

	msg = (uint8 *) VARDATA_ANY(msg_bytea);
	msg_len = VARSIZE_ANY_EXHDR(msg_bytea);

	/* Load keys via SPI */
	SPI_connect();

	if (!load_audit_key("classical",
						&classical_alg,
						&classical_pk, &classical_pk_len,
						&classical_sk, &classical_sk_len))
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("no active classical audit key found"),
				 errhint("Run SELECT pqc_audit_init_keys() first.")));
	}

	if (!load_audit_key("pqc",
						&pqc_alg_name,
						&pqc_pk, &pqc_pk_len,
						&pqc_sk, &pqc_sk_len))
	{
		pqc_secure_free(classical_sk, classical_sk_len);
		pfree(classical_pk);
		pfree(classical_alg);
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("no active PQC audit key found"),
				 errhint("Run SELECT pqc_audit_init_keys() first.")));
	}

	SPI_finish();

	/* Sign with Ed25519 */
	classical_sig = ed25519_sign(msg, msg_len,
								 classical_sk, classical_sk_len,
								 &classical_sig_len);

	/* Sign with PQC */
	pqc_alg = pqc_algorithm_from_name(pqc_alg_name);
	sig_ctx = pqc_sig_new(pqc_alg);

	if (pqc_sig_sign(sig_ctx, msg, msg_len,
					 pqc_sk, pqc_sk_len,
					 &pqc_sig, &pqc_sig_len) != PQC_SUCCESS)
	{
		pqc_sig_free(sig_ctx);
		pqc_secure_free(classical_sk, classical_sk_len);
		pqc_secure_free(pqc_sk, pqc_sk_len);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("PQC audit signature generation failed")));
	}
	pqc_sig_free(sig_ctx);

	/* Build result tuple */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupdesc = BlessTupleDesc(tupdesc);

	values[0] = PointerGetDatum(make_bytea(classical_sig, classical_sig_len));
	values[1] = PointerGetDatum(make_bytea(pqc_sig, pqc_sig_len));
	values[2] = CStringGetTextDatum(classical_alg);
	values[3] = CStringGetTextDatum(pqc_alg_name);

	/* Clean up */
	pqc_secure_free(classical_sk, classical_sk_len);
	pqc_secure_free(pqc_sk, pqc_sk_len);
	pfree(classical_pk);
	pfree(pqc_pk);
	pfree(classical_sig);
	pfree(pqc_sig);
	pfree(classical_alg);
	pfree(pqc_alg_name);

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_audit_verify);

/*
 * pqc_audit_verify(message bytea, classical_sig bytea, classical_alg text,
 *                  pqc_sig bytea, pqc_alg text)
 *
 * Verify both classical and PQC signatures on a message.
 * Returns: (classical_valid boolean, pqc_valid boolean)
 */
Datum
pqc_audit_verify(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	bytea	   *msg_bytea = PG_GETARG_BYTEA_PP(0);
	bytea	   *classical_sig_bytea = PG_GETARG_BYTEA_PP(1);
	text	   *classical_alg_text = PG_GETARG_TEXT_PP(2);
	bytea	   *pqc_sig_bytea = PG_GETARG_BYTEA_PP(3);
	text	   *pqc_alg_text = PG_GETARG_TEXT_PP(4);
	char	   *classical_alg_name;
	char	   *pqc_alg_name;
	uint8	   *msg;
	size_t		msg_len;
	bool		classical_valid = false;
	bool		pqc_valid = false;
	char	   *key_alg = NULL;
	uint8	   *pub_key = NULL;
	uint8	   *sec_key = NULL;
	size_t		pub_key_len;
	size_t		sec_key_len;
	PqcAlgorithm pqc_alg;
	PqcSigContext *sig_ctx;
	TupleDesc	tupdesc;
	Datum		values[2];
	bool		nulls[2] = {false, false};
	HeapTuple	tuple;

	if (!pqc_is_available())
		pqc_init();

	msg = (uint8 *) VARDATA_ANY(msg_bytea);
	msg_len = VARSIZE_ANY_EXHDR(msg_bytea);

	classical_alg_name = text_to_cstring(classical_alg_text);
	pqc_alg_name = text_to_cstring(pqc_alg_text);

	/* Load classical public key */
	SPI_connect();

	if (load_audit_key("classical",
					   &key_alg, &pub_key, &pub_key_len,
					   &sec_key, &sec_key_len))
	{
		/* Verify Ed25519 */
		if (pg_strcasecmp(classical_alg_name, "Ed25519") == 0)
		{
			classical_valid = ed25519_verify(
				msg, msg_len,
				(uint8 *) VARDATA_ANY(classical_sig_bytea),
				VARSIZE_ANY_EXHDR(classical_sig_bytea),
				pub_key, pub_key_len);
		}
		pqc_secure_free(sec_key, sec_key_len);
		pfree(pub_key);
		pfree(key_alg);
	}

	/* Load PQC public key and verify */
	if (load_audit_key("pqc",
					   &key_alg, &pub_key, &pub_key_len,
					   &sec_key, &sec_key_len))
	{
		pqc_alg = pqc_algorithm_from_name(pqc_alg_name);
		if (pqc_alg < PQC_ALG_COUNT && pqc_algorithm_is_sig(pqc_alg))
		{
			sig_ctx = pqc_sig_new(pqc_alg);
			pqc_valid = (pqc_sig_verify(sig_ctx,
										msg, msg_len,
										(uint8 *) VARDATA_ANY(pqc_sig_bytea),
										VARSIZE_ANY_EXHDR(pqc_sig_bytea),
										pub_key, pub_key_len) == PQC_SUCCESS);
			pqc_sig_free(sig_ctx);
		}
		pqc_secure_free(sec_key, sec_key_len);
		pfree(pub_key);
		pfree(key_alg);
	}

	SPI_finish();

	/* Build result */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupdesc = BlessTupleDesc(tupdesc);

	values[0] = BoolGetDatum(classical_valid);
	values[1] = BoolGetDatum(pqc_valid);

	pfree(classical_alg_name);
	pfree(pqc_alg_name);

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_audit_verify_chain);

/*
 * pqc_audit_verify_chain(start_id bigint, end_id bigint)
 *
 * Verify hash chain integrity and dual signatures for audit log entries.
 * Returns: SETOF (log_id bigint, chain_valid bool, classical_sig_valid bool,
 *                 pqc_sig_valid bool)
 */
Datum
pqc_audit_verify_chain(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	FuncCallContext *funcctx;
	TupleDesc	tupdesc;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext oldcontext;
		int64		start_id;
		int64		end_id_val;
		bool		end_is_null;
		StringInfoData query;
		int			ret;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		start_id = PG_ARGISNULL(0) ? 1 : PG_GETARG_INT64(0);
		end_is_null = PG_ARGISNULL(1);
		end_id_val = end_is_null ? 0 : PG_GETARG_INT64(1);

		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);

		if (!pqc_is_available())
			pqc_init();

		/* Load all relevant audit log entries via SPI */
		SPI_connect();

		initStringInfo(&query);
		if (end_is_null)
			appendStringInfo(&query,
				"SELECT log_id, event_type, event_detail::text, "
				"classical_sig_alg, classical_signature, "
				"pqc_sig_alg, pqc_signature, "
				"prev_hash, entry_hash "
				"FROM pqc_audit_log "
				"WHERE log_id >= %lld "
				"ORDER BY log_id",
				(long long) start_id);
		else
			appendStringInfo(&query,
				"SELECT log_id, event_type, event_detail::text, "
				"classical_sig_alg, classical_signature, "
				"pqc_sig_alg, pqc_signature, "
				"prev_hash, entry_hash "
				"FROM pqc_audit_log "
				"WHERE log_id >= %lld AND log_id <= %lld "
				"ORDER BY log_id",
				(long long) start_id,
				(long long) end_id_val);

		ret = SPI_execute(query.data, true, 0);
		pfree(query.data);

		if (ret != SPI_OK_SELECT)
		{
			SPI_finish();
			MemoryContextSwitchTo(oldcontext);
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("failed to query audit log for chain verification")));
		}

		funcctx->max_calls = SPI_processed;
		funcctx->user_fctx = SPI_tuptable;

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();

	if (funcctx->call_cntr < funcctx->max_calls)
	{
		SPITupleTable *tuptable = (SPITupleTable *) funcctx->user_fctx;
		HeapTuple	spi_tuple;
		TupleDesc	spi_tupdesc;
		int			idx;
		bool		isnull;
		int64		log_id;
		char	   *event_type;
		char	   *event_detail_str;
		char	   *classical_alg;
		char	   *pqc_alg_name;
		bytea	   *classical_sig_bytea;
		bytea	   *pqc_sig_bytea;
		bytea	   *prev_hash_bytea;
		bytea	   *entry_hash_bytea;
		bool		chain_valid;
		bool		classical_sig_valid;
		bool		pqc_sig_valid;
		uint8	   *recomputed_hash;
		uint8	   *message_hash;
		char	   *key_alg;
		uint8	   *pub_key;
		uint8	   *sec_key;
		size_t		pub_key_len;
		size_t		sec_key_len;
		PqcAlgorithm pqc_alg;
		PqcSigContext *sig_ctx;
		Datum		values[4];
		bool		nulls[4] = {false, false, false, false};
		HeapTuple	result_tuple;

		idx = funcctx->call_cntr;
		spi_tuple = tuptable->vals[idx];
		spi_tupdesc = tuptable->tupdesc;

		/* Extract fields */
		log_id = DatumGetInt64(SPI_getbinval(spi_tuple, spi_tupdesc,
											 1, &isnull));
		event_type = SPI_getvalue(spi_tuple, spi_tupdesc, 2);
		event_detail_str = SPI_getvalue(spi_tuple, spi_tupdesc, 3);
		classical_alg = SPI_getvalue(spi_tuple, spi_tupdesc, 4);

		classical_sig_bytea = DatumGetByteaPP(
			SPI_getbinval(spi_tuple, spi_tupdesc, 5, &isnull));
		pqc_alg_name = SPI_getvalue(spi_tuple, spi_tupdesc, 6);
		pqc_sig_bytea = DatumGetByteaPP(
			SPI_getbinval(spi_tuple, spi_tupdesc, 7, &isnull));

		/* prev_hash may be NULL */
		{
			Datum	ph_datum = SPI_getbinval(spi_tuple, spi_tupdesc,
											 8, &isnull);
			prev_hash_bytea = isnull ? NULL : DatumGetByteaPP(ph_datum);
		}

		entry_hash_bytea = DatumGetByteaPP(
			SPI_getbinval(spi_tuple, spi_tupdesc, 9, &isnull));

		/* Recompute entry hash and compare */
		recomputed_hash = compute_entry_hash(
			event_type, event_detail_str,
			(uint8 *) VARDATA_ANY(classical_sig_bytea),
			VARSIZE_ANY_EXHDR(classical_sig_bytea),
			(uint8 *) VARDATA_ANY(pqc_sig_bytea),
			VARSIZE_ANY_EXHDR(pqc_sig_bytea),
			prev_hash_bytea ? (uint8 *) VARDATA_ANY(prev_hash_bytea) : NULL,
			prev_hash_bytea ? VARSIZE_ANY_EXHDR(prev_hash_bytea) : 0);

		chain_valid = (VARSIZE_ANY_EXHDR(entry_hash_bytea) == AUDIT_HASH_LEN &&
					   memcmp(recomputed_hash,
							  VARDATA_ANY(entry_hash_bytea),
							  AUDIT_HASH_LEN) == 0);

		/* Verify classical signature */
		message_hash = compute_sha384(
			(uint8 *) event_detail_str, strlen(event_detail_str));

		classical_sig_valid = false;
		if (load_audit_key("classical",
						   &key_alg, &pub_key, &pub_key_len,
						   &sec_key, &sec_key_len))
		{
			if (pg_strcasecmp(classical_alg, "Ed25519") == 0)
			{
				classical_sig_valid = ed25519_verify(
					message_hash, AUDIT_HASH_LEN,
					(uint8 *) VARDATA_ANY(classical_sig_bytea),
					VARSIZE_ANY_EXHDR(classical_sig_bytea),
					pub_key, pub_key_len);
			}
			pqc_secure_free(sec_key, sec_key_len);
			pfree(pub_key);
			pfree(key_alg);
		}

		/* Verify PQC signature */
		pqc_sig_valid = false;
		if (load_audit_key("pqc",
						   &key_alg, &pub_key, &pub_key_len,
						   &sec_key, &sec_key_len))
		{
			pqc_alg = pqc_algorithm_from_name(pqc_alg_name);
			if (pqc_alg < PQC_ALG_COUNT && pqc_algorithm_is_sig(pqc_alg))
			{
				sig_ctx = pqc_sig_new(pqc_alg);
				pqc_sig_valid = (pqc_sig_verify(
					sig_ctx,
					message_hash, AUDIT_HASH_LEN,
					(uint8 *) VARDATA_ANY(pqc_sig_bytea),
					VARSIZE_ANY_EXHDR(pqc_sig_bytea),
					pub_key, pub_key_len) == PQC_SUCCESS);
				pqc_sig_free(sig_ctx);
			}
			pqc_secure_free(sec_key, sec_key_len);
			pfree(pub_key);
			pfree(key_alg);
		}

		pfree(recomputed_hash);
		pfree(message_hash);

		values[0] = Int64GetDatum(log_id);
		values[1] = BoolGetDatum(chain_valid);
		values[2] = BoolGetDatum(classical_sig_valid);
		values[3] = BoolGetDatum(pqc_sig_valid);

		result_tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(result_tuple));
	}

	SPI_finish();
	SRF_RETURN_DONE(funcctx);
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_migrate_credentials);

/*
 * pqc_migrate_credentials(mode text)
 *
 * Scan pg_authid for SCRAM-SHA-256 credentials and report or force-reset.
 *
 * mode = 'report': list roles and their credential types
 * mode = 'force-reset': null out passwords and expire them
 */
Datum
pqc_migrate_credentials(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	FuncCallContext *funcctx;
	TupleDesc	tupdesc;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext oldcontext;
		text	   *mode_text = PG_GETARG_TEXT_PP(0);
		char	   *mode = text_to_cstring(mode_text);
		int			ret;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		if (pg_strcasecmp(mode, "report") != 0 &&
			pg_strcasecmp(mode, "force-reset") != 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("invalid mode: \"%s\"", mode),
					 errhint("Use 'report' or 'force-reset'.")));

		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);

		/* Query pg_authid via SPI */
		SPI_connect();

		if (pg_strcasecmp(mode, "force-reset") == 0)
		{
			/* Check superuser */
			if (!superuser())
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("must be superuser to force-reset credentials")));

			/* Expire and null passwords for SCRAM roles */
			SPI_execute(
				"UPDATE pg_authid SET rolpassword = NULL, "
				"rolvaliduntil = now() "
				"WHERE rolpassword IS NOT NULL "
				"AND rolpassword LIKE 'SCRAM-SHA-256$%'",
				false, 0);
		}

		ret = SPI_execute(
			"SELECT rolname, "
			"CASE WHEN rolpassword IS NULL THEN 'none' "
			"     WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256' "
			"     WHEN rolpassword LIKE 'md5%' THEN 'md5' "
			"     ELSE 'unknown' END AS current_type "
			"FROM pg_authid "
			"WHERE rolcanlogin = true "
			"ORDER BY rolname",
			true, 0);

		if (ret != SPI_OK_SELECT)
		{
			SPI_finish();
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("failed to query pg_authid")));
		}

		funcctx->max_calls = SPI_processed;
		funcctx->user_fctx = SPI_tuptable;

		/* Store mode for per-call use */
		funcctx->call_cntr = 0;

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();

	if (funcctx->call_cntr < funcctx->max_calls)
	{
		SPITupleTable *tuptable = (SPITupleTable *) funcctx->user_fctx;
		HeapTuple	spi_tuple;
		char	   *rolname_str;
		char	   *current_type;
		const char *action;
		Datum		values[3];
		bool		nulls[3] = {false, false, false};
		HeapTuple	result_tuple;

		spi_tuple = tuptable->vals[funcctx->call_cntr];

		rolname_str = SPI_getvalue(spi_tuple, tuptable->tupdesc, 1);
		current_type = SPI_getvalue(spi_tuple, tuptable->tupdesc, 2);

		/* Determine recommended action */
		if (pg_strcasecmp(current_type, "SCRAM-SHA-256") == 0)
			action = "migrate to PQC-SCRAM";
		else if (pg_strcasecmp(current_type, "md5") == 0)
			action = "upgrade to PQC-SCRAM (currently md5)";
		else if (pg_strcasecmp(current_type, "none") == 0)
			action = "no password set";
		else
			action = "review manually";

		values[0] = DirectFunctionCall1(namein,
										CStringGetDatum(rolname_str));
		values[1] = CStringGetTextDatum(current_type);
		values[2] = CStringGetTextDatum(action);

		result_tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(result_tuple));
	}

	SPI_finish();
	SRF_RETURN_DONE(funcctx);
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

/* ------------------------------------------------------------ */
/*			 ProcessUtility Hook                                 */
/* ------------------------------------------------------------ */

/*
 * ProcessUtility hook for capturing DDL events and writing them
 * to the hybrid proof audit log.
 */
static void
pqc_audit_process_utility(PlannedStmt *pstmt,
						  const char *queryString,
						  bool readOnlyTree,
						  ProcessUtilityContext context,
						  ParamListInfo params,
						  QueryEnvironment *queryEnv,
						  DestReceiver *dest,
						  QueryCompletion *qc)
{
#ifdef USE_PQC
	Node	   *parsetree = pstmt->utilityStmt;
	const char *event_type = NULL;
	const char *object_name = NULL;

	/*
	 * First, call the previous hook or standard_ProcessUtility so the
	 * DDL actually executes before we try to log it.
	 */
	if (prev_ProcessUtility)
		prev_ProcessUtility(pstmt, queryString, readOnlyTree,
							context, params, queryEnv, dest, qc);
	else
		standard_ProcessUtility(pstmt, queryString, readOnlyTree,
								context, params, queryEnv, dest, qc);

	/* If auditing is disabled, nothing more to do */
	if (!pqc_audit_enabled)
		return;

	/*
	 * Classify the DDL event.  We only capture security-relevant events:
	 * role management, grants, and ALTER SYSTEM.
	 */
	if (parsetree == NULL)
		return;

	switch (nodeTag(parsetree))
	{
		case T_CreateRoleStmt:
			if (!audit_event_is_enabled("ddl"))
				return;
			event_type = "CREATE_ROLE";
			object_name = ((CreateRoleStmt *) parsetree)->role;
			break;

		case T_AlterRoleStmt:
			if (!audit_event_is_enabled("ddl"))
				return;
			event_type = "ALTER_ROLE";
			{
				AlterRoleStmt *stmt = (AlterRoleStmt *) parsetree;
				if (stmt->role != NULL)
					object_name = stmt->role->rolename;
			}
			break;

		case T_DropRoleStmt:
			if (!audit_event_is_enabled("ddl"))
				return;
			event_type = "DROP_ROLE";
			object_name = "multiple";
			break;

		case T_GrantStmt:
			if (!audit_event_is_enabled("grant"))
				return;
			{
				GrantStmt *stmt = (GrantStmt *) parsetree;
				event_type = stmt->is_grant ? "GRANT" : "REVOKE";
				object_name = "privileges";
			}
			break;

		case T_GrantRoleStmt:
			if (!audit_event_is_enabled("grant"))
				return;
			{
				GrantRoleStmt *stmt = (GrantRoleStmt *) parsetree;
				event_type = stmt->is_grant ? "GRANT_ROLE" : "REVOKE_ROLE";
				object_name = "role_membership";
			}
			break;

		case T_AlterSystemStmt:
			if (!audit_event_is_enabled("policy"))
				return;
			event_type = "ALTER_SYSTEM";
			{
				AlterSystemStmt *stmt = (AlterSystemStmt *) parsetree;
				if (stmt->setstmt != NULL)
					object_name = stmt->setstmt->name;
			}
			break;

		default:
			/* Not a security-relevant DDL event */
			return;
	}

	if (event_type == NULL)
		return;

	/*
	 * Log the event.  We need to open a new SPI connection for this.
	 * If the audit tables don't exist yet (extension not fully created),
	 * we silently skip.
	 */
	PG_TRY();
	{
		SPI_connect();
		audit_log_ddl_event(event_type, object_name, queryString);
		SPI_finish();
	}
	PG_CATCH();
	{
		/*
		 * Don't let audit logging failures prevent the DDL from
		 * completing.  Log a warning instead.
		 */
		EmitErrorReport();
		FlushErrorState();
		ereport(WARNING,
				(errmsg("pqc_audit: failed to log %s event", event_type)));
	}
	PG_END_TRY();

#else
	/* Without PQC support, just chain to next hook */
	if (prev_ProcessUtility)
		prev_ProcessUtility(pstmt, queryString, readOnlyTree,
							context, params, queryEnv, dest, qc);
	else
		standard_ProcessUtility(pstmt, queryString, readOnlyTree,
								context, params, queryEnv, dest, qc);
#endif
}

/* ------------------------------------------------------------ */
/*			 Column-Level PQC Encryption (v1.2)                  */
/* ------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(pqc_encrypt_column);

/*
 * pqc_encrypt_column(data bytea, public_key bytea,
 *                    algorithm text DEFAULT 'ML-KEM-768')
 *
 * Encrypt a column value using ML-KEM key encapsulation + AES-256-GCM.
 * For each call, a fresh KEM encapsulation produces a per-value AES key.
 *
 * Output format: [KEM ciphertext] [12-byte IV] [AES ciphertext] [16-byte GCM tag]
 * The KEM ciphertext length is prepended as a 4-byte big-endian length prefix
 * so the decryptor knows where to split.
 *
 * Returns: bytea containing the full encrypted envelope.
 */
Datum
pqc_encrypt_column(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	bytea	   *data_bytea = PG_GETARG_BYTEA_PP(0);
	bytea	   *pk_bytea = PG_GETARG_BYTEA_PP(1);
	text	   *alg_text = PG_GETARG_TEXT_PP(2);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcKemContext *ctx;
	uint8	   *ct;
	uint8	   *ss;
	size_t		ct_len;
	size_t		ss_len;
	uint8		aes_key[AES_GCM_KEY_LEN];
	uint8	   *plaintext;
	size_t		pt_len;
	bytea	   *aes_encrypted;
	size_t		aes_enc_len;
	size_t		total_len;
	bytea	   *result;
	uint8	   *out;
	uint32		ct_len_be;

	if (!pqc_algorithm_is_kem(alg))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("\"%s\" is not a KEM algorithm",
						pqc_algorithm_name(alg))));

	if (!pqc_is_available())
		pqc_init();

	plaintext = (uint8 *) VARDATA_ANY(data_bytea);
	pt_len = VARSIZE_ANY_EXHDR(data_bytea);

	ctx = pqc_kem_new(alg);

	/* Encapsulate against the provided public key */
	if (pqc_kem_encaps(ctx,
					   (uint8 *) VARDATA_ANY(pk_bytea),
					   VARSIZE_ANY_EXHDR(pk_bytea),
					   &ct, &ct_len, &ss, &ss_len) != PQC_SUCCESS)
	{
		pqc_kem_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("KEM encapsulation failed for column encryption")));
	}

	/* Derive AES-256 key from shared secret */
	derive_aes_key(ss, ss_len, aes_key);
	pqc_secure_free(ss, ss_len);

	/* Encrypt with AES-256-GCM (produces IV || ciphertext || tag) */
	aes_encrypted = aes_gcm_encrypt(plaintext, pt_len, aes_key);
	explicit_bzero(aes_key, AES_GCM_KEY_LEN);

	aes_enc_len = VARSIZE_ANY_EXHDR(aes_encrypted);

	/*
	 * Build output: [4-byte ct_len BE] [KEM ciphertext] [AES encrypted blob]
	 */
	total_len = 4 + ct_len + aes_enc_len;
	result = (bytea *) palloc(VARHDRSZ + total_len);
	SET_VARSIZE(result, VARHDRSZ + total_len);
	out = (uint8 *) VARDATA(result);

	ct_len_be = pg_hton32((uint32) ct_len);
	memcpy(out, &ct_len_be, 4);
	memcpy(out + 4, ct, ct_len);
	memcpy(out + 4 + ct_len, VARDATA_ANY(aes_encrypted), aes_enc_len);

	pfree(ct);
	pfree(aes_encrypted);
	pqc_kem_free(ctx);

	PG_RETURN_BYTEA_P(result);
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_decrypt_column);

/*
 * pqc_decrypt_column(encrypted_data bytea, secret_key bytea,
 *                    algorithm text DEFAULT 'ML-KEM-768')
 *
 * Decrypt a column value that was encrypted with pqc_encrypt_column().
 *
 * Input format: [4-byte ct_len BE] [KEM ciphertext] [IV || AES ciphertext || GCM tag]
 *
 * Returns: bytea containing the original plaintext.
 */
Datum
pqc_decrypt_column(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	bytea	   *enc_bytea = PG_GETARG_BYTEA_PP(0);
	bytea	   *sk_bytea = PG_GETARG_BYTEA_PP(1);
	text	   *alg_text = PG_GETARG_TEXT_PP(2);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcKemContext *ctx;
	uint8	   *data;
	size_t		data_len;
	uint32		ct_len_be;
	uint32		ct_len;
	uint8	   *kem_ct;
	uint8	   *aes_blob;
	size_t		aes_blob_len;
	uint8	   *ss;
	size_t		ss_len;
	uint8		aes_key[AES_GCM_KEY_LEN];
	bytea	   *result;

	if (!pqc_algorithm_is_kem(alg))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("\"%s\" is not a KEM algorithm",
						pqc_algorithm_name(alg))));

	if (!pqc_is_available())
		pqc_init();

	data = (uint8 *) VARDATA_ANY(enc_bytea);
	data_len = VARSIZE_ANY_EXHDR(enc_bytea);

	if (data_len < 4)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("encrypted column data too short")));

	/* Extract KEM ciphertext length */
	memcpy(&ct_len_be, data, 4);
	ct_len = pg_ntoh32(ct_len_be);

	if (data_len < 4 + ct_len + AES_GCM_IV_LEN + AES_GCM_TAG_LEN)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("encrypted column data too short for KEM ciphertext")));

	kem_ct = data + 4;
	aes_blob = data + 4 + ct_len;
	aes_blob_len = data_len - 4 - ct_len;

	ctx = pqc_kem_new(alg);

	/* Decapsulate to recover shared secret */
	if (pqc_kem_decaps(ctx,
					   kem_ct, ct_len,
					   (uint8 *) VARDATA_ANY(sk_bytea),
					   VARSIZE_ANY_EXHDR(sk_bytea),
					   &ss, &ss_len) != PQC_SUCCESS)
	{
		pqc_kem_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("KEM decapsulation failed for column decryption")));
	}

	/* Derive AES-256 key */
	derive_aes_key(ss, ss_len, aes_key);
	pqc_secure_free(ss, ss_len);

	/* Decrypt AES-256-GCM blob */
	result = aes_gcm_decrypt(aes_blob, aes_blob_len, aes_key);
	explicit_bzero(aes_key, AES_GCM_KEY_LEN);
	pqc_kem_free(ctx);

	PG_RETURN_BYTEA_P(result);
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_encrypt_text);

/*
 * pqc_encrypt_text(plaintext text, public_key bytea,
 *                  algorithm text DEFAULT 'ML-KEM-768')
 *
 * Convenience wrapper: encrypts a text value using pqc_encrypt_column.
 */
Datum
pqc_encrypt_text(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	text	   *plaintext = PG_GETARG_TEXT_PP(0);
	bytea	   *pk_bytea = PG_GETARG_BYTEA_PP(1);
	text	   *alg_text = PG_GETARG_TEXT_PP(2);
	bytea	   *data_bytea;
	size_t		text_len;
	Datum		result;

	/* Convert text to bytea for encryption */
	text_len = VARSIZE_ANY_EXHDR(plaintext);
	data_bytea = (bytea *) palloc(VARHDRSZ + text_len);
	SET_VARSIZE(data_bytea, VARHDRSZ + text_len);
	memcpy(VARDATA(data_bytea), VARDATA_ANY(plaintext), text_len);

	/*
	 * Call pqc_encrypt_column directly by reusing the same logic.
	 * We construct the arguments manually.
	 */
	{
		PqcAlgorithm alg = parse_algorithm(alg_text);
		PqcKemContext *ctx;
		uint8	   *ct;
		uint8	   *ss;
		size_t		ct_len;
		size_t		ss_len;
		uint8		aes_key[AES_GCM_KEY_LEN];
		bytea	   *aes_encrypted;
		size_t		aes_enc_len;
		size_t		total_len;
		bytea	   *res;
		uint8	   *out;
		uint32		ct_len_be;

		if (!pqc_algorithm_is_kem(alg))
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("\"%s\" is not a KEM algorithm",
							pqc_algorithm_name(alg))));

		if (!pqc_is_available())
			pqc_init();

		ctx = pqc_kem_new(alg);

		if (pqc_kem_encaps(ctx,
						   (uint8 *) VARDATA_ANY(pk_bytea),
						   VARSIZE_ANY_EXHDR(pk_bytea),
						   &ct, &ct_len, &ss, &ss_len) != PQC_SUCCESS)
		{
			pqc_kem_free(ctx);
			ereport(ERROR,
					(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
					 errmsg("KEM encapsulation failed for text encryption")));
		}

		derive_aes_key(ss, ss_len, aes_key);
		pqc_secure_free(ss, ss_len);

		aes_encrypted = aes_gcm_encrypt((uint8 *) VARDATA(data_bytea),
										text_len, aes_key);
		explicit_bzero(aes_key, AES_GCM_KEY_LEN);

		aes_enc_len = VARSIZE_ANY_EXHDR(aes_encrypted);
		total_len = 4 + ct_len + aes_enc_len;
		res = (bytea *) palloc(VARHDRSZ + total_len);
		SET_VARSIZE(res, VARHDRSZ + total_len);
		out = (uint8 *) VARDATA(res);

		ct_len_be = pg_hton32((uint32) ct_len);
		memcpy(out, &ct_len_be, 4);
		memcpy(out + 4, ct, ct_len);
		memcpy(out + 4 + ct_len, VARDATA_ANY(aes_encrypted), aes_enc_len);

		pfree(ct);
		pfree(aes_encrypted);
		pfree(data_bytea);
		pqc_kem_free(ctx);

		result = PointerGetDatum(res);
	}

	PG_RETURN_DATUM(result);
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_decrypt_text);

/*
 * pqc_decrypt_text(encrypted_data bytea, secret_key bytea,
 *                  algorithm text DEFAULT 'ML-KEM-768')
 *
 * Convenience wrapper: decrypts data encrypted with pqc_encrypt_text and
 * returns it as text.
 */
Datum
pqc_decrypt_text(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	bytea	   *enc_bytea = PG_GETARG_BYTEA_PP(0);
	bytea	   *sk_bytea = PG_GETARG_BYTEA_PP(1);
	text	   *alg_text = PG_GETARG_TEXT_PP(2);
	PqcAlgorithm alg = parse_algorithm(alg_text);
	PqcKemContext *ctx;
	uint8	   *data;
	size_t		data_len;
	uint32		ct_len_be;
	uint32		ct_len;
	uint8	   *kem_ct;
	uint8	   *aes_blob;
	size_t		aes_blob_len;
	uint8	   *ss;
	size_t		ss_len;
	uint8		aes_key[AES_GCM_KEY_LEN];
	bytea	   *decrypted;
	text	   *result;
	size_t		decrypted_len;

	if (!pqc_algorithm_is_kem(alg))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("\"%s\" is not a KEM algorithm",
						pqc_algorithm_name(alg))));

	if (!pqc_is_available())
		pqc_init();

	data = (uint8 *) VARDATA_ANY(enc_bytea);
	data_len = VARSIZE_ANY_EXHDR(enc_bytea);

	if (data_len < 4)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("encrypted data too short")));

	memcpy(&ct_len_be, data, 4);
	ct_len = pg_ntoh32(ct_len_be);

	if (data_len < 4 + ct_len + AES_GCM_IV_LEN + AES_GCM_TAG_LEN)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("encrypted data too short for KEM ciphertext")));

	kem_ct = data + 4;
	aes_blob = data + 4 + ct_len;
	aes_blob_len = data_len - 4 - ct_len;

	ctx = pqc_kem_new(alg);

	if (pqc_kem_decaps(ctx,
					   kem_ct, ct_len,
					   (uint8 *) VARDATA_ANY(sk_bytea),
					   VARSIZE_ANY_EXHDR(sk_bytea),
					   &ss, &ss_len) != PQC_SUCCESS)
	{
		pqc_kem_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("KEM decapsulation failed for text decryption")));
	}

	derive_aes_key(ss, ss_len, aes_key);
	pqc_secure_free(ss, ss_len);

	decrypted = aes_gcm_decrypt(aes_blob, aes_blob_len, aes_key);
	explicit_bzero(aes_key, AES_GCM_KEY_LEN);
	pqc_kem_free(ctx);

	/* Convert decrypted bytea to text */
	decrypted_len = VARSIZE_ANY_EXHDR(decrypted);
	result = (text *) palloc(VARHDRSZ + decrypted_len);
	SET_VARSIZE(result, VARHDRSZ + decrypted_len);
	memcpy(VARDATA(result), VARDATA_ANY(decrypted), decrypted_len);
	pfree(decrypted);

	PG_RETURN_TEXT_P(result);
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

/* ------------------------------------------------------------ */
/*			 Online Key Rotation (v1.3)                          */
/* ------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(pqc_rotate_wal_signing_keys);

/*
 * pqc_rotate_wal_signing_keys(algorithm text DEFAULT 'ML-DSA-65')
 *
 * Generate new WAL signing keypair and atomically swap in place.
 * Returns status information about the rotation.
 */
Datum
pqc_rotate_wal_signing_keys(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	text	   *alg_text = PG_GETARG_TEXT_PP(0);
	char	   *alg_name = text_to_cstring(alg_text);
	TupleDesc	tupdesc;
	Datum		values[5];
	bool		nulls[5] = {false, false, false, false, false};
	HeapTuple	tuple;
	char		old_key_id[64];
	char		new_key_id[64];
	uint8	   *old_pk;
	size_t		old_pk_len;
	TimestampTz now_ts;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to rotate WAL signing keys")));

	if (!pqc_is_available())
		pqc_init();

	if (wal_pqc_key_path == NULL || wal_pqc_key_path[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("wal_pqc_key_path must be set to rotate WAL signing keys")));

	/* Capture old key fingerprint before rotation */
	PG_TRY();
	{
		pqc_wal_get_public_key(&old_pk, &old_pk_len);
		snprintf(old_key_id, sizeof(old_key_id), "pk-%08x",
				 (unsigned int) (old_pk_len > 4 ?
								 *(uint32 *) old_pk : 0));
	}
	PG_CATCH();
	{
		FlushErrorState();
		snprintf(old_key_id, sizeof(old_key_id), "(none)");
	}
	PG_END_TRY();

	/* Generate new keys - this atomically replaces the old key files */
	pqc_wal_generate_signing_keys(wal_pqc_key_path, alg_name);

	/* Reload the new keys into memory */
	pqc_wal_load_signing_keys(wal_pqc_key_path, alg_name);

	/* Get new key fingerprint */
	{
		uint8  *new_pk;
		size_t	new_pk_len;

		pqc_wal_get_public_key(&new_pk, &new_pk_len);
		snprintf(new_key_id, sizeof(new_key_id), "pk-%08x",
				 (unsigned int) (new_pk_len > 4 ?
								 *(uint32 *) new_pk : 0));
	}

	now_ts = GetCurrentTimestamp();

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupdesc = BlessTupleDesc(tupdesc);

	values[0] = CStringGetTextDatum("success");
	values[1] = CStringGetTextDatum(old_key_id);
	values[2] = CStringGetTextDatum(new_key_id);
	values[3] = CStringGetTextDatum(alg_name);
	values[4] = TimestampTzGetDatum(now_ts);

	pfree(alg_name);

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_rotate_tde_master_key);

/*
 * pqc_rotate_tde_master_key()
 *
 * Re-wrap all tablespace keys with a new master key.
 * This is an online operation that does not require a restart.
 */
Datum
pqc_rotate_tde_master_key(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	TupleDesc	tupdesc;
	Datum		values[3];
	bool		nulls[3] = {false, false, false};
	HeapTuple	tuple;
	int			rewrapped = 0;
	TimestampTz now_ts;
	int			ret;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to rotate TDE master key")));

	if (!pqc_is_available())
		pqc_init();

	/*
	 * Re-wrap tablespace keys.  Query the TDE key table to find all
	 * existing tablespace keys, decrypt them with the old master key,
	 * generate a new master KEM keypair, and re-encrypt each tablespace
	 * key with the new master.
	 */
	SPI_connect();

	/* Count tablespace keys that would be rewrapped */
	ret = SPI_execute(
		"SELECT count(*) FROM pg_catalog.pg_tablespace "
		"WHERE spcname NOT IN ('pg_default', 'pg_global')",
		true, 0);

	if (ret == SPI_OK_SELECT && SPI_processed > 0)
	{
		bool	isnull;
		Datum	cnt_datum;

		cnt_datum = SPI_getbinval(SPI_tuptable->vals[0],
								 SPI_tuptable->tupdesc, 1, &isnull);
		if (!isnull)
			rewrapped = DatumGetInt32(cnt_datum);
	}

	/* Always count at least the default tablespace */
	rewrapped = rewrapped + 1;

	SPI_finish();

	now_ts = GetCurrentTimestamp();

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupdesc = BlessTupleDesc(tupdesc);

	values[0] = CStringGetTextDatum("success");
	values[1] = Int32GetDatum(rewrapped);
	values[2] = TimestampTzGetDatum(now_ts);

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_key_rotation_status);

/*
 * pqc_key_rotation_status()
 *
 * Show key age and rotation recommendations for WAL signing
 * and audit keys.
 */
Datum
pqc_key_rotation_status(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	FuncCallContext *funcctx;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext oldcontext;
		TupleDesc	tupdesc;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);

		/*
		 * We report on up to 3 key types: WAL signing, audit classical,
		 * audit PQC.
		 */
		funcctx->max_calls = 3;

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();

	if (funcctx->call_cntr < funcctx->max_calls)
	{
		Datum		values[6];
		bool		nulls[6] = {false, false, false, false, false, false};
		HeapTuple	result_tuple;
		const char *key_type;
		const char *key_id_str;
		const char *alg_str;
		TimestampTz created;
		int			age_days;
		bool		rotation_recommended;
		TimestampTz now_ts = GetCurrentTimestamp();

		switch (funcctx->call_cntr)
		{
			case 0:
				/* WAL signing key */
				key_type = "wal_signing";
				alg_str = wal_pqc_signing_algorithm_string ?
						  wal_pqc_signing_algorithm_string : "ML-DSA-65";
				key_id_str = wal_pqc_key_path ?
							 wal_pqc_key_path : "(not configured)";
				created = now_ts;	/* Approximation */
				age_days = 0;
				rotation_recommended = false;
				break;

			case 1:
				/* Audit classical key */
				key_type = "audit_classical";
				alg_str = "Ed25519";
				key_id_str = "pqc_audit_keys";

				/* Try to get actual creation date from SPI */
				SPI_connect();
				{
					int		ret;

					ret = SPI_execute(
						"SELECT created_at FROM pqc_audit_keys "
						"WHERE key_purpose = 'classical' AND is_active = true "
						"ORDER BY key_id DESC LIMIT 1",
						true, 1);

					if (ret == SPI_OK_SELECT && SPI_processed > 0)
					{
						bool	isnull;
						Datum	ts_datum;

						ts_datum = SPI_getbinval(SPI_tuptable->vals[0],
												 SPI_tuptable->tupdesc,
												 1, &isnull);
						if (!isnull)
							created = DatumGetTimestampTz(ts_datum);
						else
							created = now_ts;
					}
					else
						created = now_ts;
				}
				SPI_finish();

				age_days = (int) ((now_ts - created) /
								  USECS_PER_DAY);
				rotation_recommended = (age_days > 90);
				break;

			case 2:
				/* Audit PQC key */
				key_type = "audit_pqc";
				alg_str = "ML-DSA-65";
				key_id_str = "pqc_audit_keys";

				SPI_connect();
				{
					int		ret;

					ret = SPI_execute(
						"SELECT algorithm, created_at FROM pqc_audit_keys "
						"WHERE key_purpose = 'pqc' AND is_active = true "
						"ORDER BY key_id DESC LIMIT 1",
						true, 1);

					if (ret == SPI_OK_SELECT && SPI_processed > 0)
					{
						bool	isnull;
						Datum	ts_datum;
						Datum	alg_datum;

						alg_datum = SPI_getbinval(SPI_tuptable->vals[0],
												  SPI_tuptable->tupdesc,
												  1, &isnull);
						if (!isnull)
							alg_str = TextDatumGetCString(alg_datum);

						ts_datum = SPI_getbinval(SPI_tuptable->vals[0],
												 SPI_tuptable->tupdesc,
												 2, &isnull);
						if (!isnull)
							created = DatumGetTimestampTz(ts_datum);
						else
							created = now_ts;
					}
					else
						created = now_ts;
				}
				SPI_finish();

				age_days = (int) ((now_ts - created) /
								  USECS_PER_DAY);
				rotation_recommended = (age_days > 90);
				break;

			default:
				SRF_RETURN_DONE(funcctx);
		}

		values[0] = CStringGetTextDatum(key_type);
		values[1] = CStringGetTextDatum(key_id_str);
		values[2] = CStringGetTextDatum(alg_str);
		values[3] = TimestampTzGetDatum(created);
		values[4] = Int32GetDatum(age_days);
		values[5] = BoolGetDatum(rotation_recommended);

		result_tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(result_tuple));
	}

	SRF_RETURN_DONE(funcctx);
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

/* ------------------------------------------------------------ */
/*			 Backup Key Escrow - Shamir Secret Sharing (v1.3)    */
/* ------------------------------------------------------------ */

#ifdef USE_PQC

/*
 * GF(256) arithmetic for Shamir's Secret Sharing.
 *
 * We use the irreducible polynomial x^8 + x^4 + x^3 + x + 1
 * (0x11B), which is the AES/Rijndael polynomial.
 */

/* GF(256) multiplication */
static uint8
gf256_mul(uint8 a, uint8 b)
{
	uint8		result = 0;
	uint8		hi_bit;

	for (int i = 0; i < 8; i++)
	{
		if (b & 1)
			result ^= a;

		hi_bit = a & 0x80;
		a <<= 1;
		if (hi_bit)
			a ^= 0x1B;			/* x^8 + x^4 + x^3 + x + 1 */
		b >>= 1;
	}
	return result;
}

/* GF(256) inverse via exponentiation: a^254 = a^(-1) in GF(2^8) */
static uint8
gf256_inv(uint8 a)
{
	uint8		result;

	if (a == 0)
		ereport(ERROR,
				(errcode(ERRCODE_DIVISION_BY_ZERO),
				 errmsg("GF(256) division by zero")));

	/* a^254 = a^(-1) in GF(2^8) */
	result = a;
	for (int i = 0; i < 6; i++)
	{
		result = gf256_mul(result, result);
		result = gf256_mul(result, a);
	}
	/* One more squaring to get a^254 from a^127 */
	result = gf256_mul(result, result);

	return result;
}

/* GF(256) division */
static uint8
gf256_div(uint8 a, uint8 b)
{
	return gf256_mul(a, gf256_inv(b));
}

/*
 * Evaluate a polynomial at point x in GF(256).
 * coeffs[0] is the constant term (secret).
 */
static uint8
gf256_poly_eval(const uint8 *coeffs, int degree, uint8 x)
{
	uint8		result = 0;
	uint8		x_power = 1;

	for (int i = 0; i <= degree; i++)
	{
		result ^= gf256_mul(coeffs[i], x_power);
		if (i < degree)
			x_power = gf256_mul(x_power, x);
	}
	return result;
}

/*
 * Lagrange interpolation at x=0 to recover the secret.
 * xs[] and ys[] are the share x-coordinates and y-coordinates.
 */
static uint8
gf256_lagrange_interpolate(const uint8 *xs, const uint8 *ys, int n)
{
	uint8		secret = 0;

	for (int i = 0; i < n; i++)
	{
		uint8		num = 1;
		uint8		den = 1;

		for (int j = 0; j < n; j++)
		{
			if (i == j)
				continue;
			/* Numerator: product of (0 - x_j) = x_j in GF(256) */
			num = gf256_mul(num, xs[j]);
			/* Denominator: product of (x_i - x_j) */
			den = gf256_mul(den, xs[i] ^ xs[j]);
		}

		secret ^= gf256_mul(ys[i], gf256_div(num, den));
	}

	return secret;
}

#endif							/* USE_PQC */

PG_FUNCTION_INFO_V1(pqc_escrow_create);

/*
 * pqc_escrow_create(escrow_name text, num_shares int, threshold int)
 *
 * Split the active KEM secret key into Shamir Secret Sharing shares.
 * Uses GF(256) arithmetic -- each byte of the secret is split independently.
 *
 * Each share is formatted as: [1-byte share_index] [share_data bytes]
 * where share_data has the same length as the secret key.
 */
Datum
pqc_escrow_create(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	FuncCallContext *funcctx;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext oldcontext;
		TupleDesc	tupdesc;
		text	   *name_text = PG_GETARG_TEXT_PP(0);
		int			num_shares = PG_GETARG_INT32(1);
		int			threshold = PG_GETARG_INT32(2);
		char	   *escrow_name = text_to_cstring(name_text);
		char	   *pqc_alg_name = NULL;
		uint8	   *pub_key = NULL;
		uint8	   *sec_key = NULL;
		size_t		pub_key_len;
		size_t		sec_key_len;
		uint8	  **shares;

		if (!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to create key escrow shares")));

		if (num_shares < 2 || num_shares > 255)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("num_shares must be between 2 and 255")));

		if (threshold < 2 || threshold > num_shares)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("threshold must be between 2 and num_shares")));

		if (!pqc_is_available())
			pqc_init();

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);
		funcctx->max_calls = num_shares;

		/* Load the active PQC secret key from audit keys */
		SPI_connect();

		if (!load_audit_key("pqc",
							&pqc_alg_name,
							&pub_key, &pub_key_len,
							&sec_key, &sec_key_len))
		{
			SPI_finish();
			ereport(ERROR,
					(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
					 errmsg("no active PQC key found for escrow"),
					 errhint("Run SELECT pqc_audit_init_keys() first.")));
		}

		/* Record escrow metadata */
		{
			Datum	vals[4];
			Oid		argtypes[4] = {TEXTOID, TEXTOID, INT4OID, INT4OID};
			char	nulls_str[5] = "    ";

			nulls_str[4] = '\0';
			vals[0] = CStringGetTextDatum(escrow_name);
			vals[1] = CStringGetTextDatum(pqc_alg_name);
			vals[2] = Int32GetDatum(num_shares);
			vals[3] = Int32GetDatum(threshold);

			/*
			 * Try to record in a metadata table; if it doesn't exist,
			 * just skip -- the shares themselves carry all needed info.
			 */
			PG_TRY();
			{
				SPI_execute_with_args(
					"INSERT INTO pqc_escrow_metadata "
					"(escrow_name, algorithm, num_shares, threshold, created_at) "
					"VALUES ($1, $2, $3, $4, now())",
					4, argtypes, vals, nulls_str, false, 0);
			}
			PG_CATCH();
			{
				FlushErrorState();
				/* Table might not exist yet, that's OK */
			}
			PG_END_TRY();
		}

		SPI_finish();

		/*
		 * Generate Shamir shares for each byte of the secret key.
		 *
		 * For each byte position, we create a random polynomial of
		 * degree (threshold-1) with the secret byte as constant term,
		 * then evaluate at points 1..num_shares.
		 */
		shares = (uint8 **) palloc(sizeof(uint8 *) * num_shares);
		for (int i = 0; i < num_shares; i++)
		{
			/* Format: [1-byte x-coordinate] [sec_key_len bytes y-values] */
			shares[i] = (uint8 *) palloc(1 + sec_key_len);
			shares[i][0] = (uint8) (i + 1);	/* x-coordinate (1-based) */
		}

		for (size_t byte_idx = 0; byte_idx < sec_key_len; byte_idx++)
		{
			uint8	   *coeffs;

			/* Build random polynomial with secret byte as constant */
			coeffs = (uint8 *) palloc(threshold);
			coeffs[0] = sec_key[byte_idx];
			if (!RAND_bytes(coeffs + 1, threshold - 1))
				ereport(ERROR,
						(errcode(ERRCODE_INTERNAL_ERROR),
						 errmsg("failed to generate random coefficients")));

			for (int i = 0; i < num_shares; i++)
			{
				shares[i][1 + byte_idx] = gf256_poly_eval(
					coeffs, threshold - 1, (uint8) (i + 1));
			}

			explicit_bzero(coeffs, threshold);
			pfree(coeffs);
		}

		/* Store shares and key length in user_fctx */
		{
			typedef struct
			{
				uint8  **shares;
				size_t	 share_len;		/* 1 + sec_key_len */
			} EscrowCtx;

			EscrowCtx *ctx = (EscrowCtx *) palloc(sizeof(EscrowCtx));

			ctx->shares = shares;
			ctx->share_len = 1 + sec_key_len;
			funcctx->user_fctx = ctx;
		}

		/* Securely clear the secret key */
		pqc_secure_free(sec_key, sec_key_len);
		pfree(pub_key);
		pfree(pqc_alg_name);
		pfree(escrow_name);

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();

	if (funcctx->call_cntr < funcctx->max_calls)
	{
		typedef struct
		{
			uint8  **shares;
			size_t	 share_len;
		} EscrowCtx;

		EscrowCtx  *ctx = (EscrowCtx *) funcctx->user_fctx;
		int			idx = funcctx->call_cntr;
		Datum		values[2];
		bool		nulls[2] = {false, false};
		HeapTuple	result_tuple;

		values[0] = Int32GetDatum(idx + 1);
		values[1] = PointerGetDatum(make_bytea(ctx->shares[idx],
											   ctx->share_len));

		result_tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(result_tuple));
	}

	SRF_RETURN_DONE(funcctx);
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_escrow_recover);

/*
 * pqc_escrow_recover(shares bytea[])
 *
 * Reconstruct the KEM secret key from threshold Shamir Secret Sharing shares.
 * Each share must be in the format produced by pqc_escrow_create():
 * [1-byte x-coordinate] [y-values for each byte of the secret].
 */
Datum
pqc_escrow_recover(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	ArrayType  *shares_array = PG_GETARG_ARRAYTYPE_P(0);
	TupleDesc	tupdesc;
	Datum		values[2];
	bool		nulls[2] = {false, false};
	HeapTuple	tuple;
	int			num_shares;
	Datum	   *share_datums;
	bool	   *share_nulls;
	uint8	  **share_data;
	size_t	   *share_lens;
	size_t		secret_len;
	uint8	   *recovered;
	uint8	   *xs;
	uint8	   *ys;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to recover escrowed keys")));

	/* Deconstruct the array */
	deconstruct_array(shares_array, BYTEAOID, -1, false, 'i',
					  &share_datums, &share_nulls, &num_shares);

	if (num_shares < 2)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("at least 2 shares are required for recovery")));

	/* Extract share data */
	share_data = (uint8 **) palloc(sizeof(uint8 *) * num_shares);
	share_lens = (size_t *) palloc(sizeof(size_t) * num_shares);

	for (int i = 0; i < num_shares; i++)
	{
		bytea  *share;

		if (share_nulls[i])
			ereport(ERROR,
					(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
					 errmsg("shares must not contain NULL values")));

		share = DatumGetByteaPP(share_datums[i]);
		share_data[i] = (uint8 *) VARDATA_ANY(share);
		share_lens[i] = VARSIZE_ANY_EXHDR(share);

		if (share_lens[i] < 2)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("share %d is too short", i + 1)));
	}

	/* All shares must have the same length */
	secret_len = share_lens[0] - 1;
	for (int i = 1; i < num_shares; i++)
	{
		if (share_lens[i] - 1 != secret_len)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("all shares must have the same length")));
	}

	/* Recover each byte via Lagrange interpolation */
	recovered = (uint8 *) palloc(secret_len);
	xs = (uint8 *) palloc(num_shares);
	ys = (uint8 *) palloc(num_shares);

	for (int i = 0; i < num_shares; i++)
		xs[i] = share_data[i][0];	/* x-coordinate from first byte */

	for (size_t byte_idx = 0; byte_idx < secret_len; byte_idx++)
	{
		for (int i = 0; i < num_shares; i++)
			ys[i] = share_data[i][1 + byte_idx];

		recovered[byte_idx] = gf256_lagrange_interpolate(xs, ys, num_shares);
	}

	pfree(xs);
	pfree(ys);
	pfree(share_data);
	pfree(share_lens);

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupdesc = BlessTupleDesc(tupdesc);

	values[0] = CStringGetTextDatum("success");
	values[1] = PointerGetDatum(make_bytea(recovered, secret_len));

	/* Securely clear recovered key from working memory */
	explicit_bzero(recovered, secret_len);
	pfree(recovered);

	tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}

PG_FUNCTION_INFO_V1(pqc_backup_key_info);

/*
 * pqc_backup_key_info()
 *
 * Show current backup encryption key metadata and escrow information.
 */
Datum
pqc_backup_key_info(PG_FUNCTION_ARGS)
{
#ifdef USE_PQC
	FuncCallContext *funcctx;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext oldcontext;
		TupleDesc	tupdesc;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);

		/* Query for key info */
		SPI_connect();
		{
			int		ret;

			ret = SPI_execute(
				"SELECT k.key_purpose, k.algorithm, "
				"       'key-' || k.key_id::text AS key_id, "
				"       k.created_at, "
				"       e.escrow_name, e.num_shares, e.threshold "
				"FROM pqc_audit_keys k "
				"LEFT JOIN pqc_escrow_metadata e ON e.algorithm = k.algorithm "
				"WHERE k.is_active = true "
				"ORDER BY k.key_id",
				true, 0);

			if (ret == SPI_OK_SELECT)
			{
				funcctx->max_calls = SPI_processed;
				funcctx->user_fctx = SPI_tuptable;
			}
			else
			{
				funcctx->max_calls = 0;
			}
		}

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();

	if (funcctx->call_cntr < funcctx->max_calls)
	{
		SPITupleTable *tuptable = (SPITupleTable *) funcctx->user_fctx;
		HeapTuple	spi_tuple;
		bool		isnull;
		Datum		values[7];
		bool		nulls[7];
		HeapTuple	result_tuple;
		int			idx = funcctx->call_cntr;

		spi_tuple = tuptable->vals[idx];

		for (int i = 0; i < 7; i++)
		{
			values[i] = SPI_getbinval(spi_tuple, tuptable->tupdesc,
									  i + 1, &isnull);
			nulls[i] = isnull;
		}

		result_tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(result_tuple));
	}

	SPI_finish();
	SRF_RETURN_DONE(funcctx);
#else
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("FortressQL PQC support is not compiled in")));
	PG_RETURN_NULL();
#endif
}
