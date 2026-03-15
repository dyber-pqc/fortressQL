/*-------------------------------------------------------------------------
 *
 * pgcrypto_pqc.c
 *	  FortressQL: SQL-callable Post-Quantum Cryptography functions.
 *
 * Provides KEM (key encapsulation), digital signatures, and hybrid
 * encryption (ML-KEM + AES-256-GCM) through SQL functions.
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

#include "crypto/pqc/pqc_common.h"
#include "crypto/pqc/pqc_kem.h"
#include "crypto/pqc/pqc_sig.h"
#include "fmgr.h"
#include "funcapi.h"
#include "utils/builtins.h"

#ifdef USE_PQC
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#endif

PG_MODULE_MAGIC;

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

PG_FUNCTION_INFO_V1(pqc_kem_keygen);

Datum
pqc_kem_keygen(PG_FUNCTION_ARGS)
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

PG_FUNCTION_INFO_V1(pqc_sig_keygen);

Datum
pqc_sig_keygen(PG_FUNCTION_ARGS)
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

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		funcctx->max_calls = PQC_ALG_COUNT;

		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);

		/* Ensure PQC is initialized for accurate sizes */
		if (!pqc_is_available())
			pqc_init();

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();
	call_cntr = funcctx->call_cntr;

	if (call_cntr < funcctx->max_calls)
	{
		const PqcAlgorithmInfo *info;
		Datum		values[6];
		bool		nulls[6] = {false, false, false, false, false, false};
		HeapTuple	tuple;

		info = pqc_get_algorithm_info((PqcAlgorithm) call_cntr);
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
