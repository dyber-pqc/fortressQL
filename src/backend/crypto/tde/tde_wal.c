/*-------------------------------------------------------------------------
 *
 * tde_wal.c
 *	  FortressQL TDE WAL page encryption/decryption implementation.
 *
 * Encrypts the payload of WAL pages using AES-256-CTR via OpenSSL EVP.
 * The XLogPageHeaderData is left in cleartext so the WAL reader can
 * locate records and detect page boundaries.  The XLP_ENCRYPTED flag
 * is set in xlp_info to mark encrypted pages.
 *
 * IVs are derived via HKDF from a dedicated WAL encryption key and the
 * WAL segment number plus page offset, ensuring each WAL page gets a
 * unique keystream.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/tde/tde_wal.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#ifdef USE_PQC

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "crypto/tde/tde.h"
#include "crypto/tde/tde_wal.h"
#include "crypto/tde/tde_keycache.h"
#include "access/xlog_internal.h"

/*
 * WAL key label used in HKDF derivation to separate the WAL key domain
 * from the data page key domain.
 */
static const char TDE_WAL_HKDF_LABEL[] = "FortressQL-TDE-WAL-IV-v1";

/*
 * tde_derive_wal_iv
 *
 * Derive a unique IV for a WAL page from the WAL encryption key, segment
 * number, and page offset within the segment.  Uses HKDF-SHA256.
 */
static void
tde_derive_wal_iv(const uint8 *wal_key,
				  XLogSegNo segno, uint32 offset,
				  uint8 *iv_out)
{
	EVP_PKEY_CTX *pctx;
	uint8		info_buf[sizeof(XLogSegNo) + sizeof(uint32)];
	size_t		iv_len = TDE_IV_LEN;

	/* Build the info parameter: segno || offset */
	memcpy(info_buf, &segno, sizeof(XLogSegNo));
	memcpy(info_buf + sizeof(XLogSegNo), &offset, sizeof(uint32));

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("TDE: failed to allocate HKDF context for WAL IV")));

	if (EVP_PKEY_derive_init(pctx) <= 0 ||
		EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
		EVP_PKEY_CTX_set1_hkdf_salt(pctx,
									(const unsigned char *) TDE_WAL_HKDF_LABEL,
									strlen(TDE_WAL_HKDF_LABEL)) <= 0 ||
		EVP_PKEY_CTX_set1_hkdf_key(pctx, wal_key, TDE_AES_KEY_LEN) <= 0 ||
		EVP_PKEY_CTX_add1_hkdf_info(pctx, info_buf, sizeof(info_buf)) <= 0 ||
		EVP_PKEY_derive(pctx, iv_out, &iv_len) <= 0)
	{
		EVP_PKEY_CTX_free(pctx);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: HKDF derivation failed for WAL IV")));
	}

	EVP_PKEY_CTX_free(pctx);
}

/*
 * tde_wal_crypt
 *
 * Shared encrypt/decrypt for WAL pages.  AES-256-CTR is symmetric.
 *
 * Leaves XLogPageHeaderData in cleartext and operates on the remainder.
 */
static void
tde_wal_crypt(char *page, int pageSize, XLogSegNo segno, uint32 offset)
{
	XLogPageHeader hdr = (XLogPageHeader) page;
	TdeKeyEntry entry;
	uint8		iv[TDE_IV_LEN];
	EVP_CIPHER_CTX *ctx;
	int			hdr_size;
	int			payload_len;
	int			outlen;

	/*
	 * Determine the actual header size - long headers have extra fields.
	 */
	hdr_size = XLogPageHeaderSize(hdr);
	if (hdr_size >= pageSize)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("TDE: WAL page header size %d exceeds page size %d",
						hdr_size, pageSize)));

	/*
	 * Use tablespace 0 (global) for the WAL key.  The WAL shares the
	 * global tablespace's TDEK.
	 */
	if (!tde_keycache_lookup(InvalidOid, &entry))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: no WAL encryption key found"),
				 errhint("Ensure TDE is configured and the master key is loaded.")));

	/* Derive per-page IV */
	tde_derive_wal_iv(entry.key, segno, offset, iv);

	/* Set up AES-256-CTR */
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("TDE: failed to allocate cipher context for WAL")));

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL,
						   entry.key, iv) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: failed to initialize AES-256-CTR for WAL")));
	}

	payload_len = pageSize - hdr_size;

	if (EVP_EncryptUpdate(ctx, (uint8 *) page + hdr_size, &outlen,
						  (uint8 *) page + hdr_size, payload_len) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: AES-256-CTR failed for WAL page")));
	}

	if (EVP_EncryptFinal_ex(ctx, (uint8 *) page + hdr_size + outlen,
							&outlen) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: AES-256-CTR finalization failed for WAL")));
	}

	EVP_CIPHER_CTX_free(ctx);
}

/*
 * tde_encrypt_wal_page
 *
 * Encrypt a WAL page in-place and set the XLP_ENCRYPTED flag.
 */
void
tde_encrypt_wal_page(char *page, int pageSize,
					 XLogSegNo segno, uint32 offset)
{
	XLogPageHeader hdr = (XLogPageHeader) page;

	tde_wal_crypt(page, pageSize, segno, offset);

	/* Mark this page as encrypted */
	hdr->xlp_info |= XLP_ENCRYPTED;
}

/*
 * tde_decrypt_wal_page
 *
 * Decrypt a WAL page in-place.  If the XLP_ENCRYPTED flag is not set,
 * the page is assumed to be unencrypted and this is a no-op.
 */
void
tde_decrypt_wal_page(char *page, int pageSize,
					 XLogSegNo segno, uint32 offset)
{
	XLogPageHeader hdr = (XLogPageHeader) page;

	/* Skip unencrypted pages */
	if (!(hdr->xlp_info & XLP_ENCRYPTED))
		return;

	tde_wal_crypt(page, pageSize, segno, offset);

	/* Clear the encrypted flag after decryption */
	hdr->xlp_info &= ~XLP_ENCRYPTED;
}

#endif							/* USE_PQC */
