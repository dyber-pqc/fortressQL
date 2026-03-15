/*-------------------------------------------------------------------------
 *
 * tde_page.c
 *	  FortressQL TDE data page encryption/decryption implementation.
 *
 * Encrypts the payload portion of PostgreSQL data pages using AES-256-CTR
 * via the OpenSSL EVP API.  The first TDE_PAGE_HEADER_SIZE bytes (covering
 * PageHeaderData: LSN, checksum, flags, etc.) are left in cleartext so the
 * buffer manager can function without decryption.
 *
 * IVs are derived per-page using HKDF over the tablespace data encryption
 * key (TDEK) and page identity (spcOid, dbOid, relNumber, forkNum,
 * blockNum), ensuring each page gets a unique keystream.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/tde/tde_page.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#ifdef USE_PQC

#include <openssl/evp.h>

#include "crypto/tde/tde.h"
#include "crypto/tde/tde_page.h"
#include "crypto/tde/tde_keycache.h"
#include "storage/bufpage.h"
#include "utils/memutils.h"

/* GUC variable: enable Transparent Data Encryption */
bool		tde_enabled = false;

/*
 * tde_page_crypt
 *
 * Shared encrypt/decrypt implementation for data pages.  AES-256-CTR is
 * symmetric so encryption and decryption are the same operation.
 *
 * The first TDE_PAGE_HEADER_SIZE bytes of the page are skipped (left in
 * cleartext).  The remainder is encrypted/decrypted in-place.
 */
static void
tde_page_crypt(Page page, Size pageSize,
			   Oid spcOid, Oid dbOid,
			   RelFileNumber relNumber,
			   ForkNumber forkNum,
			   BlockNumber blockNum)
{
	TdeKeyEntry entry;
	uint8		iv[TDE_IV_LEN];
	EVP_CIPHER_CTX *ctx;
	int			outlen;
	int			payload_len;
	uint8	   *payload;

	/* Sanity checks */
	if (pageSize <= TDE_PAGE_HEADER_SIZE)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("TDE: page size %zu is too small for encryption",
						(size_t) pageSize)));

	/*
	 * Look up the tablespace data encryption key.  The key is copied into
	 * our local entry while the cache lock is held, preventing a concurrent
	 * invalidation from wiping the key mid-use.
	 */
	if (!tde_keycache_lookup(spcOid, &entry))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: no encryption key found for tablespace %u",
						spcOid),
				 errhint("Ensure TDE is configured for this tablespace.")));

	/* Derive a per-page IV via HKDF */
	tde_derive_page_iv(entry.key, spcOid, dbOid, relNumber,
					   forkNum, blockNum, iv);

	/* Set up AES-256-CTR context */
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
	{
		explicit_bzero(&entry, sizeof(entry));
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("TDE: failed to allocate cipher context")));
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL,
						   entry.key, iv) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		explicit_bzero(&entry, sizeof(entry));
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: failed to initialize AES-256-CTR for page "
						"(spc=%u, db=%u, rel=%u, blk=%u)",
						spcOid, dbOid, relNumber, blockNum)));
	}

	/* Encrypt/decrypt the page payload (after header) in-place */
	payload = (uint8 *) page + TDE_PAGE_HEADER_SIZE;
	payload_len = pageSize - TDE_PAGE_HEADER_SIZE;

	if (EVP_EncryptUpdate(ctx, payload, &outlen, payload, payload_len) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		explicit_bzero(&entry, sizeof(entry));
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: AES-256-CTR encryption/decryption failed for page "
						"(spc=%u, db=%u, rel=%u, blk=%u)",
						spcOid, dbOid, relNumber, blockNum)));
	}

	/*
	 * CTR mode does not require finalization for padding, but we call it
	 * for correctness.
	 */
	if (EVP_EncryptFinal_ex(ctx, payload + outlen, &outlen) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		explicit_bzero(&entry, sizeof(entry));
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE: AES-256-CTR finalization failed for page "
						"(spc=%u, db=%u, rel=%u, blk=%u)",
						spcOid, dbOid, relNumber, blockNum)));
	}

	EVP_CIPHER_CTX_free(ctx);

	/* Wipe the local copy of key material */
	explicit_bzero(&entry, sizeof(entry));
	explicit_bzero(iv, sizeof(iv));
}

/*
 * tde_encrypt_page
 *
 * Encrypt a data page in-place before writing to disk.
 *
 * Encryption failure is treated as FATAL: writing plaintext to disk when
 * TDE is enabled would silently violate the confidentiality guarantee.
 * It is better to halt the server than to leak data.
 */
void
tde_encrypt_page(Page page, Size pageSize,
				 Oid spcOid, Oid dbOid,
				 RelFileNumber relNumber,
				 ForkNumber forkNum,
				 BlockNumber blockNum)
{
	PG_TRY();
	{
		tde_page_crypt(page, pageSize, spcOid, dbOid,
					   relNumber, forkNum, blockNum);
	}
	PG_CATCH();
	{
		/*
		 * Encryption failed.  We must NOT write plaintext to disk.
		 * Escalate to PANIC to force a crash-recovery cycle rather
		 * than silently persisting unencrypted data.
		 */
		EmitErrorReport();
		FlushErrorState();
		ereport(PANIC,
				(errmsg("TDE: encryption failed for page "
						"(spc=%u, db=%u, rel=%u, blk=%u); "
						"refusing to write unencrypted data to disk",
						spcOid, dbOid, relNumber, blockNum),
				 errhint("Check OpenSSL status and TDE key availability.")));
	}
	PG_END_TRY();
}

/*
 * tde_decrypt_page
 *
 * Decrypt a data page in-place after reading from disk.
 * AES-256-CTR is symmetric, so this is the same operation as encrypt.
 *
 * If decryption fails, we emit a WARNING with page identity and return
 * the page as-is.  The page may have been stored unencrypted (e.g., if
 * encryption failed on write), so returning it unchanged is reasonable.
 */
void
tde_decrypt_page(Page page, Size pageSize,
				 Oid spcOid, Oid dbOid,
				 RelFileNumber relNumber,
				 ForkNumber forkNum,
				 BlockNumber blockNum)
{
	PG_TRY();
	{
		tde_page_crypt(page, pageSize, spcOid, dbOid,
					   relNumber, forkNum, blockNum);
	}
	PG_CATCH();
	{
		/*
		 * Decryption failed - the page may be unencrypted or corrupted.
		 * Return it as-is and let upper layers deal with any corruption.
		 */
		EmitErrorReport();
		FlushErrorState();
		ereport(WARNING,
				(errmsg("TDE: decryption failed for page "
						"(spc=%u, db=%u, rel=%u, blk=%u), "
						"returning page as-is (may be unencrypted)",
						spcOid, dbOid, relNumber, blockNum)));
	}
	PG_END_TRY();
}

#endif							/* USE_PQC */
