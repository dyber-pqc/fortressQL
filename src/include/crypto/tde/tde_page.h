/*-------------------------------------------------------------------------
 *
 * tde_page.h
 *	  FortressQL TDE data page encryption/decryption interface.
 *
 * Encrypts the payload of a data page (everything after the page header)
 * using AES-256-CTR.  The page header is left in cleartext so the buffer
 * manager can read the LSN, checksum, and other metadata without
 * decryption.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/include/crypto/tde/tde_page.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TDE_PAGE_H
#define TDE_PAGE_H

#include "postgres.h"

#ifdef USE_PQC

#include "common/relpath.h"
#include "storage/block.h"
#include "storage/bufpage.h"

/*
 * tde_encrypt_page
 *
 * Encrypt a data page in-place.  Only the portion after the first
 * TDE_PAGE_HEADER_SIZE bytes is encrypted.  The caller must supply the
 * tablespace OID, database OID, relation file number, fork number, and
 * block number so a unique IV can be derived.
 */
extern void tde_encrypt_page(Page page, Size pageSize,
							 Oid spcOid, Oid dbOid,
							 RelFileNumber relNumber,
							 ForkNumber forkNum,
							 BlockNumber blockNum);

/*
 * tde_decrypt_page
 *
 * Decrypt a data page in-place.  The same identification parameters used
 * during encryption must be supplied so the identical IV is derived.
 */
extern void tde_decrypt_page(Page page, Size pageSize,
							 Oid spcOid, Oid dbOid,
							 RelFileNumber relNumber,
							 ForkNumber forkNum,
							 BlockNumber blockNum);

#endif							/* USE_PQC */

#endif							/* TDE_PAGE_H */
