/*-------------------------------------------------------------------------
 *
 * tde_wal.h
 *	  FortressQL TDE WAL page encryption/decryption interface.
 *
 * Encrypts the payload of WAL pages using AES-256-CTR.  The
 * XLogPageHeaderData is left in cleartext so the WAL reader can locate
 * records and detect page boundaries.  An XLP_ENCRYPTED flag is set in
 * xlp_info to mark encrypted pages.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/include/crypto/tde/tde_wal.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TDE_WAL_H
#define TDE_WAL_H

#include "postgres.h"

#ifdef USE_PQC

#include "access/xlogdefs.h"

/*
 * XLP_ENCRYPTED - XLogPageHeader flag indicating the page payload is
 * AES-256-CTR encrypted.  Must not collide with existing XLP_* flags
 * defined in xlog_internal.h (currently 0x0001..0x0008).
 */
#define XLP_ENCRYPTED			0x0010

/*
 * tde_encrypt_wal_page
 *
 * Encrypt a WAL page in-place.  The header (sized according to
 * XLogPageHeaderSize) is preserved in cleartext; the remainder of the
 * page is encrypted.  Sets XLP_ENCRYPTED in xlp_info.
 */
extern void tde_encrypt_wal_page(char *page, int pageSize,
								 XLogSegNo segno, uint32 offset);

/*
 * tde_decrypt_wal_page
 *
 * Decrypt a WAL page in-place.  If XLP_ENCRYPTED is not set in xlp_info,
 * the page is assumed unencrypted and this function is a no-op.
 */
extern void tde_decrypt_wal_page(char *page, int pageSize,
								 XLogSegNo segno, uint32 offset);

#endif							/* USE_PQC */

#endif							/* TDE_WAL_H */
