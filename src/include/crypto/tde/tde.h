/*-------------------------------------------------------------------------
 *
 * tde.h
 *	  FortressQL Transparent Data Encryption (TDE) main header.
 *
 * Defines core constants, key entry structures, and function declarations
 * for the TDE subsystem.  TDE encrypts data pages and WAL at rest using
 * AES-256-CTR, with master keys protected via ML-KEM-768 (FIPS 203).
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/include/crypto/tde/tde.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TDE_H
#define TDE_H

#include "postgres.h"

#ifdef USE_PQC

#include "common/relpath.h"
#include "storage/block.h"
#include "storage/bufpage.h"
#include "access/xlogdefs.h"

/* ----------------------------------------------------------------
 *					TDE Constants
 * ----------------------------------------------------------------
 */
#define TDE_VERSION				1

/* AES-256 key length in bytes */
#define TDE_AES_KEY_LEN			32

/* AES-CTR initialization vector length in bytes */
#define TDE_IV_LEN				16

/*
 * Number of bytes at the start of each data page that remain in cleartext.
 * This covers PageHeaderData (LSN, checksum, flags, etc.) which the buffer
 * manager must read without decryption.
 */
#define TDE_PAGE_HEADER_SIZE	24

/*
 * Maximum number of tablespace data encryption keys (TDEKs) that can be
 * cached in shared memory simultaneously.
 */
#define TDE_MAX_CACHED_KEYS		256

/* Subdirectory under $PGDATA/global for encryption state */
#define TDE_KEY_DIR				"pg_encryption"

/* Filename for the encrypted master key blob */
#define TDE_MASTER_KEY_FILE		"master.key"

/* ----------------------------------------------------------------
 *					TDE Key Entry
 * ----------------------------------------------------------------
 */

/*
 * TdeKeyEntry
 *
 * Represents a tablespace data encryption key (TDEK) in the shared
 * memory key cache.  Each tablespace has at most one active TDEK.
 */
typedef struct TdeKeyEntry
{
	Oid			spc_oid;			/* tablespace OID */
	uint8		key[TDE_AES_KEY_LEN];	/* decrypted TDEK */
	int			version;			/* key version for rotation */
	bool		active;				/* true if this key is current */
} TdeKeyEntry;

/* ----------------------------------------------------------------
 *					GUC Variables
 * ----------------------------------------------------------------
 */

/* GUC: enable transparent data encryption (default: off) */
extern bool tde_enabled;

/* ----------------------------------------------------------------
 *					Function Declarations
 * ----------------------------------------------------------------
 */

/* tde_page.c - data page encryption */
extern void tde_encrypt_page(Page page, Size pageSize,
							 Oid spcOid, Oid dbOid,
							 RelFileNumber relNumber,
							 ForkNumber forkNum,
							 BlockNumber blockNum);
extern void tde_decrypt_page(Page page, Size pageSize,
							 Oid spcOid, Oid dbOid,
							 RelFileNumber relNumber,
							 ForkNumber forkNum,
							 BlockNumber blockNum);

/* tde_wal.c - WAL page encryption */
extern void tde_encrypt_wal_page(char *page, int pageSize,
								 XLogSegNo segno, uint32 offset);
extern void tde_decrypt_wal_page(char *page, int pageSize,
								 XLogSegNo segno, uint32 offset);

/* tde_keycache.c - shared memory key cache */
extern void tde_keycache_init(void);
extern TdeKeyEntry *tde_keycache_lookup(Oid spcOid);
extern void tde_keycache_invalidate(void);
extern Size tde_keycache_shmem_size(void);
extern void tde_keycache_shmem_init(void);

/* tde_keymanage.c - key lifecycle */
extern void tde_generate_master_key(void);
extern void tde_unwrap_master_key(void);
extern void tde_generate_tablespace_key(Oid spcOid);
extern void tde_rotate_master_key(void);
extern void tde_derive_page_iv(const uint8 *tdek,
							   Oid spcOid, Oid dbOid,
							   RelFileNumber relNumber,
							   ForkNumber forkNum,
							   BlockNumber blockNum,
							   uint8 *iv_out);

#endif							/* USE_PQC */

#endif							/* TDE_H */
