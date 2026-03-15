/*-------------------------------------------------------------------------
 *
 * tde_keycache.h
 *	  FortressQL TDE shared-memory key cache.
 *
 * Provides an LWLock-protected shared-memory cache of decrypted tablespace
 * data encryption keys (TDEKs).  Avoids repeated master-key unwrap and
 * TDEK decryption on every page I/O.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/include/crypto/tde/tde_keycache.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TDE_KEYCACHE_H
#define TDE_KEYCACHE_H

#include "postgres.h"

#ifdef USE_PQC

#include "crypto/tde/tde.h"
#include "storage/lwlock.h"

/*
 * TdeKeyCache
 *
 * Shared-memory structure holding cached TDEKs.  Protected by an LWLock
 * so concurrent backends can read keys without contention (shared lock)
 * while key insertion and invalidation take an exclusive lock.
 */
typedef struct TdeKeyCache
{
	LWLock		lock;				/* protects all fields below */
	int			num_entries;		/* current number of cached keys */
	TdeKeyEntry entries[TDE_MAX_CACHED_KEYS];
} TdeKeyCache;

/*
 * Shared memory sizing and initialization - called during postmaster
 * startup from the shmem init hooks.
 */
extern Size tde_keycache_shmem_size(void);
extern void tde_keycache_shmem_init(void);

/*
 * tde_keycache_init
 *
 * Runtime initialization of the key cache (post-shmem attach).
 * Called once per postmaster startup after shared memory is ready.
 */
extern void tde_keycache_init(void);

/*
 * tde_keycache_lookup
 *
 * Look up the active TDEK for the given tablespace OID.  Returns a
 * pointer to the TdeKeyEntry on hit, or NULL on miss.  The caller must
 * not modify or free the returned entry.
 *
 * On cache miss, the caller is responsible for loading the key via the
 * key management layer and inserting it into the cache.
 */
extern TdeKeyEntry *tde_keycache_lookup(Oid spcOid);

/*
 * tde_keycache_insert
 *
 * Insert or update a TDEK in the cache.  If the cache is full, evicts
 * the oldest inactive entry.  Takes an exclusive lock internally.
 */
extern void tde_keycache_insert(const TdeKeyEntry *entry);

/*
 * tde_keycache_invalidate
 *
 * Flush the entire key cache.  Used during master key rotation to force
 * all backends to re-fetch TDEKs decrypted under the new master key.
 */
extern void tde_keycache_invalidate(void);

#endif							/* USE_PQC */

#endif							/* TDE_KEYCACHE_H */
