/*-------------------------------------------------------------------------
 *
 * tde_keycache.c
 *	  FortressQL TDE shared-memory key cache implementation.
 *
 * Provides an LWLock-protected cache of decrypted tablespace data
 * encryption keys (TDEKs) in shared memory.  This avoids the overhead
 * of master-key unwrap and TDEK decryption on every page I/O.
 *
 * The cache holds up to TDE_MAX_CACHED_KEYS entries.  Lookups use a
 * linear scan (sufficient for the expected number of tablespaces).
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/tde/tde_keycache.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#ifdef USE_PQC

#include "crypto/tde/tde.h"
#include "crypto/tde/tde_keycache.h"
#include "miscadmin.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/hsearch.h"

/* Pointer to the shared memory key cache */
static TdeKeyCache *TdeKeyCacheShmem = NULL;

/*
 * tde_keycache_shmem_size
 *
 * Report the amount of shared memory needed for the TDE key cache.
 */
Size
tde_keycache_shmem_size(void)
{
	return MAXALIGN(sizeof(TdeKeyCache));
}

/*
 * tde_keycache_shmem_init
 *
 * Initialize the TDE key cache in shared memory.  Called during
 * postmaster startup from the shared memory initialization hooks.
 */
void
tde_keycache_shmem_init(void)
{
	bool		found;

	TdeKeyCacheShmem = (TdeKeyCache *)
		ShmemInitStruct("TDE Key Cache",
						tde_keycache_shmem_size(),
						&found);

	if (!found)
	{
		/* First time - initialize the structure */
		memset(TdeKeyCacheShmem, 0, sizeof(TdeKeyCache));
		LWLockInitialize(&TdeKeyCacheShmem->lock,
						 LWTRANCHE_FIRST_USER_DEFINED);
		TdeKeyCacheShmem->num_entries = 0;
	}
}

/*
 * tde_keycache_init
 *
 * Runtime initialization called once after shared memory is attached.
 * Currently just verifies that shmem was initialized.
 */
void
tde_keycache_init(void)
{
	if (TdeKeyCacheShmem == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE key cache shared memory not initialized")));
}

/*
 * tde_keycache_lookup
 *
 * Look up the active TDEK for the given tablespace OID.  Returns a
 * pointer to the entry on hit, or NULL on miss.
 *
 * Takes a shared (read) lock, so multiple backends can look up keys
 * concurrently.
 */
TdeKeyEntry *
tde_keycache_lookup(Oid spcOid)
{
	int			i;
	TdeKeyEntry *result = NULL;

	if (TdeKeyCacheShmem == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE key cache not initialized")));

	LWLockAcquire(&TdeKeyCacheShmem->lock, LW_SHARED);

	for (i = 0; i < TdeKeyCacheShmem->num_entries; i++)
	{
		TdeKeyEntry *entry = &TdeKeyCacheShmem->entries[i];

		if (entry->spc_oid == spcOid && entry->active)
		{
			result = entry;
			break;
		}
	}

	LWLockRelease(&TdeKeyCacheShmem->lock);

	return result;
}

/*
 * tde_keycache_insert
 *
 * Insert or update a TDEK in the cache.  If an entry for the same
 * tablespace OID already exists, it is updated.  Otherwise a new slot
 * is used.  If the cache is full and no existing slot can be reused,
 * the oldest inactive entry is evicted.
 *
 * Takes an exclusive lock.
 */
void
tde_keycache_insert(const TdeKeyEntry *entry)
{
	int			i;
	int			free_slot = -1;
	int			inactive_slot = -1;

	if (TdeKeyCacheShmem == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE key cache not initialized")));

	LWLockAcquire(&TdeKeyCacheShmem->lock, LW_EXCLUSIVE);

	/* Look for existing entry or a free/inactive slot */
	for (i = 0; i < TdeKeyCacheShmem->num_entries; i++)
	{
		TdeKeyEntry *cached = &TdeKeyCacheShmem->entries[i];

		if (cached->spc_oid == entry->spc_oid)
		{
			/* Update existing entry */
			memcpy(cached->key, entry->key, TDE_AES_KEY_LEN);
			cached->version = entry->version;
			cached->active = entry->active;
			LWLockRelease(&TdeKeyCacheShmem->lock);
			return;
		}

		if (!cached->active && inactive_slot < 0)
			inactive_slot = i;
	}

	/* Try to append if there is room */
	if (TdeKeyCacheShmem->num_entries < TDE_MAX_CACHED_KEYS)
		free_slot = TdeKeyCacheShmem->num_entries++;
	else if (inactive_slot >= 0)
		free_slot = inactive_slot;

	if (free_slot < 0)
	{
		LWLockRelease(&TdeKeyCacheShmem->lock);
		ereport(ERROR,
				(errcode(ERRCODE_CONFIGURATION_LIMIT_EXCEEDED),
				 errmsg("TDE key cache is full (%d entries)",
						TDE_MAX_CACHED_KEYS),
				 errhint("Consider reducing the number of encrypted tablespaces.")));
	}

	/* Insert the new entry */
	memcpy(&TdeKeyCacheShmem->entries[free_slot], entry,
		   sizeof(TdeKeyEntry));

	LWLockRelease(&TdeKeyCacheShmem->lock);
}

/*
 * tde_keycache_invalidate
 *
 * Flush the entire key cache.  Securely wipes all cached key material.
 * Used during master key rotation to force re-derivation of all TDEKs.
 */
void
tde_keycache_invalidate(void)
{
	if (TdeKeyCacheShmem == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("TDE key cache not initialized")));

	LWLockAcquire(&TdeKeyCacheShmem->lock, LW_EXCLUSIVE);

	/* Securely wipe all key material */
	explicit_bzero(TdeKeyCacheShmem->entries,
				   sizeof(TdeKeyEntry) * TDE_MAX_CACHED_KEYS);
	TdeKeyCacheShmem->num_entries = 0;

	LWLockRelease(&TdeKeyCacheShmem->lock);
}

#endif							/* USE_PQC */
