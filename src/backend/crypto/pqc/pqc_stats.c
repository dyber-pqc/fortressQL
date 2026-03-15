/*-------------------------------------------------------------------------
 *
 * pqc_stats.c
 *	  FortressQL PQC operation statistics collector.
 *
 * Provides shared-memory counters for tracking PQC operations and
 * the pg_stat_pqc SQL function that exposes them.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/pqc/pqc_stats.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "crypto/pqc/pqc_common.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/builtins.h"
#include "utils/timestamp.h"

/* Global pointer to shared-memory counters */
PqcStatCounters *pqc_stat_counters = NULL;

/* Saved hook for shared memory startup */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

/*
 * pqc_stat_shmem_size
 *
 * Compute shared memory size needed for PQC stats.
 */
Size
pqc_stat_shmem_size(void)
{
	return MAXALIGN(sizeof(PqcStatCounters));
}

/*
 * pqc_stat_shmem_startup
 *
 * Initialize PQC stats shared memory segment.
 */
void
pqc_stat_shmem_startup(void)
{
	bool		found;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	pqc_stat_counters = (PqcStatCounters *)
		ShmemInitStruct("PQC Statistics Counters",
						sizeof(PqcStatCounters),
						&found);

	if (!found)
	{
		/* First time through: initialize the counters */
		pg_atomic_init_u64(&pqc_stat_counters->kem_encaps_count, 0);
		pg_atomic_init_u64(&pqc_stat_counters->kem_decaps_count, 0);
		pg_atomic_init_u64(&pqc_stat_counters->sig_sign_count, 0);
		pg_atomic_init_u64(&pqc_stat_counters->sig_verify_count, 0);
		pg_atomic_init_u64(&pqc_stat_counters->tde_encryptions, 0);
		pg_atomic_init_u64(&pqc_stat_counters->tde_decryptions, 0);
		pg_atomic_init_u64(&pqc_stat_counters->key_cache_hits, 0);
		pg_atomic_init_u64(&pqc_stat_counters->key_cache_misses, 0);
		pg_atomic_init_u64(&pqc_stat_counters->wal_segments_signed, 0);
		pg_atomic_init_u64(&pqc_stat_counters->encrypt_time_us, 0);
		pg_atomic_init_u64(&pqc_stat_counters->sign_time_us, 0);
	}

	LWLockRelease(AddinShmemInitLock);
}

/*
 * pqc_stat_init
 *
 * Request shared memory and register the startup hook.
 * Called from _PG_init or shared_preload_libraries init.
 */
void
pqc_stat_init(void)
{
	RequestAddinShmemSpace(pqc_stat_shmem_size());

	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pqc_stat_shmem_startup;
}

/*
 * pg_stat_get_pqc
 *
 * SQL-callable function returning PQC operation statistics as a record.
 */
Datum
pg_stat_get_pqc(PG_FUNCTION_ARGS)
{
#define PG_STAT_PQC_COLS	13
	TupleDesc	tupdesc;
	Datum		values[PG_STAT_PQC_COLS] = {0};
	bool		nulls[PG_STAT_PQC_COLS] = {0};
	uint64		kem_encaps,
				kem_decaps,
				sig_sign,
				sig_verify,
				tde_enc,
				tde_dec,
				cache_hits,
				cache_misses,
				wal_signed,
				enc_time_us,
				sign_time_us;

	/* Build a tuple descriptor for the result row */
	tupdesc = CreateTemplateTupleDesc(PG_STAT_PQC_COLS);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1, "kem_encapsulations",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2, "kem_decapsulations",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3, "sig_sign_operations",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 4, "sig_verify_operations",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 5, "tde_page_encryptions",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 6, "tde_page_decryptions",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 7, "key_cache_hits",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 8, "key_cache_misses",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 9, "wal_segments_signed",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 10, "avg_encrypt_time_ms",
					   FLOAT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 11, "avg_sign_time_ms",
					   FLOAT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 12, "total_encrypt_time_ms",
					   FLOAT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 13, "total_sign_time_ms",
					   FLOAT8OID, -1, 0);

	BlessTupleDesc(tupdesc);

	/* Read counters */
	if (pqc_stat_counters != NULL)
	{
		kem_encaps = pg_atomic_read_u64(&pqc_stat_counters->kem_encaps_count);
		kem_decaps = pg_atomic_read_u64(&pqc_stat_counters->kem_decaps_count);
		sig_sign = pg_atomic_read_u64(&pqc_stat_counters->sig_sign_count);
		sig_verify = pg_atomic_read_u64(&pqc_stat_counters->sig_verify_count);
		tde_enc = pg_atomic_read_u64(&pqc_stat_counters->tde_encryptions);
		tde_dec = pg_atomic_read_u64(&pqc_stat_counters->tde_decryptions);
		cache_hits = pg_atomic_read_u64(&pqc_stat_counters->key_cache_hits);
		cache_misses = pg_atomic_read_u64(&pqc_stat_counters->key_cache_misses);
		wal_signed = pg_atomic_read_u64(&pqc_stat_counters->wal_segments_signed);
		enc_time_us = pg_atomic_read_u64(&pqc_stat_counters->encrypt_time_us);
		sign_time_us = pg_atomic_read_u64(&pqc_stat_counters->sign_time_us);
	}
	else
	{
		kem_encaps = kem_decaps = 0;
		sig_sign = sig_verify = 0;
		tde_enc = tde_dec = 0;
		cache_hits = cache_misses = 0;
		wal_signed = 0;
		enc_time_us = sign_time_us = 0;
	}

	values[0] = Int64GetDatum(kem_encaps);
	values[1] = Int64GetDatum(kem_decaps);
	values[2] = Int64GetDatum(sig_sign);
	values[3] = Int64GetDatum(sig_verify);
	values[4] = Int64GetDatum(tde_enc);
	values[5] = Int64GetDatum(tde_dec);
	values[6] = Int64GetDatum(cache_hits);
	values[7] = Int64GetDatum(cache_misses);
	values[8] = Int64GetDatum(wal_signed);

	/* Average encrypt time in ms (total_enc_ops = tde_enc + kem_encaps) */
	{
		uint64		total_enc_ops = tde_enc + kem_encaps;

		if (total_enc_ops > 0)
			values[9] = Float8GetDatum((double) enc_time_us / (double) total_enc_ops / 1000.0);
		else
			values[9] = Float8GetDatum(0.0);
	}

	/* Average sign time in ms (total_sign_ops = sig_sign + wal_signed) */
	{
		uint64		total_sign_ops = sig_sign + wal_signed;

		if (total_sign_ops > 0)
			values[10] = Float8GetDatum((double) sign_time_us / (double) total_sign_ops / 1000.0);
		else
			values[10] = Float8GetDatum(0.0);
	}

	/* Total times in ms */
	values[11] = Float8GetDatum((double) enc_time_us / 1000.0);
	values[12] = Float8GetDatum((double) sign_time_us / 1000.0);

	PG_RETURN_DATUM(HeapTupleGetDatum(
		heap_form_tuple(tupdesc, values, nulls)));
}

/*
 * pg_stat_reset_pqc
 *
 * Reset all PQC statistics counters to zero.
 */
Datum
pg_stat_reset_pqc(PG_FUNCTION_ARGS)
{
	if (pqc_stat_counters != NULL)
	{
		pg_atomic_write_u64(&pqc_stat_counters->kem_encaps_count, 0);
		pg_atomic_write_u64(&pqc_stat_counters->kem_decaps_count, 0);
		pg_atomic_write_u64(&pqc_stat_counters->sig_sign_count, 0);
		pg_atomic_write_u64(&pqc_stat_counters->sig_verify_count, 0);
		pg_atomic_write_u64(&pqc_stat_counters->tde_encryptions, 0);
		pg_atomic_write_u64(&pqc_stat_counters->tde_decryptions, 0);
		pg_atomic_write_u64(&pqc_stat_counters->key_cache_hits, 0);
		pg_atomic_write_u64(&pqc_stat_counters->key_cache_misses, 0);
		pg_atomic_write_u64(&pqc_stat_counters->wal_segments_signed, 0);
		pg_atomic_write_u64(&pqc_stat_counters->encrypt_time_us, 0);
		pg_atomic_write_u64(&pqc_stat_counters->sign_time_us, 0);
	}

	PG_RETURN_VOID();
}
