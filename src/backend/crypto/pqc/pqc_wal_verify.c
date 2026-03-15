/*-------------------------------------------------------------------------
 *
 * pqc_wal_verify.c
 *	  FortressQL Post-Quantum WAL Segment Signature Verification.
 *
 * Provides functions to verify the post-quantum digital signature
 * of a received WAL segment.  Used by the WAL receiver to ensure
 * segment integrity and authenticity.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/crypto/pqc/pqc_wal_verify.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#ifdef USE_PQC

#include <sys/stat.h>
#include <unistd.h>

#include "crypto/pqc/pqc_wal_keys.h"
#include "crypto/pqc/pqc_common.h"
#include "crypto/pqc/pqc_sig.h"
#include "common/file_perm.h"
#include "miscadmin.h"
#include "storage/fd.h"

/*
 * pqc_wal_verify_segment
 *
 * Verify the PQC signature of a WAL segment file.
 *
 * Expects segpath to be the path to the WAL segment file (e.g.,
 * "pg_wal/000000010000000000000001").  The corresponding signature
 * file is expected at segpath + ".sig".
 *
 * The public key used for verification is the one currently loaded
 * via pqc_wal_load_signing_keys().
 *
 * Returns true if the signature is valid, false otherwise.
 * Emits a WARNING on verification failure or missing files.
 */
bool
pqc_wal_verify_segment(const char *segpath)
{
	char		sigpath[MAXPGPATH];
	FILE	   *seg_fp = NULL;
	FILE	   *sig_fp = NULL;
	struct stat seg_stat;
	struct stat sig_stat;
	uint8	   *seg_data = NULL;
	size_t		seg_len;
	uint8	   *sig_data = NULL;
	size_t		sig_len;
	uint8	   *pubkey;
	size_t		pubkey_len;
	int			result;

	/* Build signature file path */
	snprintf(sigpath, MAXPGPATH, "%s.sig", segpath);

	/* Check that both files exist */
	if (stat(segpath, &seg_stat) != 0)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("PQC WAL verify: could not stat segment file \"%s\": %m",
						segpath)));
		return false;
	}

	if (stat(sigpath, &sig_stat) != 0)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("PQC WAL verify: signature file \"%s\" not found: %m",
						sigpath)));
		return false;
	}

	seg_len = (size_t) seg_stat.st_size;
	sig_len = (size_t) sig_stat.st_size;

	if (seg_len == 0)
	{
		ereport(WARNING,
				(errmsg("PQC WAL verify: segment file \"%s\" is empty",
						segpath)));
		return false;
	}

	if (sig_len == 0)
	{
		ereport(WARNING,
				(errmsg("PQC WAL verify: signature file \"%s\" is empty",
						sigpath)));
		return false;
	}

	/* Read segment data */
	seg_data = (uint8 *) palloc(seg_len);
	seg_fp = AllocateFile(segpath, "rb");
	if (seg_fp == NULL)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("PQC WAL verify: could not open segment \"%s\": %m",
						segpath)));
		pfree(seg_data);
		return false;
	}
	if (fread(seg_data, 1, seg_len, seg_fp) != seg_len)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("PQC WAL verify: could not read segment \"%s\": %m",
						segpath)));
		FreeFile(seg_fp);
		pfree(seg_data);
		return false;
	}
	FreeFile(seg_fp);

	/* Read signature data */
	sig_data = (uint8 *) palloc(sig_len);
	sig_fp = AllocateFile(sigpath, "rb");
	if (sig_fp == NULL)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("PQC WAL verify: could not open signature \"%s\": %m",
						sigpath)));
		pfree(seg_data);
		pfree(sig_data);
		return false;
	}
	if (fread(sig_data, 1, sig_len, sig_fp) != sig_len)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("PQC WAL verify: could not read signature \"%s\": %m",
						sigpath)));
		FreeFile(sig_fp);
		pfree(seg_data);
		pfree(sig_data);
		return false;
	}
	FreeFile(sig_fp);

	/* Get the loaded public key */
	pqc_wal_get_public_key(&pubkey, &pubkey_len);

	/* Verify */
	result = pqc_wal_verify_data(seg_data, seg_len,
								 sig_data, sig_len,
								 pubkey, pubkey_len);

	pfree(seg_data);
	pfree(sig_data);

	if (result != 0)
	{
		ereport(WARNING,
				(errmsg("PQC WAL verify: signature verification FAILED for \"%s\"",
						segpath)));
		return false;
	}

	ereport(DEBUG1,
			(errmsg("PQC WAL verify: signature verified for \"%s\"",
					segpath)));
	return true;
}

#endif							/* USE_PQC */
