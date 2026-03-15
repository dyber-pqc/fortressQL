/*-------------------------------------------------------------------------
 *
 * pqc_wal_keys.h
 *	  FortressQL Post-Quantum WAL Signing Key Management.
 *
 * Provides functions for generating, loading, and using post-quantum
 * digital signature keys for WAL segment signing and verification.
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/include/crypto/pqc/pqc_wal_keys.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PQC_WAL_KEYS_H
#define PQC_WAL_KEYS_H

#ifdef USE_PQC

#include "crypto/pqc/pqc_sig.h"

/* GUC variables for WAL PQC signing */
extern bool wal_pqc_signing;
extern int wal_pqc_signing_algorithm;
extern char *wal_pqc_signing_algorithm_string;
extern char *wal_pqc_key_path;
extern bool wal_pqc_verify_on_receive;

/*
 * Load an existing PQC signing key pair from disk.
 *
 * Reads key_path/wal_signing.key (secret key) and
 * key_path/wal_signing.pub (public key) into static variables.
 * The algorithm string selects the PQC signature scheme
 * (e.g., "ML-DSA-65").
 *
 * Raises ERROR if files cannot be read or are malformed.
 */
extern void pqc_wal_load_signing_keys(const char *key_path,
									  const char *algorithm);

/*
 * Generate a new PQC signing key pair and write to disk.
 *
 * Creates key_path/wal_signing.key and key_path/wal_signing.pub
 * using the specified algorithm.  Also loads the keys into memory
 * so they are ready for immediate use.
 *
 * Raises ERROR on generation or I/O failure.
 */
extern void pqc_wal_generate_signing_keys(const char *key_path,
										  const char *algorithm);

/*
 * Sign data using the loaded WAL signing secret key.
 *
 * Writes the signature into sig_out (caller-provided buffer) and
 * sets *sig_len to the actual signature length.
 *
 * Returns 0 on success, -1 on failure.
 */
extern int	pqc_wal_sign_data(const uint8 *data, size_t data_len,
							  uint8 *sig_out, size_t sig_out_buflen,
							  size_t *sig_len);

/*
 * Verify data against a signature using an externally provided
 * public key.
 *
 * Returns 0 on success (valid signature), -1 on failure.
 */
extern int	pqc_wal_verify_data(const uint8 *data, size_t data_len,
								const uint8 *sig, size_t sig_len,
								const uint8 *pubkey, size_t pubkey_len);

/*
 * Retrieve the currently loaded public key.
 *
 * Sets *pubkey to point to internal storage (do NOT pfree) and
 * *pubkey_len to its length.  Raises ERROR if no key is loaded.
 */
extern void pqc_wal_get_public_key(uint8 **pubkey, size_t *pubkey_len);

/*
 * Verify a WAL segment's PQC signature.
 *
 * Reads the segment at segpath and its corresponding .sig file,
 * then verifies the signature against the loaded public key.
 *
 * Returns true if the signature is valid, false otherwise.
 */
extern bool pqc_wal_verify_segment(const char *segpath);

#endif							/* USE_PQC */
#endif							/* PQC_WAL_KEYS_H */
