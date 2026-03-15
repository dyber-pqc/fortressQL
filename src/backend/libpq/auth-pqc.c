/*-------------------------------------------------------------------------
 *
 * auth-pqc.c
 *	  FortressQL: PQC certificate authentication implementation.
 *
 *	  Verifies that a client certificate uses a post-quantum signature
 *	  algorithm (ML-DSA or SLH-DSA) before delegating to the standard
 *	  certificate CN/DN-to-user mapping logic.
 *
 * Copyright (c) 2024, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/libpq/auth-pqc.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#ifdef USE_PQC

#include "libpq/auth.h"
#include "libpq/hba.h"
#include "libpq/libpq.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"

#ifdef USE_OPENSSL
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#endif

/*
 * List of recognized PQC signature algorithm names.
 * OpenSSL 3.5+ with native PQC or oqs-provider registers these.
 */
static const char *pqc_sig_algorithm_names[] = {
	"ML-DSA-44",
	"ML-DSA-65",
	"ML-DSA-87",
	"SLH-DSA-SHA2-128s",
	"SLH-DSA-SHA2-128f",
	"SLH-DSA-SHA2-192s",
	"SLH-DSA-SHA2-192f",
	"SLH-DSA-SHA2-256s",
	"SLH-DSA-SHA2-256f",
	"SLH-DSA-SHAKE-128s",
	"SLH-DSA-SHAKE-128f",
	"SLH-DSA-SHAKE-192s",
	"SLH-DSA-SHAKE-192f",
	"SLH-DSA-SHAKE-256s",
	"SLH-DSA-SHAKE-256f",
	/* Also accept OQS/FIPS naming variants */
	"mldsa44",
	"mldsa65",
	"mldsa87",
	"dilithium2",
	"dilithium3",
	"dilithium5",
	NULL
};

/*
 * Check if the given algorithm name is a recognized PQC signature algorithm.
 */
static bool
is_pqc_signature_algorithm(const char *alg_name)
{
	int			i;

	for (i = 0; pqc_sig_algorithm_names[i] != NULL; i++)
	{
		if (pg_strcasecmp(alg_name, pqc_sig_algorithm_names[i]) == 0)
			return true;
	}
	return false;
}

/*
 * CheckPQCCertAuth
 *
 * Authenticate using a client certificate that must use a PQC signature
 * algorithm.  This extends the standard cert authentication by verifying
 * the certificate's signature algorithm is post-quantum (ML-DSA or SLH-DSA).
 *
 * After PQC verification, the CN/DN mapping works identically to uaCert.
 */
int
CheckPQCCertAuth(Port *port)
{
#ifdef USE_OPENSSL
	int			status_check_usermap = STATUS_ERROR;
	char	   *peer_username = NULL;
	X509	   *peer_cert;
	const char *sig_alg_name = NULL;
	int			sig_nid;

	Assert(port->ssl);

	/* Ensure we have a valid client certificate */
	if (!port->peer_cert_valid)
	{
		ereport(LOG,
				(errmsg("PQC certificate authentication failed for user \"%s\": "
						"no valid client certificate",
						port->user_name)));
		return STATUS_ERROR;
	}

	/*
	 * Get the client certificate and check its signature algorithm.
	 */
	peer_cert = port->peer;
	if (peer_cert == NULL)
	{
		ereport(LOG,
				(errmsg("PQC certificate authentication failed for user \"%s\": "
						"unable to retrieve client certificate",
						port->user_name)));
		return STATUS_ERROR;
	}

	/*
	 * Extract the signature algorithm name from the certificate.
	 * X509_get_signature_nid() returns the NID of the signature algorithm.
	 * For PQC algorithms registered via oqs-provider or OpenSSL 3.5+,
	 * we can get the short name via OBJ_nid2sn().
	 */
	sig_nid = X509_get_signature_nid(peer_cert);
	if (sig_nid != NID_undef)
		sig_alg_name = OBJ_nid2sn(sig_nid);

	/*
	 * If the NID lookup didn't give us a name, try getting the algorithm
	 * name from the signature algorithm OID directly.  This handles
	 * algorithms registered by oqs-provider that may not have NIDs.
	 */
	if (sig_alg_name == NULL || strcmp(sig_alg_name, "UNDEF") == 0)
	{
		const X509_ALGOR *sig_alg_obj;
		const ASN1_OBJECT *sig_obj;

		X509_get0_signature(NULL, &sig_alg_obj, peer_cert);
		if (sig_alg_obj != NULL)
		{
			X509_ALGOR_get0(&sig_obj, NULL, NULL, sig_alg_obj);
			if (sig_obj != NULL)
			{
				int			nid = OBJ_obj2nid(sig_obj);

				if (nid != NID_undef)
					sig_alg_name = OBJ_nid2sn(nid);
				else
				{
					/*
					 * Last resort: get the human-readable name from the OID.
					 */
					char		oid_buf[256];
					int			oid_len;

					oid_len = OBJ_obj2txt(oid_buf, sizeof(oid_buf), sig_obj, 0);
					if (oid_len > 0)
						sig_alg_name = pstrdup(oid_buf);
				}
			}
		}
	}

	if (sig_alg_name == NULL)
	{
		ereport(LOG,
				(errmsg("PQC certificate authentication failed for user \"%s\": "
						"unable to determine certificate signature algorithm",
						port->user_name)));
		return STATUS_ERROR;
	}

	/*
	 * Verify the signature algorithm is a recognized PQC algorithm.
	 */
	if (!is_pqc_signature_algorithm(sig_alg_name))
	{
		ereport(LOG,
				(errmsg("PQC certificate authentication failed for user \"%s\": "
						"certificate uses non-PQC signature algorithm \"%s\"",
						port->user_name, sig_alg_name),
				 errhint("Client certificate must use ML-DSA or SLH-DSA signature algorithm. "
						 "Generate a certificate signed by a PQC CA.")));
		return STATUS_ERROR;
	}

	ereport(LOG,
			(errmsg("PQC certificate authentication: user \"%s\" presented certificate "
					"with PQC signature algorithm \"%s\"",
					port->user_name, sig_alg_name)));

	/*
	 * PQC signature verified.  Now do the standard cert-to-user mapping,
	 * same as CheckCertAuth().
	 */

	/* Select the correct field to compare */
	switch (port->hba->clientcertname)
	{
		case clientCertDN:
			peer_username = port->peer_dn;
			break;
		case clientCertCN:
			peer_username = port->peer_cn;
	}

	/* Make sure we have received a username in the certificate */
	if (peer_username == NULL || strlen(peer_username) <= 0)
	{
		ereport(LOG,
				(errmsg("PQC certificate authentication failed for user \"%s\": "
						"client certificate contains no user name",
						port->user_name)));
		return STATUS_ERROR;
	}

	/* Set the authenticated identity */
	if (!port->peer_dn)
	{
		ereport(LOG,
				(errmsg("PQC certificate authentication failed for user \"%s\": "
						"unable to retrieve subject DN",
						port->user_name)));
		return STATUS_ERROR;
	}
	set_authn_id(port, port->peer_dn);

	/* Map the certificate CN/DN to a database user */
	status_check_usermap = check_usermap(port->hba->usermap, port->user_name,
										 peer_username, false);
	return status_check_usermap;

#else							/* !USE_OPENSSL */
	ereport(LOG,
			(errmsg("PQC certificate authentication requires OpenSSL")));
	return STATUS_ERROR;
#endif							/* USE_OPENSSL */
}

#endif							/* USE_PQC */
