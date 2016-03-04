/*-------------------------------------------------------------------------
 *
 * fe-gssapi-common.c
 *	   The front-end (client) GSSAPI common code
 *
 * Portions Copyright (c) 1996-2016, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/interfaces/libpq/fe-gssapi-common.c
 *
 *-------------------------------------------------------------------------
 */

#include "fe-auth.h"
#include "fe-gssapi-common.h"

#if defined(WIN32) && !defined(WIN32_ONLY_COMPILER)
/*
 * MIT Kerberos GSSAPI DLL doesn't properly export the symbols for MingW
 * that contain the OIDs required. Redefine here, values copied
 * from src/athena/auth/krb5/src/lib/gssapi/generic/gssapi_generic.c
 */
static const gss_OID_desc GSS_C_NT_HOSTBASED_SERVICE_desc =
{10, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"};
static GSS_DLLIMP gss_OID GSS_C_NT_HOSTBASED_SERVICE = &GSS_C_NT_HOSTBASED_SERVICE_desc;
#endif

/*
 * Fetch all errors of a specific type and append to "str".
 */
static void
pg_GSS_error_int(PQExpBuffer str, const char *mprefix,
				 OM_uint32 stat, int type)
{
	OM_uint32	lmin_s;
	gss_buffer_desc lmsg;
	OM_uint32	msg_ctx = 0;

	do
	{
		gss_display_status(&lmin_s, stat, type,
						   GSS_C_NO_OID, &msg_ctx, &lmsg);
		appendPQExpBuffer(str, "%s: %s\n", mprefix, (char *) lmsg.value);
		gss_release_buffer(&lmin_s, &lmsg);
	} while (msg_ctx);
}

/*
 * GSSAPI errors contain two parts; put both into conn->errorMessage.
 */
void
pg_GSS_error(const char *mprefix, PGconn *conn,
			 OM_uint32 maj_stat, OM_uint32 min_stat)
{
	resetPQExpBuffer(&conn->errorMessage);

	/* Fetch major error codes */
	pg_GSS_error_int(&conn->errorMessage, mprefix, maj_stat, GSS_C_GSS_CODE);

	/* Add the minor codes as well */
	pg_GSS_error_int(&conn->errorMessage, mprefix, min_stat, GSS_C_MECH_CODE);
}

/*
 * Only consider encryption when GSS context is complete
 */
ssize_t
pg_GSS_should_crypto(PGconn *conn)
{
	OM_uint32 major, minor;
	int open = 1;

	if (conn->gctx == GSS_C_NO_CONTEXT)
		return 0;
	else if (conn->gencrypt)
		return 1;

	major = gss_inquire_context(&minor, conn->gctx,
								NULL, NULL, NULL, NULL, NULL, NULL,
								&open);
	if (major == GSS_S_NO_CONTEXT)
	{
		/*
         * In MIT krb5 < 1.14, it was not possible to call gss_inquire_context
         * on an incomplete context.  This was a violation of rfc2744 and has
         * been corrected in https://github.com/krb5/krb5/pull/285
         */
		return 0;
	}
	else if (GSS_ERROR(major))
	{
		pg_GSS_error(libpq_gettext("GSSAPI context state error"), conn,
					 major, minor);
		return -1;
	}
	else if (open != 0)
	{
		conn->gencrypt = true;
		return 1;
	}
	return 0;
}
