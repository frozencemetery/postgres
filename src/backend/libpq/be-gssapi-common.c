/*-------------------------------------------------------------------------
 *
 * be-gssapi-common.c
 *	  Common code for GSSAPI authentication & encryption
 *
 * Portions Copyright (c) 1996-2016, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/libpq/be-gssapi-common.c
 *
 *-------------------------------------------------------------------------
 */

#include "libpq/be-gssapi-common.h"

#include "postgres.h"

#if defined(WIN32) && !defined(WIN32_ONLY_COMPILER)
/*
 * MIT Kerberos GSSAPI DLL doesn't properly export the symbols for MingW
 * that contain the OIDs required. Redefine here, values copied
 * from src/athena/auth/krb5/src/lib/gssapi/generic/gssapi_generic.c
 */
static const gss_OID_desc GSS_C_NT_USER_NAME_desc =
{10, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02"};
static GSS_DLLIMP gss_OID GSS_C_NT_USER_NAME = &GSS_C_NT_USER_NAME_desc;
#endif

void
pg_GSS_error(int severity, char *errmsg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
	gss_buffer_desc gmsg;
	OM_uint32	lmin_s,
				msg_ctx;
	char		msg_major[128],
				msg_minor[128];

	/* Fetch major status message */
	msg_ctx = 0;
	gss_display_status(&lmin_s, maj_stat, GSS_C_GSS_CODE,
					   GSS_C_NO_OID, &msg_ctx, &gmsg);
	strlcpy(msg_major, gmsg.value, sizeof(msg_major));
	gss_release_buffer(&lmin_s, &gmsg);

	if (msg_ctx)

		/*
		 * More than one message available. XXX: Should we loop and read all
		 * messages? (same below)
		 */
		ereport(WARNING,
				(errmsg_internal("incomplete GSS error report")));

	/* Fetch mechanism minor status message */
	msg_ctx = 0;
	gss_display_status(&lmin_s, min_stat, GSS_C_MECH_CODE,
					   GSS_C_NO_OID, &msg_ctx, &gmsg);
	strlcpy(msg_minor, gmsg.value, sizeof(msg_minor));
	gss_release_buffer(&lmin_s, &gmsg);

	if (msg_ctx)
		ereport(WARNING,
				(errmsg_internal("incomplete GSS minor error report")));

	/*
	 * errmsg_internal, since translation of the first part must be done
	 * before calling this function anyway.
	 */
	ereport(severity,
			(errmsg_internal("%s", errmsg),
			 errdetail_internal("%s: %s", msg_major, msg_minor)));
}

