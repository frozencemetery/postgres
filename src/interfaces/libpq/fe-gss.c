/*-------------------------------------------------------------------------
 *
 * fe-gss.c
 *	  functions for GSSAPI support in the frontend.
 *
 * Portions Copyright (c) 2015, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/libpq/fe-gss.c
 *
 *-------------------------------------------------------------------------
 */

#include "libpq-fe.h"
#include "postgres_fe.h"
#include "fe-auth.h"
#include "libpq-int.h"

#include <assert.h>

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
 * Continue GSS authentication with next token as needed.
 */
int
pg_GSS_continue(PGconn *conn)
{
	OM_uint32	maj_stat,
				min_stat,
				lmin_s;

	maj_stat = gss_init_sec_context(&min_stat,
									GSS_C_NO_CREDENTIAL,
									&conn->gctx,
									conn->gtarg_nam,
									GSS_C_NO_OID,
									GSS_C_MUTUAL_FLAG,
									0,
									GSS_C_NO_CHANNEL_BINDINGS,
		  (conn->gctx == GSS_C_NO_CONTEXT) ? GSS_C_NO_BUFFER : &conn->ginbuf,
									NULL,
									&conn->goutbuf,
									NULL,
									NULL);

	if (conn->gctx != GSS_C_NO_CONTEXT)
	{
		free(conn->ginbuf.value);
		conn->ginbuf.value = NULL;
		conn->ginbuf.length = 0;
	}

	if (conn->goutbuf.length != 0)
	{
		/*
		 * GSS generated data to send to the server. We don't care if it's the
		 * first or subsequent packet, just send the same kind of password
		 * packet.
		 */
		if (pqPacketSend(conn, 'p',
						 conn->goutbuf.value, conn->goutbuf.length)
			!= STATUS_OK)
		{
			gss_release_buffer(&lmin_s, &conn->goutbuf);
			return STATUS_ERROR;
		}
	}
	gss_release_buffer(&lmin_s, &conn->goutbuf);

	if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
	{
		pg_GSS_error(libpq_gettext("GSSAPI continuation error"),
					 conn,
					 maj_stat, min_stat);
		gss_release_name(&lmin_s, &conn->gtarg_nam);
		if (conn->gctx)
			gss_delete_sec_context(&lmin_s, &conn->gctx, GSS_C_NO_BUFFER);
		return STATUS_ERROR;
	}

	if (maj_stat == GSS_S_COMPLETE)
		gss_release_name(&lmin_s, &conn->gtarg_nam);

	return STATUS_OK;
}

/*
 * Send initial GSS authentication token
 */
int
pg_GSS_startup(PGconn *conn)
{
	OM_uint32	maj_stat,
				min_stat;
	int			maxlen;
	gss_buffer_desc temp_gbuf;

	if (!(conn->pghost && conn->pghost[0] != '\0'))
	{
		printfPQExpBuffer(&conn->errorMessage,
						  libpq_gettext("host name must be specified\n"));
		return STATUS_ERROR;
	}

	if (conn->gctx)
	{
		printfPQExpBuffer(&conn->errorMessage,
					libpq_gettext("duplicate GSS authentication request\n"));
		return STATUS_ERROR;
	}

	/*
	 * Import service principal name so the proper ticket can be acquired by
	 * the GSSAPI system.
	 */
	maxlen = NI_MAXHOST + strlen(conn->krbsrvname) + 2;
	temp_gbuf.value = (char *) malloc(maxlen);
	if (!temp_gbuf.value)
	{
		printfPQExpBuffer(&conn->errorMessage,
						  libpq_gettext("out of memory\n"));
		return STATUS_ERROR;
	}
	snprintf(temp_gbuf.value, maxlen, "%s@%s",
			 conn->krbsrvname, conn->pghost);
	temp_gbuf.length = strlen(temp_gbuf.value);

	maj_stat = gss_import_name(&min_stat, &temp_gbuf,
							   GSS_C_NT_HOSTBASED_SERVICE, &conn->gtarg_nam);
	free(temp_gbuf.value);

	if (maj_stat != GSS_S_COMPLETE)
	{
		pg_GSS_error(libpq_gettext("GSSAPI name import error"),
					 conn,
					 maj_stat, min_stat);
		return STATUS_ERROR;
	}

	/*
	 * Initial packet is the same as a continuation packet with no initial
	 * context.
	 */
	conn->gctx = GSS_C_NO_CONTEXT;

	return pg_GSS_continue(conn);
}

ssize_t
pggss_inplace_decrypt(PGconn *conn, int gsslen)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t n;
	int conf;

	input.length = gsslen;
	input.value = conn->inBuffer + conn->inCursor;
	output.length = 0;
	output.value = NULL;

	major = gss_unwrap(&minor, conn->gctx, &input, &output, &conf, NULL);
	if (GSS_ERROR(major))
	{
		pg_GSS_error("GSSAPI unwrap error", conn, major, minor);
		return -1;
	}
	else if (conf == 0)
	{
		printfPQExpBuffer(&conn->errorMessage,
						  libpq_gettext(
							  "received GSSAPI message without confidentiality\n"));
		return -1;
	}

	memcpy(conn->inBuffer + conn->inStart, output.value, output.length);
	n = output.length;
	gss_release_buffer(&minor, &output);
	return n;
}

int
pggss_encrypt(PGconn *conn)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	int msgLen, conf;
	uint32 len_n;

	if (conn->gss_disable_enc || !conn->gctx || !conn->gss_auth_done)
		return 0;
	assert(conn->outMsgStart > 0);

	/* We need to encrypt message type as well */
	conn->outMsgStart -= 1;
	msgLen = conn->outMsgEnd - conn->outMsgStart;

	input.value = conn->outBuffer + conn->outMsgStart;
	input.length = msgLen;
	output.length = 0;
	output.value = NULL;

	major = gss_wrap(&minor, conn->gctx, 1, GSS_C_QOP_DEFAULT, &input, &conf,
					 &output);
	if (GSS_ERROR(major))
	{
		pg_GSS_error("GSSAPI wrap error", conn, major, minor);
		return -1;
	}
	else if (conf == 0)
	{
		printfPQExpBuffer(&conn->errorMessage,
						  libpq_gettext(
							  "Failed to obtain confidentiality for outgoing GSSAPI message\n"));
		return -1;
	}

	msgLen = output.length + 4;
	if (pqCheckOutBufferSpace(conn->outMsgStart + msgLen + 1, conn))
		return -1;
	
	conn->outBuffer[conn->outMsgStart] = 'g'; /* GSSAPI message */

	len_n = htonl(msgLen);
	memcpy(conn->outBuffer + conn->outMsgStart + 1, &len_n, 4);

	memcpy(conn->outBuffer + conn->outMsgStart + 1 + 4,
		   output.value, output.length);
	conn->outMsgEnd = conn->outMsgStart + msgLen + 1;

	gss_release_buffer(&minor, &output);
	return msgLen + 1;
}
