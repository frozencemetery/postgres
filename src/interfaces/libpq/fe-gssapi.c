/*-------------------------------------------------------------------------
 *
 * fe-auth.c
 *	   The front-end (client) support for GSSAPI
 *
 * Portions Copyright (c) 1996-2016, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/interfaces/libpq/fe-gssapi.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres_fe.h"

#include "libpq-fe.h"
#include "libpq-int.h"
#include "fe-auth.h"

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
static void
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

/*
 * Only consider encryption when GSS context is complete
 */
static ssize_t
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

ssize_t
pg_GSS_write(PGconn *conn, void *ptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t ret;
	int conf;
	uint32 netlen;
	char lenbuf[4];
	struct iovec iov[2];

	ret = pg_GSS_should_crypto(conn);
	if (ret == -1)
		return -1;
	else if (ret == 0)
		return pqsecure_raw_write(conn, ptr, len);

	if (conn->gwritebuf.len != 0)
	{
		ret = send(conn->sock, conn->gwritebuf.data + conn->gwritecurs,
				   conn->gwritebuf.len - conn->gwritecurs, 0);
		if (ret < 0)
			return ret;
		conn->gwritecurs += ret;
		if (conn->gwritecurs == conn->gwritebuf.len)
		{
			conn->gwritebuf.len = conn->gwritecurs = 0;
			conn->gwritebuf.data[0] = '\0';
			/* The entire request has now been written */
			return len;
		}
		/* need to be called again */
		return 0;
	}

	output.value = NULL;
	output.length = 0;

	input.value = ptr;
	input.length = len;

	conf = 0;
	major = gss_wrap(&minor, conn->gctx, 1, GSS_C_QOP_DEFAULT,
					 &input, &conf, &output);
	if (GSS_ERROR(major))
	{
		pg_GSS_error(libpq_gettext("GSSAPI wrap error"), conn,
					 major, minor);
		ret = -1;
		goto cleanup;
	}
	else if (conf == 0)
	{
		printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
							  "GSSAPI did not provide confidentiality\n"));
		ret = -1;
		goto cleanup;
	}

	netlen = htonl(output.length);
	memcpy(lenbuf, &netlen, 4);
	iov[0].iov_base = lenbuf;
	iov[0].iov_len = 4;
	iov[1].iov_base = output.value;
	iov[1].iov_len = output.length;
	errno = 0;
	ret = writev(conn->sock, iov, 2);
	if (ret == output.length + 4)
	{
		/*
		 * pqsecure_write expects the return value, when >= 0, to be the
		 * number bytes from ptr delivered, not the number of bytes actually
		 * written to socket.
		 */
		ret = len;
		goto cleanup;
	}
	else if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
	{
		printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
							  "GSSAPI writev() failed to send everything\n"));
		ret = -1;
		goto cleanup;
	}

	if (ret < 4)
	{
		appendBinaryPQExpBuffer(&conn->gwritebuf, lenbuf + ret, 4 - ret);
		ret = 0;
	}
	else
	{
		ret -= 4;
	}
	appendBinaryPQExpBuffer(&conn->gwritebuf, (char *)output.value + 4 - ret,
							output.length + 4 - ret);

	/* Set return so that we get retried when the socket becomes writable */
	ret = 0;
 cleanup:
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);

	return ret;
}

static ssize_t
pg_GSS_read_from_buffer(PGconn *conn, void *ptr, size_t len)
{
	ssize_t ret = 0;

	if (conn->gcursor < conn->gbuf.len)
	{
		if (len > conn->gbuf.len - conn->gcursor)
			len = conn->gbuf.len - conn->gcursor;

		memcpy(ptr, conn->gbuf.data + conn->gcursor, len);
		conn->gcursor += len;
		ret = len;
	}

	if (conn->gcursor == conn->gbuf.len)
	{
		conn->gcursor = conn->gbuf.len = 0;
		conn->gbuf.data[0] = '\0';
	}

	return ret;
}

/*
 * Buffering behaves as in be_gssapi_read (in be-gssapi.c).  Because this is
 * the frontend, we use a PQExpBuffer at conn->gbuf instead of a StringInfo,
 * and so there is an additional, separate cursor field in the structure.
 */
ssize_t
pg_GSS_read(PGconn *conn, void *ptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t ret;
	int conf = 0;

	ret = pg_GSS_should_crypto(conn);
	if (ret == -1)
		return -1;
	else if (ret == 0)
		return pqsecure_raw_read(conn, ptr, len);

	if (len == 0)
		return 0;

	if (conn->gcursor > 0)
	{
		ret = pg_GSS_read_from_buffer(conn, ptr, len);
		if (ret > 0)
			return ret + pg_GSS_read(conn, (char *)ptr + ret, len - ret);
	}

	/* our buffer is now empty */
	if (conn->gbuf.len < 4)
	{
		ret = enlargePQExpBuffer(&conn->gbuf, 4);
		if (ret != 1)
		{
			printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
								  "Failed to fit packet length in buffer\n"));
			return -1;
		}
		ret = pqsecure_raw_read(conn, conn->gbuf.data, 4);
		if (ret < 0)
			/* error already set by secure_raw_read */
			return ret;
		conn->gbuf.len += ret;
		conn->gbuf.data[conn->gbuf.len] = '\0';
		if (conn->gbuf.len < 4)
			return 0;
	}

	/* we know the length of the packet at this point */
	memcpy((char *)&input.length, conn->gbuf.data, 4);
	input.length = ntohl(input.length);
	ret = enlargePQExpBuffer(&conn->gbuf, input.length - conn->gbuf.len + 4);
	if (ret != 1)
	{
		printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
							  "GSSAPI encrypted packet (length %ld) too big\n"),
						  input.length);
		return -1;
	}

	ret = pqsecure_raw_read(conn, conn->gbuf.data + conn->gbuf.len,
							input.length - conn->gbuf.len + 4);
	if (ret < 0)
		return ret;
	conn->gbuf.len += ret;
	conn->gbuf.data[conn->gbuf.len] = '\0';
	if (conn->gbuf.len - 4 < input.length)
		return 0;

	output.value = NULL;
	output.length = 0;
	input.value = conn->gbuf.data + 4;
	major = gss_unwrap(&minor, conn->gctx, &input, &output, &conf, NULL);
	if (GSS_ERROR(major))
	{
		pg_GSS_error(libpq_gettext("GSSAPI unwrap error"), conn,
					 major, minor);
		ret = -1;
		goto cleanup;
	}
	else if (conf == 0)
	{
		printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
							  "GSSAPI did not provide confidentiality\n"));
		ret = -1;
		goto cleanup;
	}

	conn->gcursor = conn->gbuf.len = 0;
	conn->gbuf.data[0] = '\0';
	ret = enlargePQExpBuffer(&conn->gbuf, output.length);
	if (ret != 1)
	{
		printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
							  "GSSAPI decrypted packet (length %ld) too big\n"),
						  output.length);
		return -1;
	}
	memcpy(conn->gbuf.data, output.value, output.length);
	conn->gbuf.len = output.length;
	conn->gbuf.data[conn->gbuf.len] = '\0';

	ret = pg_GSS_read_from_buffer(conn, ptr, len);

 cleanup:
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);
	return ret;
}
