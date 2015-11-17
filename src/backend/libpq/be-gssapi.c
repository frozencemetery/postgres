/*-------------------------------------------------------------------------
 *
 * be-gssapi.c
 *	  GSSAPI authentication and encryption support
 *
 * Portions Copyright (c) 1996-2016, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/libpq/auth.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "libpq/libpq.h"
#include "libpq/libpq-be.h"
#include "libpq/pqformat.h"
#include "miscadmin.h"

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

static void
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

int
pg_GSS_recvauth(Port *port)
{
	OM_uint32	maj_stat,
				min_stat,
				lmin_s,
				gflags;
	int			mtype;
	int			ret;
	StringInfoData buf;
	gss_buffer_desc gbuf;

	/*
	 * GSS auth is not supported for protocol versions before 3, because it
	 * relies on the overall message length word to determine the GSS payload
	 * size in AuthenticationGSSContinue and PasswordMessage messages. (This
	 * is, in fact, a design error in our GSS support, because protocol
	 * messages are supposed to be parsable without relying on the length
	 * word; but it's not worth changing it now.)
	 */
	if (PG_PROTOCOL_MAJOR(FrontendProtocol) < 3)
		ereport(FATAL,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("GSSAPI is not supported in protocol version 2")));

	if (pg_krb_server_keyfile && strlen(pg_krb_server_keyfile) > 0)
	{
		/*
		 * Set default Kerberos keytab file for the Krb5 mechanism.
		 *
		 * setenv("KRB5_KTNAME", pg_krb_server_keyfile, 0); except setenv()
		 * not always available.
		 */
		if (getenv("KRB5_KTNAME") == NULL)
		{
			size_t		kt_len = strlen(pg_krb_server_keyfile) + 14;
			char	   *kt_path = malloc(kt_len);

			if (!kt_path ||
				snprintf(kt_path, kt_len, "KRB5_KTNAME=%s",
						 pg_krb_server_keyfile) != kt_len - 2 ||
				putenv(kt_path) != 0)
			{
				ereport(LOG,
						(errcode(ERRCODE_OUT_OF_MEMORY),
						 errmsg("out of memory")));
				return STATUS_ERROR;
			}
		}
	}

	/*
	 * We accept any service principal that's present in our keytab. This
	 * increases interoperability between kerberos implementations that see
	 * for example case sensitivity differently, while not really opening up
	 * any vector of attack.
	 */
	port->gss->cred = GSS_C_NO_CREDENTIAL;

	/*
	 * Initialize sequence with an empty context
	 */
	port->gss->ctx = GSS_C_NO_CONTEXT;

	/*
	 * Loop through GSSAPI message exchange. This exchange can consist of
	 * multiple messags sent in both directions. First message is always from
	 * the client. All messages from client to server are password packets
	 * (type 'p').
	 */
	do
	{
		pq_startmsgread();

		CHECK_FOR_INTERRUPTS();

		mtype = pq_getbyte();
		if (mtype != 'p')
		{
			/* Only log error if client didn't disconnect. */
			if (mtype != EOF)
				ereport(COMMERROR,
						(errcode(ERRCODE_PROTOCOL_VIOLATION),
						 errmsg("expected GSS response, got message type %d",
								mtype)));
			return STATUS_ERROR;
		}

		/* Get the actual GSS token */
		initStringInfo(&buf);
		if (pq_getmessage(&buf, PG_MAX_AUTH_TOKEN_LENGTH))
		{
			/* EOF - pq_getmessage already logged error */
			pfree(buf.data);
			return STATUS_ERROR;
		}

		/* Map to GSSAPI style buffer */
		gbuf.length = buf.len;
		gbuf.value = buf.data;

		elog(DEBUG4, "Processing received GSS token of length %u",
			 (unsigned int) gbuf.length);

		maj_stat = gss_accept_sec_context(
										  &min_stat,
										  &port->gss->ctx,
										  port->gss->cred,
										  &gbuf,
										  GSS_C_NO_CHANNEL_BINDINGS,
										  &port->gss->name,
										  NULL,
										  &port->gss->outbuf,
										  &gflags,
										  NULL,
										  NULL);

		/* gbuf no longer used */
		pfree(buf.data);

		elog(DEBUG5, "gss_accept_sec_context major: %d, "
			 "minor: %d, outlen: %u, outflags: %x",
			 maj_stat, min_stat,
			 (unsigned int) port->gss->outbuf.length, gflags);

		CHECK_FOR_INTERRUPTS();

		if (port->gss->outbuf.length != 0)
		{
			/*
			 * Negotiation generated data to be sent to the client.
			 */
			elog(DEBUG4, "sending GSS response token of length %u",
				 (unsigned int) port->gss->outbuf.length);

			sendAuthRequest(port, AUTH_REQ_GSS_CONT);

			gss_release_buffer(&lmin_s, &port->gss->outbuf);
		}

		if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
		{
			gss_delete_sec_context(&lmin_s, &port->gss->ctx, GSS_C_NO_BUFFER);
			pg_GSS_error(ERROR,
					   gettext_noop("accepting GSS security context failed"),
						 maj_stat, min_stat);
		}

		if (maj_stat == GSS_S_CONTINUE_NEEDED)
			elog(DEBUG4, "GSS continue needed");

	} while (maj_stat == GSS_S_CONTINUE_NEEDED);

	if (port->gss->cred != GSS_C_NO_CREDENTIAL)
	{
		/*
		 * Release service principal credentials
		 */
		gss_release_cred(&min_stat, &port->gss->cred);
	}

	/*
	 * GSS_S_COMPLETE indicates that authentication is now complete.
	 *
	 * Get the name of the user that authenticated, and compare it to the pg
	 * username that was specified for the connection.
	 */
	maj_stat = gss_display_name(&min_stat, port->gss->name, &gbuf, NULL);
	if (maj_stat != GSS_S_COMPLETE)
		pg_GSS_error(ERROR,
					 gettext_noop("retrieving GSS user name failed"),
					 maj_stat, min_stat);

	/*
	 * Split the username at the realm separator
	 */
	if (strchr(gbuf.value, '@'))
	{
		char	   *cp = strchr(gbuf.value, '@');

		/*
		 * If we are not going to include the realm in the username that is
		 * passed to the ident map, destructively modify it here to remove the
		 * realm. Then advance past the separator to check the realm.
		 */
		if (!port->hba->include_realm)
			*cp = '\0';
		cp++;

		if (port->hba->krb_realm != NULL && strlen(port->hba->krb_realm))
		{
			/*
			 * Match the realm part of the name first
			 */
			if (pg_krb_caseins_users)
				ret = pg_strcasecmp(port->hba->krb_realm, cp);
			else
				ret = strcmp(port->hba->krb_realm, cp);

			if (ret)
			{
				/* GSS realm does not match */
				elog(DEBUG2,
				   "GSSAPI realm (%s) and configured realm (%s) don't match",
					 cp, port->hba->krb_realm);
				gss_release_buffer(&lmin_s, &gbuf);
				return STATUS_ERROR;
			}
		}
	}
	else if (port->hba->krb_realm && strlen(port->hba->krb_realm))
	{
		elog(DEBUG2,
			 "GSSAPI did not return realm but realm matching was requested");

		gss_release_buffer(&lmin_s, &gbuf);
		return STATUS_ERROR;
	}

	ret = check_usermap(port->hba->usermap, port->user_name, gbuf.value,
						pg_krb_caseins_users);

	gss_release_buffer(&lmin_s, &gbuf);

	return ret;
}

static ssize_t
be_gssapi_should_crypto(Port *port)
{
	OM_uint32 major, minor;
	int open = 1;

	if (port->gss->ctx == GSS_C_NO_CONTEXT)
		return 0;
	else if (port->gss->should_encrypt)
		return 1;

	major = gss_inquire_context(&minor, port->gss->ctx,
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
		pg_GSS_error(ERROR,
					 gettext_noop("GSSAPI context state error"),
					 major, minor);
		return -1;
	}
	else if (open != 0)
	{
		/*
		 * Though we can start encrypting here, our client is not ready since
		 * it has not received the final auth packet.  Set encryption on for
		 * the next packet, but send this one in the clear.
		 */
		port->gss->should_encrypt = true;
	}
	return 0;
}

ssize_t
be_gssapi_write(Port *port, void *ptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t ret;
	int conf;
	uint32 netlen;
	char lenbuf[4];
	struct iovec iov[2];

	ret = be_gssapi_should_crypto(port);
	if (ret == -1)
		return -1;
	else if (ret == 0)
		return secure_raw_write(port, ptr, len);

	if (port->gss->writebuf.len != 0)
	{
		ret = send(port->sock,
				   port->gss->writebuf.data + port->gss->writebuf.cursor,
				   port->gss->writebuf.len - port->gss->writebuf.cursor,
				   0);
		if (ret < 0)
			return ret;

		port->gss->writebuf.cursor += ret;
		if (port->gss->writebuf.cursor == port->gss->writebuf.len)
		{
			port->gss->writebuf.len = port->gss->writebuf.cursor = 0;
			port->gss->writebuf.data[0] = '\0';
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
	major = gss_wrap(&minor, port->gss->ctx, 1, GSS_C_QOP_DEFAULT,
					 &input, &conf, &output);
	if (GSS_ERROR(major))
	{
		pg_GSS_error(ERROR,
					 gettext_noop("GSSAPI wrap error"),
					 major, minor);
		ret = -1;
		goto cleanup;
	}
	else if (conf == 0)
	{
		ereport(FATAL, (errmsg("GSSAPI did not provide confidentiality")));
		ret = -1;
		goto cleanup;
	}

	netlen = htonl(output.length);
	memcpy(lenbuf, &netlen, 4);
	iov[0].iov_base = lenbuf;
	iov[0].iov_len = 4;
	iov[1].iov_base = output.value;
	iov[1].iov_len = output.length;
	ret = writev(port->sock, iov, 2);
	if (ret == output.length + 4)
	{
		/*
		 * Strictly speaking, this isn't true; we did write more than `len`
		 * bytes.  However, this information is actually used to keep track of
		 * what has/hasn't been written yet, not actually report the number of
		 * bytes we wrote.
		 */
		ret = len;
		goto cleanup;
	}
	else if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
	{
		ereport(FATAL, (errmsg("Failed to send entire GSSAPI blob")));
		ret = -1;
		goto cleanup;
	}

	if (ret < 4)
	{
		appendBinaryStringInfo(&port->gss->writebuf, lenbuf + ret, 4 - ret);
		ret = 0;
	}
	else
	{
		ret -= 4;
	}
	appendBinaryStringInfo(&port->gss->writebuf, (char *)output.value + ret,
						   output.length - ret);

	/* Set return so that we get retried when the socket becomes writable */
	ret = 0;
 cleanup:
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);

	return ret;
}

static ssize_t
be_gssapi_read_from_buffer(Port *port, void *ptr, size_t len)
{
	ssize_t ret = 0;

	if (port->gss->buf.len > 4 && port->gss->buf.cursor < port->gss->buf.len)
	{
		if (len > port->gss->buf.len - port->gss->buf.cursor)
			len = port->gss->buf.len - port->gss->buf.cursor;

		memcpy(ptr, port->gss->buf.data + port->gss->buf.cursor, len);
		port->gss->buf.cursor += len;

		ret = len;
	}

	if (port->gss->buf.cursor == port->gss->buf.len)
	{
		port->gss->buf.cursor = port->gss->buf.len = 0;
		port->gss->buf.data[0] = '\0';
	}

	return ret;
}

/*
 * Here's how the buffering works:
 *
 * First, we read the packet into port->gss->buf.data.  The first four bytes
 * of this will be the network-order length of the GSSAPI-encrypted blob; from
 * position 4 to port->gss->buf.len is then this blob.  Therefore, at this
 * point port->gss->buf.len is the length of the blob plus 4.
 * port->gss->buf.cursor is zero for this entire step.
 *
 * Then we overwrite port->gss->buf.data entirely with the decrypted contents.
 * At this point, port->gss->buf.len reflects the actual length of the
 * decrypted data.  port->gss->buf.cursor is then used to incrementally return
 * this data to the caller and is therefore nonzero during this step.
 *
 * Once all decrypted data is returned to the caller, the cycle repeats.
 */
ssize_t
be_gssapi_read(Port *port, void *ptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t ret;
	int conf = 0;

	ret = be_gssapi_should_crypto(port);
	if (ret == -1)
		return -1;
	else if (ret == 0)
		return secure_raw_read(port, ptr, len);

	if (len == 0)
		return 0;

	if (port->gss->buf.cursor > 0)
	{
		ret = be_gssapi_read_from_buffer(port, ptr, len);
		if (ret > 0)
			return ret + be_gssapi_read(port, (char *)ptr + ret, len - ret);
	}

	/* our buffer is now empty */
	if (port->gss->buf.len < 4)
	{
		enlargeStringInfo(&port->gss->buf, 4);
		ret = secure_raw_read(port, port->gss->buf.data + port->gss->buf.len,
							  4 - port->gss->buf.len);
		if (ret < 0)
			return ret;

		port->gss->buf.len += ret;
		port->gss->buf.data[port->gss->buf.len] = '\0';
		if (port->gss->buf.len < 4)
			return 0;
	}

	/* we know the length of the packet at this point */
	memcpy((char *)&input.length, port->gss->buf.data, 4);
	input.length = ntohl(input.length);
	enlargeStringInfo(&port->gss->buf, input.length - port->gss->buf.len + 4);

	ret = secure_raw_read(port, port->gss->buf.data + port->gss->buf.len,
						  input.length - port->gss->buf.len + 4);
	if (ret < 0)
		return ret;

	port->gss->buf.len += ret;
	port->gss->buf.data[port->gss->buf.len] = '\0';
	if (port->gss->buf.len - 4 < input.length)
		return 0;

	output.value = NULL;
	output.length = 0;
	input.value = port->gss->buf.data + 4;
	major = gss_unwrap(&minor, port->gss->ctx, &input, &output, &conf, NULL);
	if (GSS_ERROR(major))
	{
		pg_GSS_error(ERROR,
					 gettext_noop("GSSAPI unwrap error"),
					 major, minor);
		ret = -1;
		goto cleanup;
	}
	else if (conf == 0)
	{
		ereport(FATAL, (errmsg("GSSAPI did not provide confidentiality")));
		ret = -1;
		goto cleanup;
	}

	port->gss->buf.cursor = port->gss->buf.len = 0;
	port->gss->buf.data[0] = '\0';
	enlargeStringInfo(&port->gss->buf, output.length);
	memcpy(port->gss->buf.data, output.value, output.length);
	port->gss->buf.len = output.length;
	port->gss->buf.data[port->gss->buf.len] = '\0';

	ret = be_gssapi_read_from_buffer(port, ptr, len);
 cleanup:
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);

	return ret;
}
