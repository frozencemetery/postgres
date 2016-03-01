/*-------------------------------------------------------------------------
 *
 * fe-secure-gssapi.c
 *   The front-end (client) encryption support for GSSAPI
 *
 * Portions Copyright (c) 2016, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *  src/interfaces/libpq/fe-secure-gssapi.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres_fe.h"

#include "libpq-fe.h"
#include "libpq-int.h"
#include "fe-gssapi-common.h"

/*
 * Send a message along the connection, possibly using GSSAPI.
 *
 * If not encrypting at the call-time, we send plaintext following calling
 * conventions of pqsecure_raw_write.  Partial writes are supported using a
 * dedicated PQExpBuffer in conn.  A partial write will return -1 and set
 * errno=EWOULDBLOCK; otherwise, we return -1 (for error) or the number of
 * total bytes written in the write of the current ptr.  Calling with a new
 * value of ptr after a partial write is undefined.
 */
ssize_t
pg_GSS_write(PGconn *conn, void *ptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t ret;
	int conf;
	uint32 netlen;

	if (pg_GSS_should_encrypt(conn) == false)
		return pqsecure_raw_write(conn, ptr, len);

	/* send any data we have buffered */
	if (conn->gwritebuf.len != 0)
	{
		ret = pqsecure_raw_write(conn,
								 conn->gwritebuf.data + conn->gwritecurs,
								 conn->gwritebuf.len - conn->gwritecurs);
		if (ret < 0)
			return ret;

		conn->gwritecurs += ret;

		/* update and possibly clear buffer state */
		if (conn->gwritecurs == conn->gwritebuf.len)
		{
			resetPQExpBuffer(&conn->gwritebuf);
			conn->gwritecurs = 0;

			/* The entire request has now been written */
			return len;
		}

		/* need to be called again */
		errno = EWOULDBLOCK;
		return -1;
	}

	/* encrypt the message */
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

	/* format for on-wire: 4 network-order bytes of length, then payload */
	netlen = htonl(output.length);
	appendBinaryPQExpBuffer(&conn->gwritebuf, (char *)&netlen, 4);
	appendBinaryPQExpBuffer(&conn->gwritebuf, output.value, output.length);

	/* recur to send some buffered data */
	gss_release_buffer(&minor, &output);
	return pg_GSS_write(conn, ptr, len);
 cleanup:
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);

	return ret;
}

/*
 * Wrapper function for buffering decrypted data.
 *
 * This allows us to present a stream-like interface to pqsecure_read.  For a
 * description of buffering, see comment at be_gssapi_read (in be-gssapi.c).
 */
static ssize_t
pg_GSS_read_from_buffer(PGconn *conn, void *ptr, size_t len)
{
	ssize_t ret = 0;

	/* Is any data available? */
	if (conn->gcursor < conn->gbuf.len)
	{
		/* clamp length */
		if (len > conn->gbuf.len - conn->gcursor)
			len = conn->gbuf.len - conn->gcursor;

		memcpy(ptr, conn->gbuf.data + conn->gcursor, len);
		conn->gcursor += len;

		ret = len;
	}

	/* if all data has been read, reset buffer */
	if (conn->gcursor == conn->gbuf.len)
	{
		conn->gcursor = 0;
		resetPQExpBuffer(&conn->gbuf);
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

	if (pg_GSS_should_encrypt(conn) == false)
		return pqsecure_raw_read(conn, ptr, len);

	/* ensure proper behavior under recursion */
	if (len == 0)
		return 0;

	/* report any buffered data, then recur */
	if (conn->gcursor > 0)
	{
		ret = pg_GSS_read_from_buffer(conn, ptr, len);

		/* Pass up error message fragments.  See comment below. */
		if (!conn->gss_decrypted && conn->gcursor == conn->gbuf.len)
		{
			/* call _raw_read to get any remaining parts of the message */
			gss_delete_sec_context(&minor, &conn->gctx, GSS_C_NO_BUFFER);
			conn->gctx = 0;
		}

		if (ret > 0)
		{
			ssize_t r_ret = pg_GSS_read(conn, (char *)ptr + ret, len - ret);
			if (r_ret < 0 && errno != EWOULDBLOCK
#ifdef EAGAIN
				&& errno != EAGAIN
#endif
				)
				/* connection is dead in some way */
				return r_ret;
			else if (r_ret < 0)
				/* no more data right now */
				return ret;
			return ret + r_ret;
		}
	}

	/* our buffer is now empty */
	if (conn->gbuf.len < 4)
	{
		ret = enlargePQExpBuffer(&conn->gbuf, 4 - conn->gbuf.len);
		if (ret != 1)
		{
			printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
								  "Failed to fit packet length in buffer\n"));
			return -1;
		}

		ret = pqsecure_raw_read(conn, conn->gbuf.data + conn->gbuf.len,
								4 - conn->gbuf.len);
		if (ret < 0)
			/* error already set by secure_raw_read */
			return ret;

		/* write length to buffer */
		conn->gbuf.len += ret;
		conn->gbuf.data[conn->gbuf.len] = '\0';
		if (conn->gbuf.len < 4)
		{
			errno = EWOULDBLOCK;
			return -1;
		}
	}

	/*
	 * We can receive error messages from old servers that don't support
	 * GSSAPI encryption at this time.  They need to be passed up so that we
	 * can potentially reconnect.
	 *
	 * This limits the server's first reply to not be between 1157627904
	 * (about 2**30) and 1174405119, which are both over a gigabyte in size.
	 * If the server sends a connection parameter status message of this size,
	 * there are other problems present.
	 */
	if (!conn->gss_decrypted && conn->gbuf.data[0] == 'E')
	{
		ret = pg_GSS_read_from_buffer(conn, ptr, len);
		if (conn->gcursor == conn->gbuf.len)
		{
			/* Call _raw_read to get any remaining parts of the message */
			gss_delete_sec_context(&minor, &conn->gctx, GSS_C_NO_BUFFER);
			conn->gctx = 0;
		}
		return ret;
	}

	/* we know the length of the packet at this point */
	input.length = ntohl(*(uint32 *)conn->gbuf.data);
	ret = enlargePQExpBuffer(&conn->gbuf, input.length - conn->gbuf.len + 4);
	if (ret != 1)
	{
		printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
							  "GSSAPI encrypted packet (length %ld) too big\n"),
						  input.length);
		return -1;
	}

	/* load any remaining parts of the packet into our buffer */
	if (conn->gbuf.len - 4 < input.length)
	{
		ret = pqsecure_raw_read(conn, conn->gbuf.data + conn->gbuf.len,
								input.length - conn->gbuf.len + 4);
		if (ret < 0)
			return ret;

		/* update buffer state */
		conn->gbuf.len += ret;
		conn->gbuf.data[conn->gbuf.len] = '\0';
		if (conn->gbuf.len - 4 < input.length)
		{
			errno = EWOULDBLOCK;
			return -1;
		}
	}

	/* decrypt the packet */
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

	conn->gss_decrypted = true;

	/* load decrypted packet into our buffer, then recur */
	conn->gcursor = 0;
	resetPQExpBuffer(&conn->gbuf);
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
