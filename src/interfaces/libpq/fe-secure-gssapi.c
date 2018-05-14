/*-------------------------------------------------------------------------
 *
 * fe-secure-gssapi.c
 *   The front-end (client) encryption support for GSSAPI
 *
 * Portions Copyright (c) 2016-2018, PostgreSQL Global Development Group
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

static ssize_t
send_buffered_data(PGconn *conn, size_t len)
{
	ssize_t ret = pqsecure_raw_write(conn,
									 conn->gwritebuf.data + conn->gwritecurs,
									 conn->gwritebuf.len - conn->gwritecurs);
	if (ret < 0)
		return ret;

	conn->gwritecurs += ret;

	if (conn->gwritecurs == conn->gwritebuf.len)
	{
		/* entire request has now been written */
		resetPQExpBuffer(&conn->gwritebuf);
		conn->gwritecurs = 0;
		return len;
	}

	/* need to be called again */
	errno = EWOULDBLOCK;
	return -1;
}

ssize_t
pg_GSS_write(PGconn *conn, void *ptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t ret = -1;
	int conf = 0;
	uint32 netlen;

	if (conn->gwritebuf.len != 0)
		return send_buffered_data(conn, len);

	/* encrypt the message */
	output.value = NULL;
	output.length = 0;
	input.value = ptr;
	input.length = len;

	major = gss_wrap(&minor, conn->gctx, 1, GSS_C_QOP_DEFAULT,
					 &input, &conf, &output);
	if (GSS_ERROR(major))
	{
		pg_GSS_error(libpq_gettext("GSSAPI wrap error"), conn, major, minor);
		goto cleanup;
	}
	else if (conf == 0)
	{
		printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
							  "GSSAPI did not provide confidentiality\n"));
		goto cleanup;
	}

	/* 4 network-order bytes of length, then payload */
	netlen = htonl(output.length);
	appendBinaryPQExpBuffer(&conn->gwritebuf, (char *)&netlen, 4);
	appendBinaryPQExpBuffer(&conn->gwritebuf, output.value, output.length);

	ret = send_buffered_data(conn, len);
cleanup:
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);
	return ret;
}

static ssize_t
read_from_buffer(PGconn *conn, void *ptr, size_t len)
{
	ssize_t ret = 0;

	/* check for available data */
	if (conn->gcursor < conn->gbuf.len)
	{
		/* clamp length */
		if (len > conn->gbuf.len - conn->gcursor)
			len = conn->gbuf.len - conn->gcursor;

		memcpy(ptr, conn->gbuf.data + conn->gcursor, len);
		conn->gcursor += len;
		ret = len;
	}

	/* reset buffer if all data has been read */
	if (conn->gcursor == conn->gbuf.len)
	{
		conn->gcursor = 0;
		resetPQExpBuffer(&conn->gbuf);
	}

	return ret;
}

ssize_t
pg_GSS_read(PGconn *conn, void *ptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t ret = 0;
	int conf = 0;

	/* handle any buffered data */
	if (conn->gcursor != 0)
		return read_from_buffer(conn, ptr, len);

	/* load in the packet length, if not yet loaded */
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
			return ret;

		/* update buffer state */
		conn->gbuf.len += ret;
		conn->gbuf.data[conn->gbuf.len] = '\0';
		if (conn->gbuf.len < 4)
		{
			errno = EWOULDBLOCK;
			return -1;
		}
	}

	input.length = ntohl(*(uint32 *)conn->gbuf.data);
	ret = enlargePQExpBuffer(&conn->gbuf, input.length - conn->gbuf.len + 4);
	if (ret != 1)
	{
		printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
							  "GSSAPI encrypted packet length %ld too big\n"),
						  input.length);
		return -1;
	}

	/* load any missing parts of the packet */
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

	/* load decrypted packet into our buffer */
	conn->gcursor = 0;
	resetPQExpBuffer(&conn->gbuf);
	ret = enlargePQExpBuffer(&conn->gbuf, output.length);
	if (ret != 1)
	{
		printfPQExpBuffer(&conn->errorMessage, libpq_gettext(
							  "GSSAPI decrypted packet length %ld too big\n"),
						  output.length);
		ret = -1;
		goto cleanup;
	}

	memcpy(conn->gbuf.data, output.value, output.length);
	conn->gbuf.len = output.length;
	conn->gbuf.data[conn->gbuf.len] = '\0';

	ret = read_from_buffer(conn, ptr, len);
cleanup:
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);
	return ret;
}
