/*-------------------------------------------------------------------------
 *
 * be-secure-gssapi.c
 *  GSSAPI encryption support
 *
 * Portions Copyright (c) 2018-2018, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *  src/backend/libpq/be-secure-gssapi.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "be-gssapi-common.h"

#include "libpq/libpq.h"
#include "libpq/libpq-be.h"
#include "libpq/pqformat.h"
#include "miscadmin.h"

static ssize_t
send_buffered_data(Port *port, size_t len)
{
	ssize_t ret = secure_raw_write(
		port,
		port->gss->writebuf.data + port->gss->writebuf.cursor,
		port->gss->writebuf.len - port->gss->writebuf.cursor);
	if (ret < 0)
		return ret;

	/* update and possibly clear buffer state */
	port->gss->writebuf.cursor += ret;

	if (port->gss->writebuf.cursor == port->gss->writebuf.len)
	{
		/* entire request has now been written */
		resetStringInfo(&port->gss->writebuf);
		return len;
	}

	/* need to be called again */
	errno = EWOULDBLOCK;
	return -1;
}

ssize_t
be_gssapi_write(Port *port, void *ptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t ret = -1;
	int conf = 0;
	uint32 netlen;
	pg_gssinfo *gss = port->gss;

	if (gss->writebuf.len != 0)
		return send_buffered_data(port, len);

	/* encrypt the message */
	output.value = NULL;
	output.length = 0;
	input.value = ptr;
	input.length = len;

	major = gss_wrap(&minor, gss->ctx, 1, GSS_C_QOP_DEFAULT,
					 &input, &conf, &output);
	if (GSS_ERROR(major))
	{
		pg_GSS_error(ERROR, gettext_noop("GSSAPI wrap error"), major, minor);
		goto cleanup;
	} else if (conf == 0)
	{
		ereport(FATAL, (errmsg("GSSAPI did not provide confidentiality")));
		goto cleanup;
	}

	/* 4 network-order length bytes, then payload */
	netlen = htonl(output.length);
	appendBinaryStringInfo(&gss->writebuf, (char *)&netlen, 4);
	appendBinaryStringInfo(&gss->writebuf, output.value, output.length);

	ret = send_buffered_data(port, len);
cleanup:
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);
	return ret;
}

static ssize_t
read_from_buffer(pg_gssinfo *gss, void *ptr, size_t len)
{
	ssize_t ret = 0;

	/* load up any available data */
	if (gss->buf.len > 4 && gss->buf.cursor < gss->buf.len)
	{
		/* clamp length */
		if (len > gss->buf.len - gss->buf.cursor)
			len = gss->buf.len - gss->buf.cursor;

		memcpy(ptr, gss->buf.data + gss->buf.cursor, len);
		gss->buf.cursor += len;
		ret = len;
	}

	/* reset buffer if all data has been read */
	if (gss->buf.cursor == gss->buf.len)
		resetStringInfo(&gss->buf);

	return ret;
}

ssize_t
be_gssapi_read(Port *port, void *ptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t ret;
	int conf = 0;
	pg_gssinfo *gss = port->gss;

	if (gss->buf.cursor > 0)
		return read_from_buffer(gss, ptr, len);

	/* load length if not present */
	if (gss->buf.len < 4)
	{
		enlargeStringInfo(&gss->buf, 4 - gss->buf.len);
		ret = secure_raw_read(port, gss->buf.data + gss->buf.len,
							  4 - gss->buf.len);
		if (ret < 0)
			return ret;

		/* update buffer state */
		gss->buf.len += ret;
		gss->buf.data[gss->buf.len] = '\0';
		if (gss->buf.len < 4)
		{
			errno = EWOULDBLOCK;
			return -1;
		}
	}

	input.length = ntohl(*(uint32*)gss->buf.data);
	enlargeStringInfo(&gss->buf, input.length - gss->buf.len + 4);

	ret = secure_raw_read(port, gss->buf.data + gss->buf.len,
						  input.length - gss->buf.len + 4);
	if (ret < 0)
		return ret;

	/* update buffer state */
	gss->buf.len += ret;
	gss->buf.data[gss->buf.len] = '\0';
	if (gss->buf.len - 4 < input.length)
	{
		errno = EWOULDBLOCK;
		return -1;
	}

	/* decrypt the packet */
	output.value = NULL;
	output.length = 0;
	input.value = gss->buf.data + 4;

	major = gss_unwrap(&minor, gss->ctx, &input, &output, &conf, NULL);
	if (GSS_ERROR(major))
	{
		pg_GSS_error(ERROR, gettext_noop("GSSAPI unwrap error"),
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

	/* put the decrypted packet in the buffer */
	resetStringInfo(&gss->buf);
	enlargeStringInfo(&gss->buf, output.length);

	memcpy(gss->buf.data, output.value, output.length);
	gss->buf.len = output.length;
	gss->buf.data[gss->buf.len] = '\0';

	ret = read_from_buffer(gss, ptr, len);
cleanup:
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);
	return ret;
}
