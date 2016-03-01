/*-------------------------------------------------------------------------
 *
 * be-secure-gssapi.c
 *  GSSAPI encryption support
 *
 * Portions Copyright (c) 2016, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *  src/backend/libpq/be-secure-gssapi.c
 *
 *-------------------------------------------------------------------------
 */

#include "libpq/be-gssapi-common.h"

#include "postgres.h"

#include "libpq/libpq.h"
#include "libpq/libpq-be.h"
#include "libpq/pqformat.h"
#include "miscadmin.h"

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
