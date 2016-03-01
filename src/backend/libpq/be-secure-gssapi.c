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

#include "postgres.h"

#include "libpq/be-gssapi-common.h"

#include "libpq/libpq.h"
#include "libpq/libpq-be.h"
#include "libpq/pqformat.h"
#include "miscadmin.h"

/*
 * Wrapper function indicating whether we are currently performing GSSAPI
 * connection encryption.
 *
 * gss->encrypt is set when connection parameters are processed, which happens
 * immediately after AUTH_REQ_OK is sent.
 */
static bool
be_gssapi_should_encrypt(Port *port)
{
	if (port->gss->ctx == GSS_C_NO_CONTEXT)
		return false;
	return port->gss->encrypt;
}

/*
 * Send a message along the connection, possibly encrypting using GSSAPI.
 *
 * If we are not encrypting at the moment, we send data plaintext and follow
 * the calling conventions of secure_raw_write.  Otherwise, the following
 * hold: Incomplete writes are buffered using a dedicated StringInfo in the
 * port structure.  On failure, we return -1; on partial write, we return -1
 * and set errno=EWOULDBLOCK since the translation between plaintext and
 * encrypted is indeterminate; on completed write, we return the total number
 * of bytes written including any buffering that occurred.  Behavior when
 * called with a new pointer/length combination after an incomplete write is
 * undefined.
 */
ssize_t
be_gssapi_write(Port *port, void *ptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	ssize_t ret;
	int conf;
	uint32 netlen;

	if (be_gssapi_should_encrypt(port) == false)
		return secure_raw_write(port, ptr, len);

	/* send any data we have buffered */
	if (port->gss->writebuf.len != 0)
	{
		ret = secure_raw_write(
			port,
			port->gss->writebuf.data + port->gss->writebuf.cursor,
			port->gss->writebuf.len - port->gss->writebuf.cursor);
		if (ret < 0)
			return ret;

		/* update and possibly clear buffer state */
		port->gss->writebuf.cursor += ret;

		if (port->gss->writebuf.cursor == port->gss->writebuf.len)
		{
			resetStringInfo(&port->gss->writebuf);

			/* the entire request has now been written */
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

	/* format for on-wire: 4 network-order bytes of length, then payload */
	netlen = htonl(output.length);
	appendBinaryStringInfo(&port->gss->writebuf, (char *)&netlen, 4);
	appendBinaryStringInfo(&port->gss->writebuf, output.value, output.length);

	/* recur to send any buffered data */
	gss_release_buffer(&minor, &output);
	return be_gssapi_write(port, ptr, len);
 cleanup:
	if (output.value != NULL)
		gss_release_buffer(&minor, &output);

	return ret;
}

/*
 * Wrapper function for buffering decrypted data.
 *
 * This allows us to present a stream-like interface to secure_read.  For a
 * description of buffering behavior, see comment at be_gssapi_read.
 */
static ssize_t
be_gssapi_read_from_buffer(Port *port, void *ptr, size_t len)
{
	ssize_t ret = 0;

	/* Is any data available? */
	if (port->gss->buf.len > 4 && port->gss->buf.cursor < port->gss->buf.len)
	{
		/* clamp length */
		if (len > port->gss->buf.len - port->gss->buf.cursor)
			len = port->gss->buf.len - port->gss->buf.cursor;

		memcpy(ptr, port->gss->buf.data + port->gss->buf.cursor, len);
		port->gss->buf.cursor += len;

		ret = len;
	}

	/* if all data has been read, reset buffer */
	if (port->gss->buf.cursor == port->gss->buf.len)
		resetStringInfo(&port->gss->buf);

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

	if (be_gssapi_should_encrypt(port) == false)
		return secure_raw_read(port, ptr, len);

	/* ensure proper behavior under recursion */
	if (len == 0)
		return 0;

	/* report any buffered data, then recur */
	if (port->gss->buf.cursor > 0)
	{
		ret = be_gssapi_read_from_buffer(port, ptr, len);
		if (ret > 0)
		{
			ssize_t r_ret =
				be_gssapi_read(port, (char *)ptr + ret, len - ret);
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
	if (port->gss->buf.len < 4)
	{
		enlargeStringInfo(&port->gss->buf, 4 - port->gss->buf.len);
		ret = secure_raw_read(port, port->gss->buf.data + port->gss->buf.len,
							  4 - port->gss->buf.len);
		if (ret < 0)
			return ret;

		/* write length to buffer */
		port->gss->buf.len += ret;
		port->gss->buf.data[port->gss->buf.len] = '\0';
		if (port->gss->buf.len < 4)
		{
			errno = EWOULDBLOCK;
			return -1;
		}
	}

	/* we know the length of the packet at this point */
	input.length = ntohl(*(uint32 *)port->gss->buf.data);
	enlargeStringInfo(&port->gss->buf, input.length - port->gss->buf.len + 4);

	/* read the packet into our buffer */
	ret = secure_raw_read(port, port->gss->buf.data + port->gss->buf.len,
						  input.length - port->gss->buf.len + 4);
	if (ret < 0)
		return ret;

	port->gss->buf.len += ret;
	port->gss->buf.data[port->gss->buf.len] = '\0';
	if (port->gss->buf.len - 4 < input.length)
	{
		errno = EWOULDBLOCK;
		return -1;
	}

	/* decrypt the packet */
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

	/* load decrypted packet into our buffer, then recur */
	resetStringInfo(&port->gss->buf);
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
