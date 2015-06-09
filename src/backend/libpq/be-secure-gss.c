#include <assert.h>

#include "postgres.h"

#include "libpq/libpq.h"
#include "libpq/auth.h"
#include "miscadmin.h"

/* GUC value */
bool gss_encrypt;

size_t
be_gss_encrypt(Port *port, char msgtype, const char **msgptr, size_t len)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	uint32 len_n;
	int conf;
	char *ptr = *((char **)msgptr);
	char *newbuf = palloc(len + 5);

	len += 4;
	len_n = htonl(len);

	newbuf[0] = msgtype;
	memcpy(newbuf + 1, &len_n, 4);
	memcpy(newbuf + 5, ptr, len - 4);

	input.length = len + 1; /* include type */
	input.value = newbuf;
	output.length = 0;
	output.value = NULL;

	major = gss_wrap(&minor, port->gss->ctx, 1, GSS_C_QOP_DEFAULT, &input,
					 &conf, &output);
	if (GSS_ERROR(major))
	{
		pg_GSS_error(ERROR, gettext_noop("unwrapping GSS message failed"),
					 major, minor);
		return -1;
	}
	assert(conf);

	newbuf = repalloc(newbuf, output.length);
	memcpy(newbuf, output.value, output.length);

	len = output.length;
	*msgptr = newbuf;
	gss_release_buffer(&minor, &output);

	return len;
}

int
be_gss_inplace_decrypt(StringInfo inBuf)
{
	OM_uint32 major, minor;
	gss_buffer_desc input, output;
	int qtype, conf;
	size_t msglen = 0;

	input.length = inBuf->len;
	input.value = inBuf->data;
	output.length = 0;
	output.value = NULL;

	major = gss_unwrap(&minor, MyProcPort->gss->ctx, &input, &output,
					   &conf, NULL);
	if (GSS_ERROR(major))
	{
		pg_GSS_error(ERROR, gettext_noop("wrapping GSS message failed"),
					 major, minor);
		return -1;
	}
	else if (conf == 0)
	{
		ereport(COMMERROR,
				(errcode(ERRCODE_PROTOCOL_VIOLATION),
				 errmsg("Expected GSSAPI confidentiality but it was not received")));
		return -1;
	}

	qtype = ((char *)output.value)[0]; /* first byte is message type */
	inBuf->len = output.length - 5; /* message starts */

	memcpy((char *)&msglen, ((char *)output.value) + 1, 4);
	msglen = ntohl(msglen);
	if (msglen - 4 != inBuf->len)
	{
		ereport(COMMERROR,
				(errcode(ERRCODE_PROTOCOL_VIOLATION),
				 errmsg("Length value inside GSSAPI-encrypted packet was malformed")));
		return -1;
	}

	memcpy(inBuf->data, ((char *)output.value) + 5, inBuf->len);
	inBuf->data[inBuf->len] = '\0'; /* invariant */
	gss_release_buffer(&minor, &output);

	return qtype;
}
