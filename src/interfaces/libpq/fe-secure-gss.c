#include <assert.h>

#include "libpq-fe.h"
#include "postgres_fe.h"
#include "fe-auth.h"
#include "libpq-int.h"

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
