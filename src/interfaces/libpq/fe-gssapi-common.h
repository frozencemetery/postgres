/*-------------------------------------------------------------------------
 *
 * fe-gssapi-common.h
 *
 *      Definitions for GSSAPI common routines
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/interfaces/libpq/fe-gssapi-common.h
 */

#ifndef FE_GSSAPI_COMMON_H
#define FE_GSSAPI_COMMON_H

#include "libpq-fe.h"
#include "libpq-int.h"

void pg_GSS_error(const char *mprefix, PGconn *conn,
				  OM_uint32 maj_stat, OM_uint32 min_stat);

#endif /* FE_GSSAPI_COMMON_H */
