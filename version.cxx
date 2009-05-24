//////////////////////////////////////////////////////////////////
//
// PURPOSE OF THIS FILE: Give version info
//
// Copyright (C) 2003 Nils.Bokermann@mediaways.net
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <ptlib/sockets.h>
#include "versionts.h"
#include "version.h"
#include "Toolkit.h"
#include "config.h"

const PString Toolkit::GKVersion()
{
	return PString(PString::Printf,
		       "Gatekeeper(%s) Version(%s) Ext(pthreads=%d,radius=%d,mysql=%d,pgsql=%d,firebird=%d,odbc=%d,sqlite=%d,large_fdset=%d,crypto/ssl=%d,h46018=%d)"
		       " Build(%s, %s) Sys(%s %s %s)\r\n",
		       (const unsigned char*)(PProcess::Current().GetManufacturer()),
		       (const unsigned char*)(PProcess::Current().GetVersion(true)),
#ifdef P_PTHREADS
				(int)1,
#else
				(int)0,
#endif
#if HAS_RADIUS
				(int)1,
#else
				(int)0,
#endif
#if HAS_MYSQL
				(int)1,
#else
				(int)0,
#endif
#if HAS_PGSQL
				(int)1,
#else
				(int)0,
#endif
#if HAS_FIREBIRD
				(int)1,
#else
				(int)0,
#endif
#if HAS_ODBC
				(int)1,
#else
				(int)0,
#endif
#if HAS_SQLITE
				(int)1,
#else
				(int)0,
#endif
#ifdef LARGE_FDSET
				(int)LARGE_FDSET,
#else
				(int)0,
#endif
#if P_SSL
				(int)1,
#else
				(int)0,
#endif
#if HAS_H46018
				(int)1,
#else
				(int)0,
#endif
		       __DATE__, __TIME__,
		       (const unsigned char*)(PProcess::GetOSName()),
		       (const unsigned char*)(PProcess::GetOSHardware()),
		       (const unsigned char*)(PProcess::GetOSVersion())
		);
}
