//////////////////////////////////////////////////////////////////
//
// PURPOSE OF THIS FILE: Give version info
//
// Copyright (C) 2003 Nils.Bokermann@mediaways.net
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////

#include "version.h"
#include "Toolkit.h"

const PString Toolkit::GKVersion()
{
	return PString(PString::Printf,
		       "Gatekeeper(%s) Version(%s) Ext(pthreads=%d,radius=%d,mysql=%d)"
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
		       __DATE__, __TIME__,
		       (const unsigned char*)(PProcess::GetOSName()),
		       (const unsigned char*)(PProcess::GetOSHardware()),
		       (const unsigned char*)(PProcess::GetOSVersion())
		);
}
