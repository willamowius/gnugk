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

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = GNUGK_VERSION_H;
#endif /* lint */

// a int to print
#ifdef P_PTHREADS
#define PTHREADS_MARK_STRING "1"
#else
#define PTHREADS_MARK_STRING "0"
#endif

const PString Toolkit::GKVersion()
{
	return PString(PString::Printf,
		       "Gatekeeper(%s) Version(%s) Ext(pthreads="
		       PTHREADS_MARK_STRING ") Build(%s, %s) Sys(%s %s %s)",
		       (const unsigned char*)(PProcess::Current().GetManufacturer()),
		       (const unsigned char*)(PProcess::Current().GetVersion(true)),
		       __DATE__, __TIME__,
		       (const unsigned char*)(PProcess::GetOSName()),
		       (const unsigned char*)(PProcess::GetOSHardware()),
		       (const unsigned char*)(PProcess::GetOSVersion())
		);
}
