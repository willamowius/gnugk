// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2003 Nils.Bokermann@mediaways.net
//
// PURPOSE OF THIS FILE: Give version info
//
// - Automatic Version Information via RCS:
//   $Id$
//   $Source$
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

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

const PString
Toolkit::GKVersion()
{
	return PString(PString::Printf,
		       "Gatekeeper(%s) Version(%s) Ext(pthreads="
		       PTHREADS_MARK_STRING ") Build(%s, %s) Sys(%s %s %s)",
		       (const unsigned char*)(PProcess::Current().GetManufacturer()),
		       (const unsigned char*)(PProcess::Current().GetVersion(TRUE)),
		       __DATE__, __TIME__,
		       (const unsigned char*)(PProcess::GetOSName()),
		       (const unsigned char*)(PProcess::GetOSHardware()),
		       (const unsigned char*)(PProcess::GetOSVersion())
		);
}
