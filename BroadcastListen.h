// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2002 Nils Bokermann <Nils.Bokermann@mediaWays.net>
//
// PURPOSE OF THIS FILE: Listen to Broadcast Packets
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
//
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//


#ifndef BROADCASTLISTEN_H
#define BROADCASTLISTEN_H "@(#) $Id$"

#include "ptlib.h"
#include "ptlib/sockets.h"
#include "h225.h"
#include "RasListener.h"

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 )
#endif


class BroadcastListen : public GK_RASListener
{
	  PCLASSINFO(BroadcastListen, PThread)
public:
	BroadcastListen(PIPSocket::Address Home=INADDR_ANY);
	virtual ~BroadcastListen();

	virtual void Close(void);
	virtual void Main(void);

protected:
};

#endif // BROADCASTLISTEN_H
