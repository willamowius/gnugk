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


#include "BroadcastListen.h"
#include "Toolkit.h"
#include "gk_const.h"
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#endif

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = BROADCASTLISTEN_H;
#endif /* lint */


BroadcastListen::BroadcastListen(PIPSocket::Address Home)
	: GK_RASListener(Home)

{
	PTRACE(1, "GK\tBroadcast listener started");
	listener.Listen
		(GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH),
		 WORD(GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT)),
		 PSocket::CanReuseAddress);

	if (!listener.IsOpen())
	{
		PTRACE(1,"GK\tBind to broadcast listener failed!");
	};

	Resume();
};

BroadcastListen::~BroadcastListen()
{
};

void BroadcastListen::Main(void)
{
	GKHome_mutex.Wait();
	listener.Listen(GKHome, 0, GKRasPort, PSocket::CanReuseAddress);
	GKHome_mutex.Signal();
	while (listener.IsOpen()) {
		const int buffersize = 4096;
		BYTE buffer[buffersize];
		WORD rx_port;
		PIPSocket::Address rx_addr;
		rx_port=0;
		int result=listener.ReadFrom(buffer, buffersize,  rx_addr, rx_port);
		if(result!=0) {
			PPER_Stream stream(buffer, listener.GetLastReadCount());
			// RasWorker will delete itself.
			new H323RasWorker(stream, rx_addr, rx_port, *this);
		} else {
			PTRACE(1, "RAS LISTENER: Read Error on : " << rx_addr << ":" << rx_port);
		}
	}
}

void BroadcastListen::Close(void)
{
	listener.Close();

	// terminate thread
	Terminate();
};
