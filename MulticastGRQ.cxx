// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2002 Nils Bokermann <Nils.Bokermann@mediaWays.net>
//
// PURPOSE OF THIS FILE: Listen to Multicast packages
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


#if (_MSC_VER >= 1200)
#pragma warning( disable : 4291 ) // warning about no matching operator delete
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include "MulticastGRQ.h"
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
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
static const char vcHid[] = MULTICASTGRQ_H;
#endif /* lint */


MulticastGRQ::MulticastGRQ(PIPSocket::Address Home)
	: GK_RASListener(Home), MulticastListener(WORD(GkConfig()->GetInteger("MulticastPort", GK_DEF_MULTICAST_PORT)))
{
	// own IP number
	GKRasAddress = SocketToH225TransportAddr(GKHome, WORD(GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT)));


	// set socket to multicast
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr(GkConfig()->GetString("MulticastGroup", GK_DEF_MULTICAST_GROUP));
	mreq.imr_interface.s_addr = GKHome;
	MulticastListener.Listen(GKHome,
				 GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH),
				 MulticastListener.GetPort());
	if (setsockopt(MulticastListener.GetHandle(), IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0)
	{
		PTRACE(1, "GK\tCan't join multicast group.");
		MulticastListener.Close();
		//Suspend();
	};


	Resume();
};

MulticastGRQ::~MulticastGRQ()
{
};

void MulticastGRQ::Main(void)
{
	GKHome_mutex.Wait();
	listener.Listen(GKHome, 0, GKRasPort, PSocket::CanReuseAddress);
	GKHome_mutex.Signal();
	while (listener.IsOpen()) {
		const int buffersize = 4096;
		BYTE buffer[buffersize];
		WORD rx_port;
		PIPSocket::Address rx_addr;
		BOOL result = listener.ReadFrom(buffer, buffersize,  rx_addr, rx_port);
		if (result) {
			PPER_Stream stream(buffer, listener.GetLastReadCount());
			// The RasWorker object will delete itself via the PThread-autodelete function.
			new H323RasWorker(stream, rx_addr, rx_port, *this);
		} else {
			PTRACE(1, "RAS LISTENER: Read Error on : " << rx_addr << ":" << rx_port);
		}
	}
}

void MulticastGRQ::Close(void)
{
	PTRACE(5, "MulticastGRQ::Close() " << getpid());
	MulticastListener.Close();

	// terminate thread
	Terminate();
};
