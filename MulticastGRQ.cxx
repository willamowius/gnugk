// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// MulticastGRQ.cxx thread for multicast gatekeeper discovery
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	990904	initial version (Jan Willamowius)
// 	990924	bugfix: insert GK RAS adress (Jan Willamowius)
// 	990924	bugfix: join multicast group after listen() (Jan Willamowius)
//  000807  bugfix: GRQ multicast replies now go to specified RAS port,
//					not source port (Denver Trouton)
//
//////////////////////////////////////////////////////////////////


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
	listener_mutex.Wait();
	GKHome_mutex.Wait();
	listener.Listen(GKHome, 0, GKRasPort, PSocket::CanReuseAddress);
	GKHome_mutex.Signal();
	listener_mutex.Signal();
	listener_mutex.Wait();
	while (listener.IsOpen()) {
		listener_mutex.Signal();
		const int buffersize = 4096;
		BYTE buffer[buffersize];
		WORD rx_port;
		PIPSocket::Address rx_addr;
		listener_mutex.Wait();
		PSocket::SelectList list;
		list += listener;
		listener_mutex.Signal();
		PChannel::Errors result=PSocket::Select(list);
		if(result==PChannel::NoError) {
			listener_mutex.Wait();
			BOOL result = listener.ReadFrom(buffer, buffersize,  rx_addr, rx_port);
			listener_mutex.Signal();
			if (result) {
				PPER_Stream stream(buffer, listener.GetLastReadCount());
				H323RasWorker *r = new H323RasWorker(stream, rx_addr, rx_port, *this);
			} else {
				PTRACE(1, "RAS LISTENER: Read Error on : " << rx_addr << ":" << rx_port);
			}
		}
		listener_mutex.Wait();// before new truth value for while clause is computed
	}
	listener_mutex.Signal();
}

void MulticastGRQ::Close(void)
{
	MulticastListener.Close();

	// terminate thread
//	Terminate();
};
