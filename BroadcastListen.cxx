// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// BroadcastListen.cxx thread for listening to broadcasts (only needed on some OSs)
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	991016	initial version (Jan Willamowius)
//
//////////////////////////////////////////////////////////////////


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

void BroadcastListen::Close(void)
{
	listener.Close();

	// terminate thread
	Terminate();
};
