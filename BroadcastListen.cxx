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
#include "RasSrv.h"
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


BroadcastListen::BroadcastListen(H323RasSrv * _RasSrv)
	: PThread(1000, NoAutoDeleteThread),
	  BroadcastListener(WORD(GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT)))
{
	PTRACE(1, "GK\tBroadcast listener started");

	RasSrv = _RasSrv;

	Resume();
};

BroadcastListen::~BroadcastListen()
{
};

void BroadcastListen::Main(void)
{
	ReadLock cfglock(ConfigReloadMutex);

	BroadcastListener.Listen
		(GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH),
		 BroadcastListener.GetPort(),
		 PSocket::CanReuseAddress);

	if (!BroadcastListener.IsOpen())
	{
		PTRACE(1,"GK\tBind to broadcast listener failed!");
	};
	while (BroadcastListener.IsOpen())
	{
		WORD rx_port;
		PIPSocket::Address rx_addr;

		PBYTEArray * rdbuf = new PBYTEArray(4096);
		PPER_Stream * rdstrm = new PPER_Stream(*rdbuf);
		ConfigReloadMutex.EndRead();
		int iResult = BroadcastListener.ReadFrom(rdstrm->GetPointer(), rdstrm->GetSize(), rx_addr, rx_port);
		ConfigReloadMutex.StartRead();
		if (!iResult)
		{
    		PTRACE(1, "GK\tBroadcast thread: Read error: " << BroadcastListener.GetErrorText());

			delete rdbuf;
			delete rdstrm;

			continue;
		};
		PTRACE(2, "GK\tRd from : " << rx_addr << " [" << rx_port << "]");

		H225_RasMessage obj_req;
		if (!obj_req.Decode( *rdstrm ))
		{
			PTRACE(1, "GK\tCouldn't decode message!");

			delete rdbuf;
			delete rdstrm;

			continue;
		};

		PTRACE(2, "GK\t" << obj_req.GetTagName());
		PTRACE(3, "GK\t" << endl << setprecision(2) << obj_req);

		delete rdbuf;
		delete rdstrm;

		H225_RasMessage obj_rpl;

		switch (obj_req.GetTag())
		{
		case H225_RasMessage::e_gatekeeperRequest:
			PTRACE(1, "GK\tBroadcast GRQ Received");
			if ( RasSrv->OnGRQ( rx_addr, obj_req, obj_rpl ) )
				RasSrv->SendReply( obj_rpl, rx_addr, rx_port, BroadcastListener );
			break;
		// It is said Cisco Call Manager sends RRQ via broadcast
		// But is it valid to use broadcasting RRQ?
		case H225_RasMessage::e_registrationRequest:
			PTRACE(1, "GK\tBroadcast RRQ Received");
			if ( RasSrv->OnRRQ( rx_addr, obj_req, obj_rpl ) )
				RasSrv->SendReply( obj_rpl, rx_addr, rx_port, BroadcastListener );
			break;
		case H225_RasMessage::e_locationRequest :
			PTRACE(1, "GK\tBroadcast LRQ Received");
			if ( RasSrv->OnLRQ( rx_addr, obj_req, obj_rpl ) )
				RasSrv->SendReply( obj_rpl, rx_addr, rx_port, BroadcastListener );
			break;
		default:
			PTRACE(1, "GK\tUnknown RAS message broadcast received");
			break;
		}
	};
};

void BroadcastListen::Close(void)
{
	BroadcastListener.Close();

	// terminate thread
//	Terminate();
};
