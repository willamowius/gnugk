//////////////////////////////////////////////////////////////////
//
// MulticastGRQ.cxx thread for multicast gatekeeper discovery
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
// 	990904	initial version (Jan Willamowius)
// 	990924	bugfix: insert GK RAS adress (Jan Willamowius)
// 	990924	bugfix: join multicast group after listen() (Jan Willamowius)
//
//////////////////////////////////////////////////////////////////


#include "MulticastGRQ.h"
#include "RasSrv.h"
#include "gk_const.h"
#include "Toolkit.h"
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#endif

MulticastGRQ::MulticastGRQ(PIPSocket::Address _GKHome, H323RasSrv * _RasSrv)
	: PThread(1000, NoAutoDeleteThread), 
	  MulticastListener(Toolkit::Config()->GetInteger("MulticastPort", GK_DEF_MULTICAST_PORT))
{
	GKHome = _GKHome;
	RasSrv = _RasSrv;
	GKRasAddress.SetTag(H225_TransportAddress::e_ipAddress);
	H225_TransportAddress_ipAddress & ipAddress = GKRasAddress;

	// own IP number
	ipAddress.m_ip[0] = GKHome.Byte1();
	ipAddress.m_ip[1] = GKHome.Byte2();
	ipAddress.m_ip[2] = GKHome.Byte3();
	ipAddress.m_ip[3] = GKHome.Byte4();
	ipAddress.m_port = Toolkit::Config()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT);

	Resume();
};

MulticastGRQ::~MulticastGRQ()
{
};

void MulticastGRQ::Main(void)
{
	// set socket to multicast
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr(Toolkit::Config()->GetString("MulticastGroup", GK_DEF_MULTICAST_GROUP));
	mreq.imr_interface.s_addr = GKHome;
	MulticastListener.Listen(GKHome, 
							 Toolkit::Config()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH), 
							 MulticastListener.GetPort());
	if (setsockopt(MulticastListener.GetHandle(), IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0)
	{
		PTRACE(1, "GK\tCan't join multicast group.");
		MulticastListener.Close();
		Suspend();
	};
	while (MulticastListener.IsOpen())
	{ 
		int iResult;
		WORD rx_port;
		PIPSocket::Address rx_addr;

		PBYTEArray * rdbuf = new PBYTEArray(4096);
		PPER_Stream * rdstrm = new PPER_Stream(*rdbuf);
		iResult = MulticastListener.ReadFrom(rdstrm->GetPointer(), rdstrm->GetSize(), rx_addr, rx_port);
		if (!iResult)
		{
    		PTRACE(1, "GK\tMulticast thread: Read error: " << MulticastListener.GetErrorText());

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
			PTRACE(1, "GK\tMulticast GRQ Received");
			if ( RasSrv->OnGRQ( rx_addr, obj_req, obj_rpl ) )
				RasSrv->SendReply( obj_rpl, rx_addr, rx_port, MulticastListener );
			break;
		case H225_RasMessage::e_locationRequest :
			PTRACE(1, "GK\tMulticast LRQ Received");
			if ( RasSrv->OnLRQ( rx_addr, obj_req, obj_rpl ) )
				RasSrv->SendReply( obj_rpl, rx_addr, rx_port, MulticastListener );
			break;
		default:
			PTRACE(1, "GK\tUnknown RAS message received");
			break;      
		}
	};
};

void MulticastGRQ::Close(void)
{
	MulticastListener.Close();
	
	// terminate thread
//	Terminate();
};

