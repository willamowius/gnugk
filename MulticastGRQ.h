//////////////////////////////////////////////////////////////////
//
// MulticastGRQ.h thread for multicast gatekeeper discovery
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
// 	990904	initial version (Jan Willamowius)
//
//////////////////////////////////////////////////////////////////


#ifndef MULTICASTGRQ_H
#define MULTICASTGRQ_H

#include "ptlib.h"
#include "ptlib/sockets.h"
#include "h225.h" 

class H323RasSrv;

class MulticastGRQ : public PThread
{
	  PCLASSINFO(MulticastGRQ, PThread)
public:
	MulticastGRQ(PIPSocket::Address _GKHome, H323RasSrv * _RasSrv);
	virtual ~MulticastGRQ();

	void Close(void);

protected:
	virtual void Main(void);

protected:
	PUDPSocket MulticastListener;
	H225_TransportAddress GKRasAddress;
	PIPSocket::Address GKHome;
	H323RasSrv * RasSrv;
};

#endif // MULTICASTGRQ_H

