// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// MulticastGRQ.h thread for multicast gatekeeper discovery
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	990904	initial version (Jan Willamowius)
//
//////////////////////////////////////////////////////////////////


#ifndef MULTICASTGRQ_H
#define MULTICASTGRQ_H "@(#) $Id$"

#include "ptlib.h"
#include "ptlib/sockets.h"
#include "h225.h"
#include "RasListener.h"

class MulticastGRQ : public GK_RASListener
{
	  PCLASSINFO(MulticastGRQ, PThread)
public:
	MulticastGRQ(PIPSocket::Address GKHome);
	virtual ~MulticastGRQ();

	void Close(void);
	virtual void Main(void);

protected:

protected:
	PUDPSocket MulticastListener;
	H225_TransportAddress GKRasAddress;
};

#endif // MULTICASTGRQ_H
