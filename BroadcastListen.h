// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// BroadcastListen.h thread for listening to broadcasts (only needed on some OSs)
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	991016	initial version (Jan Willamowius)
// 	991020	code cleanup (Jan Willamowius)
//
//////////////////////////////////////////////////////////////////


#ifndef BROADCASTLISTEN_H
#define BROADCASTLISTEN_H

#include "ptlib.h"
#include "ptlib/sockets.h"
#include "h225.h"

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 )
#endif

class H323RasSrv;

class BroadcastListen : public PThread
{
	  PCLASSINFO(BroadcastListen, PThread)
public:
	BroadcastListen(H323RasSrv * _RasSrv);
	virtual ~BroadcastListen();

	void Close(void);

protected:
	virtual void Main(void);

protected:
	PUDPSocket BroadcastListener;
	H323RasSrv * RasSrv;
};

#endif // BROADCASTLISTEN_H
