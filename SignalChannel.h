//////////////////////////////////////////////////////////////////
//
// SignalChannel.h
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// initial author: Sergio Artero
// initial version: 12/9/1999
//
//////////////////////////////////////////////////////////////////

#ifndef _signalchannel_h__
#define _signalchannel_h__

#include <ptlib.h>
#include <ptlib/sockets.h>
#include <ptclib/asner.h>

#include "SignalConnection.h"
#include "gk_const.h"


class CallTable; // forward


class SignalChannel:public PThread {

	PCLASSINFO ( SignalChannel, PThread )

	public:
	SignalChannel( PINDEX stackSize, PIPSocket::Address _GKHome, WORD port);
		virtual ~SignalChannel();
		void Main(void);
		BOOL Open(void);
		void Close(void);
				
	protected:
		PIPSocket::Address GKHome; 
		PTCPSocket	m_listener;
		WORD		m_port;

		PAbstractList connectionList;

		void CleanupConnections(void);
		void CloseConnections(void);
};

#endif

