// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// RAS Listener Class.
//
// This Class will listen for incoming packets and let another
// new started thread analyze and answer the PDU
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//
//////////////////////////////////////////////////////////////////

#ifndef RASLISTENER_H
#define RASLISTENER_H "@(#) $Id$"

#include <ptlib.h>
#include <ptlib/sockets.h>
#include <h225.h>
#include "RasWorker.h"
#include "GkClient.h"


class GK_RASListener : public PThread {
public:
	GK_RASListener(PIPSocket::Address Home);

	virtual void Main(void)=0; // Handle Connections.

	virtual void SetRoutedMode(BOOL routedSignaling, BOOL routedH245);
	// set routed according to the config file
	virtual void SetRoutedMode();

	virtual void LoadConfig();

	// Information Elements for RasWorker Threads.
	virtual BOOL IsGKRouted() const { return m_routedSignaling; }
	virtual BOOL IsGKRoutedH245() const { return m_routedH245; }

	virtual BOOL AcceptUnregisteredCalls(PIPSocket::Address, bool & fromParent) const;

	const H225_TransportAddress GetRasAddress(PIPSocket::Address) const;
	const H225_TransportAddress GetCallSignalAddress(PIPSocket::Address) const;

	virtual const GkClient * GetGKClient() {return NULL;};

	virtual void SendTo(PPER_Stream &buffer, const unsigned int &length,
			    const PIPSocket::Address &rx_addr, const WORD &port);

	virtual void SendTo(const H225_RasMessage &msg, const PIPSocket::Address &rx_addr,
			    const WORD &port);

	virtual void ForwardRasMsg(H225_RasMessage &msg);

	virtual void SendForward(PPER_Stream &buffer, const unsigned int &length,
				 const PIPSocket::Address &rx_addr, const WORD &port);

	virtual H225_ArrayOf_AlternateGK GetAlternativeGK();

	virtual BOOL AcceptNBCalls();

	template<class RASType> void SetAlternateGK(RASType & ras) {
		if (GetAlternativeGK().GetSize() > 0) {
			ras.IncludeOptionalField(RASType::e_alternateGatekeeper);
			ras.m_alternateGatekeeper = GetAlternativeGK();
                }
        }


protected:
	virtual ~GK_RASListener();
	PIPSocket::Address GKHome;
	mutable PMutex GKHome_mutex;
	BOOL m_routedSignaling,	m_routedH245;
	WORD GKRasPort, GKCallSigPort;
	PUDPSocket listener;
	mutable PMutex listener_mutex;
	PUDPSocket alternate;
	mutable PMutex alternate_mutex;
};

class H323RasListener : public GK_RASListener {
public:
	H323RasListener(PIPSocket::Address Home);

	virtual void Main(void); // Handle Connections.

	virtual void LoadConfig();
	virtual void UnregisterAllEndpoints(void);
	virtual void Close(void);

//	void LoadConfig();

protected:
	friend void Toolkit::delete_raslistener();
	virtual ~H323RasListener();
	PLIST(RasThreads, H323RasWorker);
	RasThreads workers;
private:
	mutable PMutex gkClient_mutex;
};


#endif // RASLISTENER_H
