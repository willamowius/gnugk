//////////////////////////////////////////////////////////////////
//
// RAS-Server for H.323 gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	990500	initial version (Xiang Ping Chen, Rajat Todi, Joe Metzger)
//	990600	ported to OpenH323 V. 1.08 (Jan Willamowius)
//
//////////////////////////////////////////////////////////////////

#ifndef __rassrv_h_
#define __rassrv_h_

#include <ptlib/sockets.h>
#include "h225.h" 
#include "h323.h"
#include "Toolkit.h"
#include "RasTbl.h"
#include "h323util.h"
#include "GkAuthorize.h"

// forward references to avoid includes
//class SignalChannel;
class HandlerList;
class resourceManager;
class GkStatus;
class GkAuthenticatorList;
class GkDestAnalysisList;
class NeighborList;
class PendingList;

class H323RasSrv : public PThread
{
  PCLASSINFO(H323RasSrv, PThread)

public:
	H323RasSrv(PIPSocket::Address GKHome);
	virtual ~H323RasSrv();
	void Close(void);

	void Main(void);  // original HandleConnections(); 

	void UnregisterAllEndpoints(void);

	// set routed method
	void SetRoutedMode(bool routedSignaling, bool routedH245);

	// set name of the gatekeeper.
	const PString GetGKName() const { return Toolkit::GKName(); }

	// Deal with GRQ. obj_grq is the incoming RAS GRQ msg, and obj_rpl is the
	// GCF or GRJ Ras msg.
	BOOL OnGRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_grq, H225_RasMessage & obj_rpl);

	BOOL OnRRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rrq, H225_RasMessage & obj_rpl);

	BOOL OnURQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_urq, H225_RasMessage & obj_rpl);

	BOOL OnARQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_arq, H225_RasMessage & obj_rpl);

	BOOL OnDRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_drq, H225_RasMessage & obj_rpl);

	BOOL OnIRR(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);

	BOOL OnBRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);

	BOOL OnLRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);

	BOOL OnLCF(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);
      
	BOOL OnLRJ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);
      
	BOOL OnRAI(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);
      
	void ReplyARQ(const endptr & RequestingEP, const endptr & CalledEP, const H225_AdmissionRequest & obj_arq);

	void SendRas(const H225_RasMessage & obj_ras, const H225_TransportAddress & dest);

	void SendRas(const H225_RasMessage & obj_ras, const PIPSocket::Address & rx_addr, WORD rx_port);

	void SendReply(const H225_RasMessage & obj_rpl, const PIPSocket::Address & rx_addr, WORD rx_port, PUDPSocket & BoundSocket);

	bool Check();
	bool IsGKRouted() const { return GKRoutedSignaling; }
	bool IsGKRoutedH245() const { return GKRoutedH245; }
	bool AcceptUnregisteredCalls() const { return AcceptUnregCalls; }

	void LoadConfig();

	const H225_TransportAddress GetRasAddress(PIPSocket::Address) const;
	const H225_TransportAddress GetCallSignalAddress(PIPSocket::Address) const;

	NeighborList * GetNeighborsGK() const { return NeighborsGK; }

protected:
	/** OnARQ checks if the dialled address (#aliasStr#) should be
	 * rejected with the reason "incompleteAddress". This is the case whenever the
	 * destination address is not a registered alias AND not matching with
	 * prefix of a registered GW.
	 */
	virtual BOOL CheckForIncompleteAddress(const H225_ArrayOf_AliasAddress &alias) const;

	virtual BOOL SetAlternateGK(H225_RegistrationConfirm &rcf);

	virtual BOOL ForwardRasMsg(H225_RasMessage msg); // not passed as const, ref or pointer!

	void ProcessARQ(PIPSocket::Address rx_addr, const endptr & RequestingEP, const endptr & CalledEP, const H225_AdmissionRequest & obj_rr, H225_RasMessage & obj_rpl, BOOL bReject = FALSE);

private:
	bool GKRoutedSignaling, GKRoutedH245, AcceptUnregCalls;
	WORD GKRasPort, GKCallSigPort;
        
	PIPSocket::Address GKHome;
	PUDPSocket listener;
	PMutex writeMutex, loadLock;

	/** this is the upd port where all requests to the alternate GK are sent to */
	PUDPSocket udpForwarding;

	HandlerList * sigHandler;

	// just pointers to global singleton objects
	RegistrationTable * EndpointTable;
	resourceManager * GKManager; 
	GkStatus * GkStatusThread;

	GkAuthenticatorList * authList;
	GkDestAnalysisList * destAnalysisList;

	NeighborList * NeighborsGK;
	PendingList * arqPendingList;
	
	GkAuthorize* GWR;
};


inline const H225_TransportAddress H323RasSrv::GetRasAddress(PIPSocket::Address peerAddr) const
{
	PIPSocket::Address localAddr((GKHome == INADDR_ANY) ? Toolkit::Instance()->GetRouteTable()->GetLocalAddress(peerAddr) : GKHome);
	return SocketToH225TransportAddr(localAddr, GKRasPort);
}

inline const H225_TransportAddress H323RasSrv::GetCallSignalAddress(PIPSocket::Address peerAddr) const
{
	PIPSocket::Address localAddr((GKHome == INADDR_ANY) ? Toolkit::Instance()->GetRouteTable()->GetLocalAddress(peerAddr) : GKHome);
	return SocketToH225TransportAddr(localAddr, GKCallSigPort);
}


extern H323RasSrv *RasThread;  // I hate global object, but...

#endif
