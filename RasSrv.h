//////////////////////////////////////////////////////////////////
//
// RAS-Server for H.323 gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
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

// forward references to avoid includes
class SignalChannel;
class resourceManager;
class GkStatus;
class GkAuthenticatorList;


class H323RasSrv : public PThread 
{
  PCLASSINFO(H323RasSrv, PThread)

public:
	H323RasSrv(PIPSocket::Address GKHome);
	virtual ~H323RasSrv();
	void Close(void);

	void Main(void);  // original HandleConnections(); 

	void UnregisterAllEndpoints(void);

	// set signaling method
	void SetGKSignaling(BOOL routedSignaling) { GKroutedSignaling = routedSignaling; };

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
      
	void SendReply(const H225_RasMessage & obj_rpl, PIPSocket::Address rx_addr, WORD rx_port, PUDPSocket & BoundSocket);

	void ReplyARQ(const endptr & RequestingEP, const endptr & CalledEP, const H225_AdmissionRequest & obj_arq);

	bool Check();

	void LoadConfig();

protected:
	/** Checks for one condition (between '&`s) the SignalAddress. Used on RRQ in the moment.
	 *  @returns TRUE if #SignalAdr# fulfills the #Condition#. #FALSE# if not. And returns 
	 *    #ON_ERROR# on a #Condition#-parse errors which may be #TRUE# (see code).
	 */
	//virtual BOOL SigAuthCondition(const H225_TransportAddress &SignalAdr, const PString &Condition) const;

	/** OnARQ checks if the dialled address (#aliasStr#) should be
	 * rejected with the reason "incompleteAddress". This is the case whenever the
	 * destination address is not a registered alias AND not matching with
	 * prefix of a registered GW.
	 */
	virtual BOOL CheckForIncompleteAddress(const H225_ArrayOf_AliasAddress &alias) const;

	virtual BOOL SetAlternateGK(H225_RegistrationConfirm &rcf);

	virtual BOOL ForwardRasMsg(H225_RasMessage msg); // not passed as const, ref or pointer!

	void ProcessARQ(const endptr & RequestingEP, const endptr & CalledEP, const H225_AdmissionRequest & obj_rr, H225_RasMessage & obj_rpl, BOOL bReject = FALSE);

	BOOL GKroutedSignaling;
	H225_TransportAddress GKCallSignalAddress;
	H225_TransportAddress GKRasAddress;
        
	PIPSocket::Address GKHome;
	PUDPSocket listener;

	/** this is the upd port where all requests to the alternate GK are sent to */
	PUDPSocket udpForwarding;

	SignalChannel * sigListener;

	// just pointers to global singleton objects
	RegistrationTable * EndpointTable;
	resourceManager * GKManager; 
	GkStatus * GkStatusThread;

	GkAuthenticatorList * authList;

  class Neighbor {
    public:
	Neighbor(const PString & gatekeeper, const PString & prefix);
	bool SendLRQ(int seqNum, const H225_AdmissionRequest &, H323RasSrv *) const;

    private:
	bool InternalSendLRQ(int seqNum, const H225_AdmissionRequest &, H323RasSrv *) const;

        PString m_prefix;
        PIPSocket::Address m_ip;
        WORD m_port;
  };

	list<Neighbor> NeighborsGK;

	friend class Neighbor;
	friend class PendingList;
	PendingList *arqPendingList;
};

#endif
