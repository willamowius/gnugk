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

#include <ptlib.h>
#include <ptlib/sockets.h>
#include "h225.h" 
#include "Toolkit.h"
#include "RasTbl.h"
#include "h323util.h"
#include "GkAuthorize.h"
#include "stl_supp.h"

// forward references to avoid includes

class HandlerList;
class GkStatus;
class GkAuthenticatorList;
class GkDestAnalysisList;
class NeighborList;
class PendingList;
class NBPendingList;
class GkClient;

class H323RasSrv : public PThread {
public:

	PCLASSINFO(H323RasSrv, PThread)

	H323RasSrv(PIPSocket::Address GKHome);
	virtual ~H323RasSrv();

	void Close(void);

	void Main(void);  // original HandleConnections(); 

	void UnregisterAllEndpoints(void);

	// set routed method
	void SetRoutedMode(bool routedSignaling, bool routedH245);
	// set routed according to the config file
	void SetRoutedMode();

	// set name of the gatekeeper.
	const PString GetGKName() const { return Toolkit::GKName(); }

	typedef BOOL (H323RasSrv::*OnRAS)(const PIPSocket::Address &, const H225_RasMessage &, H225_RasMessage &);

	// Deal with GRQ. obj_grq is the incoming RAS GRQ msg, and obj_rpl is the
	// GCF or GRJ Ras msg.
	BOOL OnGRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_grq, H225_RasMessage & obj_rpl);

	BOOL OnGCF(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_gcf, H225_RasMessage & obj_rpl);

	BOOL OnGRJ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_grj, H225_RasMessage & obj_rpl);

	BOOL OnRRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rrq, H225_RasMessage & obj_rpl);

	BOOL OnRCF(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rcf, H225_RasMessage & obj_rpl);

	BOOL OnRRJ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rrj, H225_RasMessage & obj_rpl);

	BOOL OnURQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_urq, H225_RasMessage & obj_rpl);

	BOOL OnARQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_arq, H225_RasMessage & obj_rpl);

	BOOL OnACF(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_acf, H225_RasMessage & obj_rpl);

	BOOL OnARJ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_arj, H225_RasMessage & obj_rpl);

	BOOL OnDRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_drq, H225_RasMessage & obj_rpl);

	BOOL OnIRR(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);

	BOOL OnBRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);

	BOOL OnLRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);

	BOOL OnLCF(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);
      
	BOOL OnLRJ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);
      
	BOOL OnRAI(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl);

	BOOL OnIgnored(const PIPSocket::Address &, const H225_RasMessage &, H225_RasMessage &);

	BOOL OnUnknown(const PIPSocket::Address &, const H225_RasMessage &, H225_RasMessage &);
      
	void ReplyARQ(const endptr & RequestingEP, const endptr & CalledEP, const H225_AdmissionRequest & obj_arq);

	void SendRas(const H225_RasMessage & obj_ras, const H225_TransportAddress & dest);

	void SendRas(const H225_RasMessage & obj_ras, const PIPSocket::Address & rx_addr, WORD rx_port);

	void SendReply(const H225_RasMessage & obj_rpl, const PIPSocket::Address & rx_addr, WORD rx_port, PUDPSocket & BoundSocket);

	bool Check();
	bool IsGKRouted() const { return GKRoutedSignaling; }
	bool IsGKRoutedH245() const { return GKRoutedH245; }

	bool AcceptUnregisteredCalls(PIPSocket::Address, bool & fromParent) const;

	void LoadConfig();

	const H225_TransportAddress GetRasAddress(PIPSocket::Address) const;
	const H225_TransportAddress GetCallSignalAddress(PIPSocket::Address) const;

	GkClient * GetGkClient() const { return gkClient; }
	NeighborList * GetNeighborsGK() const { return NeighborsGK; }
	bool SendLRQ(const H225_AdmissionRequest &, const endptr &);

	WORD GetRequestSeqNum() { return ++requestSeqNum; }

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
	bool GKRoutedSignaling, GKRoutedH245, AcceptNBCalls, AcceptUnregCalls;
	WORD GKRasPort, GKCallSigPort;
        
	PIPSocket::Address GKHome;
	PUDPSocket listener;
	PMutex writeMutex, loadLock;

	/** this is the upd port where all requests to the alternate GK are sent to */
	PUDPSocket udpForwarding;

	HandlerList * sigHandler;

	// just pointers to global singleton objects
	RegistrationTable * EndpointTable;
	CallTable * CallTbl; 
	GkStatus * GkStatusThread;

	GkClient * gkClient;
	GkAuthenticatorList * authList;
	GkDestAnalysisList * destAnalysisList;

	NeighborList * NeighborsGK;
	NBPendingList * arqPendingList;
	
	GkAuthorize* GWR;

	OnRAS rasHandler[H225_RasMessage::e_serviceControlResponse + 1];

	WORD requestSeqNum;
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

class PendingList {
protected:
	class PendingARQ {
	public:
		PendingARQ(int, const H225_AdmissionRequest &, const endptr &, int);

		bool DoACF(H323RasSrv *, const endptr &) const;
		bool DoARJ(H323RasSrv *) const;
		bool CompSeq(int seqNum) const;
		bool IsStaled(int) const;
		void GetRequest(H225_AdmissionRequest &, endptr &) const;

		int DecCount();

	private:
		int m_seqNum;
		H225_AdmissionRequest m_arq;
		endptr m_reqEP;
		int m_Count;
		PTime m_reqTime;
	};

public:
	typedef std::list<PendingARQ *>::iterator iterator;
	typedef std::list<PendingARQ *>::const_iterator const_iterator;

	PendingList(H323RasSrv *rs, int ttl) : RasSrv(rs), pendingTTL(ttl) {}
	~PendingList();

	void Check();
	iterator FindBySeqNum(int);
	void Remove(iterator);

protected:
	H323RasSrv *RasSrv;
	int pendingTTL;
        list<PendingARQ *> arqList;
	PMutex usedLock;

        static void delete_arq(PendingARQ *p) { delete p; }
};

inline PendingList::PendingARQ::PendingARQ(int seqNum, const H225_AdmissionRequest & obj_arq, const endptr & reqEP, int Count)
      : m_seqNum(seqNum), m_arq(obj_arq), m_reqEP(reqEP), m_Count(Count)
{
}

inline bool PendingList::PendingARQ::DoACF(H323RasSrv *RasSrv, const endptr & called) const
{
	RasSrv->ReplyARQ(m_reqEP, called, m_arq);
	return true;
}

inline bool PendingList::PendingARQ::DoARJ(H323RasSrv *RasSrv) const
{
	RasSrv->ReplyARQ(m_reqEP, endptr(NULL), m_arq);
	return true;
}

inline bool PendingList::PendingARQ::CompSeq(int seqNum) const
{
	return (m_seqNum == seqNum);
}

inline bool PendingList::PendingARQ::IsStaled(int sec) const
{
	return (PTime() - m_reqTime) > sec*1000;
}

inline void PendingList::PendingARQ::GetRequest(H225_AdmissionRequest & arq, endptr & ep) const
{
	arq = m_arq, ep = m_reqEP;
}

inline int PendingList::PendingARQ::DecCount()
{
	return --m_Count;
}

inline PendingList::~PendingList()
{
	for_each(arqList.begin(), arqList.end(), delete_arq);
}

inline PendingList::iterator PendingList::FindBySeqNum(int seqnum)
{
	return find_if(arqList.begin(), arqList.end(), bind2nd(mem_fun(&PendingARQ::CompSeq), seqnum));
}

inline void PendingList::Remove(iterator Iter)
{
	delete *Iter;
	arqList.erase(Iter);
}

extern H323RasSrv *RasThread;  // I hate global object, but...

#endif
