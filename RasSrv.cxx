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
//  990500  initial version (Xiang Ping Chen, Rajat Todi, Joe Metzger)
//  990600  ported to OpenH323 V. 1.08 (Jan Willamowius)
//  990620  bugfix for unregistration (Jan Willamowius)
//  990702  code cleanup, small fixes for compilation under Visual C++ 5 (Jan Willamowius)
//  990924  bugfix for registrations without terminalAlias (Jan Willamowius)
//  991016  clean shutdown (Jan Willamowius)
//  991027  added support for LRQ (Ashley Unitt)
//  991100  new call table (Jan Willamowius)
//  991100  status messages (Henrik Joerring)
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4800 ) // one performance warning off
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#define snprintf _snprintf
#endif

#include <ptlib.h>

#include "h323pdu.h"
#include "gk_const.h"
#include "h323util.h"
#include "gk.h"
#include "SoftPBX.h"
#include "ANSI.h"
#include "SignalChannel.h"
#include "GkStatus.h"
#include "RasSrv.h"
#include "gkauth.h"
#include "stl_supp.h"

H323RasSrv *RasThread = 0;

const char *NeighborSection = "RasSvr::Neighbors";

class PendingList {
	class PendingARQ {
	public:
		PendingARQ(int seqNum, const H225_AdmissionRequest & obj_arq, const endptr & reqEP, int nbCount)
		  : m_seqNum(seqNum), m_arq(obj_arq), m_reqEP(reqEP), m_nbCount(nbCount) {}

		bool DoACF(H323RasSrv *, const endptr &) const;
		bool DoARJ(H323RasSrv *) const;
		bool CompSeq(int seqNum) const;
		bool IsStaled(int) const;

		int DecCount() { return --m_nbCount; }

	private:
		int m_seqNum;
		H225_AdmissionRequest m_arq;
		endptr m_reqEP;
		int m_nbCount;
		PTime m_reqTime;
	};

public:
	typedef std::list<PendingARQ *>::iterator iterator;
	typedef std::list<PendingARQ *>::const_iterator const_iterator;

	PendingList(H323RasSrv *rs, int ttl) : theRasSrv(rs), pendingTTL(ttl), seqNumber(1) {}
	~PendingList();

	bool Insert(const H225_AdmissionRequest & obj_arq, const endptr & reqEP);
	void ProcessLCF(const H225_RasMessage & obj_ras);
	void ProcessLRJ(const H225_RasMessage & obj_ras);
	void Check();
	iterator FindBySeqNum(int);

private:
	H323RasSrv *theRasSrv;
	int pendingTTL;
	int seqNumber;
        list<PendingARQ *> arqList;
	PMutex usedLock;

        static void delete_arq(PendingARQ *p) { delete p; }
};

class NeighborList {
	class Neighbor {
	public:
		Neighbor(const PString & gatekeeper, const PString & prefix);
		bool SendLRQ(int seqNum, const H225_AdmissionRequest &, H323RasSrv *) const;

	private:
		bool InternalSendLRQ(int seqNum, const H225_AdmissionRequest &, H323RasSrv *) const;

		PString m_gkid;
		PString m_password;
		PString m_prefix;
		PIPSocket::Address m_ip;
		WORD m_port;
	};

public:
	typedef std::list<Neighbor>::iterator iterator;
	typedef std::list<Neighbor>::const_iterator const_iterator;

	NeighborList(H323RasSrv *, PConfig *);
	int SendLRQ(int seqNum, const H225_AdmissionRequest &);

	class InvalidNeighbor {};

private:
	list<Neighbor> nbList;
	H323RasSrv *theRasSrv;
};


inline bool PendingList::PendingARQ::DoACF(H323RasSrv *theRasSrv, const endptr & called) const
{
	theRasSrv->ReplyARQ(m_reqEP, called, m_arq);
	return true;
}

inline bool PendingList::PendingARQ::DoARJ(H323RasSrv *theRasSrv) const
{
	theRasSrv->ReplyARQ(m_reqEP, endptr(NULL), m_arq);
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

inline PendingList::~PendingList()
{
	for_each(arqList.begin(), arqList.end(), delete_arq);
}

inline PendingList::iterator PendingList::FindBySeqNum(int seqnum)
{
	return find_if(arqList.begin(), arqList.end(), bind2nd(mem_fun(&PendingARQ::CompSeq), seqnum));
}

bool PendingList::Insert(const H225_AdmissionRequest & obj_arq, const endptr & reqEP)
{
	// TODO: check if ARQ duplicate

	int nbCount = theRasSrv->GetNeighborsGK()->SendLRQ(seqNumber, obj_arq);
	if (nbCount > 0) {
		PWaitAndSignal lock(usedLock);
		arqList.push_back(new PendingARQ(seqNumber, obj_arq, reqEP, nbCount));
		++seqNumber;
		return true;
	}
	return false;
}

void PendingList::ProcessLCF(const H225_RasMessage & obj_ras)
{
	const H225_LocationConfirm & obj_lcf = obj_ras;

	// TODO: check if the LCF is sent from my neighbors
	PWaitAndSignal lock(usedLock);
	iterator Iter = FindBySeqNum(obj_lcf.m_requestSeqNum.GetValue());
	if (Iter == arqList.end()) {
		PTRACE(2, "GK\tUnknown LCF, ignore!");
		return;
	}
	endptr called = RegistrationTable::Instance()->InsertRec(const_cast<H225_RasMessage &>(obj_ras));
	if (!called) {
		PTRACE(2, "GK\tUnable to add EP for this LCF!");
		return;
	}

	(*Iter)->DoACF(theRasSrv, called);
	delete *Iter;
	arqList.erase(Iter);
}

void PendingList::ProcessLRJ(const H225_RasMessage & obj_ras)
{
	const H225_LocationReject & obj_lrj = obj_ras;

	// TODO: check if the LRJ is sent from my neighbors
	PWaitAndSignal lock(usedLock);
	iterator Iter = FindBySeqNum(obj_lrj.m_requestSeqNum.GetValue());
	if (Iter == arqList.end()) {
		PTRACE(2, "GK\tUnknown LRJ, ignore!");
		return;
	}
	if ((*Iter)->DecCount() == 0) {
		(*Iter)->DoARJ(theRasSrv);
		delete *Iter;
		arqList.erase(Iter);
	}
}

void PendingList::Check()
{
	PWaitAndSignal lock(usedLock);
	iterator Iter = find_if(arqList.begin(), arqList.end(), not1(bind2nd(mem_fun(&PendingARQ::IsStaled), pendingTTL)));
	for_each(arqList.begin(), Iter, bind2nd(mem_fun(&PendingARQ::DoARJ), theRasSrv));
	for_each(arqList.begin(), Iter, delete_arq);
	arqList.erase(arqList.begin(), Iter);
}

NeighborList::NeighborList(H323RasSrv *rs, PConfig *config) : theRasSrv(rs)
{
	PStringToString cfgs(config->GetAllKeyValues(NeighborSection));
	for (PINDEX i=0; i < cfgs.GetSize(); i++) {
		try {
			nbList.push_back(Neighbor(cfgs.GetKeyAt(i), cfgs.GetDataAt(i)));
		} catch (InvalidNeighbor) {
			PTRACE(1, "Bad neighbor " << cfgs.GetKeyAt(i));
			// ignore it :p
		}
	}
}

int NeighborList::SendLRQ(int seqNum, const H225_AdmissionRequest & obj_arq)
{
	int nbCount = 0;
	const_iterator Iter, eIter = nbList.end();
	for (Iter=nbList.begin(); Iter != eIter; ++Iter)
		if (Iter->SendLRQ(seqNum, obj_arq, theRasSrv))
			++nbCount;

	return nbCount;
}

NeighborList::Neighbor::Neighbor(const PString & gkid, const PString & cfgs) : m_gkid(gkid)
{
	PStringArray cfg(cfgs.Tokenise(",;", FALSE));
	PString ipAddr = cfg[0].Trim();
	PINDEX p = ipAddr.Find(':');
	if (!PIPSocket::GetHostAddress(ipAddr.Left(p), m_ip))
		throw InvalidNeighbor();
	m_port = (p != P_MAX_INDEX) ? ipAddr.Mid(p+1).AsUnsigned() : GK_DEF_UNICAST_RAS_PORT;
	m_prefix = (cfg.GetSize() > 1) ? cfg[1] : PString("*");
	if (cfg.GetSize() > 2)
		m_password = cfg[2];
	PTRACE(1, "Add neighbor " << m_gkid << '(' << m_ip << ':' << m_port << ") for prefix " << m_prefix);
}

bool NeighborList::Neighbor::SendLRQ(int seqNum, const H225_AdmissionRequest & obj_arq, H323RasSrv *theRasSrv) const
{
	if (m_prefix == "*")
		return InternalSendLRQ(seqNum, obj_arq, theRasSrv);

	for (PINDEX i=0; i < obj_arq.m_destinationInfo.GetSize(); ++i)
		if (AsString(obj_arq.m_destinationInfo[i], FALSE).Find(m_prefix) == 0)
			return InternalSendLRQ(seqNum, obj_arq, theRasSrv);

	return false;
}

bool NeighborList::Neighbor::InternalSendLRQ(int seqNum, const H225_AdmissionRequest & obj_arq, H323RasSrv *theRasSrv) const
{
	H225_RasMessage lrq_ras;
	lrq_ras.SetTag(H225_RasMessage::e_locationRequest);
	H225_LocationRequest & lrq_obj = lrq_ras;
	lrq_obj.m_requestSeqNum.SetValue(seqNum);
	lrq_obj.m_replyAddress = theRasSrv->GetRasAddress();
	lrq_obj.m_destinationInfo = obj_arq.m_destinationInfo;

	// tell the neighbor who I am
	lrq_obj.IncludeOptionalField(H225_LocationRequest::e_sourceInfo);
	lrq_obj.m_sourceInfo.SetSize(1);
	H323SetAliasAddress(theRasSrv->GetGKName(), lrq_obj.m_sourceInfo[0]);

	theRasSrv->SendRas(lrq_ras, m_ip, m_port);
	return true;
}

H323RasSrv::H323RasSrv(PIPSocket::Address _GKHome)
      : PThread(10000, NoAutoDeleteThread),
	listener(GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT)),
	udpForwarding()
{
	GKHome = _GKHome;
	
	EndpointTable = RegistrationTable::Instance();
	GKManager = resourceManager::Instance();

	GKroutedSignaling = FALSE;
	sigListener = NULL;

	authList = 0;
	NeighborsGK = 0;

	LoadConfig();

	udpForwarding.SetWriteTimeout(PTimeInterval(300));
 
	// we now use singelton instance mm-22.05.2001
	GkStatusThread = GkStatus::Instance();
	GkStatusThread->Initialize(_GKHome);

	arqPendingList = new PendingList(this, GkConfig()->GetInteger(NeighborSection, "NeighborTimeout", 2));
}


H323RasSrv::~H323RasSrv()
{
	delete authList;
	delete NeighborsGK;
	delete arqPendingList;
}

void H323RasSrv::LoadConfig()
{
	static PMutex loadLock;

	PWaitAndSignal lock(loadLock);
	// own IP number
	GKCallSignalAddress = SocketToH225TransportAddr(GKHome, GkConfig()->GetInteger("RouteSignalPort", GK_DEF_ROUTE_SIGNAL_PORT));
	GKRasAddress = SocketToH225TransportAddr(GKHome, GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT));

	// add authenticators
	delete authList;
	authList = new GkAuthenticatorList(GkConfig());

	// add neighbors
	delete NeighborsGK;
	NeighborsGK = new NeighborList(this, GkConfig());
}

void H323RasSrv::Close(void)
{
	PTRACE(2, "GK\tClosing RasSrv");
 
	listener.Close();
	if (GKroutedSignaling)
	{
		sigListener->Close();
		sigListener->WaitForTermination();
		delete sigListener;
		sigListener = NULL;
	};
	if (GkStatusThread != NULL)
	{
		GkStatusThread->Close();
		GkStatusThread->WaitForTermination();
		delete GkStatusThread;
		GkStatusThread = NULL;
	};
 
	PTRACE(1, "GK\tRasSrv closed");
}


void H323RasSrv::UnregisterAllEndpoints(void)
{
	SoftPBX::UnregisterAllEndpoints();
}


/* Gatekeeper request */
BOOL H323RasSrv::OnGRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_grq, H225_RasMessage & obj_rpl)
{
	const H225_GatekeeperRequest & obj_gr = obj_grq;

	BOOL bShellForwardRequest = TRUE;


	// reply only if gkID matches
	if ( obj_gr.HasOptionalField ( H225_GatekeeperRequest::e_gatekeeperIdentifier ) )
		if (obj_gr.m_gatekeeperIdentifier.GetValue() != GetGKName()) {
			PTRACE(2, "GK\tGRQ is not meant for this gatekeeper");
			return FALSE;
		}

	// mechanism 1: forwarding detection per "flag"
	if(obj_gr.HasOptionalField(H225_GatekeeperRequest::e_nonStandardData)) {
		switch(obj_gr.m_nonStandardData.m_nonStandardIdentifier.GetTag()) {
		case H225_NonStandardIdentifier::e_h221NonStandard:
			const H225_H221NonStandard &nonStandard =
				(const H225_H221NonStandard&)(obj_gr.m_nonStandardData.m_nonStandardIdentifier);
			int iec = Toolkit::Instance()->GetInternalExtensionCode(nonStandard);
			if(iec == Toolkit::iecFailoverRAS) {
				bShellForwardRequest = FALSE;
			}
		}
	}

	// mechanism 2: forwarding detection per "from"
	const PString SkipForwards = GkConfig()->GetString("SkipForwards", "");
	if (!SkipForwards)
		if (SkipForwards.Find(rx_addr.AsString()) != P_MAX_INDEX) {
			PTRACE(5, "GRQ\tWill skip forwarding GRQ to other GK.");
			bShellForwardRequest = FALSE;
		}

	PString msg;
	unsigned rsn = H225_GatekeeperRejectReason::e_securityDenial;
	if (!authList->Check(obj_gr, rsn)) {
		obj_rpl.SetTag(H225_RasMessage::e_gatekeeperReject); 
		H225_GatekeeperReject & obj_grj = obj_rpl;
		obj_grj.m_requestSeqNum = obj_gr.m_requestSeqNum;
		obj_grj.m_rejectReason.SetTag(rsn);
		obj_grj.IncludeOptionalField(obj_grj.e_gatekeeperIdentifier);
		obj_grj.m_gatekeeperIdentifier.SetValue( GetGKName() );
		msg = PString(PString::Printf, "GRJ|%s;\r\n", inet_ntoa(rx_addr));
	} else {

		obj_rpl.SetTag(H225_RasMessage::e_gatekeeperConfirm); 
		H225_GatekeeperConfirm & obj_gcf = obj_rpl;

		obj_gcf.m_requestSeqNum = obj_gr.m_requestSeqNum;
		obj_gcf.m_protocolIdentifier = obj_gr.m_protocolIdentifier;
		obj_gcf.m_nonStandardData = obj_gr.m_nonStandardData;
		obj_gcf.m_rasAddress = GKRasAddress;
		obj_gcf.IncludeOptionalField(obj_gcf.e_gatekeeperIdentifier);
		obj_gcf.m_gatekeeperIdentifier.SetValue( GetGKName() );

		PString aliasListString;
		if (obj_gr.HasOptionalField(H225_GatekeeperRequest::e_endpointAlias)) {
			aliasListString = AsString(obj_gr.m_endpointAlias);
		}
		else aliasListString = " ";

		if (bShellForwardRequest)
			ForwardRasMsg(obj_grq);

		msg = PString(PString::Printf, "GCF|%s|%s|%s;\r\n", 
			inet_ntoa(rx_addr),
			(const unsigned char *) aliasListString,
			(const unsigned char *) AsString(obj_gr.m_endpointType) );
	}

	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);
		
	return TRUE;
}

BOOL
H323RasSrv::SetAlternateGK(H225_RegistrationConfirm &rcf)
{
	PTRACE(5, ANSI::BLU << "Alternating? " << ANSI::OFF);
	BOOL result = FALSE;

	PString param = GkConfig()->GetString("AlternateGKs","");
	if(!param) {
		PTRACE(5, ANSI::BLU << "Alternating: yes, set AltGK in RCF! " << ANSI::OFF);
		result = TRUE;

        const PStringArray &altgks = param.Tokenise(" ,;\t", FALSE);
		rcf.IncludeOptionalField(H225_RegistrationConfirm::e_alternateGatekeeper);
		rcf.m_alternateGatekeeper.SetSize(altgks.GetSize());

		for(PINDEX idx=0; idx<altgks.GetSize(); idx++) {
			const PString &altgk = altgks[idx];
			const PStringArray &tokens = altgk.Tokenise(":", FALSE);

			if(tokens.GetSize() < 4) {
				PTRACE(1,"GK\tFormat error in AlternateGKs");
				continue; 
			}

			H225_AlternateGK &A = rcf.m_alternateGatekeeper[idx];
			
			const PStringArray &bytes = tokens[0].Tokenise(".", FALSE);
			if(bytes.GetSize() != 4) {
				PTRACE(1,"GK\tFormat error in AlternateGKs IP");
				continue; 
			}
			
			A.m_rasAddress.SetTag(H225_TransportAddress::e_ipAddress);
			H225_TransportAddress_ipAddress & ip = A.m_rasAddress;
			ip.m_ip.SetSize(4);
			ip.m_ip[0] = bytes[0].AsUnsigned();
			ip.m_ip[1] = bytes[1].AsUnsigned();
			ip.m_ip[2] = bytes[2].AsUnsigned();
			ip.m_ip[3] = bytes[3].AsUnsigned();
			ip.m_port  = tokens[1].AsUnsigned();
			
			A.m_needToRegister = Toolkit::AsBool(tokens[2]);
			
			A.m_priority = tokens[3].AsInteger();;
			
			if(tokens.GetSize() > 4) {
				A.IncludeOptionalField(H225_AlternateGK::e_gatekeeperIdentifier);
				A.m_gatekeeperIdentifier = tokens[4];
			}
		}
	}
	
	return result;
}


BOOL
H323RasSrv::ForwardRasMsg(H225_RasMessage msg) // not passed as const, ref or pointer!
{
	PTRACE(5, ANSI::BLU << "Forwarding? " << ANSI::OFF);
	BOOL result = FALSE;

	PString param = GkConfig()->GetString("SendTo","");
	if (!param) {
		PTRACE(5, ANSI::BLU << "Forwarding: yes! " << ANSI::OFF);
		result = TRUE;

		// include the "this is a forwared message" tag (could be a static variable to increase performance)
		H225_NonStandardParameter nonStandardParam;
		H225_NonStandardIdentifier &id = nonStandardParam.m_nonStandardIdentifier;
		id.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
		H225_H221NonStandard & h221 = id;
		h221.m_t35CountryCode   = Toolkit::t35cOpenOrg;
		h221.m_t35Extension     = Toolkit::t35eFailoverRAS;
		h221.m_manufacturerCode = Toolkit::t35mOpenOrg;
		nonStandardParam.m_data.SetSize(0);

		switch(msg.GetTag()) {
		case H225_RasMessage::e_registrationRequest: {
			H225_RegistrationRequest &o = msg;
			o.IncludeOptionalField(H225_RegistrationRequest::e_nonStandardData);
			o.m_nonStandardData = nonStandardParam;
			break;
		}
		case H225_RasMessage::e_unregistrationRequest: {
			H225_UnregistrationRequest &o = msg;
			o.IncludeOptionalField(H225_UnregistrationRequest::e_nonStandardData);
			o.m_nonStandardData = nonStandardParam;
			break;
		}
		default:
			PTRACE(2,"Warning: unsupported RAS message type for forwarding; field 'forwarded' not included in msg.");
		}
		
		// send to all
		const PStringArray &svrs = param.Tokenise(" ,;\t", FALSE);
		for(PINDEX i=0; i<svrs.GetSize(); i++) {
			const PString &svr = svrs[i];
			const PStringArray &tokens = svr.Tokenise(":", FALSE);
			if(tokens.GetSize() != 2) {
				PTRACE(1,"GK\tFormat error in Sendto");
				continue; 
			}
			PTRACE(4, ANSI::BLU << "Forwarding RRQ to " 
				   << ( (PIPSocket::Address)tokens[0] ) 
				   << ":" << ( (unsigned)(tokens[1].AsUnsigned()) ) << ANSI::OFF);
				SendReply(msg,
					  (PIPSocket::Address)tokens[0], 
					  (unsigned)(tokens[1].AsUnsigned()), 
					  udpForwarding);
		}
	}
	
	return result;
}


/* Registration Request */
BOOL H323RasSrv::OnRRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rrq, H225_RasMessage & obj_rpl)
{
	const H225_RegistrationRequest & obj_rr = obj_rrq;
	BOOL bReject = FALSE;		// RRJ with any other reason from #rejectReason#
	H225_RegistrationRejectReason rejectReason;

	PString alias;

	H225_TransportAddress SignalAdr;

	BOOL bShellSendReply = TRUE;
	BOOL bShellForwardRequest = TRUE;

	// mechanism 1: forwarding detection per "flag"
	if(obj_rr.HasOptionalField(H225_RegistrationRequest::e_nonStandardData)) {
		switch(obj_rr.m_nonStandardData.m_nonStandardIdentifier.GetTag()) {
		case H225_NonStandardIdentifier::e_h221NonStandard:
			const H225_H221NonStandard &nonStandard = 
				(const H225_H221NonStandard&)(obj_rr.m_nonStandardData.m_nonStandardIdentifier);
			int iec = Toolkit::Instance()->GetInternalExtensionCode(nonStandard);
			if(iec == Toolkit::iecFailoverRAS) {
				bShellSendReply = FALSE;
				bShellForwardRequest = FALSE;
			}
		}
	}

	// mechanism 2: forwarding detection per "from"
	const PString SkipForwards = GkConfig()->GetString("SkipForwards", "");
        if (!SkipForwards)
		if (SkipForwards.Find(rx_addr.AsString()) != P_MAX_INDEX)
		{
			PTRACE(5, "RRQ\tWill skip forwarding RRQ to other GK.");
			bShellSendReply = FALSE;
			bShellForwardRequest = FALSE;
		}

	if (obj_rr.m_callSignalAddress.GetSize() >= 1) {
		SignalAdr = obj_rr.m_callSignalAddress[0];
	} else {
		bReject = TRUE;
		rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidCallSignalAddress);
	}

	// lightweight registration update
	if (obj_rr.HasOptionalField(H225_RegistrationRequest::e_keepAlive) &&
		obj_rr.m_keepAlive.GetValue())
	{
		endptr ep = EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier);
		// check if the RRQ was sent from the registered endpoint
		if (ep && ep->GetCallSignalAddress() == SignalAdr) {
			// endpoint was already registered
			obj_rpl.SetTag(H225_RasMessage::e_registrationConfirm); 
			H225_RegistrationConfirm & rcf = obj_rpl;
			rcf.m_requestSeqNum = obj_rr.m_requestSeqNum;
			rcf.m_protocolIdentifier =  obj_rr.m_protocolIdentifier;
			rcf.m_endpointIdentifier = obj_rr.m_endpointIdentifier;
			rcf.IncludeOptionalField(rcf.e_gatekeeperIdentifier);
			rcf.m_gatekeeperIdentifier.SetValue( GetGKName() );
			if (ep->GetTimeToLive() > 0) {
				rcf.IncludeOptionalField(rcf.e_timeToLive);
				rcf.m_timeToLive = ep->GetTimeToLive();
			}

			// Alternate GKs
			SetAlternateGK(rcf);

			// forward lightweights, too
			if(bShellForwardRequest) 
				ForwardRasMsg(ep->GetCompleteRegistrationRequest());

			ep->Update(obj_rrq);
			return bShellSendReply;
		} else {
			PTRACE_IF(1, ep, "WARNING:\tPossibly endpointId collide or security attack!!");
			// endpoint was NOT registered
			bReject = TRUE;
			rejectReason.SetTag(H225_RegistrationRejectReason::e_fullRegistrationRequired);
		}
	}

	// Check if the endpoint has specified the EndpointIdentifier.
	// The GK will accept the EndpointIdentifier if
	// the EndpointIdentifier doesn't exist in the RegistrationTable,
	// or the request is sent from the original endpoint that has
	// this EndpointIdentifier. Otherwise the request will be rejected.
	if (!bReject && obj_rr.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier)) {
		endptr ep = EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier);
		if (ep && ep->GetCallSignalAddress() != SignalAdr) {
			bReject = TRUE;
			// no reason named invalidEndpointIdentifier? :(
			rejectReason.SetTag(H225_RegistrationRejectReason::e_securityDenial);
		}
	}
	
	if (!bReject) {
		if (obj_rr.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) &&
			(obj_rr.m_terminalAlias.GetSize() >= 1)) {
			const H225_ArrayOf_AliasAddress & NewAliases = obj_rr.m_terminalAlias;
			const endptr ep = EndpointTable->FindByAliases(NewAliases);
			if (ep && ep->GetCallSignalAddress() != SignalAdr) {
				bReject = TRUE;
				rejectReason.SetTag(H225_RegistrationRejectReason::e_duplicateAlias);
			}
			// reject the empty string
			for (PINDEX AliasIndex=0; AliasIndex < NewAliases.GetSize(); ++AliasIndex) {
				const PString & s = AsString(NewAliases[AliasIndex], FALSE);
				if (s.GetLength() < 1 || !(isalnum(s[0]) || s[0]=='#') ) {
					bReject = TRUE;
					rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidAlias);
				}
			}
		} else {
			// reject gw without alias
			switch (obj_rr.m_terminalType.GetTag()) {
			case H225_EndpointType::e_gatekeeper:
			case H225_EndpointType::e_gateway:
			case H225_EndpointType::e_mcu:
				bReject = TRUE;
				rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidAlias);
				break;
			/* only while debugging
			default:  
				bReject = TRUE;
				rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidAlias);
				break;
			*/
			}
		}
	}

	unsigned rsn = H225_RegistrationRejectReason::e_securityDenial;
	if (!bReject && !authList->Check(obj_rr, rsn)) {
		bReject = TRUE;
		rejectReason.SetTag(rsn);
	}

	if (!bReject) {
		// make a copy for modifying
		H225_RasMessage store_rrq = obj_rrq;

		endptr ep = EndpointTable->InsertRec(store_rrq);
		if ( ep ) {
			//	
			// OK, now send RCF
			//	
			obj_rpl.SetTag(H225_RasMessage::e_registrationConfirm); 
			H225_RegistrationConfirm & rcf = obj_rpl;
			rcf.m_requestSeqNum = obj_rr.m_requestSeqNum;
			rcf.m_protocolIdentifier =  obj_rr.m_protocolIdentifier;
			rcf.m_nonStandardData = obj_rr.m_nonStandardData;
			rcf.m_callSignalAddress.SetSize( obj_rr.m_callSignalAddress.GetSize() );
			for( PINDEX cnt = 0; cnt < obj_rr.m_callSignalAddress.GetSize(); cnt ++ )
				rcf.m_callSignalAddress[cnt] = obj_rr.m_callSignalAddress[cnt];
	
			rcf.IncludeOptionalField(H225_RegistrationConfirm::e_terminalAlias);
			rcf.m_terminalAlias = ep->GetAliases();
			rcf.m_endpointIdentifier = ep->GetEndpointIdentifier();
			rcf.IncludeOptionalField(rcf.e_gatekeeperIdentifier);
			rcf.m_gatekeeperIdentifier.SetValue( GetGKName() );
			if (ep->GetTimeToLive() > 0) {
				rcf.IncludeOptionalField(rcf.e_timeToLive);
				rcf.m_timeToLive = ep->GetTimeToLive();
			}

			// Alternate GKs
			SetAlternateGK(rcf);

			// forward heavyweight
			if(bShellForwardRequest) {
				ForwardRasMsg(store_rrq);
			}

			// Note that the terminalAlias is not optional here as we pass the auto generated alias if not were provided from
			// the endpoint itself
			PString msg(PString::Printf, "RCF|%s|%s|%s|%s;\r\n", 
				    (const unsigned char *) AsDotString(ep->GetCallSignalAddress()),
				    (const unsigned char *) AsString(rcf.m_terminalAlias),
				    (const unsigned char *) AsString(obj_rr.m_terminalType),
				    (const unsigned char *) ep->GetEndpointIdentifier().GetValue()
				    );
			PTRACE(2, msg);
			GkStatusThread->SignalStatus(msg);

			return bShellSendReply;
		} else { // Oops! Should not happen...
			bReject = TRUE;
			rejectReason.SetTag(H225_RegistrationRejectReason::e_undefinedReason);
			PTRACE(3, "Gk\tRRQAuth rejected by unknown reason " << alias);
		}
	}
	//
	// final rejection handling
	//
	obj_rpl.SetTag(H225_RasMessage::e_registrationReject); 
	H225_RegistrationReject & rrj = obj_rpl;

	rrj.m_requestSeqNum = obj_rr.m_requestSeqNum;
	rrj.m_protocolIdentifier =  obj_rr.m_protocolIdentifier;
	rrj.m_nonStandardData = obj_rr.m_nonStandardData ;
	rrj.IncludeOptionalField(rrj.e_gatekeeperIdentifier);
	rrj.m_gatekeeperIdentifier.SetValue( GetGKName() );
	rrj.m_rejectReason = rejectReason;
		
	PString aliasListString;
	if (obj_rr.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
		aliasListString = AsString(obj_rr.m_terminalAlias);
	else
		aliasListString = " ";
	
	PString msg(PString::Printf, "RRJ|%s|%s|%s|%s;\r\n", 
		    inet_ntoa(rx_addr),
		    (const unsigned char *) aliasListString,
		    (const unsigned char *) AsString(obj_rr.m_terminalType),
		    (const unsigned char *) rrj.m_rejectReason.GetTagName()
		    );
	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);
	return bShellSendReply;
}



BOOL H323RasSrv::CheckForIncompleteAddress(const H225_ArrayOf_AliasAddress & alias) const
{
	// since this routine is only called when the routing decision has been made,
	// finding a prefix that is longer than our dialled number implies the number is incomplete

	BOOL DoCheck = Toolkit::AsBool(GkConfig()->GetString
		("RasSvr::ARQ", "IncompleteAddresses", "TRUE"));

	if (!DoCheck)
		return FALSE;


	// find gateway with longest prefix matching our dialled number
	endptr GW = EndpointTable->FindByAliases(alias);

	if (!GW)
		return FALSE;
// TODO: how to port?
/*
	const PString & aliasStr = AsString (alias, FALSE);
	const PString GWAliasStr = H323GetAliasAddressString(GW->GetAliases()[0]);
	const PStringArray *prefixes = EndpointTable->GetGatewayPrefixes(GWAliasStr);


	PINDEX max = prefixes->GetSize();
	for (PINDEX i = 0; i < max; i++) {
		const PString &prefix = (*prefixes)[i];

		// is this prefix matching the dialled number and is it longer ?
		if (aliasStr.Find(prefix) == 0 && prefix.GetLength() > aliasStr.GetLength()) {
			PTRACE(4,"Gk\tConsidered to be an incomplete address: " << aliasStr << "\n" <<
				GWAliasStr << " has a longer matching prefix " << prefix);
			return TRUE;
		}
	}
*/
	return FALSE;
}


/* Admission Request */
BOOL H323RasSrv::OnARQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_arq, H225_RasMessage & obj_rpl)
{    
	const H225_AdmissionRequest & obj_rr = obj_arq;
	PTRACE(2, "GK\tOnARQ");

	BOOL bReject = FALSE;

	// find the caller
	const endptr RequestingEP = EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier);

	endptr CalledEP(NULL);

	unsigned rsn = H225_AdmissionRejectReason::e_securityDenial;
	if (!authList->Check(obj_rr, rsn)) {
		obj_rpl.SetTag(H225_RasMessage::e_admissionReject); 
		H225_AdmissionReject & arj = obj_rpl; 
 		arj.m_rejectReason.SetTag(rsn);
		bReject = TRUE;
	}
	// don't search endpoint table for an answerCall ARQ
	else if (obj_rr.m_answerCall) {
		CalledEP = RequestingEP;
	}
	else {
		// if a destination address is provided, we check if we know it
		if (obj_rr.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) 
			CalledEP = EndpointTable->FindBySignalAdr(obj_rr.m_destCallSignalAddress);
		// in routed mode, the EP may use my IP as the
		// destCallSignalAddress, thus it is possible we
		// can't find CalledEP in the RegistrationTable
		// if so, try destinationInfo
		if (!CalledEP && obj_rr.m_destinationInfo.GetSize() >= 1) {
			// apply rewrite rules
			Toolkit::Instance()->RewriteE164(obj_rr.m_destinationInfo[0]);
			CalledEP = EndpointTable->FindEndpoint(obj_rr.m_destinationInfo);
			if (!CalledEP && RequestingEP) {
				if (arqPendingList->Insert(obj_rr, RequestingEP))
					return FALSE;
			}
		}
	}

	ProcessARQ(RequestingEP, CalledEP, obj_rr, obj_rpl, bReject);
	return TRUE;
}

void H323RasSrv::ProcessARQ(const endptr & RequestingEP, const endptr & CalledEP, const H225_AdmissionRequest & obj_arq, H225_RasMessage & obj_rpl, BOOL bReject)
{
	int BWRequest = 640;

	// We use #obj_rpl# for storing information about a potential reject (e.g. the
	// rejectReason). If the request results in a confirm (bReject==FALSE) then
	// we have to ignore the previous set data in #obj_rpl# and re-cast it.
	if (obj_rpl.GetTag() != H225_RasMessage::e_admissionReject)
		obj_rpl.SetTag(H225_RasMessage::e_admissionReject); 
	H225_AdmissionReject & arj = obj_rpl; 

	// check if the endpoint requesting is registered with this gatekeeper
	if (!bReject && !RequestingEP)
	{
		bReject = TRUE;
		arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_callerNotRegistered/*was :e_invalidEndpointIdentifier*/);
	}
	
	// allow overlap sending for incomplete prefixes
	if (!CalledEP && obj_arq.m_destinationInfo.GetSize() >= 1) {
		const PString alias = AsString(obj_arq.m_destinationInfo[0], FALSE);
		if (CheckForIncompleteAddress(obj_arq.m_destinationInfo)) {
			bReject = TRUE;
			arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_incompleteAddress);
		}
	}

	if(!bReject && !CalledEP)
	{
		bReject = TRUE;
		arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_calledPartyNotRegistered);
	}

	//
	// Bandwidth 
	// and GkManager admission
	//
	if (!bReject) {
		//
		// Give bandwidth
		// 
		if (obj_arq.m_bandWidth.GetValue() < 100) {
			/* hack for Netmeeting 3.0x */
			BWRequest = std::min(1280u, GKManager->GetAvailableBW());
		}
		else {
			BWRequest = std::min(obj_arq.m_bandWidth.GetValue(), GKManager->GetAvailableBW());
		};
		PTRACE(3, "GK\tARQ will request bandwith of " << BWRequest);
		
		//
		// GkManager admission
		//
		if (!GKManager->GetAdmission(obj_arq.m_endpointIdentifier, obj_arq.m_conferenceID, BWRequest)) {
			bReject = TRUE;
			arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_resourceUnavailable);
		}
	}

#ifdef ARJREASON_ROUTECALLTOSCN
 	//
 	// call from one GW to itself? 
 	// generate ARJ-reason: 'routeCallToSCN'
 	//
 	if(!bReject && 
 	   Toolkit::AsBool(GkConfig()->GetString("RasSrv::ARQFeatures","ArjReasonRouteCallToSCN","TRUE")) ) 
 	{
 		// are the endpoints the same (GWs of course)?
 		if( (CalledEP) && (RequestingEP) && (CalledEP == RequestingEP) && 
 			(!obj_arq.m_answerCall) // only first ARQ may be rejected with with 'routeCallToSCN'
 			) 
 		{
 			// we have to extract the SCN from the destination. only EP-1 will be rejected this way
 			if ( obj_arq.m_destinationInfo.GetSize() >= 1 ) 
 			{
 				// PN will be the number that is set in the arj reason
 				H225_PartyNumber PN;
 				PN.SetTag(H225_PartyNumber::e_publicNumber);
 				H225_PublicPartyNumber &PPN = PN;
 				// set defaults
 				PPN.m_publicTypeOfNumber.SetTag(H225_PublicTypeOfNumber::e_unknown);
 				PPN.m_publicNumberDigits = "";
 				
 				// there can be diffent information in the destination info
 				switch(obj_arq.m_destinationInfo[0].GetTag()) {
 				case H225_AliasAddress::e_dialedDigits: 
 					// normal number, extract only the digits
 					PPN.m_publicNumberDigits = AsString(obj_arq.m_destinationInfo[0], FALSE);
 					break;
 				case H225_AliasAddress::e_partyNumber: 
 					// ready-to-use party number
 					PN = obj_arq.m_destinationInfo[0];
 					break;
 				default:
 					PTRACE(1,"Unsupported AliasAdress for ARQ reason 'routeCallToSCN': "
 						   << obj_arq.m_destinationInfo[0]);
 				}
 				
 				// set the ARJ reason
 				bReject = TRUE;
 				arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_routeCallToSCN);
 				H225_ArrayOf_PartyNumber &APN = arj.m_rejectReason;
 				APN.SetSize(1);
 				APN[0] = PN;
 			}
 			else { 
 				// missing destination info. is this possible at this point?
 			}
 		}
 	}
 	//:towi
#endif
	
	//
	// Do the reject or the confirm
	//
	PString srcInfoString = (RequestingEP) ? AsDotString(RequestingEP->GetCallSignalAddress()) : PString(" ");
	PString destinationInfoString = (obj_arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)) ?
		AsString(obj_arq.m_destinationInfo) : PString("unknown");
	if (bReject)
	{
		arj.m_requestSeqNum = obj_arq.m_requestSeqNum;

		PString destinationInfoString;
		if (obj_arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
			destinationInfoString = AsString(obj_arq.m_destinationInfo);
		else
			destinationInfoString = " ";

		PString msg(PString::Printf, "ARJ|%s|%s|%s|%s|%s;\r\n", 
			    (const unsigned char *) srcInfoString,
			    (const unsigned char *) destinationInfoString,
			    (const unsigned char *) AsString(obj_arq.m_srcInfo),
			    (obj_arq.m_answerCall) ? "true" : "false",
			    (const unsigned char *) arj.m_rejectReason.GetTagName() );
		PTRACE(2,msg);
		GkStatusThread->SignalStatus(msg);
	}   
	else
	{
		// new connection admitted
		obj_rpl.SetTag(H225_RasMessage::e_admissionConfirm); // re-cast (see above)
		H225_AdmissionConfirm & acf = obj_rpl;

		acf.m_requestSeqNum = obj_arq.m_requestSeqNum;
		acf.m_bandWidth = BWRequest;

		// CallRecs should be looked for using callIdentifier instead of callReferenceValue
		// callIdentifier is globally unique, callReferenceValue is just unique per-endpoint.
		callptr pExistingCallRec = (obj_arq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier)) ?
			CallTable::Instance()->FindCallRec(obj_arq.m_callIdentifier) :
		// since callIdentifier is optional, we might have to look for the callReferenceValue as well
			CallTable::Instance()->FindCallRec(obj_arq.m_callReferenceValue);

		if (pExistingCallRec) {
			if (obj_arq.m_answerCall) // the second ARQ
				pExistingCallRec->SetCalled(CalledEP, obj_arq.m_callReferenceValue);
			// else this may be a duplicate ARQ, ignore!
			PTRACE(3, "Gk\tACF: found existing call no " << pExistingCallRec->GetCallNumber());
		} else {
			// the call is not in the table
			CallRec *pCallRec = new CallRec(obj_arq.m_callIdentifier, obj_arq.m_conferenceID, destinationInfoString, BWRequest);
			int timeout = GkConfig()->GetInteger("CallTable", "DefaultCallTimeout", 0);
			pCallRec->SetTimer(timeout);
			pCallRec->StartTimer();

			pCallRec->SetCalled(CalledEP, obj_arq.m_callReferenceValue);
			if (!obj_arq.m_answerCall) // the first ARQ
				pCallRec->SetCalling(RequestingEP, obj_arq.m_callReferenceValue);
			if (!GKroutedSignaling)
				pCallRec->SetConnected(true);
			CallTable::Instance()->Insert(pCallRec);
		}
			
		if ( GKroutedSignaling ) {
/* comment out by cwhuang
   Does it have any difference from direct model?
			H225_TransportAddress destAddress;
			  // in routed mode we only use aliases
			  // we can't redirect absolut callSignalladdresses right now
			  // if that were desired, we'd have to add a list with the callRef and
			  // the callSignallAddress from the ARQ, to create the new proper
			  // connection on SETUP
			destAddress = CalledEP->GetCallSignalAddress();

			pExistingCallRec = (CallRec *)CallTable::Instance()->FindCallRec (obj_arq.m_callIdentifier);
			if (pExistingCallRec != NULL)
			{
				pExistingCallRec->Called->m_callReference.SetValue(obj_arq.m_callReferenceValue);
				pExistingCallRec->Calling->m_callReference.SetValue(obj_arq.m_callReferenceValue);
				pExistingCallRec->m_callIdentifier = obj_arq.m_callIdentifier;
			}
			else
			{
				// add the new call to global table
				EndpointCallRec Calling(RequestingEP->GetCallSignalAddress(), RequestingEP->GetRasAddress(), obj_arq.m_callReferenceValue);
				EndpointCallRec Called(CalledEP->GetCallSignalAddress(), CalledEP->GetRasAddress(), 0);
				PString destinationInfoString = "unknown";
				if (obj_arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
					destinationInfoString = AsString(obj_arq.m_destinationInfo);
				CallTable::Instance()->Insert(Calling, Called, BWRequest, obj_arq.m_callIdentifier, obj_arq.m_conferenceID, destinationInfoString);
			};
*/
			acf.m_callModel.SetTag( H225_CallModel::e_gatekeeperRouted );
			acf.m_destCallSignalAddress = GKCallSignalAddress;
		} else {
			// direct signalling

			// Set ACF fields
			acf.m_callModel.SetTag( H225_CallModel::e_direct );
			if( obj_arq.HasOptionalField( H225_AdmissionRequest::e_destCallSignalAddress) )
				acf.m_destCallSignalAddress = obj_arq.m_destCallSignalAddress;
			else
				acf.m_destCallSignalAddress = CalledEP->GetCallSignalAddress();
		}

		acf.IncludeOptionalField ( H225_AdmissionConfirm::e_irrFrequency );
		acf.m_irrFrequency.SetValue( 120 );

		PString destinationInfoString = "unknown destination alias";
		if (obj_arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
			destinationInfoString = AsString(obj_arq.m_destinationInfo);
		else if (obj_arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
			H225_TransportAddress DestSignalAdr = obj_arq.m_destCallSignalAddress;
			const endptr pEPRec = EndpointTable->FindBySignalAdr(DestSignalAdr);
			if (pEPRec)
				destinationInfoString = AsString(pEPRec->GetAliases());
		}

		// always signal ACF
		PString msg(PString::Printf, "ACF|%s|%s|%u|%s|%s;\r\n", 
				(const unsigned char *) srcInfoString,
				(const unsigned char *) RequestingEP->GetEndpointIdentifier().GetValue(),
				(unsigned) obj_arq.m_callReferenceValue,
				(const unsigned char *) destinationInfoString,
				(const unsigned char *) AsString(obj_arq.m_srcInfo)
				);
		PTRACE(2, msg);
		GkStatusThread->SignalStatus(msg);
		
	}
}

void H323RasSrv::ReplyARQ(const endptr & RequestingEP, const endptr & CalledEP, const H225_AdmissionRequest & obj_arq)
{
	H225_RasMessage obj_rpl;
	if (!RequestingEP) {
		PTRACE(1, "Err: call ReplyARQ without RequestingEP!");
		return;
	}
	if (RequestingEP->GetRasAddress().GetTag() != H225_TransportAddress::e_ipAddress) {
		PTRACE(1, "Err: RequestingEP doesn't have valid ras address!");
		return;
	}
	ProcessARQ(RequestingEP, CalledEP, obj_arq, obj_rpl);

	const H225_TransportAddress_ipAddress & ip = RequestingEP->GetRasAddress();
	PIPSocket::Address ipaddress(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
	SendReply(obj_rpl, ipaddress, ip.m_port, listener);
}

/* Disengage Request */
BOOL H323RasSrv::OnDRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_drq, H225_RasMessage & obj_rpl)
{    
	const H225_DisengageRequest & obj_rr = obj_drq;

	char callReferenceValueString[8];
	sprintf(callReferenceValueString, "%u", (unsigned) obj_rr.m_callReferenceValue);
		
//	PTRACE(4,"DRQ");
	PString msg;
	
	if ( GKManager->CloseConference(obj_rr.m_endpointIdentifier, obj_rr.m_conferenceID) )
	{
		PTRACE(4,"\tDRQ: closed conference");
		obj_rpl.SetTag(H225_RasMessage::e_disengageConfirm); 
		H225_DisengageConfirm & dcf = obj_rpl;
		dcf.m_requestSeqNum = obj_rr.m_requestSeqNum;    

		if ( GKroutedSignaling )
		{
//			sigListener->m_callTable.HungUp(obj_rr.m_callReferenceValue);
			CallTable::Instance()->RemoveCall(obj_rr);
		} else {
			// I do not know if more is to be done - if not then the routing type check is obsolete
			CallTable::Instance()->RemoveCall(obj_rr);
		}
		PTRACE(4,"\tDRQ: removed first endpoint");

		// always signal DCF
		PString msg2(PString::Printf, "DCF|%s|%s|%s|%s;\r\n", 
				 inet_ntoa(rx_addr),
				 (const unsigned char *) obj_rr.m_endpointIdentifier.GetValue(),
				 callReferenceValueString,
				 (const unsigned char *) obj_rr.m_disengageReason.GetTagName() );	
		msg = msg2;
	}
	// The first EP that sends DRQ closes the conference and removes the CallTable entry -
	// this should not exclude the second one
	// from receiving DCF. This way we will not catch stray DRQs but we send the right messages ourselves
	else if (EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier))
	{
		PTRACE(4,"\tDRQ: endpoint found");
		obj_rpl.SetTag(H225_RasMessage::e_disengageConfirm); 
		H225_DisengageConfirm & dcf = obj_rpl;
		dcf.m_requestSeqNum = obj_rr.m_requestSeqNum;

		CallTable::Instance()->RemoveCall(obj_rr);

		PTRACE(4,"\tDRQ: removed second endpoint");

		// always signal DCF
		PString msg2(PString::Printf, "DCF|%s|%s|%s|%s;\r\n", 
				 inet_ntoa(rx_addr),
				 (const unsigned char *) obj_rr.m_endpointIdentifier.GetValue(),
				 callReferenceValueString,
				 (const unsigned char *) obj_rr.m_disengageReason.GetTagName() );	
		msg = msg2;
	}
	else
	{
		PTRACE(4,"\tDRQ: reject");
		obj_rpl.SetTag(H225_RasMessage::e_disengageReject); 
		H225_DisengageReject & drj = obj_rpl;
		drj.m_requestSeqNum = obj_rr.m_requestSeqNum;
		drj.m_rejectReason.SetTag( drj.m_rejectReason.e_notRegistered );

		PString msg2(PString::Printf, "DRJ|%s|%s|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) obj_rr.m_endpointIdentifier.GetValue(),
			     callReferenceValueString,
			     (const unsigned char *) drj.m_rejectReason.GetTagName() );
		msg = msg2;
	}

	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);
	return TRUE;
}


/* Unregistration Request */
BOOL H323RasSrv::OnURQ(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_urq, H225_RasMessage &obj_rpl)
{ 
	const H225_UnregistrationRequest & obj_rr = obj_urq;
	PString msg;

	BOOL bShellSendReply = TRUE;
	BOOL bShellForwardRequest = TRUE;

	// mechanism 1: forwarding detection per "flag"
	if(obj_rr.HasOptionalField(H225_UnregistrationRequest::e_nonStandardData)) {
		switch(obj_rr.m_nonStandardData.m_nonStandardIdentifier.GetTag()) {
		case H225_NonStandardIdentifier::e_h221NonStandard:
			const H225_H221NonStandard &nonStandard = 
				(const H225_H221NonStandard&)(obj_rr.m_nonStandardData.m_nonStandardIdentifier);
			int iec = Toolkit::Instance()->GetInternalExtensionCode(nonStandard);
			if(iec == Toolkit::iecFailoverRAS) {
				bShellSendReply = FALSE;
				bShellForwardRequest = FALSE;
			}
		}
	}
	// mechanism 2: forwarding detection per "from"
	const PString addr = rx_addr;
	const PString SkipForwards = GkConfig()->GetString("SkipForwards", "");
	if (!SkipForwards)
		if (SkipForwards.Find(rx_addr.AsString()) != P_MAX_INDEX) {
			PTRACE(5, "RRQ\tWill skip forwarding RRQ to other GK.");
			bShellSendReply = FALSE;
			bShellForwardRequest = FALSE;
		}

	endptr ep = EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier);
	if (ep)
	{
		// Disconnect the calls of the endpoint
		SoftPBX::DisconnectEndpoint(ep);
		// Remove from the table
		EndpointTable->RemoveByEndpointId(obj_rr.m_endpointIdentifier);

		// Return UCF
		obj_rpl.SetTag(H225_RasMessage::e_unregistrationConfirm);
		H225_UnregistrationConfirm & ucf = obj_rpl;
		ucf.m_requestSeqNum = obj_rr.m_requestSeqNum;
		ucf.m_nonStandardData = obj_rr.m_nonStandardData;

		PString endpointIdentifierString;
		if (obj_rr.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier))
			endpointIdentifierString = obj_rr.m_endpointIdentifier.GetValue();
		else
			endpointIdentifierString = " ";

		PString msg2(PString::Printf, "UCF|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) endpointIdentifierString) ;
		msg = msg2;
	}
	else
	{
		// Return URJ	
		obj_rpl.SetTag(H225_RasMessage::e_unregistrationReject);
		H225_UnregistrationReject & urj = obj_rpl;
		urj.m_requestSeqNum = obj_rr.m_requestSeqNum;
		urj.m_nonStandardData = obj_rr.m_nonStandardData ;
		urj.m_rejectReason.SetTag(H225_UnregRejectReason::e_notCurrentlyRegistered);

		PString endpointIdentifierString;
		if (obj_rr.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier))
			endpointIdentifierString = obj_rr.m_endpointIdentifier.GetValue();
		else
			endpointIdentifierString = " ";

		PString msg2(PString::Printf, "URJ|%s|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) endpointIdentifierString,
			     (const unsigned char *) urj.m_rejectReason.GetTagName() );
		msg = msg2;
	}

	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);

	if(bShellForwardRequest) 
		ForwardRasMsg(obj_urq);

	return bShellSendReply;
}


/* Information Request Response */
BOOL H323RasSrv::OnIRR(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &obj_rpl)
{ 
	const H225_InfoRequestResponse & obj_irr = obj_rr;

	if (endptr ep = EndpointTable->FindByEndpointId(obj_irr.m_endpointIdentifier)) {
		ep->Update(obj_rr);
		if (obj_irr.HasOptionalField( H225_InfoRequestResponse::e_needResponse )) {
			obj_rpl.SetTag(H225_RasMessage::e_infoRequestAck);
			H225_InfoRequestAck & ira = obj_rpl;
			ira.m_requestSeqNum = obj_irr.m_requestSeqNum;
			ira.m_nonStandardData = obj_irr.m_nonStandardData;

			PString msg(PString::Printf, "IRR|%s;\r\n", inet_ntoa(rx_addr) );
			PTRACE(2,msg);
			GkStatusThread->SignalStatus(msg);
			return TRUE;
		}
	}
	// otherwise don't respond
	return FALSE;
}


/* Bandwidth Request */
BOOL H323RasSrv::OnBRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &obj_rpl)
{ 
	const H225_BandwidthRequest & obj_brq = obj_rr;

	obj_rpl.SetTag(H225_RasMessage::e_bandwidthConfirm);
	H225_BandwidthConfirm & bcf = obj_rpl;
	bcf.m_requestSeqNum = obj_brq.m_requestSeqNum;
	/* for now we grant whatever bandwidth was requested */
	if (obj_brq.m_bandWidth.GetValue() < 100)
	{
		/* hack for Netmeeting 3.0 */
		bcf.m_bandWidth.SetValue ( 1280 );
	}
	else
	{
		/* otherwise grant what was asked for */
		bcf.m_bandWidth = obj_brq.m_bandWidth;
	};
	bcf.m_nonStandardData = obj_brq.m_nonStandardData;

	PString msg(PString::Printf, "BCF|%s|%s|%u;\r\n", 
		    inet_ntoa(rx_addr),
		    (const unsigned char *) obj_brq.m_endpointIdentifier.GetValue(),
		    bcf.m_bandWidth.GetValue() );
	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);

	return TRUE;
}


/* Location Request */
BOOL H323RasSrv::OnLRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &obj_rpl)
{ 
	const H225_LocationRequest & obj_lrq = obj_rr;

	endptr WantedEndPoint;

	PString msg;

	// TODO: we should really send the reply to the reply address
	//       we should modify the rx_addr

	Toolkit::Instance()->RewriteE164(obj_lrq.m_destinationInfo[0]);
	unsigned rsn;
	if (authList->Check(obj_lrq, rsn) &&
		// only search registered endpoints
		(WantedEndPoint = EndpointTable->FindEndpoint(obj_lrq.m_destinationInfo, false))) {
		// Alias found
		obj_rpl.SetTag(H225_RasMessage::e_locationConfirm);
		H225_LocationConfirm & lcf = obj_rpl;
		lcf.m_requestSeqNum = obj_lrq.m_requestSeqNum;
		lcf.IncludeOptionalField(H225_LocationConfirm::e_nonStandardData);
		lcf.m_nonStandardData = obj_lrq.m_nonStandardData;

		WantedEndPoint->BuildLCF(obj_rpl);

		PString sourceInfoString;
		if (obj_lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)) {
			sourceInfoString = AsString(obj_lrq.m_sourceInfo);
		}
		else
			sourceInfoString = " ";

		msg = PString(PString::Printf, "LCF|%s|%s|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) WantedEndPoint->GetEndpointIdentifier().GetValue(),
			     (const unsigned char *) AsString(obj_lrq.m_destinationInfo),
			     (const unsigned char *) sourceInfoString);
	} else {
		// Alias not found
		obj_rpl.SetTag(H225_RasMessage::e_locationReject);
		H225_LocationReject & lrj = obj_rpl;
		lrj.m_requestSeqNum = obj_lrq.m_requestSeqNum;
		lrj.m_rejectReason.SetTag(H225_LocationRejectReason::e_requestDenied); // can't find the location
		lrj.IncludeOptionalField(H225_LocationReject::e_nonStandardData);
		lrj.m_nonStandardData = obj_lrq.m_nonStandardData;

		PString sourceInfoString;
		if (obj_lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo))
			sourceInfoString = AsString(obj_lrq.m_sourceInfo);
		else
			sourceInfoString = " ";

		msg = PString(PString::Printf, "LRJ|%s|%s|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) AsString(obj_lrq.m_destinationInfo),
			     (const unsigned char *) sourceInfoString,
			     (const unsigned char *) lrj.m_rejectReason.GetTagName() );
	}

	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);

	return TRUE;
}

/* Location Confirm */
BOOL H323RasSrv::OnLCF(const PIPSocket::Address &, const H225_RasMessage &obj_rr, H225_RasMessage &)
{
	arqPendingList->ProcessLCF(obj_rr);
	return FALSE;
}

/* Location Reject */
BOOL H323RasSrv::OnLRJ(const PIPSocket::Address &, const H225_RasMessage &obj_rr, H225_RasMessage &)
{
	arqPendingList->ProcessLRJ(obj_rr);
	return FALSE;
}

/* Resource Availability Indicate */
BOOL H323RasSrv::OnRAI(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &obj_rpl)
{ 
	const H225_ResourcesAvailableIndicate & obj_rai = obj_rr;

	/* accept all RAIs */
	obj_rpl.SetTag(H225_RasMessage::e_resourcesAvailableConfirm);
	H225_ResourcesAvailableConfirm & rac = obj_rpl;
	rac.m_requestSeqNum = obj_rai.m_requestSeqNum;
	rac.m_protocolIdentifier =  obj_rai.m_protocolIdentifier;
	rac.m_nonStandardData = obj_rai.m_nonStandardData;
    
	return TRUE;
}

bool H323RasSrv::Check()
{
	arqPendingList->Check();
	return !IsTerminated();
}

void H323RasSrv::SendRas(const H225_RasMessage & obj_ras, const H225_TransportAddress & dest)
{
	if (dest.GetTag() != H225_TransportAddress::e_ipAddress) {
		PTRACE(3, "No IP address to send!" );
		return;
	}

	const H225_TransportAddress_ipAddress & ip = dest;
	PIPSocket::Address ipaddress(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);

	SendReply(obj_ras, ipaddress, ip.m_port, listener);
}

void H323RasSrv::SendRas(const H225_RasMessage & obj_ras, const PIPSocket::Address & rx_addr, WORD rx_port)
{
	SendReply(obj_ras, rx_addr, rx_port, listener);
}

void H323RasSrv::SendReply(const H225_RasMessage & obj_rpl, const PIPSocket::Address & rx_addr, WORD rx_port, PUDPSocket & BoundSocket)
{
	PBYTEArray wtbuf(4096);
	PPER_Stream wtstrm(wtbuf);

	obj_rpl.Encode(wtstrm);
	wtstrm.CompleteEncoding();
	PTRACE(2, "GK\tSend to "<< rx_addr << " [" << rx_port << "] : " << obj_rpl.GetTagName());
	PTRACE(3, "GK\t" << endl << setprecision(2) << obj_rpl);

	PWaitAndSignal lock(writeMutex);
	if(! BoundSocket.WriteTo(wtstrm.GetPointer(), wtstrm.GetSize(), rx_addr, rx_port) ) {
		PTRACE(4, "GK\tRAS thread: Write error: " << BoundSocket.GetErrorText());
	} else {
		PTRACE(5, "GK\tSent Successful");
	}
}


void H323RasSrv::Main(void)
{
	PString err_msg("ERROR: Request received by gatekeeper: ");   
	PTRACE(2, "GK\tEntering connection handling loop");

	if (GKroutedSignaling)
		sigListener = new SignalChannel(1000, GKHome, GkConfig()->GetInteger("RouteSignalPort", GK_DEF_ROUTE_SIGNAL_PORT));
	listener.Listen(GKHome, 
			GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH), 
			listener.GetPort(), 
			PSocket::CanReuseAddress);
	if (!listener.IsOpen())
	{
		PTRACE(1,"GK\tBind to RAS port failed!");
	}

	while (listener.IsOpen())
	{ 
		WORD rx_port;
		PIPSocket::Address rx_addr;
		H225_RasMessage obj_req;   
		H225_RasMessage obj_rpl;
		BOOL ShallSendReply = FALSE;
		PBYTEArray rdbuf(4096);
		PPER_Stream rdstrm(rdbuf);

		int iResult = listener.ReadFrom(rdstrm.GetPointer(), rdstrm.GetSize(), rx_addr, rx_port);
		if (!iResult)
		{
			PTRACE(1, "GK\tRAS thread: Read error: " << listener.GetErrorText());

			// TODO: "return" (terminate) on some errors (like the one at shutdown)
			continue;
		}
		PTRACE(2, "GK\tRead from : " << rx_addr << " [" << rx_port << "]");    
    
		if (!obj_req.Decode( rdstrm ))
		{
			PTRACE(1, "GK\tCouldn't decode message!");

			continue;
		}
		
		PTRACE(3, "GK\t" << endl << setprecision(2) << obj_req);
 
		switch (obj_req.GetTag())
		{
		case H225_RasMessage::e_gatekeeperRequest:    
			PTRACE(1, "GK\tGRQ Received");
			ShallSendReply = OnGRQ( rx_addr, obj_req, obj_rpl );
			break;
			
		case H225_RasMessage::e_registrationRequest:    
			PTRACE(1, "GK\tRRQ Received");
			ShallSendReply = OnRRQ( rx_addr, obj_req, obj_rpl );
			break;
			
		case H225_RasMessage::e_unregistrationRequest :
			PTRACE(1, "GK\tURQ Received");
			ShallSendReply = OnURQ( rx_addr, obj_req, obj_rpl );
			break;
			
		case H225_RasMessage::e_admissionRequest :
			PTRACE(1, "GK\tARQ Received");
			ShallSendReply = OnARQ( rx_addr, obj_req, obj_rpl );
			break;
    
		case H225_RasMessage::e_bandwidthRequest :
			PTRACE(1, "GK\tBRQ Received");
			ShallSendReply = OnBRQ( rx_addr, obj_req, obj_rpl );
			break;
    
		case H225_RasMessage::e_disengageRequest :
			PTRACE(1, "GK\tDRQ Received");
			ShallSendReply = OnDRQ( rx_addr, obj_req, obj_rpl );
			break;
    
		case H225_RasMessage::e_locationRequest :
			PTRACE(1, "GK\tLRQ Received");
			ShallSendReply = OnLRQ( rx_addr, obj_req, obj_rpl );
			break;
    
		case H225_RasMessage::e_locationConfirm :
			PTRACE(1, "GK\tLCF Received");
			ShallSendReply = OnLCF( rx_addr, obj_req, obj_rpl );
			break;

		case H225_RasMessage::e_locationReject :
			PTRACE(1, "GK\tLRJ Received");
			ShallSendReply = OnLRJ( rx_addr, obj_req, obj_rpl );
			break;

		case H225_RasMessage::e_infoRequestResponse :
			PTRACE(1, "GK\tIRR Received");
			ShallSendReply = OnIRR( rx_addr, obj_req, obj_rpl );
			break;
    
		case H225_RasMessage::e_resourcesAvailableIndicate :
			PTRACE(1, "GK\tRAI Received");
			ShallSendReply = OnRAI( rx_addr, obj_req, obj_rpl );
			break;

		// we case safely ignore these messages and don't have to act upon them
		case H225_RasMessage::e_unregistrationConfirm :		// happens when gk actively tries to unregister URQ
		case H225_RasMessage::e_unregistrationReject :		// happens when gk actively tries to unregister URQ
		case H225_RasMessage::e_bandwidthConfirm :
		case H225_RasMessage::e_bandwidthReject :
			PTRACE(2, "GK\t" << obj_req.GetTagName() << " received and safely ignored");
			break;


		// handling these is optional (action only necessary once we send GRQs)
		case H225_RasMessage::e_nonStandardMessage :
			PTRACE(2, "GK\t" << err_msg << obj_req.GetTagName());
			break;
    
		// handling these messages is _mandatory_ ! (no action necessary)
		case H225_RasMessage::e_disengageConfirm :			// happens eg. when gk tries to force call termination with DRQ
		case H225_RasMessage::e_disengageReject :			// happens eg. when gk tries to force call termination with DRQ
			PTRACE(2, "GK\t" << obj_req.GetTagName() << " received and safely ignored");
			break;
    
		// handling this message is _mandatory_ !!  (any action necessary ??)
		case H225_RasMessage::e_unknownMessageResponse :
			PTRACE(1, "GK\tUnknownMessageResponse received - no action");
			break;
			
		default:
			PTRACE(1, "GK\tUnknown RAS message received");
			break;      
		}

		if (ShallSendReply)
			SendReply( obj_rpl, rx_addr, rx_port, listener );
	}
	PTRACE(1,"GK\tRasThread terminated!");
}

