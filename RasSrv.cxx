// -*- mode: c++; eval: (c-set-style "linux"); -*-
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

#include "RasSrv.h"
#include "h323pdu.h"
#include "gk_const.h"
#include "gk.h"
#include "SoftPBX.h"
#include "ANSI.h"
#include "GkStatus.h"
#include "GkClient.h"
#include "ProxyThread.h"
#include "gkauth.h"
#include "gkDatabase.h"
#include "gkDestAnalysis.h"

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = RASSRV_H;
#endif /* lint */

H323RasSrv *RasThread = 0;

const char *NeighborSection = "RasSvr::Neighbors";
const char *LRQFeaturesSection = "RasSvr::LRQFeatures";

class NBPendingList : public PendingList {
public:
	NBPendingList(H323RasSrv *rs, int ttl) : PendingList(rs, ttl) {}
	bool Insert(const H225_AdmissionRequest & obj_arq, const endptr & reqEP);
	void ProcessLCF(const H225_RasMessage & obj_ras);
	void ProcessLRJ(const H225_RasMessage & obj_ras);
};

class NeighborList {
	class Neighbor {
	public:
		Neighbor(const PString &, const PString &);
		bool SendLRQ(int seqNum, const H225_AdmissionRequest &, H323RasSrv *) const;
		bool ForwardLRQ(PIPSocket::Address, const H225_LocationRequest &, H323RasSrv *) const;
		bool CheckIP(PIPSocket::Address ip) const;
		PString GetPassword() const;

	private:
		bool InternalSendLRQ(int seqNum, const H225_AdmissionRequest &, H323RasSrv *) const;
		bool InternalForwardLRQ(const H225_LocationRequest &, H323RasSrv *) const;
		bool ResolveName(PIPSocket::Address & ip) const;

		PString m_gkid;
		PString m_name;
		PString m_prefix;
		PString m_password;
		bool m_dynamic;
		mutable PIPSocket::Address m_ip;

		WORD m_port;
	};

public:
	class NeighborPasswordAuth : public GkAuthenticator {
	public:
		NeighborPasswordAuth(PConfig *cfg, const char *n) : GkAuthenticator(cfg, n) {}

	private:
		virtual int Check(const H225_GatekeeperRequest &, unsigned &)  { return e_next; }
		virtual int Check(const H225_RegistrationRequest &, unsigned &) { return e_next; }
		virtual int Check(const H225_UnregistrationRequest &, unsigned &) { return e_next; }
		virtual int Check(const H225_AdmissionRequest &, unsigned &) { return e_next; }
		virtual int Check(const H225_BandwidthRequest &, unsigned &) { return e_next; }
		virtual int Check(const H225_DisengageRequest &, unsigned &) { return e_next; }
		virtual int Check(const H225_LocationRequest &, unsigned &);
		virtual int Check(const H225_InfoRequest &, unsigned &) { return e_next; }

		virtual PString GetPassword(const PString &);
	};

	typedef std::list<Neighbor>::iterator iterator;
	typedef std::list<Neighbor>::const_iterator const_iterator;

	NeighborList(H323RasSrv *, PConfig *);
	int SendLRQ(int seqNum, const H225_AdmissionRequest &);
	int ForwardLRQ(PIPSocket::Address, const H225_LocationRequest &);
	bool CheckIP(PIPSocket::Address ip) const;
	// only valid after calling CheckIP
	PString GetPassword() const { return tmppasswd; }
	void InsertSiblingIP(PIPSocket::Address ip) { siblingIPs.insert(ip); }

	class InvalidNeighbor {};

private:
	list<Neighbor> nbList;
	H323RasSrv *RasSrv;
	set<PIPSocket::Address> siblingIPs;
	mutable PString tmppasswd;
};

void PendingList::Check()
{
	PWaitAndSignal lock(usedLock);
	iterator Iter = find_if(arqList.begin(), arqList.end(), not1(bind2nd(mem_fun(&PendingARQ::IsStaled), pendingTTL)));
	for_each(arqList.begin(), Iter, bind2nd(mem_fun(&PendingARQ::DoARJ), RasSrv));
	for_each(arqList.begin(), Iter, delete_arq);
	arqList.erase(arqList.begin(), Iter);
}

bool NBPendingList::Insert(const H225_AdmissionRequest & obj_arq, const endptr & reqEP)
{
	// TODO: check if ARQ duplicate
	int seqNumber = RasSrv->GetRequestSeqNum();
	int nbCount = RasSrv->GetNeighborsGK()->SendLRQ(seqNumber, obj_arq);
	if (nbCount > 0) {
		PWaitAndSignal lock(usedLock);
		arqList.push_back(new PendingARQ(seqNumber, obj_arq, reqEP, nbCount));
		return true;
	}
	return false;
}

void NBPendingList::ProcessLCF(const H225_RasMessage & obj_ras)
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

	(*Iter)->DoACF(RasSrv, called);
	Remove(Iter);
}

void NBPendingList::ProcessLRJ(const H225_RasMessage & obj_ras)
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
		(*Iter)->DoARJ(RasSrv);
		Remove(Iter);
	}
}

NeighborList::Neighbor::Neighbor(const PString & gkid, const PString & cfgs) : m_gkid(gkid)
{
	PStringArray cfg(cfgs.Tokenise(",;", TRUE));
	PString ipAddr = cfg[0].Trim();
	PINDEX p = ipAddr.Find(':');
	m_name = ipAddr.Left(p);
	m_port = (p != P_MAX_INDEX) ? ipAddr.Mid(p+1).AsUnsigned() : GK_DEF_UNICAST_RAS_PORT;
	m_prefix = (cfg.GetSize() > 1) ? cfg[1] : PString("*");
	if (cfg.GetSize() > 2)
		m_password = cfg[2];
	m_dynamic = (cfg.GetSize() > 3) ? Toolkit::AsBool(cfg[3]) : false;

	if (!m_dynamic && !PIPSocket::GetHostAddress(m_name, m_ip))
		throw InvalidNeighbor();
	PTRACE(1, "Add neighbor " << m_gkid << '(' << (m_dynamic ? m_name : m_ip.AsString()) << ':' << m_port << ')' << ((!m_prefix) ? (" for prefix " + m_prefix) : PString()));
}

inline bool NeighborList::Neighbor::CheckIP(PIPSocket::Address ip) const
{
       return (!m_dynamic || ResolveName(m_ip)) ? ip == m_ip : false;
}

inline PString NeighborList::Neighbor::GetPassword() const
{
       return m_password;
}

bool NeighborList::Neighbor::SendLRQ(int seqNum, const H225_AdmissionRequest &  obj_arq, H323RasSrv *RasSrv) const
{
       if (m_prefix.IsEmpty())
               return false;
       else if (m_prefix == "*")
               return InternalSendLRQ(seqNum, obj_arq, RasSrv);

       for (PINDEX i = 0; i < obj_arq.m_destinationInfo.GetSize(); ++i)
               if (AsString(obj_arq.m_destinationInfo[i], FALSE).Find(m_prefix) == 0)
                       return InternalSendLRQ(seqNum, obj_arq, RasSrv);

       return false;
}

bool NeighborList::Neighbor::InternalSendLRQ(int seqNum, const H225_AdmissionRequest & obj_arq, H323RasSrv *RasSrv) const
{
	PIPSocket::Address ip = m_ip;
	if (m_dynamic && !ResolveName(ip))
		return false;
	H225_RasMessage obj_ras;
	obj_ras.SetTag(H225_RasMessage::e_locationRequest);
	H225_LocationRequest & obj_lrq = obj_ras;
	obj_lrq.m_requestSeqNum.SetValue(seqNum);
	obj_lrq.m_replyAddress = RasSrv->GetRasAddress(ip);
	obj_lrq.m_destinationInfo = obj_arq.m_destinationInfo;

	// tell the neighbor who I am
	obj_lrq.IncludeOptionalField(H225_LocationRequest::e_sourceInfo);
	obj_lrq.m_sourceInfo.SetSize(1);
	H323SetAliasAddress(RasSrv->GetGKName(), obj_lrq.m_sourceInfo[0]);
	RasSrv->GetGkClient()->SetPassword(obj_lrq, Toolkit::GKName());

	int hotCount = GkConfig()->GetInteger(LRQFeaturesSection, "ForwordHopCount", 0);
	if (hotCount > 1) { // what if set hotCount = 1?
		obj_lrq.IncludeOptionalField(H225_LocationRequest::e_hopCount);
		obj_lrq.m_hopCount = hotCount;
	}
	RasSrv->SendRas(obj_ras, ip, m_port);
	return true;
}

bool NeighborList::Neighbor::ForwardLRQ(PIPSocket::Address ip, const H225_LocationRequest & obj_lrq, H323RasSrv *RasSrv) const
{
	if (m_prefix.IsEmpty())
		return false;
	if ((m_dynamic && !ResolveName(m_ip)) || ip == m_ip || !obj_lrq.HasOptionalField(H225_LocationRequest::e_hopCount))
		return false; // don't forward to GK that sent the LRQ or LRQ without hotCount

	if (m_prefix == "*")
		return InternalForwardLRQ(obj_lrq, RasSrv);

	for (PINDEX i = 0; i < obj_lrq.m_destinationInfo.GetSize(); ++i)
		if (AsString(obj_lrq.m_destinationInfo[i], FALSE).Find(m_prefix) == 0)
			return InternalForwardLRQ(obj_lrq, RasSrv);

	return false;
}

bool NeighborList::Neighbor::InternalForwardLRQ(const H225_LocationRequest & obj_lrq, H323RasSrv *RasSrv) const
{
	int hotCount = obj_lrq.m_hopCount;
	if (--hotCount > 0) {
		H225_RasMessage obj_ras;
		obj_ras.SetTag(H225_RasMessage::e_locationRequest);
		H225_LocationRequest & lrq = obj_ras;
		lrq = obj_lrq;
		lrq.m_hopCount = hotCount;
		RasSrv->SendRas(obj_ras, m_ip, m_port);
		return true;
	}
	return false;
}

bool NeighborList::Neighbor::ResolveName(PIPSocket::Address & ip) const
{
       PIPSocket::ClearNameCache();
       // Retrieve the ip address at this time
       if (PIPSocket::GetHostAddress(m_name, ip)) {
               PTRACE(3, "Retrieve neighbor ip for " << m_name << '=' << ip);
               return true;
       } else {
               PTRACE(1, "Can't get neighbor ip for " << m_name);
               return false;
       }
}

NeighborList::NeighborList(H323RasSrv *rs, PConfig *config) : RasSrv(rs)
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
	for (Iter = nbList.begin(); Iter != eIter; ++Iter)
		if (Iter->SendLRQ(seqNum, obj_arq, RasSrv))
			++nbCount;

       PTRACE_IF(2, nbCount, "GK\tSend LRQ to " << nbCount << " neighbor(s)");
       return nbCount;
}

int NeighborList::ForwardLRQ(PIPSocket::Address ip, const H225_LocationRequest & obj_lrq)
{
       int nbCount = 0;
       const_iterator Iter, eIter = nbList.end();
       for (Iter = nbList.begin(); Iter != eIter; ++Iter)
               if (Iter->ForwardLRQ(ip, obj_lrq, RasSrv))
                       ++nbCount;

       PTRACE_IF(2, nbCount, "GK\tForward LRQ to " << nbCount << " neighbor(s)");
       return nbCount;
}

bool NeighborList::CheckIP(PIPSocket::Address ip) const
{
       const_iterator Iter = find_if(
               nbList.begin(), nbList.end(),
               bind2nd(mem_fun_ref(&Neighbor::CheckIP), ip)
       );
       if (Iter != nbList.end()) {
               tmppasswd = Iter->GetPassword();
               return true;
       }
       std::set<PIPSocket::Address>::const_iterator it = siblingIPs.find(ip);
       return (it != siblingIPs.end());
}

int NeighborList::NeighborPasswordAuth::Check(const H225_LocationRequest & lrq, unsigned & rsn)
{
       PString nullid;
       return (!GetPassword(nullid)) ? GkAuthenticator::Check(lrq, rsn) : e_next;
}

PString NeighborList::NeighborPasswordAuth::GetPassword(const PString &)
{
	return RasThread->GetNeighborsGK()->GetPassword();
}

static GkAuthInit<NeighborList::NeighborPasswordAuth> N_B_A("NeighborPasswordAuth");

H323RasSrv::H323RasSrv(PIPSocket::Address _GKHome)
      : PThread(10000, NoAutoDeleteThread), requestSeqNum(0)
{
	GKHome = _GKHome;

	GKRasPort = GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT);

	EndpointTable = RegistrationTable::Instance(); //initialisation is done in LoadConfig
	CallTbl = CallTable::Instance();

	sigHandler = 0;

	gkClient = 0;
	authList = 0;
	destAnalysisList = 0;
	NeighborsGK = 0;

	// we now use singelton instance mm-22.05.2001
	GkStatusThread = GkStatus::Instance();
	GkStatusThread->Initialize(GKHome);

	LoadConfig();

	udpForwarding.SetWriteTimeout(PTimeInterval(300));

	arqPendingList = new NBPendingList(this, GkConfig()->GetInteger(LRQFeaturesSection, "NeighborTimeout", 2));
	// initialize the handler map
	for (unsigned i = 0; i <= H225_RasMessage::e_serviceControlResponse; ++i)
		rasHandler[i] = &H323RasSrv::OnUnknown;

        rasHandler[H225_RasMessage::e_gatekeeperRequest] =          &H323RasSrv::OnGRQ;
	rasHandler[H225_RasMessage::e_registrationRequest] =        &H323RasSrv::OnRRQ;
	rasHandler[H225_RasMessage::e_registrationConfirm] =        &H323RasSrv::OnRCF;
	rasHandler[H225_RasMessage::e_registrationReject] =         &H323RasSrv::OnRRJ;
	rasHandler[H225_RasMessage::e_unregistrationRequest] =      &H323RasSrv::OnURQ;
	rasHandler[H225_RasMessage::e_unregistrationConfirm] =      &H323RasSrv::OnIgnored;
	rasHandler[H225_RasMessage::e_unregistrationReject] =       &H323RasSrv::OnIgnored;
	rasHandler[H225_RasMessage::e_admissionRequest] =           &H323RasSrv::OnARQ;
	rasHandler[H225_RasMessage::e_admissionConfirm] =           &H323RasSrv::OnACF;
	rasHandler[H225_RasMessage::e_admissionReject] =            &H323RasSrv::OnARJ;
	rasHandler[H225_RasMessage::e_bandwidthRequest] =           &H323RasSrv::OnBRQ;
	rasHandler[H225_RasMessage::e_bandwidthConfirm] =           &H323RasSrv::OnIgnored;
	rasHandler[H225_RasMessage::e_bandwidthReject] =            &H323RasSrv::OnIgnored;
	rasHandler[H225_RasMessage::e_disengageRequest] =           &H323RasSrv::OnDRQ;
	rasHandler[H225_RasMessage::e_disengageConfirm] =           &H323RasSrv::OnIgnored;
	rasHandler[H225_RasMessage::e_disengageReject] =            &H323RasSrv::OnIgnored;
	rasHandler[H225_RasMessage::e_locationRequest] =            &H323RasSrv::OnLRQ;
	rasHandler[H225_RasMessage::e_locationConfirm] =            &H323RasSrv::OnLCF;
	rasHandler[H225_RasMessage::e_locationReject] =             &H323RasSrv::OnLRJ;
	rasHandler[H225_RasMessage::e_infoRequestResponse] =        &H323RasSrv::OnIRR;
	rasHandler[H225_RasMessage::e_resourcesAvailableIndicate] = &H323RasSrv::OnRAI;
}


H323RasSrv::~H323RasSrv()
{
	delete gkClient;
	delete authList;
	delete destAnalysisList;
	delete NeighborsGK;
	delete arqPendingList;
}

void H323RasSrv::SetRoutedMode(bool routedSignaling, bool routedH245)
{
	if (GKRoutedSignaling = routedSignaling) {
		if (sigHandler)
			sigHandler->LoadConfig();
		else
			sigHandler = new HandlerList(GKHome);
		GKCallSigPort = sigHandler->GetCallSignalPort();
	}
	GKRoutedH245 = routedH245;

	const char *modemsg = GKRoutedSignaling ? "Routed" : "Direct";
	const char *h245msg = GKRoutedH245 ? "Enabled" : "Disabled";
	PTRACE(2, "GK\tUsing " << modemsg << " Signalling");
	PTRACE(2, "GK\tH.245 Routed " << h245msg);
}

// set the signaling mode according to the config file
// don't change it if not specified in the config
void H323RasSrv::SetRoutedMode()
{
       PString gkrouted(GkConfig()->GetString(RoutedSec, "GKRouted", ""));
       PString h245routed(GkConfig()->GetString(RoutedSec, "H245Routed", ""));
       SetRoutedMode(
               (!gkrouted) ? Toolkit::AsBool(gkrouted) : GKRoutedSignaling,
               (!h245routed) ? Toolkit::AsBool(h245routed) : GKRoutedH245
       );
}

bool H323RasSrv::AcceptUnregisteredCalls(PIPSocket::Address ip, bool & fp) const
{
       fp = (gkClient->IsRegistered() && gkClient->CheckGKIP(ip));
       return AcceptUnregCalls || (AcceptNBCalls ? (fp || NeighborsGK->CheckIP(ip)) : false);
}

void H323RasSrv::LoadConfig()
{
	PWaitAndSignal lock(loadLock);

	AcceptNBCalls = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AcceptNeighborsCalls", "1"));
	AcceptUnregCalls = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AcceptUnregisteredCalls", "0"));

	// First reinitialize the Database. The Database might block the auth/DestAnalysis-Funktors.
#if defined(HAS_LDAP)		// shall use LDAP

	// initialize LDAP
	GkDatabase::Instance()->Initialize(*GkConfig());

#endif // HAS_LDAP

	// add authenticators
	authlist_deleteMutex.Wait();
	delete authList;
	authList = NULL;
	authList = new GkAuthenticatorList(GkConfig());
	PAssert(NULL!=authList, "No AuthenticatorList!");
	authlist_deleteMutex.Signal();


	// add destination analysis
	destAnalysisList_deleteMutex.Wait();
	delete destAnalysisList;
	destAnalysisList = NULL;
	destAnalysisList = new GkDestAnalysisList(GkConfig());
	PAssert(NULL!=destAnalysisList, "No DestAnalysisList!");

	EndpointTable->Initialize(*destAnalysisList);
	destAnalysisList_deleteMutex.Signal();

	// add neighbors
	delete NeighborsGK;
	NeighborsGK = new NeighborList(this, GkConfig());

	//add authorize
	if (gkClient) { // don't create GkClient object at the first time
		if (gkClient->IsRegistered())
			gkClient->SendURQ();
		delete gkClient;
		gkClient = new GkClient(this);
	}
}

void H323RasSrv::Close(void)
{
	PTRACE(2, "GK\tClosing RasSrv");

	// disconnect all calls
	CallTable::Instance()->ClearTable();

	if (gkClient->IsRegistered())
		gkClient->SendURQ();

	listener.Close();
	if (sigHandler) {
		delete sigHandler;
		sigHandler = NULL;
	}
	if (GkStatusThread != NULL) {
		GkStatusThread->Close();
		GkStatusThread->WaitForTermination();
		delete GkStatusThread;
		GkStatusThread = NULL;
	}

	PTRACE(1, "GK\tRasSrv closed");
}


void H323RasSrv::UnregisterAllEndpoints(void)
{
	SoftPBX::UnregisterAllEndpoints();
}


/* Gatekeeper request */
BOOL H323RasSrv::OnGRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_grq, H225_RasMessage & obj_rpl)
{
	PTRACE(1, "GK\tGRQ Received");

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
		msg = PString(PString::Printf, "GRJ|%s;" GK_LINEBRK, inet_ntoa(rx_addr));
	} else {
		obj_rpl.SetTag(H225_RasMessage::e_gatekeeperConfirm);
		H225_GatekeeperConfirm & obj_gcf = obj_rpl;

		obj_gcf.m_requestSeqNum = obj_gr.m_requestSeqNum;
		obj_gcf.m_protocolIdentifier = obj_gr.m_protocolIdentifier;
		obj_gcf.m_nonStandardData = obj_gr.m_nonStandardData;
		obj_gcf.m_rasAddress = GetRasAddress(rx_addr);
		obj_gcf.IncludeOptionalField(obj_gcf.e_gatekeeperIdentifier);
		obj_gcf.m_gatekeeperIdentifier.SetValue( GetGKName() );

		PString aliasListString(obj_gr.HasOptionalField(H225_GatekeeperRequest::e_endpointAlias) ?
					AsString(obj_gr.m_endpointAlias) : PString());

		if (bShellForwardRequest)
			ForwardRasMsg(obj_grq);

		msg = PString(PString::Printf, "GCF|%s|%s|%s;" GK_LINEBRK,
			inet_ntoa(rx_addr),
			(const unsigned char *) aliasListString,
			(const unsigned char *) AsString(obj_gr.m_endpointType) );
	}

	PTRACE(2, msg);
	GkStatusThread->SignalStatus(msg);

	return TRUE;
}

BOOL
H323RasSrv::SetAlternateGK(H225_RegistrationConfirm &rcf)
{
        //        PTRACE(5, ANSI::BLU << "Alternating? " << ANSI::OFF);
	PString param = GkConfig()->GetString("AlternateGKs","");
	if (param.IsEmpty())
		return FALSE;
	PTRACE(5, ANSI::BLU << "Alternating: yes, set AltGK in RCF! " << ANSI::OFF);

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

		PIPSocket::Address ip(tokens[0]);
		A.m_rasAddress = SocketToH225TransportAddr(ip, tokens[1].AsUnsigned());

		A.m_needToRegister = Toolkit::AsBool(tokens[2]);
		A.m_priority = tokens[3].AsInteger();;

		if(tokens.GetSize() > 4) {
			A.IncludeOptionalField(H225_AlternateGK::e_gatekeeperIdentifier);
			A.m_gatekeeperIdentifier = tokens[4];
		}
	}
	return TRUE;
}

BOOL
H323RasSrv::ForwardRasMsg(H225_RasMessage msg) // not passed as const, ref or pointer!
{
//	PTRACE(5, ANSI::BLU << "Forwarding? " << ANSI::OFF);
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
	PTRACE(1, "GK\tRRQ Received");

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

	// lightweight registration update
	if (obj_rr.HasOptionalField(H225_RegistrationRequest::e_keepAlive) &&
		obj_rr.m_keepAlive.GetValue())
	{
		endptr ep = EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier);
		bReject = !ep;
		// check if the RRQ was sent from the registered endpoint
		if (ep) {
#ifdef CHECK_FOR_ALIAS0
			PAssert(FALSE,"H323RasSrv::OnRRQ using only first");
#endif
			if (obj_rr.m_callSignalAddress.GetSize() >= 1)
				bReject = (ep->GetCallSignalAddress() != obj_rr.m_callSignalAddress[0]);
			else if (obj_rr.m_rasAddress.GetSize() >= 1)
				bReject = (ep->GetRasAddress() != obj_rr.m_rasAddress[0]);
			// No call signal and ras address provided.
			// TODO: check rx_addr?
			else
				bReject = FALSE;
		}

		if (bReject) {
			PTRACE_IF(1, ep, "WARNING:\tPossibly endpointId collide or security attack!!");
			// endpoint was NOT registered
			rejectReason.SetTag(H225_RegistrationRejectReason::e_fullRegistrationRequired);
		} else {
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
			if (bShellForwardRequest)
				ForwardRasMsg(ep->GetCompleteRegistrationRequest());

			ep->Update(obj_rrq);
			return bShellSendReply;
		}
	}

	bool nated = false, validaddress = false;
	if (obj_rr.m_callSignalAddress.GetSize() >= 1) {
		SignalAdr = obj_rr.m_callSignalAddress[0];
		if (SignalAdr.GetTag() == H225_TransportAddress::e_ipAddress) {
			H225_TransportAddress_ipAddress & ip = SignalAdr;
			PIPSocket::Address ipaddr(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
			validaddress = (rx_addr == ipaddr);

			const PString SkipForwards = GkConfig()->GetString("SkipForwards", "");
			if (!SkipForwards)
				if (SkipForwards.Find(rx_addr.AsString()) != P_MAX_INDEX)
					validaddress = true;

			if (!validaddress && Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "SupportNATedEndpoints", "0")))
				validaddress = nated = true;
		}
	}

	if (!bReject && !validaddress) {
		bReject = TRUE;
		rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidCallSignalAddress);
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
//				if (s.GetLength() < 1 || !(isalnum(s[0]) || s[0]=='#') ) {
				if (s.GetLength() < 1) {
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
			if (nated)
				ep->SetNATAddress(rx_addr);
			//
			// OK, now send RCF
			//
			obj_rpl.SetTag(H225_RasMessage::e_registrationConfirm);
			H225_RegistrationConfirm & rcf = obj_rpl;
			rcf.m_requestSeqNum = obj_rr.m_requestSeqNum;
			rcf.m_protocolIdentifier =  obj_rr.m_protocolIdentifier;
			rcf.m_nonStandardData = obj_rr.m_nonStandardData;
			// This should copy all Addresses.
			rcf.m_callSignalAddress = obj_rr.m_callSignalAddress;
// 			rcf.m_callSignalAddress.SetSize( obj_rr.m_callSignalAddress.GetSize() );
// 			for( PINDEX cnt = 0; cnt < obj_rr.m_callSignalAddress.GetSize(); cnt ++ )
// 				rcf.m_callSignalAddress[cnt] = obj_rr.m_callSignalAddress[cnt];

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
			PString msg(PString::Printf, "RCF|%s|%s|%s|%s;" GK_LINEBRK,
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

	PString msg(PString::Printf, "RRJ|%s|%s|%s|%s;" GK_LINEBRK,
		    inet_ntoa(rx_addr),
		    (const unsigned char *) aliasListString,
		    (const unsigned char *) AsString(obj_rr.m_terminalType),
		    (const unsigned char *) rrj.m_rejectReason.GetTagName()
		    );
	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);
	return bShellSendReply;
}

/* Registration Confirm */
BOOL H323RasSrv::OnRCF(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rcf, H225_RasMessage &)
{
	PTRACE(1, "GK\tRCF Received");
	gkClient->OnRCF(obj_rcf, rx_addr);
	return FALSE;
}

/* Registration Reject */
BOOL H323RasSrv::OnRRJ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rrj, H225_RasMessage &)
{
	PTRACE(1, "GK\tRRJ Received");
	gkClient->OnRRJ(obj_rrj, rx_addr);
	return FALSE;
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

bool H323RasSrv::SendLRQ(const H225_AdmissionRequest & arq, const endptr & reqEP)
{
       return arqPendingList->Insert(arq, reqEP);
}

/* Admission Request */
BOOL H323RasSrv::OnARQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_arq, H225_RasMessage & obj_rpl)
{
	PTRACE(2, "GK\tARQ Received");

	const H225_AdmissionRequest & obj_rr = obj_arq;
	BOOL bReject = FALSE;

	// find the caller
	endptr RequestingEP = EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier);

	endptr CalledEP(NULL);

	if (RequestingEP) { // Is the ARQ from a registered endpoint?
		bool bHasDestInfo = (obj_rr.HasOptionalField(H225_AdmissionRequest::e_destinationInfo) && obj_rr.m_destinationInfo.GetSize() >= 1);
		if (bHasDestInfo) // apply rewriting rules
			Toolkit::Instance()->RewriteE164(obj_rr.m_destinationInfo[0]);

		unsigned rsn = H225_AdmissionRejectReason::e_securityDenial;
		if (!authList->Check(obj_rr, rsn)) {
			bReject = TRUE;
		} else if (obj_rr.m_answerCall) {
			// don't search endpoint table for an answerCall ARQ
			CalledEP = RequestingEP;
		} else {
			// if a destination address is provided, we check if we know it
			if (obj_rr.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress) &&
				GetCallSignalAddress(rx_addr) != obj_rr.m_destCallSignalAddress) { // if destAddr is the GK, ignore it
				CalledEP = EndpointTable->FindBySignalAdr(obj_rr.m_destCallSignalAddress);
				if (!CalledEP && Toolkit::AsBool(GkConfig()->GetString("RasSrv::ARQFeatures", "CallUnregisteredEndpoints", "1"))) {
					H225_RasMessage arq = obj_arq;
					CalledEP = EndpointTable->InsertRec(arq);
				}
			}
			if (!CalledEP && RequestingEP && obj_rr.m_destinationInfo.GetSize() >= 1) {
				// create new callRec, set callingEP and insert callRec in callTable
				CallRec *pCallRec = new CallRec(obj_rr.m_callIdentifier, obj_rr.m_conferenceID,
								AsString(obj_rr.m_destinationInfo), AsString(obj_rr.m_srcInfo), 0, GKRoutedH245); //BWRequest will be set in ProcessARQ
				pCallRec->SetCalling(RequestingEP, obj_rr.m_callReferenceValue);
				CallTable::Instance()->Insert(pCallRec);
				// get called ep
				CalledEP = EndpointTable->getMsgDestination(obj_rr, RequestingEP, rsn, TRUE);
				if (!CalledEP && rsn == H225_AdmissionRejectReason::e_incompleteAddress) {
					bReject = TRUE;
				}
				if (CalledEP!=endptr(NULL) && rsn == H225_AdmissionRejectReason::e_incompleteAddress) {
					PTRACE(1,"Setting CalledEP to NULL");
					pCallRec->SetCalled(endptr(NULL), obj_rr.m_callReferenceValue);
					CalledEP=endptr(NULL);
				}
// #else // default (old) code.

// 			Toolkit::Instance()->RewriteE164(obj_rr.m_destinationInfo[0]);
// 			CalledEP = EndpointTable->FindEndpoint(obj_rr.m_destinationInfo);

// #endif

				if (!bReject && !CalledEP &&
				    ( rsn == H225_AdmissionRejectReason::e_securityDenial ||
					    rsn == H225_AdmissionRejectReason::e_resourceUnavailable)) {
					if (gkClient->IsRegistered()) {
						H225_ArrayOf_AliasAddress dest = obj_rr.m_destinationInfo;
						H225_AdmissionRequest arq_fake=obj_rr;
						// The obj_rr is the non-rewritten H225_AdmissionRequest. We need to change the destination-address
						// so we copy it to arq_fake and then build a new AdmissionRequest.
						PString number = H323GetAliasAddressString(dest[0]);
						Q931::NumberingPlanCodes plan = Q931::ISDNPlan;
						Q931::TypeOfNumberCodes ton = Q931::UnknownType;
						H225_ScreeningIndicator::Enumerations si = H225_ScreeningIndicator::e_userProvidedNotScreened;
						Toolkit::Instance()->GetRewriteTool().PrefixAnalysis(number, plan, ton, si,
												     pCallRec->GetCallingProfile());
						H323SetAliasAddress(number, dest[0], H225_AliasAddress::e_dialedDigits);
						arq_fake.m_destinationInfo=dest;
						//PrefixAnalysis(pCallRec->GetCallingProfile(), arq_fake); // Number should be long enough to dertermine
						gkClient->SendARQ(arq_fake, RequestingEP);
						return FALSE;

					} else if (arqPendingList->Insert(obj_rr, RequestingEP)) {
						return FALSE;
					}
				}
			}
		}

		if(bReject || CalledEP==endptr(NULL)) {
			obj_rpl.SetTag(H225_RasMessage::e_admissionReject);
			H225_AdmissionReject & arj = obj_rpl;
			arj.m_rejectReason.SetTag(rsn);
			PTRACE(5, "setting Reject Reason: " << arj.m_rejectReason.GetTagName());
		}
	}

	ProcessARQ(rx_addr, RequestingEP, CalledEP, obj_rr, obj_rpl, bReject);
	return TRUE;
}

void H323RasSrv::ProcessARQ(PIPSocket::Address rx_addr, const endptr & RequestingEP, const endptr & CalledEP, const H225_AdmissionRequest & obj_arq, H225_RasMessage & obj_rpl, BOOL bReject)
{
	// We use #obj_rpl# for storing information about a potential reject (e.g. the
	// rejectReason). If the request results in a confirm (bReject==FALSE) then
	// we have to ignore the previous set data in #obj_rpl# and re-cast it.
	if (obj_rpl.GetTag() != H225_RasMessage::e_admissionReject)
		obj_rpl.SetTag(H225_RasMessage::e_admissionReject);
	H225_AdmissionReject & arj = obj_rpl;

	// check if the endpoint requesting is registered with this gatekeeper
	if (!bReject && !RequestingEP) {
		bReject = TRUE;
		arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_callerNotRegistered/*was :e_invalidEndpointIdentifier*/);
	}

/*
	// allow overlap sending for incomplete prefixes
	if (!CalledEP && obj_arq.m_destinationInfo.GetSize() >= 1) {
		const PString alias = AsString(obj_arq.m_destinationInfo[0], FALSE);
		if (CheckForIncompleteAddress(obj_arq.m_destinationInfo)) {
			bReject = TRUE;
			arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_incompleteAddress);
		}
	}
*/

	if(!bReject && !CalledEP) {
		// if bReject is false but no called EP means, that the EP won't handle ARJ correctly. We have to send a
		// ACF here and handle the Overlap Sending in Q.931
		if (arj.m_rejectReason.GetTag()==H225_AdmissionRejectReason::e_incompleteAddress) {
			obj_rpl.SetTag(H225_RasMessage::e_admissionConfirm);
			PTRACE(3, "handling ARJ with cisco");
		} else {
			bReject = TRUE;
//			arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_calledPartyNotRegistered);
		}
	}

	//
	// Bandwidth
	// and GkManager admission
	//
	int BWRequest = 1280;

	if (!bReject) {
		//
		// Give bandwidth
		//

		// hack for Netmeeting 3.0x
		if (obj_arq.m_bandWidth.GetValue() >= 100)
			BWRequest = obj_arq.m_bandWidth.GetValue();
		//BWRequest = std::min(bw, CallTbl->GetAvailableBW());
		PTRACE(3, "GK\tARQ will request bandwith of " << BWRequest);

		//
		// GkManager admission
		//
		if (!CallTbl->GetAdmission(BWRequest)) {
			bReject = TRUE;
			arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_resourceUnavailable);
		}
	}

 	//
 	// call from one GW to itself?
 	// generate ARJ-reason: 'routeCallToSCN'
 	//
 	if(!bReject &&
 	   Toolkit::AsBool(GkConfig()->GetString("RasSrv::ARQFeatures","ArjReasonRouteCallToSCN","0")) )
 	{
 		// are the endpoints the same (GWs of course)?
 		if( (CalledEP) && (RequestingEP) && (CalledEP == RequestingEP) &&
 			(!obj_arq.m_answerCall) // only first ARQ may be rejected with with 'routeCallToSCN'
 			)
 		{
 			// we have to extract the SCN from the destination. only EP-1 will be rejected this way
 			if ( obj_arq.m_destinationInfo.GetSize() >= 1 )	{
 				// PN will be the number that is set in the arj reason
 				H225_PartyNumber PN;
 				PN.SetTag(H225_PartyNumber::e_e164Number);
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
 					PN = obj_arq.m_destinationInfo[0]; // Gives a warning, nilsb
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

	//
	// Do the reject or the confirm
	//
	PString srcInfoString = (RequestingEP) ? AsDotString(RequestingEP->GetCallSignalAddress()) : PString(" ");
	PString destinationInfoString = (obj_arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)) ?
		AsString(obj_arq.m_destinationInfo) : PString("unknown");

	// get matching callRec
        // CallRecs should be looked for using callIdentifier instead of callReferenceValue
        // callIdentifier is globally unique, callReferenceValue is just unique per-endpoint.

	callptr pExistingCallRec = (obj_arq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier)) ?
		CallTable::Instance()->FindCallRec(obj_arq.m_callIdentifier) :
	// since callIdentifier is optional, we might have to look for the callReferenceValue as well
		CallTable::Instance()->FindCallRec(obj_arq.m_callReferenceValue);

	if (!bReject && Toolkit::AsBool(GkConfig()->GetString("RasSrv::ARQFeatures", "ArjReasonRouteCallToGatekeeper", "1"))) {
		if (GKRoutedSignaling && obj_arq.m_answerCall && !pExistingCallRec) {
			bool fromAlternateGK = false;
			const PString SkipForwards = GkConfig()->GetString("SkipForwards", "");
			if (!SkipForwards) {
				if (obj_arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress) &&
				    obj_arq.m_srcCallSignalAddress.GetTag() == H225_TransportAddress::e_ipAddress) {
					const H225_TransportAddress_ipAddress & srcipaddr = (const H225_TransportAddress_ipAddress &)obj_arq.m_srcCallSignalAddress;
					PString srcip(PString::Printf,"%d.%d.%d.%d", srcipaddr.m_ip[0], srcipaddr.m_ip[1], srcipaddr.m_ip[2], srcipaddr.m_ip[3]);
					fromAlternateGK = (SkipForwards.Find(srcip) != P_MAX_INDEX);
				}
			}
			if (!fromAlternateGK) {
				bReject = TRUE;
				arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_routeCallToGatekeeper);
			}
		}
	}

	if (bReject)
	{
		arj.m_requestSeqNum = obj_arq.m_requestSeqNum;
		PString msg(PString::Printf, "ARJ|%s|%s|%s|%s|%s;" GK_LINEBRK,
			    (const unsigned char *) srcInfoString,
			    (const unsigned char *) destinationInfoString,
			    (const unsigned char *) AsString(obj_arq.m_srcInfo),
			    (obj_arq.m_answerCall) ? "true" : "false",
			    (const unsigned char *) arj.m_rejectReason.GetTagName() );
		PTRACE(2, msg);
		GkStatusThread->SignalStatus(msg);
	} else 	{
		// new connection admitted
		obj_rpl.SetTag(H225_RasMessage::e_admissionConfirm); // re-cast (see above)
		H225_AdmissionConfirm & acf = obj_rpl;

		acf.m_requestSeqNum = obj_arq.m_requestSeqNum;
		acf.m_bandWidth = BWRequest;

		if (pExistingCallRec) {
//#ifdef WITH_DEST_ANALYSIS_LIST
			// set calledEP
			pExistingCallRec->SetCalled(CalledEP, obj_arq.m_callReferenceValue);
			// if it is the first ARQ then add the rest of informations in callRec
			if (!obj_arq.m_answerCall) {
				pExistingCallRec->SetBandwidth(BWRequest);
				// No Timerhandling for called Party.
// Routed mode is now in class RasSrv.
//				pExistingCallRec->SetH245Routed(GKRoutedH245);
				if (!GKRoutedSignaling) {
					pExistingCallRec->SetConnected(true);
				}
			}
// #else // default (old) code
// 			if (obj_arq.m_answerCall) // the second ARQ
// 				pExistingCallRec->SetCalled(CalledEP, obj_arq.m_callReferenceValue);
// 			// else this may be a duplicate ARQ, ignore!
// 			PTRACE(3, "Gk\tACF: found existing call no " << pExistingCallRec->GetCallNumber());
// #endif
		} else {
			// the call is not in the table
			CallRec *pCallRec = new CallRec(obj_arq.m_callIdentifier, obj_arq.m_conferenceID,
							destinationInfoString, AsString(obj_arq.m_srcInfo),
							BWRequest, GKRoutedH245);
			pCallRec->SetCalled(CalledEP, obj_arq.m_callReferenceValue);

			if (!obj_arq.m_answerCall) // the first ARQ
				pCallRec->SetCalling(RequestingEP, obj_arq.m_callReferenceValue);
			if (!GKRoutedSignaling)
				pCallRec->SetConnected(true);

			pCallRec->Lock();

			if(pCallRec->GetCallingProfile().GetCallTimeout()==0) {
				delete pCallRec;
				obj_rpl.SetTag(H225_RasMessage::e_admissionReject); // Build ARJ
				H225_AdmissionReject arj=obj_rpl;
				arj.m_requestSeqNum = obj_arq.m_requestSeqNum;
				arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_exceedsCallCapacity);
				return;
			}

			CallTable::Instance()->Insert(pCallRec);

			int timeout = (pCallRec->GetCallingProfile().GetCallTimeout()>=0 ?
				       pCallRec->GetCallingProfile().GetCallTimeout() :
				       GkConfig()->GetInteger("CallTable", "DefaultCallTimeout", 0));
			pCallRec->SetTimer(timeout);
			pCallRec->StartTimer();
			pCallRec->Unlock();
		}

		if ( GKRoutedSignaling ) {
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
			acf.m_destCallSignalAddress = GetCallSignalAddress(rx_addr);
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
		PString msg(PString::Printf, "ACF|%s|%s|%u|%s|%s;" GK_LINEBRK,
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
	const H225_TransportAddress_ipAddress & ip = RequestingEP->GetRasAddress();
	PIPSocket::Address ipaddress(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
	ProcessARQ(ipaddress, RequestingEP, CalledEP, obj_arq, obj_rpl);
	SendReply(obj_rpl, ipaddress, ip.m_port, listener);
}

/* Admission Confirm */
BOOL H323RasSrv::OnACF(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &)
{
       PTRACE(1, "GK\tACF Received");
       if (gkClient->IsRegistered())
               gkClient->OnACF(obj_rr, rx_addr);
       return FALSE;
}

/* Admission Reject */
BOOL H323RasSrv::OnARJ(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &)
{
       PTRACE(1, "GK\tARJ Received");
       if (gkClient->IsRegistered())
               gkClient->OnARJ(obj_rr, rx_addr);
       return FALSE;
}

/* Disengage Request */
BOOL H323RasSrv::OnDRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_drq, H225_RasMessage & obj_rpl)
{
	PTRACE(1, "GK\tDRQ Received");

	const H225_DisengageRequest & obj_rr = obj_drq;
	bool bReject = false;

       if (gkClient->IsRegistered() && gkClient->OnDRQ(obj_rr, rx_addr)) {
               PTRACE(4,"GKC\tDRQ: from my GK");
       } else if (EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier)) {
               PTRACE(4, "GK\tDRQ: closed conference");
       } else {
               bReject = true;
       }

       PString msg;
       if (bReject) {
               PTRACE(4, "GK\tDRQ: reject");
               obj_rpl.SetTag(H225_RasMessage::e_disengageReject);
               H225_DisengageReject & drj = obj_rpl;
               drj.m_requestSeqNum = obj_rr.m_requestSeqNum;
               drj.m_rejectReason.SetTag( drj.m_rejectReason.e_notRegistered );

	       msg = PString(PString::Printf, "DRJ|%s|%s|%u|%s;" GK_LINEBRK,
			     inet_ntoa(rx_addr),
			     (const unsigned char *) obj_rr.m_endpointIdentifier.GetValue(),
			     (unsigned) obj_rr.m_callReferenceValue,
			     (const unsigned char *) drj.m_rejectReason.GetTagName());
       } else {
		obj_rpl.SetTag(H225_RasMessage::e_disengageConfirm);
		H225_DisengageConfirm & dcf = obj_rpl;
		dcf.m_requestSeqNum = obj_rr.m_requestSeqNum;

		// always signal DCF
		msg = PString(PString::Printf, "DCF|%s|%s|%u|%s;" GK_LINEBRK,
				inet_ntoa(rx_addr),
				(const unsigned char *) obj_rr.m_endpointIdentifier.GetValue(),
				(unsigned) obj_rr.m_callReferenceValue,
				(const unsigned char *) obj_rr.m_disengageReason.GetTagName() );
		CallTable::Instance()->RemoveCall(obj_rr);
	}

	PTRACE(2, msg);
	GkStatusThread->SignalStatus(msg);
	return TRUE;
}


/* Unregistration Request */
BOOL H323RasSrv::OnURQ(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_urq, H225_RasMessage &obj_rpl)
{
	PTRACE(1, "GK\tURQ Received");

	const H225_UnregistrationRequest & obj_rr = obj_urq;
	PString msg;

	BOOL bShellSendReply = TRUE;
	BOOL bShellForwardRequest = TRUE;

	// check first if it comes from my GK
	if (gkClient->IsRegistered() && gkClient->OnURQ(obj_rr, rx_addr)) {
		// Return UCF
		obj_rpl.SetTag(H225_RasMessage::e_unregistrationConfirm);
		H225_UnregistrationConfirm & ucf = obj_rpl;
		ucf.m_requestSeqNum = obj_rr.m_requestSeqNum;
		return TRUE;
	}
	// OK, it comes from my endpoints
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

	PString endpointIdentifierString(obj_rr.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier) ? obj_rr.m_endpointIdentifier.GetValue() : PString(" "));
#ifdef CHECK_FOR_ALIAS0
	PAssert(1,"H323RasSrv::OnURQ using only field 1");
#endif

	endptr ep = obj_rr.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier) ?
		EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier) :
		EndpointTable->FindBySignalAdr(obj_rr.m_callSignalAddress[0]);
	if (ep) {
		// Disconnect all calls of the endpoint
		SoftPBX::DisconnectEndpoint(ep);
		// Remove from the table
//		EndpointTable->RemoveByEndpointId(obj_rr.m_endpointIdentifier);
		EndpointTable->RemoveByEndptr(ep);

		// Return UCF
		obj_rpl.SetTag(H225_RasMessage::e_unregistrationConfirm);
		H225_UnregistrationConfirm & ucf = obj_rpl;
		ucf.m_requestSeqNum = obj_rr.m_requestSeqNum;
		ucf.m_nonStandardData = obj_rr.m_nonStandardData;

		msg = PString(PString::Printf, "UCF|%s|%s;",
			      inet_ntoa(rx_addr),
			     (const unsigned char *) endpointIdentifierString) ;
	} else {
		// Return URJ
		obj_rpl.SetTag(H225_RasMessage::e_unregistrationReject);
		H225_UnregistrationReject & urj = obj_rpl;
		urj.m_requestSeqNum = obj_rr.m_requestSeqNum;
		urj.m_nonStandardData = obj_rr.m_nonStandardData ;
		urj.m_rejectReason.SetTag(H225_UnregRejectReason::e_notCurrentlyRegistered);

		msg = PString(PString::Printf, "URJ|%s|%s|%s;",
			      inet_ntoa(rx_addr),
			      (const unsigned char *) endpointIdentifierString,
			      (const unsigned char *) urj.m_rejectReason.GetTagName() );
	}

	PTRACE(2, msg);
	GkStatusThread->SignalStatus(msg + GK_LINEBRK);

	if(bShellForwardRequest)
		ForwardRasMsg(obj_urq);

	return bShellSendReply;
}

/* Bandwidth Request */
BOOL H323RasSrv::OnBRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl)
{
	PTRACE(1, "GK\tBRQ Received");

	const H225_BandwidthRequest & obj_brq = obj_rr;

	obj_rpl.SetTag(H225_RasMessage::e_bandwidthConfirm);
	H225_BandwidthConfirm & bcf = obj_rpl;
	bcf.m_requestSeqNum = obj_brq.m_requestSeqNum;
	/* for now we grant whatever bandwidth was requested */
	if (obj_brq.m_bandWidth.GetValue() < 100)
	{
		/* hack for Netmeeting 3.0 */
		bcf.m_bandWidth.SetValue ( 1280 );
	} else {
		/* otherwise grant what was asked for */
		bcf.m_bandWidth = obj_brq.m_bandWidth;
	}
	bcf.m_nonStandardData = obj_brq.m_nonStandardData;

	PString msg(PString::Printf, "BCF|%s|%s|%u;" GK_LINEBRK,
		    inet_ntoa(rx_addr),
		    (const unsigned char *) obj_brq.m_endpointIdentifier.GetValue(),
		    bcf.m_bandWidth.GetValue() );
	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);

	return TRUE;
}


/* Location Request */
BOOL H323RasSrv::OnLRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rr, H225_RasMessage & obj_rpl)
{
	PTRACE(1, "GK\tLRQ Received");

	PString msg;
	endptr WantedEndPoint;

	const H225_LocationRequest & obj_lrq = obj_rr;
	Toolkit::Instance()->RewriteE164(obj_lrq.m_destinationInfo[0]);
	endptr cgEP;

	for(PINDEX i=0; i<obj_lrq.m_destinationInfo.GetSize(); i++)
		Toolkit::Instance()->RewriteE164(obj_lrq.m_destinationInfo[i]);
	unsigned rsn = H225_LocationRejectReason::e_securityDenial;
	bool fromRegEndpoint = (obj_lrq.HasOptionalField(H225_LocationRequest::e_endpointIdentifier) && EndpointTable->FindByEndpointId(obj_lrq.m_endpointIdentifier));
	bool bReject = (!(fromRegEndpoint || NeighborsGK->CheckIP(rx_addr)) || !authList->Check(obj_lrq, rsn));

	PString sourceInfoString((obj_lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)) ? AsString(obj_lrq.m_sourceInfo) : PString(" "));
	if (!bReject) {
		if (
//#ifdef WITH_DEST_ANALYSIS_LIST
			// if the destAlias is not found
			(WantedEndPoint = EndpointTable->getMsgDestination(obj_lrq, cgEP, rsn, FALSE))
// #else // default (old) code
// 			// only search registered endpoints
// 			(WantedEndPoint = EndpointTable->FindEndpoint(obj_lrq.m_destinationInfo, FALSE))
// #endif
			) {
			// Alias found
			obj_rpl.SetTag(H225_RasMessage::e_locationConfirm);
			H225_LocationConfirm & lcf = obj_rpl;
			lcf.m_requestSeqNum = obj_lrq.m_requestSeqNum;
			lcf.IncludeOptionalField(H225_LocationConfirm::e_nonStandardData);
			lcf.m_nonStandardData = obj_lrq.m_nonStandardData;

			WantedEndPoint->BuildLCF(obj_rpl);
			if (GKRoutedSignaling && AcceptNBCalls) {
				lcf.m_callSignalAddress = GetCallSignalAddress(rx_addr);
				lcf.m_rasAddress = GetRasAddress(rx_addr);
			}

			msg = PString(PString::Printf, "LCF|%s|%s|%s|%s;\r\n",
				      inet_ntoa(rx_addr),
				      (const unsigned char *) WantedEndPoint->GetEndpointIdentifier().GetValue(),
				      (const unsigned char *) AsString(obj_lrq.m_destinationInfo),
				      (const unsigned char *) sourceInfoString);
		} else {
			if (NeighborsGK->ForwardLRQ(rx_addr, obj_lrq) > 0)
				return FALSE; // forward successful, nothing for us :)
			bReject = true;
			rsn = H225_LocationRejectReason::e_requestDenied;
		}
	}
	if (bReject) {
		// Alias not found
                obj_rpl.SetTag(H225_RasMessage::e_locationReject);
                H225_LocationReject & lrj = obj_rpl;
                lrj.m_requestSeqNum = obj_lrq.m_requestSeqNum;
                lrj.m_rejectReason.SetTag(rsn); // can't find the location
                lrj.IncludeOptionalField(H225_LocationReject::e_nonStandardData);
                lrj.m_nonStandardData = obj_lrq.m_nonStandardData;

                msg = PString(PString::Printf, "LRJ|%s|%s|%s|%s;\r\n",
			      inet_ntoa(rx_addr),
			      (const unsigned char *) AsString(obj_lrq.m_destinationInfo),
			      (const unsigned char *) sourceInfoString,
			      (const unsigned char *) lrj.m_rejectReason.GetTagName() );
	}
	if (obj_lrq.m_replyAddress.GetTag() == H225_TransportAddress::e_ipAddress) {
		const H225_TransportAddress_ipAddress & ip = obj_lrq.m_replyAddress;
		PIPSocket::Address ipaddr(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
		if (!bReject)
			NeighborsGK->InsertSiblingIP(ipaddr);
		SendRas(obj_rpl, ipaddr, ip.m_port);
	}

	PTRACE(2, msg);
	GkStatusThread->SignalStatus(msg);

	return FALSE; // reply to replyAddress instead of rx_addr
}

/* Location Confirm */
BOOL H323RasSrv::OnLCF(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &)
{
	PTRACE(1, "GK\tLCF Received");
//	if (NeighborsGK->CheckIP(rx_addr)) // may send from sibling
	arqPendingList->ProcessLCF(obj_rr);
	return FALSE;
}

/* Location Reject */
BOOL H323RasSrv::OnLRJ(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &)
{
	PTRACE(1, "GK\tLRJ Received");
	// we should ignore LRJ from sibling
	if (NeighborsGK->CheckIP(rx_addr))
		arqPendingList->ProcessLRJ(obj_rr);
	return FALSE;
}


/* Information Request Response */
BOOL H323RasSrv::OnIRR(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &obj_rpl)
{
	PTRACE(1, "GK\tIRR Received");

	const H225_InfoRequestResponse & obj_irr = obj_rr;

	if (endptr ep = EndpointTable->FindByEndpointId(obj_irr.m_endpointIdentifier)) {
		ep->Update(obj_rr);
		if (obj_irr.HasOptionalField( H225_InfoRequestResponse::e_needResponse) && obj_irr.m_needResponse.GetValue()) {
			obj_rpl.SetTag(H225_RasMessage::e_infoRequestAck);
			H225_InfoRequestAck & ira = obj_rpl;
			ira.m_requestSeqNum = obj_irr.m_requestSeqNum;
			ira.m_nonStandardData = obj_irr.m_nonStandardData;

			PString msg(PString::Printf, "IACK|%s;", inet_ntoa(rx_addr));
			PTRACE(2, msg);
			GkStatusThread->SignalStatus(msg + "\r\n");
			return TRUE;
		}
	}
	// otherwise don't respond
	return FALSE;
}

/* Resource Availability Indicate */
BOOL H323RasSrv::OnRAI(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &obj_rpl)
{
	PTRACE(1, "GK\tRAI Received");

	const H225_ResourcesAvailableIndicate & obj_rai = obj_rr;

	/* accept all RAIs */
	obj_rpl.SetTag(H225_RasMessage::e_resourcesAvailableConfirm);
	H225_ResourcesAvailableConfirm & rac = obj_rpl;
	rac.m_requestSeqNum = obj_rai.m_requestSeqNum;
	rac.m_protocolIdentifier =  obj_rai.m_protocolIdentifier;
	rac.m_nonStandardData = obj_rai.m_nonStandardData;

	return TRUE;
}

BOOL H323RasSrv::OnIgnored(const PIPSocket::Address &, const H225_RasMessage & obj_rr, H225_RasMessage &)
{
       PTRACE(2, "GK\t" << obj_rr.GetTagName() << " received and safely ignored");
       return FALSE;
}

BOOL H323RasSrv::OnUnknown(const PIPSocket::Address &, const H225_RasMessage &, H225_RasMessage &)
{
       PTRACE(1, "GK\tUnknown RAS message received");
       return FALSE;
}

bool H323RasSrv::Check()
{
	if (sigHandler)
		sigHandler->Check();
	gkClient->CheckRegistration();
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
#if PTRACING
	if (PTrace::CanTrace(3))
		PTRACE(3, "GK\tSend to " << rx_addr << ':' << rx_port << '\n' << setprecision(2) << obj_rpl);
	else
		PTRACE(2, "GK\tSend " << obj_rpl.GetTagName() << " to " << rx_addr << ':' << rx_port);
#endif

	PBYTEArray wtbuf(4096);
	PPER_Stream wtstrm(wtbuf);

	obj_rpl.Encode(wtstrm);
	wtstrm.CompleteEncoding();

	PWaitAndSignal lock(writeMutex);
	if(!BoundSocket.WriteTo(wtstrm.GetPointer(), wtstrm.GetSize(), rx_addr, rx_port) ) {
		PTRACE(4, "GK\tRAS thread: Write error: " << BoundSocket.GetErrorText());
	} else {
		PTRACE(5, "GK\tSent Successful");
	}
}


void H323RasSrv::Main(void)
{
	ReadLock cfglock(ConfigReloadMutex);

	const int buffersize = 4096;
	BYTE buffer[buffersize];

	PString err_msg("ERROR: Request received by gatekeeper: ");
	PTRACE(2, "GK\tEntering connection handling loop");

	// queueSize is useless for UDPSocket
	listener.Listen(GKHome, 0, GKRasPort, PSocket::CanReuseAddress);
	PTRACE_IF(1, !listener.IsOpen(), "GK\tBind to RAS port failed!");

	gkClient = new GkClient(this);

	while (listener.IsOpen()) {
		WORD rx_port;
		PIPSocket::Address rx_addr;
		H225_RasMessage obj_req;
		H225_RasMessage obj_rpl;

		// large mutex! only allow the reloadhandler be executed
		// in the small block
		ConfigReloadMutex.EndRead();

		int iResult = listener.ReadFrom(buffer, buffersize, rx_addr, rx_port);
		// not allow to reload below here
		ConfigReloadMutex.StartRead();
		if (!iResult) {
			PTRACE(1, "GK\tRAS thread: Read error: " << listener.GetErrorText());

			// TODO: "return" (terminate) on some errors (like the one at shutdown)
			continue;
		}
		PTRACE(2, "GK\tRead from " << rx_addr << ':' << rx_port);

		// get only bytes which are really read
		PPER_Stream rawPDU(buffer, listener.GetLastReadCount());
		// set rawPDU for authentication methods
                authList->setLastReceivedRawPDU(rawPDU);

                if (!obj_req.Decode( rawPDU )) {
			PTRACE(1, "GK\tCouldn't decode message!");

			continue;
		}

		PTRACE(3, "GK" << endl << setprecision(2) << obj_req);
		if (obj_req.GetTag() <= H225_RasMessage::e_serviceControlResponse) {
			if ((this->*rasHandler[obj_req.GetTag()])(rx_addr, obj_req, obj_rpl))
				SendReply( obj_rpl, rx_addr, rx_port, listener );
		} else {
			PTRACE(1, "GK\tWarning: unknown RAS message tag");
		}

	}
	PTRACE(1,"GK\tRasThread terminated!");
}
