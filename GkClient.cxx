//////////////////////////////////////////////////////////////////
//
// GkClient.cxx
//
// Copyright (c) Citron Network Inc. 2001-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 02/27/2002
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include <ptlib.h>
#include <h323pdu.h> 
#include <h235auth.h>
#include "stl_supp.h"
#include "RasPDU.h"
#include "RasSrv.h"
#include "ProxyChannel.h"
#include "GkClient.h"

namespace {
const char* const EndpointSection = "Endpoint";
const char* const RewriteE164Section = "Endpoint::RewriteE164";
}

class AlternateGKs {
public:
	AlternateGKs(const PIPSocket::Address &, WORD);
	void Set(const H225_ArrayOf_AlternateGK &);
	bool Get(PIPSocket::Address &, WORD &);

private:
	typedef std::multimap<int, H225_TransportAddress> GKList;
	GKList AltGKs;
	GKList::iterator index;
	PIPSocket::Address pgkaddr, pgkport;
};

AlternateGKs::AlternateGKs(const PIPSocket::Address & gkaddr, WORD gkport)
{
	pgkaddr = gkaddr, pgkport = gkport;
}

void AlternateGKs::Set(const H225_ArrayOf_AlternateGK & agk)
{
	AltGKs.clear();
	for (PINDEX i = 0; i < agk.GetSize(); ++i) {
		const H225_AlternateGK & gk = agk[i];
		AltGKs.insert(std::make_pair(int(gk.m_priority), gk.m_rasAddress));
	}
	index = AltGKs.begin();
}

bool AlternateGKs::Get(PIPSocket::Address & gkaddr, WORD & gkport)
{ 
	if (AltGKs.size() > 0) {
		if (index == AltGKs.end()) {
			index = AltGKs.begin();
			// switch back to original GK
			gkaddr = pgkaddr;
			gkport = (WORD)pgkport;
			return false;
		}

		const H225_TransportAddress & rasAddress = (index++)->second;
		if (GetIPAndPortFromTransportAddr(rasAddress, gkaddr, gkport))
			return true;
		PTRACE(3, "GKC\tInvalid AlternateGK Address!" );
		return Get(gkaddr, gkport); // try next
	}
	return false;
}


class NATClient : public RegularJob {
public:
	NATClient(const H225_TransportAddress &, const H225_EndpointIdentifier &);

	// override from class RegularJob
	virtual void Stop();

private:
	// override from class Task
	virtual void Exec();

	bool DetectIncomingCall();
	void SendInfo(int);

	PIPSocket::Address gkip;
	WORD gkport;
	PString endpointId;
	CallSignalSocket *socket;
};

NATClient::NATClient(const H225_TransportAddress & addr, const H225_EndpointIdentifier & id)
{
	GetIPAndPortFromTransportAddr(addr, gkip, gkport);
	endpointId = id.GetValue();
	socket = 0;
	SetName("NATClient");
	Execute();
}

void NATClient::Stop()
{
	PWaitAndSignal lock(m_deletionPreventer);
	RegularJob::Stop();
	if (socket) {
		SendInfo(Q931::CallState_DisconnectRequest);
		socket->Close();
	}
}

void NATClient::Exec()
{
	socket = new CallSignalSocket;
	socket->SetPort(gkport);
	if (socket->Connect(gkip)) {
		PTRACE(2, "GKC\t" << socket->GetName() << " connected, wainting for incoming call");
		if (DetectIncomingCall()) {
			PTRACE(3, "GKC\tIncoming call detected");
			CreateJob(socket, &CallSignalSocket::Dispatch, "NAT call");
			socket = 0;
			return;
		}
	}
	delete socket;
	socket = 0;
	int retryInterval = GkConfig()->GetInteger(EndpointSection, "NATRetryInterval", 60);
	Wait(retryInterval * 1000);
}

bool NATClient::DetectIncomingCall()
{
	while (socket->IsOpen()) {
		long retry = GkConfig()->GetInteger(
			EndpointSection, "NATKeepaliveInterval", 86400
			); // one day
		SendInfo(Q931::CallState_IncomingCallProceeding);
		while (socket->IsOpen() && --retry > 0)
			if (socket->IsReadable(1000)) // one second
				return socket->IsOpen();
	}
	return false;
}

void NATClient::SendInfo(int state)
{
	Q931 information;
	information.BuildInformation(0, false);
	PBYTEArray buf, epid(endpointId, endpointId.GetLength(), false);
	information.SetIE(Q931::FacilityIE, epid);
	information.SetCallState(Q931::CallStates(state));
	information.Encode(buf);
	socket->TransmitData(buf);
}


class GRQRequester : public RasRequester {
public:
	GRQRequester(const PString &);
	~GRQRequester();

	// override from class RasRequester
	virtual bool SendRequest(const Address &, WORD, int = 2);

private:
	// override from class RasHandler
	virtual bool IsExpected(const RasMsg *) const;

	H225_RasMessage grq_ras;
};

GRQRequester::GRQRequester(const PString & gkid) : RasRequester(grq_ras)
{
	grq_ras.SetTag(H225_RasMessage::e_gatekeeperRequest);
	H225_GatekeeperRequest & grq = grq_ras;
	grq.m_requestSeqNum = GetSeqNum();
	grq.m_protocolIdentifier.SetValue(H225_ProtocolID);
	grq.m_endpointType.IncludeOptionalField(H225_EndpointType::e_gatekeeper);
	grq.IncludeOptionalField(H225_GatekeeperRequest::e_supportsAltGK);
	if (!gkid) {
		grq.IncludeOptionalField(H225_GatekeeperRequest::e_gatekeeperIdentifier);
		grq.m_gatekeeperIdentifier = gkid;
	}
	grq.IncludeOptionalField(H225_GatekeeperRequest::e_authenticationCapability);
	grq.IncludeOptionalField(H225_GatekeeperRequest::e_algorithmOIDs);
	H235AuthSimpleMD5 md5auth;
	md5auth.SetPassword("dummy"); // activate it
	md5auth.SetCapability(grq.m_authenticationCapability, grq.m_algorithmOIDs);
	H235AuthCAT catauth;
	catauth.SetPassword("dummy"); // activate it
	catauth.SetCapability(grq.m_authenticationCapability, grq.m_algorithmOIDs);
	m_rasSrv->RegisterHandler(this);
}

GRQRequester::~GRQRequester()
{
	m_rasSrv->UnregisterHandler(this);
}

bool GRQRequester::SendRequest(const Address & addr, WORD pt, int r)
{
	m_txAddr = addr, m_txPort = pt, m_retry = r;
	H225_GatekeeperRequest & grq = grq_ras;
	std::vector<Address> GKHome;
	Toolkit::Instance()->GetGKHome(GKHome);
	for (std::vector<Address>::iterator i = GKHome.begin(); i != GKHome.end(); ++i) {
		if ((IsLoopback(addr) || IsLoopback(*i)) && addr != *i)
			continue;
		RasListener *socket = m_rasSrv->SelectInterface(*i)->GetRasListener();
		grq.m_rasAddress = socket->GetRasAddress(addr == INADDR_BROADCAST ? *i : addr);
		if (addr == INADDR_BROADCAST)
			socket->SetOption(SO_BROADCAST, 1);
		socket->SendRas(grq_ras, addr, pt);
		if (addr == INADDR_BROADCAST)
			socket->SetOption(SO_BROADCAST, 0);
	}
	m_sentTime = PTime();
	return true;
}

bool GRQRequester::IsExpected(const RasMsg *ras) const
{
	if (ras->GetSeqNum() == GetSeqNum())
		if (ras->GetTag() == H225_RasMessage::e_gatekeeperRequest)
			return m_txAddr == INADDR_BROADCAST; // catch broadcasted GRQ to avoid loop
		else if (ras->GetTag() == H225_RasMessage::e_gatekeeperConfirm || ras->GetTag() == H225_RasMessage::e_gatekeeperReject)
			return (m_txAddr == INADDR_BROADCAST) ? true : ras->IsFrom(m_txAddr, m_txPort);
	return false;
}


// handler to process requests to GkClient
class GkClientHandler : public RasHandler {
public:
	typedef bool (GkClient::*Handler)(RasMsg *);

	GkClientHandler(GkClient *c, Handler h, unsigned t) : client(c), handlePDU(h), tag(t) {}

private:
	// override from class RasHandler
	virtual bool IsExpected(const RasMsg *ras) const;
	virtual void Process(RasMsg *);

	void OnRequest(RasMsg *ras);

	GkClient *client;
	Handler handlePDU;
	unsigned tag;
};

bool GkClientHandler::IsExpected(const RasMsg *ras) const
{
	return (ras->GetTag() == tag) && client->CheckFrom(ras);
}

void GkClientHandler::Process(RasMsg *ras)
{
	CreateJob(this, &GkClientHandler::OnRequest, ras, ras->GetTagName());
}

void GkClientHandler::OnRequest(RasMsg *ras)
{
	if ((client->*handlePDU)(ras))
		ras->Reply();
	delete ras;
}

namespace {
const long DEFAULT_TTL = 60;
const long DEFAULT_RRQ_RETRY = 3;
}

// class GkClient
GkClient::GkClient(
	RasServer* rasSrv
	) : m_rasSrv(rasSrv), m_registered(false), m_discoveryComplete(false),
	m_ttl(GkConfig()->GetInteger(EndpointSection, "TimeToLive", DEFAULT_TTL)),
	m_timer(0),
	m_retry(GkConfig()->GetInteger(EndpointSection, "RRQRetryInterval", DEFAULT_RRQ_RETRY))
{
	m_resend = m_retry;
	m_gkfailtime = m_retry * 128;
	
	m_endpointId = new H225_EndpointIdentifier;
	m_gatekeeperId = new H225_GatekeeperIdentifier;
	// initialize these variable for safe
	m_rewriteInfo = 0;
	m_natClient = 0;
	m_gkport = 0;

	m_useAltGKPermanent = false;
	m_gkList = new AlternateGKs(m_gkaddr, m_gkport);

	m_handlers[0] = new GkClientHandler(this, &GkClient::OnURQ, H225_RasMessage::e_unregistrationRequest);
	m_handlers[1] = new GkClientHandler(this, &GkClient::OnBRQ, H225_RasMessage::e_bandwidthRequest);
	m_handlers[2] = new GkClientHandler(this, &GkClient::OnDRQ, H225_RasMessage::e_disengageRequest);
	m_handlers[3] = new GkClientHandler(this, &GkClient::OnIRQ, H225_RasMessage::e_infoRequest);
}

GkClient::~GkClient()
{
	DeleteObjectsInArray(m_handlers, m_handlers + 4);
	delete m_gkList;
	delete m_rewriteInfo;
	delete m_gatekeeperId;
	delete m_endpointId;
	PTRACE(1, "GKC\tDelete GkClient");
}

void GkClient::OnReload()
{
	if (IsRegistered())
		if (Toolkit::AsBool(GkConfig()->GetString(EndpointSection, "UnregisterOnReload", "0")))
			SendURQ(); // TODO
		else
			Unregister();

	m_password = GkConfig()->GetString(EndpointSection, "Password", "");
	m_retry = m_resend = GkConfig()->GetInteger(EndpointSection, "RRQRetryInterval", DEFAULT_RRQ_RETRY);
	m_gkfailtime = m_retry * 128;
	m_authMode = -1;

	PIPSocket::Address gkaddr = m_gkaddr;
	WORD gkport = m_gkport;
	const PString gk(GkConfig()->GetString(EndpointSection, "Gatekeeper", "no"));
	
	if (!IsRegistered())
		m_ttl = GkConfig()->GetInteger(EndpointSection, "TimeToLive", DEFAULT_TTL);

	if (gk == "no") {
		m_timer = 0;
		m_rrjReason = PString();
		return;
	} else if (gk == "auto") {
		m_gkaddr = INADDR_BROADCAST;
		m_gkport = GK_DEF_UNICAST_RAS_PORT;
		m_discoveryComplete = false;
	} else if (GetTransportAddress(gk, GK_DEF_UNICAST_RAS_PORT, m_gkaddr, m_gkport)) {
		m_discoveryComplete = (m_gkaddr == gkaddr) && (m_gkport == gkport);
	} else {
		// unresolvable?
		PTRACE(1, "GKC\tWarning: Can't resolve parent GK " << gk);
		return;
	}

	m_timer = 100;

	// FIXME: not thread-safed
	delete m_rewriteInfo;
	m_rewriteInfo = new Toolkit::RewriteData(GkConfig(), RewriteE164Section);
}

void GkClient::CheckRegistration()
{
	if (m_timer > 0 && (PTime() - m_registeredTime) > m_timer)
		Register();
}

bool GkClient::CheckFrom(const RasMsg *ras) const
{
	return ras->IsFrom(m_gkaddr, m_gkport);
}

PString GkClient::GetParent() const
{
	return IsRegistered() ?
		AsString(m_gkaddr, m_gkport) + '\t' + m_endpointId->GetValue() :
		"not registered\t" + m_rrjReason;
}

bool GkClient::SendARQ(Routing::AdmissionRequest & arq_obj)
{
	const H225_AdmissionRequest & oarq = arq_obj.GetRequest();
	H225_RasMessage arq_ras;
	Requester<H225_AdmissionRequest> request(arq_ras, m_loaddr);
	H225_AdmissionRequest & arq = BuildARQ(arq_ras);

	if (oarq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
		arq.m_destinationInfo = oarq.m_destinationInfo;
	}
	if (oarq.HasOptionalField(H225_AdmissionRequest::e_destExtraCallInfo)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_destExtraCallInfo);
		arq.m_destExtraCallInfo = oarq.m_destExtraCallInfo;
	}
	arq.m_srcInfo = oarq.m_srcInfo;
	RewriteE164(arq.m_srcInfo, true);
	arq.m_bandWidth = oarq.m_bandWidth;
	arq.m_callReferenceValue = oarq.m_callReferenceValue;
	arq.m_conferenceID = oarq.m_conferenceID;
	if (oarq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_callIdentifier);
		arq.m_callIdentifier = oarq.m_callIdentifier;
	}

	return WaitForACF(request, &arq_obj);
}

bool GkClient::SendLRQ(Routing::LocationRequest & lrq_obj)
{
	const H225_LocationRequest & olrq = lrq_obj.GetRequest();
	H225_RasMessage lrq_ras;
	Requester<H225_LocationRequest> request(lrq_ras, m_loaddr);
	H225_LocationRequest & lrq = lrq_ras;
	lrq.m_destinationInfo = olrq.m_destinationInfo;
	lrq.m_replyAddress = m_rasSrv->GetRasAddress(m_loaddr);
	lrq.IncludeOptionalField(H225_LocationRequest::e_endpointIdentifier);
	lrq.m_endpointIdentifier = *m_endpointId;
	if (olrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_sourceInfo);
		lrq.m_sourceInfo = olrq.m_sourceInfo;
		RewriteE164(lrq.m_sourceInfo, true);
	}
	if (olrq.HasOptionalField(H225_LocationRequest::e_canMapAlias)) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_canMapAlias);
		lrq.m_canMapAlias = olrq.m_canMapAlias;
	}
	SetNBPassword(lrq);

	request.SendRequest(m_gkaddr, m_gkport);
	if (request.WaitForResponse(5000)) {
		RasMsg *ras = request.GetReply();
		unsigned tag = ras->GetTag();
		if (tag == H225_RasMessage::e_locationConfirm) {
			H225_LocationConfirm & lcf = (*ras)->m_recvRAS;
			lrq_obj.SetDestination(lcf.m_callSignalAddress);
			RasMsg *oras = lrq_obj.GetWrapper();
			(*oras)->m_replyRAS.SetTag(H225_RasMessage::e_locationConfirm);
			H225_LocationConfirm & nlcf = (*oras)->m_replyRAS;
			if (lcf.HasOptionalField(H225_LocationConfirm::e_cryptoTokens)) {
				nlcf.IncludeOptionalField(H225_LocationConfirm::e_cryptoTokens);
				nlcf.m_cryptoTokens = lcf.m_cryptoTokens;
			}
			return true;
		}
	}
	return false;
}

bool GkClient::SendARQ(Routing::SetupRequest & setup_obj, bool answer)
{
	H225_RasMessage arq_ras;
	Requester<H225_AdmissionRequest> request(arq_ras, m_loaddr);
	H225_AdmissionRequest & arq = BuildARQ(arq_ras);

	H225_Setup_UUIE & setup = setup_obj.GetRequest();
	arq.m_callReferenceValue = setup_obj.GetWrapper()->GetCallReference();
	arq.m_conferenceID = setup.m_conferenceID;
	if (setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_callIdentifier);
		arq.m_callIdentifier = setup.m_callIdentifier;
	}
	if (setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		arq.m_srcInfo = setup.m_sourceAddress;
		if (!answer)
			RewriteE164(arq.m_srcInfo, true);
	} else {
		// no sourceAddress privided in Q.931 Setup?
		// since srcInfo is mandatory, set my aliases as the srcInfo
		arq.m_srcInfo.SetSize(1);
		H323SetAliasAddress(m_h323Id, arq.m_srcInfo[0]);
		if (!m_e164) {
			arq.m_srcInfo.SetSize(2);
			H323SetAliasAddress(m_e164, arq.m_srcInfo[1]);
		}
	}
	if (setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
		arq.m_destinationInfo = setup.m_destinationAddress;
		if (answer)
			RewriteE164(arq.m_destinationInfo, true);
	}
	arq.m_answerCall = answer;
	// workaround for bandwidth, as OpenH323 library :p
	arq.m_bandWidth = 1280;

	return WaitForACF(request, answer ? 0 : &setup_obj);
}

bool GkClient::SendARQ(Routing::FacilityRequest & facility_obj)
{
	H225_RasMessage arq_ras;
	Requester<H225_AdmissionRequest> request(arq_ras, m_loaddr);
	H225_AdmissionRequest & arq = BuildARQ(arq_ras);

	H225_Facility_UUIE & facility = facility_obj.GetRequest();
	arq.m_callReferenceValue = facility_obj.GetWrapper()->GetCallReference();
	if (facility.HasOptionalField(H225_Facility_UUIE::e_conferenceID))
		arq.m_conferenceID = facility.m_conferenceID;
	if (facility.HasOptionalField(H225_Facility_UUIE::e_callIdentifier)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_callIdentifier);
		arq.m_callIdentifier = facility.m_callIdentifier;
	}
	arq.m_srcInfo.SetSize(1);
	H323SetAliasAddress(m_h323Id, arq.m_srcInfo[0]);
	if (!m_e164) {
		arq.m_srcInfo.SetSize(2);
		H323SetAliasAddress(m_e164, arq.m_srcInfo[1]);
	}
	if (facility.HasOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
		arq.m_destinationInfo = facility.m_alternativeAliasAddress;
	}
	arq.m_answerCall = false;
	// workaround for bandwidth, as OpenH323 library :p
	arq.m_bandWidth = 1280;

	return WaitForACF(request, &facility_obj);
}

void GkClient::SendDRQ(const callptr & call)
{
	H225_RasMessage drq_ras;
	Requester<H225_DisengageRequest> request(drq_ras, m_loaddr);
	H225_DisengageRequest & drq = drq_ras;
	call->BuildDRQ(drq, H225_DisengageReason::e_normalDrop);
	drq.IncludeOptionalField(H225_DisengageRequest::e_gatekeeperIdentifier);
	drq.m_gatekeeperIdentifier = *m_gatekeeperId;
	drq.m_endpointIdentifier = *m_endpointId;
	drq.m_answeredCall = !call->GetCallingParty();
	SetPassword(drq);

	request.SendRequest(m_gkaddr, m_gkport);
	request.WaitForResponse(3000);
	// ignore response
}

void GkClient::SendURQ()
{
	// the order is important: build URQ, close NAT socket, then send URQ
	H225_RasMessage urq_ras;
	urq_ras.SetTag(H225_RasMessage::e_unregistrationRequest);
	H225_UnregistrationRequest & urq = urq_ras;
	urq.m_requestSeqNum = m_rasSrv->GetRequestSeqNum();
	urq.IncludeOptionalField(H225_UnregistrationRequest::e_gatekeeperIdentifier);
	urq.m_gatekeeperIdentifier = *m_gatekeeperId;
	urq.IncludeOptionalField(H225_UnregistrationRequest::e_endpointIdentifier);
	urq.m_endpointIdentifier = *m_endpointId;
	SetCallSignalAddress(urq.m_callSignalAddress);
	SetPassword(urq);

	Unregister();
	m_rasSrv->SendRas(urq_ras, m_gkaddr, m_gkport, m_loaddr);
}

bool GkClient::RewriteE164(H225_AliasAddress & alias, bool fromInternal)
{
	if (alias.GetTag() != H225_AliasAddress::e_dialedDigits) 
		return false;
		        
	PString e164 = H323GetAliasAddressString(alias);

	bool changed = RewriteString(e164, fromInternal);
	if (changed)
		H323SetAliasAddress(e164, alias);

	return changed;
}

bool GkClient::RewriteE164(H225_ArrayOf_AliasAddress & aliases, bool fromInternal)
{
	bool changed = false;
	for (PINDEX i = 0; i < aliases.GetSize(); ++i)
		if (RewriteE164(aliases[i], fromInternal))
			changed = true;
	return changed;
}

bool GkClient::RewriteE164(Q931 & SetupMesg, H225_Setup_UUIE & Setup, bool fromInternal)
{
	unsigned plan, type;
	PString Number;

	bool result = false;
	if (fromInternal) {
		bool r1 = SetupMesg.GetCallingPartyNumber(Number, &plan, &type);
		if (r1 && (result = RewriteString(Number, true)))
			SetupMesg.SetCallingPartyNumber(Number, plan, type);
		if ((!r1 || result) && Setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress))
			result = RewriteE164(Setup.m_sourceAddress, true) || result;
	} else {
		bool r1 = SetupMesg.GetCalledPartyNumber(Number, &plan, &type);
		if (r1 && (result = RewriteString(Number, false)))
			SetupMesg.SetCalledPartyNumber(Number, plan, type);
		if ((!r1 || result) && Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
			result = RewriteE164(Setup.m_destinationAddress, false) || result;
	}
	return result;
}

bool GkClient::Discovery()
{
	m_loaddr = m_gkaddr;
	*m_gatekeeperId = PString();
	if (!Toolkit::AsBool(GkConfig()->GetString(EndpointSection, "Discovery", "1")))
		return true;

	GRQRequester request(GkConfig()->GetString(EndpointSection, "GatekeeperIdentifier", ""));
	// the spec: timeout value 5 sec, retry count 2
	request.SendRequest(m_gkaddr, m_gkport);
	while (request.WaitForResponse(5000)) {
		RasMsg *ras = request.GetReply();
		if (ras->GetTag() == H225_RasMessage::e_gatekeeperConfirm) {
			H225_GatekeeperConfirm & gcf = (*ras)->m_recvRAS;
			m_loaddr = (*ras)->m_localAddr;
			if (gcf.HasOptionalField(H225_GatekeeperConfirm::e_gatekeeperIdentifier))
				*m_gatekeeperId = gcf.m_gatekeeperIdentifier;
			GetIPAndPortFromTransportAddr(gcf.m_rasAddress, m_gkaddr, m_gkport);
			if (gcf.HasOptionalField(H225_GatekeeperConfirm::e_authenticationMode))
				m_authMode = gcf.m_authenticationMode.GetTag();
			PTRACE(2, "GKC\tDiscover GK " << AsString(m_gkaddr, m_gkport) << " at " << m_loaddr);
			return true;
		} else if (ras->GetTag() == H225_RasMessage::e_gatekeeperReject) {
			H225_GatekeeperReject & grj = (*ras)->m_recvRAS;
			if (grj.HasOptionalField(H225_GatekeeperReject::e_altGKInfo)) {
				m_gkList->Set(grj.m_altGKInfo.m_alternateGatekeeper);
				m_useAltGKPermanent = grj.m_altGKInfo.m_altGKisPermanent;
				break;
			}
		}
	}
	return false;
}

void GkClient::Register()
{
	PWaitAndSignal lock(m_rrqMutex);
	m_rrjReason = "no response";
	if (!IsRegistered() && !m_discoveryComplete)
		while (!(m_discoveryComplete = Discovery()))
			if (!GetAltGK())
				return;

	H225_RasMessage rrq_ras;
	Requester<H225_RegistrationRequest> request(rrq_ras, m_loaddr);
	BuildRRQ(rrq_ras);
	request.SendRequest(m_gkaddr, m_gkport);
	m_registeredTime = PTime();
	if (request.WaitForResponse(m_retry * 1000)) {
		RasMsg *ras = request.GetReply();
		switch (ras->GetTag())
		{
			case H225_RasMessage::e_registrationConfirm:
				OnRCF(ras);
				return;
			case H225_RasMessage::e_registrationReject:
				OnRRJ(ras);
				break;
		}
	}
	GetAltGK();
}

void GkClient::Unregister()
{
	if (m_natClient) {
		m_natClient->Stop();
		m_natClient = 0;
	}
	for_each(m_handlers, m_handlers + 4, bind1st(mem_fun(&RasServer::UnregisterHandler), m_rasSrv));
	m_registered = false;
}

bool GkClient::GetAltGK()
{
	Unregister(); // always re-register
	bool result = false;
	if (Toolkit::AsBool(GkConfig()->GetString(EndpointSection, "UseAlternateGK", "1")))
		result = m_gkList->Get(m_gkaddr, m_gkport);
	PString altgk(AsString(m_gkaddr, m_gkport));
	if (m_useAltGKPermanent)
		Toolkit::Instance()->SetConfig(1, EndpointSection, "Gatekeeper", altgk);
	if (result) {
		m_timer = 100, m_resend = m_retry, m_discoveryComplete = false;
		PTRACE(1, "GKC\tUse Alternate GK " << altgk << (m_useAltGKPermanent ? " permanently" : " temporarily"));
	} else {
		// if no alternate gatekeeper found
		// increase our resent time to avoid flooding the parent
		m_timer = (m_resend *= 2) * 1000;
		if (m_resend >= m_gkfailtime) {
			// FIXME: not thread-safed
			Toolkit::Instance()->GetRouteTable()->InitTable();
			m_resend = m_gkfailtime;
		}
	}
	return result;
}

void GkClient::BuildRRQ(H225_RegistrationRequest & rrq)
{
	rrq.m_protocolIdentifier.SetValue(H225_ProtocolID);
	rrq.m_discoveryComplete = m_discoveryComplete;
	SetRasAddress(rrq.m_rasAddress);
	SetCallSignalAddress(rrq.m_callSignalAddress);
	rrq.IncludeOptionalField(H225_RegistrationRequest::e_supportsAltGK);
	IsRegistered() ? BuildLightWeightRRQ(rrq) : BuildFullRRQ(rrq);
	SetPassword(rrq);
}

void GkClient::BuildFullRRQ(H225_RegistrationRequest & rrq)
{
	rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_gatekeeper);

	PINDEX as, p;
	PString t(GkConfig()->GetString(EndpointSection, "Type", "gateway").ToLower());
	if (t[0] == 't') {
		rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_terminal);
	} else if (t[0] == 'g') {
		rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_gateway);
		const PString prefix(GkConfig()->GetString(EndpointSection, "Prefix", ""));
		const PStringArray prefixes=prefix.Tokenise(",;", FALSE);
		as = prefixes.GetSize();
		if (as > 0) {
			rrq.m_terminalType.m_gateway.IncludeOptionalField(H225_GatewayInfo::e_protocol);
			rrq.m_terminalType.m_gateway.m_protocol.SetSize(1);
			H225_SupportedProtocols & protocol = rrq.m_terminalType.m_gateway.m_protocol[0];
			protocol.SetTag(H225_SupportedProtocols::e_voice);
			H225_VoiceCaps & voicecap = (H225_VoiceCaps &)protocol;
			voicecap.m_supportedPrefixes.SetSize(as);
			for (PINDEX p = 0; p < as; ++p)
				H323SetAliasAddress(prefixes[p].Trim(), voicecap.m_supportedPrefixes[p].m_prefix);
		}
//		rrq.IncludeOptionalField(H225_RegistrationRequest::e_multipleCalls);
//		rrq.m_multipleCalls = FALSE;
	} // else what?

	rrq.IncludeOptionalField(H225_RegistrationRequest::e_terminalAlias);
	PString h323id(GkConfig()->GetString(EndpointSection, "H323ID", (const char *)Toolkit::GKName()));
	PStringArray h323ids=h323id.Tokenise(" ,;\t", FALSE);
	as = h323ids.GetSize();
	rrq.m_terminalAlias.SetSize(as);
	for (p = 0; p < as; ++p)
		H323SetAliasAddress(h323ids[p], rrq.m_terminalAlias[p]);
	m_h323Id = h323ids[0];

	PString e164(GkConfig()->GetString(EndpointSection, "E164", ""));
	PStringArray e164s=e164.Tokenise(" ,;\t", FALSE);
	PINDEX s = e164s.GetSize() + as;
	rrq.m_terminalAlias.SetSize(s);
	for (p = as; p < s; ++p)
		H323SetAliasAddress(e164s[p-as], rrq.m_terminalAlias[p]);
	m_e164 = e164s[0];

	int ttl = GkConfig()->GetInteger(EndpointSection, "TimeToLive", DEFAULT_TTL);
	if (ttl > 0) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_timeToLive);
		rrq.m_timeToLive = ttl;
	}

	H225_VendorIdentifier & vendor = rrq.m_endpointVendor;
	vendor.IncludeOptionalField(H225_VendorIdentifier::e_productId);
	vendor.m_productId = PString(PString::Printf, "GNU Gatekeeper on %s %s %s, %s %s", (const unsigned char*)(PProcess::GetOSName()), (const unsigned char*)(PProcess::GetOSHardware()), (const unsigned char*)(PProcess::GetOSVersion()) ,__DATE__, __TIME__);
	vendor.IncludeOptionalField(H225_VendorIdentifier::e_versionId);
	vendor.m_versionId = "Version " + PProcess::Current().GetVersion();

	PIPSocket::Address sigip;
	if (GetIPFromTransportAddr(rrq.m_callSignalAddress[0], sigip)) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_nonStandardData);
		rrq.m_nonStandardData.m_data = "IP=" + sigip.AsString();
	}

	// set user provided endpointIdentifier, if any
	PString endpointId(GkConfig()->GetString(EndpointSection, "EndpointIdentifier", ""));
	if (!endpointId) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
		rrq.m_endpointIdentifier = endpointId;
	}
	// set gatekeeperIdentifier found in discovery procedure
	if (!m_gatekeeperId->GetValue()) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_gatekeeperIdentifier);
		rrq.m_gatekeeperIdentifier = *m_gatekeeperId;
	}
	rrq.m_keepAlive = FALSE;
}

void GkClient::BuildLightWeightRRQ(H225_RegistrationRequest & rrq)
{
	rrq.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
	rrq.m_endpointIdentifier = *m_endpointId;
	rrq.IncludeOptionalField(H225_RegistrationRequest::e_gatekeeperIdentifier);
	rrq.m_gatekeeperIdentifier = *m_gatekeeperId;
	rrq.m_keepAlive = TRUE;
}

bool GkClient::WaitForACF(RasRequester & request, Routing::RoutingRequest *robj)
{
	request.SendRequest(m_gkaddr, m_gkport);
	if (request.WaitForResponse(5000)) {
		RasMsg *ras = request.GetReply();
		if (ras->GetTag() == H225_RasMessage::e_admissionConfirm) {
			if (robj) {
				H225_AdmissionConfirm & acf = (*ras)->m_recvRAS;
				robj->SetDestination(acf.m_destCallSignalAddress);
				robj->SetFlag(Routing::RoutingRequest::e_toParent);
			}
			return true;
		}
		if (ras->GetTag() == H225_RasMessage::e_admissionReject)
			OnARJ(ras);
	}
	return false;
}

H225_AdmissionRequest & GkClient::BuildARQ(H225_AdmissionRequest & arq)
{
	arq.m_callType.SetTag(H225_CallType::e_pointToPoint);

	arq.m_endpointIdentifier = *m_endpointId;

	arq.IncludeOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress);
	arq.m_srcCallSignalAddress = m_rasSrv->GetCallSignalAddress(m_loaddr);

	arq.IncludeOptionalField(H225_AdmissionRequest::e_canMapAlias);
	arq.m_canMapAlias = TRUE;

	arq.IncludeOptionalField(H225_AdmissionRequest::e_gatekeeperIdentifier);
	arq.m_gatekeeperIdentifier = *m_gatekeeperId;

	SetPassword(arq);

	return arq;
}

void GkClient::OnRCF(RasMsg *ras)
{
	H225_RegistrationConfirm & rcf = (*ras)->m_recvRAS;
	if (!IsRegistered()) {
		PTRACE(2, "GKC\tRegister with " << AsString(m_gkaddr, m_gkport) << " successfully");
		m_registered = true;
		*m_endpointId = rcf.m_endpointIdentifier;
		*m_gatekeeperId = rcf.m_gatekeeperIdentifier;
		if (rcf.HasOptionalField(H225_RegistrationConfirm::e_alternateGatekeeper))
			m_gkList->Set(rcf.m_alternateGatekeeper);
		for_each(m_handlers, m_handlers + 4, bind1st(mem_fun(&RasServer::RegisterHandler), m_rasSrv));
	}
	
	// Not all RCF contain TTL, in that case keep old value
	if (rcf.HasOptionalField(H225_RegistrationConfirm::e_timeToLive)) {
		m_ttl = PMAX(rcf.m_timeToLive - m_retry, 30);
		// Have it reregister at 3/4 of TimeToLive, otherwise the parent
		// might go out of sync and ends up sending an URQ
		m_ttl = (m_ttl / 4) * 3;
	}
	
	m_timer = m_ttl * 1000;
	m_resend = m_retry;

	// NAT handling
	if (rcf.HasOptionalField(H225_RegistrationConfirm::e_nonStandardData))
		if (rcf.m_nonStandardData.m_data.AsString().Find("NAT=") == 0)
			if (!m_natClient && rcf.m_callSignalAddress.GetSize() > 0)
				m_natClient = new NATClient(rcf.m_callSignalAddress[0], *m_endpointId);
}

void GkClient::OnRRJ(RasMsg *ras)
{
	H225_RegistrationReject & rrj = (*ras)->m_recvRAS;
	m_rrjReason =  "Reason: " + rrj.m_rejectReason.GetTagName();
	PTRACE(1, "GKC\tRegistration Rejected: " << rrj.m_rejectReason.GetTagName());

	if (rrj.HasOptionalField(H225_RegistrationReject::e_altGKInfo)) {
		m_gkList->Set(rrj.m_altGKInfo.m_alternateGatekeeper);
		m_useAltGKPermanent = rrj.m_altGKInfo.m_altGKisPermanent;
		GetAltGK();
	} else if (rrj.m_rejectReason.GetTag() == H225_RegistrationRejectReason::e_fullRegistrationRequired) {
		SendURQ();
		m_timer = 100;
		Toolkit::Instance()->GetRouteTable()->InitTable();
	}
}

void GkClient::OnARJ(RasMsg *ras)
{
	H225_AdmissionReject & arj = (*ras)->m_recvRAS;
	if (arj.HasOptionalField(H225_AdmissionReject::e_altGKInfo)) {
		m_gkList->Set(arj.m_altGKInfo.m_alternateGatekeeper);
		m_useAltGKPermanent = arj.m_altGKInfo.m_altGKisPermanent;
		GetAltGK();
	} else if (arj.m_rejectReason.GetTag() == H225_AdmissionRejectReason::e_callerNotRegistered) {
		Unregister();
		m_timer = 100; // re-register again
	}
}

bool GkClient::OnURQ(RasMsg *ras)
{
	Unregister();

	m_registeredTime = PTime();
	H225_UnregistrationRequest & urq = (*ras)->m_recvRAS;
	switch (urq.m_reason.GetTag())
	{
		case H225_UnregRequestReason::e_reregistrationRequired:
		case H225_UnregRequestReason::e_ttlExpired:
			m_timer = 500;
			break;

		default:
			m_timer = m_retry * 1000;
			if (urq.HasOptionalField(H225_UnregistrationRequest::e_alternateGatekeeper)) {
				m_gkList->Set(urq.m_alternateGatekeeper);
				GetAltGK();
			}
			break;
	}

	(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_unregistrationConfirm);
	H225_UnregistrationConfirm & ucf = (*ras)->m_replyRAS;
	ucf.m_requestSeqNum = urq.m_requestSeqNum;
	return true;
}

bool GkClient::OnDRQ(RasMsg *ras)
{
	H225_DisengageRequest & drq = (*ras)->m_recvRAS;
	if (callptr call = drq.HasOptionalField(H225_DisengageRequest::e_callIdentifier) ? CallTable::Instance()->FindCallRec(drq.m_callIdentifier) : CallTable::Instance()->FindCallRec(drq.m_callReferenceValue))
		call->Disconnect(true);

	(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_disengageConfirm); 
	H225_DisengageConfirm & dcf = (*ras)->m_replyRAS;
	dcf.m_requestSeqNum = drq.m_requestSeqNum;
	return true;
}

bool GkClient::OnBRQ(RasMsg *ras)
{
	// lazy implementation, just reply confirm
	H225_BandwidthRequest & brq = (*ras)->m_recvRAS;
	(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_bandwidthConfirm);
	H225_BandwidthConfirm & bcf = (*ras)->m_replyRAS;
	bcf.m_requestSeqNum = brq.m_requestSeqNum;
	bcf.m_bandWidth = brq.m_bandWidth;
	return true;
}

bool GkClient::OnIRQ(RasMsg *ras)
{
	// TODO
	H225_InfoRequest & irq = (*ras)->m_recvRAS;
	(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_infoRequestResponse);
	H225_InfoRequestResponse & irr = (*ras)->m_replyRAS;
	irr.m_requestSeqNum = irq.m_requestSeqNum;
	return true;
}

bool GkClient::RewriteString(PString & alias, bool fromInternal) const
{
	if (!m_rewriteInfo)
		return false;
	for (PINDEX i = 0; i < m_rewriteInfo->Size(); ++i) {
		PString prefix, insert;
		if (fromInternal) {
			insert = m_rewriteInfo->Key(i);
			prefix = m_rewriteInfo->Value(i);
		} else {
			prefix = m_rewriteInfo->Key(i);
			insert = m_rewriteInfo->Value(i);
		}
		int len = prefix.GetLength();
		if (len == 0 || strncmp(prefix, alias, len) == 0){
			PString result = insert + alias.Mid(len);
			PTRACE(2, "GKC\tRewritePString: " << alias << " to " << result);
			alias = result;
			return true;
		}
	}
	return false;
}

void GkClient::SetClearTokens(H225_ArrayOf_ClearToken & clearTokens, const PString & id)
{
	clearTokens.RemoveAll();
	H235AuthCAT auth;
	// avoid copying for thread-safely
	auth.SetLocalId((const char *)id);
	auth.SetPassword((const char *)m_password);
	H225_ArrayOf_CryptoH323Token dumbTokens;
	auth.PrepareTokens(clearTokens, dumbTokens);
}

void GkClient::SetCryptoTokens(H225_ArrayOf_CryptoH323Token & cryptoTokens, const PString & id)
{
	cryptoTokens.RemoveAll();
	H235AuthSimpleMD5 auth;
	// avoid copying for thread-safely
	auth.SetLocalId((const char *)id);
	auth.SetPassword((const char *)m_password);
	H225_ArrayOf_ClearToken dumbTokens;
	auth.PrepareTokens(dumbTokens, cryptoTokens);
}

void GkClient::SetRasAddress(H225_ArrayOf_TransportAddress & addr)
{
	addr.SetSize(1);
	addr[0] = m_rasSrv->GetRasAddress(m_loaddr);
}

void GkClient::SetCallSignalAddress(H225_ArrayOf_TransportAddress & addr)
{
	addr.SetSize(1);
	addr[0] = m_rasSrv->GetCallSignalAddress(m_loaddr);
}

void GkClient::SetNBPassword(
	H225_LocationRequest& lrq, /// LRQ message to be filled with tokens
	const PString& id // login name
	)
{
	if (!m_password) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_cryptoTokens), SetCryptoTokens(lrq.m_cryptoTokens, id);
		lrq.IncludeOptionalField(H225_LocationRequest::e_tokens), SetClearTokens(lrq.m_tokens, id);
	}
}
