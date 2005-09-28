//////////////////////////////////////////////////////////////////
//
// bookkeeping for RAS-Server in H.323 gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//  990500	initial version (Xiang Ping Chen, Rajat Todi, Joe Metzger)
//  990600	ported to OpenH323 V. 1.08 (Jan Willamowius)
//  991003	switched to STL (Jan Willamowius)
//  000215	call removed from table when <=1 ep remains; marked with "towi*1" (towi)
//
//////////////////////////////////////////////////////////////////


#if defined(_WIN32) && (_MSC_VER <= 1200)  
#pragma warning(disable:4786) // warning about too long debug symbol off
#pragma warning(disable:4284)
#define snprintf	_snprintf
#endif

#include <time.h>
#include <ptlib.h>
#include <h323pdu.h>
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "stl_supp.h"
#include "SoftPBX.h"
#include "RasSrv.h"
#include "GkClient.h"
#include "GkStatus.h"
#include "ProxyChannel.h"
#include "gkacct.h"
#include "RasTbl.h"

using std::copy;
using std::partition;
using std::back_inserter;
using std::transform;
using std::mem_fun;
using std::bind2nd;
using std::equal_to;
using std::find;
using std::find_if;
using std::distance;
using std::sort;
using std::string;

const char *CallTableSection = "CallTable";
const char *RRQFeaturesSection = "RasSrv::RRQFeatures";

namespace {
const long DEFAULT_SIGNAL_TIMEOUT = 15000;
const long DEFAULT_ALERTING_TIMEOUT = 180000;
const int DEFAULT_IRQ_POLL_COUNT = 1;
}

EndpointRec::EndpointRec(
	/// RRQ, ARQ, ACF or LCF that contains a description of the endpoint
	const H225_RasMessage& ras, 
	/// permanent endpoint flag
	bool permanent
	)
	: m_RasMsg(ras), m_timeToLive(1),
	m_activeCall(0), m_connectedCall(0), m_totalCall(0),
	m_pollCount(GkConfig()->GetInteger(RRQFeaturesSection, "IRQPollCount", DEFAULT_IRQ_POLL_COUNT)),
	m_usedCount(0), m_nat(false), m_natsocket(0), m_permanent(permanent), 
	m_hasCallCreditCapabilities(false), m_callCreditSession(-1),
	m_capacity(-1)
{
	switch (m_RasMsg.GetTag())
	{
		case H225_RasMessage::e_registrationRequest:
			SetEndpointRec((H225_RegistrationRequest &)m_RasMsg);
			PTRACE(1, "New EP|" << PrintOn(false));
			break;
		case H225_RasMessage::e_admissionRequest:
			SetEndpointRec((H225_AdmissionRequest &)m_RasMsg);
			break;
		case H225_RasMessage::e_admissionConfirm:
			SetEndpointRec((H225_AdmissionConfirm &)m_RasMsg);
			break;
		case H225_RasMessage::e_locationConfirm:
			SetEndpointRec((H225_LocationConfirm &)m_RasMsg);
			break;
		default: // should not happen
			break;
	}
	if (permanent)
		m_timeToLive = 0;
		
	LoadEndpointConfig();
}	

void EndpointRec::SetEndpointRec(H225_RegistrationRequest & rrq)
{
	if (rrq.m_rasAddress.GetSize() > 0)
		m_rasAddress = rrq.m_rasAddress[0];
	else
		m_rasAddress.SetTag(H225_TransportAddress::e_nonStandardAddress);
	if (rrq.m_callSignalAddress.GetSize() > 0)
		m_callSignalAddress = rrq.m_callSignalAddress[0];
	else
		m_callSignalAddress.SetTag(H225_TransportAddress::e_nonStandardAddress);
	m_endpointIdentifier = rrq.m_endpointIdentifier;
	m_terminalAliases = rrq.m_terminalAlias;
	m_terminalType = &rrq.m_terminalType;
	if (rrq.HasOptionalField(H225_RegistrationRequest::e_timeToLive))
		SetTimeToLive(rrq.m_timeToLive);
	else
		SetTimeToLive(SoftPBX::TimeToLive);
	m_fromParent = false;
	m_hasCallCreditCapabilities = rrq.HasOptionalField(
		H225_RegistrationRequest::e_callCreditCapability
		);
}

void EndpointRec::SetEndpointRec(H225_AdmissionRequest & arq)
{
	static H225_EndpointType termType; // nouse
	// we set it to non-standard address to avoid misuse
	m_rasAddress.SetTag(H225_TransportAddress::e_nonStandardAddress);
	m_callSignalAddress = arq.m_destCallSignalAddress;
	m_terminalType = &termType;
	m_timeToLive = (SoftPBX::TimeToLive > 0) ? SoftPBX::TimeToLive : 600;
	m_fromParent = false;
}

void EndpointRec::SetEndpointRec(H225_AdmissionConfirm & acf)
{
	// there is no RAS address in ACF
	// we set it to non-standard address to avoid misuse
	m_rasAddress.SetTag(H225_TransportAddress::e_nonStandardAddress);
	m_callSignalAddress = acf.m_destCallSignalAddress;
	if (acf.HasOptionalField(H225_AdmissionConfirm::e_destinationInfo))
		m_terminalAliases = acf.m_destinationInfo;
	if (!acf.HasOptionalField(H225_AdmissionConfirm::e_destinationType))
		acf.IncludeOptionalField(H225_AdmissionConfirm::e_destinationType);
	m_terminalType = &acf.m_destinationType;
	m_timeToLive = (SoftPBX::TimeToLive > 0) ? SoftPBX::TimeToLive : 600;
	m_fromParent = true;
}

void EndpointRec::SetEndpointRec(H225_LocationConfirm & lcf)
{
	m_rasAddress = lcf.m_rasAddress;
	m_callSignalAddress = lcf.m_callSignalAddress;
	if (lcf.HasOptionalField(H225_LocationConfirm::e_destinationInfo))
		m_terminalAliases = lcf.m_destinationInfo;
	if (!lcf.HasOptionalField(H225_LocationConfirm::e_destinationType))
		lcf.IncludeOptionalField(H225_LocationConfirm::e_destinationType);
	m_terminalType = &lcf.m_destinationType;
	m_timeToLive = (SoftPBX::TimeToLive > 0) ? SoftPBX::TimeToLive : 600;
	m_fromParent = false;
}

EndpointRec::~EndpointRec()
{
	PTRACE(3, "Gk\tDelete endpoint: " << m_endpointIdentifier.GetValue() << " " << m_usedCount);
	if (m_natsocket)
		m_natsocket->SetDeletable();
}

bool EndpointRec::LoadConfig()
{ 
	PWaitAndSignal lock(m_usedLock);
	LoadEndpointConfig();
	return true;
}

void EndpointRec::LoadEndpointConfig()
{
	PConfig* const cfg = GkConfig();
	const PStringList sections = cfg->GetSections();
	
	for (PINDEX i = 0; i < m_terminalAliases.GetSize(); i++) {
		const PString key = "EP::" + AsString(m_terminalAliases[i], FALSE);
		if (sections.GetStringsIndex(key) != P_MAX_INDEX) {
			m_capacity = cfg->GetInteger(key, "Capacity", -1);
			PTRACE(5, "RAS\tEndpoint " << key << " capacity: " << m_capacity);
			break;
		}
	}
}

/*
bool EndpointRec::PrefixMatch_IncompleteAddress(const H225_ArrayOf_AliasAddress &aliases, 
                                               bool &fullMatch) const
{
        fullMatch = 0;
        int partialMatch = 0;
        PString aliasStr;
	PINDEX aliasStr_len;
	const H225_ArrayOf_AliasAddress & reg_aliases = GetAliases();
	PString reg_alias;
	// for each given alias (dialedDigits) from request message 
	for(PINDEX i = 0; i < aliases.GetSize() && !fullMatch; i++) {
//          if (aliases[i].GetTag() == H225_AliasAddress::e_dialedDigits) {
	    aliasStr = AsString(aliases[i], FALSE);
	    aliasStr_len = aliasStr.GetLength();
	    // for each alias (dialedDigits) which is stored for the endpoint in registration
	    for (PINDEX i = 0; i < reg_aliases.GetSize() && !fullMatch; i++) {
//              if (reg_aliases[i].GetTag() == H225_AliasAddress::e_dialedDigits) {
	        reg_alias = AsString(reg_aliases[i], FALSE);
                // if alias from request message is prefix to alias which is 
		//   stored in registration
	        if ((reg_alias.GetLength() >= aliasStr_len) && 
		    (aliasStr == reg_alias.Left(aliasStr_len))) {
		  // check if it is a full match 
		  if (aliasStr == reg_alias) {
		    fullMatch = 1;
  		    PTRACE(2, ANSI::DBG << "Alias " << aliasStr << " matches endpoint " 
		      << (const unsigned char *)m_endpointIdentifier.GetValue() << " (full)" << ANSI::OFF);
  		  } else {
		    partialMatch = 1;
  		    PTRACE(2, ANSI::DBG << "Alias " << aliasStr << " matches endpoint " 
		      << (const unsigned char *)m_endpointIdentifier.GetValue() << " (partial)" << ANSI::OFF);
		  }
	        }
//	      }
	    }
//	  }
	}
	return (partialMatch || fullMatch);
}
*/

void EndpointRec::SetCapacity(
	int newCapacity /// max number of concurrent calls, -1 means no limit
	) 
{ 
	m_capacity = newCapacity; 
}

void EndpointRec::SetTimeToLive(int seconds)
{
	PWaitAndSignal lock(m_usedLock);

	if (m_timeToLive > 0 && !m_permanent) {
		// To avoid bloated RRQ traffic, don't allow ttl < 60
		if (seconds < 60)
			seconds = 60;
		m_timeToLive = (SoftPBX::TimeToLive > 0) ?
			std::min(SoftPBX::TimeToLive, seconds) : 0;
	}
}

void EndpointRec::SetSocket(CallSignalSocket *socket)
{
	PWaitAndSignal lock(m_usedLock);
	if (m_natsocket != socket) {
		PTRACE(3, "Q931\tNAT socket detected at " << socket->Name() << " for endpoint " << GetEndpointIdentifier().GetValue());
		if (m_natsocket) {
			PTRACE(1, "Q931\tWarning: natsocket " << m_natsocket->Name()
				<< " is overwritten by " << socket->Name()
				);
			m_natsocket->SetDeletable();
		}
		m_natsocket = socket;
	}
}

void EndpointRec::SetRasAddress(const H225_TransportAddress &a)
{
	PWaitAndSignal lock(m_usedLock);
	m_rasAddress = a;
}

void EndpointRec::SetEndpointIdentifier(const H225_EndpointIdentifier &i)
{
	PWaitAndSignal lock(m_usedLock);
	m_endpointIdentifier = i;
}

void EndpointRec::SetAliases(const H225_ArrayOf_AliasAddress &a)
{
	{
		PWaitAndSignal lock(m_usedLock);
		m_terminalAliases = a;
	}
	LoadConfig(); // update settings for the new aliases
}

void EndpointRec::SetEndpointType(const H225_EndpointType &t) 
{
	{
		PWaitAndSignal lock(m_usedLock);
		*m_terminalType = t;
	}
	LoadConfig(); // update settings for the new endpoint type
}

void EndpointRec::SetNATAddress(const PIPSocket::Address & ip)
{
	PWaitAndSignal lock(m_usedLock);

	m_nat = true;
	m_natip = ip;

	// we keep the original private IP in signalling address,
	// because we have to use it to identify different endpoints
	// but from the same NAT box
	if (m_rasAddress.GetTag() != H225_TransportAddress::e_ipAddress)
		m_rasAddress.SetTag(H225_TransportAddress::e_ipAddress);
	H225_TransportAddress_ipAddress & rasip = m_rasAddress;
	for (int i = 0; i < 4; ++i)
		rasip.m_ip[i] = ip[i];
}


// due to strange bug of gcc, I have to pass pointer instead of reference
bool EndpointRec::CompareAlias(const H225_ArrayOf_AliasAddress *a) const
{
	for (PINDEX i = 0; i < a->GetSize(); i++) {
		PWaitAndSignal lock(m_usedLock);
		for (PINDEX j = 0; j < m_terminalAliases.GetSize(); j++)
			if ((*a)[i] == m_terminalAliases[j])
				return true;
	}
	return false;
}

bool EndpointRec::MatchAlias(
	const H225_ArrayOf_AliasAddress& aliases,
	int& matchedalias
	) const
{
	for (PINDEX i = 0; i < aliases.GetSize(); i++) {
		PWaitAndSignal lock(m_usedLock);
		for (PINDEX j = 0; j < m_terminalAliases.GetSize(); j++)
			if (aliases[i] == m_terminalAliases[j]) {
				matchedalias = i;
				return true;
			}
	}
	return false;
}

void EndpointRec::Update(const H225_RasMessage & ras_msg)
{
	if (ras_msg.GetTag() == H225_RasMessage::e_registrationRequest) {
		const H225_RegistrationRequest & rrq = ras_msg;

		// don't update rasAddress for nated endpoint
		if (!m_nat && (rrq.m_rasAddress.GetSize() >= 1))
			SetRasAddress(rrq.m_rasAddress[0]);

		if (rrq.HasOptionalField(H225_RegistrationRequest::e_timeToLive))
			SetTimeToLive(rrq.m_timeToLive);

		// H.225.0v4: ignore fields other than rasAddress, endpointIdentifier,
		// timeToLive for a lightweightRRQ
		if (!(rrq.HasOptionalField(H225_RegistrationRequest::e_keepAlive) && rrq.m_keepAlive)) {
			if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)
				&& (rrq.m_terminalAlias.GetSize() >= 1))
				SetAliases(rrq.m_terminalAlias);
		}
	} else if (ras_msg.GetTag() == H225_RasMessage::e_locationConfirm) {
		const H225_LocationConfirm & lcf = ras_msg;
		SetRasAddress(lcf.m_rasAddress);
		if (lcf.HasOptionalField(H225_LocationConfirm::e_destinationInfo))
			SetAliases(lcf.m_destinationInfo);
	}
	PWaitAndSignal lock(m_usedLock);
	m_updatedTime = PTime();
	m_pollCount = GkConfig()->GetInteger(RRQFeaturesSection, "IRQPollCount", DEFAULT_IRQ_POLL_COUNT);
}

EndpointRec *EndpointRec::Unregister()
{
	SendURQ(H225_UnregRequestReason::e_maintenance);
	return this;
}

EndpointRec *EndpointRec::Expired()
{
	SendURQ(H225_UnregRequestReason::e_ttlExpired);
	return this;
}

/*
void EndpointRec::BuildACF(H225_AdmissionConfirm & obj_acf) const
{
	obj_acf.IncludeOptionalField(H225_AdmissionConfirm::e_destinationInfo);
	obj_acf.m_destinationInfo = GetAliases();
	obj_acf.IncludeOptionalField(H225_AdmissionConfirm::e_destinationType);
	obj_acf.m_destinationType = GetEndpointType();
}

void EndpointRec::BuildLCF(H225_LocationConfirm & obj_lcf) const
{
	obj_lcf.m_callSignalAddress = GetCallSignalAddress();
	obj_lcf.m_rasAddress = GetRasAddress();
	extern const char *LRQFeaturesSection;
	if (Toolkit::AsBool(GkConfig()->GetString(LRQFeaturesSection, "IncludeDestinationInfoInLCF", "1"))) {
		obj_lcf.IncludeOptionalField(H225_LocationConfirm::e_destinationInfo);
		obj_lcf.m_destinationInfo = GetAliases();
		obj_lcf.IncludeOptionalField(H225_LocationConfirm::e_destinationType);
		obj_lcf.m_destinationType = GetEndpointType();
	}
}
*/

PString EndpointRec::PrintOn(bool verbose) const
{
	PString msg(PString::Printf, "%s|%s|%s|%s\r\n",
		    (const unsigned char *) AsDotString(GetCallSignalAddress()),
		    (const unsigned char *) AsString(GetAliases()),
		    (const unsigned char *) AsString(GetEndpointType()),
		    (const unsigned char *) GetEndpointIdentifier().GetValue() );
	if (verbose) {
		msg += GetUpdatedTime().AsString();
		if (IsPermanent())
			msg += " (permanent)";
		PString natstring(IsNATed() ? m_natip.AsString() : PString());
		PWaitAndSignal lock(m_usedLock);
		msg += PString(PString::Printf, " C(%d/%d/%d) %s <%d>\r\n", m_activeCall, m_connectedCall, m_totalCall, (const unsigned char *)natstring, m_usedCount);
	}
	return msg;
}

bool EndpointRec::SendURQ(H225_UnregRequestReason::Choices reason)
{
	if (GetRasAddress().GetTag() != H225_TransportAddress::e_ipAddress)
		return false;  // no valid ras address

	RasServer *RasSrv = RasServer::Instance();
	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_unregistrationRequest);
	H225_UnregistrationRequest & urq = ras_msg;
	urq.m_requestSeqNum.SetValue(RasSrv->GetRequestSeqNum());
	urq.IncludeOptionalField(urq.e_gatekeeperIdentifier);
	urq.m_gatekeeperIdentifier = Toolkit::GKName();
	urq.IncludeOptionalField(urq.e_endpointIdentifier);
	urq.m_endpointIdentifier = GetEndpointIdentifier();
	urq.m_callSignalAddress.SetSize(1);
	urq.m_callSignalAddress[0] = GetCallSignalAddress();
	urq.IncludeOptionalField(H225_UnregistrationRequest::e_reason);
	urq.m_reason.SetTag(reason);

	PString msg(PString::Printf, "URQ|%s|%s|%s;\r\n", 
			(const unsigned char *) AsDotString(GetRasAddress()),
			(const unsigned char *) GetEndpointIdentifier().GetValue(),
			(const unsigned char *) urq.m_reason.GetTagName());
        GkStatus::Instance()->SignalStatus(msg, STATUS_TRACE_LEVEL_RAS);

	RasSrv->ForwardRasMsg(ras_msg);
	if (reason == H225_UnregRequestReason::e_maintenance)
		RasSrv->SetAlternateGK(urq);
	RasSrv->SendRas(ras_msg, GetRasAddress());
	return true;
}

bool EndpointRec::SendIRQ()
{
	if (m_pollCount <= 0 || GetRasAddress().GetTag() != H225_TransportAddress::e_ipAddress)
		return false;
	--m_pollCount;
	
	RasServer *RasSrv = RasServer::Instance();
	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_infoRequest);
	H225_InfoRequest & irq = ras_msg;
	irq.m_requestSeqNum.SetValue(RasSrv->GetRequestSeqNum());
	irq.m_callReferenceValue.SetValue(0); // ask for each call

	PString msg(PString::Printf, "IRQ|%s|%s;\r\n", 
			(const unsigned char *) AsDotString(GetRasAddress()),
			(const unsigned char *) GetEndpointIdentifier().GetValue());
        GkStatus::Instance()->SignalStatus(msg, STATUS_TRACE_LEVEL_RAS);
	RasSrv->SendRas(ras_msg, GetRasAddress());

	return true;
}

void EndpointRec::AddCallCreditServiceControl(
	H225_ArrayOf_ServiceControlSession& sessions, /// array to add the service control descriptor to
	const PString& amountStr, /// user's account balance amount string
	int billingMode, /// user's account billing mode (-1 if not set)
	long callDurationLimit /// call duration limit (-1 if not set)
	)
{
	const PINDEX sessionIndex = sessions.GetSize();
	sessions.SetSize(sessionIndex + 1);
	H225_ServiceControlSession& session = sessions[sessionIndex];

	// in future we may want to assign this dynamically to allow multiple
	// service control sessions
	if (m_callCreditSession == -1) {
		session.m_sessionId = m_callCreditSession = 0;
		session.m_reason = H225_ServiceControlSession_reason::e_open;
	} else {
		session.m_sessionId = m_callCreditSession;
		session.m_reason = H225_ServiceControlSession_reason::e_refresh;
	}

	session.IncludeOptionalField(H225_ServiceControlSession::e_contents);
	session.m_contents.SetTag(H225_ServiceControlDescriptor::e_callCreditServiceControl);
	H225_CallCreditServiceControl& callCreditSession = session.m_contents;
	
	if (!amountStr) {
		callCreditSession.IncludeOptionalField(H225_CallCreditServiceControl::e_amountString);
		callCreditSession.m_amountString = amountStr;
	}
	if (billingMode >= 0) {
		callCreditSession.IncludeOptionalField(H225_CallCreditServiceControl::e_billingMode);
		callCreditSession.m_billingMode = billingMode;
	}
	if (callDurationLimit > 0) {
		callCreditSession.IncludeOptionalField(H225_CallCreditServiceControl::e_callDurationLimit);
		callCreditSession.m_callDurationLimit = callDurationLimit;
		callCreditSession.IncludeOptionalField(H225_CallCreditServiceControl::e_enforceCallDurationLimit);
		callCreditSession.m_enforceCallDurationLimit = TRUE;
	}
	callCreditSession.IncludeOptionalField(H225_CallCreditServiceControl::e_callStartingPoint);
	callCreditSession.m_callStartingPoint.SetTag(H225_CallCreditServiceControl_callStartingPoint::e_connect);
}


GatewayRec::GatewayRec(const H225_RasMessage &completeRRQ, bool Permanent)
      : EndpointRec(completeRRQ, Permanent), defaultGW(false)
{
	Prefixes.reserve(8);
	LoadGatewayConfig(); // static binding
}

bool GatewayRec::LoadConfig()
{
	EndpointRec::LoadConfig();
	PWaitAndSignal lock(m_usedLock);
	LoadGatewayConfig();
	return true;
}

void GatewayRec::LoadGatewayConfig()
{
	PConfig* const cfg = GkConfig();
	const PStringList sections = cfg->GetSections();
	
	Prefixes.clear();
	
	if (Toolkit::AsBool(cfg->GetString(RRQFeaturesSection, "AcceptGatewayPrefixes", "1")))
		if (m_terminalType->m_gateway.HasOptionalField(H225_GatewayInfo::e_protocol))
			AddPrefixes(m_terminalType->m_gateway.m_protocol);
			
	for (PINDEX i = 0; i < m_terminalAliases.GetSize(); i++) {
		const PString alias = AsString(m_terminalAliases[i], FALSE);
		if (!alias) {
			AddPrefixes(cfg->GetString("RasSrv::GWPrefixes", alias, ""));
			const PString key = "EP::" + AsString(m_terminalAliases[i], FALSE);
			if (sections.GetStringsIndex(key) != P_MAX_INDEX) {
				AddPrefixes(cfg->GetString(key, "GatewayPrefixes", ""));
				priority = cfg->GetInteger(key, "GatewayPriority", 1);
				PTRACE(5, "RAS\tGateway " << key << " priority: " << priority);
				break;
			}
		}
	}

	SortPrefixes();
}

void GatewayRec::SetPriority(
	int newPriority
	) 
{
	priority = newPriority;
}

void GatewayRec::SetEndpointType(const H225_EndpointType &t)
{
	if (!t.HasOptionalField(H225_EndpointType::e_gateway)) {
		PTRACE(1, "RRJ: terminal type changed|" << (const unsigned char *)m_endpointIdentifier.GetValue());
		return;
	}
	EndpointRec::SetEndpointType(t);
}

void GatewayRec::Update(const H225_RasMessage & ras_msg)
{
    if (ras_msg.GetTag() == H225_RasMessage::e_registrationRequest) {
		const H225_RegistrationRequest & rrq = ras_msg;
		if (!(rrq.HasOptionalField(H225_RegistrationRequest::e_keepAlive) && rrq.m_keepAlive))
			SetEndpointType(rrq.m_terminalType);
	} else if (ras_msg.GetTag() == H225_RasMessage::e_locationConfirm) {
		const H225_LocationConfirm & lcf = ras_msg;
		if (lcf.HasOptionalField(H225_LocationConfirm::e_destinationType))
			SetEndpointType(lcf.m_destinationType);
	}
			
	EndpointRec::Update(ras_msg);
}

void GatewayRec::AddPrefixes(const H225_ArrayOf_SupportedProtocols &protocols)
{
	for (PINDEX i = 0; i < protocols.GetSize(); ++i) {
		H225_SupportedProtocols &p = protocols[i];
		H225_ArrayOf_SupportedPrefix *supportedPrefixes = 0;
		if (p.GetTag() == H225_SupportedProtocols::e_voice) {
			H225_VoiceCaps & v = p;
			if (v.HasOptionalField(H225_VoiceCaps::e_supportedPrefixes))
				supportedPrefixes = &v.m_supportedPrefixes;
		} else if (p.GetTag() == H225_SupportedProtocols::e_h323) {
			H225_H323Caps & v = p;
			if (v.HasOptionalField(H225_H323Caps::e_supportedPrefixes))
				supportedPrefixes = &v.m_supportedPrefixes;
		} else if (p.GetTag() == H225_SupportedProtocols::e_h320) {
			H225_H320Caps & v = p;
			if (v.HasOptionalField(H225_H320Caps::e_supportedPrefixes))
				supportedPrefixes = &v.m_supportedPrefixes;
		}
		if (supportedPrefixes)
			for (PINDEX s = 0; s < supportedPrefixes->GetSize(); ++s) {
				H225_AliasAddress &a = (*supportedPrefixes)[s].m_prefix;
				if (a.GetTag() == H225_AliasAddress::e_dialedDigits)
					Prefixes.push_back((const char *)AsString(a, false));
			}
	}
}

void GatewayRec::AddPrefixes(const PString & prefixes)
{
	PStringArray p(prefixes.Tokenise(" ,;\t\n", false));
	for (PINDEX i = 0; i < p.GetSize(); ++i)
		Prefixes.push_back((const char *)p[i]);
}

void GatewayRec::SortPrefixes()
{
	// remove duplicate aliases
	sort(Prefixes.begin(), Prefixes.end(), str_prefix_greater());
	prefix_iterator Iter = std::unique(Prefixes.begin(), Prefixes.end());
	Prefixes.erase(Iter, Prefixes.end());
	defaultGW = (std::find(Prefixes.begin(), Prefixes.end(), string("*")) != Prefixes.end());
}

int GatewayRec::PrefixMatch(const H225_ArrayOf_AliasAddress &aliases) const
{
	int dummy;
	return PrefixMatch(aliases, dummy);
}

int GatewayRec::PrefixMatch(
	const H225_ArrayOf_AliasAddress& aliases,
	int& matchedalias
	) const
{
	int maxlen = 0;
	const_prefix_iterator pfxiter = Prefixes.end();
	const_prefix_iterator eIter = Prefixes.end();

	matchedalias = 0;
	
	for (PINDEX i = 0; i < aliases.GetSize(); i++) {
		const unsigned tag = aliases[i].GetTag();
		if (tag == H225_AliasAddress::e_dialedDigits
			|| tag == H225_AliasAddress::e_partyNumber
			|| tag == H225_AliasAddress::e_h323_ID) {
			
			const PString alias = AsString(aliases[i], FALSE);
			// we also allow h_323_ID aliases consisting only from digits
			if (tag == H225_AliasAddress::e_h323_ID)
				if( strspn(alias,"1234567890*#+,") != strlen(alias) )
					continue;
					
			const_prefix_iterator Iter = Prefixes.begin();
			while (Iter != eIter) {
				if (Iter->length() > (unsigned)abs(maxlen)) {
					const int len = MatchPrefix(alias, Iter->c_str());
					// replace the current match if the new prefix is longer
					// or if lengths are equal and this is a blocking rule (!)
					if (abs(len) > abs(maxlen)
						|| (len < 0 && (len + maxlen) == 0)) {
						pfxiter = Iter;
						maxlen = len;
						matchedalias = i;
					}
				}
				++Iter;
			}
		}
	}
	
	if (maxlen < 0) {
		PTRACE(2, "RASTBL\tGateway " << (const unsigned char *)m_endpointIdentifier.GetValue() 
			<< " skipped by prefix " << pfxiter->c_str()
			);
	} else if (maxlen > 0) {
		PTRACE(2, "RASTBL\tGateway " << (const unsigned char *)m_endpointIdentifier.GetValue()
			<< " matched by prefix " << pfxiter->c_str()
			);
		return maxlen;
	} else if (defaultGW) {
		// if no match has been found and this is the default gateway,
		// assume first dialedDigits or partyNumber alias match
		for (PINDEX i = 0; i < aliases.GetSize(); i++)
			if (aliases[i].GetTag() == H225_AliasAddress::e_dialedDigits
				|| aliases[i].GetTag() == H225_AliasAddress::e_partyNumber) {
				matchedalias = i;
				break;
			}
		PTRACE(2, "RASTBL\tGateway " << (const unsigned char *)m_endpointIdentifier.GetValue()
			<< " matched as a default gateway"
			);
		return 0;
	}

	return -1;
}

/*
void GatewayRec::BuildLCF(H225_LocationConfirm & obj_lcf) const
{
	EndpointRec::BuildLCF(obj_lcf);
	if (PINDEX as = Prefixes.size()) {
		obj_lcf.IncludeOptionalField(H225_LocationConfirm::e_supportedProtocols);
		obj_lcf.m_supportedProtocols.SetSize(1);
		H225_SupportedProtocols &protocol = obj_lcf.m_supportedProtocols[0];
		protocol.SetTag(H225_SupportedProtocols::e_voice);
		H225_ArrayOf_SupportedPrefix & supportedPrefixes = ((H225_VoiceCaps &)protocol).m_supportedPrefixes;
		supportedPrefixes.SetSize(as);
		const_prefix_iterator Iter = Prefixes.begin();
		for (PINDEX p=0; p < as; ++p, ++Iter)
			H323SetAliasAddress(PString(Iter->c_str()), supportedPrefixes[p].m_prefix);
	}
}
*/

PString GatewayRec::PrintOn(bool verbose) const
{
	PString msg = EndpointRec::PrintOn(verbose);
	if (verbose) {
		msg += "Prefixes: ";
		if (Prefixes.size() == 0) {
			msg += "<none>";
		} else {
			string m=Prefixes.front();
			const_prefix_iterator Iter = Prefixes.begin(), eIter= Prefixes.end();
			while (++Iter != eIter)
				m += "," + (*Iter);
			msg += m.c_str();
		}
		msg += "\r\n";
	}
	return msg;
}

OuterZoneEPRec::OuterZoneEPRec(const H225_RasMessage & completeRAS, const H225_EndpointIdentifier &epID) : EndpointRec(completeRAS, false)
{
	m_endpointIdentifier = epID;
	PTRACE(1, "New OZEP|" << PrintOn(false));
}

OuterZoneGWRec::OuterZoneGWRec(const H225_RasMessage & completeLCF, const H225_EndpointIdentifier &epID) : GatewayRec(completeLCF, false)
{
	m_endpointIdentifier = epID;

	const H225_LocationConfirm & obj_lcf = completeLCF;
	if (obj_lcf.HasOptionalField(H225_LocationConfirm::e_supportedProtocols)) {
		AddPrefixes(obj_lcf.m_supportedProtocols);
		SortPrefixes();
	}
	defaultGW = false; // don't let outer zone gateway be default
	PTRACE(1, "New OZGW|" << PrintOn(false));
}


RegistrationTable::RegistrationTable() : Singleton<RegistrationTable>("RegistrationTable")
{
	regSize = 0;
	recCnt = rand()%9000 + 1000;
	ozCnt = 1000; // arbitrary chosen constant

	LoadConfig();
}

RegistrationTable::~RegistrationTable()
{
	ClearTable();
	// since the socket has been deleted, just get it away
	ForEachInContainer(RemovedList, mem_fun(&EndpointRec::GetSocket));
	DeleteObjectsInContainer(RemovedList);
}

endptr RegistrationTable::InsertRec(H225_RasMessage & ras_msg, PIPSocket::Address ip)
{
	endptr ep;
	switch (ras_msg.GetTag())
	{
		case H225_RasMessage::e_registrationRequest: {
			H225_RegistrationRequest & rrq = ras_msg;
			if (ep = FindBySignalAdr(rrq.m_callSignalAddress[0], ip))
				ep->Update(ras_msg);
			else
				ep = InternalInsertEP(ras_msg);
			break;
		}
		case H225_RasMessage::e_admissionRequest: {
			H225_AdmissionConfirm nouse;
			H225_AdmissionRequest & arq = ras_msg;
			if (arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress) && !(ep = FindOZEPBySignalAdr(arq.m_destCallSignalAddress)))
				ep = InternalInsertOZEP(ras_msg, nouse);
			break;
		}
		case H225_RasMessage::e_admissionConfirm: {
			H225_AdmissionConfirm & acf = ras_msg;
			if (!(ep = FindOZEPBySignalAdr(acf.m_destCallSignalAddress)))
				ep = InternalInsertOZEP(ras_msg, acf);
			break;
		}
		case H225_RasMessage::e_locationConfirm: {
			H225_LocationConfirm & lcf = ras_msg;
			if ((ep = FindOZEPBySignalAdr(lcf.m_callSignalAddress)))
				ep->Update(ras_msg);
			else
				ep = InternalInsertOZEP(ras_msg, lcf);
			break;
		}
		default:
			PTRACE(1, "RegistrationTable: unable to insert " << ras_msg.GetTagName());
			break;
	}

	return ep;
}

endptr RegistrationTable::InternalInsertEP(H225_RasMessage & ras_msg)
{
	H225_RegistrationRequest & rrq = ras_msg;
	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier) ||
	    !Toolkit::AsBool(GkConfig()->GetString(RRQFeaturesSection, "AcceptEndpointIdentifier", "1"))) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
		endptr e = InternalFind(compose1(bind2nd(equal_to<H225_TransportAddress>(), rrq.m_callSignalAddress[0]),
			mem_fun(&EndpointRec::GetCallSignalAddress)), &RemovedList);
		if (e) // re-use the old endpoint identifier
			rrq.m_endpointIdentifier = e->GetEndpointIdentifier();
		else
			GenerateEndpointId(rrq.m_endpointIdentifier);
	}
	if (!(rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) && (rrq.m_terminalAlias.GetSize() >= 1))) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_terminalAlias);
		GenerateAlias(rrq.m_terminalAlias, rrq.m_endpointIdentifier);
	}

	EndpointRec *ep = 
		(rrq.m_terminalType.HasOptionalField(H225_EndpointType::e_gateway)
			|| rrq.m_terminalType.HasOptionalField(H225_EndpointType::e_mcu))
		? new GatewayRec(ras_msg) : new EndpointRec(ras_msg);
	WriteLock lock(listLock);
	EndpointList.push_back(ep);
	++regSize;
	return endptr(ep);
}

endptr RegistrationTable::InternalInsertOZEP(H225_RasMessage & ras_msg, H225_AdmissionConfirm &)
{
	H225_EndpointIdentifier epID;
	epID = "oz_" + PString(PString::Unsigned, ozCnt++) + endpointIdSuffix;
	EndpointRec *ep = new OuterZoneEPRec(ras_msg, epID);
	WriteLock lock(listLock);
	OuterZoneList.push_front(ep);
	return endptr(ep);
}

endptr RegistrationTable::InternalInsertOZEP(H225_RasMessage & ras_msg, H225_LocationConfirm & lcf)
{
	H225_EndpointIdentifier epID;
	epID = "oz_" + PString(PString::Unsigned, ozCnt++) + endpointIdSuffix;

	EndpointRec *ep;
	if (lcf.HasOptionalField(H225_LocationConfirm::e_destinationType) &&
	    (lcf.m_destinationType.HasOptionalField(H225_EndpointType::e_gateway)
			|| lcf.m_destinationType.HasOptionalField(H225_EndpointType::e_mcu)))
		ep = new OuterZoneGWRec(ras_msg, epID);
	else
		ep = new OuterZoneEPRec(ras_msg, epID);

	WriteLock lock(listLock);
	OuterZoneList.push_front(ep);
	return endptr(ep);
}

void RegistrationTable::RemoveByEndptr(const endptr & eptr)
{
	EndpointRec *ep = eptr.operator->(); // evil
	WriteLock lock(listLock);
	InternalRemove(find(EndpointList.begin(), EndpointList.end(), ep));
}

void RegistrationTable::RemoveByEndpointId(const H225_EndpointIdentifier & epId)
{
	WriteLock lock(listLock);
	InternalRemove( find_if(EndpointList.begin(), EndpointList.end(),
			compose1(bind2nd(equal_to<H225_EndpointIdentifier>(), epId),
			mem_fun(&EndpointRec::GetEndpointIdentifier)))
	);
}

void RegistrationTable::InternalRemove(iterator Iter)
{
	if (Iter == EndpointList.end()) {
	        PTRACE(1, "Warning: remove endpoint failed");
		return;
	}
	RemovedList.push_back(*Iter);
	EndpointList.erase(Iter);
	--regSize;
}

/*
template<class F> endptr RegistrationTable::InternalFind(const F & FindObject,
	const list<EndpointRec *> *List) const
{
	ReadLock lock(listLock);
	const_iterator Iter = find_if(List->begin(), List->end(), FindObject);
	return endptr((Iter != List->end()) ? *Iter : NULL);
}
*/

endptr RegistrationTable::FindByEndpointId(const H225_EndpointIdentifier & epId) const
{
	return InternalFind(compose1(bind2nd(equal_to<H225_EndpointIdentifier>(), epId),
			mem_fun(&EndpointRec::GetEndpointIdentifier)));
}

namespace { // end of anonymous namespace

class CompareSigAdr {
public:
	CompareSigAdr(const H225_TransportAddress & adr) : SigAdr(adr) {}
	bool operator()(const EndpointRec *ep) const { return ep->GetCallSignalAddress() == SigAdr; }

protected:
	const H225_TransportAddress & SigAdr;
};

class CompareSigAdrWithNAT : public CompareSigAdr {
public:
	CompareSigAdrWithNAT(const H225_TransportAddress & adr, PIPSocket::Address ip) : CompareSigAdr(adr), natip(ip) {}
	bool operator()(const EndpointRec *ep) const { return (ep->GetNATIP() == natip) && CompareSigAdr::operator()(ep); }

private:
	PIPSocket::Address natip;
};

bool operator==(const H225_TransportAddress & adr, PIPSocket::Address ip)
{
	if (ip == INADDR_ANY)
		return true;
	PIPSocket::Address ipaddr;
	return GetIPFromTransportAddr(adr, ipaddr) ? (ip == ipaddr) : false;
}

} // end of anonymous namespace

endptr RegistrationTable::FindBySignalAdr(const H225_TransportAddress & sigAd, PIPSocket::Address ip) const
{
	return (sigAd == ip) ? InternalFind(CompareSigAdr(sigAd)) : InternalFind(CompareSigAdrWithNAT(sigAd, ip));
}

endptr RegistrationTable::FindOZEPBySignalAdr(const H225_TransportAddress & sigAd) const
{
	return InternalFind(compose1(bind2nd(equal_to<H225_TransportAddress>(), sigAd),
			mem_fun(&EndpointRec::GetCallSignalAddress)), &OuterZoneList);
}

endptr RegistrationTable::FindByAliases(const H225_ArrayOf_AliasAddress & alias) const
{
	return InternalFind(bind2nd(mem_fun(&EndpointRec::CompareAlias), &alias));
}

endptr RegistrationTable::FindEndpoint(const H225_ArrayOf_AliasAddress & alias, bool r, bool s)
{
	endptr ep = InternalFindEP(alias, &EndpointList, r);
	return (ep) ? ep : s ? InternalFindEP(alias, &OuterZoneList, r) : endptr(0);
}

namespace {
struct GWPtr {
	GWPtr(GatewayRec *gw) : gwptr(gw) {}
	GatewayRec* operator->() const { return gwptr; }
	bool operator <(const GWPtr &gw) { return gwptr->GetPriority() < gw->GetPriority(); }
	GatewayRec *gwptr;
private:
	GWPtr();
};
} /* namespace */

endptr RegistrationTable::InternalFindEP(const H225_ArrayOf_AliasAddress & alias,
	std::list<EndpointRec *> *List, bool roundrobin)
{
	endptr ep = InternalFind(bind2nd(mem_fun(&EndpointRec::CompareAlias), &alias), List);
	if (ep) {
		PTRACE(4, "Alias match for EP " << AsDotString(ep->GetCallSignalAddress()));
        return ep;
	}

	int maxlen = 0;
	std::list<GWPtr> GWlist;
	listLock.StartRead();
	const_iterator Iter = List->begin(), IterLast = List->end();
	while (Iter != IterLast) {
		if ((*Iter)->IsGateway()) {
			int len = dynamic_cast<GatewayRec *>(*Iter)->PrefixMatch(alias);
			if (maxlen < len) {
				GWlist.clear();
				maxlen = len;
			}
			if (maxlen == len)
				GWlist.push_back(GWPtr(dynamic_cast<GatewayRec*>(*Iter)));
		}
		++Iter;
	}
	listLock.EndRead();

	if (GWlist.size() > 0) {
		GWlist.sort();
		
		std::list<GWPtr>::const_iterator i = GWlist.begin();
		GatewayRec *e = GWlist.front().gwptr;
		while (!e->HasAvailableCapacity() && ++i != GWlist.end()) {
			PTRACE(5, "Capacity exceeded in GW " << AsDotString(e->GetCallSignalAddress()));
			e = i->gwptr;
		}
		if ((GWlist.size() > 1) && roundrobin) {
			PTRACE(3, "Prefix apply round robin");
			WriteLock lock(listLock);
			List->remove(e);
			List->push_back(e);
		}
		PTRACE(4, "Prefix match for GW " << AsDotString(e->GetCallSignalAddress()));
		return endptr(e);
	}
	
	return endptr(0);
}

void RegistrationTable::GenerateEndpointId(H225_EndpointIdentifier & NewEndpointId)
{
	NewEndpointId = PString(PString::Unsigned, ++recCnt) + endpointIdSuffix;
}


void RegistrationTable::GenerateAlias(H225_ArrayOf_AliasAddress & AliasList, const H225_EndpointIdentifier & endpointId) const
{
	AliasList.SetSize(1);
	H323SetAliasAddress(endpointId, AliasList[0]);
}

void RegistrationTable::PrintAllRegistrations(USocket *client, BOOL verbose)
{
	PString msg("AllRegistrations\r\n");
	InternalPrint(client, verbose, &EndpointList, msg);
}

void RegistrationTable::PrintAllCached(USocket *client, BOOL verbose)
{
	PString msg("AllCached\r\n");
	InternalPrint(client, verbose, &OuterZoneList, msg);
}

void RegistrationTable::PrintRemoved(USocket *client, BOOL verbose)
{
	PString msg("AllRemoved\r\n");
	InternalPrint(client, verbose, &RemovedList, msg);
}

void RegistrationTable::InternalPrint(USocket *client, BOOL verbose, std::list<EndpointRec *> * List, PString & msg)
{
	// copy the pointers into a temporary array to avoid large lock
	listLock.StartRead();
	const_iterator IterLast = List->end();
	unsigned k = 0, s = List->size();
	endptr *eptr = new endptr[s];
	for (const_iterator Iter = List->begin(); Iter != IterLast; ++Iter)
		eptr[k++] = endptr(*Iter);
	listLock.EndRead();
	// end of lock

	if (s > 1000) // set buffer to avoid reallocate
		msg.SetSize(s * (verbose ? 200 : 100));
	for (k = 0; k < s; k++)
		msg += "RCF|" + eptr[k]->PrintOn(verbose);
	delete [] eptr;

	msg += PString(PString::Printf, "Number of Endpoints: %u\r\n;\r\n", s);
	client->TransmitData(msg);
}

void RegistrationTable::InternalStatistics(const std::list<EndpointRec *> *List, unsigned & s, unsigned & t, unsigned & g, unsigned & n) const
{
	ReadLock lock(listLock);
	s = List->size(), t = g = n = 0;
	const_iterator IterLast = List->end();
	for (const_iterator Iter = List->begin(); Iter != IterLast; ++Iter) {
		EndpointRec *ep = *Iter;
		++(ep->IsGateway() ? g : t);
		if (ep->IsNATed())
			++n;
	}
}

PString RegistrationTable::PrintStatistics() const
{
	unsigned es, et, eg, en;
	InternalStatistics(&EndpointList, es, et, eg, en);
	unsigned cs, ct, cg, cn; // cn is useless
	InternalStatistics(&OuterZoneList, cs, ct, cg, cn);

	return PString(PString::Printf, "-- Endpoint Statistics --\r\n"
		"Total Endpoints: %u  Terminals: %u  Gateways: %u  NATed: %u\r\n"
		"Cached Endpoints: %u  Terminals: %u  Gateways: %u\r\n",
		es, et, eg, en, cs, ct, cg);
}

void RegistrationTable::LoadConfig()
{
	endpointIdSuffix = GkConfig()->GetString("EndpointIDSuffix", "_endp");

	// Load config for each endpoint
	if (regSize > 0) {
		ReadLock lock(listLock);
		ForEachInContainer(EndpointList, mem_fun(&EndpointRec::LoadConfig));
	}

	// Load permanent endpoints
	PStringToString cfgs=GkConfig()->GetAllKeyValues("RasSrv::PermanentEndpoints");

	// first, remove permanent endpoints deleted from the config
	{
		WriteLock lock(listLock);
		iterator iter = EndpointList.begin(), endIter = EndpointList.end();
		while (iter != endIter) {
			iterator epIter = iter++;
			EndpointRec *ep = *epIter;
			if (!ep->IsPermanent())
				continue;
			// find a corresponing permanent endpoint entry in the config file
			const H225_TransportAddress& epSigAddr = ep->GetCallSignalAddress();
			PINDEX i;
			for (i = 0; i < cfgs.GetSize(); ++i) {
				H225_TransportAddress taddr;
				if (GetTransportAddress(cfgs.GetKeyAt(i), (WORD)GkConfig()->GetInteger("EndpointSignalPort", GK_DEF_ENDPOINT_SIGNAL_PORT), taddr))
					if (taddr == epSigAddr)
						break;
			}
			// if the entry has not been found, unregister this permanent endpoint
			if (i >= cfgs.GetSize()) {
				SoftPBX::DisconnectEndpoint(endptr(ep));
				ep->Unregister();
				RemovedList.push_back(ep);
				EndpointList.erase(epIter);
				--regSize;
				PTRACE(2, "Permanent endpoint " << ep->GetEndpointIdentifier().GetValue() << " removed");
			}
		}
	}
	
	for (PINDEX i = 0; i < cfgs.GetSize(); ++i) {
		EndpointRec *ep;
		H225_RasMessage rrq_ras;
		rrq_ras.SetTag(H225_RasMessage::e_registrationRequest);
		H225_RegistrationRequest &rrq = rrq_ras;

		rrq.m_callSignalAddress.SetSize(1);
		GetTransportAddress(cfgs.GetKeyAt(i), (WORD)GkConfig()->GetInteger("EndpointSignalPort", GK_DEF_ENDPOINT_SIGNAL_PORT), rrq.m_callSignalAddress[0]);
		endptr eptr = FindBySignalAdr(rrq.m_callSignalAddress[0]);

		// a permanent endpoint may not support RAS
		// we set an arbitrary address here
		rrq.m_rasAddress.SetSize(1);
		rrq.m_rasAddress[0] = rrq.m_callSignalAddress[0];

		rrq.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
		GenerateEndpointId(rrq.m_endpointIdentifier);

		rrq.IncludeOptionalField(rrq.e_terminalAlias);
		PStringArray sp=cfgs.GetDataAt(i).Tokenise(";", FALSE);
		PStringArray aa=sp[0].Tokenise(",", FALSE);
		PINDEX as = aa.GetSize();
		if (as > 0) {
			rrq.m_terminalAlias.SetSize(as);
			for (PINDEX p=0; p<as; p++)
				H323SetAliasAddress(aa[p], rrq.m_terminalAlias[p]);
		}
		// GatewayInfo
		if (sp.GetSize() > 1) {
			/*
			aa = sp[1].Tokenise(",", FALSE);
			as = aa.GetSize();
			if (as > 0) {
				rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_gateway);
				rrq.m_terminalType.m_gateway.IncludeOptionalField(H225_GatewayInfo::e_protocol);
				rrq.m_terminalType.m_gateway.m_protocol.SetSize(1);
				H225_SupportedProtocols &protocol=rrq.m_terminalType.m_gateway.m_protocol[0];
				protocol.SetTag(H225_SupportedProtocols::e_voice);
				((H225_VoiceCaps &)protocol).m_supportedPrefixes.SetSize(as);
				for (PINDEX p = 0; p < as; ++p)
					H323SetAliasAddress(aa[p], ((H225_VoiceCaps &)protocol).m_supportedPrefixes[p].m_prefix);
			}
			*/
			rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_gateway);
			if (eptr && !eptr->IsGateway()) {
				RemoveByEndptr(eptr);
				eptr = endptr(0);
			}
			if (eptr)
				eptr->Update(rrq_ras), ep = eptr.operator->();
			else
				ep = new GatewayRec(rrq_ras, true);
			GatewayRec *gw = dynamic_cast<GatewayRec *>(ep);
			gw->AddPrefixes(sp[1]);
			gw->SortPrefixes();
		} else {
			rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_terminal);
			if (eptr && eptr->IsGateway()) {
				RemoveByEndptr(eptr);
				eptr = endptr(0);
			}
			if (eptr)
				eptr->Update(rrq_ras);
			else
				ep = new EndpointRec(rrq_ras, true);
		}
		if (!eptr) {
			PTRACE(2, "Add permanent endpoint " << AsDotString(rrq.m_callSignalAddress[0]));
			WriteLock lock(listLock);
			EndpointList.push_back(ep);
			++regSize;
		}
	}
}

void RegistrationTable::ClearTable()
{
	WriteLock lock(listLock);
	// Unregister all endpoints, and move the records into RemovedList
	transform(EndpointList.begin(), EndpointList.end(),
		back_inserter(RemovedList), mem_fun(&EndpointRec::Unregister));
	EndpointList.clear();
	regSize = 0;
	copy(OuterZoneList.begin(), OuterZoneList.end(), back_inserter(RemovedList));
	OuterZoneList.clear();
}

void RegistrationTable::CheckEndpoints()
{
	PTime now;
	WriteLock lock(listLock);

	iterator Iter = EndpointList.begin(), eIter = EndpointList.end();
	while (Iter != eIter) {
		iterator i = Iter++;
		EndpointRec *ep = *i;
		if (!ep->IsUpdated(&now) && !ep->SendIRQ()) {
			SoftPBX::DisconnectEndpoint(endptr(ep));
			ep->Expired();
			RemovedList.push_back(ep);
			EndpointList.erase(i);
			--regSize;
			PTRACE(2, "Endpoint " << ep->GetEndpointIdentifier().GetValue() << " expired.");
		}
	}

	Iter = partition(OuterZoneList.begin(), OuterZoneList.end(),
		bind2nd(mem_fun(&EndpointRec::IsUpdated), &now));
#if PTRACING
	if (ptrdiff_t s = distance(Iter, OuterZoneList.end()))
		PTRACE(2, s << " outerzone endpoint(s) expired.");
#endif
	copy(Iter, OuterZoneList.end(), back_inserter(RemovedList));
	OuterZoneList.erase(Iter, OuterZoneList.end());

	// Cleanup unused EndpointRec in RemovedList
	Iter = partition(RemovedList.begin(), RemovedList.end(), mem_fun(&EndpointRec::IsUsed));
	DeleteObjects(Iter, RemovedList.end());
	RemovedList.erase(Iter, RemovedList.end());
}

CallRec::CallRec(
	/// ARQ with call information
	const RasPDU<H225_AdmissionRequest>& arqPdu,
	/// bandwidth occupied by the call
	int bandwidth,
	/// called party's aliases in a string form
	const PString& destInfo,
	/// override proxy mode global setting from the config
	int proxyMode
	) : m_CallNumber(0), 
	m_callIdentifier(((const H225_AdmissionRequest&)arqPdu).m_callIdentifier),
	m_conferenceIdentifier(((const H225_AdmissionRequest&)arqPdu).m_conferenceID), 
	m_crv(((const H225_AdmissionRequest&)arqPdu).m_callReferenceValue.GetValue() & 0x7fffU),
	m_sourceAddress(((const H225_AdmissionRequest&)arqPdu).m_srcInfo),
	m_srcInfo(AsString(((const H225_AdmissionRequest&)arqPdu).m_srcInfo)), 
	m_destInfo(destInfo), m_bandwidth(bandwidth), m_setupTime(0), m_alertingTime(0),
	m_connectTime(0), m_disconnectTime(0), m_disconnectCause(0), m_releaseSource(-1),
	m_acctSessionId(Toolkit::Instance()->GenerateAcctSessionId()),
	m_routeToAlias(NULL), m_callingSocket(NULL), m_calledSocket(NULL),
	m_usedCount(0), m_nattype(none), 
	m_h245Routed(RasServer::Instance()->IsH245Routed()),
	m_toParent(false), m_forwarded(false), m_proxyMode(proxyMode)
{
	const H225_AdmissionRequest& arq = arqPdu;

	if (arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
		m_destinationAddress = arq.m_destinationInfo;
		
	m_timer = m_acctUpdateTime = m_creationTime = time(NULL);
	m_callerId = m_calleeId = m_callerAddr = m_calleeAddr = " ";

	CallTable* const ctable = CallTable::Instance();
	m_timeout = ctable->GetSignalTimeout() / 1000;
	m_durationLimit = ctable->GetDefaultDurationLimit();

	m_irrFrequency = GkConfig()->GetInteger(CallTableSection, "IRRFrequency", 120);
	m_irrCheck = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "IRRCheck", "0"));
	m_irrCallerTimer = m_irrCalleeTimer = time(NULL);
}

CallRec::CallRec(
	/// Q.931 Setup pdu with call information
	const Q931& q931pdu,
	/// H.225.0 Setup-UUIE pdu with call information
	const H225_Setup_UUIE& setup,
	/// force H.245 routed mode
	bool routeH245,
	/// called party's aliases in a string form
	const PString& destInfo,
	/// override proxy mode global setting from the config
	int proxyMode
	) : m_CallNumber(0), m_callIdentifier(setup.m_callIdentifier), 
	m_conferenceIdentifier(setup.m_conferenceID), 
	m_crv(q931pdu.GetCallReference() & 0x7fffU),
	m_destInfo(destInfo),
	m_bandwidth(1280), m_setupTime(0), m_alertingTime(0), m_connectTime(0), 
	m_disconnectTime(0), m_disconnectCause(0), m_releaseSource(-1),
	m_acctSessionId(Toolkit::Instance()->GenerateAcctSessionId()),
	m_routeToAlias(NULL), m_callingSocket(NULL), m_calledSocket(NULL),
	m_usedCount(0), m_nattype(none), m_h245Routed(routeH245),
	m_toParent(false), m_forwarded(false), m_proxyMode(proxyMode)
{
	if (setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		m_sourceAddress = setup.m_sourceAddress;
		m_srcInfo = AsString(setup.m_sourceAddress);
	}

	if (setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
		m_destinationAddress = setup.m_destinationAddress;
		
	m_timer = m_acctUpdateTime = m_creationTime = time(NULL);
	m_callerId = m_calleeId = m_callerAddr = m_calleeAddr = " ";

	CallTable* const ctable = CallTable::Instance();
	m_timeout = ctable->GetSignalTimeout() / 1000;
	m_durationLimit = ctable->GetDefaultDurationLimit();

	m_irrFrequency = GkConfig()->GetInteger(CallTableSection, "IRRFrequency", 120);
	m_irrCheck = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "IRRCheck", "0"));
	m_irrCallerTimer = m_irrCalleeTimer = time(NULL);
}

CallRec::~CallRec()
{
	PTRACE(3, "Gk\tDelete Call No. " << m_CallNumber);
	delete m_routeToAlias;
}

void CallRec::SetProxyMode(
	int mode /// proxy mode flag (see #ProxyMode enum#)
	)
{
	if (m_proxyMode == ProxyDetect)
		if (mode == ProxyEnabled || mode == ProxyDisabled)
			m_proxyMode = mode;
}

bool CallRec::GetSrcSignalAddr(
	PIPSocket::Address& addr,
	WORD& port
	) const
{
	return GetIPAndPortFromTransportAddr(m_srcSignalAddress, addr, port);
}

bool CallRec::GetDestSignalAddr(
	PIPSocket::Address& addr, 
	WORD& port
	) const
{
	return GetIPAndPortFromTransportAddr(m_destSignalAddress, addr, port);
}

int CallRec::GetNATType(
	/// filled with NAT IP of the calling party (if nat type is callingParty)
	PIPSocket::Address& callingPartyNATIP, 
	/// filled with NAT IP of the called party (if nat type is calledParty)
	PIPSocket::Address& calledPartyNATIP
	) const
{
	if (m_nattype & callingParty)
		callingPartyNATIP = m_Calling->GetNATIP();
	if (m_nattype & calledParty)
		calledPartyNATIP = m_Called->GetNATIP();
	return m_nattype;
}

void CallRec::SetSrcSignalAddr(
	const H225_TransportAddress& addr
	)
{
	m_srcSignalAddress = addr;
	m_callerAddr = AsDotString(addr);
}

void CallRec::SetDestSignalAddr(
	const H225_TransportAddress& addr
	)
{
	m_destSignalAddress = addr;
	m_calleeAddr = AsDotString(addr);
}

void CallRec::SetCalling(
	const endptr& NewCalling
	)
{
	InternalSetEP(m_Calling, NewCalling);
	if (NewCalling) {
		if (NewCalling->IsNATed()) {
			m_nattype |= callingParty, m_h245Routed = true;
			if (NewCalling->HasNATSocket())
				m_nattype |= citronNAT;
		}
		SetSrcSignalAddr(NewCalling->GetCallSignalAddress());
		m_callerId = NewCalling->GetEndpointIdentifier().GetValue();
	}
}

void CallRec::SetCalled(
	const endptr& NewCalled
	)
{
	InternalSetEP(m_Called, NewCalled);
	if (NewCalled) {
		if (NewCalled->IsNATed())
			m_nattype |= calledParty, m_h245Routed = true;
		SetDestSignalAddr(NewCalled->GetCallSignalAddress());
		m_calleeId = NewCalled->GetEndpointIdentifier().GetValue();
	}
}

void CallRec::SetForward(
	CallSignalSocket* socket, 
	const H225_TransportAddress& dest, 
	const endptr& forwarded, 
	const PString& forwarder, 
	const PString& altDestInfo
	)
{
	m_usedLock.Wait();
	m_forwarded = true;
	m_Forwarder = (socket == m_calledSocket) ? m_Called : endptr(0);
	if (m_Forwarder) {
		SetSrcSignalAddr(m_Forwarder->GetCallSignalAddress());
		m_callerId = m_Forwarder->GetEndpointIdentifier().GetValue();
	} // else TODO:
	  // how to solve billing issue if forwarder is not a registered party?

	if (!forwarder)
		m_srcInfo += "=" + forwarder;
	m_destInfo = altDestInfo;
	m_nattype &= ~calledParty;
	// FIXME: how about m_registered and m_h245Routed?
	m_usedLock.Signal();
	if (forwarded)
		SetCalled(forwarded);
	else
		SetDestSignalAddr(dest);
}

void CallRec::SetSocket(
	CallSignalSocket* calling, 
	CallSignalSocket* called
	)
{
	PWaitAndSignal lock(m_sockLock); 
	m_callingSocket = calling, m_calledSocket = called;
	if( calling ) {
		m_callerAddr = calling->GetName();
		if( !m_srcSignalAddress.IsValid() ) {
			PIPSocket::Address addr(0);
			WORD port = 0;
			calling->GetPeerAddress(addr,port);
			m_srcSignalAddress = SocketToH225TransportAddr(addr,port);
		}
	}
}

void CallRec::SetCallSignalSocketCalling(
	CallSignalSocket* socket
	)
{
	PWaitAndSignal lock(m_sockLock); 
	m_callingSocket = socket;
	if (m_callingSocket) {
		m_callerAddr = m_callingSocket->GetName();
		if (!m_srcSignalAddress.IsValid()) {
			PIPSocket::Address addr(0);
			WORD port = 0;
			m_callingSocket->GetPeerAddress(addr, port);
			m_srcSignalAddress = SocketToH225TransportAddr(addr, port);
		}
	}
}

void CallRec::SetCallSignalSocketCalled(
	CallSignalSocket* socket
	)
{
	PWaitAndSignal lock(m_sockLock); 
	m_calledSocket = socket;
}


void CallRec::SetConnected()
{
	SetConnectTime(time(NULL));

	if (m_Calling)
		m_Calling->AddConnectedCall();
	if (m_Called)
		m_Called->AddConnectedCall();
}

void CallRec::SetDurationLimit(long seconds)
{
	PWaitAndSignal lock(m_usedLock);
	// allow only to restrict duration limit
	const long sec = (m_durationLimit && seconds) 
		? PMIN(m_durationLimit,seconds) : PMAX(m_durationLimit,seconds);
	m_durationLimit = sec;
	if (IsConnected())
		m_timeout = sec;
}

void CallRec::InternalSetEP(endptr & ep, const endptr & nep)
{
	if (ep != nep) {
		if (ep)
			ep->RemoveCall();
		m_usedLock.Wait();
		ep = nep;
		m_usedLock.Signal();
		if (ep)
			ep->AddCall();
	}
}

void CallRec::RemoveAll()
{
	if (IsToParent())
		RasServer::Instance()->GetGkClient()->SendDRQ(callptr(this));
	if (m_Calling)
		m_Calling->RemoveCall();
	if (m_Called)
		m_Called->RemoveCall();
}

void CallRec::RemoveSocket()
{
	if (m_sockLock.WillBlock()) // locked by SendReleaseComplete()?
		return; // avoid deadlock

	PWaitAndSignal lock(m_sockLock);
	if (m_callingSocket) {
		m_callingSocket->SetDeletable();
		m_callingSocket = 0;
	}
	if (m_calledSocket) {
		m_calledSocket->SetDeletable();
		m_calledSocket = 0;
	}
}

int CallRec::CountEndpoints() const
{
	PWaitAndSignal lock(m_usedLock);
	int result = 0;
	if (m_Calling)
		++result;
	if (m_Called)
		++result;
	return result;
}

void CallRec::Disconnect(bool force)
{
	if ((force || Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "DropCallsByReleaseComplete", "0"))) && (m_callingSocket || m_calledSocket))
		SendReleaseComplete();
	else
		SendDRQ();

	PTRACE(2, "Gk\tDisconnect Call No. " << m_CallNumber);
}

void CallRec::SendReleaseComplete(const H225_CallTerminationCause *cause)
{
	m_sockLock.Wait();
	if (m_callingSocket) {
		PTRACE(4, "Sending ReleaseComplete to calling party ...");
		m_callingSocket->SendReleaseComplete(cause);
		//m_callingSocket->Close();
	}
	if (m_calledSocket) {
		PTRACE(4, "Sending ReleaseComplete to called party ...");
		m_calledSocket->SendReleaseComplete(cause);
		//m_calledSocket->Close();
	}
	m_sockLock.Signal();

	RemoveSocket();
}

void CallRec::BuildDRQ(H225_DisengageRequest & drq, unsigned reason) const
{
	drq.m_disengageReason.SetTag(reason);
	drq.m_conferenceID = m_conferenceIdentifier;
	drq.IncludeOptionalField(H225_DisengageRequest::e_callIdentifier);
	drq.m_callIdentifier = m_callIdentifier;
	drq.m_callReferenceValue = m_crv | (!m_Calling * 0x8000u); // a trick
}

void CallRec::SendDRQ()
{
	RasServer *RasSrv = RasServer::Instance();
	H225_RasMessage drq_ras;
	drq_ras.SetTag(H225_RasMessage::e_disengageRequest);
	H225_DisengageRequest & drq = drq_ras;
	drq.m_requestSeqNum = RasSrv->GetRequestSeqNum();
	BuildDRQ(drq, H225_DisengageReason::e_forcedDrop);
	drq.IncludeOptionalField(H225_DisengageRequest::e_gatekeeperIdentifier);
	drq.m_gatekeeperIdentifier = Toolkit::GKName();

	// FIXME: for an outer zone endpoint, the endpoint identifier may not correct
	if (m_Called) {
		drq.m_endpointIdentifier = m_Called->GetEndpointIdentifier();
		RasSrv->SendRas(drq_ras, m_Called->GetRasAddress());
	}
	if (m_Calling) {
		drq.m_endpointIdentifier = m_Calling->GetEndpointIdentifier();
		drq.m_callReferenceValue = m_crv;
		RasSrv->SendRas(drq_ras, m_Calling->GetRasAddress());
	}
}

namespace { // end of anonymous namespace

PString GetEPString(const endptr & ep, const CallSignalSocket *socket)
{
	if (ep) {
		return PString(PString::Printf, "%s|%s",
			(const char *)AsDotString(ep->GetCallSignalAddress()),
			(const char *)ep->GetEndpointIdentifier().GetValue());
	}
	return socket ? socket->Name() + "| " : PString(" | ");
}

} // end of anonymous namespace

PString CallRec::GenerateCDR(
	const PString& timestampFormat
	) const
{
	PString timeString;
	const PString fmtStr = !timestampFormat ? timestampFormat : PString("RFC822");
	Toolkit* const toolkit = Toolkit::Instance();
	
	const time_t eTime = m_disconnectTime ? m_disconnectTime : time(0);
	const PTime endTime(eTime);

	if (m_connectTime != 0) {
		const PTime startTime(m_connectTime);
		timeString = PString((unsigned)(eTime > m_connectTime
			? (eTime - m_connectTime) : 1)) + "|"
			+ toolkit->AsString(startTime, fmtStr) + "|"
			+ toolkit->AsString(endTime, fmtStr);
	} else {
		timeString = "0|unconnected|" + toolkit->AsString(endTime, fmtStr);
	}

	return PString(PString::Printf, "CDR|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s;",
		m_CallNumber,
		(const char *)AsString(m_callIdentifier.m_guid),
		(const char *)timeString,
		(const char *)m_callerAddr,
		(const char *)m_callerId,
		(const char *)m_calleeAddr,
		(const char *)m_calleeId,
		(const char *)m_destInfo,
		(const char *)m_srcInfo,
		(const char *)toolkit->GKName()
	);
}

PString CallRec::PrintOn(bool verbose) const
{
	const int timer = time(0) - m_timer;
	const int left = m_timeout > timer ? m_timeout - timer : 0;

	PString result(PString::Printf,
		"Call No. %d | CallID %s | %d | %d\r\nDial %s\r\nACF|%s|%s|%d|%s|%s|false;\r\nACF|%s|%s|%d|%s|%s|true;\r\n",
		m_CallNumber, (const char *)AsString(m_callIdentifier.m_guid), timer, left,
		// 1st ACF
		(const char *)m_destInfo,
		(const char *)m_callerAddr,
		(const char *)m_callerId,
		m_crv,
		(const char*)m_destInfo,
		(const char*)m_srcInfo,
		// 2nd ACF
		(const char *)m_calleeAddr,
		(const char *)m_calleeId,
		m_crv | 0x8000u,
		(const char*)m_destInfo,
		(const char*)m_srcInfo
	);
	if (verbose) {
		result += PString(PString::Printf, "# %s|%s|%d|%s <%d>\r\n",
				(const char *)((m_Calling) ? AsString(m_Calling->GetAliases()) : m_callerAddr),
				(const char *)((m_Called) ? AsString(m_Called->GetAliases()) : m_calleeAddr),
				m_bandwidth,
				m_connectTime ? (const char *)PTime(m_connectTime).AsString() : "unconnected",
				m_usedCount
			  );
	}

	return result;
}

void CallRec::SetSetupTime(time_t tm)
{
	PWaitAndSignal lock(m_usedLock);
	if( m_setupTime == 0 )
		m_setupTime = tm;
	if( m_connectTime == 0 )
		m_timer = tm;
	// can be the case, because CallRec is usually created
	// after Setup message has been received
	if( m_creationTime > m_setupTime )
		m_creationTime = m_setupTime;
}

void CallRec::SetAlertingTime(time_t tm)
{
	CallTable* const ctable = CallTable::Instance();
	PWaitAndSignal lock(m_usedLock);
	if( m_alertingTime == 0 ) {
		m_timer = m_alertingTime = tm;
		m_timeout = ctable->GetAlertingTimeout() / 1000;
	}
}

void CallRec::SetConnectTime(time_t tm)
{
	PWaitAndSignal lock(m_usedLock);
	if( m_connectTime == 0 ) {
		m_timer = m_connectTime = tm;
		m_timeout = m_durationLimit;
		if( m_disconnectTime && m_disconnectTime <= m_connectTime )
			m_disconnectTime = m_connectTime + 1;
	}
	// can be the case for direct signalling mode, 
	// because CallRec is usually created after ARQ message 
	// has been received
	if( m_creationTime > m_connectTime )
		m_creationTime = m_connectTime;
}

void CallRec::SetDisconnectTime(time_t tm)
{
	PWaitAndSignal lock(m_usedLock);
	if( m_disconnectTime == 0 )
		m_disconnectTime = (m_connectTime && m_connectTime >= tm)
			? (m_connectTime + 1) : tm;
}

long CallRec::GetPostDialDelay() const
{
	PWaitAndSignal lock(m_usedLock);
	const long startTime = (m_setupTime == 0
		? m_creationTime : std::min(m_creationTime, m_setupTime));

	if (startTime == 0)
		return 0;
	if (m_alertingTime)
		return (m_alertingTime > startTime) 
			? (m_alertingTime - startTime) : 0;
	if (m_connectTime)
		return (m_connectTime > startTime) 
			? (m_connectTime - startTime) : 0;
	if (m_disconnectTime)
		return (m_disconnectTime > startTime) 
			? (m_disconnectTime - startTime) : 0;
	return 0;
}

long CallRec::GetRingTime() const
{
	PWaitAndSignal lock(m_usedLock);
	if( m_alertingTime ) {
		if( m_connectTime ) {
			return (m_connectTime > m_alertingTime) 
				? (m_connectTime-m_alertingTime) : 0;
		} else {
			return (m_disconnectTime > m_alertingTime) 
				? (m_disconnectTime-m_alertingTime) : 0;
		}
	}
	return 0;
}

long CallRec::GetTotalCallDuration() const
{
	PWaitAndSignal lock(m_usedLock);
	if( m_disconnectTime ) {
		return (m_disconnectTime > m_setupTime) 
			? (m_disconnectTime-m_setupTime) : 1;
	}
	return 0;
}

int CallRec::GetReleaseSource() const
{
	return m_releaseSource;
}

void CallRec::SetReleaseSource(
	int releaseSource
	)
{
	if (m_releaseSource == -1)
		m_releaseSource = releaseSource;
}

bool CallRec::IsDurationLimitExceeded() const
{
	PWaitAndSignal lock(m_usedLock);
	const long now = time(NULL);
	return m_durationLimit > 0 && m_connectTime != 0 
		&& now >= m_connectTime && (now - m_connectTime) > m_durationLimit;
}

long CallRec::GetDuration() const
{
	PWaitAndSignal lock(m_usedLock);
	if( m_connectTime ) {
		if( m_disconnectTime )
			return (m_disconnectTime > m_connectTime) 
				? (m_disconnectTime-m_connectTime) : 1;
		else
			return (long)time(NULL) - m_connectTime;
	} else
		return 0;
}

PString CallRec::GetCallingStationId()
{
	PWaitAndSignal lock(m_usedLock);
	return m_callingStationId;
}

void CallRec::SetCallingStationId(
	const PString& id
	)
{
	PWaitAndSignal lock(m_usedLock);
	m_callingStationId = id;
}

PString CallRec::GetCalledStationId()
{
	PWaitAndSignal lock(m_usedLock);
	return m_calledStationId;
}

void CallRec::SetCalledStationId(
	const PString& id
	)
{
	PWaitAndSignal lock(m_usedLock);
	m_calledStationId = id;
}

PString CallRec::GetDialedNumber()
{
	PWaitAndSignal lock(m_usedLock);
	return m_dialedNumber;
}

void CallRec::SetDialedNumber(
	const PString& number
	)
{
	PWaitAndSignal lock(m_usedLock);
	m_dialedNumber = number;
}

H225_AliasAddress* CallRec::GetRouteToAlias() const
{
	if (m_routeToAlias != NULL) {
		PWaitAndSignal lock(m_usedLock);
		if (m_routeToAlias != NULL)
			return new H225_AliasAddress(*m_routeToAlias);
	}
	return NULL;
}

void CallRec::SetRouteToAlias(
	const H225_AliasAddress& alias /// alias to set
	)
{
	PWaitAndSignal lock(m_usedLock);
	delete m_routeToAlias;
	m_routeToAlias = new H225_AliasAddress(alias);
}

void CallRec::Update(const H225_InfoRequestResponse & irr)
{
	if (irr.HasOptionalField(H225_InfoRequestResponse::e_perCallInfo) &&
		irr.m_perCallInfo[0].HasOptionalField(H225_InfoRequestResponse_perCallInfo_subtype::e_originator)) {
		if (irr.m_perCallInfo[0].m_originator)
			m_irrCallerTimer = time(NULL);
		else
			m_irrCalleeTimer = time(NULL);
	} else {
		if (irr.m_endpointIdentifier == m_Calling->GetEndpointIdentifier())
			m_irrCallerTimer = time(NULL);
		else
			m_irrCalleeTimer = time(NULL);
	}
}

/*
bool CallRec::IsTimeout(
	const time_t now,
	const long connectTimeout
	) const
{
	PWaitAndSignal lock(m_usedLock);

	// check timeout for signalling channel creation after ARQ->ACF
	// or for the call being connected in direct signalling mode
	if( connectTimeout > 0 && m_setupTime == 0 && m_connectTime == 0 )
		if( (now-m_creationTime)*1000 > connectTimeout ) {
			PTRACE(2,"Q931\tCall #"<<m_CallNumber<<" timed out waiting for its signalling channel to be opened");
			return true;
		} else
			return false;

	// is signalling channel present?
	if( m_setupTime && m_connectTime == 0 && connectTimeout > 0 )
		if( (now-m_setupTime)*1000 > connectTimeout ) {
			PTRACE(2,"Q931\tCall #"<<m_CallNumber<<" timed out waiting for a Connect message");
			return true;
		} else
			return false;
	
	if( m_durationLimit > 0 && m_connectTime 
		&& ((now - m_connectTime) >= m_durationLimit) ) {
		PTRACE(4,"GK\tCall #"<<m_CallNumber<<" duration limit exceeded");
		return true;
	}
		
	return false;
}
*/

CallTable::CallTable() : Singleton<CallTable>("CallTable")
{
	m_CallNumber = 0, m_capacity = -1;
	m_CallCount = m_successCall = m_neighborCall = m_parentCall = m_activeCall = 0;
	LoadConfig();
}

CallTable::~CallTable()
{
	ClearTable();
	DeleteObjectsInContainer(RemovedList);
}

void CallTable::LoadConfig()
{
	m_genNBCDR = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "GenerateNBCDR", "1"));
	m_genUCCDR = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "GenerateUCCDR", "0"));
	SetTotalBandwidth(GkConfig()->GetInteger("TotalBandwidth", m_capacity));
	m_signalTimeout = std::max(
		GkConfig()->GetInteger(RoutedSec, "SignalTimeout", DEFAULT_SIGNAL_TIMEOUT),
		5000L
		);
	m_alertingTimeout = std::max(
		GkConfig()->GetInteger(RoutedSec, "AlertingTimeout", DEFAULT_ALERTING_TIMEOUT),
		5000L
		);
	m_defaultDurationLimit = GkConfig()->GetInteger(
		CallTableSection, "DefaultCallDurationLimit", 0
		);
	// backward compatibility - check DefaultCallTimeout
	if (m_defaultDurationLimit == 0)
		m_defaultDurationLimit = GkConfig()->GetInteger(
			CallTableSection, "DefaultCallTimeout", 0
			);
	m_acctUpdateInterval = GkConfig()->GetInteger(CallTableSection, "AcctUpdateInterval", 0);
	if( m_acctUpdateInterval != 0 )
		m_acctUpdateInterval = std::max(m_acctUpdateInterval, 10L);
		
	m_timestampFormat = GkConfig()->GetString(CallTableSection, "TimestampFormat", "RFC822");
}

void CallTable::Insert(CallRec * NewRec)
{
	NewRec->SetCallNumber(++m_CallNumber);
	WriteLock lock(listLock);
	CallList.push_back(NewRec);
	++m_CallCount, ++m_activeCall;
	PTRACE(2, "CallTable::Insert(CALL) Call No. " << m_CallNumber << ", total sessions : " << m_activeCall);
}

void CallTable::SetTotalBandwidth(int bw)
{
	if ((m_capacity = bw) >= 0) {
		int used = 0;
		WriteLock lock(listLock);
		iterator Iter = CallList.begin(), eIter = CallList.end();
		while (Iter != eIter)
			used += (*Iter++)->GetBandwidth();
		if (bw > used)
			m_capacity -= used;
		else
			m_capacity = 0;
	}
}

bool CallTable::GetAdmission(int bw)
{
	if (m_capacity < 0)
		return true;
	if (m_capacity < bw)
		return false;

	m_capacity -= bw;
	PTRACE(2, "GK\tAvailable Bandwidth " << m_capacity);
	return true;
}

bool CallTable::GetAdmission(int bw, const callptr & call)
{
	return GetAdmission(bw - call->GetBandwidth());
}

callptr CallTable::FindCallRec(const H225_CallIdentifier & CallId) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareCallId), &CallId));
}

callptr CallTable::FindCallRec(const H225_CallReferenceValue & CallRef) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareCRV), CallRef.GetValue()));
}

callptr CallTable::FindCallRec(PINDEX CallNumber) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareCallNumber), CallNumber));
}

callptr CallTable::FindCallRec(const endptr & ep) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareEndpoint), &ep));
}

callptr CallTable::FindBySignalAdr(const H225_TransportAddress & SignalAdr) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareSigAdr), &SignalAdr));
}

void CallTable::ClearTable()
{
	WriteLock lock(listLock);
	iterator Iter = CallList.begin(), eIter = CallList.end();
	while (Iter != eIter) {
		iterator i = Iter++;
		(*i)->SetDisconnectCause(Q931::TemporaryFailure);
		(*i)->SetReleaseSource(CallRec::ReleasedByGatekeeper);
		(*i)->Disconnect();
		InternalRemove(i);
	}
}

void CallTable::CheckCalls(
	RasServer* rassrv
	)
{
	std::list<callptr> m_callsToDisconnect;
	std::list<callptr> m_callsToUpdate;
	time_t now;
	
	{	
		WriteLock lock(listLock);
		iterator Iter = CallList.begin(), eIter = CallList.end();
		now = time(0);
		while (Iter != eIter) {
			if ((*Iter)->IsTimeout(now))
				m_callsToDisconnect.push_back(callptr(*Iter));
			else if (m_acctUpdateInterval && (*Iter)->IsConnected()) {
				if((now - (*Iter)->GetLastAcctUpdateTime()) >= m_acctUpdateInterval)
					m_callsToUpdate.push_back(callptr(*Iter));
			}
			Iter++;
		}

		Iter = partition(RemovedList.begin(), RemovedList.end(), mem_fun(&CallRec::IsUsed));
		DeleteObjects(Iter, RemovedList.end());
		RemovedList.erase(Iter, RemovedList.end());
	}
	
	std::list<callptr>::iterator call = m_callsToDisconnect.begin();
	while (call != m_callsToDisconnect.end()) {
		(*call)->SetDisconnectCause((*call)->IsConnected()
			? Q931::ResourceUnavailable : Q931::TemporaryFailure
			);
		(*call)->SetReleaseSource(CallRec::ReleasedByGatekeeper);
		(*call)->Disconnect();
		RemoveCall((*call));
		call++;
	}
	
	call = m_callsToUpdate.begin();
	while (call != m_callsToUpdate.end()) {
		if ((*call)->IsConnected())
			rassrv->LogAcctEvent(GkAcctLogger::AcctUpdate, *call, now);
		call++;
	}
	
}

void CallTable::RemoveCall(const H225_DisengageRequest & obj_drq, const endptr & ep)
{
	callptr call = obj_drq.HasOptionalField(H225_DisengageRequest::e_callIdentifier) ? FindCallRec(obj_drq.m_callIdentifier) : FindCallRec(obj_drq.m_callReferenceValue.GetValue());
	if (call) {
		if (ep == call->GetForwarder())
			return;

		if (ep != call->GetCallingParty() && ep != call->GetCalledParty()) {
			PTRACE(3, "GK\tWarning: CallRec doesn't belong to the requesting endpoint!");
			return;
		}
		call->SetReleaseSource(ep == call->GetCallingParty()
			? CallRec::ReleasedByCaller : CallRec::ReleasedByCallee
			);
		if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "SendReleaseCompleteOnDRQ", "0"))) {
			if( obj_drq.m_disengageReason.GetTag() == H225_DisengageReason::e_normalDrop )
				call->SetDisconnectCause(Q931::NormalCallClearing);
			call->SendReleaseComplete(obj_drq.HasOptionalField(H225_DisengageRequest::e_terminationCause) ? &obj_drq.m_terminationCause : 0);
		}
		RemoveCall(call);
	}
}

void CallTable::RemoveCall(const callptr & call)
{
	if (call)
		InternalRemovePtr(call.operator->());
}

bool CallTable::InternalRemovePtr(CallRec *call)
{
	PTRACE(6, "GK\tRemoving callptr: " << AsString(call->GetCallIdentifier().m_guid));
	WriteLock lock(listLock);
	InternalRemove(find(CallList.begin(), CallList.end(), call));
	return true; // useless, workaround for VC
}

void CallTable::InternalRemove(const H225_CallIdentifier & CallId)
{
	PTRACE(5, "GK\tRemoving CallId: " << AsString(CallId.m_guid));
	WriteLock lock(listLock);
	InternalRemove(
		find_if(CallList.begin(), CallList.end(),
		bind2nd(mem_fun(&CallRec::CompareCallId), &CallId))
	);
}

void CallTable::InternalRemove(WORD CallRef)
{
	PTRACE(5, "GK\tRemoving CallRef: " << CallRef);
	WriteLock lock(listLock);
	InternalRemove(
		find_if(CallList.begin(), CallList.end(),
		bind2nd(mem_fun(&CallRec::CompareCRV), CallRef))
	);
}

void CallTable::InternalRemove(iterator Iter)
{
	if (Iter == CallList.end()) {
		return;
	}

	callptr call(*Iter);
	call->SetDisconnectTime(time(NULL));

	--m_activeCall;
	if (call->IsConnected())
		++m_successCall;
	if (!call->GetCallingParty())
		++(call->IsToParent() ? m_parentCall : m_neighborCall);
	if (m_capacity >= 0)
		m_capacity += call->GetBandwidth();

	CallList.erase(Iter);
	RemovedList.push_back(call.operator->());

	WriteUnlock unlock(listLock);
	
	if ((m_genNBCDR || call->GetCallingParty()) && (m_genUCCDR || call->IsConnected())) {
		PString cdrString(call->GenerateCDR(m_timestampFormat) + "\r\n");
		GkStatus::Instance()->SignalStatus(cdrString, STATUS_TRACE_LEVEL_CDR);
		PTRACE(1, cdrString);
#if PTRACING
	} else {
		if (!call->IsConnected())
			PTRACE(2, "CDR\tignore not connected call");
		else	
			PTRACE(2, "CDR\tignore caller from neighbor");
#endif
	}

	RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctStop, call);

	call->RemoveAll();
	call->RemoveSocket();
}

void CallTable::InternalStatistics(unsigned & n, unsigned & act, unsigned & nb, unsigned & np, PString & msg, BOOL verbose) const
{
	ReadLock lock(listLock);
	n = m_activeCall, act = nb = np = 0;
	const_iterator eIter = CallList.end();
	for (const_iterator Iter = CallList.begin(); Iter != eIter; ++Iter) {
		CallRec *call = *Iter;
		if (call->IsConnected())
			++act;
		if (!call->GetCallingParty())
			++(call->IsToParent() ? np : nb);
		if (!msg)
			msg += call->PrintOn(verbose);
	}
}

void CallTable::PrintCurrentCalls(USocket *client, BOOL verbose) const
{
	PString msg = "CurrentCalls\r\n";
	unsigned n, act, nb, np;
	InternalStatistics(n, act, nb, np, msg, verbose);
	
	PString bandstr;
	if (m_capacity >= 0)
		bandstr = PString(PString::Printf, "\r\nAvailable Bandwidth: %u", m_capacity);
	msg += PString(PString::Printf, "Number of Calls: %u Active: %u From Neighbor: %u From Parent: %u%s\r\n;\r\n", n, act, nb, np, (const char *)bandstr);
	client->TransmitData(msg);
}

PString CallTable::PrintStatistics() const
{
	PString dumb;
	unsigned n, act, nb, np;
	InternalStatistics(n, act, nb, np, dumb, FALSE);

	return PString(PString::Printf, "-- Call Statistics --\r\n"
		"Current Calls: %u Active: %u From Neighbor: %u From Parent: %u\r\n"
		"Total Calls: %u  Successful: %u  From Neighbor: %u  From Parent: %u\r\n",
		n, act, nb, np,
		m_CallCount, m_successCall, m_neighborCall, m_parentCall);
}

