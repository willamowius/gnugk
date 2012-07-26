//////////////////////////////////////////////////////////////////
//
// bookkeeping for RAS-Server in H.323 gatekeeper
//
// Copyright (c) 2000-2012, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include <time.h>
#include <ptlib.h>
#include <h323.h>
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
#include "Neighbor.h"
#include "gkacct.h"
#include "RasTbl.h"
#include "gk.h"
#include "gk_const.h"
#include "config.h"

#ifdef H323_H350
  #include <h350/h350_service.h>
#endif

#ifdef HAS_H460
  #include <h460/h4601.h>
  #include <h460/h4609.h>
#ifdef HAS_H46024B
  #include <h460/h46024b.h>
#endif
#endif

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
using Routing::Route;

const char *CallTableSection = "CallTable";
const char *RRQFeaturesSection = "RasSrv::RRQFeatures";
const char *proxysection = "Proxy";

namespace {
const long DEFAULT_SIGNAL_TIMEOUT = 30000;
const long DEFAULT_ALERTING_TIMEOUT = 180000;
const int DEFAULT_IRQ_POLL_COUNT = 1;
}

/////////////////////////////////////////////////////////////////////////////////
void EPQoS::Init()
{
	m_lastMsg = 0;
	m_numCalls = 0;
	m_audioPacketLossPercent = 0.0;
	m_audioJitter = 0;
	m_videoPacketLossPercent = 0.0;
	m_videoJitter = 0;
}

PString EPQoS::AsString() const
{
	return PString(PString::Printf, "%s|%d|%0.2f%%|%lu|%0.2f%%|%lu",
		(const char*)m_lastMsg.AsString(PTime::LongISO8601, PTime::UTC), m_numCalls,
		m_audioPacketLossPercent, m_audioJitter, m_videoPacketLossPercent, m_videoJitter);
}

/////////////////////////////////////////////////////////////////////////////////

EndpointRec::EndpointRec(
	/// RRQ, ARQ, ACF or LCF that contains a description of the endpoint
	const H225_RasMessage& ras,
	/// permanent endpoint flag
	bool permanent)
	: m_RasMsg(ras), m_endpointVendor(NULL), m_timeToLive(1),
	m_activeCall(0), m_connectedCall(0), m_totalCall(0),
	m_pollCount(GkConfig()->GetInteger(RRQFeaturesSection, "IRQPollCount", DEFAULT_IRQ_POLL_COUNT)),
	m_usedCount(0), m_nat(false), m_natsocket(NULL), m_permanent(permanent), 
	m_hasCallCreditCapabilities(false), m_callCreditSession(-1),
	m_capacity(-1), m_calledTypeOfNumber(-1), m_callingTypeOfNumber(-1),
	m_calledPlanOfNumber(-1), m_callingPlanOfNumber(-1), m_proxy(0),
	m_registrationPriority(0), m_registrationPreemption(false),
    m_epnattype(NatUnknown), m_usesH46023(false), m_H46024(Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "H46023PublicIP",0))),
	m_H46024a(false), m_H46024b(false), m_natproxy(Toolkit::AsBool(GkConfig()->GetString(proxysection, "ProxyForNAT", "1"))),
	m_internal(false), m_remote(false), m_h46017disabled(false), m_h46018disabled(false), m_usesH460P(false), m_usesH46017(false), m_usesH46026(false),
    m_traversalType(None), m_bandwidth(0), m_maxBandwidth(-1)

{
	switch (m_RasMsg.GetTag())
	{
		case H225_RasMessage::e_registrationRequest:
			SetEndpointRec((H225_RegistrationRequest &)m_RasMsg);
			PTRACE(1, "New EP|" << PrintOn(false).Trim());
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

const int aliasCount = 6;
const static POrdinalToString::Initialiser H225AliasTypes[aliasCount] =
{
	{H225_AliasAddress::e_h323_ID,        "h323id"},
	{H225_AliasAddress::e_dialedDigits,   "dialeddigits"},
	{H225_AliasAddress::e_url_ID,         "url"},
	{H225_AliasAddress::e_transportID,    "transport"},
 	{H225_AliasAddress::e_email_ID,       "email"},
 	{H225_AliasAddress::e_partyNumber,    "partynumber"}
};

const static POrdinalToString h225aliastypes(aliasCount, H225AliasTypes);

const int endpointcount = 4;
const static PStringToOrdinal::Initialiser H225EndpointTypes[endpointcount] =
{
	{"gatekeeper",      H225_EndpointType::e_gatekeeper},
	{"gateway",         H225_EndpointType::e_gateway},
	{"mcu",             H225_EndpointType::e_mcu},
	{"terminal",        H225_EndpointType::e_terminal}
};
const static PStringToOrdinal h225endpointtypes(endpointcount, H225EndpointTypes, false);

void EndpointRec::LoadAliases(const H225_ArrayOf_AliasAddress & aliases, const H225_EndpointType & type)
{
	PWaitAndSignal lock(m_usedLock);
	m_terminalAliases.SetSize(0);	// clear current alias

	PStringToString kv = GkConfig()->GetAllKeyValues(RRQFeaturesSection);
	for (PINDEX r = 0; r < kv.GetSize(); r++) {
		if (kv.GetKeyAt(r) == "AliasTypeFilter") {
	        PStringList entries = kv.GetDataAt(r).ToLower().Tokenise("\r\n", false);
	        for (PINDEX e = 0; e < entries.GetSize(); e++) {
				PStringList filtertype = entries[e].Tokenise(";", false); 
				// Malformed key
				if (filtertype.GetSize() != 2) {
					PTRACE(3, "Malformed AliasTypeFilter: " << entries[e]);
					continue;
				}
				// filter does not match endpoint type
				if (!type.HasOptionalField(h225endpointtypes[filtertype[0]])) {
					continue;
				}
				PTRACE(5, "Filter rule matched: AliasTypeFilter=" << entries[e]);

				PStringList filterlist = filtertype[1].ToLower().Tokenise(",", false); 
				for (PINDEX i=0; i< aliases.GetSize(); i++) {
					PString aliasType = h225aliastypes[aliases[i].GetTag()];
					for (PINDEX j=0; j < filterlist.GetSize(); j++) {
						if (aliasType == filterlist[j]) {
							m_terminalAliases.SetSize(m_terminalAliases.GetSize() + 1);
							m_terminalAliases[m_terminalAliases.GetSize() - 1] = aliases[i];
						}
					}
				}
			}
	    }
	}
	  
	// If no filter or none match the filter than just add whatever is there
	if (m_terminalAliases.GetSize() == 0) {
          m_terminalAliases = aliases;
	}
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
    LoadAliases(rrq.m_terminalAlias,rrq.m_terminalType);
	m_terminalType = &rrq.m_terminalType;
	m_endpointVendor = new H225_VendorIdentifier(rrq.m_endpointVendor);
	if (rrq.HasOptionalField(H225_RegistrationRequest::e_timeToLive))
		SetTimeToLive(rrq.m_timeToLive);
	else
		SetTimeToLive(SoftPBX::TimeToLive);
	m_fromParent = false;
	m_hasCallCreditCapabilities = rrq.HasOptionalField(
		H225_RegistrationRequest::e_callCreditCapability
		);

	if (m_permanent) {
		PIPSocket::Address ipaddr;
		GetIPFromTransportAddr(rrq.m_callSignalAddress[0], ipaddr);
		m_internal = Toolkit::Instance()->IsInternal(ipaddr);
        m_remote = true;
	}
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
    m_remote = true;
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
    m_remote = true;
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
	m_remote = true;

#ifdef HAS_H46018
	if (Toolkit::Instance()->IsH46018Enabled()) {
		// find neighbor object to see if we have to use H.460.18
		PIPSocket::Address socketAddr;
		if (GetIPFromTransportAddr(m_rasAddress, socketAddr)) {
			NeighborList::List & neighbors = *RasServer::Instance()->GetNeighbors();
			NeighborList::List::iterator iter = find_if(neighbors.begin(), neighbors.end(), bind2nd(mem_fun(&Neighbors::Neighbor::IsFrom), &socketAddr));
			if (iter != neighbors.end()) {
				if ((*iter)->IsH46018Server()) {
					m_traversalType = TraversalServer;
				}
			}
		}
	}
#endif
 
#ifdef HAS_H460
	if (lcf.HasOptionalField(H225_LocationConfirm::e_genericData)) {
		H225_ArrayOf_GenericData & data = lcf.m_genericData;

		for (PINDEX i=0; i < data.GetSize(); i++) {
			H460_Feature & feat = (H460_Feature &)data[i];
#ifdef HAS_H46023
			if (Toolkit::Instance()->IsH46023Enabled()) {
				if (feat.GetFeatureID() == H460_FeatureID(24)) {
				   H460_FeatureStd & std24 = (H460_FeatureStd &)data[i];
				   if (std24.Contains(Std24_RemoteNAT)) {              /// Remote supports remote NAT
					   PBoolean supNAT = std24.Value(Std24_RemoteNAT);
					   SetH46024(supNAT);
				   }
				   if (std24.Contains(Std24_IsNAT)) {                /// Remote EP is Nated
					   PBoolean isnat = std24.Value(Std24_IsNAT);
					   SetNAT(isnat);
					   if (isnat) {
						   PIPSocket::Address addr;
						   GetIPFromTransportAddr(lcf.m_callSignalAddress,addr);
						   SetNATAddress(addr);
						}
				   }
				   if (std24.Contains(Std24_NATdet)) {               /// Remote type of NAT
					   unsigned ntype = std24.Value(Std24_NATdet);
					   SetEPNATType(ntype);
				   }
				   if (std24.Contains(Std24_ProxyNAT)) {                /// Whether the remote GK can proxy
					   PBoolean supProxy = std24.Value(Std24_ProxyNAT);
					   SetNATProxy(supProxy);
				   }
				   if (std24.Contains(Std24_SourceAddr)) {               /// ApparentSourceAddress
					   H323TransportAddress ta = std24.Value(Std24_SourceAddr);
					   PIPSocket::Address addr; 
					   ta.GetIpAddress(addr);
					   SetNATAddress(addr);
				   }
				   if (std24.Contains(Std24_MustProxy)) {				/// Whether this EP must proxy through GK
					   PBoolean mustProxy = std24.Value(Std24_MustProxy);
					   SetInternal(mustProxy);
				   }
				   if (std24.Contains(Std24_AnnexA)) {					/// Whether this EP supports H.460.24 Annex A
					   PBoolean annexA = std24.Value(Std24_AnnexA);
					   SetH46024A(annexA);
				   }
				   if (std24.Contains(Std24_AnnexB)) {					/// Whether this EP supports H.460.24 Annex B
					   PBoolean annexB = std24.Value(Std24_AnnexB);
					   SetH46024B(annexB);
				   }
			   }
		   }
#endif
		   /// OID9 Vendor Information
		   if (feat.GetFeatureID() == H460_FeatureID(OpalOID(OID9))) {
			   H460_FeatureOID & oid9 = (H460_FeatureOID &)data[i];
			   PString m_vendor = oid9.Value(PString(VendorProdOID));  // Vendor Information
               PString m_version = oid9.Value(PString(VendorVerOID));  // Version Information
			   SetEndpointInfo(m_vendor,m_version);
		   }

		}
	}
#endif

}

EndpointRec::~EndpointRec()
{
	PWaitAndSignal lock(m_usedLock);
	PTRACE(3, "Gk\tDelete endpoint: " << m_endpointIdentifier.GetValue() << " " << m_usedCount);

	if (m_endpointVendor) {
		delete m_endpointVendor;
		m_endpointVendor = NULL;
	}

	SetUsesH460P(false);

	if (m_natsocket) {
		m_natsocket->Close();
		m_natsocket->SetConnected(false);
		m_natsocket->SetDeletable();
	}
}

bool EndpointRec::LoadConfig()
{ 
	PWaitAndSignal lock(m_usedLock);
	LoadEndpointConfig();
	return true;
}

void EndpointRec::LoadEndpointConfig()
{
	Toolkit* toolkit = Toolkit::Instance();
	PConfig* const cfg = GkConfig();
	const PStringList sections = cfg->GetSections();
	m_prefixCapacities.clear(); // clear capacity settings
	m_activePrefixCalls.clear(); // we loose call stats on Reload, but capacities may have changed

	bool setDefaults = true;
	for (PINDEX i = 0; i < m_terminalAliases.GetSize(); i++) {
		const PString key = "EP::" + AsString(m_terminalAliases[i], FALSE);
		if (sections.GetStringsIndex(key) != P_MAX_INDEX) {
			setDefaults = false;
			m_capacity = cfg->GetInteger(key, "Capacity", -1);
			AddPrefixCapacities(cfg->GetString(key, "PrefixCapacities", ""));
			int type = cfg->GetInteger(key, "CalledTypeOfNumber", -1);
			if (type == -1)
				m_calledTypeOfNumber = toolkit->Config()->GetInteger(RoutedSec, "CalledTypeOfNumber", -1);
			else
				m_calledTypeOfNumber = type;
			type = cfg->GetInteger(key, "CallingTypeOfNumber", -1);
			if (type == -1)
				m_callingTypeOfNumber = toolkit->Config()->GetInteger(RoutedSec, "CallingTypeOfNumber", -1);
			else
				m_callingTypeOfNumber = type;

			int plan = cfg->GetInteger(key, "CalledPlanOfNumber", -1);
			if (plan == -1)
				m_calledPlanOfNumber = toolkit->Config()->GetInteger(RoutedSec, "CalledPlanOfNumber", -1);
			else
				m_calledPlanOfNumber = plan;
			plan = cfg->GetInteger(key, "CallingPlanOfNumber", -1);
			if (plan == -1)
				m_callingPlanOfNumber = toolkit->Config()->GetInteger(RoutedSec, "CallingPlanOfNumber", -1);
			else
				m_callingPlanOfNumber = plan;

			toolkit->ParseTranslationMap(m_receivedCauseMap, cfg->GetString(key, "TranslateReceivedQ931Cause", ""));
			toolkit->ParseTranslationMap(m_sentCauseMap, cfg->GetString(key, "TranslateSentQ931Cause", ""));
			m_proxy = cfg->GetInteger(key, "Proxy", 0);
			PString log;
			if (m_calledTypeOfNumber > -1)
				log += " Called Type Of Number: " +  PString(m_calledTypeOfNumber);
			if (m_callingTypeOfNumber > -1)
				log += " Calling Type Of Number: " + PString(m_callingTypeOfNumber);
			if (m_proxy > 0)
				log += " proxy: " + PString(m_proxy);
			m_h46017disabled = Toolkit::AsBool(cfg->GetString(key, "DisableH46017", "0"));
			m_h46018disabled = Toolkit::AsBool(cfg->GetString(key, "DisableH46018", "0"));
			PString numbersDef = cfg->GetString(key, "AddNumbers", "");
			if (!numbersDef.IsEmpty()) {
				AddNumbers(numbersDef);
			}
			m_maxBandwidth = cfg->GetInteger(key, "MaxBandwidth", -1);
			m_additionalDestAlias = cfg->GetString(key, "AdditionalDestinationAlias", "");
 
			PTRACE(5, "RAS\tEndpoint " << key << " capacity: " << m_capacity << log);

			break;
		}
	}
	
	if (setDefaults) {
		m_capacity = -1;
		m_calledTypeOfNumber = toolkit->Config()->GetInteger(RoutedSec, "CalledTypeOfNumber", -1);
		m_callingTypeOfNumber = toolkit->Config()->GetInteger(RoutedSec, "CallingTypeOfNumber", -1);
		m_calledPlanOfNumber = toolkit->Config()->GetInteger(RoutedSec, "CalledPlanOfNumber", -1);
		m_callingPlanOfNumber = toolkit->Config()->GetInteger(RoutedSec, "CallingPlanOfNumber", -1);
		m_proxy = 0;
	}
}

void EndpointRec::AddPrefixCapacities(const PString & prefixes)
{
	PStringArray prefix(prefixes.Tokenise(" ,;\t\n", false));
	for (PINDEX i = 0; i < prefix.GetSize(); ++i) {
		PStringArray p(prefix[i].Tokenise(":=", false));
		if (p.GetSize() > 1) {
			string cap_prefix = (const char *)p[0];
			int capacity = p[1].AsInteger();
			m_prefixCapacities.push_back(pair<std::string,int>(cap_prefix, capacity));
			m_activePrefixCalls[cap_prefix] = 0;
			PTRACE(5, "RAS\tEndpoint prefix: " << cap_prefix << " capacity: " << capacity);
		} else {
			PTRACE(1, "RAS\tEndpoint Syntax error in PrefixCapacities " << prefix[i]);
			SNMP_TRAP(7, SNMPError, Configuration, "Invalid PrefixCapacities configuration");
		}
	}
}

bool EndpointRec::HasAvailableCapacity(const H225_ArrayOf_AliasAddress & aliases) const
{
	string matched_prefix = "";
	int prefix_capacity = -1;

	for (PINDEX i = 0; i < aliases.GetSize(); i++) {
		const unsigned tag = aliases[i].GetTag();
		if (tag == H225_AliasAddress::e_dialedDigits
			|| tag == H225_AliasAddress::e_partyNumber
			|| tag == H225_AliasAddress::e_h323_ID) {
			const PString alias = AsString(aliases[i], FALSE);
			matched_prefix = LongestPrefixMatch(alias, prefix_capacity);
		}
	}
	// check if matched prefix has capacity available
	if ((matched_prefix.length() > 0) && (prefix_capacity >= 0)) {
		std::map<string, int>::const_iterator calls_iter = m_activePrefixCalls.find(matched_prefix);
		if ((calls_iter != m_activePrefixCalls.end())
			&& (calls_iter->second >= prefix_capacity)) {
			PTRACE(5, "Prefix capacity for " << matched_prefix << " reached (max. " << prefix_capacity << ")");
			return FALSE;
		}
	}

	// check if total gateway has capacity
	return m_capacity == -1 || m_activeCall < m_capacity;
}

//void EndpointRec::DumpPrefixCapacity() const
//{
//	PTRACE(1, "JW: Dumping current prefix capacities for " << AsString(m_terminalAliases, FALSE) << " (" << AsDotString(GetCallSignalAddress()) << "):");
//	PTRACE(1, "JW: Total calls = " << m_activeCall);
//	list<pair<string, int> >::const_iterator Iter = m_prefixCapacities.begin();
//	while (Iter != m_prefixCapacities.end()) {
//		string prefix = Iter->first;
//		int capacity = Iter->second;
//		int calls = 0;
//		map<string, int>::const_iterator calls_iter = m_activePrefixCalls.find(prefix);
//		if (calls_iter != m_activePrefixCalls.end()) {
//			calls = calls_iter->second;
//		} else {
//			PTRACE(1, "CODING ERROR no stats for prefix " << prefix);
//		}
//		PTRACE(1, "JW PREFIXCAP prefix/capacity/curr: " << prefix << "/" << capacity << "/" << calls);
//		++Iter;
//	}
//}

PString EndpointRec::PrintPrefixCapacities() const
{
	PString msg;
	msg += PString("-- Endpoint: ") + AsString(m_terminalAliases, FALSE) + " (" + AsDotString(GetCallSignalAddress()) + ") --\r\n";
	msg += "Total calls = " + PString(m_activeCall) + "\r\n";
	list<pair<string, int> >::const_iterator Iter = m_prefixCapacities.begin();
	while (Iter != m_prefixCapacities.end()) {
		string prefix = Iter->first;
		int capacity = Iter->second;
		int calls = 0;
		std::map<string, int>::const_iterator calls_iter = m_activePrefixCalls.find(prefix);
		if (calls_iter != m_activePrefixCalls.end()) {
			calls = calls_iter->second;
		} else {
			PTRACE(1, "CODING ERROR no stats for prefix " << prefix);
			SNMP_TRAP(7, SNMPWarning, General, "no stats for prefix " + prefix);
		}
		msg += PString("prefix/capacity/curr: ") + prefix + "/" + PString(capacity) + "/" + PString(calls) + "\r\n";
		++Iter;
	}
	return msg;
}

string EndpointRec::LongestPrefixMatch(const PString & alias, int & capacity) const
{
	int maxlen = 0;	// longest match
	string matched_prefix;
	int prefix_capacity = -1;

	list<pair<string, int> >::const_iterator Iter = m_prefixCapacities.begin();
	while (Iter != m_prefixCapacities.end()) {
		string prefix = Iter->first;
		if (prefix.length() > (unsigned)abs(maxlen)) {
			PINDEX offset, len;
			if (!alias.FindRegEx(PRegularExpression(prefix.c_str(), PRegularExpression::Extended), offset, len)) {
				// ok, ignore
			} else {
				if (len > maxlen) {
					maxlen = len;
					matched_prefix = prefix;
					prefix_capacity = Iter->second;
				}
			}
		}
		++Iter;
	}
	// two return values
	capacity = prefix_capacity;
	return matched_prefix;
}

void EndpointRec::UpdatePrefixStats(const PString & dest, int update)
{
	int capacity = -1;
	string longest_match = LongestPrefixMatch(dest, capacity);
	if (longest_match.length() > 0) {
		m_activePrefixCalls[longest_match] += update;
		// avoid neg. call numbers; can happen when config is reloaded while calls are standing
		if (m_activePrefixCalls[longest_match] < 0)
			m_activePrefixCalls[longest_match] = 0;
	} else {
		// ignore if prefix is not limited (or this is the calling endpoint)
	}
}

unsigned EndpointRec::TranslateReceivedCause(unsigned cause) const
{
	std::map<unsigned, unsigned>::const_iterator i = m_receivedCauseMap.find(cause);
	if (i != m_receivedCauseMap.end())
		return i->second;
	else
		return cause;
}

unsigned EndpointRec::TranslateSentCause(unsigned cause) const
{
	std::map<unsigned, unsigned>::const_iterator i = m_sentCauseMap.find(cause);
	if (i != m_sentCauseMap.end())
		return i->second;
	else
		return cause;
}

void EndpointRec::SetTimeToLive(int seconds)
{
	PWaitAndSignal lock(m_usedLock);

	if (m_timeToLive > 0 && !m_permanent) {
		// To avoid bloated RRQ traffic, don't allow ttl < 60 for non-H.460.17/.18 endpoints
		if (seconds < 60 && !IsTraversalClient() && !UsesH46017())
			seconds = 60;
		m_timeToLive = (SoftPBX::TimeToLive > 0) ?
			std::min(SoftPBX::TimeToLive, seconds) : 0;
	}
}

void EndpointRec::SetNATSocket(CallSignalSocket * socket)
{
	PWaitAndSignal lock(m_usedLock);

	if (!socket || !socket->IsConnected())
		return;

	if (m_natsocket != socket) {
		PTRACE(3, "Q931\tNAT socket detected at " << socket->Name() << " for endpoint " << GetEndpointIdentifier().GetValue());
		if (m_natsocket) {
			PTRACE(1, "Q931\tWarning: natsocket " << m_natsocket->Name()
				<< " is overwritten by " << socket->Name());
			m_natsocket->Close();
			m_natsocket->SetDeletable();
		}
		m_natsocket = socket;
	}
}

void EndpointRec::RemoveNATSocket()
{
	PWaitAndSignal lock(m_usedLock);

	if (m_natsocket) {
		m_natsocket->Close();
		m_natsocket->SetConnected(false);
		m_natsocket->SetDeletable();
		m_natsocket = NULL;
	}
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

void EndpointRec::AddNumbers(const PString & numbers)
{
	PWaitAndSignal lock(m_usedLock);
 
	PStringArray defs(numbers.Tokenise(",", FALSE));
	for (PINDEX i = 0; i < defs.GetSize(); i++) {
		if (defs[i].Find("-") != P_MAX_INDEX) {
			// range
			PStringArray bounds(defs[i].Tokenise("-", FALSE));
			unsigned lower = bounds[0].AsUnsigned();
			unsigned upper = 0;
			if (bounds.GetSize() == 2) {
				upper = bounds[1].AsUnsigned();
			} else {
				PTRACE(1, "AddNumber: Invalid range definition: " << defs[i]);
				continue;
			}
			if (upper <= lower) {
				PTRACE(1, "AddNumber: Invalid range bounds: " << defs[i]);
				continue;
			}
			unsigned num = upper - lower;
			for (unsigned j = 0; j <= num; j++) {
				PString number(lower + j);
				PTRACE(4, "Adding number " << number << " to endpoint (from range)");
				m_terminalAliases.SetSize(m_terminalAliases.GetSize() + 1);
				H323SetAliasAddress(number, m_terminalAliases[m_terminalAliases.GetSize() - 1], H225_AliasAddress::e_dialedDigits);
			}
		} else {
			// single number
			PTRACE(4, "Adding number " << defs[i] << " to endpoint");
			m_terminalAliases.SetSize(m_terminalAliases.GetSize() + 1);
			H323SetAliasAddress(defs[i], m_terminalAliases[m_terminalAliases.GetSize() - 1]);
		}
	}
}
 
bool EndpointRec::SetAssignedAliases(H225_ArrayOf_AliasAddress & assigned)
{
	PWaitAndSignal lock(m_usedLock);

	bool newalias = Toolkit::Instance()->GetAssignedEPAliases().GetAliases(m_terminalAliases,assigned);
	// If we have assigned Aliases then replace the existing list of aliases
	if (newalias) {
		m_terminalAliases.RemoveAll();
		m_terminalAliases = assigned;
		LoadConfig(); // update settings for the new aliases
	}

	return newalias;
}

void EndpointRec::SetEndpointType(const H225_EndpointType &t) 
{
	{
		PWaitAndSignal lock(m_usedLock);
		*m_terminalType = t;
	}
	LoadConfig(); // update settings for the new endpoint type
}

void EndpointRec::SetNATAddress(const PIPSocket::Address & ip, WORD port)
{
	PWaitAndSignal lock(m_usedLock);

	m_nat = true;
	m_natip = ip;

	// we keep the original private IP in signaling address,
	// because we have to use it to identify different endpoints
	// but from the same NAT box
	if (ip.GetVersion() == 6) {
		m_rasAddress.SetTag(H225_TransportAddress::e_ip6Address);
		H225_TransportAddress_ip6Address & rasip = m_rasAddress;
		for (int i = 0; i < 16; ++i)
			rasip.m_ip[i] = ip[i];
		rasip.m_port = port;
	} else {
		m_rasAddress.SetTag(H225_TransportAddress::e_ipAddress);
		H225_TransportAddress_ipAddress & rasip = m_rasAddress;
		for (int i = 0; i < 4; ++i)
			rasip.m_ip[i] = ip[i];
		rasip.m_port = port;
	}
}


// due to strange bug in gcc, I have to pass pointer instead of reference
bool EndpointRec::CompareAlias(const H225_ArrayOf_AliasAddress *a) const
{
	bool compareAliasType = GkConfig()->GetBoolean("CompareAliasType", true);
	bool compareAliasCase = GkConfig()->GetBoolean("CompareAliasCase", true);
	PWaitAndSignal lock(m_usedLock);
	// don't find out-of-zone EPRecs from traversal servers by alias
	// we must send a new LRQ (with CallID) so the traversal server will recognize
	// the call as a traversal call (VCS 6.x behavior)
	if (IsTraversalServer())
		return false;
	for (PINDEX i = 0; i < a->GetSize(); i++) {
		for (PINDEX j = 0; j < m_terminalAliases.GetSize(); j++) {
			bool typeMatch = compareAliasType ? ((*a)[i].GetTag() == m_terminalAliases[j].GetTag()) : true;
			bool contentMatch = false;
			if (typeMatch) {
				if (compareAliasCase) {
					contentMatch = AsString((*a)[i], false) == AsString(m_terminalAliases[j], false);
				} else {
					contentMatch = PCaselessString(AsString((*a)[i], false)) == AsString(m_terminalAliases[j], false);
				}
			}
			if (typeMatch && contentMatch)
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
				&& (rrq.m_terminalAlias.GetSize() >= 1)) {
				LoadAliases(rrq.m_terminalAlias, rrq.m_terminalType);
				LoadConfig(); // update settings for the new aliases
			}
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

EndpointRec *EndpointRec::Unregisterpreempt(int type)
{
	PTRACE(1, "EP\tUnregistering " << AsDotString(GetRasAddress()) << " Reason " << type);
	SendURQ(H225_UnregRequestReason::e_maintenance,type);
	return this;
}

EndpointRec *EndpointRec::Unregister()
{
	if (!IsPermanent())
		SendURQ(H225_UnregRequestReason::e_maintenance,0);
	return this;
}

EndpointRec *EndpointRec::Expired()
{
	SendURQ(H225_UnregRequestReason::e_ttlExpired, 0);
	return this;
}

PString EndpointRec::PrintOn(bool verbose) const
{
	PString msg = AsDotString(GetCallSignalAddress())
		    + "|" + AsString(GetAliases())
		    + "|" + AsString(GetEndpointType())
		    + "|" + GetEndpointIdentifier().GetValue()
		    + "\r\n";
	if (verbose) {
		msg += GetUpdatedTime().AsString();
		PWaitAndSignal lock(m_usedLock);
		if (IsPermanent())
			msg += " (permanent)";
		PString natstring(IsNATed() ? m_natip.AsString() : PString::Empty());
		msg += PString(PString::Printf, " C(%d/%d/%d) %s <%d>", m_activeCall, m_connectedCall, m_totalCall, (const unsigned char *)natstring, m_usedCount);
		if (UsesH46017()) {
			msg += " (H.460.17)";
		}
		if (IsTraversalClient() || IsTraversalServer()) {
			msg += " (H.460.18)";
		}
		msg += " bw:" + PString(m_bandwidth) + "/" + PString(m_maxBandwidth);
		msg += "\r\n";
	}
	return msg;
}

bool EndpointRec::SendURQ(H225_UnregRequestReason::Choices reason, int preemption)
{
	if ((GetRasAddress().GetTag() != H225_TransportAddress::e_ipAddress)
		&& (GetRasAddress().GetTag() != H225_TransportAddress::e_ip6Address)
		&& !UsesH46017())
		return false;  // no valid RAS address

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

	SetUsesH460P(false);
#ifdef HAS_H46017
	if (UsesH46017())
		urq.m_callSignalAddress.SetSize(0);
#endif
	urq.IncludeOptionalField(H225_UnregistrationRequest::e_reason);
	urq.m_reason.SetTag(reason);

#ifdef HAS_H460
	if (preemption > 0) {
		urq.IncludeOptionalField(H225_UnregistrationRequest::e_genericData);
		H460_FeatureOID pre = H460_FeatureOID(OpalOID(OID6));
		if (preemption == 1)  // Higher Priority 
           pre.Add(PString(OID6_PriNot), H460_FeatureContent(TRUE));          
		else if (preemption == 2)  // Pre-empted
           pre.Add(PString(OID6_PreNot), H460_FeatureContent(TRUE));

		H225_ArrayOf_GenericData & data = urq.m_genericData;
		PINDEX lastPos = data.GetSize();
		data.SetSize(lastPos+1);
		data[lastPos] = pre;
	}
#endif

	PString msg(PString::Printf, "URQ|%s|%s|%s;\r\n", 
			(const unsigned char *) AsDotString(GetRasAddress()),
			(const unsigned char *) GetEndpointIdentifier().GetValue(),
			(const unsigned char *) urq.m_reason.GetTagName());
        GkStatus::Instance()->SignalStatus(msg, STATUS_TRACE_LEVEL_RAS);

	RasSrv->ForwardRasMsg(ras_msg);
	if (reason == H225_UnregRequestReason::e_maintenance) {
		PIPSocket::Address ip;
		WORD notused;
		if (GetIPAndPortFromTransportAddr(GetRasAddress(), ip, notused)) {
			RasSrv->SetAlternateGK(urq, ip);
		}
	}
#ifdef HAS_H46017
	if (UsesH46017()) {
		CallSignalSocket * s = GetSocket();
		if (s) {
			s->SendH46017Message(ras_msg);
			s->Close();
		}
	} else
#endif
		RasSrv->SendRas(ras_msg, GetRasAddress());
	return true;
}

bool EndpointRec::SendIRQ()
{
	if (m_pollCount <= 0)
		return false;
	if ((GetRasAddress().GetTag() != H225_TransportAddress::e_ipAddress)
		&& (GetRasAddress().GetTag() != H225_TransportAddress::e_ip6Address)
		&& !UsesH46017()) {
		return false;
	}
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
#ifdef HAS_H46017
	if (UsesH46017()) {
		CallSignalSocket * s = GetSocket();
		if (s)
			s->SendH46017Message(ras_msg);
	} else
#endif
		RasSrv->SendRas(ras_msg, GetRasAddress());

	return true;
}

bool EndpointRec::AddCallCreditServiceControl(
	H225_ArrayOf_ServiceControlSession & sessions, /// array to add the service control descriptor to
	const PString & amountStr,	/// user's account balance amount string
	int billingMode,			/// user's account billing mode (-1 if not set)
	long callDurationLimit 		/// call duration limit (-1 if not set)
	)
{

	if (!HasCallCreditCapabilities()) 
		return false;

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

	return true;
}

bool EndpointRec::AddHTTPServiceControl(H225_ArrayOf_ServiceControlSession & sessions)
{
	PString url = GkConfig()->GetString(RRQFeaturesSection, "AccHTTPLink", "");
	if (url.IsEmpty())
		return false;

	const PINDEX sessionIndex = sessions.GetSize();
	sessions.SetSize(sessionIndex + 1);

	H225_ServiceControlSession& session = sessions[sessionIndex];
	// URL session ID is 1  
	session.m_sessionId = 1;
	session.m_reason = H225_ServiceControlSession_reason::e_open;
	session.IncludeOptionalField(H225_ServiceControlSession::e_contents);
	session.m_contents.SetTag(H225_ServiceControlDescriptor::e_url);
	PASN_IA5String & pdu = session.m_contents;
	pdu = url;   

	return true;
}

void EndpointRec::SetUsesH460P(bool uses)
{
	if (uses == m_usesH460P)
		return;
 
#ifdef HAS_H460P
	GkPresence & handler  = Toolkit::Instance()->GetPresenceHandler();
	if (uses) 
	   handler.RegisterEndpoint(m_endpointIdentifier,m_terminalAliases);
	else
	   handler.UnRegisterEndpoint(m_terminalAliases);
	m_usesH460P = uses;
#endif
}

#ifdef HAS_H460P
void EndpointRec::ParsePresencePDU(const PASN_OctetString & pdu)
{
	GkPresence & handler  = Toolkit::Instance()->GetPresenceHandler();
	handler.ProcessPresenceElement(pdu);
}

bool EndpointRec::BuildPresencePDU(unsigned msgtag, PASN_OctetString & pdu)
{
	GkPresence & handler  = Toolkit::Instance()->GetPresenceHandler();
	return handler.BuildPresenceElement(msgtag,m_endpointIdentifier, pdu);
}
#endif

#ifdef H323_H350
static const char * LDAPServiceOID = "1.3.6.1.4.1.17090.2.1";

bool EndpointRec::AddH350ServiceControl(
	H225_ArrayOf_ServiceControlSession& sessions 
	)
{
	if (!Toolkit::AsBool(GkConfig()->GetString("GkH350::Settings", "ServiceControl", "1")))
		   return false;

	PString ldap = GkConfig()->GetString("GkH350::Settings", "ServerName", "");
		if (ldap.IsEmpty()) return false;

	PString port = GkConfig()->GetString("GkH350::Settings", "ServerPort", "389");
	PString server = ldap + ":" + port;		// IPv4
	if (IsIPv6Address(ldap))
		server = "[" + ldap + "]:" + port;	// IPv6

	// TODO: this SearchBaseDN is also used for lookup of the commObjects,
	// so its probably not the right SearchBaseDN for white page lookup
	PString search = GkConfig()->GetString("GkH350::Settings", "SearchBaseDN", "");
	if (search.IsEmpty())
		return false;
	   
	const PINDEX sessionIndex = sessions.GetSize();
	sessions.SetSize(sessionIndex + 1);

	H225_ServiceControlSession& session = sessions[sessionIndex];
    // H350 session ID is 2  
    session.m_sessionId = 2;
	session.m_reason = H225_ServiceControlSession_reason::e_open;
	session.IncludeOptionalField(H225_ServiceControlSession::e_contents);

    session.m_contents.SetTag(H225_ServiceControlDescriptor::e_nonStandard);

	H225_NonStandardParameter & pdu = session.m_contents;
	H225_NonStandardIdentifier & id = pdu.m_nonStandardIdentifier;
	id.SetTag(H225_NonStandardIdentifier::e_object);
	PASN_ObjectId i = id;
	i.SetValue(LDAPServiceOID);

	PASN_OctetString & data = pdu.m_data;

	H225_H350ServiceControl svc;
	svc.m_ldapURL = server;
	svc.m_ldapDN = search;

	data.EncodeSubType(svc);
	return true;
}
#endif



GatewayRec::GatewayRec(const H225_RasMessage & completeRRQ, bool Permanent)
      : EndpointRec(completeRRQ, Permanent), defaultGW(false), priority(1)
{
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
	
	bool setDefaults = true;	
	for (PINDEX i = 0; i < m_terminalAliases.GetSize(); i++) {
		const PString alias = AsString(m_terminalAliases[i], FALSE);
		if (!alias) {
			const PString key = "EP::" + alias;
			if (sections.GetStringsIndex(key) != P_MAX_INDEX) {
				priority = cfg->GetInteger(key, "GatewayPriority", 1);
				AddPrefixes(cfg->GetString(key, "GatewayPrefixes", ""));
				setDefaults = false;
				PTRACE(5, "RAS\tGateway " << key << " priority: " << priority);
			}
			AddPrefixes(cfg->GetString("RasSrv::GWPrefixes", alias, ""));
		}
	}

	if (setDefaults)
		priority = 1;

	if (m_terminalType->HasOptionalField(H225_EndpointType::e_gateway) &&
		Toolkit::AsBool(cfg->GetString(RRQFeaturesSection, "AcceptGatewayPrefixes", "1")))
		if (m_terminalType->m_gateway.HasOptionalField(H225_GatewayInfo::e_protocol))
			AddPrefixes(m_terminalType->m_gateway.m_protocol);

	if (m_terminalType->HasOptionalField(H225_EndpointType::e_mcu) &&
		Toolkit::AsBool(cfg->GetString(RRQFeaturesSection, "AcceptMCUPrefixes", "1")))
		if (m_terminalType->m_mcu.HasOptionalField(H225_McuInfo::e_protocol))
			AddPrefixes(m_terminalType->m_mcu.m_protocol);
		
	SortPrefixes();
}

void GatewayRec::SetEndpointType(const H225_EndpointType & t)
{
	if (!t.HasOptionalField(H225_EndpointType::e_gateway) ||
		!t.HasOptionalField(H225_EndpointType::e_mcu)) {
		PTRACE(1, "RRJ: terminal type changed|" << GetEndpointIdentifier().GetValue());
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

void GatewayRec::AddPrefixes(const H225_ArrayOf_SupportedProtocols & protocols)
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
					if (!Prefixes[(const char *)AsString(a, false)])
						Prefixes[(const char *)AsString(a, false)] = priority;
			}
	}
}

void GatewayRec::AddPrefixes(const PString & prefixes)
{
	PStringArray prefix(prefixes.Tokenise(" ,;\t\n", false));
	for (PINDEX i = 0; i < prefix.GetSize(); ++i) {
		PStringArray p(prefix[i].Tokenise(":=", false));
		int prefix_priority = (p.GetSize() > 1) ? p[1].AsInteger() : priority;
		if (prefix_priority < 1)
			prefix_priority = 1;
		Prefixes[(const char *)p[0]] = prefix_priority;
	}
}

void GatewayRec::SortPrefixes()
{
	// remove duplicate aliases
//	sort(Prefixes.begin(), Prefixes.end(), str_prefix_greater());
//	prefix_iterator Iter = std::unique(Prefixes.begin(), Prefixes.end());
//	Prefixes.erase(Iter, Prefixes.end());
	defaultGW = (Prefixes.find("*") != Prefixes.end());
}

//void GatewayRec::DumpPriorities() const
//{
//      PTRACE(1, "JW Priorities for GW " << AsString(m_terminalAliases, FALSE) << " (" << AsDotString(GetCallSignalAddress()) << "):");
//      PTRACE(1, "JW GatewayPriority = " << priority);
//      map<std::string, int>::const_iterator Iter = Prefixes.begin();
//      while (Iter != Prefixes.end()) {
//              string prefix = Iter->first;
//              int prefix_priority = Iter->second;
//              PTRACE(1, "JW " << prefix << ":=" << prefix_priority);
//              ++Iter;
//      }
//}

int GatewayRec::PrefixMatch(const H225_ArrayOf_AliasAddress &aliases) const
{
	int dummy;
	return PrefixMatch(aliases, dummy, dummy);
}

int GatewayRec::PrefixMatch(
	const H225_ArrayOf_AliasAddress& aliases,
	int& matchedalias,
	int& priority_out
	) const
{
	int maxlen = 0;
	const_prefix_iterator pfxiter = Prefixes.end();
	const_prefix_iterator eIter = Prefixes.end();

	matchedalias = 0;
	priority_out = priority;
	
	for (PINDEX i = 0; i < aliases.GetSize(); i++) {
		const unsigned tag = aliases[i].GetTag();
		if (tag == H225_AliasAddress::e_dialedDigits
			|| tag == H225_AliasAddress::e_partyNumber
			|| tag == H225_AliasAddress::e_h323_ID) {
			
			const PString alias = AsString(aliases[i], FALSE);
			// we also allow h_323_ID aliases consisting only from digits
			if (tag == H225_AliasAddress::e_h323_ID)
				if(!IsValidE164(alias) )
					continue;
					
			const_prefix_iterator Iter = Prefixes.begin();
			while (Iter != eIter) {
				if (Iter->first.length() > (unsigned)abs(maxlen)) {
					const int len = MatchPrefix(alias, Iter->first.c_str());
					// replace the current match if the new prefix is longer
					// or if lengths are equal and this is a blocking rule (!)
					if (abs(len) > abs(maxlen)
						|| (len < 0 && (len + maxlen) == 0)) {
						pfxiter = Iter;
						maxlen = len;
						matchedalias = i;
						priority_out = Iter->second;
					}
				}
				++Iter;
			}
		}
	}
	
	if (maxlen < 0) {
		PTRACE(2, "RASTBL\tGateway " << GetEndpointIdentifier().GetValue() 
			<< " skipped by prefix " << pfxiter->first.c_str()
			);
	} else if (maxlen > 0) {
		PTRACE(2, "RASTBL\tGateway " << GetEndpointIdentifier().GetValue()
			<< " matched by prefix " << pfxiter->first.c_str() << ", priority: " << priority_out
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
		PTRACE(2, "RASTBL\tGateway " << GetEndpointIdentifier().GetValue()
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
		if (Prefixes.empty()) {
			msg += "<none>";
		} else {
			PString m = PString(Prefixes.begin()->first);
			m += ":=" + PString(Prefixes.begin()->second);
			const_prefix_iterator Iter = Prefixes.begin(), eIter= Prefixes.end();
			while (++Iter != eIter) {
				m += "," + PString(Iter->first);
				m += ":=" + PString(Iter->second);
			}
			msg += m;
		}
		msg += "\r\n";
	}
	return msg;
}

OutOfZoneEPRec::OutOfZoneEPRec(const H225_RasMessage & completeRAS, const H225_EndpointIdentifier &epID) : EndpointRec(completeRAS, false)
{
	m_endpointIdentifier = epID;
	PTRACE(1, "New OZEP|" << PrintOn(false));
}

OutOfZoneGWRec::OutOfZoneGWRec(const H225_RasMessage & completeLCF, const H225_EndpointIdentifier &epID) : GatewayRec(completeLCF, false)
{
	m_endpointIdentifier = epID;

	const H225_LocationConfirm & obj_lcf = completeLCF;
	if (obj_lcf.HasOptionalField(H225_LocationConfirm::e_supportedProtocols)) {
		AddPrefixes(obj_lcf.m_supportedProtocols);
		SortPrefixes();
	}
	defaultGW = false; // don't let out-of-zone gateway be default
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
	// since the socket has been deleted, just remove it
	ForEachInContainer(RemovedList, mem_fun(&EndpointRec::GetAndRemoveSocket));
	DeleteObjectsInContainer(RemovedList);
}

endptr RegistrationTable::InsertRec(H225_RasMessage & ras_msg, PIPSocket::Address ip)
{
	endptr ep;
	switch (ras_msg.GetTag())
	{
		case H225_RasMessage::e_registrationRequest: {
			H225_RegistrationRequest & rrq = ras_msg;
			if ((ep = FindBySignalAdr(rrq.m_callSignalAddress[0], ip)))
				ep->Update(ras_msg);
			else
				ep = InternalInsertEP(ras_msg);
			break;
		}
		case H225_RasMessage::e_admissionRequest: {
			H225_AdmissionRequest & arq = ras_msg;
			if (arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress) && !(ep = FindOZEPBySignalAdr(arq.m_destCallSignalAddress))) {
				H225_AdmissionConfirm nouse;
				ep = InternalInsertOZEP(ras_msg, nouse);
			}
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

	RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctRegister, ep);
	return ep;
}

endptr RegistrationTable::InsertRec(const H225_Setup_UUIE & setupBody, H225_TransportAddress addr)
{
	// TODO: check if we have an EPRec for that addr already ? or always create a new one ?
	endptr ep = InternalInsertOZEP(setupBody, addr);
	RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctRegister, ep);
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
	EndpointRec *ep = new OutOfZoneEPRec(ras_msg, epID);
	WriteLock lock(listLock);
	OutOfZoneList.push_front(ep);
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
		ep = new OutOfZoneGWRec(ras_msg, epID);
	else
		ep = new OutOfZoneEPRec(ras_msg, epID);

	WriteLock lock(listLock);
	OutOfZoneList.push_front(ep);
	return endptr(ep);
}

endptr RegistrationTable::InternalInsertOZEP(const H225_Setup_UUIE & setupBody, H225_TransportAddress addr)
{
	H225_RasMessage ras;
	ras.SetTag(H225_RasMessage::e_registrationRequest);
	H225_RegistrationRequest rrq = (H225_RegistrationRequest &)ras;	// fake RRQ to create the EPRec

	H225_EndpointIdentifier epID;
	epID = "oz_" + PString(PString::Unsigned, ozCnt++) + endpointIdSuffix;
	rrq.m_endpointIdentifier = epID;
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_terminalAlias);
		rrq.m_terminalAlias = setupBody.m_sourceAddress;
	}
	rrq.m_callSignalAddress.SetSize(1);
	rrq.m_callSignalAddress[0] = addr;

	EndpointRec * ep  = new OutOfZoneEPRec(ras, epID);

#if HAS_H46023
	if (ep && Toolkit::Instance()->IsH46023Enabled()
		&& setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
		const H225_ArrayOf_FeatureDescriptor & data = setupBody.m_supportedFeatures;
		for (PINDEX i =0; i < data.GetSize(); i++) {
		H460_Feature & feat = (H460_Feature &)data[i];

		 if (feat.GetFeatureID() == H460_FeatureID(19)) {
			ep->SetNAT(true);
			PIPSocket::Address ip;  WORD port;
			GetIPAndPortFromTransportAddr(addr, ip, port);
			ep->SetNATAddress(ip, port);
			ep->SetTraversalRole(TraversalClient);
		 }

		 if (feat.GetFeatureID() == H460_FeatureID(24)) {
			ep->SetUsesH46023(true);
			ep->SetH46024(true);
			unsigned natinst = feat.Value(Std24_NATInstruct);
			switch (natinst) {
				case CallRec::e_natAnnexA:
					ep->SetH46024A(true);
					break;
				case CallRec::e_natAnnexB:
					ep->SetH46024B(true);
					break;
				default:
					break;
			}
		 }
		}
	}
#endif

	WriteLock lock(listLock);
	OutOfZoneList.push_front(ep);
	return endptr(ep);
}

void RegistrationTable::RemoveByEndptr(const endptr & eptr)
{
	RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctUnregister, eptr);
	EndpointRec *ep = eptr.operator->(); // evil
	ep->SetUsesH460P(false);
	ep->RemoveNATSocket();
	WriteLock lock(listLock);
	InternalRemove(find(EndpointList.begin(), EndpointList.end(), ep));
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
	PWaitAndSignal m(findmutex);

	PString epIdStr;
	epIdStr = epId;
	return InternalFind(compose1(bind2nd(equal_to<PString>(), epIdStr),
			mem_fun(&EndpointRec::GetEndpointIdentifier)));
}

namespace { // anonymous namespace

class CompareSigAdr {
public:
	CompareSigAdr(const H225_TransportAddress & adr) : SigAdr(adr) {}
	bool operator()(const EndpointRec *ep) const { return ep && (ep->GetCallSignalAddress() == SigAdr); }
 
protected:
	const H225_TransportAddress & SigAdr;
};
 
class CompareSigAdrIgnorePort {
public:
	CompareSigAdrIgnorePort(const H225_TransportAddress & adr) : SigAdr(adr) {}
	bool operator()(const EndpointRec *ep) const {
		if (!ep)
			return false;
		H225_TransportAddress other = ep->GetCallSignalAddress();	// make a copy, we'll modify it temporarily!
		if ((SigAdr.GetTag() == H225_TransportAddress::e_ipAddress)
			&& (other.GetTag() == H225_TransportAddress::e_ipAddress)) {
			// set same port on copy as on other adr
			((H225_TransportAddress_ipAddress &)other).m_port = ((const H225_TransportAddress_ipAddress &)SigAdr).m_port;
		} else if ((SigAdr.GetTag() == H225_TransportAddress::e_ip6Address)
			&& (other.GetTag() == H225_TransportAddress::e_ip6Address)) {
			// set same port on copy as on other adr
			((H225_TransportAddress_ip6Address &)other).m_port = ((const H225_TransportAddress_ip6Address &)SigAdr).m_port;
		}
		return other == SigAdr;
	}

protected:
	const H225_TransportAddress & SigAdr;
};

class CompareSigAdrWithNAT : public CompareSigAdr {
public:
	CompareSigAdrWithNAT(const H225_TransportAddress & adr, PIPSocket::Address ip) : CompareSigAdr(adr), natip(ip) {}
	bool operator()(const EndpointRec *ep) const { return ep && (ep->GetNATIP() == natip) && CompareSigAdr::operator()(ep); }
 
private:
	PIPSocket::Address natip;
};
 
class CompareSigAdrWithNATIgnorePort : public CompareSigAdrIgnorePort {
public:
	CompareSigAdrWithNATIgnorePort(const H225_TransportAddress & adr, PIPSocket::Address ip) : CompareSigAdrIgnorePort(adr), natip(ip) {}
	bool operator()(const EndpointRec *ep) const { return ep && (ep->GetNATIP() == natip) && CompareSigAdrIgnorePort::operator()(ep); }

private:
	PIPSocket::Address natip;
};

bool operator==(const H225_TransportAddress & adr, PIPSocket::Address ip)
{
	if (ip == INADDR_ANY)	// TODO: also check against "::" and do *=
		return true;
	PIPSocket::Address ipaddr;
	return GetIPFromTransportAddr(adr, ipaddr) ? (ip == ipaddr) : false;
}

} // end of anonymous namespace

endptr RegistrationTable::FindBySignalAdr(const H225_TransportAddress & sigAd, PIPSocket::Address ip) const
{
	return (sigAd == ip) ? InternalFind(CompareSigAdr(sigAd)) : InternalFind(CompareSigAdrWithNAT(sigAd, ip));
}

endptr RegistrationTable::FindBySignalAdrIgnorePort(const H225_TransportAddress & sigAd, PIPSocket::Address ip) const
{
	return (sigAd == ip) ? InternalFind(CompareSigAdrIgnorePort(sigAd)) : InternalFind(CompareSigAdrWithNATIgnorePort(sigAd, ip));
}
 
endptr RegistrationTable::FindOZEPBySignalAdr(const H225_TransportAddress & sigAd) const
{
	return InternalFind(compose1(bind2nd(equal_to<H225_TransportAddress>(), sigAd),
			mem_fun(&EndpointRec::GetCallSignalAddress)), &OutOfZoneList);
}

endptr RegistrationTable::FindByAliases(const H225_ArrayOf_AliasAddress & alias) const
{
	return InternalFind(bind2nd(mem_fun(&EndpointRec::CompareAlias), &alias));
}

endptr RegistrationTable::FindFirstEndpoint(const H225_ArrayOf_AliasAddress & alias)
{
	endptr ep = InternalFindFirstEP(alias, &EndpointList);
	return (ep) ? ep : InternalFindFirstEP(alias, &OutOfZoneList);
}

bool RegistrationTable::FindEndpoint(
	const H225_ArrayOf_AliasAddress & aliases,
	bool roundRobin,
	bool searchOutOfZone,
	list<Route> & routes)
{
	bool found = InternalFindEP(aliases, &EndpointList, roundRobin, routes);
	if (searchOutOfZone && InternalFindEP(aliases, &OutOfZoneList, roundRobin, routes))
		found = true;
	return found;
}

namespace {
// a specialized comparision operator to have a gwlist sorted by increasing priority value
inline bool ComparePriority(const pair<int, GatewayRec*>& x, const pair<int, GatewayRec*>& y)
{
	return x.first < y.first;
}
}

endptr RegistrationTable::InternalFindFirstEP(const H225_ArrayOf_AliasAddress & alias,
	std::list<EndpointRec *> *List)
{
	endptr ep = InternalFind(bind2nd(mem_fun(&EndpointRec::CompareAlias), &alias), List);
	if (ep) {
		PTRACE(4, "Alias match for EP " << AsDotString(ep->GetCallSignalAddress()));
        return ep;
	}

	int maxlen = 0;
	std::list<std::pair<int, GatewayRec*> > GWlist;
	listLock.StartRead();
	const_iterator Iter = List->begin(), IterLast = List->end();
	while (Iter != IterLast) {
		if ((*Iter)->IsGateway()) {
			int dummymatchedalias, priority = 1;
			int len = dynamic_cast<GatewayRec *>(*Iter)->PrefixMatch(alias, dummymatchedalias, priority);
			if (maxlen < len) {
				GWlist.clear();
				maxlen = len;
			}
			if (maxlen == len)
				GWlist.push_back(std::pair<int, GatewayRec*>(priority, dynamic_cast<GatewayRec*>(*Iter)));
		}
		++Iter;
	}
	listLock.EndRead();

	if (!GWlist.empty()) {
		GWlist.sort(ComparePriority);
		
		GatewayRec *e = GWlist.front().second;
		PTRACE(4, "Prefix match for GW " << AsDotString(e->GetCallSignalAddress()));
		return endptr(e);
	}
	
	return endptr(0);
}

bool RegistrationTable::InternalFindEP(
	const H225_ArrayOf_AliasAddress & aliases,
	list<EndpointRec*> * endpoints,
	bool roundRobin,
	list<Route> & routes)
{
	endptr ep = InternalFind(bind2nd(mem_fun(&EndpointRec::CompareAlias), &aliases), endpoints);
	if (ep) {
		PTRACE(4, "Alias match for EP " << AsDotString(ep->GetCallSignalAddress()));
		routes.push_back(Route("internal", ep));
        return true;
	}

	int maxlen = 0;

	std::list<std::pair<int, GatewayRec*> > GWlist;
	listLock.StartRead();
	const_iterator Iter = endpoints->begin(), IterLast = endpoints->end();
	while (Iter != IterLast) {
		if ((*Iter)->IsGateway()) {
			int matchedalias, priority = 1;
			int len = dynamic_cast<GatewayRec *>(*Iter)->PrefixMatch(aliases, matchedalias, priority);
			if (maxlen < len) {
				GWlist.clear();
				maxlen = len;
			}
			if (maxlen == len)
				GWlist.push_back(std::pair<int, GatewayRec*>(priority, dynamic_cast<GatewayRec*>(*Iter)));
		}
		++Iter;
	}
	listLock.EndRead();

	if (GWlist.empty())
		return false;
		
	GWlist.sort(ComparePriority);
		
	std::list<std::pair<int, GatewayRec*> >::const_iterator i = GWlist.begin();
	while (i != GWlist.end()) {
		if (i->second->HasAvailableCapacity(aliases))
			routes.push_back(Route("internal", endptr(i->second)));
		else
			PTRACE(5, "Capacity exceeded in GW " << AsDotString(i->second->GetCallSignalAddress()));
		++i;
	}

	if (routes.size() > 1 && roundRobin) {
		PTRACE(3, "Prefix apply round robin");
		WriteLock lock(listLock);
		endpoints->remove(routes.front().m_destEndpoint.operator->());
		endpoints->push_back(routes.front().m_destEndpoint.operator->());
	}

	if (PTrace::CanTrace(4)) {
		ostream &strm = PTrace::Begin(4, __FILE__, __LINE__);
		strm << "RASTBL\tPrefix match for gateways: ";
		list<Route>::const_iterator r = routes.begin();
		while (r != routes.end()) {
			strm << endl << AsDotString(r->m_destAddr);
			++r;
		}
		PTrace::End(strm);
	}

	return true;
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

void RegistrationTable::PrintAllRegistrations(USocket *client, bool verbose)
{
	PString msg("AllRegistrations\r\n");
	InternalPrint(client, verbose, &EndpointList, msg);
}

void RegistrationTable::PrintEndpointQoS(USocket *client) //const
{
	std::map<PString, EPQoS> epqos;
	// copy data into a temporary container to avoid long locking
	listLock.StartRead();
	for (const_iterator Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
		epqos[AsString((*Iter)->GetAliases())] = EPQoS((*Iter)->GetUpdatedTime());
	listLock.EndRead();
	// end of lock
 
	PString msg("EndpointQoS\r\n");
	msg.SetSize(EndpointList.size() * 100);	// avoid realloc: estimate n rows of 100 chars
	// fetch QoS data from call table
	CallTable::Instance()->SupplyEndpointQoS(epqos);
	for (std::map<PString, EPQoS>::const_iterator i = epqos.begin(); i != epqos.end(); ++i)
		msg += "QoS|" + i->first + "|" + i->second.AsString() + "\r\n";
 
	msg += PString(PString::Printf, "Number of Endpoints: %u\r\n;\r\n", epqos.size());
	client->TransmitData(msg);
}
 
void RegistrationTable::PrintAllCached(USocket *client, bool verbose)
{
	PString msg("AllCached\r\n");
	InternalPrint(client, verbose, &OutOfZoneList, msg);
}

void RegistrationTable::PrintRemoved(USocket *client, bool verbose)
{
	PString msg("AllRemoved\r\n");
	InternalPrint(client, verbose, &RemovedList, msg);
}

void RegistrationTable::PrintPrefixCapacities(USocket *client, PString alias) const
{
	PString msg = "PrefixCapacities\r\n";
	listLock.StartRead();
	for (const_iterator Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter) {
		if (alias.IsEmpty() || (AsString((*Iter)->GetAliases()[0], FALSE).ToLower() == alias.ToLower()))
			msg += (*Iter)->PrintPrefixCapacities();
	}
	listLock.EndRead();
	// end of lock

	msg += ";\r\n";
	client->TransmitData(msg);
}

void RegistrationTable::InternalPrint(USocket *client, bool verbose, std::list<EndpointRec *> * List, PString & msg)
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
	eptr = NULL;

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
	InternalStatistics(&OutOfZoneList, cs, ct, cg, cn);

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
		iterator epIter = EndpointList.begin();
		while (epIter != EndpointList.end()) {
			EndpointRec *ep = *epIter;
			if (!ep->IsPermanent()) {
				++epIter;
				continue;
			}
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
				epIter = EndpointList.erase(epIter);
				--regSize;
				PTRACE(2, "Permanent endpoint " << ep->GetEndpointIdentifier().GetValue() << " removed");
			}
			else ++epIter;
		}
	}
	
	for (PINDEX i = 0; i < cfgs.GetSize(); ++i) {
		EndpointRec *ep = NULL;
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
	if (Toolkit::AsBool(GkConfig()->GetString("Gatekeeper::Main", "DisconnectCallsOnShutdown", "1"))) {
		// Unregister all endpoints, and move the records into RemovedList
		transform(EndpointList.begin(), EndpointList.end(),
			back_inserter(RemovedList), mem_fun(&EndpointRec::Unregister));
	}
	EndpointList.clear();
	regSize = 0;
	copy(OutOfZoneList.begin(), OutOfZoneList.end(), back_inserter(RemovedList));
	OutOfZoneList.clear();
}

void RegistrationTable::CheckEndpoints()
{
	PTime now;
	WriteLock lock(listLock);

	iterator Iter = EndpointList.begin();
	while (Iter != EndpointList.end()) {
		EndpointRec *ep = *Iter;
		if (!ep->IsUpdated(&now) && !ep->SendIRQ()) {
			SoftPBX::DisconnectEndpoint(endptr(ep));
			ep->Expired();
			RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctUnregister, endptr(ep));
			RemovedList.push_back(ep);
			Iter = EndpointList.erase(Iter);
			--regSize;
			PTRACE(2, "Endpoint " << ep->GetEndpointIdentifier().GetValue() << " expired");
		}
		else ++Iter;
	}

	Iter = partition(OutOfZoneList.begin(), OutOfZoneList.end(),
		bind2nd(mem_fun(&EndpointRec::IsUpdated), &now));
	if (ptrdiff_t s = distance(Iter, OutOfZoneList.end())) {
		PTRACE(2, s << " out-of-zone endpoint(s) expired");
	}
	copy(Iter, OutOfZoneList.end(), back_inserter(RemovedList));
	OutOfZoneList.erase(Iter, OutOfZoneList.end());

	// Cleanup unused EndpointRec in RemovedList
	Iter = partition(RemovedList.begin(), RemovedList.end(), mem_fun(&EndpointRec::IsUsed));
	DeleteObjects(Iter, RemovedList.end());
	RemovedList.erase(Iter, RemovedList.end());
}


// handle remote closing of a NAT socket
void RegistrationTable::OnNATSocketClosed(CallSignalSocket * s)
{
	WriteLock lock(listLock);

	iterator Iter = EndpointList.begin();
	while (Iter != EndpointList.end()) {
		EndpointRec *ep = *Iter;
		if (ep->UsesH46017() && (ep->GetSocket() == s)) {
			SoftPBX::DisconnectEndpoint(endptr(ep)); // disconnect ongoing calls
			RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctUnregister, endptr(ep));
			RemovedList.push_back(ep);
			Iter = EndpointList.erase(Iter);
			--regSize;
			PTRACE(2, "Endpoint " << ep->GetEndpointIdentifier().GetValue() << " removed due to closed NAT socket");
			PString msg(PString::Printf, "URQ|%s|%s|%s;\r\n", 
				(const unsigned char *) AsDotString(ep->GetRasAddress()),
				(const unsigned char *) ep->GetEndpointIdentifier().GetValue(),
				"natSocketClosed");
		    GkStatus::Instance()->SignalStatus(msg, STATUS_TRACE_LEVEL_RAS);
		}
		else ++Iter;
	}
}


#ifdef HAS_H46018
H46019KeepAlive::H46019KeepAlive()
{
	flcn = 0;
	interval = 0;
	type = RTP;
	ossocket = INVALID_OSSOCKET;
	multiplexID = INVALID_MULTIPLEX_ID;
	seq = 1;
	timer = GkTimerManager::INVALID_HANDLE;
}

H46019KeepAlive::~H46019KeepAlive()
{
	StopKeepAlive();
}

void H46019KeepAlive::StopKeepAlive()
{
	ossocket = INVALID_OSSOCKET;
	if (timer != GkTimerManager::INVALID_HANDLE) {
		Toolkit::Instance()->GetTimerManager()->UnregisterTimer(timer);
		timer = GkTimerManager::INVALID_HANDLE;
	}
}

struct RTPKeepAliveFrame
{
	BYTE b1;
	BYTE pt;
	WORD seq;
	PInt32 ts;
	PInt32 ssrc;
};

struct MultiplexedRTPKeepAliveFrame
{
	PUInt32b multiplexID;
	BYTE b1;
	BYTE pt;
	WORD seq;
	PInt32 ts;
	PInt32 ssrc;
};

struct RTCPKeepAliveFrame
{
	BYTE b1;
	BYTE pt;
	WORD len;
	PInt32 ssrc;
	PInt32 msw_ts;
	PInt32 lsw_ts;
	PInt32 rtp_ts;
	PInt32 packet_count;
	PInt32 byte_count;
};

struct MultiplexedRTCPKeepAliveFrame
{
	PUInt32b multiplexID;
	BYTE b1;
	BYTE pt;
	WORD len;
	PInt32 ssrc;
	PInt32 msw_ts;
	PInt32 lsw_ts;
	PInt32 rtp_ts;
	PInt32 packet_count;
	PInt32 byte_count;
};

void H46019KeepAlive::SendKeepAlive(GkTimer * t)
{
	if (ossocket == INVALID_OSSOCKET) {
		PTRACE(1, "Error sending RTP/RTCP keepAlive: ossocket not set");
		SNMP_TRAP(10, SNMPError, Network, "Sending multiplexed RTP/RTCP keepAlive failed: socket not set");
		return;
	}

	if (type == RTP) {
		RTPKeepAliveFrame rtpKeepAlive;
		MultiplexedRTPKeepAliveFrame multiplexedRtpKeepAlive;
		char * ka_ptr = NULL;
		size_t ka_size = 0;
		if (multiplexID == INVALID_MULTIPLEX_ID) {
			rtpKeepAlive.b1 = 0x80;
			rtpKeepAlive.pt = GNUGK_KEEPALIVE_RTP_PAYLOADTYPE;
			rtpKeepAlive.seq = htons(seq++);
			rtpKeepAlive.ts = 0;
			rtpKeepAlive.ssrc = 0;
			ka_ptr = (char*)&rtpKeepAlive;
			ka_size = sizeof(rtpKeepAlive);
		} else {
			multiplexedRtpKeepAlive.multiplexID = multiplexID;
			multiplexedRtpKeepAlive.b1 = 0x80;
			multiplexedRtpKeepAlive.pt = GNUGK_KEEPALIVE_RTP_PAYLOADTYPE;
			multiplexedRtpKeepAlive.seq = htons(seq++);
			multiplexedRtpKeepAlive.ts = 0;
			multiplexedRtpKeepAlive.ssrc = 0;
			ka_ptr = (char*)&multiplexedRtpKeepAlive;
			ka_size = sizeof(multiplexedRtpKeepAlive);
		}
		size_t sent = ::sendto(ossocket, ka_ptr, ka_size, 0, (struct sockaddr *)&dest, sizeof(dest));
		if (sent != ka_size) {
			PTRACE(1, "Error sending RTP keepAlive " << timer);
			SNMP_TRAP(10, SNMPError, Network, "Sending multiplexed RTP keepAlive failed");
		}
	} else {
		RTCPKeepAliveFrame rtcpKeepAlive;
		MultiplexedRTCPKeepAliveFrame multiplexedRtcpKeepAlive;
		char * ka_ptr = NULL;
		size_t ka_size = 0;
		if (multiplexID == INVALID_MULTIPLEX_ID) {
			rtcpKeepAlive.b1 = 0x80;
			rtcpKeepAlive.pt = 200;	// SR
			rtcpKeepAlive.len = htons(6);
			rtcpKeepAlive.ssrc = 0;
			rtcpKeepAlive.msw_ts = 0;
			rtcpKeepAlive.lsw_ts = 0;
			rtcpKeepAlive.rtp_ts = 0;
			rtcpKeepAlive.packet_count = 0;
			rtcpKeepAlive.byte_count = 0;
			ka_ptr = (char*)&rtcpKeepAlive;
			ka_size = sizeof(rtcpKeepAlive);
		} else {
			multiplexedRtcpKeepAlive.multiplexID = multiplexID;
			multiplexedRtcpKeepAlive.b1 = 0x80;
			multiplexedRtcpKeepAlive.pt = 200;	// SR
			multiplexedRtcpKeepAlive.len = htons(6);
			multiplexedRtcpKeepAlive.ssrc = 0;
			multiplexedRtcpKeepAlive.msw_ts = 0;
			multiplexedRtcpKeepAlive.lsw_ts = 0;
			multiplexedRtcpKeepAlive.rtp_ts = 0;
			multiplexedRtcpKeepAlive.packet_count = 0;
			multiplexedRtcpKeepAlive.byte_count = 0;
			ka_ptr = (char*)&multiplexedRtcpKeepAlive;
			ka_size = sizeof(multiplexedRtcpKeepAlive);
		}
		size_t sent = ::sendto(ossocket, ka_ptr, ka_size, 0, (struct sockaddr *)&dest, sizeof(dest));
		if (sent != ka_size) {
			PTRACE(1, "Error sending RTCP keepAlive " << timer);
			SNMP_TRAP(10, SNMPError, Network, "Sending multiplexed RTCP keepAlive failed");
		}
	}
}
#endif
	

CallRec::CallRec(
	/// ARQ with call information
	const RasPDU<H225_AdmissionRequest>& arqPdu,
	/// bandwidth occupied by the call
	long bandwidth,
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
	m_connectTime(0), m_disconnectTime(0), m_disconnectCause(0), m_disconnectCauseTranslated(0), m_releaseSource(-1),
	m_acctSessionId(Toolkit::Instance()->GenerateAcctSessionId()),
	m_callingSocket(NULL), m_calledSocket(NULL),
	m_usedCount(0), m_nattype(none),
#ifdef HAS_H46023
	m_natstrategy(e_natUnknown),
#endif
	m_unregNAT(false), m_h245Routed(RasServer::Instance()->IsH245Routed()),
	m_toParent(false), m_forwarded(false), m_proxyMode(proxyMode),
	m_callInProgress(false), m_h245ResponseReceived(false), m_fastStartResponseReceived(false),
	m_failoverActive(false), m_singleFailoverCDR(true), m_mediaOriginatingIp(GNUGK_INADDR_ANY), m_proceedingSent(false),
	m_clientAuthId(0), m_rerouteState(NoReroute), m_h46018ReverseSetup(false), m_callfromTraversalClient(false), m_callfromTraversalServer(false)
#ifdef HAS_H235_MEDIA
    ,m_encyptDir(none), m_dynamicPayloadTypeCounter(MIN_DYNAMIC_PAYLOAD_TYPE)
#endif
{
	const H225_AdmissionRequest& arq = arqPdu;

	if (arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
		m_destinationAddress = arq.m_destinationInfo;
		
	m_timer = m_acctUpdateTime = m_creationTime = time(NULL);
	m_callerId = m_calleeId = m_callerAddr = m_calleeAddr = " ";

	CallTable* const ctable = CallTable::Instance();
	m_timeout = ctable->GetSignalTimeout() / 1000;
	m_durationLimit = ctable->GetDefaultDurationLimit();
	m_failoverActive = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "ActivateFailover", "0"));
	m_singleFailoverCDR = ctable->SingleFailoverCDR();
	m_disabledcodecs = GkConfig()->GetString(CallTableSection, "DisabledCodecs", "");
	if (!m_disabledcodecs.IsEmpty() && m_disabledcodecs.Right(1) != ";")
		m_disabledcodecs += ";";

	m_irrFrequency = GkConfig()->GetInteger(CallTableSection, "IRRFrequency", 120);
	m_irrCheck = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "IRRCheck", "0"));
	m_irrCallerTimer = m_irrCalleeTimer = time(NULL);

	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "GenerateCallProceeding", "0")))
		m_proceedingSent = true;	// this was probably done before a CallRec existed
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
	m_disconnectTime(0), m_disconnectCause(0), m_disconnectCauseTranslated(0), m_releaseSource(-1),
	m_acctSessionId(Toolkit::Instance()->GenerateAcctSessionId()),
	m_callingSocket(NULL), m_calledSocket(NULL),
	m_usedCount(0), m_nattype(none),
#ifdef HAS_H46023
	m_natstrategy(e_natUnknown),
#endif
	m_unregNAT(false), m_h245Routed(routeH245),
	m_toParent(false), m_forwarded(false), m_proxyMode(proxyMode),
	m_callInProgress(false), m_h245ResponseReceived(false), m_fastStartResponseReceived(false),
	m_failoverActive(false), m_singleFailoverCDR(true), m_mediaOriginatingIp(GNUGK_INADDR_ANY), m_proceedingSent(false),
	m_clientAuthId(0), m_rerouteState(NoReroute), m_h46018ReverseSetup(false), m_callfromTraversalClient(false), m_callfromTraversalServer(false)
#ifdef HAS_H235_MEDIA
    ,m_encyptDir(none), m_dynamicPayloadTypeCounter(MIN_DYNAMIC_PAYLOAD_TYPE)
#endif
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
	m_failoverActive = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "ActivateFailover", "0"));
	m_singleFailoverCDR = ctable->SingleFailoverCDR();
	m_disabledcodecs = GkConfig()->GetString(CallTableSection, "DisabledCodecs", "") + ";";
	if (!m_disabledcodecs.IsEmpty() && m_disabledcodecs.Right(1) != ";")
		m_disabledcodecs += ";";

	m_irrFrequency = GkConfig()->GetInteger(CallTableSection, "IRRFrequency", 120);
	m_irrCheck = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "IRRCheck", "0"));
	m_irrCallerTimer = m_irrCalleeTimer = time(NULL);
	
	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "GenerateCallProceeding", "0")))
		m_proceedingSent = true;	// this was probably done before a CallRec existed
}

// a pretty empty CallRec, the rest is set when the Setup comes in (used with H.460.18 on SCI)
CallRec::CallRec(H225_CallIdentifier callID, H225_TransportAddress sigAdr)
  : m_CallNumber(0), m_callIdentifier(callID),
	m_crv(0),
	m_bandwidth(1280), m_setupTime(0), m_alertingTime(0), m_connectTime(0), 
	m_disconnectTime(0), m_disconnectCause(0), m_disconnectCauseTranslated(0), m_releaseSource(-1),
	m_acctSessionId(Toolkit::Instance()->GenerateAcctSessionId()),
	m_callingSocket(NULL), m_calledSocket(NULL), m_usedCount(0), m_nattype(none),
#if HAS_H46023
	m_natstrategy(e_natUnknown),
#endif
	m_unregNAT(false), m_h245Routed(true),
	m_toParent(false), m_forwarded(false), m_proxyMode(ProxyEnabled),
	m_callInProgress(false), m_h245ResponseReceived(false), m_fastStartResponseReceived(false),
	m_singleFailoverCDR(true), m_mediaOriginatingIp(GNUGK_INADDR_ANY), m_proceedingSent(false),
	m_h46018ReverseSetup(true), m_callfromTraversalClient(true), m_callfromTraversalServer(false)
#ifdef HAS_H235_MEDIA
    ,m_encyptDir(none), m_dynamicPayloadTypeCounter(MIN_DYNAMIC_PAYLOAD_TYPE)
#endif
{
}

CallRec::CallRec(
	CallRec *oldCall
	) : m_CallNumber(0), 
	m_callIdentifier(oldCall->m_callIdentifier),
	m_conferenceIdentifier(oldCall->m_conferenceIdentifier), 
	m_crv(oldCall->m_crv), m_Calling(oldCall->m_Calling),
	m_sourceAddress(oldCall->m_sourceAddress),
	m_destinationAddress(oldCall->m_destinationAddress),
	m_srcInfo(oldCall->m_srcInfo),
	m_destInfo(oldCall->m_destInfo), m_bandwidth(oldCall->m_bandwidth),
	m_callerAddr(oldCall->m_callerAddr), m_callerId(oldCall->m_callerId),
	m_inbound_rewrite_id(oldCall->m_inbound_rewrite_id),
	m_disabledcodecs(oldCall->m_disabledcodecs),
	m_setupTime(0), m_alertingTime(0), m_connectTime(0), m_disconnectTime(0),
	m_disconnectCause(0), m_disconnectCauseTranslated(0), m_releaseSource(-1),
	m_acctSessionId(Toolkit::Instance()->GenerateAcctSessionId()),
	m_srcSignalAddress(oldCall->m_srcSignalAddress),
	m_callingStationId(oldCall->m_callingStationId), m_calledStationId(oldCall->m_calledStationId),
	m_dialedNumber(oldCall->m_dialedNumber),
	m_callingSocket(NULL), m_calledSocket(NULL),
	m_usedCount(0), m_nattype(oldCall->m_nattype & ~calledParty), 
#if HAS_H46023
	m_natstrategy(e_natUnknown),
#endif
	m_unregNAT(oldCall->m_unregNAT), m_h245Routed(oldCall->m_h245Routed),
	m_toParent(false), m_forwarded(false), m_proxyMode(CallRec::ProxyDetect),
	m_failedRoutes(oldCall->m_failedRoutes), m_newRoutes(oldCall->m_newRoutes),
	m_callInProgress(false), m_h245ResponseReceived(false), m_fastStartResponseReceived(false),
	m_failoverActive(oldCall->m_failoverActive),
	m_singleFailoverCDR(oldCall->m_singleFailoverCDR), m_mediaOriginatingIp(GNUGK_INADDR_ANY), m_proceedingSent(oldCall->m_proceedingSent),
	m_clientAuthId(0), m_rerouteState(oldCall->m_rerouteState), m_h46018ReverseSetup(oldCall->m_h46018ReverseSetup),
	m_callfromTraversalClient(oldCall->m_callfromTraversalClient), m_callfromTraversalServer(oldCall->m_callfromTraversalServer)
#ifdef HAS_H235_MEDIA
    ,m_encyptDir(none), m_dynamicPayloadTypeCounter(MIN_DYNAMIC_PAYLOAD_TYPE)
#endif
{
	m_timer = m_acctUpdateTime = m_creationTime = time(NULL);
	m_calleeId = m_calleeAddr = " ";

	CallTable* const ctable = CallTable::Instance();
	m_timeout = ctable->GetSignalTimeout() / 1000;
	m_durationLimit = oldCall->m_durationLimit;

	m_irrFrequency = oldCall->m_irrFrequency;
	m_irrCheck = oldCall->m_irrCheck;
	m_irrCallerTimer = m_irrCalleeTimer = time(NULL);
	
	if (m_singleFailoverCDR) {
		m_setupTime = oldCall->m_setupTime;
		m_CallNumber = oldCall->m_CallNumber; // if we have 1 CDR, we need to preserve internal call number
	}
}

CallRec::~CallRec()
{
	PTRACE(3, "Gk\tDelete Call No. " << m_CallNumber);
#ifdef HAS_H46018
	RemoveKeepAllAlives();
#endif

	PWaitAndSignal lock(m_portListMutex);
	m_dynamicPorts.clear();
}
 
bool CallRec::CompareSigAdrIgnorePort(const H225_TransportAddress *adr) const
{
	H225_TransportAddress cmpAdr;
	if (!adr)
		return false;
	if ((adr->GetTag() != H225_TransportAddress::e_ipAddress)
		&& (adr->GetTag() != H225_TransportAddress::e_ip6Address))
		return false;
	cmpAdr = *adr;	// make a copy, we'll temporarily modify it
	if (m_Calling && (m_Calling->GetCallSignalAddress().GetTag() == H225_TransportAddress::e_ipAddress)) {
		// set same port on copy as on other adr
		((H225_TransportAddress_ipAddress &)cmpAdr).m_port = ((const H225_TransportAddress_ipAddress &)m_Calling->GetCallSignalAddress()).m_port;
		if (m_Calling->GetCallSignalAddress() == cmpAdr)
			return true;
	}
	if (m_Calling && (m_Calling->GetCallSignalAddress().GetTag() == H225_TransportAddress::e_ip6Address)) {
		// set same port on copy as on other adr
		((H225_TransportAddress_ip6Address &)cmpAdr).m_port = ((const H225_TransportAddress_ip6Address &)m_Calling->GetCallSignalAddress()).m_port;
		if (m_Calling->GetCallSignalAddress() == cmpAdr)
			return true;
	}
	if (m_Called && (m_Called->GetCallSignalAddress().GetTag() == H225_TransportAddress::e_ipAddress)) {
		// set same port on copy as on other adr
		((H225_TransportAddress_ipAddress &)cmpAdr).m_port = ((const H225_TransportAddress_ipAddress &)m_Called->GetCallSignalAddress()).m_port;
		if (m_Calling->GetCallSignalAddress() == cmpAdr)
			return true;
	}
	if (m_Called && (m_Called->GetCallSignalAddress().GetTag() == H225_TransportAddress::e_ip6Address)) {
		// set same port on copy as on other adr
		((H225_TransportAddress_ip6Address &)cmpAdr).m_port = ((const H225_TransportAddress_ip6Address &)m_Called->GetCallSignalAddress()).m_port;
		if (m_Calling->GetCallSignalAddress() == cmpAdr)
			return true;
	}
	return false;
}

int EndpointRec::GetTimeToLive() const
{
	bool enableTTLRestrictions = Toolkit::AsBool(GkConfig()->GetString("Gatekeeper::Main", "EnableTTLRestrictions", "1"));

	if (enableTTLRestrictions && (m_nat || IsTraversalClient() || UsesH46017())) {
		// force timeToLive to 5 - 30 sec, 19 sec if not set
		return m_timeToLive == 0 ? 19 : max(5, min(30, m_timeToLive));
	}
	return m_timeToLive;
}


void CallRec::SetProxyMode(
	int mode /// proxy mode flag (see #ProxyMode enum#)
	)
{
	if (m_proxyMode == ProxyDetect)
		if (mode == ProxyEnabled || mode == ProxyDisabled)
			m_proxyMode = mode;
}

H225_TransportAddress CallRec::GetSrcSignalAddr() const
{
	return m_srcSignalAddress;
}

bool CallRec::GetSrcSignalAddr(
	PIPSocket::Address& addr,
	WORD& port
	) const
{
	return GetIPAndPortFromTransportAddr(m_srcSignalAddress, addr, port);
}

H225_TransportAddress CallRec::GetDestSignalAddr() const
{
	return m_destSignalAddress;
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
	PIPSocket::Address & callingPartyNATIP, 
	/// filled with NAT IP of the called party (if nat type is calledParty)
	PIPSocket::Address & calledPartyNATIP
	) const
{
	if (m_nattype & callingParty) {
		if (m_unregNAT) {
			callingPartyNATIP = m_srcunregNATAddress;
		} else {
			if (m_Calling)
				callingPartyNATIP = m_Calling->GetNATIP();
		}
	}
	if (m_nattype & calledParty) {
		if (m_Called && m_Called->IsRemote()) {
			GetIPFromTransportAddr(m_Called->GetCallSignalAddress(), calledPartyNATIP);
		} else {
			if (m_Called)
				calledPartyNATIP = m_Called->GetNATIP();
		}
	}
 
	return m_nattype;
}

void CallRec::SetSrcSignalAddr(
	const H225_TransportAddress& addr
	)
{
	m_srcSignalAddress = addr;
	m_callerAddr = AsDotString(addr);
}

void CallRec::SetSrcNATed(const PIPSocket::Address & natip)
{
	m_unregNAT = true;
	m_srcunregNATAddress = natip;
	m_nattype = callingParty;
}

void CallRec::SetDestSignalAddr(
	const H225_TransportAddress& addr
	)
{
	m_destSignalAddress = addr;
	m_calleeAddr = AsDotString(addr);
}

void CallRec::SetCalling(const endptr & NewCalling)
{
	InternalSetEP(m_Calling, NewCalling);
	if (NewCalling) {
		if (NewCalling->IsNATed() || NewCalling->IsTraversalClient()) {
			m_nattype |= callingParty;
			m_h245Routed = true;
		}
		SetSrcSignalAddr(NewCalling->GetCallSignalAddress());
		m_callerId = NewCalling->GetEndpointIdentifier().GetValue();
	}
}

void CallRec::SetCalled(const endptr & NewCalled)
{
	InternalSetEP(m_Called, NewCalled);
	if (NewCalled) {
		if (NewCalled->IsNATed() || NewCalled->IsTraversalClient()) {
			m_nattype |= calledParty;
			m_h245Routed = true;
		}
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
	} // else TODO: how to solve billing issue if forwarder is not a registered party?

	if (!forwarder)
		m_srcInfo += "=" + forwarder;
	m_destInfo = altDestInfo;
	m_nattype &= ~calledParty;
	// TODO: how about m_registered and m_h245Routed ?
	m_usedLock.Signal();
	if (forwarded)
		SetCalled(forwarded);
	else
		SetDestSignalAddr(dest);
}

void CallRec::RerouteDropCalling()
{
	PWaitAndSignal lock(m_sockLock); 
	m_forwarded = true;
	m_Forwarder = m_Calling;
	m_callingSocket = NULL;
	CallTable::Instance()->UpdateEPBandwidth(m_Calling, -GetBandwidth());
	m_Calling = endptr(0);
}
 
void CallRec::RerouteDropCalled()
{
	PWaitAndSignal lock(m_sockLock); 
	m_forwarded = true;
	m_Forwarder = m_Called;
	m_calledSocket = NULL;
	CallTable::Instance()->UpdateEPBandwidth(m_Called, -GetBandwidth());
	m_Called = endptr(0);
}

// used for failover of GK terminated calls
bool CallRec::DropCalledAndTryNextRoute()
{
	PWaitAndSignal lock(m_sockLock);
	CallTable::Instance()->UpdateEPBandwidth(m_Called, -GetBandwidth());
	m_Called = endptr(0);
	if (m_calledSocket) {
		m_calledSocket->SendReleaseComplete(H225_ReleaseCompleteReason::e_undefinedReason);
		if (MoveToNextRoute()) {
			if (!DisableRetryChecks() && (IsFastStartResponseReceived() || IsH245ResponseReceived())) {
				PTRACE(5, "Q931\tFailover disabled for call " << GetCallNumber());
				return false;
			} else {
				PTRACE(5, "Q931\tTrying failover for call " << GetCallNumber());
				m_calledSocket->TryNextRoute();
				return true;
			}
		}
	}
	return false;
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
			calling->GetPeerAddress(addr, port);
			UnmapIPv4Address(addr);
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
			UnmapIPv4Address(addr);
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
	const time_t sec = (m_durationLimit && seconds) 
		? PMIN(m_durationLimit,seconds) : PMAX(m_durationLimit,seconds);
	m_durationLimit = sec;
	if (IsConnected())
		m_timeout = sec;
}

void CallRec::SetDisabledCodecs(const PString & codecs)
{
	m_disabledcodecs = codecs.Trim();
}

void CallRec::SetSRC_media_control_IP(const PString & IP)
{
    m_src_media_control_IP = IP;
}

void CallRec::SetDST_media_control_IP(const PString & IP)
{
    m_dst_media_control_IP = IP;
}

void CallRec::SetSRC_media_IP(const PString & IP)
{
    m_src_media_IP = IP;
}

void CallRec::SetDST_media_IP(const PString & IP)
{
    m_dst_media_IP = IP;
}

void CallRec::InitRTCP_report() {
	// audio values
    m_rtcp_source_packet_count = 0;
    m_rtcp_destination_packet_count = 0;
    m_rtcp_source_packet_lost = 0;
    m_rtcp_destination_packet_lost = 0;

    m_rtcp_source_jitter_max = 0;
    m_rtcp_source_jitter_min = 0;
    m_rtcp_source_jitter_avg = 0;
    m_rtcp_source_jitter_avg_count = 0;
    m_rtcp_source_jitter_avg_sum = 0;

    m_rtcp_destination_jitter_max = 0;
    m_rtcp_destination_jitter_min = 0;
    m_rtcp_destination_jitter_avg = 0;
    m_rtcp_destination_jitter_avg_count = 0;
    m_rtcp_destination_jitter_avg_sum = 0;

	// video values
    m_rtcp_source_video_packet_count = 0;
    m_rtcp_destination_video_packet_count = 0;
    m_rtcp_source_video_packet_lost = 0;
    m_rtcp_destination_video_packet_lost = 0;
 
    m_rtcp_source_video_jitter_max = 0;
    m_rtcp_source_video_jitter_min = 0;
    m_rtcp_source_video_jitter_avg = 0;
    m_rtcp_source_video_jitter_avg_count = 0;
    m_rtcp_source_video_jitter_avg_sum = 0;
 
    m_rtcp_destination_video_jitter_max = 0;
    m_rtcp_destination_video_jitter_min = 0;
    m_rtcp_destination_video_jitter_avg = 0;
    m_rtcp_destination_video_jitter_avg_count = 0;
    m_rtcp_destination_video_jitter_avg_sum = 0;
 
    m_src_media_IP = "0.0.0.0";
    m_dst_media_IP = "0.0.0.0";

    m_src_media_control_IP = "0.0.0.0";
    m_dst_media_control_IP = "0.0.0.0";
    
    m_rtcp_source_sdes_flag = false;
    m_rtcp_destination_sdes_flag = false;
}


void CallRec::SetRTCP_sdes(bool isSRC, const PString & val)
{
	if (isSRC) {
		SetRTCP_SRC_sdes(val);
	} else {
		SetRTCP_DST_sdes(val);
	}
}
 
void CallRec::SetRTCP_SRC_sdes(const PString & val)
{
    m_rtcp_source_sdes.AppendString(val);
    m_rtcp_source_sdes_flag = true;
}

void CallRec::SetRTCP_DST_sdes(const PString & val)
{    
    m_rtcp_destination_sdes.AppendString(val);
    m_rtcp_destination_sdes_flag = true;
}


void CallRec::SetRTCP_SRC_packet_count(long val)
{
    m_rtcp_source_packet_count = val;
}

void CallRec::SetRTCP_DST_packet_count(long val)
{
    m_rtcp_destination_packet_count = val;
}

void CallRec::SetRTCP_SRC_packet_lost(long val)
{
    m_rtcp_source_packet_lost = val;
}

void CallRec::SetRTCP_DST_packet_lost(long val)
{
    m_rtcp_destination_packet_lost = val;
}

void CallRec::SetRTCP_SRC_jitter(int val)
{	
    if (val > 0){
        if (m_rtcp_source_jitter_min == 0) {
			m_rtcp_source_jitter_min = val;
		} else if (m_rtcp_source_jitter_min > val) {
			 m_rtcp_source_jitter_min = val;
		}
		if (m_rtcp_source_jitter_max == 0) {
			m_rtcp_source_jitter_max = val;
		} else if (m_rtcp_source_jitter_max < val) {
			m_rtcp_source_jitter_max = val;
		}
		m_rtcp_source_jitter_avg_count++;
		m_rtcp_source_jitter_avg_sum += val;
		m_rtcp_source_jitter_avg = (int)(m_rtcp_source_jitter_avg_sum / m_rtcp_source_jitter_avg_count);
    } else {
		m_rtcp_source_jitter_avg = 0;
    }
}

void CallRec::SetRTCP_DST_jitter(int val)
{
    if (val > 0) {
        if (m_rtcp_destination_jitter_min == 0) {
			m_rtcp_destination_jitter_min = val;
		} else if (m_rtcp_destination_jitter_min > val) {
			m_rtcp_destination_jitter_min = val;
		}
		if (m_rtcp_destination_jitter_max == 0) {
			m_rtcp_destination_jitter_max = val;
		} else if (m_rtcp_destination_jitter_max < val) {
			m_rtcp_destination_jitter_max = val;
		}
		m_rtcp_destination_jitter_avg_count++;
		m_rtcp_destination_jitter_avg_sum += val;
		m_rtcp_destination_jitter_avg = (int)(m_rtcp_destination_jitter_avg_sum / m_rtcp_destination_jitter_avg_count);
    } else {
		m_rtcp_destination_jitter_avg = 0;
    }
}


void CallRec::SetRTCP_SRC_video_packet_count(long val)
{
    m_rtcp_source_video_packet_count = val;
}
 
void CallRec::SetRTCP_DST_video_packet_count(long val)
{
    m_rtcp_destination_video_packet_count = val;
}
 
void CallRec::SetRTCP_SRC_video_packet_lost(long val)
{
    m_rtcp_source_video_packet_lost = val;
}
 
void CallRec::SetRTCP_DST_video_packet_lost(long val)
{
    m_rtcp_destination_video_packet_lost = val;
}
 
void CallRec::SetRTCP_SRC_video_jitter(int val)
{	
    if (val > 0){
        if (m_rtcp_source_video_jitter_min == 0) {
			m_rtcp_source_video_jitter_min = val;
		} else if (m_rtcp_source_video_jitter_min > val) {
			 m_rtcp_source_video_jitter_min = val;
		}
		if (m_rtcp_source_video_jitter_max == 0) {
			m_rtcp_source_video_jitter_max = val;
		} else if (m_rtcp_source_video_jitter_max < val) {
			m_rtcp_source_video_jitter_max = val;
		}
		m_rtcp_source_video_jitter_avg_count++;
		m_rtcp_source_video_jitter_avg_sum += val;
		m_rtcp_source_video_jitter_avg = (int)(m_rtcp_source_video_jitter_avg_sum / m_rtcp_source_video_jitter_avg_count);
    } else {
		m_rtcp_source_video_jitter_avg = 0;
    }
}
 
void CallRec::SetRTCP_DST_video_jitter(int val)
{
    if (val > 0) {
        if (m_rtcp_destination_video_jitter_min == 0) {
			m_rtcp_destination_video_jitter_min = val;
		} else if (m_rtcp_destination_video_jitter_min > val) {
			m_rtcp_destination_video_jitter_min = val;
		}
		if (m_rtcp_destination_video_jitter_max == 0) {
			m_rtcp_destination_video_jitter_max = val;
		} else if (m_rtcp_destination_video_jitter_max < val) {
			m_rtcp_destination_video_jitter_max = val;
		}
		m_rtcp_destination_video_jitter_avg_count++;
		m_rtcp_destination_video_jitter_avg_sum += val;
		m_rtcp_destination_video_jitter_avg = (int)(m_rtcp_destination_video_jitter_avg_sum / m_rtcp_destination_video_jitter_avg_count);
    } else {
		m_rtcp_destination_video_jitter_avg = 0;
    }
}
 
 
void CallRec::InternalSetEP(endptr & ep, const endptr & nep)
{
	if (ep != nep) {
		if (ep)
			ep->RemoveCall(StripAliasType(GetDestInfo()));
		m_usedLock.Wait();
		ep = nep;
		m_usedLock.Signal();
		if (ep)
			ep->AddCall(StripAliasType(GetDestInfo()));
	}
}

void CallRec::RemoveAll()
{
	if (IsToParent())
		RasServer::Instance()->GetGkClient()->SendDRQ(callptr(this));
	if (m_Calling)
		m_Calling->RemoveCall(StripAliasType(GetDestInfo()));
	if (m_Called)
		m_Called->RemoveCall(StripAliasType(GetDestInfo()));
}

void CallRec::RemoveSocket()
{
	if (m_sockLock.WillBlock()) // locked by SendReleaseComplete()?
		return; // avoid deadlock

	PWaitAndSignal lock(m_sockLock);
	if (m_callingSocket) {
		if (!m_callingSocket->MaintainConnection())
			m_callingSocket->SetDeletable();
		m_callingSocket = NULL;
	}
	if (m_calledSocket) {
		if (!m_calledSocket->MaintainConnection())
			m_calledSocket->SetDeletable();
		m_calledSocket = NULL;
	}
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
	}
	if (m_calledSocket) {
		PTRACE(4, "Sending ReleaseComplete to called party ...");
		m_calledSocket->SendReleaseComplete(cause);
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

	// for an out of zone endpoint, the endpoint identifier is not correct
	if (m_Called) {
		drq.m_endpointIdentifier = m_Called->GetEndpointIdentifier();
#ifdef HAS_H46017
		if (m_Called->UsesH46017()) {
			CallSignalSocket * s = m_Called->GetSocket();
			if (s)
				s->SendH46017Message(drq_ras);
		} else
#endif
			RasSrv->SendRas(drq_ras, m_Called->GetRasAddress());
	}
	if (m_Calling) {
		drq.m_endpointIdentifier = m_Calling->GetEndpointIdentifier();
		drq.m_callReferenceValue = m_crv;
#ifdef HAS_H46017
		if (m_Calling->UsesH46017()) {
			CallSignalSocket * s = m_Calling->GetSocket();
			if (s)
				s->SendH46017Message(drq_ras);
		} else
#endif
			RasSrv->SendRas(drq_ras, m_Calling->GetRasAddress());
	}
}

PString CallRec::GenerateCDR(const PString& timestampFormat) const
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

	return PString("CDR|" + PString(m_CallNumber)
					+ "|" + AsString(m_callIdentifier.m_guid)
					+ "|" + timeString
					+ "|" + m_callerAddr
					+ "|" + m_callerId
					+ "|" + m_calleeAddr
					+ "|" + m_calleeId
					+ "|" + m_destInfo
					+ "|" + m_srcInfo
					+ "|" + toolkit->GKName()
					+ ";"
	);
}

PString CallRec::PrintOn(bool verbose) const
{
	const time_t timer = time(0) - m_timer;
	const time_t left = m_timeout > timer ? m_timeout - timer : 0;

    PString callid = AsString(m_callIdentifier.m_guid);
	callid.Replace(" ", "-", true);

	PString result = PString(PString::Printf,
		"Call No. %d | CallID %s | %ld | %ld\r\nDial %s\r\n",
		m_CallNumber, (const char *)AsString(m_callIdentifier.m_guid), (unsigned long)timer, (unsigned long)left,
		(const char *)m_destInfo)
		// 1st ACF
		+ "ACF|" + m_callerAddr
		+ "|" + m_callerId
		+ "|" + PString(m_crv)
		+ "|" + m_destInfo
		+ "|" + m_srcInfo
		+ "|false"
        + "|" + callid
        + ";\r\n"
		// 2nd ACF
		+ "ACF|" + m_calleeAddr
		+ "|" + m_calleeId
		+ "|" + PString(m_crv | 0x8000u)
		+ "|" + m_destInfo
		+ "|" + m_srcInfo
		+ "|true"
        + "|" + callid
        + ";\r\n";
	if (verbose) {
		result += "# " + ((m_Calling) ? AsString(m_Calling->GetAliases()) : m_callerAddr)
				+ "|" + ((m_Called) ? AsString(m_Called->GetAliases()) : m_calleeAddr)
				+ "|" + PString(m_bandwidth)
				+ "|" + (m_connectTime ? (const char *)PTime(m_connectTime).AsString() : "unconnected")
				+ " <" + PString(m_usedCount) + ">"
				+ " bw:" + PString(m_bandwidth)
				+ "\r\n";
	}

	return result;
}

PString CallRec::PrintPorts() const
{
	PString result = PString(PString::Printf,
		"Call No. %d | CallID %s | %ld | Dial %s\r\n",
		m_CallNumber, (const char *)AsString(m_callIdentifier.m_guid),
		(unsigned long)(time(0) - m_timer), (const char *)m_destInfo)
		+ m_callerAddr
		+ "|" + m_srcInfo
		+ "|" + m_calleeAddr
		+ "|" + m_destInfo
		+ "\r\n";
	for (list<DynamicPort>::const_iterator iter = m_dynamicPorts.begin(); iter != m_dynamicPorts.end(); ++iter) {
		switch (iter->m_type) {
			case H245Port: result += "  H.245 ";
				break;
			case RTPPort: result += "  RTP ";
				break;
			case T120Port: result += "  T.120 ";
				break;
			default: result += "  Other ";
		}
		result += AsString(iter->m_ip, iter->m_port) + "\r\n";
	}
	return result;
}

void CallRec::SetSetupTime(time_t tm)
{
	PWaitAndSignal lock(m_usedLock);
	if (m_setupTime == 0)
		m_setupTime = tm;
	if (m_connectTime == 0)
		m_timer = tm;
	// can be the case, because CallRec is usually created
	// after Setup message has been received
	if (m_creationTime > m_setupTime)
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
	// can be the case for direct signaling mode, 
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

time_t CallRec::GetPostDialDelay() const
{
	PWaitAndSignal lock(m_usedLock);
	const time_t startTime = (m_setupTime == 0
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

time_t CallRec::GetRingTime() const
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

time_t CallRec::GetTotalCallDuration() const
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

void CallRec::SetReleaseSource(int releaseSource)
{
	if (m_releaseSource == -1)
		m_releaseSource = releaseSource;
}

time_t CallRec::GetDuration() const
{
	PWaitAndSignal lock(m_usedLock);
	if( m_connectTime ) {
		if( m_disconnectTime )
			return (m_disconnectTime > m_connectTime) 
				? (m_disconnectTime - m_connectTime) : 1;
		else
			return (time(NULL) - m_connectTime);
	} else
		return 0;
}

PString CallRec::GetCallingStationId()
{
	PWaitAndSignal lock(m_usedLock);
	return m_callingStationId;
}

void CallRec::SetCallingStationId(const PString& id)
{
	PWaitAndSignal lock(m_usedLock);
	m_callingStationId = id;
}

PString CallRec::GetCalledStationId()
{
	PWaitAndSignal lock(m_usedLock);
	return m_calledStationId;
}

void CallRec::SetCalledStationId(const PString& id)
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
	if (m_dialedNumber.IsEmpty())
		m_dialedNumber = number;
}

void CallRec::Update(const H225_InfoRequestResponse & irr)
{
	if (irr.HasOptionalField(H225_InfoRequestResponse::e_perCallInfo)
		&& (irr.m_perCallInfo.GetSize() > 0)
		&& irr.m_perCallInfo[0].HasOptionalField(H225_InfoRequestResponse_perCallInfo_subtype::e_originator)) {
		if (irr.m_perCallInfo[0].m_originator)
			m_irrCallerTimer = time(NULL);
		else
			m_irrCalleeTimer = time(NULL);
	} else {
		if (m_Calling && irr.m_endpointIdentifier == m_Calling->GetEndpointIdentifier())
			m_irrCallerTimer = time(NULL);
		else
			m_irrCalleeTimer = time(NULL);
	}
}

void CallRec::ClearRoutes()
{
	m_newRoutes.clear();
}

void CallRec::SetNewRoutes(
	const std::list<Routing::Route> &routes
	)
{
	m_newRoutes = routes;
}

bool CallRec::MoveToNextRoute()
{
	if (! IsFailoverActive())
		return false;
		
	if (ShutdownMutex.WillBlock())
		return false;

	if (!m_newRoutes.empty()) {
		m_failedRoutes.push_back(m_newRoutes.front());
		m_newRoutes.pop_front();
	}
	
	while (!m_newRoutes.empty() && m_newRoutes.front().m_destEndpoint && !m_newRoutes.front().m_destEndpoint->HasAvailableCapacity(m_destinationAddress)) {
		PTRACE(5, "Capacity exceeded in GW " << AsDotString(m_newRoutes.front().m_destEndpoint->GetCallSignalAddress()));
		m_failedRoutes.push_back(m_newRoutes.front());
		m_newRoutes.pop_front();
	}

	return !m_newRoutes.empty();
}

bool CallRec::IsCallInProgress() const
{
	return m_callInProgress;
}

void CallRec::SetCallInProgress(bool val)
{
	m_callInProgress = val;
}

bool CallRec::IsH245ResponseReceived() const
{
	return m_h245ResponseReceived;
}

void CallRec::SetH245ResponseReceived()
{
	m_h245ResponseReceived = true;
}
	
bool CallRec::IsFastStartResponseReceived() const
{
	return m_fastStartResponseReceived;
}

void CallRec::SetFastStartResponseReceived()
{
	m_fastStartResponseReceived = true;
}

bool CallRec::SingleFailoverCDR() const
{
	return m_singleFailoverCDR;
}

int CallRec::GetNoCallAttempts() const
{
	int attempts = m_failedRoutes.size();
	if (!m_newRoutes.empty())
		attempts += 1;
	return attempts;
}

int CallRec::GetNoRemainingRoutes() const
{
	return m_newRoutes.size();
}

bool CallRec::DisableRetryChecks() const
{
	return Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "DisableRetryChecks", "0"));
}

void CallRec::SetCodec(const PString & codec)
{
	PWaitAndSignal lock(m_usedLock);
	m_codec = codec;
}

PString CallRec::GetCodec() const
{
	PWaitAndSignal lock(m_usedLock);
	return m_codec;
}

void CallRec::SetMediaOriginatingIp(const PIPSocket::Address & addr)
{
	PWaitAndSignal lock(m_usedLock);
	m_mediaOriginatingIp = addr;
}

bool CallRec::GetMediaOriginatingIp(PIPSocket::Address & addr) const
{
	PWaitAndSignal lock(m_usedLock);
	if (m_mediaOriginatingIp.IsValid()) {
		addr = m_mediaOriginatingIp;
		return true;
	} else
		return false;
}

bool CallRec::SingleGatekeeper() const
{
	if (!m_Calling || !m_Called)  // Default Single Gatekeeper TRUE!
		return true;

    if (!m_Calling->IsRemote() &&
		!m_Called->IsRemote())
		      return true;

	return false;
}

bool CallRec::GetRemoteInfo(PString & vendor, PString & version)
{
	if (!m_Called)
		return false;

	return m_Called->GetEndpointInfo(vendor,version);
}

#ifdef HAS_H46023

PString CallRec::GetNATOffloadString(NatStrategy type)
{
	static const char * const Names[10] = {
		"Unknown Strategy",
		"No Assistance",
		"Local Master",
		"Remote Master",
		"Local Proxy",
		"Remote Proxy",
		"Full Proxy",
		"AnnexA SameNAT",
		"AnnexB NAToffload",
		"NAT Failure"
	};

	if (type < 10)
		return Names[type];

	return PString((unsigned)type);
}

bool CallRec::NATAssistCallerUnknown(NatStrategy & natinst)
{
	if (m_Called) {
		PStringStream info;
		info << "Unknown Calling Endpoint\n";
		info << "Called Endpoint:\n";
		info << "    Support H.460.24 " << (m_Called->SupportH46024() ? "Yes" : "No") << "\n";
		info << "    NAT Type:    " << EndpointRec::GetEPNATTypeString((EndpointRec::EPNatTypes)m_Called->GetEPNATType()) << "\n";
		PTRACE(5,"RAS\t\n" << info);
		if (m_Called->SupportH46024() && (m_Called->GetEPNATType() < (int)EndpointRec::NatCone)) {
			PTRACE(4,"RAS\tSet strategy to no Assistance");
			natinst = CallRec::e_natNoassist;
			return true;
		} else if (m_Called->SupportH46024() && (m_Called->GetEPNATType() < (int)EndpointRec::NatSymmetric)) {
			PTRACE(5,"RAS\tSet strategy to Remote Master.");
			natinst = CallRec::e_natRemoteMaster;
			return true;
		} else {
			if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "H46024ForceDirect", "0"))) {
				PTRACE(4,"RAS\tForce Direct Assume remote supports NAT");
				natinst = CallRec::e_natNoassist;
				return true;
			} else {
				PTRACE(4,"RAS\tH.460.24 Startegy Unresolvable revert to proxy media");
			}
		}
	}
	natinst = CallRec::e_natUnknown;
	return false;
}

bool CallRec::NATOffLoad(bool iscalled, NatStrategy & natinst)
{
	// If calling is missing or H.460 is disabled don't continue.
	if (iscalled || !m_Calling)
	   return false;

	// If we don't have a called (usually means direct IP calling) and the calling supports H.460.24 and no NAT detected 
	// then allow call direct. If NAT is not symmetric then select remote master. This forces the Calling endpoint to 
	// use STUN and provide public IP addresses in the OLC. If Symmetric then media MUST be proxied unless H46024ForceDirect=1.
	if (!m_Called) {
		PStringStream info;
		info << "Called Endpoint not define:\n";
		info << "Calling Endpoint:\n";
		info << "    Support H.460.24 " << (m_Calling->SupportH46024() ? "Yes" : "No") << "\n";
		info << "    NAT Type:    " << EndpointRec::GetEPNATTypeString((EndpointRec::EPNatTypes)m_Calling->GetEPNATType()) << "\n";
		PTRACE(5,"RAS\t\n" << info);
		if (m_Calling->SupportH46024() && (m_Calling->GetEPNATType() < (int)EndpointRec::NatCone)) {
			PTRACE(4,"RAS\tSet strategy to no Assistance");
			natinst = CallRec::e_natNoassist;
			return true;
		} else if (m_Calling->SupportH46024() && (m_Calling->GetEPNATType() < (int)EndpointRec::NatSymmetric)) {
			PTRACE(5,"RAS\tSet strategy to Remote Master.");
			natinst = CallRec::e_natRemoteMaster;
			return true;
		} else {
			if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "H46024ForceDirect", "0"))) {
				PTRACE(4,"RAS\tForce Direct Assume remote supports NAT");
				natinst = CallRec::e_natNoassist;
				return true;
			} else {
				PTRACE(4,"RAS\tH.460.24 Startegy Unresolvable revert to proxy media");
				return false;
			}
		}
	}

	// If both the calling and called are on the same network segment (interface)
	// then we can attempt to go direct. If not we MUST Proxy media.
	bool goDirect = Toolkit::Instance()->H46023SameNetwork( 
				(m_Calling->IsNATed() ?  m_Calling->GetNATIP() : m_Calling->GetIP()),
				(m_Called->IsNATed() ?  m_Called->GetNATIP() : m_Called->GetIP()));

	// If we have the H46024ForceDirect switch then we can override the need to proxy.
	if (!goDirect && Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "H46024ForceDirect", "0"))) {
		PTRACE(4,"RAS\tH46024 Proxy Disabled. Force call to go direct");
		goDirect = true;
	}
 
	// Determine whether the calling and called support H.406.24
	bool callingSupport = (m_Calling->SupportH46024() || (m_Calling->IsNATed() && (m_Calling->GetEPNATType() > 0)));
	bool calledSupport = (m_Called->SupportH46024() || (m_Called->IsNATed() && (m_Called->GetEPNATType() > 0)));
	
	// Document the input calculations.
	PStringStream natinfo;
	natinfo << "NAT Offload (H460.23/.24) calculation inputs for Call No: " << GetCallNumber() << "\n" 
			<< " Rule : " << (goDirect ? "Go Direct (if possible)" : "Must Proxy Media");
	// Calling Endpoint
	natinfo << "\n  Calling Endpoint:\n";
	if (goDirect && m_Calling->IsNATed()) {
		natinfo << "    IsNATed:     Yes\n";
		natinfo << "    Detected IP: " << m_Calling->GetNATIP() << "\n";
		natinfo << "    NAT Type:    " << EndpointRec::GetEPNATTypeString((EndpointRec::EPNatTypes)m_Calling->GetEPNATType()) << "\n";
		natinfo << "    H.460.24 Annex B: " << (m_Calling->UseH46024B() ? "Yes" : "No");
	} else if (!goDirect) {
		natinfo << "    Proxy IP: " << m_Calling->GetIP() << "\n";
	} else {
		natinfo << "    IP: " << m_Calling->GetIP() << "\n";
		natinfo << "    Support H.460.24: " << (m_Calling->SupportH46024() ? "Yes" : "No");
	}
	// Called Endpoint
	natinfo << "\n  Called Endpoint:\n";
	if (goDirect && m_Called->IsNATed()) {
		natinfo << "    IsNATed:      Yes\n";
		natinfo << "    Detected IP: " << m_Called->GetNATIP() << "\n";
		natinfo << "    NAT Type:    " << EndpointRec::GetEPNATTypeString((EndpointRec::EPNatTypes)m_Called->GetEPNATType()) << "\n";
		natinfo << "    H.460.24 Annex B: " << (m_Called->UseH46024B() ? "Yes" : "No");
	} else if (!goDirect) {
		natinfo << "    Proxy IP: " << m_Called->GetIP() << "\n";
	} else {
		natinfo << "    IP: " << m_Called->GetIP() << "\n";
		natinfo << "    Support H.460.24: " << (m_Called->SupportH46024() ? "Yes" : "No");
	}

	PTRACE(5,"RAS\t\n" << natinfo);

	// If neither party supports H.460.24 then exit
	if (!callingSupport && !calledSupport) {
		PTRACE(4,"RAS\tDisable H.460.24 Offload as neither party supports it.");
		 return false;
	}
 
	// EP's are registered locally on different Networks and must proxy to reach eachother
	else if (!goDirect && !m_Calling->IsRemote() && !m_Called->IsRemote() && GetProxyMode() == CallRec::ProxyEnabled)
			natinst = CallRec::e_natFullProxy;

	// If both parties must proxy (ie if both on seperate distinct networks)
	else if (!goDirect && m_Called->IsInternal() && GetProxyMode() == CallRec::ProxyEnabled)
			natinst = CallRec::e_natFullProxy;

	// If the calling can proxy for NAT use it
	else if (!goDirect && GetProxyMode() != CallRec::ProxyDisabled)
			natinst = CallRec::e_natLocalProxy;

	// If can go direct and both are not NAT then no assistance required.
	else if (goDirect && (!m_Calling->IsNATed() && !m_Called->IsNATed()))
			natinst = CallRec::e_natNoassist;

	// If the called can proxy for NAT use it
	else if (goDirect && m_Called->IsInternal())
			natinst = CallRec::e_natRemoteProxy;
 
	// Same NAT (If both Parties are behind same detected NAT)
	else if ((m_Calling->IsNATed() && m_Called->IsNATed()          // both parties are NAT and
		&& (m_Calling->GetNATIP() == m_Called->GetNATIP()))) {	   // their NAT IP is the same

			if (m_Calling->SupportH46024A() && m_Called->SupportH46024A())  
		        natinst = CallRec::e_natAnnexA;
			else if (GetProxyMode() == CallRec::ProxyEnabled)		// If we have the ability to proxy
				natinst = CallRec::e_natFullProxy;
			else {
				natinst = CallRec::e_natFailure;
				m_natstrategy = natinst;
				PTRACE(2, "H46024\tFAILURE: No Annex A Support!");
				return false;
			}
	}
 
	// Both parties are NAT and both and are either restricted or port restricted NAT
	else if (goDirect && (m_Calling->UseH46024B() && m_Called->UseH46024B())) {
		if (SingleGatekeeper() || !Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "H46023SignalGKRouted", "0")))
				natinst = CallRec::e_natAnnexB;
		else if (m_Called->HasNATProxy())
			natinst = CallRec::e_natRemoteProxy;
		else {
			natinst = CallRec::e_natFailure;
			m_natstrategy = natinst;
			PTRACE(2, "H46024\tFAILURE: Signal Routed with no Remote Proxy!");
			return false;
		}
	}
    // if both devices are behind a symmetric firewall then perhaps are on the same internal network. 
    else if (goDirect && (m_Calling->GetEPNATType() == EndpointRec::FirewallSymmetric && 
			m_Called->GetEPNATType() == EndpointRec::FirewallSymmetric)) {
		if (!m_Calling->HasNATProxy() && !m_Called->HasNATProxy())
			natinst = CallRec::e_natNoassist;
		else if (m_Calling->SupportH46024A() && m_Called->SupportH46024A())  
			natinst = CallRec::e_natAnnexA;
		else
			natinst = CallRec::e_natFullProxy;
	}

	else if (goDirect && 
		(m_Calling->IsNATed() && m_Calling->GetEPNATType() > EndpointRec::NatCone) && 
		    (m_Called->IsNATed() && m_Called->GetEPNATType() > EndpointRec::NatCone) &&
			(!m_Calling->HasNATProxy() && (!m_Called->HasNATProxy()))) {
				natinst = CallRec::e_natFailure;
				m_natstrategy = natinst;
				PTRACE(2, "H46024\tFAILURE: No Annex B Support!" 
					<< " local: " << EndpointRec::GetEPNATTypeString((EndpointRec::EPNatTypes)m_Calling->GetEPNATType())
					<< " remote: " << EndpointRec::GetEPNATTypeString((EndpointRec::EPNatTypes)m_Called->GetEPNATType()));
				return false;
	}

	// if can go direct and calling supports Remote NAT and is not NAT or not symmetric
	else if (goDirect && 
		((!m_Calling->IsNATed() /*&& m_Calling->SupportH46024()*/) || (m_Calling->GetEPNATType() == EndpointRec::NatCone)))
			natinst = CallRec::e_natLocalMaster;  // Provide Assistance for Remote NAT
	else if (goDirect && 
		(!m_Called->IsNATed() && m_Calling->SupportH46024() && (m_Calling->GetEPNATType() < (int)EndpointRec::NatSymmetric)))
			natinst = CallRec::e_natRemoteMaster; 

	// if can go direct and called supports Remote NAT and is not NAT or not symmetric
	else if (goDirect && 
		((!m_Called->IsNATed() && m_Called->SupportH46024()) || (m_Called->GetEPNATType() < (int)EndpointRec::NatSymmetric)))
			natinst = CallRec::e_natRemoteMaster;

    else if (goDirect && m_Calling->IsNATed() && m_Calling->HasNATProxy())
			natinst = CallRec::e_natLocalProxy;
 
	else if (goDirect && m_Called->IsNATed() && m_Called->HasNATProxy())
			natinst = CallRec::e_natRemoteProxy;
 
	// if 1 of the EP's do not support H.460.24 then full proxy
	else if ((!callingSupport || !calledSupport) && GetProxyMode() == CallRec::ProxyEnabled)
			natinst = CallRec::e_natFullProxy;
 
	// Oops cannot proceed the media will Fail!!
	else {
		natinst = CallRec::e_natFailure;
		m_natstrategy = natinst;
		PTRACE(2, "H46024\tFAILURE: No resolvable routing policy!");
		return false;
	}

	m_natstrategy = natinst;
	return true;
}

bool CallRec::NATSignallingOffload(bool isAnswer) const
{
   return (!isAnswer  
	  && !Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "H46023SignalGKRouted", "0"))
	  && (m_natstrategy == e_natNoassist ||
		 (!(m_Called && m_Called->IsNATed()) && (m_natstrategy == e_natRemoteMaster ||  m_natstrategy == e_natLocalMaster)) ||
		 (!SingleGatekeeper() && m_natstrategy != e_natLocalProxy && m_natstrategy != e_natFullProxy)));
}
 
#ifdef HAS_H46024B
void CallRec::BuildH46024AnnexBMessage(bool initiate,H245_MultimediaSystemControlMessage & h245msg, const std::map<WORD,H46024Balternate> & alt)
{
	const char * H46024B_OID = "0.0.8.460.24.2";
	h245msg.SetTag(H245_MultimediaSystemControlMessage::e_request);
	H245_RequestMessage & msg = h245msg;
	msg.SetTag(H245_RequestMessage::e_genericRequest);
 
 	H245_GenericMessage & gmsg = msg;
	gmsg.IncludeOptionalField(H245_GenericMessage::e_subMessageIdentifier);
    gmsg.IncludeOptionalField(H245_GenericMessage::e_messageContent);
    H245_CapabilityIdentifier & id = gmsg.m_messageIdentifier;
	id.SetTag(H245_CapabilityIdentifier::e_standard);
	PASN_ObjectId & val = id;
	val.SetValue(H46024B_OID);
 
	PASN_Integer & num = gmsg.m_subMessageIdentifier;
	num = 1;
 
    gmsg.SetTag(H245_GenericMessage::e_messageContent);
    H245_ArrayOf_GenericParameter & content = gmsg.m_messageContent;
 
	content.SetSize(1);
	H245_GenericParameter & param = content[0];
	H245_ParameterIdentifier & idm = param.m_parameterIdentifier;
	idm.SetTag(H245_ParameterIdentifier::e_standard);
	PASN_Integer & idx = idm;
	idx = 1;
	param.m_parameterValue.SetTag(H245_ParameterValue::e_octetString);
	PASN_OctetString & oct = param.m_parameterValue;
 
 
	H46024B_ArrayOf_AlternateAddress addrs;
 
	std::map<WORD,H46024Balternate>::iterator i = m_H46024Balternate.begin();
	while (i != m_H46024Balternate.end()) {
		if (i->second.sent >= (initiate ? 1 : 2)) {
			i++;
			continue;
		}
		int sz = addrs.GetSize();
		addrs.SetSize(sz+1);
		H46024B_AlternateAddress addr;
		addr.m_sessionID = i->first;
		addr.IncludeOptionalField(H46024B_AlternateAddress::e_rtpAddress);
		if (initiate)
			addr.m_rtpAddress = i->second.forward;
		else
			addr.m_rtpAddress = i->second.reverse;

#if H323PLUS_VER > 1231
		if (initiate && i->second.multiplexID_fwd > 0) {
			addr.IncludeOptionalField(H46024B_AlternateAddress::e_multiplexID);
			addr.m_multiplexID = i->second.multiplexID_fwd;
		} else if (!initiate && i->second.multiplexID_rev > 0) {
			addr.IncludeOptionalField(H46024B_AlternateAddress::e_multiplexID);
			addr.m_multiplexID = i->second.multiplexID_rev;
		}
		i->second.sent = initiate ? 1 : 2;
#endif
		addrs[sz] = addr;
		i++;
	}
	PTRACE(6, "H46024B\tAlternateAddresses " << addrs);
	oct.EncodeSubType(addrs);
}
 
void SendH46024BFacility(CallSignalSocket *socket, const H245_MultimediaSystemControlMessage & h245msg)
{
	Q931 q931;
	socket->BuildFacilityPDU(q931, H225_FacilityReason::e_undefinedReason);
	H225_H323_UserInformation uuie;
	GetUUIE(q931, uuie);
	uuie.m_h323_uu_pdu.m_h245Tunneling = true;
	uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Control);
	PINDEX sz = uuie.m_h323_uu_pdu.m_h245Control.GetSize();
	uuie.m_h323_uu_pdu.m_h245Control.SetSize(sz+1);
	uuie.m_h323_uu_pdu.m_h245Control[sz].EncodeSubType(h245msg);

	SetUUIE(q931, uuie);
    PBYTEArray lBuffer;
	q931.Encode(lBuffer);
	socket->TransmitData(lBuffer);
}
 
CallSignalSocket * CallRec::H46024BSignalSocket(bool response)
{
	// If the calling party is symmetric then the probing
	// is done in reverse
	bool callerIsSymmetric = (m_Calling->GetEPNATType() > 5);
 
	if (!response)
		return (callerIsSymmetric ? GetCallSignalSocketCalled() :  GetCallSignalSocketCalling());
	else
		return (callerIsSymmetric ? GetCallSignalSocketCalling() : GetCallSignalSocketCalled());   
}
 
void CallRec::H46024BSessionFlag(WORD sessionID)
{
	list<int>::const_iterator p = find(m_h46024Bflag.begin(), m_h46024Bflag.end(), sessionID);
	if (p == m_h46024Bflag.end())
		m_h46024Bflag.push_back(sessionID);
}
 
void CallRec::H46024BInitiate(WORD sessionID, const H323TransportAddress & fwd, const H323TransportAddress & rev, unsigned muxID_fwd, unsigned muxID_rev)
{

	if (fwd.IsEmpty() || rev.IsEmpty()) {
		PTRACE(4,"H46024B\tSession " << sessionID << " NAT offload probe not ready");
		return;
	}

    if (m_h46024Bflag.empty())
		return;
 
	std::map<WORD,H46024Balternate>::const_iterator i = m_H46024Balternate.find(sessionID);
	if (i != m_H46024Balternate.end())
		return;
 
	PTRACE(5,"H46024B\tNAT offload probes S:" << sessionID << " F:" << fwd << " R:" << rev << " mux " << muxID_fwd << " " << muxID_rev);
    
    PIPSocket::Address addr;  rev.GetIpAddress(addr);
    bool revDir  = (GetCallSignalSocketCalled()->GetPeerAddr() == addr);
//PTRACE(1,"SH\tNAT offload probe " << GetCallSignalSocketCalled()->GetPeerAddr() << " " << addr << " " << revDir);
 
	H46024Balternate alt;
	bool callerIsSymmetric = (m_Calling->GetEPNATType() > 5);
	if (!callerIsSymmetric && !revDir) {
		fwd.SetPDU(alt.reverse);
		alt.multiplexID_fwd = muxID_rev;
		rev.SetPDU(alt.forward);
		alt.multiplexID_rev = muxID_fwd;
	} else {
		fwd.SetPDU(alt.forward);
		alt.multiplexID_fwd = muxID_fwd;
		rev.SetPDU(alt.reverse);
		alt.multiplexID_rev = muxID_rev;
	}
	alt.sent = 0;

	m_H46024Balternate.insert(pair<WORD,H46024Balternate>(sessionID,alt));
 
	if (m_h46024Bflag.size() == m_H46024Balternate.size()) {
		// Build the Generic Request
		H245_MultimediaSystemControlMessage h245msg;
		BuildH46024AnnexBMessage(true, h245msg, m_H46024Balternate);
 
		PTRACE(4,"H46024B\tRequest Message\n" << h245msg);
 
		// If we are tunnneling
		SendH46024BFacility(H46024BSignalSocket(false), h245msg);
	}
}
 
void CallRec::H46024BRespond()
{
	if (m_H46024Balternate.size() == 0)
		return;
 
	PTRACE(5,"H46024B\tNAT offload respond");
 
	// Build the Generic response
	H245_MultimediaSystemControlMessage h245msg;
	BuildH46024AnnexBMessage(false, h245msg, m_H46024Balternate);
	m_H46024Balternate.clear();
	m_h46024Bflag.clear();
 
	// If we are tunneling
	SendH46024BFacility(H46024BSignalSocket(true), h245msg);
 
}
#endif // HAS_H46024B
 
#endif  // HAS_H46023

PBYTEArray CallRec::GetRADIUSClass() const
{
	PWaitAndSignal lock(m_usedLock);
	return m_radiusClass;
}

void CallRec::AddDynamicPort(const DynamicPort & port)
{
	PWaitAndSignal lock(m_portListMutex);
	m_dynamicPorts.push_back(port);
}

void CallRec::RemoveDynamicPort(const DynamicPort & port)
{
	PWaitAndSignal lock(m_portListMutex);
	m_dynamicPorts.remove(port);
}

#ifdef HAS_H46018
bool CallRec::H46019Required() const
{
#ifdef HAS_H46023
	return ( (m_natstrategy != CallRec::e_natLocalMaster &&
			m_natstrategy != CallRec::e_natRemoteMaster &&
			m_natstrategy != CallRec::e_natNoassist)
			);
#else
	return true;
#endif
}

void CallRec::StoreSetup(SignalingMsg * msg)	// for H.460.18
{
	msg->Encode(m_processedSetup);
	m_processedSetup.MakeUnique();
}

PBYTEArray CallRec::RetrieveSetup() // for H.460.18
{
	PBYTEArray processedSetup(m_processedSetup);
	m_processedSetup.SetSize(0);	// delete stored Setup
	return processedSetup;
}

int CallRec::GetH46019Direction() const
{
	if (!H46019Required())
		return 0;

	int dir = 0;
	// TODO: check if this is still correct when acting as traversal client
	if (m_Calling && m_Calling->GetTraversalRole() != None)
			dir += H46019_CALLER;
	if (m_Called && m_Called->GetTraversalRole() != None)
			dir += H46019_CALLED;
	return dir;
}

void CallRec::AddRTPKeepAlive(unsigned flcn, const H323TransportAddress & keepAliveRTPAddr, unsigned keepAliveInterval, PUInt32b multiplexID)
{
	H46019KeepAlive ka;
	ka.type = RTP;
	ka.flcn = flcn;
	SetSockaddr(ka.dest, keepAliveRTPAddr);
	ka.interval = keepAliveInterval;
	ka.multiplexID = multiplexID;
	m_RTPkeepalives[flcn] = ka;
}

void CallRec::StartRTPKeepAlive(unsigned flcn, int RTPOSSocket)
{
	std::map<unsigned, H46019KeepAlive>::iterator iter = m_RTPkeepalives.find(flcn);
	// only start if it isn't running already
	if ((iter != m_RTPkeepalives.end()) && (iter->second.timer == GkTimerManager::INVALID_HANDLE)) {
		iter->second.ossocket = RTPOSSocket;
		PTime now;
		iter->second.timer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
				&(iter->second), &H46019KeepAlive::SendKeepAlive, now, iter->second.interval);	// do it now and every n seconds
	}
}

void CallRec::AddRTCPKeepAlive(unsigned flcn, const H245_UnicastAddress & keepAliveRTCPAddr, unsigned keepAliveInterval, PUInt32b multiplexID)
{
	H46019KeepAlive ka;
	ka.type = RTCP;
	ka.flcn = flcn;
	SetSockaddr(ka.dest, keepAliveRTCPAddr);
	ka.interval = keepAliveInterval;
	ka.multiplexID = multiplexID;
	m_RTCPkeepalives[flcn] = ka;
}

void CallRec::StartRTCPKeepAlive(unsigned flcn, int RTCPOSSocket)
{
	std::map<unsigned, H46019KeepAlive>::iterator iter = m_RTCPkeepalives.find(flcn);
	// only start if it isn't running already
	if ((iter != m_RTCPkeepalives.end()) && (iter->second.timer == GkTimerManager::INVALID_HANDLE)) {
		iter->second.ossocket = RTCPOSSocket;
		PTime now;
		iter->second.timer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
				&(iter->second), &H46019KeepAlive::SendKeepAlive, now, iter->second.interval);	// do it now and every n seconds
	}
}

void CallRec::RemoveKeepAlives(unsigned flcn)
{
	m_RTPkeepalives.erase(flcn);
	m_RTCPkeepalives.erase(flcn);
}

void CallRec::RemoveKeepAllAlives()
{
	m_RTPkeepalives.clear();
	m_RTCPkeepalives.clear();
}

void CallRec::SetSessionMultiplexDestination(WORD session, void * openedBy, bool isRTCP, const H323TransportAddress & toAddress, H46019Side side)
{
	// try to find LC for this session
	if (m_callingSocket && (m_callingSocket->GetH245Handler() == openedBy)) {
		m_callingSocket->SetSessionMultiplexDestination(session, isRTCP, toAddress, side);
	} else if (m_calledSocket && (m_calledSocket->GetH245Handler() == openedBy)) {
		m_calledSocket->SetSessionMultiplexDestination(session, isRTCP, toAddress, side);
	} else {
		PTRACE(1, "Error: Can't find LC for session " << session << " to set multiplex destination!");
		SNMP_TRAP(10, SNMPError, Network, "Can't find LC for multiplexed RTP session " + PString(PString::Unsigned, session));
	}
}
#endif

#ifdef HAS_H235_MEDIA
void CallRec::SetMediaEncryption(CallRec::EncDir dir) 
{
    m_encyptDir = dir;
}

BYTE CallRec::GetNewDynamicPayloadType()
{
	PWaitAndSignal lock(m_PTMutex);

	if (m_dynamicPayloadTypeCounter >= MAX_DYNAMIC_PAYLOAD_TYPE)
		m_dynamicPayloadTypeCounter = MIN_DYNAMIC_PAYLOAD_TYPE;

	return m_dynamicPayloadTypeCounter++;
}
#endif


/*
bool CallRec::IsTimeout(
	const time_t now,
	const long connectTimeout
	) const
{
	PWaitAndSignal lock(m_usedLock);

	// check timeout for signaling channel creation after ARQ->ACF
	// or for the call being connected in direct signaling mode
	if( connectTimeout > 0 && m_setupTime == 0 && m_connectTime == 0 )
		if( (now-m_creationTime)*1000 > connectTimeout ) {
			PTRACE(2,"Q931\tCall #"<<m_CallNumber<<" timed out waiting for its signaling channel to be opened");
			return true;
		} else
			return false;

	// is signaling channel present?
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
	m_CallNumber = 0;
	m_capacity = -1;
	m_minimumBandwidthPerCall = -1;
	m_maximumBandwidthPerCall = -1;
	ResetCallCounters();
	m_activeCall = 0;
	LoadConfig();
}

CallTable::~CallTable()
{
	ClearTable();
	DeleteObjectsInContainer(RemovedList);
}

void CallTable::SupplyEndpointQoS(std::map<PString, EPQoS> & epqos) const
{
	for (const_iterator Iter = CallList.begin(); Iter != CallList.end(); ++Iter) {
		CallRec *call = *Iter;
		if (call->IsConnected()) {
			endptr calling =  call->GetCallingParty();
			endptr called = call->GetCalledParty();
			if (calling) {
				std::map<PString, EPQoS>::iterator i = epqos.find(AsString(calling->GetAliases()));
				if (i != epqos.end()) {
					i->second.IncrementCalls();
					i->second.SetAudioPacketLossPercent(call->GetRTCP_SRC_packet_loss_percent());
					i->second.SetVideoPacketLossPercent(call->GetRTCP_SRC_video_packet_loss_percent());
					i->second.SetAudioJitter(call->GetRTCP_SRC_jitter_avg());
					i->second.SetVideoJitter(call->GetRTCP_SRC_video_jitter_avg());
				}
			}
			if (called) {
				std::map<PString, EPQoS>::iterator i = epqos.find(AsString(called->GetAliases()));
				if (i != epqos.end()) {
					i->second.IncrementCalls();
					i->second.SetAudioPacketLossPercent(call->GetRTCP_DST_packet_loss_percent());
					i->second.SetVideoPacketLossPercent(call->GetRTCP_DST_video_packet_loss_percent());
					i->second.SetAudioJitter(call->GetRTCP_DST_jitter_avg());
					i->second.SetVideoJitter(call->GetRTCP_DST_video_jitter_avg());
				}
			}
		}
	}
}
 
void CallTable::ResetCallCounters()
{
	m_CallCount = m_successCall = m_neighborCall = m_parentCall = 0;
}

void CallTable::LoadConfig()
{
	m_genNBCDR = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "GenerateNBCDR", "1"));
	m_genUCCDR = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "GenerateUCCDR", "0"));
	int GKCapacity = GkConfig()->GetInteger("TotalBandwidth", -1);
	if (GKCapacity == 0)
		GKCapacity = -1;	// turn bw management off when switch is set to 0
	SetTotalBandwidth(GKCapacity);	// will take into account ongoing calls
	m_minimumBandwidthPerCall = GkConfig()->GetInteger("MinimumBandwidthPerCall", -1);
	m_maximumBandwidthPerCall = GkConfig()->GetInteger("MaximumBandwidthPerCall", -1);
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
	m_singleFailoverCDR = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "SingleFailoverCDR", "1"));
}

void CallTable::Insert(CallRec * NewRec)
{
	WriteLock lock(listLock);
	if (NewRec->GetCallNumber() == 0) {
		NewRec->SetCallNumber(++m_CallNumber);
		++m_CallCount;
	}
	CallList.push_back(NewRec);
	++m_activeCall;
	NewRec->InitRTCP_report();
	PTRACE(2, "CallTable::Insert(CALL) Call No. " << NewRec->GetCallNumber() << ", total sessions : " << m_activeCall);
}

void CallTable::SetTotalBandwidth(long bw)
{
	if ((m_capacity = bw) >= 0) {
		long used = 0;
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

long CallTable::CheckTotalBandwidth(long bw) const
{
	if ((m_capacity < 0) || (m_capacity >= bw)) {
		return bw;
	}
	if (m_capacity > 0) {
		return m_capacity;
	}
	return 0;
}
void CallTable::UpdateTotalBandwidth(long bw)
{
	if (m_capacity >= 0) {
		m_capacity -= bw;
		if (m_capacity < 0)	{
			// shouldn't happen, just to make sure we can destinguish the disabled state
			m_capacity = 0;
		}
		PTRACE(2, "GK\tAvailable Bandwidth " << m_capacity);
	}
}
 
long CallTable::CheckEPBandwidth(const endptr & ep, long bw) const
{
	if (ep) {
		long epMax = ep->GetMaxBandwidth();
		if (epMax >= 0) {
			long epUsed = ep->GetBandwidth();
			if (epUsed >= epMax) {
				PTRACE(3, "EP " << ep->GetEndpointIdentifier().GetValue() << " bandwidth check: limit reached");
				return 0;
			} if (epUsed + bw <= epMax) {
				return bw;
			} else {
				PTRACE(3, "EP " << ep->GetEndpointIdentifier().GetValue() << " bandwidth check: partially granted bw=" << (epMax - epUsed));
				return (epMax - epUsed);
			}
		}
	}
	return bw;
}

void CallTable::UpdateEPBandwidth(const endptr & ep, long bw)
{
	if (ep) {
		ep->SetBandwidth(ep->GetBandwidth() + bw);
	}
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

callptr CallTable::FindBySignalAdrIgnorePort(const H225_TransportAddress & SignalAdr) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareSigAdrIgnorePort), &SignalAdr));
}
 
void CallTable::ClearTable()
{
	WriteLock lock(listLock);
	iterator Iter = CallList.begin();
	while (Iter != CallList.end()) {
		iterator i = Iter++;
		if (Toolkit::AsBool(GkConfig()->GetString("Gatekeeper::Main", "DisconnectCallsOnShutdown", "1"))) {
			(*i)->SetDisconnectCause(Q931::TemporaryFailure);
			(*i)->SetReleaseSource(CallRec::ReleasedByGatekeeper);
			(*i)->Disconnect();
		}
		InternalRemove(i);
		Iter = CallList.begin(); // reset invalidated iterator
	}
}

void CallTable::CheckCalls(RasServer * rassrv)
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
		if (((*call)->GetNoRemainingRoutes() == 0)
			|| (! (*call)->IsFailoverActive())
			|| (now - (*call)->GetSetupTime() > (GetSignalTimeout() / 1000) * 5)) {
			(*call)->Disconnect();	// sends ReleaseComplete to both parties
			RemoveCall((*call));
		} else {
			(*call)->SetCallInProgress(false);
			if (!(*call)->DropCalledAndTryNextRoute())
				(*call)->Disconnect();	// sends ReleaseComplete to both parties
		}
		call++;
	}

	call = m_callsToUpdate.begin();
	while (call != m_callsToUpdate.end()) {
		if ((*call)->IsConnected())
			rassrv->LogAcctEvent(GkAcctLogger::AcctUpdate, *call, now);
		call++;
	}
}

#ifdef HAS_H460

static PTextFile* OpenQoSFile(const PFilePath & fn)
{
	PTextFile* qosFile = new PTextFile(fn, PFile::ReadWrite, 
		PFile::Create | PFile::DenySharedWrite
		);
	if (!qosFile->IsOpen()) {
   	    PTRACE(1, "QoS\tCould not open log file "
			<< fn << "\" :" << qosFile->GetErrorText()
			);
		delete qosFile;
	    return NULL;
	}
	qosFile->SetPermissions(PFileInfo::UserRead | PFileInfo::UserWrite);
	qosFile->SetPosition(qosFile->GetLength());
	return qosFile;
}

void CallTable::OnQosMonitoringReport(const PString & conference, const endptr & ep, H4609_QosMonitoringReportData & qosdata)
{
	if (!Toolkit::AsBool(GkConfig()->GetString("GkQoSMonitor", "Enable", "0")))
		return;

	H4609_ArrayOf_RTCPMeasures report;

	if (qosdata.GetTag() == H4609_QosMonitoringReportData::e_periodic) {
        H4609_PeriodicQoSMonReport & rep = qosdata;
		H4609_ArrayOf_PerCallQoSReport & percall = rep.m_perCallInfo;
        report = percall[0].m_mediaChannelsQoS;
	} else if (qosdata.GetTag() == H4609_QosMonitoringReportData::e_final) {
        H4609_FinalQosMonReport & rep = qosdata;
        report = rep.m_mediaInfo;
	} 

	for (PINDEX i=0; i < report.GetSize(); i++) {
		// int worstdelay = -1; int packetlossrate = -1; int maxjitter = -1;
		int meandelay = -1; int packetslost = -1;
		int packetlosspercent = -1; int bandwidth = -1; int meanjitter = -1;
		H323TransportAddress sendAddr; H323TransportAddress recvAddr; PIPSocket::Address send; 
		WORD sport = 0; PIPSocket::Address recv; WORD rport = 0; int session = 0;

		H4609_RTCPMeasures & info = report[i];	
		session = info.m_sessionId;
		PTRACE(4,"QoS\tPreparing QoS Report Session " << session);

	    H225_TransportChannelInfo & rtp = info.m_rtpAddress;
	    if (rtp.HasOptionalField(H225_TransportChannelInfo::e_sendAddress))
		    sendAddr = H323TransportAddress(rtp.m_sendAddress);
	    if (rtp.HasOptionalField(H225_TransportChannelInfo::e_recvAddress)) 
		    recvAddr = H323TransportAddress(rtp.m_recvAddress);

		sendAddr.GetIpAndPort(send,sport);
		if (ep->IsNATed())   // Rewrite to External IP
			  send = ep->GetNATIP();
        recvAddr.GetIpAndPort(recv,rport);

		if (info.HasOptionalField(H4609_RTCPMeasures::e_mediaSenderMeasures)) {
			H4609_RTCPMeasures_mediaSenderMeasures & sender = info.m_mediaSenderMeasures;

//			if (sender.HasOptionalField(H4609_RTCPMeasures_mediaSenderMeasures::e_worstEstimatedEnd2EndDelay))
//				worstdelay = sender.m_worstEstimatedEnd2EndDelay;
			if (sender.HasOptionalField(H4609_RTCPMeasures_mediaSenderMeasures::e_meanEstimatedEnd2EndDelay))
				meandelay = sender.m_meanEstimatedEnd2EndDelay;
		}

		if (info.HasOptionalField(H4609_RTCPMeasures::e_mediaReceiverMeasures)) {
			H4609_RTCPMeasures_mediaReceiverMeasures & receiver = info.m_mediaReceiverMeasures;

			if (receiver.HasOptionalField(H4609_RTCPMeasures_mediaReceiverMeasures::e_cumulativeNumberOfPacketsLost))
				packetslost = receiver.m_cumulativeNumberOfPacketsLost;
//			if (receiver.HasOptionalField(H4609_RTCPMeasures_mediaReceiverMeasures::e_packetLostRate))
//				packetlossrate = receiver.m_packetLostRate;
//			if (receiver.HasOptionalField(H4609_RTCPMeasures_mediaReceiverMeasures::e_worstJitter))
//				maxjitter = receiver.m_worstJitter;
			if (receiver.HasOptionalField(H4609_RTCPMeasures_mediaReceiverMeasures::e_estimatedThroughput))
				bandwidth = receiver.m_estimatedThroughput;
			if (receiver.HasOptionalField(H4609_RTCPMeasures_mediaReceiverMeasures::e_fractionLostRate))
				packetlosspercent = receiver.m_fractionLostRate;
			if (receiver.HasOptionalField(H4609_RTCPMeasures_mediaReceiverMeasures::e_meanJitter))
				meanjitter = receiver.m_meanJitter;
		}

		// save report in call for status port/radius reporting
		callptr call = FindCallRec(StringToCallId(conference));
		if (call && ep) {
			if (call->GetCallingParty()
				&& call->GetCallingParty()->GetEndpointIdentifier() == ep->GetEndpointIdentifier()) {
				if ((session == RTP_Session::DefaultAudioSessionID)
					&& (packetslost >= 0) && (meanjitter >= 0)) {
					call->SetRTCP_SRC_packet_lost(packetslost);
					call->SetRTCP_SRC_jitter(meanjitter);
					PTRACE(5, "QoS\tSetRTCP_SRC_packet_lost:" << packetslost);
					PTRACE(5, "QoS\tSetRTCP_SRC_jitter:" << meanjitter);
				}
				if ((session == RTP_Session::DefaultVideoSessionID)
					&& (packetslost >= 0) && (meanjitter >= 0)) {
					call->SetRTCP_SRC_video_packet_lost(packetslost);
					call->SetRTCP_SRC_video_jitter(meanjitter);
					PTRACE(5, "QoS\tSetRTCP_SRC_video_packet_lost:" << packetslost);
					PTRACE(5, "QoS\tSetRTCP_SRC_video_jitter:" << meanjitter);
				}
			} else {
				if ((session == RTP_Session::DefaultAudioSessionID)
					&& (packetslost >= 0) && (meanjitter >= 0)) {
					call->SetRTCP_DST_packet_lost(packetslost);
					call->SetRTCP_DST_jitter(meanjitter);
					PTRACE(5, "QoS\tSetRTCP_DST_packet_lost:" << packetslost);
					PTRACE(5, "QoS\tSetRTCP_DST_jitter:" << meanjitter);
				}
				if ((session == RTP_Session::DefaultVideoSessionID)
					&& (packetslost >= 0) && (meanjitter >= 0)) {
					call->SetRTCP_DST_video_packet_lost(packetslost);
					call->SetRTCP_DST_video_jitter(meanjitter);
					PTRACE(5, "QoS\tSetRTCP_DST_video_packet_lost:" << packetslost);
					PTRACE(5, "QoS\tSetRTCP_DST_video_jitter:" << meanjitter);
				}
			}
		}
 
		// write report to database
#if HAS_DATABASE
		Toolkit* const toolkit = Toolkit::Instance();

		if (toolkit->QoS().Enabled()) {
			std::map<PString, PString> params;
			const time_t t = time(0);
			const PTime nowtime(t);

			params["g"] = toolkit->GKName();
			params["ConfId"] = conference;
			params["session"] = session;
			params["caller-ip"] = send.AsString();
			params["caller-port"] = sport;
			params["caller-nat"] = ep->IsNATed();

			params["callee-ip"] = recv.AsString();
			params["callee-port"] = rport;

			params["avgdelay"] = meandelay;
			params["packetloss"] = packetslost;
			params["packetloss-percent"] = packetlosspercent;
			params["avgjitter"] = meanjitter;
			params["bandwidth"] = bandwidth;
			params["t"] = nowtime.AsString();

			toolkit->QoS().PostRecord(params);
			//return;	// disabled: allow DB plus file to be active at same time
		}
#endif  // HAS_DATABASE

		// write report to file
		PString fn = GkConfig()->GetString("GkQoSMonitor", "DetailFile", "");
		bool fileoutput = !fn.IsEmpty();
		bool newfile = fileoutput ? !PFile::Exists(fn) : false;
 
		PTextFile* qosFile = NULL;
		if (fileoutput) {
			qosFile = OpenQoSFile(fn);
			if (qosFile && qosFile->IsOpen()) {
				if (newfile) {
				 PString headerstr = 
					 "time|confId|session|SendIP|SendPort|RecvIP|RecvPort|NAT|AvgDelay|PacketLost|PacketLoss%|AvgJitter|Bandwidth";
				 qosFile->WriteLine(headerstr);
				}
			} else {
                PTRACE(4,"QoS\tError opening QoS output file " << fn);
				SNMP_TRAP(6, SNMPError, General, "Error opening QoS output file " + fn);
			}
		}

	    const time_t eTime = time(0);
	    const PTime rectime(eTime);

		PString outstr = rectime.AsString()
						+ "|" + conference
						+ "|" + PString(session)
						+ "|" + send.AsString()
						+ "|" + PString(sport)
						+ "|" + recv.AsString()
						+ "|" + PString(rport)
						+ "|" + PString(ep->IsNATed())
						+ "|" + PString(meandelay)
						+ "|" + PString(packetslost)
						+ "|" + PString(packetlosspercent)
						+ "|" + PString(meanjitter)
						+ "|" + PString(bandwidth);

		PTRACE(4,"QoS\tQoS Report" << "\r\n" << outstr);

		if (qosFile && qosFile->IsOpen()) {
			if (!qosFile->WriteLine(outstr)) {
				PTRACE(4,"QoS\tError writing QoS information to file " << fn);
				SNMP_TRAP(6, SNMPError, General, "Error writing to QoS output file " + fn);
			} 
		   qosFile->Close();
		   delete qosFile;
		}
	}
}

void CallTable::QoSReport(const H225_InfoRequestResponse & /* obj_irr */, const callptr & call, const endptr & ep, const PASN_OctetString & rawstats)
{
	PPER_Stream argStream(rawstats);
    H4609_QosMonitoringReportData report;
	if (report.Decode(argStream) && report.GetTag() == H4609_QosMonitoringReportData::e_periodic) {
		PTRACE(5, "QoS\tReport " << report);
		OnQosMonitoringReport(AsString(call->GetCallIdentifier().m_guid), ep, report);
	} else {
		PTRACE(4, "QoS\tIRR Call Statistics decode failure");
	}
}

void CallTable::QoSReport(const H225_DisengageRequest & obj_drq, const endptr & ep, const PASN_OctetString & rawstats)
{
	PPER_Stream argStream(rawstats);
    H4609_QosMonitoringReportData report;
	if (report.Decode(argStream)
		&& ((report.GetTag() == H4609_QosMonitoringReportData::e_final) || (report.GetTag() == H4609_QosMonitoringReportData::e_periodic))) {
		PTRACE(5, "QoS\tReport " << report);
		OnQosMonitoringReport(AsString(obj_drq.m_conferenceID), ep, report);
	
	} else {
		PTRACE(4, "QoS\tDRQ Call Statistics decode failure");
	}
}
#endif

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

void CallTable::RemoveFailedLeg(const callptr & call)
{
	if (call) {
		CallRec *callrec = call.operator->();
		PTRACE(6, "GK\tRemoving callptr: " << AsString(call->GetCallIdentifier().m_guid));
		WriteLock lock(listLock);
		InternalRemoveFailedLeg(find(CallList.begin(), CallList.end(), callrec));
	}
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
	UpdateEPBandwidth(call->GetCallingParty(), - call->GetBandwidth());
	UpdateEPBandwidth(call->GetCalledParty(), - call->GetBandwidth());
	if (m_capacity >= 0)
		m_capacity += call->GetBandwidth();
		
	call->ClearRoutes();	// won't try any more routes for this call

	CallList.erase(Iter);
	RemovedList.push_back(call.operator->());

	WriteUnlock unlock(listLock);
	
	if ((m_genNBCDR || call->GetCallingParty()) && (m_genUCCDR || call->IsConnected())) {
		PString cdrString(call->GenerateCDR(m_timestampFormat) + "\r\n");
		GkStatus::Instance()->SignalStatus(cdrString, STATUS_TRACE_LEVEL_CDR);
		PTRACE(1, cdrString);
	} else {
		if (!call->IsConnected())
			PTRACE(2, "CDR\tignore not connected call");
		else	
			PTRACE(2, "CDR\tignore caller from neighbor");
	}

	RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctStop, call);

	call->RemoveAll();
	call->RemoveSocket();
}

void CallTable::InternalRemoveFailedLeg(iterator Iter)
{
	if (Iter == CallList.end()) {
		return;
	}

	callptr call(*Iter);
	call->SetDisconnectTime(time(NULL));

	--m_activeCall;
	
	if (m_capacity >= 0)
		m_capacity += call->GetBandwidth();

	CallList.erase(Iter);
	RemovedList.push_back(call.operator->());

	WriteUnlock unlock(listLock);

	if (call->SingleFailoverCDR() && !call->GetNewRoutes().empty())	{
		PTRACE(2, "CDR\tIgnoring failed call leg");
	} else {
		if ((m_genNBCDR || call->GetCallingParty()) && (m_genUCCDR || call->IsConnected())) {
			PString cdrString(call->GenerateCDR(m_timestampFormat) + "\r\n");
			GkStatus::Instance()->SignalStatus(cdrString, STATUS_TRACE_LEVEL_CDR);
			PTRACE(1, cdrString);
		} else {
			if (!call->IsConnected())
				PTRACE(2, "CDR\tignore not connected call");
			else	
				PTRACE(2, "CDR\tignore caller from neighbor");
		}

		RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctStop, call);
	}
	
	if (call->GetCalledParty())
		call->GetCalledParty()->RemoveCall(StripAliasType(call->GetDestInfo()));
	
	call->SetSocket(NULL, NULL);
}

void CallTable::InternalStatistics(unsigned & n, unsigned & act, unsigned & nb, unsigned & np, PString & msg, bool verbose) const
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

void CallTable::UpdatePrefixCapacityCounters()
{
	ReadLock lock(listLock);
	for (const_iterator Iter = CallList.begin(); Iter != CallList.end(); ++Iter) {
	CallRec *call = *Iter;
	endptr ep = call->GetCalledParty();
	if (ep)
		ep->UpdatePrefixStats(StripAliasType(call->GetDestInfo()), +1);
	}
}

void CallTable::PrintCurrentCalls(USocket *client, bool verbose) const
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

void CallTable::PrintCurrentCallsPorts(USocket *client) const
{
	PString msg = "CurrentCallsPorts\r\n";
	ReadLock lock(listLock);
	for (const_iterator Iter = CallList.begin(); Iter != CallList.end(); ++Iter) {
		msg += (*Iter)->PrintPorts();
	}
	msg += ";\r\n";
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

PreliminaryCallTable::PreliminaryCallTable() : Singleton<PreliminaryCallTable>("PreliminaryCallTable")
{
}

PreliminaryCallTable::~PreliminaryCallTable()
{
	calls.clear();
}
	
void PreliminaryCallTable::Insert(PreliminaryCall * call)
{
	WriteLock lock(tableLock);
	calls.insert( pair<H225_CallIdentifier, PreliminaryCall*>(call->GetCallIdentifier(), call));
}

void PreliminaryCallTable::Remove(H225_CallIdentifier id)
{
	WriteLock lock(tableLock);
	calls.erase(id);
}

PreliminaryCall * PreliminaryCallTable::Find(H225_CallIdentifier id) const
{
	WriteLock lock(tableLock);
	std::map<H225_CallIdentifier, PreliminaryCall*>::const_iterator iter = calls.find(id);
	return (iter != calls.end()) ? iter->second : NULL;
}
