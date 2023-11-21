//////////////////////////////////////////////////////////////////
//
// Routing Mechanism for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2003
// Copyright (c) 2004-2021, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "config.h"
#include <ptlib.h>
#include <ptclib/enum.h>
#include <h323pdu.h>
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "RasTbl.h"
#include "RasSrv.h"
#include "GkClient.h"
#include "GkStatus.h"
#include "sigmsg.h"
#include "Routing.h"
#include "gksql.h"
#include "gkauth.h" // for reusing GkAuthenticator::ReplaceAuthParams()

#ifdef HAS_H46023
  #include <h460/h4601.h>
#endif

#include <ptclib/http.h>

#ifdef HAS_LIBCURL
#include <curl/curl.h>
#endif // HAS_LIBCURL

using std::string;
using std::vector;
using std::list;
using std::stable_sort;
using std::binary_function;

namespace Routing {

const char *SectionName[] = {
	"RoutingPolicy::OnARQ",
	"RoutingPolicy::OnLRQ",
	"RoutingPolicy::OnSetup",
	"RoutingPolicy::OnFacility",
	"RoutingPolicy"
};

const unsigned DEFAULT_ROUTE_PRIORITY = 1;
const long DEFAULT_ROUTE_REQUEST_TIMEOUT = 10;
const char* const CTIsection = "CTI::Agents";

Route::Route() : m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_useTLS(false), m_priority(DEFAULT_ROUTE_PRIORITY)
{
	m_destAddr.SetTag(H225_TransportAddress::e_nonStandardAddress);	// set to an invalid address
	Toolkit::Instance()->SetRerouteCauses(m_rerouteCauses);
}

Route::Route(
	const PString & policyName,
	const endptr & destEndpoint,
	unsigned priority
	) : m_destAddr(destEndpoint ? destEndpoint->GetCallSignalAddress() : H225_TransportAddress()), m_destEndpoint(destEndpoint), m_policy(policyName),
	m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_useTLS(false), m_priority(priority)
{
	Toolkit::Instance()->SetRerouteCauses(m_rerouteCauses);
	if (!destEndpoint) {
		PTRACE(1, "Error: Route created with NULL endpoint!");
		SNMP_TRAP(7, SNMPWarning, General, "Route created with NULL endpoint");
	}
}

Route::Route(
	const PString & policyName,
	const H225_TransportAddress & destAddr,
	unsigned priority
	) : m_destAddr(destAddr), m_policy(policyName), m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_useTLS(false), m_priority(priority)
{
	Toolkit::Instance()->SetRerouteCauses(m_rerouteCauses);
}

Route::Route(
	const PString & policyName,
	const PIPSocket::Address & destIpAddr,
	WORD destPort,
	unsigned priority
	) : m_destAddr(SocketToH225TransportAddr(destIpAddr, destPort)),
	m_policy(policyName), m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_useTLS(false), m_priority(priority)
{
	Toolkit::Instance()->SetRerouteCauses(m_rerouteCauses);
}

PString Route::AsString() const
{
	return AsDotString(m_destAddr) + " (policy: " + m_policy + ", proxy: "
		+ PString(m_proxyMode) + ", flags: " + PString(m_flags) + ", Called-Station-Id: " + m_destNumber
		+ ", Called-Station-Id-Out: " + m_destOutNumber + ", priority: " + PString(m_priority) + ")";
}

bool Route::IsFailoverActive(
	unsigned cause
	) const
{
	cause = cause & 0x7f;
	return m_rerouteCauses[cause >> 3] & (1UL << (cause & 7));
}

bool Route::SetLanguages(const PStringList & local, const PStringList & remote)
{
	if (local.GetSize() == 0 && remote.GetSize() == 0)
		return true;

	for (PINDEX i = 0; i < local.GetSize(); ++i) {
		for (PINDEX j = 0; j < remote.GetSize(); ++j) {
			if (local[i] == remote[j])
				m_language.AppendString(local[i]);
		}
	}
	return (m_language.GetSize() > 0);
}


// class RoutingRequest
RoutingRequest::RoutingRequest()
	: m_reason(-1), m_flags(0), m_hasNewSetupAliases(false)
{
}

RoutingRequest::RoutingRequest(
	const std::list<Route> &failedRoutes
	)
	: m_reason(-1), m_flags(0), m_failedRoutes(failedRoutes), m_hasNewSetupAliases(false)
{
}

RoutingRequest::~RoutingRequest()
{
}

bool RoutingRequest::AddRoute(const Route & route)
{
	PIPSocket::Address addr;
	WORD port;
	if (!(route.m_destAddr.IsValid() && GetIPAndPortFromTransportAddr(route.m_destAddr, addr, port)
			&& addr.IsValid() && port != 0)) {
		PTRACE(1, "ROUTING\tInvalid destination address: " << AsString(route.m_destAddr));
		return false;
	}
	list<Route>::const_iterator i = m_failedRoutes.begin();
	while (i != m_failedRoutes.end()) {
		if (i->m_destAddr == route.m_destAddr && i->m_policy == route.m_policy
				&& i->m_routeId == route.m_routeId) {
			PTRACE(5, "ROUTING\tSkipping failed route " << route.AsString());
			return true;
		}
		++i;
	}
	m_routes.push_back(route);
	m_routes.sort();	// put routes in priority order
	return true;
}

bool RoutingRequest::GetFirstRoute(Route & route)
{
	if (m_routes.empty())
		return false;

	route = *m_routes.begin();
	return true;
}

void RoutingRequest::RemoveAllRoutes()
{
	m_routes.clear();
}

bool RoutingRequest::GetGatewayDestination(H225_TransportAddress & gw) const
{
	PIPSocket::Address addr;
	if (!GetIPFromTransportAddr(m_gwDestination, addr)||!addr.IsValid())
			return false;

	gw = m_gwDestination;
	return true;
}

bool RoutingRequest::SupportLanguages() const
{
#ifdef HAS_LANGUAGE
	return GkConfig()->GetBoolean("RasSrv::LRQFeatures", "EnableLanguageRouting", false);
#else
	return false;
#endif
}

// class AdmissionRequest
template<> H225_ArrayOf_AliasAddress *AdmissionRequest::GetAliases()
{
	return (m_request.HasOptionalField(H225_AdmissionRequest::e_destinationInfo) && m_request.m_destinationInfo.GetSize() > 0)
		? &m_request.m_destinationInfo : NULL;
}

template<> void AdmissionRequest::SetAliases(H225_ArrayOf_AliasAddress & aliases)
{
	m_request.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
	m_request.m_destinationInfo = aliases;
}

template<> const H225_TransportAddress *AdmissionRequest::GetDestIP() const
{
	return (m_request.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress))
		? &m_request.m_destCallSignalAddress : NULL;
}

// class LocationRequest
template<> H225_ArrayOf_AliasAddress *LocationRequest::GetAliases()
{
	return (m_request.m_destinationInfo.GetSize() > 0)
		? &m_request.m_destinationInfo : NULL;
}

template<> const H225_TransportAddress *LocationRequest::GetDestIP() const
{
	return NULL;	// TODO: check if one alias is transportID or h323ID that matches IP number ?
}

// class SetupRequest
template<> H225_ArrayOf_AliasAddress *SetupRequest::GetAliases()
{
	return (m_request.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) && m_request.m_destinationAddress.GetSize() > 0)
		? &m_request.m_destinationAddress : NULL;
}

template<> const H225_TransportAddress *SetupRequest::GetDestIP() const
{
	return (m_request.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress))
		? &m_request.m_destCallSignalAddress : NULL;
}

// class FacilityRequest
template<> H225_ArrayOf_AliasAddress *FacilityRequest::GetAliases()
{
	return (m_request.HasOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress) && m_request.m_alternativeAliasAddress.GetSize() > 0)
		? &m_request.m_alternativeAliasAddress : NULL;
}

template<> const H225_TransportAddress *FacilityRequest::GetDestIP() const
{
	return (m_request.HasOptionalField(H225_Facility_UUIE::e_alternativeAddress))
		? &m_request.m_alternativeAddress : NULL;
}

bool Policy::Handle(SetupRequest & request)
{
	if (IsActive()) {
		const PString tagname = request.GetWrapper()->GetTagName();
		const unsigned crv = request.GetWrapper()->GetCallReference();
		PTRACE(5, "ROUTING\tChecking policy " << m_name
			<< " for request " << tagname << " CRV=" << crv);
		if (OnRequest(request)) {
			PTRACE(5, "ROUTING\tPolicy " << m_name
				<< " applied to the request " << tagname << " CRV=" << crv);
			return true;
		}
	}
	return m_next && m_next->Handle(request);
}

bool Policy::Handle(FacilityRequest& request)
{
	if (IsActive()) {
		const PString tagname = request.GetWrapper()->GetTagName();
		const unsigned crv = request.GetWrapper()->GetCallReference();
		PTRACE(5, "ROUTING\tChecking policy " << m_name
			<< " for request " << tagname << " CRV=" << crv
			);
		if (OnRequest(request)) {
			PTRACE(5, "ROUTING\tPolicy " << m_name
				<< " applied to the request " << tagname << " CRV=" << crv);
			return true;
		}
	}
	return m_next && m_next->Handle(request);
}

void Policy::SetInstance(const PString & instance)
{
	PString policyName = PString(m_name);
	if (!instance.IsEmpty()) {
		m_instance = instance;
		policyName = policyName + "::" + m_instance;
		m_name = *(PString *)policyName.Clone();
	}
	m_iniSection = "Routing::" + policyName;

	LoadConfig(instance);
}


// class Analyzer
Analyzer::Analyzer() : Singleton<Analyzer>("Routing::Analyzer")
{
	// OnReload is called by holder
}

Analyzer::~Analyzer()
{
	WriteLock lock(m_reloadMutex);
	for (int i = 0; i < 4; ++i)
		DeleteObjectsInMap(m_rules[i]);
}

void Analyzer::OnReload()
{
	WriteLock lock(m_reloadMutex);

	for (int i = 0; i < 4; ++i) {
		Rules & rules = m_rules[i];

		DeleteObjectsInMap(rules);
		rules.clear();

		PStringToString cfgs(GkConfig()->GetAllKeyValues(SectionName[i]));
		if (cfgs.GetSize() == 0) // no such a section? try default
			cfgs = GkConfig()->GetAllKeyValues(SectionName[4]);

		for (PINDEX j = 0; j < cfgs.GetSize(); ++j) {
			PString prefix = cfgs.GetKeyAt(j);
			if (prefix *= "default")
				prefix = "*";
			PStringArray prefixes(prefix.Tokenise(",;|", false));
			for (PINDEX k = 0; k < prefixes.GetSize(); ++k)
				rules[prefixes[k]] = Create(cfgs.GetDataAt(j).Trim());
			PTRACE(1, SectionName[i] << " add policy " << cfgs.GetDataAt(j) << " for prefix " << prefix);
		}
		// default policy for backward compatibility
		if (rules.empty())
			rules["*"] = Create("explicit,internal,parent,neighbor");
	}
}

bool Analyzer::Parse(AdmissionRequest & request)
{
	ReadLock lock(m_reloadMutex);
	request.SetRejectReason(H225_AdmissionRejectReason::e_calledPartyNotRegistered);
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[0]);
	bool policyApplied = policy ? policy->HandleRas(request) : false;
	if (!policyApplied && request.HasRoutes()) {
		Route fallback;
		request.GetFirstRoute(fallback);
		const char * tagname = request.GetWrapper()
			? request.GetWrapper()->GetTagName() : "unknown";
		const unsigned seqnum = request.GetRequest().m_requestSeqNum.GetValue();
		PTRACE(5, "ROUTING\t" << fallback.m_policy
					<< " applied as fallback to the request " << tagname << ' ' << seqnum);
	}
	return policyApplied || request.HasRoutes();
}

bool Analyzer::Parse(LocationRequest & request)
{
	ReadLock lock(m_reloadMutex);
	request.SetRejectReason(H225_LocationRejectReason::e_requestDenied);
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[1]);
	bool policyApplied = policy ? policy->HandleRas(request) : false;
	if (!policyApplied && request.HasRoutes()) {
		Route fallback;
		request.GetFirstRoute(fallback);
		const char * tagname = request.GetWrapper()
			? request.GetWrapper()->GetTagName() : "unknown";
		const unsigned seqnum = request.GetRequest().m_requestSeqNum.GetValue();
		PTRACE(5, "ROUTING\t" << fallback.m_policy
					<< " applied as fallback to the request " << tagname << ' ' << seqnum);
	}
	return policyApplied || request.HasRoutes();
}

bool Analyzer::Parse(SetupRequest & request)
{
	ReadLock lock(m_reloadMutex);
	request.SetRejectReason(H225_ReleaseCompleteReason::e_calledPartyNotRegistered);
	Policy * policy = ChoosePolicy(request.GetAliases(), m_rules[2]);
	bool policyApplied = policy ? policy->Handle(request) : false;
	if (!policyApplied && request.HasRoutes()) {
		Route fallback;
		request.GetFirstRoute(fallback);
		const PString tagname = request.GetWrapper()->GetTagName();
		const unsigned crv = request.GetWrapper()->GetCallReference();
		PTRACE(5, "ROUTING\t" << fallback.m_policy
					<< " applied as fallback to the request " << tagname << " CRV=" << crv);
	}
	return policyApplied || request.HasRoutes();
}

bool Analyzer::Parse(FacilityRequest & request)
{
	ReadLock lock(m_reloadMutex);
	request.SetRejectReason(H225_ReleaseCompleteReason::e_calledPartyNotRegistered);
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[3]);
	bool policyApplied = policy ? policy->Handle(request) : false;
	if (!policyApplied && request.HasRoutes()) {
		Route fallback;
		request.GetFirstRoute(fallback);
		const PString tagname = request.GetWrapper()->GetTagName();
		const unsigned crv = request.GetWrapper()->GetCallReference();
		PTRACE(5, "ROUTING\t" << fallback.m_policy
					<< " applied as fallback to the request " << tagname << " CRV=" << crv);
	}
	return policyApplied || request.HasRoutes();
}

Policy *Analyzer::Create(const PString & cfg)
{
	return Policy::Create(cfg.ToLower().Tokenise(",;|", false));
}

Policy *Analyzer::ChoosePolicy(const H225_ArrayOf_AliasAddress *aliases, Rules & rules)
{
	// safeguard if we don't have any rules (eg. not yet initialized on startup)
	if (rules.empty())
		return NULL;

	// use rules.begin() as the default policy
	// since "*" has the minimum key value
	Rules::iterator iter = rules.begin();
	if (aliases && aliases->GetSize() > 0) {
		for (PINDEX i = 0; i < aliases->GetSize(); ++i) {
			const H225_AliasAddress & alias = (*aliases)[i];
			iter = rules.find(alias.GetTagName());
			if (iter != rules.end())
				break;
			PString destination(AsString(alias, false));
			while (iter != rules.begin()) {
				--iter; // search in reverse order
				if (MatchPrefix(destination, iter->first) > 0)
					return iter->second;
			}
		}
	}
	return iter->second;
}


// class AliasesPolicy
bool AliasesPolicy::OnRequest(AdmissionRequest & request)
{
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	return aliases && FindByAliases(request, *aliases);
}

bool AliasesPolicy::OnRequest(LocationRequest & request)
{
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	return aliases && FindByAliases(request, *aliases);
}

bool AliasesPolicy::OnRequest(SetupRequest & request)
{
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	return aliases && FindByAliases(request, *aliases);
}

bool AliasesPolicy::OnRequest(FacilityRequest & request)
{
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	return aliases && FindByAliases(request, *aliases);
}


std::map<PString, PString> ExplicitPolicy::m_destMap;

ExplicitPolicy::ExplicitPolicy()
{
	m_name = "Explicit";
	m_iniSection = "Routing::Explicit";
}

void ExplicitPolicy::OnReload()
{
	m_destMap.clear();
	PStringToString mappings(GkConfig()->GetAllKeyValues("Routing::Explicit"));
	for (PINDEX i = 0; i < mappings.GetSize(); ++i) {
		PString src = mappings.GetKeyAt(i);
		PString dest = mappings.GetDataAt(i);
		H225_TransportAddress srcAddr;
		if (GetTransportAddress(src, GK_DEF_ENDPOINT_SIGNAL_PORT, srcAddr)) {
			if (!dest.IsEmpty()) {
				if (IsIPAddress(dest)) {
					// test parse IP, but store again as string
					H225_TransportAddress destAddr;
					if (GetTransportAddress(dest, GK_DEF_ENDPOINT_SIGNAL_PORT, destAddr)) {
						m_destMap[AsDotString(srcAddr, false)] = AsDotString(destAddr, false);
					} else {
						PTRACE(1, "Error parsing dest entry in [Routing::Explicit]: " << src << "=" << dest);
						SNMP_TRAP(7, SNMPError, Configuration, "Invalid [Routing::Explicit] configuration");
					}
				} else {
					// store anything else as string, will be used as alias
					m_destMap[AsDotString(srcAddr, false)] = dest;
				}
			} else {
				PTRACE(1, "Error: Empty dest entry in [Routing::Explicit]: " << src << "=");
				SNMP_TRAP(7, SNMPError, Configuration, "Invalid [Routing::Explicit] configuration");
			}
		} else {
			PTRACE(1, "Error parsing src entry in [Routing::Explicit]: " << src << "=" << dest);
			SNMP_TRAP(7, SNMPError, Configuration, "Invalid [Routing::Explicit] configuration");
		}
	}
}

void ExplicitPolicy::MapDestination(H225_AdmissionRequest & arq)
{
	H225_TransportAddress & addr = arq.m_destCallSignalAddress;
	PString orig = AsDotString(addr, false);	// original IP without port
	std::map<PString, PString>::const_iterator i = m_destMap.find(orig);
	if (i != m_destMap.end()) {
		PString newDest = i->second;
		if (IsIPAddress(newDest)) {
			// just rewrite the IP
			H225_TransportAddress destAddr;
			GetTransportAddress(newDest, GK_DEF_ENDPOINT_SIGNAL_PORT, destAddr); // ignore result, we have parsed these before
			addr = destAddr;
		} else {
			// delete IP and set a new destination alias
			arq.RemoveOptionalField(H225_AdmissionRequest::e_destCallSignalAddress);
			arq.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
			arq.m_destinationInfo.SetSize(1);
			H323SetAliasAddress(newDest, arq.m_destinationInfo[0]);
		}
		PTRACE(4, "[Routing::Explicit]: map destination " << orig << " to " << newDest);
	}
}

void ExplicitPolicy::MapDestination(H225_Setup_UUIE & setupBody)
{
	H225_TransportAddress & addr = setupBody.m_destCallSignalAddress;
	PString orig = AsDotString(addr, false);	// original IP without port
	std::map<PString, PString>::const_iterator i = m_destMap.find(orig);
	if (i != m_destMap.end()) {
		PString newDest = i->second;
		if (IsIPAddress(newDest)) {
			// just rewrite the IP
			H225_TransportAddress destAddr;
			GetTransportAddress(newDest, GK_DEF_ENDPOINT_SIGNAL_PORT, destAddr); // ignore result, we have parsed these before
			addr = destAddr;
		} else {
			// delete IP and set a new destination alias
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setupBody.m_destinationAddress.SetSize(1);
			H323SetAliasAddress(newDest, setupBody.m_destinationAddress[0]);
		}
		PTRACE(4, "[Routing::Explicit]: map destination " << orig << " to " << newDest);
	}
}

void ExplicitPolicy::MapDestination(H225_Facility_UUIE & facilityBody)
{
	H225_TransportAddress & addr = facilityBody.m_alternativeAddress;
	PString orig = AsDotString(addr, false);	// original IP without port
	std::map<PString, PString>::const_iterator i = m_destMap.find(orig);
	if (i != m_destMap.end()) {
		PString newDest = i->second;
		if (IsIPAddress(newDest)) {
			// just rewrite the IP
			H225_TransportAddress destAddr;
			GetTransportAddress(newDest, GK_DEF_ENDPOINT_SIGNAL_PORT, destAddr); // ignore result, we have parsed these before
			addr = destAddr;
		} else {
			// delete IP and set a new destination alias
			facilityBody.RemoveOptionalField(H225_Facility_UUIE::e_alternativeAddress);
			facilityBody.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress);
			facilityBody.m_alternativeAliasAddress.SetSize(1);
			H323SetAliasAddress(newDest, facilityBody.m_alternativeAliasAddress[0]);
		}
		PTRACE(4, "[Routing::Explicit]: map destination " << orig << " to " << newDest);
	}
}

bool ExplicitPolicy::OnRequest(AdmissionRequest & request)
{
	H225_AdmissionRequest & arq = request.GetRequest();
	if (arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
		MapDestination(arq);
		// check if the mapping removed the destination IP
		if (!arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress))
			return false;
		// TODO: also check if one of the aliases is a transport-ID ?
		Route route(m_name, arq.m_destCallSignalAddress);
		route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
#ifdef HAS_H46023
        if (!route.m_destEndpoint &&
           arq.HasOptionalField(H225_AdmissionRequest::e_genericData) &&
           H460_FeatureSet(arq.m_genericData).HasFeature(24)) {
	         H225_RasMessage ras;
             ras.SetTag(H225_RasMessage::e_admissionRequest);
			 H225_AdmissionRequest & req = (H225_AdmissionRequest &)ras;
			 req = arq;
		   route.m_destEndpoint = RegistrationTable::Instance()->InsertRec(ras);
        }
#endif
		return request.AddRoute(route);
	}
	return false;
}

bool ExplicitPolicy::OnRequest(SetupRequest & request)
{
	H225_Setup_UUIE & setup = request.GetRequest();
	if (setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
		// don't map IP here, for Setup already done in OnSetup()
		Route route(m_name, setup.m_destCallSignalAddress);
		route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
		return request.AddRoute(route);
	}
	// TODO: also check if one of the aliases is a transport-ID ?
	return false;
}

bool ExplicitPolicy::OnRequest(FacilityRequest & request)
{
	H225_Facility_UUIE & facility = request.GetRequest();
	if (facility.HasOptionalField(H225_Facility_UUIE::e_alternativeAddress)) {
		MapDestination(facility);
		// check if the mapping removed the destination IP
		if (!facility.HasOptionalField(H225_Facility_UUIE::e_alternativeAddress))
			return false;
		Route route(m_name, facility.m_alternativeAddress);
		route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
		return request.AddRoute(route);
	}
	// TODO: also check if one of the aliases is a transport-ID ?
	return false;
}


InternalPolicy::InternalPolicy()
	: roundRobin(Toolkit::AsBool(GkConfig()->GetString("RasSrv::ARQFeatures", "RoundRobinGateways", "1"))),
	  leastUsedRouting(GkConfig()->GetBoolean("RasSrv::ARQFeatures", "LeastUsedRouting", false))
{
	m_name = "Internal";
    if (roundRobin && leastUsedRouting) {
        PTRACE(1, "ERROR: RoundRobinGateways and LeastUsedRouting are logically incompatible, round-robin disabled");
        roundRobin = false;
    }
}

bool InternalPolicy::OnRequest(AdmissionRequest & request)
{
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	if (aliases == NULL || !FindByAliases(request, *aliases))
		return false;

	return true;
}

bool InternalPolicy::OnRequest(SetupRequest & request)
{
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	if (aliases == NULL || !FindByAliases(request, *aliases))
		return false;

	return true;
}

bool InternalPolicy::FindByAliases(RoutingRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	list<Route> routes;
	RegistrationTable::Instance()->FindEndpoint(aliases, roundRobin, leastUsedRouting, true, routes);
	list<Route>::iterator i = routes.begin();
	while (i != routes.end()) {
		i->m_policy = m_name;
		request.AddRoute(*i++);
	}
	return !routes.empty();
}

bool InternalPolicy::FindByAliases(LocationRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	// do not apply round robin selection for Location ReQuests
	list<Route> routes;
	if (RegistrationTable::Instance()->FindEndpoint(aliases, false, false, true, routes))
		request.SetRejectReason(H225_LocationRejectReason::e_resourceUnavailable);

	list<Route>::iterator i = routes.begin();
	while (i != routes.end()) {
		i->m_policy = m_name;
		request.AddRoute(*i++);
	}
	return !routes.empty();
}

bool InternalPolicy::FindByAliases(SetupRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	list<Route> routes;
	if (RegistrationTable::Instance()->FindEndpoint(aliases, roundRobin, leastUsedRouting, true, routes))
		request.SetRejectReason(H225_ReleaseCompleteReason::e_gatewayResources);

	list<Route>::iterator i = routes.begin();
	while (i != routes.end()) {
		i->m_policy = m_name;
		request.AddRoute(*i++);
	}
	return !routes.empty();
}

bool InternalPolicy::FindByAliases(AdmissionRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	list<Route> routes;
	if (RegistrationTable::Instance()->FindEndpoint(aliases, roundRobin, leastUsedRouting, true, routes))
		request.SetRejectReason(H225_AdmissionRejectReason::e_resourceUnavailable);

	endptr ep;
	if (request.SupportLanguages())
		ep = RegistrationTable::Instance()->FindByEndpointId(request.GetRequest().m_endpointIdentifier);

	list<Route>::iterator i = routes.begin();
	while (i != routes.end()) {
		if (ep && i->m_destEndpoint && !i->SetLanguages(i->m_destEndpoint->GetLanguages(), ep->GetLanguages())) {
			PTRACE(4, m_name << "\tRoute found but rejected as no common language");
			++i;
		} else {
			i->m_policy = m_name;
			request.AddRoute(*i++);
		}
	}
	return !routes.empty();
}


ParentPolicy::ParentPolicy()
{
	m_gkClient = RasServer::Instance()->GetGkClient();
	m_name = "Parent";
}

bool ParentPolicy::IsActive() const
{
	return m_gkClient ? m_gkClient->IsRegistered() : false;
}

bool ParentPolicy::OnRequest(AdmissionRequest & arq_obj)
{
	return m_gkClient->SendARQ(arq_obj);
}

bool ParentPolicy::OnRequest(LocationRequest & lrq_obj)
{
	return m_gkClient->SendLRQ(lrq_obj);
}

bool ParentPolicy::OnRequest(SetupRequest & setup_obj)
{
	return !(setup_obj.GetFlags() & RoutingRequest::e_fromParent) && m_gkClient->SendARQ(setup_obj);
}

bool ParentPolicy::OnRequest(FacilityRequest & facility_obj)
{
	return !(facility_obj.GetFlags() & RoutingRequest::e_fromParent) && m_gkClient->SendARQ(facility_obj);
}


DNSPolicy::DNSPolicy()
{
	m_name = "DNS";
	m_iniSection = "Routing::DNS";
    m_resolveNonLocalLRQs = true;
}

void DNSPolicy::LoadConfig(const PString & instance)
{
	m_resolveNonLocalLRQs = Toolkit::AsBool(GkConfig()->GetString(m_iniSection, "ResolveNonLocalLRQ", "1"));
}

bool DNSPolicy::DNSLookup(const PString & hostname, PIPSocket::Address & addr) const
{
	struct addrinfo hints;
	struct addrinfo * result = NULL;
	memset(&hints, 0, sizeof(hints));
	if (Toolkit::Instance()->IsIPv6Enabled()) {
		hints.ai_family = AF_UNSPEC;
	} else {
		hints.ai_family = AF_INET;
	}
	if (getaddrinfo(hostname, NULL, &hints, &result) != 0)
		return false;
	addr = PIPSocket::Address(result->ai_family, result->ai_addrlen, result->ai_addr);
	freeaddrinfo(result);
	return true;
}

bool DNSPolicy::FindByAliases(RoutingRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	for (PINDEX i = 0; i < aliases.GetSize(); ++i) {
		// don't apply DNS to dialedDigits
		if (aliases[i].GetTag() == H225_AliasAddress::e_dialedDigits)
			continue;
		PString alias(AsString(aliases[i], FALSE));
		PINDEX at = alias.Find('@');
		PINDEX hashhash = alias.Find("##");	// Polycom's domain##alias notation

		PString domain = alias;
		if (at != P_MAX_INDEX)
			domain = alias.Mid(at + 1);
		if (hashhash != P_MAX_INDEX)
			domain = alias.Left(hashhash);
		if (domain.Find("ip$") == 0)
			domain.Replace("ip$", "", false);
		PStringArray parts = SplitIPAndPort(domain, GK_DEF_ENDPOINT_SIGNAL_PORT);
		domain = parts[0];
		WORD port = (WORD)parts[1].AsUnsigned();
		PIPSocket::Address addr;
		if (DNSLookup(domain, addr) && addr.IsValid()) {
			H225_TransportAddress dest;
			if (!request.GetGatewayDestination(dest)) {
				dest = SocketToH225TransportAddr(addr, port);
				PString aliasPart = "";
				if (at != P_MAX_INDEX)
					aliasPart = alias.Left(at);
				if (hashhash != P_MAX_INDEX)
					aliasPart = alias.Mid(hashhash + 2);
                if (!aliasPart.IsEmpty()) {
                    H323SetAliasAddress(aliasPart, aliases[i]);
                } else {
                    aliases.RemoveAt(i);
                }
				PTRACE(4, "ROUTING\tDNS policy resolves to " << aliasPart << " @ " << AsDotString(dest));
			}

			if (Toolkit::Instance()->IsGKHome(addr)
				&& ( (port == GkConfig()->GetInteger("RoutedMode", "CallSignalPort", GK_DEF_CALL_SIGNAL_PORT))
					|| (port == GkConfig()->GetInteger("RoutedMode", "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT))) ) {
				// check if the domain is my IP, if so route to local endpoint if available
				H225_ArrayOf_AliasAddress find_aliases;
				find_aliases.SetSize(1);
				PString aliasPart = "";
				if (at != P_MAX_INDEX)
					aliasPart = alias.Left(at);
				if (hashhash != P_MAX_INDEX)
					aliasPart = alias.Mid(hashhash + 2);
				H323SetAliasAddress(aliasPart, find_aliases[0]);
				endptr ep = RegistrationTable::Instance()->FindByAliases(find_aliases);
				if (ep) {
					dest = ep->GetCallSignalAddress();
				} else {
					continue;	// can't route this alias locally, try next alias
				}
			}
			bool isARQ = dynamic_cast<AdmissionRequest *>(&request);
			if (GkConfig()->GetBoolean("Routing::DNS", "RewriteARQDestination", true) || !isARQ) {
                // tell caller the changed destination
                request.SetFlag(RoutingRequest::e_aliasesChanged);
            }
			Route route(m_name, dest);
			route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(dest);
			request.AddRoute(route);
			return true;
		}
	}
	return false;
}

bool DNSPolicy::FindByAliases(LocationRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	for (PINDEX i = 0; i < aliases.GetSize(); ++i) {
		// don't apply DNS to dialedDigits
		if (aliases[i].GetTag() == H225_AliasAddress::e_dialedDigits)
			continue;
		PString alias(AsString(aliases[i], FALSE));
		PINDEX at = alias.Find('@');
		PINDEX hashhash = alias.Find("##");	// Polycom's domain##alias notation

		PString domain = alias;
		if (at != P_MAX_INDEX)
			domain = alias.Mid(at + 1);
		if (hashhash != P_MAX_INDEX)
			domain = alias.Left(hashhash);
		if (domain.Find("ip$") == 0)
			domain.Replace("ip$", "", false);
		PStringArray parts = SplitIPAndPort(domain, GK_DEF_ENDPOINT_SIGNAL_PORT);
		domain = parts[0];
		WORD port = (WORD)parts[1].AsUnsigned();
		PIPSocket::Address addr;
		if (DNSLookup(domain, addr) && addr.IsValid()) {
			H225_TransportAddress dest = SocketToH225TransportAddr(addr, port);
			if (Toolkit::Instance()->IsGKHome(addr)) {
				// only apply DNS policy to LRQs that resolve locally
				H225_ArrayOf_AliasAddress find_aliases;
				PString aliasPart = "";
				if (at != P_MAX_INDEX)
					aliasPart = alias.Left(at);
				if (hashhash != P_MAX_INDEX)
					aliasPart = alias.Mid(hashhash + 2);
				find_aliases.SetSize(1);
				H323SetAliasAddress(aliasPart, find_aliases[0]);
				endptr ep = RegistrationTable::Instance()->FindByAliases(find_aliases);
				if (ep) {
					if (!(RasServer::Instance()->IsGKRouted()) && !ep->GetForceDirectMode()) {
						// in direct mode, send call directly to EP
						dest = ep->GetCallSignalAddress();
					}
					Route route(m_name, dest);
					route.m_destEndpoint = ep;
					request.AddRoute(route);
					request.SetFlag(RoutingRequest::e_aliasesChanged);
					// remove the domain name part
					H323SetAliasAddress(alias.Left(at), aliases[i]);
					PTRACE(4, "ROUTING\tDNS policy resolves to " << alias.Left(at));
					return true;
				}
			} else if (m_resolveNonLocalLRQs) {
				Route route(m_name, dest);
				request.AddRoute(route);
				PTRACE(4, "ROUTING\tDNS policy resolves to " << domain);
				return true;
			}
		}
	}
	if (!m_resolveNonLocalLRQs) {
		PTRACE(4, "ROUTING\tPolicy DNS configured to only route LRQs that resolve locally");
	}
	return false;
}


VirtualQueue::VirtualQueue()
	: m_active(false), m_requestTimeout(DEFAULT_ROUTE_REQUEST_TIMEOUT * 1000)
{
}

VirtualQueue::~VirtualQueue()
{
	m_listMutex.Wait();

	int numrequests = m_pendingRequests.size();
	if (numrequests) {
		PTRACE(1, "VQueue\tDestroying virtual queue with " << numrequests << " pending requests");
	}
	RouteRequests::iterator i = m_pendingRequests.begin();
	while (i != m_pendingRequests.end()) {
		RouteRequest *r = *i++;
		r->m_sync.Signal();
	}

	m_listMutex.Signal();

	// wait a moment to give a chance to pending requests to cleanup
	if (numrequests) {
		PThread::Sleep(500);
	}
}

void VirtualQueue::OnReload()
{
	PWaitAndSignal lock(m_listMutex);

	m_requestTimeout = GkConfig()->GetInteger(
		CTIsection,
		GkConfig()->HasKey(CTIsection, "RequestTimeout") ? "RequestTimeout" : "CTI_Timeout", DEFAULT_ROUTE_REQUEST_TIMEOUT) * 1000;
	m_requestTimeout = PMAX((long)100, m_requestTimeout);	// min wait: 100 msec

	m_active = false;

	m_virtualQueueAliases.RemoveAll();
	PString vqueues = GkConfig()->GetString(CTIsection, "VirtualQueueAliases", "");
	if (vqueues.IsEmpty()) // backward compatibility
		vqueues = GkConfig()->GetString(CTIsection, "VirtualQueue", "");
	if (!vqueues.IsEmpty()) {
		m_virtualQueueAliases = vqueues.Tokenise(" ,;\t", false);
		if (m_virtualQueueAliases.GetSize() > 0) {
			PTRACE(2, "VQueue\t(CTI) Virtual queues enabled (aliases:" << vqueues
				<< "), request timeout: " << m_requestTimeout/1000 << " s");
			m_active = true;
		}
	}

	m_virtualQueuePrefixes.RemoveAll();
	vqueues = GkConfig()->GetString(CTIsection, "VirtualQueuePrefixes", "");
	if (!vqueues.IsEmpty()) {
		m_virtualQueuePrefixes = vqueues.Tokenise(" ,;\t", false);
		if (m_virtualQueuePrefixes.GetSize() > 0) {
			PTRACE(2, "VQueue\t(CTI) Virtual queues enabled (prefixes:" << vqueues
				<< "), request timeout: " << m_requestTimeout/1000 << " s");
			m_active = true;
		}
	}

	m_virtualQueueRegex = GkConfig()->GetString(CTIsection, "VirtualQueueRegex", "");
	if (!m_virtualQueueRegex.IsEmpty()) {
		// check if regex is valid
		PRegularExpression regex(m_virtualQueueRegex, PRegularExpression::Extended);
		if (regex.GetErrorCode() != PRegularExpression::NoError) {
			PTRACE(2, "Error '" << regex.GetErrorText() << "' compiling regex: " << m_virtualQueueRegex);
			SNMP_TRAP(7, SNMPError, Configuration, "Invalid " + PString(CTIsection) + " configuration: compiling RegEx failed");
        } else {
			PTRACE(2, "VQueue\t(CTI) Virtual queues enabled (regex:" << m_virtualQueueRegex
				<< "), request timeout: " << m_requestTimeout/1000 << " s");
			m_active = true;
		}
	}

	if (!m_active) {
		PTRACE(2, "VQueue\t(CTI) Virtual queues disabled - no virtual queues configured");
	}
}

bool VirtualQueue::SendRouteRequest(
	/// source IP of the request (endpoint for ARQ, gatekeeper for LRQ)
	const PString & source,
	/// calling endpoint
	const PString & epid,
	/// CRV (Call Reference Value) of the call associated with this request
	unsigned crv,
	/// destination (virtual queue) aliases as specified
	/// by the calling endpoint (modified by this function on successful return)
	H225_ArrayOf_AliasAddress * destinationInfo,
	/// destination (virtual queue) aliases as specified
	/// by the calling endpoint (modified by this function on successful return)
	PString * callSigAdr,
	/// bind IP for BindAndRouteToGateway
	PString * bindIP,
	/// caller ID
	PString * callerID,
	/// Display IE of caller
	PString * callerDisplayIE,
	/// Display IE of called party
	PString * calledDisplayIE,
	/// should the call be rejected modified by this function on return)
	bool & reject,
	/// H.225 ReleaseComplete reason
	unsigned & rejectReason,
    /// don't communicate updated route to caller
    bool & keepRouteInternal,
	/// actual virtual queue name (should be present in destinationInfo too)
	const PString & vqueue,
	/// a sequence of aliases for the calling endpoint
	/// (in the "alias:type[=alias:type]..." format)
	const PString & sourceInfo,
	/// the callID as string
	const PString & callID,
	/// the called IP for unregistered calls
	const PString & calledip,
	/// vendor string of caller
	const PString & vendorString,
	/// the IP we received this message from
	const PString & fromIP,
	/// type of message that caused this RouteRequest
	const PString & msgType
	)
{
	bool result = false;
	bool duprequest = false;
	if (RouteRequest * r = InsertRequest(epid, crv, callID, destinationInfo, callSigAdr, bindIP, callerID, callerDisplayIE, calledDisplayIE, duprequest)) {
		PString cid = callID;
		cid.Replace(" ", "-", true);
        PString vs = vendorString;
		vs.Replace( ";", " ", true );
		vs.Replace( "|", " ", true );
		PString msg = "RouteRequest|" + source
						+ "|" + epid
						+ "|" + PString(crv)
						+ "|" + vqueue
						+ "|" + sourceInfo
						+ "|" + cid
						+ "|" + calledip
						+ "|" + vs
						+ "|" + fromIP
						+ "|" + msgType
						+ ";";
		// signal RouteRequest to the status line only once
		if (duprequest) {
			PTRACE(4, "VQueue\tDuplicate request: " << msg);
		} else {
			PTRACE(2, msg);
			GkStatus::Instance()->SignalStatus(msg + "\r\n", STATUS_TRACE_LEVEL_ROUTEREQ);
		}

		// wait for an answer from the status line (routetoalias, routetogateway, routereject)
		result = r->m_sync.Wait(m_requestTimeout);
		reject = r->m_reject;   // set reject status
		if (r->m_rejectReason > -1)
		rejectReason = r->m_rejectReason;
		keepRouteInternal = r->m_keepRouteInternal;
		m_listMutex.Wait();
		m_pendingRequests.remove(r);
		m_listMutex.Signal();
		if (!result) {
			PTRACE(5, "VQueue\tRoute request (EPID: " << r->m_callingEpId
				<< ", CRV=" << r->m_crv << ") timed out");
		}
		delete r;
	}
	return result;
}

bool VirtualQueue::IsDestinationVirtualQueue(
	const PString & destinationAlias /// alias to be matched
	) const
{
	PWaitAndSignal lock(m_listMutex);
	for (PINDEX i = 0; i < m_virtualQueueAliases.GetSize(); ++i)
		if (m_virtualQueueAliases[i] == destinationAlias)
			return true;
	for (PINDEX i = 0; i < m_virtualQueuePrefixes.GetSize(); ++i)
		if (destinationAlias.Find(m_virtualQueuePrefixes[i]) == 0)
			return true;

	return (!m_virtualQueueRegex.IsEmpty()) && Toolkit::MatchRegex(destinationAlias, m_virtualQueueRegex);
}

bool VirtualQueue::RouteToAlias(
	/// aliases for the routing target (an agent that the call will be routed to)
	/// that will replace the original destination info
	const H225_ArrayOf_AliasAddress & agent,
	/// ip that will replace the destinationCallSignalAddress (RouteToGateway)
	/// used only if set (!= NULL)
	const PString & destinationip,
	/// identifier of the endpoint associated with the route request
	const PString & callingEpId,
	/// CRV of the call associated with the route request
	unsigned crv,
	/// callID of the call associated with the route request
	const PString & callID,
	// outgoing IP or empty
	const PString & bindIP,
	// caller ID or empty
	const PString & callerID,
	/// should this call be rejected
	bool reject,
    /// don't communicate updated route to caller
    bool keepRouteInternal,
    /// Display IE or empty
    const PString & callerDisplayIE,
    /// Display IE of called party or empty
    const PString & calledDisplayIE,
    /// H225_AdmissionRejectReason/H.225 ReleaseComplete reason (only valid on reject)
    int reason
	)
{
	PWaitAndSignal lock(m_listMutex);

	// signal the command to each pending request
	bool foundrequest = false;
	RouteRequests::iterator i = m_pendingRequests.begin();
	while (!foundrequest && (i != m_pendingRequests.end())) {
		RouteRequest *r = *i;
		bool match = ((r->m_callingEpId == callingEpId) && (r->m_crv == crv));
		if (!r->m_callID.IsEmpty() && !callID.IsEmpty()) {
			// backward compatibility: only check if set
			match = (r->m_callID == callID);
		}
		if (match) {
			if (!reject) {
				// replace virtual queue aliases info with agent aliases
				// TODO: add alias field in ARQ, LRQ if not present, but call is routed to alias ?
				// TODO: remove alias field if new agent field is size 0 ??
				if (r->m_agent)
					*(r->m_agent) = agent;
				if (!destinationip.IsEmpty())	// RouteToGateway
					*(r->m_callsignaladdr) = destinationip;
				*(r->m_sourceIP) = bindIP;	// BindAndRouteToGateway
				*(r->m_callerID) = callerID;
				*(r->m_callerDisplayIE) = callerDisplayIE;
				*(r->m_calledDisplayIE) = calledDisplayIE;
				r->m_keepRouteInternal = keepRouteInternal;  // RouteToInternalGateway
			}
			r->m_reject = reject;
			if (reason > -1)
                r->m_rejectReason = reason;
			r->m_sync.Signal();
			if (!foundrequest) {
				foundrequest = true;
				if (!reject) {
					PTRACE(2, "VQueue\tRoute request (EPID:" << callingEpId
						<< ", CRV=" << crv << ") accepted by agent " << AsString(agent));
				} else {
					PTRACE(2, "VQueue\tRoute request (EPID:" << callingEpId
						<< ", CRV=" << crv << ") rejected");
				}
			}
		}
		++i;
	}

	if (!foundrequest) {
		PTRACE(4, "VQueue\tPending route request (EPID:" << callingEpId
			<< ", CRV=" << crv << ") not found - ignoring RouteToAlias / RouteToGateway / BindAndRouteToGateway command");
	}

	return foundrequest;
}

bool VirtualQueue::RouteToAlias(
	/// alias for the routing target that
	/// will replace the original destination info
	const PString & targetAlias,
	/// will replace the original destinationCallSignalAddress
	const PString & destinationIp,
	/// identifier of the endpoint associated with the route request
	const PString & callingEpId,
	/// CRV for the call associated with the route request
	unsigned crv,
	/// callID of the call associated with the route request
	const PString & callID,
	// outgoing IP or empty
	const PString & bindIP,
	// callerID or empty
	const PString & callerID,
	/// should this call be rejected
	bool reject,
    /// don't communicate updated route to caller
    bool keepRouteInternal,
    /// Display IE or empty
    const PString & callerDisplayIE,
    /// Display IE of called party or empty
    const PString & calledDisplayIE,
    /// H225_AdmissionRejectReason/H.225 ReleaseComplete reason
    int reason
	)
{
	H225_ArrayOf_AliasAddress alias;
	if (targetAlias != "" && targetAlias != "-") {
		alias.SetSize(1);
		H323SetAliasAddress(targetAlias, alias[0]);
	}
	return RouteToAlias(alias, destinationIp, callingEpId, crv, callID, bindIP, callerID, reject, keepRouteInternal, callerDisplayIE, calledDisplayIE, reason);
}

bool VirtualQueue::RouteReject(
	/// identifier of the endpoint associated with the route request
	const PString & callingEpId,
	/// CRV of the call associated with the route request
	unsigned crv,
	/// callID of the call associated with the route request
	const PString & callID,
	/// H.225 ReleaseComplete reason
	int reason
	)
{
	H225_ArrayOf_AliasAddress nullAgent;
	return RouteToAlias(nullAgent, "", callingEpId, crv, callID, "", "", true, false, "", reason);
}

VirtualQueue::RouteRequest* VirtualQueue::InsertRequest(
	/// identifier for the endpoint associated with this request
	const PString & callingEpId,
	/// CRV for the call associated with this request
	unsigned crv,
	/// callID for the call associated with this request
	const PString & callID,
	/// a pointer to an array to be filled with agent aliases
	/// when the routing decision has been made
	H225_ArrayOf_AliasAddress * agent,
	/// a pointer to a string  to be filled with a destinationCallSignalAddress
	/// when the routing decision has been made (optional)
	PString * callSigAdr,
	/// bind IP for BindAndRouteToGateway
	PString * bindIP,
	/// caller ID
	PString * callerID,
	/// Display IE of caller
	PString * callerDisplayIE,
	/// Display IE of called party
	PString * calledDisplayIE,
	/// set by the function to true if another route request for the same
	/// call is pending
	bool & duplicate
	)
{
	duplicate = false;
	PWaitAndSignal lock(m_listMutex);

	// check if another route requests for the same EPID,CRV are pending
	int duprequests = 0;
	RouteRequests::iterator i = m_pendingRequests.begin();
	while (i != m_pendingRequests.end()) {
		RouteRequest *r = *i;
		if (r->m_callingEpId == callingEpId && r->m_crv == crv && r->m_callID == callID)
			duprequests++;
		++i;
	}

	if (duprequests) {
		duplicate = true;
		PTRACE(5, "VQueue\tRoute request (EPID: " << callingEpId
			<< ", CRV=" << crv << ") is already active - duplicate requests"
			" waiting: " << duprequests);
	}

	// insert the new pending route request
	RouteRequest* r = new RouteRequest(callingEpId, crv, callID, agent, callSigAdr, bindIP, callerID, callerDisplayIE, calledDisplayIE);
	m_pendingRequests.push_back(r);
	return r;
}


VirtualQueuePolicy::VirtualQueuePolicy()
{
	m_vqueue = RasServer::Instance()->GetVirtualQueue();
	m_name = "VirtualQueue";
}

bool VirtualQueuePolicy::IsActive() const
{
	return m_vqueue ? m_vqueue->IsActive() : false;
}

bool VirtualQueuePolicy::OnRequest(AdmissionRequest & request)
{
	bool reject = false;
	unsigned rejectReason = H225_AdmissionRejectReason::e_calledPartyNotRegistered;
	H225_ArrayOf_AliasAddress * aliases = NULL;
	PString vq = "";
	if ((aliases = request.GetAliases()))
		vq = AsString((*aliases)[0], FALSE);
	if (m_vqueue->IsDestinationVirtualQueue(vq)) {
		H225_AdmissionRequest & arq = request.GetRequest();
		PTRACE(5, "Routing\tPolicy " << m_name << " destination matched "
			"a virtual queue " << vq << " (ARQ " << arq.m_requestSeqNum.GetValue() << ')');
		endptr ep = RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier); // should not be NULL
		if (ep) {
			PString source = AsDotString(ep->GetCallSignalAddress());
			PString epid = ep->GetEndpointIdentifier().GetValue();
			PString * callSigAdr = new PString();
			PString * bindIP = new PString();
			PString * callerID = new PString();
			PString * callerDisplayIE = new PString();
			PString * calledDisplayIE = new PString();
			PString calledIP = "unknown";
			PString vendorInfo;
			if (arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
				calledIP = AsDotString(arq.m_destCallSignalAddress, true);
			}
			if (ep->GetEndpointType().HasOptionalField(H225_EndpointType::e_vendor)) {
				if (ep->GetEndpointType().m_vendor.HasOptionalField(H225_VendorIdentifier::e_productId)) {
					vendorInfo += ep->GetEndpointType().m_vendor.m_productId.AsString();
				}
				if (ep->GetEndpointType().m_vendor.HasOptionalField(H225_VendorIdentifier::e_versionId)) {
					vendorInfo += ep->GetEndpointType().m_vendor.m_versionId.AsString();
				}
                vendorInfo.Replace("|", "", true);
                vendorInfo.Replace("\r", "", true);
                vendorInfo.Replace("\n", "", true);
			}
            PIPSocket::Address remoteAddr;
            WORD remotePort;
            request.GetWrapper()->GetPeerAddr(remoteAddr, remotePort);
            PString fromIP = AsString(remoteAddr, remotePort);
            bool keepRouteInternal = false;

			if (m_vqueue->SendRouteRequest(source, epid, unsigned(arq.m_callReferenceValue), aliases, callSigAdr, bindIP, callerID, callerDisplayIE, calledDisplayIE, reject, rejectReason, keepRouteInternal,
                vq, AsString(arq.m_srcInfo), AsString(arq.m_callIdentifier), calledIP, vendorInfo, fromIP, "ARQ")) {
                if (keepRouteInternal) {
                    request.SetNewSetupInternalAliases(*request.GetAliases());
                } else {
                    request.SetFlag(RoutingRequest::e_aliasesChanged);
                    request.SetRejectReason(rejectReason);
                }
            }
			if (reject) {
				request.SetFlag(RoutingRequest::e_Reject);
			}
			request.SetSourceIP(*bindIP);
			request.SetCallerID(*callerID);
			request.SetCallerDisplayIE(*callerDisplayIE);
			request.SetCalledDisplayIE(*calledDisplayIE);
			if (!callSigAdr->IsEmpty()) {
				if (!arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
					arq.IncludeOptionalField(H225_AdmissionRequest::e_destCallSignalAddress);
				}
				PStringArray adr_parts = SplitIPAndPort(*callSigAdr, GK_DEF_ENDPOINT_SIGNAL_PORT);
				PIPSocket::Address ip(adr_parts[0]);
				WORD port = (WORD)(adr_parts[1].AsInteger());
				arq.m_destCallSignalAddress = SocketToH225TransportAddr(ip, port);
			}
			delete callSigAdr;
			delete bindIP;
			delete callerID;
			delete callerDisplayIE;
			delete calledDisplayIE;
		}
		// the trick: if empty, the request is rejected
		// so we return true to terminate the routing
		// decision process, otherwise the aliases is
		// rewritten, we return false to let subsequent
		// policies determine the request
		if (m_next == NULL || reject)
			return true;
	}
	return false;
}

bool VirtualQueuePolicy::OnRequest(LocationRequest & request)
{
	bool reject = false;
	unsigned rejectReason = H225_ReleaseCompleteReason::e_calledPartyNotRegistered;
	if (H225_ArrayOf_AliasAddress *aliases = request.GetAliases()) {
		const PString vq(AsString((*aliases)[0], false));
		if (m_vqueue->IsDestinationVirtualQueue(vq)) {
			H225_LocationRequest & lrq = request.GetRequest();
			PTRACE(5, "Routing\tPolicy " << m_name << " destination matched "
				"a virtual queue " << vq << " (LRQ "
				<< lrq.m_requestSeqNum.GetValue() << ')');

			// only use vqueue if sender is able to handle changed destination
			if (!lrq.HasOptionalField(H225_LocationRequest::e_canMapAlias) || !lrq.m_canMapAlias) {
				PTRACE(5, "Sender can't map destination alias, skipping virtual queue");
				return false;
			}

			PString source = AsDotString(lrq.m_replyAddress);
			PString epid = lrq.m_endpointIdentifier.GetValue();
			if (epid.IsEmpty()) {
				epid = lrq.m_gatekeeperIdentifier.GetValue();
				if (lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo) && (lrq.m_sourceInfo.GetSize() > 0))
					epid += "_" + AsString(lrq.m_sourceInfo, false);
			}
			if (epid.IsEmpty()) {
				epid = "unknown";	// make sure its not empty
			}
			PString * callSigAdr = new PString(); /* unused for LRQs */
			PString * bindIP = new PString();
			PString * callerID = new PString();
			PString * callerDisplayIE = new PString();
			PString * calledDisplayIE = new PString();
			PString sourceInfo = "";
			if (lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo) && (lrq.m_sourceInfo.GetSize() > 0))
				sourceInfo = AsString(lrq.m_sourceInfo);
			PString callID = "-";	/* not available for LRQs */
			PString calledIP = "unknown";
            PString vendorString = "unknown";
            PIPSocket::Address remoteAddr;
            WORD remotePort;
            request.GetWrapper()->GetPeerAddr(remoteAddr, remotePort);
            PString fromIP = AsString(remoteAddr, remotePort);
            bool keepRouteInternal = false;

			if (m_vqueue->SendRouteRequest(source, epid, unsigned(lrq.m_requestSeqNum), aliases, callSigAdr, bindIP, callerID, callerDisplayIE, calledDisplayIE, reject, rejectReason, keepRouteInternal,
                vq, sourceInfo, callID, calledIP, vendorString, fromIP, "LRQ")) {
                if (!keepRouteInternal) {
                    request.SetFlag(RoutingRequest::e_aliasesChanged);
                }
            }
			if (reject) {
				request.SetFlag(RoutingRequest::e_Reject);
                request.SetRejectReason(rejectReason);
			}
			request.SetSourceIP(*bindIP);
			request.SetCallerID(*callerID);
			request.SetCallerDisplayIE(*callerDisplayIE);
			request.SetCalledDisplayIE(*calledDisplayIE);
			if (!reject && !callSigAdr->IsEmpty()) {
				// 'explicit' policy can't handle LRQs, so we do it directly
				PStringArray adr_parts = SplitIPAndPort(*callSigAdr, GK_DEF_ENDPOINT_SIGNAL_PORT);
				PIPSocket::Address ip(adr_parts[0]);
				WORD port = (WORD)(adr_parts[1].AsInteger());
				Route route("vqueue", SocketToH225TransportAddr(ip, port));
				route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(
					route.m_destAddr
				);
				request.AddRoute(route);
				delete callSigAdr;
				delete bindIP;
				delete callerID;
				delete callerDisplayIE;
				delete calledDisplayIE;
				return true;	// stop processing
			}
			delete callSigAdr;
			delete bindIP;
			delete callerID;
			delete callerDisplayIE;
			delete calledDisplayIE;
			// the trick: if empty, the request is rejected
			// so we return true to terminate the routing
			// decision process, otherwise the aliases is
			// rewritten, we return false to let subsequent
			// policies determine the request
			if (m_next == NULL || reject)
				return true;
		}
	}
	return false;
}

bool VirtualQueuePolicy::OnRequest(SetupRequest & request)
{
	bool reject = false;
	unsigned rejectReason = H225_ReleaseCompleteReason::e_calledPartyNotRegistered;
	H225_ArrayOf_AliasAddress * aliases = new H225_ArrayOf_AliasAddress;
	aliases->SetSize(1);
	PString vq = "";
	if (request.GetAliases()) {
		vq = AsString((*request.GetAliases())[0], false);
	}
	if (m_vqueue->IsDestinationVirtualQueue(vq)) {
		H225_Setup_UUIE & setup = request.GetRequest();
		PString callerip = AsDotString(setup.m_sourceCallSignalAddress);
		PString epid = "unregistered";
		const unsigned crv = request.GetWrapper()->GetCallReference();
		PString * callSigAdr = new PString();
		PString * bindIP = new PString();
		PString * callerID = new PString();
		PString * callerDisplayIE = new PString();
		PString * calledDisplayIE = new PString();
		PString callid = AsString(setup.m_callIdentifier);
		PString src;
		if (!request.GetCallingStationId().IsEmpty()) {
            H225_AliasAddress srcAlias;
            // convert caller string back to alias to get alias type
            H323SetAliasAddress(request.GetCallingStationId(), srcAlias);
            src = AsString(srcAlias);
        }
		PIPSocket::Address localAddr;
		WORD localPort;
		request.GetWrapper()->GetLocalAddr(localAddr, localPort);
		PString calledIP = AsString(localAddr, localPort);
		PString vendorInfo;
		if (setup.m_sourceInfo.HasOptionalField(H225_EndpointType::e_vendor)) {
			if (setup.m_sourceInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_productId)) {
				vendorInfo += setup.m_sourceInfo.m_vendor.m_productId.AsString();
			}
			if (setup.m_sourceInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_versionId)) {
				vendorInfo += setup.m_sourceInfo.m_vendor.m_versionId.AsString();
			}
			vendorInfo.Replace("|", "", true);
			vendorInfo.Replace("\r", "", true);
			vendorInfo.Replace("\n", "", true);
		}
		PIPSocket::Address remoteAddr;
		WORD remotePort;
		request.GetWrapper()->GetPeerAddr(remoteAddr, remotePort);
		PString fromIP = AsString(remoteAddr, remotePort);
        bool keepRouteInternal = false;
		PTRACE(5, "Routing\tPolicy " << m_name << " destination matched "
			"a virtual queue " << vq << " (Setup " << crv << ')');

		if (m_vqueue->SendRouteRequest(callerip, epid, crv, aliases, callSigAdr, bindIP, callerID, callerDisplayIE, calledDisplayIE, reject, rejectReason, keepRouteInternal,
            vq, src, callid, calledIP, vendorInfo, fromIP, "Setup")) {
			request.SetFlag(RoutingRequest::e_aliasesChanged);
        }

		if (reject) {
			request.SetFlag(RoutingRequest::e_Reject);
            request.SetRejectReason(rejectReason);
		}
        request.SetSourceIP(*bindIP);
        request.SetCallerID(*callerID);
        request.SetCallerDisplayIE(*callerDisplayIE);
        request.SetCalledDisplayIE(*calledDisplayIE);
		if (!reject && callSigAdr->IsEmpty()) {
			if (!setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
				setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			}
			setup.m_destinationAddress = *aliases;
		}
		if (!reject && !callSigAdr->IsEmpty()) {
			if (!setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
				setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			}
			setup.m_destinationAddress = *aliases;
			if (!setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
				setup.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
			}
			PStringArray adr_parts = SplitIPAndPort(*callSigAdr, GK_DEF_ENDPOINT_SIGNAL_PORT);
			PIPSocket::Address ip(adr_parts[0]);
			WORD port = (WORD)(adr_parts[1].AsInteger());
			setup.m_destCallSignalAddress = SocketToH225TransportAddr(ip, port);
		}
		delete callSigAdr;
		delete bindIP;
		delete callerID;
		delete callerDisplayIE;
		delete calledDisplayIE;
		// the trick: if empty, the request is rejected
		// so we return true to terminate the routing
		// decision process, otherwise the aliases is
		// rewritten, we return false to let subsequent
		// policies determine the request
		if (m_next == NULL || reject) {
			delete aliases;
			return true;
		}
	}
	delete aliases;
	return false;
}

// TODO the use of binary_function needs a patch for C++17
struct PrefixGreater : public binary_function<NumberAnalysisPolicy::PrefixEntry, NumberAnalysisPolicy::PrefixEntry, bool> {

	bool operator()(const NumberAnalysisPolicy::PrefixEntry &e1, const NumberAnalysisPolicy::PrefixEntry &e2) const
	{
		if (e1.m_prefix.size() == e2.m_prefix.size())
			return e1.m_prefix > e2.m_prefix;
		else
			return e1.m_prefix.size() > e2.m_prefix.size();
	}
};

NumberAnalysisPolicy::NumberAnalysisPolicy()
{
	m_name = "NumberAnalysis";
	m_iniSection = "Routing::NumberAnalysis";
}

void NumberAnalysisPolicy::LoadConfig(const PString & instance)
{
	PStringToString kv = GkConfig()->GetAllKeyValues(m_iniSection);
	m_prefixes.resize(kv.GetSize());
	for (PINDEX i = 0; i < kv.GetSize(); i++) {
		const PString &val = kv.GetDataAt(i);

		m_prefixes[i].m_prefix = string((const char*)(kv.GetKeyAt(i)));

		const PINDEX sepIndex = val.Find(':');
		if (sepIndex == P_MAX_INDEX) {
			m_prefixes[i].m_minLength = val.AsUnsigned();
			m_prefixes[i].m_maxLength = -1;
		} else {
			m_prefixes[i].m_minLength = val.Left(sepIndex).AsUnsigned();
			m_prefixes[i].m_maxLength = val.Mid(sepIndex + 1).AsUnsigned();
		}
	}

	stable_sort(m_prefixes.begin(), m_prefixes.end(), PrefixGreater());

	PTRACE(5, "ROUTING\t" << m_name << " policy loaded with " << m_prefixes.size()
		<< " prefix entries");

	if (PTrace::CanTrace(6)) {
		ostream & strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << "ROUTING\t" << m_name << " policy prefixes:" << endl;
		for (unsigned i = 0; i < m_prefixes.size(); i++)
			strm << "\t" << m_prefixes[i].m_prefix.c_str() << " => min len: "
				<< m_prefixes[i].m_minLength << ", max len: "
				<< m_prefixes[i].m_maxLength << endl;
		PTrace::End(strm);
	}
}

bool NumberAnalysisPolicy::OnRequest(AdmissionRequest & request)
{
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	if (aliases == NULL)
		return false;

	for (PINDEX a = 0; a < aliases->GetSize(); a++) {
		const H225_AliasAddress &alias = (*aliases)[a];
		if (alias.GetTag() == H225_AliasAddress::e_dialedDigits
				|| alias.GetTag() == H225_AliasAddress::e_partyNumber) {
			const PString s = AsString(alias, FALSE);
			for (unsigned i = 0; i < m_prefixes.size(); i++)
				if (MatchPrefix(s, m_prefixes[i].m_prefix.c_str()) != 0) {
					if (s.GetLength() < m_prefixes[i].m_minLength) {
						request.RemoveAllRoutes();
						request.SetRejectReason(H225_AdmissionRejectReason::e_incompleteAddress);
						return true;
					} else if (m_prefixes[i].m_maxLength >= 0
							&& s.GetLength() > m_prefixes[i].m_maxLength) {
						request.RemoveAllRoutes();
						request.SetRejectReason(H225_AdmissionRejectReason::e_undefinedReason);
						return true;
					}
					return false;
				}
		}
	}
	return false;
}

bool NumberAnalysisPolicy::OnRequest(SetupRequest & request)
{
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	if (aliases == NULL)
		return false;

	for (PINDEX a = 0; a < aliases->GetSize(); ++a) {
		const H225_AliasAddress &alias = (*aliases)[a];
		if (alias.GetTag() == H225_AliasAddress::e_dialedDigits
				|| alias.GetTag() == H225_AliasAddress::e_partyNumber) {
			const PString s = AsString(alias, FALSE);
			for (unsigned i = 0; i < m_prefixes.size(); ++i)
				if (MatchPrefix(s, m_prefixes[i].m_prefix.c_str()) != 0) {
					if (s.GetLength() < m_prefixes[i].m_minLength) {
						request.RemoveAllRoutes();
						request.SetRejectReason(H225_ReleaseCompleteReason::e_badFormatAddress);
						return true;
					} else if (m_prefixes[i].m_maxLength >= 0
							&& s.GetLength() > m_prefixes[i].m_maxLength) {
						request.RemoveAllRoutes();
						request.SetRejectReason(H225_ReleaseCompleteReason::e_badFormatAddress);
						return true;
					}
					return false;
				}
		}
	}
	return false;
}


ENUMPolicy::ENUMPolicy()
{
	m_name = "ENUM";
	m_iniSection = "Routing::ENUM";
	m_resolveLRQs = Toolkit::AsBool(GkConfig()->GetString(m_iniSection, "ResolveLRQ", "0"));
	m_enum_schema.SetAt("E2U+h323", "");
}

void ENUMPolicy::LoadConfig(const PString & instance)
{
	if (instance.IsEmpty())
		return;

	m_enum_schema.RemoveAll();
	m_enum_schema = GkConfig()->GetAllKeyValues(m_iniSection);
}

bool ENUMPolicy::FindByAliases(RoutingRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	PString service = request.GetServiceType();
	if (!service && (service != m_instance)) {
		PTRACE(4, "ROUTING\tPolicy " << m_name << " not supported for service " << service);
		return false;
	}

#if P_DNS
	for (PINDEX i = 0; i < m_enum_schema.GetSize(); ++i) {
		PString enum_schema = m_enum_schema.GetKeyAt(i);
		PString gwDestination = m_enum_schema.GetDataAt(i);

		PBoolean changed = false;
		for (PINDEX j = 0; j < aliases.GetSize(); ++j) {
			if (!FindByAliasesInternal(enum_schema, request, aliases, changed))
				continue;

			if (!gwDestination && changed) {   // If we have a gateway destination and changed
				PStringArray parts = SplitIPAndPort(gwDestination, GK_DEF_ENDPOINT_SIGNAL_PORT);
				PString dom = parts[0];
				PIPSocket::Address addr;
				if (PIPSocket::GetHostAddress(dom, addr))
					dom = addr.AsString();
				WORD port = (WORD)parts[1].AsUnsigned();
				H225_TransportAddress dest;
				if (!GetTransportAddress(dom, port, dest)) {
					PTRACE(4, "ROUTING\tPolicy " << m_name << " " << enum_schema << " Could not resolve " << gwDestination);
					return false;
				}

				PString alias(AsString(aliases[j], FALSE));
				int at = alias.Find('@');
				PString domain = alias.Mid(at+1);
				if (IsIPAddress(domain)
					|| (domain.FindRegEx(PRegularExpression(":[0-9]+$", PRegularExpression::Extended)) != P_MAX_INDEX)) {
					// add a route and stop going any further
					PTRACE(4, "ROUTING\tPolicy " << m_name << " " << enum_schema << " set destination for " << alias << " to " << AsString(dest));
					Route * route = new Route(m_name, dest);
					route->m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(dest);
					request.AddRoute(*route);
					delete route;
					return true;
				}
				PTRACE(4, "ROUTING\tPolicy " << m_name << " " << enum_schema << " store destination for " << alias << " to " << AsString(dest));
				request.SetGatewayDestination(dest);
			}
			return false;
		}
	}
#endif
	return false;
}


bool ENUMPolicy::FindByAliasesInternal(const PString & schema, RoutingRequest & request, H225_ArrayOf_AliasAddress & aliases, PBoolean & changed)
{
#if P_DNS
	for (PINDEX i = 0; i < aliases.GetSize(); ++i) {
		PString alias(AsString(aliases[i], FALSE));
		if (alias.Left(2) *= "00") { // Check if not GDS number
			PTRACE(4, "\t" << m_name << " " << schema << " Ignored " << alias << " Not ENUM format.");
			continue;
		}
		// make sure the number has only digits
		alias.Replace("+","", true);
		alias.Replace("*","", true);
		alias.Replace("#","", true);
		alias.Replace(",","", true);
		while (alias.Left(1) *= "0")	// ENUM registries expect aliases without leading zeros
			alias = alias.Mid(1);
		PINDEX j;
		for (j = 0; j < alias.GetLength(); ++j)
			if (!isdigit(static_cast<unsigned char>(alias[j])))
				break;

		if (j >= alias.GetLength()) {
			PString str;
			if (PDNS::ENUMLookup(alias, schema, str)) {
				// Remove any + or URI Schema at the front
				PINDEX at = str.Find('@');
				PINDEX sch = str.Find(':');
				if (sch > 0 && sch < at)
					str = str.Mid(sch+1);
				str.Replace("+","", true);
				PTRACE(4, "\t" << m_name << " " << schema << " converted remote party " << alias << " to " << str);
				request.SetFlag(RoutingRequest::e_aliasesChanged);
				H323SetAliasAddress(str, aliases[i]);
				changed = true;
				return true;
			}
		}
	}
#else
	PTRACE(4, "\t" << m_name << " policy unavailable as no DNS support.");
#endif

	return false;
}

bool ENUMPolicy::FindByAliases(LocationRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	if (m_resolveLRQs) {
		return FindByAliases((RoutingRequest&)request, aliases);
	} else {
		PTRACE(4, "ROUTING\tPolicy " << m_name << " configured not to resolve LRQs");
		return false;
	}
}


DestinationRoutes::DestinationRoutes()
{
	m_endChain = false;
	m_reject = false;
	m_rejectReason = 0;
	m_aliasesChanged = false;
}

void DestinationRoutes::AddRoute(const Route & route, bool endChain)
{
	if (endChain)
		m_endChain = true;

	// check if route already exists, only use highest prio route (== lowest value)
	list<Route>::iterator it = m_routes.begin();
	while (it != m_routes.end()) {
		if (it->m_destAddr == route.m_destAddr) {
			PTRACE(5, "ROUTING\tSkipping existing route route " << route.AsString());
			// just update prio if we are lower
			if (route.GetPriority() < it->GetPriority()) {
				PTRACE(5, "ROUTING\tOnly update priority");
				it->SetPriority(route.GetPriority());
			}
			return;
		}
		++it;
	}
	m_routes.push_back(route);
}


DynamicPolicy::DynamicPolicy()
{
	m_active = false;
}

bool DynamicPolicy::OnRequest(AdmissionRequest & request)
{
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	H225_AdmissionRequest & arq = request.GetRequest();
	endptr ep = RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier); // should not be null
	if (ep) {
		PString source = AsDotString(ep->GetCallSignalAddress());
		PString calledAlias = "";
		if (aliases && !(aliases->GetSize() == 0))
			calledAlias = AsString((*aliases)[0], FALSE);
		PString calledIP = "";	/* not available for ARQs */
		PString caller = AsString(arq.m_srcInfo, FALSE);
		PString callingStationId = request.GetCallingStationId();
		PString callid = AsString(arq.m_callIdentifier);
		PString messageType = "ARQ";
		PString clientauthid = request.GetClientAuthId();
		PString language = ep->GetDefaultLanguage();
		DestinationRoutes destination;

		RunPolicy(	/* in */ source, calledAlias, calledIP, caller, callingStationId, callid, messageType, clientauthid, language,
                    /* out: */ destination);

		if (destination.m_routes.empty() && !ResolveRoute(request,destination))
			destination.SetRejectCall(true);

		if (destination.RejectCall()) {
			destination.SetChangedAliases(false);
			request.SetFlag(RoutingRequest::e_Reject);
			request.SetRejectReason(destination.GetRejectReason());
		}

		if (destination.ChangeAliases()) {
			request.SetFlag(RoutingRequest::e_aliasesChanged);
            if (!arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)) {
                arq.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
            }
			arq.m_destinationInfo = destination.GetNewAliases();
		}

		if (!destination.m_routes.empty()
			&& destination.m_routes.front().GetPriority() <= DEFAULT_ROUTE_PRIORITY) {
			request.SetFlag(RoutingRequest::e_aliasesChanged);
			if (!arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
				arq.IncludeOptionalField(H225_AdmissionRequest::e_destCallSignalAddress);
			}
			arq.m_destCallSignalAddress = destination.m_routes.front().m_destAddr;
		}
		while (!destination.m_routes.empty()) {
			request.AddRoute(destination.m_routes.front());
			destination.m_routes.pop_front();
		}

		if (m_next == NULL || destination.EndPolicyChain())
			return true;
	}
	return false;
}

bool DynamicPolicy::OnRequest(LocationRequest & request)
{
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	H225_LocationRequest & lrq = request.GetRequest();
	if (!lrq.HasOptionalField(H225_LocationRequest::e_canMapAlias) || !lrq.m_canMapAlias) {
			PTRACE(3, "WARNING: Sender can't map destination alias via dynamic policy");
	}
	PString source = AsDotString(lrq.m_replyAddress);
	PString calledAlias = "";
	if (aliases && !(aliases->GetSize() == 0))
		calledAlias = AsString((*aliases)[0], FALSE);
	PString calledIP = "";	/* not available for LRQs */
	PString caller = "";
	if (lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo) && (lrq.m_sourceInfo.GetSize() > 0))
		caller = AsString(lrq.m_sourceInfo[0], FALSE);
	PString callingStationId = request.GetCallingStationId();
	if (callingStationId.IsEmpty())
		callingStationId = caller;
	PString callid = "";	/* not available for LRQs */
	PString messageType = "LRQ";
	PString clientauthid = "";	/* not available for LRQs */
	PString language = "";
#ifdef HAS_LANGUAGE
	if (lrq.HasOptionalField(H225_LocationRequest::e_language) && (lrq.m_language.GetSize() > 0))
		language = lrq.m_language[0];
#endif
	DestinationRoutes destination;

	RunPolicy(	/* in */ source, calledAlias, calledIP, caller, callingStationId,callid, messageType, clientauthid, language,
					/* out: */ destination);

	if (destination.m_routes.empty() && !ResolveRoute(request,destination))
		destination.SetRejectCall(true);

	if (destination.RejectCall()) {
		destination.SetChangedAliases(false);
		request.SetFlag(RoutingRequest::e_Reject);
		request.SetRejectReason(destination.GetRejectReason());
	}

	if (destination.ChangeAliases()) {
		request.SetFlag(RoutingRequest::e_aliasesChanged);
		lrq.m_destinationInfo = destination.GetNewAliases();
	}

	if (!destination.m_routes.empty()) {
		// 'explicit' policy can't handle LRQs, so we do it directly
		request.SetFlag(RoutingRequest::e_aliasesChanged);
		while (!destination.m_routes.empty()) {
			request.AddRoute(destination.m_routes.front());
			destination.m_routes.pop_front();
		}
	}

	if (m_next == NULL || destination.EndPolicyChain())
		return true;

	return false;
}

bool DynamicPolicy::OnRequest(SetupRequest & request)
{
	H225_Setup_UUIE & setup = request.GetRequest();

	PString source = AsDotString(setup.m_sourceCallSignalAddress);
	PString calledAlias = "";
	if (request.GetAliases() && !(request.GetAliases()->GetSize() == 0)) {
		calledAlias = AsString((*request.GetAliases())[0], FALSE);
	}
	PIPSocket::Address localAddr;
	WORD localPort;
	request.GetWrapper()->GetLocalAddr(localAddr, localPort);
	PString calledIP = localAddr;	// TODO: only correct if a gatekeeper IP was called, should we use explicit IP if present ?
	PString caller = request.GetCallingStationId();
	PString callingStationId = request.GetCallingStationId();
	PString callid = AsString(setup.m_callIdentifier);
	PString messageType = "Setup";
	PString clientauthid = request.GetClientAuthId();
	PString language = "";
#ifdef HAS_LANGUAGE
	if (setup.HasOptionalField(H225_Setup_UUIE::e_language) && (setup.m_language.GetSize() > 0))
		language = setup.m_language[0];
#endif
	DestinationRoutes destination;

	RunPolicy(	/* in */ source, calledAlias, calledIP, caller, callingStationId, callid, messageType, clientauthid, language,
					/* out: */ destination);

	if (destination.m_routes.empty() && !ResolveRoute(request,destination))
		destination.SetRejectCall(true);

	if (destination.RejectCall()) {
		destination.SetChangedAliases(false);
		request.SetFlag(RoutingRequest::e_Reject);
		request.SetRejectReason(destination.GetRejectReason());
	}

	if (destination.ChangeAliases()) {
		request.SetFlag(RoutingRequest::e_aliasesChanged);
		if (!setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
			setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
		}
		setup.m_destinationAddress = destination.GetNewAliases();
	}

	if (!destination.m_routes.empty()
		&& destination.m_routes.front().GetPriority() <= DEFAULT_ROUTE_PRIORITY) {
		request.SetFlag(RoutingRequest::e_aliasesChanged);
		if (!setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
			setup.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		}
		setup.m_destCallSignalAddress = destination.m_routes.front().m_destAddr;
	}
	while (!destination.m_routes.empty()) {
		request.AddRoute(destination.m_routes.front());
		destination.m_routes.pop_front();
	}

	if (m_next == NULL || destination.EndPolicyChain())
		return true;

	return false;
}

SqlPolicy::SqlPolicy()
{
	m_active = false;
	m_sqlConn = NULL;
	m_name = "Sql";
	m_iniSection = "Routing::Sql";
	m_timeout = -1;
#ifndef HAS_DATABASE
	PTRACE(1, m_name << " not available - no database driver compiled into GnuGk");
#endif // HAS_DATABASE
}

void SqlPolicy::LoadConfig(const PString & instance)
{
#if HAS_DATABASE
	if (GkConfig()->GetAllKeyValues(m_iniSection).GetSize() <= 0) {
		PTRACE(1, m_name << "\tConfig section " << m_iniSection << " doesn't exist");
		return;
	}

	const PString driverName = GkConfig()->GetString(m_iniSection, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(2, m_name << "\tmodule creation failed: no SQL driver selected");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		return;
	}

	m_sqlConn = GkSQLConnection::Create(driverName, m_name);
	if (m_sqlConn == NULL) {
		PTRACE(2, m_name << "\tmodule creation failed: could not find " << driverName << " database driver");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		return;
	}

	m_query = GkConfig()->GetString(m_iniSection, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(2, m_name << "\tmodule creation failed: no query configured");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		return;
	} else
		PTRACE(4, m_name << "\tQuery: " << m_query);

	if (!m_sqlConn->Initialize(GkConfig(), m_iniSection)) {
		PTRACE(2, m_name << "\tmodule creation failed: could not connect to the database");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		return;
	}
	m_active = true;
#endif
}

SqlPolicy::~SqlPolicy()
{
	delete m_sqlConn;
}

void SqlPolicy::RunPolicy(
		/* in */
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType,
		const PString & clientauthid,
		const PString & language,
		/* out: */
		DestinationRoutes & destination)
{
#if HAS_DATABASE
	GkSQLResult::ResultRow resultRow;
	std::map<PString, PString> params;
	params["s"] = source;
	params["c"] = calledAlias;
	params["p"] = calledIP;
	params["r"] = caller;
	params["Calling-Station-Id"] = callingStationId;
	params["i"] = callid;
	params["m"] = messageType;
	params["client-auth-id"] = clientauthid;
	params["language"] = language;
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, params, m_timeout);
	if (result == NULL) {
		PTRACE(2, m_name << ": query failed - timeout or fatal error");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " query failed");
		return;
	}

	if (!result->IsValid()) {
		PTRACE(2, m_name << ": query failed (" << result->GetErrorCode() << ") - " << result->GetErrorMessage());
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " query failed");
		delete result;
		return;
	}

	if (result->GetNumRows() < 1)
		PTRACE(3, m_name << ": query returned no rows");
	else if (result->GetNumFields() < 1)
		PTRACE(2, m_name << ": bad query - no columns found in the result set");
	else if (!result->FetchRow(resultRow) || resultRow.empty()) {
		PTRACE(2, m_name << ": query failed - could not fetch the result row");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " query failed");
	} else if ((result->GetNumFields() == 1)
			|| ((result->GetNumFields() == 2) && (resultRow[1].first.ToUpper() == "IGNORE")) ) {
		PString newDestination = resultRow[0].first;
		PTRACE(5, m_name << "\tQuery result : " << newDestination);
		if (newDestination.ToUpper() == "REJECT") {
			destination.SetRejectCall(true);
		} else if (IsIPAddress(newDestination)) {
			int row = 0;
			do {
				PString destinationIp = resultRow[0].first;
				PStringArray adr_parts = SplitIPAndPort(destinationIp, GK_DEF_ENDPOINT_SIGNAL_PORT);
				PIPSocket::Address ip(adr_parts[0]);
				WORD port = (WORD)(adr_parts[1].AsInteger());

				Route route(m_name , SocketToH225TransportAddr(ip, port));
				route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
				if (!language.IsEmpty())
				    route.m_language.AppendString(language);
				destination.AddRoute(route);

				row++;
				if (row < result->GetNumRows()) {
					result->FetchRow(resultRow);	// fetch next row
					PTRACE(5, m_name << "\tResult cont'd: " << resultRow[0].first);
				}
			} while (row < result->GetNumRows());
		} else {
			H225_ArrayOf_AliasAddress newAliases;
			newAliases.SetSize(1);
			if (GkConfig()->GetBoolean(m_iniSection, "EnableRegexRewrite", false))
				newDestination = RewriteWildcard(calledAlias, newDestination);
			H323SetAliasAddress(newDestination, newAliases[0]);
			destination.SetNewAliases(newAliases);
		}
	} else if (result->GetNumFields() == 2) {
		PString newDestinationAlias = resultRow[0].first;
		PString newDestinationIP = resultRow[1].first;
		PTRACE(5, m_name << "\tQuery result : " << newDestinationAlias << ", " << newDestinationIP);
		if (newDestinationAlias.ToUpper() == "REJECT") {
			destination.SetRejectCall(true);
			destination.SetRejectReason(newDestinationIP.AsInteger());
		} else {
			H225_ArrayOf_AliasAddress newAliases;
			newAliases.SetSize(1);
			if (GkConfig()->GetBoolean(m_iniSection, "EnableRegexRewrite", false))
				newDestinationAlias = RewriteWildcard(calledAlias, newDestinationAlias);
			H323SetAliasAddress(newDestinationAlias, newAliases[0]);
			destination.SetNewAliases(newAliases);
			int row = 0;
			do {
				PString destinationAlias = resultRow[0].first;
                if (GkConfig()->GetBoolean(m_iniSection, "EnableRegexRewrite", false))
				    destinationAlias = RewriteWildcard(calledAlias, destinationAlias);

				PStringArray adr_parts = SplitIPAndPort(newDestinationIP, GK_DEF_ENDPOINT_SIGNAL_PORT);
				PIPSocket::Address ip(adr_parts[0]);
				WORD port = (WORD)(adr_parts[1].AsInteger());

				Route route(m_name, SocketToH225TransportAddr(ip, port));
				route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
				route.m_destNumber = destinationAlias;
				if (!language.IsEmpty())
				    route.m_language.AppendString(language);
				destination.AddRoute(route);

				row++;
				if (row < result->GetNumRows()) {
					result->FetchRow(resultRow);	// fetch next row
					PTRACE(5, m_name << "\tResult cont'd: " << resultRow[0].first << ", " << resultRow[1].first);
				}
			} while (row < result->GetNumRows());
		}
	}
	delete result;
#endif // HAS_DATABASE
}


HttpPolicy::HttpPolicy()
{
	m_active = false;
	m_name = "Http";
	m_iniSection = "Routing::Http";
	m_JSONResponse = false;
}

void HttpPolicy::LoadConfig(const PString & instance)
{
	if (GkConfig()->GetAllKeyValues(m_iniSection).GetSize() <= 0) {
		PTRACE(1, m_name << "\tConfig section " << m_iniSection << " doesn't exist");
		return;
	}

	m_url = GkConfig()->GetString(m_iniSection, "URL", "");
	m_body = GkConfig()->GetString(m_iniSection, "Body", "");
	m_method = GkConfig()->GetString(m_iniSection, "Method", "POST");
	m_contentType = GkConfig()->GetString(m_iniSection, "ContentType", "text/plain");
	PString resultRegex = GkConfig()->GetString(m_iniSection, "ResultRegex", ".*"); // match everything
	m_resultRegex = PRegularExpression(resultRegex, PRegularExpression::Extended);
	m_resultRegex = PRegularExpression(resultRegex);
	if (m_resultRegex.GetErrorCode() != PRegularExpression::NoError) {
		PTRACE(2, "Error '"<< m_resultRegex.GetErrorText() <<"' compiling ResultRegex: " << resultRegex);
		m_resultRegex = PRegularExpression(".", PRegularExpression::Extended);
	}
	PString deleteRegex = GkConfig()->GetString(m_iniSection, "DeleteRegex", "XXXXXXXXXX");   // default should never match
	m_deleteRegex = PRegularExpression(deleteRegex, PRegularExpression::Extended);
	if (m_deleteRegex.GetErrorCode() != PRegularExpression::NoError) {
		PTRACE(2, "Error '"<< m_deleteRegex.GetErrorText() <<"' compiling DeleteRegex: " << deleteRegex);
		m_deleteRegex = PRegularExpression("XXXXXXXXXX", PRegularExpression::Extended);
	}
	PString errorRegex = GkConfig()->GetString(m_iniSection, "ErrorRegex", "^$");
	m_errorRegex = PRegularExpression(errorRegex, PRegularExpression::Extended);
	if (m_errorRegex.GetErrorCode() != PRegularExpression::NoError) {
		PTRACE(2, "Error '"<< m_errorRegex.GetErrorText() <<"' compiling ErrorRegex: " << errorRegex);
		m_errorRegex = PRegularExpression("^$", PRegularExpression::Extended);
	}
#ifdef HAS_JSON
	m_JSONResponse = GkConfig()->GetBoolean(m_iniSection, "JSONResponse", false);
#endif
	m_active = true;
}

HttpPolicy::~HttpPolicy()
{
}

#ifdef HAS_LIBCURL
// receives the document data
static size_t CurlWriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    *((PString*)userp) = PString((const char*)contents, size * nmemb);
    return size * nmemb;
}

// receives debug output
static int DebugToTrace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
  PTRACE (6, "CURL\t" << PString((const char *)data, size).Trim());
  return 0;
}
#endif // HAS_LIBCURL

void HttpPolicy::RunPolicy(
		/* in */
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType,
		const PString & clientauthid,
		const PString & language,
		/* out: */
		DestinationRoutes & destination)
{
	std::map<PString, PString> params;
	params["s"] = source;
	params["c"] = calledAlias;
	params["p"] = calledIP;
	params["r"] = caller;
	params["Calling-Station-Id"] = callingStationId;
	params["i"] = callid;
	params["m"] = messageType;
	params["client-auth-id"] = clientauthid;
	params["language"] = language;

    PString result;

    PString url = GkAuthenticator::ReplaceAuthParams(m_url, params);
    url = Toolkit::Instance()->ReplaceGlobalParams(url);
    url.Replace(" ", "%20", true);  // TODO: better URL escaping ?
    PTRACE(6, m_iniSection + "\tURL=" << url);
    PString host = PURL(url).GetHostName();
    PString body = GkAuthenticator::ReplaceAuthParams(m_body, params);
    body = Toolkit::Instance()->ReplaceGlobalParams(body);

#ifdef HAS_LIBCURL
    CURLcode curl_res = CURLE_FAILED_INIT;
    CURL * curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headerlist = NULL;
        if (m_method == "GET") {
            // nothing special to do
        } else if (m_method == "POST") {
            PStringArray parts = url.Tokenise("?");
            if (body.IsEmpty() && parts.GetSize() == 2) {
                url = parts[0];
                body = parts[1];
            } else {
                PString header = PString("Content-Type: ") + m_contentType;
                headerlist = curl_slist_append(headerlist, (const char *)header);
                (void)curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
            }
            (void)curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)body);
        } else {
            PTRACE(2, m_name << "\tUnsupported method " << m_method);
        }
        (void)curl_easy_setopt(curl, CURLOPT_URL, (const char *)url);
        (void)curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
        (void)curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
        if (PTrace::CanTrace(6)) {
            (void)curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, DebugToTrace);
            (void)curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        }
        curl_res = curl_easy_perform(curl);
        curl_slist_free_all(headerlist);
        curl_easy_cleanup(curl);
    }

    if (curl_res != CURLE_OK) {
        PTRACE(2, m_name << "\tCould not get routing destination from " << host << " : " << curl_easy_strerror(curl_res));
        return;
    }
#else
    PHTTPClient http;
    if (m_method == "GET") {
        if (!http.GetTextDocument(url, result)) {
            PTRACE(2, m_iniSection << "\tCould not GET routing destination from " << host);
            return;
        }
    } else if (m_method == "POST") {
        PStringArray parts = url.Tokenise("?");
        if (body.IsEmpty() && parts.GetSize() == 2) {
            url = parts[0];
            body = parts[1];
        }
        PMIMEInfo outMIME;
        outMIME.SetAt(PMIMEInfo::ContentTypeTag(), (const char *)m_contentType);
        PMIMEInfo replyMIME;
        if (!http.PostData(url, outMIME, body, replyMIME, result)) {
            PTRACE(2, m_name << "\tCould not POST to " << host);
            return;
        }
    } else {
        PTRACE(2, m_name << "\tUnsupported method " << m_method);
        return;
    }
#endif // HAS_LIBCURL

    result = result.Trim();
	PTRACE(5, m_name << "\tServer response = " << result);
    PINDEX pos, len;
    if (result.FindRegEx(m_errorRegex, pos, len)) {
        PTRACE(4, m_name << "\tErrorRegex matches result from " << host);
        return;
    }

    if (m_JSONResponse) {
#ifdef HAS_JSON
        auto json_response = nlohmann::json::parse((const char *)result, NULL, false);
        // check parse error
        if (json_response.is_discarded()) {
            PTRACE(1, m_name << "\tError parsing JSON response");
            return;
        }
        if (json_response.is_array()) {
            for(unsigned n = 0; n < json_response.size(); ++n) {
                ParseJSONRoute(json_response[n], language, destination);
            }
            return;
        }
        if (json_response.find("reject") != json_response.end() && json_response["reject"]) { // eg. { "reject": true, "reject-reason": 2 }
            destination.SetRejectCall(true);
            if (json_response.find("reject-reason") != json_response.end())
                destination.SetRejectReason(json_response["reject-reason"].get<int>());
            return;
        }
        if (json_response.find("destination") == json_response.end()) {
            PTRACE(3, m_name << "\tNot rejected and no destination in JSON response");
            return;
        }
        // single new destination
        ParseJSONRoute(json_response, language, destination);
        return;
#endif // HAS_JSON
    } else {
        PString newDestination;
        if (result.FindRegEx(m_resultRegex, pos, len)) {
            newDestination = result.Mid(pos, len);
            ReplaceRegEx(newDestination, m_deleteRegex, "", true);
            PTRACE(5, m_name << "\tDestination = " << newDestination);
        } else {
            PTRACE(2, m_name << "\tError: No answer found in response from " << host);
            return;
        }

        if (newDestination.ToUpper() == "REJECT") {
            destination.SetRejectCall(true);
        } else if (IsIPAddress(newDestination)) {
            PStringArray adr_parts = SplitIPAndPort(newDestination, GK_DEF_ENDPOINT_SIGNAL_PORT);
            PIPSocket::Address ip(adr_parts[0]);
            WORD port = (WORD)(adr_parts[1].AsInteger());

            Route route(m_name, SocketToH225TransportAddr(ip, port));
            route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
            if (!language.IsEmpty())
                route.m_language.AppendString(language);
            destination.AddRoute(route);
        } else {
            H225_ArrayOf_AliasAddress newAliases;
            newAliases.SetSize(1);
            H323SetAliasAddress(newDestination, newAliases[0]);
            destination.SetNewAliases(newAliases);
        }
    }
}

#ifdef HAS_JSON
void HttpPolicy::ParseJSONRoute(const nlohmann::json & jsonRoute, const PString & language, DestinationRoutes & destination)
{
    PString destinationAlias = jsonRoute["destination"].get<std::string>().c_str();
    if (jsonRoute.find("gateway") != jsonRoute.end()) { // eg. { "destination": "support", "gateway": "1.2.3.4:1720" }
        PStringArray adr_parts = SplitIPAndPort(jsonRoute["gateway"].get<std::string>().c_str(), GK_DEF_ENDPOINT_SIGNAL_PORT);
        PIPSocket::Address ip(adr_parts[0]);
        WORD port = (WORD)(adr_parts[1].AsInteger());
        Route route(m_name, SocketToH225TransportAddr(ip, port));
        route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
        // when a gateway is set the destination is treated as an alias
        H225_ArrayOf_AliasAddress newAliases;
        newAliases.SetSize(1);
        H323SetAliasAddress(destinationAlias, newAliases[0]);
        destination.SetNewAliases(newAliases);
        if (!language.IsEmpty())
            route.m_language.AppendString(language);
        destination.AddRoute(route);
    } else {
        // if we only have a destination without gateway it can be alias or IP
        if (IsIPAddress(destinationAlias)) { // eg. { "destination": "1.2.3.4:1720" }
            PStringArray adr_parts = SplitIPAndPort(destinationAlias, GK_DEF_ENDPOINT_SIGNAL_PORT);
            PIPSocket::Address ip(adr_parts[0]);
            WORD port = (WORD)(adr_parts[1].AsInteger());
            Route route(m_name, SocketToH225TransportAddr(ip, port));
            route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
            route.m_destNumber = destinationAlias;
            if (!language.IsEmpty())
                route.m_language.AppendString(language);
            destination.AddRoute(route);
        } else { // { "destination": "support" }
            H225_ArrayOf_AliasAddress newAliases;
            newAliases.SetSize(1);
            H323SetAliasAddress(destinationAlias, newAliases[0]);
            destination.SetNewAliases(newAliases);
        }
    }
}
#endif // HAS_JSON


CatchAllPolicy::CatchAllPolicy()
{
	m_name = "CatchAll";
	m_iniSection = "Routing::CatchAll";
}

void CatchAllPolicy::LoadConfig(const PString & instance)
{
	m_catchAllAlias = GkConfig()->GetString(m_iniSection, "CatchAllAlias", "catchall");
	m_catchAllIP = GkConfig()->GetString(m_iniSection, "CatchAllIP", "");
	if (!m_catchAllIP.IsEmpty()) {
		PStringArray parts = SplitIPAndPort(m_catchAllIP, GK_DEF_ENDPOINT_SIGNAL_PORT);
		if (IsIPv6Address(parts[0])) {
			m_catchAllIP = "[" + parts[0] + "]:" + parts[1];
		} else {
			m_catchAllIP = parts[0] + ":" + parts[1];
		}
	}
}

bool CatchAllPolicy::OnRequest(AdmissionRequest & request)
{
    bool updateAlias = false;
    bool result = CatchAllRoute(request, updateAlias);
    if (updateAlias) {
		request.SetFlag(RoutingRequest::e_aliasesChanged);
        H225_AdmissionRequest & arq = request.GetRequest();
		arq.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
		arq.m_destinationInfo.SetSize(1);
		H323SetAliasAddress(m_catchAllAlias, arq.m_destinationInfo[0]);
    }
    return result;
}

bool CatchAllPolicy::OnRequest(LocationRequest & request)
{
    bool updateAlias = false;
    bool result = CatchAllRoute(request, updateAlias);
    if (updateAlias) {
		request.SetFlag(RoutingRequest::e_aliasesChanged);
        H225_LocationRequest & lrq = request.GetRequest();
		lrq.m_destinationInfo.SetSize(1);
		H323SetAliasAddress(m_catchAllAlias, lrq.m_destinationInfo[0]);
    }
    return result;
}

bool CatchAllPolicy::OnRequest(SetupRequest & request)
{
    bool updateAlias = false;
    bool result = CatchAllRoute(request, updateAlias);
    if (updateAlias) {
		request.SetFlag(RoutingRequest::e_aliasesChanged);
		H225_Setup_UUIE & setup = request.GetRequest();
		setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
		setup.m_destinationAddress.SetSize(1);
		H323SetAliasAddress(m_catchAllAlias, setup.m_destinationAddress[0]);
    }
    return result;
}

bool CatchAllPolicy::CatchAllRoute(RoutingRequest & request, bool & updateAlias) const
{
	if (!m_catchAllIP.IsEmpty()) {
		H225_TransportAddress destAddr;
		if (GetTransportAddress(m_catchAllIP, GK_DEF_UNICAST_RAS_PORT, destAddr)) {
			Route route("catchall", destAddr, 999);
			route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
			request.AddRoute(route);
			return (m_next == NULL);
		} else {
			PTRACE(1, m_name << "\tInvalid catch-all IP " << m_catchAllIP);
		}
	}
	H225_ArrayOf_AliasAddress find_aliases;
	find_aliases.SetSize(1);
	H323SetAliasAddress(m_catchAllAlias, find_aliases[0]);
	endptr ep = RegistrationTable::Instance()->FindByAliases(find_aliases);
	if (ep) {
		if (ep->GetEndpointType().HasOptionalField(H225_EndpointType::e_gateway)) {
			Route route(m_name,ep->GetCallSignalAddress(), 999);
			route.m_destEndpoint = ep;
			request.AddRoute(route);
		} else {
			Route route(m_name, ep, 999);
			request.AddRoute(route);
		}
		// rewrite destination alias
		updateAlias = true;
		return (m_next == NULL);
	}
	PTRACE(1, m_name << "\tCatch-all endpoint " << m_catchAllAlias << " not found!");
	return false;	// configured default endpoint not found
}



URIServicePolicy::URIServicePolicy()
{
	m_name = "URIService";
	m_iniSection = "Routing::URIService";
}

void URIServicePolicy::LoadConfig(const PString & instance)
{
	PStringToString routes = GkConfig()->GetAllKeyValues(m_iniSection);
	for (PINDEX i = 0; i < routes.GetSize(); i++) {
		PString service = routes.GetKeyAt(i);
		PString gwDestination = routes.GetDataAt(i);
		PStringArray parts = SplitIPAndPort(gwDestination, GK_DEF_ENDPOINT_SIGNAL_PORT);
		PString dom = parts[0];
		PIPSocket::Address addr;
		if (PIPSocket::GetHostAddress(dom, addr))
			dom = addr.AsString();
		WORD port = (WORD)parts[1].AsUnsigned();
		H225_TransportAddress dest;
		if (!GetTransportAddress(dom, port, dest)) {
			PTRACE(4, "ROUTING\tPolicy " << m_name << " " << service << " Could not resolve " << gwDestination);
			continue;
		}
		m_uriServiceRoute.insert(make_pair(service, dest));
	}
}

bool URIServicePolicy::OnRequest(AdmissionRequest & request)
{
    return URIServiceRoute(request, request.GetAliases());
}

bool URIServicePolicy::OnRequest(LocationRequest & request)
{
    return URIServiceRoute(request, request.GetAliases());
}

bool URIServicePolicy::OnRequest(SetupRequest & request)
{
    return URIServiceRoute(request, request.GetAliases());
}

bool URIServicePolicy::URIServiceRoute(RoutingRequest & request, H225_ArrayOf_AliasAddress * aliases) const
{
	if (!aliases)
		return false;

	for (PINDEX a = 0; a < aliases->GetSize(); a++) {
		PString alias = H323GetAliasAddressString((*aliases)[a]);
		PINDEX colon = alias.Find(":");
		if (colon == 0 || colon == P_MAX_INDEX)
			continue;

		PString service = alias.Left(colon);
		std::map<PString,H225_TransportAddress>::const_iterator i = m_uriServiceRoute.find(service);
		if (i == m_uriServiceRoute.end())
			continue;

		H225_TransportAddress destination = i->second;
		PString newAlias = alias.Mid(colon+1);
		request.SetFlag(RoutingRequest::e_aliasesChanged);
		H323SetAliasAddress(newAlias, (*aliases)[a]);

		PString domain = newAlias;
		PINDEX at = newAlias.Find("@");
		if (at != P_MAX_INDEX)  // URL Schema
			domain = newAlias.Mid(at+1);

		if (!IsIPAddress(domain)   // Not an IP address
			&& (domain.FindRegEx(PRegularExpression(":[0-9]+$", PRegularExpression::Extended)) == P_MAX_INDEX)) {
			PTRACE(4, "ROUTING\tPolicy " << m_name << " " << service << " store destination for " << alias << " to " << AsString(destination));
			request.SetServiceType(service);
			request.SetGatewayDestination(destination);
			return false;  // Fall through to the next
		}

		// add a route and stop going any further
		PTRACE(4, "ROUTING\tPolicy " << m_name << " " << service << " set destination for " << alias << " to " << AsString(destination));
		Route * route = new Route(m_name, destination);
		route->m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(destination);
		request.AddRoute(*route);
		delete route;
		return true;
	}

	// No route found
	return false;
}


namespace { // anonymous namespace
	SimpleCreator<ExplicitPolicy> ExplicitPolicyCreator("explicit");
	SimpleCreator<InternalPolicy> InternalPolicyCreator("internal");
	SimpleCreator<ParentPolicy> ParentPolicyCreator("parent");
	SimpleCreator<DNSPolicy> DNSPolicyCreator("dns");
	SimpleCreator<VirtualQueuePolicy> VirtualQueuePolicyCreator("vqueue");
	SimpleCreator<NumberAnalysisPolicy> NumberAnalysisPolicyCreator("numberanalysis");
	SimpleCreator<ENUMPolicy> ENUMPolicyCreator("enum");
	SimpleCreator<SqlPolicy> SqlPolicyCreator("sql");
	SimpleCreator<HttpPolicy> HttpPolicyCreator("http");
	SimpleCreator<CatchAllPolicy> CatchAllPolicyCreator("catchall");
	SimpleCreator<URIServicePolicy> URISevicePolicyCreator("uriservice");
}


} // end of namespace Routing
