//////////////////////////////////////////////////////////////////
//
// Routing Mechanism for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2003
// Copyright (c) 2004-2012, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

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
#include "config.h"

#ifdef HAS_H46023
  #include <h460/h4601.h>
#endif

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

bool DNSPolicy::m_resolveNonLocalLRQs = true;

Route::Route() : m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_priority(DEFAULT_ROUTE_PRIORITY)
{
	m_destAddr.SetTag(H225_TransportAddress::e_nonStandardAddress);	// set to an invalid address
	Toolkit::Instance()->SetRerouteCauses(m_rerouteCauses);
}

Route::Route(
	const PString & policyName,
	const endptr & destEndpoint,
	unsigned priority
	) : m_destAddr(destEndpoint ? destEndpoint->GetCallSignalAddress() : H225_TransportAddress()), m_destEndpoint(destEndpoint), m_policy(policyName),
	m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_priority(priority)
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
	) : m_destAddr(destAddr), m_policy(policyName), m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_priority(priority)
{
	Toolkit::Instance()->SetRerouteCauses(m_rerouteCauses);
}

Route::Route(
	const PString & policyName,
	const PIPSocket::Address & destIpAddr,
	WORD destPort,
	unsigned priority
	) : m_destAddr(SocketToH225TransportAddr(destIpAddr, destPort)),
	m_policy(policyName), m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_priority(priority)
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

// class RoutingRequest
RoutingRequest::RoutingRequest()
	: m_reason(-1), m_flags(0)
{
}

RoutingRequest::RoutingRequest(
	const std::list<Route> &failedRoutes
	)
	: m_reason(-1), m_flags(0), m_failedRoutes(failedRoutes)
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
		PTRACE(1, "ROUTING\tInvalid destination address: " << route.m_destAddr);
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

bool Policy::Handle(SetupRequest& request)
{
	if( IsActive() ) {
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
	if( IsActive() ) {
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
				rules[prefixes[k]] = Create(cfgs.GetDataAt(j));
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
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[2]);
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
	Rules::iterator iter, biter, eiter;
	iter = biter = rules.begin(), eiter = rules.end();
	if (aliases && aliases->GetSize() > 0) {
		for (PINDEX i = 0; i < aliases->GetSize(); ++i) {
			const H225_AliasAddress & alias = (*aliases)[i];
			iter = rules.find(alias.GetTagName());
			if (iter != eiter)
				break;
			PString destination(AsString(alias, false));
			while (iter != biter) {
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
	H225_Setup_UUIE &setup = request.GetRequest();
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
	: roundRobin(Toolkit::AsBool(GkConfig()->GetString("RasSrv::ARQFeatures", "RoundRobinGateways", "1")))
{
	m_name = "Internal";
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

bool InternalPolicy::FindByAliases(
	RoutingRequest &request, 
	H225_ArrayOf_AliasAddress &aliases
	)
{
	list<Route> routes;
	RegistrationTable::Instance()->FindEndpoint(aliases, roundRobin, true, routes);
	list<Route>::iterator i = routes.begin();
	while (i != routes.end()) {
		i->m_policy = m_name;
		request.AddRoute(*i++);
	}
	return !routes.empty();
}

bool InternalPolicy::FindByAliases(
	LocationRequest& request,
	H225_ArrayOf_AliasAddress & aliases
	)
{
	// do not apply round robin selection for Location ReQuests
	list<Route> routes;
	if (RegistrationTable::Instance()->FindEndpoint(aliases, false, true, routes))
		request.SetRejectReason(H225_LocationRejectReason::e_resourceUnavailable);
		
	list<Route>::iterator i = routes.begin();
	while (i != routes.end()) {
		i->m_policy = m_name;
		request.AddRoute(*i++);
	}
	return !routes.empty();
}

bool InternalPolicy::FindByAliases(
	SetupRequest& request,
	H225_ArrayOf_AliasAddress & aliases
	)
{
	list<Route> routes;
	if (RegistrationTable::Instance()->FindEndpoint(aliases, roundRobin, true, routes))
		request.SetRejectReason(H225_ReleaseCompleteReason::e_gatewayResources);
		
	list<Route>::iterator i = routes.begin();
	while (i != routes.end()) {
		i->m_policy = m_name;
		request.AddRoute(*i++);
	}
	return !routes.empty();
}

bool InternalPolicy::FindByAliases(
	AdmissionRequest& request,
	H225_ArrayOf_AliasAddress & aliases
	)
{
	list<Route> routes;
	if (RegistrationTable::Instance()->FindEndpoint(aliases, roundRobin, true, routes))
		request.SetRejectReason(H225_AdmissionRejectReason::e_resourceUnavailable);
		
	list<Route>::iterator i = routes.begin();
	while (i != routes.end()) {
		i->m_policy = m_name;
		request.AddRoute(*i++);
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
	m_resolveNonLocalLRQs = Toolkit::AsBool(GkConfig()->GetString("Routing::DNS", "ResolveNonLocalLRQ", "1"));
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

		PString domain = (at != P_MAX_INDEX) ? alias.Mid(at + 1) : alias;
		if (domain.Find("ip$") == 0)
			domain.Replace("ip$", "", false);
		PStringArray parts = SplitIPAndPort(domain, GK_DEF_ENDPOINT_SIGNAL_PORT);
		domain = parts[0];
		WORD port = (WORD)parts[1].AsUnsigned();
		PIPSocket::Address addr;
		if (DNSLookup(domain, addr) && addr.IsValid()) {
			H225_TransportAddress dest = SocketToH225TransportAddr(addr, port);
			if (Toolkit::Instance()->IsGKHome(addr)) {
				// check if the domain is my IP, if so route to local endpoint if available
				H225_ArrayOf_AliasAddress find_aliases;
				find_aliases.SetSize(1);
				H323SetAliasAddress(alias.Left(at), find_aliases[0]);
				endptr ep = RegistrationTable::Instance()->FindByAliases(find_aliases);
				if (ep) {
					dest = ep->GetCallSignalAddress();
				} else {
					continue;	// can't route this alias locally, try next alias
				}
			}
			Route route(m_name, dest);
			route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(dest);
			request.AddRoute(route);
			// remove the domain name part (should not be necessary with latest GnuGk as destination, but keep for older ones)
			H323SetAliasAddress(alias.Left(at), aliases[i]);
			request.SetFlag(RoutingRequest::e_aliasesChanged);
			PTRACE(4, "ROUTING\tDNS policy resolves to " << alias.Left(at) << " @ " << AsDotString(dest));
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

		PString domain = (at != P_MAX_INDEX) ? alias.Mid(at + 1) : alias;
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
				find_aliases.SetSize(1);
				H323SetAliasAddress(alias.Left(at), find_aliases[0]);
				endptr ep = RegistrationTable::Instance()->FindByAliases(find_aliases);
				if (ep) {
					if (!(RasServer::Instance()->IsGKRouted())) {
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
	:
	m_active(false),
	m_requestTimeout(DEFAULT_ROUTE_REQUEST_TIMEOUT*1000)
{
}

VirtualQueue::~VirtualQueue()
{
	m_listMutex.Wait();
	
	int numrequests = m_pendingRequests.size();
	if( numrequests ) {
		PTRACE(1,"VQueue\tDestroying virtual queue with "
			<< numrequests << " pending requests");
	}
	RouteRequests::iterator i = m_pendingRequests.begin();
	while (i != m_pendingRequests.end()) {
		RouteRequest *r = *i++;
		r->m_sync.Signal();
	}
	
	m_listMutex.Signal();

	// wait a moment to give a chance to pending requests to cleanup
	if( numrequests ) {
		PThread::Sleep(500);
	}
}

void VirtualQueue::OnReload()
{
	PWaitAndSignal lock(m_listMutex);
	
	m_requestTimeout = GkConfig()->GetInteger(
		CTIsection, 
		GkConfig()->HasKey(CTIsection,"RequestTimeout")
			? "RequestTimeout" : "CTI_Timeout", 
		DEFAULT_ROUTE_REQUEST_TIMEOUT
		) * 1000;
	m_requestTimeout = PMAX(100,m_requestTimeout);	// min wait: 100 msec

	m_active = false;

	m_virtualQueueAliases.RemoveAll();
	PString vqueues = GkConfig()->GetString(CTIsection, "VirtualQueueAliases", "");
	if( vqueues.IsEmpty() ) // backward compatibility
		vqueues = GkConfig()->GetString(CTIsection, "VirtualQueue", "");
	if( !vqueues.IsEmpty() ) {
		m_virtualQueueAliases = vqueues.Tokenise(" ,;\t", false);
		if( m_virtualQueueAliases.GetSize() > 0 ) {
			PTRACE(2,"VQueue\t(CTI) Virtual queues enabled (aliases:"<<vqueues
				<<"), request timeout: "<<m_requestTimeout/1000<<" s");
			m_active = true;
		}
	}

	m_virtualQueuePrefixes.RemoveAll();
	vqueues = GkConfig()->GetString(CTIsection, "VirtualQueuePrefixes", "");
	if( !vqueues.IsEmpty() ) {
		m_virtualQueuePrefixes = vqueues.Tokenise(" ,;\t", false);
		if( m_virtualQueuePrefixes.GetSize() > 0 ) {
			PTRACE(2,"VQueue\t(CTI) Virtual queues enabled (prefixes:"<<vqueues
				<<"), request timeout: "<<m_requestTimeout/1000<<" s");
			m_active = true;
		}
	}
	
	m_virtualQueueRegex = GkConfig()->GetString(CTIsection, "VirtualQueueRegex", "");
	if( !m_virtualQueueRegex.IsEmpty() ) {
		// check if regex is valid
		PRegularExpression regex(m_virtualQueueRegex, PRegularExpression::Extended);
		if(regex.GetErrorCode() != PRegularExpression::NoError) {
			PTRACE(2, "Error '"<< regex.GetErrorText() <<"' compiling regex: " << m_virtualQueueRegex);
			SNMP_TRAP(7, SNMPError, Configuration, "Invalid " + PString(CTIsection) + " configuration: compiling RegEx failed");
        } else {
			PTRACE(2,"VQueue\t(CTI) Virtual queues enabled (regex:"<<m_virtualQueueRegex
			<<"), request timeout: "<<m_requestTimeout/1000<<" s");
			m_active = true;
		}
	}
	
	if( !m_active ) {
		PTRACE(2,"VQueue\t(CTI) Virtual queues disabled - no virtual queues configured");
	}
}

bool VirtualQueue::SendRouteRequest(
	/// source IP of the request (endpoint for ARQ, gatekeeper for LRQ)
	const PString& source,
	/// calling endpoint
	const PString& epid,
	/// CRV (Call Reference Value) of the call associated with this request
	unsigned crv,
	/// destination (virtual queue) aliases as specified
	/// by the calling endpoint (modified by this function on successful return)
	H225_ArrayOf_AliasAddress* destinationInfo,
	/// destination (virtual queue) aliases as specified
	/// by the calling endpoint (modified by this function on successful return)
	PString* callSigAdr,
	/// bind IP for BindAndRouteToGateway
	PString* bindIP,
	/// caller ID
	PString* callerID,
	/// should the call be rejected modified by this function on return)
	bool & reject,
	/// actual virtual queue name (should be present in destinationInfo too)
	const PString& vqueue,
	/// a sequence of aliases for the calling endpoint
	/// (in the "alias:type[=alias:type]..." format)
	const PString& sourceInfo,
	/// the callID as string
	const PString& callID,
	/// the called IP for unregistered calls
	const PString& calledip,
	/// vendor string of caller
	const PString& vendorString
	)
{
	bool result = false;
	bool duprequest = false;
	if (RouteRequest *r = InsertRequest(epid, crv, callID, destinationInfo, callSigAdr, bindIP, callerID, duprequest)) {
		PString cid = callID;
		cid.Replace(" ", "-", true);
		PString msg = "RouteRequest|" + source
						+ "|" + epid
						+ "|" + PString(crv)
						+ "|" + vqueue
						+ "|" + sourceInfo
						+ "|" + cid
						+ "|" + calledip
						+ "|" + vendorString
						+ ";";
		// signal RouteRequest to the status line only once
		if( duprequest ) {
			PTRACE(4, "VQueue\tDuplicate request: "<<msg);
		} else {
			PTRACE(2, msg);
			GkStatus::Instance()->SignalStatus(msg + "\r\n", STATUS_TRACE_LEVEL_ROUTEREQ);
		}

		// wait for an answer from the status line (routetoalias,routetogateway,routereject)
		result = r->m_sync.Wait(m_requestTimeout);
		reject = r->m_reject;   // set reject status
		m_listMutex.Wait();
		m_pendingRequests.remove(r);
		m_listMutex.Signal();
		if( !result ) {
			PTRACE(5,"VQueue\tRoute request (EPID: " << r->m_callingEpId
				<< ", CRV=" << r->m_crv << ") timed out");
		}
		delete r;
	}
	return result;
}

bool VirtualQueue::IsDestinationVirtualQueue(
	const PString& destinationAlias /// alias to be matched
	) const
{
	PWaitAndSignal lock(m_listMutex);
	PINDEX i;
	for (i = 0; i < m_virtualQueueAliases.GetSize(); ++i)
		if (m_virtualQueueAliases[i] == destinationAlias)
			return true;
	for (i = 0; i < m_virtualQueuePrefixes.GetSize(); ++i)
		if (destinationAlias.Find(m_virtualQueuePrefixes[i]) == 0)
			return true;
	
	return (!m_virtualQueueRegex.IsEmpty())
		&& Toolkit::MatchRegex(destinationAlias,m_virtualQueueRegex);
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
	bool reject
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
			}
			r->m_reject = reject;
			r->m_sync.Signal();
			if (!foundrequest) {
				foundrequest = true;
				if (!reject) {
					PTRACE(2,"VQueue\tRoute request (EPID:" << callingEpId
						<< ", CRV=" << crv << ") accepted by agent " << AsString(agent));
				} else {
					PTRACE(2,"VQueue\tRoute request (EPID:" << callingEpId
						<< ", CRV=" << crv << ") rejected");
				}
			}
		}
		++i;
	}
	
	if( !foundrequest ) {
		PTRACE(4, "VQueue\tPending route request (EPID:" << callingEpId
			<< ", CRV=" << crv << ") not found - ignoring RouteToAlias / RouteToGateway / BindAndRouteToGateway command");
	}
	
	return foundrequest;
}

bool VirtualQueue::RouteToAlias(
	/// alias for the routing target that
	/// will replace the original destination info
	const PString& targetAlias, 
	/// will replace the original destinationCallSignallAddress
	const PString& destinationIp, 
	/// identifier of the endpoint associated with the route request
	const PString& callingEpId, 
	/// CRV for the call associated with the route request
	unsigned crv,
	/// callID of the call associated with the route request
	const PString& callID,
	// outgoing IP or empty
	const PString& bindIP,
	// callerID or empty
	const PString& callerID,
	/// should this call be rejected
	bool reject
	)
{
	H225_ArrayOf_AliasAddress alias;
	if (targetAlias != "" && targetAlias != "-") {
		alias.SetSize(1);
		H323SetAliasAddress(targetAlias, alias[0]);
	}
	return RouteToAlias(alias, destinationIp, callingEpId, crv, callID, bindIP, callerID, reject);
}

bool VirtualQueue::RouteReject(
	/// identifier of the endpoint associated with the route request
	const PString& callingEpId, 
	/// CRV of the call associated with the route request
	unsigned crv,
	/// callID of the call associated with the route request
	const PString& callID
	)
{
	H225_ArrayOf_AliasAddress nullAgent;
	return RouteToAlias(nullAgent, "", callingEpId, crv, callID, "", "", true);
}

VirtualQueue::RouteRequest* VirtualQueue::InsertRequest(
	/// identifier for the endpoint associated with this request
	const PString& callingEpId,
	/// CRV for the call associated with this request
	unsigned crv,
	/// callID for the call associated with this request
	const PString& callID,
	/// a pointer to an array to be filled with agent aliases
	/// when the routing decision has been made
	H225_ArrayOf_AliasAddress* agent,
	/// a pointer to a string  to be filled with a destinationCallSignalAddress
	/// when the routing decision has been made (optional)
	PString* callSigAdr,
	/// bind IP for BindAndRouteToGateway
	PString* bindIP,
	/// caller ID
	PString* callerID,
	/// set by the function to true if another route request for the same
	/// call is pending
	bool& duplicate
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
	
	if( duprequests ) {
		duplicate = true;
		PTRACE(5,"VQueue\tRoute request (EPID: "<<callingEpId
			<<", CRV="<<crv<<") is already active - duplicate requests"
			" waiting: "<<duprequests
			);
	}

	// insert the new pending route request
	RouteRequest* r = new RouteRequest(callingEpId, crv, callID, agent, callSigAdr, bindIP, callerID);
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
	H225_ArrayOf_AliasAddress *aliases = NULL;
	PString vq = "";
	if ((aliases = request.GetAliases()))
		vq = AsString((*aliases)[0], FALSE);
	if (m_vqueue->IsDestinationVirtualQueue(vq)) {
		H225_AdmissionRequest & arq = request.GetRequest();
		PTRACE(5,"Routing\tPolicy " << m_name << " destination matched "
			"a virtual queue " << vq << " (ARQ " << arq.m_requestSeqNum.GetValue() << ')');
		endptr ep = RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier); // should not be null
		if (ep) {
			PString source = AsDotString(ep->GetCallSignalAddress());
			PString epid = ep->GetEndpointIdentifier().GetValue();
			PString * callSigAdr = new PString();
			PString * bindIP = new PString();
			PString * callerID = new PString();
			PString calledIP = "unknown";
			PString vendorInfo;
			if (arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
				calledIP = AsDotString(arq.m_destCallSignalAddress, false);
			}
			if (ep->GetEndpointType().HasOptionalField(H225_EndpointType::e_vendor)) {
				if (ep->GetEndpointType().m_vendor.HasOptionalField(H225_VendorIdentifier::e_productId)) {
					vendorInfo += ep->GetEndpointType().m_vendor.m_productId.AsString();
				}
				if (ep->GetEndpointType().m_vendor.HasOptionalField(H225_VendorIdentifier::e_versionId)) {
					vendorInfo += ep->GetEndpointType().m_vendor.m_versionId.AsString();
				}
			}

			if (m_vqueue->SendRouteRequest(source, epid, unsigned(arq.m_callReferenceValue), aliases, callSigAdr, bindIP, callerID, reject, vq, AsString(arq.m_srcInfo), AsString(arq.m_callIdentifier.m_guid), calledIP, vendorInfo))
				request.SetFlag(RoutingRequest::e_aliasesChanged);
			if (reject) {
				request.SetFlag(RoutingRequest::e_Reject);
			}
			request.SetSourceIP(*bindIP);
			request.SetCallerID(*callerID);
			if (!callSigAdr->IsEmpty()) {
				if (!arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
					arq.IncludeOptionalField(H225_AdmissionRequest::e_destCallSignalAddress);
				}
				PStringArray adr_parts = SplitIPAndPort(*callSigAdr, GK_DEF_ENDPOINT_SIGNAL_PORT);
				PString ip = adr_parts[0];
				WORD port = (WORD)(adr_parts[1].AsInteger());
				arq.m_destCallSignalAddress = SocketToH225TransportAddr(ip, port);
			}
			delete callSigAdr;
			delete bindIP;
			delete callerID;
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
	if (H225_ArrayOf_AliasAddress *aliases = request.GetAliases()) {
		const PString vq(AsString((*aliases)[0], false));
		if (m_vqueue->IsDestinationVirtualQueue(vq)) {
			H225_LocationRequest & lrq = request.GetRequest();
			PTRACE(5,"Routing\tPolicy " << m_name << " destination matched "
				"a virtual queue " << vq << " (LRQ "
				<< lrq.m_requestSeqNum.GetValue() << ')'
				);

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
			PString sourceInfo = "";
			if (lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo) && (lrq.m_sourceInfo.GetSize() > 0))
				sourceInfo = AsString(lrq.m_sourceInfo);
			PString callID = "-";	/* not available for LRQs */
			if (m_vqueue->SendRouteRequest(source, epid, unsigned(lrq.m_requestSeqNum), aliases, callSigAdr, bindIP, callerID, reject, vq, sourceInfo, callID))
				request.SetFlag(RoutingRequest::e_aliasesChanged);
			if (reject) {
				request.SetFlag(RoutingRequest::e_Reject);
			}
			request.SetSourceIP(*bindIP);
			request.SetCallerID(*callerID);
			if (!reject && !callSigAdr->IsEmpty()) {
				// 'explicit' policy can't handle LRQs, so we do it directly
				PStringArray adr_parts = SplitIPAndPort(*callSigAdr, GK_DEF_ENDPOINT_SIGNAL_PORT);
				PString ip = adr_parts[0];
				WORD port = (WORD)(adr_parts[1].AsInteger());
				Route route("vqueue", SocketToH225TransportAddr(ip, port));
				route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(
					route.m_destAddr
				);
				request.AddRoute(route);					
				delete callSigAdr;
				delete bindIP;
				delete callerID;
				return true;	// stop processing
			}
			delete callSigAdr;
			delete bindIP;
			delete callerID;
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
		PString callid = AsString(setup.m_callIdentifier.m_guid);
		H225_AliasAddress srcAlias;
		// convert caller string back to alias to get alias type
		H323SetAliasAddress(request.GetCallingStationId(), srcAlias);
		PString src = AsString(srcAlias);
		PIPSocket::Address localAddr;
		WORD localPort;
		request.GetWrapper()->GetLocalAddr(localAddr, localPort);
		PString calledIP = localAddr;
		PString vendorInfo;
		if (setup.m_sourceInfo.HasOptionalField(H225_EndpointType::e_vendor)) {
			if (setup.m_sourceInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_productId)) {
				vendorInfo += setup.m_sourceInfo.m_vendor.m_productId.AsString();
			}
			if (setup.m_sourceInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_versionId)) {
				vendorInfo += setup.m_sourceInfo.m_vendor.m_versionId.AsString();
			}
			vendorInfo.Replace("|", "", true);
		}
		PTRACE(5,"Routing\tPolicy " << m_name << " destination matched "
			"a virtual queue " << vq << " (Setup "
			<< crv << ')'
			);

		if (m_vqueue->SendRouteRequest(callerip, epid, crv, aliases, callSigAdr, bindIP, callerID, reject, vq, src, callid, calledIP, vendorInfo))
			request.SetFlag(RoutingRequest::e_aliasesChanged);
		
		if (reject) {
			request.SetFlag(RoutingRequest::e_Reject);
		}
		request.SetSourceIP(*bindIP);
		request.SetCallerID(*callerID);
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
			PString ip = adr_parts[0];
			WORD port = (WORD)(adr_parts[1].AsInteger());
			setup.m_destCallSignalAddress = SocketToH225TransportAddr(ip, port);
		}
		delete callSigAdr;
		delete bindIP;
		delete callerID;
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

	PConfig *cfg = GkConfig();
	PStringToString kv = cfg->GetAllKeyValues("Routing::NumberAnalysis");
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
		ostream &strm = PTrace::Begin(6, __FILE__, __LINE__);
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
	m_resolveLRQs = Toolkit::AsBool(GkConfig()->GetString("Routing::ENUM", "ResolveLRQ", "0"));
}

bool ENUMPolicy::FindByAliases(RoutingRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
#if P_DNS
	for (PINDEX i = 0; i < aliases.GetSize(); ++i) {
		PString alias(AsString(aliases[i], FALSE));

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
			if (PDNS::ENUMLookup(alias, "E2U+h323", str)) {
				if (str.Left(5) *= "h323:")
					str = str.Mid(5);
				PTRACE(4, "\tENUM converted remote party " << alias << " to " << str);
				request.SetFlag(RoutingRequest::e_aliasesChanged);
				H323SetAliasAddress(str, aliases[i]);
		  	}
		}
	}
#else
	PTRACE(4, "\tENUM policy unavailable as no DNS support.");
#endif

	return false;
}

bool ENUMPolicy::FindByAliases(LocationRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	if (m_resolveLRQs) {
		return ENUMPolicy::FindByAliases((RoutingRequest&)request, aliases);
	} else {
		PTRACE(4, "ROUTING\tPolicy ENUM configured not to resolve LRQs");
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
		if (aliases && !aliases->GetSize() == 0)
			calledAlias = AsString((*aliases)[0], FALSE);
		PString calledIP = "";	/* not available for ARQs */
		PString caller = AsString(arq.m_srcInfo, FALSE);
		PString callingStationId = request.GetCallingStationId();
		PString callid = AsString(arq.m_callIdentifier.m_guid);
		PString messageType = "ARQ";
		PString clientauthid = request.GetClientAuthId();
		DestinationRoutes destination;

		RunPolicy(	/* in */ source, calledAlias, calledIP, caller, callingStationId, callid, messageType, clientauthid,
						/* out: */ destination);

		if (destination.RejectCall()) {
			request.SetFlag(RoutingRequest::e_Reject);
			request.SetRejectReason(destination.GetRejectReason());
		}

		if (destination.ChangeAliases()) {
			request.SetFlag(RoutingRequest::e_aliasesChanged);
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
			PTRACE(3, "WARNING: Sender can't map destination alias via SqlPolicy");
	}
	PString source = AsDotString(lrq.m_replyAddress);
	PString calledAlias = "";
	if (aliases && !aliases->GetSize() == 0)
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
	DestinationRoutes destination;

	RunPolicy(	/* in */ source, calledAlias, calledIP, caller, callingStationId,callid, messageType, clientauthid,
					/* out: */ destination);

	if (destination.RejectCall()) {
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
	if (request.GetAliases() && (!request.GetAliases()->GetSize() == 0)) {
		calledAlias = AsString((*request.GetAliases())[0], FALSE);
	}
	PIPSocket::Address localAddr;
	WORD localPort;
	request.GetWrapper()->GetLocalAddr(localAddr, localPort);
	PString calledIP = localAddr;	// TODO: only correct if a gatekeeper IP was called, should we use explicit IP if present ?
	PString caller = request.GetCallingStationId();
	PString callingStationId = request.GetCallingStationId();
	PString callid = AsString(setup.m_callIdentifier.m_guid);
	PString messageType = "Setup";
	PString clientauthid = request.GetClientAuthId();
	DestinationRoutes destination;

	RunPolicy(	/* in */ source, calledAlias, calledIP, caller, callingStationId, callid, messageType, clientauthid,
					/* out: */ destination);

	if (destination.RejectCall()) {
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
#if HAS_DATABASE
	m_active = true;
	static const char *sqlsection = "Routing::Sql";
	m_name = "SqlPolicy";
	m_timeout = -1;

	PConfig* cfg = GkConfig();

	const PString driverName = cfg->GetString(sqlsection, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"no SQL driver selected");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		m_active = false;
		return;
	}

	m_sqlConn = GkSQLConnection::Create(driverName, m_name);
	if (m_sqlConn == NULL) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"could not find " << driverName << " database driver");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		m_active = false;
		return;
	}

	m_query = cfg->GetString(sqlsection, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"no query configured");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		m_active = false;
		return;
	} else
		PTRACE(4, m_name << "\tQuery: " << m_query);
		
	if (!m_sqlConn->Initialize(cfg, sqlsection)) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"could not connect to the database");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		return;
	}
#else
	PTRACE(1, m_name << " not available - no database driver compiled into GnuGk");
#endif // HAS_DATABASE
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
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, params, m_timeout);
	if (result == NULL) {
		PTRACE(2, m_name << ": query failed - timeout or fatal error");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " query failed");
		return;
	}

	if (!result->IsValid()) {
		PTRACE(2, m_name << ": query failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage());
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " query failed");
		delete result;
		return;
	}
	
	if (result->GetNumRows() < 1)
		PTRACE(3, m_name << ": query returned no rows");
	else if (result->GetNumFields() < 1)
		PTRACE(2, m_name << ": bad query - "
			"no columns found in the result set"
			);
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
				PString ip = adr_parts[0];
				WORD port = (WORD)(adr_parts[1].AsInteger());

				Route route("Sql", SocketToH225TransportAddr(ip, port));
				route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
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
			H323SetAliasAddress(newDestinationAlias, newAliases[0]);
			destination.SetNewAliases(newAliases);
			int row = 0;
			do {
				PString destinationAlias = resultRow[0].first;
				PString destinationIp = resultRow[1].first;
				PStringArray adr_parts = SplitIPAndPort(destinationIp, GK_DEF_ENDPOINT_SIGNAL_PORT);
				PString ip = adr_parts[0];
				WORD port = (WORD)(adr_parts[1].AsInteger());

				Route route("Sql", SocketToH225TransportAddr(ip, port));
				route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
				route.m_destNumber = destinationAlias;
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


#ifdef hasLUA
LuaPolicy::LuaPolicy()
{
	static const char * luasection = "Routing::Lua";
	m_name = "LuaPolicy";
	m_active = false;

	PConfig* cfg = GkConfig();

	m_script = cfg->GetString(luasection, "Script", "");
	if (m_script.IsEmpty()) {
		PString scriptFile = cfg->GetString(luasection, "ScriptFile", "");
		if (!scriptFile.IsEmpty()) {
			PTextFile f(scriptFile, PFile::ReadOnly);
			if (!f.IsOpen()) {
				PTRACE(1, "Can't read LUA script " << scriptFile);
			} else {
				PString line;
				while (f.ReadLine(line)) {
					m_script += (line + "\n"); 
				}
			}
		}
	}

	if (m_script.IsEmpty()) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			<< "\tno LUA script");
		SNMP_TRAP(4, SNMPError, General, PString(m_name) + " creation failed");
		return;
	}
	m_active = true;
}

LuaPolicy::~LuaPolicy()
{
}

void LuaPolicy::RunPolicy(
		/* in */
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType,
		const PString & clientauthid,
		/* out: */
		DestinationRoutes & destination)
{
	m_lua.SetValue("source", source);
	m_lua.SetValue("calledAlias", calledAlias);
	m_lua.SetValue("calledIP", calledIP);
	m_lua.SetValue("caller", caller);
	m_lua.SetValue("callingStationId", callingStationId);
	m_lua.SetValue("callid", callid);
	m_lua.SetValue("messageType", messageType);
	m_lua.SetValue("clientauthid", clientauthid);

	m_lua.Run(m_script);

	PString action = m_lua.GetValue("action");
	PString rejectCode = m_lua.GetValue("rejectCode");
	PString destAlias = m_lua.GetValue("destAlias");
	PString destIP = m_lua.GetValue("destIP");

	if (action.ToUpper() == "SKIP") {
		PTRACE(5, m_name << "\tSkipping to next policy");
		return;
	}

	if (action.ToUpper() == "REJECT") {
		PTRACE(5, m_name << "\tRejecting call");
		destination.SetRejectCall(true);
		if (!rejectCode.IsEmpty()) {
			destination.SetRejectReason(rejectCode.AsInteger());
		}
		return;
	}

	if (!destAlias.IsEmpty()) {
		PTRACE(5, m_name << "\tSet new destination alias " << destAlias);
		H225_ArrayOf_AliasAddress newAliases;
		newAliases.SetSize(1);
		H323SetAliasAddress(destAlias, newAliases[0]);
		destination.SetNewAliases(newAliases);
	}

	if (!destIP.IsEmpty()) {
		PTRACE(5, m_name << "\tSet new destination IP " << destIP);
		PStringArray adr_parts = SplitIPAndPort(destIP, GK_DEF_ENDPOINT_SIGNAL_PORT);
		PString ip = adr_parts[0];
		WORD port = (WORD)(adr_parts[1].AsInteger());

		Route route("Lua", SocketToH225TransportAddr(ip, port));
		route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
		if (!destAlias.IsEmpty())
			route.m_destNumber = destAlias;
		destination.AddRoute(route);
	}
}

#endif // hasLUA


CatchAllPolicy::CatchAllPolicy()
{
	m_name = "CatchAllPolicy";
	static const char *defaultPolicySection = "Routing::CatchAll";
	PConfig* cfg = GkConfig();
	m_catchAllAlias = cfg->GetString(defaultPolicySection, "CatchAllAlias", "catchall");
	m_catchAllIP = cfg->GetString(defaultPolicySection, "CatchAllIP", "");
	if (!m_catchAllIP.IsEmpty()) {
		PStringArray parts = SplitIPAndPort(m_catchAllIP, GK_DEF_ENDPOINT_SIGNAL_PORT);
		if (IsIPv6Address(parts[0])) {
			m_catchAllIP = "[" + parts[0] + "]:" + parts[1];
		} else {
			m_catchAllIP = parts[0] + ":" + parts[1];
		}
	}
}

bool CatchAllPolicy::CatchAllRoute(RoutingRequest & request) const
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
		Route route("catchall", ep, 999);
		request.AddRoute(route);
		return (m_next == NULL);
	}
	PTRACE(1, m_name << "\tCatch-all endpoint " << m_catchAllAlias << " not found!");
	return false;	// configured default endpoint not found
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
#ifdef hasLUA
	SimpleCreator<LuaPolicy> LuaPolicyCreator("lua");
#endif
	SimpleCreator<CatchAllPolicy> CatchAllPolicyCreator("catchall");
}


} // end of namespace Routing
