//////////////////////////////////////////////////////////////////
//
// Routing Mechanism for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 06/18/2003
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <ptclib/enum.h>
#include <h323pdu.h>
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "stl_supp.h"
#include "RasTbl.h"
#include "RasSrv.h"
#include "GkClient.h"
#include "GkStatus.h"
#include "sigmsg.h"
#include "Routing.h"
#include "gksql.h"
#include "config.h"

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

const long DEFAULT_ROUTE_REQUEST_TIMEOUT = 10;
const char* const CTIsection = "CTI::Agents";

Route::Route() : m_proxyMode(CallRec::ProxyDetect), m_flags(0)
{
	Toolkit::Instance()->SetRerouteCauses(m_rerouteCauses);
}

Route::Route(
	const endptr &destEndpoint
	) : m_destAddr(destEndpoint->GetCallSignalAddress()), m_destEndpoint(destEndpoint),
	m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_destNumber(""), m_destOutNumber("")
{
	Toolkit::Instance()->SetRerouteCauses(m_rerouteCauses);
}

Route::Route(
	const PString &policyName,
	const H225_TransportAddress &destAddr
	) : m_destAddr(destAddr), m_policy(policyName), m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_destNumber(""), m_destOutNumber("")
{
	Toolkit::Instance()->SetRerouteCauses(m_rerouteCauses);
}

Route::Route(
	const PString &policyName,
	const PIPSocket::Address &destIpAddr,
	WORD destPort
	) : m_destAddr(SocketToH225TransportAddr(destIpAddr, destPort)),
	m_policy(policyName), m_proxyMode(CallRec::ProxyDetect), m_flags(0), m_destNumber(""), m_destOutNumber("")
{
	Toolkit::Instance()->SetRerouteCauses(m_rerouteCauses);
}

PString Route::AsString() const
{
	return AsDotString(m_destAddr) + " (policy: " + m_policy + ", proxy: "
		+ PString(m_proxyMode) + ", flags: " + PString(m_flags) + ", Called-Station-Id: " + m_destNumber
		+ ", Called-Station-Id-Out: " + m_destOutNumber + ")";
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

bool RoutingRequest::AddRoute(
	const Route &route
	)
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
	return true;
}

bool RoutingRequest::GetFirstRoute(
	Route &route
	)
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

// class LocationRequest
template<> H225_ArrayOf_AliasAddress *LocationRequest::GetAliases()
{
	return (m_request.m_destinationInfo.GetSize() > 0)
		? &m_request.m_destinationInfo : NULL;
}

// class SetupRequest
template<> H225_ArrayOf_AliasAddress *SetupRequest::GetAliases()
{
	return (m_request.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) && m_request.m_destinationAddress.GetSize() > 0)
		? &m_request.m_destinationAddress : NULL;
}

// class FacilityRequest
template<> H225_ArrayOf_AliasAddress *FacilityRequest::GetAliases()
{
	return (m_request.HasOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress) && m_request.m_alternativeAliasAddress.GetSize() > 0)
		? &m_request.m_alternativeAliasAddress : NULL;
}

bool Policy::Handle(SetupRequest& request)
{
	if( IsActive() ) {
#if PTRACING
		const PString tagname = request.GetWrapper()->GetTagName();
		const unsigned crv = request.GetWrapper()->GetCallReference();
		PTRACE(5, "ROUTING\tChecking policy " << m_name
			<< " for request " << tagname << " CRV=" << crv
			);
#endif
		if (OnRequest(request)) {
#if PTRACING
			PTRACE(5, "ROUTING\tPolicy " << m_name
				<< " applied to the request " << tagname << " CRV=" << crv
				);
#endif
			return true;
		}
	}
	return m_next && m_next->Handle(request);
}

bool Policy::Handle(FacilityRequest& request)
{
	if( IsActive() ) {
#if PTRACING
		const PString tagname = request.GetWrapper()->GetTagName();
		const unsigned crv = request.GetWrapper()->GetCallReference();
		PTRACE(5, "ROUTING\tChecking policy " << m_name
			<< " for request " << tagname << " CRV=" << crv
			);
#endif
		if (OnRequest(request)) {
#if PTRACING
			PTRACE(5, "ROUTING\tPolicy " << m_name
				<< " applied to the request " << tagname << " CRV=" << crv
				);
#endif
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
	return policy ? policy->HandleRas(request) : false;
}

bool Analyzer::Parse(LocationRequest & request)
{
	ReadLock lock(m_reloadMutex);
	request.SetRejectReason(H225_LocationRejectReason::e_requestDenied);
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[1]);
	return policy ? policy->HandleRas(request) : false;
}

bool Analyzer::Parse(SetupRequest & request)
{
	ReadLock lock(m_reloadMutex);
	request.SetRejectReason(H225_ReleaseCompleteReason::e_calledPartyNotRegistered);
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[2]);
	return policy ? policy->Handle(request) : false;
}

bool Analyzer::Parse(FacilityRequest & request)
{
	ReadLock lock(m_reloadMutex);
	request.SetRejectReason(H225_ReleaseCompleteReason::e_calledPartyNotRegistered);
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[3]);
	return policy ? policy->Handle(request) : false;
}

Policy *Analyzer::Create(const PString & cfg)
{
	return Policy::Create(cfg.ToLower().Tokenise(",;|", false));
}

Policy *Analyzer::ChoosePolicy(const H225_ArrayOf_AliasAddress *aliases, Rules & rules)
{
	// use rules.begin() as the default policy
	// since "*" has the minimum key value
	Rules::iterator iter, biter, eiter;
	iter = biter = rules.begin(), eiter = rules.end();
	if (aliases && aliases->GetSize() > 0)
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


// the simplest policy, the destination has been explicitly specified
class ExplicitPolicy : public Policy {
public:
	ExplicitPolicy() { m_name = "Explicit"; }
protected:
	virtual bool OnRequest(AdmissionRequest &);
	// the policy doesn't apply to LocationRequest
	virtual bool OnRequest(SetupRequest &);
	virtual bool OnRequest(FacilityRequest &);
};

bool ExplicitPolicy::OnRequest(AdmissionRequest & request)
{
	H225_AdmissionRequest & arq = request.GetRequest();
	if (arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
		Route route(m_name, arq.m_destCallSignalAddress);
		route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(
			route.m_destAddr
			);
		return request.AddRoute(route);
	}
	return false;
}

bool ExplicitPolicy::OnRequest(SetupRequest &request)
{
	H225_Setup_UUIE &setup = request.GetRequest();
	if (setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
		Route route(m_name, setup.m_destCallSignalAddress);
		route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(
			route.m_destAddr
			);
		return request.AddRoute(route);
	}
	return false;
}

bool ExplicitPolicy::OnRequest(FacilityRequest & request)
{
	H225_Facility_UUIE & facility = request.GetRequest();
	if (facility.HasOptionalField(H225_Facility_UUIE::e_alternativeAddress)) {
		Route route(m_name, facility.m_alternativeAddress);
		route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(
			route.m_destAddr
			);
		return request.AddRoute(route);
	}
	return false;
}


// the classical policy, find the dstionation from the RegistrationTable
class InternalPolicy : public AliasesPolicy {
public:
	InternalPolicy();

protected:
	virtual bool OnRequest(AdmissionRequest &);
	virtual bool OnRequest(SetupRequest &);

	virtual bool FindByAliases(RoutingRequest &, H225_ArrayOf_AliasAddress &);
	virtual bool FindByAliases(LocationRequest &, H225_ArrayOf_AliasAddress &);
	virtual bool FindByAliases(SetupRequest &, H225_ArrayOf_AliasAddress &);
	virtual bool FindByAliases(AdmissionRequest &, H225_ArrayOf_AliasAddress &);
	
private:
	bool roundRobin;
};

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


// a policy to route call to parent
// the policy was originally in GkClient.cxx,
// but damn VC has problem to instantiate the creator
class ParentPolicy : public Policy {
public:
	ParentPolicy();

private:
	// override from class Policy
	virtual bool IsActive() const;

	virtual bool OnRequest(AdmissionRequest &);
	virtual bool OnRequest(LocationRequest &);
	virtual bool OnRequest(SetupRequest &);
	virtual bool OnRequest(FacilityRequest &);

	GkClient *m_gkClient;
};

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


// a policy to look up the destination from DNS
class DNSPolicy : public AliasesPolicy {
public:
	DNSPolicy() { m_name = "DNS"; }
protected:
	virtual bool FindByAliases(RoutingRequest &, H225_ArrayOf_AliasAddress &);
	virtual bool FindByAliases(LocationRequest &, H225_ArrayOf_AliasAddress &);
};

bool DNSPolicy::FindByAliases(
	RoutingRequest &request,
	H225_ArrayOf_AliasAddress &aliases
	)
{
	for (PINDEX i = 0; i < aliases.GetSize(); ++i) {
		PString alias(AsString(aliases[i], FALSE));
		PINDEX at = alias.Find('@');

		PString domain = (at != P_MAX_INDEX) ? alias.Mid(at + 1) : alias;
		H225_TransportAddress dest;
		if (GetTransportAddress(domain, GK_DEF_ENDPOINT_SIGNAL_PORT, dest)) {
			PIPSocket::Address addr;
			if (!(GetIPFromTransportAddr(dest, addr) && addr.IsValid()))
				continue;
			Route route(m_name, dest);
			route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(dest);
			request.AddRoute(route);
			request.SetFlag(RoutingRequest::e_aliasesChanged);
			// remove the domain name part
			H323SetAliasAddress(alias.Left(at), aliases[i]);
			return true;
		}
	}
	return false;
}

bool DNSPolicy::FindByAliases(LocationRequest & /* request */, H225_ArrayOf_AliasAddress & /* aliases */)
{ 
	PTRACE(4, "ROUTING\tPolicy DNS not supported for LRQ");
	return false; // DNSPolicy::FindByAliases((RoutingRequest&)request, aliases);
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
			?"RequestTimeout":"CTI_Timeout", 
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
	const PString& calledip
	)
{
	bool result = false;
	bool duprequest = false;
	if (RouteRequest *r = InsertRequest(epid, crv, callID, destinationInfo, callSigAdr, duprequest)) {
		PString msg = PString(PString::Printf, "RouteRequest|%s|%s|%u|%s|%s", 
				(const char *)source,
				(const char *)epid,
				crv,
				(const char *)vqueue,
				(const char *)sourceInfo
			   );
		PString cid = callID;
		cid.Replace(" ", "-", true);
		msg += PString("|") + cid;
		msg += PString("|") + calledip;
		msg += PString(";");
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
	const H225_ArrayOf_AliasAddress& agent,
	/// ip that will replace the destionationCallSignalAddress (RouteToGateway)
	/// used only if set (!= NULL)
	const PString& destinationip,
	/// identifier of the endpoint associated with the route request
	const PString& callingEpId, 
	/// CRV of the call associated with the route request
	unsigned crv,
	/// callID of the call associated with the route request
	const PString& callID,
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
			<< ", CRV=" << crv << ") not found - ignoring RouteToAlias / RouteToGateway command");
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
	/// should this call be rejected
	bool reject
	)
{
	H225_ArrayOf_AliasAddress alias;
	if (targetAlias != "") {
		alias.SetSize(1);
		H323SetAliasAddress(targetAlias, alias[0]);
	}
	return RouteToAlias(alias, destinationIp, callingEpId, crv, callID, reject);
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
	return RouteToAlias(nullAgent, "", callingEpId, crv, callID, true);
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
	RouteRequest* r = new RouteRequest(callingEpId, crv, callID, agent, callSigAdr);
	m_pendingRequests.push_back(r);
	return r;
}


// a policy to route call via external program
class VirtualQueuePolicy : public Policy {
public:
	VirtualQueuePolicy();

protected:
	// override from class Policy
	virtual bool IsActive() const;

	virtual bool OnRequest(AdmissionRequest &);
	virtual bool OnRequest(LocationRequest &);
	virtual bool OnRequest(SetupRequest &);

private:
	VirtualQueue *m_vqueue;
};

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
			"a virtual queue " << vq << " (ARQ "
			<< arq.m_requestSeqNum.GetValue() << ')'
			);
		endptr ep = RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier); // should not be null
		if (ep) {
			PString source = AsDotString(ep->GetCallSignalAddress());
			PString epid = ep->GetEndpointIdentifier().GetValue();
			PString * callSigAdr = new PString();
			if (m_vqueue->SendRouteRequest(source, epid, unsigned(arq.m_callReferenceValue), aliases, callSigAdr, reject, vq, AsString(arq.m_srcInfo), AsString(arq.m_callIdentifier.m_guid)))
				request.SetFlag(RoutingRequest::e_aliasesChanged);
			if (reject) {
				request.SetFlag(RoutingRequest::e_Reject);
			}
			if (!callSigAdr->IsEmpty()) {
				if (!arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
					arq.IncludeOptionalField(H225_AdmissionRequest::e_destCallSignalAddress);
				}
				PStringArray adr_parts = callSigAdr->Tokenise(":", FALSE);
				PString ip = adr_parts[0];
				WORD port = (WORD)(adr_parts[1].AsInteger());
				if (port == 0)
					port = GK_DEF_ENDPOINT_SIGNAL_PORT;
				arq.m_destCallSignalAddress = SocketToH225TransportAddr(ip, port);
			}
			delete callSigAdr;
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
			PString sourceInfo = "";
			if (lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo) && (lrq.m_sourceInfo.GetSize() > 0))
				sourceInfo = AsString(lrq.m_sourceInfo);
			PString callID = "-";	/* not available for LRQs */
			if (m_vqueue->SendRouteRequest(source, epid, unsigned(lrq.m_requestSeqNum), aliases, callSigAdr, reject, vq, sourceInfo, callID))
				request.SetFlag(RoutingRequest::e_aliasesChanged);
			if (reject) {
				request.SetFlag(RoutingRequest::e_Reject);
			}
			if (!reject && !callSigAdr->IsEmpty()) {
				// 'explicit' policy can't handle LRQs, so we do it directly
				PStringArray adr_parts = callSigAdr->Tokenise(":", FALSE);
				PString ip = adr_parts[0];
				WORD port = (WORD)(adr_parts[1].AsInteger());
				if (port == 0)
					port = GK_DEF_ENDPOINT_SIGNAL_PORT;
				Route route("vqueue", SocketToH225TransportAddr(ip, port));
				route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(
					route.m_destAddr
				);
				request.AddRoute(route);					
				delete callSigAdr;
				return true;	// stop processing
			}
			delete callSigAdr;
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
	H225_ArrayOf_AliasAddress *aliases = new H225_ArrayOf_AliasAddress;
	aliases->SetSize(1);
	PString vq = "";
	if (request.GetAliases()) {
		vq = AsString((*request.GetAliases())[0], false);
	}
	if (m_vqueue->IsDestinationVirtualQueue(vq)) {
		H225_Setup_UUIE &setup = request.GetRequest();
		PString callerip = AsDotString(setup.m_sourceCallSignalAddress);
		PString epid = "unregistered";
		const unsigned crv = request.GetWrapper()->GetCallReference();
		PString * callSigAdr = new PString();
		PString callid = AsString(setup.m_callIdentifier.m_guid);
		PString src = AsString(setup.m_sourceAddress);
		PIPSocket::Address localAddr;
		WORD localPort;
		request.GetWrapper()->GetLocalAddr(localAddr, localPort);
		PString calledIP = localAddr;
		PTRACE(5,"Routing\tPolicy " << m_name << " destination matched "
			"a virtual queue " << vq << " (Setup "
			<< crv << ')'
			);

		if (m_vqueue->SendRouteRequest(callerip, epid, crv, aliases, callSigAdr, reject, vq, src, callid, calledIP))
			request.SetFlag(RoutingRequest::e_aliasesChanged);
		
		if (reject) {
			request.SetFlag(RoutingRequest::e_Reject);
		}
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
			PStringArray adr_parts = callSigAdr->Tokenise(":", FALSE);
			PString ip = adr_parts[0];
			WORD port = (WORD)(adr_parts[1].AsInteger());
			if (port == 0)
				port = GK_DEF_ENDPOINT_SIGNAL_PORT;
			setup.m_destCallSignalAddress = SocketToH225TransportAddr(ip, port);
		}
		delete callSigAdr;
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

class NumberAnalysisPolicy : public Policy {
public:
	struct PrefixEntry {
		string m_prefix;
		int m_minLength;
		int m_maxLength;
	};
	
	NumberAnalysisPolicy();

protected:
	virtual bool OnRequest(AdmissionRequest &);
	virtual bool OnRequest(SetupRequest &);

private:
	NumberAnalysisPolicy(const NumberAnalysisPolicy &);
	NumberAnalysisPolicy& operator=(const NumberAnalysisPolicy &);
	
private:
	typedef vector<PrefixEntry> Prefixes;

	/// list of number prefixes, with min/max number length as values
	Prefixes m_prefixes;
};

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
		<< " prefix entries"
		);
		
#if PTRACING
	if (PTrace::CanTrace(6)) {
		ostream &strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << "ROUTING\t" << m_name << " policy prefixes:" << endl;
		for (unsigned i = 0; i < m_prefixes.size(); i++)
			strm << "\t" << m_prefixes[i].m_prefix.c_str() << " => min len: "
				<< m_prefixes[i].m_minLength << ", max len: "
				<< m_prefixes[i].m_maxLength << endl;
		PTrace::End(strm);
	}
#endif /* PTRACING */
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

// a policy to look up the destination from ENUM Name Server
class ENUMPolicy : public AliasesPolicy {
public:
	ENUMPolicy() { m_name = "ENUM"; }
protected:
    virtual bool OnRequest(SetupRequest &) { return false; }
    virtual bool OnRequest(FacilityRequest &) { return false; }

	virtual bool FindByAliases(RoutingRequest &, H225_ArrayOf_AliasAddress &);
	virtual bool FindByAliases(LocationRequest &, H225_ArrayOf_AliasAddress &);
};

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

bool ENUMPolicy::FindByAliases(LocationRequest & /* request */, H225_ArrayOf_AliasAddress & /* aliases */)
{
    PTRACE(4, "ROUTING\tPolicy ENUM not supported for LRQ");
	return false; // ENUMPolicy::FindByAliases((RoutingRequest&)request, aliases);
}



class DestinationRoutes {
public:
	DestinationRoutes() { m_endChain = false; m_reject = false; m_aliasesChanged = false;}
	~DestinationRoutes() { }
	
	bool EndPolicyChain() const { return m_endChain; }
	bool RejectCall() const { return m_reject; }
	void SetRejectCall(bool reject) { m_reject = reject; m_endChain = true; }
	unsigned int GetRejectReason() const { return m_rejectReason; }
	void SetRejectReason(unsigned int reason) { m_rejectReason = reason; }
	bool ChangeAliases() const { return m_aliasesChanged; }
	H225_ArrayOf_AliasAddress GetNewAliases() const { return m_newAliases; }
	void SetNewAliases(const H225_ArrayOf_AliasAddress & aliases) { m_newAliases = aliases; m_aliasesChanged = true; }
	
	void AddRoute(const Route & route) { m_routes.push_back(route); m_endChain = true; }
	
	std::list<Route> m_routes;

protected:
	bool m_endChain;
	bool m_reject;
	unsigned int m_rejectReason;
	bool m_aliasesChanged;
	H225_ArrayOf_AliasAddress m_newAliases;
};

// a policy to route calls via an SQL database
class SqlPolicy : public Policy {
public:
	SqlPolicy();
	virtual ~SqlPolicy();

protected:
	virtual bool IsActive() const { return m_active; }

	virtual bool OnRequest(AdmissionRequest &);
	virtual bool OnRequest(LocationRequest &);
	virtual bool OnRequest(SetupRequest &);

	virtual void DatabaseLookup(
		/*in */
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType,
		/* out: */
		DestinationRoutes & destination);

private:
	// active ?
	bool m_active;
	// connection to the SQL database
	GkSQLConnection* m_sqlConn;
	// parametrized query string for the routing query
	PString m_query;
	// query timeout
	long m_timeout;
};

SqlPolicy::SqlPolicy()
{
	m_active = false;
#if HAS_DATABASE
	m_active = true;
	static const char *sqlsection = "Routing::Sql";
	m_name = "SqlPolicy";
	m_timeout = -1;

	PConfig* cfg = GkConfig();

	const PString driverName = cfg->GetString(sqlsection, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"no SQL driver selected"
			);
		m_active = false;
		return;
	}
	
	m_sqlConn = GkSQLConnection::Create(driverName, m_name);
	if (m_sqlConn == NULL) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"could not find " << driverName << " database driver"
			);
		m_active = false;
		return;
	}

	m_query = cfg->GetString(sqlsection, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"no query configured"
			);
		m_active = false;
		return;
	} else
		PTRACE(4, m_name << "\tQuery: " << m_query);
		
	if (!m_sqlConn->Initialize(cfg, sqlsection)) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"could not connect to the database"
			);
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

bool SqlPolicy::OnRequest(AdmissionRequest & request)
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
		DestinationRoutes destination;

		DatabaseLookup(	/* in */ source, calledAlias, calledIP, caller, callingStationId, callid, messageType,
						/* out: */ destination);

		if (destination.RejectCall()) {
			request.SetFlag(RoutingRequest::e_Reject);
			request.SetRejectReason(destination.GetRejectReason());
		}

		if (destination.ChangeAliases()) {
			request.SetFlag(RoutingRequest::e_aliasesChanged);
			arq.m_destinationInfo = destination.GetNewAliases();
		}

		if (!destination.m_routes.empty()) {
			request.SetFlag(RoutingRequest::e_aliasesChanged);
			if (!arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
				arq.IncludeOptionalField(H225_AdmissionRequest::e_destCallSignalAddress);
			}
			arq.m_destCallSignalAddress = destination.m_routes.front().m_destAddr;
			while (!destination.m_routes.empty()) {
				request.AddRoute(destination.m_routes.front());
				destination.m_routes.pop_front();
			}
		}

		if (m_next == NULL || destination.EndPolicyChain())
			return true;
	}
	return false;
}

bool SqlPolicy::OnRequest(LocationRequest & request)
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
	DestinationRoutes destination;

	DatabaseLookup(	/* in */ source, calledAlias, calledIP, caller, callingStationId,callid, messageType,
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

bool SqlPolicy::OnRequest(SetupRequest & request)
{
	H225_Setup_UUIE &setup = request.GetRequest();

	PString source = AsDotString(setup.m_sourceCallSignalAddress);
	PString calledAlias = "";
	if (request.GetAliases() && (!request.GetAliases()->GetSize() == 0)) {
		calledAlias = AsString((*request.GetAliases())[0], FALSE);
	}
	PIPSocket::Address localAddr;
	WORD localPort;
	request.GetWrapper()->GetLocalAddr(localAddr, localPort);
	PString calledIP = localAddr;
	PString caller = AsString(setup.m_sourceAddress, FALSE);
	PString callingStationId = request.GetCallingStationId();
	PString callid = AsString(setup.m_callIdentifier.m_guid);
	PString messageType = "Setup";
	DestinationRoutes destination;

	DatabaseLookup(	/* in */ source, calledAlias, calledIP, caller, callingStationId, callid, messageType,
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

	if (!destination.m_routes.empty()) {
		request.SetFlag(RoutingRequest::e_aliasesChanged);
		if (!setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
			setup.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		}
		setup.m_destCallSignalAddress = destination.m_routes.front().m_destAddr;
		while (!destination.m_routes.empty()) {
			request.AddRoute(destination.m_routes.front());
			destination.m_routes.pop_front();
		}
	}

	if (m_next == NULL || destination.EndPolicyChain())
		return true;

	return false;
}

void SqlPolicy::DatabaseLookup(
		/*in */
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType,
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
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, params, m_timeout);
	if (result == NULL) {
		PTRACE(2, m_name << ": query failed - timeout or fatal error");
		return;
	}

	if (!result->IsValid()) {
		PTRACE(2, m_name << ": query failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage()
			);
		delete result;
		return;
	}
	
	if (result->GetNumRows() < 1)
		PTRACE(3, m_name << ": query returned no rows");
	else if (result->GetNumFields() < 1)
		PTRACE(2, m_name << ": bad-formed query - "
			"no columns found in the result set"
			);
	else if (!result->FetchRow(resultRow) || resultRow.empty())
		PTRACE(2, m_name << ": query failed - could not fetch the result row");
	else if (result->GetNumFields() == 1) {
		PString newDestination = resultRow[0].first;
		PTRACE(5, m_name << "\tQuery result : " << newDestination);
		if (newDestination.ToUpper() == "REJECT") {
			destination.SetRejectCall(true);
		} else if (IsIPAddress(newDestination)) {
			int row = 0;
			do {
				PString destinationIp = resultRow[0].first;
				PStringArray adr_parts = destinationIp.Tokenise(":", FALSE);
				PString ip = adr_parts[0];
				WORD port = (WORD)(adr_parts[1].AsInteger());
				if (port == 0)
					port = GK_DEF_ENDPOINT_SIGNAL_PORT;

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
			destination.SetRejectCall(true);;
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
				PStringArray adr_parts = destinationIp.Tokenise(":", FALSE);
				PString ip = adr_parts[0];
				WORD port = (WORD)(adr_parts[1].AsInteger());
				if (port == 0)
					port = GK_DEF_ENDPOINT_SIGNAL_PORT;

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


namespace { // anonymous namespace
	SimpleCreator<ExplicitPolicy> ExplicitPolicyCreator("explicit");
	SimpleCreator<InternalPolicy> InternalPolicyCreator("internal");
	SimpleCreator<ParentPolicy> ParentPolicyCreator("parent");
	SimpleCreator<DNSPolicy> DNSPolicyCreator("dns");
	SimpleCreator<VirtualQueuePolicy> VirtualQueuePolicyCreator("vqueue");
	SimpleCreator<NumberAnalysisPolicy> NumberAnalysisPolicyCreator("numberanalysis");
	SimpleCreator<ENUMPolicy> ENUMPolicyCreator("enum");
	SimpleCreator<SqlPolicy> SqlPolicyCreator("sql");
}


} // end of namespace Routing
