//////////////////////////////////////////////////////////////////
//
// Routing Mechanism for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 06/18/2003
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include "Routing.h"
#include "Toolkit.h"
#include "RasTbl.h"
#include "RasSrv.h"
#include "GkClient.h"
#include "stl_supp.h"
#include "h323util.h"
#include "gk_const.h"
#include "GkStatus.h"
#include <h323pdu.h>


namespace Routing {


const char *SectionName[] = {
	"RoutingPolicy::OnARQ",
	"RoutingPolicy::OnLRQ",
	"RoutingPolicy::OnSetup",
	"RoutingPolicy::OnFacility",
	"RoutingPolicy"
};


// class RoutingRequest
RoutingRequest::~RoutingRequest()
{
	delete m_destination;
}

bool RoutingRequest::SetDestination(const H225_TransportAddress & dest, bool find_called)
{
	PAssert(!m_destination, "Error: destination overwritten!");
	m_destination = new H225_TransportAddress(dest);
	if (find_called)
		m_called = RegistrationTable::Instance()->FindBySignalAdr(dest);
	return true;
}

bool RoutingRequest::SetCalledParty(const endptr & called)
{
	return (m_called = called) ? SetDestination(called->GetCallSignalAddress()) : false;
}


// class AdmissionRequest
template<> H225_ArrayOf_AliasAddress *AdmissionRequest::GetAliases()
{
	return (m_request.HasOptionalField(H225_AdmissionRequest::e_destinationInfo) && m_request.m_destinationInfo.GetSize() > 0) ? &m_request.m_destinationInfo : 0;
}


// class LocationRequest
template<> H225_ArrayOf_AliasAddress *LocationRequest::GetAliases()
{
	return (m_request.m_destinationInfo.GetSize() > 0) ? &m_request.m_destinationInfo : 0;
}


// class SetupRequest
template<> H225_ArrayOf_AliasAddress *SetupRequest::GetAliases()
{
	return (m_request.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) && m_request.m_destinationAddress.GetSize() > 0) ? &m_request.m_destinationAddress : 0;
}


// class FacilityRequest
template<> H225_ArrayOf_AliasAddress *FacilityRequest::GetAliases()
{
	return (m_request.HasOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress) && m_request.m_alternativeAliasAddress.GetSize() > 0) ? &m_request.m_alternativeAliasAddress : 0;
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
	return policy ? policy->Handle(request) : false;
}

bool Analyzer::Parse(LocationRequest & request)
{
	ReadLock lock(m_reloadMutex);
	request.SetRejectReason(H225_LocationRejectReason::e_requestDenied);
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[1]);
	return policy ? policy->Handle(request) : false;
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
				if (strncmp(iter->first, destination, iter->first.GetLength()) == 0)
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
	return arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress) ? request.SetDestination(arq.m_destCallSignalAddress, true) : false;
}

bool ExplicitPolicy::OnRequest(SetupRequest & request)
{
	H225_Setup_UUIE & setup = request.GetRequest();
	return setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress) ? request.SetDestination(setup.m_destCallSignalAddress, true) : false;
}

bool ExplicitPolicy::OnRequest(FacilityRequest & request)
{
	H225_Facility_UUIE & facility = request.GetRequest();
	return facility.HasOptionalField(H225_Facility_UUIE::e_alternativeAddress) ? request.SetDestination(facility.m_alternativeAddress, true) : false;
}


// the classical policy, find the dstionation from the RegistrationTable
class InternalPolicy : public AliasesPolicy {
public:
	InternalPolicy() { m_name = "Internal"; }
protected:
	virtual bool FindByAliases(RoutingRequest &, H225_ArrayOf_AliasAddress &);
};

bool InternalPolicy::FindByAliases(RoutingRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	return request.SetCalledParty(RegistrationTable::Instance()->FindEndpoint(aliases, true));
}


// a policy to route call to parent
// the policy was originally in GkClient.cxx,
// but damn VC has problem to instantiate the creator
class ParentPolicy : public Policy {
public:
	ParentPolicy();

private:
	// override from class Policy
	virtual bool IsActive();

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

bool ParentPolicy::IsActive()
{
	return m_gkClient->IsRegistered();
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
};

bool DNSPolicy::FindByAliases(RoutingRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	for (PINDEX i = 0; i < aliases.GetSize(); ++i) {
		PString alias(H323GetAliasAddressString(aliases[i]));
		PINDEX at = alias.Find('@');
		PString domain = (at != P_MAX_INDEX) ? alias.Mid(at + 1) : alias;
		H225_TransportAddress dest;
		if (GetTransportAddress(domain, GK_DEF_ENDPOINT_SIGNAL_PORT, dest)) {
			request.SetDestination(dest, true);
			request.SetFlag(RoutingRequest::e_aliasesChanged);
			// remove the domain name part
			H323SetAliasAddress(alias.Left(at), aliases[i]);
			return true;
		}
	}
	return false;
}


#define DEFAULT_ROUTE_REQUEST_TIMEOUT 10
const char* CTIsection = "CTI::Agents";

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
	if( numrequests )
		PTRACE(1,"VQueue\tDestroying virtual queue with "
			<<numrequests<<" pending requests"
			);
	RouteRequests::iterator i = m_pendingRequests.begin();
	while (i != m_pendingRequests.end()) {
		RouteRequest *r = *i++;
		r->m_sync.Signal();
	}
	
	m_listMutex.Signal();

	// wait a moment to give a chance to pending requests to cleanup
	if( numrequests )
		PThread::Sleep(500);
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
	m_requestTimeout = PMIN(PMAX(100,m_requestTimeout),20000);
	const PString vqueues = GkConfig()->GetString(CTIsection, "VirtualQueue", "");
	m_virtualQueues = vqueues.Tokenise(" ,;\t", false);
	m_active = m_virtualQueues.GetSize() > 0;
	if( m_active )
		PTRACE(2,"VQueue\t(CTI) Virtual queues enabled ("<<vqueues
			<<"), request timeout: "<<m_requestTimeout/1000<<" s"
			);
	else
		PTRACE(2,"VQueue\t(CTI) Virtual queues disabled - no virtual queues configured");
}

bool VirtualQueue::SendRouteRequest(
	/// calling endpoint
	const endptr& caller, 
	/// CRV (Call Reference Value) of the call associated with this request
	unsigned crv,
	/// destination (virtual queue) aliases as specified
	/// by the calling endpoint (modified by this function on successful return)
	H225_ArrayOf_AliasAddress* destinationInfo,
	/// actual virtual queue name (should be present in destinationInfo too)
	const PString& vqueue,
	/// a sequence of aliases for the calling endpoint
	/// (in the "alias:type[=alias:type]..." format)
	const PString& sourceInfo
	)
{
	bool result = false;
	bool duprequest = false;
	const PString epid(caller->GetEndpointIdentifier().GetValue());
	if (RouteRequest *r = InsertRequest(epid, crv, destinationInfo, duprequest)) {
		const PString msg(PString::Printf, "RouteRequest|%s|%s|%u|%s|%s;", 
				(const char *)AsDotString(caller->GetCallSignalAddress()),
				(const char *)epid,
				crv,
				(const char *)vqueue,
				(const char *)sourceInfo
			   );
		// signal RouteRequest to the status line only once
		if( duprequest )
			PTRACE(4, "VQueue\tDuplicate request: "<<msg);
		else {
			PTRACE(2, msg);
			GkStatus::Instance()->SignalStatus(msg + "\r\n");
		}

		// wait for an answer from the status line (routetoalias,routereject)
		result = r->m_sync.Wait(m_requestTimeout);
		m_listMutex.Wait();
		m_pendingRequests.remove(r);
		m_listMutex.Signal();
		if( !result )
			PTRACE(5,"VQueue\tRoute request (EPID: "<<r->m_callingEpId
				<<", CRV="<<r->m_crv<<") timed out"
				);
		delete r;
	}
	return result;
}

bool VirtualQueue::IsDestinationVirtualQueue(
	const PString& destinationAlias /// alias to be matched
	) const
{
	PWaitAndSignal lock(m_listMutex);
	for (PINDEX i = 0; i < m_virtualQueues.GetSize(); ++i)
		if (m_virtualQueues[i] == destinationAlias)
			return true;
	return false;
}

bool VirtualQueue::RouteToAlias(
	/// aliases for the routing target (an agent that the call will be routed to) 
	/// that will replace the original destination info
	const H225_ArrayOf_AliasAddress& agent,
	/// identifier of the endpoint associated with the route request
	const PString& callingEpId, 
	/// CRV of the call associated with the route request
	unsigned crv
	)
{
	PWaitAndSignal lock(m_listMutex);
	
	// signal the command to each pending request
	bool foundrequest = false;
	RouteRequests::iterator i = m_pendingRequests.begin();
	while (i != m_pendingRequests.end()) {
		RouteRequest *r = *i;
		if (r->m_callingEpId == callingEpId && r->m_crv == crv) {
			// replace virtual queue aliases info with agent aliases
			*r->m_agent = agent;
			r->m_sync.Signal();
			if( !foundrequest ) {
				foundrequest = true;
				if( agent.GetSize() > 0 )
					PTRACE(2,"VQueue\tRoute request (EPID :"<<callingEpId
						<<", CRV="<<crv<<") accepted by agent "<<AsString(agent)
						);
				else				
					PTRACE(2,"VQueue\tRoute request (EPID :"<<callingEpId
						<<", CRV="<<crv<<") rejected"
						);
			}
		}
		++i;
	}
	
	if( !foundrequest )
		PTRACE(4,"VQueue\tPending route request (EPID:"<<callingEpId
			<<", CRV="<<crv<<") not found - ignoring RouteToAlias command"
			);
	
	return foundrequest;
}

bool VirtualQueue::RouteToAlias(
	/// alias for the routing target that
	/// will replace the original destination info
	const PString& agent, 
	/// identifier of the endpoint associated with the route request
	const PString& callingEpId, 
	/// CRV for the call associated with the route request
	unsigned crv
	)
{
	H225_ArrayOf_AliasAddress agentAlias;
	agentAlias.SetSize(1);
	H323SetAliasAddress(agent, agentAlias[0]);
	return RouteToAlias(agentAlias, callingEpId, crv);
}

bool VirtualQueue::RouteReject(
	/// identifier of the endpoint associated with the route request
	const PString& callingEpId, 
	/// CRV of the call associated with the route request
	unsigned crv
	)
{
	H225_ArrayOf_AliasAddress nullAgent;
	return RouteToAlias(nullAgent, callingEpId, crv);
}

VirtualQueue::RouteRequest* VirtualQueue::InsertRequest(
	/// identifier for the endpoint associated with this request
	const PString& callingEpId, 
	/// CRV for the call associated with this request
	unsigned crv, 
	/// a pointer to an array to be filled with agent aliases
	/// when the routing decision has been made
	H225_ArrayOf_AliasAddress* agent,
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
		if (r->m_callingEpId == callingEpId && r->m_crv == crv)
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
	RouteRequest* r = new RouteRequest(callingEpId, crv, agent);
	m_pendingRequests.push_back(r);
	return r;
}


// a policy to route call via external program
class VirtualQueuePolicy : public Policy {
public:
	VirtualQueuePolicy();

private:
	// override from class Policy
	virtual bool IsActive();

	virtual bool OnRequest(AdmissionRequest &);
	// TODO
	//virtual bool OnRequest(LocationRequest &);
	//virtual bool OnRequest(SetupRequest &);
	//virtual bool OnRequest(FacilityRequest &);

	VirtualQueue *m_vqueue;
};

VirtualQueuePolicy::VirtualQueuePolicy()
{
	m_vqueue = RasServer::Instance()->GetVirtualQueue();
	m_name = "VirtualQueue";
}

bool VirtualQueuePolicy::IsActive()
{
	return m_vqueue->IsActive();
}

bool VirtualQueuePolicy::OnRequest(AdmissionRequest & request)
{
	if (H225_ArrayOf_AliasAddress *aliases = request.GetAliases()) {
		const PString agent(H323GetAliasAddressString((*aliases)[0]));
		if (m_vqueue->IsDestinationVirtualQueue(agent)) {
			H225_AdmissionRequest & arq = request.GetRequest();
			PTRACE(5,"Routing\tPolicy "<<m_name<<" destination matched "
				"a virtual queue "<<agent<<" (ARQ "
				<<arq.m_requestSeqNum.GetValue()<<')'
				);
			endptr ep = RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier); // should not be null
			if (ep && m_vqueue->SendRouteRequest(ep, unsigned(arq.m_callReferenceValue), aliases, agent, AsString(arq.m_srcInfo)))
				request.SetFlag(RoutingRequest::e_aliasesChanged);
				// the trick: if empty, the request is rejected
				// so we return true to terminate the routing
				// decision process, otherwise the aliases is
				// rewritten, we return false to let subsequent
				// policies determine the request 
				if (m_next == NULL || aliases->GetSize() == 0)
					return true;
		}
	}
	return false;
}


namespace { // anonymous namespace
	SimpleCreator<ExplicitPolicy> ExplicitPolicyCreator("explicit");
	SimpleCreator<InternalPolicy> InternalPolicyCreator("internal");
	SimpleCreator<ParentPolicy> ParentPolicyCreator("parent");
	SimpleCreator<DNSPolicy> DNSPolicyCreator("dns");
	SimpleCreator<VirtualQueuePolicy> VirtualQueuePolicyCreator("vqueue");
}


} // end of namespace Routing
