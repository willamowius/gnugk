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
	for (int i = 0; i < 4; ++i)
		DeleteObjectsInMap(m_rules[i]);
}

void Analyzer::OnReload()
{
	for (int i = 0; i < 4; ++i) {
		Rules & rules = m_rules[i];
		// FIXME: not thread-safed
		DeleteObjectsInMap(rules);
		rules.clear();

		PStringToString cfgs(GkConfig()->GetAllKeyValues(SectionName[i]));
		if (cfgs.GetSize() == 0) // no such a section? try default
			cfgs = GkConfig()->GetAllKeyValues(SectionName[4]);

		for (PINDEX j = 0; j < cfgs.GetSize(); ++j) {
			PString prefix = cfgs.GetKeyAt(j);
			if (prefix *= "default")
				prefix = "*";
			rules[prefix] = Create(cfgs.GetDataAt(j));
			PTRACE(1, SectionName[i] << " add policy " << cfgs.GetDataAt(j) << " for prefix " << prefix);
		}
		// default policy for backward compatibility
		if (rules.empty())
			rules["*"] = Create("explicit,internal,parent,neighbor");
	}
}

bool Analyzer::Parse(AdmissionRequest & request)
{
	request.SetRejectReason(H225_AdmissionRejectReason::e_calledPartyNotRegistered);
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[0]);
	return policy ? policy->Handle(request) : false;
}

bool Analyzer::Parse(LocationRequest & request)
{
	request.SetRejectReason(H225_LocationRejectReason::e_requestDenied);
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[1]);
	return policy ? policy->Handle(request) : false;
}

bool Analyzer::Parse(SetupRequest & request)
{
	request.SetRejectReason(H225_ReleaseCompleteReason::e_calledPartyNotRegistered);
	Policy *policy = ChoosePolicy(request.GetAliases(), m_rules[2]);
	return policy ? policy->Handle(request) : false;
}

bool Analyzer::Parse(FacilityRequest & request)
{
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

namespace { // anonymous namespace
	SimpleCreator<ExplicitPolicy> ExplicitPolicyCreator("explicit");
	SimpleCreator<InternalPolicy> InternalPolicyCreator("internal");
	SimpleCreator<ParentPolicy> ParentPolicyCreator("parent");
	SimpleCreator<DNSPolicy> DNSPolicyCreator("dns");
}


} // end of namespace Routing
