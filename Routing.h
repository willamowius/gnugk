//////////////////////////////////////////////////////////////////
//
// Routing.h
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

#ifndef ROUTING_H
#define ROUTING_H "@(#) $Id$"

#include "slist.h"
#include "singleton.h"


// forward references to avoid includes
class H225_AdmissionRequest;
class H225_LocationRequest;
class H225_Setup_UUIE;
class H225_Facility_UUIE;
class H225_TransportAddress;
class H225_ArrayOf_AliasAddress;
class Q931;

class RasMsg;
class EndpointRec;
template<class> class SmartPtr;
typedef SmartPtr<EndpointRec> endptr;

namespace Routing {


class RoutingRequest {
public:
	// a policy can set flags to indicate extra status of a processed request
	enum ExtraFlags {
		e_aliasesChanged = 1,
		e_fromInternal	 = 2,
		e_fromParent	 = 4,
		e_fromNeighbor	 = 8,
		e_toInternal	 = 16,
		e_toParent	 = 32,
		e_toNeighbor	 = 64
	};

	// note this is not a polymorphic class
	RoutingRequest(endptr & called) : m_destination(0), m_called(called), m_flags(0) {}
	~RoutingRequest();

	bool SetDestination(const H225_TransportAddress &, bool = false);
	bool SetCalledParty(const endptr &);
	void SetRejectReason(unsigned reason) { m_reason = reason; }
	void SetFlag(unsigned f) { m_flags |= f; }
	unsigned GetRejectReason() const { return m_reason; }
	unsigned GetFlags() const { return m_flags; }

protected:
	H225_TransportAddress *m_destination;

private:
	endptr & m_called;
	short unsigned m_reason, m_flags;
};

template<class R, class W>
class Request : public RoutingRequest {
public:
	typedef R ReqObj;
	typedef W Wrapper;

	Request(ReqObj & r, Wrapper *w, endptr & c) : RoutingRequest(c), m_request(r), m_wrapper(w) {}

	H225_TransportAddress *Process();

	ReqObj & GetRequest() { return m_request; }
	Wrapper *GetWrapper() { return m_wrapper; }
	H225_ArrayOf_AliasAddress *GetAliases();
	const ReqObj & GetRequest() const { return m_request; }
	const Wrapper *GetWrapper() const { return m_wrapper; }
	const H225_ArrayOf_AliasAddress *GetAliases() const
	{ return const_cast<Request<R, W> *>(this)->GetAliases(); }

private:
	ReqObj & m_request;
	Wrapper *m_wrapper;
};

typedef Request<H225_AdmissionRequest, RasMsg> AdmissionRequest;
typedef Request<H225_LocationRequest, RasMsg> LocationRequest;
typedef Request<H225_Setup_UUIE, Q931> SetupRequest;
typedef Request<H225_Facility_UUIE, Q931> FacilityRequest;


class Policy : public SList<Policy> {
public:
	template <class R> bool Handle(R & request)
	{
		return (IsActive() && OnRequest(request)) || (m_next && m_next->Handle(request));
	}

protected:
	// new virtual function
	// if return false, the policy is disable
	virtual bool IsActive() { return true; }

	// methods to handle the request
	// return true:  fate of the request is determined (confirm or reject)
	// return false: undetermined, try next
	virtual bool OnRequest(AdmissionRequest &) { return false; }
	virtual bool OnRequest(LocationRequest &)  { return false; }
	virtual bool OnRequest(SetupRequest &)	   { return false; }
	virtual bool OnRequest(FacilityRequest &)  { return false; }
};

class AliasesPolicy : public Policy {
protected:
	// override from class Policy
	virtual bool OnRequest(AdmissionRequest &);
	virtual bool OnRequest(LocationRequest &);
	virtual bool OnRequest(SetupRequest &);
	virtual bool OnRequest(FacilityRequest &);

	// new virtual function
	virtual bool FindByAliases(RoutingRequest &, H225_ArrayOf_AliasAddress &) = 0;
};

class Analyzer : public Singleton<Analyzer> {
public:
	Analyzer();
	~Analyzer();

	void OnReload();

	bool Parse(AdmissionRequest &);
	bool Parse(LocationRequest &);
	bool Parse(SetupRequest &);
	bool Parse(FacilityRequest &);

private:
	typedef std::map<PString, Policy *> Rules;

	Policy *Create(const PString & policy);
	Policy *ChoosePolicy(const H225_ArrayOf_AliasAddress *, Rules &);

	Rules m_rules[4];
	PReadWriteMutex m_reloadMutex;
};


template<class R, class W>
inline H225_TransportAddress *Request<R, W>::Process()
{
	return Analyzer::Instance()->Parse(*this) ? m_destination : 0;
}


} // end of namespace Routing

#endif // ROUTING_H
