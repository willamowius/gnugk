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

#include <map>
#include <list>
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
class SignalingMsg;
template <class> class H225SignalingMsg;
typedef H225SignalingMsg<H225_Setup_UUIE> SetupMsg;
typedef H225SignalingMsg<H225_Facility_UUIE> FacilityMsg;

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
	RoutingRequest(endptr & called) : m_destination(0), m_neighbor_used(0), m_called(called), m_reason(-1), m_flags(0) {}
	~RoutingRequest();

	H225_TransportAddress* GetDestination() const { return m_destination; }
	bool SetDestination(const H225_TransportAddress &, bool = false);
	bool SetCalledParty(const endptr &);
	void SetRejectReason(unsigned reason) { m_reason = reason; }
	void SetFlag(unsigned f) { m_flags |= f; }
	unsigned GetRejectReason() const { return m_reason; }
	unsigned GetFlags() const { return m_flags; }
	endptr& GetCalledParty() { return m_called; }
	void SetNeighborUsed(PIPSocket::Address neighbor) { m_neighbor_used = neighbor; }
	PIPSocket::Address GetNeighborUsed() { return m_neighbor_used; }

protected:
	H225_TransportAddress *m_destination;
	PIPSocket::Address m_neighbor_used;

private:
	endptr & m_called;
	int m_reason;
	unsigned m_flags;
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
typedef Request<H225_Setup_UUIE, SetupMsg> SetupRequest;
typedef Request<H225_Facility_UUIE, FacilityMsg> FacilityRequest;


class Policy : public SList<Policy> {
public:
	Policy() : m_name("Undefined") {}

	template <class R> bool Handle(Request<R,RasMsg> & request)
	{
		if( IsActive() ) {
#if PTRACING
			const char* tagname = request.GetWrapper()
				? request.GetWrapper()->GetTagName() : "unknown";
			const unsigned seqnum = request.GetRequest().m_requestSeqNum.GetValue();
			PTRACE(5,"ROUTING\tChecking policy "<<m_name
				<<" for the request "<<tagname<<' '<<seqnum
				);
#endif
			if( OnRequest(request) ) {
#if PTRACING
				PTRACE(5,"ROUTING\tPolicy "<<m_name
					<<" applied to the request "<<tagname<<' '<<seqnum
					);
#endif
				return true;
			}
		}
		return m_next && m_next->Handle(request);
	}

	bool Handle(SetupRequest &request);
	bool Handle(FacilityRequest &request);

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

protected:
	/// human readable name for the policy - it should be set inside constructors
	/// of derived policies, default value is "undefined"
	const char* m_name;
};

class AliasesPolicy : public Policy {
public:
	AliasesPolicy() { m_name = "Aliases"; }

protected:
	// override from class Policy
	virtual bool OnRequest(AdmissionRequest &);
	virtual bool OnRequest(LocationRequest &);
	virtual bool OnRequest(SetupRequest &);
	virtual bool OnRequest(FacilityRequest &);

	// new virtual function
	virtual bool FindByAliases(RoutingRequest&, H225_ArrayOf_AliasAddress &) = 0;
	virtual bool FindByAliases(LocationRequest&, H225_ArrayOf_AliasAddress&) = 0;
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
	typedef std::map<PString, Policy *, pstr_prefix_lesser> Rules;

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

/** A class that supports ACD (Automatic Call Distribution). A call
    made to specified alias(-es) (called virtual queue) is signalled
	via the GK status line to an external application (an ACD application)
	that decides where the call should be routed (e.g. what agent should
	answe the call). Basically, it rewrites virtual queue alias
	into the alias of the specified agent.

	The route request is uniquelly identified by (EndpointIdentifier,CRV)
	values pair.
*/
class VirtualQueue
{
public:
	VirtualQueue();
	~VirtualQueue();

	/// reload settings from the config file
	void OnReload();

	/** @return
		True if there is at least one virtual queue configured.
	*/
	bool IsActive() const { return m_active; }

	/** Send RouteRequest to the GK status line	and wait
		for a routing decision to be made by some external application
		(ACD application).

		@return
		True if the external application routed the call (either by specifying
		an alias or by rejecting the call), false if timed out waiting
		for the routing decision.
		If the request was rejected, destinationInfo is set to an epmty array
		(0 elements).
	*/
	bool SendRouteRequest(
		/// calling endpoint
		const endptr& caller,
		/// CRV (Call Reference Value) of the call associated with this request
		unsigned crv,
		/// destination (virtual queue) aliases as specified
		/// by the calling endpoint (modified by this function on successful return)
		H225_ArrayOf_AliasAddress* destinationInfo,
		/// destinationCallSignalAddr (optionally set by this function on successful return)
		PString* callSigAdr,
		/// an actual virtual queue name (should be present in destinationInfo too)
		const PString& vqueue,
		/// a sequence of aliases for the calling endpoint
		/// (in the "alias:type[=alias:type]..." format)
		const PString& sourceInfo
		);

	/** Make a routing decision for a pending route request (inserted
		by SendRequest).

		@return
		True if the matching pending request has been found, false otherwise.
	*/
	bool RouteToAlias(
		/// aliases for the routing target (an agent that the call will be routed to)
		/// that will replace the original destination info
		const H225_ArrayOf_AliasAddress& agent,
		/// ip that will replace the destionationCallSignalAddress (RouteToGateway)
		/// used only if set (port != 0)
		const PString& destinationip,
		/// identifier of the endpoint associated with the route request
		const PString& callingEpId,
		/// CRV of the call associated with the route request
		unsigned crv
		);

	/** Make a routing decision for a pending route request (inserted
		by SendRequest).

		@return
		True if the matching pending request has been found, false otherwise.
	*/
	bool RouteToAlias(
		/// alias for the routing target that
		/// will replace the original destination info
		const PString& agent,
		/// will replace the original destinationCallSignallAddress
		const PString& destinationip, 		
		/// identifier of the endpoint associated with the route request
		const PString& callingEpId,
		/// CRV of the call associated with the route request
		unsigned crv
		);

	/** Reject a pending route request (inserted by SendRequest).

		@return
		True if the matching pending request has been found, false otherwise.
	*/
	bool RouteReject(
		/// identifier of the endpoint associated with the route request
		const PString& callingEpId,
		/// CRV of the call associated with the route request
		unsigned crv
		);

	/** @return
		True if the specified alias matches a name of an existing virtual queue.
	*/
	bool IsDestinationVirtualQueue(
		const PString& destinationAlias /// alias to be matched
		) const;

private:
	/// a holder for a pending route request
	struct RouteRequest
	{
		RouteRequest(
			const PString& callingEpId,
			unsigned crv,
			H225_ArrayOf_AliasAddress* agent,
			PString* callsignaladdr
			)
			:
			m_callingEpId((const char*)callingEpId), m_crv(crv),
			m_agent(agent), m_callsignaladdr(callsignaladdr) {}

		/// identifier for the endpoint associated with this request
		PString m_callingEpId;
		/// CRV for the call associated with this request
		unsigned m_crv;
		/// aliases for the virtual queue matched (on input)
		/// aliases for the target agent - target route (on output)
		H225_ArrayOf_AliasAddress* m_agent;
		/// destinationCallSignallAddress for the target agent - target route IF NOT NULL
		PString* m_callsignaladdr;
		/// a synchronization point for signalling that routing decision
		/// has been made by the external application
		PSyncPoint m_sync;
	};

	typedef std::list<RouteRequest *> RouteRequests;

	RouteRequest *InsertRequest(
		/// identifier for the endpoint associated with this request
		const PString& callingEpId,
		/// CRV for the call associated with this request
		unsigned crv,
		/// a pointer to an array to be filled with agent aliases
		/// when the routing decision has been made
		H225_ArrayOf_AliasAddress* agent,
		/// a pointer to a string to be filled with a callSignalAddress
		/// when the routing decision has been made (optional)
		PString* callSigAdr,
		/// set by the function to true if another route request for the same
		/// call is pending
		bool& duplicate
		);

	/// an array of names (aliases) for the virtual queues
	PStringArray m_virtualQueueAliases;
	/// an array of prefixes for the virtual queues
	PStringArray m_virtualQueuePrefixes;
	/// a regular expression for the virtual queues
	PString m_virtualQueueRegex;
	/// virtual queues enabled/disabled
	bool m_active;
	/// time (in milliseconds) to wait for a routing decision to be made
	long m_requestTimeout;
	/// a list of active (pending) route requests
	RouteRequests m_pendingRequests;
	/// a mutex protecting pending requests and virtual queues lists
	PMutex m_listMutex;
};


} // end of namespace Routing

#endif // ROUTING_H
