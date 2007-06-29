//////////////////////////////////////////////////////////////////
//
// bookkeeping for RAS-Server in H.323 gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////

#ifndef RASTBL_H
#define RASTBL_H "@(#) $Id$"

#include <list>
#include <vector>
#include <string>
#include "rwlock.h"
#include "singleton.h"
#include "h225.h"
#include "sigmsg.h"
#include "h323util.h"
#include "pwlib_compat.h"


#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 )
#endif

namespace Routing {
	struct Route;
}

class GkDestAnalysisList;
class USocket;
class CallSignalSocket;
class RasServer;
class Q931;
class SignalingMsg;
template <class> class H225SignalingMsg;
typedef H225SignalingMsg<H225_Setup_UUIE> SetupMsg;

// Template of smart pointer
// The class T must have Lock() & Unlock() methods
template<class T> class SmartPtr {
public:
	explicit SmartPtr(T *t = 0) : pt(t) { Inc(); }
	SmartPtr(const SmartPtr<T> & p) : pt(p.pt) { Inc(); }
	~SmartPtr() { Dec(); }
	operator bool() const { return pt != 0; }
	T *operator->() const { return pt; }

	bool operator==(const SmartPtr<T> & p) const { return pt == p.pt; }
	bool operator!=(const SmartPtr<T> & p) const { return pt != p.pt; }

	SmartPtr<T> &operator=(const SmartPtr<T> & p) {
		if (pt != p.pt)
			Dec(), pt = p.pt, Inc();
		return *this;
	}

private:
	void Inc() const { if (pt) pt->Lock(); }
	void Dec() const { if (pt) pt->Unlock(); }
	T &operator*();
	T *pt;
};

class EndpointRec
{
public:
	/** Construct internal/outer zone endpoint from the specified RAS message.
		RRQ builds an internal zone endpoint, ARQ, ACF and LCF build outer zone
		endpoints.
	*/
	EndpointRec(
		/// RRQ, ARQ, ACF or LCF that contains a description of the endpoint
		const H225_RasMessage& ras,
		/// permanent endpoint flag
		bool permanent = false
		);

	virtual ~EndpointRec();

	// public interface to access EndpointRec
	H225_TransportAddress GetRasAddress() const;
	H225_TransportAddress GetCallSignalAddress() const;
	H225_EndpointIdentifier GetEndpointIdentifier() const;
	H225_ArrayOf_AliasAddress GetAliases() const;
	H225_EndpointType GetEndpointType() const;
	int GetTimeToLive() const;
	PIPSocket::Address GetNATIP() const;
	CallSignalSocket *GetSocket();

	int GetCallTypeOfNumber(bool called = true) const { return called ? m_calledTypeOfNumber : m_callingTypeOfNumber; }
	int GetProxyType() const { return m_proxy; }

	/** checks if the given aliases are prefixes of the aliases which are stored
	    for the endpoint in the registration table. #fullMatch# returns #TRUE# if
	    a full match is found.
	    @returns #TRUE# if a match is found
	 */
    bool PrefixMatch_IncompleteAddress(const H225_ArrayOf_AliasAddress &aliases,
	                                bool &fullMatch) const;

	virtual void SetRasAddress(const H225_TransportAddress &);
	virtual void SetCallSignalAddress(const H225_TransportAddress &);
	virtual void SetEndpointIdentifier(const H225_EndpointIdentifier &);
	virtual void SetTimeToLive(int);
	virtual void SetAliases(const H225_ArrayOf_AliasAddress &);
	virtual void SetEndpointType(const H225_EndpointType &);

	virtual void Update(const H225_RasMessage & lightweightRRQ);
	virtual bool IsGateway() const { return false; }

	/** Find if one of the given aliases matches any alias for this endpoint.

		@return
		true if the match has been found, false otherwise.
	*/
	virtual bool CompareAlias(
		/// aliases to be matched (one of them)
		const H225_ArrayOf_AliasAddress* aliases
		) const;

	/** Find if one of the given aliases matches any alias for this endpoint
		and return an index for the matching alias.

		@return
		true if the match has been found, false otherwise.
	*/
	virtual bool MatchAlias(
		/// aliases to be matched (one of them)
		const H225_ArrayOf_AliasAddress& aliases,
		/// filled with an index into aliases for the matching alias (if found)
		int& matchedalias
		) const;

	virtual void LoadAliases(
		/// aliases to be matched (one of them)
	    H225_ArrayOf_AliasAddress& aliases
		);

	/** Load additional endpoint settings from the config file.
	    Derived classes should call LoadConfig method of their base class
	    at the beginning of the overriden LoadConfig.
		
	    @return
		True if the configuration has been updated successfully.	
	*/
	virtual bool LoadConfig();

	virtual EndpointRec *Unregisterpreempt(int type);
	virtual EndpointRec *Unregister();
	virtual EndpointRec *Expired();

	//virtual void BuildACF(H225_AdmissionConfirm &) const;
	//virtual void BuildLCF(H225_LocationConfirm &) const;

	virtual PString PrintOn(bool verbose) const;

	void SetNAT(bool nat);
	void SetNATAddress(const PIPSocket::Address &);
	void SetSocket(CallSignalSocket *);
	void SetSupportNAT(bool support);
	void SetPriority(int priority) { m_registrationPriority = priority; };
	void SetPreemption(bool support) { m_registrationPreemption = support; };
	void SetAssignedGatekeeper(const H225_AlternateGK & gk) { m_assignedGatekeeper = gk; };
	bool SetAssignedAliases(H225_ArrayOf_AliasAddress & assigned);


	/** @return
		true if this is a permanent endpoint loaded from the config file entry.
	*/
	bool IsPermanent() const;
	bool IsUsed() const;
	bool IsUpdated(const PTime *) const;
	bool IsFromParent() const;
	bool IsNATed() const;
	bool SupportNAT() const;

	H225_AlternateGK GetAssignedGatekeeper() { return m_assignedGatekeeper; }

	int  Priority() const { return m_registrationPriority; }
	bool HasNATSocket() const;
	PTime GetUpdatedTime() const;

	/** If this Endpoint would be register itself again with all the same data
	 * how would this RRQ would look like? May be implemented with a
	 * built-together-RRQ, but for the moment a stored RRQ.
	 */
	H225_RasMessage GetCompleteRegistrationRequest() const;

	void AddCall(const PString & dest);
	void AddConnectedCall();
	void RemoveCall(const PString & dest);

	void Lock();
	void Unlock();

	bool SendIRQ();

	bool HasCallCreditCapabilities() const;
	
	/** Append a call credit related service control descriptor to the array
	    of service control sessions, if the endpoint supports call credit 
	    capabilities.
	*/
	virtual bool AddCallCreditServiceControl(
		H225_ArrayOf_ServiceControlSession& sessions, /// array to add the service control descriptor to
		const PString& amountStr, /// user's account balance amount string
		int billingMode, /// user's account billing mode (-1 if not set)
		long callDurationLimit /// call duration limit (-1 if not set)
		);

	/** Append a URL related service control descriptor to the array
	    of service control sessions
	*/
    virtual bool AddHTTPServiceControl(
	    H225_ArrayOf_ServiceControlSession& sessions  /// array to add the service control descriptor to
	    );

	/** @return
	    True if the endpoint can handle at least one more concurrent call.
	*/
	bool HasAvailableCapacity(const H225_ArrayOf_AliasAddress & aliases) const;
	// void DumpPrefixCapacity() const;
	string LongestPrefixMatch(const PString & alias, int * capacity) const;
	void UpdatePrefixStats(const PString & dest, int update);

	// smart pointer for EndpointRec
	typedef SmartPtr<EndpointRec> Ptr;

protected:

	void SetEndpointRec(H225_RegistrationRequest &);
	void SetEndpointRec(H225_AdmissionRequest &);
	void SetEndpointRec(H225_AdmissionConfirm &);
	void SetEndpointRec(H225_LocationConfirm &);

	bool SendURQ(H225_UnregRequestReason::Choices, int preemption);

private:
	/// Load general endpoint settings from the config
	void LoadEndpointConfig();
	void AddPrefixCapacities(const PString & prefixes);

	EndpointRec();
	EndpointRec(const EndpointRec &);
	EndpointRec & operator= (const EndpointRec &);
	
protected:
	/**This field may disappear sometime when GetCompleteRegistrationRequest() can
	 * build its return value itself.
	 * @see GetCompleteRegistrationRequest()
	 */
	H225_RasMessage m_RasMsg;

	H225_TransportAddress m_rasAddress;
	H225_TransportAddress m_callSignalAddress;
	H225_EndpointIdentifier m_endpointIdentifier;
	H225_ArrayOf_AliasAddress m_terminalAliases;
	H225_EndpointType *m_terminalType;
	int m_timeToLive;   // seconds

	int m_activeCall, m_connectedCall, m_totalCall;
	/// active calls per prefix (regex)
	map<string, int> m_activePrefixCalls;

	int m_pollCount, m_usedCount;
	mutable PMutex m_usedLock;

	PTime m_updatedTime;
	bool m_fromParent, m_nat, m_natsupport;
	PIPSocket::Address m_natip;
	CallSignalSocket *m_natsocket;
	/// permanent (preconfigured) endpoint flag
	bool m_permanent;
	/// can understand H.225 CallCreditServiceControl
	bool m_hasCallCreditCapabilities;
	/// session number for call credit service control session
	int m_callCreditSession;
	/// endpoint call capacity, -1 means no limit
	int m_capacity;
	/// capacity per prefix (regex)
	list<pair<string, int> > m_prefixCapacities;
	int m_calledTypeOfNumber, m_callingTypeOfNumber;
	/// Proxy Type
	int m_proxy;
	/// Registration Priority Number
	int m_registrationPriority;
	/// Support Registration PreEmption
	bool m_registrationPreemption;

    /// Assigned Gatekeeper
	H225_AlternateGK m_assignedGatekeeper;
};

typedef EndpointRec::Ptr endptr;


class GatewayRec : public EndpointRec {
public:
	typedef std::map<std::string, int>::iterator prefix_iterator;
	typedef std::map<std::string, int>::const_iterator const_prefix_iterator;

	GatewayRec(const H225_RasMessage & completeRAS, bool Permanent=false);

	virtual void SetEndpointType(const H225_EndpointType &);

	virtual void Update(const H225_RasMessage & lightweightRRQ);
	virtual bool IsGateway() const { return true; }

	/// Overiden from EndpointRec
	virtual bool LoadConfig();

	/** Find if at least one of the given aliases matches any prefix
		for this gateway.

		@return
		Length (number of characters) of the match, 0 if no match has been
		found and this is the default gateway, -1 if no match has been found
		and this is not the default gateway.
	*/
	virtual int PrefixMatch(
		/// aliases to be matched (one of them)
		const H225_ArrayOf_AliasAddress& aliases
		) const;

	/** Find if at least one of the given aliases matches any prefix
		for this gateway and return an index of the matched alias.

		@return
		Length (number of characters) of the match, 0 if no match has been
		found and this is the default gateway, -1 if no match has been found
		and this is not the default gateway.
	*/
	virtual int PrefixMatch(
		/// aliases to be matched (one of them)
		const H225_ArrayOf_AliasAddress& aliases,
		/// filled with an index of the matching alias (if found)
		int& matchedalias,
		/// priority of matched prefix
		int& priority
		) const;

	//virtual void BuildLCF(H225_LocationConfirm &) const;

	virtual PString PrintOn(bool verbose) const;

	void AddPrefixes(const H225_ArrayOf_SupportedProtocols &);
	void AddPrefixes(const PString &);
	void SortPrefixes();

	/** @return
	    Priority for this gateway, when more than one gateway matches
	    a dialed number.
	*/
	int GetPriority() const { return priority; }
	
	/// Set the priority for this gateway.
	void SetPriority(
		int newPriority
		);

	//void DumpPriorities() const;

private:
	/// Load gateway specific settings from the config
	void LoadGatewayConfig();
	
	GatewayRec();
	GatewayRec(const GatewayRec&);
	GatewayRec& operator=(const GatewayRec&);

protected:
	std::map<std::string, int> Prefixes;

	bool defaultGW;
	/// priority for this gateway (when more than one gw matches a dialed number)
	int priority;
};


class OuterZoneEPRec : public EndpointRec {
public:
	OuterZoneEPRec(const H225_RasMessage & completeRAS, const H225_EndpointIdentifier &);

	virtual EndpointRec *Unregister() { return this; }
	virtual EndpointRec *Expired() { return this; }
};


class OuterZoneGWRec : public GatewayRec {
public:
	OuterZoneGWRec(const H225_RasMessage & completeRAS, const H225_EndpointIdentifier &);

	virtual EndpointRec *Unregister() { return this; }
	virtual EndpointRec *Expired() { return this; }
};


class RegistrationTable : public Singleton<RegistrationTable> {
public:
	typedef std::list<EndpointRec *>::iterator iterator;
	typedef std::list<EndpointRec *>::const_iterator const_iterator;

	RegistrationTable();
	~RegistrationTable();

	void Initialize(GkDestAnalysisList & list) { m_destAnalysisList = &list; }

	endptr InsertRec(H225_RasMessage & rrq, PIPSocket::Address = INADDR_ANY);
	void RemoveByEndptr(const endptr & eptr);
	void RemoveByEndpointId(const H225_EndpointIdentifier & endpointId);

	endptr FindByEndpointId(const H225_EndpointIdentifier & endpointId) const;
	endptr FindBySignalAdr(const H225_TransportAddress &, PIPSocket::Address = INADDR_ANY) const;
	endptr FindOZEPBySignalAdr(const H225_TransportAddress &) const;
	endptr FindByAliases(const H225_ArrayOf_AliasAddress & alias) const;
	endptr FindEndpoint(const H225_ArrayOf_AliasAddress & alias, bool RoundRobin, bool SearchOuterZone = true);
	void FindEndpoint(
		const H225_ArrayOf_AliasAddress &aliases,
		bool roundRobin,
		bool searchOuterZone,
		std::list<Routing::Route> &routes
		);

	void ClearTable();
	void CheckEndpoints();

	void PrintAllRegistrations(USocket *client, BOOL verbose=FALSE);
	void PrintAllCached(USocket *client, BOOL verbose=FALSE);
	void PrintRemoved(USocket *client, BOOL verbose=FALSE);

	PString PrintStatistics() const;

//	void PrintOn( ostream &strm ) const;

	/** Updates Prefix + Flags for all aliases */
	void LoadConfig();

	PINDEX Size() const { return regSize; }

private:

	endptr InternalInsertEP(H225_RasMessage &);
	endptr InternalInsertOZEP(H225_RasMessage &, H225_LocationConfirm &);
	endptr InternalInsertOZEP(H225_RasMessage &, H225_AdmissionConfirm &);

	void InternalPrint(USocket *, BOOL, std::list<EndpointRec *> *, PString &);
	void InternalStatistics(const std::list<EndpointRec *> *, unsigned & s, unsigned & t, unsigned & g, unsigned & n) const;

	void InternalRemove(iterator);

	template<class F> endptr InternalFind(const F & FindObject) const
	{ return InternalFind(FindObject, &EndpointList); }

	template<class F> endptr InternalFind(const F & FindObject, const std::list<EndpointRec *> *ListToBeFound) const
	{   //  The function body must be put here,
	    //  or the Stupid VC would fail to instantiate it
        	ReadLock lock(listLock);
        	const_iterator Iter(find_if(ListToBeFound->begin(), ListToBeFound->end(), FindObject));
	        return endptr((Iter != ListToBeFound->end()) ? *Iter : 0);
	}

	endptr InternalFindEP(const H225_ArrayOf_AliasAddress & alias, std::list<EndpointRec *> *ListToBeFound, bool roundrobin);
	void InternalFindEP(const H225_ArrayOf_AliasAddress & alias, std::list<EndpointRec *> *ListToBeFound, bool roundrobin, std::list<Routing::Route> &routes);

	void GenerateEndpointId(H225_EndpointIdentifier &);
	void GenerateAlias(H225_ArrayOf_AliasAddress &, const H225_EndpointIdentifier &) const;

	GkDestAnalysisList & getGkDestAnalysisList() { return *m_destAnalysisList; }
	std::list<EndpointRec *> EndpointList;
	std::list<EndpointRec *> OuterZoneList;
	std::list<EndpointRec *> RemovedList;
	int regSize;
	mutable PReadWriteMutex listLock;
	PMutex findmutex;          // Endpoint Find Mutex
	GkDestAnalysisList * m_destAnalysisList;

	// counter to generate endpoint identifier
	// this is NOT the count of endpoints!
	int recCnt, ozCnt;
	PString endpointIdSuffix; // Suffix of the generated Endpoint IDs

	// not assignable
	RegistrationTable(const RegistrationTable &);
	RegistrationTable& operator=(const RegistrationTable &);
};


template<class> class RasPDU;

// record of one active call
class CallRec {
public:
	/// flag to overwrite proxy settings for the call
	enum ProxyMode {
		ProxyDetect, /// use global settings from the config
		ProxyEnabled, /// force full proxy mode
		ProxyDisabled /// disable full proxy mode
	};

	/// who disconnected the call
	enum ReleaseSource {
		ReleasedByGatekeeper,
		ReleasedByCaller,
		ReleasedByCallee
	};

	/// build a new call record from the received ARQ message
	CallRec(
		/// ARQ with call information
		const RasPDU<H225_AdmissionRequest>& arq,
		/// bandwidth occupied by the call
		int bandwidth,
		/// called party's aliases in a string form
		const PString& destInfo,
		/// override proxy mode global setting from the config
		int proxyMode = ProxyDetect
		);

	/// build a new call record from the received Setup message
	CallRec(
		/// Q.931 Setup pdu with call information
		const Q931& q931pdu,
		/// H.225.0 Setup-UUIE pdu with call information
		const H225_Setup_UUIE& setup,
		/// force H.245 routed mode
		bool routeH245,
		/// called party's aliases in a string form
		const PString& destInfo,
		/// override proxy mode global setting from the config
		int proxyMode = ProxyDetect
		);
	
	CallRec(
		CallRec *oldCall
		);
		
	virtual ~CallRec();

	enum NATType { // who is nated?
		none = 0,
		callingParty = 1,
		calledParty = 2,
		both = 3,
		citronNAT = 4  // caller with Citron NAT Technology?
	};

	PINDEX GetCallNumber() const
	{ return m_CallNumber; }
	const H225_CallIdentifier & GetCallIdentifier() const
	{ return m_callIdentifier; }
	const H225_ConferenceIdentifier & GetConferenceIdentifier() const
	{ return m_conferenceIdentifier; }
	endptr GetCallingParty() const { return m_Calling; }
	endptr GetCalledParty() const { return m_Called; }
	endptr GetForwarder() const { return m_Forwarder; }
	int GetBandwidth() const { return m_bandwidth; }

	/** @return
	    A bit mask with NAT flags for calling and called parties. 
	    See #NATType enum# for more details.
	*/
	int GetNATType() const { return m_nattype; }
	int GetNATType(
		/// filled with NAT IP of the calling party (if nat type is callingParty)
		PIPSocket::Address& callingPartyNATIP, 
		/// filled with NAT IP of the called party (if nat type is calledParty)
		PIPSocket::Address& calledPartyNATIP
		) const;

	/** @return
	    Current proxy mode flag (see #ProxyMode enum#).
	*/
	int GetProxyMode() const { return m_proxyMode; }
	
	/// Override proxy mode global setting from the config
	void SetProxyMode(
		int mode /// proxy mode flag (see #ProxyMode enum#)
		);

	CallSignalSocket *GetCallSignalSocketCalled() { return m_calledSocket; }
	CallSignalSocket *GetCallSignalSocketCalling() { return m_callingSocket; }
	const H225_ArrayOf_CryptoH323Token & GetAccessTokens() const { return m_accessTokens; }
	PString GetInboundRewriteId() const { return m_inbound_rewrite_id; }
	PString GetOutboundRewriteId() const { return m_outbound_rewrite_id; }

	void SetCallNumber(PINDEX i) { m_CallNumber = i; }
	void SetCalling(const endptr & NewCalling);
	void SetCalled(const endptr & NewCalled);
	void SetForward(CallSignalSocket *, const H225_TransportAddress &, const endptr &, const PString &, const PString &);
	void SetBandwidth(int bandwidth) { m_bandwidth = bandwidth; }
	void SetSocket(CallSignalSocket *, CallSignalSocket *);
	void SetCallSignalSocketCalling(CallSignalSocket* socket);
	void SetCallSignalSocketCalled(CallSignalSocket* socket);
	void SetToParent(bool toParent) { m_toParent = toParent; }
	void SetAccessTokens(const H225_ArrayOf_CryptoH323Token & tokens) { m_accessTokens = tokens; }
	void SetInboundRewriteId(PString id) { m_inbound_rewrite_id = id; }
	void SetOutboundRewriteId(PString id) { m_outbound_rewrite_id = id; }

	void SetConnected();

	void Disconnect(bool = false); // Send Release Complete?
	void RemoveAll();
	void RemoveSocket();
	void SendReleaseComplete(const H225_CallTerminationCause * = 0);
	void BuildDRQ(H225_DisengageRequest &, unsigned reason) const;

	int CountEndpoints() const;

	bool CompareCallId(const H225_CallIdentifier *CallId) const;
	bool CompareCRV(WORD crv) const;
	bool CompareCallNumber(PINDEX CallNumber) const;
	bool CompareEndpoint(const endptr *) const;
	bool CompareSigAdr(const H225_TransportAddress *adr) const;

	bool IsUsed() const { return (m_usedCount != 0); }

	/** @return
		true if the call has been connected - a Connect message
		has been received in gk routed signalling or the call has been admitted
		(ARQ->ACF) in direct signalling. Does not necessary mean
		that the call is still in progress (may have been already disconnected).
	*/
	bool IsConnected() const { return (m_connectTime != 0); }

	bool IsH245Routed() const { return m_h245Routed; }
	bool IsToParent() const { return m_toParent; }
	bool IsForwarded() const { return m_forwarded; }
	bool IsSocketAttached() const { return (m_callingSocket != 0); }

	PString GenerateCDR(
		/// timestamp formatting string (empty for a default RFC822 format)
		const PString& timestampFormat = PString()
		) const;
	PString PrintOn(bool verbose) const;

	void Lock();
	void Unlock();

	/** @return
		Q.931 ReleaseComplete cause code for the call.
		0 if the disconnect cause could not be determined.
	*/
	unsigned GetDisconnectCause() const;

	/** Set Q.931 ReleaseComplete cause code associated with this call. */
	void SetDisconnectCause(
		unsigned causeCode
		);

	/// @return	Information about who disconnected the call (see #ReleaseSource enum#)
	int GetReleaseSource() const;

	/// Set information about who disconnected the call
	void SetReleaseSource(
		int releaseSentFrom /// see #ReleaseSource enum#
		);

	/** Set maximum duration limit (in seconds) for this call */
	void SetDurationLimit(
		long seconds /// duration limit to be set
		);

	/** @return
		Duration limit (in seconds) set for this call.
		0 if call duration is not limited.
	*/
	long GetDurationLimit() const;

	/** This function can be used to determine, if the call has been
		disconnected due to call duration limit excess.

		@return
		true if the call duration limit has been exceeded, false otherwise.
	*/
	bool IsDurationLimitExceeded() const;

	/** @return
		Timestamp (number of seconds since 1st January 1970) for the call creation
		(when this CallRec object has been instantiated).
	*/
	time_t GetCreationTime() const;

	/** @return
		Timestamp (number of seconds since 1st January 1970)
		for the Setup message associated with this call. 0 if Setup
		has not been yet received.
		Meaningful only in GK routed mode.
	*/
	time_t GetSetupTime() const;

	/** Set timestamp for a Setup message associated with this call. */
	void SetSetupTime(
		time_t tm /// timestamp (seconds since 1st January 1970)
		);

	/** @return
		Timestamp (number of seconds since 1st January 1970) 
		for the Alerting message associated with this call. 0 if Alerting
		has not been yet received.
		Meaningful only in GK routed mode.
	*/
	time_t GetAlertingTime() const;

	/** Set timestamp for a Alerting message associated with this call. */
	void SetAlertingTime( 
		time_t tm /// timestamp (seconds since 1st January 1970)
		);

	/** @return
		Timestamp (number of seconds since 1st January 1970)
		for the Connect message associated with this call. 0 if Connect
		has not been yet received. If GK is not in routed mode, this is
		timestamp for ACF generated as a response to ARQ.
	*/
	time_t GetConnectTime() const;

	/** Set timestamp for a Connect (or ACF) message associated with this call. */
	void SetConnectTime(
		time_t tm /// timestamp (seconds since 1st January 1970)
		);

	/** @return
		Timestamp (number of seconds since 1st January 1970)
		for the call disconnect event. 0 if call has not been yet disconnected
		or connected.
	*/
	time_t GetDisconnectTime() const;

	/** Set timestamp for a disconnect event for this call. */
	void SetDisconnectTime(
		time_t tm /// timestamp (seconds since 1st January 1970)
		);

	/** @return
		Timestamp for the most recent accounting update event logged for this call.
	*/
	time_t GetLastAcctUpdateTime() const { return m_acctUpdateTime; }

	/** Set timestamp for the most recent accounting update event logged
		for this call.
	*/
	void SetLastAcctUpdateTime(
		const time_t tm /// timestamp of the recent accounting update operation
		)
	{
		m_acctUpdateTime = tm;
	}

	/** Check if:
		- a signalling channel associated with this call is not timed out
		  and the call should be disconnected (removed from CallTable);
		- call duration limit has been exceeded
		- call should be disconnected from other reason

		@return
		true if call is timed out and should be disconnected, false otherwise.
	*/
	bool IsTimeout(
		/// point in time for timeouts to be measured relatively to
		/// (made as a parameter for performance reasons)
		const time_t now
		) const;

	/** @return
		Call duration in seconds. 0 for unconnected calls. Actual
		duration for calls in progress.
	*/
	long GetDuration() const;

	/** @return
		Call total time in seconds. 0 for calls without disconnect.
	*/
	long GetTotalCallDuration() const;

	/** @return
		Call Post Dial Delay in seconds.
	*/
	long GetPostDialDelay() const;

	/** @return
		Call ring time in seconds. 0 for calls without Alerting.
	*/
	long GetRingTime() const;

	/** @return
		A string that identifies uniquelly this call for accounting
		purposes. This string should be unique across subsequent GK
		start/stop events.
	*/
	PString GetAcctSessionId() const { return m_acctSessionId; }

	/** @return
		A string with ARQ.m_srcInfo for registered endpoints
		and Setup.m_sourceAddress for unregistered endpoints.
		The string has alias type appended (example: '772:dialedDigits')
		and for forwarded calls contains alias of forwarding
		after '=' (example: '772:dialedDigits=775:forward').
	*/
	PString GetSrcInfo() const { return m_srcInfo; }

	/** Set a new address for the calling party signalling channel.
	*/
	void SetSrcSignalAddr(
		const H225_TransportAddress & addr /// new signalling transport address
		);

	/** Set the unregistered calling party signalling channel as NATed.
	*/
	void SetSrcNATed(PIPSocket::Address & natip);

	/** Set a new address for the called party signalling channel.
	*/
	void SetDestSignalAddr(
		const H225_TransportAddress & addr /// new signalling transport address
		);

	/** Get IP and port for the calling party. It is a signal address
		for registered endpoints and remote signalling socket address
		for unregistered endpoints.

		@return
		true if the address has been retrieved successfully, false otherwise.
	*/
	bool GetSrcSignalAddr(
		PIPSocket::Address& addr, /// will receive the IP address
		WORD& port /// will receive the port number
		) const;

	H225_TransportAddress GetDestSignalAddr() const;

	/** Get IP and port for the called party. It is a signal address
		for registered endpoints and remote signalling socket address
		for unregistered endpoints.

		@return
		true if the address has been retrieved successfully, false otherwise.
	*/
	bool GetDestSignalAddr(
		PIPSocket::Address& addr, /// will receive the IP address
		WORD& port /// will receive the port number
		) const;

	/** @return
		A string with ARQ.m_destinationInfo or ARQ.m_destCallSignalAddress
		or "unknown" for registered endpoints
		and Setup.m_destinationAddress or called endpoint IP address
		for unregistered endpoints.
		The string has alias type appended (example: '772:dialedDigits')
		and for forwarded calls contains alias of forwarding
		after '=' (example: '772:dialedDigits=775:forward').
	*/
	PString GetDestInfo() const { return m_destInfo; }

	/** @return
	    Calling party's aliases, as presented in ARQ or Setup messages.
	    This does not change during the call.
	*/
	const H225_ArrayOf_AliasAddress& GetSourceAddress() const 
		{ return m_sourceAddress; }
		
	/** @return
	    Called party's aliases, as presented in ARQ or Setup messages.
	    This does not change during the call now, but should be fixed
	    to handle gatekeeper call forwarding properly.
	*/
	const H225_ArrayOf_AliasAddress& GetDestinationAddress() const
		{ return m_destinationAddress; }

	/** @return
	    Calling party's number or an empty string, if the number has not been
	    yet determined.
	*/
	PString GetCallingStationId();
	
	/// Set calling party's number
	void SetCallingStationId(
		const PString& id /// Calling-Station-Id
		);
		
	/** @return
	    Called party's number or an empty string, if the number has not been
	    yet determined.
	*/
	PString GetCalledStationId();

	/// Set call linkage This the party to be charged for the call. 
	void SetCallLinkage(
		const PString& id /// Calling-Station-Id (to be charged)
		);

	/** @return
        Call party to be charged for the call.
	*/
	PString GetCallLinkage()const { return m_callLinkage; };


	/// Set calling party's number
	void SetCalledStationId(
		const PString& id /// Called-Station-Id
		);

	/** @return
	    Called party's number before rewrite or an empty string, 
	    if the number has not been yet determined.
	*/
	PString GetDialedNumber();

	/// Set dialed number
	void SetDialedNumber(
		const PString& number /// Dialed-Number
		);

	/** @return
	    Fixed destination address for the call (NULL if not set).
	*/
	H225_AliasAddress* GetRouteToAlias() const;
	
	/// Set fixed destination address for the call
	void SetRouteToAlias(
		const H225_AliasAddress& alias /// alias to set
		);

	// smart pointer for CallRec
	typedef SmartPtr<CallRec> Ptr;

	/// update IRR timers
	void Update(const H225_InfoRequestResponse & irr);

	void SetNewRoutes(
		const std::list<Routing::Route> &routes
		);
	const std::list<Routing::Route> &GetNewRoutes() const { return m_newRoutes; }
	const std::list<Routing::Route> &GetFailedRoutes() const { return m_failedRoutes; }
	bool MoveToNextRoute();

	bool IsCallInProgress() const;
	void SetCallInProgress();

	bool IsH245ResponseReceived() const;
	void SetH245ResponseReceived();
	
	bool IsFastStartResponseReceived() const;
	void SetFastStartResponseReceived();

	bool SingleFailoverCDR() const;
	int GetNoCallAttempts() const;
	int GetNoRemainingRoutes() const;
	bool DisableRetryChecks() const;

	void SetCodec(const PString &codec);
	PString GetCodec() const;

	void SetMediaOriginatingIp(const PIPSocket::Address &addr);
	bool GetMediaOriginatingIp(PIPSocket::Address &addr) const;

	void SetRADIUSClass(const PBYTEArray &bytes);
	void SetRADIUSClass(void * bytes, PINDEX len);
	PBYTEArray GetRADIUSClass() const;

private:
	void SendDRQ();
	void InternalSetEP(endptr &, const endptr &);

	CallRec(const CallRec & Other);
	CallRec & operator= (const CallRec & other);

private:
	/// internal call number generated by the gatekeeper
	PINDEX m_CallNumber;
	/// H.323 Call Identifier (identifies this particular call leg)
	H225_CallIdentifier m_callIdentifier;
	/// H.323 Conference Identifier
	H225_ConferenceIdentifier m_conferenceIdentifier;
	/// Call Reference Value for the call
	WORD m_crv;
	/// EndpointRec for the calling party (if it is a registered endpoint)
	/// NOTE: it does not change during CallRec lifetime
	endptr m_Calling;
	/// EndpointRec for the called party (if it is a registered endpoint)
	/// NOTE: it can change during CallRec lifetime
	endptr m_Called;
	/// aliases identifying a calling party (as presented in ARQ or Setup)
	H225_ArrayOf_AliasAddress m_sourceAddress;
	/// aliases identifying a called party (as presented in ARQ or Setup)
	H225_ArrayOf_AliasAddress m_destinationAddress;
	/// calling party aliases in a string form
	PString m_srcInfo;
	/// called party aliases in a string form
	PString m_destInfo;
	/// bandwidth occupied by this call (as declared in ARQ)
	int m_bandwidth;

	PString m_callerAddr, m_callerId;
	PString m_calleeAddr, m_calleeId;
	// rewrite id for inbound leg of call
	PString m_inbound_rewrite_id;
	// rewrite id for outbound leg of call
	PString m_outbound_rewrite_id;

	/// current timeout (or duration limit) for the call
	long m_timeout;
	/// timestamp for call timeout measuring
	time_t m_timer;
	/// timestamp (seconds since 1st January, 1970) for the call creation
	/// (triggered by ARQ or Setup)
	time_t m_creationTime;
	/// timestamp (seconds since 1st January, 1970) for a Setup message reception
	time_t m_setupTime;
	/// timestamp (seconds since 1st January, 1970) for a Alerting message reception
	time_t m_alertingTime;
	/// timestamp (seconds since 1st January, 1970) for a Connect (routed mode)
	/// or ARQ/ACF (direct mode) message reception
	time_t m_connectTime;
	/// timestamp (seconds since 1st January, 1970) for the call disconnect
	time_t m_disconnectTime;
	/// timestamp for the most recent accounting update event logged for this call
	time_t m_acctUpdateTime;
	/// duration limit (seconds) for this call, 0 means no limit
	long m_durationLimit;
	/// Q.931 release complete cause code
	unsigned m_disconnectCause;
	/// who disconnected the call (see #RelaseSource enum#)
	int  m_releaseSource;
	/// unique accounting session id associated with this call
	PString m_acctSessionId;
	/// signalling transport address of the calling party
	H225_TransportAddress m_srcSignalAddress;
	/// signalling transport address of the called party
	H225_TransportAddress m_destSignalAddress;
	/// calling party's number
	PString m_callingStationId;
	/// called party's number
	PString m_calledStationId;
	/// party to be charged for the call
	PString m_callLinkage;
	/// dialed number (called party's number before rewrite)
	PString m_dialedNumber;
	/// fixed destination alias
	H225_AliasAddress* m_routeToAlias;

	CallSignalSocket *m_callingSocket, *m_calledSocket;

	int m_usedCount;
	mutable PTimedMutex m_usedLock, m_sockLock;
	int m_nattype;

	/// unregistered caller NAT'd
	bool m_unregNAT;
	PIPSocket::Address m_srcunregNATAddress;

	bool m_h245Routed;
	/// the call is routed to this gatekeeper's parent gatekeeper
	bool m_toParent;
	bool m_forwarded;
	endptr m_Forwarder;

	/// enable/disable proxy mode (override global settings from the config)
	int m_proxyMode;
	
	H225_ArrayOf_CryptoH323Token m_accessTokens;

	/// IRR checking
	long m_irrFrequency;
	bool m_irrCheck;
	time_t m_irrCallerTimer;
	time_t m_irrCalleeTimer;
	
	std::list<Routing::Route> m_failedRoutes;
	std::list<Routing::Route> m_newRoutes;
	bool m_callInProgress;
	bool m_h245ResponseReceived;
	bool m_fastStartResponseReceived;
	bool m_singleFailoverCDR;
	
	PString m_codec;
	PIPSocket::Address m_mediaOriginatingIp;
	PBYTEArray m_radiusClass;
};

typedef CallRec::Ptr callptr;

// all active calls
class CallTable : public Singleton<CallTable>
{
public:
	typedef std::list<CallRec *>::iterator iterator;
	typedef std::list<CallRec *>::const_iterator const_iterator;

	CallTable();
	~CallTable();

	void Insert(CallRec * NewRec);

	// bandwidth management
	void SetTotalBandwidth(int bw);
	bool GetAdmission(int bw);
	bool GetAdmission(int bw, const callptr &);
	int GetAvailableBW() const { return m_capacity; }

	callptr FindCallRec(const H225_CallIdentifier & CallId) const;
	callptr FindCallRec(const H225_CallReferenceValue & CallRef) const;
	callptr FindCallRec(PINDEX CallNumber) const;
	callptr FindCallRec(const endptr &) const;
	callptr FindBySignalAdr(const H225_TransportAddress & SignalAdr) const;

	void ClearTable();
	void CheckCalls(
		RasServer* rassrv // to avoid call RasServer::Instance every second
		);

	void RemoveCall(const H225_DisengageRequest & obj_drq, const endptr &);
	void RemoveCall(const callptr &);
	void RemoveFailedLeg(const callptr &);

	void PrintCurrentCalls(USocket *client, BOOL verbose=FALSE) const;
	PString PrintStatistics() const;

	void AddForwardedCall(const callptr &);
	endptr IsForwardedCall(const callptr &);

	void LoadConfig();

	PINDEX Size() const { return m_activeCall; }

	/** @return
	    Timeout value for a signalling channel to be opened after ACF
	    and for an Alerting message to be received after signalling start.
	    The value is expressed in milliseconds.
	*/
	long GetSignalTimeout() const { return m_signalTimeout; }

	/** @return
	    Timeout value for Connect message to be received after a call entered
	    the Alerting state. The value is expressed in milliseconds.
	*/
	long GetAlertingTimeout() const { return m_alertingTimeout; }

	/** @return
		Default call duration limit value (seconds).
	*/
	long GetDefaultDurationLimit() const { return m_defaultDurationLimit; }

	/// @return	True to log accounting for each call leg
	bool SingleFailoverCDR() const { return m_singleFailoverCDR; }

private:
	template<class F> callptr InternalFind(const F & FindObject) const
	{
        	ReadLock lock(listLock);
        	const_iterator Iter(find_if(CallList.begin(), CallList.end(), FindObject));
	        return callptr((Iter != CallList.end()) ? *Iter : 0);
	}

	bool InternalRemovePtr(CallRec *call);
	void InternalRemove(const H225_CallIdentifier & CallId);
	void InternalRemove(WORD CallRef);
	void InternalRemove(iterator);
	void InternalRemoveFailedLeg(iterator);

	void InternalStatistics(unsigned & n, unsigned & act, unsigned & nb, unsigned & np, PString & msg, BOOL verbose) const;

	std::list<CallRec *> CallList;
	std::list<CallRec *> RemovedList;

	bool m_genNBCDR;
	bool m_genUCCDR;

	PINDEX m_CallNumber;
	mutable PReadWriteMutex listLock;

	int m_capacity;

	// statistics
	unsigned m_CallCount, m_successCall, m_neighborCall, m_parentCall, m_activeCall;

	/// timeout for a Connect message to be received
	/// and for a signalling channel to be opened after ACF/ARQ
	/// (0 if GK is not in routed mode)
	long m_signalTimeout;
	/// timeout for a Connect message to be received after getting an Alerting message
	long m_alertingTimeout;
	/// default call duration limit read from the config
	long m_defaultDurationLimit;
	/// default interval (seconds) for accounting updates to be logged
	long m_acctUpdateInterval;
	/// timestamp formatting string for CDRs
	PString m_timestampFormat;
	/// flag to trigger per call leg accounting
	bool m_singleFailoverCDR;

	CallTable(const CallTable &);
	CallTable& operator==(const CallTable &);
};

// inline functions of EndpointRec
inline H225_TransportAddress EndpointRec::GetRasAddress() const
{ 
	PWaitAndSignal lock(m_usedLock);
	return m_rasAddress;
}

inline void EndpointRec::SetRasAddress(const H225_TransportAddress & addr)
{ 
	PWaitAndSignal lock(m_usedLock);
	m_rasAddress = addr;
}

inline void EndpointRec::SetCallSignalAddress(const H225_TransportAddress & addr) 
{
	PWaitAndSignal lock(m_usedLock);
    m_callSignalAddress = addr;
}

inline H225_TransportAddress EndpointRec::GetCallSignalAddress() const
{ 
	PWaitAndSignal lock(m_usedLock);
	return m_callSignalAddress;
}

inline H225_EndpointIdentifier EndpointRec::GetEndpointIdentifier() const
{
	PWaitAndSignal lock(m_usedLock);
	return m_endpointIdentifier;
}
  
inline int EndpointRec::GetTimeToLive() const
{
	return m_timeToLive;
}

inline H225_ArrayOf_AliasAddress EndpointRec::GetAliases() const
{
	PWaitAndSignal lock(m_usedLock);
	return m_terminalAliases;
}

inline H225_EndpointType EndpointRec::GetEndpointType() const
{
	PWaitAndSignal lock(m_usedLock);
	return *m_terminalType;
}

inline void EndpointRec::SetNAT(bool nat)
{ 
	m_nat = nat;
}

inline void EndpointRec::SetSupportNAT(bool support)
{
	m_natsupport = support;
}

inline bool EndpointRec::IsNATed() const
{ 
	return m_nat;
}

inline bool EndpointRec::SupportNAT() const
{
	return m_natsupport;
}

inline PIPSocket::Address EndpointRec::GetNATIP() const
{
	PWaitAndSignal lock(m_usedLock);
	return m_natip;
}

inline CallSignalSocket *EndpointRec::GetSocket() 
{
	PWaitAndSignal lock(m_usedLock);
	CallSignalSocket *socket = m_natsocket;
	m_natsocket = 0;
	return socket;
}

inline bool EndpointRec::IsPermanent() const
{
	return m_permanent;
}

inline bool EndpointRec::IsUsed() const
{
	PWaitAndSignal lock(m_usedLock);
	return (m_activeCall > 0 || m_usedCount > 0);
}

inline bool EndpointRec::IsUpdated(const PTime *now) const
{
	PWaitAndSignal lock(m_usedLock);
	return (!m_timeToLive || (*now - m_updatedTime).GetSeconds() < m_timeToLive);
}

inline bool EndpointRec::IsFromParent() const
{
	return m_fromParent;
}

inline bool EndpointRec::HasNATSocket() const
{
	return m_natsocket;
}

inline PTime EndpointRec::GetUpdatedTime() const
{ 
	PWaitAndSignal lock(m_usedLock);
	return m_updatedTime;
}

inline H225_RasMessage EndpointRec::GetCompleteRegistrationRequest() const
{ 
	PWaitAndSignal lock(m_usedLock);
	return m_RasMsg;
}

inline bool EndpointRec::HasCallCreditCapabilities() const
{ 
	return m_hasCallCreditCapabilities;
}

void UpdatePrefixStats(const PString & dest, int update);

inline void EndpointRec::AddCall(const PString & dest)
{
	PWaitAndSignal lock(m_usedLock);
	++m_activeCall, ++m_totalCall;
	UpdatePrefixStats(dest, +1);
}

inline void EndpointRec::AddConnectedCall()
{
	PWaitAndSignal lock(m_usedLock);
	++m_connectedCall;
}

inline void EndpointRec::RemoveCall(const PString & dest)
{
	PWaitAndSignal lock(m_usedLock);
	--m_activeCall;
	UpdatePrefixStats(dest, -1);
}

inline void EndpointRec::Lock()
{
	PWaitAndSignal lock(m_usedLock);
	++m_usedCount;
}

inline void EndpointRec::Unlock()
{
	PWaitAndSignal lock(m_usedLock);
	--m_usedCount;
}

// inline functions of CallRec
inline void CallRec::Lock()
{
	PWaitAndSignal lock(m_usedLock);
	++m_usedCount;
}

inline void CallRec::Unlock()
{
	PWaitAndSignal lock(m_usedLock);
	--m_usedCount;
}

inline bool CallRec::CompareCallId(const H225_CallIdentifier *CallId) const
{
	return (m_callIdentifier == *CallId);
}

inline bool CallRec::CompareCRV(WORD crv) const
{
	return m_crv == (crv & 0x7fffu);
}

inline bool CallRec::CompareCallNumber(PINDEX CallNumber) const
{
	return (m_CallNumber == CallNumber);
}

inline bool CallRec::CompareEndpoint(const endptr *ep) const
{
	return (m_Calling && m_Calling == *ep) || (m_Called && m_Called == *ep);
}

inline bool CallRec::CompareSigAdr(const H225_TransportAddress *adr) const
{
	return (m_Calling && m_Calling->GetCallSignalAddress() == *adr) ||
		(m_Called && m_Called->GetCallSignalAddress() == *adr);
}

inline long CallRec::GetDurationLimit() const
{
	return m_durationLimit;
}

inline time_t CallRec::GetCreationTime() const
{
	return m_creationTime;
}

inline time_t CallRec::GetSetupTime() const
{
	return m_setupTime;
}

inline time_t CallRec::GetAlertingTime() const
{
	return m_alertingTime;
}

inline time_t CallRec::GetConnectTime() const
{
	return m_connectTime;
}

inline time_t CallRec::GetDisconnectTime() const
{
	return m_disconnectTime;
}

inline unsigned CallRec::GetDisconnectCause() const
{
	return m_disconnectCause;
}

inline void CallRec::SetDisconnectCause( unsigned causeCode )
{
	// set the cause only if it has not been already set
	if( m_disconnectCause == 0 )
		m_disconnectCause = causeCode;
}

inline bool CallRec::IsTimeout(const time_t now) const
{
	bool result = (m_timeout > 0) && (now >= m_timer) && ((now - m_timer) >= m_timeout);
	if (m_irrCheck && (m_irrFrequency > 0)) {
		if (m_Calling)
			result |= (now >= m_irrCallerTimer) && ((now - m_irrCallerTimer) >= 2 * m_irrFrequency);
		if (m_Called)
			result |= (now >= m_irrCalleeTimer) && ((now - m_irrCalleeTimer) >= 2 * m_irrFrequency);
	}
	return result;
}

#endif // RASTBL_H
