//////////////////////////////////////////////////////////////////
//
// bookkeeping for RAS-Server in H.323 gatekeeper
//
// Copyright (c) 2000-2017, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef RASTBL_H
#define RASTBL_H "@(#) $Id$"

#include <list>
#include <map>
#include <string>
#include "rwlock.h"
#include "singleton.h"
#include "h225.h"
#include "sigmsg.h"
#include "config.h"
#include "gktimer.h"
#include "h323util.h"
#include "gkh235.h"

#ifdef HAS_H235_MEDIA
#include "h235auth.h"
#endif


namespace Routing {
	class Route;
}

class USocket;
class CallSignalSocket;
class RasServer;
class Q931;
class H323TransportAddress;

enum CallLeg { Caller, Called };
enum RerouteState { NoReroute, RerouteInitiated, Rerouting };
enum H46019Side { SideA, SideB };
const int INVALID_OSSOCKET = -1;
const WORD INVALID_RTP_SESSION = 0;
const PUInt32b INVALID_MULTIPLEX_ID = 0;
const BYTE GNUGK_KEEPALIVE_RTP_PAYLOADTYPE = 116;	// must at least be 1 less than MAX_DYNAMIC_PAYLOAD_TYPE
const BYTE MIN_DYNAMIC_PAYLOAD_TYPE = 96;
const BYTE MAX_DYNAMIC_PAYLOAD_TYPE = 127;

enum PortType { RASPort=1, Q931Port=2, H245Port=3, RTPPort=4, T120Port=5, RadiusPort=6, StatusPort=7 };
enum PortAction { PortOpen=1, PortClose=2 };

class DynamicPort
{
public:
	DynamicPort(PortType type, PIPSocket::Address ip, WORD port) { m_type = type; m_ip = ip; m_port = port; }

	bool operator==(const DynamicPort & other) const { return m_type == other.m_type && m_ip == other.m_ip && m_port == other.m_port; }

	PortType m_type;
	PIPSocket::Address m_ip;
	WORD m_port;
};


// Template of smart pointer
// The class T must have Lock() & Unlock() methods
template<class T> class SmartPtr {
public:
	explicit SmartPtr(T *t = NULL) : pt(t) { Inc(); }
	SmartPtr(const SmartPtr<T> & p) : pt(p.pt) { Inc(); }
	~SmartPtr() { Dec(); }
	operator bool() const { return pt != NULL; }
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

enum H46019TraversalType { None, TraversalClient, TraversalServer };

class EndpointRec
{
public:
	/** Construct internal/out-of-zone endpoint from the specified RAS message.
		RRQ builds an internal zone endpoint, ARQ, ACF and LCF build out-of-zone
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
	PIPSocket::Address GetIP() const;
	H225_EndpointIdentifier GetEndpointIdentifier() const;
	H225_ArrayOf_AliasAddress GetAliases() const;
	H225_EndpointType GetEndpointType() const;
    bool GetEndpointInfo(PString & vendor, PString & version) const;
	int GetTimeToLive() const;
	PIPSocket::Address GetNATIP() const;
	CallSignalSocket *GetSocket();
	CallSignalSocket *GetAndRemoveSocket();

	int GetCallTypeOfNumber(bool called = true) const { return called ? m_calledTypeOfNumber : m_callingTypeOfNumber; }
	int GetCallPlanOfNumber(bool called = true) const { return called ? m_calledPlanOfNumber : m_callingPlanOfNumber; }
	int GetProxyType() const { return m_proxy; }

	virtual void SetRasAddress(const H225_TransportAddress &);
	virtual void SetCallSignalAddress(const H225_TransportAddress &);
	virtual void SetTimeToLive(int);
	virtual bool SetAliases(const H225_ArrayOf_AliasAddress &, PBoolean = false);
	virtual bool RemoveAliases(const H225_ArrayOf_AliasAddress &);
	virtual void AddNumbers(const PString & numbers);
	virtual void SetEndpointType(const H225_EndpointType &);
    virtual void SetEndpointInfo(const PString & vendor, const PString & version);
	virtual long GetBandwidth() const { return m_bandwidth; }
	virtual void SetBandwidth(long bw) { m_bandwidth = bw;  if (m_bandwidth < 0) m_bandwidth = 0; }
	virtual int GetMaxBandwidth() const { return m_maxBandwidth; }

	virtual void Update(const H225_RasMessage & lightweightRRQ);
	virtual bool IsGateway() const { return false; }

	virtual void SetAdditiveRegistrant();
	virtual bool IsAdditiveRegistrant() const;

	/** Find if one of the given aliases matches any alias for this endpoint.

		@return
		true if the match has been found, false otherwise.
	*/
	virtual bool CompareAlias(
		/// aliases to be matched (one of them)
		const H225_ArrayOf_AliasAddress* aliases
		) const;

	virtual void LoadAliases(
		/// aliases to be matched (one of them)
	    const H225_ArrayOf_AliasAddress& aliases,
		const H225_EndpointType & type
		);

	/** Load additional endpoint settings from the config file.
	    Derived classes should call LoadConfig method of their base class
	    at the beginning of the overriden LoadConfig.

	    @return
		True if the configuration has been updated successfully.
	*/
	virtual bool LoadConfig();

	GkH235Authenticators * GetH235Authenticators();
	void SetH235Authenticators(GkH235Authenticators * auth);

	virtual EndpointRec *Unregisterpreempt(int type);
	virtual EndpointRec *Reregister();
	virtual EndpointRec *Unregister();
	virtual EndpointRec *Expired();

	//virtual void BuildACF(H225_AdmissionConfirm &) const;
	//virtual void BuildLCF(H225_LocationConfirm &) const;

	virtual PString PrintOn(bool verbose) const;
	PString PrintPrefixCapacities() const;
	PString PrintNatInfo(bool verbose) const;

	void SetNAT(bool nat);
	void SetNATAddress(const PIPSocket::Address &, WORD port = 0);
	void SetNATSocket(CallSignalSocket * socket);
	void RemoveNATSocket();
	void NullNATSocket();
	void SetH46024(bool support);
	void SetH46024A(bool support);
	void SetH46024B(bool support);

	enum EPNatTypes {
            NatUnknown,
            NatOpen,
            NatCone,
            NatRestricted,
            NatPortRestricted,
            NatSymmetric,
            FirewallSymmetric,
            NatBlocked,
            NatPartialBlocked
       };

	void SetEPNATType(int nattype) {m_epnattype = (EPNatTypes)nattype; }
	void SetNATProxy(PBoolean support) {m_natproxy = support; }
	void SetInternal(PBoolean internal) { m_internal = internal; }
	void SetUsesH46023(bool uses) { m_usesH46023 = uses; }

	void SetPriority(int priority) { m_registrationPriority = priority; }
	void SetPreemption(bool support) { m_registrationPreemption = support; }
	void SetAssignedGatekeeper(const H225_AlternateGK & gk) { m_assignedGatekeeper = gk; }
	bool SetAssignedAliases(H225_ArrayOf_AliasAddress & assigned);


	/** @return
		true if this is a permanent endpoint loaded from the config file entry.
	*/
	bool IsPermanent() const;
	bool IsUsed() const;
	bool IsUpdated(const PTime *) const;
	void DeferTTL();
	bool IsNATed() const;
	bool SupportH46024() const;
	bool SupportH46024A() const;
	bool SupportH46024B() const;
	bool UseH46024B() const;
	bool UsesH46023() const { return m_usesH46023; }

	bool HasNATProxy() const;
	bool IsInternal() const;
	bool IsRemote() const;
	int GetEPNATType() const { return (int)m_epnattype; }
	static PString GetEPNATTypeString(EPNatTypes nat);
	bool SupportPreemption() const { return m_registrationPreemption; }

	int  Priority() const { return m_registrationPriority; }
	PTime GetUpdatedTime() const;

	void SetUsesH460P(bool uses);
	bool UsesH460P() const { return m_usesH460P; }
	bool HasPresenceData();
#ifdef HAS_H460P
	void ParsePresencePDU(const PASN_OctetString & pdu);
#ifndef HAS_H460P_VER_3
	bool BuildPresencePDU(unsigned msgtag, PASN_OctetString & pdu);
#endif
#endif

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

#if H323_H350
	/** Append a H.350 related service control descriptor to the array
	    of service control sessions
	*/
    virtual bool AddH350ServiceControl(
	    H225_ArrayOf_ServiceControlSession& sessions  /// array to add the service control descriptor to
	    );
#endif

	/** @return
	    True if the endpoint can handle at least one more concurrent call.
	*/
	bool HasAvailableCapacity(const H225_ArrayOf_AliasAddress & aliases) const;
	unsigned GetActiveCalls() const { return m_activeCall; }
	// void DumpPrefixCapacity() const;
	string LongestPrefixMatch(const PString & alias, int & capacity) const;
	void UpdatePrefixStats(const PString & dest, int update);

	// cause code translation
	unsigned TranslateReceivedCause(unsigned cause) const;
	unsigned TranslateSentCause(unsigned cause) const;
	// adding a fixed alias to all calls _to_ this endpoint
	PString GetAdditionalDestinationAlias() const { return m_additionalDestAlias; }

	bool IsH46017Disabled() const { return m_h46017disabled; }
	void SetUsesH46017(bool val) { m_usesH46017 = val; }
	bool UsesH46017() const { return m_usesH46017; }
	bool IsH46018Disabled() const { return m_h46018disabled; }
	void SetUsesH46026(bool val) { m_usesH46026 = val; }
	bool UsesH46026() const { return m_usesH46026; }
#ifdef HAS_H46026
	unsigned GetH46026BW() const { return (m_maxBandwidth > 0) ? (m_maxBandwidth / 2) : 384000; }
#endif
	void SetTraversalRole(H46019TraversalType val) { m_traversalType = val; m_nat = (val == TraversalClient); }
	H46019TraversalType GetTraversalRole() const { return m_traversalType; }
	bool IsTraversalServer() const { return m_traversalType == TraversalServer; }
	bool IsTraversalClient() const { return m_traversalType == TraversalClient; }

	void SetUseTLS(bool val) { m_useTLS = val; }
	bool UseTLS() const { return m_useTLS; }
	void SetTLSAddress(const H323TransportAddress & addr) { m_tlsAddress = addr; }
	H323TransportAddress GetTLSAddress() const;
	void SetUseIPSec(bool val) { m_useIPSec = val; }
	bool UseIPSec() const { return m_useIPSec; }

#ifdef HAS_LANGUAGE
	bool SetAssignedLanguage(const H225_RegistrationRequest_language & rrqLang, H225_RegistrationConfirm_language & rcfLang);
	bool SetAssignedLanguage(H225_LocationConfirm_language & lcfLang);
#endif // HAS_LANGUAGE
	void SetLanguages(const PStringList & languages) { m_languages = languages; }
	const PStringList & GetLanguages() { return m_languages; }
	PString GetDefaultLanguage();

	bool AddCallingPartyToSourceAddress() const { return m_addCallingPartyToSourceAddress; }
    PString GetDisabledCodecs() const { return m_disabledcodecs; }

	// smart pointer for EndpointRec
	typedef SmartPtr<EndpointRec> Ptr;

protected:
	void SetEndpointRec(H225_RegistrationRequest &);
	void SetEndpointRec(H225_AdmissionRequest &);
	void SetEndpointRec(H225_AdmissionConfirm &);
	void SetEndpointRec(H225_LocationConfirm &);
	void SetEndpointRec(H225_UnregistrationRequest &);	// used for temp objects

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
	H225_VendorIdentifier *m_endpointVendor;
	int m_timeToLive;   // seconds
	int m_defaultKeepAliveInterval; // for H.460.10 in seconds

	int m_activeCall, m_connectedCall, m_totalCall;
	/// active calls per prefix (regex)
	std::map<string, int> m_activePrefixCalls;

	int m_pollCount, m_usedCount;
	mutable PMutex m_usedLock;

	PTime m_updatedTime;
	bool m_fromParent, m_nat;
	PIPSocket::Address m_natip;
	CallSignalSocket *m_natsocket;
	/// permanent (preconfigured) endpoint flag
	bool m_permanent;
	/// can understand H.225 CallCreditServiceControl
	bool m_hasCallCreditCapabilities;
	/// session number for call credit service control session
	int m_callCreditSession;
	/// endpoint call capacity, -1 means no limit
	long m_capacity;
	/// capacity per prefix (regex)
	list<pair<string, int> > m_prefixCapacities;
	int m_calledTypeOfNumber, m_callingTypeOfNumber;
	int m_calledPlanOfNumber, m_callingPlanOfNumber;
	/// Proxy Type
	int m_proxy;
	/// Registration Priority Number
	int m_registrationPriority;
	/// Support Registration PreEmption
	bool m_registrationPreemption;

    /// Assigned Gatekeeper
	H225_AlternateGK m_assignedGatekeeper;
	/// cause code translation
	std::map<unsigned, unsigned> m_receivedCauseMap;
	std::map<unsigned, unsigned> m_sentCauseMap;
	/// additional alias to be added to all calls TO this endpoint
	PString m_additionalDestAlias;

	EPNatTypes m_epnattype;
	bool m_usesH46023, m_H46024, m_H46024a, m_H46024b, m_natproxy, m_internal, m_remote;
	bool m_h46017disabled;
	bool m_h46018disabled;
	bool m_usesH460P;
	bool m_hasH460PData;
	bool m_usesH46017;
	bool m_usesH46026;
	H46019TraversalType m_traversalType;	// this is not what GnuGk acts like, but what this EPRec is a proxy for

	long m_bandwidth;	// bandwidth currently occupied by this endpoint
	long m_maxBandwidth; // maximum bandwidth allowed for this endpoint
	bool m_useTLS;
	H323TransportAddress m_tlsAddress;
	bool m_useIPSec;	// for H.460.22 negotiation
	bool m_additiveRegistrant;
	PStringList m_languages;  // languages the user of this endpoint supports
	bool m_addCallingPartyToSourceAddress;	// per endpoint switch
	/// list of disabled codes
	PString m_disabledcodecs;
	/// H.235 used to authenticate this endpoint
	GkH235Authenticators * m_authenticators;
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


class OutOfZoneEPRec : public EndpointRec {
public:
	OutOfZoneEPRec(const H225_RasMessage & completeRAS, const H225_EndpointIdentifier &);

	virtual EndpointRec *Unregister() { return this; }
	virtual EndpointRec *Expired() { return this; }
};


class OutOfZoneGWRec : public GatewayRec {
public:
	OutOfZoneGWRec(const H225_RasMessage & completeRAS, const H225_EndpointIdentifier &);

	virtual EndpointRec *Unregister() { return this; }
	virtual EndpointRec *Expired() { return this; }
};

class EPQoS {
public:
	EPQoS() { Init(); }
	EPQoS(PTime lastMsg) { Init(); m_lastMsg = lastMsg; }
	~EPQoS() { }

	void Init();
	PString AsString() const;

	void IncrementCalls() { m_numCalls++; }
	void SetAudioPacketLossPercent(float val) { m_audioPacketLossPercent = val; }
	void SetAudioJitter(unsigned val) { m_audioJitter = val; }
	void SetVideoPacketLossPercent(float val) { m_videoPacketLossPercent = val; }
	void SetVideoJitter(unsigned val) { m_videoJitter = val; }

protected:
	PTime m_lastMsg;
	unsigned m_numCalls;
	float m_audioPacketLossPercent;
	unsigned long m_audioJitter;
	float m_videoPacketLossPercent;
	unsigned long m_videoJitter;
};

class RegistrationTable : public Singleton<RegistrationTable> {
public:
	typedef std::list<EndpointRec *>::iterator iterator;
	typedef std::list<EndpointRec *>::const_iterator const_iterator;

	RegistrationTable();
	~RegistrationTable();

	endptr InsertRec(H225_RasMessage & rrq, PIPSocket::Address = GNUGK_INADDR_ANY);
	endptr InsertRec(const H225_Setup_UUIE & setupBody, H225_TransportAddress addr);
	void RemoveByEndptr(const endptr & eptr);

	endptr FindByEndpointId(const H225_EndpointIdentifier & endpointId) const;
	endptr FindBySignalAdr(const H225_TransportAddress &, PIPSocket::Address = GNUGK_INADDR_ANY) const;
	endptr FindBySignalAdrIgnorePort(const H225_TransportAddress &, PIPSocket::Address = GNUGK_INADDR_ANY) const;
	endptr FindOZEPBySignalAdr(const H225_TransportAddress &) const;
	endptr FindByAliases(const H225_ArrayOf_AliasAddress & alias) const;
	endptr FindFirstEndpoint(const H225_ArrayOf_AliasAddress & alias);
	bool FindEndpoint(
		const H225_ArrayOf_AliasAddress &aliases,
		bool roundRobin,
		bool leastUsedRouting,
		bool searchOutOfZone,
		std::list<Routing::Route> &routes
		);

	void ClearTable();
	void UpdateTable();
	void CheckEndpoints();

	// handle remote closing of a NAT socket
	void OnNATSocketClosed(CallSignalSocket * s);
#ifdef HAS_H46017
	void UnregisterAllH46017Endpoints();
#endif

	void PrintAllRegistrations(USocket *client, bool verbose=FALSE);
	void PrintAllCached(USocket *client, bool verbose=FALSE);
	void PrintRemoved(USocket *client, bool verbose=FALSE);
	void PrintPrefixCapacities(USocket *client, PString alias) const;
	void PrintEndpointQoS(USocket *client); //const;

	PString PrintStatistics() const;

//	void PrintOn( ostream &strm ) const;

	/** Updates Prefix + Flags for all aliases */
	void LoadConfig();

	PINDEX Size() const { return regSize; }

private:

	endptr InternalInsertEP(H225_RasMessage &);
	endptr InternalInsertOZEP(H225_RasMessage &, H225_LocationConfirm &);
	endptr InternalInsertOZEP(H225_RasMessage &, H225_AdmissionConfirm &);
	endptr InternalInsertOZEP(const H225_Setup_UUIE & setupBody, H225_TransportAddress addr);

	void InternalPrint(USocket *, bool, std::list<EndpointRec *> *, PString &);
	void InternalStatistics(const std::list<EndpointRec *> *, unsigned & s, unsigned & t, unsigned & g, unsigned & n) const;

	void InternalRemove(iterator);

	template<class F> endptr InternalFind(const F & FindObject) const
	{ return InternalFind(FindObject, &EndpointList); }

	template<class F> endptr InternalFind(const F & FindObject, const std::list<EndpointRec *> *ListToBeFound) const
	{   //  The function body must be put here,
	    //  or the stupid VC would fail to instantiate it
        	ReadLock lock(listLock);
        	const_iterator Iter(find_if(ListToBeFound->begin(), ListToBeFound->end(), FindObject));
	        return endptr((Iter != ListToBeFound->end()) ? *Iter : NULL);
	}

	endptr InternalFindFirstEP(const H225_ArrayOf_AliasAddress & alias, std::list<EndpointRec *> *ListToBeFound);
	bool InternalFindEP(const H225_ArrayOf_AliasAddress & alias, std::list<EndpointRec *> *ListToBeFound, bool roundrobin, bool leastUsedRouting, std::list<Routing::Route> &routes);

	void GenerateEndpointId(H225_EndpointIdentifier & NewEndpointId, PString prefix = "");
	void GenerateAlias(H225_ArrayOf_AliasAddress &, const H225_EndpointIdentifier &) const;

	std::list<EndpointRec *> EndpointList;
	std::list<EndpointRec *> OutOfZoneList;
	std::list<EndpointRec *> RemovedList;
	int regSize;
	mutable PReadWriteMutex listLock;
	PMutex findmutex;          // Endpoint Find Mutex

	PString endpointIdSuffix; // Suffix of the generated Endpoint IDs

	// not assignable
	RegistrationTable(const RegistrationTable &);
	RegistrationTable& operator=(const RegistrationTable &);
};


template<class> class RasPDU;

#ifdef HAS_H46018
enum KeepAliveType { RTP, RTCP };

class H46019KeepAlive
{
public:
	H46019KeepAlive();
	~H46019KeepAlive();

	void SendKeepAlive(GkTimer* timer);
	void StopKeepAlive();

	unsigned flcn;
	KeepAliveType type;
	H323TransportAddress dest;
	unsigned interval;
	unsigned seq;
	int ossocket;
	PUInt32b multiplexID;
	BYTE payloadType;
	GkTimerManager::GkTimerHandle timer;
};
#endif

// record of one active call
#ifdef HAS_H460
class H4609_QosMonitoringReportData;
#ifdef HAS_H46024B
class H323TransportAddress;
#endif // HAS_H46024B
#endif // HAS_H460

#ifdef HAS_H46018
// direction definitions for H.460.19
#define H46019_NONE		0	// m_h46019dir = 0 ' No party needs H.460.19, so skip the code
#define H46019_CALLER	1	// m_h46019dir = 1 ' Caller needs H.460.19
#define H46019_CALLED	2	// m_h46019dir = 2 ' Called needs H.460.19
#define H46019_BOTH		(H46019_CALLER + H46019_CALLED)	// m_h46019dir = 3 ' Both need it
#endif // HAS_H46018


class CallRec {
public:
	/// flag to overwrite proxy settings for the call
	enum ProxyMode {
		ProxyDetect, /// use global settings from the config
		ProxyEnabled, /// force full proxy mode
		ProxyDisabled /// disable full proxy mode
	};

	/// the combination of ProxyMode, RoutedMode and H245 routing
	enum RoutingMode {
		Undefined = 0,
		SignalRouted,
		H245Routed,
		Proxied
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
		const RasPDU<H225_AdmissionRequest> & arq,
		/// bandwidth occupied by the call
		long bandwidth,
		/// called party's aliases in a string form
		const PString & destInfo,
		/// override proxy mode global setting from the config
		int proxyMode = ProxyDetect
		);

	/// build a new call record from the received Setup message
	CallRec(
		/// Q.931 Setup pdu with call information
		const Q931 & q931pdu,
		/// H.225.0 Setup-UUIE pdu with call information
		const H225_Setup_UUIE & setup,
		/// force H.245 routed mode
		bool routeH245,
		/// called party's aliases in a string form
		const PString & destInfo,
		/// override proxy mode global setting from the config
		int proxyMode = ProxyDetect
		);

	/// build a new call record with just a callID and transport adr (after H.460.18 SCI)
	CallRec(const H225_CallIdentifier & callID, H225_TransportAddress sigAdr);

	CallRec(CallRec * oldCall);

	virtual ~CallRec();

	enum NATType { // who is nated?
		none = 0,
		callingParty = 1,
		calledParty = 2,
		both = 3
	};

	PINDEX GetCallNumber() const { return m_CallNumber; }
	const H225_CallIdentifier & GetCallIdentifier() const { return m_callIdentifier; }
	void ClearCallIdentifier() { m_callIdentifier = 0; }
	unsigned GetCallRef() const { return m_crv; }
	const H225_ConferenceIdentifier & GetConferenceIdentifier() const { return m_conferenceIdentifier; }
	endptr GetCallingParty() const { return m_Calling; }
	endptr GetCalledParty() const { return m_Called; }
	endptr GetForwarder() const { return m_Forwarder; }
	long GetBandwidth() const { return m_bandwidth; }

	bool HasPostDialDigits() const { return !m_postdialdigits.IsEmpty(); }
	PString GetPostDialDigits() const { return m_postdialdigits; }
	void SetPostDialDigits(const PString & digits) { m_postdialdigits = digits; }

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

#ifdef HAS_H46023
	// Override the calculated NAT type
	void SetNATType(int newNatType) { m_nattype = newNatType; }

	/** Can the call party be used to bypass proxy for NAT
	*/
	enum NatStrategy {
		e_natUnknown,
		e_natNoassist,
		e_natLocalMaster,
	    e_natRemoteMaster,
		e_natLocalProxy,
	    e_natRemoteProxy,
		e_natFullProxy,
		e_natAnnexA,		// Same NAT
		e_natAnnexB,		// Nat Offload
		e_natFailure = 100
	};

	/** Return whether a call can be offloaded from having to proxy
	  */
	bool NATOffLoad(bool iscalled, NatStrategy & natinst);

	/** Return whether an unknown incoming call can be offloaded from having to proxy
	  */
	bool NATAssistCallerUnknown(NatStrategy & natinst);

	/** Set Receive Side Strategy
	  */
	void SetReceiveNATStategy(NatStrategy & type, int & proxyMode);

	/** Get String representation of the NATStrategy */
	PString GetNATOffloadString(NatStrategy nat) const;


	/** Get the NATStrategy Default is Unknown */
	NatStrategy GetNATStrategy() const { return m_natstrategy; }

	/** Set the NATStrategy */
	void SetNATStrategy(NatStrategy strategy) { m_natstrategy = strategy; }

	/** Can Signalling be offloaded
	  */
	bool NATSignallingOffload(bool isAnswer) const;

#ifdef HAS_H46024A
    /** Whether Annex A passthrough
      */
    bool IsH46024APassThrough();

	/** Send a H.460.24 Annex A indication
	 */
	PBoolean H46024AMessage();

	/** GetSignallingSocket */
	CallSignalSocket * H46024ASignalSocket();
#endif // HAS_H46024A

#ifdef HAS_H46024B
    /** GetSignallingSocket */
    CallSignalSocket * H46024BSignalSocket(bool response);

	/** Initiate Probe */
	void H46024BInitiate(WORD sessionID, const H323TransportAddress & fwd, const H323TransportAddress & rev, unsigned muxID_fwd=0, unsigned muxID_rev=0);

	/** Response Probe */
	void H46024BRespond();

    /** Set session callback flag */
	void H46024BSessionFlag(WORD sessionID);

	/** Handle H46024B Request */
	bool HandleH46024BRequest(const H245_ArrayOf_GenericParameter & content);
#endif // HAS_H46024B

	/** Return whether the endpoints are registered at the same gatekeeper so
	    only 1 gatekeeper is involved in the call
	  */
	bool SingleGatekeeper() const;
#endif // HAS_H46023

	/** Return remote party device information
	  */
	bool GetRemoteInfo(PString & vendor, PString & version);

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
	void RerouteDropCalling();
	void RerouteDropCalled();
    void AddChannelFlcn(WORD flcn) { m_channelFlcnList.push_back(flcn); }   // list of all channel Flcn every _tried_ to open
    vector<WORD> GetChannelFlcnList() const { return m_channelFlcnList; }   // list of all channel Flcn every _tried_ to open
    void ClearChannelFlcnList() { m_channelFlcnList.clear(); }
	bool DropCalledAndTryNextRoute();
	void SetBandwidth(long bandwidth) { m_bandwidth = bandwidth; if (m_bandwidth < 0) m_bandwidth = 0; }
	void SetSocket(CallSignalSocket *, CallSignalSocket *);
	void SetCallSignalSocketCalling(CallSignalSocket* socket);
	void SetCallSignalSocketCalled(CallSignalSocket* socket);
	void SetToParent(bool toParent) { m_toParent = toParent; }
	void SetFromParent(bool fromParent) { m_fromParent = fromParent; }
	void SetAccessTokens(const H225_ArrayOf_CryptoH323Token & tokens) { m_accessTokens = tokens; }
	void SetInboundRewriteId(PString id) { m_inbound_rewrite_id = id; }
	void SetOutboundRewriteId(PString id) { m_outbound_rewrite_id = id; }

	void SetConnected();

	void Disconnect(bool = false); // send ReleaseComplete ?
	void RemoveAll();
	void RemoveSocket();
	void SendReleaseComplete(const H225_CallTerminationCause * = NULL);
	void BuildDRQ(H225_DisengageRequest &, unsigned reason) const;

	bool CompareCallId(const H225_CallIdentifier *CallId) const;
	bool CompareCRV(WORD crv) const;
	bool CompareCallNumber(PINDEX CallNumber) const;
	bool CompareEndpoint(const endptr *) const;
	bool CompareSigAdr(const H225_TransportAddress *adr) const;
	bool CompareSigAdrIgnorePort(const H225_TransportAddress *adr) const;

	bool IsUsed() const { return (m_usedCount != 0); }

	/** @return
		true if the call has been connected - a Connect message
		has been received in gk routed signaling or the call has been admitted
		(ARQ->ACF) in direct signaling. Does not necessary mean
		that the call is still in progress (may have been already disconnected).
	*/
	bool IsConnected() const { return (m_connectTime != 0); }

	void SetH245Routed(PBoolean routed) { m_h245Routed = routed; }
	bool IsH245Routed() const { return m_h245Routed; }
	bool IsToParent() const { return m_toParent; }	// to _or_ from parnet
	bool IsFromParent() const { return m_fromParent; }	// from parent only
	bool IsForwarded() const { return m_forwarded; }
	bool IsSocketAttached() const { return (m_callingSocket != NULL); }

	PString GenerateCDR(
		/// timestamp formatting string (empty for a default RFC822 format)
		const PString & timestampFormat = PString::Empty()
		) const;
	PString PrintOn(bool verbose) const;
	PString GetMediaRouting() const;
	PString PrintPorts() const;
    PString PrintFullInfo() const;

	void Lock();
	void Unlock();

	/** @return
		Q.931 ReleaseComplete cause code for the call.
		0 if the disconnect cause could not be determined.
	*/
	unsigned GetDisconnectCause() const;

	/** Set Q.931 ReleaseComplete cause code associated with this call. */
	void SetDisconnectCause(unsigned causeCode);

	/** @return
		Q.931 ReleaseComplete cause code after translation.
	*/
	unsigned GetDisconnectCauseTranslated() const;

	/** Set Q.931 ReleaseComplete cause code after translation rules for this call. */
	void SetDisconnectCauseTranslated(unsigned causeCode);

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

	/** Set the client provided authentication id **/
	void SetClientAuthId(PUInt64 id) { m_clientAuthId = id; }
	PUInt64 GetClientAuthId() const { return m_clientAuthId; }

	/** Set list of codecs to disable for this call */
	void SetDisabledCodecs(const PString & codecs);
	void AddDisabledCodecs(const PString & codecs);
	PString GetDisabledCodecs() const { return m_disabledcodecs; }

	/** @return
		Timestamp (number of seconds since 1st January 1970)
		for the Setup message associated with this call. 0 if Setup
		has not been yet received.
		Meaningful only in GK routed mode.
	*/

	PString GetSRC_media_control_IP() const;
	PString GetDST_media_control_IP() const;

	void SetSRC_media_control_IP(const PString & IP);
	void SetDST_media_control_IP(const PString & IP);

	PString GetSRC_media_IP() const;
	PString GetDST_media_IP() const;

	void SetSRC_media_IP(const PString & IP);
	void SetDST_media_IP(const PString & IP);
	void SetRTCP_sdes(bool isSRC, const PString & val);
	void SetRTCP_SRC_sdes(const PString & val);
	void SetRTCP_DST_sdes(const PString & val);

	PStringList GetRTCP_SRC_sdes() const;
	PStringList GetRTCP_DST_sdes() const;

	bool GetRTCP_SRC_sdes_flag() const;
	bool GetRTCP_DST_sdes_flag() const;

	void InitRTCP_report();

	// set audio RTCP stats
	void SetRTCP_SRC_packet_count(long val);
	void SetRTCP_SRC_packet_lost(long val);
	void SetRTCP_SRC_jitter(int val);
	void SetRTCP_DST_packet_count(long val);
	void SetRTCP_DST_packet_lost(long val);
	void SetRTCP_DST_jitter(int val);

	// get audio RTCP stats
	long GetRTCP_SRC_packet_count() const { return m_rtcp_source_packet_count; }
	long GetRTCP_SRC_packet_lost() const { return m_rtcp_source_packet_lost; }
	float GetRTCP_SRC_packet_loss_percent() const { return (m_rtcp_source_packet_count == 0) ? 0 : (float)(m_rtcp_source_packet_lost / m_rtcp_source_packet_count); }
	int GetRTCP_SRC_jitter_max() const { return m_rtcp_source_jitter_max; }
	int GetRTCP_SRC_jitter_min() const { return m_rtcp_source_jitter_min; }
	int GetRTCP_SRC_jitter_avg() const { return m_rtcp_source_jitter_avg; }
	long GetRTCP_DST_packet_count() const { return m_rtcp_destination_packet_count; }
	long GetRTCP_DST_packet_lost() const { return m_rtcp_destination_packet_lost; }
	float GetRTCP_DST_packet_loss_percent() const { return (m_rtcp_destination_packet_count == 0) ? 0 : (float)(m_rtcp_destination_packet_lost / m_rtcp_destination_packet_count); }
	int GetRTCP_DST_jitter_max() const { return m_rtcp_destination_jitter_max; }
	int GetRTCP_DST_jitter_min() const { return m_rtcp_destination_jitter_min; }
	int GetRTCP_DST_jitter_avg() const { return m_rtcp_destination_jitter_avg; }

	// set video RTCP stats
	void SetRTCP_SRC_video_packet_count(long val);
	void SetRTCP_SRC_video_packet_lost(long val);
	void SetRTCP_SRC_video_jitter(int val);
	void SetRTCP_DST_video_packet_count(long val);
	void SetRTCP_DST_video_packet_lost(long val);
	void SetRTCP_DST_video_jitter(int val);

	// get video RTCP stats
	long GetRTCP_SRC_video_packet_count() const { return m_rtcp_source_video_packet_count; }
	long GetRTCP_SRC_video_packet_lost() const { return m_rtcp_source_video_packet_lost; }
	float GetRTCP_SRC_video_packet_loss_percent() const { return (m_rtcp_source_video_packet_count == 0) ? 0 : (float)(m_rtcp_source_video_packet_lost / m_rtcp_source_video_packet_count); }
	int GetRTCP_SRC_video_jitter_max() const { return m_rtcp_source_video_jitter_max; }
	int GetRTCP_SRC_video_jitter_min() const { return m_rtcp_source_video_jitter_min; }
	int GetRTCP_SRC_video_jitter_avg() const { return m_rtcp_source_video_jitter_avg; }
	long GetRTCP_DST_video_packet_count() const { return m_rtcp_destination_video_packet_count; }
	long GetRTCP_DST_video_packet_lost() const { return m_rtcp_destination_video_packet_lost; }
	float GetRTCP_DST_video_packet_loss_percent() const { return (m_rtcp_destination_video_packet_count == 0) ? 0 : (float)(m_rtcp_destination_video_packet_lost / m_rtcp_destination_video_packet_count); }
	int GetRTCP_DST_video_jitter_max() const { return m_rtcp_destination_video_jitter_max; }
	int GetRTCP_DST_video_jitter_min() const { return m_rtcp_destination_video_jitter_min; }
	int GetRTCP_DST_video_jitter_avg() const { return m_rtcp_destination_video_jitter_avg; }

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

	/* Reset timeout
       Used when switching from routed to direct mode to avoid signalling timeouts
	*/
	void ResetTimeOut();

	/** Check if:
		- a signaling channel associated with this call is not timed out
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
	time_t GetDuration() const;

	/** @return
		Call total time in seconds. 0 for calls without disconnect.
	*/
	time_t GetTotalCallDuration() const;

	/** @return
		Call Post Dial Delay in seconds.
	*/
	time_t GetPostDialDelay() const;

	/** @return
		Call ring time in seconds. 0 for calls without Alerting.
	*/
	time_t GetRingTime() const;

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

	/** Set a new address for the calling party signaling channel.
	*/
	void SetSrcSignalAddr(
		const H225_TransportAddress & addr /// new signaling transport address
		);

	/** Set the unregistered calling party signaling channel as NATed.
	*/
	void SetSrcNATed(const PIPSocket::Address & natip);

	/** Set a new address for the called party signaling channel.
	*/
	void SetDestSignalAddr(
		const H225_TransportAddress & addr /// new signaling transport address
		);

	H225_TransportAddress GetSrcSignalAddr() const;

	/** Get IP and port for the calling party. It is a signal address
		for registered endpoints and remote signaling socket address
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
		for registered endpoints and remote signaling socket address
		for unregistered endpoints.

		@return
		true if the address has been retrieved successfully, false otherwise.
	*/
	bool GetDestSignalAddr(
		PIPSocket::Address & addr, /// will receive the IP address
		WORD & port /// will receive the port number
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
	const H225_ArrayOf_AliasAddress GetSourceAddress() const { return m_sourceAddress; }

	/** @return
	    Called party's aliases, as presented in ARQ or Setup messages.
	    This does not change during the call now, but should be fixed
	    to handle gatekeeper call forwarding properly.
	*/
	const H225_ArrayOf_AliasAddress GetDestinationAddress() const { return m_destinationAddress; }

	/** @return
	    Calling party's number or an empty string, if the number has not been
	    yet determined.
	*/
	PString GetCallingStationId() const;

	/// Set calling party's number
	void SetCallingStationId(
		const PString & id /// Calling-Station-Id
		);

	/** @return
	    Called party's number or an empty string, if the number has not been
	    yet determined.
	*/
	PString GetCalledStationId() const;

	/// Set call linkage This the party to be charged for the call.
	void SetCallLinkage(
		const PString & id /// Calling-Station-Id (to be charged)
		);

	/** @return
        Call party to be charged for the call.
	*/
	PString GetCallLinkage()const { return m_callLinkage; }

	/// Set calling party's number
	void SetCalledStationId(
		const PString & id /// Called-Station-Id
		);

	/** @return
	    Called party's number before rewrite or an empty string,
	    if the number has not been yet determined.
	*/
	PString GetDialedNumber();

	/// Set dialed number
	void SetDialedNumber(
		const PString & number /// Dialed-Number
		);

	// vendor info for calling and called party
	void SetCallingVendor(const PString & vendor, const PString & version);
	bool GetCallingVendor(PString & vendor, PString & version) const;
	void SetCalledVendor(const PString & vendor, const PString & version);
	bool GetCalledVendor(PString & vendor, PString & version) const;

    void SetSInfoIP(const PString & ip) { m_sinfoIP = ip; }
    PString GetSInfoIP() const { return m_sinfoIP; }

	/** @return
	    Fixed destination address for the call (size 0 if not set).
	*/
	H225_ArrayOf_AliasAddress GetRouteToAlias() const { return m_routeToAlias; }

	/// Set fixed destination address for the call
	void SetRouteToAlias(const H225_ArrayOf_AliasAddress & alias) { m_routeToAlias = alias; }

	// smart pointer for CallRec
	typedef SmartPtr<CallRec> Ptr;

	/// update IRR timers
	void Update(const H225_InfoRequestResponse & irr);

	void ClearRoutes();
	void SetNewRoutes(const std::list<Routing::Route> & routes);
	const std::list<Routing::Route> & GetNewRoutes() const { return m_newRoutes; }
	const std::list<Routing::Route> & GetFailedRoutes() const { return m_failedRoutes; }
	bool MoveToNextRoute();

	bool IsCallInProgress() const;
	void SetCallInProgress(bool val = true);

	bool IsH245ResponseReceived() const;
	void SetH245ResponseReceived();

	bool IsFastStartResponseReceived() const;
	void SetFastStartResponseReceived();

	bool IsFailoverActive() const { return m_failoverActive; }
	bool SingleFailoverCDR() const;
	int GetNoCallAttempts() const;
	int GetNoRemainingRoutes() const;
	bool DisableRetryChecks() const;

	void SetCallerAudioCodec(const PString & codec);
	PString GetCallerAudioCodec() const;
	void SetCalledAudioCodec(const PString & codec);
	PString GetCalledAudioCodec() const;
	void SetCallerVideoCodec(const PString & codec);
	PString GetCallerVideoCodec() const;
	void SetCalledVideoCodec(const PString & codec);
	PString GetCalledVideoCodec() const;
	void SetCallerH239Codec(const PString & codec);
	PString GetCallerH239Codec() const;
	void SetCalledH239Codec(const PString & codec);
	PString GetCalledH239Codec() const;

    void SetCallerAudioBitrate(unsigned bitrate);
	unsigned GetCallerAudioBitrate() const;
	void SetCalledAudioBitrate(unsigned bitrate);
	unsigned GetCalledAudioBitrate() const;
	void SetCallerVideoBitrate(unsigned bitrate);
	unsigned GetCallerVideoBitrate() const;
	void SetCalledVideoBitrate(unsigned bitrate);
	unsigned GetCalledVideoBitrate() const;
	void SetCallerH239Bitrate(unsigned bitrate);
	unsigned GetCallerH239Bitrate() const;
	void SetCalledH239Bitrate(unsigned bitrate);
	unsigned GetCalledH239Bitrate() const;

	void SetCallerAudioIP(const PIPSocket::Address & addr, WORD port);
	bool GetCallerAudioIP(PIPSocket::Address & addr, WORD & port) const;
	void SetCalledAudioIP(const PIPSocket::Address & addr, WORD port);
	bool GetCalledAudioIP(PIPSocket::Address & addr, WORD & port) const;
	void SetCallerVideoIP(const PIPSocket::Address & addr, WORD port);
	bool GetCallerVideoIP(PIPSocket::Address & addr, WORD & port) const;
	void SetCalledVideoIP(const PIPSocket::Address & addr, WORD port);
	bool GetCalledVideoIP(PIPSocket::Address & addr, WORD & port) const;
	void SetCallerH239IP(const PIPSocket::Address & addr, WORD port, WORD sessionID);
	bool GetCallerH239IP(PIPSocket::Address & addr, WORD & port) const;
	void SetCalledH239IP(const PIPSocket::Address & addr, WORD port, WORD sessionID);
	bool GetCalledH239IP(PIPSocket::Address & addr, WORD & port) const;

	PBYTEArray GetRADIUSClass() const;

	bool IsProceedingSent() const { return m_proceedingSent; }
	void SetProceedingSent(bool val) { m_proceedingSent = m_proceedingSent || val; }

	void SetRerouteState(RerouteState state) { m_rerouteState = state; }
	RerouteState GetRerouteState() const { return m_rerouteState; }
	void SetRerouteDirection(CallLeg dir) { m_rerouteDirection = dir; }
	CallLeg GetRerouteDirection() const { return m_rerouteDirection; }

	void SetBindHint(const PString & ip) { m_bindHint = ip; }
	PString GetBindHint() const { return m_bindHint; }

	// if set, the callerID to put into calling party number IE
	void SetCallerID(const PString & id) { m_callerID = id; }
	PString GetCallerID() const { return m_callerID; }

	// calling/called party number IE (after rewriting)
    void SetCallingPartyNumberIE(const PString & ie) { m_callingPartyNumberIE = ie; }
	PString GetCallingPartyNumberIE() const { return m_callingPartyNumberIE; }
	void SetCalledPartyNumberIE(const PString & ie) { m_calledPartyNumberIE = ie; }
	PString GetCalledPartyNumberIE() const { return m_calledPartyNumberIE; }

	// if set, the display IE to set for the caller/called party
	void SetCallerDisplayIE(const PString & display) { m_callerDisplayIE = display; }
	PString GetCallerDisplayIE() const { return m_callerDisplayIE; }
	void SetCalledDisplayIE(const PString & display) { m_calledDisplayIE = display; }
	PString GetCalledDisplayIE() const { return m_calledDisplayIE; }

	void AddDynamicPort(const DynamicPort & port);
	void RemoveDynamicPort(const DynamicPort & port);

    bool HasNewSetupInternalAliases() const { return (m_newSetupInternalAliases != NULL); }
    void SetNewSetupInternalAliases(H225_ArrayOf_AliasAddress newSetupInternalAliases) { m_newSetupInternalAliases = new H225_ArrayOf_AliasAddress(newSetupInternalAliases); }
    H225_ArrayOf_AliasAddress * GetNewSetupInternalAliases() const { return m_newSetupInternalAliases; }

#ifdef HAS_H46018
	bool IsH46018ReverseSetup() const { return m_h46018ReverseSetup; }
	void SetH46018ReverseSetup(bool val) { m_h46018ReverseSetup = val; }
	bool H46019Required() const;
	void StoreSetup(SignalingMsg * msg);
	void StoreSetup(const PBYTEArray & setup);
	PBYTEArray RetrieveSetup();
	int GetH46019Direction() const;

	void AddRTPKeepAlive(unsigned flcn, const H323TransportAddress & keepAliveRTPAddr, unsigned keepAliveInterval, PUInt32b multiplexID);
	void SetRTPKeepAlivePayloadType(unsigned flcn, BYTE payloadType);
	void StartRTPKeepAlive(unsigned flcn, int RTPOSSocket);
	void AddRTCPKeepAlive(unsigned flcn, const H245_UnicastAddress & keepAliveRTCPAddr, unsigned keepAliveInterval, PUInt32b multiplexID);
	void StartRTCPKeepAlive(unsigned flcn, int RTCPOSSocket);
	void RemoveKeepAlives(unsigned flcn);
	void RemoveKeepAllAlives();

	void SetSessionMultiplexDestination(WORD session, void * openedBy, bool isRTCP, const H323TransportAddress & toAddress, H46019Side side);
	bool IgnoreSignaledIPs() const { return m_ignoreSignaledIPs; }
	void SetIgnoreSignaledIPs(bool val) { m_ignoreSignaledIPs = val; }
#endif

	// should we use TLS on the outgoing leg, incoming determined by port caller uses
	bool ConnectWithTLS() const { return m_connectWithTLS || (m_Called && m_Called->UseTLS()); }	// per call dynamicly and config setting
	void SetConnectWithTLS(bool val) { m_connectWithTLS = val; }

#ifdef HAS_H235_MEDIA
    typedef NATType EncDir;
    H235Authenticators & GetAuthenticators() { return m_authenticators; }
    void SetMediaEncryption(EncDir dir);
    bool IsMediaEncryption() const { return m_encyptDir != none; }
    EncDir GetEncryptDirection() const { return m_encyptDir; }
	BYTE GetNewDynamicPayloadType();
#endif

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
	long m_bandwidth;
	/// post dial digits (can be any alphanumeric user input)
	PString m_postdialdigits;

	PString m_callerAddr, m_callerId;
	PString m_calleeAddr, m_calleeId;
	// rewrite id for inbound leg of call
	PString m_inbound_rewrite_id;
	// rewrite id for outbound leg of call
	PString m_outbound_rewrite_id;

	/// list of disabled codes
	PString m_disabledcodecs;

	PString m_src_media_control_IP, m_dst_media_control_IP;
	PString m_src_media_IP, m_dst_media_IP;

	PStringList m_rtcp_source_sdes;
	bool m_rtcp_source_sdes_flag;

	PStringList m_rtcp_destination_sdes;
	bool m_rtcp_destination_sdes_flag;

	// RTCP audio stats
	long m_rtcp_source_packet_count;
	long m_rtcp_destination_packet_count;
	long m_rtcp_source_packet_lost;
	long m_rtcp_destination_packet_lost;

	int m_rtcp_source_jitter_min;
	int m_rtcp_source_jitter_max;
	int m_rtcp_source_jitter_avg;

	int m_rtcp_destination_jitter_min;
	int m_rtcp_destination_jitter_max;
	int m_rtcp_destination_jitter_avg;

	int m_rtcp_source_jitter_avg_count;
	long m_rtcp_source_jitter_avg_sum;

	int m_rtcp_destination_jitter_avg_count;
	long m_rtcp_destination_jitter_avg_sum;

	// RTCP video stats
	long m_rtcp_source_video_packet_count;
	long m_rtcp_destination_video_packet_count;
	long m_rtcp_source_video_packet_lost;
	long m_rtcp_destination_video_packet_lost;

	int m_rtcp_source_video_jitter_min;
	int m_rtcp_source_video_jitter_max;
	int m_rtcp_source_video_jitter_avg;

	int m_rtcp_destination_video_jitter_min;
	int m_rtcp_destination_video_jitter_max;
	int m_rtcp_destination_video_jitter_avg;

	int m_rtcp_source_video_jitter_avg_count;
	long m_rtcp_source_video_jitter_avg_sum;

	int m_rtcp_destination_video_jitter_avg_count;
	long m_rtcp_destination_video_jitter_avg_sum;

	/// current timeout (or duration limit) for the call
	time_t m_timeout;
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
	time_t m_durationLimit;
	/// Q.931 release complete cause code
	unsigned m_disconnectCause;
	/// Q.931 release complete cause code after translation
	unsigned m_disconnectCauseTranslated;
	/// who disconnected the call (see #RelaseSource enum#)
	int  m_releaseSource;
	/// unique accounting session id associated with this call
	PString m_acctSessionId;
	/// signaling transport address of the calling party
	H225_TransportAddress m_srcSignalAddress;
	/// signaling transport address of the called party
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
	H225_ArrayOf_AliasAddress m_routeToAlias;
	H225_ArrayOf_AliasAddress * m_newSetupInternalAliases;

	CallSignalSocket *m_callingSocket, *m_calledSocket;

	int m_usedCount;
	mutable PTimedMutex m_usedLock, m_sockLock;
	int m_nattype;
#ifdef HAS_H46023
	NatStrategy m_natstrategy;
#endif

#ifdef HAS_H46024A
	void BuildH46024AnnexAIndication(H245_MultimediaSystemControlMessage & h245msg);
#endif

#ifdef HAS_H46024B
	struct H46024Balternate {
		 H245_TransportAddress forward;
		 H245_TransportAddress reverse;
		 unsigned multiplexID_fwd;
		 unsigned multiplexID_rev;
		 int sent;
	};

	std::map<WORD,H46024Balternate> m_H46024Balternate;
	void BuildH46024AnnexBRequest(bool initiate,H245_MultimediaSystemControlMessage & h245msg, const std::map<WORD,H46024Balternate> & alt);
	list<int> m_h46024Bflag;
#endif
	/// unregistered caller NAT'd
	bool m_unregNAT;
	PIPSocket::Address m_srcunregNATAddress;

	bool m_h245Routed;
	/// the call is routed to this gatekeeper's parent gatekeeper
	bool m_toParent;
	/// the call is routed to this gatekeeper from it's parent gatekeeper
	bool m_fromParent;
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
	/// flag if failover is activated for easy access
	bool m_failoverActive;
	bool m_singleFailoverCDR;

	PString m_callerAudioCodec;
	PString m_calledAudioCodec;
	PString m_callerVideoCodec;
	PString m_calledVideoCodec;
	PString m_callerH239Codec;
	PString m_calledH239Codec;
	unsigned m_callerAudioBitrate;
	unsigned m_calledAudioBitrate;
	unsigned m_callerVideoBitrate;
	unsigned m_calledVideoBitrate;
	unsigned m_callerH239Bitrate;
	unsigned m_calledH239Bitrate;
	PIPSocket::Address m_callerAudioIP;
	PIPSocket::Address m_calledAudioIP;
	PIPSocket::Address m_callerVideoIP;
	PIPSocket::Address m_calledVideoIP;
	PIPSocket::Address m_callerH239IP;
	PIPSocket::Address m_calledH239IP;
	WORD m_callerAudioPort;
	WORD m_calledAudioPort;
	WORD m_callerVideoPort;
	WORD m_calledVideoPort;
	WORD m_callerH239Port;
	WORD m_calledH239Port;
	WORD m_H239SessionID;

	PString m_callingPartyNumberIE;
	PString m_calledPartyNumberIE;

	PBYTEArray m_radiusClass;
	bool m_proceedingSent;
#ifdef HAS_H46018
	/// processed Setup data ready to be sent to the callee (for H.460.18)
	PBYTEArray m_processedSetup;
	std::map<unsigned, H46019KeepAlive> m_RTPkeepalives;
	std::map<unsigned, H46019KeepAlive> m_RTCPkeepalives;
	bool m_ignoreSignaledIPs;   // IgnoreSignaledIPs setting for this call; may be switched off during call establishemnt
#endif
	PUInt64 m_clientAuthId;
	PString m_bindHint;	// outgoing IP or empty
	RerouteState m_rerouteState;	// is Pause&Reroute transfer in progress ?
	bool m_h46018ReverseSetup;
	bool m_callfromTraversalClient;
	bool m_callfromTraversalServer;
	CallLeg m_rerouteDirection;
	PString m_callerID;	// forced caller ID or empty
	PString m_callerDisplayIE;	// forced Display IE of caller or empty
	PString m_calledDisplayIE;	// forced Display IE of called party or empty
	PMutex m_portListMutex;
	list<DynamicPort> m_dynamicPorts;
	// should we use TLS on the outgoing leg, incoming determined by port caller uses
	bool m_connectWithTLS;

#ifdef HAS_H235_MEDIA
    H235Authenticators m_authenticators;
    EncDir m_encyptDir;	// party for which we simulate encryption
	PMutex m_PTMutex;
    BYTE m_dynamicPayloadTypeCounter;
#endif
	// vendor info for calling and called party - only used if no EndpointRec available!
	PString m_callingVendor;
	PString m_callingVersion;
	PString m_calledVendor;
	PString m_calledVersion;
	// Sorenson SInfo
	PString m_sinfoIP;
    vector<WORD> m_channelFlcnList; // list of all channel Flcn every _tried_ to open so we can close them on Reroute
};

typedef CallRec::Ptr callptr;

// all active calls

class H4609_QosMonitoringReportData;
class CallTable : public Singleton<CallTable>
{
public:
	typedef std::list<CallRec *>::iterator iterator;
	typedef std::list<CallRec *>::const_iterator const_iterator;

	CallTable();
	~CallTable();

	void ResetCallCounters();
	void Insert(CallRec * NewRec);

	// bandwidth management
	void SetTotalBandwidth(long bw);
	long GetAvailableBW() const { return m_capacity; }
	long GetMinimumBandwidthPerCall() const { return m_minimumBandwidthPerCall; }
	long GetMaximumBandwidthPerCall() const { return m_maximumBandwidthPerCall; }
	long CheckTotalBandwidth(long bw) const;
	void UpdateTotalBandwidth(long bw);
	long CheckEPBandwidth(const endptr & ep, long bw) const;
	void UpdateEPBandwidth(const endptr & ep, long bw);

	callptr FindCallRec(const H225_CallIdentifier & CallId) const;
	// copy call ID for thread safety
	callptr FindCallRecByValue(H225_CallIdentifier CallId) const;
	callptr FindCallRec(const H225_CallReferenceValue & CallRef) const;
	callptr FindCallRec(PINDEX CallNumber) const;
	callptr FindCallRec(const endptr &) const;
	callptr FindBySignalAdr(const H225_TransportAddress & SignalAdr) const;
	callptr FindBySignalAdrIgnorePort(const H225_TransportAddress & SignalAdr) const;

	void ClearTable();
	void CheckCalls(
		RasServer* rassrv // to avoid call RasServer::Instance every second
		);

	void RemoveCall(const H225_DisengageRequest & obj_drq, const endptr &);
	void RemoveCall(const callptr &);
	void RemoveFailedLeg(const callptr &);
	void DropCallingParty();
	void DropCalledParty();

	void PrintCurrentCalls(USocket *client, bool verbose=FALSE) const;
	void PrintCurrentCallsPorts(USocket *client) const;
	PString PrintStatistics() const;
	void PrintCallInfo(USocket *client, const PString & callid) const;

#ifdef HAS_H460
	void OnQosMonitoringReport(const PString &,const endptr &, H4609_QosMonitoringReportData &);
    void QoSReport(const H225_DisengageRequest &, const endptr &, const PASN_OctetString &);
    void QoSReport(const H225_InfoRequestResponse &, const callptr &, const endptr &, const PASN_OctetString &);
#endif
	void SupplyEndpointQoS(std::map<PString, EPQoS> & epqos) const;

	void LoadConfig();
	void UpdatePrefixCapacityCounters();    // after Reload

	PINDEX Size() const { return m_activeCall; }	// number of currently active calls
	unsigned TotalCallCount() const { return m_CallCount; }	// number of calls since startup
	unsigned SuccessfulCallCount() const { return m_successCall; }	// number of succesfull calls since startup

	/** @return
	    Timeout value for a signaling channel to be opened after ACF
	    and for an Alerting message to be received after signaling start.
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
	void InternalRemove(iterator);
	void InternalRemoveFailedLeg(iterator);

	void InternalStatistics(unsigned & n, unsigned & act, unsigned & nb, unsigned & np, unsigned & npr, PString & msg, bool verbose) const;

	std::list<CallRec *> CallList;
	std::list<CallRec *> RemovedList;

	bool m_genNBCDR;
	bool m_genUCCDR;

	PINDEX m_CallNumber;
	mutable PReadWriteMutex listLock;

	long m_capacity;	// total available bandwidth for gatekeeper (-1 = unlimited)
	long m_minimumBandwidthPerCall;	// don't accept bandwith requests from endpoints lower tan this (eg. for Netmeeting)
	long m_maximumBandwidthPerCall;	// maximum bandwidth allowed per call (<= 0 means unlimited)

	// statistics
	unsigned m_CallCount, m_successCall, m_neighborCall, m_parentCall, m_activeCall, m_proxiedCall, m_peakCall;
	PTime m_peakTime;

	/// timeout for a Connect message to be received
	/// and for a signaling channel to be opened after ACF/ARQ
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

inline PIPSocket::Address EndpointRec::GetIP() const
{
	PWaitAndSignal lock(m_usedLock);
	PIPSocket::Address addr;
    GetIPFromTransportAddr(m_callSignalAddress,addr);
	return addr;
}

inline H225_EndpointIdentifier EndpointRec::GetEndpointIdentifier() const
{
	PWaitAndSignal lock(m_usedLock);
	return m_endpointIdentifier;
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

inline bool EndpointRec::GetEndpointInfo(PString & vendor, PString & version ) const
{
	PWaitAndSignal lock(m_usedLock);

	if (!m_endpointVendor)
		return false;

	if (m_endpointVendor->HasOptionalField(H225_VendorIdentifier::e_productId))
		vendor = m_endpointVendor->m_productId.AsString();
	if (m_endpointVendor->HasOptionalField(H225_VendorIdentifier::e_versionId))
		version = m_endpointVendor->m_versionId.AsString();

	return true;
}

inline void EndpointRec::SetEndpointInfo(const PString & vendor, const PString & version )
{
	PWaitAndSignal lock(m_usedLock);

	if (m_endpointVendor)
		delete m_endpointVendor;

	m_endpointVendor = new H225_VendorIdentifier();

	m_endpointVendor->IncludeOptionalField(H225_VendorIdentifier::e_productId);
	   m_endpointVendor->m_productId.SetValue(vendor);
	m_endpointVendor->IncludeOptionalField(H225_VendorIdentifier::e_versionId);
	   m_endpointVendor->m_versionId.SetValue(version);
}

inline void EndpointRec::SetNAT(bool nat)
{
	m_nat = nat;
}

inline void EndpointRec::SetH46024(bool support)
{
	m_H46024 = support;
}

inline void EndpointRec::SetH46024A(bool support)
{
	m_H46024a = support;
}

inline void EndpointRec::SetH46024B(bool support)
{
	m_H46024b = support;
}

inline bool EndpointRec::IsNATed() const
{
	return m_nat;
}

inline bool EndpointRec::SupportH46024() const
{
	return m_H46024;
}

inline bool EndpointRec::SupportH46024A() const
{
	return m_H46024a;
}

inline bool EndpointRec::SupportH46024B() const
{
	return m_H46024b;
}

inline bool EndpointRec::UseH46024B() const
{
	int nat = (int)m_epnattype;
	return (m_H46024b && (nat > 2 && nat < 5));
}

inline bool EndpointRec::HasNATProxy() const
{
	return m_natproxy;
}

inline bool EndpointRec::IsInternal() const
{
	return m_internal;
}

inline bool EndpointRec::IsRemote() const
{
	return m_remote;
}

inline PString EndpointRec::GetEPNATTypeString(EPNatTypes nat)
{
  static const char * const Names[9] = {
    "Unknown NAT",
    "Open NAT",
    "Cone NAT",
    "Restricted NAT",
    "Port Restricted NAT",
    "Symmetric NAT",
    "Symmetric Firewall",
    "Blocked",
    "Partially Blocked"
  };

  if (nat < 9)
    return Names[nat];

  return PString((unsigned)nat);
}

inline PIPSocket::Address EndpointRec::GetNATIP() const
{
	PWaitAndSignal lock(m_usedLock);
	return m_natip;
}

inline CallSignalSocket *EndpointRec::GetSocket()
{
	PWaitAndSignal lock(m_usedLock);
	return m_natsocket;
}

inline CallSignalSocket *EndpointRec::GetAndRemoveSocket()
{
	PWaitAndSignal lock(m_usedLock);
	CallSignalSocket *socket = m_natsocket;
	m_natsocket = NULL;
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
	int ttl = GetTimeToLive();
	return (!ttl || (*now - m_updatedTime).GetSeconds() < ttl);
}

inline void EndpointRec::DeferTTL()
{
	PWaitAndSignal lock(m_usedLock);
	m_updatedTime = PTime();
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

inline PString CallRec::GetSRC_media_control_IP() const
{
    return m_src_media_control_IP;
}

inline PString CallRec::GetDST_media_control_IP() const
{
    return m_dst_media_control_IP;
}

inline PString CallRec::GetSRC_media_IP() const
{
    return m_src_media_IP;
}

inline PString CallRec::GetDST_media_IP() const
{
    return m_dst_media_IP;
}

inline bool CallRec::GetRTCP_SRC_sdes_flag() const
{
    return m_rtcp_source_sdes_flag;
}

inline bool CallRec::GetRTCP_DST_sdes_flag() const
{
    return m_rtcp_destination_sdes_flag;
}

inline PStringList CallRec::GetRTCP_SRC_sdes() const
{
    return m_rtcp_source_sdes;
}

inline PStringList CallRec::GetRTCP_DST_sdes() const
{
    return m_rtcp_destination_sdes;
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
	if (m_disconnectCause == 0)
		m_disconnectCause = causeCode;
}

inline unsigned CallRec::GetDisconnectCauseTranslated() const
{
	return (m_disconnectCauseTranslated == 0) ? m_disconnectCause : m_disconnectCauseTranslated;
}

inline void CallRec::SetDisconnectCauseTranslated( unsigned causeCode )
{
	m_disconnectCauseTranslated = causeCode;
}

inline void CallRec::ResetTimeOut()
{
	m_timeout = 0;
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

class PreliminaryCall
{
public:
	PreliminaryCall(CallSignalSocket * callerSocket, const H225_CallIdentifier & id, unsigned ref)
		: m_socket(callerSocket), m_callid(id), m_callref(ref), m_proceedingSent(false) { }
	~PreliminaryCall() { }

	CallSignalSocket * GetCallSignalSocketCalling() const { return m_socket; }
	H225_CallIdentifier GetCallIdentifier() const { return m_callid; }
	unsigned GetCallRef() const { return m_callref; }
	bool IsProceedingSent() const { return m_proceedingSent; }
	void SetProceedingSent(bool val) { m_proceedingSent = m_proceedingSent || val; }

private:
	CallSignalSocket * m_socket;
	H225_CallIdentifier m_callid;
	unsigned m_callref;
	bool m_proceedingSent;
};

// hold data about calls being established, only valid during the routing process before calls are accepted or rejected
class PreliminaryCallTable : public Singleton<PreliminaryCallTable>
{
public:
	PreliminaryCallTable();
	~PreliminaryCallTable();

	void Insert(PreliminaryCall * call);
	void Remove(const H225_CallIdentifier & id);
	PreliminaryCall * Find(const H225_CallIdentifier & id) const;

private:
	PreliminaryCallTable(const PreliminaryCallTable &);
	PreliminaryCallTable& operator==(const PreliminaryCallTable &);

	mutable PReadWriteMutex tableLock;
	// cid -> call
	std::map<H225_CallIdentifier, PreliminaryCall*> calls;
};

#endif // RASTBL_H
