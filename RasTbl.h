//////////////////////////////////////////////////////////////////
//
// bookkeeping for RAS-Server in H.323 gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	990500	initial version (Xiang Ping Chen, Rajat Todi, Joe Metzger)
//	990600	ported to OpenH323 V. 1.08 (Jan Willamowius)
//	991003	switched to STL (Jan Willamowius)
//
//////////////////////////////////////////////////////////////////

#ifndef RASTBL_H
#define RASTBL_H "@(#) $Id$"

#include "rwlock.h" 
#include "singleton.h" 

#include <list>
#include <vector>
#include <string>

#include <h225.h>
#include <ptlib/sockets.h>

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 )
#endif


using std::list;
using std::vector;
using std::string;

class GkDestAnalysisList;
class USocket;
class CallSignalSocket;

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
	void Inc() { if (pt) pt->Lock(); }
	void Dec() { if (pt) pt->Unlock(); }
	T &operator*();
	T *pt;
};

class EndpointRec
{
public:
	EndpointRec(const H225_RasMessage & completeRAS, bool Permanent=false);
	virtual ~EndpointRec();

	// public interface to access EndpointRec
	const H225_TransportAddress & GetRasAddress() const
	{ return m_rasAddress; }
	const H225_TransportAddress & GetCallSignalAddress() const
	{ return m_callSignalAddress; }
	const H225_EndpointIdentifier & GetEndpointIdentifier() const
	{ return m_endpointIdentifier; }
	const H225_ArrayOf_AliasAddress & GetAliases() const
	{ return m_terminalAliases; }
	const H225_EndpointType & GetEndpointType() const
	{ return *m_terminalType; }
	int GetTimeToLive() const
	{ return m_timeToLive; }
	PIPSocket::Address GetNATIP() const
	{ return m_natip; }
	CallSignalSocket *GetSocket();

	/** checks if the given aliases are prefixes of the aliases which are stored
	    for the endpoint in the registration table. #fullMatch# returns #TRUE# if
	    a full match is found.
	    @returns #TRUE# if a match is found
	 */
        bool PrefixMatch_IncompleteAddress(const H225_ArrayOf_AliasAddress &aliases, 
	                                  bool &fullMatch) const;

	virtual void SetRasAddress(const H225_TransportAddress &);
	virtual void SetEndpointIdentifier(const H225_EndpointIdentifier &);
	virtual void SetTimeToLive(int);
	virtual void SetPermanent(bool = true);
	virtual void SetAliases(const H225_ArrayOf_AliasAddress &);
	virtual void SetEndpointType(const H225_EndpointType &);

	virtual void Update(const H225_RasMessage & lightweightRRQ);
	virtual bool IsGateway() const { return false; }
	virtual bool CompareAlias(const H225_ArrayOf_AliasAddress *) const;
	virtual bool LoadConfig() { return true; } // workaround: VC need a return value

	virtual EndpointRec *Unregister();
	virtual EndpointRec *Expired();

	//virtual void BuildACF(H225_AdmissionConfirm &) const;
	//virtual void BuildLCF(H225_LocationConfirm &) const;

	virtual PString PrintOn(bool verbose) const;

	void SetNAT(bool nat) { m_nat = nat; }
	void SetNATAddress(const PIPSocket::Address &);
	void SetSocket(CallSignalSocket *);

	bool IsUsed() const;
	bool IsUpdated(const PTime *) const;
	bool IsFromParent() const { return m_fromParent; }
	bool IsNATed() const { return m_nat; }
	PTime GetUpdatedTime() const { return m_updatedTime; }

	/** If this Endpoint would be register itself again with all the same data
	 * how would this RRQ would look like? May be implemented with a 
	 * built-together-RRQ, but for the moment a stored RRQ.
	 */
	const H225_RasMessage & GetCompleteRegistrationRequest() const
	{ return m_RasMsg; }

	void AddCall();
	void AddConnectedCall();
	void RemoveCall();

	void Lock();
	void Unlock();

	bool SendIRQ();

	// smart pointer for EndpointRec
	typedef SmartPtr<EndpointRec> Ptr;

protected:

	void SetEndpointRec(H225_RegistrationRequest &);
	void SetEndpointRec(H225_AdmissionRequest &);
	void SetEndpointRec(H225_AdmissionConfirm &);
	void SetEndpointRec(H225_LocationConfirm &);

	bool SendURQ(H225_UnregRequestReason::Choices);

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
	int m_pollCount, m_usedCount;
	mutable PMutex m_usedLock;

	PTime m_updatedTime;
	bool m_fromParent, m_nat;
	PIPSocket::Address m_natip;
	CallSignalSocket *m_natsocket;

private: // not assignable
	EndpointRec(const EndpointRec &);
	EndpointRec & operator= (const EndpointRec &);
};

typedef EndpointRec::Ptr endptr;


class GatewayRec : public EndpointRec {
public:
	typedef std::vector<string>::iterator prefix_iterator;
	typedef std::vector<string>::const_iterator const_prefix_iterator;

	GatewayRec(const H225_RasMessage & completeRAS, bool Permanent=false);

	virtual void SetAliases(const H225_ArrayOf_AliasAddress &);
	virtual void SetEndpointType(const H225_EndpointType &);

	virtual void Update(const H225_RasMessage & lightweightRRQ);
	virtual bool IsGateway() const { return true; }
	virtual bool LoadConfig();
	virtual int  PrefixMatch(const H225_ArrayOf_AliasAddress &) const;

	//virtual void BuildLCF(H225_LocationConfirm &) const;

	virtual PString PrintOn(bool verbose) const;

	void AddPrefixes(const H225_ArrayOf_SupportedProtocols &);
	void AddPrefixes(const PString &);
	void SortPrefixes();

protected:
	// strange! can't compile in debug mode, anybody know why??
	//vector<PString> Prefixes;  
	vector<string> Prefixes;
	bool defaultGW;
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
	
	template<class MsgType> endptr getMsgDestination(const MsgType & msg, unsigned int & reason, 
	                                                 bool SearchOuterZone = true)
	{
	  endptr ep;
	  bool ok = getGkDestAnalysisList().getMsgDestination(msg, EndpointList, listLock,
	                                                      ep, reason);
	  if (!ok && SearchOuterZone) {
            ok = getGkDestAnalysisList().getMsgDestination(msg, OuterZoneList, listLock, 
	                                                   ep, reason);
	  }
	  return (ok) ? ep : endptr(0);
	}

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

public:
  enum enumGatewayFlags {
                e_SCNType		// "trunk" or "residential"
  };
  
private:

	endptr InternalInsertEP(H225_RasMessage &);
	endptr InternalInsertOZEP(H225_RasMessage &, H225_LocationConfirm &);
	endptr InternalInsertOZEP(H225_RasMessage &, H225_AdmissionConfirm &);

	void InternalPrint(USocket *, BOOL, list<EndpointRec *> *, PString &);
	void InternalStatistics(const list<EndpointRec *> *, unsigned & s, unsigned & t, unsigned & g, unsigned & n) const;

	void InternalRemove(iterator);

	template<class F> endptr InternalFind(const F & FindObject) const
	{ return InternalFind(FindObject, &EndpointList); }

	template<class F> endptr InternalFind(const F & FindObject, const list<EndpointRec *> *ListToBeFound) const
	{   //  The function body must be put here,
	    //  or the Stupid VC would fail to instantiate it
        	ReadLock lock(listLock);
        	const_iterator Iter(find_if(ListToBeFound->begin(), ListToBeFound->end(), FindObject));
	        return endptr((Iter != ListToBeFound->end()) ? *Iter : 0);
	}

	endptr InternalFindEP(const H225_ArrayOf_AliasAddress & alias, list<EndpointRec *> *ListToBeFound, bool);

	void GenerateEndpointId(H225_EndpointIdentifier &);
	void GenerateAlias(H225_ArrayOf_AliasAddress &, const H225_EndpointIdentifier &) const;

	GkDestAnalysisList & getGkDestAnalysisList() { return *m_destAnalysisList; }
	list<EndpointRec *> EndpointList;
	list<EndpointRec *> OuterZoneList;
	list<EndpointRec *> RemovedList;
	int regSize;
	mutable PReadWriteMutex listLock;
	GkDestAnalysisList * m_destAnalysisList;

	// counter to generate endpoint identifier
	// this is NOT the count of endpoints!
	int recCnt, ozCnt;
	PString endpointIdSuffix; // Suffix of the generated Endpoint IDs

	// not assignable
	RegistrationTable(const RegistrationTable &);
	RegistrationTable& operator=(const RegistrationTable &);
};


// record of one active call
class CallRec {
public:
	CallRec(const H225_CallIdentifier &, const H225_ConferenceIdentifier &, WORD, const PString &, const PString & srcInfo, int, bool);
	virtual ~CallRec();

	enum NATType { // who is nated?
		none = 0,
		callingParty = 1,
		calledParty = 2,
		both = 3
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
	bool GetCalledAddress(PIPSocket::Address &, WORD &) const;
	int GetBandWidth() const { return m_bandWidth; }
	int GetNATType() const { return m_nattype; }
	int GetNATType(PIPSocket::Address &, PIPSocket::Address &) const;
	CallSignalSocket *GetCallSignalSocketCalled() { return m_calledSocket; }
	CallSignalSocket *GetCallSignalSocketCalling() { return m_callingSocket; }
	const H225_ArrayOf_CryptoH323Token & GetAccessTokens() const { return m_accessTokens; }

	void SetCallNumber(PINDEX i) { m_CallNumber = i; }
	void SetCalledAddress(const H225_TransportAddress & addr);
	void SetCalling(const endptr & NewCalling);
	void SetCalled(const endptr & NewCalled);
	void SetForward(CallSignalSocket *, const H225_TransportAddress &, const endptr &, const PString &, const PString &);
	void SetBandwidth(int Bandwidth) { m_bandWidth = Bandwidth; }
	void SetSocket(CallSignalSocket *, CallSignalSocket *);
	void SetRegistered(bool registered) { m_registered = registered; }
	void SetAccessTokens(const H225_ArrayOf_CryptoH323Token & tokens) { m_accessTokens = tokens; }

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
	bool IsRegistered() const { return m_registered; }
	bool IsForwarded() const { return m_forwarded; }
	bool IsSocketAttached() const { return (m_callingSocket != 0); }

	PString GenerateCDR() const;
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
	bool IsDurationLimitExceeded();

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
		const time_t now,
		/// timeout (in milliseconds) for a Connect message to be received,
		/// a signalling channel to be opened after ARQ or call being connected
		/// in direct signalling mode
		const long connectTimeout
		);
			
	// smart pointer for CallRec
	typedef SmartPtr<CallRec> Ptr;

private:
	void SendDRQ();
	void InternalSetEP(endptr &, const endptr &);

	PINDEX m_CallNumber;
	H225_CallIdentifier m_callIdentifier;
	H225_ConferenceIdentifier m_conferenceIdentifier;
	H225_TransportAddress m_calledAddress;

	endptr m_Calling, m_Called;
	WORD m_crv;

	PString m_callerAddr, m_callerId;
	PString m_calleeAddr, m_calleeId;
	PString m_destInfo;
	PString m_srcInfo; //added (MM 05.11.01)
	int m_bandWidth;

	/// timestamp (seconds since 1st January, 1970) for the call creation
	/// (triggered by ARQ or Setup)
	time_t m_creationTime;
	/// timestamp (seconds since 1st January, 1970) for a Setup message reception
	time_t m_setupTime;
	/// timestamp (seconds since 1st January, 1970) for a Connect (routed mode)
	/// or ARQ/ACF (direct mode) message reception
	time_t m_connectTime;
	/// timestamp (seconds since 1st January, 1970) for the call disconnect
	time_t m_disconnectTime;
	/// duration limit (seconds) for this call, 0 means no limit 
	long m_durationLimit;
	/// Q.931 release complete cause code
	unsigned m_disconnectCause;
	
	CallSignalSocket *m_callingSocket, *m_calledSocket;

	int m_usedCount;
	mutable PMutex m_usedLock, m_sockLock;
	int m_nattype;
	
	bool m_h245Routed;
	bool m_registered;
	bool m_forwarded;
	endptr m_Forwarder;

	H225_ArrayOf_CryptoH323Token m_accessTokens;

	CallRec(const CallRec & Other);
	CallRec & operator= (const CallRec & other);
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
	void SetTotalBandWidth(int bw);
	bool GetAdmission(int bw);
	bool GetAdmission(int bw, const callptr &);
	int GetAvailableBW() const { return m_capacity; }

	callptr FindCallRec(const H225_CallIdentifier & CallId) const;
	callptr FindCallRec(const H225_CallReferenceValue & CallRef) const;
	callptr FindCallRec(PINDEX CallNumber) const;
	callptr FindCallRec(const endptr &) const;
	callptr FindBySignalAdr(const H225_TransportAddress & SignalAdr) const;

	void ClearTable();
	void CheckCalls();

	void RemoveCall(const H225_DisengageRequest & obj_drq, const endptr &);
	void RemoveCall(const callptr &);

	void PrintCurrentCalls(USocket *client, BOOL verbose=FALSE) const;
	PString PrintStatistics() const;

	void AddForwardedCall(const callptr &);
	endptr IsForwardedCall(const callptr &);

	void LoadConfig();

	PINDEX Size() const { return m_activeCall; }

	/** @return
		ConnectTimeout value (milliseconds).
	*/
	long GetConnectTimeout() const { return m_connectTimeout; }
	
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

	void InternalStatistics(unsigned & n, unsigned & act, unsigned & nb, unsigned & np, PString & msg, BOOL verbose) const;

	list<CallRec *> CallList;
	list<CallRec *> RemovedList;

	bool m_genNBCDR;
	bool m_genUCCDR;

	PINDEX m_CallNumber;
	mutable PReadWriteMutex listLock;

	list<callptr> ForwardedCallList;
	mutable PReadWriteMutex flistLock;

	int m_capacity;

	// statistics
	unsigned m_CallCount, m_successCall, m_neighborCall, m_parentCall, m_activeCall;

	/// timeout for a Connect message to be received
	/// and for a signalling channel to be opened after ACF/ARQ
	/// (0 if GK is not in routed mode)
	long m_connectTimeout;
	
	CallTable(const CallTable &);
	CallTable& operator==(const CallTable &);
};

// inline functions of EndpointRec
inline bool EndpointRec::IsUsed() const
{
//	PWaitAndSignal lock(m_usedLock);
	return (m_activeCall > 0 || m_usedCount > 0);
}

inline bool EndpointRec::IsUpdated(const PTime *now) const
{
	return (!m_timeToLive || (*now - m_updatedTime).GetSeconds() < m_timeToLive);
}

inline void EndpointRec::AddCall()
{       
	PWaitAndSignal lock(m_usedLock);
	++m_activeCall, ++m_totalCall;
}       

inline void EndpointRec::AddConnectedCall()
{       
	PWaitAndSignal lock(m_usedLock);
	++m_connectedCall;
}       

inline void EndpointRec::RemoveCall()
{       
	PWaitAndSignal lock(m_usedLock); 
	--m_activeCall;
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

inline bool CallRec::IsDurationLimitExceeded()
{
	PWaitAndSignal lock(m_usedLock);
	const long now = time(NULL);
	return (m_durationLimit > 0 && m_connectTime != 0 
		&& ((now - m_connectTime) > m_durationLimit));
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
	m_disconnectCause = causeCode;
}

#endif // RASTBL_H
