//////////////////////////////////////////////////////////////////
//
// bookkeeping for RAS-Server in H.323 gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
// 	990500	initial version (Xiang Ping Chen, Rajat Todi, Joe Metzger)
//	990600	ported to OpenH323 V. 1.08 (Jan Willamowius)
//	991003	switched to STL (Jan Willamowius)
//
//////////////////////////////////////////////////////////////////


#ifndef _rastbl_h__
#define _rastbl_h__

#include "ptlib.h" 
#include "ptlib/sockets.h"
#include "h225.h"
#include "GkStatus.h"

#include <set>
#include <list>
#include <vector>
#include <string>

using std::set;
using std::list;
using std::vector;
using std::string;

class ReadLock {
	PReadWriteMutex &mutex;
  public:
	ReadLock(PReadWriteMutex &m) : mutex(m) { mutex.StartRead(); }
	~ReadLock() { mutex.EndRead(); }
};

class WriteLock {
	PReadWriteMutex &mutex;
  public:
	WriteLock(PReadWriteMutex &m) : mutex(m) { mutex.StartWrite(); }
	~WriteLock() { mutex.EndWrite(); }
};

// this data structure is obsolete !
// all information about ongoing calls is in CallTable
// it's still filled with correct information, but all
// functions using it should be rewritten to use CallTable
class conferenceRec
{
public:
	conferenceRec(const H225_EndpointIdentifier & src, const H225_ConferenceIdentifier & cid, const H225_BandWidth & bw);

	conferenceRec & operator= (const conferenceRec & other);
	bool operator< (const conferenceRec & other) const;

// protected:
	H225_EndpointIdentifier m_src;
	H225_ConferenceIdentifier m_cid;
	H225_BandWidth m_bw;
};  


// this data structure is obsolete !
// all information about ongoing calls is in CallTable
class resourceManager : public Singleton<resourceManager>
{
public:
	resourceManager();
protected:
	resourceManager(const resourceManager &);
public:
	void SetBandWidth(int bw);
	unsigned int GetAvailableBW(void) const;
	BOOL GetAdmission(const H225_EndpointIdentifier & src, const H225_ConferenceIdentifier & cid, const H225_BandWidth & bw);
	BOOL CloseConference(const H225_EndpointIdentifier & src, const H225_ConferenceIdentifier & cid);

protected:
	H225_BandWidth m_capacity;
	set<conferenceRec> ConferenceList;
};


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
	EndpointRec(const H225_RasMessage & completeRRQ, bool Permanent=false);
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

	virtual void SetRasAddress(const H225_TransportAddress &);
	virtual void SetEndpointIdentifier(const H225_EndpointIdentifier &);
	virtual void SetTimeToLive(int);
	virtual void SetAliases(const H225_ArrayOf_AliasAddress &);
	virtual void SetEndpointType(const H225_EndpointType &);

	virtual void Update(const H225_RasMessage & lightweightRRQ);
	virtual bool IsGateway() const { return false; }
	virtual bool CompareAlias(const H225_ArrayOf_AliasAddress *) const;
	virtual bool LoadConfig() { return true; } // workaround: VC need a return value

	virtual EndpointRec *Unregister();
	virtual EndpointRec *Expired();

	virtual void BuildLCF(H225_LocationConfirm &) const;

	virtual PString PrintOn(bool verbose) const;

	bool IsUsed() const;
	bool IsUpdated() const;
	PTime GetUpdatedTime() const { return m_updatedTime; }

	/** If this Endpoint would be register itself again with all the same data
	 * how would this RRQ would look like? May be implemented with a 
	 * built-together-RRQ, but for the moment a stored RRQ.
	 */
	const H225_RasMessage &GetCompleteRegistrationRequest() const
	{ return m_RasMsg; }

	void Lock();
	void Unlock();

	// smart pointer for EndpointRec
	typedef SmartPtr<EndpointRec> Ptr;

protected:

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

	int m_usedCount;
	mutable PMutex m_usedLock;

	PTime m_updatedTime;

private: // not assignable
	EndpointRec(const EndpointRec &);
	EndpointRec & operator= (const EndpointRec &);
};

typedef EndpointRec::Ptr endptr;

inline bool EndpointRec::IsUsed() const
{
	PWaitAndSignal lock(m_usedLock);
	return (m_usedCount != 0);
}

inline bool EndpointRec::IsUpdated() const
{
	return (!m_timeToLive || (PTime() - m_updatedTime) < (DWORD)m_timeToLive*1000);
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


class GatewayRec : public EndpointRec {
public:
	typedef std::vector<string>::iterator prefix_iterator;
	typedef std::vector<string>::const_iterator const_prefix_iterator;

	GatewayRec(const H225_RasMessage & completeRRQ, bool Permanent=false);

	virtual void SetAliases(const H225_ArrayOf_AliasAddress &);
	virtual void SetEndpointType(const H225_EndpointType &);

	virtual void Update(const H225_RasMessage & lightweightRRQ);
	virtual bool IsGateway() const { return true; }
	virtual bool LoadConfig();
	virtual int  PrefixMatch(const H225_ArrayOf_AliasAddress &) const;

	virtual void BuildLCF(H225_LocationConfirm &) const;

	virtual PString PrintOn(bool verbose) const;

protected:
	void AddPrefixes(const H225_ArrayOf_SupportedProtocols &);
	void SortPrefixes();

	// strange! can't compile in debug mode, anybody know why??
	//vector<PString> Prefixes;  
	vector<string> Prefixes;
	bool defaultGW;
};


class OuterZoneEPRec : public EndpointRec {
public:
	OuterZoneEPRec(const H225_RasMessage & completeLCF, const H225_EndpointIdentifier &);

	virtual EndpointRec *Unregister() { return this; }
	virtual EndpointRec *Expired() { return this; }
};

class OuterZoneGWRec : public GatewayRec {
public:
	OuterZoneGWRec(const H225_RasMessage & completeLCF, const H225_EndpointIdentifier &);

	virtual EndpointRec *Unregister() { return this; }
	virtual EndpointRec *Expired() { return this; }
};


class RegistrationTable : public Singleton<RegistrationTable>
{
public:
	typedef std::list<EndpointRec *>::iterator iterator;
	typedef std::list<EndpointRec *>::const_iterator const_iterator;

	RegistrationTable();
	~RegistrationTable();

	endptr InsertRec(H225_RasMessage & rrq);
	void RemoveByEndptr(const endptr & eptr);
	void RemoveByEndpointId(const H225_EndpointIdentifier & endpointId);

	endptr FindByEndpointId(const H225_EndpointIdentifier & endpointId) const;
	endptr FindBySignalAdr(const H225_TransportAddress & SignalAdr) const;
	endptr FindByAliases(const H225_ArrayOf_AliasAddress & alias) const;
	endptr FindEndpoint(const H225_ArrayOf_AliasAddress & alias, bool SearchOuterZone = true);

	void PrintAllRegistrations(GkStatus::Client &client, BOOL verbose=FALSE);
	void PrintAllCached(GkStatus::Client &client, BOOL verbose=FALSE);
	void PrintRemoved(GkStatus::Client &client, BOOL verbose=FALSE);

	void ClearTable();
	void CheckEndpoints();

//	void PrintOn( ostream &strm ) const;

	/** Updates Prefix + Flags for all aliases */
	void LoadConfig();

public:
  enum enumGatewayFlags {
                e_SCNType		// "trunk" or "residential"
  };
  
private:

	endptr InternalInsertEP(H225_RasMessage & rrq);
	endptr InternalInsertOZEP(H225_RasMessage & lcf);

	void InternalPrint(GkStatus::Client &, BOOL, list<EndpointRec *> *, PString &);

	template<class F> endptr InternalFind(const F & FindObject) const
	{ return InternalFind(FindObject, &EndpointList); }

	template<class F> endptr InternalFind(const F & FindObject, const list<EndpointRec *> *ListToBeFinded) const
	{   //  The function body must be put here,
	    //  or the Stupid VC would fail to instantiate it
        	ReadLock lock(listLock);
        	const_iterator Iter(find_if(ListToBeFinded->begin(), ListToBeFinded->end(), FindObject));
	        return endptr((Iter != ListToBeFinded->end()) ? *Iter : 0);
	}

	endptr InternalFindEP(const H225_ArrayOf_AliasAddress & alias, list<EndpointRec *> *ListToBeFinded);

	void GenerateEndpointId(H225_EndpointIdentifier &);
	void GenerateAlias(H225_ArrayOf_AliasAddress &, const H225_EndpointIdentifier &) const;

	static void delete_ep(EndpointRec *e) { delete e; }

	list<EndpointRec *> EndpointList;
	list<EndpointRec *> OuterZoneList;
	list<EndpointRec *> RemovedList;
	mutable PReadWriteMutex listLock;

	// counter to generate endpoint identifier
	// this is NOT the count of endpoints!
	int recCnt;
	PString endpointIdSuffix; // Suffix of the generated Endpoint IDs

	// not assignable
	RegistrationTable(const RegistrationTable &);
	RegistrationTable& operator=(const RegistrationTable &);
};



// data about a single endpoint in a call
class EndpointCallRec
{
public:
	EndpointCallRec(H225_TransportAddress m_callSignalAddress, H225_TransportAddress m_rasAddress, H225_CallReferenceValue m_callReference);

	bool operator< (const EndpointCallRec & other) const;

	H225_TransportAddress m_callSignalAddress;
	H225_TransportAddress m_rasAddress;	// is this redundant ? can this always be found via the RegistrationTable ?
	H225_CallReferenceValue m_callReference;
	// TODO: thread pointer (or NULL for direct calls)
};

class SignalConnection;

// record of one active call
class CallRec
{
public:
	CallRec(const H225_CallIdentifier &, const H225_ConferenceIdentifier &, const PString &, int);
	virtual ~CallRec();

	PINDEX GetCallNumber() const
	{ return m_CallNumber; }
	const H225_CallIdentifier & GetCallIdentifier() const
	{ return m_callIdentifier; }
	const H225_ConferenceIdentifier & GetConferenceIdentifier() const
	{ return m_conferenceIdentifier; }
	const H225_TransportAddress *GetCallingAddress() const
	{ return (m_Calling) ? &m_Calling->GetCallSignalAddress() : 0; }
	const H225_TransportAddress *GetCalledAddress() const
	{ return (m_Called) ? &m_Called->GetCallSignalAddress() : 0; }

	void SetCalling(const endptr & NewCalling, unsigned = 0);
	void SetCalled(const endptr & NewCalled, unsigned = 0);
	void SetBandwidth(int Bandwidth) { m_bandWidth = Bandwidth; }
	void SetCallNumber(PINDEX i) { m_CallNumber = i; }
	void SetSigConnection(SignalConnection *);

	void SetConnected(bool c);
	void SetTimer(int seconds);
	void StartTimer();
	void StopTimer();

	void Disconnect();

	/// deletes endpoint end marks it as invalid
	void RemoveCalling();
	/// deletes endpoint end marks it as invalid
	void RemoveCalled();
	/// remove all involved endpoints and marks then invalid
	void RemoveAll();
	/// counts the endpoints in this rec; currently #0 <= n <= 2#.
	int CountEndpoints() const;

	bool CompareCallId(H225_CallIdentifier *CallId) const;
	bool CompareCRV(unsigned crv) const;
	bool CompareCallNumber(PINDEX CallNumber) const;
	bool CompareEndpoint(endptr *) const;
	bool CompareSigAdr(H225_TransportAddress *adr) const;

	bool IsUsed() const;
	bool IsConnected() const;

	PString GenerateCDR() const;
	PString PrintOn(bool verbose) const;

	void Lock();
	void Unlock();

	// smart pointer for EndpointRec
	typedef SmartPtr<CallRec> Ptr;

private:
	void SendDRQ();

	PDECLARE_NOTIFIER(PTimer, CallRec, OnTimeout);
//	void OnTimeout(PTimer &, INT);

	H225_CallIdentifier m_callIdentifier;
	H225_ConferenceIdentifier m_conferenceIdentifier;
	PString m_destInfo;
	int m_bandWidth;
	PINDEX m_CallNumber;

	endptr m_Calling;
	endptr m_Called;
	unsigned m_callingCRV;
	unsigned m_calledCRV;

	PTime *m_startTime;
	PTimer *m_timer;
	int m_timeout;

	SignalConnection *m_sigConnection;

	int m_usedCount;
	mutable PMutex m_usedLock;

	CallRec(const CallRec & Other);
	CallRec & operator= (const CallRec & other);
};

typedef CallRec::Ptr callptr;

class Q931;

// all active calls
class CallTable : public Singleton<CallTable>
{
public:
	typedef std::list<CallRec *>::iterator iterator;
	typedef std::list<CallRec *>::const_iterator const_iterator;

	CallTable();
	~CallTable();

	void Insert(CallRec * NewRec);
//	void Insert(const endptr & Calling, const endptr & Called, int Bandwidth, const H225_CallIdentifier & CallId, const H225_ConferenceIdentifier & ConfID, const PString& destInfo);
//	void Insert(const EndpointCallRec & Calling, int Bandwidth, H225_CallIdentifier CallId, H225_ConferenceIdentifier ConfID, const PString& destInfo);

//	callptr FindCallRec(const Q931 & m_q931) const;
	callptr FindCallRec(const H225_CallIdentifier & CallId) const;
	callptr FindCallRec(const H225_CallReferenceValue & CallRef) const;
	callptr FindCallRec(PINDEX CallNumber) const;
	callptr FindCallRec(const endptr &) const;
	callptr FindBySignalAdr(const H225_TransportAddress & SignalAdr) const;

//	void RemoveCall(const Q931 & m_q931);
	void RemoveCall(const H225_DisengageRequest & obj_drq);
	void RemoveCall(const callptr &);

	void PrintCurrentCalls(GkStatus::Client &client, BOOL verbose=FALSE) const;

	void LoadConfig();

private:
	template<class F> callptr InternalFind(const F & FindObject) const
	{
        	ReadLock lock(listLock);
        	const_iterator Iter(find_if(CallList.begin(), CallList.end(), FindObject));
	        return callptr((Iter != CallList.end()) ? *Iter : 0);
	}

	bool InternalRemovePtr(CallRec *call);
	void InternalRemove(const H225_CallIdentifier & CallId);
	void InternalRemove(unsigned CallRef);
	void InternalRemove(iterator);

	static void delete_call(CallRec *c) { delete c; }

	list<CallRec *> CallList;
	list<CallRec *> RemovedList;
//	set <CallRec> CallList;

	bool m_genNBCDR;
	bool m_genUCCDR;

	PINDEX m_CallNumber;
	mutable PReadWriteMutex listLock;

	CallTable(const CallTable &);
	CallTable& operator==(const CallTable &);
};

// inline functions of CallRec
inline void CallRec::SetCalling(const endptr & NewCalling, unsigned crv)
{
	PWaitAndSignal lock(m_usedLock);
	m_Calling = NewCalling, m_callingCRV = crv;
}

inline void CallRec::SetCalled(const endptr & NewCalled, unsigned crv)
{
	PWaitAndSignal lock(m_usedLock);
	m_Called = NewCalled, m_calledCRV = crv;
}

inline void CallRec::SetSigConnection(SignalConnection *sigConnection)
{
	m_sigConnection = sigConnection;
}

inline void CallRec::SetTimer(int seconds)
{
	m_timeout = seconds;
}

inline void CallRec::RemoveCalling()
{
	SetCalling(endptr(0));
}

inline void CallRec::RemoveCalled()
{
	SetCalled(endptr(0));
}

inline void CallRec::RemoveAll()
{
	RemoveCalled();
	RemoveCalling();
}

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

inline bool CallRec::CompareCallId(H225_CallIdentifier *CallId) const
{
	return (m_callIdentifier == *CallId);
}

inline bool CallRec::CompareCRV(unsigned crv) const
{
	return (m_Calling && m_callingCRV == crv) || (m_Called && m_calledCRV == crv);
}

inline bool CallRec::CompareCallNumber(PINDEX CallNumber) const
{
	return (m_CallNumber == CallNumber);
}

inline bool CallRec::CompareEndpoint(endptr *ep) const
{
	return (m_Calling && m_Calling == *ep) || (m_Called && m_Called == *ep);
}

inline bool CallRec::CompareSigAdr(H225_TransportAddress *adr) const
{
	return (m_Calling && m_Calling->GetCallSignalAddress() == *adr) ||
		(m_Called && m_Called->GetCallSignalAddress() == *adr);
}

inline bool CallRec::IsUsed() const
{
	PWaitAndSignal lock(m_usedLock);
	return (m_usedCount != 0);
}

inline bool CallRec::IsConnected() const
{       
	return (m_startTime != 0);
}       

#endif

