// -*- mode: c++; eval: (c-set-style "linux"); -*-
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


#ifndef _rastbl_h__
#define _rastbl_h__

#include "ptlib.h"
#include "ptlib/sockets.h"
#include "h225.h"
#include "GkStatus.h"
#include <h323pdu.h>
#include <q931.h>
#include "singleton.h"

#ifdef P_SOLARIS
#define map stl_map
#endif

#include <set>
#include <list>
#include <vector>
#include <string>
#include <map>

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 )
#endif

using std::set;
using std::list;
using std::vector;
using std::string;

class GkDestAnalysisList;

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

// Classes to store information read form e.g. LDAP
// necessary for e.g. routing decisions
using std::map;
typedef std::map<PString, PString> SpecialDialClass;
typedef SpecialDialClass::value_type SpecialDialValuePair;

class CallingProfile {
public:
        CallingProfile() { m_honorsARJincompleteAddress = TRUE;
		           m_isCPE = FALSE;
			   m_WhiteListBeforeBlackList = FALSE; // BlacklistBeforeWhiteList, default nonblocking
	                 };

        // Get accessor methods
        const PString & getH323ID() const { return m_h323id; }
        const BOOL isCPE() const { return m_isCPE; } // Customer Promise Equipment
        const BOOL isGK() const { return m_isGK; } // Gatekeeper client
        const BOOL honorsARJincompleteAddress() const { return m_honorsARJincompleteAddress; }
	const BOOL WhiteListBeforeBlackList() const { return m_WhiteListBeforeBlackList; }
        const PStringList & getTelephoneNumbers() const { return m_telephoneNumbers; }
        const PStringToString & getSpecialDials() const { return m_specialDials; }
        const PString & getMainTelephoneNumber() const { return m_mainTelephoneNumber; }
	const PString & getSubscriberNumber() const { return m_subscriberNumber; }
        const PString & getClir() const { return m_clir; }
        const PString & getLac() const { return m_lac; }
        const PString & getNac() const { return m_nac; }
        const PString & getInac() const { return m_inac; }
        const PString & getCC() const { return m_cc; }
        const PString & getCgPN() { return m_cgPN; }

	const PStringList & getBlackList() const { return m_BlackList; }
	const PStringList & getWhiteList() const { return m_WhiteList; }

        // Set accessor methods
        void setH323ID(PString &h323id) { m_h323id = h323id; }
        void setIsCPE(BOOL isCPE) { m_isCPE = isCPE; }
	void setIsGK(BOOL isGK) {m_isGK = isGK;}
        void setTelephoneNumbers(PStringList &telNums) { m_telephoneNumbers = telNums; }
        void setSpecialDials(PStringToString & spcDials) { m_specialDials = spcDials; }
        void setMainTelephoneNumber(PString &mainTelNum) { m_mainTelephoneNumber = mainTelNum; }
	void setSubscriberNumber (PString &SN) { m_subscriberNumber = SN; }
        void setClir(PString &clir) { m_clir = clir; }
        void setLac(PString &lac) { m_lac = lac; }
        void setNac(PString &nac) { m_nac = nac; }
        void setInac(PString &inac) { m_inac = inac; }
        void setHonorsARJincompleteAddress(BOOL honor) { m_honorsARJincompleteAddress = honor; }
	void setWhiteListBeforeBlackList(BOOL wbb) {m_WhiteListBeforeBlackList = wbb; }
        void setCC(PString &cc) { m_cc = cc; }
        void setCgPN(PString &cgPN) { m_cgPN = cgPN; }

	void setBlackList(PStringList &bl) { m_BlackList = bl; }
	void setWhiteList(PStringList &wl) { m_WhiteList = wl; }

	void debugPrint(void);

private:
        PString         m_h323id;                     // H323ID
	BOOL            m_honorsARJincompleteAddress; // honorsARJincompleteAddress
        PStringList     m_telephoneNumbers;           // telephone numbers
        PStringToString m_specialDials;               // emergency call numbers
        PString         m_mainTelephoneNumber;        // main telephone number
	PString         m_subscriberNumber;           // Subscriber Number (i.e. the "80" in 49 5246 80-1234)
        PString         m_clir;                       // CLIR
        PString         m_lac;                        // local access code
        PString         m_nac;                        // national access code
        PString         m_inac;                       // international access code
        PString         m_cc;                         // country code
        PString         m_cgPN;                       // calling party number for CDR generation
        BOOL            m_isCPE;                      // CPE flag
	BOOL            m_isGK;                       // Gatekeeper client Flag
	BOOL            m_WhiteListBeforeBlackList;   // if true do WhitelistBlacklist else BlacklistWhitelistAnalysis

	PStringList     m_BlackList;                  // Blacklist of "bad" prefices
	PStringList     m_WhiteList;                  // Whitelist of "good" prefices
}; // CallingProfile

class CalledProfile {
public:
        CalledProfile() {};
        CalledProfile(PString &dialedPN, PString &calledPN);

        // Get accessor methods
        const BOOL isCPE() const { return m_isCPE; } // Customer Premise Equipment
	const BOOL isGK() const {return m_isGK; }
	const BOOL isTrunkGW() const { return !(m_isCPE || m_isGK) ; }
        const PString & getDialedPN() const { return m_dialedPN; }
        const PString & getCalledPN() const { return m_calledPN; }
        const enum Q931::TypeOfNumberCodes & getDialedPN_TON() const { return m_dialedPN_TON; }

        // Set accessor methods
        void setIsCPE(BOOL isCPE) { m_isCPE = isCPE; }
	void setIsGK(BOOL isGK) { m_isGK = isGK;}
        void setDialedPN(PString &dialedPN,
			 const enum Q931::TypeOfNumberCodes dialedPN_TON = Q931::UnknownType);
        void setDialedPN_TON(const enum Q931::TypeOfNumberCodes dialedPN_TON);
        void setCalledPN(PString &calledPN);

private:
	enum Q931::TypeOfNumberCodes m_dialedPN_TON; // type of number for dialed PN
        PString m_dialedPN; // dialed party number
        PString m_calledPN; // called party number
        BOOL    m_isCPE;    // CPE flag
	BOOL    m_isGK;
}; // CalledProfile

// End of: Classes to store information read from e.g. LDAP

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
	bool GetH323ID(H225_AliasAddress &id);

	/** checks if the given alias is a prefix of the aliases which are stored
	    for the endpoint in the registration table. #fullMatch# returns #TRUE# if
	    a full match is found.
	    @returns #TRUE# if a partial match is found
	 */
	virtual BOOL AliasIsIncomplete(const H225_AliasAddress & alias, BOOL &fullMatch) const;

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

	virtual void BuildACF(H225_AdmissionConfirm &) const;
	virtual void BuildLCF(H225_LocationConfirm &) const;

	virtual PString PrintOn(bool verbose) const;
	void SetNATAddress(PIPSocket::Address);

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
	void RemoveCall();

	void Lock();
	void Unlock();

	bool SendIRQ();

	// smart pointer for EndpointRec
	typedef SmartPtr<EndpointRec> Ptr;

protected:

	void SetEndpointRec(H225_RegistrationRequest &);
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

	int m_activeCall, m_totalCall;
	int m_pollCount, m_usedCount;
	mutable PMutex m_usedLock;

	PTime m_updatedTime;
	bool m_fromParent, m_nat;
	PIPSocket::Address m_natip;

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

	/** checks if the given alias is a prefix of a gateway prefix.
	    #fullMatch# returns #TRUE# if a full match is found.
	    @returns #TRUE# if a full match or a partial match is found
	 */
        virtual BOOL PrefixIsIncomplete(const H225_AliasAddress & alias, BOOL &fullMatch) const;

	/** checks if the given alias matches to a gateway prefix.
	    @returns length of prefix or -1 if no prefix is found
	 */
	virtual int PrefixMatch(const H225_ArrayOf_AliasAddress &) const;

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


class RegistrationTable : public Singleton<RegistrationTable>
{
public:
	typedef std::list<EndpointRec *>::iterator iterator;
	typedef std::list<EndpointRec *>::const_iterator const_iterator;

	RegistrationTable();
	~RegistrationTable();

	void Initialize(GkDestAnalysisList & list) { m_destAnalysisList = &list; }

	endptr InsertRec(H225_RasMessage & rrq);
	void RemoveByEndptr(const endptr & eptr);
	void RemoveByEndpointId(const H225_EndpointIdentifier & endpointId);

	endptr FindByEndpointId(const H225_EndpointIdentifier & endpointId) const;
	endptr FindBySignalAdr(const H225_TransportAddress & SignalAdr) const;
	endptr FindByAliases(const H225_ArrayOf_AliasAddress & alias) const;
	endptr FindEndpoint(const H225_ArrayOf_AliasAddress & alias, bool SearchOuterZone = true);

	void ClearTable();
	void CheckEndpoints();

	void PrintAllRegistrations(GkStatus::Client &client, BOOL verbose=FALSE);
	void PrintAllCached(GkStatus::Client &client, BOOL verbose=FALSE);
	void PrintRemoved(GkStatus::Client &client, BOOL verbose=FALSE);

	PString PrintStatistics() const;

//	void PrintOn( ostream &strm ) const;

	/** Updates Prefix + Flags for all aliases */
	void LoadConfig();

//#ifdef WITH_DEST_ANALYSIS_LIST

	/** Returns the destination endpoint of the message.
	    The calling endpoint must be given if MsgType == H225_AliasAddress. In
	    all other cases it can also be NULL.
	 */
	template<class MsgType> endptr getMsgDestination(const MsgType & msg,
		endptr & cgEP, unsigned int & reason, bool SearchOuterZone = true)
	{
		endptr cdEP;
		PTRACE(2, "Search for calledEP in registration table");
		bool ok = getGkDestAnalysisList().getMsgDestination(msg, EndpointList, listLock,
			cgEP, cdEP, reason);
		if (!cdEP && (reason == H225_AdmissionRejectReason::e_resourceUnavailable) && SearchOuterZone) {
			PTRACE(2, "Search for calledEP in outer zone");
			ok = getGkDestAnalysisList().getMsgDestination(msg, OuterZoneList, listLock,
				cgEP, cdEP, reason);
		}
		return (cdEP) ? cdEP : endptr(0);
	}

//#endif

public:
  enum enumGatewayFlags {
                e_SCNType		// "trunk" or "residential"
  };

private:

	endptr InternalInsertEP(H225_RasMessage &);
	endptr InternalInsertOZEP(H225_RasMessage &, H225_LocationConfirm &);
	endptr InternalInsertOZEP(H225_RasMessage &, H225_AdmissionConfirm &);

	void InternalPrint(GkStatus::Client &, BOOL, list<EndpointRec *> *, PString &);
	void InternalStatistics(const list<EndpointRec *> *, unsigned & s, unsigned & t, unsigned & g) const;

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
	GkDestAnalysisList & getGkDestAnalysisList() { return *m_destAnalysisList; }

	list<EndpointRec *> EndpointList;
	list<EndpointRec *> OuterZoneList;
	list<EndpointRec *> RemovedList;
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




//typedef PTCPSocket CallSignalSocket;
class CallSignalSocket;

// record of one active call
class CallRec
{
public:
	CallRec(const H225_CallIdentifier &, const H225_ConferenceIdentifier &, const PString &, const PString & srcInfo, int, bool);
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
	const H225_TransportAddress *GetCallingAddress() const
		{ return (m_Calling) ? &m_Calling->GetCallSignalAddress() : 0; }
	const H225_TransportAddress *GetCalledAddress() const
		{ return (m_Called) ? &m_Called->GetCallSignalAddress() : 0; }
	int GetBandWidth() const { return m_bandWidth; }
	int GetNATType(PIPSocket::Address &, PIPSocket::Address &) const;
	const PString GetCallingPartyNumber() const
		{ return (m_Calling && (m_Calling->GetAliases().GetSize() >0)) ? H323GetAliasAddressString((m_Calling->GetAliases())[0]) : PString(); }
	const PString GetCalledPartyNumber() const
		{ return (m_Called && (m_Called->GetAliases().GetSize() >0)) ? H323GetAliasAddressString((m_Called->GetAliases())[0]) : PString(); }

	endptr & GetCallingEP();
	endptr & GetCalledEP();
        CallingProfile & GetCallingProfile();
        CalledProfile & GetCalledProfile();

	void SetCalling(const endptr & NewCalling, unsigned = 0);
	void SetCalled(const endptr & NewCalled, unsigned = 0);
	void SetBandwidth(int Bandwidth) { m_bandWidth = Bandwidth; }
	void SetCallNumber(PINDEX i) { m_CallNumber = i; }
	void SetSocket(CallSignalSocket *, CallSignalSocket *);
	void SetRegistered(bool registered) { m_registered = registered; }

	void SetConnected(bool c);
	void SetTimer(int seconds);
	void StartTimer();
	void StopTimer();

	void Disconnect(bool = false); // Send Release Complete?
	void RemoveAll();
	void RemoveSocket();
	void SendReleaseComplete();

	int CountEndpoints() const;

	bool CompareCallId(const H225_CallIdentifier *CallId) const;
	bool CompareCRV(unsigned crv) const;
	bool CompareCallNumber(PINDEX CallNumber) const;
	bool CompareEndpoint(const endptr *) const;
	bool CompareSigAdr(const H225_TransportAddress *adr) const;

	bool IsUsed() const;
	bool IsConnected() const;
	bool IsTimeout(const PTime *) const;
	bool IsH245Routed() const;
	bool IsRegistered() const;

	PString GenerateCDR();
	PString PrintOn(bool verbose) const;

	void Lock();
	void Unlock();

	// smart pointer for EndpointRec
	typedef SmartPtr<CallRec> Ptr;

private:
	void SendDRQ();
	void InternalSetEP(endptr &, unsigned &, const endptr &, unsigned);

//	PDECLARE_NOTIFIER(PTimer, CallRec, OnTimeout);
	void OnTimeout();

	H225_CallIdentifier m_callIdentifier;
	H225_ConferenceIdentifier m_conferenceIdentifier;
	PString m_destInfo;
	PString m_srcInfo; //added (MM 05.11.01)
	int m_bandWidth;
	PINDEX m_CallNumber;

	endptr m_Calling;
	endptr m_Called;
	unsigned m_callingCRV;
	unsigned m_calledCRV;

        CallingProfile *m_callingProfile;
        CalledProfile  *m_calledProfile;

	PTime *m_startTime, m_timer;
	int m_timeout;

	CallSignalSocket *m_callingSocket, *m_calledSocket;

	int m_usedCount;
	mutable PMutex m_usedLock;
	int m_nattype;

	bool m_h245Routed;
	bool m_registered;

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
	bool GetAdmission(int bw) const { return m_capacity < 0 || m_capacity >= bw; }
	int GetAvailableBW() const { return m_capacity; }

	callptr FindCallRec(const H225_CallIdentifier & CallId) const;
	callptr FindCallRec(const H225_CallReferenceValue & CallRef) const;
	callptr FindCallRec(PINDEX CallNumber) const;
	callptr FindCallRec(const endptr &) const;
	callptr FindBySignalAdr(const H225_TransportAddress & SignalAdr) const;

	void ClearTable();
	void CheckCalls();

	void RemoveCall(const H225_DisengageRequest & obj_drq);
	void RemoveCall(const callptr &);

	void PrintCurrentCalls(GkStatus::Client & client, BOOL verbose=FALSE) const;
	PString PrintStatistics() const;

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

	void InternalStatistics(unsigned & n, unsigned & act, unsigned & nb, PString & msg, BOOL verbose) const;

	list<CallRec *> CallList;
	list<CallRec *> RemovedList;

	bool m_genNBCDR;
	bool m_genUCCDR;

	PINDEX m_CallNumber;
	mutable PReadWriteMutex listLock;

	int m_capacity;

	// statistics
	unsigned m_CallCount;
	unsigned m_successCall;
	unsigned m_neighborCall;

	CallTable(const CallTable &);
	CallTable& operator==(const CallTable &);
};

// inline functions of EndpointRec
inline bool EndpointRec::IsUsed() const
{
	PWaitAndSignal lock(m_usedLock);
	return (m_activeCall > 0 || m_usedCount > 0);
}

inline bool EndpointRec::IsUpdated(const PTime *now) const
{
	 return (!m_timeToLive || m_activeCall > 0 || (*now - m_updatedTime).GetSeconds() < (long)m_timeToLive);
}

inline void EndpointRec::AddCall()
{
	PWaitAndSignal lock(m_usedLock);
	++m_activeCall, ++m_totalCall;
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
inline int CallRec::GetNATType(PIPSocket::Address & calling, PIPSocket::Address & called) const
{
	if (m_nattype & callingParty)
		calling = m_Calling->GetNATIP();
	if (m_nattype & calledParty)
		called = m_Called->GetNATIP();
	return m_nattype;
}

inline void CallRec::SetSocket(CallSignalSocket *calling, CallSignalSocket *called)
{
	m_callingSocket = calling, m_calledSocket = called;
}

inline void CallRec::SetCalling(const endptr & NewCalling, unsigned crv)
{
        InternalSetEP(m_Calling, m_callingCRV, NewCalling, crv);
        if (NewCalling->IsNATed())
                m_nattype |= callingParty, m_h245Routed = true;
}

inline void CallRec::SetCalled(const endptr & NewCalled, unsigned crv)
{
        InternalSetEP(m_Called, m_calledCRV, NewCalled, crv);
        SetRegistered(m_Called && m_Called->IsFromParent());
        if (NewCalled && NewCalled->IsNATed())
                m_nattype |= calledParty, m_h245Routed = true;
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

inline bool CallRec::CompareCallId(const H225_CallIdentifier *CallId) const
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

inline bool CallRec::CompareEndpoint(const endptr *ep) const
{
	return (m_Calling && m_Calling == *ep) || (m_Called && m_Called == *ep);
}

inline bool CallRec::CompareSigAdr(const H225_TransportAddress *adr) const
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

inline bool CallRec::IsTimeout(const PTime *now) const
{
	return (m_timeout > 0 && ((*now - m_timer).GetSeconds() > (long)m_timeout));
}

inline bool CallRec::IsH245Routed() const
{
	return m_h245Routed;
}

inline bool CallRec::IsRegistered() const
{
        return m_registered;
}

#endif
