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
#include "q931.h"
#include "GkStatus.h"

#include <set>
#include <list>
#ifdef P_SOLARIS
#define map stl_map
#endif
#include <map> 

using namespace std;


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


class endpointRec
{
public:
	endpointRec(const H225_TransportAddress &rasAddress,
		    const H225_TransportAddress &callSignalAddress,
		    const H225_EndpointIdentifier &endpointId,
		    const H225_ArrayOf_AliasAddress &terminalAliases,
		    const H225_EndpointType &terminalType,
		    const H225_RasMessage &completeRRQ,
		    bool registered = true);
	~endpointRec();
//	bool operator< (const endpointRec & other) const;
//	void PrintOn( ostream &strm ) const;

	// public interface to access endpointRec
	const H225_TransportAddress &GetRasAddress() const
	{ return m_rasAddress; }
	void SetRasAddress(const H225_TransportAddress &a)
	{ m_rasAddress = a; }
	const H225_TransportAddress &GetCallSignalAddress() const
	{ return m_callSignalAddress; }
	void SetCallSignalAddress(const H225_TransportAddress &a)
	{ m_callSignalAddress = a; }
	const H225_EndpointIdentifier &GetEndpointIdentifier() const
	{ return m_endpointIdentifier; }
	void SetEndpointIdentifier(const H225_EndpointIdentifier &i)
	{ m_endpointIdentifier = i; }
	const H225_ArrayOf_AliasAddress &GetAliases() const
	{ return m_terminalAliases; }
	void SetAliases(const H225_ArrayOf_AliasAddress &a)
	{ m_terminalAliases = a; }
	const H225_EndpointType &GetEndpointType() const
	{ return m_terminalType; }
	void SetEndpointType(const H225_EndpointType &t)
	{ m_terminalType = t; }

	/** If this Endpoint would be register itself again with all the same data
	 * how would this RRQ would look like? May be implemented with a 
	 * built-together-RRQ, but for the moment a stored RRQ.
	 */
	const H225_RasMessage &GetCompleteRegistrationRequest() const
	{ return m_completeRegistrationRequest; }

	bool IsGateway() const
	{ return (bool)m_terminalType.HasOptionalField(H225_EndpointType::e_gateway); }

	bool IsRegistered() const
	{ return m_registered; }
	bool IsUsed() const; //{ return (m_usedCount != 0); }
	PTime GetUpdatedTime() const { return m_updatedTime; }
	void Refresh() { m_updatedTime = PTime(); }

	friend class endptr;

private:
	endpointRec(const endpointRec & other);
	endpointRec & operator= (const endpointRec & other);

	H225_TransportAddress m_rasAddress;
	H225_TransportAddress m_callSignalAddress;
	H225_EndpointIdentifier m_endpointIdentifier;
	H225_ArrayOf_AliasAddress m_terminalAliases;
	H225_EndpointType m_terminalType;

	/**This field may disappear sometime when GetCompleteRegistrationRequest() can 
	 * build its return value itself.
	 * @see GetCompleteRegistrationRequest()
	 */
	H225_RasMessage m_completeRegistrationRequest;

	bool m_registered;
	int m_usedCount;
	mutable PMutex m_usedLock;

	PTime m_updatedTime;
};

// smart pointer of endpointRec
class endptr {
public:
	endptr(endpointRec * = NULL);
	endptr(const endptr &);
	~endptr();
	endptr &operator=(const endptr &);
	operator bool() const { return ep != NULL; }
	endpointRec *operator->() const { return ep; }

	bool operator==(const endptr &e) const { return ep == e.ep; }
	bool operator!=(const endptr &e) const { return ep != e.ep; }

private:
	endpointRec &operator*();
	endpointRec *ep;
};

class RegistrationTable : public Singleton<RegistrationTable>
{
public:
	RegistrationTable();
protected:
	RegistrationTable(const RegistrationTable &);
public:
	void Insert(endpointRec * NewRec);
	void RemoveByEndpointId(const H225_EndpointIdentifier & endpointId);
	endptr FindByEndpointId(const H225_EndpointIdentifier & endpointId) const;
	endptr FindBySignalAdr(const H225_TransportAddress & SignalAdr) const;
	endptr FindByAlias(const H225_AliasAddress & alias) const;
	endptr FindByAnyAliasInList(const H225_ArrayOf_AliasAddress & aliases) const;
	void UpdateAliasBySignalAdr(const H225_TransportAddress &SignalAdr, const H225_ArrayOf_AliasAddress &Aliases);
	H225_ArrayOf_AliasAddress GenerateAlias(const H225_EndpointIdentifier & endpointId) const;
	H225_EndpointIdentifier GenerateEndpointId(void);
	void PrintAllRegistrations(GkStatus::Client &client, BOOL verbose=FALSE);

	void ClearTable();
	void CheckEndpoints(int Seconds);

//	void PrintOn( ostream &strm ) const;


public:
  enum enumGatewayFlags {
                e_SCNType		// "trunk" or "residential"
  };
  
  /** Add prefixes fo one gateway. 
   * @param prefixes is a list split by #PString.Tokenise(" ,;\t\n", FALSE));#
   */	  
  void AddPrefixes(const PString & NewAliasString, const PString & prefixes, const PString & flags);

  /** Add an alias (get gateway config out of ini-File */
  void AddAlias(const PString & NewAliasStr);

  /** Updates Prefix + Flags for all aliases */
  void UpdatePrefixes();

  /** removes the prefixes for a gw with the alias #AliasStr#, or does nothing. */
  void RemovePrefixes(const PString & alias);
  void RemovePrefixes(const H225_AliasAddress & alias);

  /** If alias is a e164 alias, #m_destinationInfo[0]# is matched against
   * the prefixes in the GatewayPrefixes map. 
   * @return the matching gateway or #NULL#.
   */
  endptr FindByPrefix(const H225_AliasAddress & alias);

  const PStringArray *GetGatewayPrefixes(const PString &alias)
	{ return GatewayPrefixes[alias]; }

private:
  /** A map from the aliases of GWs to the prefixes that alias feels responsible 
   * for. The map return #NULL# if there is no such entry for prefixes. 
   # Note: In OnARQ the FindByAlias search is done BEFORE FindByPrefix.
   */
	std::map<PString,PStringArray*> GatewayPrefixes; 

  /** keeps additional per-gateway information (trunk or residential gw, etc.)
   *  allow for multiple flags
   */
	std::map<PString,PStringArray*> GatewayFlags; 

	std::list<endpointRec *> EndpointList;
	std::list<endpointRec *> RemovedList;
	mutable PReadWriteMutex listLock;

	// counter to generate endpoint identifier
	// this is NOT the count of endpoints!
	int recCnt;
	const PString endpointIdSuffix; // Suffix of the generated Endpoint IDs
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

// record of one active call
class CallRec
{
public:
	CallRec();
	CallRec(const CallRec & Other);
	~CallRec();

	CallRec & operator= (const CallRec & other);
	bool operator< (const CallRec & other) const;
	void SetCalling(const EndpointCallRec & NewCalling);
	void SetCalled(const EndpointCallRec & NewCalled);
	void SetBandwidth(int Bandwidth);
	/// deletes endpoint end marks it as invalid
	void RemoveCalling();
	/// deletes endpoint end marks it as invalid
	void RemoveCalled();
	/// remove all involved endpoints and marks then invalid
	void RemoveAll(void);
	/// counts the endpoints in this rec; currently #0 <= n <= 2#.
	int CountEndpoints(void) const;


	H225_ConferenceIdentifier m_conferenceIdentifier;
	H225_CallIdentifier m_callIdentifier;
	H225_BandWidth m_bandWidth;
	time_t m_startTime;
	PINDEX m_CallNumber;

// protected:
	EndpointCallRec * Calling;
	EndpointCallRec * Called;
};

// all active calls
class CallTable : public Singleton<CallTable>
{
public:
	CallTable();

	void Insert(const CallRec & NewRec);
	void Insert(const EndpointCallRec & Calling, const EndpointCallRec & Called, int Bandwidth, H225_CallIdentifier CallId, H225_ConferenceIdentifier ConfID);
	void Insert(const EndpointCallRec & Calling, int Bandwidth, H225_CallIdentifier CallId, H225_ConferenceIdentifier ConfID);
	void RemoveEndpoint(const H225_CallReferenceValue & CallRef);

	const CallRec * FindCallRec(const Q931 & m_q931) const;
	const CallRec * FindCallRec(const H225_CallIdentifier & m_callIdentifier) const;
	const CallRec * FindCallRec(const H225_CallReferenceValue & CallRef) const;
	const CallRec * FindCallRec(PINDEX CallNumber) const;
	const CallRec * FindBySignalAdr(const H225_TransportAddress & SignalAdr) const;
	void PrintCurrentCalls(GkStatus::Client &client, BOOL verbose=FALSE) const;

protected:
	std::set <CallRec> CallList;
	PINDEX m_CallNumber;

private:
	CallTable(const CallTable &);
	CallTable& operator==(const CallTable &);
};

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

#ifndef __GNUC__
// Oops! Composition adaptor is not part of C++ standard
template <class _Operation1, class _Operation2>
class unary_compose
  : public unary_function<typename _Operation2::argument_type,
                          typename _Operation1::result_type> 
{
protected:
  _Operation1 __op1;
  _Operation2 __op2;
public:
  unary_compose(const _Operation1& __x, const _Operation2& __y) 
    : __op1(__x), __op2(__y) {}
  typename _Operation1::result_type
  operator()(const typename _Operation2::argument_type& __x) const {
    return __op1(__op2(__x));
  }
};

template <class _Operation1, class _Operation2>
inline unary_compose<_Operation1,_Operation2> 
compose1(const _Operation1& __op1, const _Operation2& __op2)
{
  return unary_compose<_Operation1,_Operation2>(__op1, __op2);
}
#endif

#ifdef WIN32
// VC++ didn't define these
template <class _Ret, class _Tp>
class const_mem_fun_t : public unary_function<const _Tp*,_Ret> {
public:
  explicit const_mem_fun_t(_Ret (_Tp::*__pf)() const) : _M_f(__pf) {}
  _Ret operator()(const _Tp* __p) const { return (__p->*_M_f)(); }
private:
  _Ret (_Tp::*_M_f)() const;
};

template <class _Ret, class _Tp>
class const_mem_fun_ref_t : public unary_function<_Tp,_Ret> {
public:
  explicit const_mem_fun_ref_t(_Ret (_Tp::*__pf)() const) : _M_f(__pf) {}
  _Ret operator()(const _Tp& __r) const { return (__r.*_M_f)(); }
private:
  _Ret (_Tp::*_M_f)() const;
};

template <class _Ret, class _Tp>
inline const_mem_fun_t<_Ret,_Tp> mem_fun(_Ret (_Tp::*__f)() const)
  { return const_mem_fun_t<_Ret,_Tp>(__f); }

template <class _Ret, class _Tp>
inline const_mem_fun_ref_t<_Ret,_Tp> mem_fun_ref(_Ret (_Tp::*__f)() const)
  { return const_mem_fun_ref_t<_Ret,_Tp>(__f); }

#endif

#endif

