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
#include <map> 

using namespace std;


// this data structure is obsolete !
// all information about ongoing calls is in CallTable
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
class resourceManager
{
public:
	static resourceManager * Instance(void);
protected:
	resourceManager();
	resourceManager(const resourceManager &);
public:
	void SetBandWidth(int bw);
	void Insert(const conferenceRec & NewRec);
	unsigned int GetConferenceCount(void) const;
	unsigned int GetAvailableBW(void) const;
	BOOL GetAdmission(const H225_EndpointIdentifier & src, const H225_ConferenceIdentifier & cid, const H225_BandWidth & bw);
	BOOL CloseConference(const H225_EndpointIdentifier & src, const H225_ConferenceIdentifier & cid);
	void AddConference(const conferenceRec & Conf);

protected:
	H225_BandWidth m_capacity;
	set<conferenceRec> ConferenceList;

	static resourceManager * m_instance;
	static PMutex m_CreationLock;		// lock to protect singleton creation
};


class endpointRec
{
public:
	endpointRec( H225_TransportAddress rasAddress, H225_TransportAddress callSignalAddress, H225_EndpointIdentifier endpointId, H225_ArrayOf_AliasAddress terminalAliases, H225_EndpointType terminalType, const H225_RasMessage completeRRQ);
	endpointRec(const endpointRec & other);
	~endpointRec() { };
	endpointRec & operator= (const endpointRec & other);
	bool operator< (const endpointRec & other) const;
//	void PrintOn( ostream &strm );

	/** If this Endpoint would be register itself again with all the same data
	 * how would this RRQ would look like? May be implemented with a 
	 * built-together-RRQ, but for the moment a stored RRQ.
	 */
	H225_RasMessage GetCompleteRegistrationRequest() const
		{ return m_completeRegistrationRequest; }
	

//protected:
	H225_TransportAddress m_rasAddress;
	H225_TransportAddress m_callSignalAddress;
	H225_ArrayOf_AliasAddress m_terminalAliases;
	H225_EndpointIdentifier m_endpointIdentifier;
    H225_EndpointType m_terminalType;

 protected:
	/**This field may disappear sometime when GetCompleteRegistrationRequest() can 
	 * build its return value itself.
	 * @see GetCompleteRegistrationRequest()
	 */
	H225_RasMessage m_completeRegistrationRequest; // towi-00/02/04
};


class RegistrationTable
{
public:
	// singleton
	static RegistrationTable* Instance(void);
protected:
	RegistrationTable();
	RegistrationTable(const RegistrationTable &);
public:
	void Insert(const endpointRec & NewRec);
	void RemoveByEndpointId(const H225_EndpointIdentifier & endpointId);
	const endpointRec * FindByEndpointId(const H225_EndpointIdentifier & endpointId) const;
	const endpointRec * FindBySignalAdr(H225_TransportAddress SignalAdr) const;
	const endpointRec * FindByAlias(H225_AliasAddress alias) const;
	const endpointRec * FindByAnyAliasInList(H225_ArrayOf_AliasAddress aliases) const;
	void UpdateAliasBySignalAdr(H225_TransportAddress SignalAdr, H225_ArrayOf_AliasAddress Aliases);
	H225_ArrayOf_AliasAddress GenerateAlias(const H225_EndpointIdentifier & endpointId) const;
	H225_EndpointIdentifier GenerateEndpointId(void);
	void PrintAllRegistrations(GkStatus::Client &client, BOOL verbose=FALSE) const; //towi

//	void PrintOn( ostream &strm );

	set<endpointRec> EndpointList;
	

public:
  /** A map from the aliases of GWs to the prefixes that alias feels responsible 
   * for. The map return #NULL# if there is no such entry for prefixes. 
   # Note: In OnARQ the FindByAlias search is done BERFORE FindByPrefix.
   */
  std::map<PString,PStringArray*> GatewayPrefixes; 

  /** Add prefixes fo one gateway. 
   * @param prefixes is a list split by #PString.Tokenise(" ,;\t\n", FALSE));#
   */	  
  void AddPrefixes(const PString & NewAliasString, const PString & prefixes);

  /** removes the prefixes for a gw with the alias #AliasStr#, or does nothing. */
  void RemovePrefixes(const H225_AliasAddress & alias);

  /** If alias is a e164 alias, #m_destinationInfo[0]# is matched against
   * the prefixes in the GatewayPrefixes map. 
   * @return the matching gateway or #NULL#.
   */
  const endpointRec * FindByPrefix(const H225_AliasAddress & alias) const;


protected:
	// counter to generate endpoint identifier
	// this is NOT the count of endpoints!
	int recCnt;
	const PString endpointIdSuffix; // Suffix of the generated Endpoint IDs
	static RegistrationTable * m_instance;
	static PMutex m_CreationLock;		// lock to protect singleton creation
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
// protected:
	EndpointCallRec * Calling;
	EndpointCallRec * Called;
};

// all active calls
class CallTable
{
public:
	static CallTable * Instance(void);
protected:
	CallTable();
	CallTable(const CallTable &);

public:
	void Insert(const CallRec & NewRec);
	void Insert(const EndpointCallRec & Calling, const EndpointCallRec & Called, int Bandwidth, H225_CallIdentifier CallId, H225_ConferenceIdentifier ConfID);
	void Insert(const EndpointCallRec & Calling, int Bandwidth, H225_CallIdentifier CallId, H225_ConferenceIdentifier ConfID);
	void RemoveEndpoint(const H225_CallReferenceValue & CallRef);
	const CallRec * FindCallRec(const H225_CallReferenceValue & CallRef) const;
	const CallRec * FindBySignalAdr(const H225_TransportAddress & SignalAdr) const;
	void PrintCurrentCalls(GkStatus::Client &client, BOOL verbose=FALSE) const; //towi000106: +verbose

protected:
	std::set <CallRec> CallList;
	static CallTable * m_instance;
	static PMutex m_CreationLock;		// lock to protect singleton creation
};

#endif
