//////////////////////////////////////////////////////////////////
//
// bookkeeping for RAS-Server in H.323 gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
//  990500	initial version (Xiang Ping Chen, Rajat Todi, Joe Metzger)
//  990600	ported to OpenH323 V. 1.08 (Jan Willamowius)
//  991003	switched to STL (Jan Willamowius)
//  000215	call removed from table when <=1 ep remains; marked with "towi*1" (towi)
//
//////////////////////////////////////////////////////////////////


#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4800 ) // one performance warning off
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#define snprintf	_snprintf
#endif

#include <time.h>
#include <ptlib.h>
#include "h323pdu.h"
#include "ANSI.h"
#include "h323util.h"
#include "Toolkit.h"
#include "SoftPBX.h"
#include "RasTbl.h"
#include <functional>


conferenceRec::conferenceRec(const H225_EndpointIdentifier & src, const H225_ConferenceIdentifier & cid, const H225_BandWidth & bw)
{
    m_src = src;
    m_cid = cid;
    m_bw = bw;
}

bool conferenceRec::operator< (const conferenceRec & other) const
{
	return (this->m_cid < other.m_cid);
};

resourceManager::resourceManager()
{
	m_capacity = 0;
};


void resourceManager::SetBandWidth(int bw)
{
	m_capacity = bw;
	cout << endl << "Available BandWidth " << m_capacity  << endl;
}


unsigned int resourceManager::GetAvailableBW(void) const
{
	unsigned int RemainingBW = m_capacity.GetValue();
	set<conferenceRec>::const_iterator Iter;

	for (Iter = ConferenceList.begin(); Iter != ConferenceList.end(); ++Iter)
	{
		if( RemainingBW >= (*Iter).m_bw.GetValue() )
			RemainingBW = RemainingBW - (*Iter).m_bw.GetValue();
		else {
			// we have already granted more bandwidth than we have capacity
			// this sould not happen
			// BUG: it happens now, because we count bandwidth twice, if both endpoints are registered with us
			RemainingBW = 0;
			return RemainingBW;
		}
	};
	return RemainingBW;
}

   
BOOL resourceManager::GetAdmission(const H225_EndpointIdentifier & src, const H225_ConferenceIdentifier & cid, const H225_BandWidth & bw)
{
    if( bw.GetValue() > GetAvailableBW() )
		return FALSE;
      
    conferenceRec cRec( src, cid, bw );
	ConferenceList.insert(cRec);
    PTRACE(2, "GK\tTotal sessions : " << ConferenceList.size() << "\tAvailable BandWidth " << GetAvailableBW());
    return TRUE;
}

 
BOOL resourceManager::CloseConference(const H225_EndpointIdentifier & src, const H225_ConferenceIdentifier & cid)
{
	set<conferenceRec>::iterator Iter;

	for (Iter = ConferenceList.begin(); Iter != ConferenceList.end(); ++Iter)
	{  
		if( ((*Iter).m_src == src) && ((*Iter).m_cid == cid) )
		{
			ConferenceList.erase(Iter);
    		PTRACE(2, "GK\tTotal sessions : " << ConferenceList.size() << "\tAvailable BandWidth " << GetAvailableBW());
			return TRUE;
		}
	}
	return FALSE;
}


//void endpointRec::PrintOn( ostream &strm ) const
//{
//    strm << "{";
//    strm << endl << " callSignalAddress ";
//    m_callSignalAddress.PrintOn( strm );
//    strm << endl << " terminalAlias ";
//    m_terminalAliases.PrintOn( strm );
//    strm << endl << " endpointIdentifier ";
//    m_endpointIdentifier.PrintOn( strm );
//    strm << "}" << endl;
//}


endpointRec::endpointRec(const H225_TransportAddress &rasAddress,
			 const H225_TransportAddress &callSignalAddress, 
			 const H225_EndpointIdentifier &endpointId, 
			 const H225_ArrayOf_AliasAddress &terminalAliases, 
			 const H225_EndpointType &terminalType, 
			 const H225_RasMessage &completeRRQ,
			 bool registered)
      : m_rasAddress(rasAddress),
	m_callSignalAddress(callSignalAddress),
	m_endpointIdentifier(endpointId),
	m_terminalAliases(terminalAliases),
	m_terminalType(terminalType),
	m_completeRegistrationRequest(completeRRQ),
	m_registered(registered),
	m_usedCount(0)
{
}	

endpointRec::~endpointRec()
{
}

bool endpointRec::IsUsed() const
{
	PWaitAndSignal lock(m_usedLock);
	return (m_usedCount != 0);
}

/*
endpointRec::endpointRec(const endpointRec & other)
{
	m_rasAddress = other.m_rasAddress;
    m_callSignalAddress = other.m_callSignalAddress;
    m_terminalAliases = other.m_terminalAliases;
    m_endpointIdentifier = other.m_endpointIdentifier;
    m_terminalType = other.m_terminalType;
	m_completeRegistrationRequest = other.GetCompleteRegistrationRequest();
}


endpointRec & endpointRec::operator= (const endpointRec & other)
{
	m_rasAddress = other.m_rasAddress;
    m_callSignalAddress = other.m_callSignalAddress;
    m_terminalAliases = other.m_terminalAliases;
    m_endpointIdentifier = other.m_endpointIdentifier;
    m_terminalType = other.m_terminalType;
	m_completeRegistrationRequest = other.GetCompleteRegistrationRequest();
    
    return *this;
}


bool endpointRec::operator< (const endpointRec & other) const
{
	return (this->m_endpointIdentifier < other.m_endpointIdentifier);
}
*/

endptr::endptr(endpointRec *e) : ep(e)
{
	if (ep) {
		PWaitAndSignal lock(ep->m_usedLock);
		ep->m_usedCount++;
	}
}

endptr::endptr(const endptr &e) : ep(e.ep)
{
	if (ep) {
		PWaitAndSignal lock(ep->m_usedLock);
		ep->m_usedCount++;
	}
}

endptr::~endptr()
{
	if (ep) {
		PWaitAndSignal lock(ep->m_usedLock);
		ep->m_usedCount--;
	}
}

endptr &endptr::operator=(const endptr &e)
{
	if (ep != e.ep) {
		if (ep) {
			PWaitAndSignal lock(ep->m_usedLock);
			ep->m_usedCount--;
		}
		if ((ep = e.ep) != NULL) {
			PWaitAndSignal lock(ep->m_usedLock);
			ep->m_usedCount++;
		}
	}
	return *this;
}

RegistrationTable::RegistrationTable()
	: GatewayPrefixes(),  // TODO: how to define a default in the map for not-found elements?
	  GatewayFlags(),
	  endpointIdSuffix(GkConfig()->GetString("EndpointIDSuffix", "_endp"))
{
	recCnt = rand()%9000+1000;
}

void RegistrationTable::Insert(endpointRec * NewRec)
{
	WriteLock lock(listLock);
	EndpointList.push_back(NewRec);
}

void RegistrationTable::RemoveByEndpointId(const H225_EndpointIdentifier & epId)
{
	WriteLock lock(listLock);
	list<endpointRec *>::iterator Iter =
	find_if(EndpointList.begin(), EndpointList.end(),
	  compose1(bind2nd(equal_to<H225_EndpointIdentifier>(), epId),
		   mem_fun(&endpointRec::GetEndpointIdentifier)));
	if (Iter != EndpointList.end()) {
		RemovedList.push_back(*Iter);
		EndpointList.erase(Iter);	// list<> is O(1), slist<> O(n) here
	} else {
	        PTRACE(1, "Warning: RemoveByEndpointId " << epId << " failed.");
	}
}

endptr RegistrationTable::FindByEndpointId(const H225_EndpointIdentifier & epId) const
{
	ReadLock lock(listLock);
	list<endpointRec *>::const_iterator Iter =
	find_if(EndpointList.begin(), EndpointList.end(),
	  compose1(bind2nd(equal_to<H225_EndpointIdentifier>(), epId),
		   mem_fun(&endpointRec::GetEndpointIdentifier)));
	return endptr((Iter != EndpointList.end()) ? *Iter : NULL);
}

endptr RegistrationTable::FindBySignalAdr(const H225_TransportAddress &sigAd) const
{
	ReadLock lock(listLock);
	typedef equal_to<H225_TransportAddress> equal_ad;
	list<endpointRec *>::const_iterator Iter =
	find_if(EndpointList.begin(), EndpointList.end(),
       	  compose1(bind2nd(equal_to<H225_TransportAddress>(), sigAd),
		   mem_fun(&endpointRec::GetCallSignalAddress)));
	return endptr((Iter != EndpointList.end()) ? *Iter : NULL);
}

bool GWAliasEqual(H225_AliasAddress GWAlias, H225_AliasAddress OtherAlias)
{
	if(!GWAlias.IsValid()) return FALSE;
	if(!OtherAlias.IsValid()) return FALSE;
	PString GWAliasStr = H323GetAliasAddressString(GWAlias);
	PString OtherAliasStr = H323GetAliasAddressString(OtherAlias);

	if (GWAlias.GetTag() == H225_AliasAddress::e_dialedDigits)
	{
		// for E.164 aliases we only compare the prefix the gateway registered
		// and assume they provide acces to the whole address space
		return (strncmp(GWAliasStr, OtherAliasStr, strlen(GWAliasStr)) == 0);
	}
	else {
	  return (GWAlias == OtherAlias);		
	}
};


void RegistrationTable::AddPrefixes(const PString & NewAliasStr, const PString &prefixes, const PString &flags)
{
	// create new
	PStringArray *prefixArr = new PStringArray(prefixes.Tokenise(" ,;\t\n", FALSE));
	GatewayPrefixes[NewAliasStr] = prefixArr;

	// allow for multiple flags
	PStringArray *flagsArr = new PStringArray(flags.Tokenise(" ,;\t\n", FALSE));
	GatewayFlags[NewAliasStr] = flagsArr;
}


void RegistrationTable::AddAlias(const PString & NewAliasStr)
{
	PString gatewayline = GkConfig()->GetString("RasSvr::GWPrefixes", NewAliasStr, "");
	PString flags = "";

	RemovePrefixes(NewAliasStr);

	const PStringArray gateway = gatewayline.Tokenise(":", FALSE);
	// gateway[0] = prefix, gateway[1] = flags
	if (!gatewayline) {
		if (gateway.GetSize() == 2)
			flags = gateway[1];
		AddPrefixes(NewAliasStr, gateway[0], flags);

		PTRACE(2, ANSI::DBG << "Gateway prefixes for '" << NewAliasStr << "' are now '" << gateway[0] << "'" << ANSI::OFF);
		PTRACE(2, ANSI::DBG << "Gateway flags for '" << NewAliasStr << "' are now '" << flags << "'" << ANSI::OFF);
	}
}


void RegistrationTable::UpdatePrefixes()
{
	list<endpointRec *>::const_iterator Iter;
	ReadLock lock(listLock);
	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		if ((*Iter)->IsGateway()) {
			PINDEX s = (*Iter)->GetAliases().GetSize();
		// gibt uns das den gewuenschten Alias-Namen ?
			for (PINDEX i = 0; i < s; i++) {
				PString Alias = AsString((*Iter)->GetAliases()[i], FALSE);
			        PTRACE(5, "Updating Alias " << i << ": " << Alias);
				AddAlias(Alias);
			}
		}
	}
        // all new gateways need to register themselves
}

void RegistrationTable::RemovePrefixes(const PString & AliasStr)
{
	// delete old if existing
	PStringArray *prefixArr = GatewayPrefixes[AliasStr];
	if (prefixArr != NULL) {
		delete prefixArr;
		GatewayPrefixes[AliasStr] = NULL;
	}
	PStringArray *flagsArr = GatewayFlags[AliasStr];
	if (flagsArr != NULL) {
		delete flagsArr;
		GatewayFlags[AliasStr] = NULL;
	}
}

void RegistrationTable::RemovePrefixes(const H225_AliasAddress & alias)
{
	if (alias.GetTag() != H225_AliasAddress::e_dialedDigits) 
		return;
	
	RemovePrefixes(H323GetAliasAddressString(alias));
}



endptr RegistrationTable::FindByAlias(const H225_AliasAddress &alias) const
{
	list<endpointRec *>::const_iterator EPIter;

	ReadLock lock(listLock);
	// loop over endpoints
	for (EPIter = EndpointList.begin(); EPIter != EndpointList.end(); ++EPIter)
	{
		PINDEX s = (*EPIter)->GetAliases().GetSize();
		// loop over alias list
		for(PINDEX AliasIndex = 0; AliasIndex < s; ++AliasIndex)
		{
			if ((*EPIter)->IsGateway()) {
				// for gateways we use a different comparison function,
				// since they provide access to a lot of numbers
				if (GWAliasEqual((*EPIter)->GetAliases()[AliasIndex], alias))
					return endptr(*EPIter);
			} else {
				if ((*EPIter)->GetAliases()[AliasIndex] == alias)
					return endptr(*EPIter);
			}
		}
	}
	return endptr(NULL);
}


endptr RegistrationTable::FindByAnyAliasInList(const H225_ArrayOf_AliasAddress &aliases) const
{
	list<endpointRec *>::const_iterator EPIter;

	PINDEX as = aliases.GetSize();
	if (as == 0)
		return endptr(NULL);

	ReadLock lock(listLock);
	// loop over endpoints
	for (EPIter = EndpointList.begin(); EPIter != EndpointList.end(); ++EPIter)
	{
		PINDEX s = (*EPIter)->GetAliases().GetSize();
		// loop over alias list
		for(PINDEX AliasIndex = 0; AliasIndex < s; ++AliasIndex)
		{
			for (PINDEX FindAliasIndex = 0; FindAliasIndex < as; ++ FindAliasIndex)
			{
				if ((*EPIter)->IsGateway()) {
				// for gateways we use a different comparison function,
				// since they provide access to a lot of numbers
					if (GWAliasEqual((*EPIter)->GetAliases()[AliasIndex], aliases[FindAliasIndex]))
						return endptr(*EPIter);
				} else {
					if ((*EPIter)->GetAliases()[AliasIndex] == aliases[FindAliasIndex])
						return endptr(*EPIter);
				}
			}
		}
	}
	return endptr(NULL);
}


endptr RegistrationTable::FindByPrefix(const H225_AliasAddress & alias)
{
	list<endpointRec *>::iterator EPIter;
  
	if (alias.GetTag() != H225_AliasAddress::e_dialedDigits)
		return endptr(NULL);

	// Here is a bug. We find the first prefix, but no the longest one, so we have to fix it.

	list<endpointRec *>::iterator EPmax;
	PINDEX maxprefix=0;

	// note that found prefix has equal length to an other.
	// if so, the found endpoint is moves to the end, so we get a round-robin.
	bool maxprefixIsConcurrent = false;

	PString aliasStr = H323GetAliasAddressString(alias);

	// Hmmm... a big lock here! anyone has better solution?
	WriteLock lock(listLock);
	// loop over endpoints
	for (EPIter = EndpointList.begin(); EPIter != EndpointList.end(); ++EPIter)
	{
		endpointRec *ep = *EPIter;
		PINDEX s = ep->GetAliases().GetSize();
		// loop over alias list
		for(PINDEX AliasIndex = 0; AliasIndex < s; ++AliasIndex)
		{
			if ((*EPIter)->IsGateway()) {
				const PString GWAliasStr = H323GetAliasAddressString(ep->GetAliases()[AliasIndex]);

				const PStringArray *prefixes = GatewayPrefixes[GWAliasStr];
				if (prefixes) {
					// try all prefixes
					int max = prefixes->GetSize();
					for (int i=0; i < max; i++) {
						const PString &prefix = (*prefixes)[i];
						if (aliasStr.Find(prefix) == 0) {	// TODO: lack of 'aliasStr.StartsWith(prefix)'
							// found at position 0 => is a prefix
							PINDEX prefixLength = prefix.GetLength();
							if(prefixLength > maxprefix)
							{
								PTRACE(2, ANSI::DBG << "Gateway '" << GWAliasStr << "' prefix '"<<prefix
									<< "' matched for '" << aliasStr << "'" << ANSI::OFF);
								if (maxprefix)
									PTRACE(2, ANSI::DBG << "Prefix '" << prefix
										<< "' is longer than other" << ANSI::OFF);
								maxprefix = prefix.GetLength();
								EPmax = EPIter;
								maxprefixIsConcurrent = false;
							}
							else if (prefixLength == maxprefix) {
								maxprefixIsConcurrent = true;
							}
						}
					}
					// no prefix matched
				}
			}
		}
	}
	// no gw matched with one of its prefixes

	// if prefix is not found
	if (maxprefix == 0)
		return endptr(NULL);

	endpointRec *ep = *EPmax;
	// round-robin
	if(maxprefixIsConcurrent) {
		PTRACE(3, ANSI::DBG << "Prefix apply round robin" << ANSI::OFF);
		EndpointList.erase(EPmax);
		EndpointList.push_back(ep);
	}

	return endptr(ep);
}


void RegistrationTable::UpdateAliasBySignalAdr(const H225_TransportAddress &SignalAdr, const H225_ArrayOf_AliasAddress &Aliases)
{
	FindBySignalAdr(SignalAdr)->SetAliases(Aliases);
}

H225_EndpointIdentifier RegistrationTable::GenerateEndpointId(void)
{
	H225_EndpointIdentifier NewEndpointId;
	NewEndpointId = PString(PString::Unsigned, ++recCnt) + endpointIdSuffix;
	return NewEndpointId;
}


H225_ArrayOf_AliasAddress RegistrationTable::GenerateAlias(const H225_EndpointIdentifier & endpointId) const
{
	H225_AliasAddress NewAlias;
	NewAlias.SetTag( H225_AliasAddress::e_h323_ID); 
	H323SetAliasAddress(endpointId, NewAlias);

	H225_ArrayOf_AliasAddress AliasList;
	AliasList.SetSize(1);
	AliasList[0] = NewAlias;

	return AliasList;
}

void RegistrationTable::PrintAllRegistrations(GkStatus::Client &client, BOOL verbose)
{
	list<endpointRec *>::const_iterator Iter;

	client.WriteString("AllRegistrations\r\n");
	ReadLock lock(listLock);
	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		const H225_TransportAddress_ipAddress & ipAddress = (*Iter)->GetRasAddress();
		PString msg(PString::Printf, "RCF|%d.%d.%d.%d|%s|%s|%s\r\n",
			    ipAddress.m_ip[0], ipAddress.m_ip[1], ipAddress.m_ip[2], ipAddress.m_ip[3],
			    (const unsigned char *) AsString((*Iter)->GetAliases()),
			    (const unsigned char *) AsString((*Iter)->GetEndpointType()),
			    (const unsigned char *) (*Iter)->GetEndpointIdentifier().GetValue() );
		PTRACE(2,msg);
		client.WriteString(msg);
		
		if (verbose)
		{
			client.WriteString((*Iter)->GetUpdatedTime().AsString() + "\r\n");
			for (PINDEX i = 0; i < (*Iter)->GetAliases().GetSize(); i++)
			{
				const PString & alias = AsString((*Iter)->GetAliases()[i], FALSE);
				PString s = "# " + alias;

				// write prefixes of this alias
				s += "|Px(";
				const PStringArray *prefixes = GatewayPrefixes[alias];
				if (prefixes != NULL) {
					if (prefixes->GetSize() > 0) 
						s += (*prefixes)[0];
					for (PINDEX i = 1; i < prefixes->GetSize(); i++) {
						s += "," + (*prefixes)[i];
					}
				}

				client.WriteString(s + ")\r\n");
			}
		}
		
	}
	
	client.WriteString(";\r\n");
}

namespace { 

inline endpointRec *unregister_endpoint(endpointRec *ep)
{
	SoftPBX::UnregisterEndpoint(endptr(ep));
	return ep;
}

inline endpointRec *unregister_expired_endpoint(endpointRec *ep)
{
	SoftPBX::UnregisterEndpoint(endptr(ep), H225_UnregRequestReason::e_ttlExpired);
	return ep;
}

// stupid VC can't instantiate the template?
// template <class T1, class T2> inline void delete_second(pair<T1, T2> &p)
inline void delete_second(pair<const PString, PStringArray *> &p)
{
	delete p.second;
}

// Oops... the standard STL minus object is too restricted
template <class _Tp, class R>
struct Minus : public binary_function<_Tp,_Tp, R> {
  R operator()(const _Tp& __x, const _Tp& __y) const { return __x - __y; }
};

}

void RegistrationTable::ClearTable()
{
	WriteLock lock(listLock);
	// Unregister all endpoints, and move the records into RemovedList
	transform(EndpointList.begin(), EndpointList.end(),
		back_inserter(RemovedList), unregister_endpoint);
	EndpointList.clear();	
	for_each(GatewayPrefixes.begin(), GatewayPrefixes.end(), delete_second);
	GatewayPrefixes.clear();
	for_each(GatewayFlags.begin(), GatewayFlags.end(), delete_second);
	GatewayFlags.clear();
}

void RegistrationTable::CheckEndpoints(int Seconds)
{
	WriteLock lock(listLock);

	// by cwhuang
	//
	// Wow...! Too complex to understand? Thanks to powerful STL!
	// Here is a brief explanation:
	// EndpointList is divided into two parts by STL partition algorithm:
	// the first part from begin() to --Iter that satisfy the predicate
	// and the second part from Iter to end() that don't.
	// The predicate is composed by several STL adapters.
	// It means: ( (PTime() - ep->GetUpdatedTime()) < Seconds*1000 )

	if (Seconds > 0) {
		list<endpointRec *>::iterator Iter =
		  partition(EndpointList.begin(), EndpointList.end(),
			compose1(bind2nd(less<PTimeInterval>(), Seconds*1000),
			compose1(bind1st(Minus<PTime, PTimeInterval>(), PTime()), mem_fun(&endpointRec::GetUpdatedTime))));
		PTRACE(2, distance(Iter, EndpointList.end()) << " endpoint(s) expired.");
		transform(Iter, EndpointList.end(), back_inserter(RemovedList),
			unregister_expired_endpoint);
		EndpointList.erase(Iter, EndpointList.end());
	// TODO: remove prefixes of expired endpoints
	}

	// Cleanup unused endpointRec in RemovedList
	list<endpointRec *>::iterator Iter =
	  partition(RemovedList.begin(), RemovedList.end(),
		mem_fun(&endpointRec::IsUsed));
	RemovedList.erase(Iter, RemovedList.end());
}

//void RegistrationTable::PrintOn(ostream & strm) const
//{
//	list<endpointRec>::const_iterator Iter;
//
//	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
//	{
//      	(*Iter).PrintOn( strm );
//	};
//}


EndpointCallRec::EndpointCallRec(H225_TransportAddress callSignalAddress, H225_TransportAddress rasAddress, H225_CallReferenceValue callReference)
  : m_callSignalAddress(callSignalAddress),
	m_rasAddress(rasAddress),
	m_callReference(callReference)
{
}

bool EndpointCallRec::operator< (const EndpointCallRec & other) const
{
	return this->m_callSignalAddress <  other.m_callSignalAddress;
}

CallRec::CallRec()
	: m_startTime(time(NULL)),
	  Calling(NULL),
	  Called(NULL)
{
	m_conferenceIdentifier = "";
	m_callIdentifier.m_guid = "";
	m_CallNumber = 0;
}


CallRec::CallRec(const CallRec & Other)

{
	m_conferenceIdentifier = Other.m_conferenceIdentifier;
	m_callIdentifier = Other.m_callIdentifier;
	m_bandWidth = Other.m_bandWidth;
	m_startTime = Other.m_startTime;
	m_CallNumber = Other.m_CallNumber;

	// copy EndpointCallrec
	if (Other.Calling == NULL)
		Calling = NULL;
	else
		Calling = new EndpointCallRec(*Other.Calling);

	if (Other.Called == NULL)
		Called = NULL;
	else
		Called = new EndpointCallRec(*Other.Called);
};


CallRec::~CallRec()
{
	// C++ guarantees deleting null pointer is safe
	delete Calling;
	delete Called;
}

CallRec & CallRec::operator=(const CallRec & Other)

{
	if (this == &Other)
		return *this;

	m_conferenceIdentifier = Other.m_conferenceIdentifier;
	m_callIdentifier = Other.m_callIdentifier;
	m_bandWidth = Other.m_bandWidth;
	m_startTime = Other.m_startTime;
	m_CallNumber = Other.m_CallNumber;

	Calling = NULL;
	Called = NULL;

	// copy EndpointCallRec
	if (Other.Calling)
		Calling = new EndpointCallRec(*Other.Calling);
	if (Other.Called)
		Called = new EndpointCallRec(*Other.Called);

	return *this;
};



bool CallRec::operator< (const CallRec & other) const
{
	return this->m_callIdentifier < other.m_callIdentifier;
};

void CallRec::SetCalling(const EndpointCallRec & NewCalling)
{
	delete Calling;
	Calling = new EndpointCallRec(NewCalling);
};

void CallRec::SetCalled(const EndpointCallRec & NewCalled)
{
	delete Called;
	Called = new EndpointCallRec(NewCalled);
};

void CallRec::SetBandwidth(int Bandwidth)
{
	m_bandWidth.SetValue(Bandwidth);
};

void CallRec::RemoveCalling(void)
{
	delete Calling;
	Calling = NULL;
};

void CallRec::RemoveCalled(void)
{
	delete Called;
	Called = NULL;
};

void CallRec::RemoveAll(void)
{
	RemoveCalled();
	RemoveCalling();
};

int CallRec::CountEndpoints(void) const
{
	int result = 0;
	if(Called != NULL) result++;
	if(Calling != NULL) result++;
	return result;
};


CallTable::CallTable()
{
	m_CallNumber = 1;
}

void CallTable::Insert(const CallRec & NewRec)
{
	PTRACE(3, "CallTable::Insert(CALL)");
	CallList.insert(NewRec);
}

void CallTable::Insert(const EndpointCallRec & Calling, const EndpointCallRec & Called, int Bandwidth, H225_CallIdentifier CallId, H225_ConferenceIdentifier ConfId)
{
	CallRec Call;

	PTRACE(3, "CallTable::Insert(EP,EP) Call No. " << m_CallNumber);
	
	Call.SetCalling(Calling);
	Call.SetCalled(Called);
	Call.SetBandwidth(Bandwidth);
	Call.m_callIdentifier = CallId;
	Call.m_conferenceIdentifier = ConfId;
	Call.m_CallNumber = m_CallNumber++;
	Insert(Call);
}

void CallTable::Insert(const EndpointCallRec & Calling, int Bandwidth, H225_CallIdentifier CallId, H225_ConferenceIdentifier ConfId)
{
	CallRec Call;

	PTRACE(3, "CallTable::Insert(EP)");
	
	Call.SetCalling(Calling);
	Call.SetBandwidth(Bandwidth);
	Call.m_callIdentifier = CallId;
	Call.m_conferenceIdentifier = ConfId;
	Call.m_CallNumber = m_CallNumber++;
	Insert(Call);
}

void CallTable::RemoveEndpoint(const H225_CallReferenceValue & CallRef)
{
	static PMutex mutex;
	GkProtectBlock _using(mutex); // Auto protect the whole method!
	BOOL hasRemoved = FALSE;
	time_t startTime;

// dirty hack, I hate it...:p
	CallRec theCall;
	set<CallRec>::iterator CallIter;
	char callRefString[10];
	sprintf(callRefString, "%u", (unsigned)CallRef.GetValue());

#ifndef NDEBUG
	GkStatus::Instance()->SignalStatus("DEBUG\tremoving callRef:" + PString(callRefString) + "...\n\r", 1);
	PTRACE(5, ANSI::PIN << "DEBUG\tremoving CallRef:" << CallRef << "...\n" << ANSI::OFF);
#endif

	// look at all calls
	CallIter = CallList.begin();
	while(CallIter != CallList.end())
	{
		// look at each endpoint in this call if it has this call reference
		if (((*CallIter).Calling != NULL) &&
			((*CallIter).Calling->m_callReference.GetValue() == CallRef.GetValue()))
		{
			CallRec rec = theCall = *CallIter;
			CallList.erase(CallIter);
			rec.RemoveCalling();
			CallList.insert(rec);
			CallIter = CallList.begin();
			hasRemoved = TRUE;
			startTime = rec.m_startTime;
#ifndef NDEBUG
	GkStatus::Instance()->SignalStatus("DEBUG\tcallRef:" + PString(callRefString) + "found&removed for calling\n\r", 1);
	PTRACE(5, ANSI::PIN << "DEBUG\tCallRef:" << CallRef << "found&removed for calling\n" << ANSI::OFF);
#endif
		}

		if (((*CallIter).Called != NULL) &&
			((*CallIter).Called->m_callReference.GetValue() == CallRef.GetValue()))
		{
			CallRec rec = *CallIter;
			if (theCall.Called == NULL)
				theCall = rec;
			CallList.erase(CallIter);
			rec.RemoveCalled();
			CallList.insert(rec);
			CallIter = CallList.begin();
			hasRemoved = TRUE;
			startTime = rec.m_startTime;
#ifndef NDEBUG
	GkStatus::Instance()->SignalStatus("DEBUG\tcallRef:" + PString(callRefString) + "found&removed for called\n\r", 1);
	PTRACE(5, ANSI::PIN <<"DEBUG\tCallRef:" << CallRef << "found&removed for called...\n" << ANSI::OFF);
#endif
		}
		
		if((*CallIter).CountEndpoints() <= 1)
		{
			CallRec rec = *CallIter;
			CallList.erase(CallIter);
			rec.RemoveAll();
			CallIter = CallList.begin();
			hasRemoved = TRUE;
			startTime = rec.m_startTime;
#ifndef NDEBUG
	GkStatus::Instance()->SignalStatus("DEBUG\tcall completely removed\n\r", 1);
	PTRACE(5, ANSI::PIN << "DEBUG\tcall completely removed\n" << ANSI::OFF);
#endif
		}
		else
			++CallIter;
	}
	if (hasRemoved) {
		struct tm * timeStructStart;
		struct tm * timeStructEnd;
		time_t now;
		double callDuration;

		timeStructStart = gmtime(&startTime);
		if (timeStructStart == NULL) 
			PTRACE(1, "ERROR\t ##################### timeconversion-error(1)!!\n");
		PString startTimeString(asctime(timeStructStart));
		startTimeString.Replace("\n", "");

		now = time(NULL);
		timeStructEnd = gmtime(&now);
		if (timeStructEnd == NULL) 
			PTRACE(1, "ERROR\t ##################### timeconversion-error(2)!!\n");
		PString endTimeString(asctime(timeStructEnd));
		endTimeString.Replace("\n", "");

		PString caller, callee;
		if (theCall.Calling) {
			H225_TransportAddress & addr = theCall.Calling->m_callSignalAddress;
			const endptr rec=RegistrationTable::Instance()->FindBySignalAdr(addr);
			caller = PString(PString::Printf, "%s|%s",
				(const unsigned char *) AsString(H225_TransportAddress_ipAddress(addr)),
				(const unsigned char *) rec->GetEndpointIdentifier().GetValue());
		}
		if (theCall.Called) {
			H225_TransportAddress & addr = theCall.Called->m_callSignalAddress;
			const endptr rec=RegistrationTable::Instance()->FindBySignalAdr(addr);
			callee = PString(PString::Printf, "%s|%s",
				(const unsigned char *) AsString(H225_TransportAddress_ipAddress(addr)),
				(const unsigned char *) rec->GetEndpointIdentifier().GetValue());
		}

		callDuration = difftime(now, startTime);
		PString cdrString(PString::Printf, "CDR|%s|%.0f|%s|%s|%s\n", callRefString, callDuration,
				 (const unsigned char *)startTimeString,
				 (const unsigned char *)caller, (const unsigned char *)callee);

		GkStatus::Instance()->SignalStatus(cdrString, 1);
		PTRACE(3, cdrString);
	}
#ifndef NDEBUG
	GkStatus::Instance()->SignalStatus("DEBUG\tdone for "  + PString(callRefString) + "...\n\r", 1);
	PTRACE(5, ANSI::PIN << "DEBUG\tdone for " + PString(callRefString) + "...\n" << ANSI::OFF);
#endif
}


const CallRec * CallTable::FindCallRec(const Q931 & m_q931) const
{
	set<CallRec>::const_iterator CallIter;
	PObject::Comparison result;


	if (m_q931.HasIE(Q931::UserUserIE)) {
		H225_H323_UserInformation signal;

		PPER_Stream q = m_q931.GetIE(Q931::UserUserIE);
		if ( ! signal.Decode(q) ) {
			PTRACE(4, "GK\tERROR DECODING Q931.UserInformation!");
			return NULL;
		}

		H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
		H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;
		H225_Setup_UUIE & setup = body;

		// look at all calls
		for (CallIter = CallList.begin(); CallIter != CallList.end(); ++CallIter)
		{
			// look at each endpoint in this call if it has this call reference
			if ((result = (*CallIter).m_callIdentifier.Compare(setup.m_callIdentifier)) == PObject::EqualTo)
				return &(*CallIter);
		};
	} else
		PTRACE(3, "ERROR\tQ931 has no UUIE!!\n");

	// callIdentifier is optional, so in case we don't find it, look for the
	// CallRec by its callReferenceValue
	H225_CallReferenceValue m_crv = m_q931.GetCallReference();
	return FindCallRec (m_crv);
};


const CallRec * CallTable::FindCallRec(const H225_CallIdentifier & m_callIdentifier) const
{
	set<CallRec>::const_iterator CallIter;
	PObject::Comparison result;

	// look at all calls
	for (CallIter = CallList.begin(); CallIter != CallList.end(); ++CallIter)
	{
		// look at each endpoint in this call if it has this call reference
		if ((result = (*CallIter).m_callIdentifier.Compare(m_callIdentifier)) == PObject::EqualTo)
			return &(*CallIter);
	};

	return NULL;
};


const CallRec * CallTable::FindCallRec(const H225_CallReferenceValue & CallRef) const
{
	set<CallRec>::const_iterator CallIter;

	// look at all calls
	for (CallIter = CallList.begin(); CallIter != CallList.end(); ++CallIter)
	{
		// look at each endpoint in this call if it has this call reference
		if ((*CallIter).Calling != NULL)
			if ((*CallIter).Calling->m_callReference.GetValue() == CallRef.GetValue())
				return &(*CallIter);
		if ((*CallIter).Called != NULL)
			if ((*CallIter).Called->m_callReference.GetValue() == CallRef.GetValue())
				return &(*CallIter);
	};
	return NULL;
};


const CallRec * CallTable::FindCallRec(PINDEX CallNumber) const
{
	set<CallRec>::const_iterator CallIter;

	// look at all calls
	for (CallIter = CallList.begin(); CallIter != CallList.end(); ++CallIter)
	{
		// look at each call if it has this call number
		if (CallIter->m_CallNumber == CallNumber)
			return &(*CallIter);
	};

	return NULL;
};


const CallRec * CallTable::FindBySignalAdr(const H225_TransportAddress & SignalAdr) const
{
	set<CallRec>::const_iterator CallIter;

	// look at all calls
	for (CallIter = CallList.begin(); CallIter != CallList.end(); ++CallIter)
	{
		// look at each endpoint in this call if it has this call reference
		if ((*CallIter).Calling != NULL)
			if ((*CallIter).Calling->m_callSignalAddress == SignalAdr)
				return &(*CallIter);
		if ((*CallIter).Called != NULL)
			if ((*CallIter).Called->m_callSignalAddress == SignalAdr)
				return &(*CallIter);
	}
	return NULL;
}

void CallTable::PrintCurrentCalls(GkStatus::Client &client, BOOL verbose) const
{
	static PMutex mutex;
	GkProtectBlock _using(mutex);

	set<CallRec>::const_iterator CallIter;
	char MsgBuffer[1024];
	char Val[10];

	client.WriteString("CurrentCalls\r\n");
	for (CallIter = CallList.begin(); CallIter != CallList.end(); ++CallIter)
	{
		const CallRec &Call = (*CallIter);
		strcpy (MsgBuffer, "Call No. ");
		sprintf(Val, "%d", Call.m_CallNumber);
		strcat (MsgBuffer, Val);
		strcat (MsgBuffer, "  CallID");
		for (PINDEX i = 0; i < Call.m_callIdentifier.m_guid.GetDataLength(); i++)
		{
			sprintf(Val, " %02x", Call.m_callIdentifier.m_guid[i]);
			strcat(MsgBuffer, Val);
		}
		strcat(MsgBuffer, "\r\n");
		client.WriteString(PString(MsgBuffer));
		if (Call.Calling)
		{
			client.WriteString(PString(PString::Printf, "ACF|%s\r\n",
				(const char *) AsString(H225_TransportAddress_ipAddress(Call.Calling->m_callSignalAddress))));
		}
		if (Call.Called)
		{
			client.WriteString(PString(PString::Printf, "ACF|%s\r\n",
				(const char *) AsString(H225_TransportAddress_ipAddress(Call.Called->m_callSignalAddress))));
		}
		if (verbose)
		{
			PString from = "?";
			PString to   = "?";
			if (Call.Calling) {
				const endptr e = RegistrationTable::Instance()->FindBySignalAdr(Call.Calling->m_callSignalAddress);
				if (e)
					from = AsString(e->GetAliases(), FALSE);
			}
			if (Call.Called) {
				const endptr e = RegistrationTable::Instance()->FindBySignalAdr(Call.Called->m_callSignalAddress);
				if (e)
					to = AsString(e->GetAliases(), FALSE);
			}
			int bw = Call.m_bandWidth;
			char ctime[100];
#if defined (WIN32)
			strncpy(ctime, asctime(localtime(&(Call.m_startTime))), 100);
#elif  defined (P_SOLARIS)
			asctime_r(localtime(&(Call.m_startTime)), ctime, 100);
#else
			asctime_r(localtime(&(Call.m_startTime)), ctime);
#endif
			sprintf(MsgBuffer, "# %s|%s|%d|%s", (const char*)from, (const char*)to, bw, ctime);
			client.WriteString(PString(MsgBuffer));
		}
	}
	client.WriteString(";\r\n");
}

