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

#include "RasTbl.h"
#include "ANSI.h"
#include <time.h>
#include <stdio.h>
#include "h323util.h"
#include "Toolkit.h"

// initialize singleton instances and locks
resourceManager * resourceManager::m_instance = NULL;
RegistrationTable * RegistrationTable::m_instance = NULL;
CallTable * CallTable::m_instance = NULL;
PMutex resourceManager::m_CreationLock;
PMutex RegistrationTable::m_CreationLock;
PMutex CallTable::m_CreationLock;


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


resourceManager * resourceManager::Instance(void)
{
	if (m_instance == NULL)
	{
		m_CreationLock.Wait();
		if (m_instance == NULL)
			m_instance = new resourceManager;
		m_CreationLock.Signal();
	}
	return m_instance;
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

void resourceManager::Insert(const conferenceRec & NewRec)
{
	ConferenceList.insert(NewRec);
};

unsigned int resourceManager::GetConferenceCount(void) const
{
	return ConferenceList.size();
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
    Insert( cRec );
    PTRACE(2, "GK\tTotal sessions : " << GetConferenceCount()<< "\tAvailable BandWidth " << GetAvailableBW());
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
			PTRACE(2, "GK\tTotal sessions : " << GetConferenceCount() << "\tAvailable BandWidth " << GetAvailableBW());
			return TRUE;
		}
	}
	return FALSE;
}

/*
void endpointRec::PrintOn( ostream &strm )
{
    strm << "{";
    strm << endl << " callSignalAddress ";
    m_callSignalAddress.PrintOn( strm );
    strm << endl << " terminalAlias ";
    m_terminalAlias.PrintOn( strm );
    strm << endl << " endpointIdentifier ";
    m_endpointIdentifier.PrintOn( strm );
    strm << "}" << endl;
}
*/

endpointRec::endpointRec(H225_TransportAddress rasAddress, H225_TransportAddress callSignalAddress, H225_EndpointIdentifier endpointId, H225_ArrayOf_AliasAddress terminalAliases, H225_EndpointType terminalType, const H225_RasMessage completeRRQ)
{
	m_rasAddress = rasAddress;
	m_callSignalAddress = callSignalAddress;
	m_endpointIdentifier = endpointId;
	m_terminalAliases = terminalAliases;
	m_terminalType = terminalType;
	m_completeRegistrationRequest = completeRRQ;
}	


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


void RegistrationTable::Insert(const endpointRec & NewRec)
{
	EndpointList.insert(NewRec);
};


RegistrationTable * RegistrationTable::Instance(void)
{
	if (m_instance == NULL)
	{
		m_CreationLock.Wait();
		if (m_instance == NULL)
			m_instance = new RegistrationTable;
		m_CreationLock.Signal();
	};

	return m_instance;
};



RegistrationTable::RegistrationTable()
	: GatewayPrefixes(),  // TODO: how to define a default in the map for not-found elements?
	  endpointIdSuffix(Toolkit::Config()->GetString("EndpointIDSuffix", "_endp"))
{
	srand(time(0));
	recCnt = rand()%9000+1000;
};


void RegistrationTable::RemoveByEndpointId(const H225_EndpointIdentifier & endpointId)
{
	set<endpointRec>::iterator Iter;

	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		if ((*Iter).m_endpointIdentifier == endpointId)
		{
			EndpointList.erase(Iter);
			return;
		};
	};
};

const endpointRec * RegistrationTable::FindByEndpointId(const H225_EndpointIdentifier & endpointId) const
{
	set<endpointRec>::const_iterator Iter;

	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		if ((*Iter).m_endpointIdentifier == endpointId)
			return &(*Iter);
	};
	return NULL;
};

const endpointRec * RegistrationTable::FindBySignalAdr(H225_TransportAddress SignalAdr) const
{
	set<endpointRec>::const_iterator Iter;

	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		if ((*Iter).m_callSignalAddress == SignalAdr)
			return &(*Iter);
	};
	return NULL;
};

bool GWAliasEqual(H225_AliasAddress GWAlias, H225_AliasAddress OtherAlias)
{
	if(!GWAlias.IsValid()) return FALSE;
	if(!OtherAlias.IsValid()) return FALSE;
    PString GWAliasStr = ((PASN_BMPString&)GWAlias.GetObject()).GetValue();
    PString OtherAliasStr = ((PASN_BMPString&)OtherAlias.GetObject()).GetValue();

	if (GWAlias.GetTag() == H225_AliasAddress::e_e164)
	{
		// for E.164 aliases we only compare the prefix the gateway registered
		// and assume they provide acces to the whole address space
		return (strncmp(GWAliasStr, OtherAliasStr, strlen(GWAliasStr)) == 0);
	}
	else {
	  return (GWAlias == OtherAlias);		
	}
};


void RegistrationTable::AddPrefixes(const PString & NewAliasStr, const PString &prefixes)
{
	// delete old if existing	
	PStringArray *prefixArr = GatewayPrefixes[NewAliasStr];
	if(prefixArr != NULL) {
		delete prefixArr;
		GatewayPrefixes[NewAliasStr] = NULL;
	}

	// create new
	prefixArr = new PStringArray(prefixes.Tokenise(" ,;\t\n", FALSE));
	GatewayPrefixes[NewAliasStr] = prefixArr;
	
	//TODO: delete the content of GatewayPrefixes somewhere.
	//...or leave it alone -- it is used until the program ends.
}


void RegistrationTable::RemovePrefixes(const H225_AliasAddress & alias)
{
	if (alias.GetTag() != H225_AliasAddress::e_e164) 
		return;
	
	PString AliasStr = ((PASN_IA5String&)(alias).GetObject()).GetValue();

	// delete old if existing
	PStringArray *prefixArr = GatewayPrefixes[AliasStr];
	if (prefixArr != NULL) {
		delete prefixArr;
		GatewayPrefixes[AliasStr] = NULL;
	}
}



const endpointRec * RegistrationTable::FindByAlias(H225_AliasAddress alias) const
{
	set<endpointRec>::const_iterator EPIter;

	// loop over endpoints
	for (EPIter = EndpointList.begin(); EPIter != EndpointList.end(); ++EPIter)
	{
		// loop over alias list
		for(unsigned int AliasIndex = 0; AliasIndex < (*EPIter).m_terminalAliases.GetSize(); ++AliasIndex)
		{
			if ((*EPIter).m_terminalType.HasOptionalField(H225_EndpointType::e_gateway))
			{
				// for gateways we use a different comparison function,
				// since they provide access to a lot of numbers
				if (GWAliasEqual((*EPIter).m_terminalAliases[AliasIndex], alias))
					return &(*EPIter);
			}
			else
			{
				if ((*EPIter).m_terminalAliases[AliasIndex] == alias)
					return &(*EPIter);
			};
		};
	};
	return NULL;
};


const endpointRec * RegistrationTable::FindByAnyAliasInList(H225_ArrayOf_AliasAddress aliases) const
{
	set<endpointRec>::const_iterator EPIter;

	// loop over endpoints
	for (EPIter = EndpointList.begin(); EPIter != EndpointList.end(); ++EPIter)
	{
		// loop over alias list
		for(unsigned int EPAliasIndex = 0; EPAliasIndex < (*EPIter).m_terminalAliases.GetSize(); ++EPAliasIndex)
		{
			for (unsigned int FindAliasIndex = 0; FindAliasIndex < aliases.GetSize(); ++ FindAliasIndex)
			{
				if ((*EPIter).m_terminalType.HasOptionalField(H225_EndpointType::e_gateway))
				{
					// for gateways we use a different comparison function,
					// since they provide access to a lot of numbers
					if (GWAliasEqual((*EPIter).m_terminalAliases[EPAliasIndex], aliases[FindAliasIndex]))
						return &(*EPIter);
				}
				else
				{
					if ((*EPIter).m_terminalAliases[EPAliasIndex] == aliases[FindAliasIndex])
						return &(*EPIter);
				};
			};
		};
	};
	return NULL;
};


const endpointRec * RegistrationTable::FindByPrefix(const H225_AliasAddress & alias) const
{
	set<endpointRec>::const_iterator EPIter;
  
	if (alias.GetTag() != H225_AliasAddress::e_e164)
		return NULL;

	PString aliasStr = ((PASN_IA5String&)(alias).GetObject()).GetValue();

	// loop over endpoints
	for (EPIter = EndpointList.begin(); EPIter != EndpointList.end(); ++EPIter)
	{
		// loop over alias list
		for(unsigned int AliasIndex = 0; AliasIndex < (*EPIter).m_terminalAliases.GetSize(); ++AliasIndex)
		{
			if ((*EPIter).m_terminalType.HasOptionalField(H225_EndpointType::e_gateway)) {
				const PString GWAliasStr = ((PASN_BMPString&)((*EPIter).m_terminalAliases[AliasIndex]).GetObject()).GetValue();

				const PStringArray *prefixes = RegistrationTable::Instance()->GatewayPrefixes[GWAliasStr];
				if (NULL == prefixes) {
					// no prefixes for this gw -> next endpoint
				continue;
				}
				else {
					// try all prefixes
					int max = prefixes->GetSize();
					for (int i=0; i < max; i++) {
						const PString &prefix = (*prefixes)[i];
						if (aliasStr.Find(prefix) == 0) {
							// found at position 0 => is a prefix
							PTRACE(2, ANSI::DBG << "Gateway '" << GWAliasStr << "' prefix '"<<prefix
								<< "' matched for '" << aliasStr << "'" << ANSI::OFF);
							return &(*EPIter);
						}
					}
					// no prefix matched
				}
			}
		};
	};
	// no gw matched with one of its prefixes
	return NULL;
};



void RegistrationTable::UpdateAliasBySignalAdr(H225_TransportAddress SignalAdr, H225_ArrayOf_AliasAddress Aliases)
{
	set<endpointRec>::iterator Iter;

	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		if ((*Iter).m_callSignalAddress == SignalAdr)
		{
			endpointRec aRec(*Iter);
			EndpointList.erase(Iter);
			aRec.m_terminalAliases = Aliases;
			EndpointList.insert(aRec);
			return;
		};
	};
};

H225_EndpointIdentifier RegistrationTable::GenerateEndpointId(void)
{
	H225_EndpointIdentifier NewEndpointId;
	NewEndpointId = PString(PString::Unsigned, ++recCnt) + endpointIdSuffix;
	return NewEndpointId;
};


H225_ArrayOf_AliasAddress RegistrationTable::GenerateAlias(const H225_EndpointIdentifier & endpointId) const
{
	H225_AliasAddress NewAlias;
	H225_ArrayOf_AliasAddress AliasList;

	NewAlias.SetTag( H225_AliasAddress::e_h323_ID); 
	(PASN_BMPString &)NewAlias = endpointId;

	AliasList.SetSize(1);
	AliasList[0] = NewAlias;

	return AliasList;
}

void RegistrationTable::PrintAllRegistrations(GkStatus::Client &client, BOOL verbose) const
{
	static PMutex mutex;
	GkProtectBlock _using(mutex); //towi: do we really need this mutex?

	std::set<endpointRec>::const_iterator Iter;
	
	client.WriteString("AllRegistrations\r\n");
	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		const H225_TransportAddress_ipAddress & ipAddress = (*Iter).m_rasAddress;
		PString msg(PString::Printf, "RCF|%d.%d.%d.%d|%s|%s|%s\r\n",
			    ipAddress.m_ip[0], ipAddress.m_ip[1], ipAddress.m_ip[2], ipAddress.m_ip[3],
			    (const unsigned char *) AsString(Iter->m_terminalAliases),
			    (const unsigned char *) AsString(Iter->m_terminalType),
			    (const unsigned char *) Iter->m_endpointIdentifier.GetValue() );
		PTRACE(2,msg);
		client.WriteString(msg);
		
		if (verbose)
		{
			const PString & alias = AsString(Iter->m_terminalAliases, FALSE);
			PString s = "# " + alias;
			// write prefixes of this alias
			s += "|Px(";
			const PStringArray *prefixes = RegistrationTable::Instance()->GatewayPrefixes[alias];
			if (prefixes) {
				if (prefixes->GetSize()>0) 
					s += (*prefixes)[0];
				for (PINDEX i=1; i<prefixes->GetSize(); i++) {
					s += "," + (*prefixes)[i];
				}
			}
			client.WriteString(s + ")\r\n");
		}
		
	}
	
	client.WriteString(";\r\n");
};
 
/*
void RegistrationTable::PrintOn( ostream &strm ) const
{
	std::set<endpointRec>::const_iterator Iter;

	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
      	(*Iter).PrintOn( strm );
	};
}
*/

EndpointCallRec::EndpointCallRec(H225_TransportAddress callSignalAddress, H225_TransportAddress rasAddress, H225_CallReferenceValue callReference)
  : m_callSignalAddress(callSignalAddress),
	m_rasAddress(rasAddress),
	m_callReference(callReference)
{
};

bool EndpointCallRec::operator< (const EndpointCallRec & other) const
{
	return this->m_callSignalAddress <  other.m_callSignalAddress;
};

CallRec::CallRec()
	: m_startTime(time(NULL)),
	  Calling(NULL),
	  Called(NULL)
{
	m_conferenceIdentifier = "";
	m_callIdentifier.m_guid = "";
};


CallRec::CallRec(const CallRec & Other)

{
	m_conferenceIdentifier = Other.m_conferenceIdentifier;
	m_callIdentifier = Other.m_callIdentifier;
	m_bandWidth = Other.m_bandWidth;
	m_startTime = Other.m_startTime;

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
	if (Calling)
		delete Calling;
	if (Called)
		delete Called;
};

CallRec & CallRec::operator=(const CallRec & Other)

{
	if (this == &Other)
		return *this;

	m_conferenceIdentifier = Other.m_conferenceIdentifier;
	m_callIdentifier = Other.m_callIdentifier;
	m_bandWidth = Other.m_bandWidth;
	m_startTime = Other.m_startTime;
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
	// return this->m_conferenceIdentifier.GetValue() < other.m_conferenceIdentifier.GetValue();
};

void CallRec::SetCalling(const EndpointCallRec & NewCalling)
{
	if (Calling != NULL)
		delete Calling;
	Calling = new EndpointCallRec(NewCalling);
};

void CallRec::SetCalled(const EndpointCallRec & NewCalled)
{
	if (Called != NULL)
		delete Called;
	Called = new EndpointCallRec(NewCalled);
};

void CallRec::SetBandwidth(int Bandwidth)
{
	m_bandWidth.SetValue(Bandwidth);
};

void CallRec::RemoveCalling(void)
{
	if(Calling != NULL)
		delete Calling;
	Calling = NULL;
};

void CallRec::RemoveCalled(void)
{
	if(Called != NULL)
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


CallTable * CallTable::Instance(void)
{
	if (m_instance == NULL)
	{
		m_CreationLock.Wait();
		if (m_instance == NULL)
			m_instance = new CallTable;
		m_CreationLock.Signal();
	};

	return m_instance;
};

CallTable::CallTable()
{
};

CallTable::CallTable(const CallTable &)
{
};
	
void CallTable::Insert(const CallRec & NewRec)
{
	PTRACE(3, "CallTable::Insert");
	CallList.insert(NewRec);
};

void CallTable::Insert(const EndpointCallRec & Calling, const EndpointCallRec & Called, int Bandwidth, H225_CallIdentifier CallId, H225_ConferenceIdentifier ConfId)
{
	CallRec Call;

	PTRACE(3, "CallTable::Insert");
	
	Call.SetCalling(Calling);
	Call.SetCalled(Called);
	Call.SetBandwidth(Bandwidth);
	Call.m_callIdentifier = CallId;
	Call.m_conferenceIdentifier = ConfId;
	Insert(Call);
};

void CallTable::Insert(const EndpointCallRec & Calling, int Bandwidth, H225_CallIdentifier CallId, H225_ConferenceIdentifier ConfId)
{
	CallRec Call;

	PTRACE(3, "CallTable::Insert");
	
	Call.SetCalling(Calling);
	Call.SetBandwidth(Bandwidth);
	Call.m_callIdentifier = CallId;
	Call.m_conferenceIdentifier = ConfId;
	Insert(Call);
};

void CallTable::RemoveEndpoint(const H225_CallReferenceValue & CallRef)
{
	static PMutex mutex;
	GkProtectBlock _using(mutex); //towi: Auto protect the whole method!

	set<CallRec>::iterator CallIter;

	// look at all calls
	CallIter = CallList.begin();
	while(CallIter != CallList.end())
	{
		// look at each endpoint in this call if it has this call reference
		if (((*CallIter).Calling != NULL) &&
			((*CallIter).Calling->m_callReference.GetValue() == CallRef.GetValue()))
		{
			CallRec rec = *CallIter;
			CallList.erase(CallIter);
			rec.RemoveCalling();
			CallList.insert(rec);
			CallIter = CallList.begin();
			//towi: continue;
			
		};
		if (((*CallIter).Called != NULL) &&
			((*CallIter).Called->m_callReference.GetValue() == CallRef.GetValue()))
		{
			CallRec rec = *CallIter;
			CallList.erase(CallIter);
			rec.RemoveCalled();
			CallList.insert(rec);
			CallIter = CallList.begin();
			// towi: continue;
			
		};
		
		/*towi*1: remove whole call if only <=1 ("<="!) endpoint remains
		// remove the whole thing if empty
		if (((*CallIter).Calling == NULL) &&
			((*CallIter).Called == NULL))
		*/
		if((*CallIter).CountEndpoints() <= 1) //towi*1
		{
			CallRec rec = *CallIter;
			CallList.erase(CallIter);
			rec.RemoveAll();
			CallIter = CallList.begin();
		}
		else
			++CallIter;
	};
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
	};
	return NULL;
};

void CallTable::PrintCurrentCalls(GkStatus::Client &client, BOOL verbose) const
{
	static PMutex mutex;
	GkProtectBlock _using(mutex);

	set<CallRec>::const_iterator CallIter;
	char MsgBuffer[1024];
	char HexVal[10];

	client.WriteString("CurrentCalls\r\n");
	for (CallIter = CallList.begin(); CallIter != CallList.end(); ++CallIter)
	{
		const CallRec &Call = (*CallIter);
		strcpy (MsgBuffer, "CallID");
		for (PINDEX i = 0; i < Call.m_callIdentifier.m_guid.GetDataLength(); i++)
		{
			sprintf(HexVal, " %02x", Call.m_callIdentifier.m_guid[i]);
			strcat(MsgBuffer, HexVal);
		};
		strcat(MsgBuffer, "\r\n");
		// sprintf(MsgBuffer, "CallID %s\n", (const unsigned char *)AsString((*CallIter).m_callIdentifier.m_guid));
		client.WriteString(PString(MsgBuffer));
		if (Call.Calling)
		{
			const H225_TransportAddress_ipAddress & ipAddressA = (const H225_TransportAddress_ipAddress &) Call.Calling->m_rasAddress;
			sprintf(MsgBuffer, "ACF|%d.%d.%d.%d\r\n", ipAddressA.m_ip[0], ipAddressA.m_ip[1], ipAddressA.m_ip[2], ipAddressA.m_ip[3]);
			client.WriteString(PString(MsgBuffer));
		};
		if (Call.Called)
		{
			const H225_TransportAddress_ipAddress & ipAddressB = (const H225_TransportAddress_ipAddress &) Call.Called->m_rasAddress;
			sprintf(MsgBuffer, "ACF|%d.%d.%d.%d\r\n", ipAddressB.m_ip[0], ipAddressB.m_ip[1], ipAddressB.m_ip[2], ipAddressB.m_ip[3]);
			client.WriteString(PString(MsgBuffer));
		};
		if (verbose)
		{
			PString from = "?";
			PString to   = "?";
			if (Call.Calling) {
				const endpointRec *e = RegistrationTable::Instance()->FindBySignalAdr(Call.Calling->m_callSignalAddress);
				from = AsString(e->m_terminalAliases, FALSE);
			}
			if (Call.Called) {
				const endpointRec *e = RegistrationTable::Instance()->FindBySignalAdr(Call.Called->m_callSignalAddress);
				to = AsString(e->m_terminalAliases, FALSE);
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
	};
	client.WriteString(".\r\n");
};

