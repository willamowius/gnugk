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
	EndpointList.push_back(NewRec);
};

RegistrationTable::RegistrationTable()
	: GatewayPrefixes(),  // TODO: how to define a default in the map for not-found elements?
	  GatewayFlags(),
	  endpointIdSuffix(GkConfig()->GetString("EndpointIDSuffix", "_endp"))
{
	recCnt = rand()%9000+1000;
};


void RegistrationTable::RemoveByEndpointId(const H225_EndpointIdentifier & endpointId)
{
	list<endpointRec>::iterator Iter;

	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		if ((*Iter).m_endpointIdentifier == endpointId)
		{
			EndpointList.erase(Iter);	// list<> is O(1), slist<> O(n) here
			return;
		};
	};
};

const endpointRec * RegistrationTable::FindByEndpointId(const H225_EndpointIdentifier & endpointId) const
{
	list<endpointRec>::const_iterator Iter;

	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		if ((*Iter).m_endpointIdentifier == endpointId)
			return &(*Iter);
	};
	return NULL;
};

const endpointRec * RegistrationTable::FindBySignalAdr(H225_TransportAddress SignalAdr) const
{
	list<endpointRec>::const_iterator Iter;

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
	PString Alias = "";

	std::list<endpointRec>::const_iterator Iter;
	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		if (!Iter->m_terminalType.HasOptionalField(H225_EndpointType::e_gateway))
			continue;
		// gibt uns das den gewuenschten Alias-Namen ?
		for (PINDEX i = 0; i < Iter->m_terminalAliases.GetSize(); i++)
		{
			Alias = AsString(Iter->m_terminalAliases[i], FALSE);
		        PTRACE(5, "Updating Alias " << i << ": " << Alias);

			AddAlias(Alias);
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



const endpointRec * RegistrationTable::FindByAlias(H225_AliasAddress alias) const
{
	list<endpointRec>::const_iterator EPIter;

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
	list<endpointRec>::const_iterator EPIter;

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


const endpointRec * RegistrationTable::FindByPrefix(const H225_AliasAddress & alias)
{
	list<endpointRec>::iterator EPIter;
  
	if (alias.GetTag() != H225_AliasAddress::e_dialedDigits)
		return NULL;

	// Here is a bug. We find the first prefix, but no the longest one, so we have to fix it.

	list<endpointRec>::iterator EPmax;
	PINDEX maxprefix=0;

	// note that found prefix has equal length to an other.
	// if so, the found endpoint is moves to the end, so we get a round-robin.
	bool maxprefixIsConcurrent = false;

	PString aliasStr = H323GetAliasAddressString(alias);

	// loop over endpoints
	for (EPIter = EndpointList.begin(); EPIter != EndpointList.end(); ++EPIter)
	{
		// loop over alias list
		for(unsigned int AliasIndex = 0; AliasIndex < (*EPIter).m_terminalAliases.GetSize(); ++AliasIndex)
		{
			if ((*EPIter).m_terminalType.HasOptionalField(H225_EndpointType::e_gateway)) {
				const PString GWAliasStr = H323GetAliasAddressString((*EPIter).m_terminalAliases[AliasIndex]);

				const PStringArray *prefixes = RegistrationTable::Instance()->GatewayPrefixes[GWAliasStr];
				if (prefixes == NULL) {
					// no prefixes for this gw -> next endpoint
					continue;
				}
				else {
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
		};
	};
	// no gw matched with one of its prefixes

	// if prefix is found
	if (maxprefix) {
		// round-robin
		if(maxprefixIsConcurrent) {
			PTRACE(3, ANSI::DBG << "Prefix apply round robin" << ANSI::OFF);
			static PMutex mutex;
			GkProtectBlock _using(mutex);

			endpointRec aRec(*EPmax);
			EndpointList.erase(EPmax);
			EndpointList.push_back(aRec);
			return &(*EndpointList.rbegin());
		}

		return &(*EPmax);
	}

	return NULL;
};


void RegistrationTable::UpdateAliasBySignalAdr(H225_TransportAddress SignalAdr, H225_ArrayOf_AliasAddress Aliases)
{
	list<endpointRec>::iterator Iter;

	for (Iter = EndpointList.begin(); Iter != EndpointList.end(); ++Iter)
	{
		if ((*Iter).m_callSignalAddress == SignalAdr)
		{
			endpointRec aRec(*Iter);
			EndpointList.erase(Iter);
			aRec.m_terminalAliases = Aliases;
			EndpointList.push_back(aRec);
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
	H323SetAliasAddress(endpointId, NewAlias);

	AliasList.SetSize(1);
	AliasList[0] = NewAlias;

	return AliasList;
}

void RegistrationTable::PrintAllRegistrations(GkStatus::Client &client, BOOL verbose) const
{
	static PMutex mutex;
	GkProtectBlock _using(mutex); // do we really need this mutex?

	std::list<endpointRec>::const_iterator Iter;
	
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
			for (PINDEX i = 0; i < Iter->m_terminalAliases.GetSize(); i++)
			{
				const PString & alias = AsString(Iter->m_terminalAliases[i], FALSE);
				PString s = "# " + alias;

				// write prefixes of this alias
				s += "|Px(";
				const PStringArray *prefixes = RegistrationTable::Instance()->GatewayPrefixes[alias];
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
};
 

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
	m_CallNumber = 0;
};


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


CallTable::CallTable()
{
	m_CallNumber = 1;
};

CallTable::CallTable(const CallTable &)
{
};
	
void CallTable::Insert(const CallRec & NewRec)
{
	PTRACE(3, "CallTable::Insert(CALL)");
	CallList.insert(NewRec);
};

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
};

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
};

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
		};

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
		};
		
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
	};
	if (hasRemoved) {
		struct tm * timeStructStart;
		struct tm * timeStructEnd;
		time_t now;
		double callDuration;
		char cdrString[200];

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

		char caller[200], callee[200];
		*caller = *callee = '\0';
		if (theCall.Calling) {
			H225_TransportAddress & addr = theCall.Calling->m_callSignalAddress;
			const endpointRec *rec=RegistrationTable::Instance()->FindBySignalAdr(addr);
			H225_TransportAddress_ipAddress & ip = addr;
			sprintf(caller, "%d.%d.%d.%d:%u|%s", ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3], (unsigned)ip.m_port.GetValue(), (const unsigned char *)rec->m_endpointIdentifier.GetValue());
		}
		if (theCall.Called) {
			H225_TransportAddress & addr = theCall.Called->m_callSignalAddress;
			const endpointRec *rec=RegistrationTable::Instance()->FindBySignalAdr(addr);
			H225_TransportAddress_ipAddress & ip = addr;
			sprintf(callee, "%d.%d.%d.%d:%u|%s", ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3], (unsigned)ip.m_port.GetValue(), (const unsigned char *)rec->m_endpointIdentifier.GetValue());
		}

		callDuration = difftime(now, startTime);
		sprintf(cdrString, "CDR|%s|%.0f|%s|%s|%s\n", callRefString, callDuration, (const unsigned char *)startTimeString, caller, callee);

		GkStatus::Instance()->SignalStatus(cdrString, 1);
		PTRACE(3, cdrString);
	}
#ifndef NDEBUG
	GkStatus::Instance()->SignalStatus("DEBUG\tdone for "  + PString(callRefString) + "...\n\r", 1);
	PTRACE(5, ANSI::PIN << "DEBUG\tdone for " + PString(callRefString) + "...\n" << ANSI::OFF);
#endif
};


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
	};
	return NULL;
};

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
		};
		strcat(MsgBuffer, "\r\n");
		client.WriteString(PString(MsgBuffer));
		if (Call.Calling)
		{
			H225_TransportAddress_ipAddress & ipAddressA = Call.Calling->m_callSignalAddress;
			sprintf(MsgBuffer, "ACF|%d.%d.%d.%d:%u\r\n", ipAddressA.m_ip[0], ipAddressA.m_ip[1], ipAddressA.m_ip[2], ipAddressA.m_ip[3], (unsigned)ipAddressA.m_port.GetValue());
			client.WriteString(PString(MsgBuffer));
		};
		if (Call.Called)
		{
			H225_TransportAddress_ipAddress & ipAddressB = Call.Called->m_callSignalAddress;
			sprintf(MsgBuffer, "ACF|%d.%d.%d.%d:%u\r\n", ipAddressB.m_ip[0], ipAddressB.m_ip[1], ipAddressB.m_ip[2], ipAddressB.m_ip[3], (unsigned)ipAddressB.m_port.GetValue());
			client.WriteString(PString(MsgBuffer));
		};
		if (verbose)
		{
			PString from = "?";
			PString to   = "?";
			if (Call.Calling) {
				const endpointRec *e = RegistrationTable::Instance()->FindBySignalAdr(Call.Calling->m_callSignalAddress);
				if (e)
					from = AsString(e->m_terminalAliases, FALSE);
			}
			if (Call.Called) {
				const endpointRec *e = RegistrationTable::Instance()->FindBySignalAdr(Call.Called->m_callSignalAddress);
				if (e)
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
	client.WriteString(";\r\n");
};

