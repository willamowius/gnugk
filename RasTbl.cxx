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
#include <h323pdu.h>
#include "ANSI.h"
#include "h323util.h"
#include "Toolkit.h"
#include "SoftPBX.h"
#include "RasSrv.h"
#include "stl_supp.h"
#include "ProxyChannel.h"
#include "gk_const.h"

const char *CallTableSection = "CallTable";

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
	std::set<conferenceRec>::const_iterator Iter;

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
	std::set<conferenceRec>::iterator Iter;

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


EndpointRec::EndpointRec(const H225_RasMessage &completeRAS, bool Permanent)
      :	m_RasMsg(completeRAS), m_timeToLive(1), m_callCount(0), m_usedCount(0)
{
	SetTimeToLive(SoftPBX::TimeToLive);
	if (m_RasMsg.GetTag() == H225_RasMessage::e_registrationRequest) {
		H225_RegistrationRequest & rrq = m_RasMsg;
		if (rrq.m_rasAddress.GetSize() > 0)
			m_rasAddress = rrq.m_rasAddress[0];
		if (rrq.m_callSignalAddress.GetSize() > 0)
			m_callSignalAddress = rrq.m_callSignalAddress[0];
		m_endpointIdentifier = rrq.m_endpointIdentifier;
		m_terminalAliases = rrq.m_terminalAlias;
		m_terminalType = &rrq.m_terminalType;
		if (rrq.HasOptionalField(H225_RegistrationRequest::e_timeToLive))
			SetTimeToLive(rrq.m_timeToLive);
		PTRACE(1, "New EP|" << PrintOn(false));
	} else if (m_RasMsg.GetTag() == H225_RasMessage::e_locationConfirm) {
		H225_LocationConfirm & lcf = m_RasMsg;
		m_rasAddress = lcf.m_rasAddress;
		m_callSignalAddress = lcf.m_callSignalAddress;
		if (lcf.HasOptionalField(H225_LocationConfirm::e_destinationInfo))
			m_terminalAliases = lcf.m_destinationInfo;
		if (!lcf.HasOptionalField(H225_LocationConfirm::e_destinationType))
			lcf.IncludeOptionalField(H225_LocationConfirm::e_destinationType);
		m_terminalType = &lcf.m_destinationType;
		m_timeToLive = (SoftPBX::TimeToLive > 0) ? SoftPBX::TimeToLive : 600;
	}
	if (Permanent)
		m_timeToLive = 0;
}	

EndpointRec::~EndpointRec()
{
	PTRACE(3, "remove endpoint: " << (const unsigned char *)m_endpointIdentifier.GetValue() << " " << m_usedCount);
}

bool EndpointRec::PrefixMatch_IncompleteAddress(const H225_ArrayOf_AliasAddress &aliases, 
                                               bool &fullMatch) const
{
        fullMatch = 0;
        int partialMatch = 0;
        PString aliasStr;
	unsigned int aliasStr_len;
	const H225_ArrayOf_AliasAddress & reg_aliases = GetAliases();
	PString reg_alias;
	// for each given alias (dialedDigits) from request message 
	for(PINDEX i = 0; i < aliases.GetSize() && !fullMatch; i++) {
//          if (aliases[i].GetTag() == H225_AliasAddress::e_dialedDigits) {
	    aliasStr = H323GetAliasAddressString(aliases[i]);
	    aliasStr_len = aliasStr.GetLength();
	    // for each alias (dialedDigits) which is stored for the endpoint in registration
	    for (PINDEX i = 0; i < reg_aliases.GetSize() && !fullMatch; i++) {
//              if (reg_aliases[i].GetTag() == H225_AliasAddress::e_dialedDigits) {
	        reg_alias = H323GetAliasAddressString(reg_aliases[i]);
                // if alias from request message is prefix to alias which is 
		//   stored in registration
	        if ((reg_alias.GetLength() >= aliasStr_len) && 
		    (aliasStr == reg_alias.Left(aliasStr_len))) {
		  // check if it is a full match 
		  if (aliasStr == reg_alias) {
		    fullMatch = 1;
  		    PTRACE(2, ANSI::DBG << "Alias " << aliasStr << " matches endpoint " 
		      << (const unsigned char *)m_endpointIdentifier.GetValue() << " (full)" << ANSI::OFF);
  		  } else {
		    partialMatch = 1;
  		    PTRACE(2, ANSI::DBG << "Alias " << aliasStr << " matches endpoint " 
		      << (const unsigned char *)m_endpointIdentifier.GetValue() << " (partial)" << ANSI::OFF);
		  }
	        }
//	      }
	    }
//	  }
	}
	return (partialMatch || fullMatch);
}

void EndpointRec::SetRasAddress(const H225_TransportAddress &a)
{
	PWaitAndSignal lock(m_usedLock);
	m_rasAddress = a;
}

void EndpointRec::SetEndpointIdentifier(const H225_EndpointIdentifier &i)
{
	PWaitAndSignal lock(m_usedLock);
	m_endpointIdentifier = i;
}
        
void EndpointRec::SetTimeToLive(int seconds)
{
	if (m_timeToLive > 0) {
		// To avoid bloated RRQ traffic, don't allow ttl < 60
		if (seconds < 60)
			seconds = 60;
		PWaitAndSignal lock(m_usedLock);
		m_timeToLive = (SoftPBX::TimeToLive > 0) ?
			std::min(SoftPBX::TimeToLive, seconds) : 0;
	}
}

void EndpointRec::SetPermanent(bool b)
{
	PWaitAndSignal lock(m_usedLock);
	m_timeToLive = (!b && SoftPBX::TimeToLive > 0) ? SoftPBX::TimeToLive : 0;
}

void EndpointRec::SetAliases(const H225_ArrayOf_AliasAddress &a)
{
	PWaitAndSignal lock(m_usedLock);
        m_terminalAliases = a;
}
        
void EndpointRec::SetEndpointType(const H225_EndpointType &t) 
{
	PWaitAndSignal lock(m_usedLock);
        *m_terminalType = t;
}

void EndpointRec::Update(const H225_RasMessage & ras_msg)
{
        if (ras_msg.GetTag() == H225_RasMessage::e_registrationRequest) {
		const H225_RegistrationRequest & rrq = ras_msg;

		if (rrq.m_rasAddress.GetSize() >= 1)
			SetRasAddress(rrq.m_rasAddress[0]);

		if (rrq.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier))
			SetEndpointIdentifier(rrq.m_endpointIdentifier);

		if (rrq.HasOptionalField(H225_RegistrationRequest::e_timeToLive))
			SetTimeToLive(rrq.m_timeToLive);

		// H.225.0v4: ignore fields other than rasAddress, endpointIdentifier,
		// timeToLive for a lightweightRRQ
		if (!(rrq.HasOptionalField(H225_RegistrationRequest::e_keepAlive) &&
			rrq.m_keepAlive.GetValue())) {
			if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)
				&& (rrq.m_terminalAlias.GetSize() >= 1))
				SetAliases(rrq.m_terminalAlias);
		}
	} else if (ras_msg.GetTag() == H225_RasMessage::e_locationConfirm) {
		const H225_LocationConfirm & lcf = ras_msg;
		SetRasAddress(lcf.m_rasAddress);
		if (lcf.HasOptionalField(H225_LocationConfirm::e_destinationInfo))
			SetAliases(lcf.m_destinationInfo);
	}
	PWaitAndSignal lock(m_usedLock);
	m_updatedTime = PTime();
}

// due to strange bug of gcc, I have to pass pointer instead of reference
bool EndpointRec::CompareAlias(const H225_ArrayOf_AliasAddress *a) const
{
	for (PINDEX i = 0; i < a->GetSize(); i++)
		for (PINDEX j = 0; j < m_terminalAliases.GetSize(); j++)
			if ((*a)[i] == m_terminalAliases[j])
				return true;
	return false;
}

EndpointRec *EndpointRec::Unregister()
{
	SendURQ(H225_UnregRequestReason::e_maintenance);
	return this;
}

EndpointRec *EndpointRec::Expired()
{
	SendURQ(H225_UnregRequestReason::e_ttlExpired);
	return this;
}

void EndpointRec::BuildLCF(H225_LocationConfirm & obj_lcf) const
{
	obj_lcf.m_callSignalAddress = GetCallSignalAddress();
	obj_lcf.m_rasAddress = GetRasAddress();
	obj_lcf.IncludeOptionalField(H225_LocationConfirm::e_destinationInfo);
	obj_lcf.m_destinationInfo = GetAliases();
	obj_lcf.IncludeOptionalField(H225_LocationConfirm::e_destinationType);
	obj_lcf.m_destinationType = GetEndpointType();
}

PString EndpointRec::PrintOn(bool verbose) const
{
	PString msg(PString::Printf, "%s|%s|%s|%s\r\n",
		    (const unsigned char *) AsDotString(GetCallSignalAddress()),
		    (const unsigned char *) AsString(GetAliases()),
		    (const unsigned char *) AsString(GetEndpointType()),
		    (const unsigned char *) GetEndpointIdentifier().GetValue() );
	if (verbose) {
		msg += GetUpdatedTime().AsString();
		if (m_timeToLive == 0)
			msg += " (permanent)";
		msg += PString(PString::Printf, " C(%d) <%d>\r\n", m_callCount, m_usedCount);
	}
	return msg;
}

bool EndpointRec::SendURQ(H225_UnregRequestReason::Choices reason)
{
	if (GetRasAddress().GetTag() != H225_TransportAddress::e_ipAddress)
		return false;  // no valid ras address

	static int RequestNum = 0;

	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_unregistrationRequest);
	H225_UnregistrationRequest & urq = ras_msg;
	urq.m_requestSeqNum.SetValue(++RequestNum);
	urq.IncludeOptionalField(urq.e_gatekeeperIdentifier);
	urq.m_gatekeeperIdentifier.SetValue( Toolkit::GKName() );
	urq.IncludeOptionalField(urq.e_endpointIdentifier);
	urq.m_endpointIdentifier = GetEndpointIdentifier();
	urq.m_callSignalAddress.SetSize(1);
	urq.m_callSignalAddress[0] = GetCallSignalAddress();
	urq.IncludeOptionalField(H225_UnregistrationRequest::e_reason);
	urq.m_reason.SetTag(reason);

	PString msg(PString::Printf, "URQ|%s|%s|%s;\r\n", 
			(const unsigned char *) AsDotString(GetRasAddress()),
			(const unsigned char *) GetEndpointIdentifier().GetValue(),
			(const unsigned char *) urq.m_reason.GetTagName());
        GkStatus::Instance()->SignalStatus(msg);

	RasThread->SendRas(ras_msg, GetRasAddress());
	return true;
}

GatewayRec::GatewayRec(const H225_RasMessage &completeRRQ, bool Permanent)
      : EndpointRec(completeRRQ, Permanent), defaultGW(false)
{
	Prefixes.reserve(8);
	GatewayRec::LoadConfig(); // static binding
}

void GatewayRec::SetAliases(const H225_ArrayOf_AliasAddress &a)
{
	EndpointRec::SetAliases(a);
	LoadConfig();
}

void GatewayRec::SetEndpointType(const H225_EndpointType &t)
{
	if (!t.HasOptionalField(H225_EndpointType::e_gateway)) {
		PTRACE(1, "RRJ: terminal type changed|" << (const unsigned char *)m_endpointIdentifier.GetValue());
		return;
	}
	EndpointRec::SetEndpointType(t);
	LoadConfig();
}

void GatewayRec::Update(const H225_RasMessage & ras_msg)
{
        if (ras_msg.GetTag() == H225_RasMessage::e_registrationRequest) {
		const H225_RegistrationRequest & rrq = ras_msg;
		if (!(rrq.HasOptionalField(H225_RegistrationRequest::e_keepAlive) &&
			rrq.m_keepAlive.GetValue()) && (*m_terminalType != rrq.m_terminalType)) {
			SetEndpointType(rrq.m_terminalType);
		}
	} else if (ras_msg.GetTag() == H225_RasMessage::e_locationConfirm) {
		const H225_LocationConfirm & lcf = ras_msg;
		if (lcf.HasOptionalField(H225_LocationConfirm::e_destinationType))
			SetEndpointType(lcf.m_destinationType);
	}
			
	EndpointRec::Update(ras_msg);
}

void GatewayRec::AddPrefixes(const H225_ArrayOf_SupportedProtocols &protocols)
{
	for (PINDEX i=0; i < protocols.GetSize(); i++) {
		H225_SupportedProtocols &p = protocols[i];
		if (p.GetTag() == H225_SupportedProtocols::e_voice) {
			H225_VoiceCaps &v = p;
			if (v.HasOptionalField(H225_VoiceCaps::e_supportedPrefixes))
				for (PINDEX s=0; s<v.m_supportedPrefixes.GetSize(); s++) {
					H225_AliasAddress &a = v.m_supportedPrefixes[s].m_prefix;
					if (a.GetTag() == H225_AliasAddress::e_dialedDigits)
						Prefixes.push_back((const char *)AsString(a, false));
				}

		}
	}
}

void GatewayRec::SortPrefixes()
{
	// remove duplicate aliases
	sort(Prefixes.begin(), Prefixes.end(), greater<string>());
	prefix_iterator Iter = unique(Prefixes.begin(), Prefixes.end());
	Prefixes.erase(Iter, Prefixes.end());
	defaultGW = (find_if(Prefixes.begin(), Prefixes.end(), bind2nd(equal_to<string>(), "*")) != Prefixes.end());
}

bool GatewayRec::LoadConfig()
{
	PWaitAndSignal lock(m_usedLock);
	Prefixes.clear();
	if (m_terminalType->m_gateway.HasOptionalField(H225_GatewayInfo::e_protocol))
		AddPrefixes(m_terminalType->m_gateway.m_protocol);
	for (PINDEX i=0; i<m_terminalAliases.GetSize(); i++) {
		PStringArray p = (GkConfig()->GetString("RasSvr::GWPrefixes",
				  H323GetAliasAddressString(m_terminalAliases[i]), "")
				 ).Tokenise(" ,;\t\n", false);
		for (PINDEX s=0; s<p.GetSize(); s++)
			Prefixes.push_back((const char *)p[s]);
	}
	SortPrefixes();
	return true;
}

int GatewayRec::PrefixMatch(const H225_ArrayOf_AliasAddress &a) const
{
	int maxlen = (defaultGW) ? 0 : -1;
	for (PINDEX i = 0; i < a.GetSize(); i++)
		if (a[i].GetTag() == H225_AliasAddress::e_dialedDigits) {
			PString AliasStr = H323GetAliasAddressString(a[i]);
			const_prefix_iterator Iter = Prefixes.begin(), eIter= Prefixes.end();
			while (Iter != eIter) {
				int len = Iter->length();
				if ((maxlen < len) && (strncmp(AliasStr, Iter->c_str(), len)==0)) {
					PTRACE(2, ANSI::DBG << "Gateway " << (const unsigned char *)m_endpointIdentifier.GetValue() << " match " << Iter->c_str() << ANSI::OFF);
					maxlen = len;
				}
				++Iter;
			}
		}
	return maxlen;
}

void GatewayRec::BuildLCF(H225_LocationConfirm & obj_lcf) const
{
	EndpointRec::BuildLCF(obj_lcf);
	if (PINDEX as = Prefixes.size()) {
		obj_lcf.IncludeOptionalField(H225_LocationConfirm::e_supportedProtocols);
		obj_lcf.m_supportedProtocols.SetSize(1);
		H225_SupportedProtocols &protocol = obj_lcf.m_supportedProtocols[0];
		protocol.SetTag(H225_SupportedProtocols::e_voice);
		((H225_VoiceCaps &)protocol).m_supportedPrefixes.SetSize(as);
		const_prefix_iterator Iter = Prefixes.begin();
		for (PINDEX p=0; p < as; ++p, ++Iter)
			H323SetAliasAddress(Iter->c_str(), ((H225_VoiceCaps &)protocol).m_supportedPrefixes[p].m_prefix);
	}
}

PString GatewayRec::PrintOn(bool verbose) const
{
	PString msg = EndpointRec::PrintOn(verbose);
	if (verbose) {
		msg += "Prefixes: ";
		if (Prefixes.size() == 0) {
			msg += "<none>";
		} else {
			string m=Prefixes.front();
			const_prefix_iterator Iter = Prefixes.begin(), eIter= Prefixes.end();
			while (++Iter != eIter)
				m += "," + (*Iter);
			msg += m.c_str();
		}
		msg += "\r\n";
	}
	return msg;
}

OuterZoneEPRec::OuterZoneEPRec(const H225_RasMessage & completeLCF, const H225_EndpointIdentifier &epID) : EndpointRec(completeLCF, false)
{
	m_endpointIdentifier = epID;
	PTRACE(1, "New OZEP|" << PrintOn(false));
}

OuterZoneGWRec::OuterZoneGWRec(const H225_RasMessage & completeLCF, const H225_EndpointIdentifier &epID) : GatewayRec(completeLCF, false)
{
	m_endpointIdentifier = epID;

	const H225_LocationConfirm & obj_lcf = completeLCF;
	if (obj_lcf.HasOptionalField(H225_LocationConfirm::e_supportedProtocols)) {
		AddPrefixes(obj_lcf.m_supportedProtocols);
		SortPrefixes();
	}
	defaultGW = false; // don't let outer zone gateway be default
	PTRACE(1, "New OZGW|" << PrintOn(false));
}


RegistrationTable::RegistrationTable()
{
	srand(time(0));
	recCnt = rand()%9000+1000;

	LoadConfig();
}

RegistrationTable::~RegistrationTable()
{
	ClearTable();
	for_each(RemovedList.begin(), RemovedList.end(), delete_ep);
}

endptr RegistrationTable::InsertRec(H225_RasMessage & ras_msg)
{
	switch (ras_msg.GetTag())
	{
		case H225_RasMessage::e_registrationRequest: {
			H225_RegistrationRequest & rrq = ras_msg;
			if (endptr ep = FindBySignalAdr(rrq.m_callSignalAddress[0])) {
				ep->Update(ras_msg);
				return ep;
			} else
				return InternalInsertEP(ras_msg);
		}
		case H225_RasMessage::e_locationConfirm: {
			H225_LocationConfirm & lcf = ras_msg;
			endptr ep = InternalFind(compose1(bind2nd(equal_to<H225_TransportAddress>(), lcf.m_callSignalAddress), mem_fun(&EndpointRec::GetCallSignalAddress)), &OuterZoneList);
			if (ep) {
				ep->Update(ras_msg);
				return ep;
			} else
				return InternalInsertOZEP(ras_msg);
		}
	}

	PTRACE(1, "RegistrationTable: unable to insert " << ras_msg.GetTagName());
	return endptr(0);
}

endptr RegistrationTable::InternalInsertEP(H225_RasMessage & ras_msg)
{
	H225_RegistrationRequest & rrq = ras_msg;
	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier)) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
		endptr e = InternalFind(compose1(bind2nd(equal_to<H225_TransportAddress>(), rrq.m_callSignalAddress[0]),
			mem_fun(&EndpointRec::GetCallSignalAddress)), &RemovedList);
		if (e) // re-use the old endpoint identifier
			rrq.m_endpointIdentifier = e->GetEndpointIdentifier();
		else
			GenerateEndpointId(rrq.m_endpointIdentifier);
	}
	if (!(rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) && (rrq.m_terminalAlias.GetSize() >= 1))) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_terminalAlias);
		GenerateAlias(rrq.m_terminalAlias, rrq.m_endpointIdentifier);
	}

	EndpointRec *ep = rrq.m_terminalType.HasOptionalField(H225_EndpointType::e_gateway) ?
			  new GatewayRec(ras_msg) : new EndpointRec(ras_msg);
	WriteLock lock(listLock);
	EndpointList.push_back(ep);
	return endptr(ep);
}

endptr RegistrationTable::InternalInsertOZEP(H225_RasMessage & ras_msg)
{
	static int ozCnt = 1000; // arbitrary chosen constant
	H225_EndpointIdentifier epID;
	epID = "oz_" + PString(PString::Unsigned, ozCnt++) + endpointIdSuffix;

	H225_LocationConfirm & lcf = ras_msg;
	EndpointRec *ep;
	if (lcf.HasOptionalField(H225_LocationConfirm::e_destinationType) &&
	    lcf.m_destinationType.HasOptionalField(H225_EndpointType::e_gateway))
		ep = new OuterZoneGWRec(ras_msg, epID);
	else
		ep = new OuterZoneEPRec(ras_msg, epID);

	WriteLock lock(listLock);
	OuterZoneList.push_front(ep);
	return endptr(ep);
}

void RegistrationTable::RemoveByEndptr(const endptr & eptr)
{
	EndpointRec *ep = eptr.operator->(); // evil
	WriteLock lock(listLock);
	if (ep) {
		RemovedList.push_back(ep);
		EndpointList.remove(ep);
	}
}

void RegistrationTable::RemoveByEndpointId(const H225_EndpointIdentifier & epId)
{
	WriteLock lock(listLock);
	iterator Iter = find_if(EndpointList.begin(), EndpointList.end(),
			compose1(bind2nd(equal_to<H225_EndpointIdentifier>(), epId),
			mem_fun(&EndpointRec::GetEndpointIdentifier)));
	if (Iter != EndpointList.end()) {
		RemovedList.push_back(*Iter);
		EndpointList.erase(Iter);	// list<> is O(1), slist<> O(n) here
	} else {
	        PTRACE(1, "Warning: RemoveByEndpointId " << epId << " failed.");
	}
}

/*
template<class F> endptr RegistrationTable::InternalFind(const F & FindObject,
	const list<EndpointRec *> *List) const
{
	ReadLock lock(listLock);
	const_iterator Iter = find_if(List->begin(), List->end(), FindObject);
	return endptr((Iter != List->end()) ? *Iter : NULL);
}
*/

endptr RegistrationTable::FindByEndpointId(const H225_EndpointIdentifier & epId) const
{
	return InternalFind(compose1(bind2nd(equal_to<H225_EndpointIdentifier>(), epId),
			mem_fun(&EndpointRec::GetEndpointIdentifier)));
}

endptr RegistrationTable::FindBySignalAdr(const H225_TransportAddress &sigAd) const
{
	return InternalFind(compose1(bind2nd(equal_to<H225_TransportAddress>(), sigAd),
			mem_fun(&EndpointRec::GetCallSignalAddress)));
}

endptr RegistrationTable::FindByAliases(const H225_ArrayOf_AliasAddress & alias) const
{
	return InternalFind(bind2nd(mem_fun(&EndpointRec::CompareAlias), &alias));
}

endptr RegistrationTable::FindEndpoint(const H225_ArrayOf_AliasAddress & alias, bool s)
{
	endptr ep = InternalFindEP(alias, &EndpointList);
	return (ep) ? ep : s ? InternalFindEP(alias, &OuterZoneList) : endptr(0);
}

endptr RegistrationTable::InternalFindEP(const H225_ArrayOf_AliasAddress & alias,
	list<EndpointRec *> *List)
{
	endptr ep = InternalFind(bind2nd(mem_fun(&EndpointRec::CompareAlias), &alias), List);
        if (ep) {
                PTRACE(4, "Alias match for EP " << AsDotString(ep->GetCallSignalAddress()));
                return ep;
        }

        int maxlen = 0;
        list<EndpointRec *> GWlist;
        listLock.StartRead();
        const_iterator Iter = List->begin(), IterLast = List->end();
        while (Iter != IterLast) {
                if ((*Iter)->IsGateway()) {
                        int len = dynamic_cast<GatewayRec *>(*Iter)->PrefixMatch(alias);
                        if (maxlen < len) {
                                GWlist.clear();
                                maxlen = len;
                        }
                        if (maxlen == len)
                                GWlist.push_back(*Iter);
                }
                ++Iter;
        }
        listLock.EndRead();

        if (GWlist.size() > 0) {
                EndpointRec *e = GWlist.front();
                if (GWlist.size() > 1) {
                        PTRACE(3, ANSI::DBG << "Prefix apply round robin" << ANSI::OFF);
                        WriteLock lock(listLock);
                        List->remove(e);
                        List->push_back(e);
                }
                PTRACE(4, "Alias match for GW " << AsDotString(e->GetCallSignalAddress()));
                return endptr(e);
        }
        return endptr(0);
}

void RegistrationTable::GenerateEndpointId(H225_EndpointIdentifier & NewEndpointId)
{
	NewEndpointId = PString(PString::Unsigned, ++recCnt) + endpointIdSuffix;
}


void RegistrationTable::GenerateAlias(H225_ArrayOf_AliasAddress & AliasList, const H225_EndpointIdentifier & endpointId) const
{
	AliasList.SetSize(1);
	H323SetAliasAddress(endpointId, AliasList[0]);
}

void RegistrationTable::PrintAllRegistrations(GkStatus::Client &client, BOOL verbose)
{
	PString msg("AllRegistrations\r\n");
	InternalPrint(client, verbose, &EndpointList, msg);
}

void RegistrationTable::PrintAllCached(GkStatus::Client &client, BOOL verbose)
{
	PString msg("AllCached\r\n");
	InternalPrint(client, verbose, &OuterZoneList, msg);
}

void RegistrationTable::PrintRemoved(GkStatus::Client &client, BOOL verbose)
{
	PString msg("AllRemoved\r\n");
	InternalPrint(client, verbose, &RemovedList, msg);
}

void RegistrationTable::InternalPrint(GkStatus::Client &client, BOOL verbose, list<EndpointRec *> * List, PString & msg)
{
	// copy the pointers into a temporary array to avoid large lock
	listLock.StartRead();
	const_iterator IterLast = List->end();
	unsigned k =0, s = List->size();
	endptr *eptr = new endptr[s];
	for (const_iterator Iter = List->begin(); Iter != IterLast; ++Iter)
		eptr[k++] = endptr(*Iter);
	listLock.EndRead();
	// end of lock

	if (s > 1000) // set buffer to avoid reallocate
		msg.SetSize(s * (verbose ? 200 : 100));
	for (k = 0; k < s; k++)
		msg += "RCF|" + eptr[k]->PrintOn(verbose);
	delete [] eptr;

	msg += PString(PString::Printf, "Number of Endpoints: %u\r\n;\r\n", s);
	client.WriteString(msg);
	//PTRACE(2, msg);
}

void RegistrationTable::InternalStatistics(const list<EndpointRec *> *List, unsigned & s, unsigned & t, unsigned & g) const
{
	ReadLock lock(listLock);
	s = List->size(), t = 0, g = 0;
	const_iterator IterLast = List->end();
	for (const_iterator Iter = List->begin(); Iter != IterLast; ++Iter)
		((*Iter)->IsGateway() ? g : t)++;
}

PString RegistrationTable::PrintStatistics() const
{
	unsigned es, et, eg;
	InternalStatistics(&EndpointList, es, et, eg);
	unsigned cs, ct, cg;
	InternalStatistics(&OuterZoneList, cs, ct, cg);

	return PString(PString::Printf, "-- Endpoint Statistics --\r\n"
		"Total Endpoints: %u  Terminals: %u  Gateways: %u\r\n"
		"Cached Endpoints: %u  Terminals: %u  Gateways: %u\r\n",
		es, et, eg, cs, ct, cg);
}

namespace { // end of anonymous namespace

void SetIpAddress(const PString &ipAddress, H225_TransportAddress & address)
{
	address.SetTag(H225_TransportAddress::e_ipAddress);
	H225_TransportAddress_ipAddress & ip = address;
	PIPSocket::Address addr;
	PString ipAddr = ipAddress.Trim();
	PINDEX p=ipAddr.Find(':');
	PIPSocket::GetHostAddress(ipAddr.Left(p), addr);
	ip.m_ip[0] = addr.Byte1();
	ip.m_ip[1] = addr.Byte2();
	ip.m_ip[2] = addr.Byte3();
	ip.m_ip[3] = addr.Byte4();
	ip.m_port = (p != P_MAX_INDEX) ? ipAddr.Mid(p+1).AsUnsigned() : GK_DEF_ENDPOINT_SIGNAL_PORT;
}

} // end of anonymous namespace

void RegistrationTable::LoadConfig()
{
	endpointIdSuffix = GkConfig()->GetString("EndpointIDSuffix", "_endp");

	// Load permanent endpoints
	PStringToString cfgs=GkConfig()->GetAllKeyValues("RasSvr::PermanentEndpoints");
	for (PINDEX i=0; i < cfgs.GetSize(); i++) {
		EndpointRec *ep;
		H225_RasMessage rrq_ras;
		rrq_ras.SetTag(H225_RasMessage::e_registrationRequest);
		H225_RegistrationRequest &rrq = rrq_ras;

		rrq.m_callSignalAddress.SetSize(1);
		SetIpAddress(cfgs.GetKeyAt(i), rrq.m_callSignalAddress[0]);
		// is the endpoint exist?
		if (endptr e = FindBySignalAdr(rrq.m_callSignalAddress[0])) {
			e->SetPermanent();
			PTRACE(3, "Endpoint " << AsDotString(rrq.m_callSignalAddress[0]) << " exists, ignore!");
			continue;
		}

		// a permanent endpoint may not support RAS
		// we set an arbitrary address here
		rrq.m_rasAddress.SetSize(1);
		rrq.m_rasAddress[0] = rrq.m_callSignalAddress[0];

		rrq.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
		GenerateEndpointId(rrq.m_endpointIdentifier);

		rrq.IncludeOptionalField(rrq.e_terminalAlias);
		PStringArray sp=cfgs.GetDataAt(i).Tokenise(";", FALSE);
		PStringArray aa=sp[0].Tokenise(",", FALSE);
		PINDEX as=aa.GetSize();
		if (as > 0) {
			rrq.m_terminalAlias.SetSize(as);
			for (PINDEX p=0; p<as; p++)
				H323SetAliasAddress(aa[p], rrq.m_terminalAlias[p]);
        	}
		// GatewayInfo
		if (sp.GetSize() > 1) {
			aa=sp[1].Tokenise(",", FALSE);
			as=aa.GetSize();
			if (as > 0) {
				rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_gateway);
				rrq.m_terminalType.m_gateway.IncludeOptionalField(H225_GatewayInfo::e_protocol);
				rrq.m_terminalType.m_gateway.m_protocol.SetSize(1);
				H225_SupportedProtocols &protocol=rrq.m_terminalType.m_gateway.m_protocol[0];
				protocol.SetTag(H225_SupportedProtocols::e_voice);
				((H225_VoiceCaps &)protocol).m_supportedPrefixes.SetSize(as);
				for (PINDEX p=0; p<as; p++)
					H323SetAliasAddress(aa[p], ((H225_VoiceCaps &)protocol).m_supportedPrefixes[p].m_prefix);
			}
			ep = new GatewayRec(rrq_ras, true);
                } else {
			rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_terminal);
			ep = new EndpointRec(rrq_ras, true);
		}

		PTRACE(2, "Add permanent endpoint " << AsDotString(rrq.m_callSignalAddress[0]));
		WriteLock lock(listLock);
		EndpointList.push_back(ep);
        }

	// Load config for each endpoint
	ReadLock lock(listLock);
	for_each(EndpointList.begin(), EndpointList.end(),
		 mem_fun(&EndpointRec::LoadConfig));
}

void RegistrationTable::ClearTable()
{
	WriteLock lock(listLock);
	// Unregister all endpoints, and move the records into RemovedList
	transform(EndpointList.begin(), EndpointList.end(),
		back_inserter(RemovedList), mem_fun(&EndpointRec::Unregister));
	EndpointList.clear();
	copy(OuterZoneList.begin(), OuterZoneList.end(), back_inserter(RemovedList));
	OuterZoneList.clear();
}

void RegistrationTable::CheckEndpoints()
{
	PTime now;
	WriteLock lock(listLock);

	iterator Iter = partition(EndpointList.begin(), EndpointList.end(),
			bind2nd(mem_fun(&EndpointRec::IsUpdated), &now));
#ifdef PTRACING
	if (ptrdiff_t s = distance(Iter, EndpointList.end()))
		PTRACE(2, s << " endpoint(s) expired.");
#endif
	transform(Iter, EndpointList.end(), back_inserter(RemovedList),
		mem_fun(&EndpointRec::Expired));
	EndpointList.erase(Iter, EndpointList.end());

	Iter = partition(OuterZoneList.begin(), OuterZoneList.end(),
		bind2nd(mem_fun(&EndpointRec::IsUpdated), &now));
#ifdef PTRACING
	if (ptrdiff_t s = distance(Iter, OuterZoneList.end()))
		PTRACE(2, s << " outerzone endpoint(s) expired.");
#endif
	copy(Iter, OuterZoneList.end(), back_inserter(RemovedList));
	OuterZoneList.erase(Iter, OuterZoneList.end());

	// Cleanup unused EndpointRec in RemovedList
	Iter = partition(RemovedList.begin(), RemovedList.end(), mem_fun(&EndpointRec::IsUsed));
	for_each(Iter, RemovedList.end(), delete_ep);
	RemovedList.erase(Iter, RemovedList.end());
}

CallRec::CallRec(const H225_CallIdentifier & CallId,
		 const H225_ConferenceIdentifier & ConfId,
		 const PString & destInfo,
		 const PString & srcInfo,
		 int Bandwidth)
      : m_callIdentifier(CallId), m_conferenceIdentifier(ConfId),
	m_destInfo(destInfo),
	m_srcInfo(srcInfo), // added (MM 05.11.01)
	m_bandWidth(Bandwidth), m_CallNumber(0),
	m_callingCRV(0), m_calledCRV(0),
	m_startTime(0), m_timeout(0),
	m_callingSocket(0), m_calledSocket(0),
	m_usedCount(0)
{
}

CallRec::~CallRec()
{
	SetConnected(false);
	PTRACE(5, "Gk\tDelete Call No. " << m_CallNumber);
}

void CallRec::SetConnected(bool c)
{
	PTime *ts = (c) ? new PTime : 0;
	delete m_startTime;
	if ((m_startTime = ts) != 0)
		StartTimer();
	else
		StopTimer();
}

void CallRec::StartTimer()
{
	if (m_timeout > 0) {
		PWaitAndSignal lock(m_usedLock);
		m_timer = PTime();
//		m_timer = new PTimer(0, m_timeout);
//		m_timer->SetNotifier(PCREATE_NOTIFIER(OnTimeout));
	}
}

void CallRec::StopTimer()
{
	PWaitAndSignal lock(m_usedLock);
	m_timeout = 0;
}

/*
void CallRec::OnTimeout()
{
	PTRACE(2, "GK\tCall No. " << m_CallNumber << " timeout!");
	Disconnect();
}
*/

void CallRec::InternalSetEP(endptr & ep, unsigned & crv, const endptr & nep, unsigned ncrv)
{
	if (ep != nep) {
		if (ep)
			ep->RemoveCall();
		m_usedLock.Wait();
		ep = nep, crv = ncrv;
		m_usedLock.Signal();
		if (ep)
			ep->AddCall();
	}
}

void CallRec::RemoveAll()
{
	if (m_Calling)
		m_Calling->RemoveCall();
	if (m_Called)
		m_Called->RemoveCall();
}

void CallRec::RemoveSocket()
{
	if (m_callingSocket) {
		m_callingSocket->SetDeletable();
		m_callingSocket = 0;
	}
//	if (m_calledSocket)
//		m_calledSocket->SetDeletable();
}

int CallRec::CountEndpoints() const
{
	PWaitAndSignal lock(m_usedLock);
	int result = 0;
	if (m_Calling)
		++result;
	if (m_Called)
		++result;
	return result;
}

void CallRec::Disconnect(bool force)
{
	if (force && (m_callingSocket || m_calledSocket)) {
		if (m_callingSocket)
			m_callingSocket->EndSession();
		if (m_calledSocket)
			m_calledSocket->EndSession();
	} else {
		SendDRQ();
	}

	PTRACE(2, "Gk\tDisconnect Call No. " << m_CallNumber);
}

void CallRec::SendDRQ()
{
	// this is the only place we are _generating_ sequence numbers at the moment
	static int RequestNum = 0;

	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_disengageRequest);
	H225_DisengageRequest & drq = ras_msg;
	drq.m_requestSeqNum.SetValue(++RequestNum);
	drq.m_disengageReason.SetTag(H225_DisengageReason::e_forcedDrop);
	drq.m_conferenceID = m_conferenceIdentifier;
	drq.IncludeOptionalField(H225_DisengageRequest::e_callIdentifier);
	drq.m_callIdentifier = m_callIdentifier;
	drq.IncludeOptionalField(H225_DisengageRequest::e_gatekeeperIdentifier);
	drq.m_gatekeeperIdentifier = Toolkit::GKName();

// Warning: For an outer zone endpoint, the endpoint identifier may not correct
	if (m_Calling) {
		drq.m_endpointIdentifier = m_Calling->GetEndpointIdentifier();
		drq.m_callReferenceValue = m_callingCRV;
		RasThread->SendRas(ras_msg, m_Calling->GetRasAddress());
	}
	if (m_Called) {
		drq.m_endpointIdentifier = m_Called->GetEndpointIdentifier();
		drq.m_callReferenceValue = m_calledCRV;
		RasThread->SendRas(ras_msg, m_Called->GetRasAddress());
	}
}

namespace { // end of anonymous namespace

PString GetEPString(const endptr & ep)
{
	if (ep) {
		return PString(PString::Printf, "%s|%s",
			(const char *)AsDotString(ep->GetCallSignalAddress()),
			(const char *)ep->GetEndpointIdentifier().GetValue());
	}
	return PString(" | ");
}

} // end of anonymous namespace

PString CallRec::GenerateCDR() const
{
	PString timeString;
	PTime endTime;
	if (m_startTime != 0) {
		PTimeInterval callDuration = endTime - *m_startTime;
		timeString = PString(PString::Printf, "%ld|%s|%s",
			callDuration.GetSeconds(),
			(const char *)m_startTime->AsString(),
			(const char *)endTime.AsString()
		);
	} else {
		timeString = "0|unconnected|" + endTime.AsString();
	}

	return PString(PString::Printf, "CDR|%d|%s|%s|%s|%s|%s|%s|%s;\r\n",
		m_CallNumber,
		(const char *)AsString(m_callIdentifier.m_guid),
		(const char *)timeString,
		(const char *)GetEPString(m_Calling),
		(const char *)GetEPString(m_Called),
		(const char *)m_destInfo,
		(const char *)m_srcInfo,
		(const char *)Toolkit::Instance()->GKName()
	);
}

PString CallRec::PrintOn(bool verbose) const
{
	int left = (m_timeout > 0 ) ? m_timeout - (PTime() - m_timer).GetSeconds() : 0;
	PString result(PString::Printf,
		"Call No. %d | CallID %s | %d\r\nDial %s\r\nACF|%s|%d\r\nACF|%s|%d\r\n",
		m_CallNumber, (const char *)AsString(m_callIdentifier.m_guid), left,
		(const char *)m_destInfo,
		(const char *)GetEPString(m_Calling), m_callingCRV,
		(const char *)GetEPString(m_Called), m_calledCRV
	);
	if (verbose) {
		result += PString(PString::Printf, "# %s|%s|%d|%s <%d>\r\n",
				(m_Calling) ? (const char *)AsString(m_Calling->GetAliases()) : "?",
				(m_Called) ? (const char *)AsString(m_Called->GetAliases()) : "?",
				m_bandWidth,
				(m_startTime) ? (const char *)m_startTime->AsString() : "unconnected",
				m_usedCount
			  );
	}

	return result;
}


CallTable::CallTable() : m_CallNumber(1)
{
	LoadConfig();
	m_CallCount = m_successCall = m_neighborCall = 0;
}

CallTable::~CallTable()
{
        for_each(CallList.begin(), CallList.end(),
		bind1st(mem_fun(&CallTable::InternalRemovePtr), this));
        for_each(RemovedList.begin(), RemovedList.end(), delete_call);
}

void CallTable::LoadConfig()
{
	m_genNBCDR = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "GenerateNBCDR", "1"));
	m_genUCCDR = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "GenerateUCCDR", "0"));
}

void CallTable::Insert(CallRec * NewRec)
{
	PTRACE(3, "CallTable::Insert(CALL) Call No. " << m_CallNumber);
	NewRec->SetCallNumber(m_CallNumber++);
	WriteLock lock(listLock);
	CallList.push_back(NewRec);
	++m_CallCount;
}

callptr CallTable::FindCallRec(const H225_CallIdentifier & CallId) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareCallId), &CallId));
}

callptr CallTable::FindCallRec(const H225_CallReferenceValue & CallRef) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareCRV), CallRef.GetValue()));
}

callptr CallTable::FindCallRec(PINDEX CallNumber) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareCallNumber), CallNumber));
}

callptr CallTable::FindCallRec(const endptr & ep) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareEndpoint), &ep));
}

callptr CallTable::FindBySignalAdr(const H225_TransportAddress & SignalAdr) const
{
	return InternalFind(bind2nd(mem_fun(&CallRec::CompareSigAdr), &SignalAdr));
}

void CallTable::CheckCalls()
{
	PTime now;
	WriteLock lock(listLock);
	iterator Iter = CallList.begin(), eIter = CallList.end();
	while (Iter != eIter) {
		iterator i = Iter++;
		if ((*i)->IsTimeout(&now)) {
			(*i)->Disconnect();
			InternalRemove(i);
		}
	}
}

void CallTable::RemoveCall(const H225_DisengageRequest & obj_drq)
{
	if (obj_drq.HasOptionalField(H225_DisengageRequest::e_callIdentifier))
		InternalRemove(obj_drq.m_callIdentifier);
	else
		InternalRemove(obj_drq.m_callReferenceValue.GetValue());
}

void CallTable::RemoveCall(const callptr & call)
{
	if (call)
		InternalRemovePtr(call.operator->());
}

bool CallTable::InternalRemovePtr(CallRec *call)
{
	PTRACE(6, ANSI::PIN << "GK\tRemoving callptr:" << AsString(call->GetCallIdentifier().m_guid) << "...\n" << ANSI::OFF);
	WriteLock lock(listLock);
	InternalRemove(find(CallList.begin(), CallList.end(), call));
	return true; // useless, workaround for VC
}

void CallTable::InternalRemove(const H225_CallIdentifier & CallId)
{
	PTRACE(5, ANSI::PIN << "GK\tRemoving CallId:" << AsString(CallId.m_guid) << "...\n" << ANSI::OFF);
	WriteLock lock(listLock);
	InternalRemove(
		find_if(CallList.begin(), CallList.end(),
		bind2nd(mem_fun(&CallRec::CompareCallId), &CallId))
	);
}

void CallTable::InternalRemove(unsigned CallRef)
{
	PTRACE(5, ANSI::PIN << "GK\tRemoving CallRef:" << CallRef << "...\n" << ANSI::OFF);
	WriteLock lock(listLock);
	InternalRemove(
		find_if(CallList.begin(), CallList.end(),
		bind2nd(mem_fun(&CallRec::CompareCRV), CallRef))
	);
}

void CallTable::InternalRemove(iterator Iter)
{
	if (Iter == CallList.end()) {
		return;
	}

	CallRec *call = *Iter;
	if ((m_genNBCDR || call->GetCallingAddress()) && (m_genUCCDR || call->IsConnected())) {
		PString cdrString(call->GenerateCDR());
		GkStatus::Instance()->SignalStatus(cdrString, 1);
		PTRACE(3, cdrString);
#ifdef PTRACING
	} else {
		if (!call->IsConnected())
			PTRACE(2, "CDR\tignore not connected call");
		else	
			PTRACE(2, "CDR\tignore caller from neighbor");
#endif
	}

	if (call->IsConnected())
		++m_successCall;
	if (call->GetCallingAddress() == 0)
		++m_neighborCall;

//	call->StopTimer();
	call->RemoveAll();
	call->RemoveSocket();

	RemovedList.push_back(call);
	CallList.erase(Iter);

	Iter = partition(RemovedList.begin(), RemovedList.end(), mem_fun(&CallRec::IsUsed));
	for_each(Iter, RemovedList.end(), delete_call);
	RemovedList.erase(Iter, RemovedList.end());
}

void CallTable::InternalStatistics(unsigned & n, unsigned & act, unsigned & nb, PString & msg, BOOL verbose) const
{
	ReadLock lock(listLock);
	n = CallList.size(), act = 0, nb = 0;
	const_iterator eIter = CallList.end();
	for (const_iterator Iter = CallList.begin(); Iter != eIter; ++Iter) {
		if ((*Iter)->IsConnected())
			++act;
		if ((*Iter)->GetCallingAddress() == 0) // from neighbors
			++nb;
		if (!msg)
			msg += (*Iter)->PrintOn(verbose);
	}
}

void CallTable::PrintCurrentCalls(GkStatus::Client & client, BOOL verbose) const
{
	PString msg = "CurrentCalls\r\n";
	unsigned n, act, nb;
	InternalStatistics(n, act, nb, msg, verbose);
	
	msg += PString(PString::Printf, "Number of Calls: %u Active: %u From NB: %u\r\n;\r\n", n, act, nb);
	client.WriteString(msg);
	//PTRACE(2, msg);
}

PString CallTable::PrintStatistics() const
{
	PString dumb;
	unsigned n, act, nb;
	InternalStatistics(n, act, nb, dumb, FALSE);

	return PString(PString::Printf, "-- Call Statistics --\r\n"
		"Current Calls: %u Active: %u From Neighbor: %u\r\n"
		"Total Calls: %u  Successful: %u  From Neighbor: %u\r\n",
		n, act, nb,
		m_CallCount, m_successCall, m_neighborCall);
}
