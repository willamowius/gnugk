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
#include "ANSI.h"		// ansi terminal codes
#include "h323util.h"
#include "Toolkit.h"
#include "SoftPBX.h"
#include "RasListener.h"
#include "GkClient.h"
#include "stl_supp.h"
#include "ProxyChannel.h"
#include "gk_const.h"
#include "gkDatabase.h"
#include "version.h"		// versioning information

#ifdef HAS_LDAP
# include "ldaplink.h"
# include "gkldap.h"
#endif

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = RASTBL_H;
#endif /* lint */

const char *CallTableSection = "CallTable";

EndpointRec::EndpointRec(const H225_RasMessage &completeRAS, bool Permanent)
	:        m_RasMsg(completeRAS), m_timeToLive(1), m_activeCall(0), m_totalCall(0), m_pollCount(2), m_usedCount(0), m_nat(false)
{
	switch (m_RasMsg.GetTag())
	{
	case H225_RasMessage::e_registrationRequest:
		SetEndpointRec((H225_RegistrationRequest &)m_RasMsg);
		PTRACE(1, "New EP|" << PrintOn(false));
		break;
	case H225_RasMessage::e_admissionRequest:
		SetEndpointRec((H225_AdmissionRequest &)m_RasMsg);
		break;
	case H225_RasMessage::e_admissionConfirm:
		SetEndpointRec((H225_AdmissionConfirm &)m_RasMsg);
		break;
	case H225_RasMessage::e_locationConfirm:
		SetEndpointRec((H225_LocationConfirm &)m_RasMsg);
		break;
	default: // should not happen
		break;
	}
	if (Permanent)
		m_timeToLive = 0;
}

void EndpointRec::SetEndpointRec(H225_RegistrationRequest & rrq)
{
        if (rrq.m_rasAddress.GetSize() > 0)
                m_rasAddress = rrq.m_rasAddress[0];
        else
                m_rasAddress.SetTag(H225_TransportAddress::e_nonStandardAddress
);
        if (rrq.m_callSignalAddress.GetSize() > 0)
                m_callSignalAddress = rrq.m_callSignalAddress[0];
        else
                m_callSignalAddress.SetTag(H225_TransportAddress::e_nonStandardAddress);
        m_endpointIdentifier = rrq.m_endpointIdentifier;
        m_terminalAliases = rrq.m_terminalAlias;
        m_terminalType = &rrq.m_terminalType;
        if (rrq.HasOptionalField(H225_RegistrationRequest::e_timeToLive))
                SetTimeToLive(rrq.m_timeToLive);
        else
                SetTimeToLive(SoftPBX::TimeToLive);
        m_fromParent = false;
}

void EndpointRec::SetEndpointRec(H225_AdmissionRequest & arq)
{
	static H225_EndpointType termType; // nouse
	// we set it to non-standard address to avoid misuse
	m_rasAddress.SetTag(H225_TransportAddress::e_nonStandardAddress);
	m_callSignalAddress = arq.m_destCallSignalAddress;
	m_terminalType = &termType;
	m_timeToLive = (SoftPBX::TimeToLive > 0) ? SoftPBX::TimeToLive : 600;
	m_fromParent = true;
}

void EndpointRec::SetEndpointRec(H225_AdmissionConfirm & acf)
{
       // there is no RAS address in ACF
       // we set it to non-standard address to avoid misuse
       m_rasAddress.SetTag(H225_TransportAddress::e_nonStandardAddress);
       m_callSignalAddress = acf.m_destCallSignalAddress;
       if (acf.HasOptionalField(H225_AdmissionConfirm::e_destinationInfo))
               m_terminalAliases = acf.m_destinationInfo;
       if (!acf.HasOptionalField(H225_AdmissionConfirm::e_destinationType))
               acf.IncludeOptionalField(H225_AdmissionConfirm::e_destinationType);
       m_terminalType = &acf.m_destinationType;
       m_timeToLive = (SoftPBX::TimeToLive > 0) ? SoftPBX::TimeToLive : 600;
       m_fromParent = true;
}

void EndpointRec::SetEndpointRec(H225_LocationConfirm & lcf)
{
        m_rasAddress = lcf.m_rasAddress;
        m_callSignalAddress = lcf.m_callSignalAddress;
        if (lcf.HasOptionalField(H225_LocationConfirm::e_destinationInfo))
                m_terminalAliases = lcf.m_destinationInfo;
        if (!lcf.HasOptionalField(H225_LocationConfirm::e_destinationType))
                lcf.IncludeOptionalField(H225_LocationConfirm::e_destinationType);
        m_terminalType = &lcf.m_destinationType;
        m_timeToLive = (SoftPBX::TimeToLive > 0) ? SoftPBX::TimeToLive : 600;
        m_fromParent = false;
}

EndpointRec::~EndpointRec()
{
	PTRACE(3, "remove endpoint: " << (const unsigned char *)m_endpointIdentifier.GetValue() << " " << m_usedCount);
}

bool EndpointRec::GetH323ID(H225_AliasAddress &id) {
	PWaitAndSignal lock(m_usedLock);
	const H225_ArrayOf_AliasAddress & aliases = GetAliases();
        for (PINDEX i = 0; i < aliases.GetSize(); i++) {
               if (aliases[i].GetTag() == H225_AliasAddress::e_h323_ID) {
                       id = aliases[i];
		       return TRUE;
	       }
        }
	return FALSE;
}

BOOL EndpointRec::AliasIsIncomplete(const H225_AliasAddress & alias, BOOL &fullMatch) const
{
        fullMatch = FALSE;
        bool partialMatch = FALSE;
	PINDEX aliasStr_len;
	const H225_ArrayOf_AliasAddress & reg_aliases = GetAliases();
	PString reg_alias;
	PString aliasStr = H323GetAliasAddressString(alias);
	aliasStr_len = aliasStr.GetLength();
	// for each alias which is stored for the endpoint in registration
	m_usedLock.Wait();
	for (PINDEX i = 0; i < reg_aliases.GetSize() && !partialMatch; i++) {
		reg_alias = H323GetAliasAddressString(reg_aliases[i]);
		// if alias from request message is prefix to alias which is
		//   stored in registration
		if ((reg_alias.GetLength() >= aliasStr_len) && (aliasStr == reg_alias.Left(aliasStr_len))) {
			// check if it is a full match
			if (aliasStr == reg_alias) {
				fullMatch = TRUE;
				PTRACE(2, ANSI::DBG << "Alias " << aliasStr << " matches endpoint "
				  << (const unsigned char *)m_endpointIdentifier.GetValue() << " (full)" << ANSI::OFF);
			} else {
				fullMatch = FALSE;
				partialMatch = TRUE;
				PTRACE(2, ANSI::DBG << "Alias " << aliasStr << " matches endpoint "
				  << (const unsigned char *)m_endpointIdentifier.GetValue() << " (partial)" << ANSI::OFF);
			}
		}
	}
	m_usedLock.Signal();
	return partialMatch;
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
	m_pollCount = 2;
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

void EndpointRec::BuildACF(H225_AdmissionConfirm & obj_acf) const
{
	obj_acf.IncludeOptionalField(H225_AdmissionConfirm::e_destinationInfo);
	obj_acf.m_destinationInfo = GetAliases();
	obj_acf.IncludeOptionalField(H225_AdmissionConfirm::e_destinationType);
	obj_acf.m_destinationType = GetEndpointType();
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
	extern const char *LRQFeaturesSection;
	if (Toolkit::AsBool(GkConfig()->GetString(LRQFeaturesSection, "IncludeDestinationInfoInLCF", "1"))) {
		obj_lcf.IncludeOptionalField(H225_LocationConfirm::e_destinationInfo);
		obj_lcf.m_destinationInfo = GetAliases();
		obj_lcf.IncludeOptionalField(H225_LocationConfirm::e_destinationType);
		obj_lcf.m_destinationType = GetEndpointType();
	}
}

PString EndpointRec::PrintOn(bool verbose) const
{
	PString msg(PString::Printf, "%s|%s|%s|%s" GK_LINEBRK,
		    (const unsigned char *) AsDotString(GetCallSignalAddress()),
		    (const unsigned char *) AsString(GetAliases()),
		    (const unsigned char *) AsString(GetEndpointType()),
		    (const unsigned char *) GetEndpointIdentifier().GetValue() );
	if (verbose) {
		msg += GetUpdatedTime().AsString();
		if (m_timeToLive == 0)
			msg += " (permanent)";
		msg += PString(PString::Printf, " C(%d%d%d) <%d>" GK_LINEBRK, m_activeCall, m_connectedCall, m_totalCall, m_usedCount);
	}
	return msg;
}

bool EndpointRec::SendURQ(H225_UnregRequestReason::Choices reason)
{
	if (GetRasAddress().GetTag() != H225_TransportAddress::e_ipAddress)
		return false;  // no valid ras address

	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_unregistrationRequest);
	H225_UnregistrationRequest & urq = ras_msg;
	urq.m_requestSeqNum.SetValue(Toolkit::Instance()->GetRequestSeqNum());
	urq.IncludeOptionalField(urq.e_gatekeeperIdentifier);
	urq.m_gatekeeperIdentifier.SetValue( Toolkit::GKName() );
	urq.IncludeOptionalField(urq.e_endpointIdentifier);
	urq.m_endpointIdentifier = GetEndpointIdentifier();
	urq.m_callSignalAddress.SetSize(1);
	urq.m_callSignalAddress[0] = GetCallSignalAddress();
	urq.IncludeOptionalField(H225_UnregistrationRequest::e_reason);
	urq.m_reason.SetTag(reason);

	PString msg(PString::Printf, "URQ|%s|%s|%s;" GK_LINEBRK,
			(const unsigned char *) AsDotString(GetRasAddress()),
			(const unsigned char *) GetEndpointIdentifier().GetValue(),
			(const unsigned char *) urq.m_reason.GetTagName());
        GkStatus::Instance()->SignalStatus(msg);

	Toolkit::Instance()->GetMasterRASListener().ForwardRasMsg(ras_msg);

	SendRas(ras_msg);
	return true;
}

bool EndpointRec::SendIRQ()
{
	if (m_pollCount-- == 0 || GetRasAddress().GetTag() != H225_TransportAddress::e_ipAddress)
		return false;

	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_infoRequest);
	H225_InfoRequest & irq = ras_msg;
	irq.m_requestSeqNum.SetValue(Toolkit::Instance()->GetRequestSeqNum());
	irq.m_callReferenceValue.SetValue(0); // ask for each call

	PString msg(PString::Printf, "IRQ|%s|%s;\r\n",
		    (const unsigned char *) AsDotString(GetRasAddress()),
		    (const unsigned char *) GetEndpointIdentifier().GetValue());
        GkStatus::Instance()->SignalStatus(msg);

	SendRas(ras_msg);

	return true;
}

void EndpointRec::SetNATAddress(PIPSocket::Address ip)
{
/* need to do this?
   if (m_rasAddress.GetTag() == H225_TransportAddress::e_ipAddress)
               m_rasAddress = SocketToH225TransportAddr(ip, ((H225_TransportAddress_ipAddress &)m_rasAddress).m_port);
   if (m_callSignalAddress.GetTag() == H225_TransportAddress::e_ipAddress)
               m_callSignalAddress = SocketToH225TransportAddr(ip, ((H225_TransportAddress_ipAddress &)m_callSignalAddress).m_port);
*/
	m_nat = true;
	m_natip = ip;
}

void EndpointRec::SendRas(const H225_RasMessage &ras_msg)
{
	const H225_TransportAddress_ipAddress & adr = GetRasAddress();
	PIPSocket::Address addr(adr.m_ip[0], adr.m_ip[1], adr.m_ip[2], adr.m_ip[3]);
	WORD port = adr.m_port;
	Toolkit::Instance()->GetMasterRASListener().SendTo(ras_msg, addr, port);
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
	if (Toolkit::AsBool(GkConfig()->GetString("RasSrv::RRQFeatures", "AcceptGatewayPrefixes", "1")))
		if (m_terminalType->m_gateway.HasOptionalField(H225_GatewayInfo::e_protocol))
			AddPrefixes(m_terminalType->m_gateway.m_protocol);
	for (PINDEX i=0; i<m_terminalAliases.GetSize(); i++) {
		// Get terminal aliases from LDAP
		PStringArray p = (GkConfig()->GetString("RasSrv::GWPrefixes",
				  H323GetAliasAddressString(m_terminalAliases[i]), "")
				 ).Tokenise(" ,;\t\n", false);
#if defined (HAS_LDAP)
		using namespace dctn;
		if(m_terminalAliases[i].GetTag()==H225_AliasAddress::e_h323_ID) {
			DBAttributeValueClass attr;
			using namespace dctn;
			DBTypeEnum dbType;
// 			if(GkDatabase::Instance()->getAttributes(H323GetAliasAddressString(m_terminalAliases[i]), attr, dbType)) {
// 				PStringList p2 = attr.find("telephonenumber")->second;
			PStringList p2;
//  			PTRACE(2, "GkDatabase::Instance()->getAttribute(" << H323GetAliasAddressString(m_terminalAliases[i])
// 			       << ", " << TelephoneNo << ", " << p2 << ")");
			if(GkDatabase::Instance()->getAttribute(H323GetAliasAddressString(m_terminalAliases[i]),
							    TelephoneNo, p2, dbType)) {
//				PTRACE(2, "got numbers: " << p2);
				for(PINDEX j=0; j<p2.GetSize(); j++) {
					if((p.GetSize()==0) || (p.GetStringsIndex(p2[j])==0)) {
						p.AppendString(E164_AnalysedNumber(p2[j]).GetAsDigitString());
					}
				}
			}
		}
#endif // HAS_LDAP
		for (PINDEX s=0; s<p.GetSize(); s++) {
			PTRACE(5, "adding prefix " << p[s]);
			Prefixes.push_back((const char *)p[s]);
		}
	}
	SortPrefixes();
	return true;
}

BOOL GatewayRec::PrefixIsIncomplete(const H225_AliasAddress & alias, BOOL &fullMatch) const
{
	fullMatch = FALSE;
	bool partialMatch = FALSE;
	// check for gw prefixes
	PString aliasStr = H323GetAliasAddressString(alias);
	PINDEX aliasStrLen = aliasStr.GetLength();
	PString regPrefix;
	// for each prefix which is stored for the endpoint in registration
	for (const_prefix_iterator Iter = Prefixes.begin(); Iter != Prefixes.end() && !partialMatch; Iter++) {
		regPrefix = Iter->c_str();
		// if alias from request message is prefix to gw prefix
		if ((regPrefix.GetLength() >= aliasStrLen) && (aliasStr == regPrefix.Left(aliasStrLen))) {
			// check if it is a full match
			if (aliasStr == regPrefix) {
				fullMatch = TRUE;
				PTRACE(2, ANSI::DBG << "Alias " << aliasStr << " matches GW "
					<< (const unsigned char *)m_endpointIdentifier.GetValue() << " (full)" << ANSI::OFF);
			} else {
				fullMatch = FALSE;
				partialMatch = TRUE;
				PTRACE(2, ANSI::DBG << "Alias " << aliasStr << " is prefix of GW "
					<< (const unsigned char *)m_endpointIdentifier.GetValue() << " (partial)" << ANSI::OFF);
			}
		}
	}
	return partialMatch;
}

int GatewayRec::PrefixMatch(const H225_ArrayOf_AliasAddress &a) const
{
	int maxlen = (defaultGW) ? 0 : -1;
	for (PINDEX i = 0; i < a.GetSize(); i++) {
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
		msg += GK_LINEBRK;
	}
	return msg;
}

OuterZoneEPRec::OuterZoneEPRec(const H225_RasMessage & completeRAS, const H225_EndpointIdentifier &epID) : EndpointRec(completeRAS, false)
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
//	srand(time(0));
	recCnt = rand()%9000+1000;
	ozCnt = 1000; // arbitrary chosen constant

	LoadConfig();
}


RegistrationTable::~RegistrationTable()
{
	ClearTable();
	RemovedList_mutex.StartWrite();
	for_each(RemovedList.begin(), RemovedList.end(), delete_ep);
	RemovedList_mutex.EndWrite();
}

endptr RegistrationTable::InsertRec(H225_RasMessage & ras_msg)
{
	endptr ep;
	switch (ras_msg.GetTag())
	{
	case H225_RasMessage::e_registrationRequest: {
		H225_RegistrationRequest & rrq = ras_msg;
		if (ep = FindBySignalAdr(rrq.m_callSignalAddress[0]))
			ep->Update(ras_msg);
		else
			ep = InternalInsertEP(ras_msg);
		break;
	}
	case H225_RasMessage::e_admissionRequest: {
		H225_AdmissionConfirm nouse;
		H225_AdmissionRequest & arq = ras_msg;
		if (arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress) && !(ep = FindOZEPBySignalAdr(arq.m_destCallSignalAddress)))
			ep = InternalInsertOZEP(ras_msg, nouse);
		break;
	}
	case H225_RasMessage::e_admissionConfirm: {
                       H225_AdmissionConfirm & acf = ras_msg;
                       if (!(ep = FindOZEPBySignalAdr(acf.m_destCallSignalAddress)))
			       ep = InternalInsertOZEP(ras_msg, acf);
                       break;
	}
	case H225_RasMessage::e_locationConfirm: {
		H225_LocationConfirm & lcf = ras_msg;
		if ((ep = FindOZEPBySignalAdr(lcf.m_callSignalAddress)))
			ep->Update(ras_msg);
		else
			ep = InternalInsertOZEP(ras_msg, lcf);
		break;

	}
	default:
		PTRACE(1, "RegistrationTable: unable to insert " << ras_msg.GetTagName());
		break;
	}

	return ep;
}

endptr RegistrationTable::InternalInsertEP(H225_RasMessage & ras_msg)
{
	H225_RegistrationRequest & rrq = ras_msg;
	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier)) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
		RemovedList_mutex.StartRead();
		endptr e = InternalFind(compose1(bind2nd(equal_to<H225_TransportAddress>(), rrq.m_callSignalAddress[0]),
			mem_fun(&EndpointRec::GetCallSignalAddress)), &RemovedList);
		if (e) // re-use the old endpoint identifier
			rrq.m_endpointIdentifier = e->GetEndpointIdentifier();
		else
			GenerateEndpointId(rrq.m_endpointIdentifier);
		RemovedList_mutex.EndRead();
	}
	if (!(rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) && (rrq.m_terminalAlias.GetSize() >= 1))) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_terminalAlias);
		GenerateAlias(rrq.m_terminalAlias, rrq.m_endpointIdentifier);
	}

	EndpointRec *ep = rrq.m_terminalType.HasOptionalField(H225_EndpointType::e_gateway) ?
			  new GatewayRec(ras_msg) : new EndpointRec(ras_msg);
	WriteLock lock(EndpointList_mutex);
	EndpointList.push_back(ep);
	return endptr(ep);
}

endptr RegistrationTable::InternalInsertOZEP(H225_RasMessage & ras_msg, H225_AdmissionConfirm &)
{
	H225_EndpointIdentifier epID;
	epID = "oz_" + PString(PString::Unsigned, ozCnt++) + endpointIdSuffix;
	EndpointRec *ep = new OuterZoneEPRec(ras_msg, epID);
	OuterZoneList_mutex.StartWrite();
	OuterZoneList.push_front(ep);
	OuterZoneList_mutex.EndWrite();
	return endptr(ep);
}

endptr RegistrationTable::InternalInsertOZEP(H225_RasMessage & ras_msg, H225_LocationConfirm & lcf)
{
	H225_EndpointIdentifier epID;
	epID = "oz_" + PString(PString::Unsigned, ozCnt++) + endpointIdSuffix;

	EndpointRec *ep;
	if (lcf.HasOptionalField(H225_LocationConfirm::e_destinationType) &&
	    lcf.m_destinationType.HasOptionalField(H225_EndpointType::e_gateway))
		ep = new OuterZoneGWRec(ras_msg, epID);
	else
		ep = new OuterZoneEPRec(ras_msg, epID);

	OuterZoneList_mutex.StartWrite();
	OuterZoneList.push_front(ep);
	OuterZoneList_mutex.EndWrite();
	return endptr(ep);
}

void RegistrationTable::RemoveByEndptr(const endptr & eptr)
{
	EndpointRec *ep = eptr.operator->(); // evil
	if (ep) {
		RemovedList_mutex.StartWrite();
		EndpointList_mutex.StartWrite();
		RemovedList.push_back(ep);
		EndpointList.remove(ep);
		RemovedList_mutex.EndWrite();
		EndpointList_mutex.EndWrite();

	}
}

void RegistrationTable::RemoveByEndpointId(const H225_EndpointIdentifier & epId)
{
	EndpointList_mutex.StartWrite();
	iterator Iter = find_if(EndpointList.begin(), EndpointList.end(),
			compose1(bind2nd(equal_to<H225_EndpointIdentifier>(), epId),
			mem_fun(&EndpointRec::GetEndpointIdentifier)));
	if (Iter != EndpointList.end()) {
		RemovedList_mutex.StartWrite();
		RemovedList.push_back(*Iter);
		RemovedList_mutex.EndWrite();
		EndpointList.erase(Iter);	// list<> is O(1), slist<> O(n) here
	} else {
	        PTRACE(1, "Warning: RemoveByEndpointId " << epId << " failed.");
	}
	EndpointList_mutex.EndWrite();
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

endptr RegistrationTable::FindOZEPBySignalAdr(const H225_TransportAddress &sigAd) const
{
       ReadLock lock(OuterZoneList_mutex);
       return InternalFind(compose1(bind2nd(equal_to<H225_TransportAddress>(), sigAd),
                       mem_fun(&EndpointRec::GetCallSignalAddress)), &OuterZoneList);
}

endptr RegistrationTable::FindByAliases(const H225_ArrayOf_AliasAddress & alias) const
{
	return InternalFind(bind2nd(mem_fun(&EndpointRec::CompareAlias), &alias));
}

endptr RegistrationTable::FindEndpoint(const H225_ArrayOf_AliasAddress & alias, bool s)
{
	EndpointList_mutex.StartRead();
	endptr ep = InternalFindEP(alias, &EndpointList);
	EndpointList_mutex.EndRead();
	ReadLock lock(OuterZoneList_mutex);
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

        if (GWlist.size() > 0) {
                EndpointRec *e = GWlist.front();
                if (GWlist.size() > 1) {
                        PTRACE(3, ANSI::DBG << "Prefix apply round robin" << ANSI::OFF);
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
	PString msg("AllRegistrations" GK_LINEBRK);
	EndpointList_mutex.StartRead();
	InternalPrint(client, verbose, &EndpointList, msg);
	EndpointList_mutex.EndRead();
}

void RegistrationTable::PrintAllCached(GkStatus::Client &client, BOOL verbose)
{
	PString msg("AllCached" GK_LINEBRK);
	OuterZoneList_mutex.StartRead();
	InternalPrint(client, verbose, &OuterZoneList, msg);
	OuterZoneList_mutex.EndRead();
}

void RegistrationTable::PrintRemoved(GkStatus::Client &client, BOOL verbose)
{
	PString msg("AllRemoved" GK_LINEBRK);
	RemovedList_mutex.StartRead();
	InternalPrint(client, verbose, &RemovedList, msg);
	RemovedList_mutex.EndRead();
}

void RegistrationTable::InternalPrint(GkStatus::Client &client, BOOL verbose, list<EndpointRec *> * List, PString & msg)
{
	// copy the pointers into a temporary array to avoid large lock
	const_iterator IterLast = List->end();
	unsigned k =0, s = List->size();
	endptr *eptr = new endptr[s];
	for (const_iterator Iter = List->begin(); Iter != IterLast; ++Iter)
		eptr[k++] = endptr(*Iter);
	// end of lock

	if (s > 1000) // set buffer to avoid reallocate
		msg.SetSize(s * (verbose ? 200 : 100));
	for (k = 0; k < s; k++)
		msg += "RCF|" + eptr[k]->PrintOn(verbose);
	delete [] eptr;

	msg += PString(PString::Printf, "Number of Endpoints: %u" GK_LINEBRK  ";" GK_LINEBRK, s);
	client.WriteString(msg);
	//PTRACE(2, msg);
}

void RegistrationTable::InternalStatistics(const list<EndpointRec *> *List, unsigned & s, unsigned & t, unsigned & g) const
{
	s = List->size(), t = 0, g = 0;
	const_iterator IterLast = List->end();
	for (const_iterator Iter = List->begin(); Iter != IterLast; ++Iter)
		((*Iter)->IsGateway() ? g : t)++;
}

PString RegistrationTable::PrintStatistics() const
{
	unsigned es, et, eg;
	EndpointList_mutex.StartRead();
	InternalStatistics(&EndpointList, es, et, eg);
	EndpointList_mutex.EndRead();
	unsigned cs, ct, cg;
	OuterZoneList_mutex.StartRead();
	InternalStatistics(&OuterZoneList, cs, ct, cg);
	OuterZoneList_mutex.EndRead();

	return PString(PString::Printf, "-- Endpoint Statistics --" GK_LINEBRK
		"Total Endpoints: %u  Terminals: %u  Gateways: %u" GK_LINEBRK
		"Cached Endpoints: %u  Terminals: %u  Gateways: %u" GK_LINEBRK,
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
	PStringToString cfgs=GkConfig()->GetAllKeyValues("RasSrv::PermanentEndpoints");
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
		EndpointList_mutex.StartWrite();
		EndpointList.push_back(ep);
		EndpointList_mutex.EndWrite();
        }

	// Load config for each endpoint
	EndpointList_mutex.StartRead();
	for_each(EndpointList.begin(), EndpointList.end(),
		 mem_fun(&EndpointRec::LoadConfig));
	EndpointList_mutex.EndRead();
}

void RegistrationTable::ClearTable()
{
	// Unregister all endpoints, and move the records into RemovedList
	EndpointList_mutex.StartWrite();
	RemovedList_mutex.StartWrite();
	transform(EndpointList.begin(), EndpointList.end(),
		back_inserter(RemovedList), mem_fun(&EndpointRec::Unregister));
	EndpointList.clear();
	EndpointList_mutex.EndWrite();
	OuterZoneList_mutex.StartWrite();
	copy(OuterZoneList.begin(), OuterZoneList.end(), back_inserter(RemovedList));
	RemovedList_mutex.EndWrite();
	OuterZoneList.clear();
	OuterZoneList_mutex.EndWrite();
}

void RegistrationTable::CheckEndpoints()
{
	PTime now;

	EndpointList_mutex.StartWrite();
	iterator Iter = EndpointList.begin(), eIter = EndpointList.end();
	while (Iter != eIter) {
		iterator i = Iter++;
		EndpointRec *ep = *i;
		if (!ep->IsUpdated(&now) && !ep->SendIRQ()) {
			ep->Expired();
			RemovedList_mutex.StartWrite();
			RemovedList.push_back(ep);
			EndpointList.erase(i);
			PTRACE(2, "Endpoint " << ep->GetEndpointIdentifier() << " expired.");

			// Prevent ep to be deleted before PTRACE is done
			RemovedList_mutex.EndWrite();
		}
	}
	EndpointList_mutex.EndWrite();

	OuterZoneList_mutex.StartWrite();
	Iter = partition(OuterZoneList.begin(), OuterZoneList.end(),
		bind2nd(mem_fun(&EndpointRec::IsUpdated), &now));
#ifdef PTRACING
	if (ptrdiff_t s = distance(Iter, OuterZoneList.end()))
		PTRACE(2, s << " outerzone endpoint(s) expired.");
#endif

	RemovedList_mutex.StartWrite();
	copy(Iter, OuterZoneList.end(), back_inserter(RemovedList));
	OuterZoneList.erase(Iter, OuterZoneList.end());
	RemovedList_mutex.EndWrite();
	OuterZoneList_mutex.EndWrite();

	// Cleanup unused EndpointRec in RemovedList
	RemovedList_mutex.StartWrite();
	Iter = partition(RemovedList.begin(), RemovedList.end(), mem_fun(&EndpointRec::IsUsed));
	for_each(Iter, RemovedList.end(), delete_ep);
	RemovedList.erase(Iter, RemovedList.end());
	RemovedList_mutex.EndWrite();
}

CallRec::CallRec(const H225_CallIdentifier & CallId,
		 const H225_ConferenceIdentifier & ConfId,
		 const PString & destInfo,
		 const PString & srcInfo,
		 int Bandwidth, bool h245Routed)
      : m_callIdentifier(CallId), m_conferenceIdentifier(ConfId),
	m_destInfo(destInfo),
	m_srcInfo(srcInfo),
	m_bandWidth(Bandwidth), m_CallNumber(0),
	m_callingCRV(0), m_calledCRV(0),
	m_startTime(0), m_stopTime(NULL), m_timeout(0),
	m_callingSocket(0), m_calledSocket(0),
	m_nattype(none), m_h245Routed(h245Routed)
{

//	PWaitAndSignal lock(m_usedLock);
	int timeout = GkConfig()->GetInteger(CallTableSection, "DefaultCallTimeout", 0);
	SetTimer(timeout);
	StartTimer();

	m_Calling = endptr(NULL);
	m_Called = endptr(NULL);
}

CallRec::~CallRec()
{
	// First of all, we have to Print a CDR :-)
	PTRACE(5, "GK\tBegining deletion of CallRec: " << this);
	m_usedLock.Wait();
	if((!m_callingProfile.GetH323ID().IsEmpty()) && (!m_calledProfile.GetH323ID().IsEmpty())) {
		PString cdrString(this->GenerateCDR());
 		GkStatus::Instance()->SignalStatus(cdrString, 1);
 		PTRACE(3, cdrString);
	}
	RemoveAll();
	m_usedLock.Signal();
	m_access_count.WaitCondition();
	m_usedLock.Wait();

	if(NULL!=m_callingSocket) {
		m_callingSocket->EndSession();
		m_callingSocket->UnlockUse("CallRec");
		m_callingSocket=NULL;
	}
	if(NULL!=m_calledSocket) {
		m_calledSocket->EndSession();
		m_calledSocket->UnlockUse("CallRec");
		m_calledSocket=NULL;
	}


	// Writeback the timeout
	// GkDatabase::Instance()->WriteCallTimeout(m_timer.GetInterval());
	delete m_startTime;
	m_startTime=NULL;
	delete m_stopTime;
	m_stopTime=NULL;

       	m_usedLock.Signal();
	StopTimer();
	PTRACE(5, "Gk\tDelete Call No. " << m_CallNumber);
}

void CallRec::Lock()
{
	PWaitAndSignal lock(m_usedLock);
	m_access_count.Lock();
}

void CallRec::Unlock()
{
	PWaitAndSignal lock(m_usedLock);
	m_access_count.Unlock();
}

void CallRec::SetConnected(bool c)
{
	PWaitAndSignal lock(m_usedLock);
	PTime *ts = (c) ? new PTime : NULL;
	delete m_startTime;
	if ((m_startTime = ts) != NULL)
		StartTimer();
	else
		StopTimer();
	if (c) {
		if (m_Calling)
			m_Calling->AddConnectedCall();
		if (m_Called)
			m_Called->AddConnectedCall();
	}
}

void CallRec::SetDisconnected()
{
	PWaitAndSignal lock(m_usedLock);
	if (NULL != m_stopTime)
		m_stopTime = new PTime();
}

void CallRec::SetTimer(int seconds)
{
       PWaitAndSignal lock(m_usedLock);
       m_timeout = seconds;
}

void CallRec::StartTimer()
{
	PWaitAndSignal lock(m_usedLock);
	if (m_timeout > 0) {
		m_timer = PTimer(0, m_timeout);
		m_timer.SetNotifier(PCREATE_NOTIFIER(OnTimeout));
	}
}

void CallRec::StopTimer()
{
	PWaitAndSignal lock(m_usedLock);
	m_timeout = 0;
}

endptr & CallRec::GetCallingEP()
{
	PWaitAndSignal lock(m_usedLock);
	return m_Calling;
}

endptr & CallRec::GetCalledEP()
{
	PWaitAndSignal lock(m_usedLock);
	return m_Called;
}

CalledProfile & CallRec::GetCalledProfile()
{
	PWaitAndSignal lock(m_cdpfLock);
	return InternalGetCalledProfile();
}

CalledProfile &
CallRec::InternalGetCalledProfile()
{
	if (m_calledProfile.GetH323ID().IsEmpty()){
		dctn::DBTypeEnum f;
		H225_AliasAddress adr;
		if ((endptr(NULL) != m_Called) && (m_Called->GetH323ID(adr))) {
			PString h323id=H323GetAliasAddressString(adr);
			PTRACE(1, "Looking for profile: " << h323id);
			GkDatabase::Instance()->getProfile(m_calledProfile, h323id ,f);
		}
	}
	return m_calledProfile;
}

CallingProfile & CallRec::GetCallingProfile()
{
	PWaitAndSignal lock(m_cgpfLock);
	return InternalGetCallingProfile();
}

CallingProfile &
CallRec::InternalGetCallingProfile()
{
	if (m_callingProfile.GetH323ID().IsEmpty()){
		dctn::DBTypeEnum f;
		H225_AliasAddress adr;
		if ((endptr(NULL) != m_Calling) && (m_Calling->GetH323ID(adr))) {
			PString h323id= H323GetAliasAddressString(adr);
			PTRACE(1, "Looking for profile: " << h323id);
			if(!GkDatabase::Instance()->getProfile(m_callingProfile, h323id,f))
				PTRACE(1, "Could not find profile for: " << h323id);
		}
	}
	return m_callingProfile;
}


void CallRec::OnTimeout()
{
	m_usedLock.Wait();
	PTRACE(2, "GK\tCall No. " << m_CallNumber << " timeout!");
	InternalDisconnect(true);
	m_usedLock.Signal();
}

void CallRec::OnTimeout(PTimer &timer, int extra) {
	m_usedLock.Wait();
	PTRACE(1, "CallRec::OnTimer(): " << timer << " : " << extra);
	if(timer.GetInterval()==0.0) {
		m_usedLock.Signal();
		OnTimeout();
		return;
	}
	m_usedLock.Signal();

}


void CallRec::InternalSetEP(endptr & ep, unsigned & crv, const endptr & nep, unsigned ncrv)
{
	if (ep != nep) {
		if (ep)
			ep->RemoveCall();
		ep = nep, crv = ncrv;
		if (ep)
			ep->AddCall();
	}
}

void CallRec::RemoveAll()
{
//	PWaitAndSignal lock(m_usedLock);
	if (m_registered) {
		H225_RasMessage ras_msg;
		ras_msg.SetTag(H225_RasMessage::e_disengageRequest);
		H225_DisengageRequest & drq = ras_msg;
		drq.m_conferenceID = m_conferenceIdentifier;
		drq.IncludeOptionalField(H225_DisengageRequest::e_callIdentifier);
		drq.m_callIdentifier = m_callIdentifier;
		drq.m_callReferenceValue = (m_Calling) ? m_callingCRV : m_calledCRV;
		if(Toolkit::Instance()->GkClientIsRegistered())
			Toolkit::Instance()->GetGkClient().SendDRQ(ras_msg);
	}

	if (m_Calling)
		m_Calling->RemoveCall();
	if (m_Called)
		m_Called->RemoveCall();
}

void CallRec::RemoveSocket()
{
	PWaitAndSignal lock(m_usedLock);
	InternalRemoveSocket();
}

void CallRec::InternalRemoveSocket()
{
	if (NULL!=m_callingSocket) {
		m_callingSocket->SetDeletable();
		m_callingSocket->UnlockUse("CallRec");
		m_callingSocket = NULL;
	}

	if (NULL!=m_calledSocket) {
		m_calledSocket->SetDeletable();
		m_calledSocket->UnlockUse("CallRec");
		m_calledSocket = NULL;
	}
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
	PWaitAndSignal lock(m_usedLock);
	InternalDisconnect(force);
}

void
CallRec::InternalDisconnect(bool force)
{
	if ((force || Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "DropCallsByReleaseComplete", "0"))) && (m_callingSocket || m_calledSocket)) {
		InternalSendReleaseComplete();
	} else {
		SendDRQ(); // This is an internal function
	}

	PTRACE(2, "Gk\tDisconnect Call No. " << m_CallNumber);
}

void CallRec::SendReleaseComplete()
{
	PWaitAndSignal lock(m_usedLock);
	InternalSendReleaseComplete();
}

void CallRec::InternalSendReleaseComplete()
{
	if (NULL!=m_callingSocket && !m_callingSocket->IsDeletable() &&
	    m_callingProfile.SendReleaseCompleteOnDRQ()) {
		m_callingSocket->MarkBlocked(TRUE);
		PTRACE(4, "Sending ReleaseComplete to calling party ..." << m_callingSocket);
		m_callingSocket->SendReleaseComplete();
		m_callingSocket->MarkBlocked(FALSE);
	}
	if (NULL!=m_calledSocket && !m_calledSocket->IsDeletable() &&
	    m_calledProfile.SendReleaseCompleteOnDRQ()) {
		m_calledSocket->MarkBlocked(TRUE);
		PTRACE(4, "Sending ReleaseComplete to called party ...");
		m_calledSocket->SendReleaseComplete();
		m_calledSocket->MarkBlocked(FALSE);

	}
}

void CallRec::SetSocket(CallSignalSocket *calling, CallSignalSocket *called)
{
	PWaitAndSignal lock(m_usedLock);
	if(NULL!=calling)
		calling->LockUse("CallRec");
	if(NULL!=m_callingSocket)
		m_callingSocket->UnlockUse("CallRec");
	if(NULL!=called)
		called->LockUse("CallRec");
	if(NULL!=m_calledSocket)
		m_calledSocket->UnlockUse("CallRec");
	m_callingSocket = calling;
	m_calledSocket = called;
}

void
CallRec::SendDRQ()
{
	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_disengageRequest);
	H225_DisengageRequest & drq = ras_msg;
	drq.m_requestSeqNum.SetValue(Toolkit::Instance()->GetRequestSeqNum());
	drq.m_disengageReason.SetTag(H225_DisengageReason::e_forcedDrop); // Set DisengageReason here
	drq.m_conferenceID = m_conferenceIdentifier;
	drq.IncludeOptionalField(H225_DisengageRequest::e_callIdentifier);
	drq.m_callIdentifier = m_callIdentifier;
	drq.IncludeOptionalField(H225_DisengageRequest::e_gatekeeperIdentifier);
	drq.m_gatekeeperIdentifier = Toolkit::GKName();

// Warning: For an outer zone endpoint, the endpoint identifier may not correct
	if(GetCalledProfile().ReleaseCauseIsSet())
			drq.m_disengageReason=GetCalledProfile().GetDisengageReason();
	if (m_Calling) {
		drq.m_endpointIdentifier = m_Calling->GetEndpointIdentifier();
		drq.m_callReferenceValue = m_callingCRV;
		m_Calling->SendRas(ras_msg);
	}
	if (m_Called) {
		drq.m_endpointIdentifier = m_Called->GetEndpointIdentifier();
		drq.m_callReferenceValue = m_calledCRV;
		m_Called->SendRas(ras_msg);
	}
}

static PString GetEPString(const endptr & ep, const CallSignalSocket *socket)
{
	if (ep) {
		return PString(PString::Printf, "%s|%s",
			(const char *)AsDotString(ep->GetCallSignalAddress()),
			(const char *)ep->GetEndpointIdentifier().GetValue());
	}
	return socket ? socket->Name() + "| " : PString(" | ");
}

// for user defined CDRs
static const char * const UseUTCinCDR = "UseUTCinCDR";
static const BOOL UseUTCinCDR_default = FALSE;
static const char * const UseCDRFormat = "UseCDRFormat";
/*
  Format description copied from pwlib/include/ptlib/ptime.h
  martinf, Wed May  8 11:23:22 2002

  \end{description}
       \item[h]         hour without leading zero
       \item[hh]        hour with leading zero
       \item[m]         minute without leading zero
       \item[mm]        minute with leading zero
       \item[s]         second without leading zero
       \item[ss]        second with leading zero
       \item[u]         tenths of second
       \item[uu]        hundedths of second with leading zero
       \item[uuu]       millisecond with leading zeros
       \item[uuuu]      microsecond with leading zeros
       \item[a]         the am/pm string
       \item[w/ww/www]  abbreviated day of week name
       \item[wwww]      full day of week name
       \item[d]         day of month without leading zero
       \item[dd]        day of month with leading zero
       \item[M]         month of year without leading zero
       \item[MM]        month of year with leading zero
       \item[MMM]       month of year as abbreviated text
       \item[MMMM]      month of year as full text
       \item[y/yy]      year without century
       \item[yyy/yyyy]  year with century
       \item[z]         the time zone description
\end{description}

All other characters are copied to the output string unchanged.

Note if there is an 'a' character in the string, the hour will be in 12
hour format, otherwise in 24 hour format.

This format applies to the following constant and analogical to the
configuration file tag to which it is the default value.

*/
static const char * const UseCDRFormat_default = "wwwe, dd MMME yyyy hh:mm:ss z";
static const PString AsCDRTimeString(const PTime & t);
static const PString AsCDRTimeString(const PTime & t)
{
	const PString format(GkConfig()->GetString(UseCDRFormat,UseCDRFormat_default));
	const int zone = (GkConfig()->GetBoolean(UseUTCinCDR,UseUTCinCDR_default) ? PTime::UTC : PTime::Local);
	const PString & result = t.AsString((const char *)format, zone);
	PTRACE(5, PString(ANSI::DBG) + "CDR: Time formated to "
	       + ANSI::PIN + result + ANSI::OFF);
	return result;
	//return t.AsString((const char *)format, zone);
}

/*
  IPTN_good will return TRUE if the number is in a known format and will
  rewrite it to the proper analysis result.
 */
static const BOOL IPTN_is_inter(E164_IPTNString & iptn);
static const BOOL IPTN_is_inter(E164_IPTNString & iptn)
{
	BOOL result = FALSE;
	E164_AnalysedNumber an(iptn); //  analyse it
	if(E164_AnalysedNumber::IPTN_unknown != an.GetIPTN_kind()) {
		result = TRUE;
		PString well_formated(an); // convert to '+CC NDC SN'
		PTRACE(2, PString(ANSI::DBG) + "CDR: rewriting " + iptn +
		       " to " + ANSI::GRE +well_formated + ANSI::OFF);
		iptn = well_formated;
	}
	return result;
}

/** Generate the Call Detail Record for a finished call
 *
 * The exact format and spezification of the elements in this record are to
 * be found in the file CDR.txt in the docs directory.
 */
PString CallRec::GenerateCDR()
{
	PString timeString;	// holding the time part
	PString srcInfo(m_srcInfo); // H.225 ARJ source info field
	PString destInfo(m_destInfo); // H.225 ARJ destination info field
	E164_IPTNString dialedPN(""); // dialed party number, formatted
	enum Q931::TypeOfNumberCodes dialedPN_TON = Q931::UnknownType;
	E164_IPTNString calledPN(""); // called party number, formatted
	CalledProfile & CalledP = InternalGetCalledProfile();

	if (NULL == m_stopTime) // oops, no stop time generated by RAS or Q.931?
		m_stopTime = new PTime();

	if (NULL != m_startTime) {
		PTimeInterval callDuration = *m_stopTime - *m_startTime;
		PString formattedStartTime(AsCDRTimeString(*m_startTime));
		if(formattedStartTime.IsEmpty()) PTRACE(5, PString(ANSI::DBG) + "CDR could not get string for Start Time" + ANSI::OFF);
		PString formattedEndTime(AsCDRTimeString(*m_stopTime));
		if(formattedEndTime.IsEmpty()) PTRACE(5, PString(ANSI::DBG) + "CDR could not get string for End Time" + ANSI::OFF);
		timeString = PString(PString::Printf, "%.3f|%s|%s",
				     (callDuration.GetMilliSeconds() / 1000.0),
				     (const char *)formattedStartTime,
				     (const char *)formattedEndTime
			);
	} else
		timeString = "0|unconnected| " + AsCDRTimeString(*m_stopTime);

	// get the proper dialed party number and its Type of Number, they
	// usually are not in international format
	if (!CalledP.GetDialedPN().IsEmpty()) {
		dialedPN = CalledP.GetDialedPN();
		dialedPN_TON = CalledP.GetDialedPN_TON();
#  if defined(CDR_RECHECK)
		PString TONstr;
		switch(dialedPN_TON) {
		case Q931::InternationalType:
			TONstr = "international type";
			break;
		case Q931::NationalType:
			TONstr = "national type";
			break;
		case Q931::NetworkSpecificType:
			TONstr = "network specific type";
			break;
		case Q931::SubscriberType:
			TONstr = "subscriber type";
			break;
		case Q931::AbbreviatedType:
			TONstr = "abbreviated type";
			break;
		case Q931::ReservedType:
			TONstr = "reserved type";
			break;
		case Q931::UnknownType:
		default:
			TONstr = "unknown";
		}
		PTRACE(2, PString(ANSI::DBG)+"CDR: dialedPN is in "
		       + ANSI::GRE + TONstr + ANSI::DBG + " format" + ANSI::OFF);
#  endif
	}
	// get the proper called party number, they should be in
	// international format
	if (!CalledP.GetCalledPN().IsEmpty()) {
		calledPN = CalledP.GetCalledPN();
#  if defined(CDR_RECHECK)
		if(IPTN_is_inter(calledPN)) {
			PTRACE(2, "CDR: calledPN is in international type format");
		} else {
			PTRACE(2, PString("CDR: ") + ANSI::RED + "WARNING" + ANSI::OFF +
			       ": calledPN " + calledPN +
			       " is " + ANSI::RED + "NOT" + ANSI::OFF +
			       " in international format; stripped!");
			calledPN = "";
		}
#  endif
	}


#if defined(CDR_MOD_INFO_FIELDS)
	// if profile for calling endpoint exists
	CallingProfile & CallingP = InternalGetCallingProfile();
	if (!CallingP.GetH323ID().IsEmpty()) {
		if (!CallingP.GetCgPN().IsEmpty()) {
			PTRACE(4, "CDR: set CgPN to international format");
			srcInfo = CallingP.GetCgPN() + ":dialedDigits";
		}
		if (!CalledP.GetCalledPN().IsEmpty()) {
			PTRACE(4, "CDR: set CdPN to international format");
			destInfo = CalledP.GetCalledPN() + ":dialedDigits";
		}
	}
#endif

	// fake destInfo if not provided by CallRec
	if (destInfo.IsEmpty()) {
		destInfo = CalledP.GetCallingPN();
	}

	return PString(PString::Printf,
		       "CDR|%d|%s|%s|%s|%s|%s|%s|%s|%u|%s|%s|%u|%s|%s%d.%d.%d-%s-%s-%s|%d;"
		       GK_LINEBRK,
		       m_CallNumber,
		       static_cast<const char *>(AsString(m_callIdentifier.m_guid)),
		       static_cast<const char *>(timeString),
		       static_cast<const char *>(GetEPString(m_Calling, m_callingSocket)),
		       static_cast<const char *>(GetEPString(m_Called, m_calledSocket)),
		       static_cast<const char *>(destInfo),
		       static_cast<const char *>(srcInfo),
		       static_cast<const char *>(Toolkit::Instance()->GKName()),
		       static_cast<unsigned int>(dialedPN_TON),
		       static_cast<const char *>(static_cast<PString>(dialedPN)),
		       static_cast<const char *>(static_cast<PString>(calledPN)),
		       static_cast<unsigned int>(InternalGetCalledProfile().GetAssumedDialedPN_TON()),
		       static_cast<const char *>(InternalGetCalledProfile().GetAssumedDialedPN()),
		       // build string from constants via cpp
		       PROGRAMMNAME
#ifdef P_PTHREADS
		       "+"
#else
		       "-"
#endif
		       "v", 	// the comma is needed
		       MAJOR_VERSION, MINOR_VERSION, BUILD_NUMBER,
		       static_cast<const char *>(PProcess::GetOSName()),
		       static_cast<const char *>(PProcess::GetOSHardware()),
		       static_cast<const char *>(PProcess::GetOSVersion()),
		       static_cast<int>(InternalGetCalledProfile().GetReleaseCause())
		);
}

PString CallRec::PrintOn(bool verbose) const
{
	m_usedLock.Wait();
	int time = m_timeout - m_timer.GetSeconds();
	int left = (m_timeout > 0 ) ? m_timer.GetSeconds() : 0;
	PString result(PString::Printf,
		       "Call No. %d | CallID %s | %d | %d\r\nDial %s\r\nACF|%s|%d\r\nACF|%s|%d\r\n",
		       m_CallNumber, (const char *)AsString(m_callIdentifier.m_guid), time, left,
		(const char *)m_destInfo,
		(const char *)GetEPString(m_Calling, m_callingSocket), m_callingCRV,
		(const char *)GetEPString(m_Called, m_calledSocket), m_calledCRV
	);
	if (verbose) {
		result += PString(PString::Printf, "# %s|%s|%d|%s" GK_LINEBRK,
				  (m_Calling) ? (const char *)AsString(m_Calling->GetAliases()) : "?",
				  (m_Called) ? (const char *)AsString(m_Called->GetAliases()) : "?",
				  m_bandWidth,
				  (m_startTime) ? (const char *)m_startTime->AsString() : "unconnected");
	}

	m_usedLock.Signal();
	return result;
}


CallTable::CallTable() : m_CallNumber(1), m_capacity(-1)
{
	LoadConfig();
	m_CallCount = m_successCall = m_neighborCall = 0;
	PTRACE(5,"Call table constructed");
}

CallTable::~CallTable()
{
	CallListMutex.Wait();
        for_each(CallList.begin(), CallList.end(),
		bind1st(mem_fun(&CallTable::InternalRemovePtr), this));
	CallListMutex.Signal();
	RemovedListMutex.Wait();
        for_each(RemovedList.begin(), RemovedList.end(), &CallTable::delete_call);
	RemovedListMutex.Signal();
}

void CallTable::LoadConfig()
{
	m_genNBCDR = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "GenerateNBCDR", "1"));
	m_genUCCDR = Toolkit::AsBool(GkConfig()->GetString(CallTableSection, "GenerateUCCDR", "0"));
	SetTotalBandWidth(GkConfig()->GetInteger("TotalBandwidth", m_capacity));
}

void CallTable::Insert(CallRec * NewRec)
{
	PTRACE(3, "CallTable::Insert(CALL) Call No. " << m_CallNumber);
	NewRec->SetCallNumber(m_CallNumber++);
	CallListMutex.Wait();
	CallList.push_back(NewRec);
	CallListMutex.Signal();
	++m_CallCount;
	if (m_capacity >= 0) {
		m_capacity -= NewRec->GetBandWidth();
		CallListMutex.Wait();
		PTRACE(2, "GK\tTotal sessions : " << CallList.size() << ", Available BandWidth " << m_capacity);
		CallListMutex.Signal();
	}
}

void CallTable::SetTotalBandWidth(int bw)
{
	if ((m_capacity = bw) >= 0) {
		int used = 0;
		CallListMutex.Wait();
		iterator Iter = CallList.begin(), eIter = CallList.end();
		while (Iter != eIter)
			used += (*Iter)->GetBandWidth();
		CallListMutex.Signal();
		if (bw > used)
			m_capacity -= used;
		else
			m_capacity = 0;
	}
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

void CallTable::ClearTable()
{
	CallListMutex.Wait();
	iterator Iter = CallList.begin(), eIter = CallList.end();
	while (Iter != eIter) {
		iterator i = Iter++;
		(*i)->Disconnect();
		InternalRemove(i);
	}
	CallListMutex.Signal();
}

void CallTable::CheckCalls()
{
/*	PTime now;
	WriteLock lock(listLock);
	iterator Iter = CallList.begin(), eIter = CallList.end();
	while (Iter != eIter) {
		iterator i = Iter++;
		if ((*i)->IsTimeout(&now)) {
			(*i)->Disconnect();
			InternalRemove(i);
		}
	}
*/
	RemovedListMutex.Wait();
	iterator Iter = partition(RemovedList.begin(), RemovedList.end(), mem_fun(&CallRec::IsUsed));
	for_each(Iter, RemovedList.end(), &CallTable::delete_call);
	RemovedList.erase(Iter, RemovedList.end());
	RemovedListMutex.Signal();
}

void CallTable::RemoveCall(const H225_DisengageRequest & obj_drq)
{
	callptr call = obj_drq.HasOptionalField(H225_DisengageRequest::e_callIdentifier) ? FindCallRec(obj_drq.m_callIdentifier) : FindCallRec(obj_drq.m_callReferenceValue.GetValue());
	PTRACE(1, "CallTable::RemoveCall " << call);
	if (call) {
		RemoveCall(call);
	}
	// Keep in mind to give a status enquiry ping to check wether call is really down.
}

void CallTable::RemoveCall(const callptr & call)
{
	if (call)
		InternalRemovePtr(call.operator->());
}

bool CallTable::InternalRemovePtr(CallRec *call)
{
	PTRACE(6, ANSI::PIN << "GK\tRemoving callptr:" << AsString(call->GetCallIdentifier().m_guid) << "...\n" << ANSI::OFF);
	CallListMutex.Wait();
	InternalRemove(find(CallList.begin(), CallList.end(), call));
	CallListMutex.Signal();
	return true; // useless, workaround for VC
}

void CallTable::InternalRemove(const H225_CallIdentifier & CallId)
{
	PTRACE(5, ANSI::PIN << "GK\tRemoving CallId:" << AsString(CallId.m_guid) << "...\n" << ANSI::OFF);
	CallListMutex.Wait();
	InternalRemove(
		find_if(CallList.begin(), CallList.end(),
		bind2nd(mem_fun(&CallRec::CompareCallId), &CallId))
	);
	CallListMutex.Signal();
}

void CallTable::InternalRemove(unsigned CallRef)
{
	PTRACE(5, ANSI::PIN << "GK\tRemoving CallRef:" << CallRef << "...\n" << ANSI::OFF);
	CallListMutex.Wait();
	InternalRemove(
		find_if(CallList.begin(), CallList.end(),
		bind2nd(mem_fun(&CallRec::CompareCRV), CallRef))
	);
	CallListMutex.Signal();
}

void CallTable::InternalRemove(iterator Iter)
{

	// Do *not* CallListMutex.Wait(), because this method is called from within a CallListMutex lock.
	if (Iter == CallList.end()) {
		return;
	}

	CallRec *call = *Iter;
	if ((m_genNBCDR || call->GetCallingAddress()) && (m_genUCCDR || call->IsConnected())) {
//		PString cdrString(call->GenerateCDR());
// 		GkStatus::Instance()->SignalStatus(cdrString, 1);
// 		PTRACE(3, cdrString);
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

///	call->StopTimer();
	PTRACE(5, "removing call: " << call);
//	call->RemoveAll();
//	call->RemoveSocket();
	if (m_capacity >= 0)
		m_capacity += call->GetBandWidth();

	RemovedListMutex.Wait();
	RemovedList.push_back(call);
	RemovedListMutex.Signal();
	CallList.erase(Iter);
}


void CallTable::InternalStatistics(unsigned & n, unsigned & act, unsigned & nb, PString & msg, BOOL verbose) const
{
	CallListMutex.Wait();
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
	CallListMutex.Signal();
}

void CallTable::PrintCurrentCalls(GkStatus::Client & client, BOOL verbose) const
{
	PString msg = "CurrentCalls" GK_LINEBRK;
	unsigned n, act, nb;
	InternalStatistics(n, act, nb, msg, verbose);

	msg += PString(PString::Printf, "Number of Calls: %u Active: %u From NB: %u" GK_LINEBRK ";" GK_LINEBRK, n, act, nb);
	client.WriteString(msg);
	//PTRACE(2, msg);
}

PString CallTable::PrintStatistics() const
{
	PString dumb;
	unsigned n, act, nb;
	InternalStatistics(n, act, nb, dumb, FALSE);

	return PString(PString::Printf, "-- Call Statistics --" GK_LINEBRK
		"Current Calls: %u Active: %u From Neighbor: %u" GK_LINEBRK
		"Total Calls: %u  Successful: %u  From Neighbor: %u" GK_LINEBRK,
		n, act, nb,
		m_CallCount, m_successCall, m_neighborCall);
}

void CallTable::delete_call(CallRec *c)
{
	PTRACE(5, "doing delete_call" << c);
	delete c;
}
