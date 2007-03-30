//////////////////////////////////////////////////////////////////
//
// New Neighboring System for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2002-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 05/30/2003
//
//////////////////////////////////////////////////////////////////

#if defined(_WIN32) && (_MSC_VER <= 1200)
#pragma warning(disable:4786) // warning about too long debug symbol off
#pragma warning(disable:4284)
#endif

#include <ptlib.h>
#include <ptclib/pdns.h>
#include <h323pdu.h>
#include <ptclib/cypher.h>
#include "gk_const.h"
#include "stl_supp.h"
#include "GkClient.h"
#include "RasPDU.h"
#include "RasSrv.h"
#include "RasTbl.h"
#include "Routing.h"
#include "sigmsg.h"
#include "cisco.h"
#include "Neighbor.h"
#include "pwlib_compat.h"

using std::multimap;
using std::make_pair;
using std::find_if;
using std::bind2nd;
using std::equal_to;
using std::mem_fun;
using Routing::Route;

namespace Neighbors {


const char *NeighborSection = "RasSrv::Neighbors";
const char *LRQFeaturesSection = "RasSrv::LRQFeatures";


class OldGK : public Neighbor {
	// override from class Neighbor
	virtual bool SetProfile(const PString &, const PString &);
};

class GnuGK : public Neighbor {
	// override from class Neighbor
	virtual bool OnSendingLRQ(H225_LocationRequest &, const AdmissionRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const SetupRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const FacilityRequest &);
	virtual bool IsAcceptable(RasMsg *ras) const;
};

class CiscoGK : public Neighbor {
public:
	// override from class Neighbor
	virtual bool OnSendingLRQ(H225_LocationRequest &, const AdmissionRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const LocationRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const SetupRequest &);
	virtual bool CheckReply(RasMsg *msg) const;
};

// stupid Clarent gatekeeper
class ClarentGK : public Neighbor {
	// override from class Neighbor
	virtual bool OnSendingLRQ(H225_LocationRequest &);
};

// a gatekeeper by Korea vendor
class GlonetGK : public Neighbor {
	// override from class Neighbor
	virtual bool OnSendingLRQ(H225_LocationRequest &, const AdmissionRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const LocationRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const SetupRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const FacilityRequest &);

	bool BuildLRQ(H225_LocationRequest &, WORD);
};

namespace { // anonymous namespace
	SimpleCreator<OldGK> OldGKCreator("OldGK");
	SimpleCreator<GnuGK> GnuGKCreator("GnuGK");
	SimpleCreator<CiscoGK> CiscoGKCreator("CiscoGK");
	SimpleCreator<ClarentGK> ClarentGKCreator("ClarentGK");
	SimpleCreator<GlonetGK> GlonetGKCreator("GlonetGK");

	int challenge;
	const char OID_T[] = "0.0.8.235.0.2.5";
}

// if we put nomatch into anonymous namespace,
// stupid VC can't find it, why??
static const PrefixInfo nomatch(-1, 0);


// template class LRQSender
typedef Functor2<PrefixInfo, Neighbor *, WORD> LRQFunctor;

template<class R>
class LRQSender : public LRQFunctor {
public:
	LRQSender(const R & r) : m_r(r) {}
	virtual PrefixInfo operator()(Neighbor *, WORD) const;

private:
	const R & m_r;
};

template<class R>
PrefixInfo LRQSender<R>::operator()(Neighbor *nb, WORD seqnum) const
{
	if (const H225_ArrayOf_AliasAddress *dest = m_r.GetAliases()) {
		H225_ArrayOf_AliasAddress aliases;
		if (PrefixInfo info = nb->GetPrefixInfo(*dest, aliases)) {
			H225_RasMessage lrq_ras;
			H225_LocationRequest & lrq = nb->BuildLRQ(lrq_ras, seqnum, aliases);
			if (nb->OnSendingLRQ(lrq, m_r) && nb->SendLRQ(lrq_ras))
				return info;
		}
	}
	return nomatch;
}

class LRQForwarder : public LRQFunctor {
public:
	LRQForwarder(const LocationRequest & l) : m_lrq(l) {}
	virtual PrefixInfo operator()(Neighbor *, WORD) const;

private:
	const LocationRequest & m_lrq;
};

PrefixInfo LRQForwarder::operator()(Neighbor *nb, WORD /*seqnum*/) const
{
	H225_ArrayOf_AliasAddress aliases;
	if (PrefixInfo info = nb->GetPrefixInfo(m_lrq.GetRequest().m_destinationInfo, aliases)) {
		H225_RasMessage lrq_ras;
		lrq_ras.SetTag(H225_RasMessage::e_locationRequest);
		H225_LocationRequest & lrq = lrq_ras;
		// copy and forward
		lrq = m_lrq.GetRequest();
		lrq.m_destinationInfo = aliases;
		// include hopCount if configured and not already included
		if (nb->GetDefaultHopCount() >= 1
			&& !lrq.HasOptionalField(H225_LocationRequest::e_hopCount)) {
			lrq.IncludeOptionalField(H225_LocationRequest::e_hopCount);
			lrq.m_hopCount = nb->GetDefaultHopCount();
		}
		if (nb->OnSendingLRQ(lrq, m_lrq) && nb->SendLRQ(lrq_ras))
			return info;
	}
	return nomatch;
}

// class Neighbor
Neighbor::Neighbor()
{
	m_rasSrv = RasServer::Instance();
}

Neighbor::~Neighbor()
{
	PTRACE(1, "NB\tDelete neighbor " << m_id);
}

bool Neighbor::SendLRQ(H225_RasMessage & lrq_ras)
{
	return m_rasSrv->SendRas(lrq_ras, GetIP(), m_port);
}

PIPSocket::Address Neighbor::GetIP() const
{
	if (m_dynamic) {
		PIPSocket::ClearNameCache();
		// Retrieve the ip address at this time
		if (!GetTransportAddress(m_name, GK_DEF_UNICAST_RAS_PORT, m_ip, m_port)) {
			PTRACE(1, "NB\tCan't get neighbor ip for " << m_name);
		}
	}
	return m_ip;
}

H225_LocationRequest & Neighbor::BuildLRQ(H225_RasMessage & lrq_ras, WORD seqnum, const H225_ArrayOf_AliasAddress & dest)
{
	lrq_ras.SetTag(H225_RasMessage::e_locationRequest);
	H225_LocationRequest & lrq = lrq_ras;
	lrq.m_requestSeqNum = seqnum;
	lrq.m_destinationInfo = dest;

	// Perform outbound per GK rewrite on the destination of the LRQ
	Toolkit::Instance()->GWRewriteE164(m_id,false,lrq.m_destinationInfo[0]);

	lrq.m_replyAddress = m_rasSrv->GetRasAddress(GetIP());

//	lrq.IncludeOptionalField(H225_LocationRequest::e_gatekeeperIdentifier);
//	lrq.m_gatekeeperIdentifier = Toolkit::GKName();
//	lrq.IncludeOptionalField(H225_LocationRequest::e_nonStandardData);
//	lrq.m_nonStandardData.m_data.SetValue(m_id);

	lrq.IncludeOptionalField(H225_LocationRequest::e_sourceInfo);
	lrq.m_sourceInfo.SetSize(1);
	H323SetAliasAddress(Toolkit::GKName(), lrq.m_sourceInfo[0], H225_AliasAddress::e_h323_ID);
	
	if (m_externalGK)
	   m_rasSrv->GetGkClient()->SetNBPassword(lrq, Toolkit::GKName());

	if (m_forwardHopCount >= 1) { // what if set hopCount = 1?
		lrq.IncludeOptionalField(H225_LocationRequest::e_hopCount);
		lrq.m_hopCount = m_forwardHopCount;
	}
	return lrq;
}

bool Neighbor::SetProfile(const PString & id, const PString & type)
{
	PConfig *config = GkConfig();
	PString section("Neighbor::" + (m_id = id));

	m_gkid = config->GetString(section, "GatekeeperIdentifier", id);
	m_name = config->GetString(section, "Host", "");
	m_dynamic = Toolkit::AsBool(config->GetString(section, "Dynamic", "0"));
	m_externalGK = false;

	if (!m_dynamic && !GetTransportAddress(m_name, GK_DEF_UNICAST_RAS_PORT, m_ip, m_port))
		return false;

	PINDEX i;
	m_sendPrefixes.clear();
	PString sprefix(config->GetString(section, "SendPrefixes", ""));
	PStringArray sprefixes(sprefix.Tokenise(",", false));
	for (i = 0; i < sprefixes.GetSize(); ++i) {
		PStringArray p(sprefixes[i].Tokenise(":=", false));
		m_sendPrefixes[p[0]] = (p.GetSize() > 1) ? p[1].AsInteger() : 1;
	}
	PString aprefix(config->GetString(section, "AcceptPrefixes", "*"));
	m_acceptPrefixes = PStringArray(aprefix.Tokenise(",", false));

	SetForwardedInfo(section);

	PString info = " of type " + type;
	if (!sprefix)
		info = " send=" + sprefix;
	if (!aprefix)
		info += " accept=" + aprefix;
	PTRACE(1, "Set neighbor " << id << '(' << (m_dynamic ? m_name : AsString(m_ip, m_port)) << ')' << info);
	return true;
}

bool Neighbor::SetProfile(const PString & name, const H323TransportAddress & addr)
{

  addr.GetIpAndPort(m_ip,m_port);
  m_id = "SRVrec";
  m_name = name;
  m_dynamic = false;
  m_externalGK = true;

  m_sendPrefixes.clear();
  PString sprefix("*");
  PStringArray sprefixes = sprefix.Tokenise(",", false);
	for (PINDEX i = 0; i < sprefixes.GetSize(); ++i) {
		PStringArray p(sprefixes[i].Tokenise(":=", false));
		m_sendPrefixes[p[0]] = (p.GetSize() > 1) ? p[1].AsInteger() : 1;
	}
 
  SetForwardedInfo(LRQFeaturesSection);

  return true;

}

PrefixInfo Neighbor::GetPrefixInfo(const H225_ArrayOf_AliasAddress & aliases, H225_ArrayOf_AliasAddress & dest)
{
	Prefixes::iterator iter, biter = m_sendPrefixes.begin(), eiter = m_sendPrefixes.end();
	for (PINDEX i = 0; i < aliases.GetSize(); ++i) {
		H225_AliasAddress & alias = aliases[i];
		iter = m_sendPrefixes.find(alias.GetTagName());
		if (iter != eiter) {
			dest.SetSize(1);
			dest[0] = alias;
			return PrefixInfo(100, (short)iter->second);
		}
		PString destination(AsString(alias, false));
		while (iter != biter) {
			--iter; // search in reverse order
			const int len = MatchPrefix(destination, iter->first);
			if (len < 0) {
				return nomatch;
			}
			else if (len > 0) {
				dest.SetSize(1);
				dest[0] = alias;
				return PrefixInfo((short)len, (short)iter->second);
			}
		}
	}
	iter = m_sendPrefixes.find("*");
	if (iter == eiter)
		return nomatch;
	dest = aliases;
	return PrefixInfo(0, (short)iter->second);
}

bool Neighbor::OnSendingLRQ(H225_LocationRequest &)
{
	return true;
}

bool Neighbor::OnSendingLRQ(H225_LocationRequest & lrq, const AdmissionRequest &)
{
	return OnSendingLRQ(lrq);
}

bool Neighbor::OnSendingLRQ(H225_LocationRequest & lrq, const LocationRequest &orig_lrq)
{
	// adjust hopCount to be lesser or equal to the original value
	if (orig_lrq.GetRequest().HasOptionalField(H225_LocationRequest::e_hopCount)) {
		if (lrq.HasOptionalField(H225_LocationRequest::e_hopCount)) {
			if (lrq.m_hopCount > orig_lrq.GetRequest().m_hopCount)
				lrq.m_hopCount = orig_lrq.GetRequest().m_hopCount;
		} else {
			lrq.IncludeOptionalField(H225_LocationRequest::e_hopCount);
			lrq.m_hopCount = orig_lrq.GetRequest().m_hopCount;
		}
	}

	// copy over canMapAlias
	if (orig_lrq.GetRequest().HasOptionalField(H225_LocationRequest::e_canMapAlias)) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_canMapAlias);
		lrq.m_canMapAlias = orig_lrq.GetRequest().m_canMapAlias;
	}

	return OnSendingLRQ(lrq);
}

bool Neighbor::OnSendingLRQ(H225_LocationRequest & lrq, const SetupRequest &)
{
	return OnSendingLRQ(lrq);
}

bool Neighbor::OnSendingLRQ(H225_LocationRequest & lrq, const FacilityRequest &)
{
	return OnSendingLRQ(lrq);
}

bool Neighbor::CheckReply(RasMsg *ras) const
{
	if( ras->IsFrom(GetIP(), 0 /*m_port*/) )
		return true;

	const H225_NonStandardParameter *param = ras->GetNonStandardParam();
	if (param == NULL)
		return false;

	int iec = Toolkit::iecUnknown;
	if (param->m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
		iec = Toolkit::Instance()->GetInternalExtensionCode((const H225_H221NonStandard&)param->m_nonStandardIdentifier);
	} else if (param->m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_object) {
		const PASN_ObjectId &oid = param->m_nonStandardIdentifier;
		if (oid.GetDataLength() == 0)
			iec = Toolkit::iecNeighborId;
	}
	
	return iec == Toolkit::iecNeighborId
		? strncmp(m_id, param->m_data.AsString(), m_id.GetLength()) == 0
		: false;
}

bool Neighbor::IsAcceptable(RasMsg *ras) const
{
	if (ras->IsFrom(GetIP(), 0 /*m_port*/)) {
		// ras must be an LRQ
		H225_LocationRequest & lrq = (*ras)->m_recvRAS;
		PINDEX i, j, sz = m_acceptPrefixes.GetSize();
		H225_ArrayOf_AliasAddress & aliases = lrq.m_destinationInfo;
		for (j = 0; j < aliases.GetSize(); ++j) {
			H225_AliasAddress & alias = aliases[j];
			for (i = 0; i < sz; ++i)
				if (m_acceptPrefixes[i] == alias.GetTagName())
					return true;
			PString destination(AsString(alias, false));
			int maxlen = 0;
			for (i = 0; i < sz; ++i) {
				const PString & prefix = m_acceptPrefixes[i];
				const int len = MatchPrefix(destination, prefix);
				if (len < 0)
					return false;
				else if (len > maxlen)
					maxlen = len;
			}
			if (maxlen > 0)
				return true;
		}
		for (i = 0; i < sz; ++i)
			if (m_acceptPrefixes[i] == "*")
				return true;
	}
	return false;
}

void Neighbor::SetForwardedInfo(const PString & section)
{
	PConfig *config = GkConfig();
	m_forwardHopCount = (WORD)config->GetInteger(section, "ForwardHopCount", 0);
	m_acceptForwarded = Toolkit::AsBool(config->GetString(section, "AcceptForwardedLRQ", "1"));
	m_forwardResponse = Toolkit::AsBool(config->GetString(section, "ForwardResponse", "0"));
	PString forwardto(config->GetString(section, "ForwardLRQ", "0"));
	if (forwardto *= "never")
		m_forwardto = -1;
	else if (forwardto *= "always")
		m_forwardto = 1;
	else
		m_forwardto = 0;
}


// class OldGK
bool OldGK::SetProfile(const PString & id, const PString & args)
{
	m_id = m_gkid = id;
	PStringArray cfg(args.Tokenise(";", true));
	m_name = cfg[0].Trim();
	m_sendPrefixes.clear();
	if (cfg.GetSize() > 1) {
		PStringArray p = cfg[1].Tokenise(",", false);
		for (PINDEX i = 0; i < p.GetSize(); ++i)
			m_sendPrefixes[p[i]] = 1;
	} else
		m_sendPrefixes["*"] = 1;
	m_acceptPrefixes.SetSize(1);
	m_acceptPrefixes[0] = "*";
	if (cfg.GetSize() > 2)
		m_password = cfg[2];
	m_dynamic = (cfg.GetSize() > 3) ? Toolkit::AsBool(cfg[3]) : false;
	if (!m_dynamic && !GetTransportAddress(m_name, GK_DEF_UNICAST_RAS_PORT, m_ip, m_port))
		return false;

	SetForwardedInfo(LRQFeaturesSection);
	if (Toolkit::AsBool(GkConfig()->GetString(LRQFeaturesSection, "AlwaysForwardLRQ", "0")))
		m_forwardto = 1;

	PTRACE(1, "Set neighbor " << m_gkid << '(' << (m_dynamic ? m_name : AsString(m_ip, m_port)) << ')' << (cfg.GetSize() > 1 ? (" for prefix " + cfg[1]) : PString()));
	return true;
}


// class GnuGK
bool GnuGK::OnSendingLRQ(H225_LocationRequest & lrq, const AdmissionRequest & request)
{
	lrq.IncludeOptionalField(H225_LocationRequest::e_gatekeeperIdentifier);
	lrq.m_gatekeeperIdentifier = Toolkit::GKName();
	lrq.IncludeOptionalField(H225_LocationRequest::e_nonStandardData);
	lrq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
	H225_H221NonStandard &t35 = lrq.m_nonStandardData.m_nonStandardIdentifier;
	t35.m_t35CountryCode = Toolkit::t35cPoland;
	t35.m_manufacturerCode = Toolkit::t35mGnuGk;
	t35.m_t35Extension = Toolkit::t35eNeighborId;
	lrq.m_nonStandardData.m_data.SetValue(m_id);

	const H225_AdmissionRequest & arq = request.GetRequest();
	lrq.IncludeOptionalField(H225_LocationRequest::e_sourceInfo);
	lrq.m_sourceInfo = arq.m_srcInfo;
	if (arq.HasOptionalField(H225_AdmissionRequest::e_canMapAlias)) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_canMapAlias);
		lrq.m_canMapAlias = arq.m_canMapAlias;
	}
	return true;
}

bool GnuGK::OnSendingLRQ(H225_LocationRequest & lrq, const SetupRequest & request)
{
	lrq.IncludeOptionalField(H225_LocationRequest::e_gatekeeperIdentifier);
	lrq.m_gatekeeperIdentifier = Toolkit::GKName();
	lrq.IncludeOptionalField(H225_LocationRequest::e_nonStandardData);
	lrq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
	H225_H221NonStandard &t35 = lrq.m_nonStandardData.m_nonStandardIdentifier;
	t35.m_t35CountryCode = Toolkit::t35cPoland;
	t35.m_manufacturerCode = Toolkit::t35mGnuGk;
	t35.m_t35Extension = Toolkit::t35eNeighborId;
	lrq.m_nonStandardData.m_data.SetValue(m_id);

	const H225_Setup_UUIE & setup = request.GetRequest();
	if (setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_sourceInfo);
		lrq.m_sourceInfo = setup.m_sourceAddress;
	}
	
	lrq.IncludeOptionalField(H225_LocationRequest::e_canMapAlias);
	lrq.m_canMapAlias = TRUE;
	return true;
}

bool GnuGK::OnSendingLRQ(H225_LocationRequest & lrq, const FacilityRequest & /*request*/)
{
	lrq.IncludeOptionalField(H225_LocationRequest::e_gatekeeperIdentifier);
	lrq.m_gatekeeperIdentifier = Toolkit::GKName();
	lrq.IncludeOptionalField(H225_LocationRequest::e_nonStandardData);
	lrq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
	H225_H221NonStandard &t35 = lrq.m_nonStandardData.m_nonStandardIdentifier;
	t35.m_t35CountryCode = Toolkit::t35cPoland;
	t35.m_manufacturerCode = Toolkit::t35mGnuGk;
	t35.m_t35Extension = Toolkit::t35eNeighborId;
	lrq.m_nonStandardData.m_data.SetValue(m_id);
	
	lrq.IncludeOptionalField(H225_LocationRequest::e_canMapAlias);
	lrq.m_canMapAlias = TRUE;
	return true;
}

bool GnuGK::IsAcceptable(RasMsg *ras) const
{
	if (Neighbor::IsAcceptable(ras)) {
		if (!m_acceptForwarded) {
			H225_LocationRequest & lrq = (*ras)->m_recvRAS;
			return lrq.HasOptionalField(H225_LocationRequest::e_gatekeeperIdentifier) && lrq.m_gatekeeperIdentifier.GetValue() == m_gkid;
		}
		return true;
	}
	return false;
}


// class CiscoGK
bool CiscoGK::OnSendingLRQ(H225_LocationRequest &lrq, const AdmissionRequest &req)
{
	const H225_AdmissionRequest &arq = req.GetRequest();
	Cisco_LRQnonStandardInfo nonStandardData;
	
	nonStandardData.m_ttl = m_forwardHopCount >= 1 ? m_forwardHopCount : 5;

	nonStandardData.IncludeOptionalField(Cisco_LRQnonStandardInfo::e_gatewaySrcInfo);
	nonStandardData.m_gatewaySrcInfo.SetSize(arq.m_srcInfo.GetSize());
	for (PINDEX i = 0; i < arq.m_srcInfo.GetSize(); i++)
		nonStandardData.m_gatewaySrcInfo[i] = arq.m_srcInfo[i];

	if (arq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier)) {
		nonStandardData.IncludeOptionalField(Cisco_LRQnonStandardInfo::e_callIdentifier);
		nonStandardData.m_callIdentifier = arq.m_callIdentifier;
	}
		
	// Cisco GK needs these
	lrq.IncludeOptionalField(H225_LocationRequest::e_nonStandardData);
	lrq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
	H225_H221NonStandard & h221 = lrq.m_nonStandardData.m_nonStandardIdentifier;
	h221.m_manufacturerCode = Toolkit::t35mCisco;
	h221.m_t35CountryCode = Toolkit::t35cUSA;
	h221.m_t35Extension = 0;
	
	PPER_Stream buff;
	nonStandardData.Encode(buff);
	buff.CompleteEncoding();
	lrq.m_nonStandardData.m_data = buff;
	
	lrq.IncludeOptionalField(H225_LocationRequest::e_canMapAlias);
	lrq.m_canMapAlias = TRUE;
	return true;
}

// class CiscoGK
bool CiscoGK::OnSendingLRQ(H225_LocationRequest &lrq, const LocationRequest &req)
{
	if (lrq.HasOptionalField(H225_LocationRequest::e_nonStandardData)
			&& lrq.m_nonStandardData.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
		const H225_H221NonStandard &h221 = lrq.m_nonStandardData.m_nonStandardIdentifier;
		if (h221.m_manufacturerCode == Toolkit::t35mCisco && h221.m_t35CountryCode == Toolkit::t35cUSA)
			return true;
			
		lrq.RemoveOptionalField(H225_LocationRequest::e_nonStandardData);
	}
	
	Cisco_LRQnonStandardInfo nonStandardData;
	nonStandardData.m_ttl = m_forwardHopCount >= 1 ? m_forwardHopCount : 5;

	if (lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)) {
		nonStandardData.IncludeOptionalField(Cisco_LRQnonStandardInfo::e_gatewaySrcInfo);
		nonStandardData.m_gatewaySrcInfo.SetSize(lrq.m_sourceInfo.GetSize());
		for (PINDEX i = 0; i < lrq.m_sourceInfo.GetSize(); i++)
			nonStandardData.m_gatewaySrcInfo[i] = lrq.m_sourceInfo[i];
	}
	
	lrq.IncludeOptionalField(H225_LocationRequest::e_nonStandardData);
	lrq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
	H225_H221NonStandard & h221 = lrq.m_nonStandardData.m_nonStandardIdentifier;
	h221.m_manufacturerCode = Toolkit::t35mCisco;
	h221.m_t35CountryCode = Toolkit::t35cUSA;
	h221.m_t35Extension = 0;
	
	PPER_Stream buff;
	nonStandardData.Encode(buff);
	buff.CompleteEncoding();
	lrq.m_nonStandardData.m_data = buff;
	
	lrq.IncludeOptionalField(H225_LocationRequest::e_canMapAlias);
	lrq.m_canMapAlias = TRUE;
	return true;
}

// class CiscoGK
bool CiscoGK::OnSendingLRQ(H225_LocationRequest &lrq, const SetupRequest &req)
{
	const Q931 &setup = req.GetWrapper()->GetQ931();
	const H225_Setup_UUIE &setupBody = req.GetRequest();
	Cisco_LRQnonStandardInfo nonStandardData;
	
	nonStandardData.m_ttl = m_forwardHopCount >= 1 ? m_forwardHopCount : 5;

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		nonStandardData.IncludeOptionalField(Cisco_LRQnonStandardInfo::e_gatewaySrcInfo);
		nonStandardData.m_gatewaySrcInfo.SetSize(setupBody.m_sourceAddress.GetSize());
		for (PINDEX i = 0; i < setupBody.m_sourceAddress.GetSize(); i++)
			nonStandardData.m_gatewaySrcInfo[i] = setupBody.m_sourceAddress[i];
	}
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
		nonStandardData.IncludeOptionalField(Cisco_LRQnonStandardInfo::e_callIdentifier);
		nonStandardData.m_callIdentifier = setupBody.m_callIdentifier;
	}
	
	if (setup.HasIE(Q931::CallingPartyNumberIE)) {
		PBYTEArray data = setup.GetIE(Q931::CallingPartyNumberIE);
		if ((data[0] & 0x80) == 0x80 && data.GetSize() >= 2) {
			nonStandardData.IncludeOptionalField(Cisco_LRQnonStandardInfo::e_callingOctet3a);
			nonStandardData.m_callingOctet3a = data[1];
		}
	}
		
	// Cisco GK needs these
	lrq.IncludeOptionalField(H225_LocationRequest::e_nonStandardData);
	lrq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
	H225_H221NonStandard & h221 = lrq.m_nonStandardData.m_nonStandardIdentifier;
	h221.m_manufacturerCode = Toolkit::t35mCisco;
	h221.m_t35CountryCode = Toolkit::t35cUSA;
	h221.m_t35Extension = 0;
	
	PPER_Stream buff;
	nonStandardData.Encode(buff);
	buff.CompleteEncoding();
	lrq.m_nonStandardData.m_data = buff;
	
	lrq.IncludeOptionalField(H225_LocationRequest::e_canMapAlias);
	lrq.m_canMapAlias = TRUE;
	return true;
}

bool CiscoGK::CheckReply(RasMsg *msg) const
{
	if (msg->IsFrom(GetIP(), 0))
		return true;
		
	if (msg->GetTag() != H225_RasMessage::e_locationConfirm
			&& msg->GetTag() != H225_RasMessage::e_locationReject)
		return false;

	H225_NonStandardParameter *nonStandardData = msg->GetNonStandardParam();
	if (nonStandardData == NULL)
		return false;
	
	if (nonStandardData->m_nonStandardIdentifier.GetTag() != H225_NonStandardIdentifier::e_h221NonStandard)
		return false;
	
	H225_H221NonStandard &h221 = nonStandardData->m_nonStandardIdentifier;
	if (h221.m_manufacturerCode != Toolkit::t35mCisco || h221.m_t35CountryCode != Toolkit::t35cUSA)
		return false;
	
	PPER_Stream strm(nonStandardData->m_data);
	Cisco_LRQnonStandardInfo ciscoNonStandardData;
	if (ciscoNonStandardData.Decode(strm)) {
		// here should go additional checks to match callIdentifier, for example
	} else
		PTRACE(5, "NB\tFailed to decode Cisco nonStandardInfo field");
		
	return true;
}

// class ClarentGK
bool ClarentGK::OnSendingLRQ(H225_LocationRequest & lrq)
{
	// Clarent gatekeeper can't decode nonStandardData, stupid!
	lrq.RemoveOptionalField(H225_LocationRequest::e_nonStandardData);
	return true;
}

// class GlonetGK
bool GlonetGK::OnSendingLRQ(H225_LocationRequest & lrq, const AdmissionRequest & request)
{
	return BuildLRQ(lrq, (WORD)request.GetRequest().m_callReferenceValue);
}

bool GlonetGK::OnSendingLRQ(H225_LocationRequest &, const LocationRequest &)
{
	// not supported, since LRQ doesn't have call reference value
	return false;
}

bool GlonetGK::OnSendingLRQ(H225_LocationRequest & lrq, const SetupRequest & request)
{
	return BuildLRQ(lrq, (WORD)request.GetWrapper()->GetCallReference());
}

bool GlonetGK::OnSendingLRQ(H225_LocationRequest & lrq, const FacilityRequest & request)
{
	return BuildLRQ(lrq, (WORD)request.GetWrapper()->GetCallReference());
}

bool GlonetGK::BuildLRQ(H225_LocationRequest & lrq, WORD crv)
{
	lrq.IncludeOptionalField(H225_LocationRequest::e_sourceInfo);
	lrq.m_sourceInfo.SetSize(2);
	H323SetAliasAddress(Toolkit::GKName(), lrq.m_sourceInfo[0], H225_AliasAddress::e_h323_ID);
	H323SetAliasAddress(PString(crv), lrq.m_sourceInfo[1]);
	return true;
}


// class LRQRequester
class LRQRequester : public RasRequester {
public:
	LRQRequester(const LRQFunctor &);
	~LRQRequester();

	bool Send(NeighborList::List &, Neighbor * = 0);
	bool Send(Neighbor * nb);
	int GetReqNumber() const { return m_requests.size(); }
	H225_LocationConfirm *WaitForDestination(int);
	PString GetNeighborUsed() { return m_neighbor_used; }

	// override from class RasRequester
	virtual bool IsExpected(const RasMsg *) const;
	virtual void Process(RasMsg *);
	virtual bool OnTimeout();

private:
	struct Request {
		Request(Neighbor *n) : m_neighbor(n), m_reply(0), m_count(1) {}

		Neighbor *m_neighbor;
		RasMsg *m_reply;
		int m_count;
	};

	typedef multimap<PrefixInfo, Request> Queue;

	Queue m_requests;
	PMutex m_rmutex;
	const LRQFunctor & m_sendto;
	RasMsg *m_result;
	PString m_neighbor_used;
};

LRQRequester::LRQRequester(const LRQFunctor & fun) : m_sendto(fun), m_result(0)
{
	AddFilter(H225_RasMessage::e_locationConfirm);
	AddFilter(H225_RasMessage::e_locationReject);
	m_rasSrv->RegisterHandler(this);
}

LRQRequester::~LRQRequester()
{
	m_rasSrv->UnregisterHandler(this);
}

bool LRQRequester::Send(NeighborList::List & neighbors, Neighbor *requester)
{
	PWaitAndSignal lock(m_rmutex);
	NeighborList::List::iterator iter = neighbors.begin();
	while (iter != neighbors.end()) {
		Neighbor *nb = *iter++;
		if (nb != requester)
			if (PrefixInfo info = m_sendto(nb, m_seqNum))
				m_requests.insert(make_pair(info, nb));
	}
	if (m_requests.empty())
		return false;

	m_retry = GkConfig()->GetInteger(LRQFeaturesSection, "SendRetries", 2); 
	PTRACE(2, "NB\t" << m_requests.size() << " LRQ(s) sent");
	return true;
}

bool LRQRequester::Send(Neighbor * nb)
{
	PWaitAndSignal lock(m_rmutex);

	if (PrefixInfo info = m_sendto(nb, m_seqNum))
		   m_requests.insert(make_pair(info, nb));

	if (m_requests.empty()) {
		PTRACE(2, "SRV\tError Sending LRQ to " << nb->GetIP());
		return false;
	}

	m_retry = GkConfig()->GetInteger(LRQFeaturesSection, "SendRetries", 2);
	PTRACE(2, "SRV\tLRQ sent to " << nb->GetIP());
	return true;
}

H225_LocationConfirm *LRQRequester::WaitForDestination(int timeout)
{
	while (WaitForResponse(timeout))
		if (m_result)
			break;
		else
			GetReply(); // ignore and increase iterator

	return m_result ? &(H225_LocationConfirm &)(*m_result)->m_recvRAS : 0;
}

bool LRQRequester::IsExpected(const RasMsg *ras) const
{
	return RasHandler::IsExpected(ras) && (ras->GetSeqNum() == m_seqNum);
}

void LRQRequester::Process(RasMsg *ras)
{
	PWaitAndSignal lock(m_rmutex);
	for (Queue::iterator iter = m_requests.begin(); iter != m_requests.end(); ++iter) {
		Request & req = iter->second;
		if (req.m_neighbor->CheckReply(ras) ||
			Toolkit::AsBool(GkConfig()->GetString(LRQFeaturesSection, "AcceptNonNeighborLCF", "0"))) {
			PTRACE(5,"NB\tReceived "<<ras->GetTagName()<<" message matched"
				<<" pending LRQ for neighbor "<<req.m_neighbor->GetId()
				<<':'<<req.m_neighbor->GetIP()
				);
			unsigned tag = ras->GetTag();
			if (tag == H225_RasMessage::e_requestInProgress) {
				if (H225_NonStandardParameter *param = ras->GetNonStandardParam()) {
					int iec = Toolkit::iecUnknown;
					if (param->m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
						iec = Toolkit::Instance()->GetInternalExtensionCode((const H225_H221NonStandard&)param->m_nonStandardIdentifier);
					} else if (param->m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_object) {
						PASN_ObjectId &oid = param->m_nonStandardIdentifier;
						if (oid.GetDataLength() == 0)
							iec = Toolkit::iecNeighborId;
					}
					if (iec == Toolkit::iecNeighborId) {
						PStringArray ttl(param->m_data.AsString().Tokenise(":", false));
						if (ttl.GetSize() > 1)
							req.m_count += ttl[1].AsInteger();
					}
				}
				RasRequester::Process(ras);
			} else if (tag == H225_RasMessage::e_locationConfirm) {
				--req.m_count;
				// Note: to avoid race condition, the order is important
				if (iter == m_requests.begin()) // the highest priority
					m_result = ras;
				AddReply(req.m_reply = ras);
				m_neighbor_used = req.m_neighbor->GetId(); // record neighbor used
				if (m_result)
					m_sync.Signal();
			} else { // should be H225_RasMessage::e_locationReject
				--req.m_count;
				delete ras;
				ras = NULL;
				if (req.m_count <= 0 && req.m_reply == 0) {
					PTRACE(5,"NB\tLRQ rejected for neighbor "<<req.m_neighbor->GetId()
						<<':'<<req.m_neighbor->GetIP()
						);
					m_requests.erase(iter);
					if (m_requests.empty())
						RasRequester::Stop();
					else if (RasMsg *reply = m_requests.begin()->second.m_reply)
						m_result = reply, RasRequester::Stop();
				}
			}
			return;
		}
	}

	PTRACE(1, "RAS\tUnknown reply " << ras->GetTagName());
	delete ras;
	ras = NULL;
}

bool LRQRequester::OnTimeout()
{
	PWaitAndSignal lock(m_rmutex);
	if (m_requests.empty())
		return false;
	Queue::iterator iter, biter = m_requests.begin(), eiter = m_requests.end();
	for (iter = biter; iter != eiter; ++iter) {
		m_result = iter->second.m_reply;
		if (m_result)
			return false;
	}
	if (m_retry-- == 0)
		return false;
	// re-send LRQs
	for (iter = biter; iter != eiter; ++iter) {
		m_sendto(iter->second.m_neighbor, m_seqNum);
		iter->second.m_count = 1; // reset count
	}
	m_sentTime = PTime();
	PTRACE(2, "NB\t" << m_requests.size() << " LRQ(s) re-sent");
	return true;
}


// class NeighborList
NeighborList::NeighborList()
{
	Factory<Neighbor>::SetDefaultCreator(&OldGKCreator);
	// OnReload is called by holder
}

NeighborList::~NeighborList()
{
	DeleteObjectsInContainer(m_neighbors);
}

void NeighborList::OnReload()
{
	challenge = rand();
	PStringToString cfgs(GkConfig()->GetAllKeyValues(NeighborSection));
	PINDEX i, sz = cfgs.GetSize();
	List::iterator iter = m_neighbors.begin();
	while (iter != m_neighbors.end()) {
		List::iterator it = iter++;
		for (i = 0; i < sz; ++i)
			if ((*it)->GetId() == cfgs.GetKeyAt(i))
				break;
		if (i == sz) {
			Neighbor * r = *it;
			m_neighbors.erase(it);
			delete r;
			r = NULL;
			iter = m_neighbors.begin();	// reset iterator after changing container
		}
	}
	for (i = 0; i < sz; ++i) {
		const PString & nbid = cfgs.GetKeyAt(i);
		const PString & type = cfgs.GetDataAt(i);
		iter = find_if(m_neighbors.begin(), m_neighbors.end(),
				compose1(bind2nd(equal_to<PString>(), nbid), mem_fun(&Neighbor::GetId))
			      );
		bool newnb = (iter == m_neighbors.end());
		Neighbor *nb = newnb ? Factory<Neighbor>::Create(type) : *iter;
		if (nb->SetProfile(nbid, type)) {
			if (newnb)
				m_neighbors.push_back(nb);
		} else {
			PTRACE(1, "NB\tCan't get profile for neighbor " << nbid);
			delete nb;
			nb = NULL;
			if (!newnb)
				m_neighbors.erase(iter);
		}
	}
}

bool NeighborList::CheckLRQ(RasMsg *ras) const
{
     return find_if(m_neighbors.begin(), m_neighbors.end(), bind2nd(mem_fun(&Neighbor::IsAcceptable), ras)) != m_neighbors.end();
}

bool NeighborList::CheckIP(const PIPSocket::Address & addr) const
{
	return find_if(m_neighbors.begin(), m_neighbors.end(), bind2nd(mem_fun(&Neighbor::IsFrom), &addr)) != m_neighbors.end();
}

PString NeighborList::GetNeighborIdBySigAdr(const H225_TransportAddress & sigAd)
{

	PIPSocket::Address ipaddr;

	// Get the Neigbor IP address from the transport address
	if (!GetIPFromTransportAddr(sigAd, ipaddr))
	{
		return PString("");
	}

	return GetNeighborIdBySigAdr(ipaddr);
}

PString NeighborList::GetNeighborIdBySigAdr(const PIPSocket::Address & sigAd)
{

	List::iterator findNeighbor;

	// Attempt to find the neigbor in the list
	findNeighbor = find_if(m_neighbors.begin(), m_neighbors.end(), bind2nd(mem_fun(&Neighbor::IsFrom), &sigAd));

	if (findNeighbor == m_neighbors.end())
	{
		return PString("");
	}

	return (*findNeighbor)->GetId();

}


/* Not used currently
H225_CryptoH323Token BuildAccessToken(const H225_TransportAddress & dest, const PIPSocket::Address & addr)
{
	H225_CryptoH323Token token;
	token.SetTag(H225_CryptoH323Token::e_nestedcryptoToken);
	H235_CryptoToken & nestedCryptoToken = token;
	nestedCryptoToken.SetTag(H235_CryptoToken::e_cryptoHashedToken);

	H235_CryptoToken_cryptoHashedToken & cryptoHashedToken = nestedCryptoToken;
	// "T" indicates that the hashed token is used for authentication and integrity
	cryptoHashedToken.m_tokenOID = OID_T;

	H235_ClearToken & clearToken = cryptoHashedToken.m_hashedVals;
	clearToken.IncludeOptionalField(H235_ClearToken::e_timeStamp);
	int timeStamp = time(0);
	clearToken.m_timeStamp = timeStamp;

	DWORD key = addr ^ timeStamp ^ challenge;
	PTEACypher::Key cryptokey;
	memset(&cryptokey, challenge, sizeof(PTEACypher::Key));
	memcpy(&cryptokey, &key, sizeof(DWORD));
	PTEACypher cypher(cryptokey);

	PPER_Stream strm;
	dest.Encode(strm);
	PString hashed(cypher.Encode(strm));

	cryptoHashedToken.m_token.m_hash.SetData(hashed.GetLength() * 8, hashed);
	return token;
}
*/

bool DecodeAccessToken(const H225_CryptoH323Token & token, const PIPSocket::Address & addr, H225_TransportAddress & dest)
{
	if (token.GetTag() != H225_CryptoH323Token::e_nestedcryptoToken)
		return false;
	const H235_CryptoToken & nestedCryptoToken = token;
	if (nestedCryptoToken.GetTag() != H235_CryptoToken::e_cryptoHashedToken)
		return false;
	const H235_CryptoToken_cryptoHashedToken & cryptoHashedToken = nestedCryptoToken;
	if (cryptoHashedToken.m_tokenOID.AsString() != OID_T)
		return false;

	const H235_ClearToken & clearToken = cryptoHashedToken.m_hashedVals;
	if (!clearToken.HasOptionalField(H235_ClearToken::e_timeStamp))
		return false;
	int now = time(0), timeStamp = clearToken.m_timeStamp.GetValue();
	if (timeStamp > now || (now - timeStamp) > 30)
		return false;

	const PASN_BitString & bitstring = cryptoHashedToken.m_token.m_hash;
	PString hashed((const char *)bitstring.GetDataPointer(), bitstring.GetSize() / 8);

	DWORD key = addr ^ timeStamp ^ challenge;
	PTEACypher::Key cryptokey;
	memset(&cryptokey, challenge, sizeof(PTEACypher::Key));
	memcpy(&cryptokey, &key, sizeof(DWORD));
	PTEACypher cypher(cryptokey);

	PPER_Stream strm;
	return cypher.Decode(hashed, strm) && dest.Decode(strm);
}


} // end of namespace Neighbors


namespace Routing {


using namespace Neighbors;

class NeighborPolicy : public Policy {
public:
	NeighborPolicy();

private:
	// override from class Policy
	virtual bool IsActive();

	virtual bool OnRequest(AdmissionRequest &);
	virtual bool OnRequest(LocationRequest &);
	virtual bool OnRequest(SetupRequest &);
	virtual bool OnRequest(FacilityRequest &);

	typedef NeighborList::List List;
	List & m_neighbors;
	int m_neighborTimeout;
};

NeighborPolicy::NeighborPolicy() : m_neighbors(*RasServer::Instance()->GetNeighbors())
{
	m_neighborTimeout = GkConfig()->GetInteger(LRQFeaturesSection, "NeighborTimeout", 5) * 1000;
	m_name = "Neighbor";
}

bool NeighborPolicy::IsActive()
{
	return !m_neighbors.empty();
}

template<class H2250>
inline void CopyCryptoTokens(const H225_LocationConfirm *lcf, H2250 & msg)
{
	// copy access tokens
	if (lcf->HasOptionalField(H225_LocationConfirm::e_cryptoTokens)) {
		msg.IncludeOptionalField(H2250::e_cryptoTokens);
		msg.m_cryptoTokens = lcf->m_cryptoTokens;
	}
}

bool NeighborPolicy::OnRequest(AdmissionRequest & arq_obj)
{
	LRQSender<AdmissionRequest> functor(arq_obj);
	LRQRequester request(functor);
	if (request.Send(m_neighbors)) {
		if (H225_LocationConfirm *lcf = request.WaitForDestination(m_neighborTimeout)) {
			Route route(m_name, lcf->m_callSignalAddress);
			route.m_routeId = request.GetNeighborUsed();
			route.m_flags |= Route::e_toNeighbor;
			if ((lcf->HasOptionalField(H225_LocationConfirm::e_destinationInfo))
				&& (lcf->m_destinationInfo.GetSize() > 0)) 
			{
				arq_obj.SetAliases(lcf->m_destinationInfo);
				arq_obj.SetFlag(Routing::AdmissionRequest::e_aliasesChanged);
			}
			arq_obj.AddRoute(route);
			RasMsg *ras = arq_obj.GetWrapper();
			(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_admissionConfirm);
			H225_AdmissionConfirm & acf = (*ras)->m_replyRAS;
			CopyCryptoTokens(lcf, acf);
			return true;
		}
	}
	return false;
}

bool NeighborPolicy::OnRequest(LocationRequest & lrq_obj)
{
	RasMsg *ras = lrq_obj.GetWrapper();
	List::iterator iter = find_if(m_neighbors.begin(), m_neighbors.end(), bind2nd(mem_fun(&Neighbor::IsAcceptable), ras));
	Neighbor *requester = (iter != m_neighbors.end()) ? *iter : 0;
	int hopCount = 0;
	if (requester)
		if (requester->ForwardLRQ() < 0)
			return false;
		else if (requester->ForwardLRQ() > 0)
			hopCount = 1;

	H225_LocationRequest & lrq = (*ras)->m_recvRAS;
	if (lrq.HasOptionalField(H225_LocationRequest::e_hopCount)) {
		hopCount = lrq.m_hopCount - 1;
		if (hopCount)
			lrq.m_hopCount = hopCount;
	}
	if (!hopCount)
		return false;


	if (requester && !requester->ForwardResponse()) {
		LRQForwarder functor(lrq_obj);
		LRQRequester request(functor);
		if (request.Send(m_neighbors, requester)) {
			(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_requestInProgress);
			H225_RequestInProgress & rip = (*ras)->m_replyRAS;
			rip.m_requestSeqNum = ras->GetSeqNum();
			rip.m_delay = m_neighborTimeout;
			if (H225_NonStandardParameter *param = ras->GetNonStandardParam()) {
				int iec = Toolkit::iecUnknown;
				if (param->m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
					iec = Toolkit::Instance()->GetInternalExtensionCode((const H225_H221NonStandard&)param->m_nonStandardIdentifier);
				} else if (param->m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_object) {
					PASN_ObjectId &oid = param->m_nonStandardIdentifier;
					if (oid.GetDataLength() == 0)
						iec = Toolkit::iecNeighborId;
				}
				if (iec == Toolkit::iecNeighborId) {
					PString data = param->m_data.AsString() + ":" + PString(request.GetReqNumber());
					rip.IncludeOptionalField(H225_RequestInProgress::e_nonStandardData);
					rip.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
					H225_H221NonStandard &t35 = rip.m_nonStandardData.m_nonStandardIdentifier;
					t35.m_t35CountryCode = Toolkit::t35cPoland;
					t35.m_manufacturerCode = Toolkit::t35mGnuGk;
					t35.m_t35Extension = Toolkit::t35eNeighborId;
					rip.m_nonStandardData.m_data.SetValue(data);
				}
			}
			return true;
		}
	} else {
		LRQSender<LocationRequest> functor(lrq_obj);
		LRQRequester request(functor);
		if (request.Send(m_neighbors, requester)) {
			if (H225_LocationConfirm *lcf = request.WaitForDestination(m_neighborTimeout)) {
				Route route(m_name, lcf->m_callSignalAddress);
				route.m_routeId = request.GetNeighborUsed();
				route.m_flags |= Route::e_toNeighbor;
				lrq_obj.AddRoute(route);
				(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_locationConfirm);
				// canMapAlias: copy new destination if changed
				if (lrq_obj.GetRequest().HasOptionalField(H225_LocationRequest::e_canMapAlias)
					&& lrq_obj.GetRequest().m_canMapAlias
					&& lcf->HasOptionalField(H225_LocationConfirm::e_destinationInfo)
				    && (lcf->m_destinationInfo.GetSize() > 0)
					&& (lrq_obj.GetRequest().m_destinationInfo != lcf->m_destinationInfo)) {
					lrq_obj.GetRequest().m_destinationInfo = lcf->m_destinationInfo;
					lrq_obj.SetFlag(RoutingRequest::e_aliasesChanged);
				}
				H225_LocationConfirm & nlcf = (*ras)->m_replyRAS;
				CopyCryptoTokens(lcf, nlcf);
				return true;
			}
		}
	}
	return false;
}

bool NeighborPolicy::OnRequest(SetupRequest & setup_obj)
{
	LRQSender<SetupRequest> functor(setup_obj);
	LRQRequester request(functor);
	if (request.Send(m_neighbors)) {
		if (H225_LocationConfirm *lcf = request.WaitForDestination(m_neighborTimeout)) {
			Route route(m_name, lcf->m_callSignalAddress);
			route.m_routeId = request.GetNeighborUsed();
			route.m_flags |= Route::e_toNeighbor;
			setup_obj.AddRoute(route);
			CopyCryptoTokens(lcf, setup_obj.GetRequest());
			// canMapAlias: adjust new destination
			if (lcf->HasOptionalField(H225_LocationConfirm::e_destinationInfo)
				&& (lcf->m_destinationInfo.GetSize() > 0)
				&& (setup_obj.GetRequest().m_destinationAddress != lcf->m_destinationInfo)) {
				setup_obj.GetRequest().m_destinationAddress = lcf->m_destinationInfo;
				setup_obj.SetFlag(RoutingRequest::e_aliasesChanged);
			}
			return true;
		}
	}
	return false;
}

bool NeighborPolicy::OnRequest(FacilityRequest & facility_obj)
{
	LRQSender<FacilityRequest> functor(facility_obj);
	LRQRequester request(functor);
	if (request.Send(m_neighbors)) {
		if (H225_LocationConfirm *lcf = request.WaitForDestination(m_neighborTimeout)) {
			Route route(m_name, lcf->m_callSignalAddress);
			route.m_routeId = request.GetNeighborUsed();
			route.m_flags |= Route::e_toNeighbor;
			facility_obj.AddRoute(route);
			CopyCryptoTokens(lcf, facility_obj.GetRequest());
			return true;
		}
	}
	return false;
}


#ifdef hasSRV
class SRVPolicy : public AliasesPolicy {
public:
	SRVPolicy() { m_name = "SRV"; }

protected:
	// override from class Policy
	virtual bool FindByAliases(RoutingRequest &, H225_ArrayOf_AliasAddress &);
	virtual bool FindByAliases(LocationRequest &, H225_ArrayOf_AliasAddress &);

private:
	int m_Timeout;
};

bool SRVPolicy::FindByAliases(
	RoutingRequest &request,
	H225_ArrayOf_AliasAddress &aliases
	)
{
	for (PINDEX i = 0; i < aliases.GetSize(); ++i) {
		PString alias(AsString(aliases[i], FALSE));
	    if (alias.GetLength() == 0) continue;

	// DNS SRV Record lookup
		PString number;
		PString domain;
		PINDEX at = alias.Find('@');
		if (at == P_MAX_INDEX) {
		   number = "h323:t@" + alias;	
		   domain = alias;
	    } else {
		   number = "h323:" + alias;
		   domain = alias.Mid(at+1);
		}
	
		// LS Record lookup
		PStringList ls;
			if (PDNS::LookupSRV(number,"_h323ls._udp.",ls)) {
			 for (PINDEX i=0; i<ls.GetSize(); i++) {
				PINDEX at = ls[i].Find('@');
				PString ipaddr = ls[i].Mid(at + 1);
				PTRACE(4, "ROUTING\tSRV LS located domain " << domain << " at " << ipaddr);
				H323TransportAddress addr = H323TransportAddress(ipaddr);

				// Create a SRV gatekeeper object
				GnuGK * nb = new GnuGK();
				if (!nb->SetProfile(domain,addr)) {
					PTRACE(4, "ROUTING\tERROR setting SRV neighbor profile " << domain << " at " << addr);
					return false;
				}

				int m_neighborTimeout = GkConfig()->GetInteger(LRQFeaturesSection, "NeighborTimeout", 5) * 100;

				// Send LRQ to retreive callers signalling address 
				LRQSender<AdmissionRequest> functor((AdmissionRequest &)request);
				LRQRequester Request(functor);
				if (Request.Send(nb)) {
					if (H225_LocationConfirm *lcf = Request.WaitForDestination(m_neighborTimeout)) {
							Route route(m_name, lcf->m_callSignalAddress);
							request.AddRoute(route);
							request.SetFlag(RoutingRequest::e_aliasesChanged);
							return true;
				    }
				}
				PTRACE(4, "ROUTING\tDNS SRV LRQ Error for " << domain << " at " << ipaddr);
			 }
			}  

        // CS SRV Lookup
		PStringList cs;
		   if (PDNS::LookupSRV(number,"_h323cs._tcp.",cs)) {
			   for (PINDEX j=0; j<cs.GetSize(); j++) {
				 PTRACE(4, "ROUTING\tSRV CS converted remote party " << alias << " to " << cs[j]);
		         H225_TransportAddress dest;
				 PINDEX in = cs[j].Find('@');
                 PString dom = cs[j].Mid(in+1);
		         if (GetTransportAddress(dom, GK_DEF_ENDPOINT_SIGNAL_PORT, dest)) {
			       PIPSocket::Address addr;
			       if (!(GetIPFromTransportAddr(dest, addr) && addr.IsValid()))
				                    continue;
			       Route route(m_name, dest);
			       route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(dest);
			       request.AddRoute(route);
			       request.SetFlag(RoutingRequest::e_aliasesChanged);	
				 }
			   }
		     return true;
		   } 
	} 
  return false; 
}


bool SRVPolicy::FindByAliases(LocationRequest & request, H225_ArrayOf_AliasAddress & aliases)
{ 
    PTRACE(4, "ROUTING\tPolicy SRV not supported for LRQ");
	return false;  
}
#endif

namespace {
	SimpleCreator<NeighborPolicy> NeighborPolicyCreator("neighbor");

#ifdef hasSRV
	SimpleCreator<SRVPolicy> SRVPolicyCreator("srv");
#endif
}


} // end of namespace Routing
