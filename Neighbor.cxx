// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2002 Nils Bokermann <Nils.Bokermann@mediaWays.net>
//
// PURPOSE OF THIS FILE: Neighboring features.
//
// - Automatic Version Information via RCS:
//   $Id$
//   $Source$
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//

#include "Neighbor.h"
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "GkClient.h"

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = NEIGHBOR_H;
#endif /* lint */

extern const char *NeighborSection = "RasSvr::Neighbors";
extern const char *LRQFeaturesSection = "RasSvr::LRQFeatures";

PendingList::~PendingList()
{
	for (PINDEX i=0; i < arqList.GetSize(); i++) {
		arqList[i].DoARJ();
		arqList.RemoveAt(i);
	}
}

void PendingList::Check()
{

	PWaitAndSignal lock(usedLock);
	for (PINDEX i = 0; i < arqList.GetSize(); i++){
		if(arqList[i].IsStaled(pendingTTL)){
			arqList[i].DoARJ();
			arqList.RemoveAt(i);
		}
	}
}

PINDEX
PendingList::FindBySeqNum(int seqnum)
{
	PINDEX i;
	BOOL not_found = TRUE;
	for (i=0; not_found && i<arqList.GetSize(); i++) {
		if (arqList[i].CompSeq(seqnum))
			not_found = FALSE;
	}
	return --i;
}

void
PendingList::RemoveAt(PINDEX number)
{
	arqList.RemoveAt(number);
}

PendingList::PendingARQ::PendingARQ(int seqNum, const H225_AdmissionRequest & obj_arq, const endptr & reqEP, int Count)
      : m_seqNum(seqNum), m_arq(obj_arq), m_reqEP(reqEP), m_Count(Count)
{
}

bool PendingList::PendingARQ::DoACF(const endptr & called) const
{
	PTRACE(1, "Doing ACF with EP: " << (endptr(NULL)==called ? PString("NULL"): called->GetEndpointIdentifier()));
	PPER_Stream stream;

	H225_RasMessage pdu;
	pdu.SetTag(H225_RasMessage::e_admissionRequest);
	H225_AdmissionRequest & arq = pdu;
	arq=m_arq;
       	pdu.Encode(stream);
	H225_RasMessage abc;
	stream.SetPosition(0);
	if(abc.Decode(stream))
		PTRACE(1, "dec: " << abc);
	else
		PTRACE(1, "didn't dec:");
	stream.SetPosition(0);
//	stream.CompleteEncoding();

	const H225_TransportAddress_ipAddress & ip = m_reqEP->GetRasAddress();
	PIPSocket::Address ipaddress(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);

	NeighborWorker *n = new NeighborWorker(stream, called, ipaddress, ip.m_port, (Toolkit::Instance()->GetMasterRASListener()));
	n->Resume();
	return true;
}

bool PendingList::PendingARQ::DoARJ() const
{
	DoACF(endptr(NULL));
	// RasSrv->ReplyARQ(m_reqEP, endptr(NULL), m_arq);
	return true;
}

bool PendingList::PendingARQ::CompSeq(int seqNum) const
{
       return (m_seqNum == seqNum);
}

bool PendingList::PendingARQ::IsStaled(int sec) const
{
       return (PTime() - m_reqTime).GetSeconds() > sec;
}

void PendingList::PendingARQ::GetRequest(H225_AdmissionRequest & arq, endptr & ep) const
{
       arq = m_arq, ep = m_reqEP;
}

int PendingList::PendingARQ::DecCount()
{
       return --m_Count;
}

bool NBPendingList::Insert(const H225_AdmissionRequest & obj_arq, const endptr & reqEP)
{
	// TODO: check if ARQ duplicate
	int seqNumber = Toolkit::Instance()->GetRequestSeqNum();
	int nbCount = Toolkit::Instance()->GetNeighbor().SendLRQ(seqNumber, obj_arq);
	if (nbCount > 0) {
		PWaitAndSignal lock(usedLock);
		arqList.Append(new PendingARQ(seqNumber, obj_arq, reqEP, nbCount));
		return true;
	}
	return false;
}

void NBPendingList::ProcessLCF(const H225_RasMessage & obj_ras)
{
	const H225_LocationConfirm & obj_lcf = obj_ras;

	PTRACE(1, "ProcessingLCF");
	// TODO: check if the LCF is sent from my neighbors
	PWaitAndSignal lock(usedLock);
	PINDEX nr = FindBySeqNum(obj_lcf.m_requestSeqNum.GetValue());
	if (P_MAX_INDEX==nr || nr >= arqList.GetSize()) {
		PTRACE(2, "GK\tUnknown LCF, ignore!");
		return;
	}
	endptr called = RegistrationTable::Instance()->InsertRec(const_cast<H225_RasMessage &>(obj_ras));
	if (!called) {
		PTRACE(2, "GK\tUnable to add EP for this LCF!");
		return;
	}

	arqList[nr].DoACF(called);
	RemoveAt(nr);
}

void NBPendingList::ProcessLRJ(const H225_RasMessage & obj_ras)
{
	PTRACE(1, "ProcessingLRJ");
	const H225_LocationReject & obj_lrj = obj_ras;

	// TODO: check if the LRJ is sent from my neighbors
	PWaitAndSignal lock(usedLock);
	PTRACE(1, "arqList: ");
	for (PINDEX i=0; i<arqList.GetSize(); i++)
		PTRACE(1, "arqlist["<<i<<"]:" << arqList[i]);
	PINDEX nr = FindBySeqNum(obj_lrj.m_requestSeqNum.GetValue());
	PTRACE(5, "Found nr: " << nr);
	if (P_MAX_INDEX == nr || nr >= arqList.GetSize()) {
		PTRACE(2, "GK\tUnknown LRJ, ignore!");
		return;
	}

	if (arqList[nr].DecCount() == 0) {
		arqList[nr].DoARJ();
		RemoveAt(nr);
	}
}

NeighborList::Neighbor::Neighbor(const PString & gkid, const PString & cfgs) : m_gkid(gkid)
{
	PStringArray cfg(cfgs.Tokenise(",;", TRUE));
	PString ipAddr = cfg[0].Trim();
	PINDEX p = ipAddr.Find(':');
	m_name = ipAddr.Left(p);
	m_port = (p != P_MAX_INDEX) ? ipAddr.Mid(p+1).AsUnsigned() : GK_DEF_UNICAST_RAS_PORT;
	m_prefix = (cfg.GetSize() > 1) ? cfg[1] : PString("*");
	if (cfg.GetSize() > 2)
		m_password = cfg[2];
	m_dynamic = (cfg.GetSize() > 3) ? Toolkit::AsBool(cfg[3]) : false;

	if (!m_dynamic && !PIPSocket::GetHostAddress(m_name, m_ip))
		throw InvalidNeighbor();
	PTRACE(1, "Add neighbor " << m_gkid << '(' << (m_dynamic ? m_name : m_ip.AsString()) << ':' << m_port << ')' << ((!m_prefix) ? (" for prefix " + m_prefix) : PString()));
}

inline bool NeighborList::Neighbor::CheckIP(PIPSocket::Address ip) const
{
       return (!m_dynamic || ResolveName(m_ip)) ? ip == m_ip : false;
}

inline PString NeighborList::Neighbor::GetPassword() const
{
       return m_password;
}

bool NeighborList::Neighbor::SendLRQ(int seqNum, const H225_AdmissionRequest &  obj_arq) const
{
       if (m_prefix.IsEmpty())
               return false;
       else if (m_prefix == "*")
               return InternalSendLRQ(seqNum, obj_arq);

       for (PINDEX i = 0; i < obj_arq.m_destinationInfo.GetSize(); ++i)
               if (AsString(obj_arq.m_destinationInfo[i], FALSE).Find(m_prefix) == 0)
                       return InternalSendLRQ(seqNum, obj_arq);

       return false;
}

bool NeighborList::Neighbor::InternalSendLRQ(int seqNum, const H225_AdmissionRequest & obj_arq) const
{
	PIPSocket::Address ip = m_ip;
	if (m_dynamic && !ResolveName(ip))
		return false;
	H225_RasMessage obj_ras;
	obj_ras.SetTag(H225_RasMessage::e_locationRequest);
	H225_LocationRequest & obj_lrq = obj_ras;
	obj_lrq.m_requestSeqNum.SetValue(seqNum);
	obj_lrq.m_replyAddress = Toolkit::Instance()->GetMasterRASListener().GetRasAddress(ip);
	obj_lrq.m_destinationInfo = obj_arq.m_destinationInfo;

	// tell the neighbor who I am
	obj_lrq.IncludeOptionalField(H225_LocationRequest::e_sourceInfo);
	obj_lrq.m_sourceInfo.SetSize(1);
	H323SetAliasAddress(Toolkit::GKName(), obj_lrq.m_sourceInfo[0]);
	Toolkit::Instance()->GetGkClient().SetPassword(obj_lrq, Toolkit::GKName());

	int hotCount = GkConfig()->GetInteger(LRQFeaturesSection, "ForwordHopCount", 0);
	if (hotCount > 1) { // what if set hotCount = 1?
		obj_lrq.IncludeOptionalField(H225_LocationRequest::e_hopCount);
		obj_lrq.m_hopCount = hotCount;
	}
	Toolkit::Instance()->GetMasterRASListener().SendTo(obj_ras, ip, m_port);
	return true;
}

bool NeighborList::Neighbor::ForwardLRQ(PIPSocket::Address ip, const H225_LocationRequest & obj_lrq) const
{
	if (m_prefix.IsEmpty())
		return false;
	if ((m_dynamic && !ResolveName(m_ip)) || ip == m_ip || !obj_lrq.HasOptionalField(H225_LocationRequest::e_hopCount))
		return false; // don't forward to GK that sent the LRQ or LRQ without hotCount

	if (m_prefix == "*")
		return InternalForwardLRQ(obj_lrq);

	for (PINDEX i = 0; i < obj_lrq.m_destinationInfo.GetSize(); ++i)
		if (AsString(obj_lrq.m_destinationInfo[i], FALSE).Find(m_prefix) == 0)
			return InternalForwardLRQ(obj_lrq);

	return false;
}

bool NeighborList::Neighbor::InternalForwardLRQ(const H225_LocationRequest & obj_lrq) const
{
	int hotCount = obj_lrq.m_hopCount;
	if (--hotCount > 0) {
		H225_RasMessage obj_ras;
		obj_ras.SetTag(H225_RasMessage::e_locationRequest);
		H225_LocationRequest & lrq = obj_ras;
		lrq = obj_lrq;
		lrq.m_hopCount = hotCount;
		Toolkit::Instance()->GetMasterRASListener().SendTo(obj_ras, m_ip, m_port);
		return true;
	}
	return false;
}

bool NeighborList::Neighbor::ResolveName(PIPSocket::Address & ip) const
{
       PIPSocket::ClearNameCache();
       // Retrieve the ip address at this time
       if (PIPSocket::GetHostAddress(m_name, ip)) {
               PTRACE(3, "Retrieve neighbor ip for " << m_name << '=' << ip);
               return true;
       } else {
               PTRACE(1, "Can't get neighbor ip for " << m_name);
               return false;
       }
}

NeighborList::NeighborList(PConfig *config)
{
	PStringToString cfgs(config->GetAllKeyValues(NeighborSection));
	for (PINDEX i=0; i < cfgs.GetSize(); i++) {
		try {
			nbList.push_back(Neighbor(cfgs.GetKeyAt(i), cfgs.GetDataAt(i)));
		} catch (InvalidNeighbor) {
			PTRACE(1, "Bad neighbor " << cfgs.GetKeyAt(i));
			// ignore it :p
		}
	}
}

int NeighborList::SendLRQ(int seqNum, const H225_AdmissionRequest & obj_arq)
{
	int nbCount = 0;
	const_iterator Iter, eIter = nbList.end();
	for (Iter = nbList.begin(); Iter != eIter; ++Iter)
		if (Iter->SendLRQ(seqNum, obj_arq))
			++nbCount;

       PTRACE_IF(2, nbCount, "GK\tSend LRQ to " << nbCount << " neighbor(s)");
       return nbCount;
}

int NeighborList::ForwardLRQ(PIPSocket::Address ip, const H225_LocationRequest & obj_lrq)
{
       int nbCount = 0;
       const_iterator Iter, eIter = nbList.end();
       for (Iter = nbList.begin(); Iter != eIter; ++Iter)
               if (Iter->ForwardLRQ(ip, obj_lrq))
                       ++nbCount;

       PTRACE_IF(2, nbCount, "GK\tForward LRQ to " << nbCount << " neighbor(s)");
       return nbCount;
}

bool NeighborList::CheckIP(PIPSocket::Address ip) const
{
       const_iterator Iter = find_if(
               nbList.begin(), nbList.end(),
               bind2nd(mem_fun_ref(&Neighbor::CheckIP), ip)
       );
       if (Iter != nbList.end()) {
               tmppasswd = Iter->GetPassword();
               return true;
       }
       std::set<PIPSocket::Address>::const_iterator it = siblingIPs.find(ip);
       return (it != siblingIPs.end());
}

int NeighborList::NeighborPasswordAuth::Check(const H225_LocationRequest & lrq, unsigned & rsn)
{
       PString nullid;
       return (!GetPassword(nullid)) ? GkAuthenticator::Check(lrq, rsn) : e_next;
}

PString NeighborList::NeighborPasswordAuth::GetPassword(const PString &)
{
	return Toolkit::Instance()->GetNeighbor().GetPassword();
}

static GkAuthInit<NeighborList::NeighborPasswordAuth> N_B_A("NeighborPasswordAuth");


// Class Neighbor

Neighbor::Neighbor()
{
	pending = new NBPendingList(GkConfig()->GetInteger(LRQFeaturesSection, "NeighborTimeout", 2));
	neighborGKs = new NeighborList(GkConfig());
}

Neighbor::~Neighbor()
{
	delete pending;
	delete neighborGKs;
}

BOOL
Neighbor::InsertARQ(const H225_AdmissionRequest &arq, endptr RequestingEP)
{
	return pending->Insert(arq, RequestingEP);
}

void Neighbor::InsertSiblingIP(PIPSocket::Address &ipaddr)
{
	neighborGKs->InsertSiblingIP(ipaddr);
}

BOOL
Neighbor::CheckIP(PIPSocket::Address addr) {
	return neighborGKs->CheckIP(addr);
}

BOOL
Neighbor::ForwardLRQ(PIPSocket::Address addr, H225_LocationRequest lrq)
{
	return neighborGKs->ForwardLRQ(addr, lrq);
}

PString
Neighbor::GetPassword()
{
	return neighborGKs->GetPassword();
}

int
Neighbor::SendLRQ(int seqnum, const H225_AdmissionRequest &arq)
{
	return neighborGKs->SendLRQ(seqnum, arq);
}

void
Neighbor::ProcessLCF(const H225_RasMessage & pdu)
{
	PTRACE(1, "Processing LCF!");
	pending->ProcessLCF(pdu);
}

void
Neighbor::ProcessLRJ(const H225_RasMessage & pdu)
{
	PTRACE(1, "Processing LRJ!");
	pending->ProcessLRJ(pdu);
}
