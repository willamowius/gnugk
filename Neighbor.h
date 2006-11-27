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

#ifndef NEIGHBOR_H
#define NEIGHBOR_H "@(#) $Id$"

#include <list>
#include <map>
#include "Routing.h"


class H225_RasMessage;
class H225_AdmissionRequest;
class H225_LocationRequest;
class H225_Setup_UUIE;
class H225_Facility_UUIE;
class H225_TransportAddress;
class H225_AliasAddress;
class H225_ArrayOf_AliasAddress;
class H225_CryptoH323Token;

class RasMsg;
class RasServer;

namespace Neighbors {


using Routing::AdmissionRequest;
using Routing::LocationRequest;
using Routing::SetupRequest;
using Routing::FacilityRequest;


struct PrefixInfo {
	PrefixInfo() {}
	PrefixInfo(short int l, short int p) : m_length(l), m_priority(p) {}
	operator bool() const { return m_length >= 0; }
	bool operator<(PrefixInfo) const;

	short int m_length;   // length of matched prefix
	short int m_priority;
};

inline bool PrefixInfo::operator<(PrefixInfo o) const
{
	return m_length > o.m_length || (m_length == o.m_length && m_priority < o.m_priority);
}

class Neighbor {
public:
	typedef Neighbor Base;	// for SimpleCreator template

	Neighbor();
	virtual ~Neighbor();

	bool SendLRQ(H225_RasMessage &);
	bool IsFrom(const PIPSocket::Address *ip) const { return GetIP() == *ip; }
	bool ForwardResponse() const { return m_forwardResponse; }
	int ForwardLRQ() const { return m_forwardto; }
	WORD GetDefaultHopCount() const { return m_forwardHopCount; }
	PString GetId() const { return m_id; }
	PIPSocket::Address GetIP() const;
	H225_LocationRequest & BuildLRQ(H225_RasMessage &, WORD, const H225_ArrayOf_AliasAddress &);

	// new virtual functions

	// the real constructor, get profile of this neighbor
	virtual bool SetProfile(const PString &, const PString &);
    // Sent profile based on SRV Record
	virtual bool SetProfile(const PString &, const H323TransportAddress &);

	// get PrefixInfo for a given aliases
	// if an alias is matched, set dest to the alias
	virtual PrefixInfo GetPrefixInfo(const H225_ArrayOf_AliasAddress &, H225_ArrayOf_AliasAddress & dest);

	// callbacks before sending LRQ
	// LRQ will not be sent if false is returned
	virtual bool OnSendingLRQ(H225_LocationRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const AdmissionRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const LocationRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const SetupRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const FacilityRequest &);

	// check if the given message is a valid reply from this neighbor
	virtual bool CheckReply(RasMsg *) const;

	// check if the given LRQ is acceptable
	virtual bool IsAcceptable(RasMsg *ras) const;

protected:
	void SetForwardedInfo(const PString &);

	typedef std::map<PString, int, pstr_prefix_lesser> Prefixes;

	RasServer *m_rasSrv;
	PString m_id, m_gkid, m_password, m_name;
	mutable PIPSocket::Address m_ip;
	mutable WORD m_port;
	WORD m_forwardHopCount;
	bool m_dynamic;
	bool m_acceptForwarded;
	bool m_forwardResponse;
	int m_forwardto;
	Prefixes m_sendPrefixes;
	PStringArray m_acceptPrefixes;
	bool m_externalGK;
};

class NeighborList {
public:
	typedef std::list<Neighbor *> List;

	NeighborList();
	~NeighborList();

	void OnReload();

	bool CheckLRQ(RasMsg *) const;
	bool CheckIP(const PIPSocket::Address &) const;

	// Return the neighbors Id from the list from the signal address.
	PString GetNeighborIdBySigAdr(const H225_TransportAddress & sigAd);
	PString GetNeighborIdBySigAdr(const PIPSocket::Address & sigAd);

	operator List & () { return m_neighbors; }
	operator const List & () const { return m_neighbors; }

private:
	List m_neighbors;
};

/* Not used currently
H225_CryptoH323Token BuildAccessToken(const H225_TransportAddress &, const PIPSocket::Address &);
*/
bool DecodeAccessToken(const H225_CryptoH323Token &, const PIPSocket::Address &, H225_TransportAddress &);


} // end of namespace Neighbors

#endif // NEIGHBOR_H
