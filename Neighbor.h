//////////////////////////////////////////////////////////////////
//
// Neighboring System for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2002-2003
// Copyright (c) 2004-2019, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef NEIGHBOR_H
#define NEIGHBOR_H "@(#) $Id$"

#include <list>
#include <map>
#include "Routing.h"
#include "gktimer.h"


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

class NeighborPingThread;

struct PrefixInfo {
	PrefixInfo() : m_length(0), m_priority(0) { }
	PrefixInfo(short int l, short int p) : m_length(l), m_priority(p) { }
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
	bool IsTraversalUser(const PString * user) const { return m_H46018Server && (m_authUser == *user); }
	bool IsTraversalZone(const PIPSocket::Address *ip) const { return (GetIP() == *ip) && (m_H46018Server || m_H46018Client); }
	bool IsTraversalClient(const PIPSocket::Address *ip) const { return (GetIP() == *ip) && m_H46018Server; }	// it is from a client, if we are the server
	bool IsTraversalServer(const PIPSocket::Address *ip) const { return (GetIP() == *ip) && m_H46018Client; }	// it is from a server, if we are the client
	void SetApparentIP(const PIPSocket::Address & ip, WORD port) { m_ip = ip; m_port = port; }
	bool ForwardResponse() const { return m_forwardResponse; }
	int ForwardLRQ() const { return m_forwardto; }
	WORD GetDefaultHopCount() const { return m_forwardHopCount; }
	PString GetId() const { return m_id; }
	PString GetGkId() const { return m_gkid; }
	PIPSocket::Address GetIP() const;
	WORD GetPort() const;
	H225_LocationRequest & BuildLRQ(H225_RasMessage & lrq_ras, WORD seq, const H225_ArrayOf_AliasAddress & dest);

	// new virtual functions

	// the real constructor, get profile of this neighbor
	virtual bool SetProfile(const PString & id, const PString & type, bool reload);
    // Sent profile based on SRV Record
	virtual bool SetProfile(const PString &, const H323TransportAddress &);

	void SetH46018Server(bool val) { m_H46018Server = val; }
	bool IsH46018Server() const { return m_H46018Server; }
	bool IsH46018Client() const { return m_H46018Client; }
	// send a H.460.18 keepAlive (triggered by a timer)
	void SendH46018GkKeepAlive(GkTimer* timer);
	void SetH46018GkKeepAliveInterval(int interval);
	// send a LRQ Ping (triggered by a timer)
	void SendLRQPing(GkTimer* timer);
	void SetLRQPingInterval(int interval);

	// get PrefixInfo for a given aliases
	// if an alias is matched, set dest to the alias
	virtual PrefixInfo GetPrefixInfo(const H225_ArrayOf_AliasAddress &, H225_ArrayOf_AliasAddress & dest);
	virtual PrefixInfo GetIPInfo(const H225_TransportAddress & ip, H225_ArrayOf_AliasAddress & dest) const;

	// callbacks before sending LRQ
	// LRQ will not be sent if false is returned
	virtual bool OnSendingLRQ(H225_LocationRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const AdmissionRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const LocationRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const SetupRequest &);
	virtual bool OnSendingLRQ(H225_LocationRequest &, const FacilityRequest &);

	// check if the given message is a valid reply from this neighbor
	virtual bool CheckReply(RasMsg *) const;

	// check if we require a password and if its correct
	virtual bool Authenticate(RasMsg *ras) const;
	// check if the given LRQ is acceptable
	virtual bool IsAcceptable(RasMsg *ras) const;
	virtual bool UseTLS() const { return m_useTLS; }

	virtual void SetDisabled(bool val) { m_disabled = val; }
	virtual bool IsDisabled() const { return m_disabled; }

protected:
	void SetForwardedInfo(const PString &);

	typedef std::map<PString, int, pstr_prefix_lesser> Prefixes;

	RasServer * m_rasSrv;
	PString m_id, m_gkid, m_password, m_name, m_authUser;
	mutable PIPSocket::Address m_ip;
	mutable WORD m_port;
	WORD m_forwardHopCount;
	bool m_dynamic;
	bool m_acceptForwarded;
	bool m_forwardResponse;
	int m_forwardto;
	Prefixes m_sendPrefixes;
	PString m_sendIPs;
	PStringArray m_sendAliases;
	PStringArray m_acceptPrefixes;
	bool m_externalGK;
	PString m_sendAuthUser, m_sendPassword;	// user + password to send to neighbor
	int m_keepAliveTimerInterval;
	GkTimerManager::GkTimerHandle m_keepAliveTimer;
	int m_lrqPingInterval;
	GkTimerManager::GkTimerHandle m_lrqPingTimer;
    NeighborPingThread * m_pingThread;
	bool m_H46018Server;
	bool m_H46018Client;
	bool m_useTLS;
	bool m_disabled; // is this neighbor disabled (eg. because of no responses)
	bool m_loopDetection;
};

class NeighborList {
public:
	typedef std::list<Neighbor *> List;

	NeighborList();
	virtual ~NeighborList();

	void OnReload();

	bool CheckLRQ(RasMsg *) const;
	bool CheckIP(const PIPSocket::Address &) const;
	bool IsTraversalClient(const PIPSocket::Address &) const;
	bool IsTraversalServer(const PIPSocket::Address &) const;

	// return the neighbor's ID from the list by signal address
	PString GetNeighborIdBySigAdr(const H225_TransportAddress & sigAd);
	PString GetNeighborIdBySigAdr(const PIPSocket::Address & sigAd);

	// return the neighbor's gatekeeper ID from the list by signal address
	PString GetNeighborGkIdBySigAdr(const H225_TransportAddress & sigAd);
	PString GetNeighborGkIdBySigAdr(const PIPSocket::Address & sigAd);

	// return the neighbor's use of TLS from the list by signal address
	bool GetNeighborTLSBySigAdr(const H225_TransportAddress & sigAd);
	bool GetNeighborTLSBySigAdr(const PIPSocket::Address & sigAd);

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
