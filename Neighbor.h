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

#ifndef NEIGHBOR_H
#define NEIGHBOR_H "@(#) $Id$"

#include "RasListener.h"

extern const char *NeighborSection;
extern const char *LRQFeaturesSection;

class PendingList {
protected:
       class PendingARQ : public PObject{
	       PCLASSINFO(PendingARQ, PObject);
       public:
               PendingARQ(int, const H225_AdmissionRequest &, const endptr &, int);

               bool DoACF(const endptr &) const;
               bool DoARJ() const;
               bool CompSeq(int seqNum) const;
               bool IsStaled(int) const;
               void GetRequest(H225_AdmissionRequest &, endptr &) const;

               int DecCount();

       private:
               int m_seqNum;
               H225_AdmissionRequest m_arq;
               endptr m_reqEP;
               int m_Count;
               PTime m_reqTime;
       };

public:
	PendingList(int ttl) : pendingTTL(ttl) {}
	~PendingList();

	void Check();
	PINDEX FindBySeqNum(int);
	void RemoveAt(PINDEX i);

protected:
	int pendingTTL;
	PLIST(ARQList, PendingARQ);
        ARQList arqList;
	PMutex usedLock;

        static void delete_arq(PendingARQ *p) { delete p; }
};

class NBPendingList : public PendingList {
public:
	NBPendingList(int ttl) : PendingList(ttl) {}
	bool Insert(const H225_AdmissionRequest & obj_arq, const endptr & reqEP);
	void ProcessLCF(const H225_RasMessage & obj_ras);
	void ProcessLRJ(const H225_RasMessage & obj_ras);
	int SendLRQ(int seqNumber, H225_AdmissionRequest arq);

};

class NeighborList {
	class Neighbor {
	public:
		Neighbor(const PString &, const PString &);
		bool SendLRQ(int seqNum, const H225_AdmissionRequest &) const;
		bool ForwardLRQ(PIPSocket::Address, const H225_LocationRequest &) const;
		bool CheckIP(PIPSocket::Address ip) const;
		PString GetPassword() const;

	private:
		bool InternalSendLRQ(int seqNum, const H225_AdmissionRequest &) const;
		bool InternalForwardLRQ(const H225_LocationRequest &) const;
		bool ResolveName(PIPSocket::Address & ip) const;

		PString m_gkid;
		PString m_name;
		PString m_prefix;
		PString m_password;
		bool m_dynamic;
		mutable PIPSocket::Address m_ip;

		WORD m_port;
	};

public:
	class NeighborPasswordAuth : public GkAuthenticator {
	public:
		NeighborPasswordAuth(PConfig *cfg, const char *n) : GkAuthenticator(cfg, n) {}

	private:
		virtual int Check(const H225_GatekeeperRequest &, unsigned &)  { return e_next; }
		virtual int Check(const H225_RegistrationRequest &, unsigned &) { return e_next; }
		virtual int Check(const H225_UnregistrationRequest &, unsigned &) { return e_next; }
		virtual int Check(const H225_AdmissionRequest &, unsigned &) { return e_next; }
		virtual int Check(const H225_BandwidthRequest &, unsigned &) { return e_next; }
		virtual int Check(const H225_DisengageRequest &, unsigned &) { return e_next; }
		virtual int Check(const H225_LocationRequest &, unsigned &);
		virtual int Check(const H225_InfoRequest &, unsigned &) { return e_next; }

		virtual PString GetPassword(const PString &);
	};

	typedef std::list<Neighbor>::iterator iterator;
	typedef std::list<Neighbor>::const_iterator const_iterator;

	NeighborList(PConfig *);
	int SendLRQ(int seqNum, const H225_AdmissionRequest &);
	int ForwardLRQ(PIPSocket::Address, const H225_LocationRequest &);
	bool CheckIP(PIPSocket::Address ip) const;
	// only valid after calling CheckIP
	PString GetPassword() const { return tmppasswd; }
	void InsertSiblingIP(PIPSocket::Address ip) { siblingIPs.insert(ip); }

	class InvalidNeighbor {};

private:
	list<Neighbor> nbList;
	set<PIPSocket::Address> siblingIPs;
	mutable PString tmppasswd;
};

class Neighbor {
public:
	Neighbor();
	virtual BOOL InsertARQ(const H225_AdmissionRequest &arq, endptr RequestingEP);
	virtual void InsertSiblingIP(PIPSocket::Address &ipaddr);
	virtual BOOL CheckIP(PIPSocket::Address addr);
	virtual BOOL ForwardLRQ(PIPSocket::Address addr, H225_LocationRequest lrq);
	virtual PString GetPassword();
	virtual int SendLRQ(int seqnum, const H225_AdmissionRequest &arq );
	virtual void ProcessLCF(const H225_RasMessage & pdu);
	virtual void ProcessLRJ(const H225_RasMessage & pdu);

protected:
	virtual ~Neighbor();
	friend void Toolkit::delete_neighbor();

private:
	NBPendingList *pending;
	NeighborList *neighborGKs;
};


#endif /* _NEIGHBOR_H */
