// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// GkClient.h
//
// Copyright (c) Citron Network Inc. 2001-2002
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 02/27/2002
//
//////////////////////////////////////////////////////////////////

#ifndef GKCLIENT_H
#define GKCLIENT_H "@(#) $Id$"

#ifndef _PTLIB_H
#include <ptlib.h>
#include <ptlib/sockets.h>
#endif

#ifdef P_SOLARIS
#define map stl_map
#endif

#include <map>
#include <h235auth.h>
#include "RasListener.h"
#include "RasWorker.h"
#include "RasTbl.h"
#include "Neighbor.h"

class GK_RASListener;
class GkClient;

class GkClientWorker : public Abstract_H323RasWorker {
public:
	GkClientWorker(PPER_Stream initial_pdu, PIPSocket::Address rx_addr, WORD rx_port, GK_RASListener & server);
	virtual ~GkClientWorker();
	virtual void Main(); // Do the actual work.

protected:
/*	virtual void OnGCF(const H225_GatekeeperConfirm &);
	virtual void OnGRJ(const H225_GatekeeperReject &);
*/
	virtual void OnRCF(H225_RegistrationConfirm &);
	virtual void OnRRJ(H225_RegistrationReject &);
	virtual void OnACF(H225_AdmissionConfirm &);
	virtual void OnARJ(H225_AdmissionReject &);
	virtual void OnDRQ(H225_DisengageRequest &);
	virtual void OnURQ(H225_UnregistrationRequest &);
//	virtual void OnIRQ(H225_InfoRequest &);
private:
	GkClient & GetMaster();
};


class GKPendingList : public PendingList {
public:
	GKPendingList(int ttl) : PendingList(ttl) {}

	bool Insert(const H225_AdmissionRequest &, const endptr &, int);
	bool ProcessACF(const H225_RasMessage &, int);
	bool ProcessARJ(int);
};

class GkClient : public GK_RASListener {
public:
	GkClient(PIPSocket::Address address);

	void SendGRQ();
	void SendRRQ();
	void SendURQ();
	void SendARQ(const H225_AdmissionRequest &, const endptr &);
	void SendARQ(const H225_Setup_UUIE &, unsigned, const callptr &, const BOOL answer_call=TRUE);
	void SendDRQ(H225_RasMessage &);

	virtual void Main();
/*
	void OnGCF(const H225_GatekeeperConfirm &);
	void OnGRJ(const H225_GatekeeperReject &);
	void OnRCF(const H225_RegiswtrationConfirm &, PIPSocket::Address);
	void OnRRJ(const H225_RegistrationReject &, PIPSocket::Address);
	void OnACF(const H225_RasMessage &, PIPSocket::Address);
	void OnARJ(const H225_RasMessage &, PIPSocket::Address);
	bool OnDRQ(const H225_DisengageRequest &, PIPSocket::Address);
	bool OnURQ(const H225_UnregistrationRequest &, PIPSocket::Address);
	bool OnIRQ(const H225_InfoRequest &);
*/

	bool IsRegistered() const { return !m_endpointId.IsEmpty(); }

	bool RewriteE164(H225_AliasAddress & alias, bool);
	bool RewriteE164(H225_ArrayOf_AliasAddress & alias, bool);
	bool RewriteE164(Q931 &, H225_Setup_UUIE &, bool);

	void CheckRegistration();
	bool CheckGKIP(PIPSocket::Address gkip) { return m_gkaddr == gkip; }
	bool CheckGKIPVerbose(PIPSocket::Address);

	template<class RAS> void SetPassword(RAS & rasmsg, const PString & id)
	{
		if (!m_password) {
			rasmsg.IncludeOptionalField(RAS::e_cryptoTokens);
			SetCryptoTokens(rasmsg.m_cryptoTokens, id);
		}
	}
	template<class RAS> void SetPassword(RAS & rasmsg)
	{
		SetPassword(rasmsg, !m_e164 ? m_e164 : m_h323Id);
	}
	void RegisterFather(const PString & endpointId, const PString & gatekeeperId, int ttl);
	void UnRegister();
	void ProcessACF(H225_RasMessage &pdu, int seqNum);
	void ProcessARJ(int seqNum);
	const PString & GetEndpointId() const;
	const int GetRetry() const;
	const PString & GetH323Id() const {return m_h323Id;}
protected:
	virtual ~GkClient();
	friend void Toolkit::delete_gkclient();

private:
	typedef std::map<int, callptr>::iterator iterator;
	typedef std::map<int, callptr>::const_iterator const_iterator;

	friend void GkClientWorker::OnDRQ(H225_DisengageRequest&);

	void SendRas(const H225_RasMessage &);
	void BuildFullRRQ(H225_RegistrationRequest &);
	void BuildLightWeightRRQ(H225_RegistrationRequest &);
	int  BuildARQ(H225_AdmissionRequest &);
	bool GetAdmission(H225_RasMessage &, H225_RasMessage &);
	bool RewriteString(PString &, bool);
	void SetCryptoTokens(H225_ArrayOf_CryptoH323Token &, const PString &);

	PIPSocket::Address m_gkaddr;
	WORD m_gkport;
	H225_TransportAddress *m_callAddr, *m_rasAddr;

	PString m_h323Id, m_e164, m_password;
	PString m_endpointId, m_gatekeeperId;

	int m_ttl, m_retry;
	PTime m_registeredTime;
	PTimer reRegisterTimer;
	PDECLARE_NOTIFIER(PTimer, GkClient, OnTimeout);

	PStringToString m_rewriteInfo;

	GKPendingList *m_arqPendingList;
	std::map<int, callptr> m_arqAnsweredList;



	H235AuthSimpleMD5 auth;
};

#endif // __gkclient_h_
