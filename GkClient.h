//////////////////////////////////////////////////////////////////
//
// GkClient.h
//
// Copyright (c) Citron Network Inc. 2001-2003
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
#include "Toolkit.h"
#include "Routing.h"

class Q931;
class H225_AliasAddress;
class H225_ArrayOf_AliasAddress;
class H225_TransportAddress;
class H225_ArrayOf_TransportAddress;
class H225_EndpointIdentifier;
class H225_GatekeeperIdentifier;
class H225_RegistrationRequest;
class H225_AdmissionRequest;
class H225_Setup_UUIE;
class H225_ArrayOf_CryptoH323Token;

class RasMsg;
class RasServer;
class AlternateGKs;
class RasRequester;
class NATClient;
class GkClientHandler;
class CallRec;
template<class> class SmartPtr;
typedef SmartPtr<CallRec> callptr;

class GkClient {
public:
	GkClient(RasServer *);
	~GkClient();

	void OnReload();
	void CheckRegistration();
	bool CheckFrom(const RasMsg *) const;
	bool CheckFrom(const PIPSocket::Address & ip) { return m_gkaddr == ip; }
	bool IsRegistered() const { return m_registered; }
	bool IsNATed() const { return m_natClient != 0; }
	PString GetParent() const;

	bool SendARQ(Routing::AdmissionRequest &);
	bool SendLRQ(Routing::LocationRequest &);
	bool SendARQ(Routing::SetupRequest &, bool = false);
	bool SendARQ(Routing::FacilityRequest &);
	bool SendARQ(const H225_Setup_UUIE &, unsigned, callptr &);
	void SendDRQ(const callptr &);
	void SendURQ();

	bool RewriteE164(H225_AliasAddress & alias, bool);
	bool RewriteE164(H225_ArrayOf_AliasAddress & alias, bool);
	bool RewriteE164(Q931 &, H225_Setup_UUIE &, bool);

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

private:
	bool Discovery();
	void Register();
	void Unregister();
	bool GetAltGK();
	void BuildRRQ(H225_RegistrationRequest &);
	void BuildFullRRQ(H225_RegistrationRequest &);
	void BuildLightWeightRRQ(H225_RegistrationRequest &);
	bool WaitForACF(RasRequester &, Routing::RoutingRequest *);
	H225_AdmissionRequest & BuildARQ(H225_AdmissionRequest &);

	void OnRCF(RasMsg *);
	void OnRRJ(RasMsg *);
	void OnARJ(RasMsg *);

	bool OnURQ(RasMsg *);
	bool OnDRQ(RasMsg *);
	bool OnBRQ(RasMsg *);
	bool OnIRQ(RasMsg *);

	bool RewriteString(PString &, bool) const;
	void SetCryptoTokens(H225_ArrayOf_CryptoH323Token &, const PString &);
	void SetRasAddress(H225_ArrayOf_TransportAddress &);
	void SetCallSignalAddress(H225_ArrayOf_TransportAddress &);

	RasServer *m_rasSrv;

	PIPSocket::Address m_gkaddr, m_loaddr;
	WORD m_gkport;

	bool m_discovery, m_registered;
	PString m_h323Id, m_e164, m_password, m_rrjReason;
	H225_EndpointIdentifier *m_endpointId;
	H225_GatekeeperIdentifier *m_gatekeeperId;
	PMutex m_rrqMutex;

	int m_ttl, m_retry, m_resend, m_gkfailtime;
	PTime m_registeredTime;

	AlternateGKs *m_gkList;
	bool m_useAltGKPermanent;

	Toolkit::RewriteData *m_rewriteInfo;

	GkClientHandler *m_handlers[4];

	NATClient *m_natClient;
};

#endif // GKCLIENT_H
