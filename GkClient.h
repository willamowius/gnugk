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

#ifndef __gkclient_h_
#define __gkclient_h_

#ifndef _PTLIB_H
#include <ptlib.h>
#include <ptlib/sockets.h>
#endif

#ifdef P_SOLARIS
#define map stl_map
#endif

#include <map>
#include <set>
#include "RasTbl.h"
//#include <ptlib/timer.h>
//#include <ptlib/timeint.h>
//#include <h225.h>

class H225_AliasAddress;
class H225_ArrayOf_AliasAddress;
class H225_TransportAddress;
class H225_EndpointIdentifier;
class H225_EndpointType;
class H225_CallIdentifier;
class H225_RasMessage;
class H225_GatekeeperRequest;
class H225_GatekeeperConfirm;
class H225_GatekeeperReject;
class H225_RegistrationRequest;
class H225_RegistrationConfirm;
class H225_RegistrationReject;
class H225_AdmissionRequest;
class H225_AdmissionConfirm;
class H225_AdmissionReject;
class H225_DisengageRequest;
class H225_UnregistrationRequest;
class H225_InfoRequest;
class H225_Setup_UUIE;
class H225_ArrayOf_CryptoH323Token;
class Q931;
class H323RasSrv;
class PendingARQ;
class GKPendingList;

extern const char *EndpointSection;
extern const char *RewriteE164Section;

class GkClient {
public:
	GkClient(H323RasSrv *);
	~GkClient();
	
	void SendGRQ();
	void SendRRQ();
	void SendURQ();
	void SendARQ(const H225_AdmissionRequest &, const endptr &);
	void SendARQ(const H225_Setup_UUIE &, unsigned, const callptr &);

	void OnGCF(const H225_GatekeeperConfirm &);
	void OnGRJ(const H225_GatekeeperReject &);
	void OnRCF(const H225_RegistrationConfirm &, PIPSocket::Address);
	void OnRRJ(const H225_RegistrationReject &, PIPSocket::Address);
	void OnACF(const H225_RasMessage &, PIPSocket::Address);
	void OnARJ(const H225_RasMessage &, PIPSocket::Address);
	bool OnDRQ(const H225_DisengageRequest &, PIPSocket::Address);
	bool OnURQ(const H225_UnregistrationRequest &, PIPSocket::Address);
	bool OnIRQ(const H225_InfoRequest &);

	bool IsRegistered() const { return !m_endpointId; }

	bool RewriteE164(H225_AliasAddress & alias, bool);
	bool RewriteE164(H225_ArrayOf_AliasAddress & alias, bool);
	bool RewriteE164(Q931 &, H225_Setup_UUIE &, bool);

	void CheckRegistration();

private:
	typedef std::map<int, callptr>::iterator iterator;
	typedef std::map<int, callptr>::const_iterator const_iterator;

	void SendRas(const H225_RasMessage &);
	bool CheckGKIP(PIPSocket::Address);
	void BuildFullRRQ(H225_RegistrationRequest &);
	void BuildLightWeightRRQ(H225_RegistrationRequest &);
	int  BuildARQ(H225_AdmissionRequest &);
	bool GetAdmission(H225_RasMessage &, H225_RasMessage &);
	bool RewriteString(PString &, bool);
	void SetCryptoTokens(H225_ArrayOf_CryptoH323Token &);
	template<class RAS> void SetPassword(RAS & rasmsg)
	{
		if (!m_password) {
			rasmsg.IncludeOptionalField(RAS::e_cryptoTokens);
			SetCryptoTokens(rasmsg.m_cryptoTokens);
		}
	}

	H323RasSrv *m_rasSrv;

	WORD m_seqNum;

	PIPSocket::Address m_gkaddr;
	WORD m_gkport;
	H225_TransportAddress *m_callAddr, *m_rasAddr;

	PString m_h323Id, m_e164, m_password;
	PString m_endpointId, m_gatekeeperId;

	int m_ttl, m_retry;
	PTime m_registeredTime;

	PStringToString m_rewriteInfo;

	GKPendingList *m_arqPendingList;
	std::map<int, callptr> m_arqAnsweredList;
#ifdef WIN32 // a workaround for damn VC
	class CallIdentifier : public H225_CallIdentifier {
	public:
		CallIdentifier() {}
		CallIdentifier(const H225_CallIdentifier & callid) : H225_CallIdentifier(callid) {}

		void *operator new(size_t, void *_p) { return _p; }
		// placement delete, but not work for VC
		// void operator delete(void *, void *) {}
	};
#else
	typedef H225_CallIdentifier CallIdentifier;
#endif
	std::set<CallIdentifier> m_callIdTable;
};


#endif // __gkclient_h_
