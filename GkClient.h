//////////////////////////////////////////////////////////////////
//
// GkClient.h
//
// Copyright (c) Citron Network Inc. 2001-2003
// Copyright (c) 2002-2011, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef GKCLIENT_H
#define GKCLIENT_H "@(#) $Id$"

#include "gk_const.h"
#include "Toolkit.h"
#include "Routing.h"
#include "config.h"

class Q931;
class H225_AliasAddress;
class H225_ArrayOf_AliasAddress;
class H225_TransportAddress;
class H225_ArrayOf_TransportAddress;
class H225_EndpointIdentifier;
class H225_GatekeeperIdentifier;
class H225_RegistrationRequest;
class H225_AdmissionRequest;
class H225_LocationRequest;
class H225_Setup_UUIE;
class H225_ArrayOf_ClearToken;
class H225_ArrayOf_CryptoH323Token;

#ifdef HAS_H46023
  class H460_FeatureStd;
  class STUNClient;
  class UDPProxySocket;
#endif

class RasMsg;
class RasServer;
class AlternateGKs;
class RasRequester;
class NATClient;
class GkClientHandler;
class CallRec;
template<class> class SmartPtr;
typedef SmartPtr<CallRec> callptr;
class SignalingMsg;
template <class> class H225SignalingMsg;
typedef H225SignalingMsg<H225_Setup_UUIE> SetupMsg;

class GkClient {
public:
	typedef GkClient Base;

	GkClient();
	virtual ~GkClient();

	void OnReload();
	void CheckRegistration();
	bool CheckFrom(const RasMsg *) const;
	bool CheckFrom(const PIPSocket::Address & ip) const { return m_gkaddr == ip; }
	bool IsRegistered() const { return m_registered; }
	bool IsNATed() const { return m_natClient != NULL; }
	PString GetParent() const;

	bool UsesAdditiveRegistration();
	bool AdditiveRegister(H225_ArrayOf_AliasAddress & aliases, int & rejectReason, 
						H225_ArrayOf_ClearToken * tokens, H225_ArrayOf_CryptoH323Token * cryptotokens);
	bool AdditiveUnRegister(const H225_ArrayOf_AliasAddress & aliases);
	void AppendLocalAlias(const H225_ArrayOf_AliasAddress & aliases);
	void RemoveLocalAlias(const H225_ArrayOf_AliasAddress & aliases);

	bool OnSendingGRQ(H225_GatekeeperRequest &grq);
	bool OnSendingRRQ(H225_RegistrationRequest &rrq);
	bool OnSendingARQ(H225_AdmissionRequest &arq, Routing::AdmissionRequest &req);
	bool OnSendingLRQ(H225_LocationRequest &lrq, Routing::LocationRequest &req);
	bool OnSendingARQ(H225_AdmissionRequest &arq, Routing::SetupRequest &req, bool answer = false);
	bool OnSendingARQ(H225_AdmissionRequest &arq, Routing::FacilityRequest &req);
	bool OnSendingDRQ(H225_DisengageRequest &drq, const callptr &call);
	bool OnSendingURQ(H225_UnregistrationRequest &urq);
	
	bool SendARQ(Routing::AdmissionRequest &);
	bool SendLRQ(Routing::LocationRequest &);
	bool SendARQ(Routing::SetupRequest &, bool answer = false, int natoffload = 0);
	bool SendARQ(Routing::FacilityRequest &);
	void SendDRQ(const callptr &);
	void SendURQ();

	bool RewriteE164(H225_AliasAddress & alias, bool);
	bool RewriteE164(H225_ArrayOf_AliasAddress & alias, bool);
	bool RewriteE164(SetupMsg &setup, bool);

	/** Fills LRQ with approtiation tokens/cryptoTokens containing
		configured username/password data. 
		Declared outside SetPassword template because it should not 
		depend on authMode.
	*/
	void SetNBPassword(
		H225_LocationRequest& lrq, /// LRQ message to be filled with tokens
		const PString& id // username to be put inside tokens/cryptoTokens
		);

	/** Fills LRQ with approtiation tokens/cryptoTokens containing,
		taking both the username and the password from config [Endpoint]
		section.
	*/
	void SetNBPassword(
		H225_LocationRequest& lrq /// LRQ message to be filled with tokens
		)
	{
#ifdef OpenH323Factory
        SetPassword(lrq);
#else
		SetNBPassword(lrq, m_h323Id.GetSize() > 0 ? m_h323Id[0] :
			(m_e164.GetSize() > 0 ? m_e164[0] : PString::Empty())
			);
#endif
	}
		
	template<class RAS> void SetPassword(RAS & rasmsg, const PString & id)
	{

#ifdef OpenH323Factory
		for (PINDEX i = 0; i < m_h235Authenticators->GetSize();  i++) {
			H235Authenticator * authenticator = (H235Authenticator *)(*m_h235Authenticators)[i].Clone();

			if (authenticator && authenticator->IsSecuredPDU(rasmsg.GetTag(), FALSE)) {
				authenticator->SetLocalId(id);
				authenticator->SetPassword(m_password);

				if (authenticator->PrepareTokens(rasmsg.m_tokens, rasmsg.m_cryptoTokens)) {
					PTRACE(4, "GKClient\tPrepared PDU with authenticator " << authenticator);
				}
			}
			delete authenticator;
		}
		if (rasmsg.m_tokens.GetSize() > 0)
			rasmsg.IncludeOptionalField(RAS::e_tokens);

		if (rasmsg.m_cryptoTokens.GetSize() > 0)
			rasmsg.IncludeOptionalField(RAS::e_cryptoTokens);
#else
		if (!m_password) {
			// to avoid including h235.h
			// 2 == H235_AuthenticationMechanism::e_pwdHash
			// 7 == H235_AuthenticationMechanism::e_authenticationBES
			if (m_authMode < 0 || m_authMode == 2)
				rasmsg.IncludeOptionalField(RAS::e_cryptoTokens), SetCryptoTokens(rasmsg.m_cryptoTokens, id);
			if (m_authMode < 0 || m_authMode == 7)
				rasmsg.IncludeOptionalField(RAS::e_tokens), SetClearTokens(rasmsg.m_tokens, id);
		}
#endif
	}
	template<class RAS> void SetPassword(RAS & rasmsg)
	{
		SetPassword(rasmsg, m_h323Id.GetSize() > 0 ? m_h323Id[0] :
			(m_e164.GetSize() > 0 ? m_e164[0] : PString::Empty())
			);
	}

private:
	bool Discovery();
	void Register();
	void Unregister();
	bool GetAltGK();
	void BuildRRQ(H225_RegistrationRequest &);
	void BuildFullRRQ(H225_RegistrationRequest &);
	void BuildLightWeightRRQ(H225_RegistrationRequest &);
	bool WaitForACF(H225_AdmissionRequest &, RasRequester &, Routing::RoutingRequest *);
	H225_AdmissionRequest & BuildARQ(H225_AdmissionRequest &);

	void OnRCF(RasMsg *);
	void OnRRJ(RasMsg *);
	void OnARJ(RasMsg *);

	bool OnURQ(RasMsg *);
	bool OnDRQ(RasMsg *);
	bool OnBRQ(RasMsg *);
	bool OnIRQ(RasMsg *);

	bool RewriteString(PString &, bool) const;
	void SetClearTokens(H225_ArrayOf_ClearToken &, const PString &);
	void SetCryptoTokens(H225_ArrayOf_CryptoH323Token &, const PString &);
	void SetRasAddress(H225_ArrayOf_TransportAddress &);
	void SetCallSignalAddress(H225_ArrayOf_TransportAddress &);

	RasServer *m_rasSrv;

	PIPSocket::Address m_gkaddr, m_loaddr;
	WORD m_gkport;

	/// status of the registration with the parent gatekeeper
	bool m_registered;
	/// parent discovery status (DNS resolved, GRQ/GCF exchanged)
	bool m_discoveryComplete;
	PString m_password, m_rrjReason;
	H225_EndpointIdentifier m_endpointId;
	H225_GatekeeperIdentifier m_gatekeeperId;
	PMutex m_rrqMutex;

	/// Use Additive Registration
	PBoolean m_useAdditiveRegistration;

	/// reregistration timeout (seconds)
	long m_ttl;
	/// timeout to send a next RRQ (milliseconds)
	long m_timer;
	/// intial interval (seconds) between resending an RRQ message (seconds)
	long m_retry;
	/// current RRQ resend interval (double with each failure) (seconds)
	long m_resend;
	/// maximun RRQ resend interval (seconds)
	long m_gkfailtime;
	PTime m_registeredTime;

	AlternateGKs *m_gkList;
	bool m_useAltGKPermanent;
	int m_authMode;

	Toolkit::RewriteData *m_rewriteInfo;

	GkClientHandler *m_handlers[4];

	NATClient *m_natClient;
	
	enum ParentVendors {
		ParentVendor_Generic,
		ParentVendor_GnuGk,
		ParentVendor_Cisco
	};
	
	/// vendor of the parent gatekeeper
	int m_parentVendor;
	
	enum EndpointTypes {
		EndpointType_Terminal,
		EndpointType_Gateway
	};
	/// endpoint type to set in RRQs
	int m_endpointType;
	/// send GRQ prior to registration
	bool m_discoverParent;
	///	list of local prefixes, if #m_endpointType# is set to gateway
	PStringArray m_prefixes;
	/// list of H.323ID aliases to register with
	PStringArray m_h323Id;
	/// list of E.164 aliases to register with
	PStringArray m_e164;
#ifdef OpenH323Factory
	/// list of Authenticators
	H235Authenticators* m_h235Authenticators;
#endif

#ifdef HAS_H46023
	// Handle H46023 RCF
	void HandleP2P_RCF(H460_FeatureStd * feat);
    // Handle H46023 ACF
	void HandleP2P_ACF(callptr m_call, H460_FeatureStd * feat);
    // Notify NAT type
    bool H46023_TypeNotify(int & nattype);
	// detected NAT type
	int m_nattype;
	// notify of NAT type
	bool m_natnotify;
	// H.460.23 support
	bool gk_H460_23;
	// STUN Client
	STUNClient * m_stunClient;

public:
	// NAT type detected
	void H46023_TypeDetected(int nattype);
    // Create socket pair
    bool H46023_CreateSocketPair(const H225_CallIdentifier & id, UDPProxySocket * & rtp, UDPProxySocket * & rtcp, bool & nated);

#endif
};

#endif // GKCLIENT_H
