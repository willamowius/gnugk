//////////////////////////////////////////////////////////////////
//
// GkClient.h
//
// Copyright (c) Citron Network Inc. 2001-2003
// Copyright (c) 2002-2017, Jan Willamowius
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
#include <map>

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

bool IsOIDForAlgo(const PString & oid, const PCaselessString & algo);

#ifdef HAS_H46023
class H460_FeatureStd;
class STUNClient;
class UDPProxySocket;
class H46024B_AlternateAddress;
class H46024B_ArrayOf_AlternateAddress;

class CallH46024Sockets
{
public:
	CallH46024Sockets(unsigned strategy);
	CallH46024Sockets(WORD sessionID, UDPProxySocket * rtp, UDPProxySocket * rtcp);
	~CallH46024Sockets();

	unsigned GetNatStrategy() const { return m_natStrategy; }
	unsigned GetSessionID() const { return m_sessionID; }
	void SetAlternate(PString cui, unsigned muxID, H323TransportAddress m_rtp, H323TransportAddress m_rtcp);
	void SetAlternate(const H46024B_AlternateAddress & alternate);
	void LoadAlternate(PString & cui, unsigned & muxID, H323TransportAddress & m_rtp, H323TransportAddress & m_rtcp);

protected:
	unsigned			m_natStrategy;
	WORD				m_sessionID;
	UDPProxySocket *	m_rtpSocket;
	UDPProxySocket *	m_rtcpSocket;
};

typedef std::map<H225_CallIdentifier, std::list<CallH46024Sockets> > GkNATSocketMap;

#endif // HAS_H46023

class GkClient {
public:
	typedef GkClient Base;

	GkClient();
	virtual ~GkClient();

	void OnReload();
	void CheckRegistration();
	bool CheckFrom(const RasMsg *) const;
	bool CheckFrom(const PIPSocket::Address & ip) const;
	bool CheckFrom(const H225_TransportAddress & addr) const;
	bool IsRegistered() const { return m_registered; }
	bool IsNATed() const { return m_natClient != NULL; }
	bool UsesH46018() const { return m_registeredH46018; }
	PString GetParent() const;
	bool UseTLS() const { return m_useTLS; }

	bool UsesAdditiveRegistration() const;
	bool AdditiveRegister(H225_ArrayOf_AliasAddress & aliases, int & rejectReason,
						H225_ArrayOf_ClearToken * tokens, H225_ArrayOf_CryptoH323Token * cryptotokens);
	bool AdditiveUnRegister(const H225_ArrayOf_AliasAddress & aliases);
	void AppendLocalAlias(const H225_ArrayOf_AliasAddress & aliases);
	void RemoveLocalAlias(const H225_ArrayOf_AliasAddress & aliases);

	bool OnSendingGRQ(H225_GatekeeperRequest & grq);
	bool OnSendingRRQ(H225_RegistrationRequest & rrq);
	bool OnSendingARQ(H225_AdmissionRequest & arq, Routing::AdmissionRequest & req);
	bool OnSendingLRQ(H225_LocationRequest & lrq, Routing::LocationRequest & req);
	bool OnSendingARQ(H225_AdmissionRequest & arq, Routing::SetupRequest & req, bool answer = false);
	bool OnSendingARQ(H225_AdmissionRequest & arq, Routing::FacilityRequest & req);
	bool OnSendingDRQ(H225_DisengageRequest & drq, const callptr & call);
	bool OnSendingURQ(H225_UnregistrationRequest & urq);

	bool SendARQ(Routing::AdmissionRequest &);
	bool SendLRQ(Routing::LocationRequest &);
	bool SendARQ(Routing::SetupRequest &, bool answer = false);
	bool SendARQ(Routing::FacilityRequest &);
	void SendDRQ(const callptr &);
	void SendURQ();

	// Signalling Messages
	bool HandleSetup(SetupMsg & setup, bool fromInternal);

	bool RewriteE164(H225_AliasAddress & alias, bool);
	bool RewriteE164(H225_ArrayOf_AliasAddress & alias, bool);
	bool RewriteE164(SetupMsg & setup, bool);

	/** Fills LRQ with approtiation tokens/cryptoTokens containing
		configured username/password data.
		Declared outside SetPassword template because it should not
		depend on authMode.
	*/
	void SetNBPassword(
		H225_LocationRequest & lrq, /// LRQ message to be filled with tokens
		const PString & id // username to be put inside tokens/cryptoTokens
		);

	/** Fills LRQ with approtiation tokens/cryptoTokens containing,
		taking both the username and the password from config [Endpoint]
		section.
	*/
	void SetNBPassword(
		H225_LocationRequest & lrq /// LRQ message to be filled with tokens
		)
	{
        SetPassword(lrq);
	}

	template<class RAS> void SetPassword(RAS & rasmsg, const PString & id)
	{
		for (PINDEX i = 0; i < m_h235Authenticators->GetSize();  i++) {
			H235Authenticator * authenticator = (H235Authenticator *)(*m_h235Authenticators)[i].Clone();

			if (authenticator) {
                authenticator->SetLocalId(id);
                authenticator->SetPassword(m_password);
                if (IsOIDForAlgo(m_authAlgo.AsString(), authenticator->GetName())
                        && authenticator->IsSecuredPDU(rasmsg.GetTag(), FALSE)) {
                    authenticator->SetLocalId(id);
                    authenticator->SetPassword(m_password);

                    if (authenticator->PrepareTokens(rasmsg.m_tokens, rasmsg.m_cryptoTokens)) {
                        PTRACE(4, "GKClient\tPrepared PDU with authenticator " << authenticator);
                    }
                }
                delete authenticator;
            }
		}
		if (rasmsg.m_tokens.GetSize() > 0)
			rasmsg.IncludeOptionalField(RAS::e_tokens);

		if (rasmsg.m_cryptoTokens.GetSize() > 0)
			rasmsg.IncludeOptionalField(RAS::e_cryptoTokens);
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
	PASN_ObjectId m_authAlgo;

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
	/// list of Authenticators
	H235Authenticators * m_h235Authenticators;

    // enable GnuGk's old NAT traversal method
    bool m_enableGnuGkNATTraversal;
	// enable H.460.18 (offer to parent)
	bool m_enableH46018;
	// registered with H.460.18 support
	bool m_registeredH46018;
	// use TLS with this parent
	bool m_useTLS;

#ifdef HAS_H46023
	// Handle H46023 RCF
	void H46023_RCF(H460_FeatureStd * feat);
    // Handle H46023 ACF
	void H46023_ACF(callptr m_call, H460_FeatureStd * feat);
    // Run STUN test
	void RunSTUNTest(const H323TransportAddress & addr);
    // Force Reregistration
	void H46023_ForceReregistration();
    // Notify NAT type
    bool H46023_TypeNotify(int & nattype);
	// detected NAT type
	int m_nattype;
	// notify of NAT type
	bool m_natnotify;
	// enable H.460.23 (offer to parent)
	bool m_enableH46023;
	// registered with H.460.23 support
	bool m_registeredH46023;
	// STUN Client
	STUNClient * m_stunClient;
	// ALG Detected
	bool m_algDetected;
    // Call NAT Strategy Map
	PMutex m_strategyMutex;
	GkNATSocketMap m_natstrategy;

public:
	// NAT type detected
	void H46023_TypeDetected(int nattype);
    // Create socket pair
	bool H46023_CreateSocketPair(const H225_CallIdentifier & id, PINDEX callNo, WORD sessionID, UDPProxySocket * & rtp, UDPProxySocket * & rtcp, bool & nated);
	// Set the NAT Strategy
	void H46023_SetNATStategy(const H225_CallIdentifier & id, unsigned nat);
	// Find the NAT Strategy
	CallRec::NatStrategy H46023_GetNATStategy(const H225_CallIdentifier & id);
	// Set the socketPair
	void H46023_SetSocketPair(const H225_CallIdentifier & id, WORD sessionID, UDPProxySocket * rtp, UDPProxySocket * rtcp);
	// Set Alternates (Annex A)
	void H46023_SetAlternates(const H225_CallIdentifier & id, WORD session, PString cui,
							unsigned muxID, H323TransportAddress m_rtp, H323TransportAddress m_rtcp);
	void H46023_LoadAlternates(const H225_CallIdentifier & id, WORD session, PString & cui,
							unsigned & muxID, H323TransportAddress & m_rtp, H323TransportAddress & m_rtcp);
	// Set Alternates (Annex B)
	void H46023_SetAlternates(const H225_CallIdentifier & id, const H46024B_ArrayOf_AlternateAddress & alternates);
#endif
};

#endif // GKCLIENT_H
