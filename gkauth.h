//////////////////////////////////////////////////////////////////
//
// gkauth.h
//
// Copyright (c) 2001-2010, Jan Willamowius
//
// Gatekeeper authentication modules
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef GKAUTH_H
#define GKAUTH_H "@(#) $Id$"

#include <map>
#include <list>
#include "name.h"
#include "rwlock.h"
#include <h235auth.h>
#include "Toolkit.h"
#include "h323util.h"

class H225_GatekeeperRequest;
class H225_GatekeeperConfirm;
class H225_RegistrationRequest;
class H225_UnregistrationRequest;
class H225_AdmissionRequest;
class H225_BandwidthRequest;
class H225_DisengageRequest;
class H225_LocationRequest;
class H225_InfoRequest;
class H225_ArrayOf_ClearToken;
class H225_ArrayOf_CryptoH323Token;
class H225_ArrayOf_AliasAddress;
class H225_ArrayOf_AuthenticationMechanism;
class H225_ArrayOf_PASN_ObjectId;
class H225_TransportAddress;
class H225_ArrayOf_TransportAddress;
class H235_AuthenticationMechanism;
class PASN_ObjectId;
class H235Authenticators;
class H235Authenticator;
class H225_Setup_UUIE;
class SignalingMsg;
template <class> class H225SignalingMsg;
typedef H225SignalingMsg<H225_Setup_UUIE> SetupMsg;

class EndpointRec;
class CallRec;
template<class> class SmartPtr;
typedef SmartPtr<EndpointRec> endptr;
typedef SmartPtr<CallRec> callptr;

template<class> class RasPDU;
template<class> struct RasInfo;

namespace Routing {
struct Route;
}

/// Data read/written during RRQ processing by all configured 
/// authenticator modules
struct RRQAuthData
{
	RRQAuthData() : m_rejectReason(-1), m_billingMode(-1) {}
		
	/// -1 if not set, H225_RegistrationRejectReason enum otherwise
	int m_rejectReason;
	/// optional user's account balance amount string
	PString m_amountString;
	/// H225_CallCreditServiceControl_billingMode or -1, if not defined
	int m_billingMode;
};

/// Data read/written during ARQ processing by all configured 
/// authenticator modules
struct ARQAuthData
{
	ARQAuthData(
		const ARQAuthData& obj
		);
	ARQAuthData(
		const endptr& ep,
		const callptr& call
		);
	virtual ~ARQAuthData();
		
	ARQAuthData& operator=(const ARQAuthData& obj);
		
	void SetRouteToAlias(H225_AliasAddress* alias);
	void SetRouteToAlias(const H225_AliasAddress& alias);
	void SetRouteToAlias(const PString& alias, int tag = -1);
		
	/// -1 if not set, H225_AdmissionRejectReason enum otherwise
	int m_rejectReason;
	/// -1 if not set, max allowe call duration in seconds otherwise
	long m_callDurationLimit;
	/// disabled codecs
	PString m_disabledcodecs;
	/// endpoint that sent the request
	endptr m_requestingEP;
	/// call associated with the request (if any, only for answering ARQ)
	callptr m_call;
	/// input/output - set or get Calling-Station-Id
	PString m_callingStationId;		
	/// call party to be billed for the call (if other then Calling-Station-Id)
	PString m_callLinkage;
	/// input/output - set or get Called-Station-Id
	PString m_calledStationId;
	/// number dialed by the user (Called-Station-Id before rewrite)
	PString m_dialedNumber;
	/// optional user's account balance amount string
	PString m_amountString;
	/// H225_CallCreditServiceControl_billingMode or -1, if not defined
	int m_billingMode;
	/// if not NULL, route the call to the specified alias
	H225_AliasAddress* m_routeToAlias;
	/// if not empty, route the call to the specified destinations
	std::list<Routing::Route> m_destinationRoutes;
	/// override global proxy setting from the config (see #CallRec::ProxyMode enum#)
	int m_proxyMode;
	/// RADIUS Class attribute, if found in Access-Accept/Access-Reject
	PBYTEArray m_radiusClass;
	/// ID provided by client, to be passed out with accounting events
	PUInt64 m_clientAuthId;
	
private:
	ARQAuthData();
};
	
/// Data read/written during Q.931/H.225.0 Setup processing 
/// by all authenticators
struct SetupAuthData
{
	SetupAuthData(
		const SetupAuthData& obj
		);
	SetupAuthData(
		/// call associated with the message (if any)
		const callptr& call,
		/// is the Setup message from a registered endpoint
		bool fromRegistered
		);
	virtual ~SetupAuthData();
		
	SetupAuthData& operator=(const SetupAuthData& obj);
	
	void SetRouteToAlias(H225_AliasAddress* alias);
	void SetRouteToAlias(const H225_AliasAddress& alias);
	void SetRouteToAlias(const PString& alias, int tag = -1);

	/// -1 if not set, H225_ReleaseCompleteReason enum otherwise
	int m_rejectReason;
	/// -1 if not set, Q931 cause value otherwise
	int m_rejectCause;
	/// -1 if not set, max allowe call duration in seconds otherwise
	long m_callDurationLimit;
	/// disabled codecs
	PString m_disabledcodecs;
	/// call associated with the message (if any)
	callptr m_call;
	/// is the Setup message from a registered endpoint
	bool m_fromRegistered;
	/// input/output - set or get Calling-Station-Id
	PString m_callingStationId;		
	/// input/output - set or get Called-Station-Id
	PString m_calledStationId;
	/// number dialed by the user (Called-Station-Id before rewrite)
	PString m_dialedNumber;
	/// if not NULL, route the call to the specified alias
	H225_AliasAddress* m_routeToAlias;
	/// if not empty, route the call to the specified destinations
	std::list<Routing::Route> m_destinationRoutes;
	/// override global proxy setting from the config (see #CallRec::ProxyMode enum#)
	int m_proxyMode;
	/// RADIUS Class attribute, if found in Access-Accept/Access-Reject
	PBYTEArray m_radiusClass;
	/// ID provided by client, to be passed out with accounting events
	PUInt64 m_clientAuthId;
		
private:
	SetupAuthData();
};

/** The base class for all authenticator modules. Authenticator modules
    are used to authenticate/authorized RAS and Q.931 messages sent 
    by endpoints and to check if the endpoints are authorized to use 
    H.323 network resources.
	
    The modules are stackable - each request can be checked by multiple
    modules to get the final authentication result.
	
    Derived classes usually override one or more Check virtual methods
    to implement specific authentication mechanism.
*/
class GkAuthenticator : public NamedObject
{
public:
	/// processing rule for the authenticator
	enum Control {
		/// if this module cannot determine authentication success or failure
		/// (due to some missing info, for example), remaining modules will
		/// decide about acceptation/rejection of the reqest,
		/// if the request is accepted it is passed to a next rule
		e_Optional, 
		/// the request has to be authenticated by this module
		/// and processing is continued with remaining modules
		e_Required, 
		/// if the request is authenticated by this module, authentication
		/// is successful, otherwise the request is rejected
		/// (no further modules are processed in both cases)
		e_Sufficient,
		/// if the request is accepted/rejected by this module, authentication
		/// processing ends, otherwise the request is passed to a next rule
		e_Alternative
	};

	/// authentication status returned from Check methods
	enum Status {
		e_ok = 1, /// the request is authenticated and accepted
		e_fail = -1, /// the request is authenticated and rejected
		e_next = 0 /// the module could not authenticate the request
	};

	/// bit masks for event types other than RAS - see miscCheckFlags variable
	enum MiscCheckEvents {
		e_Setup = 0x0001, /// Q.931/H.225 Setup message
		e_SetupUnreg = 0x0002 /// Q.931/H.225 Setup message only from an unregistered endpoint
	};

	

	/** Build a new authenticator object with the given name.
	    It is important to pass proper check flags to signal, which checks
	    are supported/implemented by this authenticator.
	*/
	GkAuthenticator(
		const char* name, /// a name for the module (to be used in the config file)
		unsigned supportedRasChecks = ~0U, /// RAS checks supported by this module
		unsigned supportedMiscChecks = ~0U /// non-RAS checks supported by this module
		);
		
	virtual ~GkAuthenticator();

		
	/** @return
	    true if this authenticator provides H.235 compatible security.
	    It simply checks if m_h235Authenticators list is not empty.
	*/
	virtual bool IsH235Capable() const;
	
	/** If the authenticator supports H.235 security,
	    this call returns H.235 security capabilities
	    associated with it. It scans list pointed by m_h235Authenticators.
		
	    @return
	    true if H.235 security is supported by this authenticator 
	    and capabilities has been set.
	*/
	virtual bool GetH235Capability(
		/// append supported authentication mechanism to this array
		H225_ArrayOf_AuthenticationMechanism& mechanisms,
		/// append supported algorithm OIDs for the given authentication
		/// mechanism
		H225_ArrayOf_PASN_ObjectId& algorithmOIDs
		) const;

	/** Check if this authenticator supports the given
	    H.235 capability (mechanism+algorithmOID) by scanning
	    the m_h235Authenticators list of H.235 capabilities.
		
	    @return
	    true if the capability is supported by this module.
	*/
	virtual bool IsH235Capability(
		/// authentication mechanism
		const H235_AuthenticationMechanism& mechanism,
		/// algorithm OID for the given authentication mechanism
		const PASN_ObjectId& algorithmOID
		) const;

	/** @return
	    Control flag determining authenticator behaviour
	    (optional, sufficient, required).
	*/
	Control GetControlFlag() const { return m_controlFlag; }

	/** @return
	    True if the check is supported (implemented) by this authenticator.
	*/
	bool IsRasCheckEnabled(
		unsigned rasCheck
		) const { return (m_enabledRasChecks & m_supportedRasChecks & rasCheck) == rasCheck; }

	/** @return
	    True if the check is supported (implemented) by this authenticator.
	*/
	bool IsMiscCheckEnabled(
		unsigned miscCheck
		) const { return (m_enabledMiscChecks & m_supportedMiscChecks & miscCheck) == miscCheck; }

	
	/** Virtual methods overriden in derived classes to perform
		the actual authentication. The first parameter is a request
	    to be checked, the second is a H225_XXXRejectReason that can
	    be set if the authentication rejects the request.
		
	    @return
	    e_fail - authentication rejected the request
	    e_ok - authentication accepted the request
	    e_next - authentication is not supported for this request
	             or cannot be determined (SQL failure, no cryptoTokens, ...)
	*/
	virtual int Check(RasPDU<H225_GatekeeperRequest>& req, unsigned& rejectReason);
	virtual int Check(RasPDU<H225_UnregistrationRequest>& req, unsigned& rejectReason);
	virtual int Check(RasPDU<H225_BandwidthRequest>& req, unsigned& rejectReason);
	virtual int Check(RasPDU<H225_DisengageRequest>& req, unsigned& rejectReason);
	virtual int Check(RasPDU<H225_LocationRequest>& req, unsigned& rejectReason);
	virtual int Check(RasPDU<H225_InfoRequest>& req, unsigned& rejectReason);

	/** Authenticate/Authorize RAS or signaling message.
	
	    @return
	    e_fail - authentication rejected the request
	    e_ok - authentication accepted the request
	    e_next - authentication is not supported for this request
	             or cannot be determined (SQL failure, no cryptoTokens, ...)
	*/
	virtual int Check(
		/// RRQ to be authenticated/authorized
		RasPDU<H225_RegistrationRequest>& request,
		/// authorization data (reject reason, ...)
		RRQAuthData& authData
		);
	virtual int Check(
		/// ARQ to be authenticated/authorized
		RasPDU<H225_AdmissionRequest>& request, 
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData& authData
		);
	virtual int Check(
		/// Q.931/H.225 Setup to be authenticated
		SetupMsg &setup, 
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData& authData
		);

	/** Get human readable information about current module state
	    that can be displayed on the status port interface.
		
		@return
		A string (may contain multiple lines) with module information.
		Each line (including the last one) has to be ended with \r\n.
	*/
	virtual PString GetInfo();

protected:
	/** @return
	    Default authentication status, if not determined by Check... method.
	*/
	int GetDefaultStatus() const { return m_defaultStatus; }

	/** @return
	    Config that contains settings for this authenticator.
	*/
	PConfig* GetConfig() const { return m_config; }

	/** Should be called only from derived constructor to add supported
	    H.235 capabilities (if any).
	*/
	void AppendH235Authenticator(
		H235Authenticator* h235Auth /// H.235 authenticator to append
		);

	/** @return
	    A string that can be used to identify an account name
	    associated with the call.
	*/
	virtual PString GetUsername(
		/// RRQ message with additional data
		const RasPDU<H225_RegistrationRequest>& request
		) const;
	virtual PString GetUsername(
		/// ARQ message with additional data
		const RasPDU<H225_AdmissionRequest>& request,
		/// additional data, like call record and requesting endpoint
		ARQAuthData& authData
		) const;
	virtual PString GetUsername(
		/// Q.931/H.225 Setup with additional data
		const SetupMsg &setup, 
		/// additional data
		SetupAuthData &authData
		) const;

	/** @return
	    A string that can be used to identify a calling number.
	*/
	virtual PString GetCallingStationId(
		/// ARQ message with additional data
		const RasPDU<H225_AdmissionRequest>& request,
		/// additional data, like call record and requesting endpoint
		ARQAuthData& authData
		) const;
	virtual PString GetCallingStationId(
		/// Q.931/H.225 Setup to be authenticated
		const SetupMsg &setup, 
		/// additional data
		SetupAuthData& authData
		) const;

	/** @return
	    A string that can be used to identify a calling number.
	*/
	virtual PString GetCalledStationId(
		/// ARQ message with additional data
		const RasPDU<H225_AdmissionRequest>& request,
		/// additional data, like call record and requesting endpoint
		ARQAuthData& authData
		) const;
	virtual PString GetCalledStationId(
		/// Q.931/H.225 Setup to be authenticated
		const SetupMsg &setup, 
		/// additional data
		SetupAuthData& authData
		) const;

	/// @return	Number actually dialed by the user (before rewrite)
	PString GetDialedNumber(
		/// ARQ message with additional data
		const RasPDU<H225_AdmissionRequest>& request,
		/// additional data
		ARQAuthData& authData
		) const;
		
	/// @return	Number actually dialed by the user (before rewrite)
	virtual PString GetDialedNumber(
		/// Q.931/H.225 Setup to be authenticated
		const SetupMsg &setup, 
		/// additional data
		SetupAuthData& authData
		) const;

	/// a list of H.235 capabilities supported by this module (if any)
	H235Authenticators* m_h235Authenticators;

private:
	GkAuthenticator();
	GkAuthenticator(const GkAuthenticator&);
	GkAuthenticator & operator=(const GkAuthenticator&);

private:
	/// default status to be returned, if not determined otherwise
	Status m_defaultStatus;
	/// processing rule for this authenticator
	Control m_controlFlag;
	/// bit flags for RAS messages to be authenticated (this enforces the limit
	/// of first 32 RAS messages being supported)
	unsigned m_enabledRasChecks;
	/// bit flags with RAS checks supported by a given authenticator
	unsigned m_supportedRasChecks;
	/// bit flags for other event types to be authenticated (like Q.931 Setup)
	unsigned m_enabledMiscChecks;
	/// bit flags with non-RAS checks supported by a given authenticator
	unsigned m_supportedMiscChecks;
	/// authenticator config
	PConfig* m_config;
};

/** Cache used by some authenticators to remember key-value associations,
    like username-password. It increases performance, as backend 
    does not need to be queried each time.
*/
class CacheManager 
{
public:
	CacheManager(
		long timeout = -1 /// cache timeout - expiry period (seconds)
		) : m_ttl(timeout) {}

	/** Get a value associated with the key.
	
	    @return
	    true if association has been found and the value is valid,
	    false if the key-value pair is not cached or the cache expired
	*/
	bool Retrieve(
		const PString& key, /// the key to look for
		PString& value /// filled with the value on return
		) const;
		
	/// Store a key-value association in the cache
	void Save(
		const PString& key, /// a key to be stored
		const PString& value /// a value to be associated with the key
		);

	void SetTimeout(
		long newTimeout /// new cache expiration timeout
		) { m_ttl = newTimeout; }

private:
	CacheManager(const CacheManager&);
	CacheManager & operator=(const CacheManager&);
	
private:
	/// cache timeout (seconds), 0 = do not cache, -1 = never expires
	long m_ttl;
	/// cached key-value pairs
	std::map<PString, PString> m_cache;
	/// timestamps for key-value pair expiration calculation
	std::map<PString, time_t> m_ctime;
	/// mutex for multiple read/mutual write access to the cache
	mutable PReadWriteMutex m_rwmutex;
};      

/** A base class for all authenticators that only checks if username-password
    pairs match. This authenticator checks H.235 tokens/cryptoTokens carried
    inside RAS requests. Currently, only simple MD5 password hash and Cisco CAT
    authentication token types are supported.
	
    Derived authenticators usually override only GetPassword virtual method.
*/
class SimplePasswordAuth : public GkAuthenticator 
{
public:
	enum SupportedRasChecks {
		/// bitmask of RAS checks implemented by this module
		SimplePasswordAuthRasChecks = RasInfo<H225_GatekeeperRequest>::flag
			| RasInfo<H225_RegistrationRequest>::flag
			| RasInfo<H225_UnregistrationRequest>::flag
			| RasInfo<H225_BandwidthRequest>::flag
			| RasInfo<H225_DisengageRequest>::flag
			| RasInfo<H225_LocationRequest>::flag
			| RasInfo<H225_InfoRequest>::flag
			| RasInfo<H225_AdmissionRequest>::flag
	};

	SimplePasswordAuth(
		const char* name, /// a name for this module (a config section name)
		unsigned supportedRasChecks = SimplePasswordAuthRasChecks,
		unsigned supportedMiscChecks = 0 /// none supported
		);
		
	virtual ~SimplePasswordAuth();

	// overriden from class GkAuthenticator
	virtual int Check(RasPDU<H225_GatekeeperRequest>& req, unsigned& rejectReason);
	virtual int Check(RasPDU<H225_UnregistrationRequest>& req, unsigned& rejectReason);
	virtual int Check(RasPDU<H225_BandwidthRequest>& req, unsigned& rejectReason);
	virtual int Check(RasPDU<H225_DisengageRequest>& req, unsigned& rejectReason);
	virtual int Check(RasPDU<H225_LocationRequest>& req, unsigned& rejectReason);
	virtual int Check(RasPDU<H225_InfoRequest>& req, unsigned& rejectReason);

	/** Authenticate/Authorize RAS or signaling message. 
	    An override from GkAuthenticator.
	
	    @return
	    e_fail - authentication rejected the request
	    e_ok - authentication accepted the request
	    e_next - authentication is not supported for this request
	             or cannot be determined (SQL failure, no cryptoTokens, ...)
	*/
	virtual int Check(
		/// RRQ to be authenticated/authorized
		RasPDU<H225_RegistrationRequest>& request, 
		/// authorization data (reject reason, ...)
		RRQAuthData& authData
		);
	virtual int Check(
		/// ARQ to be authenticated/authorized
		RasPDU<H225_AdmissionRequest>& request, 
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData& authData
		);

protected:
	/** Get a password associated with the identifier.
	
	    @return
	    true if the password is returned, false if the password 
	    could not be found.
	*/
	virtual bool GetPassword(
		const PString& id, /// get the password for this id
		PString& passwd /// filled with the password on return
		);
	
	/** Validate username/password carried inside the tokens. This method
	    supports only CAT and clear text tokens.
		
	    @return
	    e_ok if the username/password carried inside the tokens is valid,
	    e_fail if the username/password carried inside the tokens is invalid,
	    e_next if no recognized tokens have been found
	*/
	virtual int CheckTokens(
		/// an array of tokens to be checked
		const H225_ArrayOf_ClearToken& tokens,
		/// aliases for the endpoint that generated the tokens
		const H225_ArrayOf_AliasAddress* aliases
		);
		
	/** Validate username/password carried inside the tokens. This method
	    supports only simple MD5 pwdHash cryptoTokens.
		
	    @return
	    e_ok if the username/password carried inside the tokens is valid,
	    e_fail if the username/password carried inside the tokens is invalid,
	    e_next if no recognized tokens have been found
	*/
	virtual int CheckCryptoTokens(
		/// an array of cryptoTokens to be checked
		const H225_ArrayOf_CryptoH323Token& cryptoTokens, 
		/// aliases for the endpoint that generated the tokens
		const H225_ArrayOf_AliasAddress* aliases,
		/// raw data for RAS PDU - required to validate some tokens
		/// like H.235 Auth Procedure I
		const PBYTEArray& rawPDU
		);

	/** Retrieve username carried inside the tokens. 
	    @return
	    username carried inside the token
	*/
	bool ResolveUserName(
		/// an array of tokens to be checked
		const H225_ArrayOf_ClearToken& tokens,
		/// aliases for the endpoint that generated the tokens
	    const H225_ArrayOf_CryptoH323Token& crytotokens,
		/// UserName detected.
		PString & username
		);

	/** A family of template functions that check tokens/cryptoTokens
	    inside RAS messages.
		
	    @return
	    e_ok if the username/password carried inside the tokens is valid,
	    e_fail if the username/password carried inside the tokens is invalid,
	    e_next if no recognized tokens have been found
	*/
	template<class RAS> int doCheck(
		/// RAS request to be authenticated
		const RasPDU<RAS>& request,
		/// list of aliases for the endpoint sending the request
		const H225_ArrayOf_AliasAddress* aliases = NULL
		)
	{
		const RAS& req = request;
		bool finalResult = false;
		
#ifdef OpenH323Factory

		if (m_h235Authenticators == NULL) {
			PTRACE(4, "GKAUTH\tSuccess: No Loaded Authenticators");
			return e_ok;
		}

		PString username = PString();
		PString password = PString();
		if (!ResolveUserName(req.m_tokens, req.m_cryptoTokens,username)) {
            PTRACE(4, "GKAUTH\t" << GetName() << " No username resolved from tokens.");
			return e_fail;
		}

		if ((aliases == NULL) || (FindAlias(*aliases, username) == P_MAX_INDEX)) {
            PTRACE(4, "GKAUTH\t" << GetName() << " Token username " << username << " does not match aliases for Endpoint");
			return e_fail;
		}

		if (!InternalGetPassword(username, password)) {
				PTRACE(4, "GKAUTH\t" << GetName() << " password not found for " << username );
			// do not return false let the authenticator decide whether it requires a password or not.
		}

        for (PINDEX i = 0; i < m_h235Authenticators->GetSize();  i++) {
          H235Authenticator * authenticator = (H235Authenticator *)(*m_h235Authenticators)[i].Clone();

		  authenticator->SetLocalId(Toolkit::GKName());
		  authenticator->SetRemoteId(username);
		  authenticator->SetPassword(password);

          H235Authenticator::ValidationResult result = authenticator->ValidateTokens(req.m_tokens, 
			                                                        req.m_cryptoTokens, request->m_rasPDU);
          switch (result) {
             case H235Authenticator::e_OK :
               PTRACE(4, "GKAUTH\tAuthenticator " << authenticator->GetName() << " succeeded");
               return e_ok;

             case H235Authenticator::e_Absent :
               PTRACE(6, "GKAUTH\tAuthenticator " << authenticator->GetName() << " absent from PDU");
               break;

             case H235Authenticator::e_Disabled :
               PTRACE(6, "GKAUTH\tAuthenticator " << authenticator->GetName() << " disabled");
               break;

             default : // Various other failure modes
               PTRACE(6, "GKAUTH\tAuthenticator " << authenticator->GetName() << " failed: " << (int)result);
               return e_fail;
           }

         }
#else
		int result;
		if (req.HasOptionalField(RAS::e_cryptoTokens)) {
			if ((result = CheckCryptoTokens(req.m_cryptoTokens, aliases, 
					request->m_rasPDU)) == e_fail)
				return e_fail;
			finalResult = (result == e_ok);
		}
		if (req.HasOptionalField(RAS::e_tokens)) {
			if ((result = CheckTokens(req.m_tokens, aliases)) == e_fail)
				return e_fail;
			finalResult = finalResult || (result == e_ok);
		}
#endif
		return finalResult ? e_ok : GetDefaultStatus();
	}

	/// Set new timeout for username/password pairs cache
	void SetCacheTimeout(
		long newTimeout
		) { m_cache->SetTimeout(newTimeout); }

	/** @return
	    True if usernames should match one of endpoint aliases.
	*/
	bool GetCheckID() const { return m_checkID; }

private:
	/** Get password for the given user. Examine password cache first.
	
	    @return
	    true if the password has been found.
    */
	bool InternalGetPassword(
		const PString& id, /// get the password for this id
		PString& passwd /// filled with the password on return
		);

	SimplePasswordAuth();
	SimplePasswordAuth(const SimplePasswordAuth&);
	SimplePasswordAuth& operator=(const SimplePasswordAuth&);
	
private:
	/// an encryption key used to decrypt passwords from the config file
	int m_encryptionKey;
	/// if true, generalID has to be also in the endpoint alias list
	bool m_checkID;
	/// cache for username/password pairs
	CacheManager* m_cache;
	/// list of H.235 algorithms to disable
	PStringArray m_disabledAlgorithms;
};


#ifdef H323_H350

/// H.350 authenticator for H.235 enabled endpoints
class H350PasswordAuth : public SimplePasswordAuth
{
public:
	/// build authenticator reading settings from the config
	H350PasswordAuth(
		/// name for this authenticator and for the config section to read settings from
		const char* authName
		);
	
	virtual ~H350PasswordAuth();

protected:
	/** Override from SimplePasswordAuth.
	
	    @return
	    True if the password has been found for the given alias.
	*/
	virtual bool GetPassword(
		/// alias to check the password for
		const PString& alias,
		/// password string, if the match is found
		PString& password
		);

};

#endif


/** A base class for all authenticators that validate endpoints (requests)
    by alias and/or IP address only.
	
    Derived authenticators usually override GetAuthConditionString virtual 
    method only.
*/
class AliasAuth : public GkAuthenticator 
{
public:
	enum SupportedRasChecks {
		/// bitmask of RAS checks implemented by this module
		AliasAuthRasChecks = RasInfo<H225_RegistrationRequest>::flag
	};

	AliasAuth(
		const char* name, /// a name for this module (a config section name)
		unsigned supportedRasChecks = AliasAuthRasChecks,
		unsigned supportedMiscChecks = 0
		);

	virtual ~AliasAuth();
	
	/// an override from GkAuthenticator
	virtual int Check(
		/// RRQ to be authenticated/authorized
		RasPDU<H225_RegistrationRequest>& request, 
		/// authorization data (reject reason, ...)
		RRQAuthData& authData
		);

protected:
	/** Validate that the signaling addresses match the given condition.
	    The condition consists of one or more auth rules.
		
	    @return
	    true if the signaling addresses match the condition.
	*/
	virtual bool doCheck(
		/// an array of source signaling addresses for an endpoint that sent the request
		const H225_ArrayOf_TransportAddress& sigaddr,
		/// auth condition string as returned by GetAuthConditionString
		const PString& condition
		);
		
	/** Validate that the signaling address matches the given auth rule.
	
	    @return
	    true if the signal address matches the rule.
	*/
	virtual bool CheckAuthRule(
		/// a signaling address for the endpoint that sent the request
		const H225_TransportAddress& sigaddr,
		/// the auth rule to be used for checking
		const PString& authrule
		);

	/** Get AliasAuth condition string for the given alias. 
	    This implementation searches RasSrv::RRQAuth section for the string.
	    The string is then used to accept/reject the request, optionally
	    checking its source signaliing addresses. The string consists of
	    one or more auth rules separated by '|' or '&' character.
		
		@return
		The AliasAuth condition string for the given alias.
	 */
	virtual bool GetAuthConditionString(
		/// an alias the condition string is to be retrieved for
		const PString& alias,
		/// filled with auth condition string that has been found
		PString& authCond
		);

	/// Set new timeout for username/password pairs cache
	void SetCacheTimeout(
		long newTimeout
		) { m_cache->SetTimeout(newTimeout); }
		
private:
	/** Get auth condition string for the given user. 
	    Examine the cache first.
	
	    @return
	    true if the auth condition string has been found.
    */
	bool InternalGetAuthConditionString(
		const PString& id, /// get the password for this id
		PString& authCond /// filled with the auth condition string on return
		);
		
	AliasAuth();
	AliasAuth(const AliasAuth&);
	AliasAuth& operator=(const AliasAuth&);
	
private:
	/// cache for username/password pairs
	CacheManager* m_cache;
};


/** A list of authenticators. Usually created as a single global object
    by the RasServer.
*/
class GkAuthenticatorList 
{
public:
	/// creates an empty list - OnRealod builds the actual stack of authenticator
	GkAuthenticatorList();
	virtual ~GkAuthenticatorList();

	/// read the config file and build a new stack of authenticator modules
	void OnReload();
	
	/** Select H.235 authentication mechanisms supported both by the endpoint
	    sending GRQ and all the authenticators, and copy these into GCF.
	    If no common H.235 capabilities can be found, do not select 
	    any authentication mechanisms with GCF.
	*/
	void SelectH235Capability(
		const H225_GatekeeperRequest& grq, 
		H225_GatekeeperConfirm& gcf
		);

	/** Authenticate the request through all configured authenticators.
	    Currently, only RAS requests are supported.
				
	    @return
	    true if the request should be accepted, false to reject the request.
	*/
	template<class RAS> bool Validate(
		/// the request to be validated by authenticators
		RasPDU<RAS>& request,
		/// H225_RegistrationRejectReason to be set if the request is rejected
		unsigned& rejectReason
		)
	{
		ReadLock lock(m_reloadMutex);
		std::list<GkAuthenticator*>::const_iterator i = m_authenticators.begin();
		while (i != m_authenticators.end()) {
			GkAuthenticator* auth = *i++;
			if (auth->IsRasCheckEnabled(RasInfo<RAS>::flag)) {
				const int result = auth->Check(request, rejectReason);
				if (result == GkAuthenticator::e_ok) {
					PTRACE(3, "GKAUTH\t" << auth->GetName() << ' ' 
						<< request.GetTagName() << " check ok"
						);
					if (auth->GetControlFlag() == GkAuthenticator::e_Sufficient
							|| auth->GetControlFlag() == GkAuthenticator::e_Alternative)
						return true;
				} else if (result == GkAuthenticator::e_fail) {
					PTRACE(3, "GKAUTH\t" << auth->GetName() << ' '
						<< request.GetTagName() << " check failed"
						);
					return false;
				}
			}
		}
		return true;
	}
	
	/** Authenticate and authorize RRQ through all configured authenticators.
				
	    @return
	    true if the endpoint should be registered, false to send RRJ.
	*/
	bool Validate(
		/// RRQ to be validated by authenticators
		RasPDU<H225_RegistrationRequest>& request,
		/// authorization data (reject reason, ...)
		RRQAuthData& authData
		);
		
	/** Authenticate and authorize (set call duration limit) ARQ 
	    through all configured authenticators.
				
	    @return
	    true if the call should be admitted, false to send ARJ.
	*/
	bool Validate(
		/// ARQ to be validated by authenticators
		RasPDU<H225_AdmissionRequest>& request,
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData& authData
		);
	
	/** Authenticate and authorize (set call duration limit) Q.931/H.225 Setup 
	    through all configured authenticators.
				
	    @return
	    true if the call should be accepted, false to send ReleaseComplete.
	*/
	bool Validate(
		/// Q.931/H.225 Setup to be authenticated
		SetupMsg &setup, 
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData& authData
		);

	/** Get a module information string for the selected module.
	
	    @return
		The module information string for status port diplay.
	*/
	PString GetInfo(
		const PString &moduleName /// module to retrieve information for
		) {
		ReadLock lock(m_reloadMutex);
		std::list<GkAuthenticator*>::const_iterator i = m_authenticators.begin();
		while (i != m_authenticators.end()) {
			GkAuthenticator* auth = *i++;
			if (auth->GetName() == moduleName)
				return auth->GetInfo();
		}
		return moduleName + " module not found\r\n";
	}

private:
	GkAuthenticatorList(const GkAuthenticatorList&);
	GkAuthenticatorList& operator=(const GkAuthenticatorList&);

private:
	/// a list of all configured authenticators
	std::list<GkAuthenticator*> m_authenticators;
	/// reload/destroy mutex
	PReadWriteMutex m_reloadMutex;
	/// the most common authentication capabilities 
	/// shared by all authenticators on the list
#ifdef OpenH323Factory
    H235Authenticators m_h235authenticators;
#else
	H225_ArrayOf_AuthenticationMechanism* m_mechanisms;
	H225_ArrayOf_PASN_ObjectId* m_algorithmOIDs;
#endif
};

/** A factory template for authenticator objects. When you create
    your own authenticator class (derived from GkAuthenticator),
    you need to register it and tell the gatekeeper how to instantiate it.
    You can do it by putting the following code:
	
    namespace {
        GkAuthCreator<MyAuthClass> MY_AUTH_FACTORY("MyAuthClass");
    }
	
    This registers "MyAuthClass" string as the name to be used in the config
    for MyAuthClass authenticator. Of course, authenticator name 
    and class name do not have to be the same.
*/
template<class Auth>
struct GkAuthCreator : public Factory<GkAuthenticator>::Creator0 {
	GkAuthCreator(const char *n) : Factory<GkAuthenticator>::Creator0(n) {}
	virtual GkAuthenticator *operator()() const { return new Auth(m_id); }
};

#endif  // GKAUTH_H
