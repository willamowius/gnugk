//////////////////////////////////////////////////////////////////
//
// gkauth.h
//
// Copyright (c) 2001-2018, Jan Willamowius
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
#include "snmp.h"
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
	class Route;
}


#ifdef HAS_DES_ECB
////////////////////////////////////////////////////

#include <h235/h235crypto.h>

/** This class implements desECB authentication.
*/
class H235AuthDesECB : public H235Authenticator
{
    PCLASSINFO(H235AuthDesECB, H235Authenticator);
  public:
    H235AuthDesECB();

    PObject * Clone() const;

    virtual const char * GetName() const;

    static PStringArray GetAuthenticatorNames();
#if PTLIB_VER >= 2110
    static PBoolean GetAuthenticationCapabilities(Capabilities * ids);
#endif
    virtual PBoolean IsMatch(const PString & identifier) const;

    virtual H225_CryptoH323Token * CreateCryptoToken();

    virtual ValidationResult ValidateCryptoToken(
      const H225_CryptoH323Token & cryptoToken,
      const PBYTEArray & rawPDU
    );

    virtual PBoolean IsCapability(
      const H235_AuthenticationMechanism & mechansim,
      const PASN_ObjectId & algorithmOID
    );

    virtual PBoolean SetCapability(
      H225_ArrayOf_AuthenticationMechanism & mechansim,
      H225_ArrayOf_PASN_ObjectId & algorithmOIDs
    );

    virtual PBoolean IsSecuredPDU(
      unsigned rasPDU,
      PBoolean received
    ) const;

    virtual PBoolean IsSecuredSignalPDU(
      unsigned rasPDU,
      PBoolean received
    ) const;
};

#endif


/// Data read/written during RRQ processing by all configured
/// authenticator modules
struct RRQAuthData
{
	RRQAuthData() : m_rejectReason(-1), m_billingMode(-1), m_authenticator(NULL) { }

	/// -1 if not set, H225_RegistrationRejectReason enum otherwise
	int m_rejectReason;
	/// optional user's account balance amount string
	PString m_amountString;
	/// H225_CallCreditServiceControl_billingMode or -1, if not defined
	int m_billingMode;
	/// Authenticated Aliases
	PStringArray m_authAliases;
	GkH235Authenticators * m_authenticator;
};

/// Data read/written during ARQ processing by all configured
/// authenticator modules
struct ARQAuthData
{
	ARQAuthData(const ARQAuthData & obj);
	ARQAuthData(const endptr & ep, const callptr & call);

	ARQAuthData& operator=(const ARQAuthData & obj);

	void SetRouteToAlias(const H225_ArrayOf_AliasAddress & alias);
	void SetRouteToAlias(const PString & alias, int tag = -1);

	/// -1 if not set, H225_AdmissionRejectReason enum otherwise
	int m_rejectReason;
	/// -1 if not set, max allowed call duration in seconds otherwise
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
	H225_ArrayOf_AliasAddress m_routeToAlias;
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
	SetupAuthData(const SetupAuthData & obj);
	SetupAuthData(
		/// call associated with the message (if any)
		const callptr & call,
		/// is the Setup message from a registered endpoint
		bool fromRegistered,
		/// did the Setup come in over TLS
		bool overTLS = false
		);
	~SetupAuthData();

	SetupAuthData & operator=(const SetupAuthData & obj);

	void SetRouteToAlias(const H225_ArrayOf_AliasAddress & alias);
	void SetRouteToAlias(const PString & alias, int tag = -1);

	/// -1 if not set, H225_ReleaseCompleteReason enum otherwise
	int m_rejectReason;
	/// -1 if not set, Q931 cause value otherwise
	int m_rejectCause;
	/// -1 if not set, max allowed call duration in seconds otherwise
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
	H225_ArrayOf_AliasAddress m_routeToAlias;
	/// if not empty, route the call to the specified destinations
	std::list<Routing::Route> m_destinationRoutes;
	/// override global proxy setting from the config (see #CallRec::ProxyMode enum#)
	int m_proxyMode;
	/// RADIUS Class attribute, if found in Access-Accept/Access-Reject
	PBYTEArray m_radiusClass;
	/// ID provided by client, to be passed out with accounting events
	PUInt64 m_clientAuthId;
	/// True if Setup came in over TLS
	bool m_overTLS;

private:
	SetupAuthData();
};

/// Data read/written during Q.931/H.225.0 message processing (except Setup)
/// by all authenticators
struct Q931AuthData
{
	Q931AuthData(const H225_ArrayOf_AliasAddress & aliases,
                PIPSocket::Address peerAddr, WORD peerPort,
                bool overTLS, GkH235Authenticators * auth)
              : m_aliases(aliases), m_peerAddr(peerAddr), m_peerPort(peerPort),
                m_overTLS(overTLS), m_allowAnySendersID(false), m_authenticator(auth) { }
	~Q931AuthData() { }

    // the aliases of the endpoint
	const H225_ArrayOf_AliasAddress & m_aliases;
    /// IP address the request comes from
	PIPSocket::Address m_peerAddr;
	/// port number the request comes from
	WORD m_peerPort;
	/// True if Setup came in over TLS
	bool m_overTLS;
	// in RRQs we have to accept any sendersID
	bool m_allowAnySendersID;
	/// password authenticator
	GkH235Authenticators * m_authenticator;

private:
	Q931AuthData();
	Q931AuthData(const Q931AuthData & obj); // : m_rejectReason(obj.m_rejectReason), m_rejectCause(obj.m_rejectCause), m_call(obj.m_call) { }
	Q931AuthData& operator=(const Q931AuthData & obj);
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
		e_Setup             = 0x0001,   /// Q.931/H.225 Setup message
		e_SetupUnreg        = 0x0002,   /// Q.931/H.225 Setup message only from an unregistered endpoin
		e_Connect           = 0x0004,   /// Q.931/H.225 Connect message
		e_CallProceeding    = 0x0008,   /// Q.931/H.225 CallProceeding message
		e_Alerting          = 0x0010,   /// Q.931/H.225 Alerting message
		e_Information       = 0x0020,   /// Q.931/H.225 Information message
		e_ReleaseComplete   = 0x0040,   /// Q.931/H.225 ReleaseComplete message
		e_Facility          = 0x0080,   /// Q.931/H.225 Facility message
		e_Progress          = 0x0100,   /// Q.931/H.225 Progress message
		e_Empty             = 0x0200,   /// Q.931/H.225 empty message
		e_Status            = 0x0400,   /// Q.931/H.225 Status message
		e_StatusEnquiry     = 0x0800,   /// Q.931/H.225 StatusInquiry message
		e_SetupAck          = 0x1000,   /// Q.931/H.225 SetupAck message
		e_Notify            = 0x2000    /// Q.931/H.225 Notify message
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

	/** Check if this authenticator supports the given
	    H.235 capability (mechanism+algorithmOID) by scanning
	    the m_h235Authenticators list of H.235 capabilities.

	    @return
	    true if the capability is supported by this module.
	*/
	virtual bool IsH235Capability(
		/// authentication mechanism
		const H235_AuthenticationMechanism & mechanism,
		/// algorithm OID for the given authentication mechanism
		const PASN_ObjectId & algorithmOID
		) const;

	/** @return
	    Control flag determining authenticator behavior
	    (optional, sufficient, required).
	*/
	Control GetControlFlag() const { return m_controlFlag; }

	/** @return
	    True if the check is supported (implemented) by this authenticator.
	*/
	bool IsRasCheckEnabled(unsigned rasCheck) const
		{ return (m_enabledRasChecks & m_supportedRasChecks & rasCheck) == rasCheck; }

	/** @return
	    True if the check is supported (implemented) by this authenticator.
	*/
	bool IsMiscCheckEnabled(unsigned miscCheck) const
		{ return (m_enabledMiscChecks & m_supportedMiscChecks & miscCheck) == miscCheck; }

    /** @return
        Enum code for supported checks for this Q.931 message type
    */
    int AuthEnum(unsigned msgCode) const;

	/** Virtual methods overridden in derived classes to perform
		the actual authentication. The first parameter is a request
	    to be checked, the second is a H225_XXXRejectReason that can
	    be set if the authentication rejects the request.

	    @return
	    e_fail - authentication rejected the request
	    e_ok - authentication accepted the request
	    e_next - authentication is not supported for this request
	             or cannot be determined (SQL failure, no cryptoTokens, ...)
	*/
	virtual int Check(RasPDU<H225_GatekeeperRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_UnregistrationRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_BandwidthRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_DisengageRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_LocationRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_InfoRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_ResourcesAvailableIndicate> & req, unsigned & rejectReason);

	/** Authenticate/Authorize RAS or signaling message.

	    @return
	    e_fail - authentication rejected the request
	    e_ok - authentication accepted the request
	    e_next - authentication is not supported for this request
	             or cannot be determined (SQL failure, no cryptoTokens, ...)
	*/
	virtual int Check(
		/// RRQ to be authenticated/authorized
		RasPDU<H225_RegistrationRequest> & request,
		/// authorization data (reject reason, ...)
		RRQAuthData & authData
		);
	virtual int Check(
		/// ARQ to be authenticated/authorized
		RasPDU<H225_AdmissionRequest> & request,
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData & authData
		);
	virtual int Check(
		/// Q.931/H.225 Setup to be authenticated
		SetupMsg & setup,
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData & authData
		);
	virtual int Check(
		/// Q.931/H.225 message to be authenticated
		Q931 & msq,
		/// authorization data
		Q931AuthData & authData
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

	PString StatusAsString(int status) const;

	/** @return
	    Config that contains settings for this authenticator.
	*/
	PConfig* GetConfig() const { return m_config; }

	/** Should be called only from derived constructor to add supported
	    H.235 capabilities (if any).
	*/
	void AppendH235Authenticator(
		H235Authenticator * h235Auth /// H.235 authenticator to append
		);

	/** @return
	    A string that can be used to identify an account name
	    associated with the call.
	*/
	virtual PString GetUsername(
		/// RRQ message with additional data
		const RasPDU<H225_RegistrationRequest> & request
		) const;
	virtual PString GetUsername(
		/// ARQ message with additional data
		const RasPDU<H225_AdmissionRequest> & request,
		/// additional data, like call record and requesting endpoint
		ARQAuthData & authData
		) const;
	virtual PString GetUsername(
		/// Q.931/H.225 Setup with additional data
		const SetupMsg & setup,
		/// additional data
		SetupAuthData & authData
		) const;

	/** @return
	    A string that can be used to identify a calling number.
	*/
	virtual PString GetCallingStationId(
		/// ARQ message with additional data
		const RasPDU<H225_AdmissionRequest> & request,
		/// additional data, like call record and requesting endpoint
		ARQAuthData & authData
		) const;
	virtual PString GetCallingStationId(
		/// Q.931/H.225 Setup to be authenticated
		const SetupMsg & setup,
		/// additional data
		SetupAuthData & authData
		) const;

	/** @return
	    A string that can be used to identify a calling number.
	*/
	virtual PString GetCalledStationId(
		/// ARQ message with additional data
		const RasPDU<H225_AdmissionRequest> & request,
		/// additional data, like call record and requesting endpoint
		ARQAuthData & authData
		) const;
	virtual PString GetCalledStationId(
		/// Q.931/H.225 Setup to be authenticated
		const SetupMsg & setup,
		/// additional data
		SetupAuthData & authData
		) const;

	/// @return	Number actually dialed by the user (before rewrite)
	PString GetDialedNumber(
		/// ARQ message with additional data
		const RasPDU<H225_AdmissionRequest> & request,
		/// additional data
		ARQAuthData & authData
		) const;

	/// @return	Number actually dialed by the user (before rewrite)
	virtual PString GetDialedNumber(
		/// Q.931/H.225 Setup to be authenticated
		const SetupMsg & setup,
		/// additional data
		SetupAuthData & authData
		) const;

    /** Replace parameters placeholders (%a, %{Name}, ...) with actual values.
        Similar to Acct and Query params, but without the escaping.

	    @return
	    New string with all parameters replaced.
	*/
	static PString ReplaceAuthParams(
		/// parametrized accounting string
		const PString & str,
		/// parameter values
		const std::map<PString, PString> & params
	);

	/// a list of H.235 capabilities supported by this module (if any)
	H235Authenticators* m_h235Authenticators;

private:
	GkAuthenticator();
	GkAuthenticator(const GkAuthenticator &);
	GkAuthenticator & operator=(const GkAuthenticator &);

protected:
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
		) : m_ttl(timeout) { }

	/** Get a value associated with the key.

	    @return
	    true if association has been found and the value is valid,
	    false if the key-value pair is not cached or the cache expired
	*/
	bool Retrieve(
		const PString & key, /// the key to look for
		PString & value /// filled with the value on return
		) const;

	/// Store a key-value association in the cache
	void Save(
		const PString & key, /// a key to be stored
		const PString & value /// a value to be associated with the key
		);

	void SetTimeout(
		long newTimeout /// new cache expiration timeout
		) { m_ttl = newTimeout; }

private:
	CacheManager(const CacheManager &);
	CacheManager & operator=(const CacheManager &);

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
		SimplePasswordAuthRasChecks = RasInfo<H225_RegistrationRequest>::flag
			| RasInfo<H225_UnregistrationRequest>::flag
			| RasInfo<H225_BandwidthRequest>::flag
			| RasInfo<H225_DisengageRequest>::flag
			| RasInfo<H225_LocationRequest>::flag
			| RasInfo<H225_InfoRequest>::flag
			| RasInfo<H225_AdmissionRequest>::flag
			| RasInfo<H225_ResourcesAvailableIndicate>::flag
	};
	enum SupportedMiscChecks {
		/// bitmask of Misc checks implemented by this module
        SimplePasswordAuthMiscChecks = e_Setup
            | e_SetupUnreg
            | e_Connect
            | e_CallProceeding
            | e_Alerting
            | e_Information
            | e_ReleaseComplete
            | e_Facility
            | e_Progress
            | e_Empty
            | e_Status
            | e_StatusEnquiry
            | e_SetupAck
            | e_Notify
	};

	SimplePasswordAuth(
		const char* name, /// a name for this module (a config section name)
		unsigned supportedRasChecks = SimplePasswordAuthRasChecks,
		unsigned supportedMiscChecks = SimplePasswordAuthMiscChecks
		);

	virtual ~SimplePasswordAuth();

	// overridden from class GkAuthenticator
	virtual int Check(RasPDU<H225_UnregistrationRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_BandwidthRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_DisengageRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_LocationRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_InfoRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_ResourcesAvailableIndicate> & req, unsigned & rejectReason);

	/** Authenticate/Authorize RAS message.
	    An override from GkAuthenticator.

	    @return
	    e_fail - authentication rejected the request
	    e_ok - authentication accepted the request
	    e_next - authentication is not supported for this request
	             or cannot be determined (SQL failure, no cryptoTokens, ...)
	*/
	virtual int Check(
		/// RRQ to be authenticated/authorized
		RasPDU<H225_RegistrationRequest> & request,
		/// authorization data (reject reason, ...)
		RRQAuthData & authData
		);
	virtual int Check(
		/// ARQ to be authenticated/authorized
		RasPDU<H225_AdmissionRequest> & request,
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData & authData
		);

	/** Authenticate/Authorize a signaling message.
	    An override from GkAuthenticator.

	    @return
	    e_fail - authentication rejected the request
	    e_ok - authentication accepted the request
	    e_next - authentication is not supported for this request
	             or cannot be determined (SQL failure, no cryptoTokens, ...)
	*/
    virtual int Check(
		/// Q931 message to be authenticated/authorized
		Q931 & msg,
		/// authorization data
		Q931AuthData & authData
		);

    // for H.235.1 we use the generic Q931 Check() method
    // at the point where this method is called all tokens are already gone
	virtual int Check(SetupMsg & setup, SetupAuthData & authData) { return e_ok; }


protected:
	/** Get a password associated with the identifier.

	    @return
	    true if the password is returned, false if the password
	    could not be found.
	*/
	virtual bool GetPassword(
		const PString & id, /// get the password for this id
		PString & passwd, /// filled with the password on return
		std::map<PString, PString> & params /// map of authentication parameters
		);

	/** Validate username/password carried inside the tokens. This method
	    supports only CAT and clear text tokens.

	    @return
	    e_ok if the username/password carried inside the tokens is valid,
	    e_fail if the username/password carried inside the tokens is invalid,
	    e_next if no recognized tokens have been found
	*/
	virtual int CheckTokens(
		/// authenticators to be used for token validation
		GkH235Authenticators * & authenticators,
		/// an array of tokens to be checked
		const H225_ArrayOf_ClearToken & tokens,
		/// aliases for the endpoint that generated the tokens
		const H225_ArrayOf_AliasAddress * aliases,
		/// map of authentication parameters
		std::map<PString, PString> & params
		);

	/** Validate username/password carried inside the tokens.

	    @return
	    e_ok if the username/password carried inside the tokens is valid,
	    e_fail if the username/password carried inside the tokens is invalid,
	    e_next if no recognized tokens have been found
	*/
	virtual int CheckCryptoTokens(
		/// authenticators to be used for token validation
		GkH235Authenticators * & authenticators,
		/// an array of cryptoTokens to be checked
		const H225_ArrayOf_CryptoH323Token & cryptoTokens,
		/// aliases for the endpoint that generated the tokens
		const H225_ArrayOf_AliasAddress * aliases,
        /// allow any sendersID (eg. in RRQ)
        bool acceptAnySendersID,
		/// map of authentication parameters
		std::map<PString, PString> & params
		);


    int doCheck(const Q931 & msg, Q931AuthData & authData) {
		GkH235Authenticators * auth = authData.m_authenticator;
		bool authFound = auth != NULL;

		H225_ArrayOf_ClearToken emptyTokens;
		H225_ArrayOf_CryptoH323Token emptyCryptoTokens;
		H225_ArrayOf_ClearToken * tokens = &emptyTokens;
		H225_ArrayOf_CryptoH323Token * cryptoTokens = &emptyCryptoTokens;
        H225_H323_UserInformation uuie;

        if (!GetUUIE(msg, uuie)) {
            return e_next;  // without a UUIE, this message can't carry a token
        }

        GkH235Authenticators::GetQ931Tokens(msg.GetMessageType(), &uuie, &tokens, &cryptoTokens);

        if (!authFound && ((msg.GetMessageType() == Q931::SetupMsg)
            && (uuie.m_h323_uu_pdu.m_h323_message_body.GetTag() == H225_H323_UU_PDU_h323_message_body::e_setup))) {
            H225_Setup_UUIE & setup = uuie.m_h323_uu_pdu.m_h323_message_body;
            callptr call;
            if (setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
                call = CallTable::Instance()->FindCallRec(setup.m_callIdentifier);
            } else {
                call = CallTable::Instance()->FindCallRec(msg.GetCallReference());
            }
            if (call && call->GetCallingParty()) {
                auth = call->GetCallingParty()->GetH235Authenticators();
            } else {
                // TODO235: for calls with pregrantedARQ, we might not have a CallRec, yet
                // try to find EP based on sendersID ?
            }
        }

		if (!auth) {
			return GetDefaultStatus();
		}

		std::map<PString, PString> params;
        params["g"] = Toolkit::GKName();
        params["caller-ip"] = AsString(authData.m_peerAddr);
        params["called-ip"] = "unknown"; // TODO
        params["message"] = Q931MessageName(msg.GetMessageType());
        params["caller-product-name"] = "unknown";
        params["caller-product-version"] = "unknown";
        if (msg.GetMessageType() == Q931::SetupMsg) {
            H225_Setup_UUIE & setupBody = uuie.m_h323_uu_pdu.m_h323_message_body;
            if (setupBody.m_sourceInfo.HasOptionalField(H225_EndpointType::e_vendor)) {
                if (setupBody.m_sourceInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_productId)) {
                    params["caller-product-name"] = setupBody.m_sourceInfo.m_vendor.m_productId.AsString();
                }
                if (setupBody.m_sourceInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_versionId)) {
                     params["caller-product-version"] = setupBody.m_sourceInfo.m_vendor.m_versionId.AsString();
                }
            }
        }
        params["caller-vendor"] = params["caller-product-name"] + " " + params["caller-product-version"];

		if (CheckTokens(auth, *tokens, &authData.m_aliases, params) == e_fail
			|| CheckCryptoTokens(auth, *cryptoTokens, &authData.m_aliases, false, params) == e_fail) {
			return e_fail;
		}

		int result = auth->Validate(msg, *tokens, *cryptoTokens);
		if (result == H235Authenticator::e_OK)
			return e_ok;
		else {
			if (result == H235Authenticator::e_Absent || result == H235Authenticator::e_Disabled)
				return GetDefaultStatus();
			return e_fail;
		}
    }

	/** A family of template functions that check tokens/cryptoTokens
	    inside RAS messages.

	    @return
	    e_ok if the username/password carried inside the tokens is valid,
	    e_fail if the username/password carried inside the tokens is invalid,
	    e_next if no recognized tokens have been found
	*/
	template<class RAS> int doCheck(
		/// RAS request to be authenticated
		const RasPDU<RAS> & request,
		/// list of aliases for the endpoint sending the request
		const H225_ArrayOf_AliasAddress * aliases,
		/// Registration Auth data
		GkH235Authenticators * & auth)
	{
		H225_ArrayOf_ClearToken emptyTokens;
		H225_ArrayOf_CryptoH323Token emptyCryptoTokens;
		const H225_ArrayOf_ClearToken * tokens = &emptyTokens;
		const H225_ArrayOf_CryptoH323Token * cryptoTokens = &emptyCryptoTokens;

		const RAS & req = request;
		if (req.HasOptionalField(RAS::e_tokens))
            tokens = &req.m_tokens;
		if (req.HasOptionalField(RAS::e_cryptoTokens))
            cryptoTokens = &req.m_cryptoTokens;
		// can't check sendersID on some messages (eg. for RRQ we don't know the aliases or endpointID, yet)
		bool acceptAnySendersID = (request.GetTag() == H225_RasMessage::e_registrationRequest)
                                || (request.GetTag() == H225_RasMessage::e_locationRequest)
                                || (request.GetTag() == H225_RasMessage::e_infoRequest);

		std::map<PString, PString> params;
        params["g"] = Toolkit::GKName();
        PIPSocket::Address callerIP;
        request.GetPeerAddr(callerIP);
        params["caller-ip"] = AsString(callerIP);
        params["message"] = request.GetTagName();
        params["caller-product-name"] = "unknown";
        params["caller-product-version"] = "unknown";
        if (request.GetMsg() != NULL) {
            params["called-ip"] = AsString(request.GetMsg()->m_localAddr);
            if (request.GetTag() == H225_RasMessage::e_registrationRequest) {
                RasPDU<H225_RegistrationRequest> ras_rrq(new GatekeeperMessage(*request.GetMsg()));
                H225_RegistrationRequest & rrq = ras_rrq;
                if (rrq.m_terminalType.HasOptionalField(H225_EndpointType::e_vendor)) {
                    if (rrq.m_terminalType.m_vendor.HasOptionalField(H225_VendorIdentifier::e_productId)) {
                        params["caller-product-name"] = rrq.m_terminalType.m_vendor.m_productId.AsString();
                    }
                    if (rrq.m_terminalType.m_vendor.HasOptionalField(H225_VendorIdentifier::e_versionId)) {
                        params["caller-product-version"] = rrq.m_terminalType.m_vendor.m_versionId.AsString();
                    }
                }
            }
        }
        params["caller-vendor"] = params["caller-product-name"] + " " + params["caller-product-version"];
        params["env1"] = PString(::getenv("GNUGK_ENV1"));
        params["env2"] = PString(::getenv("GNUGK_ENV2"));
        params["env3"] = PString(::getenv("GNUGK_ENV3"));

		if (CheckTokens(auth, *tokens, aliases, params) == e_fail
			|| CheckCryptoTokens(auth, *cryptoTokens, aliases, acceptAnySendersID, params) == e_fail) {
			return e_fail;
		}

		if (auth == NULL)
			return GetDefaultStatus();

		int result = auth->Validate((const H225_RasMessage&)req, *tokens, *cryptoTokens, request->m_rasPDU);
		if (result == H235Authenticator::e_OK)
			return e_ok;
		else {
			if (result == H235Authenticator::e_Absent || result == H235Authenticator::e_Disabled)
				return GetDefaultStatus();
			return e_fail;
		}
	}


	/// Set new timeout for username/password pairs cache
	void SetCacheTimeout(long newTimeout) { m_cache->SetTimeout(newTimeout); }

private:
	/** Get password for the given user. Examine password cache first.

	    @return
	    true if the password has been found.
    */
	bool InternalGetPassword(
		const PString & id, /// get the password for this id
		PString & passwd, /// filled with the password on return
		std::map<PString, PString> & params /// map of authentication parameters
		);

	SimplePasswordAuth();
	SimplePasswordAuth(const SimplePasswordAuth &);
	SimplePasswordAuth & operator=(const SimplePasswordAuth &);

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
		const PString & alias,
		/// password string, if the match is found
		PString & password,
		/// map of authentication parameters
		std::map<PString, PString> & params
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
		RasPDU<H225_RegistrationRequest> & request,
		/// authorization data (reject reason, ...)
		RRQAuthData & authData
		);

protected:
	/** Validate that the signaling addresses match the given condition.
	    The condition consists of one or more auth rules.

	    @return
	    true if the signaling addresses match the condition.
	*/
	virtual bool doCheck(
		/// an array of source signaling addresses for an endpoint that sent the request
		const H225_ArrayOf_TransportAddress & sigaddr,
		/// auth condition string as returned by GetAuthConditionString
		const PString & condition,
		/// check the port in the sigIP (off when endpoint uses H.460.18)
		bool checkPort = true
		);

	/** Validate that the signaling address matches the given auth rule.

	    @return
	    true if the signal address matches the rule.
	*/
	virtual bool CheckAuthRule(
		/// a signaling address for the endpoint that sent the request
		const H225_TransportAddress & sigaddr,
		/// the auth rule to be used for checking
		const PString & authrule,
		/// check or ignore port in rule
		bool checkPort
		);

	/** Get AliasAuth condition string for the given alias.
	    This implementation searches RasSrv::RRQAuth section for the string.
	    The string is then used to accept/reject the request, optionally
	    checking its source signaling addresses. The string consists of
	    one or more auth rules separated by '|' or '&' character.

		@return
		The AliasAuth condition string for the given alias.
	 */
	virtual bool GetAuthConditionString(
		/// an alias the condition string is to be retrieved for
		const PString & alias,
		/// filled with auth condition string that has been found
		PString & authCond
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
		const PString & id, /// get the password for this id
		PString & authCond /// filled with the auth condition string on return
		);

	AliasAuth();
	AliasAuth(const AliasAuth &);
	AliasAuth& operator=(const AliasAuth &);

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
	/// creates an empty list - OnReload builds the actual stack of authenticator
	GkAuthenticatorList();
	virtual ~GkAuthenticatorList();

	/// read the config file and build a new stack of authenticator modules
	void OnReload();

	/** Select H.235 authentication mechanisms supported both by the endpoint
	    sending GRQ and all the authenticators, and copy these into GCF.
	    If no common H.235 capabilities can be found, do not select
	    any authentication mechanisms with GCF.
	*/
	void SelectH235Capability(const H225_GatekeeperRequest & grq, H225_GatekeeperConfirm & gcf);

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
					PTRACE(3, "GKAUTH\t" << auth->GetName() << ' ' << request.GetTagName() << " check ok");
					if (auth->GetControlFlag() == GkAuthenticator::e_Sufficient
							|| auth->GetControlFlag() == GkAuthenticator::e_Alternative)
						return true;
				} else if (result == GkAuthenticator::e_fail) {
					PTRACE(3, "GKAUTH\t" << auth->GetName() << ' '
						<< request.GetTagName() << " check failed");
					SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " check failed");
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
		RasPDU<H225_RegistrationRequest> & request,
		/// authorization data (reject reason, ...)
		RRQAuthData & authData
		);

	/** Authenticate and authorize (set call duration limit) ARQ
	    through all configured authenticators.

	    @return
	    true if the call should be admitted, false to send ARJ.
	*/
	bool Validate(
		/// ARQ to be validated by authenticators
		RasPDU<H225_AdmissionRequest> & request,
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData & authData
		);

	/** Authenticate and authorize (set call duration limit) Q.931/H.225 Setup
	    through all configured authenticators.

	    @return
	    true if the call should be accepted, false to send ReleaseComplete.
	*/
	bool Validate(
		/// Q.931/H.225 Setup to be authenticated
		SetupMsg & setup,
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData & authData
		);

	/** Authenticate other Q.931/H.225 messages
	    through all configured authenticators.

	    @return
	    true if the message should be accepted
	*/
	bool Validate(
		/// Q.931/H.225 Setup to be authenticated
		Q931 & setup,
		/// authorization data (call duration limit, reject reason, ...)
		Q931AuthData & authData
		);

	/** Get a module information string for the selected module.

	    @return
		The module information string for status port display.
	*/
	PString GetInfo(
		const PString & moduleName /// module to retrieve information for
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
	GkAuthenticatorList(const GkAuthenticatorList &);
	GkAuthenticatorList & operator=(const GkAuthenticatorList &);

private:
	/// a list of all configured authenticators
	std::list<GkAuthenticator*> m_authenticators;
	/// reload/destroy mutex
	PReadWriteMutex m_reloadMutex;
	/// the most common authentication capabilities
	/// shared by all authenticators on the list
    H235Authenticators m_h235authenticators;
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
	GkAuthCreator(const char *n) : Factory<GkAuthenticator>::Creator0(n) { }
	virtual GkAuthenticator *operator()() const { return new Auth(m_id); }
};

#endif  // GKAUTH_H
