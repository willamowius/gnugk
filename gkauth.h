//////////////////////////////////////////////////////////////////
//
// gkauth.h
//
// Gatekeeper authentication modules
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//
// History:
//      2001/09/19      initial version (Chih-Wei Huang)
//      2003/07/15      revision for thread-safed
//
//////////////////////////////////////////////////////////////////

#ifndef GKAUTH_H
#define GKAUTH_H "@(#) $Id$"

#ifndef NAME_H
#include "name.h"
#endif
#ifndef SLIST_H
#include "slist.h"
#endif
#include "rwlock.h"

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
class Q931;
class H225_Setup_UUIE;

template<class> class RasPDU;
template<class> struct RasInfo;

/** The base class for all authenticator modules. Authenticator modules
	are used to authenticate RAS and Q.931 messages sent by endpoints
	and to check if the endpoints are authorized to use H.323 network resources.
	
	The modules are stackable - each request can be checked by multiple
	modules to get the final authentications result.
	
	Derived classes usually override one or more Check virtual methods
	to implement specific authentication mechanism.
*/
class GkAuthenticator : public SList<GkAuthenticator>, public CNamedObject 
{
public:
	/// processing rule for the authenticator
	enum Control {
		/// if this module cannot determine authentication success or failure
		/// (due to some missing info, for example), remaining modules will
		/// decide about acceptation/rejection of the reqest
		e_Optional, 
		/// the request has to be authenticated by this module
		e_Required, 
		/// if the request is authenticated by this module, authentication
		/// is successful and no further modules are processed
		e_Sufficient 
	};

	/// authentication status returned from Check method
	enum Status {
		e_ok = 1, /// the request is authenticated
		e_fail = -1, /// the request should be rejected
		e_next = 0 /// the module could not authenticate or reject the request
	};

	/// bit masks for event types other than RAS - see miscCheckFlags variable
	enum MiscCheckEvents {
		e_Setup = 0x0001 /// Q.931/H.225 Setup message
	};
	
	GkAuthenticator(
		const char* name /// a name for the module (to be used in the config file)
		);
	virtual ~GkAuthenticator();

	/** Authenticate RAS request (all except ARQ) through this module
	    and all remaining modules.
		
		@return
		true if the request has been authenticated, false if the request
		has to be rejected.
	*/
	template<class RAS> bool Validate(
		RasPDU<RAS>& req, /// a request to be authenticated
		unsigned& reason /// H225_ReleaseCompleteReason returned if the request is rejected
		)
	{
		if (rasCheckFlags & RasInfo<RAS>::flag) {
			int r = Check(req, reason);
			if (r == e_ok) {
				PTRACE(4, "GkAuth\t" << GetName() << " check ok");
				if (controlFlag != e_Required)
					return true;
			} else if (r == e_fail) {
				PTRACE(2, "GkAuth\t" << GetName() << " check failed");
				return false;
			}
		}
		// try next rule
		return !m_next || m_next->Validate(req, reason);
	}

	/** Authenticate and authorize (get call duration limit) ARQ 
	    through this module and all remaining modules.
		
		@return
		true if the request has been authenticated, false if the request
		has to be rejected or call duration limit is 0.
	*/
	bool Validate(
		/// a request to be authenticated
		RasPDU<H225_AdmissionRequest>& req, 
		/// H225_ReleaseCompleteReason returned if the request is rejected
		unsigned& reason, 
		/// call duration limit to be set for the admitted call, 
		/// -1 if no duration limit is required
		long& callDurationLimit 
		);
	
	/** Authenticate/Authorize Setup signalling message.
	
		@return
		true if the call is authorized, fals to reject the call 
		and send a ReleaseComplete message.
	*/
	bool Validate(
		/// received Q.931 Setup message
		Q931& q931pdu, 
		/// received H.225 Setup message
		H225_Setup_UUIE& setup, 
		/// Q931 disconnect cause code to set, if authentication failed
		unsigned& releaseCompleteCause, 
		/// call duration limit to set (-1 for no duration limit)
		long& callDurationLimit
		);
		
	/** @return
		true if this authenticator provides H.235 compatible security.
		It simply checks if h235Authenticators list is not empty.
	*/
	virtual bool IsH235Capable() const;
	
	/** If the authenticator supports H.235 security,
		this call returns H.235 security capabilities
		associated with it. It scans list pointed by h235Authenticators.
		
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
		the h235Authenticators list of H.235 capabilities.
		
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
		(optional,sufficient,required).
	*/
	Control GetControlFlag() const { return controlFlag; }

protected:
	// the second argument is the reject reason, if any
	virtual int Check(RasPDU<H225_GatekeeperRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_RegistrationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_UnregistrationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_AdmissionRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_AdmissionRequest> &, unsigned &, long &);
	virtual int Check(RasPDU<H225_BandwidthRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_DisengageRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_LocationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_InfoRequest> &, unsigned &);
	/** Authenticate/Authorize Setup signalling message.
	
		@return
		e_fail - authentication failed
		e_ok - authenticated with this authenticator
		e_next - authentication could not be determined
	*/
	virtual int Check(
		/// received Q.931 Setup message
		Q931& q931pdu, 
		/// received H.225 Setup message
		H225_Setup_UUIE& setup, 
		/// Q931 disconnect cause code to set, if authentication failed
		unsigned& releaseCompleteCause, 
		/// call duration limit to set (-1 for no duration limit)
		long& callDurationLimit
		);

	/// processing rule for this authenticator
	Control controlFlag;
	/// default status to be returned, if not determined otherwise
	Status defaultStatus;
	/// authenticator config
	PConfig* config;
	/// a list of H.235 capabilities supported by this module (if any)
	H235Authenticators *h235Authenticators;
	
private:
	/// bit flags for RAS messages to be authenticated (there are currently
	/// 32 messages defined, so the whole 32 bit value is required)
	DWORD rasCheckFlags;
	/// bit flags for other event types to be authenticated (like Q.931 Setup)
	DWORD miscCheckFlags;
	
	GkAuthenticator(const GkAuthenticator &);
	GkAuthenticator & operator=(const GkAuthenticator &);
};

/** Cache used by some authenticators to remember key-value associations,
    like username-password. It increases performance, as backend 
	does not need to be queried each time.
*/
class CacheManager 
{
public:
	CacheManager(
		long timeout /// cache timeout - expiry period (seconds)
		) 
		: ttl(timeout) {}

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

private:
	/// cache timeout (seconds), 0 = do not cache, -1 = never expires
	long ttl;
	/// cached key-value pairs
	std::map<PString, PString> cache;
	/// timestamps for key-value pair expiration calculation
	std::map<PString, long> ctime;
	/// mutex for multiple read/mutual write access to the cache
	mutable PReadWriteMutex rwmutex;

	CacheManager(const CacheManager &);
	CacheManager & operator=(const CacheManager &);
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
	SimplePasswordAuth(
		const char* name /// a name for this module (a config section name)
		);
	~SimplePasswordAuth();

protected:
	// override from class GkAuthenticator
	virtual int Check(RasPDU<H225_GatekeeperRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_RegistrationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_UnregistrationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_AdmissionRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_BandwidthRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_DisengageRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_LocationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_InfoRequest> &, unsigned &);

	/** Get a password associated with the identifier.
	
		@return
		true if the password is returned, false if the password 
		could not be found.
	*/
	virtual bool GetPassword(
		const PString& id, /// get the password for this id
		PString& passwd /// filled with the password on return
		);
	
	/** Check if aliases contain the identifier.
	
		@return
		true if the identifier is a valid alias.
	*/
	virtual bool CheckAliases(
		const PString& id, /// the identifier to be checked
		const H225_ArrayOf_AliasAddress* aliases /// aliases to be searched
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

	template<class RAS> int doCheck(
		const RasPDU<RAS>& request, 
		const H225_ArrayOf_AliasAddress* aliases = NULL
		)
	{
		const RAS & req = request;
		bool finalResult = false;
		int result;
		
		if (req.HasOptionalField(RAS::e_cryptoTokens)) {
			if( (result = CheckCryptoTokens(req.m_cryptoTokens, aliases, 
					request->m_rasPDU)) == e_fail )
				return e_fail;
			finalResult = (result == e_ok);
		}
		if (req.HasOptionalField(RAS::e_tokens)) {
			if( (result = CheckTokens(req.m_tokens, aliases)) == e_fail )
				return e_fail;
			finalResult = finalResult || (result == e_ok);
		}
		return finalResult ? e_ok 
			: ((controlFlag == e_Optional) ? e_next : e_fail);
	}

private:
	PString InternalGetPassword(const PString & id);

	/// an encryption key used to decrypt passwords from the config file
	int filled;
	/// if true, generalID has to be also in the endpoint alias list
	bool checkid;
	/// cache for username/password pairs
	CacheManager *cache;
};


/** A base class for all authenticators that validate endpoints (requests)
	by alias and/or IP address only.
	
	Derived authenticators usually override GetAuthConditionString virtual 
	method only.
*/
class AliasAuth : public GkAuthenticator 
{
public:
	AliasAuth(
		const char* name /// a name for this module (a config section name)
		);

protected:
	// override from class GkAuthenticator
	virtual int Check(RasPDU<H225_GatekeeperRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_RegistrationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_UnregistrationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_AdmissionRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_BandwidthRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_DisengageRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_LocationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_InfoRequest> &, unsigned &);

	/** Validate that the signalling addresses match the given condition.
		The condition consists of one or more auth rules.
		
		@return
		true if the signalling addresses match the condition.
	*/
	virtual bool doCheck(
		/// an array of source signalling addresses for an endpoint that sent the request
		const H225_ArrayOf_TransportAddress& sigaddr,
		/// auth condition string as returned by GetAuthConditionString
		const PString& condition
		);
		
	/** Validate that the signalling address matches the given auth rule.
	
		@return
		true if the signal address matches the rule.
	*/
	virtual bool CheckAuthRule(
		/// a signalling address for the endpoint that sent the request
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
	virtual PString GetAuthConditionString(
		/// an alias the condition string is to be retrieved for
		const PString& alias
		);
};


/** A list of authenticators. Usually created as a single global object
	by the RasServer.
*/
class GkAuthenticatorList 
{
public:
	/// creates an empty list - OnRealod builds the actual stack of authenticator
	GkAuthenticatorList();
	~GkAuthenticatorList();

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
	template<class PDU> bool Validate(
		/// the request to be validated by authenticators
		PDU& request, 
		/// H225_ReleaseCompleteReason to be set if the request is rejected
		unsigned& rejectReason
		)
	{
		if( m_head ) {
			ReadLock lock(m_reloadMutex);
			return !m_head || m_head->Validate(request, rejectReason);
		} else
			return true;
	}
	
	/** Authenticate and authorize (set call duration limit) ARQ 
		through all configured authenticators.
				
		@return
		true if the call should be admitted, false to send ARJ.
	*/
	bool Validate(
		/// ARQ to be validated by authenticators
		RasPDU<H225_AdmissionRequest>& request,
		/// H225_ReleaseCompleteReason to be set if the request is rejected
		unsigned& rejectReason,
		/// duration limit to set for the admitted call, -1 to not set any limit
		long& callDurationLimit
		)
	{
		callDurationLimit = -1;
		if( m_head ) {
			ReadLock lock(m_reloadMutex);
			return !m_head 
				|| m_head->Validate(request, rejectReason, callDurationLimit);
		} else
			return true;
	}
	
	/** Authenticate and authorize (set call duration limit) Q.931/H.225 Setup 
		through all configured authenticators.
				
		@return
		true if the call should be accepted, false to send ReleaseComplete.
	*/
	bool Validate(
		/// received Q.931 Setup message
		Q931& q931pdu,
		///  H.225.0 Setup UUIE decoded from Q.931 SETUP
		H225_Setup_UUIE& setup, 
		/// Q931 disconnect cause code to set, if authentication failed
		unsigned& releaseCompleteCause,
		/// duration limit to set for the admitted call, -1 to not set any limit
		long& callDurationLimit
		)
	{
		callDurationLimit = -1;
		if( m_head ) {
			ReadLock lock(m_reloadMutex);
			return !m_head 
				|| m_head->Validate(q931pdu, setup, releaseCompleteCause, callDurationLimit);
		} else
			return true;
	}

private:
	/// a list of all configured authenticators
	GkAuthenticator *m_head;
	/// reload/destroy mutex
	PReadWriteMutex m_reloadMutex;
	/// the most common authentication capabilities 
	/// shared by all authenticators on the list
	H225_ArrayOf_AuthenticationMechanism *m_mechanisms;
	H225_ArrayOf_PASN_ObjectId *m_algorithmOIDs;

	GkAuthenticatorList(const GkAuthenticatorList &);
	GkAuthenticatorList & operator=(const GkAuthenticatorList &);
};

template<class Auth>
struct GkAuthCreator : public Factory<GkAuthenticator>::Creator0 {
	GkAuthCreator(const char *n) : Factory<GkAuthenticator>::Creator0(n) {}
	virtual GkAuthenticator *operator()() const { return new Auth(m_id); }
};

#endif  // GKAUTH_H
