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
class H235_AuthenticationMechanism;
class PASN_ObjectId;
class H235Authenticators;

class CacheManager;
template<class> class RasPDU;
template<class> struct RasInfo;

class GkAuthenticator : public SList<GkAuthenticator>, public CNamedObject {
public:
	enum Control {
		e_Optional,
		e_Required,
		e_Sufficient
	};

	enum Status {
		e_ok = 1,	// the request is authenticated
		e_fail = -1,	// the request should be rejected
		e_next = 0	// the request is undetermined
	};

	GkAuthenticator(const char *);
	virtual ~GkAuthenticator();

	template<class RAS> bool Validate(RasPDU<RAS> & req, unsigned & reason)
	{
		if (checkFlag & RasInfo<RAS>::flag) {
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

	bool Validate(
		RasPDU<H225_AdmissionRequest>& req, 
		unsigned& reason, 
		long& callDurationLimit
		);
	
	/** @return
		TRUE if this authenticator provides H.235 compatible security.
		It simply checks if h235Authenticators list is not empty.
	*/
	virtual bool IsH235Capable() const;
	
	/** If the authenticator supports H.235 security,
		this call returns H.235 security capabilities
		associated with it. It scans list pointed by h235Authenticators.
		
		@return
		TRUE is H.235 security is supported and capabilities
		has been set.
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
		list pointed by h235Authenticators.
		
		@return
		TRUE if the capability is supported.
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

	Control controlFlag;
	Status defaultStatus;
	PConfig *config;

	H235Authenticators *h235Authenticators;
	
private:
	DWORD checkFlag;

	GkAuthenticator(const GkAuthenticator &);
	GkAuthenticator & operator=(const GkAuthenticator &);
};

class SimplePasswordAuth : public GkAuthenticator {
public:
	SimplePasswordAuth(const char *);
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

	// new virtual function
	virtual bool GetPassword(const PString & id, PString & passwd);
	virtual bool CheckAliases(const PString &, const H225_ArrayOf_AliasAddress *);
	virtual bool CheckTokens(const H225_ArrayOf_ClearToken &, const H225_ArrayOf_AliasAddress *);
	virtual bool CheckCryptoTokens(const H225_ArrayOf_CryptoH323Token &, const H225_ArrayOf_AliasAddress *, const PBYTEArray &);

	template<class RAS> int doCheck(const RasPDU<RAS> & request, const H225_ArrayOf_AliasAddress *a = 0)
	{
		const RAS & req = request;
		if (req.HasOptionalField(RAS::e_cryptoTokens))
			return CheckCryptoTokens(req.m_cryptoTokens, a, request->m_rasPDU) ? e_ok : e_fail;
	 	else if (req.HasOptionalField(RAS::e_tokens))
			return CheckTokens(req.m_tokens, a) ? e_ok : e_fail;
		return (controlFlag == e_Optional) ? e_next : e_fail;
	}

private:
	PString InternalGetPassword(const PString & id);

	int filled;
	bool checkid;
	CacheManager *cache;
};

template<class Auth>
struct GkAuthCreator : public Factory<GkAuthenticator>::Creator0 {
	GkAuthCreator(const char *n) : Factory<GkAuthenticator>::Creator0(n) {}
	virtual GkAuthenticator *operator()() const { return new Auth(m_id); }
};

class GkAuthenticatorList {
public:
	GkAuthenticatorList();
	~GkAuthenticatorList();

	void OnReload();
	void SelectH235Capability(const H225_GatekeeperRequest &, H225_GatekeeperConfirm &) const;

	template<class PDU> bool Validate(PDU & req, unsigned & reason)
	{
		return !m_head || m_head->Validate(req, reason);
	}
	
	bool Validate(
		RasPDU<H225_AdmissionRequest>& req, 
		unsigned& rejectReason, 
		long& callDurationLimit
		)
	{
		callDurationLimit = -1;
		return !m_head || m_head->Validate(req, rejectReason, callDurationLimit);
	}

private:
	GkAuthenticator *m_head;

	/// the most common authentication capabilities 
	/// shared by all authenticators on the list
	H225_ArrayOf_AuthenticationMechanism *m_mechanisms;
	H225_ArrayOf_PASN_ObjectId *m_algorithmOIDs;

	GkAuthenticatorList(const GkAuthenticatorList &);
	GkAuthenticatorList & operator=(const GkAuthenticatorList &);
};

#endif  // GKAUTH_H
