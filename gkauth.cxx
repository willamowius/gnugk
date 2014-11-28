//////////////////////////////////////////////////////////////////
//
// gkauth.cxx
//
// Copyright (c) 2001-2014, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <h235.h>
#include <h323pdu.h>
#include <h235auth.h>

#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "Toolkit.h"
#include "RasTbl.h"
#include "RasPDU.h"
#include "sigmsg.h"
#include "Routing.h"
#include "gkauth.h"
#include "config.h"

#if H323_H350
extern const char *H350Section;
#include <ptclib/pldap.h>
#include "h350/h350.h"
#endif

#ifdef HAS_H46018
#include <h460/h4601.h>
#endif

#ifdef P_SSL
#include <openssl/rand.h>
#endif // P_SSL

namespace {
const char* const GkAuthSectionName = "Gatekeeper::Auth";
}

using std::stable_sort;
using std::for_each;
using std::find_if;
using std::greater;


#if defined(H323_H235) && hasCipertextStealing
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

#if PTLIB_VER >= 2110
// disabled on PTLib 2.11.x, crashes on startup
#if PTLIB_VER >= 2120
typedef H235AuthDesECB H235AuthenticatorDesECB;
PPLUGIN_STATIC_LOAD(DesECB,H235Authenticator);
H235SECURITY(DesECB);
#endif
#else
static PFactory<H235Authenticator>::Worker<H235AuthDesECB> factoryH235AuthDesECB("desECB");
#endif

static const char OID_DesECB[] = "1.3.14.3.2.6";

H235AuthDesECB::H235AuthDesECB()
{
  usage = AnyApplication; // Can be used either for GKAdmission or EPAuthenticstion
}

PObject * H235AuthDesECB::Clone() const
{
  return new H235AuthDesECB(*this);
}

const char * H235AuthDesECB::GetName() const
{
  return "desECB";
}

PStringArray H235AuthDesECB::GetAuthenticatorNames()
{
  return PStringArray("desECB");
}

#if PTLIB_VER >= 2110
PBoolean H235AuthDesECB::GetAuthenticationCapabilities(H235Authenticator::Capabilities * ids)
{
  H235Authenticator::Capability cap;
  cap.m_identifier = OID_DesECB;
  cap.m_cipher     = "DES";
  cap.m_description= "desECB";
  ids->capabilityList.push_back(cap);

  return true;
}
#endif

PBoolean H235AuthDesECB::IsMatch(const PString & identifier) const
{
    return (identifier == PString(OID_DesECB));
}

H225_CryptoH323Token * H235AuthDesECB::CreateCryptoToken()
{
  if (!IsActive())
    return NULL;

  // Create the H.225 crypto token
  H225_CryptoH323Token * cryptoToken = new H225_CryptoH323Token;
  cryptoToken->SetTag(H225_CryptoH323Token::e_cryptoEPPwdEncr);

  // TODO: encryption not implemented, yet (GnuGk only needs the decrypt)
  // see OPAL 3.14.x for encryption implementation (h235auth1.cxx)

  return cryptoToken;
}

H235Authenticator::ValidationResult H235AuthDesECB::ValidateCryptoToken(
                                             const H225_CryptoH323Token & cryptoToken,
                                             const PBYTEArray &)
{
  if (!IsActive())
	return e_Disabled;

  // verify the token is of correct type
  if (cryptoToken.GetTag() != H225_CryptoH323Token::e_cryptoEPPwdEncr)
    return e_Absent;

  PBYTEArray remoteEncryptedData = ((H235_ENCRYPTED<H235_EncodedPwdCertToken>)cryptoToken).m_encryptedData;
  PBYTEArray decryptedToken(remoteEncryptedData.GetSize());

  EVP_CIPHER_CTX cipher;
  EVP_CIPHER_CTX_init(&cipher);
  EVP_CIPHER_CTX_set_padding(&cipher, 1);

  PBYTEArray key(8);
  // Build key from password according to H.235.0/8.2.1
  memcpy(key.GetPointer(), (const char *)password, std::min(key.GetSize(), password.GetLength()));
  for (PINDEX i = key.GetSize(); i < password.GetLength(); ++i)
	key[i%key.GetSize()] ^= password[i];

  EVP_CipherInit_ex(&cipher, EVP_des_ecb(), NULL, key, NULL, 0);

  int len = -1;
  if (!EVP_DecryptUpdate_cts(&cipher, decryptedToken.GetPointer(), &len, remoteEncryptedData.GetPointer(), remoteEncryptedData.GetSize())) {
        PTRACE(1, "H235RAS\tEVP_DecryptUpdate_cts failed");
  }
  int f_len = -1;
  if(!EVP_DecryptFinal_cts(&cipher, decryptedToken.GetPointer() + len, &f_len)) {
    char buf[256];
    ERR_error_string(ERR_get_error(), buf);
    PTRACE(1, "H235RAS\tEVP_DecryptFinal_cts failed: " << buf);
  }

  EVP_CIPHER_CTX_cleanup(&cipher);

  PPER_Stream asn(decryptedToken);
  H235_ClearToken clearToken;
  clearToken.Decode(asn);

  PString generalID = clearToken.m_generalID;
  if (generalID == Toolkit::GKName()
	  && clearToken.m_timeStamp == (unsigned)time(NULL))	// TODO: add grace period ?
	return e_OK;

  PTRACE(1, "H235RAS\tH235AuthDesECB password does not match.");
  return e_BadPassword;
}

PBoolean H235AuthDesECB::IsCapability(const H235_AuthenticationMechanism & mechanism,
                                     const PASN_ObjectId & algorithmOID)
{
  return mechanism.GetTag() == H235_AuthenticationMechanism::e_pwdSymEnc &&
         algorithmOID.AsString() == OID_DesECB;
}

PBoolean H235AuthDesECB::SetCapability(H225_ArrayOf_AuthenticationMechanism & mechanisms,
                                      H225_ArrayOf_PASN_ObjectId & algorithmOIDs)
{
  return AddCapability(H235_AuthenticationMechanism::e_pwdSymEnc, OID_DesECB, mechanisms, algorithmOIDs);
}

PBoolean H235AuthDesECB::IsSecuredPDU(unsigned rasPDU, PBoolean received) const
{
  switch (rasPDU) {
    case H225_RasMessage::e_registrationRequest :
      return received ? !remoteId.IsEmpty() : !localId.IsEmpty();

    default :
      return FALSE;
  }
}

PBoolean H235AuthDesECB::IsSecuredSignalPDU(unsigned signalPDU, PBoolean received) const
{
  return FALSE;
}

/////////////////////////////////////////////////////////////////////////////
#endif

#ifdef OFF

// This stub is enough to fake 2.16.840.1.114187.1.3 support.
// We don't know what the actual crypto is.

#if defined(H323_H235)
////////////////////////////////////////////////////

#include <h235/h235crypto.h>

/** This class implements desCTS authentication.
*/
class H235AuthDesCTS : public H235Authenticator
{
    PCLASSINFO(H235AuthDesCTS, H235Authenticator);
  public:
    H235AuthDesCTS();

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

#if PTLIB_VER >= 2110
// disabled on PTLib 2.11.x, crashes on startup
#if PTLIB_VER >= 2120
typedef H235AuthDesCTS H235AuthenticatorDesCTS;
PPLUGIN_STATIC_LOAD(DesCTS,H235Authenticator);
H235SECURITY(DesCTS);
#endif
#else
static PFactory<H235Authenticator>::Worker<H235AuthDesCTS> factoryH235AuthDesCTS("desCTS");
#endif

static const char OID_DesCTS[] = "2.16.840.1.114187.1.3";

H235AuthDesCTS::H235AuthDesCTS()
{
  usage = AnyApplication; // Can be used either for GKAdmission or EPAuthenticstion
}

PObject * H235AuthDesCTS::Clone() const
{
  return new H235AuthDesCTS(*this);
}

const char * H235AuthDesCTS::GetName() const
{
  return "desCTS";
}

PStringArray H235AuthDesCTS::GetAuthenticatorNames()
{
  return PStringArray("desCTS");
}

#if PTLIB_VER >= 2110
PBoolean H235AuthDesCTS::GetAuthenticationCapabilities(H235Authenticator::Capabilities * ids)
{
  H235Authenticator::Capability cap;
  cap.m_identifier = OID_DesCTS;
  cap.m_cipher     = "DES";
  cap.m_description= "desCTS";
  ids->capabilityList.push_back(cap);

  return true;
}
#endif

PBoolean H235AuthDesCTS::IsMatch(const PString & identifier) const
{
    return (identifier == PString(OID_DesCTS));
}

H225_CryptoH323Token * H235AuthDesCTS::CreateCryptoToken()
{
  if (!IsActive())
    return NULL;

  // Create the H.225 crypto token
  H225_CryptoH323Token * cryptoToken = new H225_CryptoH323Token;
  cryptoToken->SetTag(H225_CryptoH323Token::e_cryptoEPPwdEncr);

  // TODO: encryption not implemented, yet (GnuGk only needs the decrypt)

  return cryptoToken;
}

H235Authenticator::ValidationResult H235AuthDesCTS::ValidateCryptoToken(
                                             const H225_CryptoH323Token & cryptoToken,
                                             const PBYTEArray &)
{
  if (!IsActive())
	return e_Disabled;

  // verify the token is of correct type
  if (cryptoToken.GetTag() != H225_CryptoH323Token::e_cryptoEPPwdEncr)
    return e_Absent;

  return e_OK;	// TODO: always OK for now
}

PBoolean H235AuthDesCTS::IsCapability(const H235_AuthenticationMechanism & mechanism,
                                     const PASN_ObjectId & algorithmOID)
{
  return mechanism.GetTag() == H235_AuthenticationMechanism::e_pwdSymEnc &&
         algorithmOID.AsString() == OID_DesCTS;
}

PBoolean H235AuthDesCTS::SetCapability(H225_ArrayOf_AuthenticationMechanism & mechanisms,
                                      H225_ArrayOf_PASN_ObjectId & algorithmOIDs)
{
  return AddCapability(H235_AuthenticationMechanism::e_pwdSymEnc, OID_DesCTS, mechanisms, algorithmOIDs);
}

PBoolean H235AuthDesCTS::IsSecuredPDU(unsigned rasPDU, PBoolean received) const
{
  switch (rasPDU) {
    case H225_RasMessage::e_registrationRequest :
      return received ? !remoteId.IsEmpty() : !localId.IsEmpty();

    default :
      return FALSE;
  }
}

PBoolean H235AuthDesCTS::IsSecuredSignalPDU(unsigned signalPDU, PBoolean received) const
{
  return FALSE;
}

/////////////////////////////////////////////////////////////////////////////
#endif
#endif


ARQAuthData::ARQAuthData(
	/// an endpoint requesting admission
	const endptr & ep,
	/// call record matching this ARQ (if any)
	const callptr & call
	) : m_rejectReason(-1), m_callDurationLimit(-1),
	m_requestingEP(ep),	m_call(call), m_billingMode(-1),
	m_proxyMode(CallRec::ProxyDetect),
	m_clientAuthId(0)
{
}

ARQAuthData::ARQAuthData(const ARQAuthData & obj)
	: m_rejectReason(obj.m_rejectReason),
	m_callDurationLimit(obj.m_callDurationLimit),
	m_requestingEP(obj.m_requestingEP), m_call(obj.m_call),
	m_billingMode(obj.m_billingMode), m_routeToAlias(obj.m_routeToAlias),
	m_destinationRoutes(obj.m_destinationRoutes), m_proxyMode(obj.m_proxyMode),
	m_clientAuthId(0)
{
}

ARQAuthData& ARQAuthData::operator=(const ARQAuthData & obj)
{
	if (this != &obj) {
		m_rejectReason = obj.m_rejectReason;
		m_callDurationLimit = obj.m_callDurationLimit;
		m_requestingEP = obj.m_requestingEP;
		m_call = obj.m_call;
		m_billingMode = obj.m_billingMode;
		m_proxyMode = obj.m_proxyMode;
		m_clientAuthId = obj.m_clientAuthId;
		m_routeToAlias = obj.m_routeToAlias;
		m_destinationRoutes = obj.m_destinationRoutes;
	}
	return *this;
}

void ARQAuthData::SetRouteToAlias(const H225_ArrayOf_AliasAddress & alias)
{
	m_routeToAlias = alias;
}

void ARQAuthData::SetRouteToAlias(const PString & alias, int tag)
{
	m_routeToAlias.SetSize(1);
	H323SetAliasAddress(alias, m_routeToAlias[0], tag);
}

SetupAuthData::SetupAuthData(
	/// call associated with the message (if any)
	const callptr & call,
	/// is the Setup message from a registered endpoint
	bool fromRegistered,
	/// did the Setup come in over TLS
	bool overTLS
	) : m_rejectReason(-1), m_rejectCause(-1), m_callDurationLimit(-1),
	m_call(call), m_fromRegistered(fromRegistered),
	m_proxyMode(CallRec::ProxyDetect),
	m_clientAuthId(0), m_overTLS(overTLS)
{
}

SetupAuthData::SetupAuthData(const SetupAuthData & obj)
	: m_rejectReason(obj.m_rejectReason), m_rejectCause(obj.m_rejectCause),
	m_callDurationLimit(obj.m_callDurationLimit), m_call(obj.m_call),
	m_fromRegistered(obj.m_fromRegistered),
	m_routeToAlias(obj.m_routeToAlias), m_destinationRoutes(obj.m_destinationRoutes),
	m_proxyMode(obj.m_proxyMode), m_clientAuthId(0), m_overTLS(false)
{
}

SetupAuthData& SetupAuthData::operator=(const SetupAuthData & obj)
{
	if (this != &obj) {
		m_rejectReason = obj.m_rejectReason;
		m_rejectCause = obj.m_rejectCause;
		m_callDurationLimit = obj.m_callDurationLimit;
		m_call = obj.m_call;
		m_fromRegistered = obj.m_fromRegistered;
		m_proxyMode = obj.m_proxyMode;
		m_clientAuthId = obj.m_clientAuthId;
		m_routeToAlias = obj.m_routeToAlias;
		m_destinationRoutes = obj.m_destinationRoutes;
		m_overTLS = obj.m_overTLS;
	}

	return *this;
}

SetupAuthData::~SetupAuthData()
{
}

void SetupAuthData::SetRouteToAlias(const H225_ArrayOf_AliasAddress & alias)
{
	m_routeToAlias = alias;
}

void SetupAuthData::SetRouteToAlias(const PString & alias, int tag)
{
	m_routeToAlias.SetSize(1);
	H323SetAliasAddress(alias, m_routeToAlias[0], tag);
}


// class GkAuthenticator
GkAuthenticator::GkAuthenticator(
	const char* name, /// a name for the module (to be used in the config file)
	unsigned supportedRasChecks, /// RAS checks supported by this module
	unsigned supportedMiscChecks /// non-RAS checks supported by this module
	)
	: NamedObject(name), m_defaultStatus(e_fail), m_controlFlag(e_Required),
	m_enabledRasChecks(~0U), m_supportedRasChecks(supportedRasChecks),
	m_enabledMiscChecks(~0U), m_supportedMiscChecks(supportedMiscChecks),
	m_config(GkConfig())
{
	const PStringArray control(m_config->GetString(GkAuthSectionName, name, "").Tokenise(";,"));
	if (control.GetSize() > 0) {
		const PString controlStr = control[0].Trim();
		if (strcasecmp(name, "default") == 0)
			m_controlFlag = e_Sufficient,
			m_defaultStatus = Toolkit::AsBool(controlStr) ? e_ok : e_fail;
		else if (controlStr *= "optional")
			m_controlFlag = e_Optional, m_defaultStatus = e_next;
		else if (controlStr *= "required")
			m_controlFlag = e_Required, m_defaultStatus = e_fail;
		else if (controlStr *= "sufficient")
			m_controlFlag = e_Sufficient, m_defaultStatus = e_fail;
		else if (controlStr *= "alternative")
			m_controlFlag = e_Alternative, m_defaultStatus = e_next;
		else
			PTRACE(1, "GKAUTH\tInvalid control flag '" << controlStr
				<< "' specified in the config for " << GetName());
	} else
		PTRACE(1, "GKAUTH\tNo control flag specified in the config for module '"
			<< GetName() << '\'');

	std::map<PString, unsigned> rasmap;
	rasmap["GRQ"] = RasInfo<H225_GatekeeperRequest>::flag,
	rasmap["RRQ"] = RasInfo<H225_RegistrationRequest>::flag,
	rasmap["URQ"] = RasInfo<H225_UnregistrationRequest>::flag,
	rasmap["ARQ"] = RasInfo<H225_AdmissionRequest>::flag,
	rasmap["BRQ"] = RasInfo<H225_BandwidthRequest>::flag,
	rasmap["DRQ"] = RasInfo<H225_DisengageRequest>::flag,
	rasmap["LRQ"] = RasInfo<H225_LocationRequest>::flag,
	rasmap["IRQ"] = RasInfo<H225_InfoRequest>::flag;

	std::map<PString, unsigned> miscmap;
	miscmap["SETUP"] = e_Setup;
	miscmap["SETUPUNREG"] = e_SetupUnreg;

	if (control.GetSize() > 1) {
		m_enabledRasChecks = 0;
		m_enabledMiscChecks = 0;

		for (PINDEX i = 1; i < control.GetSize(); ++i) {
			const PString checkStr = control[i].Trim().ToUpper();
			if (rasmap.find(checkStr) != rasmap.end()) {
				m_enabledRasChecks |= rasmap[checkStr];
				if ((m_supportedRasChecks & rasmap[checkStr]) != rasmap[checkStr]) {
					PTRACE(1, "GKAUTH\t" << GetName() << " does not support '"
						<< control[i] << "' check");
				}
			} else if(miscmap.find(checkStr) != miscmap.end()) {
				m_enabledMiscChecks |= miscmap[checkStr];
				if ((m_supportedMiscChecks & miscmap[checkStr]) != miscmap[checkStr]) {
					PTRACE(1, "GKAUTH\t" << GetName() << " does not support '"
						<< control[i] << "' check");
				}
			} else {
				PTRACE(1, "GKAUTH\tInvalid check flag '" << control[i]
					<< "' specified in the config for " << GetName());
			}
		}
		if ((m_enabledRasChecks & m_supportedRasChecks) == 0
			&& (m_enabledMiscChecks & m_supportedMiscChecks) == 0) {
			PTRACE(1, "GKAUTH\tNo check flags have been specified "
				"in the config for " << GetName() << " - it will be disabled");
		}
	}

	// convert bit flags to human readable names
	PString rasFlagsStr, miscFlagsStr;

	std::map<PString, unsigned>::const_iterator iter = rasmap.begin();
	while (iter != rasmap.end()) {
		if (m_enabledRasChecks & iter->second) {
			if (!rasFlagsStr)
				rasFlagsStr += ' ';
			rasFlagsStr += iter->first;
		}
		iter++;
	}

	iter = miscmap.begin();
	while (iter != miscmap.end()) {
		if (m_enabledMiscChecks & iter->second) {
			if (!miscFlagsStr)
				miscFlagsStr += ' ';
			miscFlagsStr += iter->first;
		}
		iter++;
	}

	if (rasFlagsStr.IsEmpty())
		rasFlagsStr = "NONE";
	if (miscFlagsStr.IsEmpty())
		miscFlagsStr = "NONE";

	PTRACE(1, "GKAUTH\t" << GetName() << " rule added to check RAS: "
		<< rasFlagsStr << ", OTHER: " << miscFlagsStr);

	m_h235Authenticators = NULL;
}

GkAuthenticator::~GkAuthenticator()
{
	delete m_h235Authenticators;
	PTRACE(1, "GKAUTH\t" << GetName() << " rule removed");
}

PString GkAuthenticator::StatusAsString(int status) const
{
	switch(status)
	{
		case e_ok: return "accept";
		case e_fail: return "reject";
		case e_next: return "next";
	}
	return "invalid";
}

int GkAuthenticator::Check(RasPDU<H225_GatekeeperRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_GatekeeperRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(
	/// a request to be authenticated
	RasPDU<H225_RegistrationRequest> & /*request*/,
	/// authorization data (reject reason, ...)
	RRQAuthData & /*authData*/)
{
	return IsRasCheckEnabled(RasInfo<H225_RegistrationRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_UnregistrationRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_UnregistrationRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(
	/// a request to be authenticated
	RasPDU<H225_AdmissionRequest> & /*req*/,
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData & /*authData*/)
{
	return IsRasCheckEnabled(RasInfo<H225_AdmissionRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_BandwidthRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_BandwidthRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_DisengageRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_DisengageRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_LocationRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_LocationRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_InfoRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_InfoRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(
	SetupMsg & /*setup*/,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData & /*authData*/)
{
	return (IsMiscCheckEnabled(e_Setup) || IsMiscCheckEnabled(e_SetupUnreg))
		? m_defaultStatus : e_next;
}

bool GkAuthenticator::IsH235Capability(
	/// authentication mechanism
	const H235_AuthenticationMechanism & mechanism,
	/// algorithm OID for the given authentication mechanism
	const PASN_ObjectId & algorithmOID
	) const
{
	if (m_h235Authenticators) {
		for (PINDEX i = 0; i < m_h235Authenticators->GetSize(); i++) {
			if ((*m_h235Authenticators)[i].IsCapability(mechanism, algorithmOID)) {
				return true;
			}
		}
	}
	return false;
}

bool GkAuthenticator::IsH235Capable() const
{
	return m_h235Authenticators && m_h235Authenticators->GetSize() > 0;
}

void GkAuthenticator::AppendH235Authenticator(
	H235Authenticator* h235Auth /// H.235 authenticator to append
	)
{
	if (h235Auth) {
		if (m_h235Authenticators == NULL)
			m_h235Authenticators = new H235Authenticators();
		m_h235Authenticators->Append(h235Auth);
	}
}

PString GkAuthenticator::GetUsername(
	/// RRQ message with additional data
	const RasPDU<H225_RegistrationRequest> & request
	) const
{
	const H225_RegistrationRequest& rrq = request;

	PString username;

	if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
		username = GetBestAliasAddressString(rrq.m_terminalAlias, false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	if (username.IsEmpty()) {
		PIPSocket::Address addr;
		if (rrq.m_callSignalAddress.GetSize() > 0
			&& GetIPFromTransportAddr(rrq.m_callSignalAddress[0], addr)
			&& addr.IsValid())
			username = addr.AsString();
		else if (rrq.m_rasAddress.GetSize() > 0
			&& GetIPFromTransportAddr(rrq.m_rasAddress[0], addr)
			&& addr.IsValid())
			username = addr.AsString();
	}

	return username;
}

PString GkAuthenticator::GetUsername(
	/// ARQ message with additional data
	const RasPDU<H225_AdmissionRequest> & request,
	/// additional data
	ARQAuthData & authData
	) const
{
	const H225_AdmissionRequest& arq = request;
	const bool hasCall = authData.m_call.operator->() != NULL;
	PString username;

	/// try to find h323_ID, email_ID or url_ID to use for User-Name
	if (!arq.m_answerCall)
		username = GetBestAliasAddressString(arq.m_srcInfo, true,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID)
			);
	else if (hasCall)
		username = GetBestAliasAddressString(authData.m_call->GetSourceAddress(), true,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	if (authData.m_requestingEP && (username.IsEmpty()
			|| FindAlias(authData.m_requestingEP->GetAliases(), username) == P_MAX_INDEX))
		username = GetBestAliasAddressString(authData.m_requestingEP->GetAliases(), false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	/// if no h323_ID, email_ID or url_ID has been found, try to find any alias
	if (username.IsEmpty()) {
		if (!arq.m_answerCall) {
			username = GetBestAliasAddressString(arq.m_srcInfo, false,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
				AliasAddressTagMask(H225_AliasAddress::e_email_ID)
					| AliasAddressTagMask(H225_AliasAddress::e_url_ID));
		} else if (hasCall) {
			username = GetBestAliasAddressString(
				authData.m_call->GetSourceAddress(), true,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
				AliasAddressTagMask(H225_AliasAddress::e_email_ID)
					| AliasAddressTagMask(H225_AliasAddress::e_url_ID));
		}
	}


	if (username.IsEmpty()) {
		PIPSocket::Address addr;
		if (arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress)
			&& GetIPFromTransportAddr(arq.m_srcCallSignalAddress, addr)
			&& addr.IsValid())
			username = addr.AsString();
		else if (authData.m_requestingEP
			&& GetIPFromTransportAddr(authData.m_requestingEP->GetCallSignalAddress(), addr)
			&& addr.IsValid())
			username = addr.AsString();
	}

	return username;
}

PString GkAuthenticator::GetUsername(
	const SetupMsg & setup,
	/// additional data
	SetupAuthData & authData
	) const
{
	const bool hasCall = authData.m_call.operator->() != NULL;
	PString username;
	endptr callingEP;
	Q931& q931pdu = setup.GetQ931();
	H225_Setup_UUIE &setupBody = setup.GetUUIEBody();

	if (hasCall)
		callingEP = authData.m_call->GetCallingParty();

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		username = GetBestAliasAddressString(setupBody.m_sourceAddress, true,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID)
			);
		if (!username && callingEP
				&& FindAlias(callingEP->GetAliases(), username) == P_MAX_INDEX)
			username = PString::Empty();
	}

	if (username.IsEmpty() && hasCall) {
		username = GetBestAliasAddressString(
			authData.m_call->GetSourceAddress(), true,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));
		if (!username && callingEP
				&& FindAlias(callingEP->GetAliases(), username) == P_MAX_INDEX)
			username = PString::Empty();
	}

	if (username.IsEmpty() && callingEP)
		username = GetBestAliasAddressString(callingEP->GetAliases(), false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	if (username.IsEmpty() && hasCall)
		username = GetBestAliasAddressString(
			authData.m_call->GetSourceAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	if (username.IsEmpty() && setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress))
		username = GetBestAliasAddressString(setupBody.m_sourceAddress, false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	if (username.IsEmpty())
		q931pdu.GetCallingPartyNumber(username);

	if (username.IsEmpty()) {
		PIPSocket::Address addr(0);
		WORD port = 0;
		bool addrValid = false;

		if (hasCall)
			addrValid = authData.m_call->GetSrcSignalAddr(addr, port) && addr.IsValid();

		if (!addrValid && setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress))
			addrValid = GetIPFromTransportAddr(setupBody.m_sourceCallSignalAddress, addr)
				&& addr.IsValid();

		if (!addrValid && callingEP)
			addrValid = GetIPFromTransportAddr(callingEP->GetCallSignalAddress(), addr)
				&& addr.IsValid();

		if (addrValid)
			username = addr.AsString();
	}

	return username;
}

PString GkAuthenticator::GetCallingStationId(
	/// ARQ message with additional data
	const RasPDU<H225_AdmissionRequest> & /*request*/,
	/// additional data
	ARQAuthData & authData
	) const
{
	return authData.m_callingStationId;
}

PString GkAuthenticator::GetCallingStationId(
	const SetupMsg & /*setup*/,
	/// additional data
	SetupAuthData & authData
	) const
{
	return authData.m_callingStationId;
}

PString GkAuthenticator::GetCalledStationId(
	/// ARQ message with additional data
	const RasPDU<H225_AdmissionRequest> & /*request*/,
	/// additional data
	ARQAuthData & authData
	) const
{
	return authData.m_calledStationId;
}

PString GkAuthenticator::GetCalledStationId(
	const SetupMsg & /*setup*/,
	/// additional data
	SetupAuthData & authData
	) const
{
	return authData.m_calledStationId;
}

PString GkAuthenticator::GetDialedNumber(
	/// ARQ message with additional data
	const RasPDU<H225_AdmissionRequest> & /*request*/,
	/// additional data
	ARQAuthData & authData
	) const
{
	return authData.m_dialedNumber;
}

PString GkAuthenticator::GetDialedNumber(
	const SetupMsg & /*setup*/,
	/// additional data
	SetupAuthData & authData
	) const
{
	return authData.m_dialedNumber;
}

PString GkAuthenticator::GetInfo()
{
	return "No information available\r\n";
}

// class GkAuthenticatorList
GkAuthenticatorList::GkAuthenticatorList()
{
	// TODO: should we move this into OnReload() so it can be dynamically changed ?
	PFactory<H235Authenticator>::KeyList_T keyList = PFactory<H235Authenticator>::GetKeyList();
	PFactory<H235Authenticator>::KeyList_T::const_iterator r;

	// if a global list of autenticators is configured, use it in the priority order supplied
	PStringList authlist = Toolkit::Instance()->GetAuthenticatorList();
	if (authlist.GetSize() > 0) {
		for (PINDEX i = 0; i < authlist.GetSize(); ++i) {
			for (r = keyList.begin(); r != keyList.end(); ++r) {
				H235Authenticator * Auth = PFactory<H235Authenticator>::CreateInstance(*r);
				if (Auth && (PString(Auth->GetName()) == authlist[i])) {
					m_h235authenticators.Append(Auth);
				} else {
					delete Auth;
				}
			}
		}
	} else {
		for (r = keyList.begin(); r != keyList.end(); ++r) {
			H235Authenticator * Auth = PFactory<H235Authenticator>::CreateInstance(*r);
			if ((Auth->GetApplication() == H235Authenticator::EPAuthentication)
				||(Auth->GetApplication() == H235Authenticator::GKAdmission)
				||(Auth->GetApplication() == H235Authenticator::AnyApplication) ) {
				m_h235authenticators.Append(Auth);
			} else {
				delete Auth;
			}
		}
	}
}

GkAuthenticatorList::~GkAuthenticatorList()
{
	WriteLock lock(m_reloadMutex);
	DeleteObjectsInContainer(m_authenticators);
	m_authenticators.clear();
}

void GkAuthenticatorList::OnReload()
{
	// lock here to prevent too early authenticator destruction
	// from another thread
	WriteLock lock(m_reloadMutex);

	// first destroy old authenticators
	DeleteObjectsInContainer(m_authenticators);
	m_authenticators.clear();

	std::list<GkAuthenticator*> authenticators;
	GkAuthenticator *auth;

	const PStringArray authRules = GkConfig()->GetKeys(GkAuthSectionName);
	for (PINDEX r = 0; r < authRules.GetSize(); r++) {
		auth = Factory<GkAuthenticator>::Create(authRules[r]);
		if (auth) {
			authenticators.push_back(auth);
		}
	}

	m_authenticators = authenticators;
}

void GkAuthenticatorList::SelectH235Capability(
	const H225_GatekeeperRequest & grq,
	H225_GatekeeperConfirm & gcf)
{
	ReadLock lock(m_reloadMutex);

	if (m_authenticators.empty()) {
		return;
	}

	// if GRQ does not contain a list of authentication mechanisms simply return
	if (!(grq.HasOptionalField(H225_GatekeeperRequest::e_authenticationCapability)
			&& grq.HasOptionalField(H225_GatekeeperRequest::e_algorithmOIDs)
			&& grq.m_authenticationCapability.GetSize() > 0
			&& grq.m_algorithmOIDs.GetSize() > 0)) {
		return;
	}

	for (PINDEX auth = 0; auth < m_h235authenticators.GetSize(); auth++) {
		for (PINDEX cap = 0; cap < grq.m_authenticationCapability.GetSize(); cap++) {
			for (PINDEX alg = 0; alg < grq.m_algorithmOIDs.GetSize(); alg++) {
				if (m_h235authenticators[auth].IsCapability(grq.m_authenticationCapability[cap], grq.m_algorithmOIDs[alg])) {
					std::list<GkAuthenticator*>::const_iterator iter = m_authenticators.begin();
					while (iter != m_authenticators.end()) {
						GkAuthenticator* gkauth = *iter++;
						if (gkauth->IsH235Capable() && gkauth->IsH235Capability(grq.m_authenticationCapability[cap], grq.m_algorithmOIDs[alg])) {
							PTRACE(4, "GKAUTH\tGRQ accepted on " << H323TransportAddress(gcf.m_rasAddress)
								<< " using authenticator " << m_h235authenticators[auth]);
							gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_authenticationMode);
							gcf.m_authenticationMode = grq.m_authenticationCapability[cap];
							gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_algorithmOID);
							gcf.m_algorithmOID = grq.m_algorithmOIDs[alg];
							if (gcf.m_authenticationMode.GetTag() == H235_AuthenticationMechanism::e_pwdSymEnc) {
								// add the challenge token
								gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_tokens);
								gcf.m_tokens.SetSize(1);
								gcf.m_tokens[0].m_tokenOID = "0.0";
								gcf.m_tokens[0].IncludeOptionalField(H235_ClearToken::e_timeStamp);
								gcf.m_tokens[0].m_timeStamp = (int)time(NULL); // Avaya seems to send a different timestamp that is 34 years back, but accpets this as well
								gcf.m_tokens[0].IncludeOptionalField(H235_ClearToken::e_random);
#ifdef PSSL
                                // if we have OpenSSL, use it for random number generation, fall back on stdlib rand()
                                if(RAND_bytes(gcf.m_tokens[0].m_random, sizeof(gcf.m_tokens[0].m_random)) != 1) {
                                    gcf.m_tokens[0].m_random = rand();
                                }
#else
								gcf.m_tokens[0].m_random = rand();
#endif // PSSL
								gcf.m_tokens[0].IncludeOptionalField(H235_ClearToken::e_generalID);
								gcf.m_tokens[0].m_generalID = Toolkit::GKName();
							}
							return;
						}
					}
				}
			}
		}
	}
}

bool GkAuthenticatorList::Validate(
	/// RRQ to be validated by authenticators
	RasPDU<H225_RegistrationRequest> & request,
	/// authorization data (reject reason, ...)
	RRQAuthData & authData
	)
{
	ReadLock lock(m_reloadMutex);
	std::list<GkAuthenticator*>::const_iterator i = m_authenticators.begin();
	while (i != m_authenticators.end()) {
		GkAuthenticator* auth = *i++;
		if (auth->IsRasCheckEnabled(RasInfo<H225_RegistrationRequest>::flag)) {
			const int result = auth->Check(request, authData);
			if (result == GkAuthenticator::e_ok) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " RRQ check ok");
				if (auth->GetControlFlag() == GkAuthenticator::e_Sufficient
						|| auth->GetControlFlag() == GkAuthenticator::e_Alternative)
					return true;
			} else if (result == GkAuthenticator::e_fail) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " RRQ check failed");
				SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " RRQ check failed");
				return false;
			}
		}
	}
	return true;
}

bool GkAuthenticatorList::Validate(
	/// ARQ to be validated by authenticators
	RasPDU<H225_AdmissionRequest> & request,
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData & authData)
{
	ReadLock lock(m_reloadMutex);
	std::list<GkAuthenticator*>::const_iterator i = m_authenticators.begin();
	while (i != m_authenticators.end()) {
		GkAuthenticator* auth = *i++;
		if (auth->IsRasCheckEnabled(RasInfo<H225_AdmissionRequest>::flag)) {
			const long oldDurationLimit = authData.m_callDurationLimit;
			const int result = auth->Check(request, authData);
			if (authData.m_callDurationLimit == 0) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " ARQ check failed: "
					"call duration 0");
				SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " ARQ check failed");
				return false;
			}
			if (authData.m_callDurationLimit >= 0 && oldDurationLimit >= 0)
				authData.m_callDurationLimit = PMIN(
					authData.m_callDurationLimit, oldDurationLimit
					);
			else
				authData.m_callDurationLimit = PMAX(
					authData.m_callDurationLimit, oldDurationLimit
					);
			if (result == GkAuthenticator::e_ok) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " ARQ check ok");
				if (auth->GetControlFlag() == GkAuthenticator::e_Sufficient
						|| auth->GetControlFlag() == GkAuthenticator::e_Alternative)
					return true;
			} else if (result == GkAuthenticator::e_fail) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " ARQ check failed");
				SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " ARQ check failed");
				return false;
			}
		}
	}
	return true;
}

bool GkAuthenticatorList::Validate(
	SetupMsg & setup,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData & authData)
{
	ReadLock lock(m_reloadMutex);
	std::list<GkAuthenticator*>::const_iterator i = m_authenticators.begin();
	while (i != m_authenticators.end()) {
		GkAuthenticator* auth = *i++;
		if (auth->IsMiscCheckEnabled(GkAuthenticator::e_Setup)
			|| (!authData.m_fromRegistered
				&& auth->IsMiscCheckEnabled(GkAuthenticator::e_SetupUnreg))) {
			const long oldDurationLimit = authData.m_callDurationLimit;
			const int result = auth->Check(setup, authData);
			if (authData.m_callDurationLimit == 0) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " Setup check failed: "
					"call duration limit 0");
				SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " Setup check failed");
				return false;
			}
			if (authData.m_callDurationLimit >= 0 && oldDurationLimit >= 0) {
				authData.m_callDurationLimit = PMIN(authData.m_callDurationLimit, oldDurationLimit);
			} else {
				authData.m_callDurationLimit = PMAX(authData.m_callDurationLimit, oldDurationLimit);
			}
			if (result == GkAuthenticator::e_ok) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " Setup check ok");
				if (auth->GetControlFlag() == GkAuthenticator::e_Sufficient
						|| auth->GetControlFlag() == GkAuthenticator::e_Alternative)
					return true;
			} else if (result == GkAuthenticator::e_fail) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " Setup check failed");
				SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " Setup check failed");
				return false;
			}
		}
	}
	return true;
}

// class CacheManager
bool CacheManager::Retrieve(
	const PString & key, /// the key to look for
	PString & value /// filled with the value on return
	) const
{
	// quick check
	if (m_ttl == 0)
		return false;

	ReadLock lock(m_rwmutex);

	std::map<PString, PString>::const_iterator iter = m_cache.find(key);
	if (iter == m_cache.end())
		return false;
	if (m_ttl >= 0) {
		std::map<PString, time_t>::const_iterator i = m_ctime.find(key);
		if (i == m_ctime.end() || (time(NULL) - i->second) >= m_ttl)
			return false; // cache expired
	}
	value = (const char *)(iter->second);
	return true;
}

void CacheManager::Save(
	const PString & key, /// a key to be stored
	const PString & value /// a value to be associated with the key
	)
{
	if (m_ttl != 0) {
		WriteLock lock(m_rwmutex);
		m_cache[key] = (const char*)value;
		m_ctime[key] = time(NULL);
	}
}


// class SimplePasswordAuth
SimplePasswordAuth::SimplePasswordAuth(
	const char * name,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks)
	: GkAuthenticator(name, supportedRasChecks, supportedMiscChecks), m_cache(NULL)
{
	if (!GetConfig()->HasKey(name, "KeyFilled")) {
		PTRACE(1, "GKAUTH\t" << GetName() << " KeyFilled config variable is missing");
	}
	m_encryptionKey = GetConfig()->GetInteger(name, "KeyFilled", 0);
	m_checkID = Toolkit::AsBool(GetConfig()->GetString(name, "CheckID", "0"));
	m_cache = new CacheManager(GetConfig()->GetInteger(name, "PasswordTimeout", -1));
	m_disabledAlgorithms = GetConfig()->GetString(name, "DisableAlgorithm", "").Tokenise(",;", FALSE);

    PFactory<H235Authenticator>::KeyList_T keyList = PFactory<H235Authenticator>::GetKeyList();
    PFactory<H235Authenticator>::KeyList_T::const_iterator r;

	PStringList authlist = Toolkit::Instance()->GetAuthenticatorList();
	// if a global list of autenticators is configured, use it in the priority order supplied
	if (authlist.GetSize() > 0) {
		for (PINDEX i = 0; i < authlist.GetSize(); ++i) {
			for (r = keyList.begin(); r != keyList.end(); ++r) {
				H235Authenticator * Auth = PFactory<H235Authenticator>::CreateInstance(*r);
				// only use, if it's not disabled for this GnuGk authentication method
				if (Auth && (PString(Auth->GetName()) == authlist[i])
					&& (m_disabledAlgorithms.GetStringsIndex(Auth->GetName()) == P_MAX_INDEX)) {
					if ((Auth->GetApplication() == H235Authenticator::EPAuthentication)
						||(Auth->GetApplication() == H235Authenticator::GKAdmission)
						||(Auth->GetApplication() == H235Authenticator::AnyApplication) ) {
						AppendH235Authenticator(Auth);
					} else {
						delete Auth;
					}
				}
			}
		}
	} else {
		for (r = keyList.begin(); r != keyList.end(); ++r) {
			H235Authenticator * Auth = PFactory<H235Authenticator>::CreateInstance(*r);
			// only use, if it's not disabled for this GnuGk authentication method
			if (Auth && (m_disabledAlgorithms.GetStringsIndex(Auth->GetName()) == P_MAX_INDEX)) {
				if ((Auth->GetApplication() == H235Authenticator::EPAuthentication)
					||(Auth->GetApplication() == H235Authenticator::GKAdmission)
					||(Auth->GetApplication() == H235Authenticator::AnyApplication) ) {
					AppendH235Authenticator(Auth);
				} else {
					delete Auth;
				}
			}
		}
	}
}

SimplePasswordAuth::~SimplePasswordAuth()
{
	delete m_cache;
}

int SimplePasswordAuth::Check(
	RasPDU<H225_RegistrationRequest> & request,
	RRQAuthData & authData)
{
	H225_RegistrationRequest& rrq = request;
	return doCheck(request,
		rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)
			? &rrq.m_terminalAlias : NULL,
			&authData
		);
}

int SimplePasswordAuth::Check(RasPDU<H225_UnregistrationRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(RasPDU<H225_BandwidthRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(RasPDU<H225_DisengageRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(RasPDU<H225_LocationRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(RasPDU<H225_InfoRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(
	/// ARQ to be authenticated/authorized
	RasPDU<H225_AdmissionRequest> & request,
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData & /*authData*/)
{
	H225_AdmissionRequest & arq = request;
	return doCheck(request, arq.m_answerCall ? &arq.m_destinationInfo : &arq.m_srcInfo);
}

bool SimplePasswordAuth::GetPassword(
	const PString & id, /// get the password for this id
	PString & passwd /// filled with the password on return
	)
{
	if (id.IsEmpty())
		return false;
	if (!GetConfig()->HasKey(GetName(), id))
		return false;
    // make sure the alias name is not one of the switches allowed in the SimplePasswordAuth section
	if (strcasecmp(id, "KeyFilled") == 0
        || strcasecmp(id, "CheckID") == 0
        || strcasecmp(id, "DisableAlgorithm") == 0
		|| strcasecmp(id, "PasswordTimeout") == 0) {
		PTRACE(2, "GKAUTH\t" << GetName() << " trying to get password for "
			" the forbidden alias '" << id << '\'');
		return false;
	}
	passwd = Toolkit::Instance()->ReadPassword(GetName(), id, true);
	return true;
}

bool SimplePasswordAuth::InternalGetPassword(
	const PString & id, /// get the password for this id
	PString & passwd /// filled with the password on return
	)
{
	if (m_cache->Retrieve(id, passwd)) {
		PTRACE(5, "GKAUTH\t" << GetName() << " cached password found for '" << id << '\'');
		return true;
	}
	if (GetPassword(id, passwd)) {
		m_cache->Save(id, passwd);
		return true;
	} else
		return false;
}

bool SimplePasswordAuth::ResolveUserName(const H235_ClearToken & token, PString & username)
{
	// CAT
	if (token.HasOptionalField(H235_ClearToken::e_generalID)) {
		username = token.m_generalID;
		return true;
	}
	return false;
}

bool SimplePasswordAuth::ResolveUserName(const H225_CryptoH323Token & cryptotoken, const H225_ArrayOf_AliasAddress * aliases, PString & username)
{
	// MD5
	if (cryptotoken.GetTag() == H225_CryptoH323Token::e_cryptoEPPwdHash) {
		const H225_CryptoH323Token_cryptoEPPwdHash & pwdhash = cryptotoken;
		username = AsString(pwdhash.m_alias, false);
		return true;
	} else if (cryptotoken.GetTag() == H225_CryptoH323Token::e_cryptoEPPwdEncr) {
		// use alias as username, token contans just the encrypted challenge
		if (aliases && (aliases->GetSize() > 0)) {
			username = AsString(aliases[0], false);
			return true;
		} else {
			return false;
		}
	} else if (cryptotoken.GetTag() == H225_CryptoH323Token::e_nestedcryptoToken) {
		H235_ClearToken clearToken;
		bool found = false;
		const H235_CryptoToken & nestedCryptoToken = cryptotoken;

		// H235.1
		if (nestedCryptoToken.GetTag() == H235_CryptoToken::e_cryptoHashedToken) {
			const H235_CryptoToken_cryptoHashedToken& cryptoHashedToken = nestedCryptoToken;
			clearToken = cryptoHashedToken.m_hashedVals;
			found = true;
		}
		// H235.2
		if (nestedCryptoToken.GetTag() == H235_CryptoToken::e_cryptoSignedToken) {
			const H235_CryptoToken_cryptoSignedToken & cryptoSignedToken = nestedCryptoToken;
			H235_SIGNED<H235_EncodedGeneralToken> m_Signed = cryptoSignedToken.m_token;
			if (m_Signed.m_toBeSigned.DecodeSubType(clearToken))
				found = true;
		}

		if (found && (clearToken.HasOptionalField(H235_ClearToken::e_sendersID))) {
			username = clearToken.m_sendersID;
			return true;
		}
	}

	return false;
}

#ifdef H323_H350

H350PasswordAuth::H350PasswordAuth(const char* authName) : SimplePasswordAuth(authName)
{
}

H350PasswordAuth::~H350PasswordAuth()
{
}

bool H350PasswordAuth::GetPassword(const PString & alias, PString & password)
{
	// search the directory
	PString search = GkConfig()->GetString(H350Section, "SearchBaseDN", "");

	H225_AliasAddress aliasaddress;
	H323SetAliasAddress(alias, aliasaddress);

	PString filter = "h235IdentityEndpointID=" + alias;

	H350_Session session;
	if (!Toolkit::Instance()->CreateH350Session(&session)) {
		PTRACE(1, "H350\tH235Auth: Could not connect to server");
		return false;
	}

	H350_Session::LDAP_RecordList rec;
	int count = session.Search(search, filter, rec);
	if (count <= 0) {
		PTRACE(4, "H350\tH235Auth: No record found");
		session.Close();
		return false;
	}

	// locate the record
	for (H350_Session::LDAP_RecordList::const_iterator x = rec.begin(); x != rec.end(); ++x) {
		H350_Session::LDAP_Record entry = x->second;
		if (session.GetAttribute(entry, "h235IdentityPassword", password)) {
			password = password.Trim();	// server may send newline at end etc.
			PTRACE(4, "H350\tH235Auth: Password located");
			session.Close();
			return true;
		}
	}

	PTRACE(4, "H350\tH235Auth: No password found");
	session.Close();
	return false;
}

#endif

// class AliasAuth
AliasAuth::AliasAuth(
	const char * name,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks)
	: GkAuthenticator(name, supportedRasChecks, supportedMiscChecks), m_cache(NULL)
{
	m_cache = new CacheManager(GetConfig()->GetInteger(name, "CacheTimeout", -1));
}

AliasAuth::~AliasAuth()
{
	delete m_cache;
}

int AliasAuth::Check(
	RasPDU<H225_RegistrationRequest> & request,
	RRQAuthData & /*authData*/)
{
	H225_RegistrationRequest & rrq = request;

	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
		PTRACE(3, "GKAUTH\t" << GetName() << " - terminalAlias field not found in RRQ message");
		return GetDefaultStatus();
	}

	const H225_ArrayOf_AliasAddress & aliases = rrq.m_terminalAlias;

	for (PINDEX i = 0; i <= aliases.GetSize(); i++) {
		const PString alias = (i < aliases.GetSize()) ? AsString(aliases[i], false) : PString("default");
		PString authcond;
		if (InternalGetAuthConditionString(alias, authcond)) {
			bool checkPort = true;
			// don't check the signaling port if the endpoint uses H.460.18
#ifdef HAS_H46018
			if (rrq.HasOptionalField(H225_RegistrationRequest::e_featureSet)) {
				H460_FeatureSet fs = H460_FeatureSet(rrq.m_featureSet);
				if (fs.HasFeature(18) && Toolkit::Instance()->IsH46018Enabled()) {
					checkPort = false;
				}
			}
#endif
			if (doCheck(rrq.m_callSignalAddress, authcond, checkPort)) {
				PTRACE(5, "GKAUTH\t" << GetName() << " auth condition '"
					<< authcond <<"' accepted RRQ from '" << alias << '\'');
				return e_ok;
			} else {
				PTRACE(3, "GKAUTH\t" << GetName() << " auth condition '"
					<< authcond <<"' rejected RRQ from '" << alias << '\'');
				return e_fail;
			}
		} else
			PTRACE(4, "GKAUTH\t" << GetName() << " auth condition not found for alias '" << alias << '\'');
	}
	return GetDefaultStatus();
}

bool AliasAuth::GetAuthConditionString(
	/// an alias the condition string is to be retrieved for
	const PString & alias,
	/// filled with auth condition string that has been found
	PString & authCond)
{
	if (alias.IsEmpty())
		return false;
	if (!GetConfig()->HasKey("RasSrv::RRQAuth", alias))
		return false;
	if (strcasecmp(alias, "CacheTimeout") == 0) {
		PTRACE(2, "GKAUTH\t" << GetName() << " trying to get auth condition "
			" string for the forbidden alias '" << alias << '\'');
		return false;
	}
	authCond = GetConfig()->GetString("RasSrv::RRQAuth", alias, "");
	return true;
}

bool AliasAuth::InternalGetAuthConditionString(
	const PString & id, /// get the password for this id
	PString & authCond /// filled with the auth condition string on return
	)
{
	if (m_cache->Retrieve(id, authCond)) {
		PTRACE(5, "GKAUTH\t" << GetName() << " cached auth condition string found for '" << id << '\'');
		return true;
	}
	if (GetAuthConditionString(id, authCond)) {
		m_cache->Save(id, authCond);
		return true;
	} else
		return false;
}

bool AliasAuth::doCheck(
	/// an array of source signaling addresses for an endpoint that sent the request
	const H225_ArrayOf_TransportAddress & sigaddr,
	/// auth condition string as returned by GetAuthConditionString
	const PString & condition,
	bool checkPort)
{
	const PStringArray authrules(condition.Tokenise("&|", FALSE));
	if (authrules.GetSize() < 1) {
		PTRACE(2, "GKAUTH\t" << GetName() << " contains an empty auth condition");
		return false;
	}
	for (PINDEX i = 0; i < authrules.GetSize(); ++i) {
		for (PINDEX j = 0; j < sigaddr.GetSize(); ++j) {
			if (CheckAuthRule(sigaddr[j], authrules[i], checkPort)) {
				PTRACE(5, "GKAUTH\t" << GetName() << " auth rule '"
					<< authrules[i] << "' applied successfully to RRQ "
					" from " << AsDotString(sigaddr[j]));
				return true;
			}
		}
	}
	return false;
}

bool AliasAuth::CheckAuthRule(
	/// a signaling address for the endpoint that sent the request
	const H225_TransportAddress & sigaddr,
	/// the auth rule to be used for checking
	const PString & authrule,
	bool checkPort)
{
	PStringArray rule = authrule.Tokenise(":", false);
	if (rule.GetSize() < 1) {
		PTRACE(1, "GKAUTH\t" << GetName() << " found invalid empty auth rule '" << authrule << '\'');
		return false;
	}

	// authrule = rName[:params...]
	const PString rName = rule[0].Trim();

 	if (strcasecmp(rName, "confirm") == 0 || strcasecmp(rName, "allow") == 0)
 		return true;
 	else if (strcasecmp(rName, "reject") == 0 || strcasecmp(rName, "deny") == 0
		|| strcasecmp(rName, "forbid") == 0)
 		return false;
	else if (strcasecmp(rName, "sigaddr") == 0) {
		// condition 'sigaddr' example:
		//   sigaddr:.*ipAddress .* ip = .* c3 47 e2 a2 .*port = 1720.*
		if (rule.GetSize() < 2) {
			PTRACE(1, "GKAUTH\t" << GetName() << " found invalid empty sigaddr "
				"auth rule '" << authrule << '\'');
			return false;
		}
		// ignore port for H.460.18
		if (!checkPort && rule[1].Find("port") != P_MAX_INDEX) {
			rule[1] = rule[1].Left(rule[1].Find("port"));
		}
		return Toolkit::MatchRegex(AsString(sigaddr), rule[1].Trim()) != 0;
	} else if (strcasecmp(rName, "sigip") == 0) {
		// condition 'sigip' example:
		//   sigip:195.71.129.69:1720
		if (rule.GetSize() < 2) {
			PTRACE(1, "GKAUTH\t" << GetName() << " found invalid empty sigip "
				"auth rule '" << authrule << '\'');
			return false;
		}
		PString allowed_ip = authrule.Mid(authrule.Find("sigip:")+6).Trim();
		PStringArray ip_parts = SplitIPAndPort(allowed_ip, GK_DEF_ENDPOINT_SIGNAL_PORT);
		PIPSocket::Address ip;
		PIPSocket::GetHostAddress(ip_parts[0], ip);
		WORD port = (WORD)(ip_parts[1].AsUnsigned());
		// ignore port for H.460.18
		if (!checkPort) {
			PIPSocket::Address notUsed;
			WORD EPPort;
			GetIPAndPortFromTransportAddr(sigaddr, notUsed, EPPort);
			port = EPPort;
		}
		return (sigaddr == SocketToH225TransportAddr(ip, port));
	} else {
		PTRACE(1, "GKAUTH\t" << GetName() << " found unknown auth rule '" << rName << '\'');
		return false;
	}
}

// class PrefixAuth

class AuthRule;
class AuthObj;

class PrefixAuth : public GkAuthenticator
{
public:
	typedef std::map< PString, AuthRule *, greater<PString> > Rules;

	enum SupportedRasChecks {
		PrefixAuthRasChecks = RasInfo<H225_AdmissionRequest>::flag
			| RasInfo<H225_LocationRequest>::flag,
		PrefixAuthMiscChecks = e_Setup | e_SetupUnreg
	};

	PrefixAuth(
		const char* name,
		unsigned supportedRasChecks = PrefixAuthRasChecks,
		unsigned supportedMiscChecks = PrefixAuthMiscChecks);

	virtual ~PrefixAuth();

	// override from class GkAuthenticator
	virtual int Check(RasPDU<H225_LocationRequest> & request, unsigned & rejectReason);

	/** Authenticate/Authorize ARQ message. Override from GkAuthenticator.

	    @return
	    e_fail - authentication failed
	    e_ok - authenticated with this authenticator
	    e_next - authentication could not be determined
	*/
	virtual int Check(
		/// ARQ to be authenticated/authorized
		RasPDU<H225_AdmissionRequest> & request,
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData & authData);

	/** Authenticate using data from Q.931 Setup message.

		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// Q.931/H.225 Setup message to be authenticated
		SetupMsg & setup,
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData & authData
		);

protected:
	virtual int doCheck(const AuthObj& aobj);

private:
	PrefixAuth();
	PrefixAuth(const PrefixAuth &);
	PrefixAuth& operator=(const PrefixAuth &);

private:
	Rules m_prefrules;
	int m_defaultRule;
};

// Help classes for PrefixAuth
class AuthObj // abstract class
{
public:
	virtual ~AuthObj() { }

	virtual bool IsValid() const { return true; }

	virtual PStringArray GetPrefixes() const = 0;

	virtual PIPSocket::Address GetIP() const = 0;
	virtual PString GetAliases() const = 0;
};

class ARQAuthObj : public AuthObj
{
public:
	ARQAuthObj(const H225_AdmissionRequest & arq);

	virtual bool IsValid() const { return m_ep; }

	virtual PStringArray GetPrefixes() const;

	virtual PIPSocket::Address GetIP() const;
	virtual PString GetAliases() const;

private:
	ARQAuthObj();
	ARQAuthObj(const ARQAuthObj &);
	ARQAuthObj & operator=(const ARQAuthObj &);

private:
	const H225_AdmissionRequest& m_arq;
	endptr m_ep;
};

class LRQAuthObj : public AuthObj
{
public:
	LRQAuthObj(const H225_LocationRequest & lrq);

	virtual PStringArray GetPrefixes() const;

	virtual PIPSocket::Address GetIP() const;
	virtual PString GetAliases() const;

private:
	LRQAuthObj();
	LRQAuthObj(const LRQAuthObj &);
	LRQAuthObj & operator=(const LRQAuthObj &);

private:
	const H225_LocationRequest & m_lrq;
	PIPSocket::Address m_ipAddress;
};

class SetupAuthObj : public AuthObj
{
public:
	SetupAuthObj(const SetupMsg & setup);

	virtual PStringArray GetPrefixes() const;

	virtual PIPSocket::Address GetIP() const;
	virtual PString GetAliases() const;

private:
	SetupAuthObj();
	SetupAuthObj(const SetupAuthObj &);
	SetupAuthObj & operator=(const SetupAuthObj &);

private:
	const SetupMsg & m_setup;
	PIPSocket::Address m_ipAddress;
};

class AuthRule : public NamedObject
{
public:
	enum Result {
		e_nomatch,
		e_allow,
		e_deny
	};

	AuthRule(
		Result fate,
		bool inverted
		) : m_priority(1000), m_fate(fate), m_inverted(inverted), m_next(NULL) { }

	virtual ~AuthRule() { delete m_next; }

	virtual bool Match(const AuthObj & aobj) = 0;

	int Check(const AuthObj & aobj);

	bool operator<(const AuthRule & obj) const { return m_priority < obj.m_priority; }

	void SetNext(AuthRule * next) { m_next = next; }

private:
	AuthRule();
	AuthRule(const AuthRule& );
	AuthRule & operator=(const AuthRule &);

protected:
	/// the lesser the value, the higher the priority
	int m_priority;

private:
	Result m_fate;
	bool m_inverted;
	AuthRule * m_next;
};

class NullRule : public AuthRule
{
public:
	NullRule() : AuthRule(e_nomatch, false) { SetName("NULL"); }

	virtual bool Match(const AuthObj & /*aobj*/) { return false; }

private:
	NullRule(const NullRule &);
	NullRule & operator=(const NullRule &);
};

class IPAuthRule : public AuthRule
{
public:
	IPAuthRule(Result fate, const PString & ipStr, bool inverted);

	virtual bool Match(const AuthObj & aobj);

private:
	IPAuthRule();
	IPAuthRule(const IPAuthRule &);
	IPAuthRule & operator=(const IPAuthRule &);

private:
	PIPSocket::Address m_network, m_netmask;
};

class AliasAuthRule : public AuthRule
{
public:
	AliasAuthRule(
		Result fate,
		const PString & aliasStr,
		bool inverted
		) : AuthRule(fate, inverted), m_pattern(aliasStr)
	{
		m_priority = -1;
		SetName(PString((fate == e_allow) ? "allow alias" : "deny alias")
			+ (inverted ? ":!" : ":") + aliasStr);
	}

	virtual bool Match(const AuthObj & aobj);

private:
	AliasAuthRule();
	AliasAuthRule(const AliasAuthRule &);
	AliasAuthRule & operator=(const AliasAuthRule &);

private:
	PString m_pattern;
};


ARQAuthObj::ARQAuthObj(const H225_AdmissionRequest & arq)
	: m_arq(arq), m_ep(RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier))
{
}

PStringArray ARQAuthObj::GetPrefixes() const
{
	PStringArray array;
	if (m_arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)) {
		const PINDEX ss = m_arq.m_destinationInfo.GetSize();
		if (ss > 0) {
			array.SetSize(ss);
			for (PINDEX i = 0; i < ss; ++i)
				array[i] = AsString(m_arq.m_destinationInfo[i], false);
		}
	}
	if (array.GetSize() == 0)
		array.AppendString(PString::Empty());
	return array;
}

PIPSocket::Address ARQAuthObj::GetIP() const
{
	PIPSocket::Address result;
	const H225_TransportAddress & addr =
		m_arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress)
		? m_arq.m_srcCallSignalAddress : m_ep->GetCallSignalAddress();
	GetIPFromTransportAddr(addr, result);
	return result;
}

PString ARQAuthObj::GetAliases() const
{
	return AsString(m_ep->GetAliases());
}

LRQAuthObj::LRQAuthObj(const H225_LocationRequest & lrq)
	: m_lrq(lrq)
{
	GetIPFromTransportAddr(m_lrq.m_replyAddress, m_ipAddress);
}

PStringArray LRQAuthObj::GetPrefixes() const
{
	PStringArray array;
	const PINDEX ss = m_lrq.m_destinationInfo.GetSize();
	if (ss > 0) {
		array.SetSize(ss);
		for (PINDEX i = 0; i < ss; ++i)
			array[i] = AsString(m_lrq.m_destinationInfo[i], false);
	}
	return array;
}

PIPSocket::Address LRQAuthObj::GetIP() const
{
	return m_ipAddress;
}

PString LRQAuthObj::GetAliases() const
{
	return m_lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)
		? AsString(m_lrq.m_sourceInfo) : PString::Empty();
}

SetupAuthObj::SetupAuthObj(const SetupMsg & setup) : m_setup(setup)
{
}

PStringArray SetupAuthObj::GetPrefixes() const
{
	PStringArray array;
	if (m_setup.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		const PINDEX ss = m_setup.GetUUIEBody().m_destinationAddress.GetSize();
		if (ss > 0) {
			array.SetSize(ss);
			for (PINDEX i = 0; i < ss; ++i)
				array[i] = AsString(m_setup.GetUUIEBody().m_destinationAddress[i], false);
		}
	}
	if (array.GetSize() == 0)
		array.AppendString(PString::Empty());
	return array;
}

PIPSocket::Address SetupAuthObj::GetIP() const
{
	PIPSocket::Address result;
	m_setup.GetPeerAddr(result);
	return result;
}

PString SetupAuthObj::GetAliases() const
{
	return m_setup.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_sourceAddress)
		? AsString(m_setup.GetUUIEBody().m_sourceAddress) : PString::Empty();
}

int AuthRule::Check(const AuthObj & aobj)
{
	if (Match(aobj) ^ m_inverted) {
		PTRACE(5, "GKAUTH\tPrefix auth rule '" << GetName() << "' matched");
		return m_fate;
	} else
		return m_next ? m_next->Check(aobj) : e_nomatch;
}

inline void delete_rule(PrefixAuth::Rules::value_type r)
{
	delete r.second;
	r.second = NULL;
}

IPAuthRule::IPAuthRule(Result fate, const PString & ipStr, bool inverted)
	: AuthRule(fate, inverted)
{
	Toolkit::GetNetworkFromString(ipStr, m_network, m_netmask);
	DWORD n = ~PIPSocket::Net2Host(DWORD(m_netmask));
	for (m_priority = 0; n; n >>= 1)
		++m_priority;
	SetName(PString((fate == e_allow) ? "allow ip(" : "deny ip(")
		+ PString(m_priority) + (inverted ? "):!" : "):") + ipStr);
}

bool IPAuthRule::Match(const AuthObj & aobj)
{
	return ((aobj.GetIP().GetVersion() == m_network.GetVersion()) && ((aobj.GetIP() & m_netmask) == m_network));
}

bool AliasAuthRule::Match(const AuthObj& aobj)
{
	return aobj.GetAliases().FindRegEx(m_pattern) != P_MAX_INDEX;
}

inline bool is_inverted(const PString & cfg, PINDEX p)
{
	return (p > 1) ? cfg[p-1] == '!' : false;
}

inline bool comp_authrule_priority(AuthRule *a1, AuthRule *a2)
{
	return *a1 < *a2;
}

namespace {
const char* const allowflag = "allow";
const char* const denyflag  = "deny"; // not used in code, because everything else defaults to DENY
const char* const ipflag    = "ip:";
const char* const ipv4flag  = "ipv4:";
const char* const ipv6flag  = "ipv6:";
const char* const aliasflag = "alias:";
}

// class PrefixAuth
PrefixAuth::PrefixAuth(
	const char * name,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks)
	: GkAuthenticator(name, supportedRasChecks, supportedMiscChecks)
{
	m_defaultRule = GetDefaultStatus();

	const int ipfl = (int)strlen(ipflag);
	const int ipv4fl = (int)strlen(ipv4flag);
	const int ipv6fl = (int)strlen(ipv6flag);
	const int aliasfl = (int)strlen(aliasflag);

	const PStringToString cfgs = GetConfig()->GetAllKeyValues(name);
	for (PINDEX i = 0; i < cfgs.GetSize(); ++i) {
		PString key = cfgs.GetKeyAt(i);
		if (key *= "default") {
			m_defaultRule = Toolkit::AsBool(cfgs.GetDataAt(i)) ? e_ok : e_fail;
			continue;
		} else if (key *= "ALL") {
			// use space (0x20) as the key so it will be the last resort
			key = " ";
		}
		if (m_prefrules.find(key) != m_prefrules.end()) {
			PTRACE(1, "GKAUTH\t" << GetName() << " duplicate entry for "
				"destination '" << key << '\'');
			continue; //rule already exists? ignore
		}

		const PStringArray rules = cfgs.GetDataAt(i).Tokenise("|", false);
		const PINDEX sz = rules.GetSize();
		if (sz < 1) {
			PTRACE(1, "GKAUTH\t" << GetName() << " no rules found for "
				"destination '" << key << '\'');
			continue;
		}
		//AuthRule *rls[sz];
		AuthRule **rls = new AuthRule *[sz];
		for (PINDEX j = 0; j < sz; ++j) {
			// if not allowed, assume denial
			const AuthRule::Result fate = (rules[j].Find(allowflag) != P_MAX_INDEX)
				? AuthRule::e_allow : AuthRule::e_deny;
			PINDEX pp;
			if ((pp = rules[j].Find(ipflag)) != P_MAX_INDEX)
				rls[j] = new IPAuthRule(fate, rules[j].Mid(pp + ipfl).Trim(),
					is_inverted(rules[j], pp)
					);
			else if ((pp = rules[j].Find(ipv4flag)) != P_MAX_INDEX)
				rls[j] = new IPAuthRule(fate, rules[j].Mid(pp + ipv4fl).Trim(),
					is_inverted(rules[j], pp)
					);
			else if ((pp = rules[j].Find(ipv6flag)) != P_MAX_INDEX)
				rls[j] = new IPAuthRule(fate, rules[j].Mid(pp + ipv6fl).Trim(),
					is_inverted(rules[j], pp)
					);
			else if ((pp = rules[j].Find(aliasflag)) != P_MAX_INDEX)
				rls[j] = new AliasAuthRule(fate, rules[j].Mid(pp+aliasfl).Trim(),
					is_inverted(rules[j], pp)
					);
			else {
				rls[j] = new NullRule();
			}
		}

		// sort the rules by priority
		stable_sort(rls, rls + sz, comp_authrule_priority);
		for (PINDEX k = 1; k < sz; ++k)
			rls[k-1]->SetNext(rls[k]);
		m_prefrules[key] = rls[0];
		delete [] rls;
		rls = NULL;
	}

	if (m_prefrules.empty()) {
		PTRACE(1, "GKAUTH\t" << GetName() << " contains no rules - check the config");
	}
}

PrefixAuth::~PrefixAuth()
{
	for_each(m_prefrules.begin(), m_prefrules.end(), delete_rule);
}

int PrefixAuth::Check(RasPDU<H225_LocationRequest> & request, unsigned &)
{
	LRQAuthObj tmpObj((const H225_LocationRequest&)request); // fix for GCC 3.4.2
	return doCheck(tmpObj);
}

int PrefixAuth::Check(
	/// ARQ to be authenticated/authorized
	RasPDU<H225_AdmissionRequest> & request,
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData & /*authData*/)
{
	H225_AdmissionRequest & arq = request;
	if (arq.m_answerCall
		&& arq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier)
		&& CallTable::Instance()->FindCallRec(arq.m_callIdentifier)) {
		PTRACE(5, "GKAUTH\t" << GetName() << " ARQ check skipped - call "
			"already admitted and present in the call table");
		return e_ok;
	}
	ARQAuthObj tmpObj(arq); // fix for GCC 3.4.2
	return doCheck(tmpObj);
}

int PrefixAuth::Check(
	/// Q.931/H.225 Setup message to be authenticated
	SetupMsg & setup,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData & /*authData*/
	)
{
	SetupAuthObj tmpObj(setup); // fix for GCC 3.4.2
	return doCheck(tmpObj);
}

struct comp_pref { // function object
	comp_pref(const PString & s) : value(s) {}
	bool operator()(const PrefixAuth::Rules::value_type & v) const;
	const PString & value;
};

inline bool comp_pref::operator()(const PrefixAuth::Rules::value_type & v) const
{
	return (value.Find(v.first) == 0) || (v.first *= " ");
}

int PrefixAuth::doCheck(const AuthObj & aobj)
{
	if (!aobj.IsValid())
		return e_fail;

	const PStringArray destinationInfo(aobj.GetPrefixes());
	for (PINDEX i = 0; i < destinationInfo.GetSize(); ++i) {
		// find the first match rule
		// since prefrules is descendently sorted
		// it must be the most specific prefix
		for (Rules::iterator j = m_prefrules.begin(); j != m_prefrules.end(); ++j) {
			Rules::iterator iter = find_if(j, m_prefrules.end(), comp_pref(destinationInfo[i]));
			if (iter == m_prefrules.end())
				break;
			switch (iter->second->Check(aobj))
			{
			case AuthRule::e_allow:
				PTRACE(4, "GKAUTH\t" << GetName() << " rule matched and "
					"accepted destination prefix '"
					<< ((iter->first == " ") ? PString("ALL") : iter->first)
					<< "' for alias '" << destinationInfo[i] << '\'');
				return e_ok;

			case AuthRule::e_deny:
				PTRACE(4, "GKAUTH\t" << GetName() << " rule matched and "
					"rejected destination prefix '"
					<< ((iter->first == " ") ? PString("ALL") : iter->first)
					<< "' for alias '" << destinationInfo[i] << '\'');
				return e_fail;

			default: // try next prefix...
				j = iter;
				PTRACE(4, "GKAUTH\t" << GetName() << " rule matched and "
					"could not reject or accept destination prefix '"
					<< ((iter->first == " ") ? PString("ALL") : iter->first)
					<< "' for alias '" << destinationInfo[i] << '\'');
			}
		}
	}
	if (m_defaultRule == e_ok)
		PTRACE(4, "GKAUTH\t" << GetName() << " default rule accepted the request");
	else if (m_defaultRule == e_fail)
		PTRACE(4, "GKAUTH\t" << GetName() << " default rule rejected the request");
	else
		PTRACE(4, "GKAUTH\t" << GetName() << " could not reject or accept the request");
	return m_defaultRule;
}

namespace { // anonymous namespace
	GkAuthCreator<GkAuthenticator> DefaultAuthenticatorCreator("default");
	GkAuthCreator<SimplePasswordAuth> SimplePasswordAuthCreator("SimplePasswordAuth");
#if H323_H350
	GkAuthCreator<H350PasswordAuth> SQLPasswordAuthCreator("H350PasswordAuth");
#endif
	GkAuthCreator<AliasAuth> AliasAuthCreator("AliasAuth");
	GkAuthCreator<PrefixAuth> PrefixAuthCreator("PrefixAuth");
} // end of anonymous namespace
