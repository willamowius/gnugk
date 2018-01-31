//////////////////////////////////////////////////////////////////
//
// authenticators.cxx
//
// Copyright (c) 2015, Jan Willamowius
//
// additional authentication modules
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <h225.h>
#include "Toolkit.h"
#include "authenticators.h"

#ifdef P_SSL
#include <openssl/err.h>
#include <openssl/rand.h>
#endif // P_SSL


#ifdef HAS_DES_ECB

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
    case H225_RasMessage::e_gatekeeperRequest :
      return received ? !remoteId.IsEmpty() : !localId.IsEmpty();
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

/////////////////////////////////////////////////////////////////////////////
#endif

#ifdef OFF

// This stub is enough to fake 2.16.840.1.114187.1.3 support.
// We don't know what the actual crypto is.

#if defined(H323_H235)

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

#endif // H323_H235

#endif // OFF
