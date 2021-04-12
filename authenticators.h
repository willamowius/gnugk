//////////////////////////////////////////////////////////////////
//
// authenticators.h
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

#ifndef AUTHENTICATORS_H
#define AUTHENTICATORS_H "@(#) $Id$"

#include <h235auth.h>
#include "config.h"


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


#ifndef OFF

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

#endif
#endif // OFF

#endif  // AUTHENTICATORS_H
