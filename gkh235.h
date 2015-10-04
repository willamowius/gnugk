//////////////////////////////////////////////////////////////////
//
// gkh235.h
//
// Copyright (c) 2015, Jan Willamowius
// Copyright (c) 2004-2005, Michal Zygmuntowicz
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef GKH235_H
#define GKH235_H "#(@) $Id$"

extern const char OID_H235_CAT[];
extern const char OID_H235_MD5[];
extern const char OID_DES_ECB[];
extern const char OID_H235_A_V1[];
extern const char OID_H235_A_V2[];
extern const char OID_H235_T_V1[];
extern const char OID_H235_T_V2[];
extern const char OID_H235_U_V1[];
extern const char OID_H235_U_V2[];


class H225_RasMessage;
class H225_ArrayOf_ClearToken;
class H225_ArrayOf_CryptoH323Token;
class H235AuthCAT;
class H235AuthSimpleMD5;
class H235AuthDesECB;
//class H235AuthProcedure1;

class GkH235Authenticators {
public:
	GkH235Authenticators();
	GkH235Authenticators(const GkH235Authenticators &);

	GkH235Authenticators& operator=(const GkH235Authenticators &);

	~GkH235Authenticators();

	/** Validate clear/crypto tokens from the given RAS message
	    through all active H.235 authenticators.

	    @return
	    Validation result (#H235Authenticator::ValidationResult enum#).
	*/
	int Validate(
		const H225_RasMessage & rasmsg,
		const H225_ArrayOf_ClearToken & clearTokens,
		const H225_ArrayOf_CryptoH323Token & cryptoTokens,
		const PBYTEArray & rawPDU);

	/** Validate clear/crypto tokens from the given Q931 message
	    through all active H.235 authenticators.

	    @return
	    Validation result (#H235Authenticator::ValidationResult enum#).
	*/
	int Validate(
		const Q931 & msg,
		const H225_ArrayOf_ClearToken & clearTokens,
		const H225_ArrayOf_CryptoH323Token & cryptoTokens);

	void PrepareTokens(
		H225_RasMessage & rasmsg,
		H225_ArrayOf_ClearToken & clearTokens,
		H225_ArrayOf_CryptoH323Token & cryptoTokens);

	void Finalise(
		H225_RasMessage & rasmsg,
		PBYTEArray & rawPdu);

	void PrepareTokens(
		unsigned q931Tag,
		H225_ArrayOf_ClearToken & clearTokens,
		H225_ArrayOf_CryptoH323Token & cryptoTokens);

	void Finalise(
		unsigned q931Tag,
		PBYTEArray & rawPdu);

	void SetCATData(
		const PString & generalID,
		const PString & password);

	void SetSimpleMD5Data(
		const PString & generalID,
		const PString & password);

#ifdef HAS_DES_ECB
	void SetDESData(
		const PString & generalID,
		const PString & password);
#endif

	void SetProcedure1Data(
		const PString & sendersID,
		const PString & generalID,
		const PString & password,
		PBoolean requireGeneralID);

	void SetProcedure1LocalId(const PString & localID);
	void SetProcedure1RemoteId(const PString & remoteID);

	bool HasCATPassword();
	bool HasMD5Password();
#ifdef HAS_DES_ECB
	bool HasDESPassword();
#endif
	bool HasProcedure1Password();

    // get pointers to the tokens in the different Q.931 messages
    static void GetQ931Tokens(Q931::MsgTypes type, H225_H323_UserInformation * uuie, H225_ArrayOf_ClearToken ** tokens, H225_ArrayOf_CryptoH323Token ** cryptoTokens);


protected:
	long m_timestampGracePeriod;
	// CAT
	H235AuthCAT * m_authCAT;
	PString m_localIdCAT;
	int m_authResultCAT;
	// MD5
	H235AuthSimpleMD5 * m_authMD5;
	PString m_localIdMD5;
	int m_authResultMD5;
#ifdef HAS_DES_ECB
    // DES ECB
	H235AuthDesECB * m_authDES;
	PString m_localIdDES;
	int m_authResultDES;
#endif
	// H.235.1
	H235AuthProcedure1 * m_authProcedure1;
	PString m_localIdProcedure1;
	PString m_remoteIdProcedure1;
	int m_authResultProcedure1;
	PMutex m_mutex;
};

#endif // GKH235_H

