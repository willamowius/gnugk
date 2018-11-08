//////////////////////////////////////////////////////////////////
//
// gkh235.cxx
//
// Copyright (c) 2016, Jan Willamowius
// Copyright (c) 2004-2005, Michal Zygmuntowicz
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "config.h"
#include <ptlib.h>
#include <h225.h>
#include <h235.h>
#include <h235auth.h>
#include "Toolkit.h"
#include "authenticators.h"
#include "gkh235.h"

const char OID_H235_CAT[] = "1.2.840.113548.10.1.2.1";
const char OID_H235_MD5[] = "1.2.840.113549.2.5";
const char OID_H235_DES[] = "1.3.14.3.2.6";
const char OID_H235_A_V1[] = "0.0.8.235.0.1.1";
const char OID_H235_A_V2[] = "0.0.8.235.0.2.1";
const char OID_H235_T_V1[] = "0.0.8.235.0.1.5";
const char OID_H235_T_V2[] = "0.0.8.235.0.2.5";
const char OID_H235_U_V1[] = "0.0.8.235.0.1.6";
const char OID_H235_U_V2[] = "0.0.8.235.0.2.6";

GkH235Authenticators::GkH235Authenticators()
	: m_timestampGracePeriod(GkConfig()->GetInteger("H235", "TimestampGracePeriod", 2*60*60+10)),
	m_authCAT(NULL), m_authResultCAT(H235Authenticator::e_Disabled),
	m_authMD5(NULL), m_authResultMD5(H235Authenticator::e_Disabled)
#ifdef HAS_DES_ECB
	, m_authDES(NULL), m_authResultDES(H235Authenticator::e_Disabled)
#endif
#ifdef H323_H235
	, m_authProcedure1(NULL), m_authResultProcedure1(H235Authenticator::e_Disabled)
#endif
{
}

GkH235Authenticators::GkH235Authenticators(const GkH235Authenticators & auth)
	: m_authCAT(NULL), m_authMD5(NULL)
#ifdef HAS_DES_ECB
		, m_authDES(NULL)
#endif
#ifdef H323_H235
        , m_authProcedure1(NULL)
#endif
{
	PWaitAndSignal lock(auth.m_mutex);
	m_timestampGracePeriod = auth.m_timestampGracePeriod;

	if (auth.m_authCAT != NULL)
		m_authCAT = static_cast<H235AuthCAT*>(auth.m_authCAT->Clone());
	m_localIdCAT = auth.m_localIdCAT;
	m_authResultCAT = auth.m_authResultCAT;

	if (auth.m_authMD5 != NULL)
		m_authMD5 = static_cast<H235AuthSimpleMD5*>(auth.m_authMD5->Clone());
	m_localIdMD5 = auth.m_localIdMD5;
	m_authResultMD5 = auth.m_authResultMD5;

#ifdef HAS_DES_ECB
	if (auth.m_authDES != NULL)
		m_authDES = static_cast<H235AuthDesECB*>(auth.m_authDES->Clone());
	m_localIdDES = auth.m_localIdDES;
	m_authResultDES = auth.m_authResultDES;
#endif

#ifdef H323_H235
	if (auth.m_authProcedure1 != NULL)
		m_authProcedure1 = static_cast<H235AuthProcedure1*>(auth.m_authProcedure1->Clone());
	m_localIdProcedure1 = auth.m_localIdProcedure1;
	m_remoteIdProcedure1 = auth.m_remoteIdProcedure1;
	m_authResultProcedure1 = auth.m_authResultProcedure1;
#endif
}

GkH235Authenticators & GkH235Authenticators::operator=(const GkH235Authenticators & auth)
{
	GkH235Authenticators temp(auth);

	PWaitAndSignal lock(m_mutex);

	m_timestampGracePeriod = temp.m_timestampGracePeriod;

	m_authCAT = temp.m_authCAT;
	temp.m_authCAT = NULL;
	m_localIdCAT = temp.m_localIdCAT;
	m_authResultCAT = temp.m_authResultCAT;

	m_authMD5 = temp.m_authMD5;
	temp.m_authMD5 = NULL;
	m_localIdMD5 = temp.m_localIdMD5;
	m_authResultMD5 = temp.m_authResultMD5;

#ifdef H323_H235
	m_authProcedure1 = temp.m_authProcedure1;
	temp.m_authProcedure1 = NULL;
	m_localIdProcedure1 = temp.m_localIdProcedure1;
	m_remoteIdProcedure1 = temp.m_remoteIdProcedure1;
	m_authResultProcedure1 = temp.m_authResultProcedure1;
#endif // H323_H235

	return *this;
}

GkH235Authenticators::~GkH235Authenticators()
{
	delete m_authCAT;
	delete m_authMD5;
#ifdef H323_H235
	delete m_authProcedure1;
#endif // H323_H235
}

int GkH235Authenticators::Validate(
	const Q931 & msg,
	const H225_ArrayOf_ClearToken & clearTokens,
	const H225_ArrayOf_CryptoH323Token & cryptoTokens)
{
#ifdef H323_H235
	PWaitAndSignal lock(m_mutex);

    if (!GkConfig()->GetBoolean("H235", "FullQ931Checking", false)) {
        return H235Authenticator::e_OK;
    }

	const PTime now;
	bool procedure1Found = false;
	for (PINDEX i = 0; i < cryptoTokens.GetSize(); i++) {
		const H225_CryptoH323Token & token = cryptoTokens[i];
		if (token.GetTag() == H225_CryptoH323Token::e_nestedcryptoToken) {
			const H235_CryptoToken & nestedCryptoToken = token;
			if (nestedCryptoToken.GetTag() == H235_CryptoToken::e_cryptoHashedToken) {
  				const H235_CryptoToken_cryptoHashedToken & cryptoHashedToken = nestedCryptoToken;
				if (cryptoHashedToken.m_tokenOID == OID_H235_A_V1
						|| cryptoHashedToken.m_tokenOID == OID_H235_A_V2) {
					procedure1Found = true;
					if (m_authProcedure1 == NULL)
						m_authProcedure1 = new H235AuthProcedure1;
					m_authProcedure1->Enable();

					const long deltaTime = (long)(now.GetTimeInSeconds() - cryptoHashedToken.m_hashedVals.m_timeStamp);
					if (std::abs(deltaTime) > m_timestampGracePeriod) {
						PTRACE(2, "GKH235\tInvalid Procedure I timestamp ABS(" << now.GetTimeInSeconds()
							<< '-' << (int)cryptoHashedToken.m_hashedVals.m_timeStamp << ") > "
							<< m_timestampGracePeriod);
						return m_authResultProcedure1 = H235Authenticator::e_InvalidTime;
	  				}

					const PString oldLocalId = m_authProcedure1->GetLocalId();
					const PString oldRemoteId = m_authProcedure1->GetRemoteId();
					m_authProcedure1->SetLocalId(m_localIdProcedure1);
					m_authProcedure1->SetRemoteId(m_remoteIdProcedure1);
                   	bool checkSendersID = GkConfig()->GetBoolean("H235", "CheckSendersID", true);
					if (cryptoHashedToken.m_hashedVals.HasOptionalField(H235_ClearToken::e_sendersID) && checkSendersID) {
                        bool idOK = true;
                        // TODO235: check if sendersID == EPID or == alias and then set the actual as expected, don't set if its not a correct one
                        if (!idOK) {
                            return H235Authenticator::e_Error;
                        }
					}
                    // copy actual sendersID into what we expect
                    m_authProcedure1->SetRemoteId(cryptoHashedToken.m_hashedVals.m_sendersID);

                    // re-encode the message to check it, not sure why (PByteArray &)msg crashes
                    PBYTEArray buf(1024); // buffer with initial size 1024
                    if (!msg.Encode(buf)) {
                        PTRACE(1, "H235\tError: re-encode failed"); // should never happen
                    }

					m_authResultProcedure1 = m_authProcedure1->ValidateCryptoToken(token, buf);
					if (m_authResultProcedure1 != H235Authenticator::e_OK) {
						m_authProcedure1->SetLocalId(oldLocalId);
						m_authProcedure1->SetRemoteId(oldRemoteId);
					}
				}
			}
		}
	}

	if (!procedure1Found && m_authProcedure1 && m_authProcedure1->IsActive()
		&& m_authProcedure1->IsSecuredSignalPDU(msg.GetMessageType(), TRUE)) {
		m_authResultProcedure1 = H235Authenticator::e_Absent;
		return m_authResultProcedure1;
	} else if (procedure1Found && m_authResultProcedure1 != H235Authenticator::e_OK) {
		return m_authResultProcedure1;
	}

	return H235Authenticator::e_OK;
#else
	return H235Authenticator::e_Disabled;
#endif // H323_H235
}

int GkH235Authenticators::Validate(
	const H225_RasMessage & rasmsg,
	const H225_ArrayOf_ClearToken & clearTokens,
	const H225_ArrayOf_CryptoH323Token & cryptoTokens,
	const PBYTEArray & rawPDU)
{
	PWaitAndSignal lock(m_mutex);

	const PTime now;
	bool catFound = false;
	bool md5Found = false;
#ifdef HAS_DES_ECB
	bool desFound = false;
#endif
#ifdef H323_H235
	bool procedure1Found = false;
#endif // H323_H235

	PINDEX i;
	for (i = 0; i < clearTokens.GetSize(); i++) {
		const H235_ClearToken & token = clearTokens[i];
		// check for CAT (Cisco Access Token)
  		if (token.m_tokenOID == OID_H235_CAT && Toolkit::Instance()->IsAuthenticatorEnabled("CAT")) {
			catFound = true;
			if (m_authCAT == NULL)
				m_authCAT = new H235AuthCAT;
			m_authCAT->Enable();

			if (!token.HasOptionalField(H235_ClearToken::e_timeStamp)) {
				PTRACE(2, "GKH235\tCAT requires timeStamp field");
				return m_authResultCAT = H235Authenticator::e_Error;
			}

			const long deltaTime = (long)(now.GetTimeInSeconds() - token.m_timeStamp);
			if (std::abs(deltaTime) > m_timestampGracePeriod) {
				PTRACE(2, "GKH235\tInvalid CAT timestamp ABS(" << now.GetTimeInSeconds()
					<< '-' << (int)token.m_timeStamp << ") > " << m_timestampGracePeriod);
				return m_authResultCAT = H235Authenticator::e_InvalidTime;
  			}

			const PString oldLocalId = m_authCAT->GetLocalId();
			m_authCAT->SetLocalId(m_localIdCAT);

			m_authResultCAT = m_authCAT->ValidateClearToken(token);
			if (m_authResultCAT != H235Authenticator::e_OK)
				m_authCAT->SetLocalId(oldLocalId);
		}
	}

	for (i = 0; i < cryptoTokens.GetSize(); i++) {
		const H225_CryptoH323Token& token = cryptoTokens[i];
		if (token.GetTag() == H225_CryptoH323Token::e_cryptoEPPwdHash && Toolkit::Instance()->IsAuthenticatorEnabled("MD5")) {
			const H225_CryptoH323Token_cryptoEPPwdHash & cryptoEPPwdHash = token;
			if (cryptoEPPwdHash.m_token.m_algorithmOID == OID_H235_MD5) {
				md5Found = true;
				if (m_authMD5 == NULL)
					m_authMD5 = new H235AuthSimpleMD5();
				m_authMD5->Enable();

				const long deltaTime = (long)(now.GetTimeInSeconds() - cryptoEPPwdHash.m_timeStamp);
				if (std::abs(deltaTime) > m_timestampGracePeriod) {
					PTRACE(2, "GKH235\tInvalid MD5 timestamp ABS(" << now.GetTimeInSeconds()
						<< '-' << (int)cryptoEPPwdHash.m_timeStamp << ") > " << m_timestampGracePeriod);
					return m_authResultMD5 = H235Authenticator::e_InvalidTime;
  				}

				const PString oldLocalId = m_authMD5->GetLocalId();
				m_authMD5->SetLocalId(m_localIdMD5);

				m_authResultMD5 = m_authMD5->ValidateCryptoToken(token, rawPDU);
				if (m_authResultMD5 != H235Authenticator::e_OK) {
					m_authMD5->SetLocalId(oldLocalId);
					return m_authResultMD5;
				}
			}
		} else if (token.GetTag() == H225_CryptoH323Token::e_nestedcryptoToken && Toolkit::Instance()->IsAuthenticatorEnabled("H.235.1")) {
#ifdef H323_H235
			const H235_CryptoToken & nestedCryptoToken = token;
			if (nestedCryptoToken.GetTag() == H235_CryptoToken::e_cryptoHashedToken) {
  				const H235_CryptoToken_cryptoHashedToken & cryptoHashedToken = nestedCryptoToken;
				if (cryptoHashedToken.m_tokenOID == OID_H235_A_V1
						|| cryptoHashedToken.m_tokenOID == OID_H235_A_V2) {
					procedure1Found = true;
					if (m_authProcedure1 == NULL)
						m_authProcedure1 = new H235AuthProcedure1();
					m_authProcedure1->Enable();

					const long deltaTime = (long)(now.GetTimeInSeconds() - cryptoHashedToken.m_hashedVals.m_timeStamp);
					if (std::abs(deltaTime) > m_timestampGracePeriod) {
						PTRACE(2, "GKH235\tInvalid Procedure I timestamp ABS(" << now.GetTimeInSeconds()
							<< '-' << (int)cryptoHashedToken.m_hashedVals.m_timeStamp << ") > "
							<< m_timestampGracePeriod);
						return m_authResultProcedure1 = H235Authenticator::e_InvalidTime;
	  				}

					const PString oldLocalId = m_authProcedure1->GetLocalId();
					const PString oldRemoteId = m_authProcedure1->GetRemoteId();
					m_authProcedure1->SetLocalId(m_localIdProcedure1);
					m_authProcedure1->SetRemoteId(m_remoteIdProcedure1);

					m_authResultProcedure1 = m_authProcedure1->ValidateCryptoToken(token, rawPDU);
					if (m_authResultProcedure1 != H235Authenticator::e_OK) {
						m_authProcedure1->SetLocalId(oldLocalId);
						m_authProcedure1->SetRemoteId(oldRemoteId);
					}
				}
			}
#endif // H323_H235
		} else if (token.GetTag() == H225_CryptoH323Token::e_cryptoEPPwdEncr) {
		    H235_ENCRYPTED<H235_EncodedPwdCertToken> cryptoEPPwdEncr = (H235_ENCRYPTED<H235_EncodedPwdCertToken>)token;
#ifdef HAS_DES_ECB
		    if (cryptoEPPwdEncr.m_algorithmOID == OID_H235_DES && Toolkit::Instance()->IsAuthenticatorEnabled("DES")) {
				desFound = true;
				if (m_authDES == NULL)
					m_authDES = new H235AuthDesECB();
				m_authDES->Enable();

				const PString oldLocalId = m_authDES->GetLocalId();
				m_authDES->SetLocalId(m_localIdDES);

				m_authResultDES = m_authDES->ValidateCryptoToken(token, rawPDU);
				if (m_authResultDES != H235Authenticator::e_OK) {
					m_authDES->SetLocalId(oldLocalId);
					return m_authResultDES;
				}
		    }
#endif
		} else {
            PTRACE(4, "GKH235\tUnhandled cryptoToken " << token.GetTagName());
		}
	}

	if (!catFound && m_authCAT && m_authCAT->IsActive()
		&& m_authCAT->IsSecuredPDU(rasmsg.GetTag(), TRUE)) {
		m_authResultCAT = H235Authenticator::e_Absent;
		return m_authResultCAT;
	} else if (catFound && m_authResultCAT != H235Authenticator::e_OK)
		return m_authResultCAT;

	if (!md5Found && m_authMD5 && m_authMD5->IsActive()
		&& m_authMD5->IsSecuredPDU(rasmsg.GetTag(), TRUE)) {
		m_authResultMD5 = H235Authenticator::e_Absent;
		return m_authResultMD5;
	} else if (md5Found && m_authResultMD5 != H235Authenticator::e_OK)
		return m_authResultMD5;

#ifdef HAS_DES_ECB
	if (!desFound && m_authDES && m_authDES->IsActive()
		&& m_authDES->IsSecuredPDU(rasmsg.GetTag(), TRUE)) {
		m_authResultDES = H235Authenticator::e_Absent;
		return m_authResultDES;
	} else if (desFound && m_authResultDES != H235Authenticator::e_OK)
		return m_authResultDES;
#endif

#ifdef H323_H235
	if (!procedure1Found && m_authProcedure1 && m_authProcedure1->IsActive()
		&& m_authProcedure1->IsSecuredPDU(rasmsg.GetTag(), TRUE)) {
		m_authResultProcedure1 = H235Authenticator::e_Absent;
		return m_authResultProcedure1;
	} else if (procedure1Found && m_authResultProcedure1 != H235Authenticator::e_OK)
		return m_authResultProcedure1;
#endif // H323_H235

	return H235Authenticator::e_OK;
}

void GkH235Authenticators::PrepareTokens(
	H225_RasMessage & rasmsg,
	H225_ArrayOf_ClearToken & clearTokens,
	H225_ArrayOf_CryptoH323Token & cryptoTokens)
{
	PWaitAndSignal lock(m_mutex);

	if (m_authCAT != NULL && m_authCAT->IsActive()
			&& m_authCAT->IsSecuredPDU(rasmsg.GetTag(), FALSE)
			&& m_authResultCAT == H235Authenticator::e_OK) {
		m_authCAT->SetLocalId(m_localIdCAT);
		m_authCAT->PrepareTokens(clearTokens, cryptoTokens);
	}

	if (m_authMD5 && m_authMD5->IsActive()
			&& m_authMD5->IsSecuredPDU(rasmsg.GetTag(), FALSE)
			&& m_authResultMD5 == H235Authenticator::e_OK) {
		m_authMD5->SetLocalId(m_localIdMD5);
		m_authMD5->PrepareTokens(clearTokens, cryptoTokens);
	}

#ifdef HAS_DES_ECB
	if (m_authDES && m_authDES->IsActive()
			&& m_authDES->IsSecuredPDU(rasmsg.GetTag(), FALSE)
			&& m_authResultDES == H235Authenticator::e_OK) {
		m_authDES->SetLocalId(m_localIdDES);
		m_authDES->PrepareTokens(clearTokens, cryptoTokens);
	}
#endif

#ifdef H323_H235
	if (m_authProcedure1 && m_authProcedure1->IsActive()
			&& m_authProcedure1->IsSecuredPDU(rasmsg.GetTag(), FALSE)) {
//			&& m_authResultProcedure1 == H235Authenticator::e_OK) {     // this hurts when sending call from ep without H.235.1 to one with H.235.1
		m_authProcedure1->SetLocalId(m_localIdProcedure1);
		m_authProcedure1->SetRemoteId(m_remoteIdProcedure1);
		m_authProcedure1->PrepareTokens(clearTokens, cryptoTokens);
	}
#endif // H323_H235
}

void GkH235Authenticators::Finalise(H225_RasMessage & rasmsg, PBYTEArray & rawPdu)
{
	PWaitAndSignal lock(m_mutex);

	if (m_authCAT != NULL && m_authCAT->IsActive()
			&& m_authCAT->IsSecuredPDU(rasmsg.GetTag(), FALSE))
		m_authCAT->Finalise(rawPdu);

	if (m_authMD5 && m_authMD5->IsActive()
			&& m_authMD5->IsSecuredPDU(rasmsg.GetTag(), FALSE))
		m_authMD5->Finalise(rawPdu);

#ifdef H323_H235
	if (m_authProcedure1 && m_authProcedure1->IsActive()
			&& m_authProcedure1->IsSecuredPDU(rasmsg.GetTag(), FALSE)) {
		m_authProcedure1->Finalise(rawPdu);
    }
#endif // H323_H235
}

void GkH235Authenticators::PrepareTokens(
	unsigned q931Tag,
	H225_ArrayOf_ClearToken & clearTokens,
	H225_ArrayOf_CryptoH323Token & cryptoTokens)
{
#ifdef H323_H325
	PWaitAndSignal lock(m_mutex);

	if (m_authProcedure1 && m_authProcedure1->IsActive()
			&& m_authProcedure1->IsSecuredPDU(q931Tag, FALSE)) {
		m_authProcedure1->SetLocalId(m_localIdProcedure1);
		m_authProcedure1->SetRemoteId(m_remoteIdProcedure1);
		m_authProcedure1->PrepareTokens(clearTokens, cryptoTokens);
	}
#endif
}

void GkH235Authenticators::Finalise(unsigned q931Tag, PBYTEArray & rawPdu)
{
#ifdef H323_H235
	PWaitAndSignal lock(m_mutex);

	if (m_authProcedure1 && m_authProcedure1->IsActive()
			&& m_authProcedure1->IsSecuredPDU(q931Tag, FALSE)) {
		m_authProcedure1->Finalise(rawPdu);
    }
#endif // H323_H235
}

void GkH235Authenticators::SetCATData(const PString & generalID, const PString & password)
{
	PWaitAndSignal lock(m_mutex);

	if (m_authCAT == NULL)
		m_authCAT = new H235AuthCAT();
	m_authCAT->Enable();
	m_localIdCAT = generalID;
	m_authCAT->SetPassword(password);
}

void GkH235Authenticators::SetSimpleMD5Data(const PString & generalID, const PString & password)
{
	PWaitAndSignal lock(m_mutex);

	if (m_authMD5 == NULL)
		m_authMD5 = new H235AuthSimpleMD5();
	m_authMD5->Enable();
	m_localIdMD5 = generalID;
	m_authMD5->SetPassword(password);
}

#ifdef HAS_DES_ECB
void GkH235Authenticators::SetDESData(const PString & generalID, const PString & password)
{
	PWaitAndSignal lock(m_mutex);

	if (m_authDES == NULL)
		m_authDES = new H235AuthDesECB();
	m_authDES->Enable();
	m_localIdDES = generalID;
	m_authDES->SetPassword(password);
}
#endif

void GkH235Authenticators::SetProcedure1Data(const PString & sendersID, const PString & remoteID, const PString & password, PBoolean requireGeneralID)
{
#ifdef H323_H235
	PWaitAndSignal lock(m_mutex);

	if (m_authProcedure1 == NULL)
		m_authProcedure1 = new H235AuthProcedure1();
	m_authProcedure1->Enable();
	m_localIdProcedure1 = sendersID;
	m_remoteIdProcedure1 = remoteID;
	m_authProcedure1->SetPassword(password);
#ifdef HAS_H2351_CONFIG
	m_authProcedure1->RequireGeneralID(requireGeneralID);
	m_authProcedure1->CheckSendersID(GkConfig()->GetBoolean("H235", "CheckSendersID", true));
	m_authProcedure1->FullQ931Checking(GkConfig()->GetBoolean("H235", "FullQ931Checking", false));
	m_authProcedure1->VerifyRandomNumber(GkConfig()->GetBoolean("H235", "VerifyRandomNumber", true));
#endif // HAS_H2351_CONFIG
#endif // H323_H235
}

void GkH235Authenticators::SetProcedure1LocalId(const PString & localID)
{
#ifdef H323_H235
	PWaitAndSignal lock(m_mutex);

	m_localIdProcedure1 = localID;
#endif // H323_H235
}

void GkH235Authenticators::SetProcedure1RemoteId(const PString & remoteID)
{
#ifdef H323_H235
	PWaitAndSignal lock(m_mutex);

	m_remoteIdProcedure1 = remoteID;
#endif // H323_H235
}

bool GkH235Authenticators::HasProcedure1Password()
{
#ifdef H323_H235
	PWaitAndSignal lock(m_mutex);
	return m_authProcedure1 != NULL && m_authProcedure1->IsActive() && !m_authProcedure1->GetPassword();
#else
    return false;
#endif // H323_H235
}

bool GkH235Authenticators::HasMD5Password()
{
	PWaitAndSignal lock(m_mutex);
	return m_authMD5 != NULL && m_authMD5->IsActive() && !m_authMD5->GetPassword();
}

#ifdef HAS_DES_ECB
bool GkH235Authenticators::HasDESPassword()
{
	PWaitAndSignal lock(m_mutex);
	return m_authDES != NULL && m_authDES->IsActive() && !m_authDES->GetPassword();
}
#endif

bool GkH235Authenticators::HasCATPassword()
{
	PWaitAndSignal lock(m_mutex);
	return m_authCAT != NULL && m_authCAT->IsActive() && !m_authCAT->GetPassword();
}

// get pointers to the tokens in the different Q.931 messages
void GkH235Authenticators::GetQ931Tokens(Q931::MsgTypes type, H225_H323_UserInformation * uuie, H225_ArrayOf_ClearToken ** tokens, H225_ArrayOf_CryptoH323Token ** cryptoTokens)
{
    if (!uuie || (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() == H225_H323_UU_PDU_h323_message_body::e_empty)) {
        return;
    }

    switch (type) {
        case Q931::AlertingMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_alerting) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (Alerting)");
                    return;
                }
                H225_Alerting_UUIE & alerting = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &alerting.m_tokens;
                *cryptoTokens = &alerting.m_cryptoTokens;
            }
            break;
        case Q931::CallProceedingMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_callProceeding) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (CallProceeding)");
                    return;
                }
                H225_CallProceeding_UUIE & proceeding = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &proceeding.m_tokens;
                *cryptoTokens = &proceeding.m_cryptoTokens;
            }
            break;
        case Q931::ConnectMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_connect) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (Connect)");
                    return;
                }
                H225_Connect_UUIE & connect = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &connect.m_tokens;
                *cryptoTokens = &connect.m_cryptoTokens;
            }
            break;
        case Q931::ProgressMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_progress) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (Progress)");
                    return;
                }
                H225_Progress_UUIE & progress = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &progress.m_tokens;
                *cryptoTokens = &progress.m_cryptoTokens;
            }
            break;
        case Q931::SetupMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_setup) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (Setup)");
                    return;
                }
                H225_Setup_UUIE & setup = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &setup.m_tokens;
                *cryptoTokens = &setup.m_cryptoTokens;
            }
            break;
        case Q931::SetupAckMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_setupAcknowledge) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (SetupAck)");
                    return;
                }
                H225_SetupAcknowledge_UUIE & setupAck = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &setupAck.m_tokens;
                *cryptoTokens = &setupAck.m_cryptoTokens;
            }
            break;
        case Q931::ReleaseCompleteMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_releaseComplete) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (ReleaseComplete)");
                    return;
                }
                H225_ReleaseComplete_UUIE & rc = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &rc.m_tokens;
                *cryptoTokens = &rc.m_cryptoTokens;
            }
            break;
        case Q931::InformationMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_information) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (Information)");
                    return;
                }
                H225_Information_UUIE & info = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &info.m_tokens;
                *cryptoTokens = &info.m_cryptoTokens;
            }
            break;
        case Q931::NotifyMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_notify) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (Notify)");
                    return;
                }
                H225_Notify_UUIE & notify = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &notify.m_tokens;
                *cryptoTokens = &notify.m_cryptoTokens;
            }
            break;
        case Q931::StatusMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_status) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (Status)");
                    return;
                }
                H225_Status_UUIE & status = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &status.m_tokens;
                *cryptoTokens = &status.m_cryptoTokens;
            }
            break;
        case Q931::StatusEnquiryMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_statusInquiry) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (StatusInquiry)");
                    return;
                }
                H225_StatusInquiry_UUIE & statusInquiry = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &statusInquiry.m_tokens;
                *cryptoTokens = &statusInquiry.m_cryptoTokens;
            }
            break;
        case Q931::FacilityMsg: {
                if (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_facility) {
                    PTRACE(1, "Error: UUIE (" << uuie->m_h323_uu_pdu.m_h323_message_body.GetTagName() << ") doesn't match Q.931 message (Facility)");
                    return;
                }
                H225_Facility_UUIE & facility = uuie->m_h323_uu_pdu.m_h323_message_body;
                *tokens = &facility.m_tokens;
                *cryptoTokens = &facility.m_cryptoTokens;
            }
            break;
        default:
            return;
            break;
    }
}

