/*
 * radauth.cxx
 *
 * RADIUS protocol authenticator module for GNU Gatekeeper. 
 * Please see docs/radauth.txt for more details.
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.17  2004/06/17 10:47:13  zvision
 * New h323-ivr-out=h323-call-id accounting attribute
 *
 * Revision 1.16  2004/06/17 10:03:17  zvision
 * Better Framed-IP-Address handling in RadAliasAuth Setup check
 *
 * Revision 1.15  2004/06/16 23:46:47  zvision
 * RadAliasAuth will work even when Setup-UUIE does not contain sourceAddress
 *
 * Revision 1.14  2004/05/22 12:25:17  zvision
 * Check aliases only when authenticating RRQ message
 *
 * Revision 1.13  2004/04/17 11:43:43  zvision
 * Auth/acct API changes.
 * Header file usage more consistent.
 *
 * Revision 1.12  2004/03/17 00:00:38  zvision
 * Conditional compilation to allow to control RADIUS on Windows just by setting HA_RADIUS macro
 *
 * Revision 1.11  2004/02/20 14:44:11  zvision
 * Changed API for GkAuthenticator class. Modified RadAuth/RadAliasAuth classes.
 * Added Q.931 Setup authentication for RadAuth module.
 *
 * Revision 1.10  2003/11/14 00:27:30  zvision
 * Q.931/H.225 Setup authentication added
 *
 * Revision 1.9  2003/10/31 00:01:28  zvision
 * Improved accounting modules stacking control, optimized radacct/radauth a bit
 *
 * Revision 1.8  2003/10/21 15:55:27  zvision
 * Fixed compiler warnings for gcc < 3
 *
 * Revision 1.7  2003/10/15 10:16:57  zvision
 * Fixed VC6 compiler warnings. Thanks to Hu Yuxin.
 *
 * Revision 1.6  2003/10/08 12:40:48  zvision
 * Realtime accounting updates added
 *
 * Revision 1.5  2003/09/28 16:24:31  zvision
 * Introduced call duration limit feature for registered endpoints (ARQ)
 *
 * Revision 1.4  2003/08/25 12:53:38  zvision
 * Introduced includeTerminalAliases config option. Changed visibility
 * of some member variables to private.
 *
 * Revision 1.3  2003/08/20 14:46:19  zvision
 * Avoid PString reference copying. Small code improvements.
 *
 * Revision 1.2  2003/08/19 10:47:37  zvision
 * Initially added to 2.2 brach. Completely redesigned.
 * Redundant code removed. Added h323-return-code, h323-credit-time
 * and Session-Timeout respone attributes processing.
 *
 * Revision 1.1.2.17  2003/07/31 22:59:24  zvision
 * Fixed IP address retrieval for unregistered endpoints
 *
 * Revision 1.1.2.16  2003/07/31 13:09:15  zvision
 * Added Q.931 Setup message authentication and call duration limit feature
 *
 * Revision 1.1.2.15  2003/07/17 14:40:39  zvision
 * Conditional compilation of features available only when HAS_ACCT is defined.
 *
 * Revision 1.1.2.14  2003/07/16 22:13:21  zvision
 * Fixed Radius attributes for answer call ARQs.
 *
 * Revision 1.1.2.13  2003/07/07 14:28:30  zvision
 * Added missing NAS-Identifier attribute in RadAliasAuth. Thanks Julius Stavaris.
 *
 * Revision 1.1.2.12  2003/07/07 12:02:55  zvision
 * Improved H.235 handling.
 *
 * Revision 1.1.2.11  2003/06/19 15:33:29  zvision
 * Removed static modifier from GetConferenceIDString function.
 *
 * Revision 1.1.2.10  2003/06/11 13:06:57  zvision
 * Added gk_const.h include directive (OPENH323_NEWVERSION macro definition)
 *
 * Revision 1.1.2.9  2003/06/11 12:14:35  zvision
 * Cosmetic changes
 *
 * Revision 1.1.2.8  2003/06/05 10:03:04  zvision
 * Small fix to h323-gw-id attribute.
 *
 * Revision 1.1.2.7  2003/05/29 17:21:22  zvision
 * Fixed compilation errors with OpenH323 versions prior to 1.11.5 (no H235AuthCAT)
 *
 * Revision 1.1.2.6  2003/05/28 13:25:19  zvision
 * Added alias based authentication (RadAliasAuth)
 *
 * Revision 1.1.2.5  2003/05/27 00:13:05  zvision
 * Smart Calling and Called -Station-Id selection (dialedDigits and partyNumber alias types preferred)
 *
 * Revision 1.1.2.4  2003/05/26 23:09:59  zvision
 * Added new OnSend and OnReceive hooks. LocalInterface config parameter introduced.
 *
 * Revision 1.1.2.3  2003/05/13 17:49:49  zvision
 * Removed acctPort. New includeFramedIP feature. Better tracing. Bug-fixes
 *
 * Revision 1.1.2.2  2003/04/29 14:56:27  zvision
 * Added H.235 capability matching
 *
 * Revision 1.1.2.1  2003/04/23 20:15:37  zvision
 * Initial revision
 *
 */
 
#if HAS_RADIUS

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug sumbol off
#endif

#include <vector>
#include <ptlib.h>
#include <h225ras.h>
#include <h323pdu.h>
#include <h235.h>
#include <h235auth.h>
#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "Toolkit.h"
#include "RasTbl.h"
#include "RasPDU.h"
#include "radproto.h"
#include "gkauth.h"
#include "radauth.h"

namespace {
// Settings for H.235 based module will be stored inside [RadAuth] config section
const char* const RadAuthConfigSectionName = "RadAuth";
// Settings for alias based module will be stored inside [RadAliasAuth] config section
const char* const RadAliasAuthConfigSectionName = "RadAliasAuth";
}

// OID for CAT (Cisco Access Token) algorithm
PString RadAuth::OID_CAT("1.2.840.113548.10.1.2.1");


RadAuthBase::RadAuthBase( 
	const char* authName,
	const char* configSectionName,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks
	)
	:
	GkAuthenticator(authName, supportedRasChecks, supportedMiscChecks),
	m_radiusClient(NULL)
{
	// read settings from the config
	m_appendCiscoAttributes = Toolkit::AsBool(GetConfig()->GetString(
		configSectionName,"AppendCiscoAttributes", "1"
		));
	m_includeTerminalAliases = Toolkit::AsBool(GetConfig()->GetString(
		configSectionName, "IncludeTerminalAliases", "1"
		));
	m_nasIdentifier = Toolkit::Instance()->GKName();
	/// build RADIUS client
	m_radiusClient = new RadiusClient(*GetConfig(), configSectionName);
	m_nasIpAddress = m_radiusClient->GetLocalAddress();
	if (m_nasIpAddress == INADDR_ANY) {
		std::vector<PIPSocket::Address> interfaces;
		Toolkit::Instance()->GetGKHome(interfaces);
		if (!interfaces.empty())
			m_nasIpAddress = interfaces.front();
		else
			PTRACE(1, "RADAUTH\t" << GetName() << " cannot determine "
				" NAS IP address"
				);
	}
}

RadAuthBase::~RadAuthBase()
{
	delete m_radiusClient;
}

int RadAuthBase::Check(
	/// RRQ RAS message to be authenticated
	RasPDU<H225_RegistrationRequest>& rrqPdu, 
	/// authorization data (reject reason, ...)
	RRQAuthData& authData
	)
{
	H225_RegistrationRequest& rrq = (H225_RegistrationRequest&)rrqPdu;
	
	// build RADIUS Access-Request
	RadiusPDU* pdu = m_radiusClient->BuildPDU();
	if (pdu == NULL) {
		PTRACE(2, "RADAUTH\t" << GetName() << " RRQ auth failed: "
			"could not to create Access-Request PDU"
			);
		authData.m_rejectReason = H225_RegistrationRejectReason::e_undefinedReason;
		return GetDefaultStatus();
	}

	pdu->SetCode(RadiusPDU::AccessRequest);

	// Append User-Name and a password related attributes
	// (User-Password or Chap-Password and Chap-Timestamp)
	const int status = AppendUsernameAndPassword(*pdu, rrqPdu, authData);
	if (status != e_ok) {
		delete pdu;
		return status;
	}
		
	// Gk works as NAS point, so append NAS IP
	*pdu += new RadiusAttr(RadiusAttr::NasIpAddress, m_nasIpAddress);
	// NAS-Identifier as Gk name
	*pdu += new RadiusAttr(RadiusAttr::NasIdentifier, m_nasIdentifier);
	// Gk does not have a concept of physical ports,
	// so define port type as NAS-Port-Virtual
	*pdu += new RadiusAttr(RadiusAttr::NasPortType, 
		RadiusAttr::NasPort_Virtual 
		);
	// RRQ service type is Login-User
	*pdu += new RadiusAttr(RadiusAttr::ServiceType, RadiusAttr::ST_Login);

	// append Framed-IP-Address					
	PIPSocket::Address addr;
	bool ipFound = false;
	if (rrq.m_callSignalAddress.GetSize() > 0) {
		if (GetIPFromTransportAddr(rrq.m_callSignalAddress[0], addr)
			&& addr.IsValid())
			ipFound = true;
	} else if (rrq.m_rasAddress.GetSize() > 0) {
		if (GetIPFromTransportAddr(rrq.m_rasAddress[0], addr) 
			&& addr.IsValid())
			ipFound = true;
	}
	if (!ipFound) {
		PTRACE(2, "RADAUTH\t" << GetName() << " RRQ auth failed: "
			"could not determine Framed-IP-Address"
			);
		authData.m_rejectReason = H225_RegistrationRejectReason::e_invalidCallSignalAddress;
		delete pdu;
		return e_fail;
	} else
		*pdu += new RadiusAttr(RadiusAttr::FramedIpAddress, addr);
				
	if (m_appendCiscoAttributes && m_includeTerminalAliases
			&& rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
		PString aliasList("terminal-alias:");
		for (PINDEX i = 0; i < rrq.m_terminalAlias.GetSize(); i++) {
			if(i > 0)
				aliasList += ",";
			aliasList += H323GetAliasAddressString(rrq.m_terminalAlias[i]);
		}
		// Cisco-AV-Pair
		*pdu += new RadiusAttr( 
			PString("h323-ivr-out=") + aliasList + ";", 9, 1 
			);
	}
	
	if (!OnSendPDU(*pdu, rrqPdu, authData)) {
		delete pdu;
		return e_fail;
	}
	// send request and wait for response
	RadiusPDU* response = NULL;
	bool result = m_radiusClient->MakeRequest(*pdu, response) && response;
		
	delete pdu;
			
	if (!result) {
		PTRACE(2, "RADAUTH\t" << GetName() << " RRQ auth failed: "
			" could not receive or decode response from RADIUS"
			);
		delete response;
		authData.m_rejectReason = H225_RegistrationRejectReason::e_undefinedReason;
		return GetDefaultStatus();
	}
				
	result = (response->GetCode() == RadiusPDU::AccessAccept);
	if (result)
		result = OnReceivedPDU(*response, rrqPdu, authData);
	else
		authData.m_rejectReason = H225_RegistrationRejectReason::e_securityDenial;
				
	delete response;
	return result ? e_ok : e_fail;
}
		
namespace {
bool GetAVPair(
	RadiusPDU& pdu,
	int vendorId,
	unsigned char vendorType,
	PString& value,
	const char* name
	)
{
	const PINDEX index = pdu.FindVsaAttr(vendorId, vendorType);
	if (index == P_MAX_INDEX)
		return false;
		
	const RadiusAttr* attr = pdu.GetAttrAt(index);
	if (attr == NULL || !attr->IsValid())
		return false;

	value = attr->AsVsaString();
	PINDEX i;
	if (name && (i = value.Find(name)) == 0)
		value = value.Mid(strlen(name) + 1);

	return true;
}
}
 
int RadAuthBase::Check(
	/// ARQ nessage to be authenticated
	RasPDU<H225_AdmissionRequest> & arqPdu, 
	/// authorization data (call duration limit, reject reason, ...)
	GkAuthenticator::ARQAuthData& authData
	)
{
	H225_AdmissionRequest& arq = (H225_AdmissionRequest&)arqPdu;

	// build RADIUS Access-Request packet
	RadiusPDU* pdu = m_radiusClient->BuildPDU();
	if (pdu == NULL) {
		PTRACE(2, "RADAUTH\t" << GetName() << " ARQ auth failed: "
			"could not to create Access-Request PDU"
			);
		authData.m_rejectReason = H225_AdmissionRejectReason::e_undefinedReason;
		return GetDefaultStatus();
	}

	pdu->SetCode(RadiusPDU::AccessRequest);

	PIPSocket::Address addr;
	endptr callingEP, calledEP;
	
	// try to extract calling/called endpoints from RegistrationTable
	// (unregistered endpoints will not be present there)
	if (arq.m_answerCall) {
		calledEP = authData.m_requestingEP;
		if (authData.m_call)
			callingEP = authData.m_call->GetCallingParty();
	} else {
		callingEP = authData.m_requestingEP;
		if (authData.m_call)
			calledEP = authData.m_call->GetCalledParty();
		if (!calledEP && arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress))
			calledEP = RegistrationTable::Instance()->FindBySignalAdr(arq.m_destCallSignalAddress);
	}
	
	// at least requesting endpoint (the one that is sending ARQ)
	// has to be present in the RegistrationTable
	if (arq.m_answerCall ? !calledEP : !callingEP) {
		delete pdu;
		PTRACE(3, "RADAUTH\t" << GetName() << " ARQ auth failed: "
			"requesting endpoint " << arq.m_endpointIdentifier 
			<< " not registered"
			);
		authData.m_rejectReason = arq.m_answerCall
			? H225_AdmissionRejectReason::e_calledPartyNotRegistered
			: H225_AdmissionRejectReason::e_callerNotRegistered;
		return e_fail;
	}

	// Append User-Name and a password related attributes
	// (User-Password or Chap-Password and Chap-Timestamp)
	PString username;				
	const int status = AppendUsernameAndPassword(*pdu, arqPdu, authData, &username);
	if (status != e_ok) {
		delete pdu;
		return status;
	}
	
	// Gk acts as NAS, so include NAS IP
	*pdu += new RadiusAttr(RadiusAttr::NasIpAddress, m_nasIpAddress);
	// NAS-Identifier as Gk name
	*pdu += new RadiusAttr(RadiusAttr::NasIdentifier, m_nasIdentifier);
	// NAS-Port-Type as Virtual, since Gk does
	// not care about physical ports concept
	*pdu += new RadiusAttr(RadiusAttr::NasPortType, 
		RadiusAttr::NasPort_Virtual 
		);
	// Service-Type is Login-User if originating the call
	// and Call Check if answering the call
	*pdu += new RadiusAttr(RadiusAttr::ServiceType,
		arq.m_answerCall ? RadiusAttr::ST_CallCheck : RadiusAttr::ST_Login
		);
				
	// append Frame-IP-Address					
	bool ipFound = false;
	if (arq.m_answerCall) {
		if (calledEP 
			&& GetIPFromTransportAddr(calledEP->GetCallSignalAddress(), addr)
			&& addr.IsValid())
			ipFound = true;
		else if (arq.HasOptionalField(arq.e_destCallSignalAddress) 
			&& GetIPFromTransportAddr(arq.m_destCallSignalAddress, addr)
			&& addr.IsValid())
			ipFound = true;
	} else {
		if (callingEP 
			&& GetIPFromTransportAddr(callingEP->GetCallSignalAddress(), addr)
			&& addr.IsValid())
			ipFound = true;
		else if(arq.HasOptionalField(arq.e_srcCallSignalAddress)
			&& GetIPFromTransportAddr(arq.m_srcCallSignalAddress, addr) 
			&& addr.IsValid())
			*pdu += new RadiusAttr(RadiusAttr::FramedIpAddress, addr);
	}
	if (!ipFound) {
		PTRACE(2, "RADAUTH\t" << GetName() << " ARQ auth failed: "
			"could not setup Framed-IP-Address"
			);
		authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		delete pdu;
		return e_fail;
	} else
		*pdu += new RadiusAttr(RadiusAttr::FramedIpAddress, addr);
					
	// fill Calling-Station-Id and Called-Station-Id fields
	PString stationId = GetCallingStationId(arqPdu, authData);
	if (!stationId) {
		*pdu += new RadiusAttr(RadiusAttr::CallingStationId, stationId);
		if (authData.m_callingStationId.IsEmpty())
			authData.m_callingStationId = stationId;
	}
						
	stationId = GetCalledStationId(arqPdu, authData);
	if (stationId.IsEmpty()) {
		delete pdu;
		PTRACE(2, "RADAUTH\t" << GetName() << " ARQ auth failed: "
			"no suitable alias for Calling-Station-Id has been found"
			);
		authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		return e_fail;
	} else {
		*pdu += new RadiusAttr(RadiusAttr::CalledStationId, stationId);
		if (authData.m_calledStationId.IsEmpty())
			authData.m_calledStationId = stationId;
	}
	
	if (m_appendCiscoAttributes) {
		*pdu += new RadiusAttr(
			PString("h323-conf-id=") + GetGUIDString(arq.m_conferenceID),
			9, 24
			);
		*pdu += new RadiusAttr(
			PString(arq.m_answerCall 
				? "h323-call-origin=answer" : "h323-call-origin=originate"),
				9, 26
				);
		*pdu += new RadiusAttr( PString("h323-call-type=VoIP"),	9, 27 );
		*pdu += new RadiusAttr( 
			PString("h323-gw-id=") + m_nasIdentifier, 9, 33 
			);
	}
				
	if (!OnSendPDU(*pdu, arqPdu, authData)) {
		delete pdu;
		return e_fail;
	}
	// send the request and wait for a response
	RadiusPDU* response = NULL;
	bool result = m_radiusClient->MakeRequest(*pdu, response) && response;
			
	delete pdu;
			
	if (!result) {
		PTRACE(2, "RADAUTH\t" << GetName() << " ARQ auth failed: "
			" could not receive or decode response from RADIUS"
			);
		delete response;
		authData.m_rejectReason = H225_AdmissionRejectReason::e_undefinedReason;
		return GetDefaultStatus();
	}
				
	// authenticated?
	result = (response->GetCode() == RadiusPDU::AccessAccept);
	
	PString value;
	// test for h323-return-code attribute (has to be 0 if accept)
	if (result && GetAVPair(*response, 9, 103, value, "h323-return-code"))
		if (value.GetLength() > 0
			&& strspn((const char*)value, "0123456789") == (size_t)value.GetLength()) {
			const unsigned retcode = value.AsUnsigned();
			if (retcode != 0) {
				PTRACE(3, "RADAUTH\t" << GetName() << " ARQ check failed: "
					"return code " << retcode
					);
				result = false;
			}
		} else {
			PTRACE(2, "RADAUTH\t" << GetName() << " ARQ check failed: "
				"invalid h323-return-code attribute '" << value << '\''
				);
			result = false;
		}

	// check for h323-credit-time attribute (call duration limit)	
	if (result && GetAVPair(*response, 9, 102, value, "h323-credit-time"))
		if( value.GetLength() > 0 
			&& strspn((const char*)value,"0123456789") == (size_t)value.GetLength()) {
			authData.m_callDurationLimit = value.AsInteger();
			PTRACE(5, "RADAUTH\t" << GetName() << " ARQ check set duration "
				"limit: " << authData.m_callDurationLimit
				);
			if (authData.m_callDurationLimit == 0)						
				result = false;
		} else {
			PTRACE(2, "RADAUTH\t" << GetName() << " ARQ check failed: "
				"invalid h323-credit-time attribute '" << value << '\''
				);
			result = false;
		}

	// check for Session-Timeout attribute (alternate call duration limit)	
	if (result) {
		const PINDEX index = response->FindAttr(RadiusAttr::SessionTimeout);
		if (index != P_MAX_INDEX) {
			RadiusAttr* attr = response->GetAttrAt(index);
			if (attr && attr->IsValid()) {
				const long sessionTimeout = attr->AsInteger();
				if (authData.m_callDurationLimit < 0 
					|| authData.m_callDurationLimit > sessionTimeout) {
					authData.m_callDurationLimit = sessionTimeout;
					PTRACE(5, "RADAUTH\t" << GetName() << " ARQ check set "
						"duration limit set " << authData.m_callDurationLimit
						);
				}
				if (authData.m_callDurationLimit == 0)
					result = false;
			} else {
				PTRACE(2, "RADAUTH\t" << GetName() << " ARQ check failed: "
					"invalid Session-Timeout attribute"
					);
				result = false;
			}
		}
	}
			
	if (result)
		result = OnReceivedPDU(*response, arqPdu, authData);
	else
		authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
					
	delete response;
	return result ? e_ok : e_fail;
}

int RadAuthBase::Check(
	Q931& q931pdu,
	H225_Setup_UUIE& setup,
	GkAuthenticator::SetupAuthData& authData
	)
{
	// build RADIUS Access-Request packet
	RadiusPDU* pdu = m_radiusClient->BuildPDU();
	if (pdu == NULL) {
		PTRACE(2, "RADAUTH\t" << GetName() << " Setup auth failed: "
			"could not to create Access-Request PDU"
			);
		authData.m_rejectCause = Q931::TemporaryFailure;
		return GetDefaultStatus();
	}

	pdu->SetCode(RadiusPDU::AccessRequest);

	PIPSocket::Address addr;
	endptr callingEP, calledEP;
	
	if (authData.m_call)
		callingEP = authData.m_call->GetCallingParty();
	if (!callingEP && setup.HasOptionalField(H225_Setup_UUIE::e_endpointIdentifier))
		callingEP = RegistrationTable::Instance()->FindByEndpointId(
			setup.m_endpointIdentifier
			);
		
	// Append User-Name and a password related attributes
	// (User-Password or Chap-Password and Chap-Timestamp)
	PString username;				
	const int status = AppendUsernameAndPassword(*pdu, q931pdu, setup, 
		callingEP, authData, &username
		);
	if (status != e_ok) {
		delete pdu;
		return status;
	}
	
	// Gk acts as NAS, so include NAS IP
	*pdu += new RadiusAttr(RadiusAttr::NasIpAddress, m_nasIpAddress);
	// NAS-Identifier as Gk name
	*pdu += new RadiusAttr(RadiusAttr::NasIdentifier, m_nasIdentifier);
	// NAS-Port-Type as Virtual, since Gk does
	// not care about physical ports concept
	*pdu += new RadiusAttr(RadiusAttr::NasPortType, 
		RadiusAttr::NasPort_Virtual 
		);
	// Service-Type is Login-User if originating the call
	// and Call Check if answering the call
	*pdu += new RadiusAttr(RadiusAttr::ServiceType, RadiusAttr::ST_Login );
				
	// append Frame-IP-Address					
	bool ipFound = false;
	WORD dummyPort;
		
	if (authData.m_call && authData.m_call->GetSrcSignalAddr(addr, dummyPort) 
		&& addr.IsValid())
		ipFound = true;	
	else if (callingEP 
		&& GetIPFromTransportAddr(callingEP->GetCallSignalAddress(), addr)
		&& addr.IsValid())
		ipFound = true;
	else if (setup.HasOptionalField(setup.e_sourceCallSignalAddress)
		&& GetIPFromTransportAddr(setup.m_sourceCallSignalAddress, addr)
		&& addr.IsValid())
		ipFound = true;
			
	if (!ipFound) {
		PTRACE(2, "RADAUTH\t" << GetName() << " Setup auth failed: "
			"could not setup Framed-IP-Address"
			);
		delete pdu;
		authData.m_rejectCause = Q931::CallRejected;
		return e_fail;
	} else
		*pdu += new RadiusAttr(RadiusAttr::FramedIpAddress, addr);
				
	// fill Calling-Station-Id and Called-Station-Id fields
	PString stationId = GetCallingStationId(q931pdu, setup, authData);
	if (!stationId) {
		*pdu += new RadiusAttr(RadiusAttr::CallingStationId, stationId);
		if (authData.m_callingStationId.IsEmpty())
			authData.m_callingStationId = stationId;
	}
						
	stationId = GetCalledStationId(q931pdu, setup, authData);
	if (stationId.IsEmpty()) {
		delete pdu;
		PTRACE(2, "RADAUTH\t" << GetName() << " Setup check failed: "
			"no called station id found"
			);
		authData.m_rejectReason = H225_ReleaseCompleteReason::e_badFormatAddress;
		return e_fail;
	} else {
		*pdu += new RadiusAttr(RadiusAttr::CalledStationId, stationId);
		if (authData.m_calledStationId.IsEmpty())
			authData.m_calledStationId = stationId;
	}
			
	if (m_appendCiscoAttributes) {
		*pdu += new RadiusAttr(
			PString("h323-conf-id=") + GetGUIDString(setup.m_conferenceID),
			9, 24
			);
		*pdu += new RadiusAttr(
			PString("h323-call-origin=originate"),
			9, 26
			);
		*pdu += new RadiusAttr(PString("h323-call-type=VoIP"),	9, 27);
		*pdu += new RadiusAttr(
			PString("h323-gw-id=") + m_nasIdentifier, 9, 33 
			);
	}
				
	if (!OnSendPDU(*pdu, q931pdu, setup, authData)) {
		delete pdu;
		return e_fail;
	}
	// send the request and wait for a response
	RadiusPDU* response = NULL;
	bool result = m_radiusClient->MakeRequest(*pdu, response) && response;
			
	delete pdu;
			
	if (!result) {
		PTRACE(2, "RADAUTH\t" << GetName() << " Setup auth failed: "
			" could not receive or decode response from RADIUS"
			);
		delete response;
		authData.m_rejectCause = Q931::TemporaryFailure;
		return GetDefaultStatus();
	}
				
	// authenticated?
	result = (response->GetCode() == RadiusPDU::AccessAccept);
	
	PString value;
	// test for h323-return-code attribute (has to be 0 if accept)
	if (result && GetAVPair(*response, 9, 103, value, "h323-return-code"))
		if (value.GetLength() > 0 
			&& strspn((const char*)value, "0123456789") == (size_t)value.GetLength()) {
			const unsigned retcode = value.AsUnsigned();
			if (retcode != 0) {
				PTRACE(5, "RADAUTH\t" << GetName() << " Setup check failed: "
					"return code " << retcode
					);
				result = false;
			}
		} else {
			PTRACE(2, "RADAUTH\t" << GetName() << " Setup check failed: "
				"invalid h323-return-code attribute '" << value << '\''
				);
			result = false;
		}

	// check for h323-credit-time attribute (call duration limit)	
	if (result && GetAVPair(*response, 9, 102, value, "h323-credit-time"))
		if (value.GetLength() > 0 
			&& strspn((const char*)value,"0123456789") == (size_t)value.GetLength() ) {
			authData.m_callDurationLimit = value.AsInteger();
			PTRACE(5, "RADAUTH\t" << GetName() << " Setup check set duration "
				"limit: " << authData.m_callDurationLimit
				);
			if (authData.m_callDurationLimit == 0)
				result = false;
		} else {
			PTRACE(2, "RADAUTH\t" << GetName() << " Setup check failed: "
				"invalid h323-credit-time attribute '" << value << '\''
				);
			result = false;
		}

	// check for Session-Timeout attribute (alternate call duration limit)	
	if (result) {
		const PINDEX index = response->FindAttr( RadiusAttr::SessionTimeout );
		if (index != P_MAX_INDEX) {
			RadiusAttr* attr = response->GetAttrAt(index);
			if (attr && attr->IsValid()) {
				const long sessionTimeout = attr->AsInteger();
				if (authData.m_callDurationLimit < 0 
					|| authData.m_callDurationLimit > sessionTimeout) {
					authData.m_callDurationLimit = sessionTimeout;
					PTRACE(5, "RADAUTH\t" << GetName() << " Setup check "
						"set duration limit: " << authData.m_callDurationLimit
						);
				}
				if (authData.m_callDurationLimit == 0)
					result = false;
			} else {
				PTRACE(2, "RADAUTH\t" << GetName() << " Setup check failed: "
					"invalid Session-Timeout attribute"
					);
				result = false;
			}
		}
	}
			
	if (result)
		result = OnReceivedPDU(*response, q931pdu, setup, authData);
	else
		authData.m_rejectCause = Q931::CallRejected;
					
	delete response;
	return result ? e_ok : e_fail;
}		

bool RadAuthBase::OnSendPDU(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_RegistrationRequest>& /*rrqPdu*/,
	GkAuthenticator::RRQAuthData& /*authData*/
	)
{
	return true;
}

bool RadAuthBase::OnSendPDU(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_AdmissionRequest>& /*arqPdu*/,
	GkAuthenticator::ARQAuthData& /*authData*/
	)
{
	return true;
}

bool RadAuthBase::OnSendPDU(
	RadiusPDU& /*pdu*/,
	Q931& /*q931pdu*/,
	H225_Setup_UUIE& /*setup*/,
	GkAuthenticator::SetupAuthData& /*authData*/
	)
{
	return true;
}

bool RadAuthBase::OnReceivedPDU(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_RegistrationRequest>& /*rrqPdu*/,
	GkAuthenticator::RRQAuthData& /*authData*/
	)
{
	return true;
}

bool RadAuthBase::OnReceivedPDU(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_AdmissionRequest>& /*arqPdu*/,
	GkAuthenticator::ARQAuthData& /*authData*/
	)
{
	return true;
}

bool RadAuthBase::OnReceivedPDU(
	RadiusPDU& /*pdu*/,
	Q931& /*q931pdu*/,
	H225_Setup_UUIE& /*setup*/,
	GkAuthenticator::SetupAuthData& /*authData*/
	)
{
	return true;
}

int RadAuthBase::AppendUsernameAndPassword(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_RegistrationRequest>& /*rrqPdu*/,
	GkAuthenticator::RRQAuthData& /*authData*/,
	PString* /*username*/
	) const
{
	return GetDefaultStatus();
}

int RadAuthBase::AppendUsernameAndPassword(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_AdmissionRequest>& /*arqPdu*/,
	GkAuthenticator::ARQAuthData& /*authData*/,
	PString* /*username*/
	) const
{
	return GetDefaultStatus();
}

int RadAuthBase::AppendUsernameAndPassword(
	RadiusPDU& /*pdu*/,
	Q931& /*q931pdu*/,
	H225_Setup_UUIE& /*setup*/,
	endptr& /*callingEP*/,
	GkAuthenticator::SetupAuthData& /*authData*/,
	PString* /*username*/
	) const
{
	return GetDefaultStatus();
}

RadAuth::RadAuth(
	const char* authName
	)
	: 
	RadAuthBase(authName, RadAuthConfigSectionName)
{
	// setup H.235 algorithm and method types used
	// by this authenticator - this will make sure
	// GCF H.235 alogirthm selection will not skip
	// information required by this authenticator
	H235AuthCAT* authenticator = new H235AuthCAT;
	authenticator->SetLocalId("dummy");
	authenticator->SetRemoteId("dummy");
	authenticator->SetPassword("dummy");
	AppendH235Authenticator(authenticator);
}

RadAuth::~RadAuth() 
{
}

int RadAuth::CheckTokens(
	RadiusPDU& pdu,
	const H225_ArrayOf_ClearToken& tokens,
	const H225_ArrayOf_AliasAddress* aliases,
	PString* username
	) const
{
	// scan ClearTokens and find CATs
	for (PINDEX i = 0; i < tokens.GetSize(); i++) {
		const H235_ClearToken& token = tokens[i];
			
		// is this CAT?
		if (token.m_tokenOID != OID_CAT)
			continue;

		// these field are required for CAT
	  	if (!(token.HasOptionalField(H235_ClearToken::e_generalID)
			&& token.HasOptionalField(H235_ClearToken::e_random)
			&& token.HasOptionalField(H235_ClearToken::e_timeStamp)
			&& token.HasOptionalField(H235_ClearToken::e_challenge))) 
		{	
			PTRACE(3, "RADAUTH\t" << GetName() << " auth failed: "
				"CAT without all required fields"
				);
			return e_fail;
		}
				
		// generalID should be present in the list of terminal aliases
		const PString id = token.m_generalID;
		if (aliases && FindAlias(*aliases, id) == P_MAX_INDEX) {
			PTRACE(3, "RADAUTH\t" << GetName() << " auth failed: "
				"CAT m_generalID is not a valid alias"
				);
			return e_fail;
		}
					
		// CAT pseudo-random has to be one byte only
		const int randomInt = token.m_random;
		if (randomInt < -127 || randomInt > 255) {
			PTRACE(3, "RADAUTH\t" << GetName() << " auth failed: "
				"CAT m_random out of range"
				);
			return e_fail;
		}
					
		// CAT challenge has to be 16 bytes
		if (token.m_challenge.GetValue().GetSize() < 16) {
			PTRACE(3, "RADAUTH\t" << GetName() << " auth failed: "
				"m_challenge less than 16 bytes"
				);
			return e_fail;
		}
					
		// append User-Name
		pdu += new RadiusAttr(RadiusAttr::UserName, id);
		if (username != NULL)
			*username = (const char*)id;
				
		// build CHAP-Password
		char password[17] = { (BYTE)randomInt };
		memcpy(password + 1, (const BYTE*)(token.m_challenge), 16);
				
		pdu += new RadiusAttr(RadiusAttr::ChapPassword,
			password, sizeof(password)
			);
		pdu += new RadiusAttr(RadiusAttr::ChapChallenge,
			(int)(DWORD)token.m_timeStamp
			);
				
		return e_ok;
	}
	PTRACE(3, "RADAUTH\t" << GetName() << " auth failed: no CAT token found");
	return GetDefaultStatus();
}

int RadAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	RasPDU<H225_RegistrationRequest>& rrqPdu,
	GkAuthenticator::RRQAuthData& authData,
	PString* username
	) const
{
	H225_RegistrationRequest& rrq = (H225_RegistrationRequest&)rrqPdu;
	
	// RRQ has to carry at least one terminalAlias
	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
		PTRACE(3, "RADAUTH\t" << GetName() << " RRQ auth failed: "
			"no m_terminalAlias field"
			);
		authData.m_rejectReason = H225_RegistrationRejectReason::e_securityDenial;
		return GetDefaultStatus();
	}
		
	// check for ClearTokens (CAT uses ClearTokens)
	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_tokens)) {
		PTRACE(3, "RADAUTH\t" << GetName() << " RRQ auth failed: "
			"tokens not found"
			);
		authData.m_rejectReason = H225_RegistrationRejectReason::e_securityDenial;
		return GetDefaultStatus();
	}

	const int result = CheckTokens(pdu, rrq.m_tokens, &rrq.m_terminalAlias, username);
	if (result != e_ok)	
		authData.m_rejectReason = H225_RegistrationRejectReason::e_securityDenial;
	return result;
}

int RadAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	RasPDU<H225_AdmissionRequest>& arqPdu,
	GkAuthenticator::ARQAuthData& authData,
	PString* username
	) const
{
	H225_AdmissionRequest& arq = (H225_AdmissionRequest&)arqPdu;
	
	// check for ClearTokens
	if (!arq.HasOptionalField(H225_AdmissionRequest::e_tokens)) {
		PTRACE(3, "RADAUTH\t" << GetName() << " ARQ auth failed: "
			"tokens not found"
			);
		authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		return GetDefaultStatus();
	}

	const int result = CheckTokens(pdu, arq.m_tokens, NULL, username);
	if (result != e_ok)	
		authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
	return result;
}

int RadAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	Q931& /*q931pdu*/,
	H225_Setup_UUIE& setup,
	endptr& /*callingEP*/,
	GkAuthenticator::SetupAuthData& authData,
	PString* username
	) const
{
	// check for ClearTokens (CAT uses ClearTokens)
	if (!setup.HasOptionalField(H225_Setup_UUIE::e_tokens)) {
		PTRACE(3, "RADAUTH\t" << GetName() << " Setup auth failed: no tokens");
		authData.m_rejectReason = H225_ReleaseCompleteReason::e_securityDenied;
		return GetDefaultStatus();
	}

	const int result = CheckTokens(pdu, setup.m_tokens, NULL, username);
	if (result != e_ok)	
		authData.m_rejectCause = Q931::CallRejected;
	return result;
}

RadAliasAuth::RadAliasAuth( 
	const char* authName 
	)
	:
	RadAuthBase(authName, RadAliasAuthConfigSectionName)
{
	m_fixedUsername = GetConfig()->GetString(
		RadAliasAuthConfigSectionName, "FixedUsername", ""
		);
	m_fixedPassword = GetConfig()->GetString(
		RadAliasAuthConfigSectionName, "FixedPassword", ""
		);
}

RadAliasAuth::~RadAliasAuth()
{
}

int RadAliasAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	RasPDU<H225_RegistrationRequest>& rrqPdu, 
	GkAuthenticator::RRQAuthData& authData,
	PString* username
	) const
{
	const PString id = GetUsername(rrqPdu);
	if (id.IsEmpty() && m_fixedUsername.IsEmpty()) {
		PTRACE(3, "RADAUTH\t" << GetName() << " RRQ check failed: "
			"neither FixedUsername nor alias inside RRQ were found"
			);
		authData.m_rejectReason = H225_RegistrationRejectReason::e_securityDenial;
		return GetDefaultStatus();
	}
	
	// append User-Name
   	pdu += new RadiusAttr(RadiusAttr::UserName, 
		m_fixedUsername.IsEmpty() ? id : m_fixedUsername
		);
	
	if (username != NULL)
		*username = (const char*)id;
		
	// append User-Password
	if (!m_fixedPassword)
		pdu += new RadiusAttr(RadiusAttr::UserPassword, m_fixedPassword);
	else 
		pdu += new RadiusAttr(RadiusAttr::UserPassword, 
			m_fixedUsername.IsEmpty() ? id : m_fixedUsername
			);
		
	return e_ok;			
}

int RadAliasAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	RasPDU<H225_AdmissionRequest>& arqPdu,
	GkAuthenticator::ARQAuthData& authData,
	PString* username
	) const
{
	const PString id = GetUsername(arqPdu, authData);
	if (id.IsEmpty() && m_fixedUsername.IsEmpty()) {
		PTRACE(3, "RADAUTH\t" << GetName() << " ARQ check failed: "
			"neither FixedUsername nor alias inside ARQ were found"
			);
		authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		return GetDefaultStatus();
	}
	
	// append User-Name
   	pdu += new RadiusAttr(RadiusAttr::UserName, 
		m_fixedUsername.IsEmpty() ? id : m_fixedUsername
		);

	if (username != NULL)
		*username = (const char*)id;
				
	if (!m_fixedPassword)
		pdu += new RadiusAttr(RadiusAttr::UserPassword, m_fixedPassword);
	else
		pdu += new RadiusAttr(RadiusAttr::UserPassword, 
			m_fixedUsername.IsEmpty() ? id : m_fixedUsername
			);
			
	return e_ok;
}

int RadAliasAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	Q931& q931pdu, 
	H225_Setup_UUIE& setup,
	endptr& /*callingEP*/,
	GkAuthenticator::SetupAuthData& authData,
	PString* username
	) const
{
	const PString id = GetUsername(q931pdu, setup, authData);
	if (id.IsEmpty() && m_fixedUsername.IsEmpty()) {
		PTRACE(3, "RADAUTH\t" << GetName() << " Setup check failed: "
			"neither FixedUsername nor alias inside Setup were found"
			);
		authData.m_rejectReason = H225_ReleaseCompleteReason::e_badFormatAddress;
		return GetDefaultStatus();
	}
	
	// append User-Name
   	pdu += new RadiusAttr(RadiusAttr::UserName, 
		m_fixedUsername.IsEmpty() ? id : m_fixedUsername
		);

	if (username != NULL)
		*username = (const char*)id;
				
	if (!m_fixedPassword)
		pdu += new RadiusAttr(RadiusAttr::UserPassword, m_fixedPassword);
	else
		pdu += new RadiusAttr(RadiusAttr::UserPassword, 
			m_fixedUsername.IsEmpty() ? id : m_fixedUsername
			);
			
	return e_ok;
}
	
namespace {
	GkAuthCreator<RadAuth> RadAuthCreator("RadAuth");
	GkAuthCreator<RadAliasAuth> RadAliasAuthCreator("RadAliasAuth");
}

#endif /* HAS_RADIUS */
