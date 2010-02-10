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
 * We also explicitly grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.50  2009/10/25 22:13:09  willamowius
 * allow to set proxy mode through 'proxy' variable in Radius h323-ivr-in attribute (thanks to Yuriy Georgiewskiy)
 *
 * Revision 1.49  2009/05/24 20:48:26  willamowius
 * remove hacks for VC6 which isn't supported any more since quite a while
 *
 * Revision 1.48  2009/05/19 14:38:07  willamowius
 * codec filtering
 *
 * Revision 1.47  2009/02/09 13:25:59  willamowius
 * typo in comment
 *
 * Revision 1.46  2008/09/15 08:42:09  zvision
 * Allow outbound number rewrite by SQL/RADIUS modules
 *
 * Revision 1.45  2008/08/13 13:10:52  zvision
 * h323-redirect-ip crash when no h323-redirect-number fixed
 *
 * Revision 1.44  2008/04/18 14:37:28  willamowius
 * never include gnugkbuildopts.h directly, always include config.h
 *
 * Revision 1.43  2008/04/18 13:14:11  shorne
 * Fixes for auto-configure on windows
 *
 * Revision 1.42  2008/01/30 19:00:31  willamowius
 * fix bug introduced when renaming variables
 *
 * Revision 1.41  2007/11/25 23:23:40  willamowius
 * cleanup: rename variables that shadow others with the same name
 *
 * Revision 1.40  2007/11/04 03:26:21  shorne
 * Fix problem with FramedIP with NATed endpoints.
 *
 * Revision 1.39  2007/09/11 01:02:29  willamowius
 * clean up includes
 *
 * Revision 1.38  2007/07/10 19:33:27  willamowius
 * allow Radius server to send multiple destinations in "h323-redirect-number" attribute for call failover (patch by Lucas Martinez)
 *
 * Revision 1.37  2006/12/06 16:34:04  zvision
 * Handle RADIUS Class attribute correctly
 *
 * Revision 1.36  2006/07/06 15:25:13  willamowius
 * set all deleted pointers to NULL (most probably more than needed)
 *
 * Revision 1.35  2006/06/08 08:58:48  willamowius
 * gcc 4.1 compile fixes
 *
 * Revision 1.34  2006/04/14 13:56:19  willamowius
 * call failover code merged
 *
 * Revision 1.2  2005/12/05 13:29:02  zvision
 * Accept multiple routes from RADIUS/SQL auth modules
 *
 * Revision 1.1.1.1  2005/11/21 20:19:58  willamowius
 *
 *
 * Revision 1.4  2005/11/15 19:52:56  jan
 * Michal v1 (works, but on in routed, not proxy mode)
 *
 * Revision 1.33  2005/04/24 16:39:44  zvision
 * MSVC6.0 compatibility fixed
 *
 * Revision 1.32  2005/02/10 23:26:39  zvision
 * Accounting updates/call disconnect handling does not lock the whole call table
 *
 * Revision 1.31  2005/02/01 14:28:10  zvision
 * Parts of signaling code rewritten
 *
 * Revision 1.30  2005/01/28 11:19:42  zvision
 * All passwords in the config can be stored in an encrypted form
 *
 * Revision 1.29  2005/01/26 23:50:26  zvision
 * Framed-IP-Address could not be determined to unregistered calls without
 * Setup-UUIE.sourceCallSignalAddress field
 *
 * Revision 1.28  2005/01/25 18:59:08  zvision
 * Aliases handling fixed, alias type is not appended anymore
 *
 * Revision 1.27  2005/01/25 00:37:35  zvision
 * Handle aliases of type partyNumber properly
 *
 * Revision 1.26  2005/01/10 22:49:29  willamowius
 * typo
 *
 * Revision 1.25  2004/12/08 13:02:56  zvision
 * Better Calling/Called-Station-Id handling
 *
 * Revision 1.24  2004/11/15 23:57:42  zvision
 * Ability to choose between the original and the rewritten dialed number
 *
 * Revision 1.23  2004/11/03 10:40:17  zvision
 * Add/remove RRQ aliases using h323-ivr-in=terminal-alias Cisco AV-Pair attr
 *
 * Revision 1.22  2004/08/09 21:52:23  zvision
 * RADIUS based call routing
 *
 * Revision 1.21  2004/07/26 12:19:41  zvision
 * New faster Radius implementation, thanks to Pavel Pavlov for ideas!
 *
 * Revision 1.20.2.2  2004/07/07 23:11:07  zvision
 * Faster and more elegant handling of Cisco VSA
 *
 * Revision 1.20.2.1  2004/07/07 20:50:14  zvision
 * New, faster, Radius client implementation. Thanks to Pavel Pavlov for ideas!
 *
 * Revision 1.20  2004/07/06 23:46:20  zvision
 * gcc 2.95.x compilation errors fixed
 *
 * Revision 1.19  2004/07/05 16:39:45  zvision
 * Support for CallCreditServiceControl
 *
 * Revision 1.18  2004/06/25 13:33:19  zvision
 * Better Username, Calling-Station-Id and Called-Station-Id handling.
 * New SetupUnreg option in Gatekeeper::Auth section.
 *
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

#include "config.h"

#if HAS_RADIUS

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
#include "Routing.h"
#include "sigmsg.h"
#include "radproto.h"
#include "radauth.h"

using std::vector;
using Routing::Route;

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
	m_radiusClient(NULL),
	m_attrH323CallType(RadiusAttr::CiscoVSA_h323_call_type, false, 
		PString("VoIP")),
	m_attrH323CallOriginOriginate(RadiusAttr::CiscoVSA_h323_call_origin, false,
		PString("originate")),
	m_attrH323CallOriginAnswer(RadiusAttr::CiscoVSA_h323_call_origin, false,
		PString("answer"))
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
		vector<PIPSocket::Address> interfaces;
		Toolkit::Instance()->GetGKHome(interfaces);
		if (!interfaces.empty())
			m_nasIpAddress = interfaces.front();
		else
			PTRACE(1, "RADAUTH\t" << GetName() << " cannot determine "
				" NAS IP address"
				);
	}
	m_useDialedNumber = Toolkit::AsBool(GetConfig()->GetString(
		configSectionName, "UseDialedNumber", "0"
		));
	m_attrH323GwId = RadiusAttr(RadiusAttr::CiscoVSA_h323_gw_id, false, m_nasIdentifier);
	m_attrNasIdentifier = RadiusAttr(RadiusAttr::NasIdentifier, m_nasIdentifier);
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
	RadiusPDU* const pdu = new RadiusPDU(RadiusPDU::AccessRequest);

	// Append User-Name and a password related attributes
	// (User-Password or Chap-Password and Chap-Timestamp)
	const int status = AppendUsernameAndPassword(*pdu, rrqPdu, authData);
	if (status != e_ok) {
		delete pdu;
		return status;
	}
	
	// Gk works as NAS point, so append NAS IP
	pdu->AppendAttr(RadiusAttr::NasIpAddress, m_nasIpAddress);
	// NAS-Identifier as Gk name
	pdu->AppendAttr(m_attrNasIdentifier);
	// Gk does not have a concept of physical ports,
	// so define port type as NAS-Port-Virtual
	pdu->AppendAttr(RadiusAttr::NasPortType, RadiusAttr::NasPort_Virtual);
	// RRQ service type is Login-User
	pdu->AppendAttr(RadiusAttr::ServiceType, RadiusAttr::ST_Login);

	// append Framed-IP-Address					
	PIPSocket::Address addr;
	const PIPSocket::Address & rx_addr = rrqPdu->m_peerAddr;
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
		pdu->AppendAttr(RadiusAttr::FramedIpAddress, (rx_addr != addr)? rx_addr : addr);
				
	if (m_appendCiscoAttributes && m_includeTerminalAliases
			&& rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
		PString aliasList("terminal-alias:");
		for (PINDEX i = 0; i < rrq.m_terminalAlias.GetSize(); i++) {
			if(i > 0)
				aliasList += ",";
			aliasList += AsString(rrq.m_terminalAlias[i], FALSE);
		}
		// Cisco-AV-Pair
		pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
			PString("h323-ivr-out=") + aliasList + ";",
			true
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
		response = NULL;
		authData.m_rejectReason = H225_RegistrationRejectReason::e_undefinedReason;
		return GetDefaultStatus();
	}
				
	result = (response->GetCode() == RadiusPDU::AccessAccept);

	PString value;
	const RadiusAttr* attr;
	
	// test for h323-return-code attribute (has to be 0 if accept)
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_return_code
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();	
			if (value.GetLength() > 0
				&& strspn((const char*)value, "0123456789") == (size_t)value.GetLength()) {
				const unsigned retcode = value.AsUnsigned();
				if (retcode != 0) {
					PTRACE(3, "RADAUTH\t" << GetName() << " RRQ check failed: "
						"return code " << retcode
						);
					result = false;
				}
			} else {
				PTRACE(2, "RADAUTH\t" << GetName() << " RRQ check failed: "
					"invalid h323-return-code attribute '" << value << '\''
					);
				result = false;
			}
		}
	}
	
	// check for h323-billing-model	
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_billing_model
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();	
			if (value.GetLength() > 0 
					&& strspn((const char*)value,"0123456789") == (size_t)value.GetLength()) {
				const int intVal = value.AsInteger();
				if (intVal == 0)
					authData.m_billingMode = H225_CallCreditServiceControl_billingMode::e_credit;
				else if (intVal == 1 || intVal == 2)
					authData.m_billingMode = H225_CallCreditServiceControl_billingMode::e_debit;
			} else {
				PTRACE(3, "RADAUTH\t" << GetName() << " invalid h323-billing-model "
					"attribute '" << value << '\''
					);
			}
		}
	}
	
	// check for h323-credit-amount
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_credit_amount
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();	
			if (value.GetLength() > 0 
					&& strspn((const char*)value,"0123456789.") == (size_t)value.GetLength()) {
				if (value.Find('.') == P_MAX_INDEX) {
					PTRACE(3, "RADAUTH\t" << GetName() << " h323-credit-amount "
						"without a decimal dot is ambiguous '" << value << '\''
						);
					authData.m_amountString = psprintf(PString("%d.%d"), 
						value.AsInteger() / 100, value.AsInteger() % 100
						);
				} else
					authData.m_amountString = value;
				
				attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
			 		RadiusAttr::CiscoVSA_h323_currency
					);
				if (attr != NULL)
					authData.m_amountString += attr->AsCiscoString(); 
			} else {
				PTRACE(3, "RADAUTH\t" << GetName() << " invalid h323-credit-amount "
					"attribute '" << value << '\''
					);
			}
		}
	}

	// process h323-ivr-in=terminal-alias attribute
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
			RadiusAttr::CiscoVSA_AV_Pair
			);
		while (attr != NULL) {
			PINDEX index;
			value = attr->AsCiscoString();
			if (value.Find("h323-ivr-in=") == 0 
				&& ((index = value.Find("terminal-alias:")) != P_MAX_INDEX)) {
				index += strlen("terminal-alias:");
				const PINDEX semicolonpos = value.Find(';', index);
				value = value.Mid(index, semicolonpos == P_MAX_INDEX
					? P_MAX_INDEX : (semicolonpos-index)
					);
				PStringArray aliases = value.Tokenise(",");
				if (aliases.GetSize() > 0 
					&& rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
					PINDEX i = 0;
					while (i < rrq.m_terminalAlias.GetSize()) {
						PINDEX j = aliases.GetStringsIndex(AsString(rrq.m_terminalAlias[i], FALSE));
						if( j == P_MAX_INDEX )
							rrq.m_terminalAlias.RemoveAt(i);
						else {
							i++;
							aliases.RemoveAt(j);
						}
					}
				}
				for (PINDEX i = 0; i < aliases.GetSize(); i++) {
					if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
						rrq.m_terminalAlias.SetSize(rrq.m_terminalAlias.GetSize()+1);
					else {
						rrq.IncludeOptionalField(H225_RegistrationRequest::e_terminalAlias);
						rrq.m_terminalAlias.SetSize(1);
					}
					H323SetAliasAddress(aliases[i], rrq.m_terminalAlias[rrq.m_terminalAlias.GetSize()-1]);
				}
				break;
			}
			attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
				RadiusAttr::CiscoVSA_AV_Pair, attr
				);
		}
	}

	if (result)
		result = OnReceivedPDU(*response, rrqPdu, authData);
	else
		authData.m_rejectReason = H225_RegistrationRejectReason::e_securityDenial;
				
	delete response;
	response = NULL;
	return result ? e_ok : e_fail;
}
 
int RadAuthBase::Check(
	/// ARQ nessage to be authenticated
	RasPDU<H225_AdmissionRequest> & arqPdu, 
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData& authData
	)
{
	H225_AdmissionRequest& arq = (H225_AdmissionRequest&)arqPdu;

	// build RADIUS Access-Request packet
	RadiusPDU* const pdu = new RadiusPDU(RadiusPDU::AccessRequest);
	const bool hasCall = authData.m_call.operator->() != NULL;
	PIPSocket::Address addr;
	endptr callingEP, calledEP;
	
	// try to extract calling/called endpoints from RegistrationTable
	// (unregistered endpoints will not be present there)
	if (arq.m_answerCall) {
		calledEP = authData.m_requestingEP;
		if (hasCall)
			callingEP = authData.m_call->GetCallingParty();
	} else {
		callingEP = authData.m_requestingEP;
		if (hasCall)
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
	pdu->AppendAttr(RadiusAttr::NasIpAddress, m_nasIpAddress);
	// NAS-Identifier as Gk name
	pdu->AppendAttr(m_attrNasIdentifier);
	// NAS-Port-Type as Virtual, since Gk does
	// not care about physical ports concept
	pdu->AppendAttr(RadiusAttr::NasPortType, RadiusAttr::NasPort_Virtual);
	// Service-Type is Login-User if originating the call
	// and Call Check if answering the call
	pdu->AppendAttr(RadiusAttr::ServiceType,
		arq.m_answerCall ? RadiusAttr::ST_CallCheck : RadiusAttr::ST_Login
		);
				
	// append Frame-IP-Address	
    const PIPSocket::Address & rx_addr = arqPdu->m_peerAddr;
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
			ipFound = true;
	}
	if (!ipFound) {
		PTRACE(2, "RADAUTH\t" << GetName() << " ARQ auth failed: "
			"could not setup Framed-IP-Address"
			);
		authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		delete pdu;
		return e_fail;
	} else
		pdu->AppendAttr(RadiusAttr::FramedIpAddress, (rx_addr != addr)? rx_addr : addr);
					
	// fill Calling-Station-Id and Called-Station-Id fields
	PString stationId = GetCallingStationId(arqPdu, authData);
	if (!stationId) {
		pdu->AppendAttr(RadiusAttr::CallingStationId, stationId);
	}

	const PString dialedNumber = GetDialedNumber(arqPdu, authData);
	const PString calledStationId = GetCalledStationId(arqPdu, authData);
	
	stationId = m_useDialedNumber ? dialedNumber : calledStationId;
	if (stationId.IsEmpty()) {
		delete pdu;
		PTRACE(2, "RADAUTH\t" << GetName() << " ARQ auth failed: "
			"no suitable alias for Calling-Station-Id has been found"
			);
		authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		return e_fail;
	} else
		pdu->AppendAttr(RadiusAttr::CalledStationId, stationId);
	
	
	if (m_appendCiscoAttributes) {
		pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_conf_id,
			GetGUIDString(arq.m_conferenceID)
			);
		if (arq.m_answerCall)
			pdu->AppendAttr(m_attrH323CallOriginAnswer);
		else
			pdu->AppendAttr(m_attrH323CallOriginOriginate);
		pdu->AppendAttr(m_attrH323CallType);
		pdu->AppendAttr(m_attrH323GwId);
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
		response = NULL;
		authData.m_rejectReason = H225_AdmissionRejectReason::e_undefinedReason;
		return GetDefaultStatus();
	}
				
	// authenticated?
	result = (response->GetCode() == RadiusPDU::AccessAccept);
	
	PString value;
	const RadiusAttr* attr;
	
	// check for Class attribute
	if (result) {
		attr = response->FindAttr(RadiusAttr::AttrTypeClass);
		if (attr != NULL) {
			PBYTEArray classData;
			if (attr->GetValue(classData))
				authData.m_radiusClass = classData;
		}
	}
	
	// test for h323-return-code attribute (has to be 0 if accept)
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_return_code
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();	
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
		}
	}
	// process h323-ivr-in=codec-disable attribute 
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, RadiusAttr::CiscoVSA_AV_Pair);
		while (attr != NULL) {
			PINDEX index;
			value = attr->AsCiscoString();
			if (value.Find("h323-ivr-in=") == 0 && ((index = value.Find("codec-disable:")) != P_MAX_INDEX)) {
				index += strlen("codec-disable:");
				const PINDEX semicolonpos = value.FindLast(';', index);
				value = value.Mid(index, semicolonpos == P_MAX_INDEX ? P_MAX_INDEX : (semicolonpos-index));
				PTRACE(4, "RADAUTH\t" << GetName() << " Setup check set codec-disable: " << value); 
				authData.m_disabledcodecs = value;
				break;
			}
			attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
			RadiusAttr::CiscoVSA_AV_Pair, attr);
		}
	}
	// check for h323-credit-time attribute (call duration limit)	
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_credit_time
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();	
			if (value.GetLength() > 0 
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
		}
	}
	// check for Session-Timeout attribute (alternate call duration limit)	
	if (result) {
		const RadiusAttr* const tattr = response->FindAttr(RadiusAttr::SessionTimeout);
		if (tattr != NULL) {
			const long sessionTimeout = tattr->AsInteger();
			if (authData.m_callDurationLimit < 0 
				|| authData.m_callDurationLimit > sessionTimeout) {
				authData.m_callDurationLimit = sessionTimeout;
				PTRACE(5, "RADAUTH\t" << GetName() << " ARQ check set "
					"duration limit set " << authData.m_callDurationLimit
					);
			}
			if (authData.m_callDurationLimit == 0)
				result = false;
		}
	}

	// check for h323-billing-model	
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_billing_model
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();	
			if (value.GetLength() > 0 
					&& strspn((const char*)value,"0123456789") == (size_t)value.GetLength()) {
				const int intVal = value.AsInteger();
				if (intVal == 0)
					authData.m_billingMode = H225_CallCreditServiceControl_billingMode::e_credit;
				else if (intVal == 1 || intVal == 2)
					authData.m_billingMode = H225_CallCreditServiceControl_billingMode::e_debit;
			} else {
				PTRACE(3, "RADAUTH\t" << GetName() << " invalid h323-billing-model "
					"attribute '" << value << '\''
					);
			}
		}
	}
	// check for h323-credit-amount
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_credit_amount
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();	
			if (value.GetLength() > 0 
					&& strspn((const char*)value,"0123456789.") == (size_t)value.GetLength()) {
				if (value.Find('.') == P_MAX_INDEX) {
					PTRACE(3, "RADAUTH\t" << GetName() << " h323-credit-amount "
						"without a decimal dot is ambiguous '" << value << '\''
						);
					authData.m_amountString = psprintf(PString("%d.%d"), 
						value.AsInteger() / 100, value.AsInteger() % 100
						);
				} else
					authData.m_amountString = value;
				
				attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
			 		RadiusAttr::CiscoVSA_h323_currency
					);
				if (attr != NULL)
					authData.m_amountString += attr->AsCiscoString(); 
			} else {
				PTRACE(3, "RADAUTH\t" << GetName() << " invalid h323-credit-amount "
					"attribute '" << value << '\''
					);
			}
		}
	}
	PStringArray numbersToDial;
	// check for h323-redirect-number
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_redirect_number
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();
			if (!value) {
				numbersToDial = value.Tokenise("; \t", FALSE);
				if (numbersToDial.GetSize() > 0) {
					authData.SetRouteToAlias(numbersToDial[0]);
					PTRACE(5, "RADAUTH\t" << GetName() << " ARQ check redirect "
						"to the number " << value
						);
				} else {
					PTRACE(1, "RADAUTH\t" << GetName()
						<< " invalid ARQ check redirect numbers list: " << value
						);
				}
			}
		}
	}

	// check for h323-redirect-ip-address
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_redirect_ip_address
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();
			if (!value) {
				PStringArray tokens(value.Tokenise("; \t", FALSE));
				for (PINDEX i = 0; i < tokens.GetSize(); ++i) {
					PIPSocket::Address raddr;
					WORD rport = 0;
					
					if (GetTransportAddress(tokens[i], GK_DEF_ENDPOINT_SIGNAL_PORT, raddr, rport)
							&& raddr.IsValid() && rport != 0) {
						Route route("RADIUS", raddr, rport);
						route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(
							SocketToH225TransportAddr(raddr, rport)
							);
						if (numbersToDial.GetSize() > 0) {
							route.m_destNumber = (i < numbersToDial.GetSize()) ? numbersToDial[i] : numbersToDial[numbersToDial.GetSize() - 1];
							PINDEX pos = route.m_destNumber.Find('=');
							if (pos != P_MAX_INDEX) {
								route.m_destOutNumber = route.m_destNumber.Mid(pos + 1);
								route.m_destNumber = route.m_destNumber.Left(pos);
							}
						}
						authData.m_destinationRoutes.push_back(route);
						PTRACE(5, "RADAUTH\t" << GetName() << " ARQ check redirect "
							"to the address " << route.AsString()
							);
					}
				}
			}
		}
	}

	// process h323-ivr-in=proxy attribute
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
			RadiusAttr::CiscoVSA_AV_Pair
			);
		while (attr != NULL) {
			PINDEX index;
			value = attr->AsCiscoString();
			if (value.Find("h323-ivr-in=") == 0 
				&& ((index = value.Find("proxy:")) != P_MAX_INDEX)) {
				index += strlen("proxy:");
				const PINDEX semicolonpos = value.Find(';', index);
				value = value.Mid(index, semicolonpos == P_MAX_INDEX
					? P_MAX_INDEX : (semicolonpos-index)
					);
				if (!value) {
					authData.m_proxyMode = Toolkit::AsBool(value)
						? CallRec::ProxyEnabled : CallRec::ProxyDisabled;
					PTRACE(5, "RADAUTH\t" << GetName() << " - proxy mode "
						<< (authData.m_proxyMode == CallRec::ProxyEnabled ? "enabled" : "disabled")
					);
				}
			}
			attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
				RadiusAttr::CiscoVSA_AV_Pair, attr
				);
		}
	}

	if (result)
		result = OnReceivedPDU(*response, arqPdu, authData);
	else
		authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
					
	delete response;
	response = NULL;
	return result ? e_ok : e_fail;
}

int RadAuthBase::Check(
	SetupMsg &setup,
	SetupAuthData &authData
	)
{
	// build RADIUS Access-Request packet
	RadiusPDU* const pdu = new RadiusPDU(RadiusPDU::AccessRequest);
	H225_Setup_UUIE& setupBody = setup.GetUUIEBody();
	const bool hasCall = authData.m_call.operator->() != NULL;
	PIPSocket::Address addr;
	endptr callingEP;
	
	if (hasCall)
		callingEP = authData.m_call->GetCallingParty();
	if (!callingEP && setupBody.HasOptionalField(H225_Setup_UUIE::e_endpointIdentifier))
		callingEP = RegistrationTable::Instance()->FindByEndpointId(
			setupBody.m_endpointIdentifier
			);
		
	// Append User-Name and a password related attributes
	// (User-Password or Chap-Password and Chap-Timestamp)
	PString username;				
	const int status = AppendUsernameAndPassword(*pdu, setup, callingEP, 
		authData, &username
		);
	if (status != e_ok) {
		delete pdu;
		return status;
	}
	
	// Gk acts as NAS, so include NAS IP
	pdu->AppendAttr(RadiusAttr::NasIpAddress, m_nasIpAddress);
	// NAS-Identifier as Gk name
	pdu->AppendAttr(m_attrNasIdentifier);
	// NAS-Port-Type as Virtual, since Gk does
	// not care about physical ports concept
	pdu->AppendAttr(RadiusAttr::NasPortType, RadiusAttr::NasPort_Virtual);
	// Service-Type is Login-User if originating the call
	// and Call Check if answering the call
	pdu->AppendAttr(RadiusAttr::ServiceType, RadiusAttr::ST_Login);
				
	// append Frame-IP-Address
	bool ipFound = false;
	WORD dummyPort;
		
	if (hasCall && authData.m_call->GetSrcSignalAddr(addr, dummyPort) 
		&& addr.IsValid())
		ipFound = true;	
	else if (callingEP 
		&& GetIPFromTransportAddr(callingEP->GetCallSignalAddress(), addr)
		&& addr.IsValid())
		ipFound = true;
	else if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress)
		&& GetIPFromTransportAddr(setupBody.m_sourceCallSignalAddress, addr)
		&& addr.IsValid())
		ipFound = true;
	else {
		setup.GetPeerAddr(addr);
		ipFound = addr.IsValid();
	}
	if (!ipFound) {
		PTRACE(2, "RADAUTH\t" << GetName() << " Setup auth failed: "
			"could not setup Framed-IP-Address"
			);
		delete pdu;
		authData.m_rejectCause = Q931::CallRejected;
		return e_fail;
	} else
		pdu->AppendAttr(RadiusAttr::FramedIpAddress, addr);
				
	// fill Calling-Station-Id and Called-Station-Id fields
	PString stationId = GetCallingStationId(setup, authData);
	if (!stationId) {
		pdu->AppendAttr(RadiusAttr::CallingStationId, stationId);
	}

	const PString calledStationId = GetCalledStationId(setup, authData);
	const PString dialedNumber = GetDialedNumber(setup, authData);

	stationId = m_useDialedNumber ? dialedNumber : calledStationId;
	if (stationId.IsEmpty()) {
		delete pdu;
		PTRACE(2, "RADAUTH\t" << GetName() << " Setup check failed: "
			"no called station id found"
			);
		authData.m_rejectReason = H225_ReleaseCompleteReason::e_badFormatAddress;
		return e_fail;
	} else
		pdu->AppendAttr(RadiusAttr::CalledStationId, stationId);
			
	if (m_appendCiscoAttributes) {
		pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_conf_id,
			GetGUIDString(setupBody.m_conferenceID)
			);
		pdu->AppendAttr(m_attrH323CallOriginOriginate);
		pdu->AppendAttr(m_attrH323CallType);
		pdu->AppendAttr(m_attrH323GwId);
	}
				
	if (!OnSendPDU(*pdu, setup, authData)) {
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
		response = NULL;
		authData.m_rejectCause = Q931::TemporaryFailure;
		return GetDefaultStatus();
	}
				
	// authenticated?
	result = (response->GetCode() == RadiusPDU::AccessAccept);
	
	PString value;
	const RadiusAttr* attr;
	
	// check for Class attribute
	if (result) {
		attr = response->FindAttr(RadiusAttr::AttrTypeClass);
		if (attr != NULL) {
			PBYTEArray classData;
			if (attr->GetValue(classData))
				authData.m_radiusClass = classData;
		}
	}

	// test for h323-return-code attribute (has to be 0 if accept)
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_return_code
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();	
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
		}
	}
	// process h323-ivr-in=codec-disable attribute
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, RadiusAttr::CiscoVSA_AV_Pair);
		while (attr != NULL) {
			PINDEX index;
			value = attr->AsCiscoString();
			if (value.Find("h323-ivr-in=") == 0 && ((index = value.Find("codec-disable:")) != P_MAX_INDEX)) {
				index += strlen("codec-disable:");
				const PINDEX semicolonpos = value.FindLast(';', index);
				value = value.Mid(index, semicolonpos == P_MAX_INDEX ? P_MAX_INDEX : (semicolonpos-index));
				PTRACE(4, "RADAUTH\t" << GetName() << " Setup check set codec-disable: " << value); 
				authData.m_disabledcodecs = value;
				break;
			}
			attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
			RadiusAttr::CiscoVSA_AV_Pair, attr);
		}
	}
	// check for h323-credit-time attribute (call duration limit)	
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_credit_time
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();	
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
		}
	}
	// check for Session-Timeout attribute (alternate call duration limit)	
	if (result) {
		const RadiusAttr* const tattr = response->FindAttr(RadiusAttr::SessionTimeout);
		if (tattr != NULL) {
			const long sessionTimeout = tattr->AsInteger();
			if (authData.m_callDurationLimit < 0 
				|| authData.m_callDurationLimit > sessionTimeout) {
				authData.m_callDurationLimit = sessionTimeout;
				PTRACE(5, "RADAUTH\t" << GetName() << " Setup check "
					"set duration limit: " << authData.m_callDurationLimit
					);
			}
			if (authData.m_callDurationLimit == 0)
				result = false;
		}
	}

	PStringArray numbersToDial;
	// check for h323-redirect-number
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_redirect_number
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();
			if (!value) {
				numbersToDial = value.Tokenise("; \t", FALSE);
				if (numbersToDial.GetSize() > 0) {
					authData.SetRouteToAlias(numbersToDial[0]);
					PTRACE(5, "RADAUTH\t" << GetName() << " ARQ check redirect "
						"to the number " << value
						);
				} else {
					PTRACE(1, "RADAUTH\t" << GetName()
						<< " invalid ARQ check redirect numbers list: " << value
						);
				}
			}
		}
	}

	// check for h323-redirect-ip-address
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
	 		RadiusAttr::CiscoVSA_h323_redirect_ip_address
			);
		if (attr != NULL) {
			value = attr->AsCiscoString();
			if (!value) {
				PStringArray tokens(value.Tokenise("; \t", FALSE));
				for (PINDEX i = 0; i < tokens.GetSize(); ++i) {
					PIPSocket::Address raddr;
					WORD rport = 0;
					
					if (GetTransportAddress(tokens[i], GK_DEF_ENDPOINT_SIGNAL_PORT, raddr, rport)
							&& raddr.IsValid() && rport != 0) {
						Route route("RADIUS", raddr, rport);
						route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(
							SocketToH225TransportAddr(raddr, rport)
							);
						if (numbersToDial.GetSize() > 0) {
							route.m_destNumber = (i < numbersToDial.GetSize()) ? numbersToDial[i] : numbersToDial[numbersToDial.GetSize() - 1];
							PINDEX pos = route.m_destNumber.Find('=');
							if (pos != P_MAX_INDEX) {
								route.m_destOutNumber = route.m_destNumber.Mid(pos + 1);
								route.m_destNumber = route.m_destNumber.Left(pos);
							}
						}
						authData.m_destinationRoutes.push_back(route);
						PTRACE(5, "RADAUTH\t" << GetName() << " Setup check redirect "
							"to the address " << route.AsString()
							);
					}
				}
			}
		}
	}

	// process h323-ivr-in=proxy attribute
	if (result) {
		attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
			RadiusAttr::CiscoVSA_AV_Pair
			);
		while (attr != NULL) {
			PINDEX index;
			value = attr->AsCiscoString();
			if (value.Find("h323-ivr-in=") == 0 
				&& ((index = value.Find("proxy:")) != P_MAX_INDEX)) {
				index += strlen("proxy:");
				const PINDEX semicolonpos = value.Find(';', index);
				value = value.Mid(index, semicolonpos == P_MAX_INDEX
					? P_MAX_INDEX : (semicolonpos-index)
					);
				if (!value) {
					authData.m_proxyMode = Toolkit::AsBool(value)
						? CallRec::ProxyEnabled : CallRec::ProxyDisabled;
					PTRACE(5, "RADAUTH\t" << GetName() << " - proxy mode "
						<< (authData.m_proxyMode == CallRec::ProxyEnabled ? "enabled" : "disabled")
						);
				}
			}
			attr = response->FindVsaAttr(RadiusAttr::CiscoVendorId, 
				RadiusAttr::CiscoVSA_AV_Pair, attr
				);
		}
	}

	if (result)
		result = OnReceivedPDU(*response, setup, authData);
	else
		authData.m_rejectCause = Q931::CallRejected;
					
	delete response;
	response = NULL;
	return result ? e_ok : e_fail;
}		

bool RadAuthBase::OnSendPDU(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_RegistrationRequest>& /*rrqPdu*/,
	RRQAuthData& /*authData*/
	)
{
	return true;
}

bool RadAuthBase::OnSendPDU(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_AdmissionRequest>& /*arqPdu*/,
	ARQAuthData& /*authData*/
	)
{
	return true;
}

bool RadAuthBase::OnSendPDU(
	RadiusPDU& /*pdu*/,
	SetupMsg &/*setup*/,
	SetupAuthData& /*authData*/
	)
{
	return true;
}

bool RadAuthBase::OnReceivedPDU(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_RegistrationRequest>& /*rrqPdu*/,
	RRQAuthData& /*authData*/
	)
{
	return true;
}

bool RadAuthBase::OnReceivedPDU(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_AdmissionRequest>& /*arqPdu*/,
	ARQAuthData& /*authData*/
	)
{
	return true;
}

bool RadAuthBase::OnReceivedPDU(
	RadiusPDU& /*pdu*/,
	SetupMsg &/*setup*/,
	SetupAuthData& /*authData*/
	)
{
	return true;
}

int RadAuthBase::AppendUsernameAndPassword(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_RegistrationRequest>& /*rrqPdu*/,
	RRQAuthData& /*authData*/,
	PString* /*username*/
	) const
{
	return GetDefaultStatus();
}

int RadAuthBase::AppendUsernameAndPassword(
	RadiusPDU& /*pdu*/,
	RasPDU<H225_AdmissionRequest>& /*arqPdu*/,
	ARQAuthData& /*authData*/,
	PString* /*username*/
	) const
{
	return GetDefaultStatus();
}

int RadAuthBase::AppendUsernameAndPassword(
	RadiusPDU &/*pdu*/,
	SetupMsg &/*setup*/,
	endptr &/*callingEP*/,
	SetupAuthData &/*authData*/,
	PString * /*username*/
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
		pdu.AppendAttr(RadiusAttr::UserName, id);
		if (username != NULL)
			*username = (const char*)id;
				
		// build CHAP-Password
		char password[17] = { (BYTE)randomInt };
		memcpy(password + 1, (const BYTE*)(token.m_challenge), 16);
				
		pdu.AppendAttr(RadiusAttr::ChapPassword, password, sizeof(password));
		pdu.AppendAttr(RadiusAttr::ChapChallenge, (int)(DWORD)token.m_timeStamp);
				
		return e_ok;
	}
	PTRACE(3, "RADAUTH\t" << GetName() << " auth failed: no CAT token found");
	return GetDefaultStatus();
}

int RadAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	RasPDU<H225_RegistrationRequest>& rrqPdu,
	RRQAuthData& authData,
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
	ARQAuthData& authData,
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
	SetupMsg &setup,
	endptr& /*callingEP*/,
	SetupAuthData& authData,
	PString* username
	) const
{
	H225_Setup_UUIE &setupBody = setup.GetUUIEBody();
	// check for ClearTokens (CAT uses ClearTokens)
	if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_tokens)) {
		PTRACE(3, "RADAUTH\t" << GetName() << " Setup auth failed: no tokens");
		authData.m_rejectReason = H225_ReleaseCompleteReason::e_securityDenied;
		return GetDefaultStatus();
	}

	const int result = CheckTokens(pdu, setupBody.m_tokens, NULL, username);
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
	m_fixedPassword = Toolkit::Instance()->ReadPassword(
		RadAliasAuthConfigSectionName, "FixedPassword"
		);
}

RadAliasAuth::~RadAliasAuth()
{
}

int RadAliasAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	RasPDU<H225_RegistrationRequest>& rrqPdu, 
	RRQAuthData& authData,
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
   	pdu.AppendAttr(RadiusAttr::UserName, 
		m_fixedUsername.IsEmpty() ? id : m_fixedUsername
		);
	
	if (username != NULL)
		*username = (const char*)id;
		
	// append User-Password
	if (!m_fixedPassword)
		pdu.AppendAttr(RadiusAttr::UserPassword, m_fixedPassword);
	else 
		pdu.AppendAttr(RadiusAttr::UserPassword, 
			m_fixedUsername.IsEmpty() ? id : m_fixedUsername
			);
		
	return e_ok;			
}

int RadAliasAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	RasPDU<H225_AdmissionRequest>& arqPdu,
	ARQAuthData& authData,
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
   	pdu.AppendAttr(RadiusAttr::UserName, 
		m_fixedUsername.IsEmpty() ? id : m_fixedUsername
		);

	if (username != NULL)
		*username = (const char*)id;
				
	if (!m_fixedPassword)
		pdu.AppendAttr(RadiusAttr::UserPassword, m_fixedPassword);
	else
		pdu.AppendAttr(RadiusAttr::UserPassword, 
			m_fixedUsername.IsEmpty() ? id : m_fixedUsername
			);
			
	return e_ok;
}

int RadAliasAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	SetupMsg &setup,
	endptr& /*callingEP*/,
	SetupAuthData& authData,
	PString* username
	) const
{
	const PString id = GetUsername(setup, authData);
	if (id.IsEmpty() && m_fixedUsername.IsEmpty()) {
		PTRACE(3, "RADAUTH\t" << GetName() << " Setup check failed: "
			"neither FixedUsername nor alias inside Setup were found"
			);
		authData.m_rejectReason = H225_ReleaseCompleteReason::e_badFormatAddress;
		return GetDefaultStatus();
	}
	
	// append User-Name
   	pdu.AppendAttr(RadiusAttr::UserName, 
		m_fixedUsername.IsEmpty() ? id : m_fixedUsername
		);

	if (username != NULL)
		*username = (const char*)id;
				
	if (!m_fixedPassword)
		pdu.AppendAttr(RadiusAttr::UserPassword, m_fixedPassword);
	else
		pdu.AppendAttr(RadiusAttr::UserPassword, 
			m_fixedUsername.IsEmpty() ? id : m_fixedUsername
			);
			
	return e_ok;
}
	
namespace {
	GkAuthCreator<RadAuth> RadAuthCreator("RadAuth");
	GkAuthCreator<RadAliasAuth> RadAliasAuthCreator("RadAliasAuth");
}

#endif /* HAS_RADIUS */
