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
#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug sumbol off
#endif

#include <ptlib.h>
#include <h225ras.h>
#include <h323pdu.h>
#include <h235.h>
#include <h235auth.h>
#include "gkauth.h"
#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "RasTbl.h"
#include "RasPDU.h"
#include "Toolkit.h"
#include "radproto.h"
#include "radauth.h"

// Settings for H.235 based module will be stored inside [RadAuth] config section
#define RadAuthConfigSectionName "RadAuth"
// Settings for alias based module will be stored inside [RadAliasAuth] config section
#define RadAliasAuthConfigSectionName "RadAliasAuth"


// OID for CAT (Cisco Access Token) algorithm
PString RadAuth::OID_CAT( "1.2.840.113548.10.1.2.1" );

/** Return conference identifier as a string compatible with Cisco
	equipment (four 32-bit hex numbers, with leading zeros skipped)
	
	@return
	A string with formatted conference identifier.
*/
PString GetConferenceIDString( const H225_ConferenceIdentifier& id )
{
	if( id.GetSize() < 16 )
		return PString();
		
	PString h323ConfId;
					
	for( int j = 0, i = 0; j < 4; j++ )	{
		const unsigned hex = ((unsigned)(id[i++])<<24) | ((unsigned)(id[i++])<<16) 
			| ((unsigned)(id[i++])<<8) | ((unsigned)(id[i++]));
							
		h323ConfId += PString( PString::Unsigned, (long)hex, 16 );
		if( j < 3 )
			h323ConfId += ' ';
	}

	return h323ConfId;
}


RadAuthBase::RadAuthBase( 
	const char* authName,
	const char* configSectionName 
	)
	:
	GkAuthenticator( authName ),
	portBase( 1024 ),
	portMax( 65535 ),
	radiusClient( NULL )
{
	// read settings from the config
	radiusServers = config->GetString(
		configSectionName,"Servers",""
		).Tokenise( ";, |\t", FALSE );
	sharedSecret = config->GetString(
		configSectionName,"SharedSecret",""
		);
	authPort = (WORD)(config->GetInteger(
		configSectionName,"DefaultAuthPort"
		));
	requestTimeout = config->GetInteger(
		configSectionName,"RequestTimeout"
		);
	idCacheTimeout = config->GetInteger(
		configSectionName,"IdCacheTimeout"
		);
	socketDeleteTimeout = config->GetInteger(
		configSectionName,"SocketDeleteTimeout"
		);
	numRequestRetransmissions = config->GetInteger(
		configSectionName,"RequestRetransmissions"
		);
	roundRobin = Toolkit::AsBool(config->GetString(
		configSectionName,"RoundRobinServers", "1"
		));
	appendCiscoAttributes = Toolkit::AsBool(config->GetString(
		configSectionName,"AppendCiscoAttributes", "1"
		));
	includeTerminalAliases = Toolkit::AsBool(config->GetString(
		configSectionName, "IncludeTerminalAliases", "1"
		));
	includeFramedIp = Toolkit::AsBool(config->GetString(
		configSectionName, "IncludeEndpointIP", "1"
		));
	localInterface = config->GetString(
		configSectionName, "LocalInterface", ""
		);
			
	if( radiusServers.GetSize() < 1 ) {
		PTRACE(1,"RADAUTH\tCannot build "<<GetName()<<" authenticator"
			" - no RADIUS servers specified in the config"
			);
		return;
	}

	if( (!localInterface.IsEmpty()) && (!PIPSocket::IsLocalHost(localInterface)) ) {
		PTRACE(1,"RADAUTH\tSpecified local interface - "<<localInterface
			<<" - does not belong to this machine"
			);
		localInterface = PString();
	}
	/// build RADIUS client
	radiusClient = new RadiusClient( 
		radiusServers[0],
		(radiusServers.GetSize() > 1) ? radiusServers[1] : PString(),
		localInterface
		);

	/// if there were specified more than two RADIUS servers, append them
	for( int i = 2; i < radiusServers.GetSize(); i++ )
		radiusClient->AppendServer( radiusServers[i] );	
		
	radiusClient->SetSharedSecret( sharedSecret );
	radiusClient->SetRoundRobinServers( roundRobin );
		
	if( authPort > 0 )
		radiusClient->SetAuthPort( authPort );
		
	if( requestTimeout > 0 )
		radiusClient->SetRequestTimeout( requestTimeout );
	if( idCacheTimeout > 0 )
		radiusClient->SetIdCacheTimeout( idCacheTimeout );
	if( socketDeleteTimeout > 0 )
		radiusClient->SetSocketDeleteTimeout( socketDeleteTimeout );
	if( numRequestRetransmissions > 0 )
		radiusClient->SetRetryCount( numRequestRetransmissions );
	
	PStringArray s = config->GetString(
		configSectionName,"RadiusPortRange",""
		).Tokenise( "-" );

	// parse port range (if it does exist)
	if( s.GetSize() >= 2 ) { 
		unsigned p1 = s[0].AsUnsigned();
		unsigned p2 = s[1].AsUnsigned();
	
		// swap if base is greater than max
		if( p2 < p1 ) {
			const unsigned temp = p1;
			p1 = p2;
			p2 = temp;
		}
		
		if( p1 > 65535 )
			p1 = 65535;
		if( p2 > 65535 )
			p2 = 65535;
	
		if( (p1 > 0) && (p2 > 0) ) {
			portBase = (WORD)p1;
			portMax = (WORD)p2;
		}
	}
	
	radiusClient->SetClientPortRange( portBase, portMax-portBase+1 );
}

RadAuthBase::~RadAuthBase()
{
	delete radiusClient;
}

bool RadAuthBase::CheckAliases( 
	const H225_ArrayOf_AliasAddress& aliases, 
	const PString& id 
	) const
{
	bool result = false;
	
	for( PINDEX i = 0; i < aliases.GetSize(); i++ )
		if( H323GetAliasAddressString(aliases[i]) == id ) {
			result = true;
			break;
		}
	
	return result;
}

int RadAuthBase::Check(
	/// RRQ RAS message to be authenticated
	RasPDU<H225_RegistrationRequest>& rrq, 
	/// reference to the variable, that can be set 
	/// to custom H225_RegistrationRejectReason
	/// if the check fails
	unsigned& rejectReason
	)
{
	return doCheck((const H225_RegistrationRequest&)rrq,rejectReason);
}
		
int RadAuthBase::Check(
	/// ARQ nessage to be authenticated
	RasPDU<H225_AdmissionRequest> & arq, 
	/// reference to the variable, that can be set 
	/// to custom H225_AdmissionRejectReason
	/// if the check fails
	unsigned& rejectReason,
	/// call duration limit to be set for the call
	/// (-1 stands for no limit)
	long& callDurationLimit
	)
{
	return doCheck((const H225_AdmissionRequest&)arq,rejectReason,callDurationLimit);
}

int RadAuthBase::doCheck(
	const H225_RegistrationRequest& rrq, 
	unsigned& rejectReason
	)
{
	if( radiusClient == NULL ) {
		PTRACE(3,"RADAUTH\tRRQ Auth failed - NULL Radius client");
		if( defaultStatus == e_fail )
			rejectReason = H225_RegistrationRejectReason::e_undefinedReason;
		return defaultStatus;
	}

	// build RADIUS Access-Request
	RadiusPDU* pdu = radiusClient->BuildPDU();
	if( pdu == NULL ) {
		PTRACE(3,"RADAUTH\tRRQ auth failed - could not to create Access-Request PDU");
		rejectReason = H225_RegistrationRejectReason::e_undefinedReason;
		return defaultStatus;
	}

	pdu->SetCode( RadiusPDU::AccessRequest );

	// Append User-Name and a password related attributes
	// (User-Password or Chap-Password and Chap-Timestamp)
	const int status = AppendUsernameAndPassword(*pdu,rrq,rejectReason);
	if( status != e_ok  ) {
		delete pdu;
		return status;
	}
		
	// Gk works as NAS point, so append NAS IP
	if( localInterface.IsEmpty() )
		*pdu += new RadiusAttr( RadiusAttr::NasIpAddress, 
			Toolkit::Instance()->GetRouteTable()->GetLocalAddress()
			);
	else
		*pdu += new RadiusAttr( RadiusAttr::NasIpAddress, 
			PIPSocket::Address(localInterface)
			);
	// NAS-Identifier as Gk name
	*pdu += new RadiusAttr( RadiusAttr::NasIdentifier,
		Toolkit::Instance()->GKName()
		);
	// Gk does not have a concept of physical ports,
	// so define port type as NAS-Port-Virtual
	*pdu += new RadiusAttr( RadiusAttr::NasPortType, 
		RadiusAttr::NasPort_Virtual 
		);
	// RRQ service type is Login-User
	*pdu += new RadiusAttr( RadiusAttr::ServiceType, RadiusAttr::ST_Login );

	// append Framed-IP-Address					
	if( includeFramedIp ) {
		PIPSocket::Address addr;
		if( rrq.m_callSignalAddress.GetSize() > 0 ) {
			if( GetIPFromTransportAddr(rrq.m_callSignalAddress[0],addr)
				&& addr.IsValid() )
				*pdu += new RadiusAttr( RadiusAttr::FramedIpAddress, addr );
		} else if( rrq.m_rasAddress.GetSize() > 0 ) {
			if( GetIPFromTransportAddr(rrq.m_rasAddress[0],addr) 
				&& addr.IsValid() )
				*pdu += new RadiusAttr( RadiusAttr::FramedIpAddress, addr );
		}
	}
				
	if( appendCiscoAttributes && includeTerminalAliases ) {
		PString aliasList( "terminal-alias:" );
		for( PINDEX i = 0; i < rrq.m_terminalAlias.GetSize(); i++ ) {
			if( i > 0 )
				aliasList += ",";
			aliasList += H323GetAliasAddressString(rrq.m_terminalAlias[i]);
		}
		// Cisco-AV-Pair
		*pdu += new RadiusAttr( 
			PString("h323-ivr-out=") + aliasList + ";", 9, 1 
			);
	}
	
	// send request and wait for response
	RadiusPDU* response = NULL;
	bool result = OnSendPDU(*pdu,rrq,rejectReason)
		&& radiusClient->MakeRequest( *pdu, response ) 
		&& (response != NULL);
		
	delete pdu;
			
	if( !result ) {
		delete response;
		return defaultStatus;
	}
				
	result = (response->GetCode() == RadiusPDU::AccessAccept);
	if( result )
		result = OnReceivedPDU(*response,rrq,rejectReason);
	else
		rejectReason = H225_RegistrationRejectReason::e_securityDenial;
				
	delete response;
	return result ? e_ok : e_fail;
}

int RadAuthBase::doCheck(
	const H225_AdmissionRequest& arq, 
	unsigned& rejectReason,
	long& durationLimit
	)
{
	if( radiusClient == NULL ) {
		PTRACE(3,"RADAUTH\tARQ Auth failed - NULL Radius client");
		if( defaultStatus == e_fail )
			rejectReason = H225_AdmissionRejectReason::e_undefinedReason;
		return defaultStatus;
	}
	
	// build RADIUS Access-Request packet
	RadiusPDU* pdu = radiusClient->BuildPDU();
	if( pdu == NULL ) {
		PTRACE(3,"RADAUTH\tARQ auth failed - could not to create Access-Request PDU");
		return defaultStatus;
	}

	pdu->SetCode( RadiusPDU::AccessRequest );

	// Append User-Name and a password related attributes
	// (User-Password or Chap-Password and Chap-Timestamp)
	PString username;				
	const int status = AppendUsernameAndPassword(*pdu,arq,rejectReason,&username);
	if( status != e_ok ) {
		delete pdu;
		return status;
	}
	
	// Gk acts as NAS, so include NAS IP
	if( localInterface.IsEmpty() )
		*pdu += new RadiusAttr( RadiusAttr::NasIpAddress, 
			Toolkit::Instance()->GetRouteTable()->GetLocalAddress()
			);
	else
		*pdu += new RadiusAttr( RadiusAttr::NasIpAddress, 
			PIPSocket::Address(localInterface)
			);
					
	// NAS-Identifier as Gk name
	*pdu += new RadiusAttr( RadiusAttr::NasIdentifier,
		Toolkit::Instance()->GKName()
		);
	// NAS-Port-Type as Virtual, since Gk does
	// not care about physical ports concept
	*pdu += new RadiusAttr( RadiusAttr::NasPortType, 
		RadiusAttr::NasPort_Virtual 
		);
					
	// Service-Type is Login-User if originating the call
	// and Call Check if answering the call
	*pdu += new RadiusAttr( RadiusAttr::ServiceType,
		arq.m_answerCall ? RadiusAttr::ST_CallCheck : RadiusAttr::ST_Login
		);
				
	PIPSocket::Address addr;
	callptr call;
	endptr callingEP, calledEP;
	
	// extract CallRec for the call being admitted (if it already exists)
	if( arq.HasOptionalField(arq.e_callIdentifier ) )
		call = CallTable::Instance()->FindCallRec(arq.m_callIdentifier);
	else 
		call = CallTable::Instance()->FindCallRec(arq.m_callReferenceValue);
	
	// try to extract calling/called endpoints from RegistrationTable
	// (unregistered endpoints will not be present there)
	if( arq.m_answerCall ) {
		calledEP = RegistrationTable::Instance()->FindByEndpointId(
			arq.m_endpointIdentifier
			);
		if( call )
			callingEP = call->GetCallingParty();
	} else {
		callingEP = RegistrationTable::Instance()->FindByEndpointId(
			arq.m_endpointIdentifier
			);
		if( call )
			calledEP = call->GetCalledParty();
		if( (!calledEP) && arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress) )
			calledEP = RegistrationTable::Instance()->FindBySignalAdr(arq.m_destCallSignalAddress);
	}
	
	// at least requesting endpoint (the one that is sending ARQ)
	// has to be present in the RegistrationTable
	if( arq.m_answerCall ? (!calledEP) : (!callingEP) ) {
		delete pdu;
		PTRACE(3,"RADAUTH\tARQ Auth failed - requesting endpoint "
			<< arq.m_endpointIdentifier << " not registered"
			);
		return e_fail;
	}

	// append Frame-IP-Address					
	if( includeFramedIp )
		if( arq.m_answerCall ) {
			if( calledEP 
				&& GetIPFromTransportAddr( calledEP->GetCallSignalAddress(), addr)
				&& addr.IsValid() )
				*pdu += new RadiusAttr( RadiusAttr::FramedIpAddress, addr );
			else if( arq.HasOptionalField( arq.e_destCallSignalAddress ) 
				&& GetIPFromTransportAddr(arq.m_destCallSignalAddress,addr)
				&& addr.IsValid() )
				*pdu += new RadiusAttr( RadiusAttr::FramedIpAddress, addr );
		} else {
			if( callingEP 
				&& GetIPFromTransportAddr( callingEP->GetCallSignalAddress(), addr)
				&& addr.IsValid() )
				*pdu += new RadiusAttr( RadiusAttr::FramedIpAddress, addr );
			else if( arq.HasOptionalField( arq.e_srcCallSignalAddress )
				&& GetIPFromTransportAddr(arq.m_srcCallSignalAddress,addr) 
				&& addr.IsValid() )
				*pdu += new RadiusAttr( RadiusAttr::FramedIpAddress, addr );
		}
				
	// fill Calling-Station-Id and Called-Station-Id fields
				
	// Calling-Station-Id
	// Priority:
	//	ARQ.m_srcInfo (first dialedDigits alias, then first partyNumber alias,...)
	//  first dialedDigits alias from registration table, then first partyNumber ...
	//	generalID from CAT ClearToken (if the call originator)
					
	PString stationId;

	// first try to extract Calling-Station-Id from m_srcInfo field
	// (this field usually contains alias displayed to the remote party)
	if( arq.m_srcInfo.GetSize() > 0 ) {
		stationId = GetBestAliasAddressString(
			arq.m_srcInfo,
			H225_AliasAddress::e_dialedDigits, 
			H225_AliasAddress::e_partyNumber,
			H225_AliasAddress::e_h323_ID
			);
		// check for valid alias (some endpoint like NM place in m_srcInfo
		// funny things). For gateways, skip the test.
		if( callingEP && !stationId.IsEmpty() )
			if( !(callingEP->IsGateway()
				|| CheckAliases(callingEP->GetAliases(),stationId)) )
				stationId = PString();
	}

	// if no alias found in m_srcInfo, then try to get alias
	// that the calling party is registered with				
	if( stationId.IsEmpty() && callingEP )
		stationId = GetBestAliasAddressString(
			callingEP->GetAliases(),
			H225_AliasAddress::e_dialedDigits,
			H225_AliasAddress::e_partyNumber,
			H225_AliasAddress::e_h323_ID
			);

	// if no alias has been found, then use User-Name
	if( stationId.IsEmpty() && !arq.m_answerCall )
		stationId = username;
				
	if( !stationId.IsEmpty() )		
		*pdu += new RadiusAttr( RadiusAttr::CallingStationId, stationId );
						
	stationId = PString();
					
	// Called-Station-Id
	// Priority:
	//	ARQ.m_destinationInfo[0] (first dialedDigits alias, then first partyNumber ...)
	//  first dialedDigitst alias from registration table, first partyNumber ...
	//  generalID from CAT token (if answering the call)
	//	ARQ.m_destCallSignalAddress::e_ipAddress
	if( arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo) 
		&& (arq.m_destinationInfo.GetSize() > 0) )
		stationId = GetBestAliasAddressString(
			arq.m_destinationInfo,
			H225_AliasAddress::e_dialedDigits,
			H225_AliasAddress::e_partyNumber,
			H225_AliasAddress::e_h323_ID
			);
				
	if( stationId.IsEmpty() && calledEP )
		stationId = GetBestAliasAddressString(
			calledEP->GetAliases(),
			H225_AliasAddress::e_dialedDigits,
			H225_AliasAddress::e_partyNumber,
			H225_AliasAddress::e_h323_ID
			);
						
	if( stationId.IsEmpty() && arq.m_answerCall )
		stationId = username;
		
	if( stationId.IsEmpty() 
		&& arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress) )
	{
		stationId = AsDotString(arq.m_destCallSignalAddress);
	}
				
	if( stationId.IsEmpty() ) {
		delete pdu;
		PTRACE(3,"RADAUTH\tARQ Auth failed - no suitable alias"
			" for Calling-Station-Id has been found"
			);
		return e_fail;
	}
				
	*pdu += new RadiusAttr( RadiusAttr::CalledStationId, stationId );
			
	if( appendCiscoAttributes ) {
		*pdu += new RadiusAttr(
			PString("h323-conf-id=") + GetConferenceIDString(arq.m_conferenceID),
			9, 24
			);
		*pdu += new RadiusAttr(
			PString(arq.m_answerCall 
				? "h323-call-origin=answer" : "h323-call-origin=originate"),
				9, 26
				);
		*pdu += new RadiusAttr( PString("h323-call-type=VoIP"),	9, 27 );
		*pdu += new RadiusAttr( 
			PString("h323-gw-id=") + Toolkit::Instance()->GKName(),	9, 33 
			);
	}
					
	// send the request and wait for a response
	RadiusPDU* response = NULL;
	bool result = OnSendPDU(*pdu,arq,rejectReason) 
		&& radiusClient->MakeRequest( *pdu, response ) 
		&& (response != NULL);
			
	delete pdu;
			
	if( !result ) {
		delete response;
		return defaultStatus;
	}
				
	// authenticated?
	const RadiusAttr* attr;
	bool found;
	
	result = (response->GetCode() == RadiusPDU::AccessAccept);
	// test for h323-return-code attribute (has to be 0 if accept)
	if( result ) {
		const PINDEX index = response->FindVsaAttr( 9, 103 );
		if( index != P_MAX_INDEX ) {
			attr = response->GetAttrAt(index);
			bool valid = false;
			if( attr && attr->IsValid() ) {
				PString s = attr->AsVsaString();
				// Cisco prepends attribute name to the attribute value				
				if( s.Find("h323-return-code=") == 0 )
					s = s.Mid( s.FindOneOf("=") + 1 );
				if( s.GetLength() > 0 
					&& strspn((const char*)s,"0123456789") == (size_t)s.GetLength() ) {
					const unsigned retcode = s.AsUnsigned();
					if( retcode != 0 ) {
						PTRACE(5,"RADAUTH\t"<<GetName()<<" ARQ check failed - return code "<<retcode);
						result = false;
					}
					valid = true;
				}
			}
			if( !valid ) {
				PTRACE(5,"RADAUTH\t"<<GetName()<<" check failed - invalid h323-return-code attribute");
				result = false;
			}
		}
	}

	// check for h323-credit-time attribute (call duration limit)	
	if( result ) {
		found = false;
		const PINDEX index = response->FindVsaAttr( 9, 102 );
		if( index != P_MAX_INDEX ) {
			attr = response->GetAttrAt(index);
			if( attr && attr->IsValid() ) {
				PString s = attr->AsVsaString();
				// Cisco prepends attribute name to the attribute value
				if( s.Find("h323-credit-time=") == 0 )
					s = s.Mid( s.FindOneOf("=") + 1 );
				if( s.GetLength() > 0 
					&& strspn((const char*)s,"0123456789") == (size_t)s.GetLength() ) {
					found = true;
					durationLimit = s.AsInteger();
					PTRACE(5,"RADAUTH\t"<<GetName()<<" ARQ check set duration limit set: "<<durationLimit);
					if( durationLimit == 0 )						
						result = false;
				}
			}
			if( !found ) {
				PTRACE(5,"RADAUTH\t"<<GetName()<<" ARQ check failed - invalid h323-credit-time attribute: ");
				result = false;
			}
		}
	}

	// check for Session-Timeout attribute (alternate call duration limit)	
	if( result ) {
		found = false;
		const PINDEX index = response->FindAttr( RadiusAttr::SessionTimeout );
		if( index != P_MAX_INDEX ) {
			attr = response->GetAttrAt(index);
			if( attr && attr->IsValid() ) {
				found = true;
				const long sessionTimeout = attr->AsInteger();
				if( (durationLimit < 0) || (durationLimit > sessionTimeout) ) {
					durationLimit = sessionTimeout;
					PTRACE(5,"RADAUTH\t"<<GetName()<<" ARQ check set duration limit set: "<<durationLimit);
				}
				if( durationLimit == 0 )
					result = false;
			}
			if( !found ) {
				PTRACE(5,"RADAUTH\t"<<GetName()<<" ARQ check failed - invalid Session-Timeout attribute");
				result = false;
			}
		}
	}
			
	if( result )
		result = OnReceivedPDU(*response,arq,rejectReason,durationLimit);
	else
		rejectReason = H225_AdmissionRejectReason::e_securityDenial;
					
	delete response;
	return result ? e_ok : e_fail;
}		

bool RadAuthBase::OnSendPDU(
	RadiusPDU& pdu,
	const H225_RegistrationRequest& rrq,
	unsigned& rejectReason
	)
{
	return true;
}

bool RadAuthBase::OnSendPDU(
	RadiusPDU& pdu,
	const H225_AdmissionRequest& rrq,
	unsigned& rejectReason
	)
{
	return true;
}

bool RadAuthBase::OnReceivedPDU(
	RadiusPDU& pdu,
	const H225_RegistrationRequest& rrq,
	unsigned& rejectReason
	)
{
	return true;
}

bool RadAuthBase::OnReceivedPDU(
	RadiusPDU& pdu,
	const H225_AdmissionRequest& rrq,
	unsigned& rejectReason,
	long& durationLimit
	)
{
	return true;
}


RadAuth::RadAuth(
	const char* authName
	)
	: 
	RadAuthBase( authName, RadAuthConfigSectionName )
{
#ifdef OPENH323_NEWVERSION
	// setup H.235 algorithm and method types used
	// by this authenticator - this will make sure
	// GCF H.235 alogirthm selection will not skip
	// information required by this authenticator
	if( h235Authenticators == NULL )
		h235Authenticators = new H235Authenticators;
		
	H235AuthCAT* authenticator = new H235AuthCAT;
	authenticator->SetLocalId("dummy");
	authenticator->SetRemoteId("dummy");
	authenticator->SetPassword("dummy");
	h235Authenticators->Append(authenticator);
#endif
}

RadAuth::~RadAuth() 
{
}

int RadAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	const H225_RegistrationRequest& rrq,
	unsigned& rejectReason,
	PString* username
	) const
{
	// RRQ has to carry at least one terminalAlias
	if( !rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) ) {
		PTRACE(3,"RADAUTH\tRRQ Auth failed - no m_terminalAlias field");
		if( defaultStatus == e_fail )
			rejectReason = H225_RegistrationRejectReason::e_securityDenial;
		return defaultStatus;
	}
		
	// check for ClearTokens (CAT uses ClearTokens)
	if( !rrq.HasOptionalField(H225_RegistrationRequest::e_tokens) ) {
		if( defaultStatus == e_fail ) {
			PTRACE(3,"RADAUTH\tRRQ Auth failed - no m_tokens");
			rejectReason = H225_RegistrationRejectReason::e_securityDenial;
		} else if( defaultStatus != e_ok )
			PTRACE(4,"RADAUTH\tRRQ Auth undetermined - no m_tokens");
		return defaultStatus;
	}
	
	const H225_ArrayOf_AliasAddress& aliases = rrq.m_terminalAlias;
	const H225_ArrayOf_ClearToken& tokens = rrq.m_tokens;
	bool foundCAT = false;
		
	// scan ClearTokens and find CATs
	for( PINDEX i = 0; i < tokens.GetSize(); i++ ) {
		const H235_ClearToken& token = tokens[i];
			
		// is it CAT?
		if( token.m_tokenOID == OID_CAT ) {
			foundCAT = true;
				
			// these field are required for CAT
		  	if( !(token.HasOptionalField(H235_ClearToken::e_generalID)
				&& token.HasOptionalField(H235_ClearToken::e_random)
				&& token.HasOptionalField(H235_ClearToken::e_timeStamp)
				&& token.HasOptionalField(H235_ClearToken::e_challenge)) ) 
			{	
				PTRACE(4,"RADAUTH\tRRQ Auth failed - CAT without all required fields");
				rejectReason = H225_RegistrationRejectReason::e_securityDenial;
				return e_fail;
			}
				
			// generalID should be present in the list of terminal aliases
			const PString id = token.m_generalID;
			if( !CheckAliases(aliases,id) ) {
				PTRACE(4,"RADAUTH\tRRQ Auth failed - CAT m_generalID is not a valid alias");
				rejectReason = H225_RegistrationRejectReason::e_invalidTerminalAliases;
				return e_fail;
			}
					
			// CAT pseudo-random has to be one byte only
			const int randomInt = token.m_random;
					
			if( (randomInt < -127) || (randomInt > 255) ) {
				PTRACE(4,"RADAUTH\tRRQ Auth failed - CAT m_random out of range");
				rejectReason = H225_RegistrationRejectReason::e_securityDenial;
				return e_fail;
			}
					
			// CAT challenge has to be 16 bytes
			if( token.m_challenge.GetValue().GetSize() < 16 ) {
				PTRACE(4,"RADAUTH\tRRQ Auth failed - m_challenge less than 16 bytes");
				rejectReason = H225_RegistrationRejectReason::e_securityDenial;
				return e_fail;
			}
					
			// append User-Name
			pdu += new RadiusAttr( RadiusAttr::UserName, id );
			if( username != NULL )
				*username = (const char*)id;
				
			// build CHAP-Password
			char password[17] = { (BYTE)randomInt };
			memcpy(password+1,(const BYTE*)(token.m_challenge),16);
				
			pdu += new RadiusAttr( RadiusAttr::ChapPassword,
				password, sizeof(password)
				);
			pdu += new RadiusAttr( RadiusAttr::ChapChallenge,
				(int)(DWORD)token.m_timeStamp
				);
				
			return e_ok;
		}
	}
	
	if( defaultStatus == e_fail ) {
		PTRACE(3,"RADAUTH\tRRQ Auth failed - m_tokens without CAT");
		rejectReason = H225_RegistrationRejectReason::e_securityDenial;
	} else if( defaultStatus != e_ok )
		PTRACE(4,"RADAUTH\tRRQ Auth undetermined - m_tokens without CAT");

	return defaultStatus;
}

int RadAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	const H225_AdmissionRequest& arq,
	unsigned& rejectReason,
	PString* username
	) const
{
	// check for ClearTokens
	if( !arq.HasOptionalField(H225_AdmissionRequest::e_tokens) ) {
		if( defaultStatus == e_fail ) {
			PTRACE(3,"RADAUTH\tARQ Auth failed - no m_tokens");
			rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		} else if( defaultStatus != e_ok )
			PTRACE(4,"RADAUTH\tARQ Auth undetermined - no m_tokens");
		return defaultStatus;
	}
	
	const H225_ArrayOf_ClearToken& tokens = arq.m_tokens;
	bool foundCAT = FALSE;
		
	// scan ClearTokens for CATs
	for( PINDEX i = 0; i < tokens.GetSize(); i++ ) {
		const H235_ClearToken& token = tokens[i];
				
		// is it CAT?
		if( token.m_tokenOID == OID_CAT ) {
			foundCAT = true;
				
			// these field are required for CAT
		  	if( !(token.HasOptionalField(H235_ClearToken::e_generalID)
				&& token.HasOptionalField(H235_ClearToken::e_random)
				&& token.HasOptionalField(H235_ClearToken::e_timeStamp)
				&& token.HasOptionalField(H235_ClearToken::e_challenge)) )
			{
				PTRACE(4,"RADAUTH\tARQ Auth failed - CAT without all required fields");
				rejectReason = H225_AdmissionRejectReason::e_securityDenial;
				return e_fail;
			}
			
			const PString id = token.m_generalID;
					
			// CAT random has to be one byte only				
			const int randomInt = token.m_random;
					
			if( (randomInt < -127) || (randomInt > 255) ) {
				PTRACE(4,"RADAUTH\tARQ Auth failed - CAT m_random out of range");
				rejectReason = H225_AdmissionRejectReason::e_securityDenial;
				return e_fail;
			}
					
			// CAT challenge has to be 16 bytes
			if( token.m_challenge.GetValue().GetSize() < 16 ) {
				PTRACE(4,"RADAUTH\tARQ Auth failed - CAT m_challenge less than 16 bytes");
				rejectReason = H225_AdmissionRejectReason::e_securityDenial;
				return e_fail;
			}
					
			pdu += new RadiusAttr( RadiusAttr::UserName, id );
			
			if( username != NULL )
				*username = (const char*)id;
								
			// build CHAP-Password
			char password[17] = { (BYTE)randomInt };
			memcpy(password+1,(const BYTE*)(token.m_challenge),16);
				
			pdu += new RadiusAttr( RadiusAttr::ChapPassword,
				password, sizeof(password)
				);
				
			// append CHAP-Challenge 
			pdu += new RadiusAttr( RadiusAttr::ChapChallenge,
				(int)(DWORD)token.m_timeStamp
				);
				
			return e_ok;
		}
	}
	
	if( defaultStatus == e_fail )
		PTRACE(3,"RADAUTH\tARQ Auth failed - m_tokens without CAT");
	else if( defaultStatus != e_ok )
		PTRACE(4,"RADAUTH\tARQ Auth undetermined - m_tokens without CAT");

	if( defaultStatus == e_fail )
		rejectReason = H225_AdmissionRejectReason::e_securityDenial;
	
	return defaultStatus;
}

RadAliasAuth::RadAliasAuth( 
	const char* authName 
	)
	:
	RadAuthBase( authName, RadAliasAuthConfigSectionName )
{
	fixedUsername = config->GetString(
		RadAliasAuthConfigSectionName, "FixedUsername", ""
		);
	fixedPassword = config->GetString(
		RadAliasAuthConfigSectionName, "FixedPassword", ""
		);
}

RadAliasAuth::~RadAliasAuth()
{
}

int RadAliasAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	const H225_RegistrationRequest& rrq, 
	unsigned& rejectReason,
	PString* username
	) const
{
	PString id;				

	if( fixedUsername.IsEmpty() )
	{
		if( rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) 
			&& (rrq.m_terminalAlias.GetSize() > 0) )
			id = GetBestAliasAddressString(
				rrq.m_terminalAlias,
				H225_AliasAddress::e_h323_ID, H225_AliasAddress::e_dialedDigits
				);
	} else
		id = fixedUsername;
		
	if( id.IsEmpty() )
	{
		PTRACE(2,"RADAUTH\tRRQ AliasAuth failed - neither FixedUsername"
			" nor alias inside RRQ were found"
			);
		rejectReason = H225_RegistrationRejectReason::e_securityDenial;
		return defaultStatus;
	}
	
	// append User-Name
   	pdu += new RadiusAttr( RadiusAttr::UserName, id );
	
	if( username != NULL )
		*username = (const char*)id;
		
	// append User-Password
	if( !fixedPassword.IsEmpty() )
		pdu += new RadiusAttr( RadiusAttr::UserPassword, fixedPassword );
	else 
		pdu += new RadiusAttr( RadiusAttr::UserPassword, id );
		
	return e_ok;			
}

int RadAliasAuth::AppendUsernameAndPassword(
	RadiusPDU& pdu,
	const H225_AdmissionRequest& arq, 
	unsigned& rejectReason,
	PString* username
	) const
{
	PString id;				
	PIPSocket::Address addr;

	if( fixedUsername.IsEmpty() )
	{	
		endptr ep = RegistrationTable::Instance()->FindByEndpointId(
			arq.m_endpointIdentifier
			);
			
		if( ep && (ep->GetAliases().GetSize() > 0) )
			id = GetBestAliasAddressString(
				ep->GetAliases(),
				H225_AliasAddress::e_h323_ID, H225_AliasAddress::e_dialedDigits
				);

		if( id.IsEmpty() && (arq.m_srcInfo.GetSize() > 0) )
			id = GetBestAliasAddressString(
				arq.m_srcInfo,
				H225_AliasAddress::e_h323_ID, H225_AliasAddress::e_dialedDigits
				);
	}
	else
		id = fixedUsername;
		
	if( id.IsEmpty() ) {
		PTRACE(2,"RADAUTH\tARQ AliasAuth failed - neither FixedUsername"
			" nor alias inside ARQ were found"
			);
		rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		return defaultStatus;
	}
	
	// append User-Name
   	pdu += new RadiusAttr( RadiusAttr::UserName, id );

	if( username != NULL )
		*username = (const char*)id;
				
	if( !fixedPassword.IsEmpty() )
		pdu += new RadiusAttr( RadiusAttr::UserPassword, fixedPassword );
	else
		pdu += new RadiusAttr( RadiusAttr::UserPassword, id );
			
	return e_ok;
}
	
namespace {
#ifdef HAS_RADIUS
	GkAuthCreator<RadAuth> RadAuthCreator("RadAuth");
	GkAuthCreator<RadAliasAuth> RadAliasAuthCreator("RadAliasAuth");
#endif 
}
