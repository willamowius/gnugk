/*
 * radacct.cxx
 *
 * RADIUS protocol accounting logger module for GNU Gatekeeper. 
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.9  2004/04/17 11:43:43  zvision
 * Auth/acct API changes.
 * Header file usage more consistent.
 *
 * Revision 1.8  2004/03/17 00:00:38  zvision
 * Conditional compilation to allow to control RADIUS on Windows just by setting HA_RADIUS macro
 *
 * Revision 1.7  2003/10/31 00:01:24  zvision
 * Improved accounting modules stacking control, optimized radacct/radauth a bit
 *
 * Revision 1.6  2003/10/15 10:16:57  zvision
 * Fixed VC6 compiler warnings. Thanks to Hu Yuxin.
 *
 * Revision 1.5  2003/10/08 12:40:48  zvision
 * Realtime accounting updates added
 *
 * Revision 1.4  2003/09/17 19:23:01  zvision
 * Removed unnecessary setup-time double check.
 * Added h323-connect-time to AcctUpdate packets.
 *
 * Revision 1.3  2003/09/14 21:10:34  zvision
 * Changes due to accounting API redesign.
 *
 * Revision 1.2  2003/09/12 16:31:16  zvision
 * Accounting initially added to the 2.2 branch
 *
 * Revision 1.1.2.5  2003/08/21 15:28:58  zvision
 * Fixed double h323-setup-time sent in Acct-Stop
 *
 * Revision 1.1.2.4  2003/08/17 20:05:39  zvision
 * Added h323-setup-time attribute to Acct-Start packets (Cisco compatibility).
 *
 * Revision 1.1.2.3  2003/07/31 22:58:48  zvision
 * Added Framed-IP-Address attribute and improved h323-disconnect-cause handling
 *
 * Revision 1.1.2.2  2003/07/03 15:30:39  zvision
 * Added cvs Log keyword
 *
 */
#if HAS_RADIUS

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug sumbol off
#endif

#include <ptlib.h>
#include <h323pdu.h>
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "RasTbl.h"
#include "gkacct.h"
#include "radproto.h"
#include "radacct.h"

RadAcct::RadAcct( 
	const char* moduleName,
	const char* cfgSecName
	)
	:
	GkAcctLogger(moduleName, cfgSecName),
	m_nasIdentifier(Toolkit::Instance()->GKName()),
	m_radiusClient(NULL)
{
	// it is very important to set what type of accounting events
	// are supported for each accounting module, otherwise Log method
	// will no get called
	SetSupportedEvents(RadAcctEvents);
	
	PConfig* cfg = GetConfig();
	const PString& cfgSec = GetConfigSectionName();

	m_radiusClient = new RadiusClient(*cfg, cfgSec);

	m_nasIpAddress = m_radiusClient->GetLocalAddress();
	if (m_nasIpAddress == INADDR_ANY) {
		std::vector<PIPSocket::Address> interfaces;
		Toolkit::Instance()->GetGKHome(interfaces);
		if (!interfaces.empty())
			m_nasIpAddress = interfaces.front();
		else
			PTRACE(1, "RADACCT\t" << GetName() << " cannot determine "
				" NAS IP address"
				);
	}

	m_appendCiscoAttributes = Toolkit::AsBool(cfg->GetString(
		cfgSec, "AppendCiscoAttributes", "1"
		));
	m_includeFramedIp = Toolkit::AsBool(cfg->GetString(
		cfgSec, "IncludeEndpointIP", "1"
		));
	m_fixedUsername = cfg->GetString(cfgSec, "FixedUsername", "");
}

RadAcct::~RadAcct()
{
	delete m_radiusClient;
}

GkAcctLogger::Status RadAcct::Log(
	GkAcctLogger::AcctEvent evt, 
	callptr& call
	)
{
	// a workaround to prevent processing end on "sufficient" module
	// if it is not interested in this event type
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;
		
	if (m_radiusClient == NULL) {
		PTRACE(1,"RADACCT\t"<<GetName()<<" - null RADIUS client instance");
		return Fail;
	}

	if( (evt & (AcctStart | AcctStop | AcctUpdate)) && (!call) ) {
		PTRACE(1,"RADACCT\t"<<GetName()<<" - missing call info for event"<<evt);
		return Fail;
	}
	
	// build RADIUS Accounting-Request
	RadiusPDU* pdu = m_radiusClient->BuildPDU();
	if( pdu == NULL ) {
		PTRACE(2,"RADACCT\t"<<GetName()<<" - could not build Accounting-Request PDU"
			<<" for event "<<evt<<", call no. "<<(call?call->GetCallNumber():0)
			);
		return Fail;
	}

	pdu->SetCode( RadiusPDU::AccountingRequest );

	*pdu += new RadiusAttr( RadiusAttr::AcctStatusType, 
		(evt & AcctStart) ? RadiusAttr::AcctStatus_Start
		: ((evt & AcctStop) ? RadiusAttr::AcctStatus_Stop
		: ((evt & AcctUpdate) ? RadiusAttr::AcctStatus_InterimUpdate
		: ((evt & AcctOn) ? RadiusAttr::AcctStatus_AccountingOn
		: ((evt & AcctOff) ? RadiusAttr::AcctStatus_AccountingOff : 0)
		))) );

	PIPSocket::Address addr;
	WORD port;
					
	// Gk works as NAS point, so append NAS IP
	*pdu += new RadiusAttr(RadiusAttr::NasIpAddress, m_nasIpAddress);
	*pdu += new RadiusAttr(RadiusAttr::NasIdentifier, m_nasIdentifier);
	*pdu += new RadiusAttr(RadiusAttr::NasPortType, 
		RadiusAttr::NasPort_Virtual 
		);
		
	if( evt & (AcctStart | AcctStop | AcctUpdate) ) {
		*pdu += new RadiusAttr( RadiusAttr::ServiceType, RadiusAttr::ST_Login );
		*pdu += new RadiusAttr( RadiusAttr::AcctSessionId, 
			call->GetAcctSessionId() 
			);

		PString srcInfo = call->GetSrcInfo();
		if( !srcInfo.IsEmpty() ) {
			const PINDEX index = srcInfo.FindOneOf(":");
			if( index != P_MAX_INDEX )
				srcInfo = srcInfo.Left(index);
		}
	
		endptr callingEP = call->GetCallingParty();
		PIPSocket::Address callerIP(0);
		WORD callerPort = 0;		
		
		call->GetSrcSignalAddr(callerIP,callerPort);

		PString userName;
	
		if( !m_fixedUsername.IsEmpty() )
			userName = m_fixedUsername;
		else if( callingEP && (callingEP->GetAliases().GetSize() > 0) )
			userName = GetBestAliasAddressString(
				callingEP->GetAliases(),
				H225_AliasAddress::e_h323_ID
				);
		else if( !srcInfo.IsEmpty() )
			userName = srcInfo;
		else if( callerIP.IsValid() )
			userName = ::AsString(callerIP,callerPort);

		if( !userName.IsEmpty() )					
			*pdu += new RadiusAttr( RadiusAttr::UserName, userName );
		else
			PTRACE(3,"RADACCT\t"<<GetName()<<" could not determine User-Name"
				<<" for the call no. "<<call->GetCallNumber()
				);
		
		if( m_includeFramedIp && callerIP.IsValid() )
			*pdu += new RadiusAttr( RadiusAttr::FramedIpAddress, callerIP );
		
		if( (evt & AcctStart) == 0 )
			*pdu += new RadiusAttr( RadiusAttr::AcctSessionTime, 
				call->GetDuration() 
				);
	
		PString callingStationId;
	
		if( callingEP && callingEP->GetAliases().GetSize() > 0 )
			callingStationId = GetBestAliasAddressString(
				callingEP->GetAliases(),
				H225_AliasAddress::e_dialedDigits,
				H225_AliasAddress::e_partyNumber,
				H225_AliasAddress::e_h323_ID
				);
					
		if( callingStationId.IsEmpty() )
			callingStationId = srcInfo;
			
		if( callingStationId.IsEmpty() && callerIP.IsValid() )
			callingStationId = ::AsString(callerIP,callerPort);
		
		if( !callingStationId.IsEmpty() )
			*pdu += new RadiusAttr( RadiusAttr::CallingStationId,
				callingStationId
				);
		else
			PTRACE(3,"RADACCT\t"<<GetName()<<" could not determine"
				<<" Calling-Station-Id for the call "<<call->GetCallNumber()
				);
		
		PString calledStationId = call->GetDestInfo();
								
		if( !calledStationId.IsEmpty() ) {
			const PINDEX index = calledStationId.FindOneOf(":");
			if( index != P_MAX_INDEX )				
				calledStationId = calledStationId.Left(index);
		}
		
		if( calledStationId.IsEmpty() ) {
			endptr calledEP = call->GetCalledParty();
			if( calledEP && (calledEP->GetAliases().GetSize() > 0) )
				calledStationId = GetBestAliasAddressString(
					calledEP->GetAliases(),
					H225_AliasAddress::e_dialedDigits,
					H225_AliasAddress::e_partyNumber,
					H225_AliasAddress::e_h323_ID
					);
		}
	
		if( calledStationId.IsEmpty() )
			if( call->GetDestSignalAddr(addr,port) )
				calledStationId = ::AsString(addr,port);
		
		if( calledStationId.IsEmpty() )
			PTRACE(3,"RADACCT\t"<<GetName()<<" could not determine"
				<<" Called-Station-Id for the call no. "<<call->GetCallNumber()
				);
		else
			*pdu += new RadiusAttr( RadiusAttr::CalledStationId, calledStationId );
		
		if( m_appendCiscoAttributes ) {
			*pdu += new RadiusAttr(
				PString("h323-gw-id=") + m_nasIdentifier,
				CiscoVendorId, 33 
				);
			
			*pdu += new RadiusAttr(
				PString("h323-conf-id=") 
					+ GetGUIDString(call->GetConferenceIdentifier()),
				CiscoVendorId, 24
				);
						
			*pdu += new RadiusAttr( PString("h323-call-origin=proxy"),
				CiscoVendorId, 26
				);
				
			*pdu += new RadiusAttr(	PString("h323-call-type=VoIP"),
				CiscoVendorId, 27
				);
	
			time_t tm = call->GetSetupTime();
			if( tm != 0 ) 					
				*pdu += new RadiusAttr( 
					PString("h323-setup-time=") + AsString(tm),
					CiscoVendorId, 25
					);
			
			if( evt & (AcctStop | AcctUpdate) ) {
				tm = call->GetConnectTime();
				if( tm != 0 )		
					*pdu += new RadiusAttr(
						PString("h323-connect-time=") + AsString(tm),
						CiscoVendorId, 28
						);
			}
			
			if( evt & AcctStop ) {
				tm = call->GetDisconnectTime();
				if( tm != 0 )
					*pdu += new RadiusAttr(
						PString("h323-disconnect-time=") + AsString(tm),
						CiscoVendorId, 29
						);
				
				*pdu += new RadiusAttr(
					PString("h323-disconnect-cause=") 
						+ PString( PString::Unsigned, (long)(call->GetDisconnectCause()), 16 ),
					CiscoVendorId, 30
					);
			}					
			
			if( call->GetDestSignalAddr(addr,port) )
				*pdu += new RadiusAttr(
					PString("h323-remote-address=") + addr.AsString(),
					CiscoVendorId, 23
					);

			*pdu += new RadiusAttr(PString("h323-ivr-out=h323-call-id:") 
				+ GetGUIDString(call->GetCallIdentifier().m_guid),
				CiscoVendorId, 1
				);
		}
	
		*pdu += new RadiusAttr( RadiusAttr::AcctDelayTime, 0 );
	}
		
	// send request and wait for response
	RadiusPDU* response = NULL;
	bool result = OnSendPDU(*pdu,evt,call);
	
	// accounting updates must be fast, so we are just sending
	// the request to the server and are not waiting for a response
	if( result )
		if( evt & AcctUpdate )
			result = m_radiusClient->SendRequest( *pdu );
		else
			result = m_radiusClient->MakeRequest( *pdu, response ) && (response != NULL);
			
	delete pdu;
			
	if( !result ) {
		delete response;
		return Fail;
	}
				
	if( response ) {
		// check if Access-Request has been accepted
		result = (response->GetCode() == RadiusPDU::AccountingResponse);
		if( result )
			result = OnReceivedPDU(*response,evt,call);
		else
			PTRACE(4,"RADACCT\t"<<GetName()<<" - received response is not "
				" an AccountingResponse, event "<<evt<<", call no. "
				<<(call?call->GetCallNumber():0)
				);
		delete response;
	}
	return result ? Ok : Fail;
}

bool RadAcct::OnSendPDU(
	RadiusPDU& /*pdu*/,
	GkAcctLogger::AcctEvent /*evt*/,
	callptr& /*call*/
	)
{
	return true;
}

bool RadAcct::OnReceivedPDU(
	RadiusPDU& /*pdu*/,
	GkAcctLogger::AcctEvent /*evt*/,
	callptr& /*call*/
	)
{
	return true;
}

namespace {
	// append RADIUS based accounting logger to the global list of loggers
	GkAcctLoggerCreator<RadAcct> RadAcctCreator("RadAcct");
}

#endif /* HAS_RADIUS */
