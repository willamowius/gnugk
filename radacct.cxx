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
 * Revision 1.12  2004/07/26 12:19:41  zvision
 * New faster Radius implementation, thanks to Pavel Pavlov for ideas!
 *
 * Revision 1.11.2.2  2004/07/07 23:11:07  zvision
 * Faster and more elegant handling of Cisco VSA
 *
 * Revision 1.11.2.1  2004/07/07 20:50:14  zvision
 * New, faster, Radius client implementation. Thanks to Pavel Pavlov for ideas!
 *
 * Revision 1.11  2004/06/25 13:33:18  zvision
 * Better Username, Calling-Station-Id and Called-Station-Id handling.
 * New SetupUnreg option in Gatekeeper::Auth section.
 *
 * Revision 1.10  2004/06/17 10:47:13  zvision
 * New h323-ivr-out=h323-call-id accounting attribute
 *
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
	m_radiusClient(NULL),
	m_attrH323CallOrigin(RadiusAttr::CiscoVSA_h323_call_origin, false,
		PString("proxy")),
	m_attrH323CallType(RadiusAttr::CiscoVSA_h323_call_type, false, 
		PString("VoIP"))
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
	m_fixedUsername = cfg->GetString(cfgSec, "FixedUsername", "");

	m_timestampFormat = cfg->GetString(cfgSec, "TimestampFormat", "");
	
	m_attrNasIdentifier = RadiusAttr(RadiusAttr::NasIdentifier, m_nasIdentifier);
	m_attrH323GwId = RadiusAttr(RadiusAttr::CiscoVSA_h323_gw_id, false, m_nasIdentifier);
}

RadAcct::~RadAcct()
{
	delete m_radiusClient;
}

GkAcctLogger::Status RadAcct::Log(
	GkAcctLogger::AcctEvent evt, 
	const callptr& call
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

	if ((evt & (AcctStart | AcctStop | AcctUpdate)) && (!call)) {
		PTRACE(1,"RADACCT\t"<<GetName()<<" - missing call info for event"<<evt);
		return Fail;
	}
	
	// build RADIUS Accounting-Request
	RadiusPDU* const pdu = new RadiusPDU(RadiusPDU::AccountingRequest);

	pdu->AppendAttr(RadiusAttr::AcctStatusType, 
		(evt & AcctStart) ? RadiusAttr::AcctStatus_Start
		: ((evt & AcctStop) ? RadiusAttr::AcctStatus_Stop
		: ((evt & AcctUpdate) ? RadiusAttr::AcctStatus_InterimUpdate
		: ((evt & AcctOn) ? RadiusAttr::AcctStatus_AccountingOn
		: ((evt & AcctOff) ? RadiusAttr::AcctStatus_AccountingOff : 0)
		))));

	PIPSocket::Address addr;
	WORD port;
					
	// Gk works as NAS point, so append NAS IP
	pdu->AppendAttr(RadiusAttr::NasIpAddress, m_nasIpAddress);
	pdu->AppendAttr(m_attrNasIdentifier);
	pdu->AppendAttr(RadiusAttr::NasPortType, RadiusAttr::NasPort_Virtual);
		
	if (evt & (AcctStart | AcctStop | AcctUpdate)) {
		pdu->AppendAttr(RadiusAttr::ServiceType, RadiusAttr::ST_Login);
		pdu->AppendAttr(RadiusAttr::AcctSessionId, call->GetAcctSessionId());

		endptr callingEP = call->GetCallingParty();
		PIPSocket::Address callerIP(0);
		WORD callerPort = 0;		
		
		call->GetSrcSignalAddr(callerIP, callerPort);

		const PString username = GetUsername(call);
		if (username.IsEmpty() && m_fixedUsername.IsEmpty())
			PTRACE(3,"RADACCT\t"<<GetName()<<" could not determine User-Name"
				<<" for the call no. "<<call->GetCallNumber()
				);
		else
			pdu->AppendAttr(RadiusAttr::UserName, 
				m_fixedUsername.IsEmpty() ? username : m_fixedUsername
				);
		
		if (callerIP.IsValid())
			pdu->AppendAttr(RadiusAttr::FramedIpAddress, callerIP);
		
		if ((evt & AcctStart) == 0)
			pdu->AppendAttr(RadiusAttr::AcctSessionTime, call->GetDuration());
	
		PString stationId = GetCallingStationId(call);
		if (!stationId)
			pdu->AppendAttr(RadiusAttr::CallingStationId, stationId);
		else
			PTRACE(3,"RADACCT\t"<<GetName()<<" could not determine"
				<<" Calling-Station-Id for the call "<<call->GetCallNumber()
				);

		stationId = GetCalledStationId(call);
		if (!stationId)
			pdu->AppendAttr(RadiusAttr::CalledStationId, stationId);
		else
			PTRACE(3,"RADACCT\t"<<GetName()<<" could not determine"
				<<" Called-Station-Id for the call no. "<<call->GetCallNumber()
				);
		
		if (m_appendCiscoAttributes) {
			pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_conf_id,
				GetGUIDString(call->GetConferenceIdentifier())
				);
						
			pdu->AppendAttr(m_attrH323GwId);
			pdu->AppendAttr(m_attrH323CallOrigin);
			pdu->AppendAttr(m_attrH323CallType);

			Toolkit* const toolkit = Toolkit::Instance();
				
			time_t tm = call->GetSetupTime();
			if (tm != 0)
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_setup_time,
					toolkit->AsString(PTime(tm), m_timestampFormat)
					);
			
			if (evt & (AcctStop | AcctUpdate)) {
				tm = call->GetConnectTime();
				if (tm != 0)
					pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_connect_time,
						toolkit->AsString(PTime(tm), m_timestampFormat)
						);
			}
			
			if (evt & AcctStop) {
				tm = call->GetDisconnectTime();
				if (tm != 0)
					pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_disconnect_time,
						toolkit->AsString(PTime(tm), m_timestampFormat)
						);
				
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_disconnect_cause,
					PString(PString::Unsigned, (long)(call->GetDisconnectCause()), 16)
					);
			}					
			
			if (call->GetDestSignalAddr(addr,port))
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_remote_address,
					addr.AsString()
					);

			pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
				PString("h323-ivr-out=h323-call-id:") 
					+ GetGUIDString(call->GetCallIdentifier().m_guid),
				true
				);
		}
	
		pdu->AppendAttr(RadiusAttr::AcctDelayTime, 0);
	}
		
	// send request and wait for response
	RadiusPDU* response = NULL;
	bool result = OnSendPDU(*pdu, evt, call);
	
	// accounting updates must be fast, so we are just sending
	// the request to the server and are not waiting for a response
	if (result)
		if (evt & AcctUpdate)
			result = m_radiusClient->SendRequest(*pdu);
		else
			result = m_radiusClient->MakeRequest(*pdu, response) && (response != NULL);
			
	delete pdu;
			
	if (!result) {
		delete response;
		return Fail;
	}
				
	if (response) {
		// check if Access-Request has been accepted
		result = (response->GetCode() == RadiusPDU::AccountingResponse);
		if (result)
			result = OnReceivedPDU(*response, evt, call);
		else
			PTRACE(4, "RADACCT\t" << GetName() << " - received response is not "
				" an AccountingResponse, event " << evt << ", call no. "
				<< (call ? call->GetCallNumber() : 0)
				);
		delete response;
	}
	return result ? Ok : Fail;
}

bool RadAcct::OnSendPDU(
	RadiusPDU& /*pdu*/,
	GkAcctLogger::AcctEvent /*evt*/,
	const callptr& /*call*/
	)
{
	return true;
}

bool RadAcct::OnReceivedPDU(
	RadiusPDU& /*pdu*/,
	GkAcctLogger::AcctEvent /*evt*/,
	const callptr& /*call*/
	)
{
	return true;
}

namespace {
	// append RADIUS based accounting logger to the global list of loggers
	GkAcctLoggerCreator<RadAcct> RadAcctCreator("RadAcct");
}

#endif /* HAS_RADIUS */
