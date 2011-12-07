/*
 * radacct.cxx
 *
 * RADIUS protocol accounting logger module for GNU Gatekeeper. 
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 * Copyright (c) 2005-2011, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"

#if HAS_RADIUS

#include <ptlib.h>
#include <h323pdu.h>
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "radproto.h"
#include "radacct.h"

using std::vector;


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
	UnmapIPv4Address(m_nasIpAddress);
	if (m_nasIpAddress == GNUGK_INADDR_ANY) {
		vector<PIPSocket::Address> interfaces;
		Toolkit::Instance()->GetGKHome(interfaces);
		if (!interfaces.empty())
			m_nasIpAddress = interfaces.front();
		else
			PTRACE(1, "RADACCT\t" << GetName() << " cannot determine "
				" NAS IP address");
	}

	m_appendCiscoAttributes = Toolkit::AsBool(cfg->GetString(cfgSec, "AppendCiscoAttributes", "1"));
	m_fixedUsername = cfg->GetString(cfgSec, "FixedUsername", "");
	m_timestampFormat = cfg->GetString(cfgSec, "TimestampFormat", "");
	m_useDialedNumber = Toolkit::AsBool(cfg->GetString(cfgSec, "UseDialedNumber", "0"));
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
		PTRACE(1,"RADACCT\t"<<GetName()<<" - missing call info for event "<<evt);
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
					
	// Gk works as NAS point, so append NAS IP
	if (m_nasIpAddress.GetVersion() == 6)
		pdu->AppendAttr(RadiusAttr::NasIpv6Address, m_nasIpAddress);
	else
		pdu->AppendAttr(RadiusAttr::NasIpAddress, m_nasIpAddress);
	pdu->AppendAttr(m_attrNasIdentifier);
	pdu->AppendAttr(RadiusAttr::NasPortType, RadiusAttr::NasPort_Virtual);
		
	if (evt & (AcctStart | AcctStop | AcctUpdate)) {
		pdu->AppendAttr(RadiusAttr::ServiceType, RadiusAttr::ST_Login);
		pdu->AppendAttr(RadiusAttr::AcctSessionId, call->GetAcctSessionId());
		
		PBYTEArray classAttr(call->GetRADIUSClass());
		if (classAttr.GetSize() > 0)
			pdu->AppendAttr(RadiusAttr::AttrTypeClass, (const BYTE*)classAttr, classAttr.GetSize());

		endptr callingEP = call->GetCallingParty();
		PIPSocket::Address callerIP(0);
		WORD callerPort = 0;		
		
		call->GetSrcSignalAddr(callerIP, callerPort);

		const PString username = GetUsername(call);
		if (username.IsEmpty() && m_fixedUsername.IsEmpty())
			PTRACE(3, "RADACCT\t" << GetName() << " could not determine User-Name"
				<< " for the call no. " << call->GetCallNumber());
		else
			pdu->AppendAttr(RadiusAttr::UserName, 
				m_fixedUsername.IsEmpty() ? username : m_fixedUsername);
		
		if (callerIP.IsValid())
			pdu->AppendAttr(RadiusAttr::FramedIpAddress, callerIP);
		
		if ((evt & AcctStart) == 0)
			pdu->AppendAttr(RadiusAttr::AcctSessionTime, (long)call->GetDuration());
	
		PString stationId = GetCallingStationId(call);
		if (!stationId)
			pdu->AppendAttr(RadiusAttr::CallingStationId, stationId);
		else
			PTRACE(3, "RADACCT\t" << GetName() << " could not determine"
				<< " Calling-Station-Id for the call " << call->GetCallNumber());

		stationId = m_useDialedNumber ? GetDialedNumber(call) : GetCalledStationId(call);
		if (!stationId)
			pdu->AppendAttr(RadiusAttr::CalledStationId, stationId);
		else
			PTRACE(3, "RADACCT\t" << GetName() << " could not determine"
				<< " Called-Station-Id for the call no. " << call->GetCallNumber());
		
		if (m_appendCiscoAttributes) {
			pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_conf_id,
				GetGUIDString(call->GetConferenceIdentifier())
				);
						
			pdu->AppendAttr(m_attrH323GwId);
			pdu->AppendAttr(m_attrH323CallOrigin);
			pdu->AppendAttr(m_attrH323CallType);

			Toolkit * const toolkit = Toolkit::Instance();
				
			time_t tm = call->GetSetupTime();
			if (tm != 0)
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_setup_time,
					toolkit->AsString(PTime(tm), m_timestampFormat));
			
			if (evt & (AcctStop | AcctUpdate)) {
				tm = call->GetConnectTime();
				if (tm != 0)
					pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_connect_time,
						toolkit->AsString(PTime(tm), m_timestampFormat));
			}
			
			if (evt & AcctStop) {
				tm = call->GetDisconnectTime();
				if (tm != 0)
					pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_disconnect_time,
						toolkit->AsString(PTime(tm), m_timestampFormat));
				
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_disconnect_cause,
					PString(PString::Unsigned, (long)(call->GetDisconnectCause()), 16)
					);
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_release_source,call->GetReleaseSource());
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_preferred_codec,call->GetCodec());
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_rewritten_e164_num,call->GetCalledStationId());

				// Post Dial Delay Time
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
					PString("h323pddtime=")+PString(PString::Unsigned,(long)call->GetPostDialDelay()),true);

				// Ring Time
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
					PString("h323ringtime=")+PString(PString::Unsigned,(long)call->GetRingTime()),true);

				// Number of Route Attempts
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
					PString("h323routeattempts=")+PString(PString::Unsigned,call->GetNoCallAttempts()),
					true);
				
				// Proxy Mode
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
					PString("h323_rtp_proxy=")+PString(PString::Unsigned,
					((call->GetProxyMode() == CallRec::ProxyEnabled) ? 1 : 0)), true);

				// RTCP SOURCE REPORT
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
				    PString("RTP_source_IP=")+call->GetSRC_media_IP(),
					true);
				
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
				    PString("RTP_destination_IP=")+call->GetDST_media_IP(),
					true);
				
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
				    PString("RTCP_source_packet_count=")+PString(PString::Unsigned, call->GetRTCP_SRC_packet_count()),
					true);
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
				    PString("RTCP_source_packet_lost=")+PString(PString::Unsigned, call->GetRTCP_SRC_packet_lost()),
				    true);
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
				    PString("RTCP_source_jitter=")+PString(PString::Unsigned, call->GetRTCP_SRC_jitter_min())+PString("|")+PString(PString::Unsigned,call->GetRTCP_SRC_jitter_avg())+PString("|")+PString(PString::Unsigned, call->GetRTCP_SRC_jitter_max()),
				    true);
				
				PINDEX i_sdes = 0;
				PStringList sdes = call->GetRTCP_SRC_sdes();
				while (i_sdes < sdes.GetSize()) {
				    pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
						PString("RTCP_source_sdes_")+sdes[i_sdes],
						true);
				    i_sdes ++;
				}
				// RTCP DESTINATION REPORT
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
				    PString("RTCP_destination_packet_count=")+PString(PString::Unsigned, call->GetRTCP_DST_packet_count()),
				    true);
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
				    PString("RTCP_destination_packet_lost=")+PString(PString::Unsigned, call->GetRTCP_DST_packet_lost()),
				    true);
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
				    PString("RTCP_destination_jitter=")+PString(PString::Unsigned,call->GetRTCP_DST_jitter_min())+PString("|")+PString(PString::Unsigned, call->GetRTCP_DST_jitter_avg())+PString("|")+PString(PString::Unsigned, call->GetRTCP_DST_jitter_max()),
				    true);
				i_sdes = 0;
				sdes = call->GetRTCP_DST_sdes();
				while (i_sdes < sdes.GetSize()) {
				    pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
						PString("RTCP_destination_sdes_")+sdes[i_sdes],
						true);
				    i_sdes ++;
				}
			}					

			WORD port;
			if (call->GetDestSignalAddr(addr, port))
				pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_h323_remote_address,
					addr.AsString());

			pdu->AppendCiscoAttr(RadiusAttr::CiscoVSA_AV_Pair,
				PString("h323-ivr-out=h323-call-id:") + GetGUIDString(call->GetCallIdentifier().m_guid),
				true);
			
		}
	
		pdu->AppendAttr(RadiusAttr::AcctDelayTime, 0);
	}
		
	// send request and wait for response
	RadiusPDU * response = NULL;
	bool result = true;

	// accounting updates must be fast, so we are just sending
	// the request to the server and are not waiting for a response
	if (evt & AcctUpdate) {
		result = m_radiusClient->SendRequest(*pdu);
	} else {
		result = m_radiusClient->MakeRequest(*pdu, response) && (response != NULL);
	}
			
	delete pdu;

	if (!result) {
		delete response;
		return Fail;
	}
				
	if (response) {
		// check if Access-Request has been accepted
		result = (response->GetCode() == RadiusPDU::AccountingResponse);
		if (!result) {
			PTRACE(4, "RADACCT\t" << GetName() << " - received response is not "
				" an AccountingResponse, event " << evt << ", call no. "
				<< (call ? call->GetCallNumber() : 0));
		}
		delete response;
	}
	return result ? Ok : Fail;
}

namespace {
	// append RADIUS based accounting logger to the global list of loggers
	GkAcctLoggerCreator<RadAcct> RadAcctCreator("RadAcct");
}

#endif /* HAS_RADIUS */
