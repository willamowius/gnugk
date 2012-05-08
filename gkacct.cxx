/*
 * gkacct.cxx
 *
 * Accounting modules for GNU Gatekeeper. Provides generic
 * support for accounting to the gatekeeper.
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 * Copyright (c) 2005-2012, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include <ptlib.h>
#include <h225.h>
#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "Toolkit.h"
#include "gktimer.h"
#include "snmp.h"
#include "gkacct.h"

using std::find;
using std::vector;

/// Name of the config file section for accounting configuration
namespace {
const char* GkAcctSectionName = "Gatekeeper::Acct";
}

extern const char* CallTableSection;


GkAcctLogger::GkAcctLogger(
	const char* moduleName,
	const char* cfgSecName
	)
	: NamedObject(moduleName), m_controlFlag(Required), m_defaultStatus(Fail),
	m_enabledEvents(AcctAll), m_supportedEvents(AcctNone), m_config(GkConfig()),
	m_configSectionName(cfgSecName)
{
	if (m_configSectionName.IsEmpty())
		m_configSectionName = moduleName;
		
	const PStringArray control(
		m_config->GetString(GkAcctSectionName, moduleName, "").Tokenise(";,")
		);

	if (control.GetSize() < 1)
		PTRACE(1, "GKACCT\tEmpty config entry for module " << moduleName);
	else if (strcasecmp(moduleName, "default") == 0) {
		m_controlFlag = Required;
		m_defaultStatus = Toolkit::AsBool(control[0]) ? Ok : Fail;
		m_supportedEvents = AcctAll;
	} else if (control[0] *= "optional")
		m_controlFlag = Optional;
	else if (control[0] *= "sufficient")
		m_controlFlag = Sufficient;
	else if (control[0] *= "alternative")
		m_controlFlag = Alternative;
	
	if (control.GetSize() > 1)
		m_enabledEvents = GetEvents(control);
	
	PTRACE(1, "GKACCT\tCreated module " << moduleName << " with event mask "
		<< PString(PString::Unsigned, (long)m_enabledEvents, 16)
		);
}

GkAcctLogger::~GkAcctLogger()
{
	PTRACE(1,"GKACCT\tDestroyed module "<<GetName());
}

int GkAcctLogger::GetEvents(
	const PStringArray& tokens
	) const
{
	int mask = 0;
	
	for( PINDEX i = 1; i < tokens.GetSize(); i++ ) {
		const PString& token = tokens[i];
		if( token *= "start" )
			mask |= AcctStart;
		else if( token *= "stop" )
			mask |= AcctStop;
		else if( token *= "update" )
			mask |= AcctUpdate;
		else if( token *= "alert" )
			mask |= AcctAlert;
		else if( token *= "connect" )
			mask |= AcctConnect;
		else if( token *= "register" )
			mask |= AcctRegister;
		else if( token *= "unregister" )
			mask |= AcctUnregister;
		else if( token *= "on" )
			mask |= AcctOn;
		else if( token *= "off" )
			mask |= AcctOff;
	}
	
	return mask;
}

GkAcctLogger::Status GkAcctLogger::Log(
	AcctEvent evt, /// accounting event to log
	const callptr& /*call*/ /// a call associated with the event (if any)
	)
{
	return (evt & m_enabledEvents & m_supportedEvents) ? m_defaultStatus : Next;
}

GkAcctLogger::Status GkAcctLogger::Log(
	AcctEvent evt, /// accounting event to log
	const endptr& /*ep*/ /// endpoint associated with the event (if any)
	)
{
	return (evt & m_enabledEvents & m_supportedEvents) ? m_defaultStatus : Next;
}

void GkAcctLogger::SetupAcctParams(
	/// CDR parameters (name => value) associations
	std::map<PString, PString>& params,
	/// call (if any) associated with an accounting event being logged
	const callptr& call,
	/// timestamp formatting string
	const PString& timestampFormat
	) const
{
	PIPSocket::Address addr;
	WORD port = 0;
	time_t t;
	vector<PIPSocket::Address> interfaces;
	Toolkit* const toolkit = Toolkit::Instance();
	toolkit->GetGKHome(interfaces);

	params["g"] = toolkit->GKName();
	params["n"] = PString(call->GetCallNumber());
	params["u"] = GetUsername(call);
	params["d"] = call->GetDuration();
	params["c"] = call->GetDisconnectCause();
	params["cause-translated"] = call->GetDisconnectCauseTranslated();
	params["s"] = call->GetAcctSessionId();
	params["p"] = call->GetPostDialDelay();
	params["r"] = call->GetReleaseSource();
	params["t"] = call->GetTotalCallDuration();
	if (interfaces.empty())
		params["gkip"] = "";
	else
		params["gkip"] = interfaces.front().AsString();
	params["CallId"] = ::AsString(call->GetCallIdentifier().m_guid);
	params["ConfId"] = ::AsString(call->GetConferenceIdentifier());
	params["CallLink"] = call->GetCallLinkage();
	
	t = call->GetSetupTime();
	if (t)
		params["setup-time"] = toolkit->AsString(PTime(t), timestampFormat);
	t = call->GetAlertingTime();
	if (t)
		params["alerting-time"] = toolkit->AsString(PTime(t), timestampFormat);
	t = call->GetConnectTime();
	if (t)
		params["connect-time"] = toolkit->AsString(PTime(t), timestampFormat);
	t = call->GetDisconnectTime();
	if (t)
		params["disconnect-time"] = toolkit->AsString(PTime(t), timestampFormat);
	params["ring-time"] = call->GetRingTime();

	if (call->GetSrcSignalAddr(addr, port)) {
		params["caller-ip"] = addr.AsString();
		params["caller-port"] = port;
	}
	
	params["src-info"] = call->GetSrcInfo();
	params["Calling-Station-Id"] = GetCallingStationId(call);
		
	addr = (DWORD)0;
	port = 0;
		
	if (call->GetDestSignalAddr(addr, port)) {
		params["callee-ip"] = addr.AsString();
		params["callee-port"] = port;
	}

	params["dest-info"] = call->GetDestInfo();
	params["Called-Station-Id"] = GetCalledStationId(call);
	params["Dialed-Number"] = GetDialedNumber(call);

	endptr caller;
	if ((caller = call->GetCallingParty())) {
		params["caller-epid"] = caller->GetEndpointIdentifier().GetValue();
	}
	endptr callee;
	if ((callee = call->GetCalledParty())) {
		params["callee-epid"] = callee->GetEndpointIdentifier().GetValue();
	}
	params["call-attempts"] = PString(call->GetNoCallAttempts());
	params["last-cdr"] = call->GetNoRemainingRoutes() > 0 ? "0" : "1";

	if ((call->GetMediaOriginatingIp(addr)))
		params["media-oip"] = addr.AsString();
	params["codec"] = call->GetCodec();
	params["bandwidth"] = call->GetBandwidth();
	params["client-auth-id"] = call->GetClientAuthId();
}

void GkAcctLogger::SetupAcctEndpointParams(
	/// parameter (name => value) associations
	std::map<PString, PString>& params,
	/// endpoint associated with an accounting event being logged
	const endptr& ep
	) const
{
	PIPSocket::Address addr;
	WORD port = 0;

	H225_TransportAddress sigip = ep->GetCallSignalAddress();
	if (GetIPAndPortFromTransportAddr(sigip, addr, port)) {
		params["endpoint-ip"] = addr.AsString();
		params["endpoint-port"] = port;
	}

	PString aliasString = AsString(ep->GetAliases(), false);
	aliasString.Replace(PString("="), PString(","), true);	// make list comma separated
	params["aliases"] = aliasString;

	// The username is always the last in the Alias List
	PStringArray aliasList = aliasString.Tokenise(",");
    if (aliasList.GetSize() > 0)
	    params["u"] = aliasList[aliasList.GetSize()-1];

	params["epid"] = ep->GetEndpointIdentifier().GetValue();
	params["g"] = Toolkit::GKName();
}

// avoid warning in PTLib object.h
#if (!_WIN32) && (GCC_VERSION >= 40400)
#pragma GCC diagnostic ignored "-Wstrict-overflow"
#endif

PString GkAcctLogger::ReplaceAcctParams(
	/// parametrized CDR string
	const PString& cdrStr,
	/// parameter values
	const std::map<PString, PString>& params
	) const
{
	PString finalCDR((const char*)cdrStr);
	PINDEX len = finalCDR.GetLength();
	PINDEX pos = 0;

	while (pos != P_MAX_INDEX && pos < len) {
		pos = finalCDR.Find('%', pos);
		if (pos++ == P_MAX_INDEX)
			break;
		if (pos >= len) // strings ending with '%' - special case
			break;
		const char c = finalCDR[pos]; // char next after '%'
		if (c == '%') { // replace %% with %
			finalCDR.Delete(pos, 1);
			len--;
		} else if (c == '{') { // escaped syntax (%{Name})
			const PINDEX closingBrace = finalCDR.Find('}', ++pos);
			if (closingBrace != P_MAX_INDEX) {
				const PINDEX paramLen = closingBrace - pos;
				std::map<PString, PString>::const_iterator i = params.find(
					finalCDR.Mid(pos, paramLen)
					);
				if (i != params.end()) {
					const PINDEX escapedLen = EscapeAcctParam(i->second).GetLength();
					finalCDR.Splice(EscapeAcctParam(i->second), pos - 2, paramLen + 3);
					len = len + escapedLen - paramLen - 3;
					pos = pos - 2 + escapedLen;
				} else {
					// replace out of range parameter with an empty string
					finalCDR.Delete(pos - 2, paramLen + 3);
					len -= paramLen + 3;
					pos -= 2;
				}
			}
		} else { // simple syntax (%c)
			std::map<PString, PString>::const_iterator i = params.find(c);
			if (i != params.end()) {
				const PINDEX escapedLen = EscapeAcctParam(i->second).GetLength();
				finalCDR.Splice(EscapeAcctParam(i->second), pos - 1, 2);
				len = len + escapedLen - 2;
				pos = pos - 1 + escapedLen;
			} else {
				// replace out of range parameter with an empty string
				finalCDR.Delete(pos - 1, 2);
				len -= 2;
				pos--;
			}
		}
	}

	return finalCDR;
}

PString GkAcctLogger::EscapeAcctParam(const PString& param) const
{
	return param;	// default implementation: don't escape anything
}

PString GkAcctLogger::GetUsername(
	/// call (if any) associated with the RAS message
	const callptr& call
	) const
{
	if (!call)
		return PString::Empty();
		
	const endptr callingEP = call->GetCallingParty();
	PString username;
		
	username = GetBestAliasAddressString(call->GetSourceAddress(), true,
		AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
		AliasAddressTagMask(H225_AliasAddress::e_email_ID)
			| AliasAddressTagMask(H225_AliasAddress::e_url_ID)
		);
			
	if (callingEP && (username.IsEmpty()
			|| FindAlias(callingEP->GetAliases(), username) == P_MAX_INDEX))
		username = GetBestAliasAddressString(callingEP->GetAliases(), false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID)
			);
		
	if (username.IsEmpty())
		username = GetBestAliasAddressString(call->GetSourceAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID)
			);

	if (username.IsEmpty())
		username = call->GetCallingStationId();

	if (username.IsEmpty()) {
		PIPSocket::Address callingSigAddr;
		WORD callingSigPort;
		if (call->GetSrcSignalAddr(callingSigAddr, callingSigPort)
			&& callingSigAddr.IsValid())
			username = callingSigAddr.AsString();
	}
	
	return username;
}

PString GkAcctLogger::GetCallingStationId(
	/// call associated with the accounting event
	const callptr& call
	) const
{
	if (!call)
		return PString::Empty();

	PString id = call->GetCallingStationId();
	if (!id)
		return id;

	if (id.IsEmpty())
		id = GetBestAliasAddressString(call->GetSourceAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);
				
	if (id.IsEmpty()) {
		const endptr callingEP = call->GetCallingParty();
		if (callingEP)
			id = GetBestAliasAddressString(callingEP->GetAliases(), false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
	}
					
	if (id.IsEmpty()) {
		PIPSocket::Address callingSigAddr;
		WORD callingSigPort = 0;
		if (call->GetSrcSignalAddr(callingSigAddr, callingSigPort)
			&& callingSigAddr.IsValid())
			id = ::AsString(callingSigAddr, callingSigPort);
	}
	
	return id;
}

PString GkAcctLogger::GetCalledStationId(
	/// call associated with the accounting event
	const callptr& call
	) const
{
	if (!call)
		return PString::Empty();

	PString id = call->GetCalledStationId();
	if (!id)
		return id;
			
	if (id.IsEmpty())
		id = GetBestAliasAddressString(call->GetDestinationAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);
		
	if (id.IsEmpty()) {
		const endptr calledEP = call->GetCalledParty();
		if (calledEP)
			id = GetBestAliasAddressString(calledEP->GetAliases(), false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
	}
	
	if (id.IsEmpty()) {
		PIPSocket::Address calledSigAddr;
		WORD calledSigPort = 0;
		if (call->GetDestSignalAddr(calledSigAddr, calledSigPort)
		 	&& calledSigAddr.IsValid())
			id = ::AsString(calledSigAddr, calledSigPort);
	}
	
	return id;
}

PString GkAcctLogger::GetDialedNumber(
	/// call associated with the accounting event
	const callptr& call
	) const
{
	if (!call)
		return PString::Empty();

	PString id = call->GetDialedNumber();
	if (!id)
		return id;
			
	if (id.IsEmpty())
		id = GetBestAliasAddressString(call->GetDestinationAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);
		
	if (id.IsEmpty()) {
		const endptr calledEP = call->GetCalledParty();
		if (calledEP)
			id = GetBestAliasAddressString(calledEP->GetAliases(), false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
	}
	
	if (id.IsEmpty()) {
		PIPSocket::Address calledSigAddr;
		WORD calledSigPort = 0;
		if (call->GetDestSignalAddr(calledSigAddr, calledSigPort)
		 	&& calledSigAddr.IsValid())
			id = ::AsString(calledSigAddr, calledSigPort);
	}
	
	return id;
}

PString GkAcctLogger::GetInfo()
{
	return "No information available\r\n";
}

const char* const FileAcct::m_intervalNames[] =
{
	"Hourly", "Daily", "Weekly", "Monthly"
};

FileAcct::FileAcct(
	const char* moduleName,
	const char* cfgSecName
	)
	:
	GkAcctLogger(moduleName, cfgSecName),
	m_cdrFile(NULL), m_rotateLines(-1), m_rotateSize(-1), m_rotateInterval(-1),
	m_rotateMinute(-1), m_rotateHour(-1), m_rotateDay(-1),
	m_rotateTimer(GkTimerManager::INVALID_HANDLE), m_cdrLines(0),
	m_standardCDRFormat(true)
{
	SetSupportedEvents(FileAcctEvents);
	
	m_cdrString = GetConfig()->GetString(GetConfigSectionName(), "CDRString", "");
	m_standardCDRFormat = Toolkit::AsBool(
		GetConfig()->GetString(GetConfigSectionName(), "StandardCDRFormat",
			m_cdrString.IsEmpty() ? "1" : "0"
			));
	m_timestampFormat = GetConfig()->GetString(GetConfigSectionName(),
		"TimestampFormat", ""
		);
		
	// determine rotation type (by lines, by size, by time)	
	const PString rotateCondition = GetConfig()->GetString(
		GetConfigSectionName(), "Rotate", ""
		).Trim();
	if (!rotateCondition) {
		const char suffix = rotateCondition[rotateCondition.GetLength()-1];
		if (rotateCondition[0] == 'L' || rotateCondition[0] == 'l') {
			// rotate per number of lines
			m_rotateLines = rotateCondition.Mid(1).AsInteger();
			if (suffix == 'k' || suffix == 'K')
				m_rotateLines *= 1000;
			else if (suffix == 'm' || suffix == 'M')
				m_rotateLines *= 1000*1000;
		} else if (rotateCondition[0] == 'S' || rotateCondition[0] == 's') {
			// rotate per CDR file size
			m_rotateSize = rotateCondition.Mid(1).AsInteger();
			if (suffix == 'k' || suffix == 'K')
				m_rotateSize *= 1024;
			else if (suffix == 'm' || suffix == 'M')
				m_rotateSize *= 1024*1024;
		} else {
			for (int i = 0; i < RotationIntervalMax; i++)
				if (strcasecmp(rotateCondition, m_intervalNames[i]) == 0)
					m_rotateInterval = i;

			if (m_rotateInterval < 0 || m_rotateInterval >= RotationIntervalMax)
				PTRACE(1, "GKACCT\t" << GetName() << " unsupported rotation "
					"method: " << rotateCondition << " - rotation disabled"
					);
			else {
				// time based rotation
				GetRotateInterval(*GetConfig(), GetConfigSectionName());
			}
		}
	}

	m_cdrFilename = GetConfig()->GetString(GetConfigSectionName(), "DetailFile", "");
	m_cdrFile = OpenCDRFile(m_cdrFilename);
	if (m_cdrFile && m_cdrFile->IsOpen()) {
		PTRACE(2, "GKACCT\t" << GetName() << " CDR file: "
			<< m_cdrFile->GetFilePath()
			);
		// count an initial number of CDR lines
		if (m_rotateLines > 0) {
			PString s;
			m_cdrFile->SetPosition(0);
			while (m_cdrFile->ReadLine(s))
				m_cdrLines++;
			m_cdrFile->SetPosition(m_cdrFile->GetLength());
		}
	}

	// setup rotation timer in case of time based rotation
	PTime now, rotateTime;

	switch (m_rotateInterval)
	{
	case Hourly:
		rotateTime = PTime(0, m_rotateMinute, now.GetHour(), now.GetDay(),
			now.GetMonth(), now.GetYear(), now.GetTimeZone()
			);
		if (rotateTime <= now)
			rotateTime += PTimeInterval(0, 0, 0, 1); // 1 hour
		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			this, &FileAcct::RotateOnTimer, rotateTime, 60*60
			);
		PTRACE(5, "GKACCT\t" << GetName() << " hourly rotation enabled (first "
			"rotation scheduled at " << rotateTime
			);
		break;
		
	case Daily:
		rotateTime = PTime(0, m_rotateMinute, m_rotateHour, now.GetDay(),
			now.GetMonth(), now.GetYear(), now.GetTimeZone()
			);
		if (rotateTime <= now)
			rotateTime += PTimeInterval(0, 0, 0, 0, 1); // 1 day
		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			this, &FileAcct::RotateOnTimer, rotateTime, 60*60*24
			);
		PTRACE(5, "GKACCT\t" << GetName() << " daily rotation enabled (first "
			"rotation scheduled at " << rotateTime
			);
		break;
		
	case Weekly:
		rotateTime = PTime(0, m_rotateMinute, m_rotateHour, now.GetDay(),
			now.GetMonth(), now.GetYear(), now.GetTimeZone()
			);
		if (rotateTime.GetDayOfWeek() < m_rotateDay)
			rotateTime += PTimeInterval(0, 0, 0, 0,
				m_rotateDay - rotateTime.GetDayOfWeek()
				);
		else if (rotateTime.GetDayOfWeek() > m_rotateDay)
			rotateTime -= PTimeInterval(0, 0, 0, 0,
				rotateTime.GetDayOfWeek() - m_rotateDay
				);
		if (rotateTime <= now)
			rotateTime += PTimeInterval(0, 0, 0, 0, 7); // 1 week
		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			this, &FileAcct::RotateOnTimer, rotateTime, 60*60*24*7
			);
		PTRACE(5, "GKACCT\t" << GetName() << " weekly rotation enabled (first "
			"rotation scheduled at " << rotateTime
			);
		break;
		
	case Monthly:
		rotateTime = PTime(0, m_rotateMinute, m_rotateHour, 1,
			now.GetMonth(), now.GetYear(), now.GetTimeZone()
			);
		rotateTime += PTimeInterval(0, 0, 0, 0, m_rotateDay - 1);
		while (rotateTime.GetMonth() != now.GetMonth())				
			rotateTime -= PTimeInterval(0, 0, 0, 0, 1); // 1 day

		if (rotateTime <= now) {
			rotateTime = PTime(0, m_rotateMinute, m_rotateHour, 1,
				now.GetMonth() + (now.GetMonth() == 12 ? -11 : 1),
				now.GetYear() + (now.GetMonth() == 12 ? 1 : 0),
				now.GetTimeZone()
				);
			const int month = rotateTime.GetMonth();
			rotateTime += PTimeInterval(0, 0, 0, 0, m_rotateDay - 1);
			while (rotateTime.GetMonth() != month)				
				rotateTime -= PTimeInterval(0, 0, 0, 0, 1); // 1 day
		}

		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			this, &FileAcct::RotateOnTimer, rotateTime
			);
		PTRACE(5, "GKACCT\t" << GetName() << " monthly rotation enabled (first "
			"rotation scheduled at " << rotateTime
			);
		break;
	}
}

FileAcct::~FileAcct()
{
	if (m_rotateTimer != GkTimerManager::INVALID_HANDLE)
		Toolkit::Instance()->GetTimerManager()->UnregisterTimer(m_rotateTimer);
		
	PWaitAndSignal lock(m_cdrFileMutex);
	if (m_cdrFile) {
		m_cdrFile->Close();
		delete m_cdrFile;
	}
}

void FileAcct::GetRotateInterval(
	PConfig& cfg,
	const PString& section
	)
{
	PString s;
	
	if (m_rotateInterval == Hourly)
		m_rotateMinute = cfg.GetInteger(section, "RotateTime", 59);
	else {
		s = cfg.GetString(section, "RotateTime", "00:59");
		m_rotateHour = s.AsInteger();
		m_rotateMinute = 0;
		if (s.Find(':') != P_MAX_INDEX)
			m_rotateMinute = s.Mid(s.Find(':') + 1).AsInteger();
			
		if (m_rotateHour < 0 || m_rotateHour > 23 || m_rotateMinute < 0
			|| m_rotateMinute > 59) {
			PTRACE(1, "GKACCT\t" << GetName() << " invalid "
				"RotateTime specified: " << s
				);
			m_rotateMinute = 59;
			m_rotateHour = 0;
		}
	}
			
	if (m_rotateInterval == Weekly)	{
		s = cfg.GetString(section, "RotateDay", "Sun");
		if (strspn(s, "0123456") == (size_t)s.GetLength()) {
			m_rotateDay = s.AsInteger();
		} else {
			std::map<PCaselessString, int> dayNames;
			dayNames["sun"] = 0; dayNames["sunday"] = 0;
			dayNames["mon"] = 1; dayNames["monday"] = 1;
			dayNames["tue"] = 2; dayNames["tuesday"] = 2;
			dayNames["wed"] = 3; dayNames["wednesday"] = 3;
			dayNames["thu"] = 4; dayNames["thursday"] = 4;
			dayNames["fri"] = 5; dayNames["friday"] = 5;
			dayNames["sat"] = 6; dayNames["saturday"] = 6;
			std::map<PCaselessString, int>::const_iterator i = dayNames.find(s);
			m_rotateDay = (i != dayNames.end()) ? i->second : -1;
		}
		if (m_rotateDay < 0 || m_rotateDay > 6) {
			PTRACE(1, "GKACCT\t" << GetName() << " invalid "
				"RotateDay specified: " << s
				);
			m_rotateDay = 0;
		}
	} else if (m_rotateInterval == Monthly) {
		m_rotateDay = cfg.GetInteger(section, "RotateDay", 1);
		if (m_rotateDay < 1 || m_rotateDay > 31) {
			PTRACE(1, "GKACCT\t" << GetName() << " invalid "
				"RotateDay specified: " << cfg.GetString(section, "RotateDay", "")
				);
			m_rotateDay = 1;
		}
	}
}

GkAcctLogger::Status FileAcct::Log(
	GkAcctLogger::AcctEvent evt,
	const callptr& call
	)
{
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;
		
	if (!call) {
		PTRACE(1, "GKACCT\t" << GetName() << " - missing call info for event " << evt);
		return Fail;
	}
	
	PString cdrString;
	
	if (!GetCDRText(cdrString, evt, call)) {
		PTRACE(2, "GKACCT\t" << GetName() << " - unable to get CDR text for "
			"event " << evt << ", call no. " << call->GetCallNumber()
			);
		return Fail;
	}
	
	PWaitAndSignal lock(m_cdrFileMutex);
	
	if (m_cdrFile && m_cdrFile->IsOpen()) {
		if (m_cdrFile->WriteLine(PString(cdrString))) {
			PTRACE(5, "GKACCT\t" << GetName() << " - CDR string for event "
				<< evt << ", call no. " << call->GetCallNumber()
				<< ": " << cdrString
				);
			m_cdrLines++;
			if (IsRotationNeeded())
				Rotate();
			return Ok;
		} else
			PTRACE(1, "GKACCT\t" << GetName() << " - write CDR text for event "
				<< evt << ", call no. " << call->GetCallNumber()
				<< " failed: " << m_cdrFile->GetErrorText());
	} else
		PTRACE(1, "GKACCT\t" << GetName() << " - write CDR text for event "
			<< evt << ", for call no. " << call->GetCallNumber()
			<< " failed: CDR file is closed");

	SNMP_TRAP(6, SNMPError, Accounting, GetName() + " failed");
	return Fail;
}

bool FileAcct::GetCDRText(
	PString& cdrString,
	AcctEvent evt,
	const callptr& call
	)
{
	if ((evt & AcctStop) != AcctStop || !call)
		return false;
	
	if (m_standardCDRFormat)	
		cdrString = call->GenerateCDR(m_timestampFormat);
	else {
		std::map<PString, PString> params;

		SetupAcctParams(params, call, m_timestampFormat);
		cdrString = ReplaceAcctParams(m_cdrString, params);
	}	
	
	return !cdrString;
}

bool FileAcct::IsRotationNeeded()
{
	if (m_rotateLines > 0 && m_cdrLines >= m_rotateLines)
		return true;
	if (m_rotateSize > 0 && m_cdrFile && m_cdrFile->GetLength() >= m_rotateSize)
		return true;
	return false;
}

void FileAcct::RotateOnTimer(
	GkTimer* timer
	)
{
	if (m_rotateInterval == Monthly) {
		// setup next time for one-shot timer
		const PTime& rotateTime = timer->GetExpirationTime();
		PTime newRotateTime(rotateTime.GetSecond(), rotateTime.GetMinute(),
			rotateTime.GetHour(), 1,
			rotateTime.GetMonth() < 12 ? rotateTime.GetMonth() + 1 : 1,
			rotateTime.GetMonth() < 12 ? rotateTime.GetYear() : rotateTime.GetYear() + 1,
			rotateTime.GetTimeZone()
			);
	
		const int month = newRotateTime.GetMonth();
		newRotateTime += PTimeInterval(0, 0, 0, 0, m_rotateDay - 1);
		while (newRotateTime.GetMonth() != month)
			newRotateTime -= PTimeInterval(0, 0, 0, 0, 1);
		timer->SetExpirationTime(newRotateTime);
		timer->SetFired(false);
	}	
	PWaitAndSignal lock(m_cdrFileMutex);
	Rotate();
}

void FileAcct::Rotate()
{
	if (m_cdrFile) {
		if (m_cdrFile->IsOpen())
			m_cdrFile->Close();
		delete m_cdrFile;
		m_cdrFile = NULL;
	}
	
	const PFilePath fn = m_cdrFilename;
	
	if (PFile::Exists(fn)) {
		if (!PFile::Rename(fn, fn.GetFileName() + PTime().AsString(".yyyyMMdd-hhmmss"))) {
			PTRACE(1, "GKACCT\t" << GetName() << " rotate failed - could not "
				"rename the log file");
			SNMP_TRAP(6, SNMPError, Accounting, GetName() + " failed");
		}
	}

	m_cdrFile = OpenCDRFile(fn);
	m_cdrLines = 0;
}

PTextFile* FileAcct::OpenCDRFile(
	const PFilePath& fn
	)
{
	PTextFile* cdrFile = new PTextFile(fn, PFile::ReadWrite, 
		PFile::Create | PFile::DenySharedWrite
		);
	if (!cdrFile->IsOpen()) {
		PTRACE(1, "GKACCT\t" << GetName() << " could not open file"
			" required for plain text accounting \""
			<< fn << "\" :" << cdrFile->GetErrorText()
			);
		delete cdrFile;
		return NULL;
	}
	cdrFile->SetPermissions(PFileInfo::UserRead | PFileInfo::UserWrite);
	cdrFile->SetPosition(cdrFile->GetLength());
	return cdrFile;
}


GkAcctLoggerList::GkAcctLoggerList()
	: m_acctUpdateInterval(
		GkConfig()->GetInteger(CallTableSection, "AcctUpdateInterval", 0)
		)
{
	// should not be less than 10 seconds
	if (m_acctUpdateInterval)
		m_acctUpdateInterval = PMAX(10, m_acctUpdateInterval);
}

GkAcctLoggerList::~GkAcctLoggerList()
{
	DeleteObjectsInContainer(m_loggers);
	m_loggers.clear();
}

void GkAcctLoggerList::OnReload()
{
	m_acctUpdateInterval = GkConfig()->GetInteger(CallTableSection, 
		"AcctUpdateInterval", 0
		);
	// should not be less than 10 seconds
	if (m_acctUpdateInterval)
		m_acctUpdateInterval = PMAX(10, m_acctUpdateInterval);

	DeleteObjectsInContainer(m_loggers);
	m_loggers.clear();
	
	const PStringArray modules = GkConfig()->GetKeys(GkAcctSectionName);
	for (PINDEX i = 0; i < modules.GetSize(); i++) {
		GkAcctLogger* logger = Factory<GkAcctLogger>::Create(modules[i]);
		if (logger)
			m_loggers.push_back(logger);
	}
}

bool GkAcctLoggerList::LogAcctEvent( 
	GkAcctLogger::AcctEvent evt, /// the accounting event to be logged
	const callptr& call, /// a call associated with the event (if any)
	time_t now /// "now" timestamp for accounting update events
	)
{
	// if this is an accounting update, check the interval
	if (evt & GkAcctLogger::AcctUpdate) {
		if ((!call) || m_acctUpdateInterval == 0 
			|| (now - call->GetLastAcctUpdateTime()) < m_acctUpdateInterval) {
			return true;
		} else {
			call->SetLastAcctUpdateTime(now);
		}
	}
			
	bool finalResult = true;
	GkAcctLogger::Status status = GkAcctLogger::Ok;
	std::list<GkAcctLogger*>::const_iterator iter = m_loggers.begin();
	
	while (iter != m_loggers.end()) {
		GkAcctLogger* logger = *iter++;
	
		if ((evt & logger->GetEnabledEvents() & logger->GetSupportedEvents()) == 0)
			continue;
		
		status = logger->Log(evt, call);
		switch (status)
		{
		case GkAcctLogger::Ok:
			if (PTrace::CanTrace(3)) {
				ostream& strm = PTrace::Begin(3,__FILE__,__LINE__);
				strm << "GKACCT\t" << logger->GetName() << " logged event " << evt;
				if (call)
					strm << " for call no. " << call->GetCallNumber();
				PTrace::End(strm);
			}
			break;
			
		default:
			if (PTrace::CanTrace(3)) {
				ostream& strm = PTrace::Begin(3, __FILE__, __LINE__);
				strm << "GKACCT\t" << logger->GetName() << " failed to log event " << evt;
				SNMP_TRAP(7, SNMPError, Accounting, logger->GetName() + " failed");
				if (call)
					strm << " for call no. " << call->GetCallNumber();
				PTrace::End(strm);
			}
			// required and sufficient rules always determine 
			// status of the request
			if (logger->GetControlFlag() == GkAcctLogger::Required
				|| logger->GetControlFlag() == GkAcctLogger::Sufficient)
				finalResult = false;
		}
		
		// sufficient and alternative are terminal rules (on log success)
		if (status == GkAcctLogger::Ok 
			&& (logger->GetControlFlag() == GkAcctLogger::Sufficient
			|| logger->GetControlFlag() == GkAcctLogger::Alternative))
			break;
	}

	// a last rule determine status of the the request
	if (finalResult && status != GkAcctLogger::Ok)
		finalResult = false;
		
	if (PTrace::CanTrace(2)) {
		ostream& strm = PTrace::Begin(2, __FILE__, __LINE__);
		strm << "GKACCT\t" << (finalResult ? "Successfully logged event " 
			: "Failed to log event ") << evt;
		if (call)
			strm << " for call no. " << call->GetCallNumber();
		PTrace::End(strm);
		if (!finalResult)
			SNMP_TRAP(7, SNMPError, Accounting, "Failed to log event " + evt);
	}
	return finalResult;
}

bool GkAcctLoggerList::LogAcctEvent( 
	GkAcctLogger::AcctEvent evt, /// the accounting event to be logged
	const endptr& ep /// endpoint associated with the event
	)
{
	bool finalResult = true;
	GkAcctLogger::Status status = GkAcctLogger::Ok;
	std::list<GkAcctLogger*>::const_iterator iter = m_loggers.begin();
	
	while (iter != m_loggers.end()) {
		GkAcctLogger* logger = *iter++;
	
		if ((evt & logger->GetEnabledEvents() & logger->GetSupportedEvents()) == 0)
			continue;
		
		status = logger->Log(evt, ep);
		switch (status)
		{
		case GkAcctLogger::Ok:
			if (PTrace::CanTrace(3)) {
				ostream& strm = PTrace::Begin(3,__FILE__,__LINE__);
				strm << "GKACCT\t" << logger->GetName() << " logged event " << evt;
				if (ep)
					strm << " for endpoint " << ep->GetEndpointIdentifier().GetValue();
				PTrace::End(strm);
			}
			break;
			
		default:
			if (PTrace::CanTrace(3)) {
				ostream& strm = PTrace::Begin(3, __FILE__, __LINE__);
				strm << "GKACCT\t" << logger->GetName() << " failed to log event " << evt;
				if (ep)
					strm << " for endpoint " << ep->GetEndpointIdentifier().GetValue();
				PTrace::End(strm);
				SNMP_TRAP(7, SNMPError, Accounting, logger->GetName() + " failed to log event " + PString(evt));
			}
			// required and sufficient rules always determine 
			// status of the request
			if (logger->GetControlFlag() == GkAcctLogger::Required
				|| logger->GetControlFlag() == GkAcctLogger::Sufficient)
				finalResult = false;
		}
		
		// sufficient and alternative are terminal rules (on log success)
		if (status == GkAcctLogger::Ok 
			&& (logger->GetControlFlag() == GkAcctLogger::Sufficient
			|| logger->GetControlFlag() == GkAcctLogger::Alternative))
			break;
	}

	// a last rule determine status of the the request
	if (finalResult && status != GkAcctLogger::Ok)
		finalResult = false;
		
	if (PTrace::CanTrace(2)) {
		ostream& strm = PTrace::Begin(2, __FILE__, __LINE__);
		strm << "GKACCT\t" << (finalResult ? "Successfully logged event " 
			: "Failed to log event ") << evt;
		if (ep)
			strm << " for endpoint " << ep->GetEndpointIdentifier().GetValue();
		PTrace::End(strm);
		if (!finalResult)
			SNMP_TRAP(7, SNMPError, Accounting, "Failed to log event " + evt);
	}
	return finalResult;
}

namespace {
	GkAcctLoggerCreator<GkAcctLogger> DefaultAcctLoggerCreator("default");
	GkAcctLoggerCreator<FileAcct> FileAcctLoggerCreator("FileAcct");
}
