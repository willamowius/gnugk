/*
 * gkacct.cxx
 *
 * Accounting modules for GNU Gatekeeper. Provides generic
 * support for accounting to the gatekeeper.
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.11  2004/05/12 11:49:08  zvision
 * New flexible CDR file rotation
 *
 * Revision 1.10  2004/04/17 11:43:42  zvision
 * Auth/acct API changes.
 * Header file usage more consistent.
 *
 * Revision 1.9  2003/12/21 00:58:17  zvision
 * FileAcct logger should work fine with the reload command now
 *
 * Revision 1.8  2003/11/01 10:36:34  zvision
 * Fixed missing semicolon. Thanks to Hu Yuxin
 *
 * Revision 1.7  2003/10/31 00:01:23  zvision
 * Improved accounting modules stacking control, optimized radacct/radauth a bit
 *
 * Revision 1.6  2003/10/15 10:16:57  zvision
 * Fixed VC6 compiler warnings. Thanks to Hu Yuxin.
 *
 * Revision 1.5  2003/10/08 12:40:48  zvision
 * Realtime accounting updates added
 *
 * Revision 1.4  2003/09/28 15:45:49  zvision
 * Microsecond field added back to h323-xxx-time attributes
 *
 * Revision 1.3  2003/09/14 21:09:29  zvision
 * Added new FileAcct logger from Tamas Jalsovszky. Thanks!
 * Fixed module stacking. Redesigned API.
 *
 * Revision 1.2  2003/09/12 16:31:16  zvision
 * Accounting initially added to the 2.2 branch
 *
 * Revision 1.1.2.1  2003/06/19 15:36:04  zvision
 * Initial generic accounting support for GNU GK.
 *
 */
#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug sumbol off
#endif

#include <ptlib.h>
#include <h225.h>
#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "Toolkit.h"
#include "RasTbl.h"
#include "gktimer.h"
#include "gkacct.h"

/// Name of the config file section for accounting configuration
namespace {
const char* GkAcctSectionName = "Gatekeeper::Acct";
}

extern const char* CallTableSection;


PString GkAcctLogger::AsString(
	const PTime& tm
	)
{
	struct tm _tm;
	struct tm* tmptr = &_tm;
	time_t t;
	
	if( (time(&t) != (time_t)(-1))
#ifndef WIN32
		&& (localtime_r(&t,tmptr) == tmptr) )
#else
		&& ((tmptr = localtime(&t)) != NULL) )
#endif
	{
		char buf[10];
		
		buf[0] = 0;
		if( strftime(buf,sizeof(buf),"%Z",tmptr) < 10 )
		{
			buf[9] = 0;
			const PString tzname(buf);
			if( !tzname.IsEmpty() )
			{
				PString s = tm.AsString( "hh:mm:ss.uuu @@@ www MMM d yyyy" );
				s.Replace("@@@",tzname);
				return s;
			}
		}
	}
	
	return tm.AsString( "hh:mm:ss.uuu z www MMM d yyyy" );
}

PString GkAcctLogger::AsString(
	const time_t& tm
	)
{
	struct tm _tm;
	struct tm* tmptr = &_tm;
	time_t t = tm;
	
	
#ifndef WIN32
	if( localtime_r(&t,tmptr) == tmptr ) {
		char buf[48];
		size_t sz = strftime(buf,sizeof(buf),"%T.000 %Z %a %b %d %Y",tmptr);
#else
	if( (tmptr = localtime(&t)) != NULL ) {
		char buf[96];
		size_t sz = strftime(buf,sizeof(buf),"%H:%M:%S.000 %Z %a %b %d %Y",tmptr);
#endif
		if( sz < sizeof(buf) && sz > 0 )
			return buf;
	}
	
	return PTime(tm).AsString( "hh:mm:ss.uuu z www MMM d yyyy" );
}

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
		<< PString(PString::Unsigned,(long)m_enabledEvents,16)
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
		else if( token *= "on" )
			mask |= AcctOn;
		else if( token *= "off" )
			mask |= AcctOff;
	}
	
	return mask;
}

GkAcctLogger::Status GkAcctLogger::Log(
	AcctEvent evt, /// accounting event to log
	callptr& /*call*/ /// a call associated with the event (if any)
	)
{
	return (evt & m_enabledEvents & m_supportedEvents) ? m_defaultStatus : Next;
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
	m_standardCDRFormat(true), m_gkName(Toolkit::Instance()->GKName())
{
	SetSupportedEvents(FileAcctEvents);
	
	m_cdrString = GetConfig()->GetString(GetConfigSectionName(), "CDRString", "");
	m_standardCDRFormat = Toolkit::AsBool(
		GetConfig()->GetString(GetConfigSectionName(), "StandardCDRFormat", 
			m_cdrString.IsEmpty() ? "1" : "0"
			));

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
			rotateTime += PTimeInterval(60*60*1000);
		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			this, &FileAcct::RotateOnTimer, rotateTime, 60*60
			);
		PTRACE(5, "GKACCT\t" << GetName() << " hourly rotation enabled (first "
			"rotation sheduled at " << rotateTime
			);
		break;
		
	case Daily:
		rotateTime = PTime(0, m_rotateMinute, m_rotateHour, now.GetDay(), 
			now.GetMonth(), now.GetYear(), now.GetTimeZone()
			);
		if (rotateTime <= now)
			rotateTime += PTimeInterval(60*60*24*1000);
		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			this, &FileAcct::RotateOnTimer, rotateTime, 60*60*24
			);
		PTRACE(5, "GKACCT\t" << GetName() << " daily rotation enabled (first "
			"rotation sheduled at " << rotateTime
			);
		break;
		
	case Weekly:
		rotateTime = PTime(0, m_rotateMinute, m_rotateHour, now.GetDay(), 
			now.GetMonth(), now.GetYear(), now.GetTimeZone()
			);
		if (rotateTime.GetDayOfWeek() < m_rotateDay)
			rotateTime += PTimeInterval(
				60*60*24*1000*(m_rotateDay-rotateTime.GetDayOfWeek())
				);
		else if (rotateTime.GetDayOfWeek() > m_rotateDay)
			rotateTime -= PTimeInterval(
				60*60*24*1000*(rotateTime.GetDayOfWeek()-m_rotateDay)
				);
		if (rotateTime <= now)
			rotateTime += PTimeInterval(60*60*24*7*1000);
		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			this, &FileAcct::RotateOnTimer, rotateTime, 60*60*24*7
			);
		PTRACE(5, "GKACCT\t" << GetName() << " weekly rotation enabled (first "
			"rotation sheduled at " << rotateTime
			);
		break;
		
	case Monthly:
		rotateTime = PTime(0, m_rotateMinute, m_rotateHour, 1, 
			now.GetMonth(), now.GetYear(), now.GetTimeZone()
			);
		rotateTime += PTimeInterval(1000*60*60*24*(m_rotateDay-1));
		while (rotateTime.GetMonth() != now.GetMonth())				
			rotateTime -= PTimeInterval(1000*60*60*24);
		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			this, &FileAcct::RotateOnTimer, rotateTime
			);
		PTRACE(5, "GKACCT\t" << GetName() << " monthly rotation enabled (first "
			"rotation sheduled at " << rotateTime
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
	callptr& call
	)
{
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;
		
	if (!call) {
		PTRACE(1, "GKACCT\t" << GetName() << " - missing call info for event" << evt);
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
				<< " failed: " << m_cdrFile->GetErrorText()
				);
	} else
		PTRACE(1, "GKACCT\t" << GetName() << " - write CDR text for event "
			<< evt << ", for call no. " << call->GetCallNumber()
			<< " failed: CDR file is closed"
			);
		
	return Fail;
}

bool FileAcct::GetCDRText(
	PString& cdrString,
	AcctEvent evt,
	callptr& call
	)
{
	if ((evt & AcctStop) != AcctStop || !call)
		return false;
	
	if (m_standardCDRFormat)	
		cdrString = call->GenerateCDR();
	else {
		std::map<PString, PString> params;

		SetupCDRParams(params, call);
		cdrString = ReplaceCDRParams(m_cdrString, params);
	}	
	
	return !cdrString;
}

void FileAcct::SetupCDRParams(
	/// CDR parameters (name => value) associations
	std::map<PString, PString>& params,
	/// call (if any) associated with an accounting event being logged
	callptr& call
	) const
{
	PIPSocket::Address addr;
	WORD port = 0;
	time_t t;
	
	params["g"] = m_gkName;
	params["n"] = PString(call->GetCallNumber());
	params["d"] = call->GetDuration();
	params["c"] = call->GetDisconnectCause();
	params["s"] = call->GetAcctSessionId();
	params["CallId"] = ::AsString(call->GetCallIdentifier().m_guid);
	params["ConfId"] = ::AsString(call->GetConferenceIdentifier());
	
	t = call->GetSetupTime();
	if (t)
		params["setup-time"] = AsString(t);
	t = call->GetConnectTime();
	if (t)
		params["connect-time"] = AsString(t);
	t = call->GetDisconnectTime();
	if (t)
		params["disconnect-time"] = AsString(t);
	
	if (call->GetSrcSignalAddr(addr, port)) {
		params["caller-ip"] = addr.AsString();
		params["caller-port"] = port;
	}
	
	PString srcInfo = call->GetSrcInfo();
	params["src-info"] = srcInfo;

	// Get User-name
	if (!(srcInfo.IsEmpty() || srcInfo == "unknown")) {
		const PINDEX index = srcInfo.FindOneOf(":");
		if( index != P_MAX_INDEX )
			srcInfo = srcInfo.Left(index);
	}
	
	endptr callingEP = call->GetCallingParty();
	PString userName;
		
	if (callingEP && callingEP->GetAliases().GetSize() > 0)
		userName = GetBestAliasAddressString(
			callingEP->GetAliases(),
			H225_AliasAddress::e_h323_ID
			);
	else if (!srcInfo)
		userName = srcInfo;
	else if (addr.IsValid())
		userName = addr.AsString();
		
	if (!userName)
		params["u"] = userName;

	PString stationId = srcInfo;

	if (!stationId) {
		const PINDEX index = stationId.FindOneOf(":");
		if (index != P_MAX_INDEX)
			stationId = stationId.Left(index);
	}
		
	if (stationId.IsEmpty() && callingEP && callingEP->GetAliases().GetSize() > 0)
		stationId = GetBestAliasAddressString(
			callingEP->GetAliases(),
			H225_AliasAddress::e_dialedDigits,
			H225_AliasAddress::e_partyNumber,
			H225_AliasAddress::e_h323_ID
			);
					
	if (stationId.IsEmpty() && addr.IsValid() && port)
		stationId = ::AsString(addr, port);

	if (!stationId)
		params["Calling-Station-Id"] = stationId;
		
	addr = (DWORD)0;
	port = 0;
		
	if (call->GetDestSignalAddr(addr, port)) {
		params["callee-ip"] = addr.AsString();
		params["callee-port"] = port;
	}

	PString destInfo = call->GetDestInfo();
	params["dest-info"] = destInfo;

	stationId = destInfo;
	
	if (!stationId) {
		const PINDEX index = stationId.FindOneOf(":");
		if (index != P_MAX_INDEX)
			stationId = destInfo.Left(index);
	}
		
	if (stationId.IsEmpty()) {
		endptr calledEP = call->GetCalledParty();
		if (calledEP && calledEP->GetAliases().GetSize() > 0)
			stationId = GetBestAliasAddressString(
				calledEP->GetAliases(),
				H225_AliasAddress::e_dialedDigits,
				H225_AliasAddress::e_partyNumber,
				H225_AliasAddress::e_h323_ID
				);
	}
	
	if (stationId.IsEmpty() && addr.IsValid() && port)
		stationId = ::AsString(addr, port);
		
	if (!stationId)
		params["Called-Station-Id"] = stationId;
}

PString FileAcct::ReplaceCDRParams(
	/// parametrized CDR string
	const PString& cdrStr,
	/// parameter values
	const std::map<PString, PString>& params
	)
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
					const PINDEX escapedLen = i->second.GetLength();
					finalCDR.Splice(i->second, pos - 2, paramLen + 3);
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
				const PINDEX escapedLen = i->second.GetLength();
				finalCDR.Splice(i->second, pos - 1, 2);
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
		newRotateTime += PTimeInterval(1000*60*60*24*(m_rotateDay-1));
		while (newRotateTime.GetMonth() != month)				
			newRotateTime -= PTimeInterval(1000*60*60*24);
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
	
	if (PFile::Exists(fn))
		if (!PFile::Rename(fn, fn.GetFileName() + PTime().AsString(".yyyyMMdd-hhmmss")))
			PTRACE(1, "GKACCT\t" << GetName() << " rotate failed - could not "
				"rename the log file"
				);
	
	m_cdrFile = OpenCDRFile(fn);
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
	WriteLock lock(m_reloadMutex);
	DeleteObjectsInContainer(m_loggers);
	m_loggers.clear();
}

void GkAcctLoggerList::OnReload()
{
	WriteLock lock(m_reloadMutex);
		
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
	callptr& call, /// a call associated with the event (if any)
	time_t now /// "now" timestamp for accounting update events
	)
{
	// if this is an accounting update, check the interval
	if (evt & GkAcctLogger::AcctUpdate)
		if ((!call) || m_acctUpdateInterval == 0 
			|| (now - call->GetLastAcctUpdateTime()) < m_acctUpdateInterval)
			return true;
		else
			call->SetLastAcctUpdateTime(now);
			
	bool finalResult = true;
	GkAcctLogger::Status status = GkAcctLogger::Ok;
	ReadLock lock(m_reloadMutex);
	std::list<GkAcctLogger*>::const_iterator iter = m_loggers.begin();
	
	while (iter != m_loggers.end()) {
		GkAcctLogger* logger = *iter++;
	
		if ((evt & logger->GetEnabledEvents() & logger->GetSupportedEvents()) == 0)
			continue;
		
		status = logger->Log(evt, call);
		switch (status)
		{
		case GkAcctLogger::Ok:
#if PTRACING
			if (PTrace::CanTrace(3)) {
				ostream& strm = PTrace::Begin(3,__FILE__,__LINE__);
				strm << "GKACCT\t" << logger->GetName() << " logged event " << evt;
				if (call)
					strm << " for call no. " << call->GetCallNumber();
				PTrace::End(strm);
			}
#endif
			break;
			
		default:
#if PTRACING
			if (PTrace::CanTrace(3)) {
				ostream& strm = PTrace::Begin(3, __FILE__, __LINE__);
				strm << "GKACCT\t" << logger->GetName() << " failed to log event "
					<< evt;
				if (call)
					strm << " for call no. " << call->GetCallNumber();
				PTrace::End(strm);
			}
#endif
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
		
#if PTRACING
	if (PTrace::CanTrace(2)) {
		ostream& strm = PTrace::Begin(2, __FILE__, __LINE__);
		strm << "GKACCT\t" << (finalResult ? "Successfully logged event " 
			: "Failed to log event ") << evt;
		if (call)
			strm << " for call no. " << call->GetCallNumber();
		PTrace::End(strm);
	}
#endif
	return finalResult;
}

namespace {
	GkAcctLoggerCreator<GkAcctLogger> DefaultAcctLoggerCreator("default");
	GkAcctLoggerCreator<FileAcct> FileAcctLoggerCreator("FileAcct");
}
