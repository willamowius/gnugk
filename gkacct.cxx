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


FileAcct::FileAcct( 
	const char* moduleName,
	const char* cfgSecName
	)
	:
	GkAcctLogger(moduleName, cfgSecName),
	m_cdrFile(NULL)
{
	SetSupportedEvents(FileAcctEvents);
	
	m_cdrFilename = GetConfig()->GetString(GetConfigSectionName(), "DetailFile", "");
	m_rotateCdrFile = Toolkit::AsBool(GetConfig()->GetString(
		GetConfigSectionName(), "Rotate", "0"
		));

	Rotate();
	if (m_cdrFile && m_cdrFile->IsOpen())
		PTRACE(2, "GKACCT\t" << GetName() << " CDR file: " << m_cdrFile->GetFilePath());
}

FileAcct::~FileAcct()
{
	PWaitAndSignal lock(m_cdrFileMutex);
	if (m_cdrFile) {
		m_cdrFile->Close();
		delete m_cdrFile;
	}
}

GkAcctLogger::Status FileAcct::Log(
	GkAcctLogger::AcctEvent evt, 
	callptr& call
	)
{
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;
		
	if ((evt & (AcctStart|AcctUpdate|AcctStop)) && (!call)) {
		PTRACE(1,"GKACCT\t"<<GetName()<<" - missing call info for event"<<evt);
		return Fail;
	}
	
	PString cdrString;
	
	if (!GetCDRText(cdrString, evt, call)) {
		PTRACE(2,"GKACCT\t"<<GetName()<<" - unable to get CDR text for event "<<evt
			<<", call no. "<<call->GetCallNumber()
			);
		return Fail;
	}
	
	PWaitAndSignal lock(m_cdrFileMutex);
	
	if (m_cdrFile && m_cdrFile->IsOpen()) {
		if (m_cdrFile->WriteLine(PString(cdrString))) {
			PTRACE(5,"GKACCT\t"<<GetName()<<" - CDR string for event "<<evt
				<<", call no. "<<call->GetCallNumber()<<": "<<cdrString
				);
			return Ok;
		} else
			PTRACE(1,"GKACCT\t"<<GetName()<<" - write CDR text for event "<<evt
				<<", call no. "<<call->GetCallNumber()<<" failed: "<<m_cdrFile->GetErrorText()
				);
	} else
		PTRACE(1,"GKACCT\t"<<GetName()<<" - write CDR text for event "<<evt
			<<", for call no. "<<call->GetCallNumber()<<" failed: CDR file is closed"
			);
		
	return Fail;
}

bool FileAcct::GetCDRText(
	PString& cdrString,
	AcctEvent evt,
	callptr& call
	)
{
	if( (evt & AcctStop) && call ) {
		cdrString = call->GenerateCDR();
		return !cdrString.IsEmpty();
	}
	
	return false;	
}

void FileAcct::Rotate()
{
	PWaitAndSignal lock(m_cdrFileMutex);

	if (m_cdrFile) {
		if (m_cdrFile->IsOpen())
			if (m_rotateCdrFile)
				m_cdrFile->Close();
			else
				return;
		delete m_cdrFile;
		m_cdrFile = NULL;
	}
	
	const PFilePath fn = m_cdrFilename;
	
	if (m_rotateCdrFile && PFile::Exists(fn))
		if (!PFile::Rename(fn, fn.GetFileName() + PTime().AsString(".yyyyMMdd-hhmmss")))
			PTRACE(1,"GKACCT\t"<<GetName()<<" rotate failed - could not rename"
				" the log file: "<<m_cdrFile->GetErrorText()
				);
	
	m_cdrFile = new PTextFile(fn, PFile::WriteOnly, PFile::Create | PFile::DenySharedWrite);
	if (!m_cdrFile->IsOpen()) {
   	    PTRACE(1,"GKACCT\t"<<GetName()<<" could not open file"
			" required for plain text accounting \""
			<<fn<<"\" :"<<m_cdrFile->GetErrorText()
			);
		delete m_cdrFile;
		m_cdrFile = NULL;
	    return;
	}
	m_cdrFile->SetPermissions(PFileInfo::UserRead | PFileInfo::UserWrite);
	m_cdrFile->SetPosition(m_cdrFile->GetLength());
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
