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
 * Revision 1.2  2003/09/12 16:31:16  zvision
 * Accounting initially added to the 2.2 branch
 *
 * Revision 1.1.2.1  2003/06/19 15:36:04  zvision
 * Initial generic accounting support for GNU GK.
 *
 */
#include <ptlib.h>
#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "Toolkit.h"
#include "RasTbl.h"
#include "gkacct.h"

#ifdef P_SOLARIS
#define map stl_map
#endif

#include <map>
#include <list>

using std::map;
using std::list;

/// Name of the config file section for accounting configuration
const char* GkAcctSectionName = "Gatekeeper::Acct";



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
#else
	if( (tmptr = localtime(&t)) != NULL ) {
#endif
		char buf[48];
		size_t sz = strftime(buf,sizeof(buf),"%T %Z %a %b %d %Y",tmptr);
		if( sz < sizeof(buf) && sz > 0 )
			return buf;
	}
	
	return PTime(tm).AsString( "hh:mm:ss.uuu z www MMM d yyyy" );
}

GkAcctLogger::GkAcctLogger(
	const char* moduleName,
	const char* cfgSecName
	) 
	: 
	controlFlag(Required),
	defaultStatus(Fail),
	enabledEvents(AcctAll),
	supportedEvents(AcctNone),
	configSectionName(cfgSecName)
{
	config = GkConfig();
	SetName(moduleName);
	if( configSectionName.IsEmpty() )
		configSectionName = moduleName;
		
	const PStringArray control( 
		config->GetString( GkAcctSectionName, moduleName, "" ).Tokenise(";,")
		);

	if( control.GetSize() < 1 )
		PTRACE(1,"GKACCT\tEmpty config entry for module "<<moduleName);
	else if (control[0] *= "optional") {
		controlFlag = Optional;
		defaultStatus = Next;
	} else if (control[0] *= "sufficient") {
		controlFlag = Sufficient;
		defaultStatus = Next;
	}
	
	if( control.GetSize() > 1 )
		enabledEvents = GetEvents(control);
	
	PTRACE(1,"GKACCT\tCreated module "<<moduleName<<" with event mask "
		<<PString(PString::Unsigned,(long)enabledEvents,16)
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
	callptr& call /// additional data for the event
	)
{
	return (evt & enabledEvents & supportedEvents) 
		? defaultStatus : ((controlFlag == Sufficient) ? Next : Ok);
}

bool GkAcctLogger::LogAcctEvent( 
	AcctEvent evt, /// accounting event to log
	callptr& call /// additional data for the event
	)
{
	Status result;
	
	if( evt & enabledEvents & supportedEvents ) {
		result = Log(evt,call);
		if( result == Ok ) {
			PTRACE(4,"GKACCT\t"<<GetName()<<" logged event "
				<<PString(PString::Unsigned,(long)evt,16));
			if( controlFlag == Sufficient )
				return true;
		} else if( result == Fail || (result == Next && controlFlag == Required) )
			PTRACE(2,"GKACCT\t"<<GetName()<<" failed to log event "
				<<PString(PString::Unsigned,(long)evt,16));
	} else
		result = ((controlFlag == Sufficient) ? Next : Ok);
		
	if( m_next && !m_next->LogAcctEvent(evt,call) )
		return false;
		
	return result == Ok || (result == Next && controlFlag != Required); 
}


FileAcct::FileAcct( 
	const char* moduleName,
	const char* cfgSecName
	)
	:
	GkAcctLogger( moduleName, cfgSecName ),
	cdrFile(NULL)
{
	SetSupportedEvents( FileAcctEvents );	
	
	cdrFilename = GetConfig()->GetString(GetConfigSectionName(),"DetailFile","");
	rotateCdrFile = Toolkit::AsBool(GetConfig()->GetString(
		GetConfigSectionName(),"Rotate","0"
		));

	Rotate();
}

FileAcct::~FileAcct()
{
	PWaitAndSignal lock(cdrFileMutex);
	if( cdrFile ) {
		cdrFile->Close();
		delete cdrFile;
	}
}

GkAcctLogger::Status FileAcct::Log(
	GkAcctLogger::AcctEvent evt, 
	callptr& call
	)
{
	if( (evt & GetEnabledEvents() & GetSupportedEvents()) == 0 )
		return (GetControlFlag() == Sufficient) ? Next : Ok;
		
	if( (evt & (AcctStart|AcctUpdate|AcctStop)) && (!call) ) {
		PTRACE(1,"GKACCT\t"<<GetName()<<" log event "<<evt
			<<((GetDefaultStatus() == Fail)?" failed":" skipped")
			<<" - missing call info"
			);
		return GetDefaultStatus();
	}
	
	PString cdrString;
	
	if( !GetCDRText(cdrString,evt,call) ) {
		PTRACE(2,"GKACCT\t"<<GetName()<<" log event "<<evt
			<<((GetDefaultStatus() == Fail)?" failed":" skipped")
			<<" - unable to get CDR text"
			);
		return GetDefaultStatus();
	}
	
	PTRACE(5,"GKACCT\t"<<GetName()<<" CDR event "<<evt<<" text: "<<cdrString);

	PWaitAndSignal lock(cdrFileMutex);
	
	if( cdrFile && cdrFile->IsOpen() ) {
		if( cdrFile->WriteLine(PString(cdrString)) )
			return Ok;
		else
			PTRACE(1,"GKACCT\t"<<GetName()<<" write CDR text failed - "
				<<cdrFile->GetErrorText()
				);
	} else
		PTRACE(5,"GKACCT\t"<<GetName()<<" CDR file is closed - log failed");
		
	return GetDefaultStatus();
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
	PWaitAndSignal lock(cdrFileMutex);

	if( cdrFile ) {
		if( cdrFile->IsOpen() )
			if( rotateCdrFile )
				cdrFile->Close();
			else
				return;
		delete cdrFile;
		cdrFile = NULL;
	}
	
	const PFilePath fn = cdrFilename;
	
	if( rotateCdrFile && PFile::Exists(fn) )
		if( !PFile::Rename(fn,fn.GetFileName() + PTime().AsString(".yyyyMMdd-hhmmss")) )
			PTRACE(1,"GKACCT\t"<<GetName()<<" rotate failed - could not rename"
				" the log file: "<<cdrFile->GetErrorText()
				);
	
	cdrFile = new PTextFile(fn,PFile::WriteOnly, PFile::Create | PFile::DenySharedWrite);
	if (!cdrFile->IsOpen()) {
   	    PTRACE(1,"GKACCT\t"<<GetName()<<" could not open file"
			" required for plain text accounting \""
			<<fn<<"\" :"<<cdrFile->GetErrorText()
			);
		delete cdrFile;
		cdrFile = NULL;
	    return;
	}
	cdrFile->SetPermissions(PFileInfo::UserRead|PFileInfo::UserWrite);
	cdrFile->SetPosition(cdrFile->GetLength());
}

GkAcctLoggerList::GkAcctLoggerList()
	:
	m_head(NULL)
{
}

GkAcctLoggerList::~GkAcctLoggerList()
{
	WriteLock lock(m_reloadMutex);
	delete m_head;
}

void GkAcctLoggerList::OnReload()
{
	GkAcctLogger* head 
		= GkAcctLogger::Create(GkConfig()->GetKeys(GkAcctSectionName));
	{
		WriteLock lock(m_reloadMutex);
		swap(m_head,head);
	}
	delete head;	
}

namespace {
	GkAcctLoggerCreator<GkAcctLogger> DefaultAcctLoggerCreator("default");
	GkAcctLoggerCreator<FileAcct> FileAcctLoggerCreator("FileAcct");
}
