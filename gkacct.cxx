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
	const char* moduleName
	) 
	: 
	controlFlag(Sufficient),
	defaultStatus(Fail),
	eventMask(AcctAll)
{
	config = GkConfig();
	SetName(moduleName);
	
	const PStringArray control( 
		config->GetString( GkAcctSectionName, moduleName, "" ).Tokenise(";,")
		);

	if( control.GetSize() < 1 )
		PTRACE(1,"GKACCT\tEmpty config entry for module "<<moduleName);
	else if( strcmp(moduleName,"default") == 0 ) {
		controlFlag = Sufficient,
		defaultStatus = Toolkit::AsBool(control[0]) ? Ok : Fail;
	} else if (control[0] *= "optional") {
		controlFlag = Optional;
		defaultStatus = Next;
	} else if (control[0] *= "required") {
		controlFlag = Required;
		defaultStatus = Fail;
	}
	
	if( control.GetSize() > 1 )
		eventMask = ReadEventMask(control);
	
	PTRACE(1,"GKACCT\tCreated module "<<moduleName<<" with event mask "
		<<PString(PString::Unsigned,(long)eventMask,16)
		);
}

GkAcctLogger::~GkAcctLogger()
{
	PTRACE(1,"GKACCT\tDestroyed module "<<GetName());
}

int GkAcctLogger::ReadEventMask(
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
	return defaultStatus;
}

bool GkAcctLogger::LogAcctEvent( 
	AcctEvent evt, /// accounting event to log
	callptr& call /// additional data for the event
	)
{
	Status result;
	
	if( eventMask & evt ) {
		result = Log(evt,call);
		if( result == Ok ) {
			PTRACE(4,"GKACCT\t"<<GetName()<<" logged event "
				<<PString(PString::Unsigned,(long)evt,16));
			if( controlFlag == Sufficient )
				return true;
		} else if( result == Fail || (result == Next && controlFlag != Optional) )
			PTRACE(2,"GKACCT\t"<<GetName()<<" failed to log event "
				<<PString(PString::Unsigned,(long)evt,16));
	} else
		result = Ok;
		
	if( m_next && !m_next->LogAcctEvent(evt,call) )
		return false;
		
	return result == Ok || (result == Next && controlFlag == Optional); 
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
}
