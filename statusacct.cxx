/*
 * statusacct.cxx
 *
 * accounting module for GNU Gatekeeper for the status port.
 *
 * Copyright (c) 2005, Jan Willamowius
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.3  2006/06/19 22:06:58  willamowius
 * compile fix for gcc 3.3.1 on Solaris
 *
 * Revision 1.2  2006/04/14 13:56:19  willamowius
 * call failover code merged
 *
 * Revision 1.1.1.1  2005/11/21 20:19:58  willamowius
 *
 *
 * Revision 1.4  2005/11/15 19:52:56  jan
 * Michal v1 (works, but on in routed, not proxy mode)
 *
 * Revision 1.1  2005/08/28 18:05:55  willamowius
 * new accounting module StatusAcct
 *
 *
 */

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbols off
#endif

#include <ptlib.h>
#include <h323pdu.h>
#include "GkStatus.h"
#include "statusacct.h"

StatusAcct::StatusAcct( 
	const char* moduleName,
	const char* cfgSecName
	)
	:
	GkAcctLogger(moduleName, cfgSecName)
{
	// it is very important to set what type of accounting events
	// are supported for each accounting module, otherwise the Log method
	// will no get called
	SetSupportedEvents(StatusAcctEvents);

	PConfig* cfg = GetConfig();
	const PString& cfgSec = GetConfigSectionName();
	m_timestampFormat = cfg->GetString(cfgSec, "TimestampFormat", "");
	m_startEvent = cfg->GetString(cfgSec, "StartEvent", "CALL|Start|%{caller-ip}:%{caller-port}|%{callee-ip}:%{callee-port}|%{CallId}");
	m_stopEvent = cfg->GetString(cfgSec, "StopEvent", "CALL|Stop|%{caller-ip}:%{caller-port}|%{callee-ip}:%{callee-port}|%{CallId}");
	m_updateEvent = cfg->GetString(cfgSec, "UpdateEvent", "CALL|Update|%{caller-ip}:%{caller-port}|%{callee-ip}:%{callee-port}|%{CallId}");
	m_connectEvent = cfg->GetString(cfgSec, "ConnectEvent", "CALL|Connect|%{caller-ip}:%{caller-port}|%{callee-ip}:%{callee-port}|%{CallId}");
}

StatusAcct::~StatusAcct()
{
}

GkAcctLogger::Status StatusAcct::Log(
	GkAcctLogger::AcctEvent evt, 
	const callptr& call
	)
{
	// a workaround to prevent processing end on "sufficient" module
	// if it is not interested in this event type
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;
		
	if (!call) {
		PTRACE(1,"STATUSACCT\t"<<GetName()<<" - missing call info for event "<<evt);
		return Fail;
	}

	PString eventTmpl;
	if (evt == AcctStart) {
		eventTmpl = m_startEvent;
	} else if (evt == AcctConnect) {
		eventTmpl = m_connectEvent;
	} else if (evt == AcctUpdate) {
		eventTmpl = m_updateEvent;
	} else if (evt == AcctStop) {
		eventTmpl = m_stopEvent;
	}

	if (!eventTmpl.IsEmpty()) {		// don't send event if the template string is empty
		std::map<PString, PString> params;
		SetupAcctParams(params, call, m_timestampFormat);
		PString msg = ReplaceAcctParams(eventTmpl, params);
		GkStatus::Instance()->SignalStatus(msg + "\r\n", STATUS_TRACE_LEVEL_CDR);
	}

	return Ok;
}

PString StatusAcct::EscapeAcctParam(const PString& param) const
{
	return param;	// don't quote here, quote in template if needed
}

namespace {
	// append status port accounting logger to the global list of loggers
	GkAcctLoggerCreator<StatusAcct> StatusAcctCreator("StatusAcct");
}

