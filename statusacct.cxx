/*
 * statusacct.cxx
 *
 * accounting module for GNU Gatekeeper for the status port.
 *
 * Copyright (c) 2005-2010, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

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
	m_alertEvent = cfg->GetString(cfgSec, "AlertEvent", "CALL|Alert|%{caller-ip}:%{caller-port}|%{callee-ip}:%{callee-port}|%{CallId}");
	m_registerEvent = cfg->GetString(cfgSec, "RegisterEvent", "EP|Register|%{endpoint-ip}:%{endpoint-port}|%{aliases}");
	m_unregisterEvent = cfg->GetString(cfgSec, "UnregisterEvent", "EP|Unregister|%{endpoint-ip}:%{endpoint-port}|%{aliases}");
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
		PTRACE(1,"STATUSACCT\t"<<GetName()<<" - missing call info for event " << evt);
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
	} else if (evt == AcctAlert) {
		eventTmpl = m_alertEvent;
	}

	if (!eventTmpl.IsEmpty()) {		// don't send event if the template string is empty
		std::map<PString, PString> params;
		SetupAcctParams(params, call, m_timestampFormat);
		PString msg = ReplaceAcctParams(eventTmpl, params);
		GkStatus::Instance()->SignalStatus(msg + "\r\n", STATUS_TRACE_LEVEL_CDR);
	}

	return Ok;
}

GkAcctLogger::Status StatusAcct::Log(
	GkAcctLogger::AcctEvent evt, 
	const endptr& ep
	)
{
	// a workaround to prevent processing end on "sufficient" module
	// if it is not interested in this event type
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;
		
	if (!ep) {
		PTRACE(1,"STATUSACCT\t"<<GetName()<<" - missing endpoint info for event " << evt);
		return Fail;
	}

	PString eventTmpl;
	if (evt == AcctRegister) {
		eventTmpl = m_registerEvent;
	} else if (evt == AcctUnregister) {
		eventTmpl = m_unregisterEvent;
	}

	if (!eventTmpl.IsEmpty()) {		// don't send event if the template string is empty
		std::map<PString, PString> params;
		SetupAcctEndpointParams(params, ep);
		PString msg = ReplaceAcctParams(eventTmpl, params);
		GkStatus::Instance()->SignalStatus(msg + "\r\n", STATUS_TRACE_LEVEL_CDR);
	}

	return Ok;
}

PString StatusAcct::EscapeAcctParam(const PString& param) const
{
	return param;	// don't quote here, quote in template if needed
}

// override output format of callid
PString StatusAcct::ReplaceAcctParams(
		/// parametrized accounting string
		const PString& cdrStr,
		/// parameter values
		const std::map<PString, PString>& params
	) const
{
	std::map<PString, PString> new_params = params;
	std::map<PString, PString>::iterator i = new_params.find("CallId");
	if (i != new_params.end()) {
		i->second.Replace(" ", "-", TRUE);
	}
	return GkAcctLogger::ReplaceAcctParams(cdrStr, new_params);
}


namespace {
	// append status port accounting logger to the global list of loggers
	GkAcctLoggerCreator<StatusAcct> StatusAcctCreator("StatusAcct");
}

