/*
 * syslogacct.cxx
 *
 * accounting module for GNU Gatekeeper for the syslog.
 *
 * Copyright (c) 2006-2010, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */
 
#ifndef _WIN32

#include <syslog.h>
#include <ptlib.h>
#include <h323pdu.h>
#include "GkStatus.h"
#include "syslogacct.h"
#include "Toolkit.h"

const char* const SyslogSec = "SyslogAcct";
static int syslog_level = LOG_INFO;
static int syslog_facility = LOG_USER;

SyslogAcct::SyslogAcct( 
	const char* moduleName,
	const char* cfgSecName
	)
	:
	GkAcctLogger(moduleName, cfgSecName)
{
	// it is very important to set what type of accounting events
	// are supported for each accounting module, otherwise the Log method
	// will no get called
	SetSupportedEvents(SyslogAcctEvents);

	PConfig* cfg = GetConfig();
	const PString& cfgSec = GetConfigSectionName();
	m_timestampFormat = cfg->GetString(cfgSec, "TimestampFormat", "");
	m_startEvent = cfg->GetString(cfgSec, "StartEvent", "CALL|Start|%{caller-ip}:%{caller-port}|%{callee-ip}:%{callee-port}|%{CallId}");
	m_stopEvent = cfg->GetString(cfgSec, "StopEvent", "CALL|Stop|%{caller-ip}:%{caller-port}|%{callee-ip}:%{callee-port}|%{CallId}");
	m_updateEvent = cfg->GetString(cfgSec, "UpdateEvent", "CALL|Update|%{caller-ip}:%{caller-port}|%{callee-ip}:%{callee-port}|%{CallId}");
	m_connectEvent = cfg->GetString(cfgSec, "ConnectEvent", "CALL|Connect|%{caller-ip}:%{caller-port}|%{callee-ip}:%{callee-port}|%{CallId}");
}

SyslogAcct::~SyslogAcct()
{
}

GkAcctLogger::Status SyslogAcct::Log(
	GkAcctLogger::AcctEvent evt, 
	const callptr& call
	)
{
	// a workaround to prevent processing end on "sufficient" module
	// if it is not interested in this event type
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;
		
	if (!call) {
		PTRACE(1,"SYSLOGACCT\t"<<GetName()<<" - missing call info for event "<<evt);
		return Fail;
	}

	PString sysloglevelconfig = GkConfig()->GetString(SyslogSec, "SyslogLevel", "LOG_INFO");
	PString syslogfacilityconfig = GkConfig()->GetString(SyslogSec, "SyslogFacility", "LOG_USER");

	if (sysloglevelconfig == "LOG_EMERG") {
		syslog_level = LOG_EMERG;
	} else if (sysloglevelconfig == "LOG_ALERT") {
		syslog_level = LOG_ALERT;
	} else if (sysloglevelconfig == "LOG_CRIT") {
		syslog_level = LOG_CRIT;
	} else if (sysloglevelconfig == "LOG_ERR") {
		syslog_level = LOG_ERR;
	} else if (sysloglevelconfig == "LOG_WARNING") {
		syslog_level = LOG_WARNING;
	} else if (sysloglevelconfig == "LOG_NOTICE") {
		syslog_level = LOG_NOTICE;
	} else if (sysloglevelconfig == "LOG_INFO") {
		syslog_level = LOG_INFO;
	} else if (sysloglevelconfig == "LOG_DEBUG") {
		syslog_level = LOG_DEBUG;
	} else {
		syslog_level = LOG_INFO;
	}

	if (syslogfacilityconfig == "LOG_DAEMON") {
		syslog_facility = LOG_DAEMON;
	} else if (syslogfacilityconfig == "LOG_USER") {
		syslog_facility = LOG_USER;
	} else if (syslogfacilityconfig == "LOG_AUTH") {
		syslog_facility = LOG_AUTH;
	} else if (syslogfacilityconfig == "LOG_LOCAL0") {
		syslog_facility = LOG_LOCAL0;
	} else if (syslogfacilityconfig == "LOG_LOCAL1") {
		syslog_facility = LOG_LOCAL1;
	} else if (syslogfacilityconfig == "LOG_LOCAL2") {
		syslog_facility = LOG_LOCAL2;
	} else if (syslogfacilityconfig == "LOG_LOCAL3") {
		syslog_facility = LOG_LOCAL3;
	} else if (syslogfacilityconfig == "LOG_LOCAL4") {
		syslog_facility = LOG_LOCAL4;
	} else if (syslogfacilityconfig == "LOG_LOCAL5") {
		syslog_facility = LOG_LOCAL5;
	} else if (syslogfacilityconfig == "LOG_LOCAL6") {
		syslog_facility = LOG_LOCAL6;
	} else if (syslogfacilityconfig == "LOG_LOCAL7") {
		syslog_facility = LOG_LOCAL7;
	} else {
		syslog_facility = LOG_USER;
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
		openlog("GnuGk", LOG_PID, syslog_facility);
		syslog(syslog_facility | syslog_level, "%s", (const char *)msg);
		closelog();
	}

	return Ok;
}

PString SyslogAcct::EscapeAcctParam(const PString& param) const
{
	return "\"" + param + "\"";	// test: quote
}

namespace {
	// append syslog accounting logger to the global list of loggers
	GkAcctLoggerCreator<SyslogAcct> SyslogAcctCreator("SyslogAcct");
}

#endif // not _WIN32
