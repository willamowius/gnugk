/*
 * sqlacct.cxx
 *
 * SQL accounting module for GNU Gatekeeper
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 * Copyright (c) 2005-2010, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include <vector>
#include <ptlib.h>
#include "RasSrv.h"
#include "gksql.h"
#include "sqlacct.h"

using std::vector;


SQLAcct::SQLAcct(
	const char* moduleName,
	const char* cfgSecName
	) : GkAcctLogger(moduleName, cfgSecName),
	m_sqlConn(NULL)
{
	SetSupportedEvents(SQLAcctEvents);	

	PConfig* const cfg = GkConfig();	
	const PString& cfgSec = GetConfigSectionName();
	
	const PString driverName = cfg->GetString(cfgSec, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(0, "GKACCT\t" << GetName() << " module creation failed: "
			"no SQL driver selected"
			);
		PTRACE(0, "GKACCT\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	}
	
	m_sqlConn = GkSQLConnection::Create(driverName, cfgSec);
	if (m_sqlConn == NULL) {
		PTRACE(0, "GKACCT\t" << GetName() << " module creation failed: "
			"could not find " << driverName << " database driver"
			);
		PTRACE(0, "GKACCT\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	}

	m_startQuery = cfg->GetString(cfgSec, "StartQuery", "");
	if (m_startQuery.IsEmpty() 
		&& (GetEnabledEvents() & GetSupportedEvents() & AcctStart) == AcctStart) {
		PTRACE(0, "GKACCT\t" << GetName() << " module creation failed: "
			"no start query configured"
			);
		PTRACE(0, "GKACCT\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	} else
		PTRACE(4, "GKACCT\t" << GetName() << " start query: " << m_startQuery);
	
	m_startQueryAlt = cfg->GetString(cfgSec, "StartQueryAlt", "");
	if (!m_startQueryAlt) {
		PTRACE(4, "GKACCT\t" << GetName() << " alternative start query: " << m_startQueryAlt);
	}

	m_updateQuery = cfg->GetString(cfgSec, "UpdateQuery", "");
	if (m_updateQuery.IsEmpty() 
		&& (GetEnabledEvents() & GetSupportedEvents() & (AcctUpdate | AcctConnect)) != 0) {
		PTRACE(0, "GKACCT\t" << GetName() << " module creation failed: "
			"no update query configured");
		PTRACE(0, "GKACCT\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	} else {
		PTRACE(4, "GKACCT\t" << GetName() << " update query: " << m_updateQuery);
	}

	m_stopQuery = cfg->GetString(cfgSec, "StopQuery", "");
	if (m_stopQuery.IsEmpty() 
		&& (GetEnabledEvents() & GetSupportedEvents() & AcctStop) == AcctStop) {
		PTRACE(0, "GKACCT\t" << GetName() << " module creation failed: "
			"no stop query configured");
		PTRACE(0, "GKACCT\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	} else
		PTRACE(4, "GKACCT\t" << GetName() << " stop query: " << m_stopQuery);
	
	m_stopQueryAlt = cfg->GetString(cfgSec, "StopQueryAlt", "");
	if (!m_stopQueryAlt) {
		PTRACE(4, "GKACCT\t" << GetName() << " alternative stop query: " 
			<< m_stopQueryAlt);
	}

	m_alertQuery = cfg->GetString(cfgSec, "AlertQuery", "");
	if (!m_alertQuery) {
		PTRACE(4, "GKACCT\t" << GetName() << " alert query: " << m_alertQuery);
	}

	m_registerQuery = cfg->GetString(cfgSec, "RegisterQuery", "");
	if (!m_registerQuery) {
		PTRACE(4, "GKACCT\t" << GetName() << " registration query: " << m_registerQuery);
	}
	m_unregisterQuery = cfg->GetString(cfgSec, "UnregisterQuery", "");
	if (!m_unregisterQuery) {
		PTRACE(4, "GKACCT\t" << GetName() << " un-registration query: " << m_unregisterQuery);
	}

	vector<PIPSocket::Address> interfaces;
	Toolkit::Instance()->GetGKHome(interfaces);
	if (interfaces.empty()) {
		PTRACE(0, "GKACCT\t" << GetName() << " cannot determine gatekeeper IP address");
		PTRACE(0, "GKACCT\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	}

	if (!m_sqlConn->Initialize(cfg, cfgSec)) {
		PTRACE(0, "GKACCT\t" << GetName() << " module creation failed: "
			"could not connect to the database"
			);
		PTRACE(0, "GKACCT\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	}
	
	m_timestampFormat = cfg->GetString(cfgSec, "TimestampFormat", "");
}

SQLAcct::~SQLAcct()
{
	delete m_sqlConn;
}

GkAcctLogger::Status SQLAcct::Log(
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
	
	const long callNumber = call->GetCallNumber();
		
	if (m_sqlConn == NULL) {
		PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
			"data (event: " << evt << ", call: " << callNumber 
			<< "): SQL connection not active"
			);
		return Fail;
	}
	
	PString query, queryAlt;
	if (evt == AcctStart) {
		query = m_startQuery;
		queryAlt = m_startQueryAlt;
	} else if (evt == AcctUpdate || evt == AcctConnect)
		query = m_updateQuery;
	else if (evt == AcctStop) {
		query = m_stopQuery;
		queryAlt = m_stopQueryAlt;
	} if (evt == AcctAlert)
		query = m_alertQuery;

	if (query.IsEmpty() && (evt == AcctAlert)) {
	}

	if (query.IsEmpty()) {
		if (evt != AcctAlert) {
			PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
				"data (event: " << evt << ", call: " << callNumber 
				<< "): SQL query is empty");
		}
		return Fail;
	}

	std::map<PString, PString> params;
	SetupAcctParams(params, call, m_timestampFormat);
	GkSQLResult* result = m_sqlConn->ExecuteQuery(query, params);
	if (result == NULL) {
		PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
			"data (event: " << evt << ", call: " << callNumber 
			<< "): timeout or fatal error");
	}
	
	if (result) {
		if (result->IsValid()) {
			if (result->GetNumRows() < 1) {
				PTRACE(4, "GKACCT\t" << GetName() << " failed to store accounting "
					"data (event: " << evt << ", call: " << callNumber 
					<< "): no rows have been updated"
					);
				delete result;
				result = NULL;
			}
		} else {
			PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
				"data (event: " << evt << ", call: " << callNumber 
				<< "): (" << result->GetErrorCode() << ") "
				<< result->GetErrorMessage()
				);
			delete result;
			result = NULL;
		}
	}
	
	if (result == NULL && !queryAlt) {
		result = m_sqlConn->ExecuteQuery(queryAlt, params);
		if (result == NULL)
			PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
				"data (event: " << evt << ", call: " << callNumber 
				<< "): timeout or fatal error"
				);
		else {
			if (result->IsValid()) {
				if (result->GetNumRows() < 1) {
					PTRACE(4, "GKACCT\t" << GetName() << " failed to store accounting "
						"data (event: " << evt << ", call: " << callNumber 
						<< "): no rows have been updated");
				}
			} else
				PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
					"data (event: " << evt << ", call: " << callNumber 
					<< "): (" << result->GetErrorCode() << ") "
					<< result->GetErrorMessage()
					);
		}
	}

	const bool succeeded = result != NULL && result->IsValid();	
	delete result;
	return succeeded ? Ok : Fail;
}

GkAcctLogger::Status SQLAcct::Log(
	GkAcctLogger::AcctEvent evt, 
	const endptr& ep
	)
{
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;
		
	if (!ep) {
		PTRACE(1, "GKACCT\t" << GetName() << " - missing call info for event " << evt);
		return Fail;
	}
	
	const PString epid = ep->GetEndpointIdentifier().GetValue();

	if (m_sqlConn == NULL) {
		PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
			"data (event: " << evt << ", endpoint: " << epid
			<< "): SQL connection not active"
			);
		return Fail;
	}
	
	PString query;
	if (evt == AcctRegister)
		query = m_registerQuery;
	else if (evt == AcctUnregister)
		query = m_unregisterQuery;

	if (query.IsEmpty()) {
		return Fail;
	}

	std::map<PString, PString> params;
	SetupAcctEndpointParams(params, ep);
	GkSQLResult* result = m_sqlConn->ExecuteQuery(query, params);
	if (result == NULL) {
		PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
			"data (event: " << evt << ", endpoint: " << epid
			<< "): timeout or fatal error");
	}
	
	if (result) {
		if (result->IsValid()) {
			if (result->GetNumRows() < 1) {
				PTRACE(4, "GKACCT\t" << GetName() << " failed to store accounting "
					"data (event: " << evt << ", endpoint: " << epid
					<< "): no rows have been updated"
					);
				delete result;
				result = NULL;
			}
		} else {
			PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
				"data (event: " << evt << ", endpoint: " << epid
				<< "): (" << result->GetErrorCode() << ") "
				<< result->GetErrorMessage()
				);
			delete result;
			result = NULL;
		}
	}

	const bool succeeded = result != NULL && result->IsValid();	
	delete result;
	return succeeded ? Ok : Fail;
}

PString SQLAcct::GetInfo()
{
	PString result;
	
	if (m_sqlConn == NULL)
		result += "  No SQL connection available\r\n";
	else {
		GkSQLConnection::Info info;
		m_sqlConn->GetInfo(info);
		result += "  Connected to an SQL Backend: " + PString(info.m_connected ? "Yes" : "No") + "\r\n";
		result += "  Min Connection Pool Size:    " + PString(info.m_minPoolSize) + "\r\n";
		result += "  Max Connection Pool Size:    " + PString(info.m_maxPoolSize) + "\r\n";
		result += "  Idle Connections:            " + PString(info.m_idleConnections) + "\r\n";
		result += "  Busy Connections::           " + PString(info.m_busyConnections) + "\r\n";
		result += "  Waiting Requests:            " + PString(info.m_waitingRequests) + "\r\n";
	}
	
	result += ";\r\n";
	
	return result;
}

namespace {
GkAcctLoggerCreator<SQLAcct> SQLAcctLoggerCreator("SQLAcct");
}
