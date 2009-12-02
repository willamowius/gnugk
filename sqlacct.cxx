/*
 * sqlacct.cxx
 *
 * SQL accounting module for GNU Gatekeeper
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.18  2009/05/24 20:48:26  willamowius
 * remove hacks for VC6 which isn't supported any more since quite a while
 *
 * Revision 1.17  2009/02/09 13:25:59  willamowius
 * typo in comment
 *
 * Revision 1.16  2008/09/05 13:44:14  zvision
 * GetInfo implemented for SQL acct/auth modules
 *
 * Revision 1.15  2008/07/10 08:07:54  willamowius
 * avoid gcc 4.3.x warnings
 *
 * Revision 1.14  2007/09/28 22:20:23  willamowius
 * cleanup includes
 *
 * Revision 1.13  2006/04/14 13:56:19  willamowius
 * call failover code merged
 *
 * Revision 1.1.1.1  2005/11/21 20:20:00  willamowius
 *
 *
 * Revision 1.4  2005/11/15 19:52:56  jan
 * Michal v1 (works, but on in routed, not proxy mode)
 *
 * Revision 1.12  2005/05/19 16:41:17  zvision
 * Solaris need explicit std::map
 *
 * Revision 1.11  2005/04/24 16:39:45  zvision
 * MSVC6.0 compatibility fixed
 *
 * Revision 1.10  2005/03/15 11:49:38  zvision
 * Make reconnect working correctly when a database server is down
 *
 * Revision 1.9  2005/03/08 00:13:47  zvision
 * Support for connect event in SqlAcct module, thanks to Boian Bonev
 *
 * Revision 1.8  2005/01/12 17:55:07  willamowius
 * fix gkip accounting parameter
 *
 * Revision 1.7  2005/01/05 15:42:41  willamowius
 * new accounting event 'connect', parameter substitution unified in parent class
 *
 * Revision 1.6  2005/01/04 18:13:42  willamowius
 * space in trace msg
 *
 * Revision 1.5  2004/12/15 14:43:25  zvision
 * Shutdown the gatekeeper on SQL auth/acct module config errors.
 * Thanks to Mikko Oilinki.
 *
 * Revision 1.4  2004/11/15 23:57:43  zvision
 * Ability to choose between the original and the rewritten dialed number
 *
 * Revision 1.3  2004/11/10 18:30:41  zvision
 * Ability to customize timestamp strings
 *
 * Revision 1.2  2004/07/09 22:11:36  zvision
 * SQLAcct module ported from 2.0 branch
 *
 * Revision 1.1.2.6  2004/06/22 18:41:17  zvision
 * Username, Calling-Station-Id and Called-Station-Id handling rewritten.
 * Radius modules optimized.
 *
 * Revision 1.1.2.5  2004/06/18 15:42:51  zvision
 * Better User-Name and Calling-Station-Id handling for unregistered endpoints
 *
 * Revision 1.1.2.4  2004/06/06 12:31:04  zvision
 * New SQLAcct/FileAcct parameters. Thanks to Patrick!
 *
 * Revision 1.1.2.3  2004/05/12 14:00:48  zvision
 * Header file usage more consistent. Solaris std::map problems fixed.
 * Compilation warnings removed. VSNET2003 project files added. ANSI.h removed.
 *
 * Revision 1.1.2.2  2004/04/24 10:31:57  zvision
 * Use baseclass GetConfigSectionName
 *
 * Revision 1.1.2.1  2004/04/23 16:01:16  zvision
 * New direct SQL accounting module (SQLAcct)
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

	if (query.IsEmpty()) {
		PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
			"data (event: " << evt << ", call: " << callNumber 
			<< "): SQL query is empty"
			);
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
	
	PString query, queryAlt;
	if (evt == AcctRegister)
		query = m_registerQuery;
	else if (evt == AcctUnregister)
		query = m_unregisterQuery;

	if (query.IsEmpty()) {
		PTRACE(2, "GKACCT\t" << GetName() << " failed to store accounting "
			"data (event: " << evt << ", endpoint: " << epid
			<< "): SQL query is empty"
			);
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
