/*
 * gksql.cxx
 *
 * Generic interface to access SQL databases
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 * Copyright (c) 2006-2010, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include <ptlib.h>
#include <ptlib/sockets.h>
#include "stl_supp.h"
#include "Toolkit.h"
#include "gksql.h"

using std::max;
using std::min;

namespace {
const int GKSQL_DEFAULT_MIN_POOL_SIZE = 1;
const int GKSQL_DEFAULT_MAX_POOL_SIZE = 1;
const long GKSQL_CLEANUP_TIMEOUT = 5000;
}


GkSQLResult::~GkSQLResult() 
{
}

GkSQLConnection::GkSQLConnection(
	/// name to use in the log
	const char* name
	)
	: NamedObject(name),
	m_minPoolSize(GKSQL_DEFAULT_MIN_POOL_SIZE), 
	m_maxPoolSize(GKSQL_DEFAULT_MAX_POOL_SIZE),
	m_destroying(false), m_connected(false)
{
}

GkSQLConnection* GkSQLConnection::Create(
	const char* driverName,
	const char* connectionName
	)
{
	return Factory<GkSQLConnection>::Create(driverName, connectionName);
}

bool GkSQLConnection::Initialize(
	/// config to be read
	PConfig* cfg,
	/// name of the config section with SQL settings
	const char* cfgSectionName
	)
{
	PWaitAndSignal lock(m_connectionsMutex);
	
	if (!(cfg && cfgSectionName)) {
		PTRACE(1, GetName() << "\tInitialize failed: NULL config or config section not specified!");
		return false;
	}

	m_library = cfg->GetString(cfgSectionName, "Library", "");
	GetHostAndPort(cfg->GetString(cfgSectionName, "Host", "localhost"), m_host, m_port);
	m_database = cfg->GetString(cfgSectionName, "Database", "");
	m_username = cfg->GetString(cfgSectionName, "Username", "");
	m_password = Toolkit::Instance()->ReadPassword(cfgSectionName, "Password");
	m_minPoolSize = cfg->GetInteger(cfgSectionName, "MinPoolSize", GKSQL_DEFAULT_MIN_POOL_SIZE);
	m_minPoolSize = max(m_minPoolSize, 0);
	m_maxPoolSize = cfg->GetInteger(cfgSectionName, "MaxPoolSize", m_minPoolSize);
	if (m_maxPoolSize >= 0)
		m_maxPoolSize = max(m_minPoolSize, m_maxPoolSize);
		
	if (m_host.IsEmpty() || m_database.IsEmpty()) {
		PTRACE(1, GetName() << "\tInitialize failed: database name or host not specified!");
		return false;
	}

	return Connect();	
}

bool GkSQLConnection::Connect()
{
	PWaitAndSignal lock(m_connectionsMutex);
	
	for (PINDEX i = m_idleConnections.size(); i < m_minPoolSize; ++i) {
		SQLConnPtr connptr = CreateNewConnection(i);
		if (connptr != NULL)
			m_idleConnections.push_back(connptr);
	}
	
	if (m_idleConnections.empty() && m_minPoolSize) {
		PTRACE(1, GetName() << "\tDatabase connection failed: " 
			<< m_username << '@' << m_host << '[' << m_database << ']'
			);
		return false;
	} else {
		PTRACE(3, GetName() << "\tDatabase connection pool created: " 
			<< m_username << '@' << m_host << '[' << m_database << ']'
			);
		PTRACE(5, GetName() << "\tConnection pool: " 
			<< m_idleConnections.size() << " SQL connections created, "
			<< (m_minPoolSize - m_idleConnections.size()) << " failed"
			);
		m_connected = true;
		return true;
	}
}

void GkSQLConnection::Disconnect()
{
	PWaitAndSignal lock(m_connectionsMutex);
	
	// disconnect/delete all connections
	PTRACE(3, GetName() << "\tDisconnecting all SQL connections in pool");
	for(iterator Iter = m_idleConnections.begin(); Iter != m_idleConnections.end(); ++Iter) {
		delete *Iter;
	}
	m_idleConnections.clear();
	m_connected = false;
}

GkSQLConnection::~GkSQLConnection()
{
	const PTime timeStart;
	
	m_destroying = true;
	// wakeup any waiting threads
	m_connectionAvailable.Signal();
	
	// wait for still active connections (should not happen, but...)
	do {
		{
			PWaitAndSignal lock(m_connectionsMutex);
			m_waitingRequests.clear();
			if (m_busyConnections.empty())
				break;
			else
				PTRACE(2, GetName() << "\tActive connections (" << m_busyConnections.size() << ") during cleanup - sleeping 250ms");
		}
		PThread::Sleep(250);
	} while ((PTime()-timeStart).GetMilliSeconds() < GKSQL_CLEANUP_TIMEOUT);
	
	// close connections from the idle list and leave any on the busy list
	// busy list should be empty at this moment
	PWaitAndSignal lock(m_connectionsMutex);
	
	m_waitingRequests.clear();
	iterator iter = m_idleConnections.begin();
	iterator end = m_idleConnections.end();
	
	while (iter != end) {
		PTRACE(5, GetName() << "\tDatabase connection (id " << (*iter)->m_id << ") closed");
		delete *iter++;
	}

	m_idleConnections.clear();

	PTRACE(5, GetName() << "\tConnection pool cleanup finished");
	if (!m_busyConnections.empty()) {
		PTRACE(1, GetName() << "\tConnection cleanup finished with " << m_busyConnections.size() << " active connections");
	}
}

bool GkSQLConnection::AcquireSQLConnection(
	SQLConnPtr& connptr,
	long timeout
	)
{
	if (m_destroying)
		return false;

	if (!m_connected) {
		PTRACE(2, GetName() << "\tAttempting to reconnect to the database");
		Disconnect();
		if (!Connect()) {
			PTRACE(2, GetName() << "\tFailed to reconnect to the database");
			return false;
		}
	}
	
	const PTime timeStart;
	connptr = NULL;
	bool waiting = false;

	// wait for an idle connection or timeout
	do {
		if (!waiting) {
			PWaitAndSignal lock(m_connectionsMutex);

			if (m_destroying)
				break;

			// grab an idle connection if available or add itself
			// to the list of waiting requests
			if (!m_idleConnections.empty()) {
				connptr = m_idleConnections.front();
				m_idleConnections.pop_front();
				m_busyConnections.push_front(connptr);
			} else {
				m_waitingRequests.push_back(&connptr);
				waiting = true;
			}
		}

		if (connptr == NULL && timeout != 0 && !m_destroying)
			m_connectionAvailable.Wait(min(250L,timeout));

		if (connptr == NULL && timeout >= 0)
			if ((PTime()-timeStart).GetMilliSeconds() >= timeout)
				break;
	} while (connptr == NULL && !m_destroying);

	if (connptr == NULL || m_destroying) {
		PWaitAndSignal lock(m_connectionsMutex);
		m_waitingRequests.remove(&connptr);
		if (connptr) {
			m_idleConnections.push_back(connptr);
			m_busyConnections.remove(connptr);
		}
		PTRACE(2, GetName() << "\tQuery timed out waiting for idle connection");
		return false;
	}

	return connptr != NULL;
}

void GkSQLConnection::ReleaseSQLConnection(
	SQLConnPtr& connptr,
	bool deleteFromPool
	)
{
	if (connptr == NULL)
		return;

	// mark the connection as idle or give it to the first waiting request
	{
		PWaitAndSignal lock(m_connectionsMutex);

		// remove itself from the list of waiting requests
		m_waitingRequests.remove(&connptr);

		witerator iter = m_waitingRequests.begin();
		witerator end = m_waitingRequests.end();

		// find a waiting requests that has not been given a connection yet
		while (iter != end) {
			// check if SQLConnPtr* is not NULL and if SQLConnPtr is empty (NULL)
			if (*iter && *(*iter) == NULL)
				break;
			iter++;
		}
		if (iter != end && !m_destroying && !deleteFromPool) {
			// do not remove itself from the list of busy connections
			// just move the connection to the waiting request
			*(*iter) = connptr;
		} else {
			// move the connection to the list of idle connections
			m_busyConnections.remove(connptr);
			if (deleteFromPool)
				delete connptr;
			else
				m_idleConnections.push_back(connptr);
		}

		connptr = NULL;
	}

	// wake up any threads waiting for an idle connection
	if (!deleteFromPool)
		m_connectionAvailable.Signal();
}

GkSQLResult* GkSQLConnection::ExecuteQuery(
	const char* queryStr,
	const PStringArray* queryParams,
	long timeout
	)
{
	SQLConnPtr connptr;
	
	if (AcquireSQLConnection(connptr, timeout)) {
		GkSQLResult* result = NULL;
		if (queryParams) {
			const PString finalQueryStr = ReplaceQueryParams(connptr, queryStr, *queryParams);
			PTRACE(5, GetName() << "\tExecuting query: " << finalQueryStr);
			result = ExecuteQuery(connptr, finalQueryStr, timeout);
		} else {
			PTRACE(5, GetName() << "\tExecuting query: " << queryStr);
			result = ExecuteQuery(connptr, queryStr, timeout);
		}
		ReleaseSQLConnection(connptr, !m_connected);
		return result;
	} else {
		PTRACE(2, GetName() << "\tQuery failed - no idle connection in the pool");
		return NULL;
	}
}

GkSQLResult* GkSQLConnection::ExecuteQuery(
	const char* queryStr,
	const std::map<PString, PString>& queryParams,
	long timeout
	)
{
	SQLConnPtr connptr;
	
	if (AcquireSQLConnection(connptr, timeout)) {
		GkSQLResult* result = NULL;
		if (queryParams.empty()) {
			PTRACE(5, GetName() << "\tExecuting query: " << queryStr);
			result = ExecuteQuery(connptr, queryStr, timeout);
		} else {
			const PString finalQueryStr = ReplaceQueryParams(connptr, queryStr, queryParams);
			PTRACE(5, GetName() << "\tExecuting query: " << finalQueryStr);
			result = ExecuteQuery(connptr, finalQueryStr, timeout);
		}
		ReleaseSQLConnection(connptr, !m_connected);
		return result;
	} else {
		PTRACE(2, GetName() << "\tQuery failed - no idle connection in the pool");
		return NULL;
	}
}

PString GkSQLConnection::ReplaceQueryParams(
	/// SQL connection to get escape parameters from
	GkSQLConnection::SQLConnPtr conn,
	/// parametrized query string
	const char* queryStr,
	/// parameter values
	const PStringArray& queryParams
	)
{
	const PINDEX numParams = queryParams.GetSize();
	PString finalQuery(queryStr);
	PINDEX queryLen = finalQuery.GetLength();
	PINDEX pos = 0;
	char* endChar;

	while (pos != P_MAX_INDEX && pos < queryLen) {
		pos = finalQuery.Find('%', pos);
		if (pos++ == P_MAX_INDEX)
			break;
		if (pos >= queryLen) // strings ending with '%' - special case
			break;
		const char c = finalQuery[pos]; // char next after '%'
		if (c == '%') { // replace %% with %
			finalQuery.Delete(pos, 1);
			queryLen--;
		} else if (c >= '0' && c <= '9') { // simple syntax (%1)
			const long paramNo = strtol((const char*)finalQuery + pos, &endChar, 10);
			const long paramLen = endChar - (const char*)finalQuery - pos;
			if (paramNo >= 1 && paramNo <= numParams) {
				const PString escapedStr = EscapeString(conn, queryParams[paramNo-1]);
				const PINDEX escapedLen = escapedStr.GetLength();
				finalQuery.Splice(escapedStr, pos - 1, paramLen + 1);
				queryLen = queryLen + escapedLen - paramLen - 1;
				pos = pos - 1 + escapedLen;
			} else if (paramNo && paramLen) {
				// replace out of range parameter with an empty string
				finalQuery.Delete(pos - 1, paramLen + 1);
				queryLen -= paramLen + 1;
				pos--;
			}
		} else if (c == '{') { // escaped syntax (%{1})
			const PINDEX closingBrace = finalQuery.Find('}', ++pos);
			if (closingBrace != P_MAX_INDEX) {
				const long paramNo = strtol((const char*)finalQuery + pos, &endChar, 10);
				const long paramLen = endChar - (const char*)finalQuery - pos;
				if (*endChar == '}' && paramNo >= 1 && paramNo <= numParams) {
					const PString escapedStr = EscapeString(conn, queryParams[paramNo-1]);
					const PINDEX escapedLen = escapedStr.GetLength();
					finalQuery.Splice(escapedStr, pos - 2, paramLen + 3);
					queryLen = queryLen + escapedLen - paramLen - 3;
					pos = pos - 2 + escapedLen;
				} else if (paramNo && paramLen) {
					// replace out of range parameter with an empty string
					finalQuery.Delete(pos - 2, paramLen + 3);
					queryLen -= paramLen + 3;
					pos -= 2;
				}
			}
		}
	}

	return finalQuery;
}

PString GkSQLConnection::ReplaceQueryParams(
	/// SQL connection to get escape parameters from
	GkSQLConnection::SQLConnPtr conn,
	/// parametrized query string
	const char* queryStr,
	/// parameter values
	const std::map<PString, PString>& queryParams
	)
{
	PString finalQuery(queryStr);
	PINDEX queryLen = finalQuery.GetLength();
	PINDEX pos = 0;

	while (pos != P_MAX_INDEX && pos < queryLen) {
		pos = finalQuery.Find('%', pos);
		if (pos++ == P_MAX_INDEX)
			break;
		if (pos >= queryLen) // strings ending with '%' - special case
			break;
		const char c = finalQuery[pos]; // char next after '%'
		if (c == '%') { // replace %% with %
			finalQuery.Delete(pos, 1);
			queryLen--;
		} else if (c == '{') { // escaped syntax (%{Name})
			const PINDEX closingBrace = finalQuery.Find('}', ++pos);
			if (closingBrace != P_MAX_INDEX) {
				const PINDEX paramLen = closingBrace - pos;
				std::map<PString, PString>::const_iterator i = queryParams.find(
					finalQuery.Mid(pos, paramLen)
					);
				if (i != queryParams.end()) {
					const PString escapedStr = EscapeString(conn, i->second);
					const PINDEX escapedLen = escapedStr.GetLength();
					finalQuery.Splice(escapedStr, pos - 2, paramLen + 3);
					queryLen = queryLen + escapedLen - paramLen - 3;
					pos = pos - 2 + escapedLen;
				} else {
					// replace out of range parameter with an empty string
					finalQuery.Delete(pos - 2, paramLen + 3);
					queryLen -= paramLen + 3;
					pos -= 2;
				}
			}
		} else { // simple syntax (%1)
			std::map<PString, PString>::const_iterator i = queryParams.find(c);
			if (i != queryParams.end()) {
				const PString escapedStr = EscapeString(conn, i->second);
				const PINDEX escapedLen = escapedStr.GetLength();
				finalQuery.Splice(escapedStr, pos - 1, 2);
				queryLen = queryLen + escapedLen - 2;
				pos = pos - 1 + escapedLen;
			} else {
				// replace out of range parameter with an empty string
				finalQuery.Delete(pos - 1, 2);
				queryLen -= 2;
				pos--;
			}
		}
	}

	return finalQuery;
}

void GkSQLConnection::GetInfo(
	Info &info /// filled with SQL connection state information upon return
	)
{
	PWaitAndSignal lock(m_connectionsMutex);

	info.m_connected = m_connected;
	info.m_minPoolSize = m_minPoolSize;
	info.m_maxPoolSize = m_maxPoolSize;
	info.m_idleConnections = m_idleConnections.size();
	info.m_busyConnections = m_busyConnections.size();
	info.m_waitingRequests = m_waitingRequests.size();
}

GkSQLConnection::SQLConnWrapper::~SQLConnWrapper()
{
}
