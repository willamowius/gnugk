#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#endif

#include <ptlib.h>
#include "gksql.h"
#include "stl_supp.h"

#define GKSQL_DEFAULT_MIN_POOL_SIZE 1
#define GKSQL_DEFAULT_MAX_POOL_SIZE 1
#define GKSQL_CLEANUP_TIMEOUT 5000

GkSQLResult::~GkSQLResult() 
{
}

GkSQLConnection::GkSQLConnection(
	/// name to use in the log
	const char* name
	)
	: NamedObject(name),
	m_minPoolSize(GKSQL_DEFAULT_MIN_POOL_SIZE), 
	m_maxPoolSize(GKSQL_DEFAULT_MAX_POOL_SIZE), m_destroying(false)
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
	
	PStringArray hosts = cfg->GetString(cfgSectionName, "Host", "localhost").Tokenise(";");
	for (PINDEX i = 0; i < hosts.GetSize(); i++) {
		const PString host = hosts[i].Trim();
		if (!host.IsEmpty())
			m_hosts += host;
	}

	m_database = cfg->GetString(cfgSectionName, "Database", "");
	m_username = cfg->GetString(cfgSectionName, "Username", "");
	m_password = cfg->GetString(cfgSectionName, "Password", "");
	m_minPoolSize = cfg->GetInteger(cfgSectionName, "MinPoolSize", GKSQL_DEFAULT_MIN_POOL_SIZE);
	m_minPoolSize = std::max(m_minPoolSize, 0);
	m_maxPoolSize = cfg->GetInteger(cfgSectionName, "MaxPoolSize", m_minPoolSize);
	if (m_maxPoolSize >= 0)
		m_maxPoolSize = std::max(m_minPoolSize, m_maxPoolSize);
		
	if (m_hosts.GetSize() < 1 || m_database.IsEmpty()) {
		PTRACE(1, GetName() << "\tInitialize failed: database name or host no specified!");
		return false;
	}

	return Connect();	
}

bool GkSQLConnection::Initialize(
	const char* hosts,
	const char* database,
	const char* username,
	const char* password,
	int minPoolSize,
	int maxPoolSize
	)
{
	PWaitAndSignal lock(m_connectionsMutex);
	
	m_minPoolSize = std::max(minPoolSize,0);
	if (maxPoolSize == -1)
		m_maxPoolSize = -1;
	else
		m_maxPoolSize = std::max(maxPoolSize,m_minPoolSize);
	
	PStringArray hostArray = PString(hosts).Tokenise(";");
	for (PINDEX i = 0; i < hostArray.GetSize(); i++) {
		const PString host = hostArray[i].Trim();
		if (!host.IsEmpty())
			m_hosts += host;
	}

	m_database = database;
	m_username = username;
	m_password = password;

	if (m_hosts.GetSize() < 1 || m_database.IsEmpty()) {
		PTRACE(1, GetName() << "\tInitialize failed: database name or host no specified!");
		return false;
	}
	
	return Connect();	
}

bool GkSQLConnection::Connect()
{
	for (PINDEX i = 0; i < m_minPoolSize; i++) {
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
		return true;
	}
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
	if (!m_busyConnections.empty())
		PTRACE(1, GetName() << "\tConnection cleanup finished with " << m_busyConnections.size() << " active connections");
}

GkSQLResult* GkSQLConnection::ExecuteQuery(
	const char* queryStr,
	const PStringArray* queryParams,
	long timeout
	)
{
	if (m_destroying)
		return NULL;

	const PTime timeStart;
	GkSQLResult* result = NULL;

	// special case (no pool) for fast execution
	if (m_minPoolSize == 1 && m_maxPoolSize == 1) {
		if (!(timeout == -1 ? (m_connectionsMutex.Wait(), true) : m_connectionsMutex.Wait(timeout))) {
			PTRACE(2, GetName() << "\tQuery timed out waiting " << timeout << "ms for the connection");
			return NULL;
		}
		if (!m_destroying) {
			SQLConnPtr connptr = m_idleConnections.front();
			if (connptr) {
				if (queryParams) {
					const PString finalQueryStr = ReplaceQueryParams(connptr, queryStr, *queryParams);
					PTRACE(5, GetName() << "\tExecuting query: " << finalQueryStr);
					result = ExecuteQuery(connptr, finalQueryStr, timeout);
				} else {
					PTRACE(5, GetName() << "\tExecuting query: " << queryStr);
					result = ExecuteQuery(connptr, queryStr, timeout);
				}
			} else
				PTRACE(2, GetName() << "\tQuery failed - no idle connection in the pool");
		}
		m_connectionsMutex.Signal();
		return result;
	}

	SQLConnPtr connptr = NULL;
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
			m_connectionAvailable.Wait(std::min(250L,timeout));
		
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
		return NULL;
	}

	// backed specific query execution
	if (queryParams) {
		const PString finalQueryStr = ReplaceQueryParams(connptr, queryStr, *queryParams);
		PTRACE(5, GetName() << "\tExecuting query: " << finalQueryStr);
		result = ExecuteQuery(connptr, finalQueryStr, timeout);
	} else {
		PTRACE(5, GetName() << "\tExecuting query: " << queryStr);
		result = ExecuteQuery(connptr, queryStr, timeout);
	}
	
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
		if (iter != end && *iter && !m_destroying) {
			// do not remove itself from the list of busy connections
			// just move the connection to the waiting request
			*(*iter) = connptr;
		} else {
			// move the connection to the list of idle connections
			m_busyConnections.remove(connptr);
			m_idleConnections.push_back(connptr);
		}
		
		connptr = NULL;
	}

	// wake up any threads waiting for an idle connection
	m_connectionAvailable.Signal();
	
	return result;
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
	PString finalQuery(queryStr);
	PINDEX queryLen = finalQuery.GetLength();
	char* endChar;
	PINDEX percentPos = 0;

	for (PINDEX i = 0; i < queryParams.GetSize(); i++) {
		while (percentPos != P_MAX_INDEX && percentPos < queryLen) {
			percentPos = finalQuery.Find('%', percentPos);
			if (percentPos == P_MAX_INDEX)
				break;
			percentPos++;
			if (percentPos >= queryLen) {
				percentPos = P_MAX_INDEX;
				break;
			}
			if (finalQuery[percentPos] == '%') {
				percentPos++;
				continue;
			}
			if (finalQuery[percentPos] >= '0' && finalQuery[percentPos] <= '9') {
				const long paramNo = strtol((const char*)finalQuery + percentPos, &endChar, 10);
				if (paramNo == (i+1)) {
					const PString escapedStr = EscapeString(conn, queryParams[i]);
					finalQuery.Splice(escapedStr, percentPos - 1, 
						endChar - (const char*)finalQuery - percentPos + 1
						);
					queryLen = finalQuery.GetLength();
					percentPos += escapedStr.GetLength() - 1;
					break;
				} else if (paramNo > (i+1)) {
					percentPos--;
					break;
				}
				continue;
			}
			if (finalQuery[percentPos] != '{')
				continue;
			
			percentPos++;
			const PINDEX closingBrace = finalQuery.Find('}', percentPos);
			if (closingBrace == P_MAX_INDEX)
				continue;

			const int paramNo = strtol((const char*)finalQuery + percentPos, &endChar, 10);
			if (*endChar == '}')
				if (paramNo == (i+1)) {
					const PString escapedStr = EscapeString(conn, queryParams[i]);
					finalQuery.Splice(escapedStr, percentPos - 2, endChar - (const char*)finalQuery - percentPos + 3);
					queryLen = finalQuery.GetLength();
					percentPos += escapedStr.GetLength() - 2;
					break;
				} else if (paramNo > (i+1)) {
					percentPos -= 2;
					break;
				}
		}
	}

	return finalQuery;
}

GkSQLConnection::SQLConnWrapper::~SQLConnWrapper()
{
}
