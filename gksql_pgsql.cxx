/*
 * gksql_pgsql.cxx
 *
 * PostgreSQL driver module for GnuGk
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 * Copyright (c) 2006-2012, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"

#if HAS_PGSQL

#include <ptlib.h>
#include <libpq-fe.h>
#include "gksql.h"

static PDynaLink g_sharedLibrary;
static void (*g_PQclear)(PGresult *res) = NULL;
static char * (*g_PQcmdTuples)(PGresult *res) = NULL;
static char * (*g_PQerrorMessage)(const PGconn *conn) = NULL;
static size_t (*g_PQescapeStringConn)(PGconn *conn, char *to, const char *from, size_t length, int *error) = NULL;
static PGresult * (*g_PQexec)(PGconn *conn, const char *query) = NULL;
static void (*g_PQfinish)(PGconn *conn) = NULL;
static char * (*g_PQfname)(const PGresult *res, int field_num) = NULL;
static int (*g_PQgetlength)(const PGresult *res, int tup_num, int field_num) = NULL;
static char * (*g_PQgetvalue)(const PGresult *res, int tup_num, int field_num) = NULL;
static int (*g_PQnfields)(const PGresult *res) = NULL;
static int (*g_PQntuples)(const PGresult *res) = NULL;
static char * (*g_PQresultErrorMessage)(const PGresult *res) = NULL;
static ExecStatusType (*g_PQresultStatus)(const PGresult *res) = NULL;
static PGconn * (*g_PQsetdbLogin)(const char *pghost, const char *pgport,
             const char *pgoptions, const char *pgtty,
             const char *dbName,
             const char *login, const char *pwd) = NULL;
static ConnStatusType (*g_PQstatus)(const PGconn *conn) = NULL;


/** Class that encapsulates SQL query result for PostgreSQL backend.
	It does not provide any multithread safety, so should be accessed
	from a single thread at time.
*/
class GkPgSQLResult : public GkSQLResult
{
public:
	/// Build the result from SELECT type query
	GkPgSQLResult(
		/// SELECT type query result
		PGresult* selectResult
		);

	/// Build the result from INSERT, DELETE or UPDATE query
	GkPgSQLResult(
		/// number of rows affected by the query
		long numRowsAffected
		);

	/// Build the empty	result and store query execution error information
	GkPgSQLResult(
		/// PostgreSQL specific error code
		unsigned int errorCode,
		/// PostgreSQL specific error message text
		const char* errorMsg
		);
	
	virtual ~GkPgSQLResult();
	
	/** @return
	    Backend specific error message, if the query failed.
	*/	
	virtual PString GetErrorMessage();
	
	/** @return
	    Backend specific error code, if the query failed.
	*/	
	virtual long GetErrorCode();
	
	/** Fetch a single row from the result set. After each row is fetched,
	    cursor position is moved to a next row.
		
	    @return
	    True if the row has been fetched, false if no more rows are available.
	*/
	virtual bool FetchRow(
		/// array to be filled with string representations of the row fields
		PStringArray& result
		);
	virtual bool FetchRow(
		/// array to be filled with string representations of the row fields
		ResultRow& result
		);

private:
	GkPgSQLResult();
	GkPgSQLResult(const GkPgSQLResult&);
	GkPgSQLResult& operator=(const GkPgSQLResult&);
	
protected:
	/// query result for SELECT type queries, NULL otherwise
	PGresult* m_sqlResult;
	/// the most recent row returned by fetch operation
	int m_sqlRow;
	/// PgSQL specific error code (if the query failed)
	unsigned int m_errorCode;
	/// PgSQL specific error message text (if the query failed)
	PString m_errorMessage;
};

/// PostgreSQL backend connection implementation.
class GkPgSQLConnection : public GkSQLConnection
{
public:
	/// Build a new PgSQL connection object
	GkPgSQLConnection(
		/// name to use in the log
		const char* name = "PostgreSQL"
		);
	
	virtual ~GkPgSQLConnection();

protected:
	class PgSQLConnWrapper : public GkSQLConnection::SQLConnWrapper
	{
	public:
		PgSQLConnWrapper(
			/// unique identifier for this connection
			int id,
			/// host:port this connection is made to
			const PString& host,
			/// PostgreSQL connection object
			PGconn* conn
			) : SQLConnWrapper(id, host), m_conn(conn) {}

		virtual ~PgSQLConnWrapper();

	private:
		PgSQLConnWrapper();
		PgSQLConnWrapper(const PgSQLConnWrapper&);
		PgSQLConnWrapper& operator=(const PgSQLConnWrapper&);

	public:
		PGconn* m_conn;
	};

	/** Create a new SQL connection using parameters stored in this object.
	    When the connection is to be closed, the object is simply deleted
	    using delete operator.

	    @return
	    NULL if database connection could not be established 
	    or an object of PgSQLConnWrapper class.
	*/
	virtual SQLConnPtr CreateNewConnection(
		/// unique identifier for this connection
		int id
		);
	
	/** Execute the query using specified SQL connection.

		@return
		Query execution result.
	*/
	virtual GkSQLResult* ExecuteQuery(
		/// SQL connection to use for query execution
		SQLConnPtr conn,
		/// query string
		const char* queryStr,
		/// maximum time (ms) for the query execution, -1 means infinite
		long timeout = -1
		);
		
	/** Escape any special characters in the string, so it can be used in a SQL query.

		@return
		Escaped string.
	*/
	virtual PString EscapeString(
		/// SQL connection to get escaping parameters from
		SQLConnPtr conn,
		/// string to be escaped
		const char* str
		);

private:
	GkPgSQLConnection(const GkPgSQLConnection&);
	GkPgSQLConnection& operator=(const GkPgSQLConnection&);
};


GkPgSQLResult::GkPgSQLResult(
	/// SELECT type query result
	PGresult* selectResult
	) 
	: GkSQLResult(false), m_sqlResult(selectResult), m_sqlRow(-1),
	m_errorCode(0)
{
	if (m_sqlResult) {
		m_numRows = (*g_PQntuples)(m_sqlResult);
		m_numFields = (*g_PQnfields)(m_sqlResult);
	} else
		m_queryError = true;
}

GkPgSQLResult::GkPgSQLResult(
	/// number of rows affected by the query
	long numRowsAffected
	) 
	: GkSQLResult(false), m_sqlResult(NULL), m_sqlRow(-1), 
	m_errorCode(0)
{
	m_numRows = numRowsAffected;
}
	
GkPgSQLResult::GkPgSQLResult(
	/// PostgreSQL specific error code
	unsigned int errorCode,
	/// PostgreSQL specific error message text
	const char* errorMsg
	) 
	: GkSQLResult(true), m_sqlResult(NULL), m_sqlRow(-1),
	m_errorCode(errorCode), m_errorMessage(errorMsg)
{
}

GkPgSQLResult::~GkPgSQLResult()
{
	if (m_sqlResult)
		(*g_PQclear)(m_sqlResult);
}

PString GkPgSQLResult::GetErrorMessage()
{
	return m_errorMessage;
}
	
long GkPgSQLResult::GetErrorCode()
{
	return m_errorCode;
}

bool GkPgSQLResult::FetchRow(
	/// array to be filled with string representations of the row fields
	PStringArray& result
	)
{
	if (m_sqlResult == NULL || m_numRows <= 0)
		return false;
	
	if (m_sqlRow < 0)
		m_sqlRow = 0;
		
	if (m_sqlRow >= m_numRows)
		return false;
		
	result.SetSize(m_numFields);
	
	for (PINDEX i = 0; i < m_numFields; i++)
		result[i] = PString(
			(*g_PQgetvalue)(m_sqlResult, m_sqlRow, i), 
			(*g_PQgetlength)(m_sqlResult, m_sqlRow, i)
			);
	
	m_sqlRow++;
	
	return true;
}

bool GkPgSQLResult::FetchRow(
	/// array to be filled with string representations of the row fields
	ResultRow& result
	)
{
	if (m_sqlResult == NULL || m_numRows <= 0)
		return false;
	
	if (m_sqlRow < 0)
		m_sqlRow = 0;
		
	if (m_sqlRow >= m_numRows)
		return false;
		
	result.resize(m_numFields);
	
	for (PINDEX i = 0; i < m_numFields; i++) {
		result[i].first = PString(
			(*g_PQgetvalue)(m_sqlResult, m_sqlRow, i), 
			(*g_PQgetlength)(m_sqlResult, m_sqlRow, i)
			);
		result[i].second = (*g_PQfname)(m_sqlResult, i);
	}
	
	m_sqlRow++;
	
	return true;
}


GkPgSQLConnection::GkPgSQLConnection(
	/// name to use in the log
	const char* name
	) : GkSQLConnection(name)
{
}
	
GkPgSQLConnection::~GkPgSQLConnection()
{
}

GkPgSQLConnection::PgSQLConnWrapper::~PgSQLConnWrapper()
{
	(*g_PQfinish)(m_conn);
}

GkSQLConnection::SQLConnPtr GkPgSQLConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	if (!g_sharedLibrary.IsLoaded()) {
		if (m_library.IsEmpty()) {
			m_library = "libpq" + g_sharedLibrary.GetExtension();
		}

		if (!g_sharedLibrary.Open(m_library)) {
			PTRACE (1, GetName() << "\tCan't load library " << m_library);
			return NULL;
		}

		if (!g_sharedLibrary.GetFunction("PQclear", (PDynaLink::Function &)g_PQclear)
			|| !g_sharedLibrary.GetFunction("PQcmdTuples", (PDynaLink::Function &)g_PQcmdTuples)
			|| !g_sharedLibrary.GetFunction("PQerrorMessage", (PDynaLink::Function &)g_PQerrorMessage)
			|| !g_sharedLibrary.GetFunction("PQescapeStringConn", (PDynaLink::Function &)g_PQescapeStringConn)
			|| !g_sharedLibrary.GetFunction("PQexec", (PDynaLink::Function &)g_PQexec)
			|| !g_sharedLibrary.GetFunction("PQfinish", (PDynaLink::Function &)g_PQfinish)
			|| !g_sharedLibrary.GetFunction("PQfname", (PDynaLink::Function &)g_PQfname)
			|| !g_sharedLibrary.GetFunction("PQgetlength", (PDynaLink::Function &)g_PQgetlength)
			|| !g_sharedLibrary.GetFunction("PQgetvalue", (PDynaLink::Function &)g_PQgetvalue)
			|| !g_sharedLibrary.GetFunction("PQnfields", (PDynaLink::Function &)g_PQnfields)
			|| !g_sharedLibrary.GetFunction("PQntuples", (PDynaLink::Function &)g_PQntuples)
			|| !g_sharedLibrary.GetFunction("PQresultErrorMessage", (PDynaLink::Function &)g_PQresultErrorMessage)
			|| !g_sharedLibrary.GetFunction("PQresultStatus", (PDynaLink::Function &)g_PQresultStatus)
			|| !g_sharedLibrary.GetFunction("PQsetdbLogin", (PDynaLink::Function &)g_PQsetdbLogin)
			|| !g_sharedLibrary.GetFunction("PQstatus", (PDynaLink::Function &)g_PQstatus)
			) {
#ifdef hasDynaLinkGetLastError
			PTRACE (1, GetName() << "\tFailed to load shared database library: " << g_sharedLibrary.GetLastError());
#else
			PTRACE (1, GetName() << "\tFailed to load shared database library: unknown error");
#endif
			g_sharedLibrary.Close();
			SNMP_TRAP(5, SNMPError, Database, GetName() + " DLL load error");
			return NULL;
		}
	}

	PGconn* conn;
	const PString portStr(m_port);
//	const PString optionsStr("connect_timeout=10000");
	if ((conn = (*g_PQsetdbLogin)(m_host, 
			m_port ? (const char*)portStr : (const char*)NULL,
			NULL /*(const char*)optionsStr*/, NULL,
			m_database, m_username, 
			m_password.IsEmpty() ? (const char*)NULL : (const char*)m_password
			)) && (*g_PQstatus)(conn) == CONNECTION_OK) {
		PTRACE(5, GetName() << "\tPgSQL connection to " << m_username << '@' << m_host 
			<< '[' << m_database << "] established successfully"
			);
		return new PgSQLConnWrapper(id, m_host, conn);
	} else {
		PTRACE(2, GetName() << "\tPgSQL connection to " << m_username << '@' << m_host 
			<< '[' << m_database << "] failed (PQsetdbLogin failed): " 
			<< (conn ? (*g_PQerrorMessage)(conn) : ""));
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed")
		if (conn)
			(*g_PQfinish)(conn);
	}
	return NULL;
}
	
GkSQLResult* GkPgSQLConnection::ExecuteQuery(
	/// SQL connection to use for query execution
	GkSQLConnection::SQLConnPtr conn,
	/// query string
	const char* queryStr,
	/// maximum time (ms) for the query execution, -1 means infinite
	long /*timeout*/
	)
{
	PGconn* pgsqlconn = ((PgSQLConnWrapper*)conn)->m_conn;
	PGresult* result = (*g_PQexec)(pgsqlconn, queryStr);
	if (result == NULL) {
		GkSQLResult * sqlResult = new GkPgSQLResult(PGRES_FATAL_ERROR, (*g_PQerrorMessage)(pgsqlconn));
		Disconnect();
		return sqlResult;
	}
		
	ExecStatusType resultInfo = (*g_PQresultStatus)(result);
	switch (resultInfo)
	{
	case PGRES_COMMAND_OK:
		return new GkPgSQLResult(
			(*g_PQcmdTuples)(result) ? atoi((*g_PQcmdTuples)(result)) : 0
			);
		
	case PGRES_TUPLES_OK:
		return new GkPgSQLResult(result);
		
	default:
		GkSQLResult * sqlResult = new GkPgSQLResult(resultInfo, (*g_PQresultErrorMessage)(result));
		Disconnect();
		return sqlResult;
	}
}

PString GkPgSQLConnection::EscapeString(
	/// SQL connection to get escaping parameters from
	SQLConnPtr conn,
	/// string to be escaped
	const char* str
	)
{
	PString escapedStr;
	const size_t numChars = str ? strlen(str) : 0;
	int err = 0;
	
	if (numChars) {
		char * buf = (char *)malloc(numChars * 2 + 1);
		(*g_PQescapeStringConn) (((PgSQLConnWrapper*)conn)->m_conn, buf, str, numChars, &err);
		escapedStr = buf;
		free(buf);
	}
	return escapedStr;
}

namespace {
	GkSQLCreator<GkPgSQLConnection> PgSQLCreator("PostgreSQL");
}

#endif /* HAS_PGSQL */
