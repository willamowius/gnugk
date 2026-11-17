/*
 * gksql_pgsql.cxx
 *
 * PostgreSQL driver module for GnuGk
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 * Copyright (c) 2006-2014, Jan Willamowius
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

#if _WIN32 || _WIN64
#	include <winsock2.h>
#	define poll WSAPoll
#else
#	include <poll.h>
#endif // _WIN32

static PDynaLink g_sharedLibrary;
static void (*g_PQclear)(PGresult *res) = NULL;
static char * (*g_PQcmdTuples)(PGresult *res) = NULL;
static PGconn * (*g_PQconnectdbParams)(const char * const *keywords, const char * const *values, int expand_dbname) = NULL;
static int (*g_PQconsumeInput)(PGconn *conn) = NULL;
static char * (*g_PQerrorMessage)(const PGconn *conn) = NULL;
static size_t (*g_PQescapeStringConn)(PGconn *conn, char *to, const char *from, size_t length, int *error) = NULL;
static void (*g_PQfinish)(PGconn *conn) = NULL;
static char * (*g_PQfname)(const PGresult *res, int field_num) = NULL;
static int (*g_PQgetlength)(const PGresult *res, int tup_num, int field_num) = NULL;
static PGresult * (*g_PQgetResult)(PGconn *conn) = NULL;
static char * (*g_PQgetvalue)(const PGresult *res, int tup_num, int field_num) = NULL;
static int (*g_PQisBusy)(PGconn *conn) = NULL;
static int (*g_PQnfields)(const PGresult *res) = NULL;
static int (*g_PQntuples)(const PGresult *res) = NULL;
static char * (*g_PQresultErrorMessage)(const PGresult *res) = NULL;
static ExecStatusType (*g_PQresultStatus)(const PGresult *res) = NULL;
static int (*g_PQsendQuery)(PGconn *conn, const char *query) = NULL;
static int (*g_PQsocket)(const PGconn *conn) = NULL;
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
		/// maximum time (ms) for the query execution, -1 means ReadTimeout
		long timeout = -1
		);

	/** Wait until PQgetResult() can be called without blocking.

		@return
		False if the server did not answer in time or the connection is broken.
	*/
	bool WaitForResult(
		/// PostgreSQL connection the query has been sent on
		PGconn* conn,
		/// time the query execution has been started
		const PTime& timeStart,
		/// maximum time (ms) for the query execution, 0 means infinite
		PInt64 maxWait
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
	PStringArray & result
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
	ResultRow & result
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
			|| !g_sharedLibrary.GetFunction("PQconnectdbParams", (PDynaLink::Function &)g_PQconnectdbParams)
			|| !g_sharedLibrary.GetFunction("PQconsumeInput", (PDynaLink::Function &)g_PQconsumeInput)
			|| !g_sharedLibrary.GetFunction("PQerrorMessage", (PDynaLink::Function &)g_PQerrorMessage)
			|| !g_sharedLibrary.GetFunction("PQescapeStringConn", (PDynaLink::Function &)g_PQescapeStringConn)
			|| !g_sharedLibrary.GetFunction("PQfinish", (PDynaLink::Function &)g_PQfinish)
			|| !g_sharedLibrary.GetFunction("PQfname", (PDynaLink::Function &)g_PQfname)
			|| !g_sharedLibrary.GetFunction("PQgetlength", (PDynaLink::Function &)g_PQgetlength)
			|| !g_sharedLibrary.GetFunction("PQgetResult", (PDynaLink::Function &)g_PQgetResult)
			|| !g_sharedLibrary.GetFunction("PQgetvalue", (PDynaLink::Function &)g_PQgetvalue)
			|| !g_sharedLibrary.GetFunction("PQisBusy", (PDynaLink::Function &)g_PQisBusy)
			|| !g_sharedLibrary.GetFunction("PQnfields", (PDynaLink::Function &)g_PQnfields)
			|| !g_sharedLibrary.GetFunction("PQntuples", (PDynaLink::Function &)g_PQntuples)
			|| !g_sharedLibrary.GetFunction("PQresultErrorMessage", (PDynaLink::Function &)g_PQresultErrorMessage)
			|| !g_sharedLibrary.GetFunction("PQresultStatus", (PDynaLink::Function &)g_PQresultStatus)
			|| !g_sharedLibrary.GetFunction("PQsendQuery", (PDynaLink::Function &)g_PQsendQuery)
			|| !g_sharedLibrary.GetFunction("PQsocket", (PDynaLink::Function &)g_PQsocket)
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
	const PString connectTimeoutStr(m_connectTimeout);
	// dbname goes first, so the other settings win if it is a connection string (like with PQsetdbLogin)
	const char * const keywords[] = { "dbname", "host", "port", "user", "password", "connect_timeout", NULL };
	const char * const values[] = { m_database, m_host,
			m_port ? (const char*)portStr : (const char*)NULL,
			m_username,
			m_password.IsEmpty() ? (const char*)NULL : (const char*)m_password,
			connectTimeoutStr, NULL };
	if ((conn = (*g_PQconnectdbParams)(keywords, values, 1)) && (*g_PQstatus)(conn) == CONNECTION_OK) {
		PTRACE(5, GetName() << "\tPgSQL connection to " << m_username << '@' << m_host
			<< '[' << m_database << "] established successfully");
		return new PgSQLConnWrapper(id, m_host, conn);
	} else {
		PTRACE(2, GetName() << "\tPgSQL connection to " << m_username << '@' << m_host
			<< '[' << m_database << "] failed (PQconnectdbParams failed): "
			<< (conn ? (*g_PQerrorMessage)(conn) : ""));
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed")
		if (conn)
			(*g_PQfinish)(conn);
	}
	return NULL;
}

bool GkPgSQLConnection::WaitForResult(
	/// PostgreSQL connection the query has been sent on
	PGconn* conn,
	/// time the query execution has been started
	const PTime& timeStart,
	/// maximum time (ms) for the query execution, 0 means infinite
	PInt64 maxWait
	)
{
	while ((*g_PQisBusy)(conn)) {
		int timeout = -1;
		if (maxWait > 0) {
			const PInt64 remaining = maxWait - (PTime() - timeStart).GetMilliSeconds();
			if (remaining <= 0) {
				PTRACE(2, GetName() << "\tNo answer from the database within " << maxWait << " ms");
				return false;
			}
			timeout = (int)PMIN(remaining, (PInt64)INT_MAX);
		}
		struct pollfd fds[1];
		memset(fds, 0, sizeof(fds));
		fds[0].fd = (*g_PQsocket)(conn);
		fds[0].events = POLLIN;
		if (fds[0].fd < 0)
			return false;	// connection is broken
		const int r = ::poll(fds, 1, timeout);
		if (r < 0 && errno != EINTR)
			return false;
		if (r > 0 && !(*g_PQconsumeInput)(conn))
			return false;
	}
	return true;
}

GkSQLResult* GkPgSQLConnection::ExecuteQuery(
	/// SQL connection to use for query execution
	GkSQLConnection::SQLConnPtr conn,
	/// query string
	const char* queryStr,
	/// maximum time (ms) for the query execution, -1 means ReadTimeout
	long timeout
	)
{
	PGconn * pgsqlconn = ((PgSQLConnWrapper*)conn)->m_conn;
	// PQexec() would wait forever if the server doesn't answer,
	// so send the query asynchronously and wait for the result with a deadline
	const PTime timeStart;
	const PInt64 maxWait = (timeout > 0) ? timeout : PInt64(m_readTimeout) * 1000;
	PGresult* result = NULL;
	bool ok = (*g_PQsendQuery)(pgsqlconn, queryStr) != 0;
	while (ok) {
		ok = WaitForResult(pgsqlconn, timeStart, maxWait);
		PGresult* nextResult = ok ? (*g_PQgetResult)(pgsqlconn) : NULL;
		if (nextResult == NULL)
			break;
		// like PQexec(): return the result of the last command in the query string
		if (result)
			(*g_PQclear)(result);
		result = nextResult;
		// stop like PQexec() does: PQgetResult() would keep returning the COPY state
		const ExecStatusType status = (*g_PQresultStatus)(result);
		if (status == PGRES_COPY_IN || status == PGRES_COPY_OUT || status == PGRES_COPY_BOTH
			|| (*g_PQstatus)(pgsqlconn) == CONNECTION_BAD)
			break;
	}
	if (!ok && result) {
		(*g_PQclear)(result);
		result = NULL;
	}
	if (result == NULL) {
		PString errorMsg((*g_PQerrorMessage)(pgsqlconn));
		if (errorMsg.IsEmpty())
			errorMsg = "no answer from the database server";
		GkSQLResult * sqlResult = new GkPgSQLResult(PGRES_FATAL_ERROR, errorMsg);
		Disconnect();
		return sqlResult;
	}

	// every non-NULL PGresult must be PQclear()ed, only the SELECT result is kept (and freed by GkPgSQLResult)
	ExecStatusType resultInfo = (*g_PQresultStatus)(result);
	switch (resultInfo)
	{
	case PGRES_COMMAND_OK:
		{
			long numRowsAffected = (*g_PQcmdTuples)(result) ? atoi((*g_PQcmdTuples)(result)) : 0;
			(*g_PQclear)(result);
			return new GkPgSQLResult(numRowsAffected);
		}

	case PGRES_TUPLES_OK:
		return new GkPgSQLResult(result);

	default:
		GkSQLResult * sqlResult = new GkPgSQLResult(resultInfo, (*g_PQresultErrorMessage)(result));
		(*g_PQclear)(result);
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
