/*
 * gksql_mysql.cxx
 *
 * MySQL driver module for GnuGk
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

#if HAS_MYSQL

#include <ptlib.h>
#include <mysql.h>
#include "gksql.h"

static PDynaLink g_sharedLibrary;
static MYSQL * (STDCALL *g_mysql_init)(MYSQL *mysql) = NULL;
static void (STDCALL *g_mysql_free_result)(MYSQL_RES *result) = NULL;
static unsigned long (STDCALL *g_mysql_real_escape_string)(MYSQL *mysql, char *to, const char *from, unsigned long length) = NULL;
static my_ulonglong (STDCALL *g_mysql_num_rows)(MYSQL_RES *result) = NULL;
static unsigned int (STDCALL *g_mysql_num_fields)(MYSQL_RES *result) = NULL;
static MYSQL_ROW (STDCALL *g_mysql_fetch_row)(MYSQL_RES *result) = NULL;
static MYSQL_FIELD * (STDCALL *g_mysql_fetch_fields)(MYSQL_RES *result) = NULL;
static unsigned long * (STDCALL *g_mysql_fetch_lengths)(MYSQL_RES *result) = NULL;
static void (STDCALL *g_mysql_close)(MYSQL *mysql) = NULL;
static int (STDCALL *g_mysql_options)(MYSQL *mysql, enum mysql_option option, const char *arg) = NULL;
static MYSQL * (STDCALL *g_mysql_real_connect)(MYSQL *mysql, const char *host, const char *user, const char *passwd, const char *db, unsigned int port, const char *unix_socket, unsigned long client_flag) = NULL;
static int (STDCALL *g_mysql_real_query)(MYSQL *mysql, const char *stmt_str, unsigned long length) = NULL;
static MYSQL_RES * (STDCALL *g_mysql_store_result)(MYSQL *mysql) = NULL;
static int (STDCALL *g_mysql_next_result)(MYSQL *mysql) = NULL;
static unsigned int (STDCALL *g_mysql_errno)(MYSQL *mysql) = NULL;
static const char * (STDCALL *g_mysql_error)(MYSQL *mysql) = NULL;
static my_ulonglong (STDCALL *g_mysql_affected_rows)(MYSQL *mysql) = NULL;



/** Class that encapsulates SQL query result for MySQL backend.
	It does not provide any multithread safety, so should be accessed
	from a single thread at time.
*/
class GkMySQLResult : public GkSQLResult
{
public:
	/// Build the result from SELECT type query
	GkMySQLResult(
		/// SELECT type query result
		MYSQL_RES* selectResult
		);

	/// Build the result from INSERT, DELETE or UPDATE query
	GkMySQLResult(
		/// number of rows affected by the query
		long numRowsAffected
		);

	/// Build the empty	result and store query execution error information
	GkMySQLResult(
		/// MySQL specific error code
		unsigned int errorCode,
		/// MySQL specific error message text
		const char* errorMsg
		);
	
	virtual ~GkMySQLResult();
	
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
	GkMySQLResult();
	GkMySQLResult(const GkMySQLResult&);
	GkMySQLResult& operator=(const GkMySQLResult&);
	
protected:
	/// query result for SELECT type queries, NULL otherwise
	MYSQL_RES* m_sqlResult;
	/// the most recent row returned by fetch operation
	MYSQL_ROW m_sqlRow;
	/// lenghts (bytes) for each field in m_sqlRow result row
	unsigned long* m_sqlRowLengths;
	/// MySQL specific error code (if the query failed)
	unsigned int m_errorCode;
	/// MySQL specific error message text (if the query failed)
	PString m_errorMessage;
};

/// MySQL backend connection implementation.
class GkMySQLConnection : public GkSQLConnection
{
public:
	/// Build a new MySQL connection object
	GkMySQLConnection(
		/// name to use in the log
		const char* name = "MySQL"
		);
	
	virtual ~GkMySQLConnection();

protected:
	class MySQLConnWrapper : public GkSQLConnection::SQLConnWrapper
	{
	public:
		MySQLConnWrapper(
			/// unique identifier for this connection
			int id,
			/// host:port this connection is made to
			const PString& host,
			/// MySQL connection object
			MYSQL* conn
			) : SQLConnWrapper(id, host), m_conn(conn) {}

		virtual ~MySQLConnWrapper();

	private:
		MySQLConnWrapper();
		MySQLConnWrapper(const MySQLConnWrapper&);
		MySQLConnWrapper& operator=(const MySQLConnWrapper&);

	public:
		MYSQL* m_conn;
	};

	/** Create a new SQL connection using parameters stored in this object.
	    When the connection is to be closed, the object is simply deleted
	    using delete operator.
	    
	    @return
	    NULL if database connection could not be established 
	    or an object of MySQLConnWrapper class.
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
	GkMySQLConnection(const GkMySQLConnection&);
	GkMySQLConnection& operator=(const GkMySQLConnection&);
};


GkMySQLResult::GkMySQLResult(
	/// SELECT type query result
	MYSQL_RES* selectResult
	) 
	: GkSQLResult(false), m_sqlResult(selectResult), m_sqlRow(NULL),
	m_sqlRowLengths(NULL), m_errorCode(0)
{
	if (m_sqlResult) {
		m_numRows = (long)(*g_mysql_num_rows)(m_sqlResult);
		m_numFields = (*g_mysql_num_fields)(m_sqlResult);
	} else
		m_queryError = true;
}

GkMySQLResult::GkMySQLResult(
	/// number of rows affected by the query
	long numRowsAffected
	) 
	: GkSQLResult(false), m_sqlResult(NULL), m_sqlRow(NULL), 
	m_sqlRowLengths(NULL), m_errorCode(0)
{
	m_numRows = numRowsAffected;
}
	
GkMySQLResult::GkMySQLResult(
	/// MySQL specific error code
	unsigned int errorCode,
	/// MySQL specific error message text
	const char* errorMsg
	) 
	: GkSQLResult(true), m_sqlResult(NULL), m_sqlRow(NULL),
	m_sqlRowLengths(NULL), m_errorCode(errorCode), m_errorMessage(errorMsg)
{
}

GkMySQLResult::~GkMySQLResult()
{
	if (m_sqlResult)
		(*g_mysql_free_result)(m_sqlResult);
}

PString GkMySQLResult::GetErrorMessage()
{
	return m_errorMessage;
}
	
long GkMySQLResult::GetErrorCode()
{
	return m_errorCode;
}

bool GkMySQLResult::FetchRow(
	/// array to be filled with string representations of the row fields
	PStringArray& result
	)
{
	if (m_sqlResult == NULL || m_numRows <= 0)
		return false;
	
	m_sqlRow = (*g_mysql_fetch_row)(m_sqlResult);
	m_sqlRowLengths = (*g_mysql_fetch_lengths)(m_sqlResult);
	if (m_sqlRow == NULL || m_sqlRowLengths == NULL) {
		m_sqlRow = NULL;
		m_sqlRowLengths = NULL;
		return false;
	}
		
	result.SetSize(m_numFields);
	
	for (PINDEX i = 0; i < m_numFields; i++)
		result[i] = PString(m_sqlRow[i], m_sqlRowLengths[i]);
	
	return true;
}

bool GkMySQLResult::FetchRow(
	/// array to be filled with string representations of the row fields
	ResultRow& result
	)
{
	if (m_sqlResult == NULL || m_numRows <= 0)
		return false;
	
	m_sqlRow = (g_mysql_fetch_row)(m_sqlResult);
	m_sqlRowLengths = (*g_mysql_fetch_lengths)(m_sqlResult);
	MYSQL_FIELD* fields = (*g_mysql_fetch_fields)(m_sqlResult);
	if (m_sqlRow == NULL || m_sqlRowLengths == NULL || fields == NULL) {
		m_sqlRow = NULL;
		m_sqlRowLengths = NULL;
		return false;
	}
		
	result.resize(m_numFields);
	
	for (PINDEX i = 0; i < m_numFields; i++) {
		result[i].first = PString(m_sqlRow[i], m_sqlRowLengths[i]);
		result[i].second = fields[i].name;
	}
	
	return true;
}


GkMySQLConnection::GkMySQLConnection(
	/// name to use in the log
	const char* name
	) : GkSQLConnection(name)
{
}
	
GkMySQLConnection::~GkMySQLConnection()
{
}

GkMySQLConnection::MySQLConnWrapper::~MySQLConnWrapper()
{
	(*g_mysql_close)(m_conn);
}

GkSQLConnection::SQLConnPtr GkMySQLConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	if (!g_sharedLibrary.IsLoaded()) {
		if (m_library.IsEmpty()) {
#ifdef _WIN32
			m_library = "libmysql" + g_sharedLibrary.GetExtension();
#else
			m_library = "libmysqlclient" + g_sharedLibrary.GetExtension();
#endif
		}

		if (!g_sharedLibrary.Open(m_library)) {
			PTRACE (1, GetName() << "\tCan't load library " << m_library);
			return NULL;
		}

		if (!g_sharedLibrary.GetFunction("mysql_init", (PDynaLink::Function &)g_mysql_init)
			|| !g_sharedLibrary.GetFunction("mysql_free_result", (PDynaLink::Function &)g_mysql_free_result)
			|| !g_sharedLibrary.GetFunction("mysql_real_escape_string", (PDynaLink::Function &)g_mysql_real_escape_string)
			|| !g_sharedLibrary.GetFunction("mysql_num_rows", (PDynaLink::Function &)g_mysql_num_rows)
			|| !g_sharedLibrary.GetFunction("mysql_num_fields", (PDynaLink::Function &)g_mysql_num_fields)
			|| !g_sharedLibrary.GetFunction("mysql_fetch_row", (PDynaLink::Function &)g_mysql_fetch_row)
			|| !g_sharedLibrary.GetFunction("mysql_fetch_fields", (PDynaLink::Function &)g_mysql_fetch_fields)
			|| !g_sharedLibrary.GetFunction("mysql_fetch_lengths", (PDynaLink::Function &)g_mysql_fetch_lengths)
			|| !g_sharedLibrary.GetFunction("mysql_close", (PDynaLink::Function &)g_mysql_close)
			|| !g_sharedLibrary.GetFunction("mysql_options", (PDynaLink::Function &)g_mysql_options)
			|| !g_sharedLibrary.GetFunction("mysql_real_connect", (PDynaLink::Function &)g_mysql_real_connect)
			|| !g_sharedLibrary.GetFunction("mysql_real_query", (PDynaLink::Function &)g_mysql_real_query)
			|| !g_sharedLibrary.GetFunction("mysql_store_result", (PDynaLink::Function &)g_mysql_store_result)
			|| !g_sharedLibrary.GetFunction("mysql_next_result", (PDynaLink::Function &)g_mysql_next_result)
			|| !g_sharedLibrary.GetFunction("mysql_errno", (PDynaLink::Function &)g_mysql_errno)
			|| !g_sharedLibrary.GetFunction("mysql_error", (PDynaLink::Function &)g_mysql_error)
			|| !g_sharedLibrary.GetFunction("mysql_affected_rows", (PDynaLink::Function &)g_mysql_affected_rows)
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

	const unsigned int CONNECT_TIMEOUT = 10;	// connect timeout in seconds (!)

	MYSQL* conn = (*g_mysql_init)(NULL);
	if (conn == NULL) {
		PTRACE(1, GetName() << "\tCannot allocate MySQL connection object (mysql_init failed)");
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
		return NULL;
	}
	(*g_mysql_options)(conn, MYSQL_OPT_CONNECT_TIMEOUT, (const char*)&CONNECT_TIMEOUT);

#if (MYSQL_VERSION_ID >= 50013)
	my_bool reconnect = 1;	// enable auto-reconnect, older versions have it on by default
	(*g_mysql_options)(conn, MYSQL_OPT_RECONNECT, (const char*)&reconnect);
#endif

	// this call to mysql_options is needed for libmysqlclient to read /etc/my.cnf,
	// which might contain eg. a setting where to find the mysql socket
	(*g_mysql_options)(conn, MYSQL_READ_DEFAULT_GROUP, "gnugk");

	// connect to the MySQL database, try each host on the list in case of failure
	if ((*g_mysql_real_connect)(conn, m_host, m_username, 
			m_password.IsEmpty() ? (const char*)NULL : (const char*)m_password,
			m_database, m_port, NULL, CLIENT_MULTI_STATEMENTS)) {
		PTRACE(5, GetName() << "\tMySQL connection to " << m_username << '@' << m_host 
			<< '[' << m_database << "] established successfully");
		return new MySQLConnWrapper(id, m_host, conn);
	} else {
		PTRACE(2, GetName() << "\tMySQL connection to " << m_username << '@' << m_host 
			<< '[' << m_database << "] failed (mysql_real_connect failed): " << (*g_mysql_error)(conn));
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
	}
	return NULL;
}
	
GkSQLResult* GkMySQLConnection::ExecuteQuery(
	/// SQL connection to use for query execution
	GkSQLConnection::SQLConnPtr conn,
	/// query string
	const char* queryStr,
	/// maximum time (ms) for the query execution, -1 means infinite
	long /*timeout*/
	)
{
	MYSQL* mysqlconn = ((MySQLConnWrapper*)conn)->m_conn;

	int result = (*g_mysql_real_query)(mysqlconn, queryStr, strlen(queryStr));
	if (result) {
		GkSQLResult * sqlResult = new GkMySQLResult(result, (*g_mysql_error)(mysqlconn));
		Disconnect();
		return sqlResult;
	}

	MYSQL_RES* queryResult = (*g_mysql_store_result)(mysqlconn);

	if (queryResult) {
		/* loop and discard results after first if any */
		MYSQL_RES* tmpResult;
		int tmpstatus;
		while ( (tmpstatus = (*g_mysql_next_result)(mysqlconn) ) >= 0) {
			if (tmpstatus > 0) {
				/* error fetching next result */
				break;
			}
			tmpResult = (*g_mysql_store_result)(mysqlconn);
			(*g_mysql_free_result)(tmpResult);
		}
	}

	if (queryResult)
		return new GkMySQLResult(queryResult);

	result = (*g_mysql_errno)(mysqlconn);
	if (result) {
		GkSQLResult * sqlResult = new GkMySQLResult(result, (*g_mysql_error)(mysqlconn));
		Disconnect();
		return sqlResult;
	}

	return new GkMySQLResult((long)(*g_mysql_affected_rows)(mysqlconn));
}

PString GkMySQLConnection::EscapeString(
	/// SQL connection to get escaping parameters from
	SQLConnPtr conn,
	/// string to be escaped
	const char* str
	)
{
	PString escapedStr;
	const size_t numChars = str ? strlen(str) : 0;
	
	if (numChars) {
		char * buf = (char *)malloc(numChars * 2 + 1);
		MYSQL* mysqlconn = ((MySQLConnWrapper*)conn)->m_conn;
		(*g_mysql_real_escape_string)(mysqlconn, buf, str, numChars);
		escapedStr = buf;
		free(buf);
	}
	return escapedStr;
}

namespace {
	GkSQLCreator<GkMySQLConnection> MySQLCreator("MySQL");
}

#endif /* HAS_MYSQL */
