/*
 * gksql_mysql.cxx
 *
 * MySQL driver module for GnuGk
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.8  2006/04/14 13:56:19  willamowius
 * call failover code merged
 *
 * Revision 1.1.1.1  2005/11/21 20:19:59  willamowius
 *
 *
 * Revision 1.4  2005/11/15 19:52:56  jan
 * Michal v1 (works, but on in routed, not proxy mode)
 *
 * Revision 1.7  2005/04/24 16:39:44  zvision
 * MSVC6.0 compatibility fixed
 *
 * Revision 1.6  2005/01/16 15:22:35  zvision
 * Database Host parameter accepts only one host now
 *
 * Revision 1.5  2004/08/02 10:52:07  zvision
 * Ability to extract column names from a result set
 *
 * Revision 1.4  2004/07/09 22:11:36  zvision
 * SQLAcct module ported from 2.0 branch
 *
 */
#if HAS_MYSQL

#if defined(_WIN32) && (_MSC_VER <= 1200)
#pragma warning(disable:4786) // warning about too long debug symbol off
#pragma warning(disable:4284)
#endif

#ifdef _WIN32
#pragma comment( lib, "libmysql.lib" )
#endif

#include <ptlib.h>
#include <mysql.h>
#include "gksql.h"

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
		m_numRows = (long)mysql_num_rows(m_sqlResult);
		m_numFields = mysql_num_fields(m_sqlResult);
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
		mysql_free_result(m_sqlResult);
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
	
	m_sqlRow = mysql_fetch_row(m_sqlResult);
	m_sqlRowLengths = mysql_fetch_lengths(m_sqlResult);
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
	
	m_sqlRow = mysql_fetch_row(m_sqlResult);
	m_sqlRowLengths = mysql_fetch_lengths(m_sqlResult);
	MYSQL_FIELD* fields = mysql_fetch_fields(m_sqlResult);
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
	mysql_close(m_conn);
}

GkSQLConnection::SQLConnPtr GkMySQLConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	const unsigned int CONNECT_TIMEOUT = 10000;

	MYSQL* conn = mysql_init(NULL);
	if (conn == NULL) {
		PTRACE(1, GetName() << "\tCannot allocate MySQL connection object (mysql_init failed)");
		return NULL;
	}
	mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, (const char*)&CONNECT_TIMEOUT);

	// connect to the MySQL database, try each host on the list in case of failure
	if (mysql_real_connect(conn, m_host, m_username, 
			m_password.IsEmpty() ? (const char*)NULL : (const char*)m_password,
			m_database, m_port, NULL, 0)) {
		PTRACE(5, GetName() << "\tMySQL connection to " << m_username << '@' << m_host 
			<< '[' << m_database << "] established successfully"
			);
		return new MySQLConnWrapper(id, m_host, conn);
	} else {
		PTRACE(2, GetName() << "\tMySQL connection to " << m_username << '@' << m_host 
			<< '[' << m_database << "] failed (mysql_real_connect failed): " << mysql_error(conn)
			);
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
	
	int result = mysql_real_query(mysqlconn, queryStr, strlen(queryStr));
	if (result)
		return new GkMySQLResult(result, mysql_error(mysqlconn));
	
	MYSQL_RES* queryResult = mysql_store_result(mysqlconn);
	if (queryResult)
		return new GkMySQLResult(queryResult);

	result = mysql_errno(mysqlconn);
	if (result)
		return new GkMySQLResult(result, mysql_error(mysqlconn));

	return new GkMySQLResult((long)mysql_affected_rows(mysqlconn));
}

PString GkMySQLConnection::EscapeString(
	/// SQL connection to get escaping parameters from
	SQLConnPtr conn,
	/// string to be escaped
	const char* str
	)
{
	PString escapedStr;
	const unsigned long numChars = str ? strlen(str) : 0;
	
	if (numChars) {
		MYSQL* mysqlconn = ((MySQLConnWrapper*)conn)->m_conn;
		escapedStr.SetSize(
			mysql_real_escape_string(
				mysqlconn, escapedStr.GetPointer(numChars*2+1), str, numChars
				) + 1
			);
	}
	return escapedStr;
}

namespace {
	GkSQLCreator<GkMySQLConnection> MySQLCreator("MySQL");
}

#endif /* HAS_MYSQL */
