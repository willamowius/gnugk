/*
 * gksql_odbc.cxx
 *
 * native ODBC / unixODBC driver module for GnuGk
 *
 * Copyright (c) 2008, Jan Willamowius
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.9  2008/05/02 09:51:27  zvision
 * No need to disconnect ODBC environment handle
 *
 * Revision 1.8  2008/04/18 14:37:28  willamowius
 * never include gnugkbuildopts.h directly, always include config.h
 *
 * Revision 1.7  2008/04/18 14:22:32  willamowius
 * make the unixODBC driver the general ODBC driver for Unix and Windows
 *
 * Revision 1.3  2008/04/18 13:14:11  shorne
 * Fixes for auto-configure on windows
 *
 * Revision 1.2  2008/04/18 05:37:44  shorne
 * Ported to Windows
 *
 * Revision 1.1  2008/04/03 09:43:03  willamowius
 * native unixodbc driver
 *
 *
 */

#include "config.h"

#if HAS_ODBC

#include <ptlib.h>
#include "gksql.h"

namespace nativeodbc
{
#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>
}


#ifdef _WIN32
 #pragma comment(lib, ODBC_LIBRARY_1 )
 #pragma comment(lib, ODBC_LIBRARY_2 )
#endif

using namespace nativeodbc;

namespace {

PString GetODBCDiagMsg(
	SQLRETURN result,
	SQLSMALLINT handleType,
	SQLHANDLE handle
	)
{
	if (result == SQL_SUCCESS)
		return "Sucesss";
	if (result == SQL_INVALID_HANDLE)
		return "Invalid ODBC handle passed";
	if (result == SQL_NO_DATA)
		return "No more data to fetch";

	SQLCHAR sqlState[6];
	SQLINTEGER nativeError = 0;
	SQLCHAR *msg = new SQLCHAR[SQL_MAX_MESSAGE_LENGTH];
	SQLSMALLINT msgSize;
	SQLRETURN r;
	
	memset(msg, 0, SQL_MAX_MESSAGE_LENGTH);
	r = SQLGetDiagRec(handleType, handle, 1, reinterpret_cast<SQLCHAR*>(sqlState),
		&nativeError, msg, SQL_MAX_MESSAGE_LENGTH, &msgSize
		);
	if (r == SQL_SUCCESS || r == SQL_SUCCESS_WITH_INFO) {
		sqlState[5] = 0;
		PString text(reinterpret_cast<const char*>(sqlState));
		text += " (";
		text += PString(nativeError);
		text += ") ";
		text += reinterpret_cast<const char*>(msg);
		delete[] msg;
		return text;
	} else {
		delete[] msg;
		return "Could not retrieve a diagnostic message";
	}
}

}

/** Class that encapsulates SQL query result for the ODBC backend.
	It does not provide any multithread safety, so should be accessed
	from a single thread at time.
*/
class GkODBCResult : public GkSQLResult
{
public:
	/// Build the result from SELECT type query
	GkODBCResult(
		/// number of rows affected by the query
		long numRowsAffected,
		/// number of columns in the result set
		long numFields,
		/// query result
		std::list<ResultRow*> * resultRows
		);

	/// Build the empty	result and store query execution error information
	GkODBCResult(
		/// error code
		unsigned int errorCode,
		/// error message text
		const char* errorMsg
		);
	
	virtual ~GkODBCResult();
	
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
	GkODBCResult();
	GkODBCResult(const GkODBCResult&);
	GkODBCResult& operator=(const GkODBCResult&);
	
protected:
	/// query result for SELECT type queries
	std::list<ResultRow*> *m_sqlResult;
	/// iterator to the most recent row returned by fetch operation
	std::list<ResultRow*>::iterator m_sqlRowIter;
	/// the most recent row returned by fetch operation
	int m_sqlRow;
	/// error code (if the query failed)
	unsigned int m_errorCode;
	/// error message text (if the query failed)
	PString m_errorMessage;
};

/// ODBC backend connection implementation.
class GkODBCConnection : public GkSQLConnection
{
public:
	/// Build a new connection object
	GkODBCConnection(
		/// name to use in the log
		const char* name = "ODBC"
		);
	
	virtual ~GkODBCConnection();

protected:
	class GkODBCConnWrapper : public GkSQLConnection::SQLConnWrapper
	{
	public:
		GkODBCConnWrapper(
			/// unique identifier for this connection
			int id,
			/// ODBC connection handle
			SQLHDBC conn,
			/// DSN
			const PString &dsn
			) : SQLConnWrapper(id, dsn), m_conn(conn) {}

		virtual ~GkODBCConnWrapper();

	private:
		GkODBCConnWrapper();
		GkODBCConnWrapper(const GkODBCConnWrapper&);
		GkODBCConnWrapper& operator=(const GkODBCConnWrapper&);

	public:
		SQLHDBC m_conn;
	};

	/** Create a new SQL connection using parameters stored in this object.
	    When the connection is to be closed, the object is simply deleted
	    using delete operator.
	    
	    @return
	    NULL if database connection could not be established 
	    or an object of GkODBCConnWrapper class.
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
	GkODBCConnection(const GkODBCConnection&);
	GkODBCConnection& operator=(const GkODBCConnection&);
	
private:
	SQLHENV m_env;
};


GkODBCResult::GkODBCResult(
	/// number of rows affected by the query
	long numRowsAffected,
	/// number of columns in the result set
	long numFields,
	/// query result
	std::list<ResultRow*> *selectResult
	)
	: GkSQLResult(false), m_sqlResult(selectResult), m_sqlRow(-1),
	m_errorCode(0)
{
	m_numRows = numRowsAffected;
	m_numFields = numFields;
	
	if (m_sqlResult != NULL && !m_sqlResult->empty())
		m_numRows = m_sqlResult->size();
	
	m_queryError = false;
}

GkODBCResult::GkODBCResult(
	/// error code
	unsigned int errorCode,
	/// error message text
	const char* errorMsg
	) 
	: GkSQLResult(true), m_sqlResult(NULL), m_sqlRow(-1),
	m_errorCode(errorCode), m_errorMessage(errorMsg)
{
	m_queryError = true;
}

GkODBCResult::~GkODBCResult()
{
	if (m_sqlResult != NULL) {
		std::list<ResultRow*>::iterator i = m_sqlResult->begin();
		while (i != m_sqlResult->end()) {
			delete *i;
			++i;
		}
		delete m_sqlResult;
		m_sqlResult = NULL;
	}
}

PString GkODBCResult::GetErrorMessage()
{
	return m_errorMessage;
}
	
long GkODBCResult::GetErrorCode()
{
	return m_errorCode;
}

bool GkODBCResult::FetchRow(
	/// array to be filled with string representations of the row fields
	PStringArray& result
	)
{
	if (m_sqlResult == NULL || m_numRows <= 0)
		return false;
	
	if (m_sqlRow < 0) {
		m_sqlRow = 0;
		m_sqlRowIter = m_sqlResult->begin();
	}
	
	if (m_sqlRow >= m_numRows)
		return false;

	result.SetSize(m_numFields);
	for (int i = 0; i < m_numFields; ++i)
		result[i] = (**m_sqlRowIter)[i].first;
	
	++m_sqlRow;
	++m_sqlRowIter;
	
	return true;
}

bool GkODBCResult::FetchRow(
	/// array to be filled with string representations of the row fields
	ResultRow& result
	)
{
	if (m_sqlResult == NULL || m_numRows <= 0)
		return false;
	
	if (m_sqlRow < 0) {
		m_sqlRow = 0;
		m_sqlRowIter = m_sqlResult->begin();
	}
	
	if (m_sqlRow >= m_numRows)
		return false;

	result = *(*m_sqlRowIter);
	
	++m_sqlRow;
	++m_sqlRowIter;
	
	return true;
}


GkODBCConnection::GkODBCConnection(
	/// name to use in the log
	const char* name
	) : GkSQLConnection(name), m_env(SQL_NULL_HENV)
{
	// allocate Environment handle and register version 
	SQLRETURN r = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_env);
	if (!SQL_SUCCEEDED(r)) {
		PTRACE(1, GetName() << "\tFailed to allocate an ODBC environment handle: " << GetODBCDiagMsg(r, SQL_HANDLE_ENV, SQL_NULL_HENV));
		return;
	}
	r = SQLSetEnvAttr(m_env, SQL_ATTR_ODBC_VERSION, reinterpret_cast<SQLPOINTER>(SQL_OV_ODBC3), 0); 
	if (!SQL_SUCCEEDED(r)) {
		PTRACE(1, GetName() << "\tFailed to request ODBC interface version 3.0: " << GetODBCDiagMsg(r, SQL_HANDLE_ENV, m_env));
		SQLFreeHandle(SQL_HANDLE_ENV, m_env);
		m_env = SQL_NULL_HENV;
		return;
	}
	PTRACE(5, GetName() << "\tODBC environment created");
}
	
GkODBCConnection::~GkODBCConnection()
{
	if (m_env != SQL_NULL_HENV) {
		SQLFreeHandle(SQL_HANDLE_ENV, m_env);
		m_env = SQL_NULL_HENV;
	}
}

GkODBCConnection::GkODBCConnWrapper::~GkODBCConnWrapper()
{
	if (m_conn != SQL_NULL_HDBC) {
		SQLRETURN r = SQLDisconnect(m_conn);
		if (!SQL_SUCCEEDED(r))
			PTRACE(1, "ODBC disconnect failed: " << GetODBCDiagMsg(r, SQL_HANDLE_DBC, m_conn));
		SQLFreeHandle(SQL_HANDLE_DBC, m_conn);
		m_conn = SQL_NULL_HDBC;
	}
}

GkSQLConnection::SQLConnPtr GkODBCConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	SQLHDBC conn = SQL_NULL_HDBC;

	// allocate connection handle, set timeout
	SQLRETURN r = SQLAllocHandle(SQL_HANDLE_DBC, m_env, &conn); 
	if (!SQL_SUCCEEDED(r)) {
		PTRACE(1, GetName() << "\tFailed to allocate an ODBC connection handle: " << GetODBCDiagMsg(r, SQL_HANDLE_ENV, m_env));
		return NULL;
	}
	
	r = SQLSetConnectAttr(conn, SQL_ATTR_LOGIN_TIMEOUT, reinterpret_cast<SQLPOINTER>(10), 0);
	if (!SQL_SUCCEEDED(r))
		PTRACE(1, GetName() << "\tFailed to set ODBC connection login timeout: " << GetODBCDiagMsg(r, SQL_HANDLE_DBC, conn));
	
	r = SQLSetConnectAttr(conn, SQL_ATTR_CONNECTION_TIMEOUT, reinterpret_cast<SQLPOINTER>(10), 0);
	if (!SQL_SUCCEEDED(r))
		PTRACE(1, GetName() << "\tFailed to set ODBC connection request timeout: " << GetODBCDiagMsg(r, SQL_HANDLE_DBC, conn));

	// Connect to datasource
	r = SQLConnect(conn,
		reinterpret_cast<SQLCHAR*>(const_cast<char*>(m_database.IsEmpty() ? "" : (const char*)m_database)), SQL_NTS,
		reinterpret_cast<SQLCHAR*>(const_cast<char*>(m_username.IsEmpty() ? "" : (const char*)m_username)), SQL_NTS,
		reinterpret_cast<SQLCHAR*>(const_cast<char*>(m_password.IsEmpty() ? "" : (const char*)m_password)), SQL_NTS
		);
	if (!SQL_SUCCEEDED(r)) {
		PTRACE(1, GetName() << "\tODBC connect to " << m_database << " failed: " << GetODBCDiagMsg(r, SQL_HANDLE_DBC, conn));
		SQLFreeHandle(SQL_HANDLE_DBC, conn);
		return NULL;
	}

	PTRACE(5, GetName() << "\tODBC connection to " << m_database << " established successfully");

	return new GkODBCConnWrapper(id, conn, m_database);
}

GkSQLResult* GkODBCConnection::ExecuteQuery(
	/// SQL connection to use for query execution
	GkSQLConnection::SQLConnPtr con,
	/// query string
	const char* queryStr,
	/// maximum time (ms) for the query execution, -1 means infinite
	long timeout
	)
{
	SQLHDBC conn = ((GkODBCConnWrapper*)con)->m_conn;
	SQLHSTMT stmt = SQL_NULL_HSTMT;

	SQLRETURN r = SQLAllocHandle(SQL_HANDLE_STMT, conn, &stmt); 
	if (!SQL_SUCCEEDED(r)) {
		PString errmsg(GetODBCDiagMsg(r, SQL_HANDLE_DBC, conn));
		PTRACE(1, GetName() << "\tFailed to allocate an ODBC statement handle: " << errmsg);
		Disconnect();
		return new GkODBCResult(r, errmsg);
	}

	r = SQLSetStmtAttr(stmt, SQL_ATTR_QUERY_TIMEOUT, reinterpret_cast<SQLPOINTER>(timeout == -1 ? 10 : ((timeout + 999) / 1000)), 0);
	if (!SQL_SUCCEEDED(r))
		PTRACE(1, GetName() << "\tSQL query timeout not set: " << GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
	
	r = SQLExecDirect(stmt, reinterpret_cast<SQLCHAR*>(const_cast<char*>((const char*)queryStr)), SQL_NTS);
	bool nodata = (r == SQL_NO_DATA);
	if (r != SQL_NO_DATA && !SQL_SUCCEEDED(r)) {
		PString errmsg(GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
		PTRACE(1, GetName() << "\tFailed to execute an ODBC query: " << errmsg);
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
		Disconnect();
		return new GkODBCResult(r, errmsg + ", query: " + queryStr);
	}
	
	SQLSMALLINT columns = 0;
	r = SQLNumResultCols(stmt, &columns);
	if (!SQL_SUCCEEDED(r)) {
		PString errmsg(GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
		PTRACE(1, GetName() << "\tFailed to get ODBC number of result columns: " << errmsg);
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
		Disconnect();
		return new GkODBCResult(r, errmsg + ", query: " + queryStr);
	}
	
	SQLINTEGER rows = 0;
	
	if (columns == 0) {
		if (nodata) {
			SQLFreeHandle(SQL_HANDLE_STMT, stmt);
			return new GkODBCResult(0, 0, NULL);
		} else {
			r = SQLRowCount(stmt, &rows);
			if (!SQL_SUCCEEDED(r))
				PTRACE(1, GetName() << "\tFailed to get ODBC number of rows affected by a query: " << GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
			SQLFreeHandle(SQL_HANDLE_STMT, stmt);
			return new GkODBCResult(rows, 0, NULL);
		}
	}

	if (nodata)
		return new GkODBCResult(0, columns, NULL);

	std::vector<PString> fieldNames(columns);
	
	for (SQLUSMALLINT i = 1; i <= columns; ++i) {
		SQLCHAR colname[64];
		r = SQLDescribeCol(stmt, i, colname, sizeof(colname), NULL, NULL, NULL, NULL, NULL);
		if (!SQL_SUCCEEDED(r))
			PTRACE(1, GetName() << "\tFailed to get an ODBC result set column #" << i << " name: " << GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
		else
			fieldNames[i-1] = PString(reinterpret_cast<const char*>(colname));
	}

	std::list<GkSQLResult::ResultRow*> *resultRows = new std::list<GkSQLResult::ResultRow*>();
	do {
		r = SQLFetch(stmt);
		if (r == SQL_NO_DATA)
			break;
			
		if (!SQL_SUCCEEDED(r)) {
			PTRACE(1, GetName() << "\tFailed to fetch an ODBC result row: " << GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
			// we should return an error instead
			break;
		}
		
		GkSQLResult::ResultRow * row = new GkSQLResult::ResultRow(columns);
		
		for (SQLUSMALLINT i = 1; i <= columns; ++i) {
			SQLINTEGER indicator;
			char data[512];
			/* retrieve column data as a string */
			SQLRETURN result = SQLGetData(stmt, i, SQL_C_CHAR, data, sizeof(data), &indicator);
			if (SQL_SUCCEEDED(result)) {
				/* Handle null columns */
				if (indicator == SQL_NULL_DATA)
					data[0] = 0;
			} else {
				PTRACE(1, GetName() << "\tFailed to get ODBC result set column #" << i << " data: " << GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
				data[0] = 0;
			}
			(*row)[i-1] = pair<PString, PString>(data, fieldNames[i-1]);
		}

		resultRows->push_back(row);

		++rows;

	} while (SQL_SUCCEEDED(r));

	SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	
	return new GkODBCResult(rows, columns, resultRows);
}

PString GkODBCConnection::EscapeString(
	/// SQL connection to get escaping parameters from
	SQLConnPtr /*conn*/,
	/// string to be escaped
	const char* str
	)
{
	PString s(str);
	s.Replace("'", "''", TRUE);
	return s;
}

namespace {
	GkSQLCreator<GkODBCConnection> ODBCCreator("ODBC");
}

#endif /* HAS_ODBC */
