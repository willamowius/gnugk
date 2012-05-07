/*
 * gksql_odbc.cxx
 *
 * native ODBC / unixODBC driver module for GnuGk
 *
 * Copyright (c) 2008-2012, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"

#if HAS_ODBC

#include <ptlib.h>
#include "gksql.h"

#ifdef P_SOLARIS
#ifdef P_64BIT
#define SIZEOF_LONG_INT	8
#else
#define SIZEOF_LONG_INT	4
#endif
#endif

#ifndef BOOL
#define BOOL		int
#endif

namespace nativeodbc
{
#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>
}

using namespace nativeodbc;

namespace {

static PDynaLink g_sharedLibrary;
static SQLRETURN (SQL_API *g_SQLAllocHandle)(SQLSMALLINT HandleType,
									SQLHANDLE InputHandle, SQLHANDLE *OutputHandle) = NULL;
static SQLRETURN (SQL_API *g_SQLConnect)(SQLHDBC ConnectionHandle,
                                  SQLCHAR *ServerName, SQLSMALLINT NameLength1,
                                  SQLCHAR *UserName, SQLSMALLINT NameLength2,
                                  SQLCHAR *Authentication, SQLSMALLINT NameLength3) = NULL;
static SQLRETURN (SQL_API *g_SQLDescribeCol)(SQLHSTMT StatementHandle,
                                      SQLUSMALLINT ColumnNumber, SQLCHAR *ColumnName,
                                      SQLSMALLINT BufferLength, SQLSMALLINT *NameLength,
                                      SQLSMALLINT *DataType, SQLULEN *ColumnSize,
                                      SQLSMALLINT *DecimalDigits, SQLSMALLINT *Nullable) = NULL;
static SQLRETURN (SQL_API *g_SQLDisconnect)(SQLHDBC ConnectionHandle) = NULL;
static SQLRETURN (SQL_API *g_SQLExecDirect)(SQLHSTMT StatementHandle,
                                     SQLCHAR *StatementText, SQLINTEGER TextLength) = NULL;
static SQLRETURN (SQL_API *g_SQLFetch)(SQLHSTMT StatementHandle) = NULL;
static SQLRETURN (SQL_API *g_SQLFreeHandle)(SQLSMALLINT HandleType, SQLHANDLE Handle) = NULL;
static SQLRETURN (SQL_API *g_SQLGetData)(SQLHSTMT StatementHandle,
                                  SQLUSMALLINT ColumnNumber, SQLSMALLINT TargetType,
                                  SQLPOINTER TargetValue, SQLLEN BufferLength,
                                  SQLLEN *StrLen_or_Ind) = NULL;
static SQLRETURN (SQL_API *g_SQLGetDiagRec)(SQLSMALLINT HandleType, SQLHANDLE Handle,
                                     SQLSMALLINT RecNumber, SQLCHAR *Sqlstate,
                                     SQLINTEGER *NativeError, SQLCHAR *MessageText,
                                     SQLSMALLINT BufferLength, SQLSMALLINT *TextLength) = NULL;
static SQLRETURN (SQL_API *g_SQLNumResultCols)(SQLHSTMT StatementHandle,
                                        SQLSMALLINT *ColumnCount) = NULL;
static SQLRETURN (SQL_API *g_SQLRowCount)(SQLHSTMT StatementHandle,
                                   SQLLEN *RowCount) = NULL;
static SQLRETURN (SQL_API *g_SQLSetConnectAttr)(SQLHDBC ConnectionHandle,
                                         SQLINTEGER Attribute, SQLPOINTER Value,
                                         SQLINTEGER StringLength) = NULL;
static SQLRETURN (SQL_API *g_SQLSetEnvAttr)(SQLHENV EnvironmentHandle,
                                     SQLINTEGER Attribute, SQLPOINTER Value,
                                     SQLINTEGER StringLength);
static SQLRETURN (SQL_API *g_SQLSetStmtAttr)(SQLHSTMT StatementHandle,
                                      SQLINTEGER Attribute, SQLPOINTER Value,
                                      SQLINTEGER StringLength) = NULL;

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
	r = (*g_SQLGetDiagRec)(handleType, handle, 1, reinterpret_cast<SQLCHAR*>(sqlState),
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
}
	
GkODBCConnection::~GkODBCConnection()
{
	if (m_env != SQL_NULL_HENV) {
		(*g_SQLFreeHandle)(SQL_HANDLE_ENV, m_env);
		m_env = SQL_NULL_HENV;
	}
}

GkODBCConnection::GkODBCConnWrapper::~GkODBCConnWrapper()
{
	if (m_conn != SQL_NULL_HDBC) {
		SQLRETURN r = (*g_SQLDisconnect)(m_conn);
		if (!SQL_SUCCEEDED(r)) {
			PTRACE(1, "ODBC disconnect failed: " << GetODBCDiagMsg(r, SQL_HANDLE_DBC, m_conn));
			SNMP_TRAP(5, SNMPError, Database, "ODBC disconnection failed");
		}
		(*g_SQLFreeHandle)(SQL_HANDLE_DBC, m_conn);
		m_conn = SQL_NULL_HDBC;
	}
}

GkSQLConnection::SQLConnPtr GkODBCConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	if (!g_sharedLibrary.IsLoaded()) {
		if (m_library.IsEmpty()) {
#ifdef _WIN32
			m_library = "odbc32" + g_sharedLibrary.GetExtension();
#else
			m_library = "libodbc" + g_sharedLibrary.GetExtension();
#endif
		}

		if (!g_sharedLibrary.Open(m_library)) {
			PTRACE (1, GetName() << "\tCan't load library " << m_library);
			return NULL;
		}

		if (!g_sharedLibrary.GetFunction("SQLAllocHandle", (PDynaLink::Function &)g_SQLAllocHandle)
			|| !g_sharedLibrary.GetFunction("SQLConnect", (PDynaLink::Function &)g_SQLConnect)
			|| !g_sharedLibrary.GetFunction("SQLDescribeCol", (PDynaLink::Function &)g_SQLDescribeCol)
			|| !g_sharedLibrary.GetFunction("SQLDisconnect", (PDynaLink::Function &)g_SQLDisconnect)
			|| !g_sharedLibrary.GetFunction("SQLExecDirect", (PDynaLink::Function &)g_SQLExecDirect)
			|| !g_sharedLibrary.GetFunction("SQLFetch", (PDynaLink::Function &)g_SQLFetch)
			|| !g_sharedLibrary.GetFunction("SQLFreeHandle", (PDynaLink::Function &)g_SQLFreeHandle)
			|| !g_sharedLibrary.GetFunction("SQLGetData", (PDynaLink::Function &)g_SQLGetData)
			|| !g_sharedLibrary.GetFunction("SQLGetDiagRec", (PDynaLink::Function &)g_SQLGetDiagRec)
			|| !g_sharedLibrary.GetFunction("SQLNumResultCols", (PDynaLink::Function &)g_SQLNumResultCols)
			|| !g_sharedLibrary.GetFunction("SQLRowCount", (PDynaLink::Function &)g_SQLRowCount)
			|| !g_sharedLibrary.GetFunction("SQLSetConnectAttr", (PDynaLink::Function &)g_SQLSetConnectAttr)
			|| !g_sharedLibrary.GetFunction("SQLSetEnvAttr", (PDynaLink::Function &)g_SQLSetEnvAttr)
			|| !g_sharedLibrary.GetFunction("SQLSetStmtAttr", (PDynaLink::Function &)g_SQLSetStmtAttr)
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

		// allocate Environment handle and register version 
		SQLRETURN r = (*g_SQLAllocHandle)(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_env);
		if (!SQL_SUCCEEDED(r)) {
			PTRACE(1, GetName() << "\tFailed to allocate an ODBC environment handle: " << GetODBCDiagMsg(r, SQL_HANDLE_ENV, SQL_NULL_HENV));
			SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
			return NULL;
		}
		r = (*g_SQLSetEnvAttr)(m_env, SQL_ATTR_ODBC_VERSION, reinterpret_cast<SQLPOINTER>(SQL_OV_ODBC3), 0); 
		if (!SQL_SUCCEEDED(r)) {
			PTRACE(1, GetName() << "\tFailed to request ODBC interface version 3.0: " << GetODBCDiagMsg(r, SQL_HANDLE_ENV, m_env));
			(*g_SQLFreeHandle)(SQL_HANDLE_ENV, m_env);
			m_env = SQL_NULL_HENV;
			SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
			return NULL;
		}
		PTRACE(5, GetName() << "\tODBC environment created");
	}

	SQLHDBC conn = SQL_NULL_HDBC;

	// allocate connection handle, set timeout
	SQLRETURN r = (*g_SQLAllocHandle)(SQL_HANDLE_DBC, m_env, &conn); 
	if (!SQL_SUCCEEDED(r)) {
		PTRACE(1, GetName() << "\tFailed to allocate an ODBC connection handle: " << GetODBCDiagMsg(r, SQL_HANDLE_ENV, m_env));
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
		return NULL;
	}
	
	r = (g_SQLSetConnectAttr)(conn, SQL_ATTR_LOGIN_TIMEOUT, reinterpret_cast<SQLPOINTER>(10), 0);
	if (!SQL_SUCCEEDED(r)) {
		PTRACE(1, GetName() << "\tFailed to set ODBC connection login timeout: " << GetODBCDiagMsg(r, SQL_HANDLE_DBC, conn));
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
	}
	
	r = (*g_SQLSetConnectAttr)(conn, SQL_ATTR_CONNECTION_TIMEOUT, reinterpret_cast<SQLPOINTER>(10), 0);
	if (!SQL_SUCCEEDED(r)) {
		PTRACE(1, GetName() << "\tFailed to set ODBC connection request timeout: " << GetODBCDiagMsg(r, SQL_HANDLE_DBC, conn));
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
	}

	// Connect to datasource
	r = (*g_SQLConnect)(conn,
		reinterpret_cast<SQLCHAR*>(const_cast<char*>(m_database.IsEmpty() ? "" : (const char*)m_database)), SQL_NTS,
		reinterpret_cast<SQLCHAR*>(const_cast<char*>(m_username.IsEmpty() ? "" : (const char*)m_username)), SQL_NTS,
		reinterpret_cast<SQLCHAR*>(const_cast<char*>(m_password.IsEmpty() ? "" : (const char*)m_password)), SQL_NTS
		);
	if (!SQL_SUCCEEDED(r)) {
		PTRACE(1, GetName() << "\tODBC connect to " << m_database << " failed: " << GetODBCDiagMsg(r, SQL_HANDLE_DBC, conn));
		(*g_SQLFreeHandle)(SQL_HANDLE_DBC, conn);
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
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

	SQLRETURN r = (*g_SQLAllocHandle)(SQL_HANDLE_STMT, conn, &stmt); 
	if (!SQL_SUCCEEDED(r)) {
		PString errmsg(GetODBCDiagMsg(r, SQL_HANDLE_DBC, conn));
		PTRACE(1, GetName() << "\tFailed to allocate an ODBC statement handle: " << errmsg);
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
		Disconnect();
		return new GkODBCResult(r, errmsg);
	}

	r = (*g_SQLSetStmtAttr)(stmt, SQL_ATTR_QUERY_TIMEOUT, reinterpret_cast<SQLPOINTER>(timeout == -1 ? 10 : ((timeout + 999) / 1000)), 0);
	if (!SQL_SUCCEEDED(r)) {
		PTRACE(1, GetName() << "\tSQL query timeout not set: " << GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
	}

	r = (*g_SQLExecDirect)(stmt, reinterpret_cast<SQLCHAR*>(const_cast<char*>((const char*)queryStr)), SQL_NTS);
	bool nodata = (r == SQL_NO_DATA);
	if (r != SQL_NO_DATA && !SQL_SUCCEEDED(r)) {
		PString errmsg(GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
		PTRACE(1, GetName() << "\tFailed to execute an ODBC query: " << errmsg);
		(*g_SQLFreeHandle)(SQL_HANDLE_STMT, stmt);
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
		Disconnect();
		return new GkODBCResult(r, errmsg + ", query: " + queryStr);
	}
	
	SQLSMALLINT columns = 0;
	r = (*g_SQLNumResultCols)(stmt, &columns);
	if (!SQL_SUCCEEDED(r)) {
		PString errmsg(GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
		PTRACE(1, GetName() << "\tFailed to get ODBC number of result columns: " << errmsg);
		(*g_SQLFreeHandle)(SQL_HANDLE_STMT, stmt);
		SNMP_TRAP(5, SNMPError, Database, GetName() + " query failed");
		Disconnect();
		return new GkODBCResult(r, errmsg + ", query: " + queryStr);
	}
	
	SQLLEN rows = 0;
	
	if (columns == 0) {
		if (nodata) {
			(*g_SQLFreeHandle)(SQL_HANDLE_STMT, stmt);
			return new GkODBCResult(0, 0, NULL);
		} else {
			r = (*g_SQLRowCount)(stmt, &rows);
			if (!SQL_SUCCEEDED(r)) {
				PTRACE(1, GetName() << "\tFailed to get ODBC number of rows affected by a query: " << GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
				SNMP_TRAP(5, SNMPError, Database, GetName() + " query failed")
			}
			(*g_SQLFreeHandle)(SQL_HANDLE_STMT, stmt);
			return new GkODBCResult(rows, 0, NULL);
		}
	}

	if (nodata)
		return new GkODBCResult(0, columns, NULL);

	std::vector<PString> fieldNames(columns);
	
	for (SQLUSMALLINT i = 1; i <= columns; ++i) {
		SQLCHAR colname[64];
		r = (*g_SQLDescribeCol)(stmt, i, colname, sizeof(colname), NULL, NULL, NULL, NULL, NULL);
		if (!SQL_SUCCEEDED(r)) {
			PTRACE(1, GetName() << "\tFailed to get an ODBC result set column #" << i << " name: " << GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
			SNMP_TRAP(5, SNMPError, Database, GetName() + " query failed")
		} else
			fieldNames[i-1] = PString(reinterpret_cast<const char*>(colname));
	}

	std::list<GkSQLResult::ResultRow*> *resultRows = new std::list<GkSQLResult::ResultRow*>();
	do {
		r = (*g_SQLFetch)(stmt);
		if (r == SQL_NO_DATA)
			break;
			
		if (!SQL_SUCCEEDED(r)) {
			PTRACE(1, GetName() << "\tFailed to fetch an ODBC result row: " << GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
			SNMP_TRAP(5, SNMPError, Database, GetName() + " query failed")
			// we should return an error instead
			break;
		}
		
		GkSQLResult::ResultRow * row = new GkSQLResult::ResultRow(columns);
		
		for (SQLUSMALLINT i = 1; i <= columns; ++i) {
			SQLLEN indicator;
			char data[512];
			/* retrieve column data as a string */
			SQLRETURN result = (*g_SQLGetData)(stmt, i, SQL_C_CHAR, data, sizeof(data), &indicator);
			if (SQL_SUCCEEDED(result)) {
				/* Handle null columns */
				if (indicator == SQL_NULL_DATA)
					data[0] = 0;
			} else {
				PTRACE(1, GetName() << "\tFailed to get ODBC result set column #" << i << " data: " << GetODBCDiagMsg(r, SQL_HANDLE_STMT, stmt));
				SNMP_TRAP(5, SNMPError, Database, GetName() + " query failed")
				data[0] = 0;
			}
			(*row)[i-1] = pair<PString, PString>(data, fieldNames[i-1]);
		}

		resultRows->push_back(row);

		++rows;

	} while (SQL_SUCCEEDED(r));

	(*g_SQLFreeHandle)(SQL_HANDLE_STMT, stmt);
	
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
