/*
 * gksql_unixodbc.cxx
 *
 * native unixODBC driver module for GnuGk
 *
 * Copyright (c) 2008, Jan Willamowius
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 *
 */
#if HAS_UNIXODBC

#include <ptlib.h>
#include "gksql.h"

namespace unixodbc
{
#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>
}

using namespace unixodbc;

/** Class that encapsulates SQL query result for the unixODBC backend.
	It does not provide any multithread safety, so should be accessed
	from a single thread at time.
*/
class GkunixODBCResult : public GkSQLResult
{
public:
	/// Build the result from SELECT type query
	GkunixODBCResult(
		/// number of rows affected by the query
		long numRowsAffected,
		/// query result
		vector<ResultRow*> * resultRows
		);

	/// Build the empty	result and store query execution error information
	GkunixODBCResult(
		/// error code
		unsigned int errorCode,
		/// error message text
		const char* errorMsg
		);
	
	virtual ~GkunixODBCResult();
	
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
	GkunixODBCResult();
	GkunixODBCResult(const GkunixODBCResult&);
	GkunixODBCResult& operator=(const GkunixODBCResult&);
	
protected:
	/// query result for SELECT type queries
	vector<ResultRow*> * m_sqlResult;
	/// the most recent row returned by fetch operation
	int m_sqlRow;
	/// error code (if the query failed)
	unsigned int m_errorCode;
	/// error message text (if the query failed)
	PString m_errorMessage;
};

/// unixODBC backend connection implementation.
class GkunixODBCConnection : public GkSQLConnection
{
public:
	/// Build a new connection object
	GkunixODBCConnection(
		/// name to use in the log
		const char* name = "unixODBC"
		);
	
	virtual ~GkunixODBCConnection();

protected:
	class GkunixODBCConnWrapper : public GkSQLConnection::SQLConnWrapper
	{
	public:
		GkunixODBCConnWrapper(
			/// unique identifier for this connection
			int id,
			/// unixODBC environment handle
			SQLHENV env,
			/// unixODBC connection handle
			SQLHDBC conn
			) : SQLConnWrapper(id, "localhost"), m_env(env), m_conn(conn) {}

		virtual ~GkunixODBCConnWrapper();

	private:
		GkunixODBCConnWrapper();
		GkunixODBCConnWrapper(const GkunixODBCConnWrapper&);
		GkunixODBCConnWrapper& operator=(const GkunixODBCConnWrapper&);

	public:
		SQLHENV m_env;
		SQLHDBC m_conn;
	};

	/** Create a new SQL connection using parameters stored in this object.
	    When the connection is to be closed, the object is simply deleted
	    using delete operator.
	    
	    @return
	    NULL if database connection could not be established 
	    or an object of GkunixODBCConnWrapper class.
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
	GkunixODBCConnection(const GkunixODBCConnection&);
	GkunixODBCConnection& operator=(const GkunixODBCConnection&);
};


GkunixODBCResult::GkunixODBCResult(
	/// number of rows affected by the query
	long numRowsAffected,
	/// query result
	vector<ResultRow*> * selectResult
	) 
	: GkSQLResult(false), m_sqlResult(selectResult), m_sqlRow(-1),
	m_errorCode(0)
{
	m_numRows = numRowsAffected;
	if ((long)selectResult->size() > numRowsAffected)
		m_numRows = selectResult->size();
	if (selectResult->size() > 0)
		m_numFields = (*selectResult)[0]->size();
	else
		m_numFields = 0;

	m_queryError = false;
}

GkunixODBCResult::GkunixODBCResult(
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

GkunixODBCResult::~GkunixODBCResult()
{
	if (m_sqlResult != NULL) {
		for(unsigned i=0; i < m_sqlResult->size(); i++){
			delete (*m_sqlResult)[i];
		}
		delete m_sqlResult;
	}
}

PString GkunixODBCResult::GetErrorMessage()
{
	return m_errorMessage;
}
	
long GkunixODBCResult::GetErrorCode()
{
	return m_errorCode;
}

bool GkunixODBCResult::FetchRow(
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

	for (int i=0; i < m_numFields; i++) {
		result[i] = (*((*m_sqlResult)[m_sqlRow]))[i].first;
	}
	
	m_sqlRow++;
	
	return true;
}

bool GkunixODBCResult::FetchRow(
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

	result = *((*m_sqlResult)[m_sqlRow]);
	
	m_sqlRow++;
	
	return true;
}


GkunixODBCConnection::GkunixODBCConnection(
	/// name to use in the log
	const char* name
	) : GkSQLConnection(name)
{
}
	
GkunixODBCConnection::~GkunixODBCConnection()
{
}

GkunixODBCConnection::GkunixODBCConnWrapper::~GkunixODBCConnWrapper()
{
	SQLDisconnect(m_conn);
	SQLFreeHandle(SQL_HANDLE_DBC, m_conn);
	SQLDisconnect(m_env);
	SQLFreeHandle(SQL_HANDLE_ENV, m_env);
}

GkSQLConnection::SQLConnPtr GkunixODBCConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	SQLHENV env;
	SQLHDBC conn;
	SQLRETURN result;
	
	// allocate Environment handle and register version 
	result = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
	if (SQL_SUCCEEDED(result)) {
		PTRACE(2, GetName() << "\tunixODBC connection to " << m_database 
			<< " failed (SQLAllocHandle(ENV) failed)");
		return NULL;
	}
	result = SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0); 
	if (SQL_SUCCEEDED(result)) {
		PTRACE(2, GetName() << "\tunixODBC connection to " << m_database 
			<< " failed (SQLSetEnvAttr failed)");
		printf("Error SetEnv\n");
		SQLFreeHandle(SQL_HANDLE_ENV, env);
		return NULL;
	}

	// allocate connection handle, set timeout
	result = SQLAllocHandle(SQL_HANDLE_DBC, env, &conn); 
	if (SQL_SUCCEEDED(result)) {
		PTRACE(2, GetName() << "\tunixODBC connection to " << m_database 
			<< " failed (SQLAllocHandle(DBC) failed)");
		SQLFreeHandle(SQL_HANDLE_ENV, env);
		return NULL;
	}
	SQLSetConnectAttr(conn, SQL_LOGIN_TIMEOUT, (SQLPOINTER *)10, 0);

	// Connect to datasource
	result = SQLDriverConnect(conn, NULL, (SQLCHAR*)(const char*) m_database, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
	if (SQL_SUCCEEDED(result)) {
		char stat[10]; // Status SQL
		SQLINTEGER err;
		SQLSMALLINT	mlen;
		char msg[100];
		SQLGetDiagRec(SQL_HANDLE_DBC, conn, 1, (SQLCHAR*)stat, &err, (SQLCHAR*)msg, sizeof(msg), &mlen);
		PTRACE(2, GetName() << "\tunixODBC connection to " << m_database 
			<< " failed (SQLConnect() failed): " << msg << " (" << err << ")");
		SQLFreeHandle(SQL_HANDLE_DBC, conn);
		SQLFreeHandle(SQL_HANDLE_ENV, env);
		return NULL;
	}

	PTRACE(5, GetName() << "\tunixODBC connection to " << m_database
		<< " established successfully");
	return new GkunixODBCConnWrapper(id, env, conn);
}

GkSQLResult* GkunixODBCConnection::ExecuteQuery(
	/// SQL connection to use for query execution
	GkSQLConnection::SQLConnPtr con,
	/// query string
	const char* queryStr,
	/// maximum time (ms) for the query execution, -1 means infinite
	long /*timeout*/
	)
{
	SQLHDBC conn = ((GkunixODBCConnWrapper*)con)->m_conn;
	SQLHSTMT stmt;
	SQLSMALLINT columns;
	SQLINTEGER rows;
	SQLRETURN result;

	result = SQLAllocHandle(SQL_HANDLE_STMT, conn, &stmt); 
	if (SQL_SUCCEEDED(result)) {
		PTRACE(2, GetName() << "\tunixODBC connection to " << m_database 
			<< " failed (SQLAllocHandle(STMT) failed)");
		Disconnect();
		return new GkunixODBCResult(result, "SQLAllocHandle(STMT) failed");
	}

	result = SQLExecDirect(stmt, (SQLCHAR*)(const char*) queryStr, SQL_NTS);
	if (SQL_SUCCEEDED(result)) {
		char stat[10]; // Status SQL
		SQLINTEGER err;
		SQLSMALLINT	mlen;
		char msg[100];
		SQLGetDiagRec(SQL_HANDLE_DBC, conn, 1, (SQLCHAR*)stat, &err, (SQLCHAR*)msg, 100, &mlen);
		SQLFreeHandle(SQL_HANDLE_STMT, stmt);
		Disconnect();
		return new GkunixODBCResult(result, PString("SQLExecDirect() failed: ") + msg + " (" + err + ")");
	}
	
	vector<GkSQLResult::ResultRow*> * resultRows = new vector<GkSQLResult::ResultRow*>();
	SQLNumResultCols(stmt, &columns);
	SQLRowCount(stmt, &rows);
	while (SQL_SUCCEEDED(result = SQLFetch(stmt))) {
		GkSQLResult::ResultRow * row = new GkSQLResult::ResultRow();
		resultRows->push_back(row);
		SQLUSMALLINT i;
	    for (i = 1; i <= columns; i++) {
		    SQLINTEGER indicator;
			char data[512];
			/* retrieve column data as a string */
			result = SQLGetData(stmt, i, SQL_C_CHAR, data, sizeof(data), &indicator);
			if (SQL_SUCCEEDED(result)) {
				/* Handle null columns */
				if (indicator == SQL_NULL_DATA)
					strcpy(data, "NULL");
				// get column name (should be moved out of the loop)
				SQLCHAR colname[30];
				SQLDescribeCol(stmt, i, colname, sizeof(colname), NULL, NULL, NULL, NULL, NULL);
		        row->push_back(pair<PString, PString>(data, (const char *)colname));
			}
		}
	}

	SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	return new GkunixODBCResult(rows, resultRows);
}

PString GkunixODBCConnection::EscapeString(
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
	GkSQLCreator<GkunixODBCConnection> unixODBCCreator("unixODBC");
}

#endif /* HAS_UNIXODBC */
