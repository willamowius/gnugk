/*
 * gksql_sqlite.cxx
 *
 * SQLite driver module for GnuGk
 *
 * Copyright (c) 2007-2012, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"

#if HAS_SQLITE

#include <ptlib.h>
#include <sqlite3.h>
#include "gksql.h"

static PDynaLink g_sharedLibrary;
static int (*g_sqlite3_changes)(sqlite3*) = NULL;
static int (*g_sqlite3_close)(sqlite3 *) = NULL;
static const char * (*g_sqlite3_errmsg)(sqlite3*) = NULL;
static int (*g_sqlite3_exec)(sqlite3*, const char *sql, int (*callback)(void*,int,char**,char**), void *, char **errmsg) = NULL;
static void (*g_sqlite3_free)(void*) = NULL;
static char * (*g_sqlite3_mprintf)(const char*,...) = NULL;
static int (*g_sqlite3_open)(const char *filename, sqlite3 **ppDb) = NULL;


/** Class that encapsulates SQL query result for SQLite backend.
	It does not provide any multithread safety, so should be accessed
	from a single thread at time.
*/
class GkSQLiteResult : public GkSQLResult
{
public:
	/// Build the result from SELECT type query
	GkSQLiteResult(
		/// number of rows affected by the query
		long numRowsAffected,
		/// query result
		vector<ResultRow*> * resultRows
		);

	/// Build the empty	result and store query execution error information
	GkSQLiteResult(
		/// SQLite specific error code
		unsigned int errorCode,
		/// SQLite specific error message text
		const char* errorMsg
		);
	
	virtual ~GkSQLiteResult();
	
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
	GkSQLiteResult();
	GkSQLiteResult(const GkSQLiteResult&);
	GkSQLiteResult& operator=(const GkSQLiteResult&);
	
protected:
	/// query result for SELECT type queries
	vector<ResultRow*> * m_sqlResult;
	/// the most recent row returned by fetch operation
	int m_sqlRow;
	/// SQLite specific error code (if the query failed)
	unsigned int m_errorCode;
	/// SQLite specific error message text (if the query failed)
	PString m_errorMessage;
};

/// SQLite backend connection implementation.
class GkSQLiteConnection : public GkSQLConnection
{
public:
	/// Build a new SQLite connection object
	GkSQLiteConnection(
		/// name to use in the log
		const char* name = "SQLite"
		);
	
	virtual ~GkSQLiteConnection();

protected:
	class GkSQLiteConnWrapper : public GkSQLConnection::SQLConnWrapper
	{
	public:
		GkSQLiteConnWrapper(
			/// unique identifier for this connection
			int id,
			/// SQLite connection object
			sqlite3 * conn
			) : SQLConnWrapper(id, "localhost"), m_conn(conn) {}

		virtual ~GkSQLiteConnWrapper();

	private:
		GkSQLiteConnWrapper();
		GkSQLiteConnWrapper(const GkSQLiteConnWrapper&);
		GkSQLiteConnWrapper& operator=(const GkSQLiteConnWrapper&);

	public:
		sqlite3 * m_conn;
	};

	/** Create a new SQL connection using parameters stored in this object.
	    When the connection is to be closed, the object is simply deleted
	    using delete operator.

	    @return
	    NULL if database connection could not be established 
	    or an object of GkSQLiteConnWrapper class.
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
	GkSQLiteConnection(const GkSQLiteConnection&);
	GkSQLiteConnection& operator=(const GkSQLiteConnection&);
};


GkSQLiteResult::GkSQLiteResult(
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
	if (!selectResult->empty())
		m_numFields = (*selectResult)[0]->size();
	else
		m_numFields = 0;

	m_queryError = false;
}

GkSQLiteResult::GkSQLiteResult(
	/// SQLite specific error code
	unsigned int errorCode,
	/// SQLite specific error message text
	const char* errorMsg
	) 
	: GkSQLResult(true), m_sqlResult(NULL), m_sqlRow(-1),
	m_errorCode(errorCode), m_errorMessage(errorMsg)
{
	m_queryError = true;
}

GkSQLiteResult::~GkSQLiteResult()
{
	if (m_sqlResult != NULL) {
		for(unsigned i=0; i < m_sqlResult->size(); i++){
			delete (*m_sqlResult)[i];
		}
		delete m_sqlResult;
	}
}

PString GkSQLiteResult::GetErrorMessage()
{
	return m_errorMessage;
}
	
long GkSQLiteResult::GetErrorCode()
{
	return m_errorCode;
}

bool GkSQLiteResult::FetchRow(
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

bool GkSQLiteResult::FetchRow(
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


GkSQLiteConnection::GkSQLiteConnection(
	/// name to use in the log
	const char* name
	) : GkSQLConnection(name)
{
}
	
GkSQLiteConnection::~GkSQLiteConnection()
{
}

GkSQLiteConnection::GkSQLiteConnWrapper::~GkSQLiteConnWrapper()
{
	(*g_sqlite3_close)(m_conn);
}

GkSQLConnection::SQLConnPtr GkSQLiteConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	if (!g_sharedLibrary.IsLoaded()) {
		if (m_library.IsEmpty()) {
#ifdef _WIN32
			m_library = "sqlite3" + g_sharedLibrary.GetExtension();
#else
			m_library = "libsqlite3" + g_sharedLibrary.GetExtension();
#endif
		}

		if (!g_sharedLibrary.Open(m_library)) {
			PTRACE (1, GetName() << "\tCan't load library " << m_library);
			return NULL;
		}

		if (!g_sharedLibrary.GetFunction("sqlite3_changes", (PDynaLink::Function &)g_sqlite3_changes)
			|| !g_sharedLibrary.GetFunction("sqlite3_close", (PDynaLink::Function &)g_sqlite3_close)
			|| !g_sharedLibrary.GetFunction("sqlite3_errmsg", (PDynaLink::Function &)g_sqlite3_errmsg)
			|| !g_sharedLibrary.GetFunction("sqlite3_exec", (PDynaLink::Function &)g_sqlite3_exec)
			|| !g_sharedLibrary.GetFunction("sqlite3_free", (PDynaLink::Function &)g_sqlite3_free)
			|| !g_sharedLibrary.GetFunction("sqlite3_mprintf", (PDynaLink::Function &)g_sqlite3_mprintf)
			|| !g_sharedLibrary.GetFunction("sqlite3_open", (PDynaLink::Function &)g_sqlite3_open)
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

	sqlite3 *conn;
	int rc = (*g_sqlite3_open)(m_database, &conn);
	if (rc) {
		PTRACE(2, GetName() << "\tSQLite connection to " <<  m_database 
			<< " failed (sqlite3_open failed): " << (*g_sqlite3_errmsg)(conn));
		(*g_sqlite3_close)(conn);
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed")
		return NULL;
	}	
	
	PTRACE(5, GetName() << "\tSQLite connection to " << m_database
		<< " established successfully");
	return new GkSQLiteConnWrapper(id, conn);
}

static int sqlite_callback(void * result, int argc, char **argv, char **azColName)
{
	GkSQLResult::ResultRow * row = new GkSQLResult::ResultRow();
	((vector<GkSQLResult::ResultRow*> *)result)->push_back(row);
	for(int i=0; i < argc; i++){
		row->push_back(pair<PString, PString>(argv[i] ? argv[i] : "NULL", azColName[i]));
	}
	return 0;
}

GkSQLResult* GkSQLiteConnection::ExecuteQuery(
	/// SQL connection to use for query execution
	GkSQLConnection::SQLConnPtr con,
	/// query string
	const char* queryStr,
	/// maximum time (ms) for the query execution, -1 means infinite
	long /*timeout*/
	)
{
	sqlite3 * conn = ((GkSQLiteConnWrapper*)con)->m_conn;

	vector<GkSQLResult::ResultRow*> * resultRows = new vector<GkSQLResult::ResultRow*>();
	char *errormsg = NULL;
	int rc = (*g_sqlite3_exec)(conn, queryStr, sqlite_callback, resultRows, &errormsg);
	if (rc != SQLITE_OK) {
		delete resultRows;
		Disconnect();
		return new GkSQLiteResult(rc, errormsg);
	}
	return new GkSQLiteResult((*g_sqlite3_changes)(conn), resultRows);
}

PString GkSQLiteConnection::EscapeString(
	/// SQL connection to get escaping parameters from
	SQLConnPtr /*conn*/,
	/// string to be escaped
	const char* str
	)
{
	char * quoted = (*g_sqlite3_mprintf)("%q",str);
	PString result(quoted);
	(*g_sqlite3_free)(quoted);
	return result;
}

namespace {
	GkSQLCreator<GkSQLiteConnection> SQLiteCreator("SQLite");
}

#endif /* HAS_SQLITE */
