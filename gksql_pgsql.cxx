/*
 * gksql_pgsql.cxx
 *
 * PostgreSQL driver module for GnuGk
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.11  2006/05/07 12:22:59  willamowius
 * fix comments
 *
 * Revision 1.10  2006/04/14 13:56:19  willamowius
 * call failover code merged
 *
 * Revision 1.1.1.1  2005/11/21 20:19:59  willamowius
 *
 *
 * Revision 1.4  2005/11/15 19:52:56  jan
 * Michal v1 (works, but on in routed, not proxy mode)
 *
 * Revision 1.9  2005/04/24 16:39:44  zvision
 * MSVC6.0 compatibility fixed
 *
 * Revision 1.8  2005/03/15 15:34:03  zvision
 * Compiler warning removed
 *
 * Revision 1.7  2005/01/16 15:22:35  zvision
 * Database Host parameter accepts only one host now
 *
 * Revision 1.6  2004/10/20 09:16:23  zvision
 * VC6 compilation errors fixed
 *
 * Revision 1.5.4.1  2004/10/20 09:10:12  zvision
 * VC6 compilation errors fixed
 *
 * Revision 1.5  2004/08/02 10:52:07  zvision
 * Ability to extract column names from a result set
 *
 * Revision 1.4  2004/07/09 22:11:36  zvision
 * SQLAcct module ported from 2.0 branch
 *
 */
#if HAS_PGSQL

#if defined(_WIN32) && (_MSC_VER <= 1200)
#pragma warning(disable:4786) // warning about too long debug symbol off
#pragma warning(disable:4284)
#endif

#include <ptlib.h>
#include <libpq-fe.h>
#include "gksql.h"

#ifdef _WIN32
#pragma comment( lib, "libpq.lib" )
#endif

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
		m_numRows = PQntuples(m_sqlResult);
		m_numFields = PQnfields(m_sqlResult);
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
		PQclear(m_sqlResult);
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
			PQgetvalue(m_sqlResult, m_sqlRow, i), 
			PQgetlength(m_sqlResult, m_sqlRow, i)
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
			PQgetvalue(m_sqlResult, m_sqlRow, i), 
			PQgetlength(m_sqlResult, m_sqlRow, i)
			);
		result[i].second = PQfname(m_sqlResult, i);
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
	PQfinish(m_conn);
}

GkSQLConnection::SQLConnPtr GkPgSQLConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	PGconn* conn;
	const PString portStr(m_port);
//	const PString optionsStr("connect_timeout=10000");
	if ((conn = PQsetdbLogin(m_host, 
			m_port ? (const char*)portStr : (const char*)NULL,
			NULL /*(const char*)optionsStr*/, NULL,
			m_database, m_username, 
			m_password.IsEmpty() ? (const char*)NULL : (const char*)m_password
			)) && PQstatus(conn) == CONNECTION_OK) {
		PTRACE(5, GetName() << "\tPgSQL connection to " << m_username << '@' << m_host 
			<< '[' << m_database << "] established successfully"
			);
		return new PgSQLConnWrapper(id, m_host, conn);
	} else {
		PTRACE(2, GetName() << "\tPgSQL connection to " << m_username << '@' << m_host 
			<< '[' << m_database << "] failed (PQsetdbLogin failed): " 
			<< (conn ? PQerrorMessage(conn) : "")
			);
		if (conn)
			PQfinish(conn);
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
	PGresult* result = PQexec(pgsqlconn, queryStr);
	if (result == NULL)
		return new GkPgSQLResult(PGRES_FATAL_ERROR, PQerrorMessage(pgsqlconn));
		
	ExecStatusType resultInfo = PQresultStatus(result);
	switch (resultInfo)
	{
	case PGRES_COMMAND_OK:
		return new GkPgSQLResult(
			PQcmdTuples(result) ? atoi(PQcmdTuples(result)) : 0
			);
		
	case PGRES_TUPLES_OK:
		return new GkPgSQLResult(result);
		
	default:
		return new GkPgSQLResult(resultInfo, PQresultErrorMessage(result));
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
	const unsigned long numChars = str ? strlen(str) : 0;
	
	if (numChars)
		escapedStr.SetSize(
			PQescapeString(escapedStr.GetPointer(numChars*2+1), str, numChars) + 1
			);
	return escapedStr;
}

namespace {
	GkSQLCreator<GkPgSQLConnection> PgSQLCreator("PostgreSQL");
}

#endif /* HAS_PGSQL */
