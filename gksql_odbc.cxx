/*
 * gksql_odbc.cxx
 *
 * ODBC driver module for GnuGk
 *
 * Copyright (c) 2006, Simon Horne
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 */

#ifdef P_ODBC

#include <ptlib.h>
#include <ptlib/podbc.h>


/** Class that encapsulates SQL query result for odbc backend.
	It does not provide any multithread safety, so should be accessed
	from a single thread at time.
*/
class GkodbcResult : public GkSQLResult
{
public:
	/// Build the result from SELECT type query
	GkodbcResult(
		/// SELECT type query result
		PGresult* selectResult
		);

	/// Build the result from INSERT, DELETE or UPDATE query
	GkodbcResult(
		/// number of rows affected by the query
		long numRowsAffected
		);

	/// Build the empty	result and store query execution error information
	GkodbcResult(
		/// odbc specific error code
		unsigned int errorCode,
		/// odbc specific error message text
		const char* errorMsg
		);
	
	virtual ~GkodbcResult();
	
	/** @return
	    Backend specific error message, if the query failed.
	*/	
	virtual PString GetErrorMessage();
	
	/** @return
	    Backend specific error code, if the query failed.
	*/	
	virtual long GetErrorCode();
	
	/** @return
	    True if rows can be fetched in random access order, false if
	    rows have to be fethed sequentially and can be retrieved only once.
	*/
	virtual bool HasRandomAccess();

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

	/** @return
	    True if the column at the index #fieldOffset# is NULL in the row 
	    fetched most recently.
	*/
	virtual bool IsNullField(
		/// index of the column to check
		long fieldOffset
		);
			
	/** Fetch a single row from the result set. This function requires
		that the backend supports random row access.
		
	    @return
	    True if the row has been fetched, false if a row at the given offset
		does not exists or SQL backend does not support random row access.
	*/
	virtual bool FetchRow(
		/// array to be filled with string representations of the row fields
		PStringArray& result,
		/// index (0 based) of the row to fetch
		long rowOffset
		);
	virtual bool FetchRow(
		/// array to be filled with string representations of the row fields
		ResultRow& result,
		/// index (0 based) of the row to fetch
		long rowOffset
		);
		
	/** @return
	    True if the column at the index #fieldOffset# is NULL in the row 
	    at the specified index.
	*/
	virtual bool IsNullField(
		/// index of the column to check
		long fieldOffset,
		/// index (0 based) of the row to check
		long rowOffset
		);

private:
	GkodbcResult();
	GkodbcResult(const GkodbcResult&);
	GkodbcResult& operator=(const GkodbcResult&);
	
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

/// odbc backend connection implementation.
class GkodbcConnection : public GkSQLConnection
{
public:
	/// Build a new PgSQL connection object
	GkodbcConnection(
		/// name to use in the log
		const char* name = "odbc"
		);
	
	virtual ~GkodbcConnection();

protected:
	class odbcConnWrapper : public GkSQLConnection::SQLConnWrapper
	{
	public:
		odbcConnWrapper(
			/// unique identifier for this connection
			int id,
			/// host:port this connection is made to
			const PString& host,
			/// odbc connection object
			PODBC * conn
			) : SQLConnWrapper(id, host), m_conn(conn) {}

		virtual ~odbcConnWrapper();

	private:
		odbcConnWrapper();
		odbcConnWrapper(const odbcConnWrapper&);
		odbcConnWrapper& operator=(const odbcConnWrapper&);

	public:
		PODBC* m_conn;
	};

	/** Create a new SQL connection using parameters stored in this object.
	    When the connection is to be closed, the object is simply deleted
	    using delete operator.
	    
	    @return
	    NULL if database connection could not be established 
	    or an object of odbcConnWrapper class.
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
	GkodbcConnection(const GkodbcConnection&);
	GkodbcConnection& operator=(const GkodbcConnection&);
};


GkodbcResult::GkodbcResult(
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
		
	m_selectType = true;
}

GkodbcResult::GkodbcResult(
	/// number of rows affected by the query
	long numRowsAffected
	) 
	: GkSQLResult(false), m_sqlResult(NULL), m_sqlRow(-1), 
	m_errorCode(0)
{
	m_numRows = numRowsAffected;
	m_selectType = false;
}
	
GkodbcResult::GkodbcResult(
	/// odbc specific error code
	unsigned int errorCode,
	/// odbc specific error message text
	const char* errorMsg
	) 
	: GkSQLResult(true), m_sqlResult(NULL), m_sqlRow(-1),
	m_errorCode(errorCode), m_errorMessage(errorMsg)
{
}

GkodbcResult::~GkodbcResult()
{
}

bool GkodbcResult::HasRandomAccess()
{
	return true;
}

PString GkodbcResult::GetErrorMessage()
{
	return m_errorMessage;
}
	
long GkodbcResult::GetErrorCode()
{
	return m_errorCode;
}

bool GkodbcResult::FetchRow(
	/// array to be filled with string representations of the row fields
	PStringArray& result
	)
{
       return false;
}

bool GkodbcResult::FetchRow(
	/// array to be filled with string representations of the row fields
	ResultRow& result
	)
{
	return false;
}

bool GkodbcResult::IsNullField(
	/// index of the column to check
	long fieldOffset
	)
{
	return false;
}

bool GkodbcResult::FetchRow(
	/// array to be filled with string representations of the row fields
	PStringArray& result,
	/// index (0 based) of the row to fetch
	long rowOffset
	)
{
	return false;
}

bool GkodbcResult::FetchRow(
	/// array to be filled with string representations of the row fields
	ResultRow& result,
	/// index (0 based) of the row to fetch
	long rowOffset
	)
{
	return false;
}

bool GkodbcResult::IsNullField(
	/// index of the column to check
	long fieldOffset,
	/// index (0 based) of the row to check
	long rowOffset
	)
{
	return false;
}


GkodbcConnection::GkodbcConnection(
	/// name to use in the log
	const char* name
	) : GkSQLConnection(name)
{
}
	
GkodbcConnection::~GkodbcConnection()
{
}

GkodbcConnection::odbcConnWrapper::~odbcConnWrapper()
{
}

GkSQLConnection::SQLConnPtr GkodbcConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	return NULL;
}
	
GkSQLResult* GkodbcConnection::ExecuteQuery(
	/// SQL connection to use for query execution
	GkSQLConnection::SQLConnPtr conn,
	/// query string
	const char* queryStr,
	/// maximum time (ms) for the query execution, -1 means infinite
	long /*timeout*/
	)
{

	return new GkodbcResult(resultInfo, PQresultErrorMessage(result));
	
}

PString GkodbcConnection::EscapeString(
	/// SQL connection to get escaping parameters from
	SQLConnPtr conn,
	/// string to be escaped
	const char* str
	)
{
	PString escapedStr;

	return escapedStr;
}

namespace {
	GkSQLCreator<GkodbcConnection> PgSQLCreator("odbc");
}

#endif /* HAS_PGSQL */
