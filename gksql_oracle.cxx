/*
 * gksql_oracle.cxx
 *
 * Oracle driver module for GnuGk
 *
 * Copyright (c) 2023, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"

#if HAS_ORACLE

#include <ptlib.h>
#include "dpi.h"
#include "gksql.h"

static dpiContext *gContext = NULL;

/** Class that encapsulates query result for Oracle backend.
	It does not provide any multithread safety, so should be accessed
	from a single thread at time.
*/
class GkOracleResult : public GkSQLResult
{
public:
	/// Build the result from the query
	GkOracleResult(
		/// all result rows
		vector<GkSQLResult::ResultRow*> * rows
		);

	/// result from an INSERT/UPDATe query with no result rows
	GkOracleResult(
		long numRowsAffected
		);

	/// Build the empty	result and store query execution error information
	GkOracleResult(
		/// Oracle specific error code
		unsigned int errorCode,
		/// Oracle specific error message text
		const char* errorMsg
		);

	virtual ~GkOracleResult();

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
		PStringArray & result
		);
	virtual bool FetchRow(
		/// array to be filled with string representations of the row fields
		ResultRow & result
		);

private:
	GkOracleResult();
	GkOracleResult(const GkOracleResult &);
	GkOracleResult& operator=(const GkOracleResult &);

protected:
	/// all result rows
	vector<GkSQLResult::ResultRow*> * m_rows;
	/// the most recent row returned by fetch operation
	int m_sqlRow;
	/// Oracle specific error code (if the query failed)
	unsigned int m_errorCode;
	/// Oracle specific error message text (if the query failed)
	PString m_errorMessage;
};

/// Oracle backend connection implementation.
class GkOracleConnection : public GkSQLConnection
{
public:
	/// Build a new Oracle connection object
	GkOracleConnection(
		/// name to use in the log
		const char* name = "Oracle"
		);

	virtual ~GkOracleConnection();

protected:
	class GkOracleConnWrapper : public GkSQLConnection::SQLConnWrapper
	{
	public:
		GkOracleConnWrapper(
			/// unique identifier for this connection
			int id,
			/// Oracle connection object
			dpiConn * conn
			) : SQLConnWrapper(id, "localhost"), m_conn(conn) { }

		virtual ~GkOracleConnWrapper();

	private:
		GkOracleConnWrapper();
		GkOracleConnWrapper(const GkOracleConnWrapper&);
		GkOracleConnWrapper& operator=(const GkOracleConnWrapper&);

	public:
		dpiConn * m_conn;
	};

	/** Create a new Oracle connection using parameters stored in this object.
	    When the connection is to be closed, the object is simply deleted
	    using delete operator.

	    @return
	    NULL if database connection could not be established
	    or an object of GkOracleConnWrapper class.
	*/
	virtual SQLConnPtr CreateNewConnection(
		/// unique identifier for this connection
		int id
		);

	/** Execute the query using specified SQL connection.

		@return
		Query execution result.
	*/
	virtual GkSQLResult * ExecuteQuery(
		/// connection to use for query execution
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
		/// connection to get escaping parameters from
		SQLConnPtr conn,
		/// string to be escaped
		const char* str
		) { return str; } // TODO

private:
	GkOracleConnection(const GkOracleConnection &);
	GkOracleConnection & operator=(const GkOracleConnection &);
};


GkOracleResult::GkOracleResult(
	/// all result rows
	vector<GkSQLResult::ResultRow*> * rows
	)
	: GkSQLResult(false), m_sqlRow(-1), m_errorCode(0)
{
	m_rows = rows;
	m_numRows = m_rows->size();
	if (!m_rows->empty())
		m_numFields = (*m_rows)[0]->size();
	else
		m_numFields = 0;

	m_queryError = false;
}

GkOracleResult::GkOracleResult(long numRowsAffected)
	: GkSQLResult(false), m_rows(NULL), m_sqlRow(-1), m_errorCode(0)
{
	m_numRows = numRowsAffected;
}

GkOracleResult::GkOracleResult(
	/// Oracle specific error code
	unsigned int errorCode,
	/// Oracle specific error message text
	const char* errorMsg
	)
	: GkSQLResult(true), m_rows(NULL), m_sqlRow(-1),
	m_errorCode(errorCode), m_errorMessage(errorMsg)
{
	m_queryError = true;
}

GkOracleResult::~GkOracleResult()
{
	if (m_rows != NULL) {
		for(auto r : *m_rows) {
			delete r;
		}
		delete m_rows;
	}
}

PString GkOracleResult::GetErrorMessage()
{
	return m_errorMessage;
}

long GkOracleResult::GetErrorCode()
{
	return m_errorCode;
}

bool GkOracleResult::FetchRow(
	/// array to be filled with string representations of the row fields
	PStringArray & result
	)
{
	if (m_rows == NULL || m_numRows <= 0)
		return false;

	if (m_sqlRow < 0)
		m_sqlRow = 0;

	if (m_sqlRow >= m_numRows)
		return false;

	result.SetSize(m_numFields);
	for (PINDEX i = 0; i < m_numFields; i++) {
		ResultRow * row = ((*m_rows)[m_sqlRow]);
		result[i] = (*row)[i].first;
	}

	m_sqlRow++;

	return true;
}

bool GkOracleResult::FetchRow(
	/// array to be filled with string representations of the row fields
	ResultRow & result
	)
{
	if (m_rows == NULL || m_numRows <= 0)
		return false;

	if (m_sqlRow < 0)
		m_sqlRow = 0;

	if (m_sqlRow >= m_numRows)
		return false;

	result.resize(m_numFields);

	result = *((*m_rows)[m_sqlRow]);

	m_sqlRow++;

	return true;
}


GkOracleConnection::GkOracleConnection(
	/// name to use in the log
	const char* name
	) : GkSQLConnection(name)
{
}

GkOracleConnection::~GkOracleConnection()
{
}

GkOracleConnection::GkOracleConnWrapper::~GkOracleConnWrapper()
{
	dpiConn_release(m_conn);
}

GkSQLConnection::SQLConnPtr GkOracleConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	dpiErrorInfo errorInfo;
    if (!gContext) {
        if (dpiContext_createWithParams(DPI_MAJOR_VERSION, DPI_MINOR_VERSION,
                NULL, &gContext, &errorInfo) < 0) {
			PTRACE(1, "Oracle\tCannot create DPI context: " << errorInfo.message);
			return NULL;
        }
	}
	dpiConn *conn;
    if (m_port <= 0) {
        m_port = 1521; // default port
    }
	PString connectString = m_host + "/" + m_database + ":" + m_port;
    if (dpiConn_create(gContext,
			m_username, m_username.GetLength(),
			m_password, m_password.GetLength(),
			connectString, connectString.GetLength(),
			NULL, NULL, &conn) < 0) {
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed")
		dpiContext_getError(gContext, &errorInfo);
    	PTRACE(2, GetName() << "\tConnection to " << m_host << " failed: " << errorInfo.message);
		return NULL;
    }

	PTRACE(5, GetName() << "\tOracle connection to " << m_host << " established successfully");
	return new GkOracleConnWrapper(id, conn);
}

GkSQLResult* GkOracleConnection::ExecuteQuery(
	/// connection to use for query execution
	GkSQLConnection::SQLConnPtr con,
	/// query string
	const char* queryStr,
	/// maximum time (ms) for the query execution, -1 means infinite
	long timeout
	)
{
	dpiConn * conn = ((GkOracleConnWrapper*)con)->m_conn;

	if (timeout > 0) {
		if (dpiConn_setCallTimeout(conn, timeout) < 0) {
    		PTRACE(2, "Failed to set statement timeout");
		}
	}

	dpiStmt *stmt = NULL;
	if (dpiConn_prepareStmt(conn, 0, queryStr, strlen(queryStr), NULL, 0, &stmt) < 0) {
    	PTRACE(2, "Failed to prepare statement: " << queryStr);
		GkSQLResult * result = new GkOracleResult(DPI_FAILURE, "Failed to prepare query");
		Disconnect();
		return result;
	}
	uint32_t numQueryColumns;
	if (dpiStmt_execute(stmt, 0, &numQueryColumns) < 0) {
    	PTRACE(2, GetName() << "\tFailed to execute statement: " << queryStr);
		GkSQLResult * result = new GkOracleResult(DPI_FAILURE, "Failed to execute query");
		Disconnect();
		return result;
	}
	// fetch all rows now, so we know the number of rows and cna release the statement handle right away
	vector<GkSQLResult::ResultRow*> * rows = new vector<GkSQLResult::ResultRow*>();
	while (true) {
		int found  = 0;
		uint32_t bufferRowIndex;
		if (dpiStmt_fetch(stmt, &found, &bufferRowIndex) < 0) {
			PTRACE(1, "Error fetching row");
			break;
		}
		if (!found)  // done
			break;

		GkSQLResult::ResultRow * row = new GkSQLResult::ResultRow(numQueryColumns);
		for (uint32_t i = 0; i < numQueryColumns; i++) {
			dpiNativeTypeNum nativeTypeNum = 0;
			dpiData * rawColValue = NULL;
			if (dpiStmt_getQueryValue(stmt, i + 1, &nativeTypeNum, &rawColValue) < 0) { // Oracle counts fields starting with 1
				PTRACE(1, "Error fetching column " << i);
				break;
			}
			PString strval;
			switch(nativeTypeNum) {
				case DPI_NATIVE_TYPE_INT64:
					strval = PString(rawColValue->value.asInt64);
					break;
				case DPI_NATIVE_TYPE_UINT64:
					strval = PString(rawColValue->value.asUint64);
					break;
				case DPI_NATIVE_TYPE_FLOAT:
					strval = psprintf("%f", rawColValue->value.asFloat);
					break;
				case DPI_NATIVE_TYPE_DOUBLE:
					strval = psprintf("%lf", rawColValue->value.asDouble);
					break;
				case DPI_NATIVE_TYPE_BYTES:
					strval = PString(rawColValue->value.asBytes.ptr, rawColValue->value.asBytes.length);
					break;
				case DPI_NATIVE_TYPE_BOOLEAN:
					strval = rawColValue->value.asBoolean ? "TRUE" : "FALSE";
					break;
				default:
					strval = "unsupported data type: " + PString(nativeTypeNum);
			}
			dpiQueryInfo queryInfo;
			if (dpiStmt_getQueryInfo(stmt, i + 1, &queryInfo) < 0) {
				PTRACE(1, "Error fetching column info " << i);
				break;
			}
			(*row)[i].first = strval;
			(*row)[i].second = queryInfo.name;
		}
		rows->push_back(row);
	}
	dpiStmt_release(stmt);
	PCaselessString sql(queryStr);
	if (rows->size() == 0 && (sql.Find("INSERT") != P_MAX_INDEX || sql.Find("UPDATE") != P_MAX_INDEX)) {
		delete rows;
    	return new GkOracleResult(1); // assume a working INSERT/UPDATE affected at least 1 row
	} else {
    	return new GkOracleResult(rows);
	}
}

namespace {
	GkSQLCreator<GkOracleConnection> OracleCreator("Oracle");
}

#endif // HAS_ORACLE
