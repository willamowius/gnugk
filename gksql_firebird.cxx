/*
 * gksql_firebird.cxx
 *
 * Firebird/Interbase driver module for GnuGk
 *
 * Copyright (c) 2006, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.12  2008/05/20 18:13:51  willamowius
 * more braces to avoid gcc 4.3.0 warnings
 *
 * Revision 1.11  2008/04/18 14:37:28  willamowius
 * never include gnugkbuildopts.h directly, always include config.h
 *
 * Revision 1.10  2008/04/18 13:14:11  shorne
 * Fixes for auto-configure on windows
 *
 * Revision 1.9  2008/04/02 22:32:22  willamowius
 * auto-reconnect on database errors
 *
 * Revision 1.8  2007/09/10 18:13:48  willamowius
 * clean up sql driver interface and remove unused methods from all drivers
 *
 * Revision 1.7  2007/09/10 11:17:21  willamowius
 * fix comment
 *
 * Revision 1.6  2007/08/15 09:43:14  zvision
 * Compilation error fixed
 *
 * Revision 1.5  2007/03/13 18:39:43  willamowius
 * compile fix for PWLib 1.11.3CVS
 *
 * Revision 1.4  2006/08/08 12:24:36  zvision
 * Escape quote characters in query strings
 *
 * Revision 1.3  2006/07/06 15:25:13  willamowius
 * set all deleted pointers to NULL (most probably more than needed)
 *
 * Revision 1.2  2006/06/08 07:38:42  willamowius
 * compile fixes for gcc 3.3.x
 *
 * Revision 1.1  2006/06/02 09:21:34  zvision
 * Firebird SQL driver
 *
 */

#include "config.h"

#if HAS_FIREBIRD

#if defined(_WIN32) && (_MSC_VER <= 1200)
#pragma warning(disable:4786) // warning about too long debug symbol off
#pragma warning(disable:4284)
#endif

#include <ptlib.h>
#include <cmath>
#include <ibase.h>
#include "gksql.h"

#ifdef _WIN32
#pragma comment( lib, FIREBIRD_LIBRARY )
#endif

namespace {
PString XSQLVARToPString(XSQLVAR *sqlvar)
{
	if (sqlvar->sqltype & 1)
		if (*(sqlvar->sqlind) == -1)
			return PString();

	switch (sqlvar->sqltype & ~1L) {
	case SQL_TEXT:
		return PString(sqlvar->sqldata, sqlvar->sqllen);
	case SQL_SHORT:
		return sqlvar->sqlscale < 0 
			? PString(PString::Decimal, *(int*)(sqlvar->sqldata) * pow(10.0, sqlvar->sqlscale), abs(sqlvar->sqlscale)) 
			: PString(*(short*)(sqlvar->sqldata));
	case SQL_LONG:
		return sqlvar->sqlscale < 0
			? PString(PString::Decimal, *(long*)(sqlvar->sqldata) * pow(10.0, sqlvar->sqlscale), abs(sqlvar->sqlscale)) 
			: PString(*(long*)(sqlvar->sqldata));
	case SQL_DOUBLE:
		return sqlvar->sqlscale < 0 
			? PString(PString::Decimal, *(double*)(sqlvar->sqldata) * pow(10.0, sqlvar->sqlscale), abs(sqlvar->sqlscale))
			: PString(PString::Printf, "%f", *(double*)(sqlvar->sqldata));
	case SQL_INT64:
		return sqlvar->sqlscale < 0 
			? PString(PString::Decimal, *(ISC_INT64*)(sqlvar->sqldata) * pow(10.0, sqlvar->sqlscale), abs(sqlvar->sqlscale))
			: PString(*(ISC_INT64*)(sqlvar->sqldata));
	case SQL_FLOAT:
		return PString(PString::Printf, "%f", (double)*(float*)(sqlvar->sqldata));
	case SQL_VARYING:
		return PString(sqlvar->sqldata + 2, *(short*)(sqlvar->sqldata));
	default:
		return PString();
	}
}
} // end of namespace

/** Class that encapsulates SQL query result for Firebird backend.
	It does not provide any multithread safety, so should be accessed
	from a single thread at time.
*/
class GkIBSQLResult : public GkSQLResult
{
public:
	/// Build the result from SELECT type query
	GkIBSQLResult(
		/// transaction handle
		isc_tr_handle tr,
		/// statement handle
		isc_stmt_handle stmt,
		/// SELECT type query result
		XSQLDA* selectResult
		);

	/// Build the empty	result and store query execution error information
	GkIBSQLResult(
		/// Firebird specific error code
		unsigned int errorCode,
		/// Firebird specific error message text
		const char* errorMsg,
		/// transaction handle
		isc_tr_handle tr = NULL,
		/// statement handle
		isc_stmt_handle stmt = NULL,
		/// SELECT type query result
		XSQLDA* selectResult = NULL
		);
	
	virtual ~GkIBSQLResult();
	
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
	GkIBSQLResult();
	GkIBSQLResult(const GkIBSQLResult&);
	GkIBSQLResult& operator=(const GkIBSQLResult&);
	
protected:
	/// query result for SELECT type queries
	XSQLDA* m_sqlResult;
	/// transaction handle
	isc_tr_handle m_tr;
	/// statement handle
	isc_stmt_handle m_stmt;
	/// the most recent row returned by fetch operation
	int m_sqlRow;
	/// Firebird specific error code (if the query failed)
	unsigned int m_errorCode;
	/// Firebird specific error message text (if the query failed)
	PString m_errorMessage;
};

/// Firebird/Interbase backend connection implementation.
class GkIBSQLConnection : public GkSQLConnection
{
public:
	/// Build a new Firebird connection object
	GkIBSQLConnection(
		/// name to use in the log
		const char* name = "Firebird"
		);
	
	virtual ~GkIBSQLConnection();

protected:
	class IBSQLConnWrapper : public GkSQLConnection::SQLConnWrapper
	{
	public:
		IBSQLConnWrapper(
			/// unique identifier for this connection
			int id,
			/// host:port this connection is made to
			const PString& host,
			/// Firebird connection object
			isc_db_handle conn
			) : SQLConnWrapper(id, host), m_conn(conn) {}

		virtual ~IBSQLConnWrapper();

	private:
		IBSQLConnWrapper();
		IBSQLConnWrapper(const IBSQLConnWrapper&);
		IBSQLConnWrapper& operator=(const IBSQLConnWrapper&);

	public:
		isc_db_handle m_conn;
	};

	/** Create a new SQL connection using parameters stored in this object.
	    When the connection is to be closed, the object is simply deleted
	    using delete operator.
	    
	    @return
	    NULL if database connection could not be established 
	    or an object of IBSQLConnWrapper class.
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
	GkIBSQLConnection(const GkIBSQLConnection&);
	GkIBSQLConnection& operator=(const GkIBSQLConnection&);
};


GkIBSQLResult::GkIBSQLResult(
	/// transaction handle
	isc_tr_handle tr,
	/// statement handle
	isc_stmt_handle stmt,
	/// SELECT type query result
	XSQLDA* selectResult
	) 
	: GkSQLResult(false), m_sqlResult(selectResult), m_tr(tr), m_stmt(stmt), m_sqlRow(-1),
	m_errorCode(0)
{
	if (m_sqlResult != NULL) {
		m_numRows = 100000;
		m_numFields = m_sqlResult->sqld;
		for (int i = 0; i < m_sqlResult->sqld; ++i) {
			m_sqlResult->sqlvar[i].sqlind = new short;
			if ((m_sqlResult->sqlvar[i].sqltype & ~1L) == SQL_VARYING)
				m_sqlResult->sqlvar[i].sqldata = new char[m_sqlResult->sqlvar[i].sqllen + 2];
			else
				m_sqlResult->sqlvar[i].sqldata = new char[m_sqlResult->sqlvar[i].sqllen];
		}
	} else
		m_queryError = true;
}

GkIBSQLResult::GkIBSQLResult(
	/// Firebird specific error code
	unsigned int errorCode,
	/// Firebird specific error message text
	const char* errorMsg,
	/// transaction handle
	isc_tr_handle tr,
	/// statement handle
	isc_stmt_handle stmt,
	/// SELECT type query result
	XSQLDA* selectResult
	) 
	: GkSQLResult(true), m_sqlResult(selectResult), m_tr(tr), m_stmt(stmt), m_sqlRow(-1),
	m_errorCode(errorCode), m_errorMessage(errorMsg)
{
}

GkIBSQLResult::~GkIBSQLResult()
{
	ISC_STATUS status[20];
	
	if (m_stmt != NULL)
		isc_dsql_free_statement(status, &m_stmt, DSQL_drop);
	if (m_sqlResult != NULL) {
		for (int i = 0; i < m_sqlResult->sqld; ++i) {
			if (m_sqlResult->sqlvar[i].sqldata != NULL) {
				delete [] m_sqlResult->sqlvar[i].sqldata;
				m_sqlResult->sqlvar[i].sqldata = NULL;
			}
			if (m_sqlResult->sqlvar[i].sqlind != NULL) {
				delete m_sqlResult->sqlvar[i].sqlind;
				m_sqlResult->sqlvar[i].sqlind = NULL;
			}
		}
		delete [] reinterpret_cast<char*>(m_sqlResult);
		m_sqlResult = NULL;
	}
	if (m_tr != NULL) {
		if (m_queryError) {
			isc_rollback_transaction(status, &m_tr);
		} else {
			isc_commit_transaction(status, &m_tr);
		}
	}
}

PString GkIBSQLResult::GetErrorMessage()
{
	return m_errorMessage;
}
	
long GkIBSQLResult::GetErrorCode()
{
	return m_errorCode;
}

bool GkIBSQLResult::FetchRow(
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
	
	ISC_STATUS retval;
	ISC_STATUS status[20];	
	retval = isc_dsql_fetch(status, &m_stmt, 1, m_sqlResult);
	if (status[0] == 1 && status[1] != 0) {
		m_numRows = m_sqlRow;
		if (retval != 100) {
			long errcode = isc_sqlcode(status);
			char errormsg[512];
			if (errcode == -999) {
				errcode = status[1];
				long *pvector = status;
				// TODO: replace all isc_interprete() with fb_interpret()
				errormsg[isc_interprete(errormsg, &pvector)] = 0;
			} else {
				strcpy(errormsg, "SQL:");
				isc_sql_interprete(static_cast<short>(errcode), errormsg + 4, 512 - 4); 
			}
			PTRACE(2, "Firebird\tFailed to fetch query row (" << errcode
				<< "): " << errormsg
				);
		}
		return false;
	}
		
	result.SetSize(m_sqlResult->sqld);
	
	for (PINDEX i = 0; i < m_sqlResult->sqld; ++i)
		result[i] = XSQLVARToPString(&(m_sqlResult->sqlvar[i]));
	
	m_sqlRow++;
	
	return true;
}

bool GkIBSQLResult::FetchRow(
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
	ISC_STATUS retval;	
	ISC_STATUS status[20];	
	retval = isc_dsql_fetch(status, &m_stmt, 1, m_sqlResult);
	if (status[0] == 1 && status[1] != 0) {
		m_numRows = m_sqlRow;
		if (retval != 100) {
			long errcode = isc_sqlcode(status);
			char errormsg[512];
			if (errcode == -999) {
				errcode = status[1];
				long *pvector = status;
				errormsg[isc_interprete(errormsg, &pvector)] = 0;
			} else {
				strcpy(errormsg, "SQL:");
				isc_sql_interprete(static_cast<short>(errcode), errormsg + 4, 512 - 4); 
			}
			PTRACE(2, "Firebird\tFailed to fetch query row (" << errcode
				<< "): " << errormsg
				);
		}
		return false;
	}

	result.resize(m_numFields);
	
	for (PINDEX i = 0; i < m_numFields; i++) {
		result[i].first = XSQLVARToPString(&(m_sqlResult->sqlvar[i]));
		result[i].second = PString(m_sqlResult->sqlvar[i].aliasname, m_sqlResult->sqlvar[i].aliasname_length);
	}
	
	m_sqlRow++;
	
	return true;
}


GkIBSQLConnection::GkIBSQLConnection(
	/// name to use in the log
	const char* name
	) : GkSQLConnection(name)
{
}
	
GkIBSQLConnection::~GkIBSQLConnection()
{
}

GkIBSQLConnection::IBSQLConnWrapper::~IBSQLConnWrapper()
{
	ISC_STATUS status[20];
	isc_detach_database(status, &m_conn);
}

GkSQLConnection::SQLConnPtr GkIBSQLConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	unsigned dpb_offset = 0;
	std::vector<char> dpb(1);
	
	dpb[dpb_offset++] = isc_dpb_version1;
	
	if (!m_username) {
		dpb.resize(dpb.size() + 2 + m_username.GetLength());
		dpb[dpb_offset++] = isc_dpb_user_name;
		dpb[dpb_offset++] = m_username.GetLength();
		memcpy(&(dpb[dpb_offset]), (const char*)m_username, m_username.GetLength());
		dpb_offset += m_username.GetLength();
	}

	if (!m_password) {	
		dpb.resize(dpb.size() + 2 + m_password.GetLength());
		dpb[dpb_offset++] = isc_dpb_password;
		dpb[dpb_offset++] = m_password.GetLength();
		memcpy(&(dpb[dpb_offset]), (const char*)m_password, m_password.GetLength());
		dpb_offset += m_password.GetLength();
	}
	
	ISC_STATUS status[20];
	isc_db_handle conn = NULL;
	std::string dbname((const char*)m_database);
	
	if (!m_host) {
		dbname.insert(0, ":");
		dbname.insert(0, (const char *)m_host);
	}
	
	isc_attach_database(status, 0, const_cast<char*>(dbname.c_str()), &conn, dpb_offset, &(dpb[0]));
	if (status[0] == 1 && status[1] != 0) {
		long *pvector = status;
		char errormsg[512];
		errormsg[isc_interprete(errormsg, &pvector)] = 0;
		PTRACE(2, GetName() << "\tFirebird connection to " << m_username << '@' << dbname 
			<< " failed (isc_attach_database failed): " << errormsg
			);
		return NULL;
	}	
	
	PTRACE(5, GetName() << "\tFirebird connection to " << m_username << '@' << dbname
		<< " established successfully"
		);
	return new IBSQLConnWrapper(id, dbname, conn);
}

GkSQLResult* GkIBSQLConnection::ExecuteQuery(
	/// SQL connection to use for query execution
	GkSQLConnection::SQLConnPtr con,
	/// query string
	const char* queryStr,
	/// maximum time (ms) for the query execution, -1 means infinite
	long /*timeout*/
	)
{
	isc_db_handle conn = ((IBSQLConnWrapper*)con)->m_conn;

	char errormsg[512];
	ISC_STATUS status[20];
	isc_tr_handle tr = NULL;
	isc_stmt_handle stmt = NULL;
	
	isc_start_transaction(status, &tr, 1, &conn, 0, NULL);
	if (status[0] == 1 && status[1] != 0) {
		long *pvector = status;
		char errormsg[512];
		errormsg[isc_interprete(errormsg, &pvector)] = 0;
		return new GkIBSQLResult(status[1], errormsg);
	}
	
	isc_dsql_allocate_statement(status, &conn, &stmt);
	if (status[0] == 1 && status[1] != 0) {
		long errorcode = isc_sqlcode(status);
		if (errorcode == -999) {
			errorcode = status[1];
			long *pvector = status;
			errormsg[isc_interprete(errormsg, &pvector)] = 0;
		} else {
			strcpy(errormsg, "SQL:");
			isc_sql_interprete(static_cast<short>(errorcode), errormsg, 512 - 4);
		}
		Disconnect();
		return new GkIBSQLResult(errorcode, errormsg, tr);
	}

	int numcols = 1;
	XSQLDA *result = reinterpret_cast<XSQLDA*>(new char[XSQLDA_LENGTH(numcols)]);
	memset(result, 0, XSQLDA_LENGTH(numcols));
	result->version = SQLDA_VERSION1;
	result->sqln = numcols;
	
	isc_dsql_prepare(status, &tr, &stmt, 0, const_cast<char*>(queryStr), SQL_DIALECT_CURRENT, result);
	if (status[0] == 1 && status[1] != 0) {
		long errorcode = isc_sqlcode(status);
		if (errorcode == -999) {
			errorcode = status[1];
			long *pvector = status;
			errormsg[isc_interprete(errormsg, &pvector)] = 0;
		} else {
			strcpy(errormsg, "SQL:");
			isc_sql_interprete(static_cast<short>(errorcode), errormsg, 512 - 4);
		}
		Disconnect();
		return new GkIBSQLResult(errorcode, errormsg, tr, stmt);
	}
	
	if (result->sqld > result->sqln) {
		numcols = result->sqld;
		delete [] reinterpret_cast<char*>(result);
		result = reinterpret_cast<XSQLDA*>(new char[XSQLDA_LENGTH(numcols)]);
		memset(result, 0, XSQLDA_LENGTH(numcols));
		result->version = SQLDA_VERSION1;
		result->sqln = numcols;
	
		isc_dsql_describe(status, &stmt, SQLDA_VERSION1, result);
		if (status[0] == 1 && status[1] != 0) {
			long errorcode = isc_sqlcode(status);
			if (errorcode == -999) {
				errorcode = status[1];
				long *pvector = status;
				errormsg[isc_interprete(errormsg, &pvector)] = 0;
			} else {
				strcpy(errormsg, "SQL:");
				isc_sql_interprete(static_cast<short>(errorcode), errormsg, 512 - 4);
			}
			delete [] reinterpret_cast<char*>(result);
			result = NULL;
			Disconnect();
			return new GkIBSQLResult(errorcode, errormsg, tr, stmt);
		}
	}

	isc_dsql_execute(status, &tr, &stmt, SQLDA_VERSION1, NULL);
	if (status[0] == 1 && status[1] != 0) {
		long errorcode = isc_sqlcode(status);
		if (errorcode == -999) {
			errorcode = status[1];
			long *pvector = status;
			errormsg[isc_interprete(errormsg, &pvector)] = 0;
		} else {
			strcpy(errormsg, "SQL:");
			isc_sql_interprete(static_cast<short>(errorcode), errormsg, 512 - 4);
		}
		delete [] reinterpret_cast<char*>(result);
		result = NULL;
		Disconnect();
		return new GkIBSQLResult(errorcode, errormsg, tr, stmt);
	}

	return new GkIBSQLResult(tr, stmt, result);
}

PString GkIBSQLConnection::EscapeString(
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
	GkSQLCreator<GkIBSQLConnection> IBSQLCreator("Firebird");
}

#endif /* HAS_FIREBIRD */
