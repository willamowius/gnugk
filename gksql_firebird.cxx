/*
 * gksql_firebird.cxx
 *
 * Firebird/Interbase driver module for GnuGk
 *
 * Copyright (c) 2006, Michal Zygmuntowicz
 * Copyright (c) 2006-2012, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"

#if HAS_FIREBIRD

#include <ptlib.h>
#include <cmath>
#include <ibase.h>
#include "gksql.h"

const unsigned int FB_BUFF_SIZE = 2048;

static PDynaLink g_sharedLibrary;
static ISC_LONG (ISC_EXPORT *g_fb_interpret)(ISC_SCHAR*, unsigned int, const ISC_STATUS**) = NULL;
static ISC_STATUS (ISC_EXPORT *g_isc_attach_database)(ISC_STATUS*,
                                          short,
                                          const ISC_SCHAR*,
                                          isc_db_handle*,
                                          short,
                                          const ISC_SCHAR*) = NULL;
static ISC_STATUS (ISC_EXPORT *g_isc_commit_transaction)(ISC_STATUS *, isc_tr_handle *) = NULL;
static ISC_STATUS (ISC_EXPORT *g_isc_detach_database)(ISC_STATUS *, isc_db_handle *) = NULL;
static ISC_STATUS (ISC_EXPORT *g_isc_dsql_allocate_statement)(ISC_STATUS *,
                                                  isc_db_handle *,
                                                  isc_stmt_handle *) = NULL;
static ISC_STATUS (ISC_EXPORT *g_isc_dsql_describe)(ISC_STATUS *,
                                        isc_stmt_handle *,
                                        unsigned short,
                                        XSQLDA *) = NULL;
static ISC_STATUS (ISC_EXPORT *g_isc_dsql_execute)(ISC_STATUS*,
                                       isc_tr_handle*,
                                       isc_stmt_handle*,
                                       unsigned short,
                                       XSQLDA*) = NULL;
static ISC_STATUS (ISC_EXPORT *g_isc_dsql_fetch)(ISC_STATUS *,
                                     isc_stmt_handle *,
                                     unsigned short,
                                     XSQLDA *) = NULL;
static ISC_STATUS (ISC_EXPORT *g_isc_dsql_free_statement)(ISC_STATUS *, isc_stmt_handle *, unsigned short) = NULL;
static	ISC_STATUS (ISC_EXPORT *g_isc_dsql_prepare)(ISC_STATUS*,
                                       isc_tr_handle*,
                                       isc_stmt_handle*,
                                       unsigned short,
                                       const ISC_SCHAR*,
                                       unsigned short,
                                       XSQLDA*) = NULL;
static ISC_STATUS (ISC_EXPORT *g_isc_rollback_transaction)(ISC_STATUS *, isc_tr_handle *) = NULL;
static ISC_LONG (ISC_EXPORT *g_isc_sqlcode)(const ISC_STATUS*) = NULL;
static void (ISC_EXPORT *g_isc_sql_interprete)(short, ISC_SCHAR*, short) = NULL;
static ISC_STATUS (ISC_EXPORT_VARARG *g_isc_start_transaction)(ISC_STATUS *,
                                                   isc_tr_handle *,
                                                   short, ...) = NULL;

namespace {

PString XSQLVARToPString(XSQLVAR *sqlvar)
{
	if (sqlvar->sqltype & 1)
		if (*(sqlvar->sqlind) == -1)
			return PString::Empty();

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
		return PString::Empty();
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
		isc_tr_handle tr = 0L,
		/// statement handle
		isc_stmt_handle stmt = 0L,
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
	
	if (m_stmt != 0L)
		(*g_isc_dsql_free_statement)(status, &m_stmt, DSQL_drop);
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
	if (m_tr != 0L) {
		if (m_queryError) {
			(*g_isc_rollback_transaction)(status, &m_tr);
		} else {
			(*g_isc_commit_transaction)(status, &m_tr);
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
	retval = (*g_isc_dsql_fetch)(status, &m_stmt, 1, m_sqlResult);
	if (status[0] == 1 && status[1] != 0) {
		m_numRows = m_sqlRow;
		if (retval != 100) {
			long errcode = (*g_isc_sqlcode)(status);
			char errormsg[FB_BUFF_SIZE];
			if (errcode == -999) {
				errcode = status[1];
				const ISC_STATUS *pvector = status;
				(*g_fb_interpret)(errormsg, FB_BUFF_SIZE, &pvector);	// fetch first error message only
			} else {
				(*g_isc_sql_interprete)(static_cast<short>(errcode), errormsg, FB_BUFF_SIZE); 
			}
			PTRACE(2, "Firebird\tFailed to fetch query row (" << errcode
				<< "): SQL:" << errormsg);
			SNMP_TRAP(5, SNMPError, Database, "Firebird query failed");
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
	retval = (*g_isc_dsql_fetch)(status, &m_stmt, 1, m_sqlResult);
	if (status[0] == 1 && status[1] != 0) {
		m_numRows = m_sqlRow;
		if (retval != 100) {
			long errcode = (*g_isc_sqlcode)(status);
			char errormsg[FB_BUFF_SIZE];
			if (errcode == -999) {
				errcode = status[1];
				const ISC_STATUS *pvector = status;
				(*g_fb_interpret)(errormsg, FB_BUFF_SIZE, &pvector);	// fetch first error message only
			} else {
				(*g_isc_sql_interprete)(static_cast<short>(errcode), errormsg, FB_BUFF_SIZE); 
			}
			PTRACE(2, "Firebird\tFailed to fetch query row (" << errcode
				<< "): SQL:" << errormsg);
			SNMP_TRAP(5, SNMPError, Database, "Firebird query failed");
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
	const char * name
	) : GkSQLConnection(name)
{
}
	
GkIBSQLConnection::~GkIBSQLConnection()
{
}

GkIBSQLConnection::IBSQLConnWrapper::~IBSQLConnWrapper()
{
	ISC_STATUS status[20];
	(*g_isc_detach_database)(status, &m_conn);
}

GkSQLConnection::SQLConnPtr GkIBSQLConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	if (!g_sharedLibrary.IsLoaded()) {
		if (m_library.IsEmpty()) {
#ifdef _WIN32
			m_library = "fbclient" + g_sharedLibrary.GetExtension();
#else
			m_library = "libfbclient" + g_sharedLibrary.GetExtension();
#endif
		}

		if (!g_sharedLibrary.Open(m_library)) {
			PTRACE (1, GetName() << "\tCan't load library " << m_library);
			return NULL;
		}

		if (!g_sharedLibrary.GetFunction("fb_interpret", (PDynaLink::Function &)g_fb_interpret)
			|| !g_sharedLibrary.GetFunction("isc_attach_database", (PDynaLink::Function &)g_isc_attach_database)
			|| !g_sharedLibrary.GetFunction("isc_commit_transaction", (PDynaLink::Function &)g_isc_commit_transaction)
			|| !g_sharedLibrary.GetFunction("isc_detach_database", (PDynaLink::Function &)g_isc_detach_database)
			|| !g_sharedLibrary.GetFunction("isc_dsql_allocate_statement", (PDynaLink::Function &)g_isc_dsql_allocate_statement)
			|| !g_sharedLibrary.GetFunction("isc_dsql_describe", (PDynaLink::Function &)g_isc_dsql_describe)
			|| !g_sharedLibrary.GetFunction("isc_dsql_execute", (PDynaLink::Function &)g_isc_dsql_execute)
			|| !g_sharedLibrary.GetFunction("isc_dsql_fetch", (PDynaLink::Function &)g_isc_dsql_fetch)
			|| !g_sharedLibrary.GetFunction("isc_dsql_free_statement", (PDynaLink::Function &)g_isc_dsql_free_statement)
			|| !g_sharedLibrary.GetFunction("isc_dsql_prepare", (PDynaLink::Function &)g_isc_dsql_prepare)
			|| !g_sharedLibrary.GetFunction("isc_rollback_transaction", (PDynaLink::Function &)g_isc_rollback_transaction)
			|| !g_sharedLibrary.GetFunction("isc_sqlcode", (PDynaLink::Function &)g_isc_sqlcode)
			|| !g_sharedLibrary.GetFunction("isc_sql_interprete", (PDynaLink::Function &)g_isc_sql_interprete)
			|| !g_sharedLibrary.GetFunction("isc_start_transaction", (PDynaLink::Function &)g_isc_start_transaction)
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
	isc_db_handle conn = 0L;
	std::string dbname((const char*)m_database);
	
	if (!m_host) {
		dbname.insert(0, ":");
		dbname.insert(0, (const char *)m_host);
	}
	
	(*g_isc_attach_database)(status, 0, const_cast<char*>(dbname.c_str()), &conn, dpb_offset, &(dpb[0]));
	if (status[0] == 1 && status[1] != 0) {
		char errormsg[FB_BUFF_SIZE];
  		const ISC_STATUS *pvector = status;
		(*g_fb_interpret)(errormsg, FB_BUFF_SIZE, &pvector);	// fetch first error message only
		PTRACE(2, GetName() << "\tFirebird connection to " << m_username << '@' << dbname 
			<< " failed (isc_attach_database failed): " << errormsg);
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed");
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

	char errormsg[FB_BUFF_SIZE];
	ISC_STATUS status[20];
	isc_tr_handle tr = 0L;
	isc_stmt_handle stmt = 0L;
	
	(*g_isc_start_transaction)(status, &tr, 1, &conn, 0, NULL);
	if (status[0] == 1 && status[1] != 0) {
		char errormsg[FB_BUFF_SIZE];
		const ISC_STATUS *pvector = status;
		(*g_fb_interpret)(errormsg, FB_BUFF_SIZE, &pvector);	// fetch first error message only
		return new GkIBSQLResult(status[1], errormsg);
	}
	
	(*g_isc_dsql_allocate_statement)(status, &conn, &stmt);
	if (status[0] == 1 && status[1] != 0) {
		long errorcode = (*g_isc_sqlcode)(status);
		if (errorcode == -999) {
			errorcode = status[1];
			const ISC_STATUS *pvector = status;
			(*g_fb_interpret)(errormsg, FB_BUFF_SIZE, &pvector);	// fetch first error message only
		} else {
			(*g_isc_sql_interprete)(static_cast<short>(errorcode), errormsg, FB_BUFF_SIZE);
		}
		Disconnect();
		return new GkIBSQLResult(errorcode, errormsg, tr);
	}

	int numcols = 1;
	XSQLDA *result = reinterpret_cast<XSQLDA*>(new char[XSQLDA_LENGTH(numcols)]);
	memset(result, 0, XSQLDA_LENGTH(numcols));
	result->version = SQLDA_VERSION1;
	result->sqln = numcols;
	
	(*g_isc_dsql_prepare)(status, &tr, &stmt, 0, const_cast<char*>(queryStr), SQL_DIALECT_CURRENT, result);
	if (status[0] == 1 && status[1] != 0) {
		long errorcode = (*g_isc_sqlcode)(status);
		if (errorcode == -999) {
			errorcode = status[1];
			const ISC_STATUS *pvector = status;
			(*g_fb_interpret)(errormsg, FB_BUFF_SIZE, &pvector);	// fetch first error message only
		} else {
			(*g_isc_sql_interprete)(static_cast<short>(errorcode), errormsg, FB_BUFF_SIZE);
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
	
		(*g_isc_dsql_describe)(status, &stmt, SQLDA_VERSION1, result);
		if (status[0] == 1 && status[1] != 0) {
			long errorcode = (*g_isc_sqlcode)(status);
			if (errorcode == -999) {
				errorcode = status[1];
				const ISC_STATUS *pvector = status;
				(*g_fb_interpret)(errormsg, FB_BUFF_SIZE, &pvector);	// fetch first error message only
			} else {
				(*g_isc_sql_interprete)(static_cast<short>(errorcode), errormsg, FB_BUFF_SIZE);
			}
			delete [] reinterpret_cast<char*>(result);
			result = NULL;
			Disconnect();
			return new GkIBSQLResult(errorcode, errormsg, tr, stmt);
		}
	}

	(*g_isc_dsql_execute)(status, &tr, &stmt, SQLDA_VERSION1, NULL);
	if (status[0] == 1 && status[1] != 0) {
		long errorcode = (*g_isc_sqlcode)(status);
		if (errorcode == -999) {
			errorcode = status[1];
			const ISC_STATUS *pvector = status;
			(*g_fb_interpret)(errormsg, FB_BUFF_SIZE, &pvector);	// fetch first error message only
		} else {
			(*g_isc_sql_interprete)(static_cast<short>(errorcode), errormsg, FB_BUFF_SIZE);
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
