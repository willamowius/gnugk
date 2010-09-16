/*
 * gksql.h
 *
 * Generic interface to access SQL databases
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.18  2009/07/16 12:48:40  willamowius
 * remove unused code
 *
 * Revision 1.17  2009/05/24 20:48:26  willamowius
 * remove hacks for VC6 which isn't supported any more since quite a while
 *
 * Revision 1.16  2009/02/09 13:25:59  willamowius
 * typo in comment
 *
 * Revision 1.15  2008/09/05 13:44:14  zvision
 * GetInfo implemented for SQL acct/auth modules
 *
 * Revision 1.14  2008/09/04 08:19:04  zvision
 * SQL reconnect thread safety fixes
 *
 * Revision 1.13  2008/04/03 10:24:20  willamowius
 * new header config.h for configuration details
 *
 * Revision 1.12  2008/04/02 22:32:22  willamowius
 * auto-reconnect on database errors
 *
 * Revision 1.11  2007/09/10 18:13:48  willamowius
 * clean up sql driver interface and remove unused methods from all drivers
 *
 * Revision 1.10  2006/04/30 09:22:56  willamowius
 * PTimedMutex patch for PWLib >= 1.9.2
 *
 * Revision 1.9  2006/04/14 13:56:19  willamowius
 * call failover code merged
 *
 * Revision 1.1.1.1  2005/11/21 20:19:59  willamowius
 *
 *
 * Revision 1.4  2005/11/15 19:52:56  jan
 * Michal v1 (works, but on in routed, not proxy mode)
 *
 * Revision 1.8  2005/04/24 16:39:44  zvision
 * MSVC6.0 compatibility fixed
 *
 * Revision 1.7  2005/02/11 17:23:05  zvision
 * Write SCCS keyword correctly
 *
 * Revision 1.6  2005/01/16 15:22:35  zvision
 * Database Host parameter accepts only one host now
 *
 * Revision 1.5  2004/12/15 13:41:33  zvision
 * Reconnect to the database, if the initial attempt failed. Thanks to Mikko Oilinki
 *
 * Revision 1.4  2004/08/02 10:52:07  zvision
 * Ability to extract column names from a result set
 *
 * Revision 1.3  2004/07/09 22:11:36  zvision
 * SQLAcct module ported from 2.0 branch
 *
 */
#ifndef GKSQL_H
#define GKSQL_H "@(#) $Id$"

#include <list>
#include <map>
#include <vector>
#include "name.h"
#include "factory.h"
#include "config.h"

/** Abstract base class that encapsulates SQL query result.
    Backend specific operations are performed by derived classes.
*/
class GkSQLResult
{
protected:
	GkSQLResult(
		/// true if the query failed and no result is available
		bool queryError = false
		) : m_numRows(0), m_numFields(0),
			m_queryError(queryError) {}

public:
	/// the first element of the pair is a field value and the second 
	/// is a field name
	typedef std::vector< std::pair<PString, PString> > ResultRow;
	
	virtual ~GkSQLResult();
	
	/** @return
	    True if the query succeeded and the result is available.
	    Otherwise only GetErrorMessage and GetErrorCode member functions
	    are meaningful.
	*/
	bool IsValid() const { return !m_queryError; }
	
	/** @return
	    Number of rows in the result set (to be fetched) for SELECT-like
	    query, or number of rows affected for INSERT, UPDATE or DELETE query.
	*/
	long GetNumRows() const { return m_numRows; }
	
	/** @return
	    Number of columns in the result set rows for SELECT-like query.
	*/
	long GetNumFields() const { return m_numFields; }

	/** @return
	    Backend specific error message, if the query failed.
	*/	
	virtual PString GetErrorMessage() = 0;
	
	/** @return
	    Backend specific error code, if the query failed.
	*/	
	virtual long GetErrorCode() = 0;
	
	/** Fetch a single row from the result set. After each row is fetched,
	    cursor position is moved to a next row.
		
	    @return
	    True if the row has been fetched, false if no more rows are available.
	*/
	virtual bool FetchRow(
		/// array to be filled with string representations of the row fields
		PStringArray& result
		) = 0;
	virtual bool FetchRow(
		/// array to be filled with string representations of the row fields
		ResultRow& result
		) = 0;
			
private:
	GkSQLResult(const GkSQLResult&);
	GkSQLResult& operator=(const GkSQLResult&);
	
protected:
	/// number of rows in the result set or rows affected by the query
	long m_numRows;
	/// number of columns in each row in the result set
	long m_numFields;
	/// true if query execution failed
	bool m_queryError;
};

/** Abstract class that provides generic access to SQL backend.
    Can provide a single SQL connection or maintain a pool of SQL connections.
    Thread safe.

    NOTE: Currently it implements only fixed SQL connections pool size,
    so only minPoolSize parameter is examined.
*/
class GkSQLConnection : public NamedObject
{
public:
	struct Info {
		bool m_connected;
		unsigned m_idleConnections;
		unsigned m_busyConnections;
		unsigned m_waitingRequests;
		int m_minPoolSize;
		int m_maxPoolSize;
	};
	
	GkSQLConnection(
		/// name to use in the log
		const char* name = "SQL"
	);

	virtual ~GkSQLConnection();

	/** Create an instance of a GkSQLConnection derived class,
	    that implements access to a specific SQL backend. The class to be created
	    is found by searching a global factory list for #driverName# entry.
	*/
	static GkSQLConnection* Create(
		/// driver name for the connection object
		const char* driverName,
		/// name for the connection to use in the log file
		const char* connectionName
		);

	/** Read SQL settings from the config and connect to the database.
	    Derived classes do not have to override this member function.
				
	    @return
	    True if settings have been read and connections have been established.
	*/
	virtual bool Initialize(
		/// config to be read
		PConfig* cfg,
		/// name of the config section with SQL settings
		const char* cfgSectionName
		);

	/** Execute the query and return the result set. It uses first idle SQL
	    connection or waits for an idle SQL connection, if all connections 
	    are busy with query execution. Pool size defines how many concurrent
	    queries can be executed by this object.
		The query can be parametrized and the parameters are replaced with
		strings from the #queryParams# list. Usage:
			SELECT name, surname FROM people WHERE name = '%1' and age > %2
		Use double %% to embed % and %{1} notation to allow strings like %{1}123.

	    @return
	    Query execution result (no matters the query failed or succeeded) 
	    or NULL if timed out waiting for an idle SQL connection.
	*/
	GkSQLResult* ExecuteQuery(
		/// query to be executed
		const char* queryStr,
		/// query parameters (%1, %2, ... notation), NULL if the query 
		/// does not take any parameters
		const PStringArray* queryParams = NULL,
		/// time (ms) to wait for an idle connection, -1 means infinite
		long timeout = -1
		);

	/** Execute the query and return the result set. It uses first idle SQL
	    connection or waits for an idle SQL connection, if all connections 
	    are busy with query execution. Pool size defines how many concurrent
	    queries can be executed by this object.
	    The query can be parametrized and the parameters are replaced with
	    strings from the #queryParams# list. Usage:
	    	SELECT name, surname FROM people WHERE name = '%{Name}' and age > %a
	    The parameter names can be a one letter (%a, for example) or whole
	    strings (%{Name}, for example).

	    @return
	    Query execution result (no matters the query failed or succeeded) 
	    or NULL if timed out waiting for an idle SQL connection.
	*/
	GkSQLResult* ExecuteQuery(
		/// query to be executed
		const char* queryStr,
		/// query parameters (name => value associations)
		const std::map<PString, PString>& queryParams,
		/// time (ms) to wait for an idle connection, -1 means infinite
		long timeout = -1
		);

	/// Get information about SQL connection state
	void GetInfo(
		Info &info /// filled with SQL connection state information upon return
		);
		
protected:
	/** Generic SQL database connection object - should be extended 
	    by derived classes to include backed specific connection data.
	*/
	class SQLConnWrapper
	{
	public:
		SQLConnWrapper(
			/// unique identifier for this connection
			int id,
			/// host:port this connection is made to
			const PString& host
			) : m_id(id), m_host(host) {}

		virtual ~SQLConnWrapper();

	private:
		SQLConnWrapper();
		SQLConnWrapper(const SQLConnWrapper&);
		SQLConnWrapper& operator=(const SQLConnWrapper&);

	public:
		/// unique identifier for this connection
		int m_id;
		/// host:port this connection is made to
		PString m_host;
	};
	typedef SQLConnWrapper* SQLConnPtr;

protected:
	/** Create a new SQL connection using parameters stored in this object.
	    When the connection is to be closed, the object is simply deleted
	    using delete operator.
	    
	    @return
	    NULL if database connection could not be established 
	    or an object derived from SQLConnWrapper class.
	*/
	virtual SQLConnPtr CreateNewConnection(
		/// unique identifier for this connection
		int id
		) = 0;
	
	/** Get the first idle connection from the pool and set connptr	variable
	    to point to this connection. IMPORTANT: After connection is successfully
	    acquired, ReleaseSQLConnection has to be called to return back 
	    the connection to the pool.
		
	    @return
	    True if the connection has been acquired, false if it is not available
	    (timeout, network connection lost, ...).
	*/
	bool AcquireSQLConnection(
		SQLConnPtr& connptr, /// variable to hold connection pointer (handle)
		long timeout /// timeout (ms) to wait for an idle connection
		);

	/** Return previously acquired connection back to the pool. It is important
	    that the reference references the same variable as when calling
	    AcquireSQLConnection.
	*/
	void ReleaseSQLConnection(
		SQLConnPtr& connptr, /// connection to release (mark as idle)
		bool deleteFromPool = false /// true to delete the connection (a broken connection)
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
		) = 0;

	/** Replace query parameters placeholders (%1, %2, ...) with actual values
		and escape parameter strings.
		Derived classes do not need to override this function, unless want to
		perform some custom parameter processing.

		@return
		New query string with all parameters replaced.
	*/
	virtual PString ReplaceQueryParams(
		/// SQL connection to get escape parameters from
		SQLConnPtr conn,
		/// parametrized query string
		const char* queryStr,
		/// parameter values
		const PStringArray& queryParams
		);

	/** Replace query parameters placeholders (%a, %{Name}, ...) with 
	    actual values and escape parameter strings. Derived classes do not need 
	    to override this function, unless want to perform some custom parameter 
	    processing.

	    @return
	    New query string with all parameters replaced.
	*/
	virtual PString ReplaceQueryParams(
		/// SQL connection to get escape parameters from
		SQLConnPtr conn,
		/// parametrized query string
		const char* queryStr,
		/// parameter name => value associations
		const std::map<PString, PString>& queryParams
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
		) = 0;

	/// Retrieve hostname (IP or DNS) and optional port number (separated by ':') from the string
	void GetHostAndPort(
		/// string to be examined
		const PString& str,
		/// set to the host name
		PString& host,
		/// set to the port number or 0, if no port is given
		WORD& port
		);

private:
	GkSQLConnection(const GkSQLConnection&);
	GkSQLConnection& operator=(const GkSQLConnection&);

	/** Creates m_minPoolSize initial database connections.
	    Called from Initialize.
		
	    @return
	    True if at least one database connection has been established.
	*/
	bool Connect();

protected:
	/** Disconnect connection pool from DB on connection error
	*/
	void Disconnect();
	
	/// filled with the actual host from m_hosts the database connection is made to
	PString m_host;
	/// database port to connect to
	WORD m_port;
	/// database name
	PString m_database;
	/// database username to connect as
	PString m_username;
	/// password associated with the username (if any)
	PString m_password;
	/// name of shared library
	PString m_library;

private:
	/// iterator typedefs for convenience
	typedef std::list<SQLConnPtr>::iterator iterator;
	typedef std::list<SQLConnPtr>::const_iterator const_iterator;
	typedef std::list<SQLConnPtr*>::iterator witerator;
	typedef std::list<SQLConnPtr*>::const_iterator const_witerator;

	/// minimum number of SQL connections active
	int m_minPoolSize;
	/// maximum number of SQL connections active
	int m_maxPoolSize;
	/// list of idle SQL connections
	std::list<SQLConnPtr> m_idleConnections;
	/// list of connections busy with query execution
	std::list<SQLConnPtr> m_busyConnections;
	/// FIFO queue of queries waiting to be executed when there is no idle connections
	std::list<SQLConnPtr*> m_waitingRequests;
	/// mutual access to the lists
	PTimedMutex m_connectionsMutex;
	/// signalled when a connections moves from the busy to the idle list
	PSyncPoint m_connectionAvailable;
	/// set to true when destructor is being invoked
	bool m_destroying;
	/// remain false while connection to the database not yet established
	/// reset to false on disconnect or error during operation -> reconnect
	bool m_connected;
};

typedef Factory<GkSQLConnection>::Creator1<const char*> SQLCreator1;
template<class SQLDriver>
struct GkSQLCreator : public SQLCreator1
{
	GkSQLCreator(
		const char* name
		) : SQLCreator1(name) {}
		
	virtual GkSQLConnection* operator()(
		const char* connectionName
		) const { return new SQLDriver(connectionName); }
};


inline void GkSQLConnection::GetHostAndPort(
	const PString& str,
	PString& host,
	WORD& port
	)
{
	const PINDEX i = str.Find(':');
	if (i == P_MAX_INDEX) {
		host = str;
		port = 0;
	} else {
		host = str.Left(i);
		port = (WORD)(str.Mid(i+1).AsUnsigned());
	}
}

#endif /* GKSQL_H */
