#ifndef gksql__h__included
#define gksql__h__included "#(@) $Id$"

#include <list>
#include "name.h"
#include "factory.h"

/** Abstract base class that encapsulates SQL query result.
    Backend specific operations are performed by derived classes.
*/
class GkSQLResult
{
protected:
	GkSQLResult(
		/// true if the query failed and no result is available
		bool queryError = false
		) 
		: m_numRows(0), m_numFields(0), m_selectType(true), 
		m_queryError(queryError) {}
	
public:
	virtual ~GkSQLResult();
	
	/** @return
	    True if the query succeeded and the result is available.
	    Otherwise only GetErrorMessage and GetErrorCode member functions
	    are meaningful.
	*/
	bool IsValid() const { return !m_queryError; }
	
	/** @return
	    True if the query was SELECT-like and there are 0 or more rows
	    to be fetched, otherwise false (INSERT, DELETE, UPDATE).
	*/
	bool IsSelectType() const { return m_selectType; }
	
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
	
	/** @return
	    True if rows can be fetched in random access order, false if
	    rows have to be fethed sequentially and can be retrieved only once.
	*/
	virtual bool HasRandomAccess() = 0;

	/** Fetch a single row from the result set. After each row is fetched,
	    cursor position is moved to a next row.
		
	    @return
	    True if the row has been fetched, false if no more rows are available.
	*/
	virtual bool FetchRow(
		/// array to be filled with string representations of the row fields
		PStringArray& result
		) = 0;

	/** @return
	    True if the column at the index #fieldOffset# is NULL in the row 
	    fetched most recently.
	*/
	virtual bool IsNullField(
		/// index of the column to check
		long fieldOffset
		) = 0;
			
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
		) = 0;
		
	/** @return
	    True if the column at the index #fieldOffset# is NULL in the row 
	    at the specified index.
	*/
	virtual bool IsNullField(
		/// index of the column to check
		long fieldOffset,
		/// index (0 based) of the row to check
		long rowOffset
		) = 0;

private:
	GkSQLResult(const GkSQLResult&);
	GkSQLResult& operator=(const GkSQLResult&);
	
protected:
	/// number of rows in the result set or rows affected by the query
	long m_numRows;
	/// number of columns in each row in the result set
	long m_numFields;
	/// true for SELECT type query, false for INSERT, DELETE and UPDATE
	bool m_selectType;
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
	GkSQLConnection(
		/// name to use in the log
		const char* name = "SQL"
	);

	virtual ~GkSQLConnection();

	static GkSQLConnection* Create(
		const char* driverName,
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

	/** Build a new SQL connection using given parameters.
	    Derived classes do not have to override this member function.
		
	    @return
	    True if connections have been established.
	*/	
	virtual bool Initialize(
		const char* host,
		/// database name to connect to
		const char* database,
		/// database username to connect as
		const char* username,
		/// password to use (or NULL to not use any password)
		const char* password = NULL,
		/// minimum number of active SQL connections
		int minPoolSize = 1,
		/// maximum number of active SQL connections
		int maxPoolSize = -1
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

#if defined(WIN32) && (_MSC_VER < 1300)
public:
#else
protected:
#endif
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
	/// list of database hosts (IP:PORT or DNS:PORT)
	PStringArray m_hosts;
	/// filled with the actual host from m_hosts the database connection is made to
	PString m_host;
	/// database name
	PString m_database;
	/// database username to connect as
	PString m_username;
	/// password associated with the username (if any)
	PString m_password;

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
	PMutex m_connectionsMutex;
	/// signalled when a connections moves from the busy to the idle list
	PSyncPoint m_connectionAvailable;
	/// set to true when destructor is being invoked
	bool m_destroying;
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

#endif /* gksql__h__included */
