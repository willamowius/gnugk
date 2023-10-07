/*
 * gksql_redis.cxx
 *
 * redis driver module for GnuGk
 *
 * Copyright (c) 2019, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"

#if HAS_REDIS

#include <ptlib.h>
#include <hiredis.h>
#include "gksql.h"


/** Class that encapsulates query result for redis backend.
	It does not provide any multithread safety, so should be accessed
	from a single thread at time.
*/
class GkRedisResult : public GkSQLResult
{
public:
	/// Build the result from the query
	GkRedisResult(
		/// number of rows affected by the query
		long numRowsAffected,
		/// query result
		vector<ResultRow*> * resultRows
		);

	/// Build the empty	result and store query execution error information
	GkRedisResult(
		/// redis specific error code
		unsigned int errorCode,
		/// redis specific error message text
		const char* errorMsg
		);

	virtual ~GkRedisResult();

	/** @return
	    Backend specific error message, if the query failed.
	*/
	virtual PString GetErrorMessage();

	/** @return
	    Backend specific error code, if the query failed.
	*/
	virtual long GetErrorCode();

	/** unused in this driver
	*/
	virtual bool FetchRow(
		/// array to be filled with string representations of the row fields
		PStringArray & result
		) { return false; }
	virtual bool FetchRow(
		/// array to be filled with string representations of the row fields
		ResultRow & result
		) { return false; }

private:
	GkRedisResult();
	GkRedisResult(const GkRedisResult &);
	GkRedisResult& operator=(const GkRedisResult &);

protected:
	/// query result for queries
	vector<ResultRow*> * m_sqlResult;
	/// the most recent row returned by fetch operation
	int m_sqlRow;
	/// redis specific error code (if the query failed)
	unsigned int m_errorCode;
	/// redis specific error message text (if the query failed)
	PString m_errorMessage;
};

/// redis backend connection implementation.
class GkRedisConnection : public GkSQLConnection
{
public:
	/// Build a new redis connection object
	GkRedisConnection(
		/// name to use in the log
		const char* name = "redis"
		);

	virtual ~GkRedisConnection();

protected:
	class GkRedisConnWrapper : public GkSQLConnection::SQLConnWrapper
	{
	public:
		GkRedisConnWrapper(
			/// unique identifier for this connection
			int id,
			/// redis connection object
			redisContext * conn
			) : SQLConnWrapper(id, "localhost"), m_conn(conn) { }

		virtual ~GkRedisConnWrapper();

	private:
		GkRedisConnWrapper();
		GkRedisConnWrapper(const GkRedisConnWrapper&);
		GkRedisConnWrapper& operator=(const GkRedisConnWrapper&);

	public:
		redisContext * m_conn;
	};

	/** Create a new redis connection using parameters stored in this object.
	    When the connection is to be closed, the object is simply deleted
	    using delete operator.

	    @return
	    NULL if database connection could not be established
	    or an object of GkRedisConnWrapper class.
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
		) { return str; }

private:
	GkRedisConnection(const GkRedisConnection &);
	GkRedisConnection & operator=(const GkRedisConnection &);
};


GkRedisResult::GkRedisResult(
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

GkRedisResult::GkRedisResult(
	/// redis specific error code
	unsigned int errorCode,
	/// redis specific error message text
	const char* errorMsg
	)
	: GkSQLResult(true), m_sqlResult(NULL), m_sqlRow(-1),
	m_errorCode(errorCode), m_errorMessage(errorMsg)
{
	m_queryError = true;
}

GkRedisResult::~GkRedisResult()
{
	if (m_sqlResult != NULL) {
		for(unsigned i = 0; i < m_sqlResult->size(); i++){
			delete (*m_sqlResult)[i];
		}
		delete m_sqlResult;
	}
}

PString GkRedisResult::GetErrorMessage()
{
	return m_errorMessage;
}

long GkRedisResult::GetErrorCode()
{
	return m_errorCode;
}


GkRedisConnection::GkRedisConnection(
	/// name to use in the log
	const char* name
	) : GkSQLConnection(name)
{
}

GkRedisConnection::~GkRedisConnection()
{
}

GkRedisConnection::GkRedisConnWrapper::~GkRedisConnWrapper()
{
	redisFree(m_conn);
}

GkSQLConnection::SQLConnPtr GkRedisConnection::CreateNewConnection(
	/// unique identifier for this connection
	int id
	)
{
	redisContext *conn;
	struct timeval timeout = { (time_t)m_connectTimeout, 0 };
    if (m_port <= 0) {
        m_port = 6379; // default port
    }
    conn = redisConnectWithTimeout(m_host, m_port, timeout);
    //conn = redisConnectUnixWithTimeout(m_host, timeout); // TODO: support domain sockets, too ?
    if (conn == NULL || conn->err) {
        if (conn) {
    		PTRACE(2, GetName() << "\tredis connection to " << m_host << " failed: " << conn->errstr);
            redisFree(conn);
        } else {
    		PTRACE(2, GetName() << "\tredis connection to " << m_host << " failed: can't allocate redis context");
        }
		SNMP_TRAP(5, SNMPError, Database, GetName() + " connection failed")
		return NULL;
    }

    if (!m_password.IsEmpty()) {
        redisReply * reply = (redisReply *)redisCommand(conn, "AUTH %s", (const char *)m_password);
        if (!reply || !reply->str || PString(reply->str).Left(2) != "OK") {
    		if (reply && reply->str) {
                PTRACE(2, GetName() << "\tredis authentication failed: " << reply->str);
            }
            if (reply)
                freeReplyObject(reply);
            return NULL;
        }
        freeReplyObject(reply);
    }

	PTRACE(5, GetName() << "\tredis connection to " << m_host << " established successfully");
	return new GkRedisConnWrapper(id, conn);
}

GkSQLResult* GkRedisConnection::ExecuteQuery(
	/// connection to use for query execution
	GkSQLConnection::SQLConnPtr con,
	/// query string
	const char* queryStr,
	/// maximum time (ms) for the query execution, -1 means infinite
	long /*timeout*/
	)
{
	redisContext * conn = ((GkRedisConnWrapper*)con)->m_conn;

	redisReply * reply = (redisReply *)redisCommand(conn, queryStr);
	if (conn->err || !reply) {
        if (reply) {
            freeReplyObject(reply);
        }
		GkSQLResult * result = new GkRedisResult(conn->err, conn->errstr);
		Disconnect();
		return result;
	}
	if (reply->str) {
        GkSQLResult::ResultRow * row = new GkSQLResult::ResultRow();
        row->resize(1);
        (*row)[0].first = reply->str;
        (*row)[0].second = queryStr;
        (*row)[0].second.Replace("GET ", "");
        //(*row)[0].second.Replace("SET ", "");   // TODO: remove value, too
        (*row)[0].second = (*row)[0].second.Trim();
        freeReplyObject(reply);

        vector<GkSQLResult::ResultRow*> * rows = new vector<GkSQLResult::ResultRow*>(1);
        (*rows)[0] = row;
        return new GkRedisResult(1, rows);
	} else {
	    // Nothing found
        vector<GkSQLResult::ResultRow*> * rows = new vector<GkSQLResult::ResultRow*>(0);
        return new GkRedisResult(0, rows);
	}
}

namespace {
	GkSQLCreator<GkRedisConnection> RedisCreator("redis");
}

#endif // HAS_REDIS
