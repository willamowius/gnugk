#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include <ptlib.h>
#include <h235.h>
#include <h323pdu.h>
#include <h235auth.h>

#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "RasTbl.h"
#include "RasPDU.h"
#include "Toolkit.h"
#include "gksql.h"
#include "gkauth.h"

#if HAS_MYSQL

#include <mysql.h>

class MySQLPasswordAuth : public SimplePasswordAuth
{
public:
	MySQLPasswordAuth(
		const char* authName
		);

	virtual ~MySQLPasswordAuth();

protected:
	virtual bool GetPassword(
		const PString& alias,
		PString& password
		);

private:
	MySQLPasswordAuth();
	MySQLPasswordAuth(const MySQLPasswordAuth&);
	MySQLPasswordAuth& operator=(const MySQLPasswordAuth&);
	
protected:
	GkSQLConnection* m_sqlConn;
	PString m_query;
};

class MySQLAliasAuth : public AliasAuth
{
public:
	MySQLAliasAuth(
		const char* authName
		);
	
	virtual ~MySQLAliasAuth();

protected:
	virtual bool GetAuthConditionString(
		const PString& alias,
		PString& authCond
		);

private:
	MySQLAliasAuth();
	MySQLAliasAuth(const MySQLAliasAuth&);
	MySQLAliasAuth& operator=(const MySQLAliasAuth&);
	
protected:
	GkSQLConnection* m_sqlConn;
	PString m_query;
};

#endif // HAS_MYSQL

/// Generic SQL authenticator for H.235 enabled endpoints
class SQLPasswordAuth : public SimplePasswordAuth
{
public:
	/// build authenticator reading settings from the config
	SQLPasswordAuth(
		/// name for this authenticator and for the config section to read settings from
		const char* authName
		);
	
	virtual ~SQLPasswordAuth();

protected:
	/** Override from SimplePasswordAuth.
	
	    @return
	    True if the password has been found for the given alias.
	*/
	virtual bool GetPassword(
		/// alias to check the password for
		const PString& alias,
		/// password string, if the match is found
		PString& password
		);

private:
	SQLPasswordAuth();
	SQLPasswordAuth(const SQLPasswordAuth&);
	SQLPasswordAuth& operator=(const SQLPasswordAuth&);
	
protected:
	/// connection to the SQL database
	GkSQLConnection* m_sqlConn;
	/// parametrized query string for password retrieval
	PString m_query;
};

/// Generic SQL authenticator for alias/IP based authentication
class SQLAliasAuth : public AliasAuth
{
public:
	/// build authenticator reading settings from the config
	SQLAliasAuth(
		/// name for this authenticator and for the config section to read settings from
		const char* authName
		);
	
	virtual ~SQLAliasAuth();

protected:
	/** Get auth condition string for the given alias. 
	    This implementation searches the SQL database for the string.
	    Override from AliasAuth.
		
	    @return
	    The AliasAuth condition string for the given alias.
	*/
	virtual bool GetAuthConditionString(
		/// an alias the condition string is to be retrieved for
		const PString& alias,
		/// filled with auth condition string that has been found
		PString& authCond
		);

private:
	SQLAliasAuth();
	SQLAliasAuth(const SQLAliasAuth&);
	SQLAliasAuth& operator=(const SQLAliasAuth&);
	
protected:
	/// connection to the SQL database
	GkSQLConnection* m_sqlConn;
	/// parametrized query string for the auth condition string retrieval
	PString m_query;
};


#if HAS_MYSQL

// class MySQLPasswordAuth
MySQLPasswordAuth::MySQLPasswordAuth(
	const char* authName
	)
	: SimplePasswordAuth(authName), m_sqlConn(NULL)
{
	m_sqlConn = GkSQLConnection::Create("MySQL", authName);
	if (m_sqlConn == NULL) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not find driver for MySQL database"
			);
		return;
	}

	PConfig* cfg = GetConfig();
	SetCacheTimeout(cfg->GetInteger(authName, "CacheTimeout", 0));
		
	const PString password = cfg->GetString(authName, "Password", "");
	
	PString host = cfg->GetString(authName, "Host", "localhost");
	if (cfg->GetInteger(authName, "Port", -1) > 0)
		host += ":" + PString(cfg->GetInteger(authName, "Port", MYSQL_PORT));
		
	if (!m_sqlConn->Initialize(
			host,
			cfg->GetString(authName, "Database", "mysql"),
			cfg->GetString(authName, "User", "mysql"),
			password.IsEmpty() ? (const char*)NULL : (const char*)password,
			1, 1)) {
		delete m_sqlConn;
		m_sqlConn = NULL;
		PTRACE(2, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not connect to the database"
			);
		return;
	}
	
	const PString table = cfg->GetString(authName, "Table", "");
	const PString passwordField = cfg->GetString(authName, "DataField", "");
	const PString aliasField = cfg->GetString(authName, "KeyField", "");
	
	if (table.IsEmpty() || passwordField.IsEmpty() || aliasField.IsEmpty()) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " cannot build query: "
			"Table, KeyField or DataField not specified"
			);
		return;
	}
	
	m_query = "SELECT " + passwordField + " FROM " + table + " WHERE " 
		+ aliasField + " = '%1'";
		
	const PString extraCrit = cfg->GetString(authName, "ExtraCriterion", "");
	if (!extraCrit)
		m_query += " AND " + extraCrit;
		
	PTRACE(4, "SQLAUTH\t" << GetName() << " query: " << m_query);
}

MySQLPasswordAuth::~MySQLPasswordAuth()
{
	delete m_sqlConn;
}

bool MySQLPasswordAuth::GetPassword(
	const PString& alias, 
	PString& password
	)
{
	if (m_sqlConn == NULL) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " password query for alias '" 
			<< alias << "' failed: SQL connection not active"
			);
		return false;
	}
	
	if (m_query.IsEmpty()) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " password query for alias '" 
			<< alias << "' failed: query string not configured"
			);
		return false;
	}
	
	PStringArray params;
	params += alias;
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, &params);
	if (result == NULL) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " password query for alias '" 
			<< alias << "' failed: timeout or fatal error"
			);
		return false;
	}
	
	if (result->IsValid()) {
		PStringArray fields;
		if (result->GetNumRows() < 1)
			PTRACE(3, "SQLAUTH\t" << GetName() << " password not found for "
				"alias '" << alias << '\''
				);
		else if (result->GetNumFields() < 1)
			PTRACE(2, "SQLAUTH\t" << GetName() << " bad-formed query: "
				"no columns found in the result set"
				);
		else if ((!result->FetchRow(fields)) || fields.GetSize() < 1)
			PTRACE(2, "SQLAUTH\t" << GetName() << " password query for alias '" 
				<< alias << "' failed: could not fetch the result row"
				);
		else {
			password = fields[0];
			delete result;
			return true;
		}
	} else
		PTRACE(2, "SQLAUTH\t" << GetName() << " password query for alias '" 
			<< alias << "' failed (" << result->GetErrorCode() << "): "
			<< result->GetErrorMessage()
			);

	delete result;
	return false;
}

// class MySQLAliasAuth
MySQLAliasAuth::MySQLAliasAuth(
	const char* authName
	)
	: AliasAuth(authName), m_sqlConn(NULL)
{
	m_sqlConn = GkSQLConnection::Create("MySQL", authName);
	if (m_sqlConn == NULL) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not find driver for MySQL database"
			);
		return;
	}

	PConfig* cfg = GetConfig();
	SetCacheTimeout(cfg->GetInteger(authName, "CacheTimeout", 0));
	
	const PString password = cfg->GetString(authName, "Password", "");
	
	PString host = cfg->GetString(authName, "Host", "localhost");
	if (cfg->GetInteger(authName, "Port", -1) > 0)
		host += ":" + PString(cfg->GetInteger(authName, "Port", MYSQL_PORT));
		
	if (!m_sqlConn->Initialize(
			host,
			cfg->GetString(authName, "Database", "mysql"),
			cfg->GetString(authName, "User", "mysql"),
			password.IsEmpty() ? (const char*)NULL : (const char*)password,
			1, 1)) {
		delete m_sqlConn;
		m_sqlConn = NULL;
		PTRACE(2, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not connect to the database"
			);
		return;
	}
	
	const PString table = cfg->GetString(authName, "Table", "");
	const PString ipField = cfg->GetString(authName, "DataField", "");
	const PString aliasField = cfg->GetString(authName, "KeyField", "");
	
	if (table.IsEmpty() || ipField.IsEmpty() || aliasField.IsEmpty()) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " cannot build query: "
			"Table, KeyField or DataField not specified"
			);
		return;
	}
	
	m_query = "SELECT " + ipField + " FROM " + table + " WHERE " 
		+ aliasField + " = '%1'";
		
	const PString extraCrit = cfg->GetString(authName, "ExtraCriterion", "");
	if (!extraCrit)
		m_query += " AND " + extraCrit;
		
	PTRACE(4, "SQLAUTH\t" << GetName() << " query: " << m_query);
}

MySQLAliasAuth::~MySQLAliasAuth()
{
	delete m_sqlConn;
}

bool MySQLAliasAuth::GetAuthConditionString(
	const PString& alias,
	PString& authCond
	)
{
	if (m_sqlConn == NULL) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " query for alias '" << alias 
			<< "' failed: SQL connection not active"
			);
		return false;
	}
	
	if (m_query.IsEmpty()) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " query for alias '" << alias 
			<< "' failed: Query string not configured"
			);
		return false;
	}
	
	PStringArray params;
	params += alias;
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, &params);
	if (result == NULL) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " query for alias '" << alias 
			<< "' failed: timeout or fatal error"
			);
		return false;
	}

	if (result->IsValid()) {
		PStringArray fields;
		if (result->GetNumRows() < 1)
			PTRACE(3, "SQLAUTH\t" << GetName() << " auth condition string "
				"not found for alias '" << alias << '\''
				);
		else if (result->GetNumFields() < 1)
			PTRACE(2, "SQLAUTH\t" << GetName() << " bad-formed query: "
				"no columns found in the result set"
				);
		else if ((!result->FetchRow(fields)) || fields.GetSize() < 1)
			PTRACE(3, "SQLAUTH\t" << GetName() << " qery for alias '" << alias 
				<< "' failed: could not fetch the result row"
				);
		else {
			authCond = fields[0];
			delete result;
			return true;
		}
	} else
		PTRACE(2, "SQLAUTH\t" << GetName() << " query for alias '" << alias 
			<< "' failed (" << result->GetErrorCode() << "): "
			<< result->GetErrorMessage()
			);
			
	delete result;
	return false;
}

#endif // HAS_MYSQL

SQLPasswordAuth::SQLPasswordAuth(
	const char* authName
	)
	: SimplePasswordAuth(authName), m_sqlConn(NULL)
{
	PConfig* cfg = GetConfig();

	const PString driverName = cfg->GetString(authName, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no SQL driver selected"
			);
		return;
	}
	
	m_sqlConn = GkSQLConnection::Create(driverName, authName);
	if (m_sqlConn == NULL) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not find " << driverName << " database driver"
			);
		return;
	}

	SetCacheTimeout(cfg->GetInteger(authName, "CacheTimeout", 0));
		
	if (!m_sqlConn->Initialize(cfg, authName)) {
		delete m_sqlConn;
		m_sqlConn = NULL;
		PTRACE(2, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not connect to the database"
			);
		return;
	}
	
	m_query = cfg->GetString(authName, "Query", "");
	if (m_query.IsEmpty())
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no query configured"
			);
	else
		PTRACE(4, "SQLAUTH\t" << GetName() << " query: " << m_query);
}

SQLPasswordAuth::~SQLPasswordAuth()
{
	delete m_sqlConn;
}

bool SQLPasswordAuth::GetPassword(
	const PString& alias,
	PString& password
	)
{
	if (m_sqlConn == NULL) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " password query for alias '" 
			<< alias << "' failed: SQL connection not active"
			);
		return false;
	}
	
	if (m_query.IsEmpty()) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " password query for alias '" 
			<< alias << "' failed: Query string not configured"
			);
		return false;
	}
	
	PStringArray params;
	params += alias;
	params += Toolkit::GKName();
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, &params);
	if (result == NULL) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " password query for alias '" 
			<< alias << "' failed: timeout or fatal error"
			);
		return false;
	}

	if (result->IsValid()) {
		PStringArray fields;
		if (result->GetNumRows() < 1)
			PTRACE(3, "SQLAUTH\t" << GetName() << " password not found for "
				"alias '" << alias << '\''
				);
		else if (result->GetNumFields() < 1)
			PTRACE(2, "SQLAUTH\t" << GetName() << " bad-formed query: "
				"no columns found in the result set"
				);
		else if ((!result->FetchRow(fields)) || fields.GetSize() < 1)
			PTRACE(2, "SQLAUTH\t" << GetName() << " password query for alias '" 
				<< alias << "' failed: could not fetch the result row"
				);
		else {
			password = fields[0];
			delete result;
			return true;
		}
	} else
		PTRACE(2, "SQLAUTH\t" << GetName() << " password query for alias '" 
			<< alias << "' failed (" << result->GetErrorCode() << "): "
			<< result->GetErrorMessage()
			);

	delete result;
	return false;
}

SQLAliasAuth::SQLAliasAuth(
	const char* authName
	)
	: AliasAuth(authName), m_sqlConn(NULL)
{
	PConfig* cfg = GetConfig();

	const PString driverName = cfg->GetString(authName, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no SQL driver selected"
			);
		return;
	}
	
	m_sqlConn = GkSQLConnection::Create(driverName, authName);
	if (m_sqlConn == NULL) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not find " << driverName << " database driver"
			);
		return;
	}

	SetCacheTimeout(cfg->GetInteger(authName, "CacheTimeout", 0));
	
	if (!m_sqlConn->Initialize(cfg, authName)) {
		delete m_sqlConn;
		m_sqlConn = NULL;
		PTRACE(2, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not connect to the database"
			);
		return;
	}
	
	m_query = cfg->GetString(authName, "Query", "");
	if (m_query.IsEmpty())
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no query configured"
			);
	else
		PTRACE(4, "SQLAUTH\t" << GetName() << " query: " << m_query);
}

SQLAliasAuth::~SQLAliasAuth()
{
	delete m_sqlConn;
}

bool SQLAliasAuth::GetAuthConditionString(
	const PString& alias,
	PString& authCond
	)
{
	if (m_sqlConn == NULL) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " query for alias '" << alias 
			<< "' failed: SQL connection not active"
			);
		return false;
	}
	
	if (m_query.IsEmpty()) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " query for alias '" << alias 
			<< "' failed: Query string not configured"
			);
		return false;
	}
	
	PStringArray params;
	params += alias;
	params += Toolkit::GKName();
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, &params);
	if (result == NULL) {
		PTRACE(2, "SQLAUTH\t" << GetName() << " query for alias '" << alias 
			<< "' failed: timeout or fatal error"
			);
		return false;
	}

	if (result->IsValid()) {
		PStringArray fields;
		if (result->GetNumRows() < 1)
			PTRACE(3, "SQLAUTH\t" << GetName() << " auth condition string "
				"not found for alias '" << alias << '\''
				);
		else if (result->GetNumFields() < 1)
			PTRACE(2, "SQLAUTH\t" << GetName() << " bad-formed query: "
				"no columns found in the result set"
				);
		else if ((!result->FetchRow(fields)) || fields.GetSize() < 1)
			PTRACE(2, "SQLAUTH\t" << GetName() << " query for alias '" << alias 
				<< "' failed: could not fetch the result row"
				);
		else {
			authCond = fields[0];
			delete result;
			return true;
		}
	} else
		PTRACE(2, "SQLAUTH\t" << GetName() << " query for alias '" << alias 
			<< "' failed (" << result->GetErrorCode() << "): "
			<< result->GetErrorMessage()
			);

	delete result;
	return false;
}

namespace { // anonymous namespace
	GkAuthCreator<SQLPasswordAuth> SQLPasswordAuthCreator("SQLPasswordAuth");
	GkAuthCreator<SQLAliasAuth> SQLAliasAuthCreator("SQLAliasAuth");
#if HAS_MYSQL
	GkAuthCreator<MySQLPasswordAuth> MySQLPasswordAuthCreator("MySQLPasswordAuth");
	GkAuthCreator<MySQLAliasAuth> MySQLAliasAuthCreator("MySQLAliasAuth");
#endif
} // end of anonymous namespace
