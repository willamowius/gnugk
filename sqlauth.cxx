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
#include "RasSrv.h"
#include "gksql.h"
#include "gkauth.h"

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


SQLPasswordAuth::SQLPasswordAuth(
	const char* authName
	)
	: SimplePasswordAuth(authName), m_sqlConn(NULL)
{
	PConfig* cfg = GetConfig();

	const PString driverName = cfg->GetString(authName, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(0, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no SQL driver selected"
			);
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	}
	
	m_sqlConn = GkSQLConnection::Create(driverName, authName);
	if (m_sqlConn == NULL) {
		PTRACE(0, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not find " << driverName << " database driver"
			);
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	}

	SetCacheTimeout(cfg->GetInteger(authName, "CacheTimeout", 0));
		
	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(0, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not connect to the database"
			);
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	}
	
	m_query = cfg->GetString(authName, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(0, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no query configured"
			);
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	} else
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
		PTRACE(0, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no SQL driver selected"
			);
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	}
	
	m_sqlConn = GkSQLConnection::Create(driverName, authName);
	if (m_sqlConn == NULL) {
		PTRACE(0, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not find " << driverName << " database driver"
			);
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	}

	SetCacheTimeout(cfg->GetInteger(authName, "CacheTimeout", 0));
	
	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(0, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not connect to the database"
			);
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	}
	
	m_query = cfg->GetString(authName, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no query configured"
			);
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	} else
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
} // end of anonymous namespace
