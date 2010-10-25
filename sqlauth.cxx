/*
 * sqlauth.cxx
 *
 * SQL authentication/authorization modules for GNU Gatekeeper
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 * Copyright (c) 2006-2010, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include <ptlib.h>
#include <h235.h>
#include <h323pdu.h>
#include <h235auth.h>
#include <limits>

#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "RasTbl.h"
#include "RasPDU.h"
#include "Routing.h"
#include "Toolkit.h"
#include "RasSrv.h"
#include "gksql.h"
#include "sigmsg.h"
#include "h323util.h"
#include "Neighbor.h"
#include "gkauth.h"

using Routing::Route;

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

	virtual PString GetInfo();
	
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

	virtual PString GetInfo();

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

/// Generic SQL authenticator for non-password, SQL based authentication
class SQLAuth : public GkAuthenticator
{
public:
	enum SupportedChecks {
		SQLAuthRasChecks = RasInfo<H225_RegistrationRequest>::flag
			| RasInfo<H225_AdmissionRequest>::flag
			| RasInfo<H225_LocationRequest>::flag,
		SQLAuthMiscChecks = e_Setup | e_SetupUnreg
	};
	
	/// build authenticator reading settings from the config
	SQLAuth(
		/// name for this authenticator and for the config section to read settings from
		const char* authName,
		/// RAS check events supported by this module
		unsigned supportedRasChecks = SQLAuthRasChecks,
		/// Misc check events supported by this module
		unsigned supportedMiscChecks = SQLAuthMiscChecks
		);
	
	virtual ~SQLAuth();

	/** Authenticate using data from RRQ RAS message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// RRQ RAS message to be authenticated
		RasPDU<H225_RegistrationRequest>& rrqPdu, 
		/// authorization data (reject reason, ...)
		RRQAuthData& authData
		);
		
	/** Authenticate using data from ARQ RAS message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// ARQ nessage to be authenticated
		RasPDU<H225_AdmissionRequest> & arqPdu, 
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData& authData
		);

	/** Authenticate using data from LRQ RAS message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		RasPDU<H225_LocationRequest>& req,
		unsigned& rejectReason
		);
		
	/** Authenticate using data from Q.931 Setup message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// Q.931/H.225 Setup message to be authenticated
		SetupMsg &setup,
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData& authData
		);

	virtual PString GetInfo();

private:
	SQLAuth();
	SQLAuth(const SQLAuth&);
	SQLAuth& operator=(const SQLAuth&);

protected:
	/// connection to the SQL database
	GkSQLConnection* m_sqlConn;
	/// parametrized query string for RRQ auth
	PString m_regQuery;
	/// parametrized query string for LRQ auth
	PString m_nbQuery;
	/// parametrized query string for ARQ/Setup auth
	PString m_callQuery;
};


namespace {

/// a common wrapper for SELECT query execution and result retrieval
bool RunQuery(
	const PString &traceStr,
	GkSQLConnection *conn,
	const PString &query,
	const std::map<PString, PString>& params,
	GkSQLResult::ResultRow& resultRow,
	long timeout
	)
{
	resultRow.clear();
	
	if (conn == NULL) {
		PTRACE(2, traceStr << ": query failed - SQL connection not active");
		return false;
	}
	
	if (query.IsEmpty()) {
		PTRACE(2, traceStr << ": query failed - query string not configured");
		return false;
	}
	
	GkSQLResult* result = conn->ExecuteQuery(query, params, timeout);
	if (result == NULL) {
		PTRACE(2, traceStr << ": query failed - timeout or fatal error");
		return false;
	}

	if (!result->IsValid()) {
		PTRACE(2, traceStr << ": query failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage()
			);
		delete result;
		return false;
	}
	
	if (result->GetNumRows() < 1)
		PTRACE(3, traceStr << ": query returned no rows");
	else if (result->GetNumFields() < 1)
		PTRACE(2, traceStr << ": bad query - "
			"no columns found in the result set"
			);
	else if (!result->FetchRow(resultRow) || resultRow.empty())
		PTRACE(2, traceStr << ": query failed - could not fetch the result row");
	else {
		delete result;
		return true;
	}

	delete result;
	return false;
}

inline GkSQLResult::ResultRow::iterator FindField(
	GkSQLResult::ResultRow& result,
	const PString& fieldName
	)
{
	GkSQLResult::ResultRow::iterator i = result.begin();
	while (i != result.end() && i->second != fieldName)
		i++;
	return i;
}

} /* namespace */


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
		
	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(0, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not connect to the database"
			);
		return;
	}
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
	GkSQLResult::ResultRow result;
	std::map<PString, PString> params;
	params["1"] = alias;
	params["u"] = alias;
	params["2"] = Toolkit::GKName();
	params["g"] = Toolkit::GKName();

	if (!RunQuery("SQLAUTH\t" + GetName() + "('" + alias + "')", m_sqlConn, m_query, params, result, -1))
		return false;
		
	password = result[0].first;
	return true;
}

PString SQLPasswordAuth::GetInfo()
{
	PString result;
	
	if (m_sqlConn == NULL)
		result += "  No SQL connection available\r\n";
	else {
		GkSQLConnection::Info info;
		m_sqlConn->GetInfo(info);
		result += "  Connected to an SQL Backend: " + PString(info.m_connected ? "Yes" : "No") + "\r\n";
		result += "  Min Connection Pool Size:    " + PString(info.m_minPoolSize) + "\r\n";
		result += "  Max Connection Pool Size:    " + PString(info.m_maxPoolSize) + "\r\n";
		result += "  Idle Connections:            " + PString(info.m_idleConnections) + "\r\n";
		result += "  Busy Connections::           " + PString(info.m_busyConnections) + "\r\n";
		result += "  Waiting Requests:            " + PString(info.m_waitingRequests) + "\r\n";
	}
	
	result += ";\r\n";
	
	return result;
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
		
	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(0, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not connect to the database"
			);
		return;
	}
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
	GkSQLResult::ResultRow result;
	std::map<PString, PString> params;
	params["1"] = alias;
	params["u"] = alias;
	params["2"] = Toolkit::GKName();
	params["g"] = Toolkit::GKName();

	if (!RunQuery("SQLAUTH\t" + GetName() + "('" + alias + "')", m_sqlConn, m_query, params, result, -1))
		return false;
		
	authCond = result[0].first;
	return true;
}

PString SQLAliasAuth::GetInfo()
{
	PString result;
	
	if (m_sqlConn == NULL)
		result += "  No SQL connection available\r\n";
	else {
		GkSQLConnection::Info info;
		m_sqlConn->GetInfo(info);
		result += "  Connected to an SQL Backend: " + PString(info.m_connected ? "Yes" : "No") + "\r\n";
		result += "  Min Connection Pool Size:    " + PString(info.m_minPoolSize) + "\r\n";
		result += "  Max Connection Pool Size:    " + PString(info.m_maxPoolSize) + "\r\n";
		result += "  Idle Connections:            " + PString(info.m_idleConnections) + "\r\n";
		result += "  Busy Connections::           " + PString(info.m_busyConnections) + "\r\n";
		result += "  Waiting Requests:            " + PString(info.m_waitingRequests) + "\r\n";
	}
	
	result += ";\r\n";
	
	return result;
}

SQLAuth::SQLAuth(
	const char* authName,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks
	) 
	: 
	GkAuthenticator(authName, supportedRasChecks, supportedMiscChecks), 
	m_sqlConn(NULL)
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

	m_regQuery = cfg->GetString(authName, "RegQuery", "");
	if (m_regQuery.IsEmpty() && IsRasCheckEnabled(RasInfo<H225_RegistrationRequest>::flag)) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no RRQ query configured"
			);
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	} else if (!m_regQuery) {
		PTRACE(4, "SQLAUTH\t" << GetName() << " RRQ query: " << m_regQuery);
	}

	m_nbQuery = cfg->GetString(authName, "NbQuery", "");
	if (m_nbQuery.IsEmpty() && IsRasCheckEnabled(RasInfo<H225_LocationRequest>::flag)) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no LRQ query configured");
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	} else if (!m_nbQuery) {
		PTRACE(4, "SQLAUTH\t" << GetName() << " LRQ query: " << m_nbQuery);
	}

	m_callQuery = cfg->GetString(authName, "CallQuery", "");
	if (m_callQuery.IsEmpty() && (IsRasCheckEnabled(RasInfo<H225_AdmissionRequest>::flag)
			|| IsMiscCheckEnabled(e_Setup) || IsMiscCheckEnabled(e_SetupUnreg))) {
		PTRACE(1, "SQLAUTH\t" << GetName() << " module creation failed: "
			"no ARQ/Setup query configured");
		PTRACE(0, "SQLAUTH\tFATAL: Shutting down");
		RasServer::Instance()->Stop();
		return;
	} else if (!m_callQuery) {
		PTRACE(4, "SQLAUTH\t" << GetName() << " ARQ/Setup query: " << m_callQuery);
	}

	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(0, "SQLAUTH\t" << GetName() << " module creation failed: "
			"could not connect to the database");
		return;
	}
}

SQLAuth::~SQLAuth()
{
	delete m_sqlConn;
}

int SQLAuth::Check(
	/// RRQ RAS message to be authenticated
	RasPDU<H225_RegistrationRequest>& rrqPdu, 
	/// authorization data (reject reason, ...)
	RRQAuthData& authData
	)
{
	H225_RegistrationRequest &rrq = rrqPdu;
	std::map<PString, PString> params;
	
	// get the username for User-Name attribute		
	params["u"] = GetUsername(rrqPdu);
	params["g"] = Toolkit::GKName();
	
	PIPSocket::Address addr = (rrqPdu.operator->())->m_peerAddr;

	const PString traceStr = "SQLAUTH\t" + GetName() + "(RRQ from "
		+ addr.AsString() + " Username=" + params["u"]
		+ ")";
	params["callerip"] = addr.AsString();
	
	addr = (rrqPdu.operator->())->m_localAddr;
	params["gkip"] = addr.AsString();

	if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
		PString aliasList;
		for (PINDEX i = 0; i < rrq.m_terminalAlias.GetSize(); i++) {
			if(i > 0)
				aliasList += ",";
			aliasList += AsString(rrq.m_terminalAlias[i], FALSE);
		}
		params["aliases"] = aliasList;
	}

	GkSQLResult::ResultRow result;	
	if (!RunQuery(traceStr, m_sqlConn, m_regQuery, params, result, -1)) {
		authData.m_rejectReason = H225_RegistrationRejectReason::e_resourceUnavailable;
		return GetDefaultStatus();
	}

	if (!Toolkit::AsBool(result[0].first)) {
		authData.m_rejectReason = H225_RegistrationRejectReason::e_securityDenial;
		return e_fail;
	}

	GkSQLResult::ResultRow::const_iterator iter = FindField(result, "billingmode");
	if (iter != result.end()) {
		const PString &s = iter->first;
		if (!s) {
			if (strspn((const char*)s,"0123456789.") == (size_t)s.GetLength()) {
				const int intVal = s.AsInteger();
				if (intVal == 0)
					authData.m_billingMode = H225_CallCreditServiceControl_billingMode::e_credit;
				else if (intVal == 1 || intVal == 2)
					authData.m_billingMode = H225_CallCreditServiceControl_billingMode::e_debit;
			} else {
				PTRACE(3, traceStr << " - invalid billingmode attribute '"
					<< s << '\''
					);
			}
		}
	}

	iter = FindField(result, "creditamount");
	if (iter != result.end()) {
		if (!iter->first)
			authData.m_amountString = iter->first;
	}

	iter = FindField(result, "aliases");
	if (iter != result.end()) {
		PStringArray aliases = iter->first.Tokenise(",");
		if (aliases.GetSize() > 0 
				&& rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
			PINDEX i = 0;
			while (i < rrq.m_terminalAlias.GetSize()) {
				PINDEX j = aliases.GetStringsIndex(AsString(rrq.m_terminalAlias[i], FALSE));
				if( j == P_MAX_INDEX )
					rrq.m_terminalAlias.RemoveAt(i);
				else {
					i++;
					aliases.RemoveAt(j);
				}
			}
		}
		for (PINDEX i = 0; i < aliases.GetSize(); i++) {
			if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
				rrq.m_terminalAlias.SetSize(rrq.m_terminalAlias.GetSize()+1);
			else {
				rrq.IncludeOptionalField(H225_RegistrationRequest::e_terminalAlias);
				rrq.m_terminalAlias.SetSize(1);
			}
			H323SetAliasAddress(aliases[i], rrq.m_terminalAlias[rrq.m_terminalAlias.GetSize()-1]);
		}
	}
			
	return e_ok;
}
		
int SQLAuth::Check(
	/// ARQ nessage to be authenticated
	RasPDU<H225_AdmissionRequest> & arqPdu, 
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData& authData
	)
{
	const H225_AdmissionRequest &arq = arqPdu;
	std::map<PString, PString> params;
	
	PIPSocket::Address addr = (arqPdu.operator->())->m_peerAddr;

	const PString traceStr = "SQLAUTH\t" + GetName() + "(ARQ from "
		+ addr.AsString() + " CRV=" + PString(arq.m_callReferenceValue.GetValue() & 0x7fff)
		+ ")";
	params["callerip"] = addr.AsString();
		
	// get the username for User-Name attribute		
	params["u"] = GetUsername(arqPdu, authData);
	params["g"] = Toolkit::GKName();
	
	addr = (arqPdu.operator->())->m_localAddr;
	params["gkip"] = addr.AsString();

	params["Calling-Station-Id"] = GetCallingStationId(arqPdu, authData);
	params["Called-Station-Id"] = GetCalledStationId(arqPdu, authData);
	params["Dialed-Number"] = GetDialedNumber(arqPdu, authData);
	params["bandwidth"] = PString(arq.m_bandWidth.GetValue());
	params["answer"] = arq.m_answerCall ? "1" : "0";
	params["arq"] = "1";
	params["CallId"] = AsString(arq.m_callIdentifier.m_guid);
	
	GkSQLResult::ResultRow result;	
	if (!RunQuery(traceStr, m_sqlConn, m_callQuery, params, result, -1)) {
		authData.m_rejectReason = H225_AdmissionRejectReason::e_resourceUnavailable;
		return GetDefaultStatus();
	}

	if (!Toolkit::AsBool(result[0].first)) {
		authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		return e_fail;
	}

	GkSQLResult::ResultRow::const_iterator iter = FindField(result, "billingmode");
	if (iter != result.end()) {
		const PString &s = iter->first;
		if (!s) {
			if (strspn((const char*)s,"0123456789.") == (size_t)s.GetLength()) {
				const int intVal = s.AsInteger();
				if (intVal == 0)
					authData.m_billingMode = H225_CallCreditServiceControl_billingMode::e_credit;
				else if (intVal == 1 || intVal == 2)
					authData.m_billingMode = H225_CallCreditServiceControl_billingMode::e_debit;
			} else {
				PTRACE(3, traceStr << " - invalid billingmode attribute '"
					<< s << '\''
					);
			}
		}
	}

	iter = FindField(result, "creditamount");
	if (iter != result.end()) {
		if (!iter->first)
			authData.m_amountString = iter->first;
	}

	iter = FindField(result, "credittime");
	if (iter != result.end()) {
		const PString &s = iter->first;
		if (s.GetLength() > 0
			&& strspn((const char*)s, "0123456789") == (size_t)s.GetLength()) {
			PUInt64 limit = s.AsUnsigned64();
			if (limit > PUInt64(std::numeric_limits<long>::max()))
				authData.m_callDurationLimit = std::numeric_limits<long>::max();
			else
				authData.m_callDurationLimit = static_cast<long>(limit);
			PTRACE(5, traceStr << " - duration limit set to "
				<< authData.m_callDurationLimit
				);
			if (authData.m_callDurationLimit == 0) {
				authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
				return e_fail;
			}
		}
	}

	PStringArray numbersToDial;
	iter = FindField(result, "redirectnumber");
	if (iter != result.end()) {
		const PString &s = iter->first;
		if (!s) {
			numbersToDial = s.Tokenise("; \t", FALSE);
			if (numbersToDial.GetSize() > 0) {
				PString rewrittenNumber(numbersToDial[0]);
				PINDEX pos = rewrittenNumber.Find('=');
				if (pos != P_MAX_INDEX)
					rewrittenNumber = rewrittenNumber.Left(pos);
				authData.SetRouteToAlias(rewrittenNumber);
				PTRACE(5, traceStr << " - call redirected to the number " << rewrittenNumber);
			}
			PTRACE(5, traceStr << " - call redirected to the number " << s);
		}
	}
			
	iter = FindField(result, "redirectip");
	if (iter != result.end()) {
		const PString &s = iter->first;
		if (!s) {
			PStringArray tokens(s.Tokenise("; \t", FALSE));
			for (PINDEX i = 0; i < tokens.GetSize(); ++i) {
				PIPSocket::Address raddr;
				WORD port = 0;
					
				if (GetTransportAddress(tokens[i], GK_DEF_ENDPOINT_SIGNAL_PORT, raddr, port)
						&& raddr.IsValid() && port != 0) {
					Route route("SQLAuth", raddr, port);
					route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(
						SocketToH225TransportAddr(raddr, port)
						);
					if (numbersToDial.GetSize() > 0) {
						route.m_destNumber = (i < numbersToDial.GetSize() ? numbersToDial[i] : numbersToDial[numbersToDial.GetSize() - 1]);
						PINDEX pos = route.m_destNumber.Find('=');
						if (pos != P_MAX_INDEX) {
							route.m_destOutNumber = route.m_destNumber.Mid(pos + 1);
							route.m_destNumber = route.m_destNumber.Left(pos);
						}
					}
					authData.m_destinationRoutes.push_back(route);
					PTRACE(5, traceStr << " - call redirected to the address " <<
						route.AsString()
						);
				}
			}
		}
	}

	iter = FindField(result, "proxy");
	if (iter != result.end()) {
		const PString &s = iter->first;
		if (!s) {
			authData.m_proxyMode = Toolkit::AsBool(s)
				? CallRec::ProxyEnabled : CallRec::ProxyDisabled;
			PTRACE(5, traceStr << " - proxy mode "
				<< (authData.m_proxyMode == CallRec::ProxyEnabled ? "enabled" : "disabled")
				);
		}
	}

	iter = FindField(result, "clientauthid");
	if (iter != result.end()) {
		const PString & s = iter->first;
		if (s.GetLength() > 0
			&& strspn((const char*)s, "0123456789") == (size_t)s.GetLength()) {
			authData.m_clientAuthId = s.AsUnsigned64();
			PTRACE(5, traceStr << " - clientAuthId = " << authData.m_clientAuthId);
		}
	}
	
	return e_ok;
}

int SQLAuth::Check(
	RasPDU<H225_LocationRequest>& lrqPdu,
	unsigned& rejectReason
	)
{
	H225_LocationRequest &lrq = lrqPdu;
	std::map<PString, PString> params;
	
	PIPSocket::Address addr = (lrqPdu.operator->())->m_peerAddr;

	const PString traceStr = "SQLAUTH\t" + GetName() + "(LRQ from "
		+ addr.AsString() + ")";
	params["nbip"] = addr.AsString();
	params["nbid"] = RasServer::Instance()->GetNeighbors()->GetNeighborIdBySigAdr(addr);
	params["g"] = Toolkit::GKName();
	
	addr = (lrqPdu.operator->())->m_localAddr;
	params["gkip"] = addr.AsString();

	if (lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)) {
		params["Calling-Station-Id"] = GetBestAliasAddressString(lrq.m_sourceInfo,
			false, AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);
		params["src-info"] = AsString(lrq.m_sourceInfo);
	}
	params["Called-Station-Id"] = GetBestAliasAddressString(lrq.m_destinationInfo,
		false, AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
			| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
		);
	params["dest-info"] = AsString(lrq.m_destinationInfo);

	if (lrq.HasOptionalField(H225_LocationRequest::e_bandWidth))
		params["bandwidth"] = PString(lrq.m_bandWidth.GetValue());

	GkSQLResult::ResultRow result;	
	if (!RunQuery(traceStr, m_sqlConn, m_nbQuery, params, result, -1)) {
		rejectReason = H225_LocationRejectReason::e_resourceUnavailable;
		return GetDefaultStatus();
	}

	if (!Toolkit::AsBool(result[0].first)) {
		rejectReason = H225_LocationRejectReason::e_securityDenial;
		return e_fail;
	}

	GkSQLResult::ResultRow::const_iterator iter = FindField(result, "destination");
	if (iter != result.end()) {
		PStringArray aliases = iter->first.Tokenise(",");
		if (aliases.GetSize() > 0) {
			PINDEX i = 0;
			while (i < lrq.m_destinationInfo.GetSize()) {
				PINDEX j = aliases.GetStringsIndex(AsString(lrq.m_destinationInfo[i], FALSE));
				if( j == P_MAX_INDEX )
					lrq.m_destinationInfo.RemoveAt(i);
				else {
					i++;
					aliases.RemoveAt(j);
				}
			}
		}
		for (PINDEX i = 0; i < aliases.GetSize(); i++) {
			const PINDEX sz = lrq.m_destinationInfo.GetSize();
			lrq.m_destinationInfo.SetSize(sz + 1);
			H323SetAliasAddress(aliases[i], lrq.m_destinationInfo[sz]);
		}
	}
			
	return e_ok;
}
	
int SQLAuth::Check(
	/// Q.931/H.225 Setup message to be authenticated
	SetupMsg &setup,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData& authData
	)
{
	std::map<PString, PString> params;
	
	PIPSocket::Address addr;
	setup.GetPeerAddr(addr);

	const PString traceStr = "SQLAUTH\t" + GetName() + "(Setup from "
		+ addr.AsString() + " CRV=" + PString(setup.GetQ931().GetCallReference())
		+ ")";
	params["callerip"] = addr.AsString();
		
	// get the username for User-Name attribute		
	params["u"] = GetUsername(setup, authData);
	params["g"] = Toolkit::GKName();
	
	setup.GetLocalAddr(addr);
	params["gkip"] = addr.AsString();

	params["Calling-Station-Id"] = GetCallingStationId(setup, authData);
	params["Called-Station-Id"] = GetCalledStationId(setup, authData);
	params["Dialed-Number"] = GetDialedNumber(setup, authData);
	params["answer"] = "0";
	params["arq"] = "0";
	params["CallId"] = AsString(setup.GetUUIEBody().m_callIdentifier.m_guid);

	if (authData.m_call)
		params["bandwidth"] = PString(authData.m_call->GetBandwidth());

	GkSQLResult::ResultRow result;	
	if (!RunQuery(traceStr, m_sqlConn, m_callQuery, params, result, -1)) {
		authData.m_rejectCause = Q931::TemporaryFailure;
		return GetDefaultStatus();
	}

	if (!Toolkit::AsBool(result[0].first)) {
		authData.m_rejectCause = Q931::CallRejected;
		// check for extra fields for rejected calls
		GkSQLResult::ResultRow::const_iterator iter = FindField(result, "q931cause");
		if (iter != result.end()) {
			const PString & s = iter->first;
			if (s.GetLength() > 0
				&& strspn((const char*)s, "0123456789") == (size_t)s.GetLength()) {
				int cause = s.AsInteger();
				if (cause > 0 && cause < 128) {
					authData.m_rejectCause = cause;
					PTRACE(5, traceStr << " - Q.931 cause set to " << authData.m_rejectCause);
				}
			}
		}
		iter = FindField(result, "clientauthid");
		if (iter != result.end()) {
			const PString & s = iter->first;
			if (s.GetLength() > 0
				&& strspn((const char*)s, "0123456789") == (size_t)s.GetLength()) {
				authData.m_clientAuthId = s.AsUnsigned64();
				PTRACE(5, traceStr << " - clientAuthId = " << authData.m_clientAuthId);
			}
		}
		return e_fail;
	}

	// check for extra fields for accepted calls
	GkSQLResult::ResultRow::const_iterator iter = FindField(result, "credittime");
	if (iter != result.end()) {
		const PString &s = iter->first;
		if (s.GetLength() > 0
			&& strspn((const char*)s, "0123456789") == (size_t)s.GetLength()) {
			PUInt64 limit = s.AsUnsigned64();
			if (limit > PUInt64(std::numeric_limits<long>::max()))
				authData.m_callDurationLimit = std::numeric_limits<long>::max();
			else
				authData.m_callDurationLimit = static_cast<long>(limit);
			PTRACE(5, traceStr << " - duration limit set to "
				<< authData.m_callDurationLimit
				);
			if (authData.m_callDurationLimit == 0) {
				authData.m_rejectCause = Q931::CallRejected;
				return e_fail;
			}
		}
	}

	PStringArray numbersToDial;
	iter = FindField(result, "redirectnumber");
	if (iter != result.end()) {
		const PString &s = iter->first;
		if (!s) {
			numbersToDial = s.Tokenise("; \t", FALSE);
			if (numbersToDial.GetSize() > 0) {
				PString rewrittenNumber(numbersToDial[0]);
				PINDEX pos = rewrittenNumber.Find('=');
				if (pos != P_MAX_INDEX)
					rewrittenNumber = rewrittenNumber.Left(pos);
				authData.SetRouteToAlias(rewrittenNumber);
				PTRACE(5, traceStr << " - call redirected to the number " << rewrittenNumber);
			}
		}
	}
			
	iter = FindField(result, "redirectip");
	if (iter != result.end()) {
		const PString &s = iter->first;
		if (!s) {
			PStringArray tokens(s.Tokenise("; \t", FALSE));
			for (PINDEX i = 0; i < tokens.GetSize(); ++i) {
				PIPSocket::Address raddr;
				WORD port = 0;
					
				if (GetTransportAddress(tokens[i], GK_DEF_ENDPOINT_SIGNAL_PORT, raddr, port)
						&& raddr.IsValid() && port != 0) {
					Route route("SQLAuth", raddr, port);
					route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(
						SocketToH225TransportAddr(raddr, port)
						);
					if (numbersToDial.GetSize() > 0) {
						route.m_destNumber = (i < numbersToDial.GetSize() ? numbersToDial[i] : numbersToDial[numbersToDial.GetSize() - 1]);
						PINDEX pos = route.m_destNumber.Find('=');
						if (pos != P_MAX_INDEX) {
							route.m_destOutNumber = route.m_destNumber.Mid(pos + 1);
							route.m_destNumber = route.m_destNumber.Left(pos);
						}
					}
					authData.m_destinationRoutes.push_back(route);
					PTRACE(5, traceStr << " - call redirected to the address " <<
						route.AsString()
						);
				}
			}
		}
	}

	iter = FindField(result, "proxy");
	if (iter != result.end()) {
		const PString &s = iter->first;
		if (!s) {
			authData.m_proxyMode = Toolkit::AsBool(s)
				? CallRec::ProxyEnabled : CallRec::ProxyDisabled;
			PTRACE(5, traceStr << " - proxy mode "
				<< (authData.m_proxyMode == CallRec::ProxyEnabled ? "enabled" : "disabled")
				);
		}
	}

	iter = FindField(result, "clientauthid");
	if (iter != result.end()) {
		const PString & s = iter->first;
		if (s.GetLength() > 0
			&& strspn((const char*)s, "0123456789") == (size_t)s.GetLength()) {
			authData.m_clientAuthId = s.AsUnsigned64();
			PTRACE(5, traceStr << " - clientAuthId = " << authData.m_clientAuthId);
		}
	}

	return e_ok;
}

PString SQLAuth::GetInfo()
{
	PString result;
	
	if (m_sqlConn == NULL)
		result += "  No SQL connection available\r\n";
	else {
		GkSQLConnection::Info info;
		m_sqlConn->GetInfo(info);
		result += "  Connected to an SQL Backend: " + PString(info.m_connected ? "Yes" : "No") + "\r\n";
		result += "  Min Connection Pool Size:    " + PString(info.m_minPoolSize) + "\r\n";
		result += "  Max Connection Pool Size:    " + PString(info.m_maxPoolSize) + "\r\n";
		result += "  Idle Connections:            " + PString(info.m_idleConnections) + "\r\n";
		result += "  Busy Connections::           " + PString(info.m_busyConnections) + "\r\n";
		result += "  Waiting Requests:            " + PString(info.m_waitingRequests) + "\r\n";
	}
	
	result += ";\r\n";
	
	return result;
}

namespace { // anonymous namespace
	GkAuthCreator<SQLPasswordAuth> SQLPasswordAuthCreator("SQLPasswordAuth");
	GkAuthCreator<SQLAliasAuth> SQLAliasAuthCreator("SQLAliasAuth");
	GkAuthCreator<SQLAuth> SQLAuthCreator("SQLAuth");
} // end of anonymous namespace
