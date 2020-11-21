/*
 * ldapauth.cxx
 *
 * LDAP authentication/authorization modules for GNU Gatekeeper
 *
 * Copyright (c) 2013-2020, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include <ptlib.h>

#ifdef P_LDAP

#include <ptclib/pldap.h>
#include "gk_const.h"
#include "RasTbl.h"
#include "RasPDU.h"
#include "gkauth.h"
#include "Routing.h"
#include "config.h"

const char* LDAPServerSect = "GkLDAP::Settings";
const char* LDAPAttributeSect = "GkLDAP::LDAPAttributeNames";

class LDAPBase
{
public:
	LDAPBase() : m_serverPort(0), m_authMethod(PLDAPSession::AuthSimple), m_sizelimit(1), m_startTLS(false) { }
	virtual ~LDAPBase() { }

protected:
	virtual void Init();
	virtual PLDAPSession * CreateConnection();
	virtual void DestroyConnection(PLDAPSession * session) const;

protected:
	PString m_serverName;
	unsigned m_serverPort;
	PLDAPSession::AuthenticationMethod m_authMethod;
	PTimeInterval m_timeout;
	unsigned m_sizelimit;
	PString m_baseDN;
	PString m_bindUserDN;
	PString m_bindUserPW;
	PString m_IDFilter;
	PString m_E164Filter;
	PString m_attribute;
	bool m_startTLS;
};

/// Generic LDAP authenticator for H.235 enabled endpoints
class LDAPPasswordAuth : public LDAPBase, public SimplePasswordAuth
{
public:
	LDAPPasswordAuth(const char* authName);
	virtual ~LDAPPasswordAuth() { }

protected:
	/** Override from SimplePasswordAuth.

	    @return
	    True if the password has been found for the given alias.
	*/
	virtual bool GetPassword(const PString & alias, PString & password, std::map<PString, PString> & params);

private:
	LDAPPasswordAuth();
	LDAPPasswordAuth(const LDAPPasswordAuth&);
	LDAPPasswordAuth& operator=(const LDAPPasswordAuth&);
};

/// Generic LDAP authenticator for alias/IP based authentication
class LDAPAliasAuth : public LDAPBase, public AliasAuth
{
public:
	LDAPAliasAuth(const char* authName);
	virtual ~LDAPAliasAuth() { }

protected:
	/** Get auth condition string for the given alias.
	    This implementation searches the LDAP database for the string.
	    Override from AliasAuth.

	    @return
	    The AliasAuth condition string for the given alias.
	*/
	virtual bool GetAuthConditionString(const PString & alias, PString & authCond);

private:
	LDAPAliasAuth();
	LDAPAliasAuth(const LDAPAliasAuth&);
	LDAPAliasAuth& operator=(const LDAPAliasAuth&);
};


void LDAPBase::Init()
{
	PConfig* cfg = GkConfig();
	m_serverName = cfg->GetString(LDAPServerSect, "ServerName", "localhost");
	m_serverPort = cfg->GetInteger(LDAPServerSect, "ServerPort", 389);
    PCaselessString mode = cfg->GetString(LDAPServerSect, "BindAuthMode", "simple");
	m_authMethod = PLDAPSession::AuthSimple;
	if (mode == "sasl")
		m_authMethod = PLDAPSession::AuthSASL;
	else if (mode == "kerberos")
		m_authMethod = PLDAPSession::AuthKerberos;
	m_timeout = cfg->GetInteger(LDAPServerSect, "timelimit", 30) * 1000;
	m_sizelimit = cfg->GetInteger(LDAPServerSect, "sizelimit", 1);
	m_baseDN = cfg->GetString(LDAPServerSect, "SearchBaseDN", "");
	m_bindUserDN = cfg->GetString(LDAPServerSect, "BindUserDN", "");
	m_bindUserPW = cfg->GetString(LDAPServerSect, "BindUserPW", "");
	m_IDFilter = cfg->GetString(LDAPAttributeSect, "H323ID", "mail") + "=";
	m_E164Filter = cfg->GetString(LDAPAttributeSect, "TelephonNo", "telephoneNumber") + "=";
#ifdef hasLDAPStartTLS
	m_startTLS = GkConfig()->GetBoolean(LDAPServerSect, "StartTLS", false);
#endif
}

PLDAPSession * LDAPBase::CreateConnection()
{
	PLDAPSession * session = new PLDAPSession();
	if (!session->Open(m_serverName, m_serverPort)) {
		PTRACE(1, "LDAP\tCan't connect to LDAP server " << m_serverName << ":" << m_serverPort);
		delete session;
		return NULL;
	}
	if (m_startTLS) {
#ifdef hasLDAPStartTLS
		if (!session->StartTLS()) {
			PTRACE(1, "LDAP\tStartTLS failed");
			return NULL;
		}
#else
		PTRACE(1, "LDAP\tError: LDAP StartTLS not supported in this version");
#endif
	}
	if (m_timeout > 0)
		session->SetTimeout(m_timeout);	// TODO: if we set timeout=0, default timeout 30 of LDAPSession class remains, error if we set 0
	if (m_sizelimit > 0)
		session->SetSearchLimit(m_sizelimit);
	session->SetBaseDN(m_baseDN);
	if (!m_bindUserDN.IsEmpty())
		session->Bind(m_bindUserDN, m_bindUserPW, m_authMethod);
	return session;
}

void LDAPBase::DestroyConnection(PLDAPSession * session) const
{
	session->Close();
	delete session;
}


LDAPPasswordAuth::LDAPPasswordAuth(const char* authName)
	: SimplePasswordAuth(authName)
{
	Init();
	m_attribute = GetConfig()->GetString(LDAPAttributeSect, "H235PassWord", "plaintextPassword");
}

bool LDAPPasswordAuth::GetPassword(const PString & alias, PString & password, std::map<PString, PString> & params)
{
	PLDAPSession * ldapClient = CreateConnection();
	if (!ldapClient)
		return false;
	PList<PStringToString> data = ldapClient->Search(m_IDFilter + alias, m_attribute);
    if (data.IsEmpty()) {
		data = ldapClient->Search(m_E164Filter + alias, m_attribute);
		if (data.IsEmpty()) {
			PTRACE(2, "LDAP\tCan't find password for " << alias << ": " << ldapClient->GetErrorText());
			DestroyConnection(ldapClient);
			return false;
		} else {
			if (data.front().Contains(m_attribute))
				password = data.front()[m_attribute];
		}
	} else {
		if (data.front().Contains(m_attribute))
			password = data.front()[m_attribute];
	}
	DestroyConnection(ldapClient);
	return (!password.IsEmpty());
}


LDAPAliasAuth::LDAPAliasAuth(const char* authName)
	: AliasAuth(authName)
{
	Init();
	m_attribute = GetConfig()->GetString(LDAPAttributeSect, "IPAddress", "voIPIpAddress");
}

bool LDAPAliasAuth::GetAuthConditionString(const PString & alias, PString & authCond)
{
	PLDAPSession * ldapClient = CreateConnection();
	if (!ldapClient)
		return false;
	PList<PStringToString> data = ldapClient->Search(m_IDFilter + alias, m_attribute);
    if (data.IsEmpty()) {
		data = ldapClient->Search(m_E164Filter + alias, m_attribute);
	    if (data.IsEmpty()) {
			PTRACE(2, "LDAP\tCan't find auth rule for " << alias << ": " << ldapClient->GetErrorText());
			DestroyConnection(ldapClient);
			return false;
		}
	}
	if (data.front().Contains(m_attribute)) {
		PString ip = data.front()[m_attribute];
		if (ip.Find('.') == P_MAX_INDEX) {
			// add default port if none specified
			authCond = "sigip:" + ip + ":" + PString(GK_DEF_ENDPOINT_SIGNAL_PORT);
		} else {
			authCond = "sigip:" + ip;
		}
	}
	DestroyConnection(ldapClient);
	return (!authCond.IsEmpty());
}

// a routing policy to look up the destination from an LDAP server
class LDAPPolicy : public LDAPBase, public Routing::AliasesPolicy
{
public:
	LDAPPolicy();
protected:
	virtual bool FindByAliases(Routing::RoutingRequest &, H225_ArrayOf_AliasAddress &);
	virtual bool FindByAliases(Routing::LocationRequest &, H225_ArrayOf_AliasAddress &);
};

LDAPPolicy::LDAPPolicy()
{
	m_name = "LDAP";
	Init();
	m_attribute = GkConfig()->GetString(LDAPAttributeSect, "CallDestination", "voIPIpAddress");
}

bool LDAPPolicy::FindByAliases(Routing::RoutingRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	bool routed = false;
	PLDAPSession * ldapClient = CreateConnection();
	if (!ldapClient)
		return false;
	for (PINDEX i = 0; i < aliases.GetSize(); ++i) {
		H225_AliasAddress & alias = aliases[i];
		PList<PStringToString> data;
		if (alias.GetTag() == H225_AliasAddress::e_dialedDigits) {
			data = ldapClient->Search(m_E164Filter + AsString(alias, false), m_attribute);
		} else {
			data = ldapClient->Search(m_IDFilter + AsString(alias, false), m_attribute);
		}
		if (!data.IsEmpty()) {
			if (data.front().Contains(m_attribute)) {
				PString destinationIp = data.front()[m_attribute];
				if (IsIPAddress(destinationIp)) {
					PStringArray adr_parts = destinationIp.Tokenise(":", FALSE);
					PIPSocket::Address ip(adr_parts[0]);
					WORD port = (WORD)(adr_parts[1].AsInteger());
					if (port == 0)
						port = GK_DEF_ENDPOINT_SIGNAL_PORT;
					Routing::Route route(m_name, SocketToH225TransportAddr(ip, port));
					route.m_destEndpoint = RegistrationTable::Instance()->FindByAliases(aliases);
					request.AddRoute(route);
					routed = true;
				} else {
					PTRACE(1, "Invalid IP for LDAP routing in " << m_attribute);
					// TODO: also allow routing to a new alias ?
				}
			}
		}
	}
	DestroyConnection(ldapClient);
	return routed;
}

bool LDAPPolicy::FindByAliases(Routing::LocationRequest & request, H225_ArrayOf_AliasAddress & aliases)
{
	return FindByAliases((Routing::RoutingRequest&)request, aliases);
}

namespace { // anonymous namespace
	// instantiate auth policies
	GkAuthCreator<LDAPPasswordAuth> LDAPPasswordAuthCreator("LDAPPasswordAuth");
	GkAuthCreator<LDAPAliasAuth> LDAPAliasAuthCreator("LDAPAliasAuth");
	// instatiate routing policy
	SimpleCreator<LDAPPolicy> LDAPPolicyCreator("ldap");
} // end of anonymous namespace

#endif

