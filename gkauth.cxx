//////////////////////////////////////////////////////////////////
//
// gkauth.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//      2001/09/19      initial version (Chih-Wei Huang)
//
//////////////////////////////////////////////////////////////////

#include "gkauth.h"
#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "Toolkit.h"
#include <h235auth.h>
#include <h323pdu.h>
#include <ptclib/cypher.h>

#ifdef P_SOLARIS
#define map stl_map
#endif

#include <map>
#include <list>

using std::map;
using std::list;

const char *GkAuthSectionName = "Gatekeeper::Auth";

GkAuthenticator *GkAuthenticator::head = 0;

static GkAuthInit<GkAuthenticator> _defaultGKA_("default");

//////////////////////////////////////////////////////////////////////
// Definition of authentication rules

class SimplePasswordAuth : public GkAuthenticator {
public:
	typedef std::map<PString, PString>::iterator iterator;
	typedef std::map<PString, PString>::const_iterator const_iterator;

	SimplePasswordAuth(PConfig *, const char *);

protected:
	virtual int Check(const H225_GatekeeperRequest &, unsigned &);
	virtual int Check(const H225_RegistrationRequest &, unsigned &);
	virtual int Check(const H225_UnregistrationRequest &, unsigned &);
	virtual int Check(const H225_AdmissionRequest &, unsigned &);
	virtual int Check(const H225_BandwidthRequest &, unsigned &);
	virtual int Check(const H225_DisengageRequest &, unsigned &);
	virtual int Check(const H225_LocationRequest &, unsigned &);
	virtual int Check(const H225_InfoRequest &, unsigned &);

	virtual PString GetPassword(PString &);

	virtual bool CheckAliases(const PString &);
	virtual bool CheckTokens(const H225_ArrayOf_ClearToken &);
	virtual bool CheckCryptoTokens(const H225_ArrayOf_CryptoH323Token &);

	template<class RasType> int doCheck(const RasType & req)
	{
		if (req.HasOptionalField(RasType::e_cryptoTokens))
			return CheckCryptoTokens(req.m_cryptoTokens) ? e_ok : e_fail;
	 	else if (req.HasOptionalField(RasType::e_tokens))
			return CheckTokens(req.m_tokens) ? e_ok : e_fail;
		return (controlFlag == e_Optional) ? e_next : e_fail;
	}

	map<PString, PString> passwdCache;
	int filled;
	bool checkid;

private:
	H235AuthSimpleMD5 authMD5;
	H235AuthProcedure1 authProcedure1;
	PBYTEArray nullPDU;
	const H225_ArrayOf_AliasAddress *aliases;
};

static GkAuthInit<SimplePasswordAuth> _SPA_("SimplePasswordAuth");

#ifdef HAS_MYSQL
#define MYSQL_NO_SHORT_NAMES  // use long names
#include <mysql++>

class MySQLPasswordAuth : public SimplePasswordAuth {
public:
	MySQLPasswordAuth(PConfig *, const char *);
	~MySQLPasswordAuth();

private:
	virtual PString GetPassword(PString &);
	bool MySQLInit();
	void Cleanup();

	MysqlConnection *connection;
	MysqlQuery *query;
};

static GkAuthInit<MySQLPasswordAuth> _MPA_("MySQLPasswordAuth");

#endif // HAS_MYSQL


// LDAP authentification
#if defined(HAS_LDAP)		// shall use LDAP
#include "ldaplink.h"		// link to LDAP functions

class LDAPAuth : public SimplePasswordAuth {
public:
  LDAPAuth(PConfig *, const char *);
  ~LDAPAuth();
private:
  // Data
  LDAPAttributeNamesClass AN;	// names of the LDAP attributes
  LDAPCtrl * LDAPConn;		// a HAS-A relation is prefered over a IS-A relation
				// because one can better steer the parameters
  // Methods
  void Initialize(PConfig *);
  void Destroy(void);
  virtual PString GetPassword(PString &);
};

// ISO 14882:1998 (C++), ISO9899:1999 (C), ISO9945-1:1996 (POSIX) have a
// very clear oppinion regarding user symbols starting or ending with '_'
static GkAuthInit<LDAPAuth> L_P_A("LDAPPasswordAuth");

#endif // HAS_LDAP

class RadiusAuth : public SimplePasswordAuth {
public:
	RadiusAuth(PConfig *, const char *);
// TODO
};


class AliasAuth : public GkAuthenticator {
public:
	AliasAuth(PConfig *, const char *);

protected:
	virtual int Check(const H225_GatekeeperRequest &, unsigned &);
	virtual int Check(const H225_RegistrationRequest &, unsigned &);
//	virtual int Check(const H225_UnregistrationRequest &, unsigned &);
	virtual int Check(const H225_AdmissionRequest &, unsigned &);
//	virtual int Check(const H225_BandwidthRequest &, unsigned &);
//	virtual int Check(const H225_DisengageRequest &, unsigned &);
	virtual int Check(const H225_LocationRequest &, unsigned &);
//	virtual int Check(const H225_InfoRequest &, unsigned &);

	virtual bool AuthCondition(const H225_TransportAddress &SignalAdr, const PString &);
};

static GkAuthInit<AliasAuth> _AA_("AliasAuth");

//////////////////////////////////////////////////////////////////////

GkAuthenticator::GkAuthenticator(PConfig *cfg, const char *authName) : config(cfg), name(authName), checkFlag(e_ALL)
{
	PStringArray control(config->GetString(GkAuthSectionName, name, "").Tokenise(";,"));
	if (PString(name) == "default")
		controlFlag = e_Sufficient,
		defaultStatus = Toolkit::AsBool(control[0]) ? e_ok : e_fail;
	else if (control[0] *= "optional")
		controlFlag = e_Optional, defaultStatus = e_next;
	else if (control[0] *= "required")
		controlFlag = e_Required, defaultStatus = e_fail;
	else
		controlFlag = e_Sufficient, defaultStatus = e_fail;

	if (control.GetSize() > 1) {
		checkFlag = 0;
		map<PString, int> rasmap;
		rasmap["GRQ"] = e_GRQ, rasmap["RRQ"] = e_RRQ,
		rasmap["URQ"] = e_URQ, rasmap["ARQ"] = e_ARQ,
		rasmap["BRQ"] = e_BRQ, rasmap["DRQ"] = e_DRQ,
		rasmap["LRQ"] = e_LRQ, rasmap["IRQ"] = e_IRQ;
		for (PINDEX i=1; i < control.GetSize(); ++i) {
			if (rasmap.find(control[i]) != rasmap.end())
				checkFlag |= rasmap[control[i]];
		}
	}
	
	next = head;
	head = this;

	PTRACE(1, "GkAuth\tAdd " << name << " rule with flag " << hex << checkFlag << dec);
}

GkAuthenticator::~GkAuthenticator()
{
	PTRACE(1, "GkAuth\tRemove " << name << " rule");
	delete next;  // delete whole list recursively
}

int GkAuthenticator::Check(const H225_GatekeeperRequest &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(const H225_RegistrationRequest &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(const H225_UnregistrationRequest &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(const H225_AdmissionRequest &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(const H225_BandwidthRequest &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(const H225_DisengageRequest &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(const H225_LocationRequest &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(const H225_InfoRequest &, unsigned &)
{
	return defaultStatus;
}


// SimplePasswordAuth
SimplePasswordAuth::SimplePasswordAuth(PConfig *cfg, const char *authName)
      : GkAuthenticator(cfg, authName), aliases(0)
{
	filled = config->GetInteger("Password", "KeyFilled", 0);
	checkid = Toolkit::AsBool(config->GetString("Password", "CkeckID", "0"));
}

int SimplePasswordAuth::Check(const H225_GatekeeperRequest & grq, unsigned &)
{
	return doCheck(grq);
}

int SimplePasswordAuth::Check(const H225_RegistrationRequest & rrq, unsigned &)
{
	if (checkid) {
		if (!rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
			return e_fail;
		aliases = &rrq.m_terminalAlias;
	}
	return doCheck(rrq);
}

int SimplePasswordAuth::Check(const H225_UnregistrationRequest & urq, unsigned &)
{
	return doCheck(urq);
}

int SimplePasswordAuth::Check(const H225_AdmissionRequest & arq, unsigned &)
{
	return doCheck(arq);
}

int SimplePasswordAuth::Check(const H225_BandwidthRequest & brq, unsigned &)
{
	return doCheck(brq);
}

int SimplePasswordAuth::Check(const H225_DisengageRequest & drq, unsigned &)
{
	return doCheck(drq);
}

int SimplePasswordAuth::Check(const H225_LocationRequest & lrq, unsigned &)
{
	return doCheck(lrq);
}

int SimplePasswordAuth::Check(const H225_InfoRequest & drq, unsigned &)
{
	return doCheck(drq);
}

PString SimplePasswordAuth::GetPassword(PString & id)
{
	PTEACypher::Key key;
	memset(&key, filled, sizeof(PTEACypher::Key));
	memcpy(&key, id.GetPointer(), std::min(sizeof(PTEACypher::Key), (size_t)id.GetLength()));
       	PTEACypher cypher(key);
	return cypher.Decode(config->GetString("Password", id, ""));
}

bool SimplePasswordAuth::CheckAliases(const PString & id)
{
	bool r = false;
	for (PINDEX i = 0; i < aliases->GetSize(); i++)
		if (H323GetAliasAddressString((*aliases)[i]) == id) {
			r = true;
			break;
		}
	aliases = 0;
	return r;
}

bool SimplePasswordAuth::CheckTokens(const H225_ArrayOf_ClearToken & tokens)
{
	for (PINDEX i=0; i < tokens.GetSize(); ++i) {
		H235_ClearToken & token = tokens[i];
		if (token.HasOptionalField(H235_ClearToken::e_generalID) &&
		    token.HasOptionalField(H235_ClearToken::e_password)) {
			PString id = token.m_generalID;
			if (aliases && !CheckAliases(id))
				return false;
			PString passwd = token.m_password;
			iterator Iter = passwdCache.find(id);
			if (Iter != passwdCache.end() && Iter->second == passwd) {
				PTRACE(5, "GkAuth\t cache " << id << " found and match");
				return true;
			}
			if (GetPassword(id) == passwd) {
				PTRACE(4, "GkAuth\t" << id << " password match");
				passwdCache[id] = passwd;
				return true;
			}
		}
	}
	return false;
}

bool SimplePasswordAuth::CheckCryptoTokens(const H225_ArrayOf_CryptoH323Token & tokens)
{
	for (PINDEX i=0; i < tokens.GetSize(); ++i){
		if (tokens[i].GetTag() == H225_CryptoH323Token::e_cryptoEPPwdHash) {
			H225_CryptoH323Token_cryptoEPPwdHash & pwdhash = tokens[i];
			PString id = AsString(pwdhash.m_alias, FALSE);
			if (aliases && !CheckAliases(id))
				return false;
			iterator Iter = passwdCache.find(id);
			PString passwd = (Iter == passwdCache.end()) ? GetPassword(id) : Iter->second;
			authMD5.SetLocalId(id);
			authMD5.SetPassword(passwd);
			if (authMD5.VerifyToken(tokens[i], nullPDU) == H235Authenticator::e_OK) {
				PTRACE(4, "GkAuth\t" << id << " password match (MD5)");
				passwdCache[id] = passwd;
				return true;
			}
		}else if(tokens[i].GetTag() == H225_CryptoH323Token::e_nestedcryptoToken){
			H235_CryptoToken & nestedCryptoToken = tokens[i];
			H235_CryptoToken_cryptoHashedToken & cryptoHashedToken = nestedCryptoToken;
			H235_ClearToken & clearToken = cryptoHashedToken.m_hashedVals;
			PString gk_id = clearToken.m_generalID;
			PString id = clearToken.m_sendersID;
			if (aliases && !CheckAliases(id))
				return false;
			iterator Iter = passwdCache.find(id);
			PString passwd = (Iter == passwdCache.end()) ? GetPassword(id) : Iter->second;
			authProcedure1.SetLocalId(gk_id);
			authProcedure1.SetPassword(passwd);
			if (authProcedure1.VerifyToken(tokens[i], getLastReceivedRawPDU()) == H235Authenticator::e_OK) {
				PTRACE(4, "GkAuth\t" << id << " password match (SHA-1)");
				passwdCache[id] = passwd;
				return true;
			}
		}
	}
	return false;
}


#ifdef HAS_MYSQL

const char *mysqlsec = "MySQLAuth";

// MysqlPasswordAuth
MySQLPasswordAuth::MySQLPasswordAuth(PConfig *cfg, const char *authName)
	: SimplePasswordAuth(cfg, authName), connection(0), query(0)
{
	MySQLInit();
}

MySQLPasswordAuth::~MySQLPasswordAuth()
{
	Cleanup();
}

void MySQLPasswordAuth::Cleanup()
{
	delete query;
	query = 0;
	delete connection;
	connection = 0; // disable the authenticator
}

bool MySQLPasswordAuth::MySQLInit()
{
	try {
		PString host = config->GetString(mysqlsec, "Host", "localhost");
		PString dbname = config->GetString(mysqlsec, "Database", "billing");
		PString user = config->GetString(mysqlsec, "User", "cwhuang");
		PString passwd = config->GetString(mysqlsec, "Password", "123456");

		PString table = config->GetString(mysqlsec, "Table", "customer");
		PString id_field = config->GetString(mysqlsec, "IDField", "IPN");
		PString passwd_field = config->GetString(mysqlsec, "PasswordField", "Password");
		PString check_field = config->GetString(mysqlsec, "CheckEnableField", "");

		connection = new MysqlConnection(mysql_use_exceptions);
		connection->connect(dbname, host, user, passwd);

		PTRACE(2, "MySQL\tConnect to server " << host << ", database " << dbname);
		query = new MysqlQuery(connection, true);
		PString selectString(PString::Printf,
			"select %s from %s where %s = '%%0:id'",
			(const char *)passwd_field,
			(const char *)table,
			(const char *)id_field
		);
		if (!check_field)
			selectString += " and " + check_field + " = 1";
		PTRACE(3, "MySQL\t" << selectString);

		*query << selectString;
		query->parse();
		PTRACE(1, "MySQL\tReady for query");
		return true;
	} catch (MysqlBadQuery er) { // any error?
		PTRACE(1, "MySQL\tError: " << er.error);
		Cleanup();
		return false;
	}
}

PString MySQLPasswordAuth::GetPassword(PString & id)
{
	PString passwd;
	if (connection || MySQLInit()) {
		try {
			MysqlRes res = query->store(SQLString(id));
			if (!res.empty())
				passwd = (*res.begin())[0].c_str();
		} catch (MysqlBadQuery er) {
			PTRACE(1, "MySQL\tBadQuery: " << er.error);
			Cleanup();
		} catch (MysqlBadConversion er) {
			PTRACE(1,  "MySQL\tBadConversion: Tried to convert \"" << er.data << "\" to a \"" << er.type_name << "\".");
		} 
	}
	return passwd;
}

#endif // HAS_MYSQL

// LDAP authentification
#if defined(HAS_LDAP)

// init file section name
const char *ldap_attr_name_sec = "LDAPAuth::LDAPAttributeNames";
const char *ldap_auth_sec = "LDAPAuth::Settings";

// constructor
LDAPAuth::LDAPAuth(PConfig * cfg, const char * authName)
  : SimplePasswordAuth(cfg, authName)
{
  Initialize(cfg);
} // LDAPAuth constructor

// constructor
LDAPAuth::~LDAPAuth()
{
  Destroy();
} // LDAPAuth destructor


void 
LDAPAuth::Initialize(PConfig * cfg) // 'real', private constructor
{
  struct timeval default_timeout;
  default_timeout.tv_sec = 10l;	// seconds
  default_timeout.tv_usec = 0l;	// micro seconds
  using namespace lctn;		// LDAP config tags and names
  // The defaults are given by the constructor of LDAPAttributeNamesClass
  AN.insert(LDAPANValuePair(LDAPAttrTags[UserIdentity], 
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[UserIdentity],
					      "uid"))); // 0.9.2342.19200300.100.1.1
  AN.insert(LDAPANValuePair(LDAPAttrTags[H323ID],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[H323ID],
					      "cn"))); // 2.5.4.3
  AN.insert(LDAPANValuePair(LDAPAttrTags[TelephonNo],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[TelephonNo],
					      "telephoneNumber"))); // 2.5.4.20
  AN.insert(LDAPANValuePair(LDAPAttrTags[H245PassWord],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[H245PassWord],
					      "plaintextPassword")));	// ...9564.2.1.1.8
  AN.insert(LDAPANValuePair(LDAPAttrTags[aliasH323ID],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[aliasH323ID],
					      "voIPnickName"))); // ...9564.2.5.1000
  AN.insert(LDAPANValuePair(LDAPAttrTags[CountryCode],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[CountryCode],
					      "voIPcountryCode"))); // ...9564.2.5.2000
  AN.insert(LDAPANValuePair(LDAPAttrTags[AreaCode],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[AreaCode],
					      "voIPareaCode"))); // ...9564.2.5.2010
  AN.insert(LDAPANValuePair(LDAPAttrTags[LocalAccessCode],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[LocalAccessCode],
					      "voIPlocalAccessCode"))); // ...9564.2.5.2020
  AN.insert(LDAPANValuePair(LDAPAttrTags[NationalAccessCode],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[NationalAccessCode],
					      // ...9564.2.5.2030
					      "voIPnationalAccessCode")));
  AN.insert(LDAPANValuePair(LDAPAttrTags[InternationalAccessCode],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[InternationalAccessCode],
					       // ...9564.2.5.2040
					      "voIPinternationalAccessCode")));
  AN.insert(LDAPANValuePair(LDAPAttrTags[CallingLineIdPresentation],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[CallingLineIdPresentation],
					      "voIPcallingLineIdPresentation"))); // ...2050
  AN.insert(LDAPANValuePair(LDAPAttrTags[PrefixBlacklist],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[PrefixBlacklist],
					      "voIPprefixBlacklist"))); // ...9564.2.5.2060
  AN.insert(LDAPANValuePair(LDAPAttrTags[PrefixWhitelist],
			    config->GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[PrefixWhitelist],
					      "voIPprefixWhitelist"))); // ...9564.2.5.2070

  PString ServerName = config->GetString(ldap_auth_sec, "ServerName", "ldap");
  int ServerPort = config->GetString(ldap_auth_sec, "ServerPort", "389").AsInteger();
  PString SearchBaseDN = config->GetString(ldap_auth_sec, "SearchBaseDN", 
					   "o=University of Michigan, c=US");
  PString BindUserDN = config->GetString(ldap_auth_sec, "BindUserDN", 
					 "cn=Babs Jensen,o=University of Michigan, c=US");
  PString BindUserPW = config->GetString(ldap_auth_sec, "BindUserPW", "RealySecretPassword");
  unsigned int sizelimit = config->GetString(ldap_auth_sec, "sizelimit", "0").AsUnsigned();
  unsigned int timelimit = config->GetString(ldap_auth_sec, "timelimit", "0").AsUnsigned();

  LDAPConn = new LDAPCtrl(&AN, &default_timeout, ServerName, 
			  SearchBaseDN, BindUserDN, BindUserPW, 
			  sizelimit, timelimit, ServerPort);

} // Initialize

void
LDAPAuth::Destroy()		// 'real', private destructor
{
  delete LDAPConn;
} // Destroy

PString LDAPAuth::GetPassword(PString & id)
{
  LDAPQuery q;			// using query class to make interface flexible
  q.userH323ID = id;
  using namespace lctn;
  // FIXME: (?) always take first value for the H245PassWord attribute
  return (LDAPConn->DirectoryUserLookup(q)->AV[LDAPAttrTags[H245PassWord]])[0]; 
}

#endif // HAS_LDAP

// AliasAuth
AliasAuth::AliasAuth(PConfig *cfg, const char *authName) : GkAuthenticator(cfg, authName)
{
}

int AliasAuth::Check(const H225_GatekeeperRequest &, unsigned &)
{
	return e_next;
}

int AliasAuth::Check(const H225_RegistrationRequest & rrq, unsigned &)
{
	bool AliasFoundInConfig = false;

	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
		return defaultStatus;

	const H225_ArrayOf_AliasAddress & NewAliases = rrq.m_terminalAlias;

	// alias is the config file entry of this endpoint
	for (PINDEX i=0; !AliasFoundInConfig && i < NewAliases.GetSize(); ++i) {
		PString alias = AsString(NewAliases[i], FALSE);
		const PString cfgString = config->GetString("RasSrv::RRQAuth", alias, "");

		if (cfgString != "") {
			const PStringArray conditions = cfgString.Tokenise("&", FALSE);

			for (PINDEX iCnd = 0; iCnd < conditions.GetSize(); ++iCnd) {

				if (!AuthCondition(rrq.m_callSignalAddress[0], conditions[iCnd])) {
					PTRACE(4, "Gk\tRRQAuth condition '" << conditions[iCnd] << "' rejected endpoint " << alias);
					return e_fail;
				} else {
					AliasFoundInConfig = true;
					PTRACE(5, "Gk\tRRQAuth condition applied successfully for endpoint " << alias);
				}
			}
		}
	}
	return (AliasFoundInConfig) ? e_ok : defaultStatus;
}

int AliasAuth::Check(const H225_AdmissionRequest &, unsigned &)
{
	return e_next;
}

int AliasAuth::Check(const H225_LocationRequest &, unsigned &)
{
	return e_next;
}

bool AliasAuth::AuthCondition(const H225_TransportAddress & SignalAdr, const PString & Condition)
{
	const bool ON_ERROR = true; // return value on parse error in condition

	const PStringArray rule = Condition.Tokenise(":", FALSE);
	if(rule.GetSize() < 1) {
		PTRACE(1, "Errornous RRQAuth rule: " << Condition);
		return ON_ERROR;
	}
	
	// 
	// condition = rule[0]:rule[1]... = rName:params...
	//
	
	const PString &rName = rule[0];

 	if (rName=="confirm" || rName=="allow") {
 		return true;
 	}
 	else if (rName=="reject" || rName=="deny" || rName=="forbid") {
 		return false;
 	}
	//
	// condition 'sigaddr' example:
	//   sigaddr:.*ipAddress .* ip = .* c3 47 e2 a2 .*port = 1720.*
	//
	else if(rName=="sigaddr") {
		if( rule.GetSize() < 2)
			return false;
		return Toolkit::MatchRegex(AsString(SignalAdr), rule[1]) != 0;
	}
	//
	// condition 'sigip' example:
	//   sigip:195.71.129.69:1720
	//
	else if(rName=="sigip") {
		if (rule.GetSize() < 2)
			return false;
		PIPSocket::Address ip;
		PIPSocket::GetHostAddress(rule[1], ip);
		WORD port = (rule.GetSize() < 3) ? GK_DEF_ENDPOINT_SIGNAL_PORT : rule[2].AsInteger();
		return (SignalAdr == SocketToH225TransportAddr(ip, port));
	} else {
		PTRACE(4, "Unknown RRQAuth condition: " << Condition);
		return ON_ERROR;
	}

	// not reached...
	return false;
}

static list<GkAuthInitializer *> *AuthNameList;

GkAuthInitializer::GkAuthInitializer(const char *n) : name(n)
{
	static list<GkAuthInitializer *> aList;
	AuthNameList = &aList;

	AuthNameList->push_back(this);
}

GkAuthInitializer::~GkAuthInitializer()
{
}

bool GkAuthInitializer::Compare(PString n) const
{
	return n == name;
}

GkAuthenticatorList::GkAuthenticatorList(PConfig *cfg)
{
	PStringList authList(cfg->GetKeys(GkAuthSectionName));

	for (PINDEX i=authList.GetSize(); i-- > 0; ) {
		PString authName(authList[i]);
		std::list<GkAuthInitializer *>::iterator Iter =
			find_if(AuthNameList->begin(), AuthNameList->end(),
				bind2nd(mem_fun(&GkAuthInitializer::Compare), authName));
		if (Iter != AuthNameList->end())
			(*Iter)->CreateAuthenticator(cfg);
#ifdef PTRACING
		else
			PTRACE(1, "GkAuth\tUnknown auth " << authName << ", ignore!");
#endif
	}
}

GkAuthenticatorList::~GkAuthenticatorList()
{
	delete GkAuthenticator::head;
	GkAuthenticator::head = 0;
}

