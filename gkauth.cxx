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

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include "gkauth.h"
#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "RasTbl.h"
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

private:
	/** @returns the value for a given alias from section #RasSrv::RRQAuth# 
	    in ini-file
	 */
	virtual PString getConfigString(const PString &alias) const;
};

static GkAuthInit<AliasAuth> _AA_("AliasAuth");


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

#ifdef P_SSL
	H235AuthProcedure1 authProcedure1;
#endif

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

class RadiusAuth : public SimplePasswordAuth {
public:
	RadiusAuth(PConfig *, const char *);
// TODO
};

// LDAP authentification
#if defined(HAS_LDAP)		// shall use LDAP

#include "gkldap.h"

class LDAPPasswordAuth : public SimplePasswordAuth {
public:
  LDAPPasswordAuth(PConfig *, const char *);
  virtual ~LDAPPasswordAuth();

  virtual PString GetPassword(PString &alias);
  
  virtual int Check(const H225_RegistrationRequest & rrq, unsigned & reason);
};

// ISO 14882:1998 (C++), ISO9899:1999 (C), ISO9945-1:1996 (POSIX) have a
// very clear oppinion regarding user symbols starting or ending with '_'
static GkAuthInit<LDAPPasswordAuth> L_P_A("LDAPPasswordAuth");

class LDAPAliasAuth : public AliasAuth {
public:
	LDAPAliasAuth(PConfig *, const char *);
	virtual ~LDAPAliasAuth();
	
	virtual int Check(const H225_RegistrationRequest & rrq, unsigned &);

private:
	/** Searchs for an alias in LDAP and converts it to a valid config
	    string (the expected return value from LDAP is only an IP-address!).
	    @returns config-string (format: see description in ini-file)
	 */
	virtual PString getConfigString(const PString &alias) const;
};

static GkAuthInit<LDAPAliasAuth> L_A_A ("LDAPAliasAuth");

#endif // HAS_LDAP

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
#ifdef P_SSL
		}else if(tokens[i].GetTag() == H225_CryptoH323Token::e_nestedcryptoToken){
			H235_CryptoToken & nestedCryptoToken = tokens[i];
			H235_CryptoToken_cryptoHashedToken & cryptoHashedToken = nestedCryptoToken;
			H235_ClearToken & clearToken = cryptoHashedToken.m_hashedVals;
			PString gk_id = clearToken.m_generalID;
			//assumption: sendersID == endpoint alias (RRQ)
			PString ep_alias = clearToken.m_sendersID; 
			if (aliases && !CheckAliases(ep_alias))
				return false;
			iterator Iter = passwdCache.find(ep_alias);
			PString passwd = (Iter == passwdCache.end()) ? GetPassword(ep_alias) : Iter->second;
			//if a password is not found: senderID == endpointIdentifier?
			if (passwd.IsEmpty()){
			 	//get endpoint by endpointIdentifier
				H225_EndpointIdentifier ep_id;
				ep_id = clearToken.m_sendersID;
				endptr ep = RegistrationTable::Instance()->FindByEndpointId(ep_id);
				if(!ep){
					return false;
				}
				//check all endpoint aliases for a password
				H225_ArrayOf_AliasAddress ep_aliases = ep->GetAliases();
				for (PINDEX i = 0; i < ep_aliases.GetSize(); i++){
					ep_alias = H323GetAliasAddressString(ep_aliases[i]);
					iterator Iter = passwdCache.find(ep_alias);
					passwd = (Iter == passwdCache.end()) ? GetPassword(ep_alias) : Iter->second;
					if(!passwd.IsEmpty())
						break;
				}
			}
			authProcedure1.SetLocalId(gk_id);
			authProcedure1.SetPassword(passwd);
			if (authProcedure1.VerifyToken(tokens[i], getLastReceivedRawPDU()) == H235Authenticator::e_OK) {
				PTRACE(4, "GkAuth\t" << ep_alias << " password match (SHA-1)");
				passwdCache[ep_alias] = passwd;
				return true;
			}
#endif
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

LDAPPasswordAuth::LDAPPasswordAuth(PConfig * cfg, const char * authName)
  : SimplePasswordAuth(cfg, authName)
{
}

LDAPPasswordAuth::~LDAPPasswordAuth()
{
}

PString LDAPPasswordAuth::GetPassword(PString & alias)
{
	PStringList attr_values;
	using namespace lctn; // LDAP config tags and names
	// get pointer to new answer object
	if(GkLDAP::Instance()->getAttribute(alias, H245PassWord, attr_values) && 
	   !attr_values.IsEmpty()){
		return attr_values[0];
	}
	return "";
}  

int LDAPPasswordAuth::Check(const H225_RegistrationRequest & rrq, unsigned & reason)
{
	int result = SimplePasswordAuth::Check(rrq, reason);
	if(result == e_ok) {
		// check if all aliases in RRQ exists in LDAP entry
		const H225_ArrayOf_AliasAddress & aliases = rrq.m_terminalAlias;
		if(!GkLDAP::Instance()->validAliases(aliases)) {
			result = e_fail;
		}
	}
	return result;
}


LDAPAliasAuth::LDAPAliasAuth(PConfig *cfg, const char *authName) : AliasAuth(cfg, authName)
{
}

LDAPAliasAuth::~LDAPAliasAuth()
{
}

PString LDAPAliasAuth::getConfigString(const PString &alias) const
{
	PStringList attr_values;
	using namespace lctn; // LDAP config tags and names
	// get pointer to new answer object
	if (GkLDAP::Instance()->getAttribute(alias, IPAddress, attr_values) && (!attr_values.IsEmpty())) {
		PString ip = attr_values[0];
    		if(!ip.IsEmpty()){
      			PString port = GK_DEF_ENDPOINT_SIGNAL_PORT;    
			return "sigip:" + ip + ":" + port;
		}
	}
	return "";
}

int LDAPAliasAuth::Check(const H225_RegistrationRequest & rrq, unsigned & reason)
{
	int result = AliasAuth::Check(rrq, reason);
	if(result == e_ok) {
		// check if all aliases in RRQ exists in LDAP entry
		const H225_ArrayOf_AliasAddress & aliases = rrq.m_terminalAlias;
		if(!GkLDAP::Instance()->validAliases(aliases)) {
      			result = e_fail;
    		}
	}
  	return result;
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
		const PString cfgString = getConfigString(alias);

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

PString AliasAuth::getConfigString(const PString &alias) const {
	return config->GetString("RasSrv::RRQAuth", alias, "");
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

