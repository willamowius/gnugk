// -*- mode: c++; eval: (c-set-style "linux"); -*-
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

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = GKAUTH_H;
#endif /* lint */

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
	virtual PString GetConfigString(const PString &alias) const;
};

static GkAuthInit<AliasAuth> A_A("AliasAuth");
#ifdef HAS_MYSQL

class MySQLAuthBase;

class MySQLPasswordAuth : public SimplePasswordAuth {
public:
       MySQLPasswordAuth(PConfig *, const char *);
       ~MySQLPasswordAuth();

 private:
	virtual PString GetPassword(const PString &);

	MySQLAuthBase *mysqlconn;
};

static GkAuthInit<MySQLPasswordAuth> M_P_A("MySQLPasswordAuth");

class MySQLAliasAuth : public AliasAuth {
public:
	MySQLAliasAuth(PConfig *, const char *);
	~MySQLAliasAuth();

private:
	virtual PString GetConfigString(const PString & alias) const;

	MySQLAuthBase *mysqlconn;
	CacheManager *cache;
};

static GkAuthInit<MySQLAliasAuth> M_A_A("MySQLAliasAuth");

#endif // HAS_MYSQL

#if ((defined(__GNUC__) && __GNUC__ <= 2) && !defined(WIN32))
#include <unistd.h>
#if defined(__GNUG__)
#include <procbuf.h>		// this is a obscure GNU extension
#endif

class ExternalPasswordAuth : public SimplePasswordAuth {
public:
       ExternalPasswordAuth(PConfig *, const char *);

       virtual PString GetPassword(const PString &);
private:
       bool ExternalInit();

       PString Program;
};

static GkAuthInit<ExternalPasswordAuth> E_P_A("ExternalPasswordAuth");

#endif

class RadiusAuth : public SimplePasswordAuth {
public:
	RadiusAuth(PConfig *,  const char *);
// TODO
};

class DBPasswordAuth : public SimplePasswordAuth {
public:
  DBPasswordAuth(PConfig *, const char *);
  virtual ~DBPasswordAuth();

  virtual PString GetPassword(const PString &alias);

  virtual int Check(const H225_RegistrationRequest & rrq, unsigned & reason);
};

// ISO 14882:1998 (C++), ISO9899:1999 (C), ISO9945-1:1996 (POSIX) have a
// very clear oppinion regarding user symbols starting or ending with '_'
static GkAuthInit<DBPasswordAuth> L_P_A("DBPasswordAuth");

class DBAliasAuth : public AliasAuth {
public:
	DBAliasAuth(PConfig *, const char *);
	virtual ~DBAliasAuth();

	virtual int Check(const H225_RegistrationRequest & rrq, unsigned &);

private:
	/** Searchs for an alias in DB and converts it to a valid config
	    string (the expected return value from DB is only an IP-address!).
	    @returns config-string (format: see description in ini-file)
	 */
	virtual PString GetConfigString(const PString &alias) const;
};

static GkAuthInit<DBAliasAuth> L_A_A ("DBAliasAuth");

// Initial author: Michael Rubashenkkov  2002/01/14 (GkAuthorize)
// Completely rewrite by Chih-Wei Huang  2002/05/01
class AuthObj;
class AuthRule;
class PrefixAuth : public GkAuthenticator {
public:
	PrefixAuth(PConfig *, const char *);
	~PrefixAuth();

	typedef std::map< PString, AuthRule *, greater<PString> > Rules;

private:
	virtual int Check(const H225_GatekeeperRequest &, unsigned &);
	virtual int Check(const H225_RegistrationRequest &, unsigned &);
	virtual int Check(const H225_UnregistrationRequest &, unsigned &);
	virtual int Check(const H225_AdmissionRequest &, unsigned &);
	virtual int Check(const H225_BandwidthRequest &, unsigned &);
	virtual int Check(const H225_DisengageRequest &, unsigned &);
	virtual int Check(const H225_LocationRequest &, unsigned &);
	virtual int Check(const H225_InfoRequest &, unsigned &);

	virtual int doCheck(const AuthObj &);

	Rules prefrules;
};

static GkAuthInit<PrefixAuth> PF_A("PrefixAuth");


class CacheManager {
public:
	CacheManager(int t) : ttl(t) {}

	bool Retrieve(const PString & key, PString & value);
	void Save(const PString & key, const PString & value);

private:
	map<PString, PString> cache;
	map<PString, PTime> ctime;
	// 0 means don't cache, -1 means never expires
	int ttl; // miliseconds

	CacheManager(const CacheManager &);
	CacheManager & operator=(const CacheManager &);
};

bool CacheManager::Retrieve(const PString & key, PString & value)
{
	std::map<PString, PString>::iterator iter = cache.find(key);
	if (iter == cache.end())
		return false;
	if (ttl > 0) {
		std::map<PString, PTime>::iterator i = ctime.find(key);
		if ((PTime() - i->second) > ttl)
			return false; // cache expired
	}
	value = iter->second;
	PTRACE(5, "GkAuth\tCache found for " << key << " value: " << value);
	return true;
}

void CacheManager::Save(const PString & key, const PString & value)
{
	if (ttl != 0) {
		cache[key] = value;
		ctime[key] = PTime();
	}
}

//////////////////////////////////////////////////////////////////////

GkAuthenticator::GkAuthenticator(PConfig *cfg, const char *authName) : config(cfg), name(authName), checkFlag(e_ALL)
{
	PStringArray control(config->GetString(GkAuthSectionName, name, "").Tokenise(";,"));
	if (PString(name) == "default")
		controlFlag = e_Sufficient,
		defaultStatus = Toolkit::AsBool(control[0]) ? e_ok : e_fail;
	else if (control[0] *= "optional")
		controlFlag = e_Optional, defaultStatus = e_next;
	else if (control[0] *= "alternative")
		controlFlag = e_Alternative, defaultStatus = e_next;
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
	deleteMutex.Wait();
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

static GkAuthInit<SimplePasswordAuth> S_P_A("SimplePasswordAuth");

const char *passwdsec = "Password";


// SimplePasswordAuth
SimplePasswordAuth::SimplePasswordAuth(PConfig *cfg, const char *authName)
      : GkAuthenticator(cfg, authName), aliases(0)
{
	filled = config->GetInteger(passwdsec, "KeyFilled", 0);
	checkid = Toolkit::AsBool(config->GetString(passwdsec, "CkeckID", "0"));
	cache = new CacheManager(config->GetInteger(passwdsec, "PasswordTimeout", -1) * 1000);
}

SimplePasswordAuth::~SimplePasswordAuth()
{
	deleteMutex.Wait();
	delete cache;
}


int SimplePasswordAuth::Check(const H225_GatekeeperRequest & grq, unsigned &)
{
	PWaitAndSignal lock(deleteMutex);
	return doCheck(grq);
}

int SimplePasswordAuth::Check(const H225_RegistrationRequest & rrq, unsigned &)
{
	PWaitAndSignal lock(deleteMutex);
	m_aliasesChecked = checkid ? FALSE : TRUE;
	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
		return e_fail;
	aliases = &rrq.m_terminalAlias;
	return doCheck(rrq);
}

int SimplePasswordAuth::Check(const H225_UnregistrationRequest & urq, unsigned &)
{
	PWaitAndSignal lock(deleteMutex);
	return doCheck(urq);
}

int SimplePasswordAuth::Check(const H225_AdmissionRequest & arq, unsigned &)
{
	PWaitAndSignal lock(deleteMutex);
	return doCheck(arq);
}

int SimplePasswordAuth::Check(const H225_BandwidthRequest & brq, unsigned &)
{
	PWaitAndSignal lock(deleteMutex);
	return doCheck(brq);
}

int SimplePasswordAuth::Check(const H225_DisengageRequest & drq, unsigned &)
{
	PWaitAndSignal lock(deleteMutex);
	return doCheck(drq);
}

int SimplePasswordAuth::Check(const H225_LocationRequest & lrq, unsigned &)
{
	PWaitAndSignal lock(deleteMutex);
	return doCheck(lrq);
}

int SimplePasswordAuth::Check(const H225_InfoRequest & drq, unsigned &)
{
	PWaitAndSignal lock(deleteMutex);
	return doCheck(drq);
}

PString SimplePasswordAuth::GetPassword(const PString & id)
{
	PTEACypher::Key key;
	memset(&key, filled, sizeof(PTEACypher::Key));
	memcpy(&key, (const char *)id, std::min(sizeof(PTEACypher::Key), (size_t)id.GetLength()));
       	PTEACypher cypher(key);
	return cypher.Decode(config->GetString(passwdsec, id, ""));
}

bool SimplePasswordAuth::CheckAliases(const PString & id)
{
	bool r = false;
	for (PINDEX i = 0; i < aliases->GetSize(); i++)
		if (H323GetAliasAddressString((*aliases)[i]) == id) {
			r = true;
			break;
		}
	m_aliasesChecked = TRUE;
	return r;
}

bool SimplePasswordAuth::CheckTokens(const H225_ArrayOf_ClearToken & tokens)
{
	for (PINDEX i=0; i < tokens.GetSize(); ++i) {
		H235_ClearToken & token = tokens[i];
		if (token.HasOptionalField(H235_ClearToken::e_generalID) &&
		    token.HasOptionalField(H235_ClearToken::e_password)) {
			PString id = token.m_generalID;
			if (!m_aliasesChecked && !CheckAliases(id)) {
				return false;
			}
			PString passwd = GetPassword(id);
			PString tokenpasswd = token.m_password;
			if (passwd == tokenpasswd) {
                                PTRACE(4, "GkAuth\t" << id << " password match");
				return true;
			}
		}
	}
	return false;
}

PString SimplePasswordAuth::GetPassword(PString & tokenAlias, const H225_ArrayOf_AliasAddress & moreAliases, BOOL checkTokenAlias = TRUE)
{
	PString passwd = "";
	bool found;
	// first check tokenAlias
	if (checkTokenAlias) {
		found = cache->Retrieve(tokenAlias,passwd);
		if(!found) {
			passwd = GetPassword(tokenAlias);
			cache->Save(tokenAlias, passwd);
		}
	}
	if (passwd.IsEmpty() && moreAliases.GetSize() > 0) {
		// check all aliases which are not equal to tokenAlias
		PString alias;
		for (PINDEX i = 0; i < moreAliases.GetSize() && passwd.IsEmpty(); i++){
			alias = H323GetAliasAddressString(moreAliases[i]);
			if (alias != tokenAlias) {
				found = cache->Retrieve(alias,passwd);
				if (!found) {
					passwd = GetPassword(alias);
					cache->Save(alias, passwd);
				}
			}
		}
	}
	//if a password is not found: senderID == endpointIdentifier?
	if (passwd.IsEmpty()){
		 //get endpoint by endpointIdentifier
		H225_EndpointIdentifier epID;
		epID = tokenAlias;
		endptr ep = RegistrationTable::Instance()->FindByEndpointId(epID);
		if(ep){
			//check all endpoint aliases for a password which are not
			// equal to tokenAlias
			PString epAlias = "";
			H225_ArrayOf_AliasAddress epAliases = ep->GetAliases();
			for (PINDEX i = 0; i < epAliases.GetSize() && passwd.IsEmpty(); i++){
				epAlias = H323GetAliasAddressString(epAliases[i]);
				if (epAlias != tokenAlias) {
					found =  cache->Retrieve(epAlias, passwd);
					if (!found) {
						passwd = GetPassword(epAlias);
						cache->Save(epAlias, passwd);
					}
				}
			}
		}
	}
	return passwd;
}

bool SimplePasswordAuth::CheckCryptoTokens(const H225_ArrayOf_CryptoH323Token & tokens)
{
	for (PINDEX i = 0; i < tokens.GetSize(); ++i){
		if (tokens[i].GetTag() == H225_CryptoH323Token::e_cryptoEPPwdHash) {
			H225_CryptoH323Token_cryptoEPPwdHash & pwdhash = tokens[i];
			PString id = AsString(pwdhash.m_alias, FALSE);
			if (!m_aliasesChecked && !CheckAliases(id)) {
				return false;
			}
			PString passwd = GetPassword(id, *aliases);
			H235AuthSimpleMD5 authMD5;
			authMD5.SetLocalId(id);
			authMD5.SetPassword(passwd);
			if (authMD5.VerifyToken(tokens[i], nullPDU) == H235Authenticator::e_OK) {
				PTRACE(4, "GkAuth\t" << id << " password match (MD5)");
				return true;
			}
#ifdef P_SSL
		} else if (tokens[i].GetTag() == H225_CryptoH323Token::e_nestedcryptoToken){
			H235_CryptoToken & nestedCryptoToken = tokens[i];
			H235_CryptoToken_cryptoHashedToken & cryptoHashedToken = nestedCryptoToken;
			H235_ClearToken & clearToken = cryptoHashedToken.m_hashedVals;
			PString gk_id = clearToken.m_generalID;
			//assumption: sendersID == endpoint alias (RRQ)
			PString ep_alias = clearToken.m_sendersID;
			if (!m_aliasesChecked && !CheckAliases(ep_alias)) {
				return false;
			}
			PString passwd = GetPassword(ep_alias, *aliases);
			H235AuthProcedure1 authProcedure1;
			authProcedure1.SetLocalId(gk_id);
			authProcedure1.SetPassword(passwd);
			if (authProcedure1.VerifyToken(tokens[i], getLastReceivedRawPDU()) == H235Authenticator::e_OK) {
				PTRACE(4, "GkAuth\t" << ep_alias << " password match (SHA-1)");
				return true;
			}
#endif
		}
	}
	return false;
}


#ifdef HAS_MYSQL
#define MYSQL_NO_SHORT_NAMES  // use long names
#include <mysql++>

class MySQLAuthBase {
public:
	MySQLAuthBase(PConfig *,
		      const char *section,
		      const char *host,
		      const char *dbname,
		      const char *user,
		      const char *passwd,
		      const char *table,
		      const char *alias,
		      const char *query,
		      const char *extra
		);
	~MySQLAuthBase();
	bool Exec(const PString &, MysqlRes &);
	PString GetString(const PString &);
private:
	bool MySQLInit();
	void Cleanup();

	MysqlConnection *mysql_connection;
	MysqlQuery *mysql_query;

	PConfig *config;
	const char *section_n;
	const char *host_n, *dbname_n, *user_n, *passwd_n;
	const char *table_n, *alias_n, *query_n, *extra_n;
};

MySQLAuthBase::MySQLAuthBase(PConfig *cfg,
			     const char *section,
			     const char *host,
			     const char *dbname,
			     const char *user,
			     const char *passwd,
			     const char *table,
			     const char *alias,
			     const char *query,
			     const char *extra
	) : mysql_connection(0), mysql_query(0),
	    config(cfg), section_n(section),
	    host_n(host), dbname_n(dbname), user_n(user), passwd_n(passwd),
	    table_n(table), alias_n(alias), query_n(query), extra_n(extra)
{
	MySQLInit();
}

MySQLAuthBase::~MySQLAuthBase()
{
	Cleanup();
}

bool MySQLAuthBase::Exec(const PString & id, MysqlRes & result)
{
	if (mysql_connection || MySQLInit()) {
		try {
			result = mysql_query->store(SQLString(id));
			return true;
		} catch (MysqlBadQuery er) {
			PTRACE(1, "MySQL\tBadQuery: " << er.error);
			Cleanup();
		} catch (MysqlBadConversion er) {
			PTRACE(1,  "MySQL\tBadConversion: Tried to convert \"" << er.data << "\" to a \"" << er.type_name << "\".");
		}
	}
	return false;
}

PString MySQLAuthBase::GetString(const PString & id)
{
	PString str;
	MysqlRes result;
	if (Exec(id, result) && !result.empty())
		str = (*result.begin())[0].c_str();
	return str;
}

bool MySQLAuthBase::MySQLInit()
{
	try {
		PString host = config->GetString(section_n, host_n, "localhost");
		PString dbname = config->GetString(section_n, dbname_n, "billing");
		PString user = config->GetString(section_n, user_n, "cwhuang");
		PString passwd = config->GetString(section_n, passwd_n, "123456");

		PString table = config->GetString(section_n, table_n, "customer");
		PString alias = config->GetString(section_n, alias_n, "IPN");
		PString query = config->GetString(section_n, query_n, "Password");
		PString extra = config->GetString(section_n, extra_n, "");

		mysql_connection = new MysqlConnection(mysql_use_exceptions);
		mysql_connection->connect(dbname, host, user, passwd);

		PTRACE(2, "MySQL\tConnect to server " << host << ", database " << dbname);
		mysql_query = new MysqlQuery(mysql_connection, true);
		PString select_clause(PString::Printf,
			"select %s from %s where %s = '%%0:id'",
			(const char *)query,
			(const char *)table,
			(const char *)alias
		);
		if (!extra)
			select_clause += " and " + extra;
		PTRACE(2, "MySQL\t" << select_clause);

		*mysql_query << select_clause;
		mysql_query->parse();
		PTRACE(1, "MySQL\tReady for query");
		return true;
	} catch (MysqlBadQuery er) { // any error?
		PTRACE(1, "MySQL\tError: " << er.error);
		Cleanup();
		return false;
	}
}

void MySQLAuthBase::Cleanup()
{
	delete mysql_query;
	mysql_query = 0;
	delete mysql_connection;
	mysql_connection = 0; // disable the authenticator
}

// MySQLPasswordAuth
MySQLPasswordAuth::MySQLPasswordAuth(PConfig *cfg, const char *authName)
	: SimplePasswordAuth(cfg, authName)
{
	mysqlconn = new MySQLAuthBase(cfg, "MySQLAuth",
				      "Host", "Database", "User", "Password",
				      "Table", "IDField", "PasswordField", "ExtraCriterion"
		);
}

MySQLPasswordAuth::~MySQLPasswordAuth()
{
	delete mysqlconn;
}

PString MySQLPasswordAuth::GetPassword(const PString & id)
{
	return mysqlconn->GetString(id);
}

// MySQLAliasAuth
MySQLAliasAuth::MySQLAliasAuth(PConfig *cfg, const char *authName)
	: AliasAuth(cfg, authName)
{
	const char *secname = "MySQLAliasAuth";
	mysqlconn = new MySQLAuthBase(cfg, secname,
				      "Host", "Database", "User", "Password",
				      "Table", "IDField", "IPField", "ExtraCriterion"
		);
	cache = new CacheManager(config->GetInteger(secname, "CacheTimeout", -1) * 1000);
}

MySQLAliasAuth::~MySQLAliasAuth()
{
	delete mysqlconn;
	delete cache;
}

PString MySQLAliasAuth::GetConfigString(const PString & alias) const
{
	PString result;
	if (!cache->Retrieve(alias, result)) {
		result = mysqlconn->GetString(alias);
		if (!result)
			cache->Save(alias, result);
	}
	return result;
}

#endif // HAS_MYSQL

#if ((defined(__GNUC__) && __GNUC__ <= 2) && !defined(WIN32))
// ExternalPasswordAuth

ExternalPasswordAuth::ExternalPasswordAuth(PConfig * cfg, const char * authName)
	: SimplePasswordAuth(cfg, authName)
{
	ExternalInit();
}

bool ExternalPasswordAuth::ExternalInit()
{
	const char *ExternalSec = "ExternalAuth";

	// Read the configuration
	Program = config->GetString(ExternalSec, "PasswordProgram", "");

	return true;
}

PString ExternalPasswordAuth::GetPassword(const PString & id)
{
	const int BUFFSIZE = 256;
	char buff[BUFFSIZE] = "";
	if (!Program) {
		procbuf proc(Program + " " + id, ios::in);
		istream istr(&proc);
		istr.getline(buff, BUFFSIZE);
	} else {
		PTRACE(2, "GkAuth\tProgram is not defined");
	}
	return PString(buff);
}

#endif // !defined(WIN32)


#include "gkDatabase.h"
// PasswordAuth (using database list)
DBPasswordAuth::DBPasswordAuth(PConfig * cfg,  const char * authName)
	: SimplePasswordAuth(cfg, authName)
{
}

DBPasswordAuth::~DBPasswordAuth()
{
	deleteMutex.Wait();
}

PString DBPasswordAuth::GetPassword(const PString & alias)
{
	PStringList attr_values;
	using namespace dctn; // database config tags and names
	DBTypeEnum dbType;
	if(GkDatabase::Instance()->getAttribute(alias, H235PassWord, attr_values, dbType) &&
	   !attr_values.IsEmpty()){
		return attr_values[0];
	}
	return "";
}

int DBPasswordAuth::Check(const H225_RegistrationRequest & rrq, unsigned & reason)
{
	PWaitAndSignal lock(deleteMutex);
	int result = SimplePasswordAuth::Check(rrq, reason);
	if(result == e_ok) {
		// check if all aliases in RRQ exists in DB entry
		const H225_ArrayOf_AliasAddress & aliases = rrq.m_terminalAlias;
		if(!GkDatabase::Instance()->validAliases(aliases)) {
			result = e_fail;
		}
	}
	return result;
}

// AliasAuth (using database list)
DBAliasAuth::DBAliasAuth(PConfig *cfg, const char *authName) : AliasAuth(cfg, authName)
{
}

DBAliasAuth::~DBAliasAuth()
{
	deleteMutex.Wait();
}

PString DBAliasAuth::GetConfigString(const PString &alias) const
{
	PStringList attr_values;
	using namespace dctn; // DB config tags and names
	// get pointer to new answer object
	DBTypeEnum dbType;
	PString rv;
	if (GkDatabase::Instance()->getAttribute(alias, IPAddress, attr_values, dbType)
			&& (!attr_values.IsEmpty())) {
		for(PINDEX i=0; i<attr_values.GetSize(); i++) {
			PString ip = attr_values[i];
			if(!ip.IsEmpty()){
				if((rv.GetSize()==0) || (rv==""))
					rv = "sigip:" + ip;
				else
					rv += "|sigip:" + ip;
			}
		}
	}
	return rv;
}

int DBAliasAuth::Check(const H225_RegistrationRequest & rrq, unsigned & reason)
{
	int result = AliasAuth::Check(rrq, reason);
	if(result == e_ok) {
		// check if all aliases in RRQ exists in database entry
		const H225_ArrayOf_AliasAddress & aliases = rrq.m_terminalAlias;
		if(!GkDatabase::Instance()->validAliases(aliases)) {
			result = e_fail;
    		}
	}
  	return result;
}


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
	PWaitAndSignal lock(deleteMutex);
	bool AliasFoundInConfig = false;

	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
		return defaultStatus;

	const H225_ArrayOf_AliasAddress & NewAliases = rrq.m_terminalAlias;

	// alias is the config file entry of this endpoint
	for (PINDEX i=0; !AliasFoundInConfig && i < NewAliases.GetSize(); ++i) {
		PString alias = AsString(NewAliases[i], FALSE);
		const PString cfgString = GetConfigString(alias);

		if (cfgString != "") {
			if(cfgString.Find("&")<cfgString.GetSize()) {
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
			} else {
				const PStringArray conditions = cfgString.Tokenise("|", FALSE);

				for (PINDEX iCnd = 0; iCnd < conditions.GetSize(); ++iCnd) {
					if (rrq.m_callSignalAddress.GetSize()==0 || !AuthCondition(rrq.m_callSignalAddress[0], conditions[iCnd])) {
						PTRACE(4, "Gk\tRRQAuth condition '" << conditions[iCnd] << "' rejected endpoint " << alias);
						//return e_fail;
					} else {
						AliasFoundInConfig = true;
						PTRACE(5, "Gk\tRRQAuth condition applied successfully for endpoint " << alias);
					}
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

PString AliasAuth::GetConfigString(const PString &alias) const
{
	return config->GetString("RasSrv::RRQAuth", alias, "");
}


bool AliasAuth::AuthCondition(const H225_TransportAddress & SignalAdr, const PString & Condition)
{
	const bool ON_ERROR = false; // return value on parse error in condition


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
		if ((rule.GetSize()>=3) && (rule[2]=="*")) {
			const H225_TransportAddress_ipAddress & sig_ip = SignalAdr;
			const H225_TransportAddress rtip = SocketToH225TransportAddr(ip,0);
			const H225_TransportAddress_ipAddress &rule_ip = rtip;
			return (rule_ip.m_ip==sig_ip.m_ip);
		}
		WORD port = (rule.GetSize() < 3) ? GK_DEF_ENDPOINT_SIGNAL_PORT : rule[2].AsInteger();
		return (SignalAdr == SocketToH225TransportAddr(ip, port));
	} else {
		PTRACE(4, "Unknown RRQAuth condition: " << Condition);
		return ON_ERROR;
	}

	// not reached...
	return false;
}


// Help classes for PrefixAuth
static const char* const prfflag="prf:";
static const char* const allowflag="allow";
static const char* const denyflag="deny";
static const char* const ipflag="ipv4:";
static const char* const aliasflag="alias:";

class AuthObj { // abstract class
public:
	virtual ~AuthObj() {}

	virtual bool IsValid() const { return true; }

	virtual PStringArray GetPrefixes() const = 0;

	virtual PIPSocket::Address GetIP() const = 0;
	virtual PString GetAliases() const = 0;
};

class RRQAuthObj : public AuthObj {
public:
	RRQAuthObj(const H225_RegistrationRequest & ras) : rrq(ras) {}

	virtual PStringArray GetPrefixes() const;

	virtual PIPSocket::Address GetIP() const;
	virtual PString GetAliases() const;

private:
	const H225_RegistrationRequest & rrq;
};

class ARQAuthObj : public AuthObj {
public:
	ARQAuthObj(const H225_AdmissionRequest & ras);

	virtual bool IsValid() const { return ep; }

	virtual PStringArray GetPrefixes() const;

	virtual PIPSocket::Address GetIP() const;
	virtual PString GetAliases() const;

private:
	const H225_AdmissionRequest & arq;
	endptr ep;
};

ARQAuthObj::ARQAuthObj(const H225_AdmissionRequest & ras) : arq(ras)
{
	ep = RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier);
}

PStringArray ARQAuthObj::GetPrefixes() const
{
	PStringArray array;
	if (arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
		if (PINDEX ss = arq.m_destinationInfo.GetSize() > 0) {
			array.SetSize(ss);
			for (PINDEX i = 0; i < ss; ++i)
				array[i] = AsString(arq.m_destinationInfo[i], FALSE);
		}
	return array;
}

PIPSocket::Address ARQAuthObj::GetIP() const
{
	PIPSocket::Address result;
	const H225_TransportAddress & addr = (arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress)) ?
		arq.m_srcCallSignalAddress : ep->GetCallSignalAddress();
	if (addr.GetTag() == H225_TransportAddress::e_ipAddress) {
		const H225_TransportAddress_ipAddress & ip = addr;
		result = PIPSocket::Address(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
	}
	return result;
}

PString ARQAuthObj::GetAliases() const
{
	return AsString(ep->GetAliases());
}

class LRQAuthObj : public AuthObj {
public:
	LRQAuthObj(const H225_LocationRequest & ras);

	virtual PStringArray GetPrefixes() const;

	virtual PIPSocket::Address GetIP() const;
	virtual PString GetAliases() const;

private:
	const H225_LocationRequest & lrq;
	PIPSocket::Address ipaddress;
};

LRQAuthObj::LRQAuthObj(const H225_LocationRequest & ras) : lrq(ras)
{
	const H225_TransportAddress & addr = lrq.m_replyAddress;
	if (addr.GetTag() == H225_TransportAddress::e_ipAddress) {
		const H225_TransportAddress_ipAddress & ip = addr;
		ipaddress = PIPSocket::Address(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
	}
}

PStringArray LRQAuthObj::GetPrefixes() const
{
	PStringArray array;
	if (PINDEX ss = lrq.m_destinationInfo.GetSize() > 0) {
		array.SetSize(ss);
		for (PINDEX i = 0; i < ss; ++i)
			array[i] = AsString(lrq.m_destinationInfo[i], FALSE);
	}
	return array;
}

PIPSocket::Address LRQAuthObj::GetIP() const
{
	return ipaddress;
}

PString LRQAuthObj::GetAliases() const
{
	return (lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)) ? AsString(lrq.m_sourceInfo) : PString();
}


class AuthRule {
public:
	enum Result {
		e_nomatch,
		e_allow,
		e_deny
	};

	AuthRule(Result f, AuthRule *prev);
	virtual ~AuthRule() { delete next; }

	virtual bool Match(const AuthObj &) = 0;
	int Check(const AuthObj &);

private:
	Result fate;
	AuthRule *next;
};

AuthRule::AuthRule(Result f, AuthRule *prev) : fate(f), next(0)
{
	if (prev)
		prev->next = this;
}

int AuthRule::Check(const AuthObj & aobj)
{
	return Match(aobj) ? fate : (next) ? next->Check(aobj) : e_nomatch;
}

inline void delete_rule(PrefixAuth::Rules::value_type r)
{
	delete r.second;
}

class IPv4AuthRule : public AuthRule {
public:
	IPv4AuthRule(Result, const PString &, AuthRule *);

private:
	virtual bool Match(const AuthObj &);

	PIPSocket::Address network, netmask;
};

IPv4AuthRule::IPv4AuthRule(Result f, const PString & cfg, AuthRule *prev) : AuthRule(f, prev)
{
	GetNetworkFromString(cfg, network, netmask);
}

bool IPv4AuthRule::Match(const AuthObj & aobj)
{
	return ((aobj.GetIP() & netmask) == network);
}

class AliasAuthRule : public AuthRule {
public:
	AliasAuthRule(Result f, const PString & cfg, AuthRule *prev) : AuthRule(f, prev), pattern(cfg) {}

private:
	virtual bool Match(const AuthObj &);

	PString pattern;
};

bool AliasAuthRule::Match(const AuthObj & aobj)
{
	return (aobj.GetAliases().FindRegEx(pattern) != P_MAX_INDEX);
}

// PrefixAuth
PrefixAuth::PrefixAuth(PConfig *cfg, const char *authName)
      : GkAuthenticator(cfg, authName)
{
	int ipfl = strlen(ipflag), aliasfl = strlen(aliasflag);
	PStringToString cfgs=cfg->GetAllKeyValues("PrefixAuth");
	for (PINDEX i = 0; i < cfgs.GetSize(); ++i) {
		AuthRule *head = 0, *next = 0;
		PString key = cfgs.GetKeyAt(i);
		if (key *= "default") {
			if (!Toolkit::AsBool(cfgs.GetDataAt(i)))
				defaultStatus = e_fail;
			continue;
		} else if (key *= "ALL") {
			// use space (0x20) as the key so it will be the last resort
			key = " ";
		}
		PStringArray rules = cfgs.GetDataAt(i).Tokenise("|", FALSE);
		for (PINDEX j = 0; j < rules.GetSize(); ++j) {
			PINDEX pp;
			AuthRule *rl = 0;
			// if not allowed, assume denial
			AuthRule::Result ft = (rules[j].Find(allowflag) != P_MAX_INDEX) ? AuthRule::e_allow : AuthRule::e_deny;
			if ((pp=rules[j].Find(ipflag)) != P_MAX_INDEX)
				rl = new IPv4AuthRule(ft, rules[j].Mid(pp+ipfl), next);
			else if ((pp=rules[j].Find(aliasflag)) != P_MAX_INDEX)
				rl = new AliasAuthRule(ft, rules[j].Mid(pp+aliasfl), next);

			if (rl) {
				if (!next)
					head = rl;
				next = rl;
			}
		}
		if (head)
			prefrules[key] = head;
	}
}

PrefixAuth::~PrefixAuth()
{
	for_each(prefrules.begin(), prefrules.end(), delete_rule);
}

int PrefixAuth::Check(const H225_GatekeeperRequest &, unsigned &)
{
	return e_next;
}

int PrefixAuth::Check(const H225_RegistrationRequest & rrq, unsigned &)
{
	return e_next;
}

int PrefixAuth::Check(const H225_UnregistrationRequest &, unsigned &)
{
	return e_next;
}

int PrefixAuth::Check(const H225_AdmissionRequest & arq, unsigned &)
{
	return CallTable::Instance()->FindCallRec(arq.m_callIdentifier) ? e_ok : doCheck(ARQAuthObj(arq));
}

int PrefixAuth::Check(const H225_BandwidthRequest &, unsigned &)
{
	return e_next;
}

int PrefixAuth::Check(const H225_DisengageRequest &, unsigned &)
{
	return e_next;
}

int PrefixAuth::Check(const H225_LocationRequest & lrq, unsigned &)
{
	return doCheck(LRQAuthObj(lrq));
}

int PrefixAuth::Check(const H225_InfoRequest &, unsigned &)
{
	return e_next;
}

struct comp_pref { // function object
	comp_pref(const PString & s) : value(s) {}
	bool operator()(const PrefixAuth::Rules::value_type & v) const;
	const PString & value;
};

inline bool comp_pref::operator()(const PrefixAuth::Rules::value_type & v) const
{
	return (value.Find(v.first) == 0) || (v.first *= " ");
}

int PrefixAuth::doCheck(const AuthObj & aobj)
{
	if (!aobj.IsValid())
		return e_fail;
	PStringArray ary(aobj.GetPrefixes());
	for (PINDEX i = 0; i < ary.GetSize(); ++i) {
		// find the first match rule
		// since prefrules is descendently sorted
		// it must be the most specific prefix
		Rules::iterator iter = find_if(prefrules.begin(), prefrules.end(), comp_pref(ary[i]));
		if (iter != prefrules.end()) {
			switch (iter->second->Check(aobj))
			{
				case AuthRule::e_allow:
					return e_ok;
				case AuthRule::e_deny:
					return e_fail;
				// default, try next prefix...
			}
		}
	}
	return defaultStatus;
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
