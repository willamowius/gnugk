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
//      2003/07/16      revision for thread-safe
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
#include "RasPDU.h"
#include "Toolkit.h"
#include <h235.h>
#include <h323pdu.h>
#include <h235auth.h>

#ifdef P_SOLARIS
#define map stl_map
#endif

#include <map>
#include <list>

using std::map;
using std::list;

const char *GkAuthSectionName = "Gatekeeper::Auth";

//////////////////////////////////////////////////////////////////////
// Definition of authentication rules

class AliasAuth : public GkAuthenticator {
public:
	AliasAuth(const char *name) : GkAuthenticator(name) {}

protected:
	// override from class GkAuthenticator
	virtual int Check(RasPDU<H225_GatekeeperRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_RegistrationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_UnregistrationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_AdmissionRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_BandwidthRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_DisengageRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_LocationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_InfoRequest> &, unsigned &);

	virtual bool doCheck(const H225_ArrayOf_TransportAddress &, const PString &);
	virtual bool AuthCondition(const H225_TransportAddress & SignalAdr, const PString &);

private:
	/** @returns the value for a given alias from section #RasSrv::RRQAuth# 
	    in ini-file
	 */
	virtual PString GetConfigString(const PString & alias);
};

#ifdef HAS_MYSQL

#include "mysqlcon.h"

class MySQLPasswordAuth : public SimplePasswordAuth, private MySQLConnection {
public:
	MySQLPasswordAuth(const char *);

private:
	virtual bool GetPassword(const PString &, PString &);
};

class MySQLAliasAuth : public AliasAuth, private MySQLConnection {
public:
	MySQLAliasAuth(const char *);
	~MySQLAliasAuth();

private:
	virtual PString GetConfigString(const PString & alias);

	CacheManager *cache;
};

#endif // HAS_MYSQL

#if ((defined(__GNUC__) && __GNUC__ <= 2) && !defined(WIN32))
#include <unistd.h>
#include <procbuf.h>

class ExternalPasswordAuth : public SimplePasswordAuth {
public:
	ExternalPasswordAuth(const char *);

private:
	bool ExternalInit();
	virtual bool GetPassword(const PString &, PString &);

	PString Program;
};

#endif

// Initial author: Michael Rubashenkkov  2002/01/14 (GkAuthorize)
// Completely rewrite by Chih-Wei Huang  2002/05/01
class AuthObj;
class AuthRule;
class PrefixAuth : public GkAuthenticator {
public:
	PrefixAuth(const char *);
	~PrefixAuth();

	typedef std::map< PString, AuthRule *, greater<PString> > Rules;

private:
	// override from class GkAuthenticator
	virtual int Check(RasPDU<H225_GatekeeperRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_RegistrationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_UnregistrationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_AdmissionRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_BandwidthRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_DisengageRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_LocationRequest> &, unsigned &);
	virtual int Check(RasPDU<H225_InfoRequest> &, unsigned &);

	virtual int doCheck(const AuthObj &);
	
	Rules prefrules;
};


class CacheManager {
public:
	CacheManager(int t) : ttl(t) {}

	bool Retrieve(const PString & key, PString & value) const;
	void Save(const PString & key, const PString & value);

private:
	// 0 means don't cache, -1 means never expires
	int ttl; // miliseconds
	map<PString, PString> cache;
	map<PString, PTime> ctime;
	mutable PReadWriteMutex rwmutex;

	CacheManager(const CacheManager &);
	CacheManager & operator=(const CacheManager &);
};      

bool CacheManager::Retrieve(const PString & key, PString & value) const
{
	ReadLock lock(rwmutex);
	std::map<PString, PString>::const_iterator iter = cache.find(key);
	if (iter == cache.end())
		return false;
	if (ttl > 0) {
		std::map<PString, PTime>::const_iterator i = ctime.find(key);
		if ((PTime() - i->second) > ttl)
			return false; // cache expired
	}
	value = (const char *)iter->second;
	PTRACE(5, "GkAuth\tCache found for " << key);
	return true;
}

void CacheManager::Save(const PString & key, const PString & value)
{
	if (ttl != 0) {
		WriteLock lock(rwmutex);
		cache[key] = value;
		ctime[key] = PTime();
	}
}

//////////////////////////////////////////////////////////////////////

GkAuthenticator::GkAuthenticator(const char *name) : h235Authenticators(0)
{
	config = GkConfig();
	SetName(name);

	PStringArray control(config->GetString(GkAuthSectionName, name, "").Tokenise(";,"));
	if (strcmp(name, "default") == 0)
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
		rasmap["GRQ"] = RasInfo<H225_GatekeeperRequest>::flag,
		rasmap["RRQ"] = RasInfo<H225_RegistrationRequest>::flag,
		rasmap["URQ"] = RasInfo<H225_UnregistrationRequest>::flag,
		rasmap["ARQ"] = RasInfo<H225_AdmissionRequest>::flag,
		rasmap["BRQ"] = RasInfo<H225_BandwidthRequest>::flag,
		rasmap["DRQ"] = RasInfo<H225_DisengageRequest>::flag,
		rasmap["LRQ"] = RasInfo<H225_LocationRequest>::flag,
		rasmap["IRQ"] = RasInfo<H225_InfoRequest>::flag;
		for (PINDEX i=1; i < control.GetSize(); ++i) {
			if (rasmap.find(control[i]) != rasmap.end())
				checkFlag |= rasmap[control[i]];
		}
	} else
		checkFlag = ~0;

	PTRACE(1, "GkAuth\tAdd " << name << " rule with flag " << hex << checkFlag << dec);
}

GkAuthenticator::~GkAuthenticator()
{
	delete h235Authenticators;
	PTRACE(1, "GkAuth\tRemove " << GetName() << " rule");
}

bool GkAuthenticator::Validate(
	RasPDU<H225_AdmissionRequest>& req, 
	unsigned& rejectReason,
	long& callDurationLimit
	)
{
	callDurationLimit = -1;
	if (checkFlag & RasInfo<H225_AdmissionRequest>::flag) {
		int r = Check(req, rejectReason, callDurationLimit);
		if( callDurationLimit == 0 ) {
			PTRACE(2,"GkAuth\t"<<GetName()<<" - call duration limit 0");
			return false;
		}
		if (r == e_ok) {
			PTRACE(4, "GkAuth\t" << GetName() << " check ok");
			if (controlFlag != e_Required)
				return true;
		} else if (r == e_fail) {
			PTRACE(2, "GkAuth\t" << GetName() << " check failed");
			return false;
		}
	}
	if( m_next ) {
		long newDurationLimit = -1;
		if( !m_next->Validate(req, rejectReason,newDurationLimit) )
			return false;
		if( newDurationLimit >= 0 )
			callDurationLimit = PMIN(callDurationLimit,newDurationLimit);
	}
	if( callDurationLimit == 0 ) {
		PTRACE(2,"GkAuth\t"<<GetName()<<" - call duration limit 0");
		return false;
	}
	return true;
}

int GkAuthenticator::Check(RasPDU<H225_GatekeeperRequest> &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(RasPDU<H225_RegistrationRequest> &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(RasPDU<H225_UnregistrationRequest> &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(RasPDU<H225_AdmissionRequest> &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(RasPDU<H225_AdmissionRequest>& req, unsigned& reason, long& limit)
{
	return Check(req,reason);
}

int GkAuthenticator::Check(RasPDU<H225_BandwidthRequest> &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(RasPDU<H225_DisengageRequest> &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(RasPDU<H225_LocationRequest> &, unsigned &)
{
	return defaultStatus;
}

int GkAuthenticator::Check(RasPDU<H225_InfoRequest> &, unsigned &)
{
	return defaultStatus;
}

bool GkAuthenticator::GetH235Capability(
	H225_ArrayOf_AuthenticationMechanism& mechanisms,
	H225_ArrayOf_PASN_ObjectId& algorithmOIDs
	) const
{
	if (h235Authenticators) {
		for (int i = 0; i < h235Authenticators->GetSize(); ++i)
			(*h235Authenticators)[i].SetCapability(mechanisms, algorithmOIDs);
		return true;
	}
	return false;
}		

bool GkAuthenticator::IsH235Capability(
	const H235_AuthenticationMechanism& mechanism,
	const PASN_ObjectId& algorithmOID
	) const
{
	if (h235Authenticators) {
		for (int i = 0; i < h235Authenticators->GetSize(); ++i)
			if ((*h235Authenticators)[i].IsCapability(mechanism,algorithmOID))
				return true;
	}
	return false;
}

bool GkAuthenticator::IsH235Capable() const
{
	return h235Authenticators && h235Authenticators->GetSize() > 0;
}


const char *passwdsec = "Password";

// class SimplePasswordAuth
SimplePasswordAuth::SimplePasswordAuth(const char *name) : GkAuthenticator(name)
{
	filled = config->GetInteger(passwdsec, "KeyFilled", 0);
	checkid = Toolkit::AsBool(config->GetString(passwdsec, "CheckID", "0"));
	cache = new CacheManager(config->GetInteger(passwdsec, "PasswordTimeout", -1) * 1000);
	
	h235Authenticators = new H235Authenticators;
	H235Authenticator* authenticator;
	
	authenticator = new H235AuthSimpleMD5;
	authenticator->SetLocalId("dummy");
	authenticator->SetRemoteId("dummy");
	authenticator->SetPassword("dummy");
	h235Authenticators->Append(authenticator);
#ifdef OPENH323_NEWVERSION
	authenticator = new H235AuthCAT;
	authenticator->SetLocalId("dummy");
	authenticator->SetRemoteId("dummy");
	authenticator->SetPassword("dummy");
	h235Authenticators->Append(authenticator);
#endif
#ifdef P_SSL
	authenticator = new H235AuthProcedure1;
	authenticator->SetLocalId("dummy");
	authenticator->SetRemoteId("dummy");
	authenticator->SetPassword("dummy");
	h235Authenticators->Append(authenticator);
#endif
}

SimplePasswordAuth::~SimplePasswordAuth()
{
	delete cache;
}

int SimplePasswordAuth::Check(RasPDU<H225_GatekeeperRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(RasPDU<H225_RegistrationRequest> & request, unsigned &)
{
	H225_RegistrationRequest & rrq = request;
	return doCheck(request, rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) ? &rrq.m_terminalAlias : 0);
}

int SimplePasswordAuth::Check(RasPDU<H225_UnregistrationRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(RasPDU<H225_AdmissionRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(RasPDU<H225_BandwidthRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(RasPDU<H225_DisengageRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(RasPDU<H225_LocationRequest> & request, unsigned &)
{
	return doCheck(request);
}

int SimplePasswordAuth::Check(RasPDU<H225_InfoRequest> & request, unsigned &)
{
	return doCheck(request);
}

bool SimplePasswordAuth::GetPassword(const PString & id, PString & passwd)
{
	if (!config->HasKey(passwdsec, id))
		return false;
	passwd = Toolkit::CypherDecode(id, config->GetString(passwdsec, id, ""), filled);
	return true;
}

PString SimplePasswordAuth::InternalGetPassword(const PString & id)
{
	PString passwd;
	if (!cache->Retrieve(id, passwd))
		if (GetPassword(id, passwd))
			cache->Save(id, passwd);
	return passwd;
}

bool SimplePasswordAuth::CheckAliases(const PString & id, const H225_ArrayOf_AliasAddress *aliases)
{
	bool result = !checkid;
	if (checkid && aliases)
		for (PINDEX i = 0; i < aliases->GetSize(); ++i)
			if (H323GetAliasAddressString((*aliases)[i]) == id) {
				result = true;
				break;
			}
	return result;
}

static const char OID_CAT[] = "1.2.840.113548.10.1.2.1";

bool SimplePasswordAuth::CheckTokens(const H225_ArrayOf_ClearToken & tokens, const H225_ArrayOf_AliasAddress *aliases)
{
	for (PINDEX i=0; i < tokens.GetSize(); ++i) {
		H235_ClearToken & token = tokens[i];
		if (!token.HasOptionalField(H235_ClearToken::e_generalID))
			return false;
		PString id = token.m_generalID;
		if (!CheckAliases(id, aliases))
			return false;

#ifdef OPENH323_NEWVERSION
		// check for Cisco Access Token
		if (token.m_tokenOID == OID_CAT) {
			PString passwd = InternalGetPassword(id);

			H235AuthCAT authCAT;
			authCAT.SetLocalId(id);
			authCAT.SetPassword(passwd);
			if (authCAT.ValidateClearToken(token) == H235Authenticator::e_OK) {
				PTRACE(4, "GkAuth\t" << id << " password match (CAT)");
				return true;
			}
			return false;
		}
#endif
		if (token.HasOptionalField(H235_ClearToken::e_password)) {
			PString passwd = InternalGetPassword(id), tokenpasswd = token.m_password;
			if (passwd == tokenpasswd) {
				PTRACE(4, "GkAuth\t" << id << " password match");
				return true;
			}
		}
	}
	return false;
}

bool SimplePasswordAuth::CheckCryptoTokens(const H225_ArrayOf_CryptoH323Token & tokens, const H225_ArrayOf_AliasAddress *aliases, const PBYTEArray & rawPDU)
{
	for (PINDEX i = 0; i < tokens.GetSize(); ++i) {
		if (tokens[i].GetTag() == H225_CryptoH323Token::e_cryptoEPPwdHash) {
			H225_CryptoH323Token_cryptoEPPwdHash & pwdhash = tokens[i];
			PString id = AsString(pwdhash.m_alias, false);
			if (!CheckAliases(id, aliases))
				return false;

			PString passwd = InternalGetPassword(id);
			H235AuthSimpleMD5 authMD5;
			authMD5.SetLocalId(id);
			authMD5.SetPassword(passwd);
			PBYTEArray nullPDU;
#ifdef OPENH323_NEWVERSION
			if (authMD5.ValidateCryptoToken(tokens[i], nullPDU) == H235Authenticator::e_OK) {
#else
			if (authMD5.VerifyToken(tokens[i], nullPDU) == H235Authenticator::e_OK) {
#endif
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
			if (!CheckAliases(ep_alias, aliases))
				return false;
			PString passwd = InternalGetPassword(ep_alias);
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
					passwd = InternalGetPassword(ep_alias);
					if (!passwd)
						break;
				}
			}
			H235AuthProcedure1 authProcedure1;
			authProcedure1.SetLocalId(gk_id);
			authProcedure1.SetPassword(passwd);
#ifdef OPENH323_NEWVERSION
			if (authProcedure1.ValidateCryptoToken(tokens[i], rawPDU) == H235Authenticator::e_OK) {
#else
			if (authProcedure1.VerifyToken(tokens[i], rawPDU) == H235Authenticator::e_OK) {
#endif
				PTRACE(4, "GkAuth\t" << ep_alias << " password match (SHA-1)");
				return true;
			}
#endif
		}
	}
	return false;
}


// class AliasAuth
int AliasAuth::Check(RasPDU<H225_GatekeeperRequest> &, unsigned &)
{
	return e_next;
}

int AliasAuth::Check(RasPDU<H225_RegistrationRequest> & request, unsigned &)
{
	H225_RegistrationRequest & rrq = request;
	bool AliasFoundInConfig = false;

	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
		return defaultStatus;

	const H225_ArrayOf_AliasAddress & NewAliases = rrq.m_terminalAlias;

	// alias is the config file entry of this endpoint
	for (PINDEX i = 0; i <= NewAliases.GetSize(); ++i) {
		const PString alias = (i < NewAliases.GetSize()) ? AsString(NewAliases[i], false) : PString("default");
		const PString cfgString = GetConfigString(alias);
		if (!cfgString) {
			if (doCheck(rrq.m_callSignalAddress, cfgString)) {
				AliasFoundInConfig = true;
				break;
			} else {
				PTRACE(4, "Gk\tRRQAuth condition '" << cfgString << "' rejected endpoint " << alias);
				return e_fail;
			}
		}
	}
	return (AliasFoundInConfig) ? e_ok : defaultStatus;
}

int AliasAuth::Check(RasPDU<H225_UnregistrationRequest> &, unsigned &)
{
	return e_next;
}

int AliasAuth::Check(RasPDU<H225_AdmissionRequest> &, unsigned &)
{
	return e_next;
}

int AliasAuth::Check(RasPDU<H225_BandwidthRequest> &, unsigned &)
{
	return e_next;
}

int AliasAuth::Check(RasPDU<H225_DisengageRequest> &, unsigned &)
{
	return e_next;
}

int AliasAuth::Check(RasPDU<H225_LocationRequest> &, unsigned &)
{
	return e_next;
}

int AliasAuth::Check(RasPDU<H225_InfoRequest> &, unsigned &)
{
	return e_next;
}

PString AliasAuth::GetConfigString(const PString & alias)
{
	return config->GetString("RasSrv::RRQAuth", alias, "");
}

bool AliasAuth::doCheck(const H225_ArrayOf_TransportAddress & addrs, const PString & cfgString)
{
	const PStringArray conditions(cfgString.Tokenise("&|", false));
	for (PINDEX i = 0; i < conditions.GetSize(); ++i) {
		for (PINDEX j = 0; j < addrs.GetSize(); ++j) {
			if (AuthCondition(addrs[j], conditions[i])) {
				PTRACE(4, "Gk\tRRQAuth condition '" << conditions[i] << "' applied successfully for endpoint " << AsDotString(addrs[j]));
				return true;
			}
		}
	}
	return false;
}

bool AliasAuth::AuthCondition(const H225_TransportAddress & SignalAdr, const PString & Condition)
{
	const bool ON_ERROR = false; // return value on parse error in condition

	const PStringArray rule = Condition.Tokenise(":", false);
	if (rule.GetSize() < 1) {
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
	else if (rName=="sigaddr") {
		if(rule.GetSize() < 2)
			return false;
		return Toolkit::MatchRegex(AsString(SignalAdr), rule[1]) != 0;
	}
	//
	// condition 'sigip' example:
	//   sigip:195.71.129.69:1720
	//
	else if (rName=="sigip") {
		if (rule.GetSize() < 2)
			return false;
		PIPSocket::Address ip;
		PIPSocket::GetHostAddress(rule[1], ip);
		WORD port = (WORD)((rule.GetSize() < 3) ? GK_DEF_ENDPOINT_SIGNAL_PORT : rule[2].AsInteger());
		return (SignalAdr == SocketToH225TransportAddr(ip, port));
	} else {
		PTRACE(4, "Unknown RRQAuth condition: " << Condition);
		return ON_ERROR;
	}

	// not reached...
	return false;
}

#ifdef HAS_MYSQL

// class MySQLPasswordAuth
MySQLPasswordAuth::MySQLPasswordAuth(const char *name)
      : SimplePasswordAuth(name), MySQLConnection(config, name)
{
}

bool MySQLPasswordAuth::GetPassword(const PString & id, PString & passwd)
{
	return Query(id, passwd);
}

// class MySQLAliasAuth
MySQLAliasAuth::MySQLAliasAuth(const char *name)
      : AliasAuth(name), MySQLConnection(config, name)
{
	cache = new CacheManager(config->GetInteger(name, "CacheTimeout", -1) * 1000);
}

MySQLAliasAuth::~MySQLAliasAuth()
{
	delete cache;
}

PString MySQLAliasAuth::GetConfigString(const PString & alias)
{
	PString result;
	if (!cache->Retrieve(alias, result))
		if (Query(alias, result))
			cache->Save(alias, result);
	return result;
}

#endif // HAS_MYSQL

#if ((defined(__GNUC__) && __GNUC__ <= 2) && !defined(WIN32))

// class ExternalPasswordAuth
ExternalPasswordAuth::ExternalPasswordAuth(const char *name) : SimplePasswordAuth(name)
{
	ExternalInit();
}

bool ExternalPasswordAuth::ExternalInit()
{
	const char *ExternalSec = GetName();
	// Read the configuration
	Program = config->GetString(ExternalSec, "PasswordProgram", "");
	return true;
}

bool ExternalPasswordAuth::GetPassword(const PString & id, PString & passwd)
{
	const int BUFFSIZE = 256;
	char buff[BUFFSIZE] = "";
	if (Program.IsEmpty()) {
		PTRACE(1, "GkAuth\tProgram is not defined");
		return false;
	}

	procbuf proc(Program + " " + id, ios::in);
	istream istr(&proc);
	istr.getline(buff, BUFFSIZE);
	PTRACE(3, "EXT\tget " << buff);
	passwd = buff;
	return true;
}

#endif // class ExternalPasswordAuth

static const char* const prfflag="prf:";
static const char* const allowflag="allow";
static const char* const denyflag="deny";
static const char* const ipflag="ipv4:";
static const char* const aliasflag="alias:";

// Help classes for PrefixAuth
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
				array[i] = AsString(arq.m_destinationInfo[i], false);
		}
	if (array.GetSize() == 0)
		// let empty destinationInfo match the ALL rule
		array.SetSize(1);

	return array;
}

PIPSocket::Address ARQAuthObj::GetIP() const
{
	PIPSocket::Address result;
	const H225_TransportAddress & addr = (arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress)) ?
		arq.m_srcCallSignalAddress : ep->GetCallSignalAddress();
	GetIPFromTransportAddr(addr, result);
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
	GetIPFromTransportAddr(lrq.m_replyAddress, ipaddress);
}

PStringArray LRQAuthObj::GetPrefixes() const
{
	PStringArray array;
	if (PINDEX ss = lrq.m_destinationInfo.GetSize() > 0) {
		array.SetSize(ss);
		for (PINDEX i = 0; i < ss; ++i)
			array[i] = AsString(lrq.m_destinationInfo[i], false);
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

	AuthRule(Result f, bool r) : priority(1000), fate(f), inverted(r), next(0) {}
	virtual ~AuthRule() { delete next; }

	virtual bool Match(const AuthObj &) = 0;
	int Check(const AuthObj &);
	
	bool operator<(const AuthRule & o) const { return priority < o.priority; }
	void SetNext(AuthRule *n) { next = n; }

//	virtual PString GetName() const { return PString(); }

protected:
	int priority; // the lesser the value, the higher the priority

private:
	Result fate;
	bool inverted;
	AuthRule *next;
};

int AuthRule::Check(const AuthObj & aobj)
{
//	PTRACE(3, "auth\t" << GetName());
	return (Match(aobj) ^ inverted) ? fate : (next) ? next->Check(aobj) : e_nomatch;
}

inline void delete_rule(PrefixAuth::Rules::value_type r)
{
	delete r.second;
}

class NullRule : public AuthRule {
public:
	NullRule() : AuthRule(e_nomatch, false) {}
	virtual bool Match(const AuthObj &) { return false; }
};

class IPv4AuthRule : public AuthRule {
public:
	IPv4AuthRule(Result, const PString &, bool);

private:
	virtual bool Match(const AuthObj &);
//	virtual PString GetName() const { return network.AsString() + "/" + PString(PString::Unsigned, 32-priority); }

	PIPSocket::Address network, netmask;
};

IPv4AuthRule::IPv4AuthRule(Result f, const PString & cfg, bool r) : AuthRule(f, r)
{
	Toolkit::GetNetworkFromString(cfg, network, netmask);
	DWORD n = ~PIPSocket::Net2Host(DWORD(netmask));
	for (priority = 0; n; n >>= 1)
		++priority;
}

bool IPv4AuthRule::Match(const AuthObj & aobj)
{
	return ((aobj.GetIP() & netmask) == network);
}

class AliasAuthRule : public AuthRule {
public:
	AliasAuthRule(Result f, const PString & cfg, bool r) : AuthRule(f, r), pattern(cfg) { priority = -1; }

private:
	virtual bool Match(const AuthObj &);
//	virtual PString GetName() const { return pattern; }

	PString pattern;
};

bool AliasAuthRule::Match(const AuthObj & aobj)
{
	return (aobj.GetAliases().FindRegEx(pattern) != P_MAX_INDEX);
}

inline bool is_inverted(const PString & cfg, PINDEX p)
{
	return (p > 1) ? cfg[p-1] == '!' : false;
}

inline bool comp_authrule_priority(AuthRule *a1, AuthRule *a2)
{
	return *a1 < *a2;
}

// class PrefixAuth
PrefixAuth::PrefixAuth(const char *name) : GkAuthenticator(name)
{
	int ipfl = strlen(ipflag), aliasfl = strlen(aliasflag);
	PStringToString cfgs = config->GetAllKeyValues(name);
	for (PINDEX i = 0; i < cfgs.GetSize(); ++i) {
		PString key = cfgs.GetKeyAt(i);
		if (key *= "default") {
			defaultStatus = Toolkit::AsBool(cfgs.GetDataAt(i)) ? e_ok : e_fail;
			continue;
		} else if (key *= "ALL") {
			// use space (0x20) as the key so it will be the last resort
			key = " ";
		}
		if (prefrules.find(key) != prefrules.end())
			continue; //rule already exists? ignore

		PStringArray rules = cfgs.GetDataAt(i).Tokenise("|", false);
		PINDEX sz = rules.GetSize();
		if (sz < 1)
			continue;
		//AuthRule *rls[sz];
		AuthRule **rls = new AuthRule *[sz];
		for (PINDEX j = 0; j < sz; ++j) {
			PINDEX pp;
			// if not allowed, assume denial
			AuthRule::Result ft = (rules[j].Find(allowflag) != P_MAX_INDEX) ? AuthRule::e_allow : AuthRule::e_deny;
			if ((pp=rules[j].Find(ipflag)) != P_MAX_INDEX)
				rls[j] = new IPv4AuthRule(ft, rules[j].Mid(pp+ipfl), is_inverted(rules[j], pp));
			else if ((pp=rules[j].Find(aliasflag)) != P_MAX_INDEX)
				rls[j] = new AliasAuthRule(ft, rules[j].Mid(pp+aliasfl), is_inverted(rules[j], pp));
			else
				rls[j] = new NullRule;
		}

		// sort the rules by priority
		stable_sort(rls, rls + sz, comp_authrule_priority);
		for (PINDEX k = 1; k < sz; ++k)
			rls[k-1]->SetNext(rls[k]);
		prefrules[key] = rls[0];
		delete [] rls;
	}
}

PrefixAuth::~PrefixAuth()
{
	for_each(prefrules.begin(), prefrules.end(), delete_rule);
}

int PrefixAuth::Check(RasPDU<H225_GatekeeperRequest> &, unsigned &)
{
	return e_next;
}

int PrefixAuth::Check(RasPDU<H225_RegistrationRequest> & request, unsigned &)
{
	return e_next;
}

int PrefixAuth::Check(RasPDU<H225_UnregistrationRequest> &, unsigned &)
{
	return e_next;
}

int PrefixAuth::Check(RasPDU<H225_AdmissionRequest> & request, unsigned &)
{
	H225_AdmissionRequest & arq = request;
	return CallTable::Instance()->FindCallRec(arq.m_callIdentifier) ? e_ok : doCheck(ARQAuthObj(arq));
}

int PrefixAuth::Check(RasPDU<H225_BandwidthRequest> &, unsigned &)
{
	return e_next;
}

int PrefixAuth::Check(RasPDU<H225_DisengageRequest> &, unsigned &)
{
	return e_next;
}

int PrefixAuth::Check(RasPDU<H225_LocationRequest> & request, unsigned &)
{
	return doCheck(LRQAuthObj((const H225_LocationRequest&)request));
}

int PrefixAuth::Check(RasPDU<H225_InfoRequest> &, unsigned &)
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
		for (Rules::iterator j = prefrules.begin(); j != prefrules.end(); ++j) {
			Rules::iterator iter = find_if(j, prefrules.end(), comp_pref(ary[i]));
			if (iter == prefrules.end())
				break;
			switch (iter->second->Check(aobj))
			{
				case AuthRule::e_allow:
					return e_ok;
				case AuthRule::e_deny:
					return e_fail;
				default: // try next prefix...
					j = iter;
			}
		}
	}
	return defaultStatus;
}


// class GkAuthenticatorList
GkAuthenticatorList::GkAuthenticatorList() : m_head(0)
{
	m_mechanisms = new H225_ArrayOf_AuthenticationMechanism;
	m_algorithmOIDs = new H225_ArrayOf_PASN_ObjectId;
}

GkAuthenticatorList::~GkAuthenticatorList()
{
	delete m_head;
	delete m_mechanisms;
	delete m_algorithmOIDs;
}

void GkAuthenticatorList::OnReload()
{
	GkAuthenticator *head, *authenticator;
	head = GkAuthenticator::Create(GkConfig()->GetKeys(GkAuthSectionName));

	H225_ArrayOf_AuthenticationMechanism mechanisms;
	H225_ArrayOf_PASN_ObjectId algorithmOIDs;

	authenticator = head;
	bool found = false;
	int i, j, k;

	// scan all authenticators that are either "required" or "sufficient"
	// (skip "optional") and fill #mechanisms# and #algorithmOIDs# arrays
	// with H.235 capabilities that are supported by all these authenticators
	while (authenticator) {
		if (authenticator->IsH235Capable() 
				&& ((authenticator->GetControlFlag() == GkAuthenticator::e_Required)
					|| (authenticator->GetControlFlag() == GkAuthenticator::e_Sufficient))) {
			if (mechanisms.GetSize() == 0) {
				// append H.235 capability to empty arrays
				authenticator->GetH235Capability(mechanisms, algorithmOIDs);
				// should never happen, but we should check just for a case				
				if (algorithmOIDs.GetSize() == 0)
					mechanisms.RemoveAll();
				else
					found = true;
				authenticator = authenticator->GetNext();
				continue;
			}

			// Already have H.235 capabilities - check the current
			// authenticator if it supports any of the capabilities.
			// Remove capabilities that are not supported

			H225_ArrayOf_AuthenticationMechanism matchedMechanisms;

			for (i = 0; i < algorithmOIDs.GetSize(); i++) {
				bool matched = false;

				for( j = 0; j < mechanisms.GetSize(); j++ )
					if (authenticator->IsH235Capability(mechanisms[j], algorithmOIDs[i])) {
						for (k = 0; k < matchedMechanisms.GetSize(); k++)
							if (matchedMechanisms[k].GetTag() == mechanisms[j].GetTag())
								break;
						if (k == matchedMechanisms.GetSize()) {
							matchedMechanisms.SetSize(k+1);
							matchedMechanisms[k].SetTag(mechanisms[j].GetTag());
						}
						matched = true;
					}

				if (!matched) {
					PTRACE(5, "GkAuth\tRemoved from GCF list algorithm OID: " << algorithmOIDs[i]);
					algorithmOIDs.RemoveAt(i--);
				}
			}

			for (i = 0; i < mechanisms.GetSize(); i++) {
				for( j = 0; j < matchedMechanisms.GetSize(); j++ )
					if (mechanisms[i].GetTag() == matchedMechanisms[j].GetTag())
						break;
				if( j == matchedMechanisms.GetSize() ) {
					PTRACE(5, "GkAuth\tRemoved from GCF list mechanism: " << mechanisms[i]);
					mechanisms.RemoveAt(i--);
				}
			}

			if ((mechanisms.GetSize() == 0) || (algorithmOIDs.GetSize() == 0))
				break;
		}
		authenticator = authenticator->GetNext();
	}

	// Scan "optional" authenticators if the above procedure has not found
	// any H.235 capabilities or has found more than one
	if ((!found) || (mechanisms.GetSize() > 1) || (algorithmOIDs.GetSize() > 1)) {
		authenticator = head;
		while (authenticator) {
			if (authenticator->IsH235Capable() 
					&& (authenticator->GetControlFlag() == GkAuthenticator::e_Optional)) {
				if (mechanisms.GetSize() == 0) {
					authenticator->GetH235Capability(mechanisms, algorithmOIDs);
					if (algorithmOIDs.GetSize() == 0 )
						mechanisms.RemoveAll();
					else
						found = true;
					authenticator = authenticator->GetNext();
					continue;
				}

				H225_ArrayOf_AuthenticationMechanism matchedMechanisms;

				for (i = 0; i < algorithmOIDs.GetSize(); i++) {
					bool matched = false;

					for (j = 0; j < mechanisms.GetSize(); j++)
						if (authenticator->IsH235Capability(mechanisms[j], algorithmOIDs[i])) {
							for (k = 0; k < matchedMechanisms.GetSize(); k++)
								if (matchedMechanisms[k].GetTag() == mechanisms[j].GetTag())
									break;
							if (k == matchedMechanisms.GetSize()) {
								matchedMechanisms.SetSize(k+1);
								matchedMechanisms[k].SetTag(mechanisms[j].GetTag());
							}
							matched = true;
						}

					if (!matched) {
						PTRACE(5, "GkAuth\tRemoved from GCF list algorithm OID: " << algorithmOIDs[i]);
						algorithmOIDs.RemoveAt(i--);
					}
				}

				for (i = 0; i < mechanisms.GetSize(); i++) {
					for (j = 0; j < matchedMechanisms.GetSize(); j++)
						if (mechanisms[i].GetTag() == matchedMechanisms[j].GetTag())
							break;
					if (j == matchedMechanisms.GetSize()) {
						PTRACE(5, "GkAuth\tRemoved from GCF list mechanism: " << mechanisms[i]);
						mechanisms.RemoveAt(i--);
					}
				}

				if ((mechanisms.GetSize() == 0) || (algorithmOIDs.GetSize() == 0))
					break;
			}
			authenticator = authenticator->GetNext();
		}
	}

	if ((mechanisms.GetSize() > 0) && (algorithmOIDs.GetSize() > 0)) {
		if (PTrace::CanTrace(5)) {
#if PTRACING
			ostream& strm = PTrace::Begin(5,__FILE__,__LINE__);
			strm <<"GkAuth\tH.235 capabilities selected for GCF:\n";
			strm <<"\tAuthentication mechanisms: \n";
			for (i = 0; i < mechanisms.GetSize(); i++)
				strm << "\t\t" << mechanisms[i] << '\n';
			strm <<"\tAuthentication algorithm OIDs: \n";
			for (i = 0; i < algorithmOIDs.GetSize(); i++)
				strm << "\t\t" << algorithmOIDs[i] << '\n';
			PTrace::End(strm);
#endif
		}
	} else {
		PTRACE(4,"GkAuth\tConflicting H.235 capabilities are active - GCF will not select any particular capability");
		mechanisms.RemoveAll();
		algorithmOIDs.RemoveAll();
	}

	// now switch to new setting
	// FIXME: not thread-safe
	*m_mechanisms = mechanisms;
	*m_algorithmOIDs = algorithmOIDs;
	swap(m_head, head);
	delete head;
}

void GkAuthenticatorList::SelectH235Capability(const H225_GatekeeperRequest & grq, H225_GatekeeperConfirm & gcf) const
{
	if (!m_head)
		return;
		
	// if GRQ does not contain a list of authentication mechanisms simply return
	if (!(grq.HasOptionalField(H225_GatekeeperRequest::e_authenticationCapability)
			&& grq.HasOptionalField(H225_GatekeeperRequest::e_algorithmOIDs)
			&& (grq.m_authenticationCapability.GetSize() > 0))
			&& (grq.m_algorithmOIDs.GetSize() > 0))
		return;

	H225_ArrayOf_AuthenticationMechanism & mechanisms = *m_mechanisms;
	H225_ArrayOf_PASN_ObjectId & algorithmOIDs = *m_algorithmOIDs;

	// And now match H.235 capabilities found with those from GRQ
	// to find the one to be returned in GCF		
	for (int i = 0; i < grq.m_authenticationCapability.GetSize(); i++)
		for (int j = 0; j < mechanisms.GetSize(); j++)	
			if (grq.m_authenticationCapability[i].GetTag() == mechanisms[j].GetTag())
				for (int l = 0; l < algorithmOIDs.GetSize(); l++)
					for (int k = 0; k < grq.m_algorithmOIDs.GetSize(); k++)
						if (grq.m_algorithmOIDs[k] == algorithmOIDs[l]) {
							GkAuthenticator *authenticator = m_head;
							while (authenticator) {
								if (authenticator->IsH235Capable() && authenticator->IsH235Capability(mechanisms[j], algorithmOIDs[l])) {
									gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_authenticationMode);
									gcf.m_authenticationMode = mechanisms[j];
									gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_algorithmOID);
									gcf.m_algorithmOID = algorithmOIDs[l];

									PTRACE(4,"GK\tGCF will select authentication mechanism: "
										<< mechanisms[j] << " and algorithm OID: "<< algorithmOIDs[l]
									      );
									return;
								}
								authenticator = authenticator->GetNext();
							}

							PTRACE(5, "GK\tAuthentication mechanism: "
								<< mechanisms[j] << " and algorithm OID: "
								<< algorithmOIDs[l] << " dropped"
							      );
						}
}


namespace { // anonymous namespace

	GkAuthCreator<GkAuthenticator> DefaultAuthenticatorCreator("default");
	GkAuthCreator<SimplePasswordAuth> SimplePasswordAuthCreator("SimplePasswordAuth");
	GkAuthCreator<AliasAuth> AliasAuthCreator("AliasAuth");
	GkAuthCreator<PrefixAuth> PrefixAuthCreator("PrefixAuth");

#ifdef HAS_MYSQL
	GkAuthCreator<MySQLPasswordAuth> MySQLPasswordAuthCreator("MySQLPasswordAuth");
	GkAuthCreator<MySQLAliasAuth> MySQLAliasAuthCreator("MySQLAliasAuth");
#endif
#if ((defined(__GNUC__) && __GNUC__ <= 2) && !defined(WIN32))
	GkAuthCreator<ExternalPasswordAuth> ExternalPasswordAuthCreator("ExternalPasswordAuth");
#endif
} // end of anonymous namespace
