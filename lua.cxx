//////////////////////////////////////////////////////////////////
//
// lua.cxx
//
// LUA routing and authentication policies for GNU Gatekeeper
//
// Copyright (c) 2012-2016, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "config.h"

#ifdef HAS_LUA

#include "Routing.h"
#include "Toolkit.h"
#include "gk_const.h"
#include "snmp.h"

#include "rasinfo.h"
#include "RasPDU.h"
#include "gkauth.h"


extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

static int gnugk_trace(lua_State * L) {
	if ((lua_gettop(L) != 2) || !lua_isnumber(L, 1) || !lua_isstring(L, 2)) {
		lua_pushstring(L, "Incorrect arguments for 'trace(level, 'message')'");
		lua_error(L);
		return 0;
	}

	PTRACE(lua_tonumber(L, 1), "LUA\t" << lua_tostring(L, 2));

	return 0; // no results
}

namespace Routing {

// a policy to route calls with LUA
class LuaPolicy : public DynamicPolicy {
public:
	LuaPolicy();
	virtual ~LuaPolicy();

protected:
	virtual void LoadConfig(const PString & instance);

	virtual void RunPolicy(
		/*in */
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType,
		const PString & clientauthid,
		const PString & language,
		/* out: */
		DestinationRoutes & destination);

	void SetValue(const char * name, const char * value);
	PString GetValue(const char * name) const;

protected:
	// LUA interpreter
	lua_State * m_lua;
	// script to run
	PString m_script;
};

LuaPolicy::LuaPolicy()
{
	m_name = "Lua";
	m_iniSection = "Routing::Lua";
	m_active = false;
	m_lua = NULL;
}

void LuaPolicy::LoadConfig(const PString & instance)
{
	m_script = GkConfig()->GetString(m_iniSection, "Script", "");
	if (m_script.IsEmpty()) {
		PString scriptFile = GkConfig()->GetString(m_iniSection, "ScriptFile", "");
		if (!scriptFile.IsEmpty()) {
			PTextFile f(scriptFile, PFile::ReadOnly);
			if (!f.IsOpen()) {
				PTRACE(1, "LUA\tCan't read LUA script " << scriptFile);
			} else {
				PString line;
				while (f.ReadLine(line)) {
					m_script += (line + "\n");
				}
			}
		}
	}

	if (m_script.IsEmpty()) {
		PTRACE(2, m_name << "\tmodule creation failed: no LUA script");
		SNMP_TRAP(4, SNMPError, General, PString(m_name) + " creation failed");
		return;
	}

	if (!m_lua) {
		m_lua = luaL_newstate();
		luaL_openlibs(m_lua);
		lua_register(m_lua, "trace", gnugk_trace);
	}
	m_active = true;
}

LuaPolicy::~LuaPolicy()
{
    if (m_lua) {
        lua_close(m_lua);
    }
}

void LuaPolicy::SetValue(const char * name, const char * value)
{
	lua_pushstring(m_lua, value);
	lua_setglobal(m_lua, name);
}

PString LuaPolicy::GetValue(const char * name) const
{
	lua_getglobal(m_lua, name);
	PString result = lua_tostring(m_lua, -1);
	lua_pop(m_lua, 1);
	return result;
}

void LuaPolicy::RunPolicy(
		/* in */
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType,
		const PString & clientauthid,
		const PString & language,
		/* out: */
		DestinationRoutes & destination)
{
	SetValue("source", source);
	SetValue("calledAlias", calledAlias);
	SetValue("calledIP", calledIP);
	SetValue("caller", caller);
	SetValue("callingStationId", callingStationId);
	SetValue("callid", callid);
	SetValue("messageType", messageType);
	SetValue("clientauthid", clientauthid);
	SetValue("language", language);
	SetValue("destAlias", "");
	SetValue("destIP", "");
	SetValue("action", "");
	SetValue("rejectCode", "");

	if (luaL_loadstring(m_lua, m_script) != 0 || lua_pcall(m_lua, 0, 0, 0) != 0) {
		PTRACE(1, "LUA\tError in LUA script: " << lua_tostring(m_lua, -1));
		lua_pop(m_lua, 1);
		return;
	}

	PString action = GetValue("action");
	PString rejectCode = GetValue("rejectCode");
	PString destAlias = GetValue("destAlias");
	PString destIP = GetValue("destIP");

	if (action.ToUpper() == "SKIP") {
		PTRACE(5, m_name << "\tSkipping to next policy");
		return;
	}

	if (action.ToUpper() == "REJECT") {
		PTRACE(5, m_name << "\tRejecting call");
		destination.SetRejectCall(true);
		if (!rejectCode.IsEmpty()) {
			destination.SetRejectReason(rejectCode.AsInteger());
		}
		return;
	}

	if (!destAlias.IsEmpty()) {
		PTRACE(5, m_name << "\tSet new destination alias " << destAlias);
		H225_ArrayOf_AliasAddress newAliases;
		newAliases.SetSize(1);
		H323SetAliasAddress(destAlias, newAliases[0]);
		destination.SetNewAliases(newAliases);
	}

	if (!destIP.IsEmpty()) {
		PTRACE(5, m_name << "\tSet new destination IP " << destIP);
		PStringArray adr_parts = SplitIPAndPort(destIP, GK_DEF_ENDPOINT_SIGNAL_PORT);
		PIPSocket::Address ip(adr_parts[0]);
		WORD port = (WORD)(adr_parts[1].AsInteger());

		Route route("Lua", SocketToH225TransportAddr(ip, port));
		route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
		if (!destAlias.IsEmpty())
			route.m_destNumber = destAlias;
		destination.AddRoute(route);
	}
}

namespace { // anonymous namespace
	SimpleCreator<LuaPolicy> LuaPolicyCreator("lua");
}

}	// namespace Routing



/// LUA authentication policy

class LuaAuth : public GkAuthenticator
{
public:
	enum SupportedRasChecks {
		/// bitmask of RAS checks implemented by this module
		LuaAuthRasChecks = RasInfo<H225_RegistrationRequest>::flag
//			| RasInfo<H225_UnregistrationRequest>::flag
//			| RasInfo<H225_BandwidthRequest>::flag
//			| RasInfo<H225_DisengageRequest>::flag
//			| RasInfo<H225_LocationRequest>::flag
//			| RasInfo<H225_InfoRequest>::flag
			| RasInfo<H225_AdmissionRequest>::flag,
		LuaAuthMiscChecks = e_Setup | e_SetupUnreg
	};

	LuaAuth(
		const char* name, /// a name for this module (a config section name)
		unsigned supportedRasChecks = LuaAuthRasChecks,
		unsigned supportedMiscChecks = LuaAuthMiscChecks
		);

	virtual ~LuaAuth();

	// overriden from class GkAuthenticator
//	virtual int Check(RasPDU<H225_UnregistrationRequest> & req, unsigned & rejectReason);
//	virtual int Check(RasPDU<H225_BandwidthRequest> & req, unsigned & rejectReason);
//	virtual int Check(RasPDU<H225_DisengageRequest> & req, unsigned & rejectReason);
//	virtual int Check(RasPDU<H225_LocationRequest> & req, unsigned & rejectReason);
//	virtual int Check(RasPDU<H225_InfoRequest> & req, unsigned & rejectReason);

	/** Authenticate/Authorize RAS or signaling message.
	    An override from GkAuthenticator.

	    @return
	    e_fail - authentication rejected the request
	    e_ok - authentication accepted the request
	    e_next - authentication is not supported for this request
	             or cannot be determined (SQL failure, no cryptoTokens, ...)
	*/
	virtual int Check(
		/// RRQ to be authenticated/authorized
		RasPDU<H225_RegistrationRequest> & request,
		/// authorization data (reject reason, ...)
		RRQAuthData & authData
		);
	virtual int Check(
		/// ARQ to be authenticated/authorized
		RasPDU<H225_AdmissionRequest> & request,
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData & authData
		);

	/** Authenticate using data from Q.931 Setup message.

		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// Q.931/H.225 Setup message to be authenticated
		SetupMsg & setup,
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData & authData
		);

protected:
	/** Run the LUA registration authentication script

		@return
		e_ok 	if authentication OK
		e_fail	if authentication failed
		e_next	go to next policy
	*/
	int doRegistrationCheck(
		const PString & username,
		const PString & callerIP,
		const PString & aliases,
		const PString & messageType
		);

	/** Run the LUA call authentication script

		@return
		e_ok 	if authentication OK
		e_fail	if authentication failed
		e_next	go to next policy
	*/
	int doCallCheck(
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType
		);

	void SetString(const char * name, const char * value);
	PString GetString(const char * name) const;
	void SetNumber(const char * name, double value);
	double GetNumber(const char * name) const;
	void SetBoolean(const char * name, bool value);
	bool GetBoolean(const char * name) const;

private:
	LuaAuth();
	LuaAuth(const LuaAuth &);
	LuaAuth & operator=(const LuaAuth &);

protected:
	// LUA interpreter
	lua_State * m_lua;
	// scripts to run
	PString m_registrationScript;
	PString m_callScript;
};

LuaAuth::LuaAuth(
	const char * name,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks)
	: GkAuthenticator(name, supportedRasChecks, supportedMiscChecks)
{
	m_registrationScript = GkConfig()->GetString("LuaAuth", "RegistrationScript", "");
	if (m_registrationScript.IsEmpty()) {
		PString scriptFile = GkConfig()->GetString("LuaAuth", "RegistrationScriptFile", "");
		if (!scriptFile.IsEmpty()) {
			PTextFile f(scriptFile, PFile::ReadOnly);
			if (!f.IsOpen()) {
				PTRACE(1, "LuaAuth\tCan't read LUA call script " << scriptFile);
			} else {
				PString line;
				while (f.ReadLine(line)) {
					m_registrationScript += (line + "\n");
				}
			}
		}
	}

	m_callScript = GkConfig()->GetString("LuaAuth", "CallScript", "");
	if (m_callScript.IsEmpty()) {
		PString scriptFile = GkConfig()->GetString("LuaAuth", "CallScriptFile", "");
		if (!scriptFile.IsEmpty()) {
			PTextFile f(scriptFile, PFile::ReadOnly);
			if (!f.IsOpen()) {
				PTRACE(1, "LuaAuth\tCan't read LUA call script " << scriptFile);
			} else {
				PString line;
				while (f.ReadLine(line)) {
					m_callScript += (line + "\n");
				}
			}
		}
	}

	if (m_registrationScript.IsEmpty() && m_callScript.IsEmpty()) {
		PTRACE(2, "LuaAuth\tno LUA script");
		SNMP_TRAP(4, SNMPError, General, "LuaAuth: no script");
	}

	m_lua = luaL_newstate();
	luaL_openlibs(m_lua);
	lua_register(m_lua, "trace", gnugk_trace);
}

LuaAuth::~LuaAuth()
{
    if (m_lua) {
        lua_close(m_lua);
    }
}

void LuaAuth::SetString(const char * name, const char * value)
{
	lua_pushstring(m_lua, value);
	lua_setglobal(m_lua, name);
}

PString LuaAuth::GetString(const char * name) const
{
	lua_getglobal(m_lua, name);
	PString result = lua_tostring(m_lua, -1);
	lua_pop(m_lua, 1);
	return result;
}

void LuaAuth::SetNumber(const char * name, double value)
{
	lua_pushnumber(m_lua, value);
	lua_setglobal(m_lua, name);
}

double LuaAuth::GetNumber(const char * name) const
{
	lua_getglobal(m_lua, name);
	double result = lua_tonumber(m_lua, -1);
	lua_pop(m_lua, 1);
	return result;
}

void LuaAuth::SetBoolean(const char * name, bool value)
{
	lua_pushboolean(m_lua, value);
	lua_setglobal(m_lua, name);
}

bool LuaAuth::GetBoolean(const char * name) const
{
	lua_getglobal(m_lua, name);
	bool result = lua_toboolean(m_lua, -1);
	lua_pop(m_lua, 1);
	return result;
}

/*
int LuaAuth::Check(RasPDU<H225_UnregistrationRequest> & request, unsigned &)
{
	return doCheck(request);
}

int LuaAuth::Check(RasPDU<H225_BandwidthRequest> & request, unsigned &)
{
	return doCheck(request);
}

int LuaAuth::Check(RasPDU<H225_DisengageRequest> & request, unsigned &)
{
	return doCheck(request);
}

int LuaAuth::Check(RasPDU<H225_LocationRequest> & request, unsigned &)
{
	return doCheck(request);
}

int LuaAuth::Check(RasPDU<H225_InfoRequest> & request, unsigned &)
{
	return doCheck(request);
}
*/

int LuaAuth::Check(
	RasPDU<H225_RegistrationRequest> & rrqPdu,
	RRQAuthData & authData)
{
	H225_RegistrationRequest & rrq = rrqPdu;

	PString username = GetUsername(rrqPdu);
	PIPSocket::Address addr = (rrqPdu.operator->())->m_peerAddr;
	PString callerIP = addr.AsString();
    PString aliases = "";
	if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
		for (PINDEX i = 0; i < rrq.m_terminalAlias.GetSize(); i++) {
			if (i > 0) {
				aliases += ",";
            }
			aliases += AsString(rrq.m_terminalAlias[i], FALSE);
		}
	}

	PString messageType = "RRQ";
	return doRegistrationCheck(username, callerIP, aliases, messageType);
}

int LuaAuth::Check(
	/// ARQ to be authenticated/authorized
	RasPDU<H225_AdmissionRequest> & request,
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData & authData)
{
	H225_ArrayOf_AliasAddress aliases;
	H225_AdmissionRequest & arq = request;
	if (arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)) {
		aliases = arq.m_destinationInfo;
	}
	endptr ep = RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier);
	if (ep) {
		PString source = AsDotString(ep->GetCallSignalAddress());
		PString calledAlias = "";
		if (aliases.GetSize() > 0)
			calledAlias = AsString(aliases[0], FALSE);
		PString calledIP = "";	/* not available for ARQs */
		PString caller = AsString(arq.m_srcInfo, FALSE);
		PString callingStationId = authData.m_callingStationId;
		PString callid = AsString(arq.m_callIdentifier.m_guid);
		PString messageType = "ARQ";
		return doCallCheck(source, calledAlias, calledIP, caller, callingStationId, callid, messageType);
	} else {
		return e_fail;
	}
}

int LuaAuth::Check(
	/// Q.931/H.225 Setup message to be authenticated
	SetupMsg & setup,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData & authData
	)
{
	H225_Setup_UUIE & setup_uuie = setup.GetUUIEBody();

    PString source = "";
    if (setup_uuie.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress))
        source = AsDotString(setup_uuie.m_sourceCallSignalAddress);
	PString calledAlias = GetCalledStationId(setup, authData);
	PString calledIP = "";
	if (setup_uuie.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress))
        calledIP = AsDotString(setup_uuie.m_destCallSignalAddress);
	PString callingStationId = GetCallingStationId(setup, authData);
	PString caller = callingStationId;
	PString callid = AsString(setup_uuie.m_callIdentifier.m_guid);
	PString messageType = "Setup";
	return doCallCheck(source, calledAlias, calledIP, caller, callingStationId, callid, messageType);
}

int LuaAuth::doRegistrationCheck(
		const PString & username,
		const PString & callerIP,
		const PString & aliases,
		const PString & messageType
		)
{
    if (!m_lua || m_registrationScript.IsEmpty()) {
		PTRACE(1, "LuaAuth\tError: LUA not configured");
		return e_fail;
    }

	SetString("username", username);
	SetString("callerIP", callerIP);
	SetString("aliases", aliases);
	SetString("messageType", messageType);
	SetString("result", "FAIL");

	if (luaL_loadstring(m_lua, m_registrationScript) != 0 || lua_pcall(m_lua, 0, 0, 0) != 0) {
		PTRACE(1, "LuaAuth\tError in LUA script: " << lua_tostring(m_lua, -1));
		lua_pop(m_lua, 1);
		return e_fail;
	}

	PString result = GetString("result");
	if (result.ToUpper() == "OK") {
		return e_ok;
	} else if (result.ToUpper() == "NEXT") {
		return e_next;
	} else {
		return e_fail;
	}
}

int LuaAuth::doCallCheck(
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType
		)
{
    if (!m_lua || m_callScript.IsEmpty()) {
		PTRACE(1, "LuaAuth\tError: LUA not configured");
		return e_fail;
    }

	SetString("source", source);
	SetString("calledAlias", calledAlias);
	SetString("calledIP", calledIP);
	SetString("caller", caller);
	SetString("callingStationId", callingStationId);
	SetString("callid", callid);
	SetString("messageType", messageType);
	SetString("result", "FAIL");

	if (luaL_loadstring(m_lua, m_callScript) != 0 || lua_pcall(m_lua, 0, 0, 0) != 0) {
		PTRACE(1, "LuaAuth\tError in LUA script: " << lua_tostring(m_lua, -1));
		lua_pop(m_lua, 1);
		return e_fail;
	}

	PString result = GetString("result");
	if (result.ToUpper() == "OK") {
		return e_ok;
	} else if (result.ToUpper() == "NEXT") {
		return e_next;
	} else {
		return e_fail;
	}
}

namespace { // anonymous namespace
	GkAuthCreator<LuaAuth> LuaAuthCreator("LuaAuth");
} // end of anonymous namespace

#endif	// HAS_LUA
