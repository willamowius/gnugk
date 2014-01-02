//////////////////////////////////////////////////////////////////
//
// lua.cxx
//
// LUA routing policy for GNU Gatekeeper
//
// Copyright (c) 2012, Jan Willamowius
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

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
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
	PString GetValue(const char * name);

protected:
	// LUA interpreter
	lua_State * m_lua;
	// script to run
	PString m_script;
};

static int gnugk_trace(lua_State * L) {
	if ((lua_gettop(L) != 2) || !lua_isnumber(L, 1) || !lua_isstring(L, 2)) {
		lua_pushstring(L, "Incorrect arguments for 'trace(level, 'message')'");
		lua_error(L);
		return 0;
	}

	PTRACE(lua_tonumber(L, 1), "LUA\t" << lua_tostring(L, 2));

	return 0; // no results
}

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
		PTRACE(2, m_name << "\tmodule creation failed: "
			<< "\tno LUA script");
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
	lua_close(m_lua);
}

void LuaPolicy::SetValue(const char * name, const char * value)
{
	lua_pushstring(m_lua, value);
	lua_setglobal(m_lua, name);
}

PString LuaPolicy::GetValue(const char * name)
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

#endif	// HAS_LUA
