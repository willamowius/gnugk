//////////////////////////////////////////////////////////////////
//
// snmp.cxx for GNU Gatekeeper
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

#ifdef HAS_SNMP

#include "snmp.h"
#include "gk.h"
#include "job.h"
#include "SoftPBX.h"

void ReloadHandler();

const char * const GnuGkMIBStr           = "1.3.6.1.4.1.27938.11";
const char * const ShortVersionOIDStr    = "1.3.6.1.4.1.27938.11.1.1";
const char * const LongVersionOIDStr     = "1.3.6.1.4.1.27938.11.1.2";
const char * const RegistrationsOIDStr   = "1.3.6.1.4.1.27938.11.1.3";
const char * const CallsOIDStr           = "1.3.6.1.4.1.27938.11.1.4";
const char * const TraceLevelOIDStr      = "1.3.6.1.4.1.27938.11.1.5";
const char * const CatchAllOIDStr        = "1.3.6.1.4.1.27938.11.1.6";
const char * const TotalCallsOIDStr      = "1.3.6.1.4.1.27938.11.1.7";
const char * const SuccessfulCallsOIDStr = "1.3.6.1.4.1.27938.11.1.8";
const char * const severityOIDStr        = "1.3.6.1.4.1.27938.11.2.1";
const char * const groupOIDStr           = "1.3.6.1.4.1.27938.11.2.2";
const char * const displayMsgOIDStr      = "1.3.6.1.4.1.27938.11.2.3";


#ifdef HAS_NETSNMP

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/agent_module_config.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

const char * agent_name = "gnugk-agent";

static oid snmptrap_oid[]       = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
static oid ShortVersionOID[]    = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 1 };
static oid LongVersionOID[]     = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 2 };
static oid RegistrationsOID[]   = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 3 };
static oid CallsOID[]           = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 4 };
static oid TraceLevelOID[]      = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 5 };
static oid CatchAllOID[]        = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 6 };
static oid TotalCallsOID[]      = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 7 };
static oid SuccessfulCallsOID[] = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 8 };
static oid severityOID[]        = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 1 };
static oid groupOID[]           = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 2 };
static oid displayMsgOID[]      = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 3 };


void SendNetSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg)
{
	PTRACE(5, "SNMP\tSendSNMPTrap " << trapNumber << ", " << severity << ", " << group << ", " << msg);
	oid trapOID[]              = { 1, 3, 6, 1, 4, 1, 27938, 11, 0, 99999 };

	// insert trapNumber as last digit
	trapOID[ OID_LENGTH(trapOID) - 1 ] = trapNumber;

	netsnmp_variable_list *var_list = NULL;
	// set snmpTrapOid.0 value
    snmp_varlist_add_variable(&var_list,
                              snmptrap_oid, OID_LENGTH(snmptrap_oid),
                              ASN_OBJECT_ID, (u_char *)trapOID, sizeof(trapOID));
	// add severity and group object
	snmp_varlist_add_variable(&var_list, severityOID, OID_LENGTH(severityOID),
                              ASN_INTEGER, (u_char *)&severity, sizeof(severity));
	snmp_varlist_add_variable(&var_list, groupOID, OID_LENGTH(groupOID),
                              ASN_INTEGER, (u_char *)&group, sizeof(group));
	snmp_varlist_add_variable(&var_list, displayMsgOID, OID_LENGTH(displayMsgOID),
                              ASN_OCTET_STR, (u_char *)((const char *)msg), msg.GetLength());
	send_v2trap(var_list);
	snmp_free_varbind(var_list);
}

extern "C" {

int ptrace_logger(netsnmp_log_handler * handler, int prio, const char * message)
{
	if (message) {
		PTRACE((prio <= LOG_WARNING ? 1 : 4), "NetSNMP\t" << message);
	}
    return 1;
}

int short_version_handler(netsnmp_mib_handler * /* handler */,
							netsnmp_handler_registration * /* reg */,
							netsnmp_agent_request_info * reqinfo,
							netsnmp_request_info * requests)
{
    if (reqinfo->mode != MODE_GET)
		return SNMPERR_SUCCESS;
    for (netsnmp_request_info *request = requests; request; request = request->next) {
	    PString version = PProcess::Current().GetVersion(true);
		snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (u_char *)((const char *)version), version.GetLength());
	}
	return SNMPERR_SUCCESS;
}

int long_version_handler(netsnmp_mib_handler * /* handler */,
							netsnmp_handler_registration * /* reg */,
							netsnmp_agent_request_info * reqinfo,
							netsnmp_request_info * requests)
{
    if (reqinfo->mode != MODE_GET)
		return SNMPERR_SUCCESS;
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (u_char *)((const char *)Toolkit::GKVersion()), Toolkit::GKVersion().GetLength());
	}
	return SNMPERR_SUCCESS;
}

int registrations_handler(netsnmp_mib_handler * /* handler */,
							netsnmp_handler_registration * /* reg */,
							netsnmp_agent_request_info * reqinfo,
							netsnmp_request_info * requests)
{
    if (reqinfo->mode != MODE_GET)
		return SNMPERR_SUCCESS;
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		unsigned no_regs = RegistrationTable::Instance()->Size();
		snmp_set_var_typed_integer(request->requestvb, ASN_UNSIGNED, no_regs);
	}
	return SNMPERR_SUCCESS;
}

int calls_handler(netsnmp_mib_handler * /* handler */,
							netsnmp_handler_registration * /* reg */,
							netsnmp_agent_request_info * reqinfo,
							netsnmp_request_info * requests)
{
    if (reqinfo->mode != MODE_GET)
		return SNMPERR_SUCCESS;
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		unsigned no_calls = CallTable::Instance()->Size();
		snmp_set_var_typed_integer(request->requestvb, ASN_UNSIGNED, no_calls);
	}
	return SNMPERR_SUCCESS;
}

int totalcalls_handler(netsnmp_mib_handler * /* handler */,
							netsnmp_handler_registration * /* reg */,
							netsnmp_agent_request_info * reqinfo,
							netsnmp_request_info * requests)
{
    if (reqinfo->mode != MODE_GET)
		return SNMPERR_SUCCESS;
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		unsigned no_calls = CallTable::Instance()->TotalCallCount();
		snmp_set_var_typed_integer(request->requestvb, ASN_COUNTER, no_calls);
	}
	return SNMPERR_SUCCESS;
}

int successfulcalls_handler(netsnmp_mib_handler * /* handler */,
							netsnmp_handler_registration * /* reg */,
							netsnmp_agent_request_info * reqinfo,
							netsnmp_request_info * requests)
{
    if (reqinfo->mode != MODE_GET)
		return SNMPERR_SUCCESS;
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		unsigned no_calls = CallTable::Instance()->SuccessfulCallCount();
		snmp_set_var_typed_integer(request->requestvb, ASN_COUNTER, no_calls);
	}
	return SNMPERR_SUCCESS;
}

int tracelevel_handler(netsnmp_mib_handler * /* handler */,
							netsnmp_handler_registration * /* reg */,
							netsnmp_agent_request_info * reqinfo,
							netsnmp_request_info * requests)
{
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		if (reqinfo->mode == MODE_GET) {
			snmp_set_var_typed_integer(request->requestvb, ASN_UNSIGNED, PTrace::GetLevel());
		} else if (reqinfo->mode == MODE_SET_ACTION) {
			if (requests->requestvb->val.integer) {
				PTrace::SetLevel(*(requests->requestvb->val.integer));
			} else {
				return SNMPERR_GENERR;
			}
		}
	}
	return SNMPERR_SUCCESS;
}

int catchall_handler(netsnmp_mib_handler * /* handler */,
							netsnmp_handler_registration * /* reg */,
							netsnmp_agent_request_info * reqinfo,
							netsnmp_request_info * requests)
{
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		if (reqinfo->mode == MODE_GET) {
			PString catchAllDest = GkConfig()->GetString("Routing::CatchAll", "CatchAllIP", "");
			if (catchAllDest.IsEmpty())
				catchAllDest = GkConfig()->GetString("Routing::CatchAll", "CatchAllAlias", "catchall");
			snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (u_char*)((const char *)catchAllDest), catchAllDest.GetLength());
		} else if (reqinfo->mode == MODE_SET_ACTION) {
			PString dest = (const char *)requests->requestvb->val.string;
			if (IsIPAddress(dest)) {
				Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllIP", dest);
				Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllAlias", "");
			} else {
				Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllIP", "");
				Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllAlias", dest);
			}
			ConfigReloadMutex.StartWrite();
			ReloadHandler();
			ConfigReloadMutex.EndWrite();
		}
	}
	return SNMPERR_SUCCESS;
}

}


class NetSNMPAgent : public Singleton<NetSNMPAgent>
{
public:
	NetSNMPAgent();
	virtual ~NetSNMPAgent();

	virtual void Run();
	virtual void Stop();

protected:
	netsnmp_log_handler * m_logger;
	netsnmp_handler_registration * m_handler;
	bool m_shutdown;
};

NetSNMPAgent::NetSNMPAgent() : Singleton<NetSNMPAgent>("NetSNMPAgent")
{
	PTRACE(1, "SNMP\tStarting SNMP agent (Net-SNMP)");
	m_logger = NULL;
	m_handler = NULL;
	m_shutdown = false;
}

NetSNMPAgent::~NetSNMPAgent()
{
	PTRACE(1, "SNMP\tDeleting SNMP agent (Net-SNMP)");
	m_shutdown = true;
}

void NetSNMPAgent::Stop()
{
	PTRACE(1, "SNMP\tStopping SNMP agent (Net-SNMP)");
	m_shutdown = true;
	snmp_shutdown(agent_name);
}

void NetSNMPAgent::Run()
{
	bool standalone = Toolkit::AsBool(GkConfig()->GetString(SNMPSection, "Standalone", "0"));

	// enable Net-SNMP logging via PTRACE
	m_logger = netsnmp_register_loghandler(NETSNMP_LOGHANDLER_CALLBACK, LOG_DEBUG);
	if (m_logger) {
		m_logger->handler = ptrace_logger;
		snmp_enable_calllog();
		PTRACE(5, "SNMP\tLogger installed");
	} else {
		PTRACE(1, "SNMP\tError installing logger");
	}

	if (standalone) {
		netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_NO_ROOT_ACCESS, 1);
		netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_AGENTX_MASTER, 0);
		netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_SMUX_SOCKET, "127.0.0.1:11199");
		PString listenIP = "udp:" + GkConfig()->GetString(SNMPSection, "AgentListenIP", "127.0.0.1");
		PString listenPort = PString(PString::Unsigned, GkConfig()->GetInteger(SNMPSection, "AgentListenPort", 161));
		listenIP += ":" + listenPort;
		netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_PORTS, (const char *)listenIP);
	} else {
		// run as AgentX sub-agent
		netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
		// use 127.0.0.1:705 by default, can be overriden in $HOME/.snmp/agentx.conf
		netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_X_SOCKET, "tcp:127.0.0.1:705");
		netsnmp_enable_subagent();
	}

	init_agent(agent_name);

	netsnmp_register_scalar(
		netsnmp_create_handler_registration("short version", short_version_handler, ShortVersionOID, OID_LENGTH(ShortVersionOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("long version", long_version_handler, LongVersionOID, OID_LENGTH(LongVersionOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("registrations", registrations_handler, RegistrationsOID, OID_LENGTH(RegistrationsOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("calls", calls_handler, CallsOID, OID_LENGTH(CallsOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("total calls", totalcalls_handler, TotalCallsOID, OID_LENGTH(TotalCallsOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("successful calls", successfulcalls_handler, SuccessfulCallsOID, OID_LENGTH(SuccessfulCallsOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("catchall", tracelevel_handler, TraceLevelOID, OID_LENGTH(TraceLevelOID), HANDLER_CAN_RWRITE));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("catchall", catchall_handler, CatchAllOID, OID_LENGTH(CatchAllOID), HANDLER_CAN_RWRITE));

	init_snmp(agent_name);   // reads $HOME/.snmp/gnugk-agent.conf + $HOME/.snmp/agentx.conf

	if (standalone)
		init_master_agent();

	SNMP_TRAP(1, SNMPInfo, General, "GnuGk started");	// when registering as agent, send started trap after connecting

	while (!m_shutdown) {
		agent_check_and_process(1); // 1 means block
	}

	if (standalone)
		shutdown_master_agent();
}

#endif // HAS_NETSNMP


#ifdef P_SNMP

#include <ptclib/psnmp.h>

class PTLibSNMPAgent;

static PTLibSNMPAgent * g_ptlibAgentPtr = NULL;

void SendPTLibSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg)
{
	PTRACE(5, "SNMP\tSendSNMPTrap " << trapNumber << ", " << severity << ", " << group << ", " << msg);
	PString trapHost = GkConfig()->GetString(SNMPSection, "TrapHost", "");
	if (!trapHost.IsEmpty()) {
		// DNS resolve TrapHost
		PIPSocket::Address trapHostIP;
		H323TransportAddress addr = H323TransportAddress(trapHost);
		addr.GetIpAddress(trapHostIP);
		if (!trapHostIP.IsValid()) {
			PTRACE(1, "SNMP\tCan't resolve TrapHost " << trapHost);
			return;
		}
		PString trapCommunity = GkConfig()->GetString(SNMPSection, "TrapCommunity", "public");
		PSNMPVarBindingList vars;
		vars.Append(PString(severityOIDStr), new PASNInteger(severity));
		vars.Append(PString(groupOIDStr), new PASNInteger(group));
		vars.AppendString(displayMsgOIDStr, msg);
		PSNMP::SendEnterpriseTrap(trapHostIP, trapCommunity,
			GnuGkMIBStr + PString(".0"), trapNumber,
			PInt32((PTime() - SoftPBX::StartUp).GetMilliSeconds() / 10), vars);
	}
}

class PTLibSNMPAgent : public PSNMPServer
{
public:
	PTLibSNMPAgent();
	virtual ~PTLibSNMPAgent();

    virtual PBoolean Authorise(const PIPSocket::Address & received);
    virtual PBoolean ConfirmCommunity(PASN_OctetString & community);
    virtual PBoolean OnGetRequest(PINDEX reqID, PSNMP::BindingList & vars, PSNMP::ErrorType & errCode);
    virtual PBoolean OnGetNextRequest(PINDEX reqID, PSNMP::BindingList & vars, PSNMP::ErrorType & errCode);
    virtual PBoolean OnSetRequest(PINDEX reqID, PSNMP::BindingList & vars, PSNMP::ErrorType & errCode);
    virtual PBoolean ConfirmVersion(PASN_Integer vers);
	virtual PBoolean MIB_LocalMatch(PSNMP_PDU & answerPDU);

  protected:
    PRFC1155_SimpleSyntax sys_description;
};


PTLibSNMPAgent::PTLibSNMPAgent()
	: PSNMPServer(PIPSocket::Address(GkConfig()->GetString(SNMPSection, "AgentListenIP", "127.0.0.1")),
		(WORD)GkConfig()->GetInteger(SNMPSection, "AgentListenPort", 161))
{
	PTRACE(1, "SNMP\tStarting SNMP agent (PTLib)");
}

PTLibSNMPAgent::~PTLibSNMPAgent()
{
	PTRACE(1, "SNMP\tDeleting SNMP agent (PTLib)");
}

PBoolean PTLibSNMPAgent::Authorise(const PIPSocket::Address & ip)
{
	PStringArray networks = GkConfig()->GetString(SNMPSection, "AllowRequestsFrom", "").Tokenise(",", FALSE);
	for (PINDEX n=0; n < networks.GetSize(); ++n) {
		if (networks[n].Find('/') == P_MAX_INDEX)
			networks[n] += "/32";	// add netmask to pure IPs
		NetworkAddress net = NetworkAddress(networks[n]);
		if (ip << net) {
			return PTrue;
		}
	}
	return PFalse;
}

PBoolean PTLibSNMPAgent::ConfirmCommunity(PASN_OctetString & community)
{
	// community string security is a joke, just accept any community and rely on IP authorization
	return PTrue;
}

PBoolean PTLibSNMPAgent::OnGetRequest(PINDEX reqID, PSNMP::BindingList & vars, PSNMP::ErrorType & errCode)
{
	return PTrue; // allow GET requests
}

PBoolean PTLibSNMPAgent::OnGetNextRequest(PINDEX reqID, PSNMP::BindingList & vars, PSNMP::ErrorType & errCode)
{
	return PTrue; // allow GETNEXT requests
}

PBoolean PTLibSNMPAgent::OnSetRequest(PINDEX reqID, PSNMP::BindingList & vars, PSNMP::ErrorType & errCode)
{
	return PFalse;	// doesn't work

/*
	// TODO: PSNMPServer::ProcessPDU() must send a response and the decoding of SET values is broken
	for(PSNMP::BindingList::iterator i = vars.begin(); i != vars.end(); ++i){
		if (i->first == TraceLevelOIDStr + PString(".0")) {
			if (i->second.GetObject().GetTag() == PASN_Object::UniversalInteger) {
				PASN_Integer & num = (PASN_Integer &)(i->second.GetObject());
				PTRACE(0, "JW SET " << i->first << " to " << num << " = " << num.GetValue());	// TODO / BUG
				//PTrace::SetLevel(num.GetValue());
				return PTrue;
			} else {
				PTRACE(1, "SNMP\tWrong data type for SET " << i->first);
				return PFalse;
			}
		} else if (i->first == CatchAllOIDStr + PString(".0")) {
			if (i->second.GetObject().GetTag() == PASN_Object::UniversalOctetString) {
				PASN_OctetString & str = (PASN_OctetString &)(i->second.GetObject());
				PTRACE(0, "JW SET " << i->first << " to " << str << " = " << str.GetValue());	// TODO / BUG
				return PTrue;
			} else {
				PTRACE(1, "SNMP\tWrong data type for SET " << i->first);
				return PFalse;
			}
		}
	}
	return PFalse;
*/
}

// 0=SNMPv1, 1=SNMPv2
PBoolean PTLibSNMPAgent::ConfirmVersion(PASN_Integer vers)
{
	return (vers <= 1);	// only accept version 1 or 2
}

void SetRFC1155Object(PRFC1155_ObjectSyntax & obj, unsigned i)
{
	// according to RFC 1902 Gauge32 is identical ro Unsigned32; PTLib only has Gauge
	PRFC1155_ApplicationSyntax appl(PRFC1155_ApplicationSyntax::e_gauge);
	PRFC1155_ObjectSyntax * newObj = (PRFC1155_ObjectSyntax*)&appl;
	PASN_Integer * num = (PASN_Integer *)&appl.GetObject();
	num->SetValue(i);
	obj = *newObj;
}

void SetRFC1155CounterObject(PRFC1155_ObjectSyntax & obj, unsigned i)
{
	PRFC1155_ApplicationSyntax appl(PRFC1155_ApplicationSyntax::e_counter);
	PRFC1155_ObjectSyntax * newObj = (PRFC1155_ObjectSyntax*)&appl;
	PASN_Integer * num = (PASN_Integer *)&appl.GetObject();
	num->SetValue(i);
	obj = *newObj;
}

void SetRFC1155Object(PRFC1155_ObjectSyntax & obj, const PString & str)
{
	PRFC1155_SimpleSyntax simple(PRFC1155_SimpleSyntax::e_string);
	PRFC1155_ObjectSyntax * newObj = (PRFC1155_ObjectSyntax*)&simple;
	PASN_OctetString * strObj = (PASN_OctetString *)&simple.GetObject();
	strObj->SetValue(str);
	obj = *newObj;
}

PBoolean PTLibSNMPAgent::MIB_LocalMatch(PSNMP_PDU & answerPDU)
{
	PSNMP_VarBindList & vars = answerPDU.m_variable_bindings;
	bool found = false;

	for(PINDEX i = 0; i < vars.GetSize(); i++){
		if (vars[i].m_name == ShortVersionOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, PProcess::Current().GetVersion(true));
			found = true;
		} else if (vars[i].m_name == LongVersionOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, Toolkit::GKVersion());
			found = true;
		} else if (vars[i].m_name == RegistrationsOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, RegistrationTable::Instance()->Size());
			found = true;
		} else if (vars[i].m_name == CallsOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, CallTable::Instance()->Size());
			found = true;
		} else if (vars[i].m_name == TotalCallsOIDStr + PString(".0")) {
			SetRFC1155CounterObject(vars[i].m_value, CallTable::Instance()->TotalCallCount());
			found = true;
		} else if (vars[i].m_name == SuccessfulCallsOIDStr + PString(".0")) {
			SetRFC1155CounterObject(vars[i].m_value, CallTable::Instance()->SuccessfulCallCount());
			found = true;
		} else if (vars[i].m_name == TraceLevelOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, PTrace::GetLevel());
			found = true;
		} else if (vars[i].m_name == CatchAllOIDStr + PString(".0")) {
			PString catchAllDest = GkConfig()->GetString("Routing::CatchAll", "CatchAllIP", "");
			if (catchAllDest.IsEmpty())
				catchAllDest = GkConfig()->GetString("Routing::CatchAll", "CatchAllAlias", "catchall");
			SetRFC1155Object(vars[i].m_value, catchAllDest);
			found = true;
		}
	}

	return found;
}

#endif	// P_SNMP


#ifdef _WIN32

#define BUFSIZE 512
const char * const getPipename = "\\\\.\\pipe\\GnuGkGetSNMP";
const char * const trapPipename = "\\\\.\\pipe\\GnuGkTrapSNMP";

class WindowsSNMPAgent : public Singleton<WindowsSNMPAgent>
{
public:
	WindowsSNMPAgent();
	virtual ~WindowsSNMPAgent();

	virtual void Run();
	virtual void Stop();
	virtual PString HandleRequest(const PString & request);

	virtual void SendWindowsSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg);

protected:
	HANDLE m_getPipe;
	bool m_shutdown;
};

WindowsSNMPAgent::WindowsSNMPAgent() : Singleton<WindowsSNMPAgent>("WindowsSNMPAgent")
{
	PTRACE(1, "SNMP\tStarting SNMP agent (Windows)");
	m_shutdown = false;
	m_getPipe = CreateNamedPipe(getPipename,
		PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		1, BUFSIZE, BUFSIZE, 0, NULL);
}

WindowsSNMPAgent::~WindowsSNMPAgent()
{
	PTRACE(1, "SNMP\tDeleting SNMP agent (Windows)");
	// CloseHandle(m_getPipe);	// don't close get pipe, will hang in blocking ConnectNamedPipe()
}

void WindowsSNMPAgent::Stop()
{
	PTRACE(1, "SNMP\tStopping SNMP agent (Windows)");
	m_shutdown = true;
}

void WindowsSNMPAgent::Run()
{
	SNMP_TRAP(1, SNMPInfo, General, "GnuGk started");
	while (!m_shutdown) {	// main loop: wait for connection from extension DLL until shutdown
		if (ConnectNamedPipe(m_getPipe, NULL)) {	// wait for DLL to connect
			// the pipe is connected; change to message-read mode.
			DWORD dwMode = PIPE_READMODE_MESSAGE;
			if (!SetNamedPipeHandleState(m_getPipe, &dwMode, NULL, NULL)) {
				PTRACE(1, "SNMP\tSetNamedPipeHandleState failed. GLE=" << GetLastError());
			}

			PTRACE(0, "JW connected SNMP extension DLL pipes");
			// read server request and respond, then disconnect
			char buffer[BUFSIZE];
			DWORD bytesRead;
			if (ReadFile(m_getPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
				PString request((const char *)&buffer, bytesRead);
				PString response = HandleRequest(request);
				// Send response to the pipe server
				DWORD bytesWritten;
				WriteFile(m_getPipe, response.GetPointer(), response.GetLength(), &bytesWritten, NULL);
			}
			DisconnectNamedPipe(m_getPipe);
		}
	} // while running
}

PString WindowsSNMPAgent::HandleRequest(const PString & request)
{
	PStringArray token = request.Tokenise(" ", FALSE);
	if ((token.GetSize() == 2) && (token[0] == "GET")) {
		if (token[1] == ShortVersionOIDStr + PString(".0")) {
			return "GET_RESPONSE s " + PProcess::Current().GetVersion(true);
		}
		if (token[1] == LongVersionOIDStr + PString(".0")) {
			return "GET_RESPONSE s " + Toolkit::GKVersion();
		}
		if (token[1] == RegistrationsOIDStr + PString(".0")) {
			return "GET_RESPONSE u " + PString(PString::Unsigned, RegistrationTable::Instance()->Size());
		}
		if (token[1] == CallsOIDStr + PString(".0")) {
			return "GET_RESPONSE u " + PString(PString::Unsigned, CallTable::Instance()->Size());
		}
		if (token[1] == TotalCallsOIDStr + PString(".0")) {
			return "GET_RESPONSE c " + PString(PString::Unsigned, CallTable::Instance()->TotalCallCount());
		}
		if (token[1] == SuccessfulCallsOIDStr + PString(".0")) {
			return "GET_RESPONSE c " + PString(PString::Unsigned, CallTable::Instance()->SuccessfulCallCount());
		}
		if (token[1] == TraceLevelOIDStr + PString(".0")) {
			return "GET_RESPONSE u " + PString(PString::Unsigned, PTrace::GetLevel());
		}
		if (token[1] == CatchAllOIDStr + PString(".0")) {
			PString catchAllDest = GkConfig()->GetString("Routing::CatchAll", "CatchAllIP", "");
			if (catchAllDest.IsEmpty())
				catchAllDest = GkConfig()->GetString("Routing::CatchAll", "CatchAllAlias", "catchall");
			return "GET_RESPONSE s " + catchAllDest;
		}
	} else if ((token.GetSize() == 3) && (token[0] == "SET")) {
		if (token[1] == TraceLevelOIDStr + PString(".0")) {
			PTrace::SetLevel(token[2].AsUnsigned());
			return "SET_RESPONSE u " + PString(PString::Unsigned, PTrace::GetLevel());
		}
		if (token[1] == CatchAllOIDStr + PString(".0")) {
			if (IsIPAddress(token[2])) {
				Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllIP", token[2]);
				Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllAlias", "");
			} else {
				Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllIP", "");
				Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllAlias", token[2]);
			}
			ConfigReloadMutex.StartWrite();
			ReloadHandler();
			ConfigReloadMutex.EndWrite();
			return "SET_RESPONSE s " + token[2];
		}
	}
	return "ERROR";
}

void WindowsSNMPAgent::SendWindowsSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg)
{
	PTRACE(5, "SNMP\tSendSNMPTrap " << trapNumber << ", " << severity << ", " << group << ", " << msg);
	if (!m_shutdown) {
		PString trap = "TRAP " + PString(PString::Unsigned, trapNumber)
						+ " " + PString(PString::Unsigned, severity)
						+ " " + PString(PString::Unsigned, group)
						+ " " + msg;
		CallNamedPipe(trapPipename, trap.GetPointer(), trap.GetLength(), NULL, 0, NULL, 1000);
	}
}

#endif // _WIN32


PCaselessString SelectSNMPImplementation() 
{
	PCaselessString implementation = GkConfig()->GetString(SNMPSection, "Implementation", "Net-SNMP");

	// switch to other implementation if only one is available
#ifndef HAS_NETSNMP
	if (implementation == "Net-SNMP") {
		PTRACE(1, "SNMP\tNet-SNMP implementation not available, using PTLib implementation");
		implementation = "PTLib";
	}
#endif
#ifndef P_SNMP
	if (implementation == "PTLib") {
		PTRACE(1, "SNMP\tPTLib implementation not available, using Net-SNMP implementation");
		implementation = "Net-SNMP";
	}
#endif
#ifndef _WIN32
	if (implementation == "Windows") {
		PTRACE(1, "SNMP\tWindows implementation not available, using PTLib implementation");
		implementation = "PTLib";
	}
#endif
	return implementation;
}

void SendSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg)
{
	PCaselessString implementation = SelectSNMPImplementation();
#ifdef HAS_NETSNMP
	if (implementation == "Net-SNMP") {
		SendNetSNMPTrap(trapNumber, severity, group, msg);
	}
#endif
#ifdef P_SNMP
	if (implementation == "PTLib") {
		SendPTLibSNMPTrap(trapNumber, severity, group, msg);
	}
#endif
#ifdef _WIN32
	if (implementation == "Windows") {
		WindowsSNMPAgent::Instance()->SendWindowsSNMPTrap(trapNumber, severity, group, msg);
	}
#endif
}

void StartSNMPAgent() 
{
	PCaselessString implementation = SelectSNMPImplementation();
#ifdef HAS_NETSNMP
	if (implementation == "Net-SNMP") {
		CreateJob(NetSNMPAgent::Instance(), &NetSNMPAgent::Run, "SNMPAgent");
		return;
	}
#endif
#ifdef P_SNMP
	if (implementation == "PTLib") {
		new PTLibSNMPAgent();
		return;
	}
#endif
#ifdef _WIN32
	if (implementation == "Windows") {
		CreateJob(WindowsSNMPAgent::Instance(), &WindowsSNMPAgent::Run, "SNMPAgent");
		return;
	}
#endif
}

void StopSNMPAgent() 
{
	PCaselessString implementation = SelectSNMPImplementation();
#ifdef HAS_NETSNMP
	if (implementation == "Net-SNMP") {
		delete NetSNMPAgent::Instance();
		return;
	}
#endif
#ifdef P_SNMP
	if (implementation == "PTLib") {
		// nothing to do
		return;
	}
#endif
#ifdef _WIN32
	if (implementation == "Windows") {
		WindowsSNMPAgent::Instance()->Stop();
		return;
	}
#endif
}

void DeleteSNMPAgent() 
{
#ifdef HAS_NETSNMP
	if (NetSNMPAgent::InstanceExists()) {
		delete NetSNMPAgent::Instance();
	}
#endif
#ifdef P_SNMP
	if (g_ptlibAgentPtr) {
		delete g_ptlibAgentPtr;
		g_ptlibAgentPtr = NULL;
	}
#endif
#ifdef _WIN32
	if (WindowsSNMPAgent::InstanceExists()) {
		delete WindowsSNMPAgent::Instance();
	}
#endif
}

#endif	// HAS_SNMP
