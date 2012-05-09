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
#include "SoftPBX.h"

void ReloadHandler();


#ifdef HAS_NETSNMP

#include "job.h"
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/agent_module_config.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

const char * subagent_name = "gnugk-agent";

static oid snmptrap_oid[]     = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
static oid ShortVersionOID[]  = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 1 };
static oid LongVersionOID[]   = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 2 };
static oid RegistrationsOID[] = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 3 };
static oid CallsOID[]         = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 4 };
static oid TraceLevelOID[]    = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 5 };
static oid CatchAllOID[]      = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 6 };
static oid severityOID[]      = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 1 };
static oid groupOID[]         = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 2 };
static oid displayMsgOID[]    = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 3 };


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
		snmp_set_var_typed_integer(request->requestvb, ASN_INTEGER, no_regs);
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
		snmp_set_var_typed_integer(request->requestvb, ASN_INTEGER, no_calls);
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
			snmp_set_var_typed_integer(request->requestvb, ASN_INTEGER, PTrace::GetLevel());
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

protected:
	netsnmp_log_handler * m_logger;
	netsnmp_handler_registration * m_handler;
};

NetSNMPAgent::NetSNMPAgent() : Singleton<NetSNMPAgent>("NetSNMPAgent")
{
	PTRACE(1, "SNMP\tStarting SNMP agent (Net-SNMP)");
	m_logger = NULL;
	m_handler = NULL;
}

NetSNMPAgent::~NetSNMPAgent()
{
	PTRACE(1, "SNMP\tStopping SNMP agent (Net-SNMP)");
	snmp_shutdown(subagent_name);
}

void NetSNMPAgent::Run()
{
	// enable Net-SNMP logging via PTRACE
	m_logger = netsnmp_register_loghandler(NETSNMP_LOGHANDLER_CALLBACK, LOG_DEBUG);
	if (m_logger) {
		m_logger->handler = ptrace_logger;
		snmp_enable_calllog();
		PTRACE(5, "SNMP\tLogger installed");
	} else {
		PTRACE(1, "SNMP\tError installing logger");
	}
	// run as AgentX sub-agent
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
	// use 127.0.0.1:705 by default, can be overriden in $HOME/.snmp/agentx.conf
	netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_X_SOCKET, "tcp:127.0.01:705");
	netsnmp_enable_subagent();

	init_agent(subagent_name);

	netsnmp_register_scalar(
		netsnmp_create_handler_registration("short version", short_version_handler, ShortVersionOID, OID_LENGTH(ShortVersionOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("long version", long_version_handler, LongVersionOID, OID_LENGTH(LongVersionOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("registrations", registrations_handler, RegistrationsOID, OID_LENGTH(RegistrationsOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("calls", calls_handler, CallsOID, OID_LENGTH(CallsOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("catchall", tracelevel_handler, TraceLevelOID, OID_LENGTH(TraceLevelOID), HANDLER_CAN_RWRITE));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("catchall", catchall_handler, CatchAllOID, OID_LENGTH(CatchAllOID), HANDLER_CAN_RWRITE));

	init_snmp(subagent_name);   // reads $HOME/.snmp/gnugk-agent.conf + $HOME/.snmp/agentx.conf
	SNMP_TRAP(1, SNMPInfo, General, "GnuGk started");	// when registering as agent, send started trap after connecting

	while (!ShutdownMutex.WillBlock()) {
		agent_check_and_process(1); // where 1==block
	}
}

#endif // HAS_NETSNMP


#ifdef P_SNMP

#include <ptclib/psnmp.h>

const char * const GnuGkMIBStr      = "1.3.6.1.4.1.27938.11";
const char * const severityOIDStr   = "1.3.6.1.4.1.27938.11.2.1";
const char * const groupOIDStr      = "1.3.6.1.4.1.27938.11.2.2";
const char * const displayMsgOIDStr = "1.3.6.1.4.1.27938.11.2.3";


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
		if (!msg.IsEmpty())
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
    virtual PBoolean ConfirmVersion(PASN_Integer vers);
	virtual PBoolean MIB_LocalMatch(PSNMP_PDU & pdu);

  protected:
    PRFC1155_SimpleSyntax sys_description;
};


PTLibSNMPAgent::PTLibSNMPAgent()
	: PSNMPServer(PIPSocket::Address(GkConfig()->GetString(SNMPSection, "AgentListenIP", "127.0.0.1")),
		GkConfig()->GetInteger(SNMPSection, "AgentListenPort", 161))
{
	PTRACE(1, "SNMP\tStarting SNMP agent (PTLib)");
}

PTLibSNMPAgent::~PTLibSNMPAgent()
{
	PTRACE(1, "SNMP\tStopping SNMP agent (PTLib)");
}

PBoolean PTLibSNMPAgent::Authorise(const PIPSocket::Address & received)
{
	PTRACE(1, "SNMP\tReceived request from " << received);
	// TODO
	return PTrue;
}

PBoolean PTLibSNMPAgent::ConfirmCommunity(PASN_OctetString & community)
{
	// community string security is a joke, just accept any community and rely on IP authorization
	return PTrue;
}

PBoolean PTLibSNMPAgent::OnGetRequest(PINDEX reqID, PSNMP::BindingList & vars, PSNMP::ErrorType & errCode)
{
	return PTrue;
}

// 0=SNMPv1, 1=SNMPv2
PBoolean PTLibSNMPAgent::ConfirmVersion(PASN_Integer vers)
{
	return (vers <= 1);	// only accept version 1 or 2
}

PBoolean PTLibSNMPAgent::MIB_LocalMatch(PSNMP_PDU & pdu)
{
	PTRACE(0, "JW MIB_LocalMatch pdu=" << pdu);
	PSNMP_VarBindList & vars = pdu.m_variable_bindings;
	bool found = false;

	for(PINDEX i = 0 ;i < vars.GetSize(); i++){
		PTRACE(0, "JW oid=" << vars[i].m_name);
		if (vars[i].m_name == "1.3.6.1.4.1.27938.11.1.1.0") {
			PRFC1155_SimpleSyntax answer(PRFC1155_SimpleSyntax::e_string);
			PRFC1155_ObjectSyntax * obj = (PRFC1155_ObjectSyntax*)&answer;
			PASN_OctetString * str = (PASN_OctetString *)&answer.GetObject();
			str->SetValue(PProcess::Current().GetVersion(true));
			vars[i].m_value = *obj;
			found = true;
		} else if (vars[i].m_name == "1.3.6.1.4.1.27938.11.1.2.0") {
			PRFC1155_SimpleSyntax answer(PRFC1155_SimpleSyntax::e_string);
			PRFC1155_ObjectSyntax * obj = (PRFC1155_ObjectSyntax*)&answer;
			PASN_OctetString * str = (PASN_OctetString *)&answer.GetObject();
			str->SetValue(Toolkit::GKVersion());
			vars[i].m_value = *obj;
			found = true;
		} else if (vars[i].m_name == "1.3.6.1.4.1.27938.11.1.3.0") {
			PRFC1155_SimpleSyntax answer(PRFC1155_SimpleSyntax::e_number);
			PRFC1155_ObjectSyntax * obj = (PRFC1155_ObjectSyntax*)&answer;
			PASN_Integer * num = (PASN_Integer *)&answer.GetObject();
			num->SetValue(RegistrationTable::Instance()->Size());
			vars[i].m_value = *obj;
			found = true;
		} else if (vars[i].m_name == "1.3.6.1.4.1.27938.11.1.4.0") {
			PRFC1155_SimpleSyntax answer(PRFC1155_SimpleSyntax::e_number);
			PRFC1155_ObjectSyntax * obj = (PRFC1155_ObjectSyntax*)&answer;
			PASN_Integer * num = (PASN_Integer *)&answer.GetObject();
			num->SetValue(CallTable::Instance()->Size());
			vars[i].m_value = *obj;
			found = true;
		} else if (vars[i].m_name == "1.3.6.1.4.1.27938.11.1.5.0") {
			PRFC1155_SimpleSyntax answer(PRFC1155_SimpleSyntax::e_number);
			PRFC1155_ObjectSyntax * obj = (PRFC1155_ObjectSyntax*)&answer;
			PASN_Integer * num = (PASN_Integer *)&answer.GetObject();
			num->SetValue(PTrace::GetLevel());
			vars[i].m_value = *obj;
			found = true;
		} else if (vars[i].m_name == "1.3.6.1.4.1.27938.11.1.6.0") {
			PString catchAllDest = GkConfig()->GetString("Routing::CatchAll", "CatchAllIP", "");
			if (catchAllDest.IsEmpty())
				catchAllDest = GkConfig()->GetString("Routing::CatchAll", "CatchAllAlias", "catchall");
			PRFC1155_SimpleSyntax answer(PRFC1155_SimpleSyntax::e_string);
			PRFC1155_ObjectSyntax * obj = (PRFC1155_ObjectSyntax*)&answer;
			PASN_OctetString * str = (PASN_OctetString *)&answer.GetObject();
			str->SetValue(catchAllDest);
			vars[i].m_value = *obj;
			found = true;
		}
	}

	return found; // not found
}

#endif	// P_SNMP


PCaselessString SelectSNMPImplementation() 
{
	PCaselessString implementation = GkConfig()->GetString(SNMPSection, "Implementation", "NetSNMP");

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
}

#endif	// HAS_SNMP
