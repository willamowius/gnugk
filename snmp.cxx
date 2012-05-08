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

#include "snmp.h"

#ifdef HAS_SNMPTRAPS

#include "SoftPBX.h"
#ifdef P_SNMP
#include <ptclib/psnmp.h>
#endif

const char * const GnuGkMIBStr      = "1.3.6.1.4.1.27938.11";
const char * const severityOIDStr   = "1.3.6.1.4.1.27938.11.2.1";
const char * const groupOIDStr      = "1.3.6.1.4.1.27938.11.2.2";
const char * const displayMsgOIDStr = "1.3.6.1.4.1.27938.11.2.3";


void SendSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg)
{
	PTRACE(5, "SNMP\tSendSNMPTrap " << trapNumber << ", " << severity << ", " << group << ", " << msg);
#ifdef HAS_NETSNMP
	static oid snmptrap_oid[]  = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
	static oid severityOID[]   = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 1 };
	static oid groupOID[]      = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 2 };
	static oid displayMsgOID[] = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 3 };
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
                              ASN_OCTET_STR, (const char *)msg, msg.GetLength());
	send_v2trap(var_list);
	snmp_free_varbind(var_list);

#else
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
#endif
}
#endif


#ifdef HAS_SNMPAGENT

#include "gk.h"

void ReloadHandler();

const char * subagent_name = "gnugk-agent";

static oid ShortVersionOID[]  = { 1, 3, 6, 1, 4, 1, 27938, 11, 1 };
static oid LongVersionOID[]   = { 1, 3, 6, 1, 4, 1, 27938, 11, 2 };
static oid RegistrationsOID[] = { 1, 3, 6, 1, 4, 1, 27938, 11, 3 };
static oid CallsOID[]         = { 1, 3, 6, 1, 4, 1, 27938, 11, 4 };
static oid TraceLevelOID[]    = { 1, 3, 6, 1, 4, 1, 27938, 11, 5 };
static oid CatchAllOID[]      = { 1, 3, 6, 1, 4, 1, 27938, 11, 6 };

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
		snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (const char *)version, version.GetLength());
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
		snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (const char *)Toolkit::GKVersion(), Toolkit::GKVersion().GetLength());
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
			snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (const char *)catchAllDest, catchAllDest.GetLength());
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

SNMPAgent::SNMPAgent() : Singleton<SNMPAgent>("SNMPAgent")
{
	PTRACE(1, "SNMP\tStarting SNMP agent");
	m_logger = NULL;
	m_handler = NULL;
}

SNMPAgent::~SNMPAgent()
{
	PTRACE(1, "SNMP\tStopping SNMP agent");
	snmp_shutdown(subagent_name);
}

void SNMPAgent::LoadConfig()
{
	PTRACE(5, "SNMP\tReading SNMP config");
}

void SNMPAgent::Run()
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
	netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_X_SOCKET, "tcp:localhost:705");
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

#endif	// HAS_SNMPAGENT
