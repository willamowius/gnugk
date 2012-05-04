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

#ifdef HAS_SNMPAGENT

const char * subagent_name = "gnugk-agent";

static oid RegOID[]	     = { 1, 3, 6, 1, 4, 1, 27938, 11, 1 };
static oid CatchAllOID[] = { 1, 3, 6, 1, 4, 1, 27938, 11, 2 };

extern "C" {

int ptrace_logger(netsnmp_log_handler * handler, int prio, const char * message)
{
	if (message) {
		PTRACE((prio <= LOG_WARNING ? 1 : 4), "NetSNMP\t" << message);
	}
    return 1;
}

int registrations_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests)
{
	PTRACE(0, "JW Registrations handler called");
    if (reqinfo->mode != MODE_GET)
		return SNMPERR_SUCCESS;
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		unsigned no_regs = RegistrationTable::Instance()->Size();
		snmp_set_var_typed_integer(request->requestvb, ASN_INTEGER, no_regs);
	}
	return SNMPERR_SUCCESS;
}

int catchall_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests)
{
	PTRACE(0, "JW CatchAll handler called");
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		if (reqinfo->mode == MODE_GET) {
			snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, "Bar", strlen("Bar"));
		} else if (reqinfo->mode == MODE_SET_ACTION) {
			PTRACE(0, "JW CatchAll SET " << requests->requestvb->val.string);
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
		netsnmp_create_handler_registration("registrations", registrations_handler, RegOID, OID_LENGTH(RegOID), HANDLER_CAN_RONLY));
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("catchall", catchall_handler, CatchAllOID, OID_LENGTH(CatchAllOID), HANDLER_CAN_RWRITE));

	init_snmp(subagent_name);   // reads $HOME/.snmp/gnugk-agent.conf + $HOME/.snmp/agentx.conf
	while (true) {
		agent_check_and_process(1); // where 1==block
	}
}

#endif	// HAS_SNMPAGENT
