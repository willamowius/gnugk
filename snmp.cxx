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

#ifdef HAS_SNMP

const char * subagent_name = "gnugk-agent";

int ptrace_logger(netsnmp_log_handler * handler, int priority, const char * message)
{
	// TODO: set trace level according to priority
	if (message) {
		PTRACE(1, "NetSNMP\t(" << priority << ") " << message);
	}
    return 1;
}

SNMPAgent::SNMPAgent() : Singleton<SNMPAgent>("SNMPAgent")
{
	PTRACE(1, "SNMP\tStarting SNMP agent");
	logger = NULL;
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
	snmp_enable_calllog();
	logger = netsnmp_register_loghandler(NETSNMP_LOGHANDLER_CALLBACK, LOG_DEBUG);
	if (logger) {
		logger->handler = ptrace_logger;
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
	init_snmp(subagent_name);   // reads $HOME/.snmp/gnugk-agent.conf + $HOME/.snmp/agentx.conf
	while (true) {
		agent_check_and_process(1); // where 1==block
	}
}

#endif	// HAS_SNMP
