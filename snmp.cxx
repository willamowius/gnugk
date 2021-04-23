//////////////////////////////////////////////////////////////////
//
// snmp.cxx for GNU Gatekeeper
//
// Copyright (c) 2012-2019, Jan Willamowius
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

#ifdef HAS_PTLIBSNMP
#include "RasSrv.h"
#endif

void ReloadHandler();

// NOTE: all OIDs must also be in m_nextList for PTLib-SNMP !
const char * const sysDescrOIDStr        = "1.3.6.1.2.1.1.1";
const char * const sysObjectIDOIDStr     = "1.3.6.1.2.1.1.2";
const char * const sysUpTimeOIDStr       = "1.3.6.1.2.1.1.3";
const char * const sysNameOIDStr         = "1.3.6.1.2.1.1.5";

const char * const GnuGkMIBStr           = "1.3.6.1.4.1.27938.11";
const char * const ShortVersionOIDStr    = "1.3.6.1.4.1.27938.11.1.1";
const char * const LongVersionOIDStr     = "1.3.6.1.4.1.27938.11.1.2";
const char * const RegistrationsOIDStr   = "1.3.6.1.4.1.27938.11.1.3";
const char * const CallsOIDStr           = "1.3.6.1.4.1.27938.11.1.4";
const char * const TraceLevelOIDStr      = "1.3.6.1.4.1.27938.11.1.5";
const char * const CatchAllOIDStr        = "1.3.6.1.4.1.27938.11.1.6";
const char * const TotalCallsOIDStr      = "1.3.6.1.4.1.27938.11.1.7";
const char * const SuccessfulCallsOIDStr = "1.3.6.1.4.1.27938.11.1.8";
const char * const TotalBandwidthOIDStr  = "1.3.6.1.4.1.27938.11.1.9";

const char * const severityOIDStr        = "1.3.6.1.4.1.27938.11.2.1";
const char * const groupOIDStr           = "1.3.6.1.4.1.27938.11.2.2";
const char * const displayMsgOIDStr      = "1.3.6.1.4.1.27938.11.2.3";

const char * const NoNextOIDStr          = "99.99";


#ifdef HAS_NETSNMP

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/agent_module_config.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

const char * agent_name = "gnugk-agent";
PMutex g_NetSNMPMutex;

static oid snmptrap_oid[]       = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
static oid ShortVersionOID[]    = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 1 };
static oid LongVersionOID[]     = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 2 };
static oid RegistrationsOID[]   = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 3 };
static oid CallsOID[]           = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 4 };
static oid TraceLevelOID[]      = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 5 };
static oid CatchAllOID[]        = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 6 };
static oid TotalCallsOID[]      = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 7 };
static oid SuccessfulCallsOID[] = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 8 };
static oid TotalBandwidthOID[]  = { 1, 3, 6, 1, 4, 1, 27938, 11, 1, 9 };

static oid severityOID[]        = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 1 };
static oid groupOID[]           = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 2 };
static oid displayMsgOID[]      = { 1, 3, 6, 1, 4, 1, 27938, 11, 2, 3 };


void SendNetSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg)
{
    PWaitAndSignal lock(g_NetSNMPMutex);

	PTRACE(5, "SNMP\tSendSNMPTrap " << trapNumber << ", " << severity << ", " << group << ", " << msg);
	oid trapOID[] = { 1, 3, 6, 1, 4, 1, 27938, 11, 0, 99999 };

	// insert trapNumber as last digit
	trapOID[ OID_LENGTH(trapOID) - 1 ] = trapNumber;

	netsnmp_variable_list * var_list = NULL;
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
    PWaitAndSignal lock(g_NetSNMPMutex);

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
    PWaitAndSignal lock(g_NetSNMPMutex);

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
    PWaitAndSignal lock(g_NetSNMPMutex);

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
    PWaitAndSignal lock(g_NetSNMPMutex);

    if (reqinfo->mode != MODE_GET)
		return SNMPERR_SUCCESS;
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		unsigned no_calls = CallTable::Instance()->Size();
		snmp_set_var_typed_integer(request->requestvb, ASN_UNSIGNED, no_calls);
	}
	return SNMPERR_SUCCESS;
}

int bandwidth_handler(netsnmp_mib_handler * /* handler */,
							netsnmp_handler_registration * /* reg */,
							netsnmp_agent_request_info * reqinfo,
							netsnmp_request_info * requests)
{
    PWaitAndSignal lock(g_NetSNMPMutex);

    if (reqinfo->mode != MODE_GET)
		return SNMPERR_SUCCESS;
    for (netsnmp_request_info *request = requests; request; request = request->next) {
		unsigned total_bandwidth = CallTable::Instance()->GetTotalAllocatedBandwidth();
		snmp_set_var_typed_integer(request->requestvb, ASN_UNSIGNED, total_bandwidth);
	}
	return SNMPERR_SUCCESS;
}

int totalcalls_handler(netsnmp_mib_handler * /* handler */,
							netsnmp_handler_registration * /* reg */,
							netsnmp_agent_request_info * reqinfo,
							netsnmp_request_info * requests)
{
    PWaitAndSignal lock(g_NetSNMPMutex);

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
    PWaitAndSignal lock(g_NetSNMPMutex);

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
    PWaitAndSignal lock(g_NetSNMPMutex);

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
    PWaitAndSignal lock(g_NetSNMPMutex);

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
			ReloadHandler();
		}
	}
	return SNMPERR_SUCCESS;
}

} // extern "C"


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
	bool standalone = GkConfig()->GetBoolean(SNMPSection, "Standalone", false);

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
		// use 127.0.0.1:705 by default, can be overridden in $HOME/.snmp/agentx.conf
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
	netsnmp_register_scalar(
		netsnmp_create_handler_registration("bandwidth", bandwidth_handler, TotalBandwidthOID, OID_LENGTH(TotalBandwidthOID), HANDLER_CAN_RONLY));

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


#ifdef HAS_PTLIBSNMP

#include <ptclib/psnmp.h>

class PTLibSNMPAgent;

void SendPTLibSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg)
{
	PString trapHost = GkConfig()->GetString(SNMPSection, "TrapHost", "");
	if (!trapHost.IsEmpty()) {
    	PTRACE(5, "SNMP\tSendSNMPTrap " << trapNumber << ", " << severity << ", " << group << ", " << msg);
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
    list<PString> m_nextList;
};


PTLibSNMPAgent::PTLibSNMPAgent()
	: PSNMPServer(PIPSocket::Address(GkConfig()->GetString(SNMPSection, "AgentListenIP", "127.0.0.1")),
		(WORD)GkConfig()->GetInteger(SNMPSection, "AgentListenPort", 161))
{
	PTRACE(1, "SNMP\tStarting SNMP agent (PTLib)");
	// NOTE: the list must have _all_ OIDs we support in _numerical_order_
	m_nextList.push_back(sysDescrOIDStr);
	m_nextList.push_back(sysObjectIDOIDStr);
	m_nextList.push_back(sysUpTimeOIDStr);
	m_nextList.push_back(sysNameOIDStr);

	m_nextList.push_back(ShortVersionOIDStr);
	m_nextList.push_back(LongVersionOIDStr);
	m_nextList.push_back(RegistrationsOIDStr);
	m_nextList.push_back(CallsOIDStr);
	m_nextList.push_back(TraceLevelOIDStr);
	m_nextList.push_back(CatchAllOIDStr);
	m_nextList.push_back(TotalCallsOIDStr);
	m_nextList.push_back(SuccessfulCallsOIDStr);
	m_nextList.push_back(TotalBandwidthOIDStr);
}

PTLibSNMPAgent::~PTLibSNMPAgent()
{
	PTRACE(1, "SNMP\tDeleting SNMP agent (PTLib)");
}

PBoolean PTLibSNMPAgent::Authorise(const PIPSocket::Address & ip)
{
	PStringArray networks = GkConfig()->GetString(SNMPSection, "AllowRequestsFrom", "").Tokenise(",", FALSE);
	for (PINDEX n = 0; n < networks.GetSize(); ++n) {
		if (networks[n].Find('/') == P_MAX_INDEX) {
            if (IsIPv4Address(networks[n])) {
                networks[n] += "/32";	// add netmask to pure IPs
            } else {
                networks[n] += "/128";	// add netmask to pure IPs
            }
        }

		NetworkAddress net = NetworkAddress(networks[n]);
		if (ip << net) {
            PTRACE(4, "SNMP\tAccepting SNMP request from " << ip);
			return PTrue;
		}
	}
    PTRACE(2, "SNMP\tWarning: Rejecting SNMP request from " << ip);
	return PFalse;
}

PBoolean PTLibSNMPAgent::ConfirmCommunity(PASN_OctetString & community)
{
	// community string security is a joke, just accept any community and rely on IP authorization
	return PTrue;
}

PBoolean PTLibSNMPAgent::OnGetRequest(PINDEX reqID, PSNMP::BindingList & vars, PSNMP::ErrorType & errCode)
{
	return PTrue; // respond to GET request
}

PBoolean PTLibSNMPAgent::OnGetNextRequest(PINDEX reqID, PSNMP::BindingList & vars, PSNMP::ErrorType & errCode)
{
    PString oid = vars.front().first;
    if (oid.Right(2) == ".0")
        oid = oid.Left(oid.GetLength() - 2);
    list<PString>::const_iterator it = m_nextList.begin();
    while(it != m_nextList.end() && (OIDCmp(*it, oid) <= 0)) {
        ++it;
    }
    if (it != m_nextList.end() /* TODO: && is in same space? */) {
        vars.front().first = *it + PString(".0");
	    return PTrue; // respond to GET-NEXT request
    } else {
        vars.front().first = NoNextOIDStr + PString(".0");
        return PTrue; // no further OID found
    }
}

PBoolean PTLibSNMPAgent::OnSetRequest(PINDEX reqID, PSNMP::BindingList & vars, PSNMP::ErrorType & errCode)
{
	// SET operation is broken in PTLib PSNMPServer, you need a patched 2.10.9 version later than 2019-05-26
    list< pair<PString, PRFC1155_ObjectSyntax> >::const_iterator iter = vars.begin();
    while (iter != vars.end()) {
        const PString & oid = iter->first;
        const PRFC1155_ObjectSyntax & value = iter->second;

		if (oid == TraceLevelOIDStr + PString(".0")) {
            if (value.GetTag() == PRFC1155_SimpleSyntax::e_number) {
                const PRFC1155_SimpleSyntax & simple = value;
                const PASN_Integer & num = simple;
                PTRACE(4, "SNMP\tSetting trace level to " << num.GetValue());
                PTrace::SetLevel(num.GetValue());
            } else {
                errCode = BadValue;
            }
		} else if (oid == CatchAllOIDStr + PString(".0")) {
            if (value.GetTag() == PRFC1155_SimpleSyntax::e_string) {
                const PRFC1155_SimpleSyntax & simple = value;
                const PASN_OctetString & str = simple;
                PString dest = AsString(str.GetValue());
                PTRACE(4, "SNMP\tSetting CatchAll to " << dest);
                if (IsIPAddress(dest)) {
                    Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllIP", dest);
                    Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllAlias", "");
                } else {
                    Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllIP", "");
                    Toolkit::Instance()->SetConfig(1, "Routing::CatchAll", "CatchAllAlias", dest);
                }
                ReloadHandler();
            } else {
                errCode = BadValue;
            }
		} else {
		    PTRACE(2, "SNMP\tWarning: SNMP SET for unsupported OID " << oid);
		    errCode = NoSuchName;
		}
        ++iter;
    }
	return PTrue; // send response
}

// 0=SNMPv1, 1=SNMPv2
PBoolean PTLibSNMPAgent::ConfirmVersion(PASN_Integer vers)
{
	return (vers <= 1);	// only accept version 1 or 2
}

void SetRFC1155Object(PRFC1155_ObjectSyntax & obj, unsigned i)
{
	// according to RFC 1902 Gauge32 is identical to Unsigned32; PTLib only has Gauge
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

void SetRFC1155TicksObject(PRFC1155_ObjectSyntax & obj, unsigned i)
{
	PRFC1155_ApplicationSyntax appl(PRFC1155_ApplicationSyntax::e_ticks);
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

void SetRFC1155OIDObject(PRFC1155_ObjectSyntax & obj, const PString & str)
{
	PRFC1155_SimpleSyntax simple(PRFC1155_SimpleSyntax::e_object);
	PRFC1155_ObjectSyntax * newObj = (PRFC1155_ObjectSyntax*)&simple;
	PASN_ObjectId * idObj = (PASN_ObjectId *)&simple.GetObject();
	idObj->SetValue(str);
	obj = *newObj;
}

PBoolean PTLibSNMPAgent::MIB_LocalMatch(PSNMP_PDU & answerPDU)
{
	const PSNMP_VarBindList & vars = answerPDU.m_variable_bindings;

	for (PINDEX i = 0; i < vars.GetSize(); i++) {
        const PRFC1155_ObjectName & oid = vars[i].m_name;
        // GnuGk's OIDs
		if (oid == ShortVersionOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, PProcess::Current().GetVersion(true));
		} else if (oid == LongVersionOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, Toolkit::GKVersion().Trim());
		} else if (oid == RegistrationsOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, RegistrationTable::Instance()->Size());
		} else if (oid == CallsOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, CallTable::Instance()->Size());
		} else if (oid == TotalBandwidthOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, CallTable::Instance()->GetTotalAllocatedBandwidth());
		} else if (oid == TotalCallsOIDStr + PString(".0")) {
			SetRFC1155CounterObject(vars[i].m_value, CallTable::Instance()->TotalCallCount());
		} else if (oid == SuccessfulCallsOIDStr + PString(".0")) {
			SetRFC1155CounterObject(vars[i].m_value, CallTable::Instance()->SuccessfulCallCount());
		} else if (oid == TraceLevelOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, PTrace::GetLevel());
		} else if (oid == CatchAllOIDStr + PString(".0")) {
			PString catchAllDest = GkConfig()->GetString("Routing::CatchAll", "CatchAllIP", "");
			if (catchAllDest.IsEmpty())
				catchAllDest = GkConfig()->GetString("Routing::CatchAll", "CatchAllAlias", "catchall");
			SetRFC1155Object(vars[i].m_value, catchAllDest);

        // generic OIDs
		} else if (oid == sysDescrOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, "GNU Gatekeeper " + PProcess::Current().GetVersion(true));
		} else if (oid == sysObjectIDOIDStr + PString(".0")) {
			SetRFC1155OIDObject(vars[i].m_value, LongVersionOIDStr);
		} else if (oid == sysUpTimeOIDStr + PString(".0")) {
			SetRFC1155TicksObject(vars[i].m_value, SoftPBX::UptimeTicks());
		} else if (oid == sysNameOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, Toolkit::Instance()->GKName());

        // dummy OID to signal end in Get-Next
		} else if (oid == NoNextOIDStr + PString(".0")) {
			SetRFC1155Object(vars[i].m_value, 0);

		} else {
		    PTRACE(2, "SNMP\tWarning: SNMP GET for unsupported OID " << oid);
		    answerPDU.m_error_status = PSNMP::NoSuchName;
		}
	}

	return true;
}

#endif	// HAS_PTLIBSNMP


PCaselessString SelectSNMPImplementation()
{
	PCaselessString implementation = GkConfig()->GetString(SNMPSection, "Implementation", "PTLib");

	// switch to other implementation if only one is available
#ifndef HAS_NETSNMP
	if (implementation == "Net-SNMP") {
		PTRACE(1, "SNMP\tNet-SNMP implementation not available, using PTLib implementation");
		implementation = "PTLib";
	}
#endif
#ifndef HAS_PTLIBSNMP
	if (implementation == "PTLib") {
		PTRACE(1, "SNMP\tPTLib implementation not available, using Net-SNMP implementation");
		implementation = "Net-SNMP";
	}
#endif
	return implementation;
}

void SendSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg)
{
	if (!GkConfig()->GetBoolean(SNMPSection, "EnableTraps", true)
        || ( (severity == SNMPWarning) && !GkConfig()->GetBoolean(SNMPSection, "EnableWarningTraps", false)) ) {
		// don't throw trap
		return;
	}

	PCaselessString implementation = SelectSNMPImplementation();
#ifdef HAS_NETSNMP
	if (implementation == "Net-SNMP") {
		SendNetSNMPTrap(trapNumber, severity, group, msg);
	}
#endif
#ifdef HAS_PTLIBSNMP
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
#ifdef HAS_PTLIBSNMP
	if (implementation == "PTLib") {
		PTLibSNMPAgent * agent = new PTLibSNMPAgent();   // will be deleted when GnuGk shuts down
		if (!agent->IsOpen()) {
		    PTRACE(1, "SNMP\tFATAL: Error starting PTLib SNMP agent - shutting down");
		    cout <<  "Error starting PTLib SNMP agent - shutting down" << endl;
            RasServer::Instance()->Stop();
            _exit(1);
		}
		return;
	}
#endif
}

void StopSNMPAgent()
{
#ifdef HAS_NETSNMP
	if (NetSNMPAgent::InstanceExists()) {
		NetSNMPAgent::Instance()->Stop();
	}
#endif
#ifdef HAS_PTLIBSNMP
	// nothing to do
#endif
}

void DeleteSNMPAgent()
{
#ifdef HAS_NETSNMP
	if (NetSNMPAgent::InstanceExists()) {
		delete NetSNMPAgent::Instance();
	}
#endif
#ifdef HAS_PTLIBSNMP
    // nothing to delete
#endif
}

#endif	// HAS_SNMP
