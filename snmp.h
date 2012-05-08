//////////////////////////////////////////////////////////////////
//
// snmp.h for GNU Gatekeeper
//
// Copyright (c) 2012, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef GNUGKSNMP_H
#define GNUGKSNMP_H "@(#) $Id$"

#include "config.h"

const char * const SNMPSection = "SNMP";


#ifdef HAS_SNMPTRAPS

#include "Toolkit.h"

enum SNMPLevel { SNMPError=1, SNMPWarning=2, SNMPInfo=3 };
enum SNMPGroup { General=1, Network=2, Database=3, Accounting=4, Authentication=5, Configuration=6 };

void SendSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg);

#define SNMP_TRAP(NO,LEVEL,GROUP,MSG) if (Toolkit::Instance()->IsSNMPEnabled()) { SendSNMPTrap(NO,LEVEL,GROUP,MSG); }

#else // HAS_SNMPTRAPS

#define SNMP_TRAP(NO,LEVEL,GROUP,MSG)

#endif // HAS_SNMPTRAPS


#ifdef HAS_SNMPAGENT

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/agent_module_config.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

class SNMPAgent : public Singleton<SNMPAgent>
{
public:
	SNMPAgent();
	virtual ~SNMPAgent();

	virtual void LoadConfig();
	virtual void Run();

protected:
	netsnmp_log_handler * m_logger;
	netsnmp_handler_registration * m_handler;
};

#endif	// HAS_SNMPAGENT

#endif	// GNUGKSNMP_H
