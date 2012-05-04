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

#ifndef SNMP_H
#define SNMP_H "@(#) $Id$"

#include "config.h"

// always define these type to avoid compile errors
enum SNMPLevel { Error=1, Warning=2, Info=3 };
enum SNMPGroup { General=1, Network=2, Database=3 };

const char * const SNMPSection = "SNMP";

const char * const GnuGkMIBStr      = "1.3.6.1.4.1.27938.11";
const char * const severityOIDStr   = "1.3.6.1.4.1.27938.11.1.1";
const char * const groupOIDStr      = "1.3.6.1.4.1.27938.11.1.2";
const char * const displayMsgOIDStr = "1.3.6.1.4.1.27938.11.1.3";


#ifdef HAS_SNMPTRAPS

#include "Toolkit.h"
#ifdef P_SNMP
#include <ptclib/psnmp.h>
#endif

#define SNMP_TRAP(NO,LEVEL,GROUP,MSG) if (Toolkit::Instance()->IsSNMPEnabled()) { Toolkit::Instance()->SendSNMPTrap(NO,LEVEL,GROUP,MSG); }

#else // HAS_SNMPTRAPS

#define SNMP_TRAP(NO,LEVEL,GROUP,MSG)

#endif // HAS_SNMPTRAPS


#ifdef HAS_SNMPAGENT

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
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

#endif	// SNMP_H
