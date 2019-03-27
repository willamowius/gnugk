//////////////////////////////////////////////////////////////////
//
// snmp.h for GNU Gatekeeper
//
// Copyright (c) 2012-2019, Jan Willamowius
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

#ifdef HAS_SNMP

#include "Toolkit.h"

const char * const SNMPSection = "SNMP";

enum SNMPLevel { SNMPError = 1, SNMPWarning = 2, SNMPInfo = 3 };
enum SNMPGroup { General = 1, Network = 2, Database = 3, Accounting = 4, Authentication = 5, Configuration = 6 };

PCaselessString SelectSNMPImplementation();

void StartSNMPAgent();
void StopSNMPAgent();
void DeleteSNMPAgent();

void SendSNMPTrap(unsigned trapNumber, SNMPLevel severity, SNMPGroup group, const PString & msg);

#define SNMP_TRAP(NO,LEVEL,GROUP,MSG) if (Toolkit::Instance()->IsSNMPEnabled()) { SendSNMPTrap(NO,LEVEL,GROUP,MSG); }

#else // HAS_SNMP

#define SNMP_TRAP(NO,LEVEL,GROUP,MSG)

#endif // HAS_SNMP


#endif	// GNUGKSNMP_H
