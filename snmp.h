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

#ifdef HAS_SNMP

#include "Toolkit.h"

const char * const SNMPSection = "SNMP";

#define GnuGkMIB		"1.3.6.1.4.1.27938.11"
#define severityOID	"1.3.6.1.4.1.27938.11.1.1"
#define groupOID		"1.3.6.1.4.1.27938.11.1.2"
#define displayMsgOID	"1.3.6.1.4.1.27938.11.1.3"


#define SNMP_TRAP(NO,LEVEL,GROUP,MSG) if (Toolkit::Instance()->IsSNMPEnabled()) { Toolkit::Instance()->SendSNMPTrap(NO,LEVEL,GROUP,MSG); }

#else // HAS_SNMP

#define SNMP_TRAP(NO,LEVEL,GROUP,MSG)

#endif	// HAS_SNMP

#endif	// SNMP_H
