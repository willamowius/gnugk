//////////////////////////////////////////////////////////////////
//
// config.h configuration header
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////


#ifndef CONFIG_H
#define CONFIG_H "@(#) $Id$"

#include "pwlib_compat.h"

#ifdef _WIN32
#include "gnugkbuildopts.h"
#endif

#if HAS_MYSQL || HAS_PGSQL || HAS_FIREBIRD || HAS_UNIXODBC || HAS_SQLITE
#define		HAS_DATABASE 1
#endif

#endif // CONFIG_H

