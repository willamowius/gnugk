//////////////////////////////////////////////////////////////////
//
// config.h configuration header
//
// Copyright (c) 2008-2010, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////


#ifndef CONFIG_H
#define CONFIG_H "@(#) $Id$"

#include "pwlib_compat.h"

#ifdef _WIN32
#include "gnugkbuildopts.h"
#else
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif


#if (defined P_LINUX) || (defined P_FREEBSD) || (defined P_HPUX9) || (defined P_SOLARIS) || (defined P_OPENBSD)
// On some OS we don't get broadcasts on a socket that is
// bound to a specific interface. For those we have to start
// a listener just for those broadcasts.
// On Windows NT we get all messages on the RAS socket, even
// if it's bound to a specific interface and thus don't have
// to start a listener for broadcast.
#define NEED_BROADCASTLISTENER 1
#else
#define NEED_BROADCASTLISTENER 0
#endif

#if HAS_MYSQL || HAS_PGSQL || HAS_FIREBIRD || HAS_ODBC || HAS_SQLITE
#define		HAS_DATABASE 1
#endif

#endif // CONFIG_H

