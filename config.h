//////////////////////////////////////////////////////////////////
//
// config.h PWLib/PTLib and H323Plus compatibility header
//
// Copyright (c) 2006-2018, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////


#ifndef CONFIG_H
#define CONFIG_H "@(#) $Id$"

#include <ptlib.h>
#include <ptlib/ipsock.h>
#include "gnugkbuildopts.h"

#ifndef _WIN32
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif


#include "openh323buildopts.h"
#if PTLIB_MAJOR == 2 && PTLIB_MINOR < 13
    #include <ptbuildopts.h>
#else
    #include <ptlib_config.h>
#endif

// use at least PWLib Pandora
#if PWLIB_MAJOR == 1
	#if PWLIB_MINOR < 7
		#error "PWLib too old, use at least 1.7.5.2"
	#endif
#endif

#ifndef PTRACING
	#error "Enable PTRACING in PTLIB to compile GnuGk"
#endif

// check for PConfig support
#ifndef P_CONFIG_FILE
	#error "Make sure PTLib has config file support enabled, avoid --disable-configfile or --enable-openh323 or --enable-minsize etc."
#endif

// define PTimedMutex for PWLib < 1.9.2
#if PWLIB_MAJOR == 1
	#if PWLIB_MINOR < 9
		#define PTimedMutex PMutex
	#endif
#endif
#if PWLIB_MAJOR == 1
	#if PWLIB_MINOR == 9
		#if PWLIB_BUILD < 2
			#define PTimedMutex PMutex
		#endif
	#endif
#endif

#if PTLIB_MAJOR == 2 && PTLIB_MINOR < 13
    #if !defined(P_USE_STANDARD_CXX_BOOL) && !defined(P_USE_INTEGER_BOOL)
        typedef int PBoolean;
    #endif
#endif

#if !defined(P_DNS) && defined(P_DNS_RESOLVER)
#define P_DNS   1
#endif

#ifdef P_DNS
	#define hasSRV 1	             // DNS SRV
	// define hasRDS for PWLib >= 1.11.3
	#if PWLIB_MAJOR == 1
		#if PWLIB_MINOR >= 11
			#if PWLIB_BUILD > 2
				#define hasRDS 1
			#endif
		#endif
	#endif

	// define hasSETENUMSERVERS for PWLib >= 1.9.3
	#if PWLIB_MAJOR == 1
		#if PWLIB_MINOR >= 9
			#define hasSETENUMSERVERS 1
		#endif
	#endif
#endif

// define hasDeletingSetStream for PWLib >= 1.11.2
#if PWLIB_MAJOR == 1
	#if PWLIB_MINOR >= 11
		#if PWLIB_BUILD >= 2
			#define hasDeletingSetStream 1
		#endif
	#endif
#endif

#ifdef P_DNS
	#if PWLIB_MAJOR == 1
		#if PWLIB_MINOR == 12
			#define hasRDS 1
			#define hasSETENUMSERVERS 1
		#endif
	#endif
#endif

// for PTlib v2.x
#ifdef PTLIB_MAJOR
	#ifdef P_DNS
		#define hasRDS 1
		#define hasSETENUMSERVERS 1
	#endif
	#define hasDeletingSetStream 1
#endif

#if PTLIB_MAJOR == 2
	// changed PConfig interface in PWLib >= 2.2.0
	#if PTLIB_MINOR >= 2
		#define hasPConfigArray 1
	#endif
	// availability of GetLastError in PDynaLink
	#if PTLIB_MINOR >= 8
		#define hasDynaLinkGetLastError 1
	#endif
	#if PTLIB_MINOR == 9
		#define hasPTLibTraceOnShutdownBug	1
	#endif
	#if PTLIB_MINOR >= 10
		#ifdef P_HAS_IPV6
			// IPv6 support before 2.10.0 is too buggy
			#define hasIPV6     1
		#endif
		#if PTLIB_BUILD >= 6
			#define hasLDAPStartTLS 1
		#endif
		#ifdef _WIN32
			#define hasWorkerDeleteBug	1
		#endif
	#endif
	#if (PTLIB_MINOR == 10) || (PTLIB_MINOR == 11)
		#define hasThreadAutoDeleteBug	1
	#endif
	#if PTLIB_MINOR >= 11
		#define hasLDAPStartTLS 1
        #define hasNewSTUN      1
        #define hasPTRACE2      1
        #define hasAutoCreateAuthenticators	1
	#endif
	#if PTLIB_MINOR >= 12
		#define hasNoMutexWillBlock	1
	#endif
	// bug with no trailing NULL bytes in BMP strings, fixed in PTLib 2.7.1
	#if ((PTLIB_MINOR == 2) || (PTLIB_MINOR == 4 && PTLIB_BUILD <= 5) || (PTLIB_MINOR == 5 && PTLIB_BUILD <= 2) || (PTLIB_MINOR == 6 && PTLIB_BUILD <= 4))
		#ifdef _WIN32
			#pragma message("PTLib with MD5 token bug")
		#else
			#warning "PTLib with MD5 token bug"
		#endif
	#endif
#endif

#if defined(P_SSL)
	#define HAS_TLS 1
#endif

#if defined(hasPTRACE2)
   #define PTRACEX(level, args)  PTRACE2(level,NULL,args)
#else
   #define PTRACEX(level, args)  PTRACE(level,args)
#endif

#if !defined(PWLIB_MAJOR) && !defined(PTLIB_MAJOR)
	#if _WIN32
		#pragma message ("warning: Can't detect PTLib version")
	#else
		#warning "Can't detect PTLib version"
	 #endif
	// be on the safe side and risk a small memleak instead of a crash
	#define hasDeletingSetStream 1
#endif

// store version number it PT macros for display later on
#if !defined(PTLIB_MAJOR)
	#define PTLIB_MAJOR	PWLIB_MAJOR
	#define PTLIB_MINOR	PWLIB_MINOR
	#define PTLIB_BUILD	PWLIB_BUILD
#endif

///////////////////////////////////////////////
// OpenH323/H323Plus version matching

#ifdef H323PCH
	#include <h323.h>
#endif

#ifdef H323_H235
	#define HAS_H235_MEDIA 1      // H.235.6 Media Encryption Support
#endif

#ifdef H323_H450
	#define HAS_H450 1
#endif

#ifdef H323_H460
	#define HAS_H460 1    // H460 support
	#define HAS_H460VEN	1
#else
	#undef HAS_H46017
	#undef HAS_H46018
	#undef HAS_H46023
#endif

// feature detection, if library supports H.460.26 (unusable before 12.5.3)
#ifdef HAS_H46017			// config switch H.460.17 must be enabled
	#if defined(H323_H46026) && (H323PLUS_VER >= 1253)
		#define HAS_H46026 1
	#endif
#endif

#ifdef HAS_H46023		// config switch if H.460.23 should be enabled
	#ifdef H323_H46023	// feature detection, if library supports H.460.23
		#ifdef H323_H46024A
			#define HAS_H46024A	1
		#endif
		#ifdef H323_H46024B
			#define HAS_H46024B	1
		#endif
	#endif
#endif

#ifdef H323_H460P
	#define HAS_H460P	1  // Presence
    #ifdef H323_H460P_VER
        #if H323_H460P_VER == 3
            #define HAS_H460P_VER_3	 1
        #else
            #define HAS_H460P_VER_2	 1
        #endif
    #else
        #define HAS_H460P_VER_1  1
    #endif
#endif

#ifdef H323_H460PRE
	#define HAS_H460PRE 1
#endif

#if OPENH323_MAJOR == 1
	#if OPENH323_MINOR == 22
		#if OPENH323_BUILD >= 1
		#define HAS_ROUTECALLTOMC 1	// H323Plus endpoints supports RouteCallToMC() - starts with 1.22.1
		#endif
	#endif
#endif
#if OPENH323_MAJOR == 1
	#if OPENH323_MINOR > 22
		#define HAS_ROUTECALLTOMC 1	// H323Plus endpoints supports RouteCallToMC() - starts inside 1.22.1
	#endif
#endif

#if OPENH323_MAJOR == 1
	#if OPENH323_MINOR >= 19
		#if OPENH323_MINOR == 19
			#if OPENH323_BUILD > 4
				#define h323pluslib 1		// Indicate H323plus Library
				#define h323v6 1			// Version 6 features
			#endif
		#else // h323plus v1.20
			#define h323pluslib 1			// Indicate H323plus Library
			#define h323v6 1				// Version 6 features
		#endif
	#endif
#endif

#if defined(HAS_PTLIBSNMP) || defined(HAS_NETSNMP)
    #define HAS_SNMP 1
#endif

#if (H323PLUS_VER >= 1254)
    #define HAS_LANGUAGE 1
    #define HAS_SETTOKENLENGTH 1
#endif

#if (H323PLUS_VER >= 1267)
    #define HAS_H2351_CONFIG 1
#endif

#if (H323PLUS_VER >= 1270 && defined(H323_H235))
    // DES_ECB code uses new OpenSSL 1.1 code in H323Plus
    #define HAS_DES_ECB 1
#endif



//////////////////////////////////////////////////////////////////

#if (defined P_LINUX) || (defined P_FREEBSD) || (defined P_HPUX9) || (defined P_SOLARIS) || (defined P_OPENBSD)
// On some OS we don't get broadcasts on a socket that is
// bound to a specific interface. For those we have to start
// a listener just for those broadcasts.
// On Windows NT we get all messages on the RAS socket, even
// if it's bound to a specific interface and thus we don't have
// to start a listener for broadcast.
#define NEED_BROADCASTLISTENER 1
#else
#define NEED_BROADCASTLISTENER 0
#endif

#if HAS_MYSQL || HAS_PGSQL || HAS_FIREBIRD || HAS_ODBC || HAS_SQLITE
#define		HAS_DATABASE 1
#endif

extern PIPSocket::Address GNUGK_INADDR_ANY;

// a snprintf() implementation for Visual C++ prior to 2015
// found at https://stackoverflow.com/questions/2915672/snprintf-and-visual-studio-2010

#if defined(_MSC_VER) && _MSC_VER < 1900

#define snprintf c99_snprintf
#define vsnprintf c99_vsnprintf

__inline int c99_vsnprintf(char *outBuf, size_t size, const char *format, va_list ap)
{
    int count = -1;

    if (size != 0)
        count = _vsnprintf_s(outBuf, size, _TRUNCATE, format, ap);
    if (count == -1)
        count = _vscprintf(format, ap);

    return count;
}

__inline int c99_snprintf(char *outBuf, size_t size, const char *format, ...)
{
    int count;
    va_list ap;

    va_start(ap, format);
    count = c99_vsnprintf(outBuf, size, format, ap);
    va_end(ap);

    return count;
}

#endif

#endif // CONFIG_H

