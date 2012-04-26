//////////////////////////////////////////////////////////////////
//
// pwlib_compat.h PWLib compatibility header
//
// Copyright (c) 2006-2011, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////


#ifndef PWLIB_COMPAT_H
#define PWLIB_COMPAT_H "@(#) $Id$"

#include "ptbuildopts.h"
#include "openh323buildopts.h"
#include "gnugkbuildopts.h"

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

// define PWCharArray for PWLib < 2.x.x
#if PTLIB_MAJOR < 2
	#define PWCharArray PWORDArray
#endif


#if !defined(P_USE_STANDARD_CXX_BOOL) && !defined(P_USE_INTEGER_BOOL)
	typedef int PBoolean;
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
			#ifdef P_LUA
				#define hasLUA      1
			#endif
		#endif
	#endif
	#if PTLIB_MINOR >= 11
		#define hasLDAPStartTLS 1
        #define hasNewSTUN      1
        #define hasPTRACE2      1
        #ifdef P_LUA
			#define hasLUA      1
		#endif
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

#if !defined(PWLIB_MAJOR) && !defined(PTLIB_MAJOR)
	#if _WIN32
		#pragma message ("warning: Can't detect PTLib version")
	#else
		#warning "Can't detect PTLib version"
	 #endif
	// be on the safe side and risk a small memleak instead of a crash
	#define hasDeletingSetStream 1
#endif

// store version numver it PT macros for dispaly later on
#if !defined(PTLIB_MAJOR)
	#define PTLIB_MAJOR	PWLIB_MAJOR
	#define PTLIB_MINOR	PWLIB_MINOR
	#define PTLIB_BUILD	PWLIB_BUILD
#endif

///////////////////////////////////////////////

// OpenH323/H323Plus version matching
#ifdef H323_H235
	// loading of the H.235.6 authenticator only works with PTLib 2.11.x
	#define HAS_H235_MEDIA 1      // H.235.6 Media Encryption Support
#endif

#ifdef H323_H460
	#define HAS_H460 1    // H460 support
#else
	#undef HAS_H46017
	#undef HAS_H46018
	#undef HAS_H46023
#endif

#ifdef HAS_H46023		// config switch if H.460.23 should be enabled
	#ifdef H323_H46023	// feature detection, if library supports H.460.23
		#ifdef H323_H46024B
			#define HAS_H46024B	1
		#endif
	#endif
#endif

#ifdef H323_H460P
	#define HAS_H460P	1  // Presence
#ifdef H323_H460P_VER
	#define H460P_VER H323_H460P_VER
	#define OID3 "1.3.6.1.4.1.17090.0.12"  // Presence v2
#else
	#define H460P_VER 1
	#define OID3 "1.3.6.1.4.1.17090.0.3"  // Presence
#endif
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
			#if OPENH323_BUILD > 0
				#define OpenH323Factory 1	// OpenH323 Factory Loader Auth
			#endif
			#if OPENH323_BUILD > 4
				#define h323pluslib 1		// Indicate H323plus Library
				#define h323v6 1			// Version 6 features
			#endif
		#else // h323plus v1.20
			#define OpenH323Factory 1		// OpenH323 Factory Loader Auth 
			#define h323pluslib 1			// Indicate H323plus Library
			#define h323v6 1				// Version 6 features  
		#endif
	#endif	
#endif

#if defined(hasPTRACE2)
   #define PTRACEX(level, args)  PTRACE2(level,NULL,args)
#else
   #define PTRACEX(level, args)  PTRACE(level,args)   
#endif

#endif
