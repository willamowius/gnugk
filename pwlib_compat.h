//////////////////////////////////////////////////////////////////
//
// pwlib_compat.h PWLib compatibility header
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////


#ifndef PWLIB_COMPAT_H
#define PWLIB_COMPAT_H "@(#) $Id$"

#include "ptbuildopts.h"
#include "openh323buildopts.h"

// use at least PWLib Pandora
#if PWLIB_MAJOR == 1
	#if PWLIB_MINOR < 7
		#error "PWLib too old, use at least 1.7.5.2"
	#endif
#endif

// check for PConfig support
#ifndef P_CONFIG_FILE
	#error "Make sure PWLib has config file support enabled, avoid --disable-configfile or --enable-openh323 or --enable-minsize etc."
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

#if PWLIB_MAJOR == 1
	#if PWLIB_MINOR == 12
		#define hasRDS 1 
		#define hasSETENUMSERVERS 1    
	#endif
#endif

// for Ptlib v2.x
#ifdef PTLIB_MAJOR 
	#define hasRDS 1 
	#define hasSETENUMSERVERS 1    
	#define hasDeletingSetStream 1
#endif

#if PTLIB_MAJOR == 2
	// changed PConfig interface in PWLib >= 2.2.0
	#if PTLIB_MINOR >= 2
		#define hasPConfigArray 1
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
		#pragma message ("warning: Can't detect PWLib/PTLib version")
	#else
		#warning "Can't detect PWLib/PTLib version"
	 #endif
	// be on the safe side and risk a small memleak instead of a crash
	#define hasDeletingSetStream 1
#endif

///////////////////////////////////////////////

// OpenH323 version matching
#ifdef H323_H460
	#define HAS_H460 1    // H460 support
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

#endif
