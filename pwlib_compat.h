//////////////////////////////////////////////////////////////////
//
// pwlib_compat.h PWLib compatibility header
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
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
    #if PWLIB_BUILD < 5
      #error "PWLib too old, use at least 1.7.5.2"
    #endif
  #endif
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

///////////////////////////////////////////////
// H460 and DNS SRV Support
#ifdef H323_H460
   #define hasH460 1
#endif

// DNS SRV 
#ifdef P_DNS
   #define hasSRV 1 
#endif

// Disable if below OpenH323 v1.19
#if OPENH323_MAJOR == 1
  #if OPENH323_MINOR < 19
       #undef hasH460 
       #undef hasSRV  
  #endif
#endif

//////////////////////////////////////////////
// Factory loader System

#define OpenH323Factory 1

// Disable if below OpenH323 v1.18
#if OPENH323_MAJOR == 1
  #if OPENH323_MINOR < 19
       #undef OpenH323Factory
  #endif
#endif


#endif // PWLIB_COMPAT_H

