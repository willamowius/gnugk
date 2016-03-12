/*
* h323headers.h
*
* Precompile header file for GnuGk
* Precompiled headers are required for H323PLUS 1.28 or above
*
* Copyright (c) 2015, Simon Horne
*
* This work is published under the GNU Public License version 2 (GPLv2)
* see file COPYING for details.
* We also explicitly grant the right to link this code
* with the OpenH323/H323Plus and OpenSSL library.
*
*/

#ifdef USE_PCH
    #include <openh323buildopts.h>
    #ifdef H323PCH
        #include <h323.h>
    #else 
        #include <ptlib.h>
    #endif
#else
    #include <ptlib.h>
#endif

