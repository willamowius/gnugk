// -*- c++ -*-
// Copyright (C) 2001 Dr.-Ing. Martin Froehlich <Martin.Froehlich@mediaWays.net>
//  
// PURPOSE OF THIS FILE: 
//   Realizes the LDAP search functions based on the RFC 1823 LDAP-API
//  
// - Automatic Version Information via CVS/RCS:
//   $Id$
//   $Source$
//  
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//  
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//  

#include "ldaplink.h"		// First of includes: own interface

#ifndef lint
static char vcid[] = "@(#) $Id$";
static char vcHid[] = LDAPLINK_H;
#endif /* lint */

/* This is the place to include standardized headers */
#if (defined(__cplusplus) && defined(USE_ISO_HEADERS))
#  include <cstdlib>            // ISO C++: standard library
using namespace std;            // <--- NOTE!
#else /* either not C++ or the ISO headers shouldn't be used*/
#  include <stdlib.h>           /* ANSI C: standard library */
#endif /* use of header type resolved */

#include "GkStatus.h"		// gatekeeper status port for error handling


// simplified output
#if !defined(LDAP_DBG_LVL)
#  define LDAP_DBG_LVL 2
#endif
#if !defined(LDAP_DBG_LINEEND)
#  if defined(WIN32)
#    define LDAP_DBG_LINEEND "\r\n"
#  else
#    define LDAP_DBG_LINEEND "\n"
#  endif
#endif
// NOTE: Do not use the ldap_perror function! This environment provides its
//       own error handling:
#define ERRORPRINT(stream) GkStatus::Instance()->                    \
                           SignalStatus(PString(stream) + LDAP_DBG_LINEEND);
#define DEBUGPRINT(stream) PTRACE(LDAP_DBG_LVL, stream << LDAP_DBG_LINEEND);


// CLASS: LDAPAttributeNamesClass
LDAPAttributeNamesClass::LDAPAttributeNamesClass() 
{
  // defaults from the supplied VoIP-Scheme (OID as comment)
  UserIdentity_ldap_attr = "uid"; // 0.9.2342.19200300.100.1.1
  H323ID_ldap_attr = "cn";	// 2.5.4.3
  TelephonNr_ldap_attr = "telephoneNumber"; // 2.5.4.20
  H245PassWord_ldap_attr = "plaintextPassword";	// ...9564.2.1.1.8
  aliasH3232ID_ldap_attr = "voIPnickName"; // ...9564.2.5.1000
  CountryCode_ldap_attr = "voIPcountryCode"; // ...9564.2.5.2000
  AreaCode_ldap_attr = "voIPareaCode"; // ...9564.2.5.2010
  LocalAccessCode_ldap_attr = "voIPlocalAccessCode"; // ...9564.2.5.2020
  NationalAccessCode_ldap_attr = "voIPnationalAccessCode"; // ...9564.2.5.2030
  InternationalAccessCode_ldap_attr = "voIPinternationalAccessCode"; // ...9564.2.5.2040
  CallingLineIdPresentation_ldap_attr = "voIPcallingLineIdPresentation"; // ...2050
  PrefixBlacklist_ldap_attr = "voIPprefixBlacklist"; // ...9564.2.5.2060
  PrefixWhitelist_ldap_attr = "voIPprefixWhitelist"; // ...9564.2.5.2070
}

LDAPAttributeNamesClass::~LDAPAttributeNamesClass() 
{
  // do nothing
}

// CLASS: LDAPAnswer

// CLASS: LDAPCtrl

LDAPCtrl::LDAPCtrl(LDAPAttributeNamesClass * AttrNames,
		   struct timeval * default_timeout,
		   PString ServerName,
		   PString SearchBaseDN,
		   PString BindUserDN,
		   PString BindUserPW,
		   unsigned int sizelimit = LDAP_NO_LIMIT,
		   unsigned int timelimit = LDAP_NO_LIMIT,
		   int ServerPort = LDAP_PORT)
{
  // Some of this data might look superflous, but experience teaches to
  // keep the connection details. At least they come handy during a
  // debugging session
  LDAPCtrl::timeout = default_timeout;
  LDAPCtrl::AttributeNames = AttrNames;
  LDAPCtrl::ServerName = ServerName;
  LDAPCtrl::ServerPort = ServerPort;
  LDAPCtrl::SearchBaseDN = SearchBaseDN;
  LDAPCtrl::BindUserDN = BindUserDN;
  LDAPCtrl::BindUserPW = BindUserPW;
  LDAPCtrl::sizelimit = sizelimit;
  LDAPCtrl::timelimit = timelimit;

  // get ldap c-object
  LDAP * ld = NULL;
  if (NULL == (ld = ldap_init(ServerName, ServerPort))) {
    DEBUGPRINT("ldap_ctrl: no connection on " << 
	       ServerName << ":(" << ServerPort << ")");
    ERRORPRINT(PString("ldap_ctrl: no connection on " + 
	       ServerName + ":(" + ServerPort + ")"));
    ldap = NULL;
  } else {
    DEBUGPRINT("ldap_ctrl: connection OK on" << 
	       ServerName << ":(" << ServerPort << ")");
    ldap = ld;
  }

#if ((LDAP_API_VERSION >= 2004) && defined(LDAP_API_FEATURE_X_OPENLDAP))
  // OpenLDAP API 2000+draft revision provides better controlled access
  int opt_ret = LDAP_OPT_SUCCESS;
  if(LDAP_OPT_SUCCESS != 
     (opt_ret = ldap_set_option(ldap, LDAP_OPT_TIMELIMIT, (void*)&timelimit))) {
    DEBUGPRINT("timelimit");
    ERRORPRINT("timelimit");
  }
  if(LDAP_OPT_SUCCESS != 
     (opt_ret = ldap_set_option(ldap, LDAP_OPT_SIZELIMIT, (void*)&sizelimit))) {
    DEBUGPRINT("sizelimit");
    ERRORPRINT("sizelimit");
  }
#else /* LDAP_API_VERSION */
  // strictly RFC1823
  ldap->ld_timelimit = (int)timelimit;
  ldap->ld_sizelimit = (int)sizelimit;
#endif /* LDAP_API_VERSION */


#if (defined(LDAP_USE_CACHE) && (LDAP_USE_CACHE < 1))
  // avoid bogus settings of LDAP_HAS_CACHE and use it as size parameter (bytes)
  if(LDAP_SUCCESS != ldap_enable_cache(ldap, timelimit, LDAP_HAS_CACHE)) {
    ERRORPRINT("ldap_ctrl: error while trying to get cache(" 
	       + PString(timelimit)
	       + ", " + PString(LDAP_HAS_CACHE) + ")");
#endif /* LDAP_USE_CACHE */

} // constructor: LDAPCtrl

LDAPCtrl::~LDAPCtrl()
{
#if (defined(LDAP_USE_CACHE) && (LDAP_USE_CACHE < 1))
    ldap_destroy_cache(ldap); // get rid of cache
#endif /* LDAP_USE_CACHE */
  if(NULL != ldap) {
    int ld_errno;
    if(LDAP_SUCCESS != (ld_errno = ldap_unbind(ldap)))
      ERRORPRINT("~LDAPCtrl: couldn't get rid of cache:" 
		 + PString(ldap_err2string(ld_errno)));
  }
} // destructor: LDAPCtrl




//
// End of ldaplink.cxx
//
