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
// mark object with version info
static char vcid[] = "@(#) $Id$";
static char vcHid[] = LDAPLINK_H;
#endif /* lint */

/* This is the place to include standardized headers */
#if (defined(__cplusplus) && defined(USE_ISO_HEADERS))
#  include <cstdlib>            // ISO C++: C standard library
using namespace std;            // <--- NOTE!
#else /* either not C++ or the ISO headers shouldn't be used*/
#  include <stdlib.h>           /* ANSI C: C standard library */
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
#define ERRORPRINT(strpar) GkStatus::Instance()->                    \
                           SignalStatus(PString(strpar) + LDAP_DBG_LINEEND);
#define DEBUGPRINT(stream) PTRACE(LDAP_DBG_LVL, stream << endl);


// list of names (keys) as used in config file, keep in sync with LDAPAttributeNamesEnum
const char *  lctn::LDAPAttrTags[lctn::MAX_ATTR_NO] =
{"UserIdentity", "H323ID", "TelephonNo", "H245PassWord", "CountryCode", 
 "AreaCode", "LocalAccessCode", "NationalAccessCode", "InternationalAccessCode",
 "CallingLineIdPresentation", "PrefixBlacklist", "PrefixWhitelist"};



// CLASS: LDAPAnswer

LDAPAnswer::LDAPAnswer(): 
  status(LDAP_SUCCESS)
{
  // this space left blank intentionally
}

LDAPAnswer::~LDAPAnswer()
{
  // this space left blank intentionally
}

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
	       ServerName << ":(" << ServerPort << ")" << 
	       endl << vcid << endl << vcHid);
    ERRORPRINT(PString("ldap_ctrl: no connection on ") +
	       ServerName + ":(" + ServerPort + ")");
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
  }
#endif /* LDAP_USE_CACHE */

} // constructor: LDAPCtrl

LDAPCtrl::~LDAPCtrl()
{
  int ldap_ret;
#if (defined(LDAP_USE_CACHE) && (LDAP_USE_CACHE < 1))
    if(LDAP_SUCCESS != (ldap_ret = ldap_destroy_cache(ldap)))
      ERRORPRINT("~LDAPCtrl: couldn't get rid of cache: " 
		 + PString(ldap_err2string(ldap_ret)));
#endif /* LDAP_USE_CACHE */
  if(NULL != ldap)
    if(LDAP_SUCCESS != (ldap_ret = ldap_unbind(ldap)))
      ERRORPRINT("~LDAPCtrl: couldn't unbind: " 
		 + PString(ldap_err2string(ldap_ret)));
} // destructor: LDAPCtrl

// searching for user
LDAPAnswer * 
LDAPCtrl::DirectoryUserLookup(LDAPQuery & p) 
{
  LDAPAnswer * result = new LDAPAnswer;
  int ldap_ret = LDAP_SUCCESS;

  // this is the local bind version
  DEBUGPRINT("Binding with " << BindUserDN << "pw length:" << BindUserPW.GetLength());
  if (LDAP_SUCCESS == 
      (ldap_ret = ldap_simple_bind_s(ldap, BindUserDN, BindUserPW))) {
    DEBUGPRINT("ldap_simple_bind: OK " << PString(ldap_err2string(ldap_ret)));
  } else {
    ERRORPRINT("ldap_simple_bind: " + PString(ldap_err2string(ldap_ret)));
    result->status=ldap_ret;
    return result;
  }

  result = DirectoryLookup(p);

  DEBUGPRINT("Unbinding " << BindUserDN);
  if (LDAP_SUCCESS == (ldap_ret = ldap_unbind(ldap))) {
    DEBUGPRINT("ldap_unbind: OK " << PString(ldap_err2string(ldap_ret)));
  } else {
    ERRORPRINT("ldap_unbind: " + PString(ldap_err2string(ldap_ret)));
    result->status=ldap_ret;
    return result;
  }

  return result;
}

// searching for user
LDAPAnswer * 
LDAPCtrl::DirectoryLookup(LDAPQuery & p) 
{
  LDAPAnswer * result = new LDAPAnswer;
  int ldap_ret = LDAP_SUCCESS;
  LDAPMessage * res;		/* response */

  // basic search
  using namespace lctn;
  const char * (attrs[MAX_ATTR_NO]);
  unsigned int pos = 0;
  LDAPAttributeNamesClass::iterator iter = AttributeNames->begin();
  while((iter != AttributeNames->end()) && (MAX_ATTR_NO >= pos)) {
    // This cast is directly from hell, but pwlib is not nice to C APIs
    attrs[pos++] = (const char *)((*iter).second) ;
  }
  attrs[pos] = NULL;		// C construct: array of unknown size 
                                // terminated by NULL-pointer 

  int attrsonly = 0;		/* 0: attr&value; 1: attr */
  PString filter;
  filter.sprintf("(|(%s=%s)(%s=%s))", // RFC 1558 conform template
		 LDAPAttrTags[H323ID], // attribute name (H323ID)
		 (const char *)p.userH323ID, // requested value(H323ID)
		 // possible alternative
		 (char*)aliasH3232ID,// attribute name (H323ID)
		 (const char *)p.userH323ID // requested value (H323ID)
		 );


  DEBUGPRINT("ldap_search_st(" << SearchBaseDN << ", " << filter << ")");

  if (LDAP_SUCCESS == 
      (ldap_ret = ldap_search_st(ldap, SearchBaseDN, LDAP_SCOPE_SUBTREE, 
				 filter, (char **)attrs, attrsonly,
				 timeout, &res))) {
    DEBUGPRINT("ldap_search_st: OK " << PString(ldap_err2string(ldap_ret)));
  } else {
    ERRORPRINT("ldap_search_st: " + PString(ldap_err2string(ldap_ret)));
    result->status = ldap_ret;
    return result;
  }

  // analyze answer
  if (0 > (ldap_ret = ldap_count_entries(ldap, res))) {
    ERRORPRINT("ldap_search_st: " + PString(ldap_err2string(ldap_ret)));
    result->status = ldap_ret;
    return result;
  } else {
    DEBUGPRINT("ldap_search: " << ldap_ret << " results");
  }

  LDAPMessage * chain;		// iterate throght chain of answers
  for(chain = ldap_first_entry(ldap, res);
      chain != NULL;
      chain = ldap_next_entry(ldap, chain)) {
    char * attr = NULL;
    char * dn = NULL;
    BerElement * ber = NULL;
    if(NULL == (dn = ldap_get_dn(ldap, chain))) {
      ERRORPRINT("ldap_get_dn: Could not get distinguished name.");
    }
    DEBUGPRINT("found DN: " << dn);

    for(attr = ldap_first_attribute(ldap, chain, &ber);
	attr != NULL;
	attr = ldap_next_attribute(ldap, chain, ber)) {
      char ** valv = NULL;
      int valc = 0;
      if(NULL == (valv = ldap_get_values(ldap, chain, attr))) {
	ERRORPRINT("ldap_get_values: Could not get attribute values");
	result->status = LDAP_OTHER;
	return result;
      }
      valc = ldap_count_values(valv);

      //AV.insert(LDAPAVValuePair(attr,PStringList()));

      ldap_value_free(valv);
    } // attr
  } // answer chain
  return result;
}

//
// End of ldaplink.cxx
//




