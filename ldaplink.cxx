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

#include <math.h>		/* ANSI C: C math library */
#include "GkStatus.h"		// gatekeeper status port for error handling
#include <ptlib.h>		// the PWlib
#if defined(HAS_MWBB1)
#  include <bb1.h>		// LDAP coding
#endif


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
#define DEBUGPRINT(stream) PTRACE(LDAP_DBG_LVL, "GK\t" << stream << endl);


// list of names (keys) as used in config file, keep in sync with LDAPAttributeNamesEnum
const char *  lctn::LDAPAttrTags[lctn::MAX_ATTR_NO] =
{"DN", "H323ID", "TelephonNo", "H245PassWord", "IPAddress", "SubscriberNo", 
 "LocalAccessCode", "NationalAccessCode",  "InternationalAccessCode", 
 "CallingLineIdRestriction", "SpecialDial", "PrefixBlacklist", "PrefixWhitelist"};



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

bool
LDAPAnswer::complete(void)
{
  bool result = true;
  // FIXME: this is just stub a t the moment;
  return result;
}

// CLASS: LDAPCtrl

LDAPCtrl::LDAPCtrl(LDAPAttributeNamesClass * AttrNames,
		   struct timeval default_timeout,
		   PString & ServerName,
		   PString & SearchBaseDN,
		   PString & BindUserDN,
		   PString & BindUserPW,
		   unsigned int sizelimit = LDAP_NO_LIMIT,
		   unsigned int timelimit = LDAP_NO_LIMIT,
		   int ServerPort = LDAP_PORT):
  AttributeNames(AttrNames), timeout(default_timeout), ServerName(ServerName),
  ServerPort(ServerPort), SearchBaseDN(SearchBaseDN), BindUserDN(BindUserDN),
  BindUserPW(BindUserPW), sizelimit(sizelimit), timelimit(timelimit), 
  ldap(NULL), known_to_be_bound(false)
{
  Initialize();
  if(LDAP_SUCCESS != Bind(true)){ // bind (enforced)
    ERRORPRINT("LDAPCtrl: can not access LDAP, destroying object")
    Destroy();
  }
} // constructor: LDAPCtrl


LDAPCtrl::~LDAPCtrl()
{
  Destroy();
} // destructor: LDAPCtrl


// binding, may be enforced by passing true
int
LDAPCtrl::Bind(bool force = false)
{
  int ldap_ret = LDAP_SUCCESS;
  if(known_to_be_bound && force)
    DEBUGPRINT("Bind: I think I'm already bound, but action is forced");

  if(!known_to_be_bound || force) {
    // this is the local bind version
    DEBUGPRINT("Binding with " << BindUserDN << "pw length:" << BindUserPW.GetLength());
    if (LDAP_SUCCESS == 
	(ldap_ret = gk_ldap_simple_bind_s(ldap, BindUserDN, BindUserPW))) {
      known_to_be_bound = true;
      DEBUGPRINT("LDAPCtrl::Bind: OK bound");
    } else {
      ERRORPRINT("LDAPCtrl::Bind: " + PString(gk_ldap_err2string(ldap_ret)));
    }
  }
  return ldap_ret;
}

// unbinding, may be enforced by passing true
int
LDAPCtrl::Unbind(bool force = false)
{
  int ldap_ret = LDAP_SUCCESS;

  if(!known_to_be_bound && force)
    DEBUGPRINT("Unbind: I think I'm already unbound, but action is forced");

  if((NULL != ldap) && (known_to_be_bound || force))
    if(LDAP_SUCCESS != (ldap_ret = gk_ldap_unbind(ldap))) {
      ERRORPRINT("Unbind: couldn't unbind: " 
		 + PString(gk_ldap_err2string(ldap_ret)));
    } else {
      known_to_be_bound = false;
    }
  return ldap_ret;
}

// privat: initializer called from constructors
void
LDAPCtrl::Initialize(void)
{
  // get ldap c-object
  GK_LDAP * ld = NULL;
  if (NULL == (ld = gk_ldap_init(ServerName, ServerPort))) {
    DEBUGPRINT("Initialize: no connection on " << 
	       ServerName << ":(" << ServerPort << ")" << 
	       endl << vcid << endl << vcHid);
    ERRORPRINT(PString("LDAPCtrl::Initialize: no connection on ") +
	       ServerName + ":(" + ServerPort + ")");
    ldap = NULL;
  } else {
    DEBUGPRINT("LDAPCtrl::Initialize: connection OK on" << 
	       ServerName << ":(" << ServerPort << ")");
    ldap = ld;
  }

#if (((LDAP_API_VERSION >= 2004) && defined(LDAP_API_FEATURE_X_OPENLDAP)) || \
 defined (HAS_LEVEL_TWO_LDAPAPI))
  // OpenLDAP API 2000+draft revision provides better controlled access
  int opt_ret = LDAP_OPT_SUCCESS;
  if(LDAP_OPT_SUCCESS != 
     (opt_ret = gk_ldap_set_option(ldap, LDAP_OPT_TIMELIMIT, (void*)&timelimit))) {
    DEBUGPRINT("ldap_set_option: Couln't set timelimit");
    ERRORPRINT("ldap_set_option: Couln't set timelimit");
  }
  if(LDAP_OPT_SUCCESS != 
     (opt_ret = gk_ldap_set_option(ldap, LDAP_OPT_SIZELIMIT, (void*)&sizelimit))) {
    DEBUGPRINT("ldap_set_option: Couln't set sizelimit");
    ERRORPRINT("ldap_set_option: Couln't set sizelimit");
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

} // privat: Initialize


void 
LDAPCtrl::Destroy(void)
{
  Unbind();

#if (defined(LDAP_USE_CACHE) && (LDAP_USE_CACHE < 1))
  if(LDAP_SUCCESS != (ldap_ret = ldap_destroy_cache(ldap)))
    ERRORPRINT("~LDAPCtrl: couldn't get rid of cache: " 
	       + PString(ldap_err2string(ldap_ret)));
#endif /* LDAP_USE_CACHE */
}



// searching for user
LDAPAnswer * 
LDAPCtrl::DirectoryUserLookup(LDAPQuery & q) 
{
  LDAPAnswer * result = new LDAPAnswer;
  const unsigned int maxretries = 10; // we may migrate this into the object
  unsigned int retry = 0;
  using namespace lctn;

  // search until found or out of retries
  while((!((result = DirectoryLookup(q))->complete())) && 
	(maxretries>(retry++))) {
    // FIXME: modify q to complete result
    if(result->AV[LDAPAttrTags[DN]][0].GetSize()) {}
  }

#if defined(HAS_MWBB1)
  const char * const mwbb1 = MWBB1_TAG;	// MWBB1_TAG has to be a string literal
  unsigned int mwbb1_len = strlen(mwbb1);
  PString & pwlist = AV[LDAPAttrTags[H245PassWord]];
  PINDEX pwlistsize = pwlist.GetSize();
  for(PINDEX i = 0; i <= pwlistsize; i++) {
    PString & pw = pwlist[i];
    if(mwbb1 == pw.Left(mwbb1_len-1)) {
      pw.Delete(0,mwbb1_len-1);	// remove the header
      pw = PString(DeCryptBB1(pw)); // DeCryptBB1 is not thread save at all!
    }
  }
#endif

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
    iter++;
  }
  attrs[pos] = NULL;		// C construct: array of unknown size 
                                // terminated by NULL-pointer 

  int attrsonly = 0;		/* 0: attr&value; 1: attr */
  PString filter;
  if(p.LDAPAttributeValues.empty()) { // "Old" default behavior
  filter.sprintf("(%s=%s)", // RFC 1558 conform template
		 (const char *)(*AttributeNames)[LDAPAttrTags[H323ID]], // attribute name (H323ID)
		 (const char *)p.userH323ID // requested value(H323ID)
		 );
  } else {
    filter="(";
    switch(p.LDAPOperator) {
      case (LDAPQuery::LDAPand):
	filter+="&";
	break;
      case (LDAPQuery::LDAPor):
	filter+="|";
	break;
      case (LDAPQuery::LDAPnot):
	filter+="!";
    }
    for(LDAPAttributeValueClass::iterator iter=p.LDAPAttributeValues.begin(); iter!=p.LDAPAttributeValues.end();
	iter++) {
      PString attribute=(*iter).first;
      for (PINDEX index=0; (*iter).second.GetSize(); index++) {
	filter+="(";
	filter+=attribute;
	filter+="=";
	filter+=(*iter).second[index];
	filter+=")";
      }
    }
    filter+=")";
  }
//   DEBUGPRINT("ldap_search_st(" << SearchBaseDN << ", " << filter << ", " << timeout.tv_sec << ":" << 
// 	     timeout.tv_usec << ")");
  unsigned int retry_count = 0;
  do {
    struct timeval * tm = new struct timeval;
    memcpy(tm, &timeout, sizeof(struct timeval));
    DEBUGPRINT("ldap_search_st(" << SearchBaseDN << ", " << filter << ", " << timeout.tv_sec << ":" << 
	       timeout.tv_usec << ")");
  
    // The linux-implementation of select(2) will change the given value of
    // struct timeval *. This syscall is used within ldap_search.
    if (LDAP_SUCCESS == 
	(ldap_ret = gk_ldap_search_st(ldap, SearchBaseDN, LDAP_SCOPE_SUBTREE, 
				   filter, (char **)attrs, attrsonly,
				   tm, &res))) {
      DEBUGPRINT("ldap_search_st: OK " << PString(gk_ldap_err2string(ldap_ret)));
    } else {
      DEBUGPRINT("ldap_search_st: " + PString(gk_ldap_err2string(ldap_ret)));
      ERRORPRINT("ldap_search_st: " + PString(gk_ldap_err2string(ldap_ret)));
      result->status = ldap_ret;
      if(LDAP_UNAVAILABLE == ldap_ret) known_to_be_bound = false;
      sleep((int)pow(2.0,retry_count)); // exponential back off
      Bind();			// rebind 
    }
    delete tm;
  } while((LDAP_SUCCESS != ldap_ret)&&(retry_count++ < 4));

  // analyze answer
  if (0 >= (ldap_ret = gk_ldap_count_entries(ldap, res))) {
    ERRORPRINT("ldap_search_st: " + PString(gk_ldap_err2string(ldap_ret)));
    result->status = (0==ldap_ret) ? (-1) : ldap_ret;
    return result;
  } else {
    DEBUGPRINT("ldap_search: " << ldap_ret << " results");
  }
  LDAPMessage * chain;		// iterate throught chain of answers
  for(chain = gk_ldap_first_entry(ldap, res);
      chain != NULL;		// NULL terminated
      chain = gk_ldap_next_entry(ldap, chain)) {
    char * dn = NULL;
    if(NULL == (dn = gk_ldap_get_dn(ldap, chain))) {
      ERRORPRINT("ldap_get_dn: Could not get distinguished name.");
    }
    DEBUGPRINT("found DN: " << dn);
    // treating the dn as a kind of attribute
    result->AV.insert(LDAPAVValuePair(PString(LDAPAttrTags[DN]),
				      PStringList(1, &dn, false)));
    BerElement * ber = NULL;	// a 'void *' would do the same but RFC 1823
				// indicates it to be a pointer to a BerElement
    char * attr = NULL;		// iterate throught list of attributes
    for(attr = gk_ldap_first_attribute(ldap, chain, &ber);
	attr != NULL;		// NULL terminated
	attr = gk_ldap_next_attribute(ldap, chain, ber)) {
      char ** valv = gk_ldap_get_values(ldap, chain, attr); // vector
      int valc = gk_ldap_count_values(valv); // count
      if(0 == valc) DEBUGPRINT("value handling: No values returned");
      // put list of values (of this partyicular attribute) into PStringList
      // which can be accessed by a STL map, indexed by attribute names.
      // This implies, that the data is not bit- or octet-string, 
      // because it may NOT contain \0.
      result->AV.insert(LDAPAVValuePair(PString(attr),
					PStringList(valc, valv, false)));
      gk_ldap_value_free(valv);	// remove value vector
    } // attr
  } // answer chain
  return result;
}

//
// End of ldaplink.cxx
//




