// -*- c++ -*-
// Copyright (C) 2001 Dr.-Ing. Martin Froehlich <Martin.Froehlich@mediaWays.net>
//  
// PURPOSE OF THIS FILE: 
//   Provides the LDAP search functions based on the RFC 1823 LDAP-API
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

#if !defined(LDAPLINK_H)	/* make idempotent */
#define LDAPLINK_H "@(#) $Id$"

#if defined(HAS_LEVEL_TWO_LDAPAPI) 
#  include "ldapapi.h"		// local API to libOpenH323 classes
#else
#  include <ldap.h>		// std RFC 1823 LDAP-API
#  if defined(NO_BERVAL_IN_LDAP_H) // set in case of old headers
// this is the value type used in the RFC 1823 LDAP-API
typedef struct berval {
  unsigned long bv_len;
  char *bv_val;
};
#  endif
#endif

#include <ptlib.h>		// the PWlib
#include <map>			// STL map

/** Class that holds the current names of the attribute names used for the
    LDAP access 
*/
using std::map;
typedef std::map<PString, PString> LDAPAttributeNamesClass;
typedef LDAPAttributeNamesClass::value_type LDAPANValuePair;

// LDAP config tags and names
namespace lctn {
  /// tags named after config file tags, used as indices to LDAPAttrTags
  enum LDAPAttributeNamesEnum {
    UserIdentity=0, H323ID, TelephonNo, H245PassWord, aliasH3232ID,
    CountryCode, AreaCode, LocalAccessCode, NationalAccessCode,
    InternationalAccessCode, CallingLineIdPresentation, PrefixBlacklist,
    PrefixWhitelist, MAX_ATTR_NO };

  /// list of names (keys) as used in config file
  extern const char * LDAPAttrTags[MAX_ATTR_NO];
}


/** Class that contains search queries
*/
class LDAPQuery {
public:
  PString userH323ID;
};

/** Class that contains search answers
*/
class LDAPAnswer {
public:
  LDAPAnswer();
  ~LDAPAnswer();
  int status;			// as LDAP.ld_errno
  typedef map<PString, PStringList> LDAPAttributeValueClass;
  typedef LDAPAttributeNamesClass::value_type LDAPAVValuePair;
  LDAPAttributeValueClass AV;	// the attributes and their values
};

class LDAPCtrl {
public:
  LDAPCtrl(LDAPAttributeNamesClass *, // the Attribute names
	   struct timeval *,	// the devault timeout for *_st operations
	   PString,		// Name of the LDAP Server
	   PString,		// Distinguished Name (DN) from where to search
	   PString,		// UserDN of acting user
	   PString,		// Pasword for simple auth. of BindUserDN
	   unsigned int,	// 0 for no cache (default 0)
	   unsigned int,	// timeout in seconds (default 10)
	   int			// Port of the LDAP Server (default IANA port)
	   ); 
  ~LDAPCtrl();

  // searching for user accreditation
  LDAPAnswer * DirectoryUserLookup(LDAPQuery &); 

protected:
  LDAPAttributeNamesClass * AttributeNames; // names of the LDAP attributes
  struct timeval * timeout;	// timeout for *_st operations
  PString ServerName;		// Name of the LDAP Server
  int ServerPort;		// Port of the LDAP Server
  PString SearchBaseDN;		// Distinguished Name (DN) from where to search
  PString BindUserDN;		// UserDN of acting user
  PString BindUserPW;		// Pasword for simple auth. of BindUserDN
  unsigned int sizelimit;	// size of local cache in bytes
  unsigned int timelimit;	// timeout for operations in seconds
private:
  LDAP * ldap;			// The ldap connection
  LDAPAnswer * DirectoryLookup(LDAPQuery &); // internal look up
};

#endif /* defined(LDAPLINK_H) */

//
// End of ldaplink.h
//
