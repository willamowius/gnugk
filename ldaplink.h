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
    DN=0, UserIdentity, H323ID, TelephonNo, H245PassWord, aliasH3232ID,
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

typedef map<PString, PStringList> LDAPAttributeValueClass;
typedef LDAPAttributeValueClass::value_type LDAPAVValuePair;
/** Class that contains search answers
*/
class LDAPAnswer {
public:
  LDAPAnswer();
  virtual ~LDAPAnswer();
  int status;			// as LDAP.ld_errno
  LDAPAttributeValueClass AV;	// the attributes and their values
  virtual bool complete(void);	// test if this is all we need
};

class LDAPCtrl {
public:
  LDAPCtrl(LDAPAttributeNamesClass *, // the Attribute names
	   struct timeval *,	// the devault timeout for *_st operations
	   PString &,		// Name of the LDAP Server
	   PString &,		// Distinguished Name (DN) from where to search
	   PString &,		// UserDN of acting user
	   PString &,		// Pasword for simple auth. of BindUserDN
	   unsigned int,	// 0 for no cache (default 0)
	   unsigned int,	// timeout in seconds (default 10)
	   int			// Port of the LDAP Server (default IANA port)
	   ); 
  virtual ~LDAPCtrl();

  // searching for user accreditation
  virtual LDAPAnswer * DirectoryUserLookup(LDAPQuery &); 

protected:
  // Some of this data might look superflous, but experience teaches to
  // keep the connection details. At least they come handy during a
  // debugging session
  LDAPAttributeNamesClass * AttributeNames; // names of the LDAP attributes
  struct timeval * timeout;	// timeout for *_st operations
  PString ServerName;		// Name of the LDAP Server
  int ServerPort;		// Port of the LDAP Server
  PString SearchBaseDN;		// Distinguished Name (DN) from where to search
  PString BindUserDN;		// UserDN of acting user
  PString BindUserPW;		// Pasword for simple auth. of BindUserDN
  unsigned int sizelimit;	// size of local cache in bytes
  unsigned int timelimit;	// timeout for operations in seconds
  virtual LDAPAnswer * DirectoryLookup(LDAPQuery &); // internal look up
private:
  LDAP * ldap;			// The ldap connection
  bool known_to_be_bound;	// _known_ status of binding
  void Initialize(void);	// initializer, called from constructors
  void Destroy(void);		// actual destructor called from formal one
  int Bind(bool);		// binding, may be enforced by passing true
  int Unbind(bool);		// unbinding, may be enforced by passing true

};

#endif /* defined(LDAPLINK_H) */

//
// End of ldaplink.h
//
