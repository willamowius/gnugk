//////////////////////////////////////////////////////////////////
//
// gkldap.h
//
// Gatekeeper authentication modules
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//
// History:
//      2002/01/28      initial version (Markus Muehlenbernd)
//
//////////////////////////////////////////////////////////////////


#ifndef __gkldap_h_
#define __gkldap_h_

// LDAP authentification
#if defined(HAS_LDAP)		// shall use LDAP

#ifndef _PTLIB_H
#include <ptlib.h>
#endif

#include "ldaplink.h"		// link to LDAP functions
#include "singleton.h"
#include "h225.h"
#include "h323pdu.h"

class GkLDAP : public Singleton<GkLDAP>{
public:
  
  /** LDAP initialisation must be done with method "Initialize". 
      This is necessary because this class is singleton.
   */
  GkLDAP();
  virtual void Initialize(PConfig &);
  
  virtual ~GkLDAP();
  
  /** returns attribute values for a given alias + attribute
      @returns #TRUE# if LDAPQuery succeeds
   */
  virtual bool getAttribute(const PString &alias, const int attr_name, PStringList &attr_values);
  
  /** checks if all given aliases (dialedDigits) exist in 
      telephonNo attribute of LDAP entry
      @returns #TRUE# if aliases are valid
   */
  virtual bool validAliases(const H225_ArrayOf_AliasAddress & aliases);
  
  /** converts a telephonNo from LDAP entry (E.123 string) to
      dialedDigits
      @returns dialedDigits
   */
  virtual PString convertE123ToDialedDigits(PString e123);  

private:

  // Methods
  void Destroy(void);
  
  // Data
  LDAPAttributeNamesClass AN;	// names of the LDAP attributes
  LDAPCtrl *LDAPConn;		// a HAS-A relation is prefered over a IS-A relation
				// because one can better steer the parameters  

  PMutex m_usedLock;
};

#endif // HAS_LDAP

#endif  // __gkldap_h_
