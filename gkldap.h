// -*- mode: c++; eval: (c-set-style "linux"); -*-
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


#ifndef GKLDAP_H
#define GKLDAP_H "@(#) $Id$"

// LDAP authentification
#if defined(HAS_LDAP)		// shall use LDAP

#ifndef _PTLIB_H
#include <ptlib.h>
#endif

#include "gkDatabase.h"
#include "ldaplink.h"

class GkLDAP : public GkDBHandler{
	PCLASSINFO(GkLDAP, GkDBHandler)
public:

	GkLDAP(PConfig &, DBAttributeNamesClass & attrNames);
	virtual ~GkLDAP();

	/** returns attribute values for a given alias + attribute
	    @returns #TRUE# if an entry is found
	 */
	virtual BOOL getAttribute(const PString &alias, const dctn::DBAttributeNamesEnum attr_name, PStringList &attr_values);

	/** returns attribute values for a given alias and all attributes
	    @returns #TRUE# if LDAPQuery succeeds and exactly 1 match is found
	 */
	virtual BOOL getAttributes(const PString &alias, DBAttributeValueClass &attr_map);

	/** checks if an alias is a prefix of an attribute value in a LDAP entry.
	    #matchFound# returns #TRUE# if a match is found and #fullMatch# returns
	    #TRUE# if it is a full match.
	    @returns #TRUE# if succeeds
	 */
	virtual BOOL prefixMatch(const H225_AliasAddress & alias, const dctn::DBAttributeNamesEnum attr_name,
					BOOL & matchFound, BOOL & fullMatch, BOOL & gwFound, CalledProfile & calledProfile);
	/** @returns database type
	 */
	virtual dctn::DBTypeEnum GkLDAP::dbType();

protected:

	DBAttributeNamesClass AN;	// names of the database attributes

private:

	LDAPCtrl *LDAPConn;		// a HAS-A relation is prefered over a IS-A relation
				// because one can better steer the parameters
};

#endif // HAS_LDAP

#endif /* GKLDAP_H */
