//////////////////////////////////////////////////////////////////
//
// gkDatabase.h
//
// Gatekeeper database module
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//
// History:
//      2002/03/27      initial version (Markus Muehlenbernd)
//
//////////////////////////////////////////////////////////////////


#ifndef __gkDatabase_h_
#define __gkDatabase_h_

#ifndef _PTLIB_H
#include <ptlib.h>
#endif

#ifdef P_SOLARIS
#define map stl_map
#endif

#include <map>			// STL map
#include "singleton.h"
#include "RasTbl.h"
#include <h225.h>


/** Class that holds the current names of the attribute names used for the
    database access
*/
using std::map;
typedef std::map<PString, PString> DBAttributeNamesClass;
typedef DBAttributeNamesClass::value_type DBANValuePair;

typedef std::map<PString, PStringList> DBAttributeValueClass;
typedef DBAttributeValueClass::value_type DBAVValuePair;

// database config tags and names
namespace dctn {

enum DBTypeEnum {
	e_TypeUnknown=0, e_LDAP, e_IniFile, MAX_TYPE_NO
};
	/// tags named after config file tags, used as indices to DBAttrTags
enum DBAttributeNamesEnum {
	NameUnknown=0, H323ID, TelephoneNo, FacsimileTelephoneNo, H235PassWord, IPAddress,
	LocalAccessCode, NationalAccessCode, InternationalAccessCode,
	MainTelephoneNo, SubscriberTelephoneNumber, CallingLineIdRestriction, SpecialDials,
	HonorsARJincompleteAddress, PrefixOutgoingBlacklist, PrefixOutgoingWhitelist,
	PrefixIncomingBlacklist, PrefixIncomingWhitelist, PrependCallbackAC, EPType, CountryCode,
	MAX_ATTR_NO };

	/// list of names (keys) as used in config file
extern const char * DBAttrTags[MAX_ATTR_NO];
}

class GkDBHandler : public PObject{
	PCLASSINFO(GkDBHandler, PObject)
public:

	GkDBHandler() {};
	virtual ~GkDBHandler() {};

	/** returns attribute values for a given alias + attribute
	    @returns #TRUE# if an entry is found
	 */
	virtual BOOL getAttribute(const PString &alias, const dctn::DBAttributeNamesEnum attr_name, PStringList &attr_values) = 0;

	/** returns attribute values for a given alias and all attributes
	    @returns #TRUE# if database query succeeds and exactly 1 match is found
	 */
	virtual BOOL getAttributes(const PString &alias, DBAttributeValueClass &attr_map) = 0;

	/** checks if an alias is a prefix of an attribute value in a database entry.
	    #matchFound# returns #TRUE# if a match is found and #fullMatch# returns
	    #TRUE# if it is a full match.
	    @returns #TRUE# if succeeds
	 */
	virtual BOOL prefixMatch(const H225_AliasAddress & alias, const dctn::DBAttributeNamesEnum attr_name,
			   BOOL & matchFound, BOOL & fullMatch, BOOL & gwFound) = 0;

	/** @returns database type
	 */
	virtual dctn::DBTypeEnum dbType() = 0;
};

PLIST(DBListType, GkDBHandler);

class GkDatabase : public Singleton<GkDatabase>{
public:

  /** Database initialisation must be done with method "Initialize".
      This is necessary because this class is singleton.
   */
  GkDatabase();
  virtual void Initialize(PConfig &);
  virtual ~GkDatabase();

  /** @returns profile data and dbType in
   */
  virtual BOOL getProfile(CallingProfile & cgProfile, PString & h323id, dctn::DBTypeEnum & dbType);

  /** @returns #TRUE# if the endpoint with given H323ID is an CPE.
   */
  virtual BOOL isCPE(PString &h323id, dctn::DBTypeEnum & dbType);

  /** returns the attribute name as string
   */
  virtual PString attrNameAsString(const dctn::DBAttributeNamesEnum &attr_name);

  /** removes invalid characters from telephoneNumber-attribute (like dots)
      @returns converted telNo
   */
  virtual PString rmInvalidCharsFromTelNo(PString telNo);

  /** checks if all given aliases exist in
      telephoneNumber attribute of the matching LDAP entry.
      The LDAP entry is searched by the given H323ID. If a H323ID is not found,
      the function returns #FALSE#.
      @returns #TRUE# if aliases are valid
   */
  virtual BOOL validAliases(const H225_ArrayOf_AliasAddress & aliases);

  /** returns attribute values for a given alias + attribute
      @returns #TRUE# if an entry was found
   */
  virtual BOOL getAttribute(const PString &alias, const dctn::DBAttributeNamesEnum attr_name,
		  	    PStringList &attr_values, dctn::DBTypeEnum & dbType);

  /** returns attribute values for a given alias and all attributes
      @returns #TRUE# if exactly 1 match is found
   */
  virtual BOOL getAttributes(const PString &alias, DBAttributeValueClass &attr_map,
			     dctn::DBTypeEnum & dbType);

  /** Checks if an alias is a prefix of an attribute value in a database entry.
      #matchFound# returns #TRUE# if a match is found, #fullMatch# returns
      #TRUE# if it is a full match and #gwFound# returns #TRUE# if it is a gateway.
      #fullMatch# and #gwFound# must be initialized before the function
      is called! Example: if fullMatch is initialized with #TRUE# then the function does not
      search for a gateway (priority of fullMatch > priority of gwFound).
      #dbType# returns the type of database in which the first match with highest priority
      was found.
      @returns #TRUE# if succeeds
   */
  virtual BOOL prefixMatch(const H225_AliasAddress & alias, const dctn::DBAttributeNamesEnum attr_name,
			   BOOL & matchFound, BOOL & fullMatch, BOOL & gwFound,
			   dctn::DBTypeEnum & dbType);

private:

  void Destroy();

  DBAttributeNamesClass AN;	// names of the database attributes
  PMutex m_usedLock;
  DBListType m_dbList;
};

#endif  // __gkDatabase_h_
