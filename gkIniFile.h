//////////////////////////////////////////////////////////////////
//
// gkIniFile.h
//
// Gatekeeper database modules
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//
// History:
//      2002/04/03      initial version (Markus Muehlenbernd)
//
//////////////////////////////////////////////////////////////////


#ifndef __gkIniFile_h_
#define __gkIniFile_h_

#ifndef _PTLIB_H
#include <ptlib.h>
#endif

#include "gkDatabase.h"

extern const char *GK_DATABASES_SECTION_NAME;

class GkIniFile : public GkDBHandler{
	PCLASSINFO(GkIniFile, GkDBHandler)
public:

	GkIniFile(PConfig &);
	virtual ~GkIniFile();

	/** returns attribute values for a given alias + attribute
	    @returns #TRUE# if an entry is found
	 */
	virtual BOOL getAttribute(const PString &alias, const dctn::DBAttributeNamesEnum attr_name, PStringList &attr_values);

	/** returns attribute values for a given alias and all attributes
	    @returns #TRUE# if exactly 1 match is found
	 */
	virtual BOOL getAttributes(const PString &alias, DBAttributeValueClass &attr_map);

	/** checks if an alias is a prefix of an attribute value in an entry.
	    #matchFound# returns #TRUE# if a match is found and #fullMatch# returns
	    #TRUE# if it is a full match.
	    @returns #TRUE# if succeeds
	 */
	virtual BOOL prefixMatch(const H225_AliasAddress & alias, const dctn::DBAttributeNamesEnum attr_name,
					BOOL & matchFound, BOOL & fullMatch, BOOL & gwFound, CalledProfile & calledProfile);

	/** @returns database type
	 */
	virtual dctn::DBTypeEnum dbType();

private:

	void checkMatch(const PString & H323ID, const PString & iniValue, const PString & refValue,
			    BOOL & partialMatch, BOOL & fullMatch, BOOL & gwFound);

	PConfig * m_cfg;
};

#endif  // __gkIniFile_h_
