// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// gkIniFile.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//      2002/04/03      initial version (Markus Muehlenbernd)
//
//////////////////////////////////////////////////////////////////

#include "gkDatabase.h"
#include "gkIniFile.h"
#include "Toolkit.h"
#include "h323pdu.h"
#include "ANSI.h"

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = GKINIFILE_H;
#endif /* lint */


const char *GK_GW_PREFIXES_SECTION_NAME = "RasSrv::GWPrefixes";
const char *GK_EP_SECTION_NAME = "RasSrv::EndpointOptions";
const char *GK_DATABASES_SECTION_NAME = "Gatekeeper::Databases";

GkIniFile::GkIniFile(PConfig &cfg)
{
	m_cfg = &cfg;
}

GkIniFile::~GkIniFile()
{
}

BOOL GkIniFile::getAttribute(const PString &alias, const dctn::DBAttributeNamesEnum attrName,
                           PStringList & attrValues)
{
	BOOL attrFound = FALSE;
	if (GkConfig()->HasKey(PString(GK_EP_SECTION_NAME), alias)) {
		if (attrName == dctn::H323ID) {
			attrValues.AppendString(alias);
		} else {
			// get values from ini
			PString values = GkConfig()->GetString(PString(GK_EP_SECTION_NAME), alias, "");
			if (!values.IsEmpty()) {
				// split for attributes at each ";"
				PStringArray dataArray = values.Tokenise(";");
				// for each attribute
				for (PINDEX i=0; i < dataArray.GetSize() && !attrFound; i++) {
					// split for key/values by first "="
					PINDEX pos = dataArray[i].Find('=');
					if (pos != P_MAX_INDEX) {
						PString key = dataArray[i].Left(pos);
						PString value = dataArray[i].Mid(pos+1);
						// if attribute found
						if (key == GkDatabase::Instance()->attrNameAsString(attrName)) {
							attrFound = TRUE;
							// split for values at each ","
							attrValues = value.Tokenise(",");
						}
					}
				}
			}
		}
		return TRUE;
	}
	return FALSE;
}

BOOL GkIniFile::getAttributes(const PString &alias, DBAttributeValueClass & attrMap)
{
	if (GkConfig()->HasKey(PString(GK_EP_SECTION_NAME), alias)) {
		PStringList h323id;
		h323id.AppendString(alias);
		// insert H323ID
		attrMap.insert(DBAVValuePair(GkDatabase::Instance()->attrNameAsString(dctn::H323ID), h323id));
		// get values from ini
		PString data = GkConfig()->GetString(PString(GK_EP_SECTION_NAME), alias, "");
		if (!data.IsEmpty()) {
			// split for attributes at each ";"
			PStringArray dataArray = data.Tokenise(";");
			// for each attribute
			for (PINDEX i=0; i < dataArray.GetSize(); i++) {
				// split for key/values by first "="
				PINDEX pos = dataArray[i].Find('=');
				if (pos != P_MAX_INDEX) {
					PString key = dataArray[i].Left(pos);
					PString value = dataArray[i].Mid(pos+1);
					// split for values at each ","
					PStringList values = value.Tokenise(",");
					using namespace dctn;
					attrMap.insert(DBAVValuePair(key, values));
				}
			}
		}
		return TRUE;
	}
	return FALSE;
}

void GkIniFile::checkMatch(const PString & H323ID, const PString & iniValue, const PString & refValue,
			    BOOL & partialMatch, BOOL & fullMatch, BOOL & gwFound)
{
	// if attribute value equals ini entry
	if (refValue == iniValue) {
		gwFound = FALSE;
		fullMatch = TRUE;
		PTRACE(2, ANSI::DBG << "TelephoneNo "
		  << refValue << " matches endpoint "
		  << H323ID << " in ini-file (full)" << ANSI::OFF);
	// if no full match is found up to now and
	// ini entry is prefix of attribute value
	} else if (!fullMatch && iniValue == refValue.Left(iniValue.GetLength())) {
		gwFound = TRUE;
		PTRACE(2, ANSI::DBG << "TelephoneNo "
		  << refValue << " matches endpoint "
		  << H323ID << " in ini-file (gateway found)" << ANSI::OFF);
	// if attribute value is prefix of ini entry
	} else if (refValue == iniValue.Left(refValue.GetLength())) {
		gwFound = FALSE;
		fullMatch = FALSE;
		partialMatch = TRUE;
		PTRACE(2, ANSI::DBG << "TelephoneNo "
		  << refValue << " matches to "
		  << H323ID << " in ini-file (partial)" << ANSI::OFF);
	}
}

BOOL GkIniFile::prefixMatch(const H225_AliasAddress & alias, const dctn::DBAttributeNamesEnum attrName,
			    BOOL & matchFound, BOOL & fullMatch, BOOL & gwFound, CalledProfile & calledProfile)
{
	// check endpoints for match
	PString aliasStr = H323GetAliasAddressString(alias);
	PStringToString allKeyValues = GkConfig()->GetAllKeyValues(PString(GK_EP_SECTION_NAME));
	BOOL partialMatch = (matchFound && !fullMatch && !gwFound);
	BOOL attrFound = FALSE;
	// for each ep in ini file
	for(PINDEX i=0; i < allKeyValues.GetSize() && !partialMatch; i++) {
		// split for attributes at each ";"
		PStringArray dataArray = allKeyValues.GetDataAt(i).Tokenise(";", FALSE);
		// for each attribute
		attrFound = FALSE;
		for (PINDEX j=0; j < dataArray.GetSize() && !attrFound; j++) {
			// split for key/values by first "="
			PINDEX pos = dataArray[j].Find('=');
			if (pos != P_MAX_INDEX) {
				PString key = dataArray[j].Left(pos);
				PString value = dataArray[j].Mid(pos+1);
				// if attribute found
				using namespace dctn;
				if (key == GkDatabase::Instance()->attrNameAsString(attrName)) {
					attrFound = TRUE;
					// split for values at each ","
					PStringList values = value.Tokenise(",");
					// for each attribute value
					for (PINDEX k=0; k < values.GetSize() && !partialMatch; k++) {
						// remove invalid characters from attribute value
						PString attrValue(GkDatabase::Instance()->rmInvalidCharsFromTelNo(values[k]));
						// check for match
						checkMatch(allKeyValues.GetKeyAt(i), attrValue,
								aliasStr, partialMatch, fullMatch, gwFound);
					}
				}
			}
		}
	}
	if (!partialMatch && attrName == dctn::TelephoneNo) {
		// check gw prefixes in GWPrefixes section
		PStringToString allKeyValuesGWPrefixes = GkConfig()->GetAllKeyValues(PString(GK_GW_PREFIXES_SECTION_NAME));
 		// for each endpoint
		for (PINDEX i=0; i < allKeyValuesGWPrefixes.GetSize(); i++) {
			// get prefixes for endpoint
			PStringArray prefixes = allKeyValuesGWPrefixes.GetDataAt(i).Tokenise(" ,;\t}n", FALSE);
			// for each gw prefix
			for (PINDEX j=0; j < prefixes.GetSize(); j++) {
				// check for match
				checkMatch(allKeyValuesGWPrefixes.GetKeyAt(i), prefixes[j],
						aliasStr, partialMatch, fullMatch, gwFound);
			}
		}
	}

	matchFound = (partialMatch || fullMatch || gwFound);
	return TRUE;
}

dctn::DBTypeEnum GkIniFile::dbType()
{
	return dctn::e_IniFile;
}
