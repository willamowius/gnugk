// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// gkDatabase.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//      2002/03/27      initial version (Markus Muehlenbernd)
//
//////////////////////////////////////////////////////////////////


#include "gkDatabase.h"
#include "Toolkit.h"
#include <h323pdu.h>

// include databases
#include "gkIniFile.h"

#if defined (HAS_LDAP)
#include "gkldap.h"
#endif

// list of names (keys) as used in config file, keep in sync with DBAttributeNamesEnum
const char *  dctn::DBAttrTags[dctn::MAX_ATTR_NO] =
{"DN", "H323ID", "TelephoneNo", "FacsimileTelephoneNo", "H235PassWord", "IPAddress",
 "LocalAccessCode", "NationalAccessCode",  "InternationalAccessCode",
 "MainTelephoneNo", "SubscriberTelephoneNumber", "CallingLineIdRestriction", "SpecialDials",
 "HonorsARJincompleteAddress", "PrefixOutgoingBlacklist", "PrefixOutgoingWhitelist",
 "PrefixIncomingBlacklist", "PrefixIncomingWhitelist", "voIPprependCallbackAC",
 "EPType", "CountryCode"};

// section name for database names which shall be used
const char *DB_NAMES_SEC = "Gatekeeper::Databases";
const char *DB_ATTR_NAME_SEC = "GkDatabase::DBAttributeNames";
const char *GK_EP_TYPE_TRUNK_GW = "trunk";


GkDatabase::GkDatabase()
{
	//Initialisation must be done with method "Initialize"!
}

GkDatabase::~GkDatabase()
{
	Destroy();
}

void GkDatabase::Initialize(PConfig &cfg) // 'real', private constructor
{
	using namespace dctn;		// database config tags and names
	// The defaults are given by the constructor of DBAttributeNamesClass
	AN.insert(DBANValuePair(DBAttrTags[H323ID],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[H323ID],
					      "mail"))); // 0.9.2342.19200300.100.1.3
	AN.insert(DBANValuePair(DBAttrTags[TelephoneNo],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[TelephoneNo],
					      "telephoneNumber"))); // 2.5.4.20
	AN.insert(DBANValuePair(DBAttrTags[FacsimileTelephoneNo],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[FacsimileTelephoneNo],
					      "facsimileTelephoneNumber")));	// 2.5.4.23
	AN.insert(DBANValuePair(DBAttrTags[H235PassWord],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[H235PassWord],
					      "plaintextPassword")));	// 1.3.6.1.4.1.9564.2.1.1.8
	AN.insert(DBANValuePair(DBAttrTags[IPAddress],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[IPAddress],
					      "voIPIpAddress"))); // ...9564.2.5.2010
	AN.insert(DBANValuePair(DBAttrTags[LocalAccessCode],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[LocalAccessCode],
					      "voIPlocalAccessCode"))); // ...2020
	AN.insert(DBANValuePair(DBAttrTags[NationalAccessCode],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[NationalAccessCode],			      // ...9564.2.5.2030
					      "voIPnationalAccessCode"))); // ...2030
	AN.insert(DBANValuePair(DBAttrTags[InternationalAccessCode],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[InternationalAccessCode],
					       // ...9564.2.5.2040
					      "voIPinternationalAccessCode"))); // ...2040
	AN.insert(DBANValuePair(DBAttrTags[MainTelephoneNo],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[MainTelephoneNo],
					      "voIPmainTelephoneNumber"))); // ...2060
	AN.insert(DBANValuePair(DBAttrTags[SubscriberTelephoneNumber],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[SubscriberTelephoneNumber],
					      "voIPsubscriberTelephoneNumber"))); // ...2050
	AN.insert(DBANValuePair(DBAttrTags[CallingLineIdRestriction],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[CallingLineIdRestriction],
					      "voIPcallingLineIdRestriction"))); // ...2070
	AN.insert(DBANValuePair(DBAttrTags[SpecialDials],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[SpecialDials],
					      "voIPspecialDial"))); // ...2080
	AN.insert(DBANValuePair(DBAttrTags[HonorsARJincompleteAddress],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[HonorsARJincompleteAddress],
					      "voIPhonorsARJincompleteAddress"))); // ...2090
	AN.insert(DBANValuePair(DBAttrTags[PrefixOutgoingBlacklist],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[PrefixOutgoingBlacklist],
					      "voIPprefixOutgoingBlacklist"))); // ...2140
	AN.insert(DBANValuePair(DBAttrTags[PrefixOutgoingWhitelist],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[PrefixOutgoingWhitelist],
					      "voIPprefixOutgoingWhitelist"))); // ...2150
	AN.insert(DBANValuePair(DBAttrTags[PrefixIncomingBlacklist],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[PrefixIncomingBlacklist],
					      "voIPprefixIncomingBlacklist"))); // ...2160
	AN.insert(DBANValuePair(DBAttrTags[PrefixIncomingWhitelist],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[PrefixIncomingWhitelist],
					      "voIPprefixIncomingWhitelist"))); // ...2170
	AN.insert(DBANValuePair(DBAttrTags[PrependCallbackAC],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[PrependCallbackAC],
					      "voIPprependCallbackAC"))); // ...2090
	AN.insert(DBANValuePair(DBAttrTags[EPType],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[EPType],
					      "voIPEndpointType")));
	AN.insert(DBANValuePair(DBAttrTags[CountryCode],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[CountryCode],
					      "voIPCountryCode")));

	// read database names which shall be used and append them to m_dbList
	if(m_dbList.GetSize()>0) {
		m_dbList.RemoveAll();
	}
	// check if section with database list exists in ini file
	PStringList sections = GkConfig()->GetSections();
	PINDEX pos = sections.GetStringsIndex(DB_NAMES_SEC);
	// if section exists
	if (P_MAX_INDEX != pos) {
		PStringList dbNamesList(cfg.GetKeys(DB_NAMES_SEC));
		PStringToString dbNamesDict(cfg.GetAllKeyValues(DB_NAMES_SEC));
		for (PINDEX i=0; i < dbNamesList.GetSize(); i++) {
			PString dbName(dbNamesList[i]);
			if (Toolkit::AsBool(dbNamesDict[dbName])) {
				if (dbName == "IniFile") {
					m_dbList.Append(PNEW GkIniFile(cfg));
					PTRACE(1, "Added IniFile to database list");
#if defined (HAS_LDAP)
				} else if (dbName == "LDAP") {
					m_dbList.Append(PNEW GkLDAP(cfg, AN));
					PTRACE(1, "Added LDAP to database list");
#endif
				}
			}
		}
	} else {
		m_dbList.Append(PNEW GkIniFile(cfg));
		PTRACE(1, "Added IniFile to database list");
	}
}

void GkDatabase::Destroy()		// 'real', private destructor
{
}

BOOL GkDatabase::getProfile(CallingProfile & cgProfile, PString & h323id, dctn::DBTypeEnum & dbType)
{
	DBAttributeValueClass attrMap;
	using namespace dctn;
	if (getAttributes(h323id,  attrMap, dbType)) {
	// 1 match
		PStringArray spDialArray;
		PStringToString spDialDict;
		for (PINDEX i = 0; i < attrMap[attrNameAsString(SpecialDials)].GetSize(); i++) {
			spDialArray = attrMap[attrNameAsString(SpecialDials)][i].Tokenise("=");
			if (spDialArray.GetSize() == 2) {
				spDialDict.SetAt(spDialArray[0], spDialArray[1]);
			}
		}
		cgProfile.setSpecialDials(spDialDict);
		if (attrMap[attrNameAsString(TelephoneNo)].GetSize() > 0)
			cgProfile.setTelephoneNumbers(attrMap[attrNameAsString(TelephoneNo)]);
		if (attrMap[attrNameAsString(PrefixOutgoingBlacklist)].GetSize() > 0)
			cgProfile.setBlackList(attrMap[attrNameAsString(PrefixOutgoingBlacklist)]);
		if (attrMap[attrNameAsString(PrefixOutgoingWhitelist)].GetSize() > 0)
			cgProfile.setWhiteList(attrMap[attrNameAsString(PrefixOutgoingWhitelist)]);
		if (attrMap[attrNameAsString(HonorsARJincompleteAddress)].GetSize() > 0)
			cgProfile.setHonorsARJincompleteAddress(Toolkit::AsBool(attrMap[attrNameAsString(HonorsARJincompleteAddress)][0]));
		if (attrMap[attrNameAsString(H323ID)].GetSize() > 0)
			cgProfile.setH323ID(attrMap[attrNameAsString(H323ID)][0]);
		if (attrMap[attrNameAsString(MainTelephoneNo)].GetSize() > 0)
			cgProfile.setMainTelephoneNumber(attrMap[attrNameAsString(MainTelephoneNo)][0]);
		if (attrMap[attrNameAsString(SubscriberTelephoneNumber)].GetSize() > 0)
			cgProfile.setSubscriberNumber(attrMap[attrNameAsString(SubscriberTelephoneNumber)][0]);
		if (attrMap[attrNameAsString(CallingLineIdRestriction)].GetSize() > 0)
			cgProfile.setClir(attrMap[attrNameAsString(CallingLineIdRestriction)][0]);
		if (attrMap[attrNameAsString(LocalAccessCode)].GetSize() > 0)
			cgProfile.setLac(attrMap[attrNameAsString(LocalAccessCode)][0]);
		if (attrMap[attrNameAsString(NationalAccessCode)].GetSize() > 0)
			cgProfile.setNac(attrMap[attrNameAsString(NationalAccessCode)][0]);
		if (attrMap[attrNameAsString(InternationalAccessCode)].GetSize() > 0)
			cgProfile.setInac(attrMap[attrNameAsString(InternationalAccessCode)][0]);
		if (attrMap[attrNameAsString(CountryCode)].GetSize() > 0)
			cgProfile.setCC(attrMap[attrNameAsString(CountryCode)][0]);
		if (attrMap[attrNameAsString(EPType)].GetSize() == 0) {
			cgProfile.setIsCPE(TRUE);
		} else if (attrMap[attrNameAsString(EPType)].GetSize() > 0) {
			cgProfile.setIsCPE( (attrMap[attrNameAsString(EPType)][0] == PString(GK_EP_TYPE_TRUNK_GW)) ? FALSE : TRUE);
		}

		cgProfile.debugPrint();
	} else {
		return FALSE;
	}
        return TRUE;
}

BOOL GkDatabase::isCPE(PString &h323id, dctn::DBTypeEnum & dbType)
{
	BOOL isCPE = TRUE;
	PStringList values;
	using namespace dctn;
	if (getAttribute(h323id, EPType, values, dbType)
			&& values.GetSize() > 0) {
		if (values[0] == GK_EP_TYPE_TRUNK_GW) {
			PTRACE(5, "Call comes from a gateway");
			isCPE = FALSE;
		} else {
			PTRACE(5, "Call comes from a CPE");
			isCPE = TRUE;
		}
	}
        return isCPE;
}


PString GkDatabase::attrNameAsString(const dctn::DBAttributeNamesEnum &attr_name) {
	using namespace dctn;
	return AN[DBAttrTags[attr_name]];
}

PString GkDatabase::rmInvalidCharsFromTelNo(PString telNo)
{
	telNo.Replace(".", "", TRUE);
	return telNo;
}

BOOL GkDatabase::validAliases(const H225_ArrayOf_AliasAddress & aliases) {
	PString aliasStr;
	bool found = 0;
	// search H323ID in aliases
	for (PINDEX i = 0; i < aliases.GetSize() && !found; i++) {
		if (aliases[i].GetTag() == H225_AliasAddress::e_h323_ID) {
			aliasStr = H323GetAliasAddressString(aliases[i]);
			found = 1;
		}
	}
	if(!found) return FALSE;
	PStringList telephoneNumbers;
	// get telephone numbers from database for H323ID
	using namespace dctn;		// database config tags and names
	DBTypeEnum dbType;
	if(getAttribute(aliasStr, TelephoneNo, telephoneNumbers, dbType)) {
		// for each alias
		for (PINDEX i = 0; i < aliases.GetSize(); i++) {
			if (aliases[i].GetTag() != H225_AliasAddress::e_h323_ID) {
				aliasStr = H323GetAliasAddressString(aliases[i]);
				// check if alias exists in telephoneNumber attributes from database entry
				for (PINDEX j = 0; j < telephoneNumbers.GetSize(); j++) {
					if(aliasStr != rmInvalidCharsFromTelNo(telephoneNumbers[j])) {
						return FALSE;
					}
				}
			}
		}
		return TRUE;
	}
	return FALSE;
}

BOOL GkDatabase::getAttribute(const PString &alias, const dctn::DBAttributeNamesEnum attr_name, PStringList &attr_values,
		dctn::DBTypeEnum & dbType)
{
	PWaitAndSignal lock(m_usedLock);
	dbType = dctn::e_TypeUnknown;
	BOOL found = FALSE;
	for (PINDEX i=0; i < m_dbList.GetSize() && !found; i++) {
		if (m_dbList[i].getAttribute(alias, attr_name, attr_values)) {
			dbType = m_dbList[i].dbType();
			found = TRUE;
		}
	}
	return found;
}

BOOL GkDatabase::getAttributes(const PString &alias, DBAttributeValueClass &attr_map, dctn::DBTypeEnum & dbType)
{
	PWaitAndSignal lock(m_usedLock);
	dbType = dctn::e_TypeUnknown;
	BOOL found = FALSE;
	for (PINDEX i=0; i < m_dbList.GetSize() && !found; i++) {
		if (m_dbList[i].getAttributes(alias, attr_map)) {
			dbType = m_dbList[i].dbType();
			found = TRUE;
		}
	}
	return found;
}

BOOL GkDatabase::prefixMatch(const H225_AliasAddress & alias, const dctn::DBAttributeNamesEnum attr_name,
			   BOOL & matchFound, BOOL & fullMatch, BOOL & gwFound, dctn::DBTypeEnum & dbType)
{
	PWaitAndSignal lock(m_usedLock);
	dbType = dctn::e_TypeUnknown;
	BOOL fullMatchOld = FALSE;
	BOOL gwFoundOld = FALSE;
	fullMatch = FALSE;
	gwFound = FALSE;
	matchFound = FALSE;
	for (PINDEX i=0; i < m_dbList.GetSize(); i++) {
		// if prefixMatch succeeds
		if (m_dbList[i].prefixMatch(alias, attr_name, matchFound, fullMatch, gwFound)) {
			if (matchFound){
				// if first full match is found
				if (fullMatch && !fullMatchOld) {
					dbType = m_dbList[i].dbType();
					fullMatchOld = TRUE;
				// if first gateway is found
				} else if (gwFound && !gwFoundOld) {
					dbType = m_dbList[i].dbType();
					gwFoundOld = TRUE;
				// else if partial match is found
				} else if (!fullMatch && !gwFound) {
					dbType = m_dbList[i].dbType();
					return TRUE;
				}
			}
		} else {
			return FALSE;
		}
	}
	return TRUE;
}
