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

#include "rwlock.h"
#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = GKDATABASE_H;
#endif /* lint */


// list of names (keys) as used in config file, keep in sync with DBAttributeNamesEnum
const char *  dctn::DBAttrTags[dctn::MAX_ATTR_NO] =
{"DN", "H323ID", "TelephoneNumber", "FacsimileTelephoneNumber", "H235PassWord", "IPAddress",
 "LocalAccessCode", "NationalAccessCode",  "InternationalAccessCode",
 "MainTelephoneNumber", "SubscriberTelephoneNumber", "CallingLineIdRestriction", "SpecialDials",
 "HonorsARJincompleteAddress", "PrefixOutgoingBlacklist", "PrefixOutgoingWhitelist",
 "PrefixIncomingBlacklist", "PrefixIncomingWhitelist", "PrependCallbackAC",
 "EndpointType", "CountryCode", "NationalDestnationCode", "OutgoingWhitelistBeforeBlacklist", "ConvertToLocal",
 "TreatCallingPartyNumberAs", "TreatCalledPartyNumberAs", "StatusEnquiryInterval", "CallTimeout", "MinimumPrefixLength"};

// section name for database names which shall be used
const char *DB_NAMES_SEC = "Gatekeeper::Databases";
const char *DB_ATTR_NAME_SEC = "GkDatabase::DBAttributeNames";
const char *GK_EP_TYPE_TRUNK_GW = "trunk";
const char *GK_EP_TYPE_GATEKEEPER = "gk";


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
	AN_mutex.StartWrite();
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
	AN.insert(DBANValuePair(DBAttrTags[OutgoingWhitelistBeforeBlacklist],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[OutgoingWhitelistBeforeBlacklist],
					      "voIPWhiteListBeforeBlackList")));
	AN.insert(DBANValuePair(DBAttrTags[ConvertToLocal],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[ConvertToLocal],
					      "voIPConvertToLocal")));
	AN.insert(DBANValuePair(DBAttrTags[StatusEnquiryInterval],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[StatusEnquiryInterval],
					      "voIPStatusEnquiryInterval")));
	AN.insert(DBANValuePair(DBAttrTags[CallTimeout],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[CallTimeout],
					      "voIPCallTimeout")));
	AN.insert(DBANValuePair(DBAttrTags[TreatCallingPartyNumberAs],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[TreatCallingPartyNumberAs],
					      "voIPTreatCallingPartyNumberAs")));
	AN.insert(DBANValuePair(DBAttrTags[TreatCalledPartyNumberAs],
				cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[TreatCalledPartyNumberAs],
					      "voIPTreatCalledPartyNumberAs")));
	AN.insert(DBANValuePair(DBAttrTags[MinimumPrefixLength],
			    cfg.GetString(DB_ATTR_NAME_SEC,
					      DBAttrTags[MinimumPrefixLength],
					      "voIPMinimumPrefixLength")));

	AN_mutex.EndWrite();
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
					AN_mutex.StartRead();
					m_dbList.Append(PNEW GkLDAP(cfg, AN));
					AN_mutex.EndRead();
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

BOOL GkDatabase::getProfile(CallProfile & cgProfile, PString & h323id, dctn::DBTypeEnum & dbType)
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
		cgProfile.SetSpecialDials(spDialDict);
		if (attrMap[attrNameAsString(TelephoneNo)].GetSize() > 0)
			cgProfile.SetTelephoneNumbers(attrMap[attrNameAsString(TelephoneNo)]);
		if (attrMap[attrNameAsString(PrefixOutgoingBlacklist)].GetSize() > 0)
			cgProfile.SetBlackList(attrMap[attrNameAsString(PrefixOutgoingBlacklist)]);
		if (attrMap[attrNameAsString(PrefixOutgoingWhitelist)].GetSize() > 0)
			cgProfile.SetWhiteList(attrMap[attrNameAsString(PrefixOutgoingWhitelist)]);
		if (attrMap[attrNameAsString(HonorsARJincompleteAddress)].GetSize() > 0)
			cgProfile.SetHonorsARJincompleteAddress(Toolkit::AsBool(attrMap[attrNameAsString(HonorsARJincompleteAddress)][0]));
		if (attrMap[attrNameAsString(H323ID)].GetSize() > 0)
			cgProfile.SetH323ID(attrMap[attrNameAsString(H323ID)][0]);
		if (attrMap[attrNameAsString(MainTelephoneNo)].GetSize() > 0)
			cgProfile.SetMainTelephoneNumber(attrMap[attrNameAsString(MainTelephoneNo)][0]);
		if (attrMap[attrNameAsString(SubscriberTelephoneNumber)].GetSize() > 0)
			cgProfile.SetSubscriberNumber(attrMap[attrNameAsString(SubscriberTelephoneNumber)][0]);
		if (attrMap[attrNameAsString(CallingLineIdRestriction)].GetSize() > 0)
			cgProfile.SetClir(attrMap[attrNameAsString(CallingLineIdRestriction)][0]);
		if (attrMap[attrNameAsString(LocalAccessCode)].GetSize() > 0)
			cgProfile.SetLac(attrMap[attrNameAsString(LocalAccessCode)][0]);
		if (attrMap[attrNameAsString(NationalAccessCode)].GetSize() > 0)
			cgProfile.SetNac(attrMap[attrNameAsString(NationalAccessCode)][0]);
		if (attrMap[attrNameAsString(InternationalAccessCode)].GetSize() > 0)
			cgProfile.SetInac(attrMap[attrNameAsString(InternationalAccessCode)][0]);
		if (attrMap[attrNameAsString(NationalDestinationCode)].GetSize() > 0 &&
		    !attrMap[attrNameAsString(NationalDestinationCode)][0].IsEmpty()) {
			cgProfile.SetNDC_IC(attrMap[attrNameAsString(NationalDestinationCode)][0]);
		} else if (!cgProfile.GetMainTelephoneNumber().IsEmpty()) {
			E164_AnalysedNumber number(cgProfile.GetMainTelephoneNumber());
			cgProfile.SetNDC_IC(number.GetNDC_IC());
		} else if (cgProfile.GetTelephoneNumbers().GetSize()==1) {
			E164_AnalysedNumber number(cgProfile.GetTelephoneNumbers()[0]);
			cgProfile.SetNDC_IC(number.GetNDC_IC());
		}
		if (attrMap[attrNameAsString(CountryCode)].GetSize() > 0 &&
		    !attrMap[attrNameAsString(CountryCode)][0].IsEmpty()) {
			cgProfile.SetCC(attrMap[attrNameAsString(CountryCode)][0]);
		} else if (!cgProfile.GetMainTelephoneNumber().IsEmpty()) {
			E164_AnalysedNumber number(cgProfile.GetMainTelephoneNumber());
			cgProfile.SetCC(number.GetCC());
		} else if (cgProfile.GetTelephoneNumbers().GetSize()==1) {
			E164_AnalysedNumber number(cgProfile.GetTelephoneNumbers()[0]);
			cgProfile.SetCC(number.GetCC());
		} else { // No Country code can be found.
			 // Use a unknown (spare) Country Code
			cgProfile.SetCC("899");
		}
		if (attrMap[attrNameAsString(EPType)].GetSize() == 0) {
			cgProfile.SetIsCPE(TRUE);
		} else if (attrMap[attrNameAsString(EPType)].GetSize() > 0) {
			cgProfile.SetIsCPE( (attrMap[attrNameAsString(EPType)][0] == PString(GK_EP_TYPE_TRUNK_GW)) ? FALSE : TRUE);
			cgProfile.SetIsGK( (attrMap[attrNameAsString(EPType)][0] == PString(GK_EP_TYPE_GATEKEEPER)) ? FALSE : TRUE);
		}
		if (attrMap[attrNameAsString(PrependCallbackAC)].GetSize() == 0 ||
		    attrMap[attrNameAsString(PrependCallbackAC)][0].IsEmpty()) {
			cgProfile.SetPrependCallbackAC(FALSE);
		} else if (attrMap[attrNameAsString(EPType)].GetSize() > 0) {
			cgProfile.SetPrependCallbackAC(Toolkit::AsBool(attrMap[attrNameAsString(PrependCallbackAC)][0]));
		}
		if (attrMap[attrNameAsString(ConvertToLocal)].GetSize() == 0 ||
		    attrMap[attrNameAsString(ConvertToLocal)][0].IsEmpty()) {
			cgProfile.SetConvertToLocal(FALSE);
		} else if (attrMap[attrNameAsString(ConvertToLocal)].GetSize() > 0) {
			cgProfile.SetConvertToLocal(Toolkit::AsBool(attrMap[attrNameAsString(ConvertToLocal)][0]));
		}
		if (attrMap[attrNameAsString(StatusEnquiryInterval)].GetSize() == 0) {
			cgProfile.SetStatusEnquiryInterval(0);
		} else {
			cgProfile.SetStatusEnquiryInterval(attrMap[attrNameAsString(StatusEnquiryInterval)][0].AsInteger());
		}
/*
		if (attrMap[attrNameAsString(CallTimeout)].GetSize() == 0) {
			cgProfile.SetCallTimeout(0);
		} else {
			cgProfile.SetCallTimeout(attrMap[attrNameAsString(CallTimeout)].AsInteger());
		}
*/
		if (attrMap[attrNameAsString(TreatCallingPartyNumberAs)].GetSize() > 0)
			cgProfile.SetTreatCallingPartyNumberAs(static_cast <CallProfile::Conversions>
							       (attrMap[attrNameAsString(TreatCallingPartyNumberAs)][0].AsInteger()));
		if (attrMap[attrNameAsString(TreatCalledPartyNumberAs)].GetSize() > 0)
			cgProfile.SetTreatCalledPartyNumberAs(static_cast <CallProfile::Conversions>
							      (attrMap[attrNameAsString(TreatCalledPartyNumberAs)][0].AsInteger()));
		if (attrMap[attrNameAsString(OutgoingWhitelistBeforeBlacklist)].GetSize() > 0)
			cgProfile.SetWhiteListBeforeBlackList(Toolkit::AsBool(attrMap[attrNameAsString(OutgoingWhitelistBeforeBlacklist)][0]));
		if (attrMap[attrNameAsString(MinimumPrefixLength)].GetSize() > 0)
			cgProfile.SetMinPrefixLen(attrMap[attrNameAsString(MinimumPrefixLength)][0].AsInteger());
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
		} else if (values[0] == GK_EP_TYPE_GATEKEEPER) {
			PTRACE(5, "Call comes from a GK"); // should this ever happen?
			isCPE=FALSE;
		} else {
			PTRACE(5, "Call comes from a CPE");
			isCPE = TRUE;
		}
	}
        return isCPE;
}

BOOL GkDatabase::isGK(PString &h323id, dctn::DBTypeEnum & dbType)
{
	BOOL isGK = FALSE;
	PStringList values;
	using namespace dctn;
	if (getAttribute(h323id, EPType, values, dbType)
			&& values.GetSize() > 0) {
		if (values[0] == GK_EP_TYPE_GATEKEEPER) {
			PTRACE(5, "Is a gatekeeper");
			isGK = TRUE;
		}
	}
        return isGK;
}


PString GkDatabase::attrNameAsString(const dctn::DBAttributeNamesEnum &attr_name) {
	using namespace dctn;
	ReadLock lock(AN_mutex);
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
				BOOL found=FALSE;
				// check if alias exists in telephoneNumber attributes from database entry
				for (PINDEX j = 0; j < telephoneNumbers.GetSize() && !found ; j++) {
					if(aliasStr == rmInvalidCharsFromTelNo(telephoneNumbers[j])) {
						found=TRUE;
					}
				}
				if (!found)
					return FALSE; // Not in list.
			}
		}
		return TRUE;
	}
	return FALSE;
}

BOOL GkDatabase::getAttribute(const PString &alias, const dctn::DBAttributeNamesEnum attr_name, PStringList &attr_values,
		dctn::DBTypeEnum & dbType)
{
	ReadLock lock(m_usedLock);
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
	ReadLock lock(m_usedLock);
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
			   BOOL & matchFound, BOOL & fullMatch, BOOL & gwFound, dctn::DBTypeEnum & dbType, CalledProfile & calledProfile)
{
	ReadLock lock(m_usedLock);
	dbType = dctn::e_TypeUnknown;
	BOOL fullMatchOld = FALSE;
	BOOL gwFoundOld = FALSE;
	fullMatch = FALSE;
	gwFound = FALSE;
	matchFound = FALSE;
	for (PINDEX i=0; i < m_dbList.GetSize(); i++) {
		// if prefixMatch succeeds
		if (m_dbList[i].prefixMatch(alias, attr_name, matchFound, fullMatch, gwFound, calledProfile)) {
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

void
GkDatabase::flush_cache()
{
	for (PINDEX i=0; i < m_dbList.GetSize(); i++) {
		m_dbList[i].flush_cache();
	}
}
