// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// gkldap.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//      2002/01/28      initial version (Markus Muehlenbernd)
//
//////////////////////////////////////////////////////////////////


// LDAP authentification
#if defined(HAS_LDAP)

#include "gkDatabase.h"
#include "Toolkit.h"
#include "gkldap.h"
#include "ldaplink.h"		// link to LDAP functions
#include "h225.h"
#include "h323pdu.h"
#include "ANSI.h"

const char *LDAP_SETTINGS_SEC = "GkLDAP::Settings";

GkLDAP::GkLDAP(PConfig &cfg, DBAttributeNamesClass & attrNames)
{
	AN = attrNames;
	LDAPConn=NULL;
	struct timeval default_timeout;
	default_timeout.tv_sec = 10l;	// seconds
	default_timeout.tv_usec = 0l;	// micro seconds

	PString ServerName = cfg.GetString(LDAP_SETTINGS_SEC, "ServerName", "ldap");
	int ServerPort = cfg.GetString(LDAP_SETTINGS_SEC, "ServerPort", "389").AsInteger();
	PString SearchBaseDN = cfg.GetString(LDAP_SETTINGS_SEC, "SearchBaseDN",
					   "o=University of Michigan, c=US");
	PString BindUserDN = cfg.GetString(LDAP_SETTINGS_SEC, "BindUserDN",
					 "cn=Babs Jensen,o=University of Michigan, c=US");
	PString BindUserPW = cfg.GetString(LDAP_SETTINGS_SEC, "BindUserPW", "RealySecretPassword");
	unsigned int sizelimit = cfg.GetString(LDAP_SETTINGS_SEC, "sizelimit", "0").AsUnsigned();
	unsigned int timelimit = cfg.GetString(LDAP_SETTINGS_SEC, "timelimit", "0").AsUnsigned();

	LDAPConn = new LDAPCtrl(&AN, default_timeout, ServerName,
			  SearchBaseDN, BindUserDN, BindUserPW,
			  sizelimit, timelimit, ServerPort);
}

GkLDAP::~GkLDAP()
{
	delete LDAPConn;
	LDAPConn=NULL;
}

BOOL GkLDAP::getAttribute(const PString &alias, const dctn::DBAttributeNamesEnum attr_name,
                           PStringList &attr_values)
{
	BOOL found = FALSE;
	LDAPAnswer *answer = LDAPConn->DirectoryUserLookup(alias);
	// if LDAP succeeds
	if((NULL!=answer) && (answer->status == 0)){
		if (answer->LDAPec.size()){
			PString attrNameStr = GkDatabase::Instance()->attrNameAsString(attr_name);
			LDAPEntryClass::iterator pFirstDN = answer->LDAPec.begin();
			if((pFirstDN->second).count(attrNameStr)){
				found = TRUE;
				attr_values = (pFirstDN->second)[attrNameStr];
			}
		}
	}
	return found;
}

BOOL GkLDAP::getAttributes(const PString &alias, DBAttributeValueClass &attr_map)
{
        LDAPAnswer *answer = LDAPConn->DirectoryUserLookup(alias);
        if ((NULL!=answer) && (answer->status == 0) && (answer->LDAPec.size() == 1)) {
        // LDAP succeeds and exactly 1 match
                LDAPEntryClass::iterator pFirstDN = answer->LDAPec.begin();
                attr_map =  pFirstDN->second;
                return TRUE;
        } else {
        // not 1 match
                return FALSE;
        }
}

BOOL GkLDAP::prefixMatch(const H225_AliasAddress & alias, const dctn::DBAttributeNamesEnum attr_name, BOOL & matchFound,
			 BOOL & fullMatch, BOOL & gwFound, CalledProfile & calledProfile)
{
	PString aliasStr = H323GetAliasAddressString(alias);
	PString attrNameStr = GkDatabase::Instance()->attrNameAsString(attr_name);
	BOOL partialMatch = (matchFound && !fullMatch && !gwFound);
	LDAPQuery query;
	query.LDAPOperator = LDAPQuery::LDAPNONE;
	PStringList searchPattern;
	// { nilsb
	searchPattern.AppendString(aliasStr + "*");
	if(alias.GetTag()==H225_AliasAddress::e_dialedDigits) {
		E164_AnalysedNumber e164_alias(aliasStr);
		if(e164_alias.GetIPTN_kind()!=E164_AnalysedNumber::IPTN_unknown) {
			unsigned int len=e164_alias.GetGSN_SN().GetValue().GetLength();
			if(len!=0) {
				query.LDAPOperator = LDAPQuery::LDAPor;
				PString substr = aliasStr;
				for (PINDEX j=1; j<len+1;j++) {
					substr[substr.GetLength()-j]='.';
					searchPattern.AppendString(substr + "*");
				}
			}
		}
	}
	// nilsb }
	query.DBAttributeValues[attrNameStr] = searchPattern;
	LDAPAnswer *answer = LDAPConn->DirectoryLookup(query);
	//LDAPAnswer *answer = LDAPConn->collectAttributes(query);
	// if LDAP succeeds and an entry has been found
	if(answer->status == 0 && answer->LDAPec.size()){
		// check for full/partial match
		// for each DN
		LDAPEntryClass::iterator iterDN = answer->LDAPec.begin();
		for(; iterDN != answer->LDAPec.end() && !partialMatch; iterDN++){
			DBAttributeValueClass::iterator iterAttr = (iterDN->second).begin();
			// for each attribute
			for(; iterAttr != (iterDN->second).end() && !partialMatch; iterAttr++) {
				if (iterAttr->first == attrNameStr) {
					// for each value
					for(PINDEX i=0; i < (iterAttr->second).GetSize() && !fullMatch; i++) {
						PString telno(GkDatabase::Instance()->rmInvalidCharsFromTelNo((iterAttr->second)[i]));
						// if dialed number equals LDAP entry
						if (aliasStr == telno) {
							gwFound = FALSE;
							fullMatch = TRUE;
							PTRACE(2, ANSI::DBG << "TelephoneNo "
							  << alias << " matches endpoint "
							  << iterDN->first
							  << " (full)" << ANSI::OFF);
							using namespace dctn;
							DBAttributeValueClass::iterator h323id = (iterDN->second).find(PString(PString(GkDatabase::Instance()->attrNameAsString(H323ID))));
							DBTypeEnum d;
							PString h = h323id->second[0];
							calledProfile.SetIsGK(GkDatabase::Instance()->isGK(h323id->second[0],d));
						// if no full match is found up to now and
						// LDAP entry is prefix of dialed number
						} else if (!fullMatch && telno == aliasStr.Left(telno.GetLength())) {
							gwFound = TRUE;
							PTRACE(2, ANSI::DBG << "TelephoneNo "
							  << alias << " matches endpoint "
							  << iterDN->first
							  << " (gateway found)" << ANSI::OFF);
							if(!calledProfile.IsGK()) {
								using namespace dctn;
								DBAttributeValueClass::iterator h323id = (iterDN->second).find(PString(PString(GkDatabase::Instance()->attrNameAsString(H323ID))));
								DBTypeEnum d;
								PString h = h323id->second[0];
								calledProfile.SetIsGK(GkDatabase::Instance()->isGK(h323id->second[0],d));
							}
						// dialed number is prefix of LDAP entry
						} else {
							gwFound = FALSE;
							fullMatch = FALSE;
							partialMatch = TRUE;
							PTRACE(2, ANSI::DBG << "TelephoneNo "
							  << alias << " matches endpoint "
							       << iterDN->first
							  << " (partial)" << ANSI::OFF);
						}
					}
				}
			}
		}
	}
	matchFound = (fullMatch || partialMatch || gwFound);
	return (answer->status == 0) ? TRUE : FALSE;
}

dctn::DBTypeEnum GkLDAP::dbType()
{
	return dctn::e_LDAP;
}

#endif // HAS_LDAP
