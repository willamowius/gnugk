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

#include "gkldap.h"

// init file section name
const char *ldap_attr_name_sec = "GkLDAP::LDAPAttributeNames";
const char *ldap_auth_sec = "GkLDAP::Settings";

// constructor
GkLDAP::GkLDAP()
{
  LDAPConn=NULL;
  //Initialisation must be done with method "Initialize"!
} // GkLDAP constructor

// destructor
GkLDAP::~GkLDAP()
{
  Destroy();
} // GkLDAP destructor

void GkLDAP::Initialize(PConfig &cfg) // 'real', private constructor
{
  if(NULL!=LDAPConn)
    return;
  struct timeval default_timeout;
  default_timeout.tv_sec = 10l;	// seconds
  default_timeout.tv_usec = 0l;	// micro seconds
  using namespace lctn;		// LDAP config tags and names
  // The defaults are given by the constructor of LDAPAttributeNamesClass
  AN.insert(LDAPANValuePair(LDAPAttrTags[H323ID],
 		            cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[H323ID],
					      "mail"))); // 0.9.2342.19200300.100.1.3
  AN.insert(LDAPANValuePair(LDAPAttrTags[TelephonNo],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[TelephonNo],
					      "telephoneNumber"))); // 2.5.4.20
  AN.insert(LDAPANValuePair(LDAPAttrTags[H245PassWord],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[H245PassWord],
					      "plaintextPassword")));	// 1.3.6.1.4.1.9564.2.1.1.8
  AN.insert(LDAPANValuePair(LDAPAttrTags[IPAddress],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[IPAddress],
					      "voIPIpAddress"))); // ...9564.2.5.2010
  AN.insert(LDAPANValuePair(LDAPAttrTags[SubscriberNo],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[SubscriberNo],
					      "voIPsubscriberNumber"))); // ...2050
  AN.insert(LDAPANValuePair(LDAPAttrTags[LocalAccessCode],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[LocalAccessCode],
					      "voIPlocalAccessCode"))); // ...2020
  AN.insert(LDAPANValuePair(LDAPAttrTags[NationalAccessCode],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[NationalAccessCode],
					      // ...9564.2.5.2030
					      "voIPnationalAccessCode"))); // ...2030
  AN.insert(LDAPANValuePair(LDAPAttrTags[InternationalAccessCode],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[InternationalAccessCode],
					       // ...9564.2.5.2040
					      "voIPinternationalAccessCode"))); // ...2040
  AN.insert(LDAPANValuePair(LDAPAttrTags[CallingLineIdRestriction],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[CallingLineIdRestriction],
					      "voIPcallingLineIdRestriction"))); // ...2060
  AN.insert(LDAPANValuePair(LDAPAttrTags[SpecialDial],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[SpecialDial],
					      "voIPspecialDial"))); // ...2070
  AN.insert(LDAPANValuePair(LDAPAttrTags[PrefixBlacklist],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[PrefixBlacklist],
					      "voIPprefixBlacklist"))); // ...2070
  AN.insert(LDAPANValuePair(LDAPAttrTags[PrefixWhitelist],
			    cfg.GetString(ldap_attr_name_sec, 
					      LDAPAttrTags[PrefixWhitelist],
					      "voIPprefixWhitelist"))); // ...2090

  PString ServerName = cfg.GetString(ldap_auth_sec, "ServerName", "ldap");
  int ServerPort = cfg.GetString(ldap_auth_sec, "ServerPort", "389").AsInteger();
  PString SearchBaseDN = cfg.GetString(ldap_auth_sec, "SearchBaseDN", 
					   "o=University of Michigan, c=US");
  PString BindUserDN = cfg.GetString(ldap_auth_sec, "BindUserDN", 
					 "cn=Babs Jensen,o=University of Michigan, c=US");
  PString BindUserPW = cfg.GetString(ldap_auth_sec, "BindUserPW", "RealySecretPassword");
  unsigned int sizelimit = cfg.GetString(ldap_auth_sec, "sizelimit", "0").AsUnsigned();
  unsigned int timelimit = cfg.GetString(ldap_auth_sec, "timelimit", "0").AsUnsigned();

  LDAPConn = new LDAPCtrl(&AN, default_timeout, ServerName, 
			  SearchBaseDN, BindUserDN, BindUserPW, 
			  sizelimit, timelimit, ServerPort);
} // Initialize

void GkLDAP::Destroy()		// 'real', private destructor
{
  delete LDAPConn;
} // Destroy

PString GkLDAP::convertE123ToDialedDigits(PString e123) {
  e123.Replace("+","");
  // remove all whitespaces
  e123.Replace(" ","", TRUE);
  // remove all "."
  e123.Replace(".","", TRUE);
  return e123;
}

bool GkLDAP::getAttribute(const PString &alias, const int attr_name, 
                           PStringList &attr_values){
  PWaitAndSignal lock(m_usedLock);
  LDAPAnswer *answer = LDAPConn->DirectoryUserLookup(alias);
  // if LDAP succeeds
  if(answer->status == 0){
    using namespace lctn;
    if (answer->LDAPec.size()){
      LDAPEntryClass::iterator pFirstDN = answer->LDAPec.begin();
      if((pFirstDN->second).count(AN[LDAPAttrTags[attr_name]])){
	attr_values = (pFirstDN->second)[AN[LDAPAttrTags[attr_name]]];
      }
    }
  }
  return (answer->status == 0) ? true : false;
}

bool GkLDAP::validAliases(const H225_ArrayOf_AliasAddress & aliases) {
  PString aliasStr;
  bool found = 0;
  // search H323ID in aliases
  for (PINDEX i = 0; i < aliases.GetSize() && !found; i++) {
    if (aliases[i].GetTag() == H225_AliasAddress::e_h323_ID) {
      aliasStr = H323GetAliasAddressString(aliases[i]);
      found = 1;
    }
  }
  if(!found) return false;
  PStringList telephoneNumbers;
  // get telephone numbers from LDAP for H323ID
  using namespace lctn;		// LDAP config tags and names
  if(getAttribute(aliasStr, TelephonNo, telephoneNumbers)) {
    // for each alias == dialedDigits
    for (PINDEX i = 0; i < aliases.GetSize(); i++) { 
      if (aliases[i].GetTag() == H225_AliasAddress::e_dialedDigits) {
        aliasStr = H323GetAliasAddressString(aliases[i]);
        // check if alias exists in telephoneNumbers from LDAP entry
        for (PINDEX j = 0; j < telephoneNumbers.GetSize(); j++) {
          if(aliasStr != convertE123ToDialedDigits(telephoneNumbers[j])) {
            return false;
          }
        }
      }
    }
    return true;
  }
  return false;
}

#endif // HAS_LDAP
