// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2001 Dr.-Ing. Martin Froehlich <Martin.Froehlich@mediaWays.net>
//
// PURPOSE OF THIS FILE:
//   Realizes the LDAP search functions based on the RFC 1823 LDAP-API
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

#include "ldaplink.h"		// First of includes: own interface
#include "Toolkit.h"

#ifndef lint
// mark object with version info in such a way that it is retreivable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = LDAPLINK_H;
#endif /* lint */

/* This is the place to include standardized headers */
#if (defined(__cplusplus) && defined(USE_ISO_HEADERS))
#  include <cstdlib>            // ISO C++: C standard library
using namespace std;            // <--- NOTE!
#else /* either not C++ or the ISO headers shouldn't be used*/
#  include <stdlib.h>           /* ANSI C: C standard library */
#endif /* use of header type resolved */

#include <math.h>		/* ANSI C: C math library */
#include "GkStatus.h"		// gatekeeper status port for error handling
#include <ptlib.h>		// the PWlib
#if defined(HAS_MWBB1)
#  include <bb1.h>		// LDAP coding
#endif

// simplified output
#if !defined(LDAP_DBG_LVL)
#  define LDAP_DBG_LVL 2
#endif
#if !defined(LDAP_DBG_LINEEND)
#  if defined(WIN32)
#    define LDAP_DBG_LINEEND "\r\n"
#  else
#    define LDAP_DBG_LINEEND "\n"
#  endif
#endif
// NOTE: Do not use the ldap_perror function! This environment provides its
//       own error handling:
#define ERRORPRINT(strpar) GkStatus::Instance()->                    \
                           SignalStatus(PString(strpar) + LDAP_DBG_LINEEND)
#define DEBUGPRINT(stream) PTRACE(LDAP_DBG_LVL, "GK\t" << stream)


// CLASS: LDAPAnswer

LDAPAnswer::LDAPAnswer():
	status(LDAP_SUCCESS)
{
	// this space left blank intentionally
}

LDAPAnswer::~LDAPAnswer()
{
	// this space left blank intentionally
}

/*
bool
LDAPAnswer::complete(void)
{
	bool result = true;
	// FIXME: this is just stub at the moment;
	return result;
}
*/
// CLASS: LDAPCtrl

LDAPCtrl::LDAPCtrl(DBAttributeNamesClass * AttrNames,
		   struct timeval default_timeout,
		   PString & ServerName,
		   PString & SearchBaseDN,
		   PString & BindUserDN,
		   PString & BindUserPW,
		   unsigned int sizelimit = LDAP_NO_LIMIT,
		   unsigned int timelimit = LDAP_NO_LIMIT,
		   int ServerPort = LDAP_PORT):
	AttributeNames(AttrNames), timeout(default_timeout), ServerName(ServerName),
	ServerPort(ServerPort), SearchBaseDN(SearchBaseDN), BindUserDN(BindUserDN),
	BindUserPW(BindUserPW), sizelimit(sizelimit), timelimit(timelimit),
	ldap(NULL), known_to_be_bound(false)
{
	Initialize();
	if(LDAP_SUCCESS != Bind(true)) { // bind (enforced)
		ERRORPRINT("LDAPCtrl: can not access LDAP, destroying object");
		Destroy();
	}
} // constructor: LDAPCtrl


LDAPCtrl::~LDAPCtrl()
{
	PWaitAndSignal lock(m_readLock);
	Destroy();
} // destructor: LDAPCtrl


// binding, may be enforced by passing true
int
LDAPCtrl::Bind(bool force = false)
{
	if(m_bindLock.WillBlock()){
		PTRACE(1, "Will not Bind, because I'm blocked with Mutex: " );
		known_to_be_bound=false;
		return LDAP_UNAVAILABLE;
	}
	PWaitAndSignal lock(m_bindLock);
	int ldap_ret = LDAP_SUCCESS;
	if(known_to_be_bound && force)
		DEBUGPRINT("Bind: I think I'm already bound, but action is forced");

	if(!known_to_be_bound || force) {
		// this is the local bind version
		DEBUGPRINT("Binding with " << BindUserDN << "pw length:"
			   << BindUserPW.GetLength());
		if(NULL==ldap) Initialize();
		if (LDAP_SUCCESS ==
		    (ldap_ret = gk_ldap_simple_bind_s(ldap, BindUserDN, BindUserPW))) {
			known_to_be_bound = true;
			DEBUGPRINT("LDAPCtrl::Bind: OK bound");
		} else {
			ERRORPRINT("LDAPCtrl::Bind: " +
				   PString(gk_ldap_err2string(ldap_ret)));
			gk_ldap_unbind(ldap);
			//delete ldap;
			ldap=NULL;
		}
	}
	return ldap_ret;
}

// unbinding, may be enforced by passing true
int
LDAPCtrl::Unbind(bool force = false)
{
	if(m_bindLock.WillBlock()) {
		PTRACE(1, "Will not unbind because Blocked Thread by Mutex");
		return LDAP_UNAVAILABLE;
	}
	PWaitAndSignal lock(m_bindLock);
	int ldap_ret = LDAP_SUCCESS;

	if(!known_to_be_bound && force)
		DEBUGPRINT("Unbind: I think I'm already unbound, but action is forced");

	if((NULL != ldap) && (known_to_be_bound || force))
		if(LDAP_SUCCESS != (ldap_ret = gk_ldap_unbind(ldap))) {
			ERRORPRINT("Unbind: couldn't unbind: "
				   + PString(gk_ldap_err2string(ldap_ret)));
		} else {
			known_to_be_bound = false;
		}

	ldap = NULL; // ldap is no longer valid.

	return ldap_ret;
}

// privat: initializer called from constructors
void
LDAPCtrl::Initialize(void)
{
	if(m_bindLock.WillBlock()){
		PTRACE(1, "Will not Initialize, because I'm blocked with Mutex: " );
		known_to_be_bound=false;
		ldap = NULL;
		return;
	}
	PWaitAndSignal lock(m_bindLock);
	// get ldap c-object
	GK_LDAP * ld = NULL;
	if (NULL == (ld = gk_ldap_init(ServerName, ServerPort))) {
		DEBUGPRINT("Initialize: no connection on " <<
			   ServerName << ":(" << ServerPort << ")" <<
			   endl << vcid << endl << vcHid);
		ERRORPRINT(PString("LDAPCtrl::Initialize: no connection on ") +
			   static_cast<PString>(ServerName) + static_cast<PString>(":(") + static_cast<PString>(ServerPort) + static_cast<PString>(")"));
		ldap = NULL;
	} else {
		DEBUGPRINT("LDAPCtrl::Initialize: connection OK on " <<
			   ServerName << ":(" << ServerPort << ")");
		ldap = ld;
	}
	gk_filter.SetSize(0);
        gk_filter = GkConfig()->GetString("GkLDAP::Settings", "Filter", "");

#if (((LDAP_API_VERSION >= 2004) && defined(LDAP_API_FEATURE_X_OPENLDAP)) || \
 defined (HAS_LEVEL_TWO_LDAPAPI)) || defined(HAS_OPENH323_LDAPAPI)
	// OpenLDAP API 2000+draft revision provides better controlled access
	int opt_ret = LDAP_OPT_SUCCESS;
	if(LDAP_OPT_SUCCESS !=
	   (opt_ret = gk_ldap_set_option(ldap, LDAP_OPT_TIMELIMIT, (void*)&timelimit))) {
		DEBUGPRINT("ldap_set_option: Couln't set timelimit");
		ERRORPRINT("ldap_set_option: Couln't set timelimit");
	}
	if(LDAP_OPT_SUCCESS !=
	   (opt_ret = gk_ldap_set_option(ldap, LDAP_OPT_SIZELIMIT, (void*)&sizelimit))) {
		DEBUGPRINT("ldap_set_option: Couln't set sizelimit");
		ERRORPRINT("ldap_set_option: Couln't set sizelimit");
	}
#else /* LDAP_API_VERSION */
	// strictly RFC1823
	ldap->ld_timelimit = (int)timelimit;
	ldap->ld_sizelimit = (int)sizelimit;
#endif /* LDAP_API_VERSION */


} // privat: Initialize


void
LDAPCtrl::Destroy(void)
{
	Unbind();
}



// searching for user
LDAPAnswer *
LDAPCtrl::DirectoryUserLookup(const PString &alias)
{
	LDAPAnswer * result = NULL;
	LDAPQuery q;
	PStringList values;
	using namespace dctn;

	DEBUGPRINT("DirectoryUserLookup for User: " << alias);
	values.AppendString(alias);
	// assemble the search.
	AttributeNames_mutex.StartRead();
	q.DBAttributeValues.insert(DBAVValuePair((*AttributeNames)[DBAttrTags[H323ID]],values));
	AttributeNames_mutex.EndRead();
	q.LDAPOperator=LDAPQuery::LDAPNONE;

	// search until found or out of retries
	result = DirectoryLookup(q);

	return result;
}

// searching for user
LDAPAnswer *
LDAPCtrl::DirectoryLookup(LDAPQuery &q)
{
	PStringList attrs;
	using namespace dctn;
	AttributeNames_mutex.StartRead();
	DBAttributeNamesClass::iterator iter = AttributeNames->begin();
	while(iter != AttributeNames->end()) {
		attrs.AppendString((*iter).second);
		iter++;
	}
	AttributeNames_mutex.EndRead();
	BaseDN_mutex.StartRead();
	PString DN=SearchBaseDN;
	BaseDN_mutex.EndRead();
	LDAPAnswer * answer=collectAttributes(q, attrs, DN);
#ifdef ENCRYPTED_PASSWORD
	for(LDAPEntryClass::iterator iter = answer->LDAPec.begin(); iter!=answer->LDAPec.end(); iter++) {
		LDAPAttributeValueClass AV=iter->second;
	// Decode The Password.
		PStringList & pwlist = AV[LDAPAttrTags[H235PassWord]];
		PINDEX pwlistsize = pwlist.GetSize();
		for(PINDEX i = 0; i <= pwlistsize; i++) { // i, for all answers
			PString & pw = pwlist[i];
			PTPW_Codec::codec_kind algo = PTPW_Codec::GetAlgo(pw); // which algorithm
			pw.Delete(0,strlen(PTPW_Codec::GetId(algo))-1); // remove the header
			PTPW_Codec codec(algo, PTPW_Codec::CT_DECODE); // setup codec
			codec.cipher(pw); // do the crypto stuff
		} // i, for all answers
	}
#endif
	return answer;
}

LDAPAnswer *
LDAPCtrl::collectAttributes(LDAPQuery &q, PStringList &attrs, PString &DN, unsigned int scope) {
	LDAPAnswer *query=InternalcollectAttributes(q, attrs, DN, scope);
	if (query->status!=LDAP_SUCCESS) {
		delete query;
		return NULL; // emergency exit
	}
	if (query->LDAPec.empty())
		return query;
	for (map<PString, DBAttributeValueClass>::iterator iter=query->LDAPec.begin();
	     iter!=query->LDAPec.end();
	     iter++) {
		PStringList attribute_remainder;
		PString ODN=iter->first;
		for(PINDEX index=0; index<attrs.GetSize(); index++) {
			LDAPEntryClass::iterator current=iter;
			if(0==((*current).second.count(attrs[index])))
				attribute_remainder.AppendString(attrs[index]+" ");
		}
		PString DN=ODN(ODN.Find(",")+1,ODN.GetSize()); // delete first part of DN.
		PTRACE(5, "looking for: " << attribute_remainder << "in " << DN);
		LDAPQuery new_query;
		new_query.LDAPOperator=LDAPQuery::LDAPNONE;
		LDAPAnswer *subquery=collectAttributes(new_query, attribute_remainder, DN, LDAP_SCOPE_BASE);
		// insert subquery to query
		if(NULL!=subquery) {
			for(PINDEX j=0; j<attribute_remainder.GetSize();j++) {
				PTRACE(1, "Inserting: " << attribute_remainder[j] << ":" <<
				       subquery->LDAPec[DN][attribute_remainder[j]] <<
				       " into " << iter->first);
				iter->second.insert(DBAVValuePair(attribute_remainder[j],
									 subquery->LDAPec[DN][attribute_remainder[j]]));
			}
			delete subquery;
		}
	}
	return query;
}

LDAPAnswer *
LDAPCtrl::InternalcollectAttributes(LDAPQuery &p, PStringList &want_attrs, PString &DN, unsigned int scope) {
	LDAPAnswer * result = new LDAPAnswer;
	int ldap_ret = LDAP_SUCCESS;
	LDAPMessage * res;		/* response */

	// basic search
	using namespace dctn;
	const char * (attrs[MAX_ATTR_NO]);
	PINDEX pos = 0;
	for (pos=0; pos<want_attrs.GetSize(); pos++){
		attrs[pos]=(const char *)(want_attrs[pos]);
	}
 	attrs[want_attrs.GetSize()] = NULL;	// C construct: array of unknown size
 				// terminated by NULL-pointer

	int attrsonly = 0;	/* 0: attr&value; 1: attr */
	PString filter;

	switch(p.LDAPOperator) {
	case (LDAPQuery::LDAPand):
		filter="(&";
		break;
	case (LDAPQuery::LDAPor):
		filter="(|";
		break;
	case (LDAPQuery::LDAPnot):
		filter="(!";
	case (LDAPQuery::LDAPNONE):
		filter="";
	}
	for(DBAttributeValueClass::iterator iter=p.DBAttributeValues.begin();
	    iter!=p.DBAttributeValues.end();
	    iter++) {
		PString attribute=(*iter).first;
		for (PINDEX index=0; index<(*iter).second.GetSize(); index++) {
			filter+="(";
			filter+=attribute;
			filter+="=";
			filter+=(*iter).second[index];
			filter+=")";
		}
	}
	if(p.LDAPOperator!=LDAPQuery::LDAPNONE)
		filter+=")";

 	if (!gk_filter.IsEmpty())
 		filter="(&(" + gk_filter + ")" + (( !filter.IsEmpty() ) ? ("(" + filter + "))") : PString(")")) ;

	unsigned int retry_count = 0;
	do {
		struct timeval * tm = new struct timeval;
		m_miscLock.Wait();
		memcpy(tm, &timeout, sizeof(struct timeval));
		m_miscLock.Signal();
		DEBUGPRINT("ldap_search_st(" << SearchBaseDN << ", " << filter << ", "
			   << timeout.tv_sec << ":"
			   << timeout.tv_usec << ")");

		// The linux-implementation of select(2) will change the given value of
		// struct timeval *. This syscall is used within ldap_search.
		m_readLock.Wait();
		if (LDAP_SUCCESS ==
		    (ldap_ret = gk_ldap_search_st(ldap, DN, scope,
						  filter, (char **)attrs, attrsonly,
						  tm, &res))) {
			m_readLock.Signal();
			DEBUGPRINT("ldap_search_st: OK " << PString(gk_ldap_err2string(ldap_ret)));
		} else {
			m_readLock.Signal();
			gk_ldap_msgfree(res);
			DEBUGPRINT("ldap_search_st: " + PString(gk_ldap_err2string(ldap_ret)));
			//ERRORPRINT("ldap_search_st: " + PString(gk_ldap_err2string(ldap_ret)));
			result->status = ldap_ret;
			if(LDAP_UNAVAILABLE == ldap_ret) known_to_be_bound = false;
			retry_count++;
			if(retry_count>4)
				PTRACE(1, "Ooops -- retry_count reached");
			sleep(static_cast<int>(pow(static_cast<float>(2.0),static_cast<int>(retry_count)))); // exponential back off
			Destroy();
			if(LDAP_SUCCESS!=Bind())
				PTRACE(1,"Could not bind!");
		}
		delete tm;
	} while((LDAP_SUCCESS != ldap_ret)&&(retry_count < 4));

	if(retry_count>=4) {
		result->status=ldap_ret;
		PTRACE(1, "didn't get LDAP-Answer.");
		return result;
	}
	result->status = ldap_ret;
	// analyze answer
	if (0 > (ldap_ret = gk_ldap_count_entries(ldap, res))) {
		ERRORPRINT("ldap_search_st: " + PString(gk_ldap_err2string(ldap_ret)));
		result->status = ldap_ret;
		return result;
	} else {
		DEBUGPRINT("ldap_search: " << ldap_ret << " results");
	}
	LDAPMessage * chain;		// iterate throught chain of answers
	for(chain = gk_ldap_first_entry(ldap, res);
	    chain != NULL;		// NULL terminated
	    chain = gk_ldap_next_entry(ldap, chain)) {
		char * dn = NULL;
		if(NULL == (dn = gk_ldap_get_dn(ldap, chain))) {
			ERRORPRINT("ldap_get_dn: Could not get distinguished name.");
		}
		DEBUGPRINT("found DN: " << dn);
		DBAttributeValueClass AV;
		// treating the dn as a kind of attribute
		BerElement * ber = NULL;	// a 'void *' would do the same but RFC 1823
		// indicates it to be a pointer to a BerElement
		char * attr = NULL;		// iterate throught list of attributes
		for(attr = gk_ldap_first_attribute(ldap, chain, &ber);
		    attr != NULL;		// NULL terminated
		    attr = gk_ldap_next_attribute(ldap, chain, ber)) {
			char ** valv = gk_ldap_get_values(ldap, chain, attr); // vector
			int valc = gk_ldap_count_values(valv); // count
			if(0 == valc) DEBUGPRINT("value handling: No values returned");
			// put list of values (of this partyicular attribute) into PStringList
			// which can be accessed by a STL map, indexed by attribute names.
			// This implies that the data is not bit- or octet-string,
			// because it may NOT contain \0.
			AV.insert(DBAVValuePair(PString(attr),
						  PStringList(valc, valv, false)));
			gk_ldap_value_free(valv);	// remove value vector
			gk_ldap_memfree(attr); // remove attr
		} // attr
		gk_ber_free(ber,0);
  		PString out="AV=";
  		for (std::map<PString,PStringList>::iterator Iter=AV.begin();Iter!=AV.end(); Iter++)
  			out += (*Iter).first + ":" + (*Iter).second[0] + " ";
  		PTRACE(1, out);
		if(!AV.empty())
			result->LDAPec.insert(LDAPECValuePair(dn,AV));
		gk_ldap_memfree(dn);
	} // answer chain
	gk_ldap_msgfree(res);
	return result;
}

void
LDAPCtrl::flush_cache()
{
	gk_ldap_cache_delete(ldap,0,0); // delete old cache
}

//
// End of ldaplink.cxx
//
