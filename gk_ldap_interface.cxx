// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2001 Nils Bokermann <Nils.Bokermann@mediaWays.net>
//
// PURPOSE OF THIS FILE: Define the non-opaque part to the LDAP-C-API
//
// - Automatic Version Information via RCS:
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


#include <ptlib.h>
#include "gk_ldap_interface.h"
#include "Toolkit.h"

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = GK_LDAP_H;
#endif /* lint */


GK_LDAP *gk_ldap_init (const char *hostname, int portno) {
	GK_LDAP *ld=new GK_LDAP();
	if (NULL==ld)
		return NULL;
	ld->ld=ldap_init(hostname,portno);
	if (NULL==ld->ld){
		delete ld;
		return NULL;
	}
	return ld;
}

GK_LDAP *gk_ldap_open (const char *hostname, int portno) {
	GK_LDAP *ld=new GK_LDAP();
	if (NULL==ld)
		return NULL;
	ld->ld=ldap_open(hostname,portno);
	if (NULL==ld->ld){
		delete ld;
		return NULL;
	}
	return ld;
}

int gk_ldap_sasl_bind (GK_LDAP *ld,  char const *dn, char const *mechanism,
		       struct berval const *cred, LDAPControl **serverctrls,
		       LDAPControl **clientctrls, int *msgidp) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#if (LDAP_VERSION_MAX < LDAP_VERSION3)
	return LDAP_PROTOCOL_ERROR;
#else
	gk_ldap_cache_enable(ld->ld, CACHE_TIMEOUT, CACHE_MAXMEM);
	return ldap_sasl_bind(ld->ld, dn, mechanism, cred, serverctrls, clientctrls, msgidp);
#endif
}

int gk_ldap_sasl_bind_s (GK_LDAP *ld,  char *dn, char const *mechanism,
			 struct berval const *cred, LDAPControl **serverctrls,
			 LDAPControl **clientctrls, struct berval **servercredp) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#if (LDAP_VERSION_MAX < LDAP_VERSION3)
	return LDAP_PROTOCOL_ERROR;
#else
	gk_ldap_cache_enable(ld->ld, CACHE_TIMEOUT, CACHE_MAXMEM);
	return ldap_sasl_bind_s(ld->ld, dn, mechanism, cred, serverctrls, clientctrls, servercredp);
#endif
}

int gk_ldap_simple_bind (GK_LDAP *ld,  char const *dn, char const *passwd) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	gk_ldap_cache_enable(ld, CACHE_TIMEOUT, CACHE_MAXMEM);
	return ldap_simple_bind(ld->ld, dn, passwd);
}

int gk_ldap_simple_bind_s (GK_LDAP *ld,  char const *dn, char const *passwd) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	gk_ldap_cache_enable(ld, CACHE_TIMEOUT, CACHE_MAXMEM);
	return ldap_simple_bind_s(ld->ld, dn, passwd);
}

int gk_ldap_bind (GK_LDAP *ld,  char const *dn, char const *cred, int method) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	gk_ldap_cache_enable(ld, CACHE_TIMEOUT, CACHE_MAXMEM);
	return ldap_bind(ld->ld, dn, cred, method);
}

int gk_ldap_bind_s (GK_LDAP *ld,  char const *dn, char const *cred, int method) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	gk_ldap_cache_enable(ld, CACHE_TIMEOUT, CACHE_MAXMEM);
	return ldap_bind_s(ld->ld, dn, cred, method);
}

int gk_ldap_unbind_ext (GK_LDAP *ld, LDAPControl *serverctrls, LDAPControl *clientctrls){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#if (LDAP_VERSION_MAX < LDAP_VERSION3)
	return LDAP_PROTOCOL_ERROR;
#else
	gk_ldap_cache_delete(ld, CACHE_TIMEOUT, CACHE_MAXMEM);
	int i = ldap_unbind_ext(ld->ld, serverctrls, clientctrls);
	delete ld;
	return i;
#endif
}

int gk_ldap_unbind (GK_LDAP *ld) {
	if (NULL==ld||NULL==ld->ld)
		return LDAP_UNAVAILABLE;
	int i = ldap_unbind(ld->ld);
	delete ld;
	return i;
}

int gk_ldap_unbind_s (GK_LDAP *ld) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	int i = ldap_unbind_s(ld->ld);
	delete ld;
	return i;
}

int gk_ldap_get_option (GK_LDAP *ld, int option, void *outvalue) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_get_option(ld->ld, option, outvalue);
}

int gk_ldap_set_option (GK_LDAP *ld, int option,  void const *outvalue) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_set_option (ld->ld, option, outvalue);
}
int gk_ldap_search_ext (GK_LDAP *ld,  char const *base,
			int scope,  char const *filter, char **attrs, int attrsonly,
			LDAPControl **serverctrls, LDAPControl **clientctrls,
			struct timeval *timeout, int sizelimit, int *msgidp) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#if (LDAP_VERSION_MAX < LDAP_VERSION3)
	return LDAP_PROTOCOL_ERROR;
#else
#ifdef LDAP_PROVIDES_CACHE
	return ldap_search_ext(ld->ld, base, scope, filter, attrs, attrsonly, serverctrls, clientctrls, timeout, sizelimit, msidp);
#else
	int rv=ldap_search_ext(ld->ld, base, scope, filter, attrs, attrsonly, serverctrls, clientctrls, timeout, sizelimit, msidp);
	gk_ldap_cache_add_id(base, scope, filter, attrs, attrsonly, *msgidp);
	return rv;
#endif
#endif
}

int gk_ldap_search_ext_s (GK_LDAP *ld,  char const *base, int scope,  char const *filter,
			  char **attrs, int attrsonly, LDAPControl **serverctrls,
			  LDAPControl **clientctrls, struct timeval *timeout,
			  int sizelimit, LDAPMessage **res) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#if (LDAP_VERSION_MAX < LDAP_VERSION3)
	return LDAP_PROTOCOL_ERROR;
#else
#ifdef LDAP_PROVIDES_CACHE
	return ldap_search_ext_s(ld->ld, base, scope, filter, attrs, attrsonly, serverctrls, clientctrls, timeout, sizelimit, res);
#else
	int rv=ldap_search_ext_s(ld->ld, base, scope, filter, attrs, attrsonly, serverctrls, clientctrls, timeout, sizelimit, res);
	gk_ldap_cache_add_searchresult(ld, base, scope, filter, attrs, attrsonly, *res);
	return rv;
#endif
#endif
}

int gk_ldap_search (GK_LDAP *ld,  char const *base, int scope, char const *filter, char **attrs,
		    int attrsonly) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_search(ld->ld, base, scope, filter, attrs, attrsonly);
#else
	// lookup in cache
	int messageid;
	if((messageid=gk_ldap_cache_check(ld, base, scope, filter, attrs, attrsonly))!=-1) {
		return messageid;
	} else { // not in cache
		int rv=ldap_search(ld->ld, base, scope, filter, attrs, attrsonly);
		gk_ldap_cache_add_searchresult(ld, base, scope, filter, attrs, attrsonly, NULL);
		return rv;
	}
	return -1;
#endif
}

int gk_ldap_search_s (GK_LDAP *ld,  char const *base, int scope, char const *filter, char **attrs,
		      int attrsonly, LDAPMessage **res){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_search_s(ld->ld, base, scope, filter, attrs, attrsonly, res);
#else
	// lookup in cache
	int messageid;
	if((messageid=gk_ldap_cache_check(ld, base, scope, filter, attrs, attrsonly))!=-1) { // found it
		*res=gk_ldap_cache_get_message(ld, messageid);
		return LDAP_SUCCESS;
	} else {
		int rv=ldap_search_s(ld->ld, base, scope, filter, attrs, attrsonly, res);
		gk_ldap_cache_add_searchresult(ld, base, scope, filter, attrs, attrsonly, *res);
		return rv;
	}
	return -1;
#endif
}

int gk_ldap_search_st (GK_LDAP *ld,  char const *base, int scope, char const *filter, char **attrs,
		       int attrsonly, struct timeval *timeout, LDAPMessage **res) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_search_st(ld->ld, base, scope, filter, attrs, attrsonly, timeout, res);
#else
	// lookup in cache
	int messageid;
	if((messageid=gk_ldap_cache_check(ld, base, scope, filter, attrs, attrsonly))!=-1) { // found it
		*res=gk_ldap_cache_get_message(ld, messageid);
		return LDAP_SUCCESS;
	} else {
		int rv=ldap_search_st(ld->ld, base, scope, filter, attrs, attrsonly, timeout, res);
		gk_ldap_cache_add_searchresult(ld, base, scope, filter, attrs, attrsonly, *res);
		return rv;
	}
	return -1;
#endif
}

int gk_ldap_compare_ext (GK_LDAP *ld,  char const *dn, char const *attr,
			 struct berval const *bvalue, LDAPControl **serverctrls,
			 LDAPControl **clientctrls, int *msgidp){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_compare_ext(ld->ld, dn, attr, bvalue, serverctrls, clientctrls, msgidp);
#else
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
	return ldap_compare_ext(ld->ld, dn, attr, bvalue, serverctrls, clientctrls, msgidp);
#endif // LDAP_VERSION_MAX
	return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_compare_ext_s (GK_LDAP *ld,  char const *dn, char const *attr,
			   struct berval const *bvalue, LDAPControl **serverctrls,
			   LDAPControl **clientctrls){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_compare_ext_s(ld->ld, dn, attr, bvalue, serverctrls, clientctrls);
#else
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
	int rv=ldap_compare_ext_s(ld->ld, dn, attr, bvalue, serverctrls, clientctrls);
	// Need to put into cache.
	return rv;
#endif // LDAP_VERSION_MAX
	return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_compare (GK_LDAP *ld,  char const *dn, char const *attr, char const *value){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_compare(ld->ld, dn, attr, value);
#else
	return ldap_compare(ld->ld, dn, attr, value);
#endif
}

int gk_ldap_compare_s (GK_LDAP *ld,  char const *dn, char const *attr, char const *value) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_compare(ld->ld, dn, attr, value);
#else
	int rv=ldap_compare_s(ld->ld, dn, attr, value);
	// Need to put into cache
	return rv;
#endif
}

int gk_ldap_modify_ext (GK_LDAP *ld,  char const *dn, LDAPMod **mods, LDAPControl **serverctrls,
			LDAPControl **clientctrls, int *msgidp) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_modify_ext(ld->ld, dn, mods, serverctrls, clientctrls, msgidp);
#else
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
	// should uncache the dn.
	return ldap_modify_ext(ld->ld, dn, mods, serverctrls, clientctrls, msgidp);
#endif // LDAP_VERSION_MAX
	return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_modify_ext_s (GK_LDAP *ld, char const *dn, LDAPMod **mods,
			  LDAPControl **serverctrls, LDAPControl **clientctrls ) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_modify_ext_s(ld->ld, dn, mods, serverctrls, clientctrls);
#else
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
	// should uncache the dn.
	return ldap_modify_ext_s(ld->ld, dn, mods, serverctrls, clientctrls);
#endif
	return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_modify (GK_LDAP *ld, char const *dn, LDAPMod **mods){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_modify(ld->ld, dn, mods);
#else
	// should uncache the dn.
	return ldap_modify(ld->ld, dn, mods);
#endif
}

int gk_ldap_modify_s (GK_LDAP *ld, char const *dn, LDAPMod **mods){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_modify_s(ld->ld, dn, mods);
#else
	// should uncache the dn.
	return ldap_modify_s(ld->ld, dn, mods);
#endif
}

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
int gk_ldap_rename (GK_LDAP *ld,  char *dn,
		    char *newrdn, char *newSuperior, int deleteoldrdn,
		    LDAPControl **sctrls, LDAPControl **cctrls, int *msgidp) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_rename(ld->ld, dn, newrdn, newSuperior deleteoldrdn, sctrsl, cctrls, msgidp);
}

int gk_ldap_rename_s (GK_LDAP *ld,  char *dn, char *newrdn,
		      char *newSuperior, int deleteoldrdn, LDAPControl **sctrls,
		      LDAPControl **cctrls){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_rename_s(ld->ld, dn, newrdn, newSuperior, deleteoldrdn, sctrls, cctrls);
}
#endif

int gk_ldap_modrdn2 (GK_LDAP *ld, char const *dn, char const *newrdn, int deleteoldrdn) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	// should uncache dn
	return ldap_modrdn2(ld->ld, dn, newrdn, deleteoldrdn);
}

int gk_ldap_modrdn2_s (GK_LDAP *ld,  char const *dn, char const *newrdn, int deleteoldrdn) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	// should uncache dn
	return ldap_modrdn2_s(ld->ld, dn, newrdn, deleteoldrdn);
}

int gk_ldap_modrdn (GK_LDAP *ld,  char const *dn, char const *newrdn) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	// should uncache dn
	return ldap_modrdn(ld->ld, dn, newrdn);
}

int gk_ldap_modrdn_s (GK_LDAP *ld,  char const *dn, char const *newrdn) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	// should uncache dn
	return ldap_modrdn_s(ld->ld, dn, newrdn);
}

int gk_ldap_add_ext (GK_LDAP *ld, char const *dn, LDAPMod **attrs,
		     LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
	// should uncache dn -- negative responses
	return ldap_add_ext(ld->ld, dn, attrs, serverctrls, clientctrls, msgidp);
#else // LDAP_VERSION_MAX
	return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_add_ext_s (GK_LDAP *ld, char const *dn, LDAPMod **attrs,
		       LDAPControl **serverctrls, LDAPControl **clientctrls) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
	// should uncache dn -- negative responses
	return ldap_add_ext_s(ld->ld, dn, attrs, serverctrls, clientctrls);
#else // LDAP_VERSION_MAX
	return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_add (GK_LDAP *ld,  char const *dn, LDAPMod **attrs) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	// should uncache negative responses to dn.
	return ldap_add(ld->ld, dn, attrs);
}

int gk_ldap_add_s (GK_LDAP *ld,  char const *dn, LDAPMod **attrs ) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	// should uncache negative responses to dn.
	return ldap_add_s(ld->ld, dn, attrs);
}

int gk_ldap_delete_ext (GK_LDAP *ld,  char const *dn, LDAPControl **serverctrls,
			LDAPControl **clientctrls, int *msgidp) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
	// should uncache dn
	return ldap_delete_ext(ld->ld, dn, serverctrls, clientctrls, msgidp);
#else
	return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_delete_ext_s (GK_LDAP *ld,  char const *dn, LDAPControl **serverctrls,
			  LDAPControl **clientctrls) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
	// should uncache dn
	return ldap_delete_ext_s(ld->ld, dn, serverctrls, clientctrls);
#else
	return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_delete (GK_LDAP *ld,  char const *dn ) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	// should uncache dn
	return ldap_delete(ld->ld, dn);
}

int gk_ldap_delete_s (GK_LDAP *ld,  char const *dn ) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	// should uncache dn
	return ldap_delete_s(ld->ld, dn);
}

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
int gk_ldap_extended_operation (GK_LDAP *ld, char *reqoid,
				struct berval *reqdata, LDAPControl **serverctrls,
				LDAPControl **clientctrls, int *msgidp) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_extended_operation(ld->ld, reqoid, reqdata, serverctrls, clientctrls, msgidp);
}

int gk_ldap_extended_operation_s (GK_LDAP *ld, char *reqoid,
				  struct berval *reqdata, LDAPControl **serverctrls,
				  LDAPControl **clientctrls, char **retoidp, struct berval **retdatap) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_extended_operation_s(ld->ld, reqoid, reqdata, serverctrls, clientctrls, retoidp, retdatap);
}

int gk_ldap_parse_extended_result (GK_LDAP *ld, LDAPMessage *res,
				   char **retoidp, struct berval **retdatap, int freeit){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_parse_extended_result(ld->ld, res, retoidp, retdatap, freeit);
}

int gk_ldap_parse_extended_partial (GK_LDAP *ld, LDAPMessage *res,
				    char **retoidp, struct berval **retdatap, LDAPControl ***serverctrls,
				    int freeit){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_parse_extended_partial(ld->ld, res, retoidp, retdatap, serverctrls, freeit);
}
#endif /* LDAPv3 */

int gk_ldap_abandon_ext (GK_LDAP *ld, int msgid, LDAPControl **serverctrls,
			 LDAPControl **clientctrls) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
	return ldap_abandon_ext(ld->ld, msgidp, serverctrls, clientctrls);
#else
	return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_abandon (GK_LDAP *ld, int msgid) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifndef LDAP_PROVIDES_CACHE
	gk_ldap_cache_abandon(ld, msgid);
#endif
	return ldap_abandon(ld->ld, msgid);
}

int gk_ldap_result (GK_LDAP *ld, int msgid, int all,struct timeval *timeout,
		    LDAPMessage **result){
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
#ifdef LDAP_PROVIDES_CACHE
	return ldap_result(ld->ld, msgid, all, timeout, result);
#else
	if((*result=gk_ldap_cache_get_result(ld, msgid, all))!=NULL) {
		return LDAP_SUCCESS;
	}
	int rv=ldap_result(ld->ld, msgid, all, timeout, result);
	gk_ldap_add_result_by_id(ld, msgid, all, *result);
	return rv;
#endif
}

int gk_ldap_msgid (LDAPMessage *lm) {
	return ldap_msgid(lm);
}

int gk_ldap_msgtype (LDAPMessage *lm){
	return ldap_msgtype(lm);
}

int gk_ldap_parse_result (GK_LDAP *ld, LDAPMessage *res,
			  int *errcodep, char **matcheddnp, char **errmsgp,
			  char ***referralsp, LDAPControl ***serverctrls,
			  int freeit) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_parse_result(ld->ld, res, errcodep, matcheddnp, errmsgp, referralsp, serverctrls, freeit);
}

int gk_ldap_parse_sasl_bind_result (GK_LDAP *ld, LDAPMessage *res,
				    struct berval **servercredp, int freeit) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_parse_sasl_bind_result(ld->ld, res, servercredp, freeit);
}

const char * gk_ldap_err2string (int err){
	return ldap_err2string(err);
}

int gk_ldap_result2error (GK_LDAP *ld, LDAPMessage *res, int freeit) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_result2error(ld->ld, res, freeit);
}

void gk_ldap_perror (GK_LDAP *ld,  char const *s) {
	if (NULL==ld)
		return ;
	ldap_perror(ld->ld, s);
}

LDAPMessage * gk_ldap_first_message (GK_LDAP *ld, LDAPMessage *chain) {
	if (NULL==ld)
		return NULL;
	return ldap_first_message(ld->ld, chain);
}

LDAPMessage * gk_ldap_next_message (GK_LDAP *ld, LDAPMessage *msg) {
	if (NULL==ld)
		return NULL;
	return ldap_next_message(ld->ld, msg);
}

int gk_ldap_count_messages (GK_LDAP *ld, LDAPMessage *chain) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_count_messages(ld->ld, chain);
}

LDAPMessage * gk_ldap_first_entry (GK_LDAP *ld, LDAPMessage *chain) {
	if (NULL==ld)
		return NULL;
	return ldap_first_entry(ld->ld, chain);
}

LDAPMessage * gk_ldap_next_entry (GK_LDAP *ld, LDAPMessage *entry) {
	if (NULL==ld)
		return NULL;
	return ldap_next_entry(ld->ld, entry);
}

int gk_ldap_count_entries (GK_LDAP *ld, LDAPMessage *chain) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_count_entries(ld->ld, chain);
}

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
LDAPMessage * gk_ldap_first_reference (GK_LDAP *ld, LDAPMessage *chain) {
	if (NULL==ld)
		return NULL;
	return ldap_first_reference(ld->ld, chain);
}

LDAPMessage * gk_ldap_next_reference (GK_LDAP *ld, LDAPMessage *ref) {
	if (NULL==ld)
		return NULL;
	return ldap_next_reference(ld->ld, ref);
}

int gk_ldap_count_references (GK_LDAP *ld, LDAPMessage *chain) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_count_references(ld->ld, chain);
}
#endif

char * gk_ldap_first_attribute (GK_LDAP *ld, LDAPMessage *entry, BerElement **ber) {
	if (NULL==ld)
		return NULL;
	return ldap_first_attribute(ld->ld, entry, ber);
}

char * gk_ldap_next_attribute (GK_LDAP *ld, LDAPMessage *entry, BerElement *ber) {
	if (NULL==ld)
		return NULL;
	return ldap_next_attribute(ld->ld, entry, ber);
}

char ** gk_ldap_get_values (GK_LDAP *ld, LDAPMessage *entry, char const *target) {
	if (NULL==ld)
		return NULL;
	return ldap_get_values(ld->ld, entry, target);
}

struct berval ** gk_ldap_get_values_len (GK_LDAP *ld, LDAPMessage *entry,
					 char const *target) {
	if (NULL==ld)
		return NULL;
	return ldap_get_values_len(ld->ld, entry, target);
}

int gk_ldap_count_values (char **vals) {
	return ldap_count_values(vals);
}

int gk_ldap_count_values_len (struct berval **vals) {
	return ldap_count_values_len(vals);
}

char * gk_ldap_get_dn (GK_LDAP *ld, LDAPMessage *entry) {
	if (NULL==ld)
		return NULL;
	return ldap_get_dn(ld->ld, entry);
}

char * gk_ldap_dn2ufn ( char *dn) {
	return ldap_dn2ufn(dn);
}

char ** gk_ldap_explode_dn (char const *dn, int notypes) {
	return ldap_explode_dn(dn, notypes);
}

char ** gk_ldap_explode_rdn (char const *rdn, int notypes) {
	return ldap_explode_rdn(rdn, notypes);
}

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
int gk_ldap_get_entry_controls (GK_LDAP *ld, LDAPMessage *entry,
				LDAPControl	***serverctrls) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_get_entry_controls(ld->ld, entry, serverctrls);
}
#endif

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
int gk_ldap_parse_reference (GK_LDAP *ld, LDAPMessage *ref,
			     char ***referralsp, LDAPControl ***serverctrls, int freeit) {
	if (NULL==ld)
		return LDAP_UNAVAILABLE;
	return ldap_parse_reference(ld->ld, ref, refarralsp, serverctrls, freeit);
}
#endif

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
void gk_ldap_control_free (LDAPControl *ctrl) {
	ldap_control_free(ctrl);
}

void gk_ldap_controls_free (LDAPControl **ctrl) {
	ldap_controls_free(ctrl);
}
#endif

int gk_ldap_msgfree (LDAPMessage *lm) {
#ifndef LDAP_PROVIDES_CACHE
	return LDAP_SUCCESS; // Do not delete if in ldap_cache.
#else
	return ldap_msgfree(lm);
#endif
}

void gk_ldap_value_free (char **vals) {
	return ldap_value_free(vals);
}

void gk_ldap_value_free_len (struct berval **vals) {
	return ldap_value_free_len(vals);
}

void gk_ldap_memfree (char *mem) {
	return ldap_memfree(mem);
}

void gk_ldap_cache_enable(GK_LDAP *ld, int timeout, int maxmem){
	const PConfig * const gkconf = Toolkit::Instance()->Config();
	if(0!=gkconf->GetBoolean("LDAPCache", "Enable", FALSE)){
		int gkconfig_timeout=gkconf->GetInteger("LDAPCache", "TTL", timeout);
		int gkconfig_maxmem=gkconf->GetInteger("LDAPCache", "MaxMemory", maxmem);
#ifdef LDAP_PROVIDES_OPENLDAP_CACHE
		ldap_cache_enable(ld->ld, gkconfig_timeout, gkconfig_maxmem);
		PTRACE(5, "Using openldap-cache");
#else
	// Use own cache...
		ld->search_cache=gk_ldap_search_type();
		ld->maxmem=gkconfig_maxmem/CACHE_AVERAGE_SEARCH_SIZE;
		ld->max_cache_time=PTimeInterval(gkconfig_timeout*1000); // PTimeIntervall is in miliseconds
		PTRACE(5, "Using internal cache");
#endif
		PTRACE(3, "Setting Cache to: " << gkconfig_maxmem << " bytes and timeout " << gkconfig_timeout
		       << " seconds");
	} else {
		ld->maxmem=0;
	}
	return;
}

#ifndef LDAP_PROVIDES_CACHE

int gk_ldap_cache_check(GK_LDAP *ld, char const *base, int scope, char const *filter,  char **attrs, int attrsonly) {
	if((NULL==ld) || (0==ld->maxmem))
		return -1;
	PINDEX i=0;
	for(i=0; i<ld->search_cache.GetSize(); i++) {
		if(ld->search_cache[i].is_search(base, scope, filter, attrs, attrsonly)) {
			if((PTime()-ld->search_cache[i].get_insert_time())>=ld->max_cache_time) {
				PTRACE(5, "max cache time hit: \t" << filter);
				gk_ldap_cache_search_class *obj=
					dynamic_cast <gk_ldap_cache_search_class *> (ld->search_cache.RemoveAt(i));
				delete obj;
				return -1; // was too old
			}
			PTRACE(5, "cache hit\tfilter=" << filter);
			return ld->search_cache[i].msgid;
		}
	}
	return -1;
}

void gk_ldap_cache_add_searchresult(GK_LDAP *ld,  char const *base, int scope, char const *filter, char **attrs,
				    int attrsonly, LDAPMessage *res) {
	if ((NULL==ld) || (0==ld->maxmem))
		return;
	gk_ldap_cache_search_class *a=new gk_ldap_cache_search_class(base, scope, filter, attrs, attrsonly, res);
	a->msgid=gk_ldap_msgid(res);
	ld->search_cache.Append(a);
	gk_ldap_cache_delete_oldest(ld);
}

void gk_ldap_cache_delete_oldest(GK_LDAP *ld) {
	if (NULL==ld)
		return ;
	while (ld->search_cache.GetSize() > (unsigned) (ld->maxmem) || (ld->search_cache[0].get_insert_time()-PTime()>ld->max_cache_time)) {
		gk_ldap_cache_search_class *obj=dynamic_cast <gk_ldap_cache_search_class *> (ld->search_cache.RemoveAt(1));
		delete obj;
	}
}

void gk_ldap_cache_delete(GK_LDAP *ld, int timeout, int maxmem) {
	if (NULL==ld)
		return ;
	ld->search_cache=gk_ldap_search_type();
}

int gk_ldap_cache_check_compare(GK_LDAP *ld,  char const *dn, char const *attr, struct berval bv) {
	return -1;
}

void gk_ldap_cache_abandon(GK_LDAP *ld, int msgid) {
	if ((NULL==ld) || (0==ld->maxmem))
		return ;
	PINDEX i=0;
	for(i=0; i<ld->search_cache.GetSize(); i++)
		if(ld->search_cache[i].msgid==msgid) {
			gk_ldap_cache_search_class *obj=dynamic_cast <gk_ldap_cache_search_class *> (ld->search_cache.RemoveAt(i));
			delete obj;
		}
}

LDAPMessage * gk_ldap_cache_get_message(GK_LDAP *ld, int messageid) {
	if ((NULL==ld) || (0==ld->maxmem))
		return NULL;
	PINDEX i=0;
	for(i=0; i<ld->search_cache.GetSize(); i++)
		if(ld->search_cache[i].msgid==messageid)
			return ld->search_cache[i].message;
	return NULL;
}


LDAPMessage * gk_ldap_cache_get_result(GK_LDAP *ld, int msgid, int all) {
	if ((NULL==ld) || (0==ld->maxmem))
		return NULL;
	PINDEX i=0;
	for(i=0; i<ld->search_cache.GetSize(); i++)
		if(ld->search_cache[i].msgid==msgid)
			return ld->search_cache[i].message;
	return NULL;
}

void gk_ldap_add_result_by_id(GK_LDAP *ld, int msgid, int all, LDAPMessage *result) {
	if ((NULL==ld) || (0==ld->maxmem))
		return ;
	PINDEX i=0;
	for(i=0; i<ld->search_cache.GetSize(); i++) {
		if(ld->search_cache[i].msgid==msgid) {
			ld->search_cache[i].message=result;
			gk_ldap_cache_delete_oldest(ld);
			return;
		}
	}
}

// implementation of the search class.

gk_ldap_cache_search_class::gk_ldap_cache_search_class(): base(NULL),  filter(NULL),  message(NULL),
							  msgid(0) {}

gk_ldap_cache_search_class::gk_ldap_cache_search_class(const char *bse, int scpe, const char *fltr, char **attr, int attrsnly, LDAPMessage *res) :
	scope(scpe), attrsonly(attrsnly),  message(res)
{
	base=strndup(bse, strlen(bse));
	filter=strndup(fltr, strlen(fltr));
	attrs=PStringList(ldap_count_values(attr),attr);
	msgid=gk_ldap_msgid(res);
	insert_time=PTime();
}

gk_ldap_cache_search_class::~gk_ldap_cache_search_class(void) {
	delete base;
	delete filter;
	ldap_msgfree(message);
}

void gk_ldap_cache_search_class::set_values(char *bse, int scpe, char *fltr, char **attr, int attrsnly, LDAPMessage *res){
	scope=scpe;
	attrsonly=attrsnly;
	message=res; // cannot copy LDAPMessage.
	base=strndup(bse, strlen(bse));
	filter=strndup(fltr, strlen(fltr));
	attrs=PStringList(ldap_count_values(attr),attr);
}

bool gk_ldap_cache_search_class::is_search(char const *bse, int scpe, char const *fltr, char **attr, int attrsnly){
	PStringList p(ldap_count_values(attr),attr);
	return ((strcmp(bse,base)==0) && (0==strcmp(fltr,filter)) && (scpe==scope) && (attrsnly==attrsonly) && (p==attrs) && (message!=NULL));
}

char * gk_ldap_cache_search_class::strndup(const char s[],int n) {
	const char *old=s;
	size_t len=(size_t) n ; // Very optimistic...
	if(len < 8)
		len=8;
	char *nc=new char[len+1];
	if(NULL==nc)
		return NULL;
	nc[n]='\0';
	memcpy(nc,old,n);
	return nc;
}

#endif // LDAP_PROVIDES_CACHE
