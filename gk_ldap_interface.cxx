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


#include <gk_ldap_interface.h>

GK_LDAP *gk_ldap_init (const char *hostname, int portno) {
  GK_LDAP *ld=new GK_LDAP();
  ld->ld=ldap_init(hostname,portno);
  return ld;
}

GK_LDAP *gk_ldap_open (const char *hostname, int portno) {
  GK_LDAP *ld=new GK_LDAP();
  ld->ld=ldap_open(hostname,portno);
  return ld;
}

int gk_ldap_sasl_bind (GK_LDAP *ld,  char const *dn, char const *mechanism,
		       struct berval const *cred, LDAPControl **serverctrls,
		       LDAPControl **clientctrls, int *msgidp) {
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
#if (LDAP_VERSION_MAX < LDAP_VERSION3)
  return LDAP_PROTOCOL_ERROR;
#else
  gk_ldap_cache_enable(ld->ld, CACHE_TIMEOUT, CACHE_MAXMEM);
  return ldap_sasl_bind_s(ld->ld, dn, mechanism, cred, serverctrls, clientctrls, servercredp);
#endif
}

int gk_ldap_simple_bind (GK_LDAP *ld,  char const *dn, char const *passwd) {
  gk_ldap_cache_enable(ld, CACHE_TIMEOUT, CACHE_MAXMEM);
  return ldap_simple_bind(ld->ld, dn, passwd);
}

int gk_ldap_simple_bind_s (GK_LDAP *ld,  char const *dn, char const *passwd) {
  gk_ldap_cache_enable(ld, CACHE_TIMEOUT, CACHE_MAXMEM);
  return ldap_simple_bind_s(ld->ld, dn, passwd);
}

int gk_ldap_bind (GK_LDAP *ld,  char const *dn, char const *cred, int method) {
  gk_ldap_cache_enable(ld, CACHE_TIMEOUT, CACHE_MAXMEM);
  return ldap_bind(ld->ld, dn, cred, method);
}

int gk_ldap_bind_s (GK_LDAP *ld,  char const *dn, char const *cred, int method) {
  gk_ldap_cache_enable(ld, CACHE_TIMEOUT, CACHE_MAXMEM);
  return ldap_bind_s(ld->ld, dn, cred, method);
}

int gk_ldap_unbind_ext (GK_LDAP *ld, LDAPControl *serverctrls, LDAPControl *clientctrls){
#if (LDAP_VERSION_MAX < LDAP_VERSION3)
  return LDAP_PROTOCOL_ERROR;
#else
  gk_ldap_cache_delete(ld, CACHE_TIMEOUT, CACHE_MAXMEM);
  return ldap_unbind_ext(ld->ld, serverctrls, clientctrls);
#endif
}

int gk_ldap_unbind (GK_LDAP *ld) {
  return ldap_unbind(ld->ld);
}

int gk_ldap_unbind_s (GK_LDAP *ld) {
  return ldap_unbind_s(ld->ld);
}

int gk_ldap_get_option (GK_LDAP *ld, int option, void *outvalue) {
  return ldap_get_option(ld->ld, option, outvalue);
}

int gk_ldap_set_option (GK_LDAP *ld, int option,  void const *outvalue) {
  return ldap_set_option (ld->ld, option, outvalue);
}
int gk_ldap_search_ext (GK_LDAP *ld,  char const *base,
			int scope,  char const *filter, char **attrs, int attrsonly, 
			LDAPControl **serverctrls, LDAPControl **clientctrls,
			struct timeval *timeout, int sizelimit, int *msgidp) {
#if (LDAP_VERSION_MAX < LDAP_VERSION3)
  return LDAP_PROTOCOL_ERROR;
#else
#ifdef LDAP_HAS_CACHE
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
#if (LDAP_VERSION_MAX < LDAP_VERSION3)
  return LDAP_PROTOCOL_ERROR;
#else
#ifdef LDAP_HAS_CACHE
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
#ifdef LDAP_HAS_CACHE
  return ldap_search(ld->ld, base, scope, filter, attrs, attrsonly);
#else
  // lookup in cache
  int messageid;
  if((messageid=gk_ldap_cache_check(ld, base, scope, filter, attrs, attrsonly))!=-1) {
    return messageid;
  } else { // not in cache
    int rv=ldap_search(ld->ld, base, scope, filter, attrs, attrsonly);
    gk_ldap_cache_add_searchresult(ld, base, scope, filter, attrs, attrsonly, NULL);
  }
  return -1;
#endif
}

int gk_ldap_search_s (GK_LDAP *ld,  char const *base, int scope, char const *filter, char **attrs,
		      int attrsonly, LDAPMessage **res){
#ifdef LDAP_HAS_CACHE
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
#ifdef LDAP_HAS_CACHE
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
#ifdef LDAP_HAS_CACHE
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
#ifdef LDAP_HAS_CACHE
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
#ifdef LDAP_HAS_CACHE
  return ldap_compare(ld->ld, dn, attr, value);
#else
  return ldap_compare(ld->ld, dn, attr, value);
#endif
}

int gk_ldap_compare_s (GK_LDAP *ld,  char const *dn, char const *attr, char const *value) {
#ifdef LDAP_HAS_CACHE
  return ldap_compare(ld->ld, dn, attr, value);
#else
  int rv=ldap_compare_s(ld->ld, dn, attr, value);
  // Need to put into cache
  return rv;
#endif
}
    
int gk_ldap_modify_ext (GK_LDAP *ld,  char const *dn, LDAPMod **mods, LDAPControl **serverctrls,
			LDAPControl **clientctrls, int *msgidp) {
#ifdef LDAP_HAS_CACHE
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
#ifdef LDAP_HAS_CACHE
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
#ifdef LDAP_HAS_CACHE
  return ldap_modify(ld->ld, dn, mods);
#else
  // should uncache the dn.
  return ldap_modify(ld->ld, dn, mods);
#endif
}

int gk_ldap_modify_s (GK_LDAP *ld, char const *dn, LDAPMod **mods){
#ifdef LDAP_HAS_CACHE
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
  return ldap_rename(ld->ld, dn, newrdn, newSuperior deleteoldrdn, sctrsl, cctrls, msgidp);
}

int gk_ldap_rename_s (GK_LDAP *ld,  char *dn, char *newrdn,
		      char *newSuperior, int deleteoldrdn, LDAPControl **sctrls,
		      LDAPControl **cctrls){
  return ldap_rename_s(ld->ld, dn, newrdn, newSuperior, deleteoldrdn, sctrls, cctrls); 
}
#endif

int gk_ldap_modrdn2 (GK_LDAP *ld, char const *dn, char const *newrdn, int deleteoldrdn) {
  // should uncache dn
  return ldap_modrdn2(ld->ld, dn, newrdn, deleteoldrdn);
}

int gk_ldap_modrdn2_s (GK_LDAP *ld,  char const *dn, char const *newrdn, int deleteoldrdn) {
  // should uncache dn
  return ldap_modrdn2_s(ld->ld, dn, newrdn, deleteoldrdn);
}

int gk_ldap_modrdn (GK_LDAP *ld,  char const *dn, char const *newrdn) {
  // should uncache dn
  return ldap_modrdn(ld->ld, dn, newrdn);
}

int gk_ldap_modrdn_s (GK_LDAP *ld,  char const *dn, char const *newrdn) {
  // should uncache dn
  return ldap_modrdn_s(ld->ld, dn, newrdn);
}

int gk_ldap_add_ext (GK_LDAP *ld, char const *dn, LDAPMod **attrs,
		     LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp) {
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
  // should uncache dn -- negative responses 
  return ldap_add_ext(ld->ld, dn, attrs, serverctrls, clientctrls, msgidp);
#else // LDAP_VERSION_MAX
  return LDAP_PROTOCOL_ERROR;
#endif 
}

int gk_ldap_add_ext_s (GK_LDAP *ld, char const *dn, LDAPMod **attrs,
		       LDAPControl **serverctrls, LDAPControl **clientctrls) {
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
  // should uncache dn -- negative responses 
  return ldap_add_ext_s(ld->ld, dn, attrs, serverctrls, clientctrls);
#else // LDAP_VERSION_MAX
  return LDAP_PROTOCOL_ERROR;
#endif 
}

int gk_ldap_add (GK_LDAP *ld,  char const *dn, LDAPMod **attrs) {
  // should uncache negative responses to dn.
  return ldap_add(ld->ld, dn, attrs);
}

int gk_ldap_add_s (GK_LDAP *ld,  char const *dn, LDAPMod **attrs ) {
  // should uncache negative responses to dn.
  return ldap_add_s(ld->ld, dn, attrs);
}

int gk_ldap_delete_ext (GK_LDAP *ld,  char const *dn, LDAPControl **serverctrls,
			LDAPControl **clientctrls, int *msgidp) {
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
  // should uncache dn
  return ldap_delete_ext(ld->ld, dn, serverctrls, clientctrls, msgidp);
#else
  return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_delete_ext_s (GK_LDAP *ld,  char const *dn, LDAPControl **serverctrls,
			  LDAPControl **clientctrls) {
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
  // should uncache dn
  return ldap_delete_ext_s(ld->ld, dn, serverctrls, clientctrls);
#else
  return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_delete (GK_LDAP *ld,  char const *dn ) {
  // should uncache dn
  return ldap_delete(ld->ld, dn);
}

int gk_ldap_delete_s (GK_LDAP *ld,  char const *dn ) {
  // should uncache dn
  return ldap_delete_s(ld->ld, dn);
}

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
int gk_ldap_extended_operation (GK_LDAP *ld, char *reqoid,
				struct berval *reqdata, LDAPControl **serverctrls,
				LDAPControl **clientctrls, int *msgidp) {
  return ldap_extended_operation(ld->ld, reqoid, reqdata, serverctrls, clientctrls, msgidp);
}

int gk_ldap_extended_operation_s (GK_LDAP *ld, char *reqoid,
				  struct berval *reqdata, LDAPControl **serverctrls,
				  LDAPControl **clientctrls, char **retoidp, struct berval **retdatap) {
  return ldap_extended_operation_s(ld->ld, reqoid, reqdata, serverctrls, clientctrls, retoidp, retdatap);
}

int gk_ldap_parse_extended_result (GK_LDAP *ld, LDAPMessage *res,
				   char **retoidp, struct berval **retdatap, int freeit){
  return ldap_parse_extended_result(ld->ld, res, retoidp, retdatap, freeit);
}

int gk_ldap_parse_extended_partial (GK_LDAP *ld, LDAPMessage *res,
				    char **retoidp, struct berval **retdatap, LDAPControl ***serverctrls,
				    int freeit){
  return ldap_parse_extended_partial(ld->ld, res, retoidp, retdatap, serverctrls, freeit);
}
#endif /* LDAPv3 */

int gk_ldap_abandon_ext (GK_LDAP *ld, int msgid, LDAPControl **serverctrls,
			 LDAPControl **clientctrls) {
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
  return ldap_abandon_ext(ld->ld, msgidp, serverctrls, clientctrls);
#else
  return LDAP_PROTOCOL_ERROR;
#endif
}

int gk_ldap_abandon (GK_LDAP *ld, int msgid) {
#ifndef LDAP_HAS_CACHE
  gk_ldap_cache_abandon(ld, msgid);
#endif
  return ldap_abandon(ld->ld, msgid);
}

int gk_ldap_result (GK_LDAP *ld, int msgid, int all,struct timeval *timeout,
		    LDAPMessage **result){
#ifdef LDAP_HAS_CACHE
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
  return ldap_parse_result(ld->ld, res, errcodep, matcheddnp, errmsgp, referralsp, serverctrls, freeit);
}

int gk_ldap_parse_sasl_bind_result (GK_LDAP *ld, LDAPMessage *res,
				    struct berval **servercredp, int freeit) {
  return ldap_parse_sasl_bind_result(ld->ld, res, servercredp, freeit);
}

const char * gk_ldap_err2string (int err){
  return ldap_err2string(err);
}

int gk_ldap_result2error (GK_LDAP *ld, LDAPMessage *res, int freeit) {
  return ldap_result2error(ld->ld, res, freeit);
}

void gk_ldap_perror (GK_LDAP *ld,  char const *s) {
  ldap_perror(ld->ld, s);
}

LDAPMessage * gk_ldap_first_message (GK_LDAP *ld, LDAPMessage *chain) {
  return ldap_first_message(ld->ld, chain);
}

LDAPMessage * gk_ldap_next_message (GK_LDAP *ld, LDAPMessage *msg) {
  return ldap_next_message(ld->ld, msg);
}

int gk_ldap_count_messages (GK_LDAP *ld, LDAPMessage *chain) {
  return ldap_count_messages(ld->ld, chain);
}

LDAPMessage * gk_ldap_first_entry (GK_LDAP *ld, LDAPMessage *chain) {
  return ldap_first_entry(ld->ld, chain);
}

LDAPMessage * gk_ldap_next_entry (GK_LDAP *ld, LDAPMessage *entry) {
  return ldap_next_entry(ld->ld, entry);
}

int gk_ldap_count_entries (GK_LDAP *ld, LDAPMessage *chain) {
  return ldap_count_entries(ld->ld, chain);
}

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
LDAPMessage * gk_ldap_first_reference (GK_LDAP *ld, LDAPMessage *chain) {
  return ldap_first_reference(ld->ld, chain);
}

LDAPMessage * gk_ldap_next_reference (GK_LDAP *ld, LDAPMessage *ref) {
  return ldap_next_reference(ld->ld, ref);
}

int gk_ldap_count_references (GK_LDAP *ld, LDAPMessage *chain) {
  return ldap_count_references(ld->ld, chain);
}
#endif

char * gk_ldap_first_attribute (GK_LDAP *ld, LDAPMessage *entry, BerElement **ber) {
  return ldap_first_attribute(ld->ld, entry, ber);
}

char * gk_ldap_next_attribute (GK_LDAP *ld, LDAPMessage *entry, BerElement *ber) {
  return ldap_next_attribute(ld->ld, entry, ber);
}

char ** gk_ldap_get_values (GK_LDAP *ld, LDAPMessage *entry, char const *target) {
  return ldap_get_values(ld->ld, entry, target);
}

struct berval ** gk_ldap_get_values_len (GK_LDAP *ld, LDAPMessage *entry,
					 char const *target) {
  return ldap_get_values_len(ld->ld, entry, target);
}

int gk_ldap_count_values (char **vals) {
  return ldap_count_values(vals);
}

int gk_ldap_count_values_len (struct berval **vals) {
  return ldap_count_values_len(vals);
}

char * gk_ldap_get_dn (GK_LDAP *ld, LDAPMessage *entry) {
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
  return ldap_get_entry_controls(ld->ld, entry, serverctrls);
}
#endif

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
int gk_ldap_parse_reference (GK_LDAP *ld, LDAPMessage *ref,
			     char ***referralsp, LDAPControl ***serverctrls, int freeit) {
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
#ifndef LDAP_HAS_CACHE
//   int msgid=ldap_msgid(lm);
//   for (vector<search *>::iterator iter=ld->search_cache.begin();iter!=ld->search_cache.end();iter++) {
//     if((*iter)->msgid==msgid)
      return LDAP_SUCCESS; // Do not delete if in ldap_cache. 
//   }
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
#ifdef LDAP_HAS_CACHE
  //  ldap_cache_enable(ld->ld, timeout, maxmem);
#else
  // Use own cache...
  ld->search_cache.clear();
  ld->maxmem=maxmem;
  return;
#endif
}

#ifndef LDAP_HAS_CACHE

int gk_ldap_cache_check(GK_LDAP *ld, char const *base, int scope, char const *filter,  char **attrs, int attrsonly) {
  for (search_t::iterator iter=ld->search_cache.begin();iter!=ld->search_cache.end();iter++) {
    if((*iter).is_search(base, scope, filter, attrs, attrsonly)) 
      return (*iter).msgid;
  }
  return -1;
}

LDAPMessage * gk_ldap_cache_get_message(GK_LDAP *ld, int messageid) {
  for (search_t::iterator iter=ld->search_cache.begin();iter!=ld->search_cache.end();iter++) {
    if(messageid==(*iter).msgid)
      return (*iter).message;
  }
  return NULL;
}

void gk_ldap_cache_add_searchresult(GK_LDAP *ld,  char const *base, int scope, char const *filter, char **attrs,
				    int attrsonly, LDAPMessage *res) {
  ld->search_cache.push_back(search(base, scope, filter, attrs, attrsonly, res));
}

int gk_ldap_cache_check_compare(GK_LDAP *ld,  char const *dn, char const *attr, struct berval bv) {
  return -1;
}

void gk_ldap_cache_abandon(GK_LDAP *ld, int msgid) {
  for (search_t::iterator iter=ld->search_cache.begin();iter!=ld->search_cache.end();iter++) {
    if(msgid==(*iter).msgid) 
      ld->search_cache.erase(iter);
  }
}

LDAPMessage * gk_ldap_cache_get_result(GK_LDAP *ld, int msgid, int all) {
  for (search_t::iterator iter=ld->search_cache.begin();iter!=ld->search_cache.end();iter++) {
    if(msgid==(*iter).msgid)
      return (*iter).message;
  }
  return NULL;
}

void gk_ldap_add_result_by_id(GK_LDAP *ld, int msgid, int all, LDAPMessage *result) {
  for (search_t::iterator iter=ld->search_cache.begin();iter!=ld->search_cache.end();iter++) {
    if(msgid==(*iter).msgid) {
      (*iter).message=result;
      return;
    }
  }
}

#endif // LDAP_HAS_CACHE
