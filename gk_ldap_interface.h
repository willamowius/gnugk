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

/*
 * Non opaque part of the LDAP-C-API
 */

#ifndef GK_LDAP_H
#define GK_LDAP_H "@(#) $Id$"

#ifdef HAS_LEVEL_TWO_LDAPAPI
# include <ldapapi.h>
#else
# include <ldap.h>
#endif // HAS_LDAP_LEVEL_TWO_API

#if (LDAP_API_VERSION >= 2004) && defined(LDAP_API_FEATURE_X_OPENLDAP) // if any other LDAP-library implements caching, add here.
# define LDAP_PROVIDES_OPENLDAP_CACHE
# define LDAP_PROVIDES_CACHE
#endif

//#include <vector>

#include <ptlib.h>

#define CACHE_TIMEOUT 100
#define CACHE_MAXMEM 1000
#define CACHE_AVERAGE_SEARCH_SIZE 10

#ifndef LDAP_PROVIDES_CACHE

class gk_ldap_cache_search_class : public PObject {
private:
	char *base;
	int scope;
	char *filter;
	PStringList attrs;
	int attrsonly;
	PTime insert_time;
	char * strndup(const char orig[], int len);
public:
	LDAPMessage *message;
	int msgid;
	gk_ldap_cache_search_class(const char *bse, int scpe, const char *fltr, char **attr, int attrsnly, LDAPMessage *res);
	gk_ldap_cache_search_class();
	~gk_ldap_cache_search_class();
	void set_values(char *bse, int scpe, char *fltr, char **attr, int attrsnly, LDAPMessage *res);
	bool is_search(char const *base, int scope, char const *filter, char **attrs, int attrsonly);
	const PTime & get_insert_time() const {return insert_time;}
};

#ifdef DOC_PLUS_PLUS
class  ldap_cache_search_class : public PList {
#endif
PDECLARE_LIST(gk_ldap_search_type,gk_ldap_cache_search_class);
};


typedef struct {
	LDAP * ld;
	PTimeInterval max_cache_time;
	gk_ldap_search_type search_cache;
	int maxmem;
	mutable PMutex search_cache_mutex;
} GK_LDAP;

#else

typedef struct {
	LDAP * ld;
} GK_LDAP;

#endif //LDAP_PROVIDES_CACHE

GK_LDAP *gk_ldap_init (const char *hostname, int portno);


/* depricated */ /* bind.cxx */
/** gk_ldap_open initializes the LDAP * session handle. As in @ref{ldap_init} it {\em must}
    be passed to all following calls. Unlike gk_ldap_init gk_ldap_open will open a connection to
    a gk_ldap server.
    @see gk_ldap_init, gk_ldap_bind
*/
GK_LDAP *gk_ldap_open (const char *hostname, int portno);

/* binding */

/// Bind with sasl mechanism. Currently only simple bind is allowed
int gk_ldap_sasl_bind (GK_LDAP *ld,  char const *dn, char const *mechanism,
		       struct berval const *cred, LDAPControl **serverctrls,
		       LDAPControl **clientctrls, int *msgidp);

/// Bind with sasl mechanism. Synchronous version.
int gk_ldap_sasl_bind_s (GK_LDAP *ld,  char *dn, char const *mechanism,
			 struct berval const *cred, LDAPControl **serverctrls,
			 LDAPControl **clientctrls, struct berval **servercredp);

/// Bind with simple pasword.
int gk_ldap_simple_bind (GK_LDAP *ld,  char const *dn, char const *passwd);

/// Bind with simple pasword. Synchronous version.
int gk_ldap_simple_bind_s (GK_LDAP *ld,  char const *dn, char const *passwd);

/* depricated */
/// Old bind. For backward compatibility
int gk_ldap_bind (GK_LDAP *ld,  char const *dn, char const *cred, int method);

/// Old bind. For backward compatibility. Synchronous version.
int gk_ldap_bind_s (GK_LDAP *ld,  char const *dn, char const *cred, int method);
/*
  LDAP_F(int) gk_ldap_kerberos_bind LDAP_P((GK_LDAP *ld,  char const *dn));

  LDAP_F(int) gk_ldap_kerberos_bind_s LDAP_P((GK_LDAP *ld,  char const *dn));
*/
/* unbinding */

/// Unbind Request. Send an unbind request and terminate the connection.
int gk_ldap_unbind_ext (GK_LDAP *ld, LDAPControl *serverctrls, LDAPControl *clientctrls);

/// Unbind Request. Send an unbind request and terminate the connection.
int gk_ldap_unbind (GK_LDAP *ld);

/// Unbind Request. Send an unbind request and terminate the connection.
int gk_ldap_unbind_s (GK_LDAP *ld);
//@}
/* options */
/** @name Option handling
 */
//@{

/** Get an option from a connection. The user has to provide the right datatype and cast
    it to void.
*/
int gk_ldap_get_option (GK_LDAP *ld, int option, void *outvalue);

/** Set an option in a connection. The user has to provide the right datatype and cast
    it to void.
*/
int gk_ldap_set_option (GK_LDAP *ld, int option,  void const *outvalue);

//@}
/* searching */
/** @name Searching entries.
 */
//@{
/** Comlete search request.
    @param base the search base
    @param scope the search scope
    @param filter the search filter
    @param attrs array of attributes to be fetched or NULL
    @param attrsonly 0 if values \em and attributes should be fetched, in any other
    case only attributes will be fetched.
    @param timeout Servertimeout
    @param msgidp pointer to the messageID
*/
int gk_ldap_search_ext (GK_LDAP *ld,  char const *base,
			int scope,  char const *filter, char **attrs, int attrsonly,
			LDAPControl **serverctrls, LDAPControl **clientctrls,
			struct timeval *timeout, int sizelimit, int *msgidp);

/** Complete search request (synchronous).
    @param res the search results
    @see gk_ldap_search_ext for details.
*/
int gk_ldap_search_ext_s (GK_LDAP *ld,  char const *base, int scope,  char const *filter,
			  char **attrs, int attrsonly, LDAPControl **serverctrls,
			  LDAPControl **clientctrls, struct timeval *timeout,
			  int sizelimit, LDAPMessage **res);
/** Simple search request.
    @param base the search base
    @param scope the search scope
    @param filter the search filter
    @param attrs array of attributes to be fetched or NULL
    @param attrsonly 0 if values \em and attributes should be fetched, in any other
    case only attributes will be fetched.
    @return messageID
*/
int gk_ldap_search (GK_LDAP *ld,  char const *base, int scope, char const *filter, char **attrs,
		    int attrsonly);

/** Simple search request (synchronous). @see gk_ldap_search for details.
    @param res the search results
    @return LDAP_SUCCESS if search was successful, a GK_LDAP error otherwise.
*/
int gk_ldap_search_s (GK_LDAP *ld,  char const *base, int scope, char const *filter, char **attrs,
		      int attrsonly, LDAPMessage **res);

/** Simple search request with timeout.
    @param timeout overall timeout to get the messages
    @see gk_ldap_search_s
*/
int gk_ldap_search_st (GK_LDAP *ld,  char const *base, int scope, char const *filter, char **attrs,
		       int attrsonly, struct timeval *timeout, LDAPMessage **res);

//@}
/* comparing between local values and entries */
/** @name Comparing entries and local values.
 */
//@{
/** Compare.
    @param attr array of attributes to compare
    @param bvalue array of bervals (values to compare)
    @param msgidp pointer to the messageid
    @return LDAP_SUCCESS on success. Error othterwise
*/
int gk_ldap_compare_ext (GK_LDAP *ld,  char const *dn, char const *attr,
			 struct berval const *bvalue, LDAPControl **serverctrls,
			 LDAPControl **clientctrls, int *msgidp);

/** Compare (synchronous).
    @see gk_ldap_compare_ext for details.
    @return MessageID
*/
int gk_ldap_compare_ext_s (GK_LDAP *ld,  char const *dn, char const *attr,
			   struct berval const *bvalue, LDAPControl **serverctrls,
			   LDAPControl **clientctrls);

/** Compare.
    @param attr array of attributes to compare
    @param bvalue array of values
    @return MessageID
*/
int gk_ldap_compare (GK_LDAP *ld,  char const *dn, char const *attr, char *const value);

/** Compare.
 */
int gk_ldap_compare_s (GK_LDAP *ld,  char const *dn, char const *attr, char *const value);
//@}


/* Modifying entries */
/** @name Modifying Entries.
    @deprecated gk_ldap_modify gk_ldap_modify_s
*/
//@{
/** Complete modification Request.
    @param mods Array of modifications
    @param msgidp Pointer to the messageid
    @return LDAP_SUCCESS on success. Error othterwise
*/
int gk_ldap_modify_ext (GK_LDAP *ld,  char const *dn, LDAPMod **mods, LDAPControl **serverctrls,
			LDAPControl **clientctrls, int *msgidp);

/** Complete modification Request (synchronous).
    @see gk_ldap_modify_ext for details
*/
int gk_ldap_modify_ext_s (GK_LDAP *ld, char const *dn, LDAPMod **mods,
			  LDAPControl **serverctrls, LDAPControl **clientctrls );

/* deprecated */
/// Simple modification request.
int gk_ldap_modify (GK_LDAP *ld, char const *dn, LDAPMod **mods);

/// Simple modification request (synchronous).
int gk_ldap_modify_s (GK_LDAP *ld, char const *dn, LDAPMod **mods);

/* Modifying names of entries */
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
int gk_ldap_rename (GK_LDAP *ld,  char *dn,
		    char *newrdn, char *newSuperior, int deleteoldrdn,
		    LDAPControl **sctrls, LDAPControl **cctrls, int *msgidp); /* LDAPv3 */

int gk_ldap_rename_s (GK_LDAP *ld,  char *dn, char *newrdn,
		      char *newSuperior, int deleteoldrdn, LDAPControl **sctrls,
		      LDAPControl **cctrls);
#endif

/* deprecated with LDAPv3 */
/** Modify the relative distinguished name of an entry.
    @param deleteoldrdn 0 if not to delete the old rdn.
    @return MessageID
*/
int gk_ldap_modrdn2 (GK_LDAP *ld, char const *dn, char const *newrdn, int deleteoldrdn);

/** Modify the relative distinguished name of an entry (synchronous).
    @see gk_ldap_modrdn2 for details
    @return LDAP_SUCCESS on success. Error otherwise
*/
int gk_ldap_modrdn2_s (GK_LDAP *ld,  char const *dn, char const *newrdn, int deleteoldrdn);

/** Modify the relative distinguished name of an entry.
    The old RDN will be deleted.
    @see gk_ldap_modrdn2
*/
int gk_ldap_modrdn (GK_LDAP *ld,  char const *dn, char const *newrdn);

/** Modify the relative distinguished name of an entry (synchronous).
    The old RDN will be deleted.
    @see gk_ldap_modrdn2
    @return LDAP_SUCCESS on success. Error otherwise
*/
int gk_ldap_modrdn_s (GK_LDAP *ld, char const *dn, char const *newrdn);


/* Adding entries */
/** Add an entry.
    @param attrs Array of attribute/values to add. The (*attr)->mod_op is ignored.
    Only the decision wether to take the berval or the char is done.
    @param msgidp pointer to the MessageID
    @return LDAP_SUCCESS on success. Error otherwise
*/
int gk_ldap_add_ext (GK_LDAP *ld, char const *dn, LDAPMod **attrs,
		     LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp);

/** Add an entry (synchronous).
    @see gk_ldap_add_ext for details.
*/
int gk_ldap_add_ext_s (GK_LDAP *ld, char const *dn, LDAPMod **attrs,
		       LDAPControl **serverctrls, LDAPControl **clientctrls);
/** Add an entry.
    @see gk_ldap_add_ext for details.
*/
int gk_ldap_add (GK_LDAP *ld,  char const *dn, LDAPMod **attrs);

/** Add an entry (synchronous).
    @see gk_ldap_add_ext for details.
*/
int gk_ldap_add_s (GK_LDAP *ld,  char const *dn, LDAPMod **attrs );

/* Deleting entries */

/** Delete an entry.
    @param msgidp pointer to the MessageID
    @return LDAP_SUCCESS on success. Error otherwise
*/
int gk_ldap_delete_ext (GK_LDAP *ld,  char const *dn, LDAPControl **serverctrls,
			LDAPControl **clientctrls, int *msgidp);

/** Delete an entry (synchronous).
    @see gk_ldap_delete_ext for details.
*/
int gk_ldap_delete_ext_s (GK_LDAP *ld,  char const *dn, LDAPControl **serverctrls,
			  LDAPControl **clientctrls);

/** Delete an entry.
    @see gk_ldap_delete_ext for details.
*/
int gk_ldap_delete (GK_LDAP *ld,  char const *dn );

/** Delete an entry (synchronous).
    @see gk_ldap_delete_ext for details.
*/
int gk_ldap_delete_s (GK_LDAP *ld,  char const *dn );

//@}
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
int gk_ldap_extended_operation (GK_LDAP *ld, char *reqoid,
				struct berval *reqdata, LDAPControl **serverctrls,
				LDAPControl **clientctrls, int *msgidp);

int gk_ldap_extended_operation_s (GK_LDAP *ld, char *reqoid,
				  struct berval *reqdata, LDAPControl **serverctrls,
				  LDAPControl **clientctrls, char **retoidp, struct berval **retdatap);

int gk_ldap_parse_extended_result (GK_LDAP *ld, LDAPMessage *res,
				   char **retoidp, struct berval **retdatap, int freeit);

int gk_ldap_parse_extended_partial (GK_LDAP *ld, LDAPMessage *res,
				    char **retoidp, struct berval **retdatap, LDAPControl ***serverctrls,
				    int freeit );
#endif /* LDAPv3 */

/* Abandoning operations */
/** @name Abandoning requests.
 */
//@{
/// Abandon.
int gk_ldap_abandon_ext (GK_LDAP *ld, int msgid, LDAPControl **serverctrls,
			 LDAPControl **clientctrls);
/// Abandon.
int gk_ldap_abandon (GK_LDAP *ld, int msgid);

//@}
/* Obtaining results */
/** @name Getting resulsts.
    @deprecated gk_ldap_result2error, gk_ldap_perror
*/
//@{
/** Getting a LDAPMessage pointer.
    @param msgid MessageID.
    @param all 0 if not all messages should be fetched.
    @param timeout overall timeout for the operation.
    @param result pointer to LDAPMessage *
    @return type of the message fetched.
*/
int gk_ldap_result (GK_LDAP *ld, int msgid, int all,struct timeval *timeout,
		    LDAPMessage **result);

/// Getting the MessageID from an LDAPMessage
int gk_ldap_msgid (LDAPMessage *lm);

/// Getting the message type from an LDAPMessage
int gk_ldap_msgtype (LDAPMessage *lm);

/* Handling results */
/** Parse a LDAPMessage.
    @param matcheddnp the matched DN
    @param errmsg textual message the server returned.
    @param freeit 0 if the LDAPMessage should not be freed.
*/
int gk_ldap_parse_result (GK_LDAP *ld, LDAPMessage *res,
			  int *errcodep, char **matcheddnp, char **errmsgp,
			  char ***referralsp, LDAPControl ***serverctrls,
			  int freeit);

int gk_ldap_parse_sasl_bind_result (GK_LDAP *ld, LDAPMessage *res,
				    struct berval **servercredp, int freeit);

/// Get the textual representation of a numeric error.
const char * gk_ldap_err2string (int err);

/* deprecated */
/// Get the error from a LDAPMessage.
int gk_ldap_result2error (GK_LDAP *ld, LDAPMessage *res, int freeit);

/* deprecated */
/// Print the textual error with a "string" in front.
void gk_ldap_perror (GK_LDAP *ld,  char const *s);

/* Stepping through results */
/// Get the first message of a chain.
LDAPMessage * gk_ldap_first_message (GK_LDAP *ld, LDAPMessage *chain);

/// Get the following message of a chain.
LDAPMessage * gk_ldap_next_message (GK_LDAP *ld, LDAPMessage *msg);

/// Count messages in chain.
int gk_ldap_count_messages (GK_LDAP *ld, LDAPMessage *chain);

/* Stepping through lists of entries or references */

/// Get first (LDAP) entry of chain.
LDAPMessage * gk_ldap_first_entry (GK_LDAP *ld, LDAPMessage *chain);

/// Get next (LDAP) entry of chain.
LDAPMessage * gk_ldap_next_entry (GK_LDAP *ld, LDAPMessage *entry);

/// Count (LDAP) entries of chain.
int gk_ldap_count_entries (GK_LDAP *ld, LDAPMessage *chain);

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)
LDAPMessage * gk_ldap_first_reference (GK_LDAP *ld, LDAPMessage *chain);

LDAPMessage * gk_ldap_next_reference (GK_LDAP *ld, LDAPMessage *ref);

int gk_ldap_count_references (GK_LDAP *ld, LDAPMessage *chain);
#endif

/* Stepping through the attributes */
/// Get the first attribute from a LDAPMessage.
char * gk_ldap_first_attribute (GK_LDAP *ld, LDAPMessage *entry, BerElement **ber);

/// Get the next attribute from a LDAPMessage.
char * gk_ldap_next_attribute (GK_LDAP *ld, LDAPMessage *entry, BerElement *ber);

/* Retrieving the values of an attribute */

/// Get all values for an attribute from a LDAPMessage (as strings).
char ** gk_ldap_get_values (GK_LDAP *ld, LDAPMessage *entry, char const *target);

/// Get all values for an attribute from a LDAPMessage (as bervals).
struct berval ** gk_ldap_get_values_len (GK_LDAP *ld, LDAPMessage *entry,
					 char const *target);

/// Count values returned by gk_ldap_get_values
int gk_ldap_count_values (char **vals);

/// Count values returned by gk_ldap_get_values_len
int gk_ldap_count_values_len (struct berval **vals);

/* Retrieving the name of an entry */
/// get the DN of a LDAPMessage as a string.
char * gk_ldap_get_dn (GK_LDAP *ld, LDAPMessage *entry);

/// Get the user friendly notation of a DN.
char * gk_ldap_dn2ufn ( char *dn);

/// Get all entries from a DN.
char ** gk_ldap_explode_dn (char const *dn, int notypes);

/// Get all entries from a RDN.
char ** gk_ldap_explode_rdn (char const *rdn, int notypes);


/* Retrieving the controls of an entry */
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)

int gk_ldap_get_entry_controls (GK_LDAP *ld, LDAPMessage *entry,
				LDAPControl	***serverctrls);

#endif

/* Parsing references */
#if (LDAP_VERSION_MAX >= LDAP_VERSION3)

int gk_ldap_parse_reference (GK_LDAP *ld, LDAPMessage *ref,
			     char ***referralsp, LDAPControl ***serverctrls, int freeit);

#endif

//@}

/* freeing memory */
/** @name Freeing memory returned by the gk_ldap API
 */
//@{

#if (LDAP_VERSION_MAX >= LDAP_VERSION3)

void gk_ldap_control_free (LDAPControl *ctrl);

void gk_ldap_controls_free (LDAPControl **ctrl);

#endif

/// Frees the structure LDAPMessage.
int gk_ldap_msgfree (LDAPMessage *lm);

/// Frees the char ** returned by gk_ldap_get_values.
void gk_ldap_value_free (char **vals);

/// Frees the struct berval ** returned by gk_ldap_get_values_len.
void gk_ldap_value_free_len (struct berval **vals);

/// Frees any char * returned by gk_ldap-API functions
void gk_ldap_memfree (char *mem);

//@}

// gk_ldap_cache-functions.

int gk_ldap_cache_check(GK_LDAP *ld, char const *base, int scope, char const *filter,  char **attrs, int attrsonly);

LDAPMessage * gk_ldap_cache_get_message(GK_LDAP *ld, int messageid);

void gk_ldap_cache_add_searchresult(GK_LDAP *ld,  char const *base, int scope, char const *filter, char **attrs,
				    int attrsonly, LDAPMessage *res);

int gk_ldap_cache_check_compare(GK_LDAP *ld,  char const *dn, char const *attr, struct berval bv);

void gk_ldap_cache_abandon(GK_LDAP *ld, int msgid);

LDAPMessage * gk_ldap_cache_get_result(GK_LDAP *ld, int msgid, int all);

void gk_ldap_add_result_by_id(GK_LDAP *ld, int msgid, int all, LDAPMessage *result);

void gk_ldap_cache_enable(GK_LDAP *ld, int timeout, int maxmem);

#define GK_LDAP_SIZEOF_REQUEST 10

void gk_ldap_cache_delete_oldest(GK_LDAP *ld);

void gk_ldap_cache_delete(GK_LDAP *ld, int timeout, int maxmem);

#endif /* GK_LDAP_H */
//
// End of gk_ldap_interface.h
//
