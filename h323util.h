//////////////////////////////////////////////////////////////////
//
// H.323 utility functions that should migrate into the OpenH323 library
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////


#ifndef H323UTIL_H
#define H323UTIL_H "@(#) $Id$"

#include <ptlib/sockets.h>

class H225_GloballyUniqueID;
class H225_TransportAddress;
class H225_TransportAddress_ipAddress;
class H225_EndpointType;
class H225_AliasAddress;
class H225_ArrayOf_AliasAddress;
class PASN_OctetString;

PString AsString(const PIPSocket::Address &, WORD);

PString AsString(const H225_TransportAddress & ta);

PString AsDotString(const H225_TransportAddress & ip);

PString AsString(const H225_TransportAddress_ipAddress & ip);

PString AsString(const H225_EndpointType & terminalType);

PString AsString(const H225_AliasAddress & terminalAlias, bool includeAliasName = TRUE);

PString AsString(const H225_ArrayOf_AliasAddress & terminalAlias, bool includeAliasName = TRUE);

PString AsString(const PASN_OctetString & Octets);

PString StripAliasType(const PString & alias);

// convert a socket IP address into an H225 transport address
H225_TransportAddress SocketToH225TransportAddr(const PIPSocket::Address & Addr, WORD Port);

bool GetTransportAddress(const PString & addr, WORD def_port, PIPSocket::Address & ip, WORD & port);

bool GetTransportAddress(const PString & addr, WORD def_port, H225_TransportAddress & Result);

bool GetIPFromTransportAddr(const H225_TransportAddress & addr, PIPSocket::Address & ip);

bool GetIPAndPortFromTransportAddr(const H225_TransportAddress & addr, PIPSocket::Address & ip, WORD & port);

bool IsIPAddress(const PString & addr);

bool IsRemoteNATSupport(const PString & addr);

bool IsLoopback(const PIPSocket::Address &);

/** Find an alias which tag is of type specified by #primaryTags#.
    If no such aliases are found, #secondaryTags# are examined.
    If still no match is found and #exactMatch# is false, the first
    alias on the list is returned.

    @return
    An index of the alias found or P_MAX_INDEX if there was no match.
*/
PINDEX GetBestAliasAddressIndex(
	const H225_ArrayOf_AliasAddress& aliases, /// aliases to be searched
	bool exactMatch, /// search only specified tags or find any alias
	unsigned primaryTags, /// ORed tag flags (AliasAddressTagMask)
	unsigned secondaryTags = 0 /// ORed tag flags (AliasAddressTagMask)
	);

/** @return
    An alias tag converted to a bit flag suitable to use with primaryTags
    or secondaryTags parameter to #GetBestAliasAddressIndex#.
*/
inline unsigned AliasAddressTagMask(unsigned tag) { return 1U << tag; }
	
/** Find an alias which tag is of type specified by #primaryTags#.
    If no such aliases are found, #secondaryTags# are examined.
    If still no match is found and #exactMatch# is false, the first
    alias on the list is returned.

    @return
    A string with the alias found or an empty string if there was no match.
*/
PString GetBestAliasAddressString(
	const H225_ArrayOf_AliasAddress& aliases, /// aliases to be searched
	bool exactMatch, /// search only specified tags or find any alias
	unsigned primaryTags, /// ORed tag flags (BestAliasTagMask)
	unsigned secondaryTags = 0 /// ORed tag flags (BestAliasTagMask)
	);

/** Return 128-bit globally unique identifier as a string composed of four 
    32-bit hex numbers, with leading zeros skipped or not. This format is 
    compatible with Cisco equipment.
	
    @return
    A string with properly formatted identifier.
*/
PString GetGUIDString(
	const H225_GloballyUniqueID& id, /// 128-bit identifier to convert
	bool fixedLength = false /// skip leading zeros (false) or not (true)
	);

/** Check if the given #alias# is present on the list of #aliases#.

    @return
    An index of the alias on the list or P_MAX_INDEX if the alias is not found.
*/
PINDEX FindAlias(
	const H225_ArrayOf_AliasAddress& aliases, /// the list of aliases to check
	const PString& alias /// alias to find on the list
	);

/** Check if the given alias matches the prefix. The prefix can be preceeded
    with '!' to force negative match and contain dots ('.') or percent signs ('%')
    to match any character.
	
    @return
    0 if no match is found, a positive integer if normal match is found 
    (the integer gives the match length) or a negative integer if '!' match is found
    (absolute value gives the match length).
*/
int MatchPrefix(
	const char* alias,
	const char* prefix
	);
	
/** Rewrite the string #s# replacing #prefix# with #value#. The #prefix# 
    and #value# strings can contain dots ('.') to copy source characters
    to the destination string. The #prefix# string can also contain percent
    signs ('%') to match any character and skip copying, as it is done in case
    of dots. Examples (prefix=value):
	
    49=111149 - this will change numbers like 497654321 into 1111497654321
	49..1=111149..1 - this will change numbers like 49771777 into 111149771777
	%%%%49=49 - this will change numbers like 777749123456 into 49123456
    %%%%.=. - tricky, but should work as a prefix stripper

	There are some restrictions:
	1.2.3=4.5.6 - this will work (112233 will be changed to 415263)
	1..2=1.2.3 - this will work (1122 will be changed to 11223)
	1.2.3=1..3 - this won't work
	
	The main idea is that "dot strips" on the right hand side of the rule
    have to match "dot strips" of the same length on the left hand side of the rule.
	
    @return	Rewritten string.
*/
PString RewriteString(
	const PString& s, /// original string to rewrite
	const char *prefix, /// prefix string that matched
	const char *value /// new string that replaces the prefix string
	);
	
	
#endif // H323UTIL_H
