//////////////////////////////////////////////////////////////////
//
// H.323 utility functions that should migrate into the OpenH323 library
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	991129	initial version (Henrik Joerring)
//
//////////////////////////////////////////////////////////////////


#ifndef H323UTIL_H
#define H323UTIL_H "@(#) $Id$"

#include <ptlib.h>
#include <ptlib/sockets.h>


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

PString AsString(const H225_AliasAddress & terminalAlias, BOOL includeAliasName = TRUE);

PString AsString(const H225_ArrayOf_AliasAddress & terminalAlias, BOOL includeAliasName = TRUE);

PString AsString(const PASN_OctetString & Octets);

// convert a socket IP address into an H225 transport address
H225_TransportAddress SocketToH225TransportAddr(const PIPSocket::Address & Addr, WORD Port);

bool GetTransportAddress(const PString & addr, WORD def_port, PIPSocket::Address & ip, WORD & port);

bool GetTransportAddress(const PString & addr, WORD def_port, H225_TransportAddress & Result);

bool GetIPFromTransportAddr(const H225_TransportAddress & addr, PIPSocket::Address & ip);

bool GetIPAndPortFromTransportAddr(const H225_TransportAddress & addr, PIPSocket::Address & ip, WORD & port);

bool IsLoopback(const PIPSocket::Address &);

/** Find alias that matches best passed alias types,
	in order of precedence. Example usage:
	
	GetBestAliasAddressString( aliases, 
		H225_AliasAddress::e_dialedDigits,
		H225_AliasAddress::e_partyNumber,
		H225_AliasAddress::e_h323_ID
		);
		
	Finds first alias that is of type dialedDigits. 
	If dialedDigits is not found, it searches for the first
	partyNumber type alias, then for H.323 ID. If no alias
	is found, first alias from the array is returned or an empty
	string, if zero-length array is passed.
*/
PString GetBestAliasAddressString( 
	const H225_ArrayOf_AliasAddress& aliases, /// aliases to be searched
	int tag = -1, /// the most wanted alias type
	int tag2 = -1, /// if alias type #tag# not found
	int tag3 = -1, /// if alias types #tag# and #tag2# not found
	int tag4 = -1 /// if alias types #tag#, #tag2# and #tag3# not found
	);
	
#endif // H323UTIL_H
