//////////////////////////////////////////////////////////////////
//
// H.323 utility functions that should migrate into the OpenH323 library
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
// 	991129	initial version (Henrik Joerring)
//
//////////////////////////////////////////////////////////////////


#ifndef H323UTIL_H
#define H323UTIL_H

#include "ptlib.h"
#include "ptlib/sockets.h"
#include "h225.h"


PString AsString(const H225_TransportAddress & ta);

PString AsString(const H225_EndpointType & terminalType);

PString AsString(const H225_AliasAddress & terminalAlias, BOOL includeAliasName = TRUE);

PString AsString(const H225_ArrayOf_AliasAddress & terminalAlias, BOOL includeAliasName = TRUE);

PString AsString(const PASN_OctetString & Octets);

bool AliasEqualN(H225_AliasAddress AliasA, H225_AliasAddress AliasB, int n);

// convert a socket IP address into an H225 transport address
H225_TransportAddress SocketToH225TransportAddr(const PIPSocket::Address & Addr, WORD Port);

void ReloadHandler(void);

#endif
