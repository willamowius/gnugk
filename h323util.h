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

class Q931;
class H225_CallIdentifier;
class H225_RasMessage;
class H225_TransportAddress;
class H225_TransportAddress_ipAddress;
class H225_EndpointType;
class H225_AliasAddress;
class H225_ArrayOf_AliasAddress;
class PASN_OctetString;

H225_CallIdentifier *GetCallIdentifier(const Q931 & m_q931);

bool SendRasPDU(H225_RasMessage & ras_msg, const H225_TransportAddress & dest);

PString AsString(const H225_TransportAddress & ta);

PString AsDotString(const H225_TransportAddress & ip);

PString AsString(const H225_TransportAddress_ipAddress & ip);

PString AsString(const H225_EndpointType & terminalType);

PString AsString(const H225_AliasAddress & terminalAlias, BOOL includeAliasName = TRUE);

PString AsString(const H225_ArrayOf_AliasAddress & terminalAlias, BOOL includeAliasName = TRUE);

PString AsString(const PASN_OctetString & Octets);

//bool AliasEqualN(H225_AliasAddress AliasA, H225_AliasAddress AliasB, int n);

// convert a socket IP address into an H225 transport address
H225_TransportAddress SocketToH225TransportAddr(const PIPSocket::Address & Addr, WORD Port);

#endif
