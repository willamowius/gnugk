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


#include "h323util.h"
#include "gk_const.h"
#include "h323pdu.h"


PString AsString(const PIPSocket::Address & ip, WORD pt)
{
	return PString(PString::Printf, "%d.%d.%d.%d:%u",
		ip[0], ip[1], ip[2], ip[3], pt);
}

PString AsString(const H225_TransportAddress & ta)
{
	PStringStream stream;
	stream << ta;
	return stream;
}

PString AsDotString(const H225_TransportAddress & ip)
{
	return (ip.GetTag() == H225_TransportAddress::e_ipAddress) ?
		AsString((const H225_TransportAddress_ipAddress &)ip) : PString();
}

PString AsString(const H225_TransportAddress_ipAddress & ip)
{
	return PString(PString::Printf, "%d.%d.%d.%d:%u",
		ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3],
		ip.m_port.GetValue());
}

PString AsString(const H225_EndpointType & terminalType)
{
	PString terminalTypeString;
			
	if (terminalType.HasOptionalField(H225_EndpointType::e_terminal))
		terminalTypeString = ",terminal";

	if (terminalType.HasOptionalField(H225_EndpointType::e_gateway))
		terminalTypeString += ",gateway";
	
	if (terminalType.HasOptionalField(H225_EndpointType::e_mcu))
		terminalTypeString += ",mcu";

	if (terminalType.HasOptionalField(H225_EndpointType::e_gatekeeper))
		terminalTypeString += ",gatekeeper";

/* vendor seems always to be set - this clutters up the display
	if (terminalType.HasOptionalField(H225_EndpointType::e_vendor))
		terminalTypeString += ",vendor";
*/

	if (terminalTypeString.IsEmpty())
		terminalTypeString = ",unknown";
	
	return terminalTypeString.Mid(1);
}

PString AsString(const H225_AliasAddress & terminalAlias, BOOL includeAliasName)
{
	PString aliasString;

	if(!terminalAlias.IsValid())
		return includeAliasName ? "invalid:UnknownType" : "invalid";

	switch (terminalAlias.GetTag()) {
		case H225_AliasAddress::e_dialedDigits:
		case H225_AliasAddress::e_url_ID:
		case H225_AliasAddress::e_email_ID:
		case H225_AliasAddress::e_h323_ID:
		case H225_AliasAddress::e_transportID:
		case H225_AliasAddress::e_partyNumber:
			aliasString = H323GetAliasAddressString(terminalAlias);
			if (includeAliasName) {
				aliasString += ":" + terminalAlias.GetTagName();
			}
			return aliasString;
			break;
	}

	return includeAliasName ? "none:UnknownType" : "none";
}


PString AsString(const H225_ArrayOf_AliasAddress & terminalAlias, BOOL includeAliasName)
{
	PString aliasListString = "";

	for(PINDEX cnt = 0; cnt < terminalAlias.GetSize(); cnt ++ )
	{

		aliasListString += AsString(terminalAlias[cnt], includeAliasName);

		if (cnt < (terminalAlias.GetSize() - 1)) {
			aliasListString += "=";
		}
	}
	return (aliasListString);
}


PString AsString(const PASN_OctetString & Octets)
{
	PString result;
	if (Octets.GetDataLength() > 0) {
		result = PString(PString::Printf, "%02x", Octets[0]);
		for (PINDEX i = 1; i < Octets.GetDataLength(); ++i)
			result += PString(PString::Printf, " %02x", Octets[i]);
	}
	return result;
}

// convert a socket IP address into an H225 transport address
H225_TransportAddress SocketToH225TransportAddr(const PIPSocket::Address & Addr, WORD Port)
{
	H225_TransportAddress Result;

	Result.SetTag( H225_TransportAddress::e_ipAddress );
	H225_TransportAddress_ipAddress & ResultIP = Result;

	for (int i = 0; i < 4; ++i)
		ResultIP.m_ip[i] = Addr[i];
	ResultIP.m_port  = Port;

	return Result;
}

bool GetTransportAddress(const PString & addr, WORD def_port, PIPSocket::Address & ip, WORD & port)
{
	PString ipAddr = addr.Trim();
	PINDEX p = ipAddr.Find(':');
	port = (p != P_MAX_INDEX) ? WORD(ipAddr.Mid(p+1).AsUnsigned()) : def_port;
	return PIPSocket::GetHostAddress(ipAddr.Left(p), ip) != 0;
}

bool GetTransportAddress(const PString & addr, WORD def_port, H225_TransportAddress & Result)
{
	PIPSocket::Address ip;
	WORD port;
	bool res = GetTransportAddress(addr, def_port, ip, port);
	if (res)
		Result = SocketToH225TransportAddr(ip, port);
	return res;
}

bool GetIPFromTransportAddr(const H225_TransportAddress & addr, PIPSocket::Address & ip)
{
	WORD port;
	return GetIPAndPortFromTransportAddr(addr, ip, port);
}

bool GetIPAndPortFromTransportAddr(const H225_TransportAddress & addr, PIPSocket::Address & ip, WORD & port)
{
	if (addr.GetTag() != H225_TransportAddress::e_ipAddress)
		return false;
	const H225_TransportAddress_ipAddress & ipaddr = addr;
	ip = *reinterpret_cast<const DWORD *>((const BYTE *)ipaddr.m_ip);
	port = ipaddr.m_port;
	return true;
}

bool IsLoopback(const PIPSocket::Address & addr)
{
#ifdef OPENH323_NEWVERSION
	return addr.IsLoopback() != 0;
#else
	return addr == PIPSocket::Address(127,0,0,1);
#endif
}

PString GetBestAliasAddressString( 
	const H225_ArrayOf_AliasAddress& aliases,
	int tag,
	int tag2,
	int tag3,
	int tag4
	)
{
	PINDEX i;
	
	if( tag != -1 )
		for( i = 0; i < aliases.GetSize(); i++ )
			if( aliases[i].GetTag() == (unsigned)tag )
				return H323GetAliasAddressString(aliases[i]);
			
	if( tag2 != -1 )
		for( i = 0; i < aliases.GetSize(); i++ )
			if( aliases[i].GetTag() == (unsigned)tag2 )
				return H323GetAliasAddressString(aliases[i]);
				
	if( tag3 != -1 )
		for( i = 0; i < aliases.GetSize(); i++ )
			if( aliases[i].GetTag() == (unsigned)tag3 )
				return H323GetAliasAddressString(aliases[i]);
				
	if( tag4 != -1 )
		for( i = 0; i < aliases.GetSize(); i++ )
			if( aliases[i].GetTag() == (unsigned)tag4 )
				return H323GetAliasAddressString(aliases[i]);

	if( aliases.GetSize() > 0 )
		return H323GetAliasAddressString(aliases[0]);
	else
		return PString();
}
