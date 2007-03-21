//////////////////////////////////////////////////////////////////
//
// H.323 utility functions that should migrate into the OpenH323 library
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <h323pdu.h>
#include "gk_const.h"
#include "h323util.h"


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
	return (ip.IsValid() && ip.GetTag() == H225_TransportAddress::e_ipAddress) ?
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
			// OpenH323 prepends a special prefix to partyNumbers
			// to distinguish a number subtype - we don't need this
			if (terminalAlias.GetTag() == H225_AliasAddress::e_partyNumber) {
				const PINDEX prefixIndex = aliasString.Find(':');
				if (prefixIndex != P_MAX_INDEX)
					aliasString = aliasString.Mid(prefixIndex + 1);
			}
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
	if (!(addr.IsValid() && addr.GetTag() == H225_TransportAddress::e_ipAddress))
		return false;
	const H225_TransportAddress_ipAddress & ipaddr = addr;
	ip = PIPSocket::Address(ipaddr.m_ip.GetSize(), (const BYTE*)ipaddr.m_ip);
	port = (WORD)ipaddr.m_port;
	return true;
}

bool IsRemoteNATSupport(const PString & addr)
{
	PString ipAddr = addr.Trim();
	PINDEX p = ipAddr.Find('*');
	return (p != P_MAX_INDEX);
}

bool IsLoopback(const PIPSocket::Address & addr)
{
	return addr.IsLoopback() != 0;
}

PString GetGUIDString(
	const H225_GloballyUniqueID& id, /// 128-bit identifier to convert
	bool fixedLength /// skip leading zeros (false) or not (true)
	)
{
	if (id.GetSize() < 16)
		return "Invalid";
		
	PString idstr;
					
	for (int j = 0, i = 0; j < 4; j++) {
		const unsigned hex = ((unsigned)(id[i])<<24) | ((unsigned)(id[i+1])<<16) 
			| ((unsigned)(id[i+2])<<8) | ((unsigned)(id[i+3]));
		i += 4;
		
		idstr += fixedLength ? PString(PString::Printf, "%08x", hex)
			: PString(PString::Unsigned, (long)hex, 16);
		if (j < 3)
			idstr += ' ';
	}

	return idstr;
}

PINDEX GetBestAliasAddressIndex(
	const H225_ArrayOf_AliasAddress& aliases, /// aliases to be searched
	bool exactMatch, /// search only specified tags or find any alias
	unsigned primaryTags, /// ORed tag flags (BestAliasTagMask)
	unsigned secondaryTags /// ORed tag flags (BestAliasTagMask)
	)
{
	if (primaryTags)
		for (PINDEX i = 0; i < aliases.GetSize(); i++)
			if (primaryTags & (1U << aliases[i].GetTag()))
				return i;

	if (secondaryTags)
		for (PINDEX i = 0; i < aliases.GetSize(); i++)
			if (secondaryTags & (1U << aliases[i].GetTag()))
				return i;

	if (!exactMatch && aliases.GetSize() > 0)
		return 0;

	return P_MAX_INDEX;
}

PString GetBestAliasAddressString(
	const H225_ArrayOf_AliasAddress& aliases, /// aliases to be searched
	bool exactMatch, /// search only specified tags or find any alias
	unsigned primaryTags, /// ORed tag flags (BestAliasTagMask)
	unsigned secondaryTags /// ORed tag flags (BestAliasTagMask)
	)
{
	const PINDEX i = GetBestAliasAddressIndex(aliases, exactMatch,
		primaryTags, secondaryTags
		);
	if (i != P_MAX_INDEX)
		return AsString(aliases[i], FALSE);
	else
		return PString();
}

PINDEX FindAlias(
	const H225_ArrayOf_AliasAddress& aliases, /// the list of aliases to check
	const PString& alias /// alias to find on the list
	)
{
	const PINDEX sz = aliases.GetSize();
	for (PINDEX i = 0; i < sz; i++)
		if (alias == AsString(aliases[i], FALSE))
			return i;
			
	return P_MAX_INDEX;
}

int MatchPrefix(
	const char* alias,
	const char* prefix
	)
{
	if (alias == NULL || prefix == NULL)
		return 0;

	const bool negative = (prefix[0] == '!');
	
	int i = 0;
	int j = (negative ? 1 : 0);
	
	while (prefix[j] != 0) {
		const char c = prefix[j];
		if (alias[i] == 0 || (c != '.' && c != '%' && c != alias[i]))
			return 0;
		i++;
		j++;
	}
	
	return negative ? -j + 1 : j;
}

PString RewriteString(
	const PString& s, /// original string to rewrite
	const char *prefix, /// prefix string that matched
	const char *value /// new string that replaces the prefix string
	)
{
	if (prefix == NULL || value == NULL)
		return s;
	
	PString result = value + s.Mid(strlen(prefix));

	const char *lastSrcDot = prefix;
	const char *lastDstDot = strchr(value, '.');
	while (lastDstDot != NULL) {
		lastSrcDot = strchr(lastSrcDot, '.');
		if (lastSrcDot == NULL) {
			PTRACE(0, "GK\tInvalid rewrite rule (dots do not match) - "
				<< prefix << " = " << value
				);
			break;
		}
		int dotDstOffset = (long)lastDstDot - (long)value;
		int dotSrcOffset = (long)lastSrcDot - (long)prefix;
		while (*lastDstDot++ == '.' && *lastSrcDot++ == '.')
			result[dotDstOffset++] = s[dotSrcOffset++];
						
		lastDstDot = strchr(lastDstDot, '.');
	}
	
	return result;
}
