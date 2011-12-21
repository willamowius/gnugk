//////////////////////////////////////////////////////////////////
//
// H.323 utility functions
//
// Copyright (c) 2000-2011, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <h323pdu.h>
#include "gk_const.h"
#include "config.h"
#include "h323util.h"


#if defined(_WIN32) && defined(hasIPV6)
// Windows doesn't have inet_ntop, so we fake it
const char * inet_ntop(int family, const void *src, char *dst, socklen_t cnt)
{
	if (family == AF_INET) {
		struct sockaddr_in in;
		memset(&in, 0, sizeof(in));
		in.sin_family = AF_INET;
		memcpy(&in.sin_addr, src, sizeof(struct in_addr));
		getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
		return dst;
	} else if (family == AF_INET6) {
		struct sockaddr_in6 in;
		memset(&in, 0, sizeof(in));
		in.sin6_family = AF_INET6;
		memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
		getnameinfo((struct sockaddr *)&in, sizeof(struct
		sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
		return dst;
	}
	return NULL;
}
#endif

PString AsString(const PIPSocket::Address & ip)
{
	if (ip.GetVersion() == 4)
		return PString(PString::Printf, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
#ifdef hasIPV6
  	if (ip.GetVersion() == 6) {
		char buf[INET6_ADDRSTRLEN];
		sockaddr_in6 ipv6addr;
		memset(&ipv6addr, 0, sizeof(ipv6addr));
		ipv6addr.sin6_addr = ip;
		return inet_ntop(AF_INET6, &ipv6addr.sin6_addr, buf, INET6_ADDRSTRLEN);
	}
#endif
	return ip.AsString();
}

PString AsString(const PIPSocket::Address & ip, WORD pt)
{
	if (ip.GetVersion() == 4)
		return PString(PString::Printf, "%d.%d.%d.%d:%u", ip[0], ip[1], ip[2], ip[3], pt);
	if (ip.GetVersion() == 6) {
		return "[" + AsString(ip) + "]:" + PString(pt);
	}
	return ip.AsString() + ":" + PString(pt);
}

PString AsString(const H245_UnicastAddress & ip)
{
	if (ip.GetTag() == H245_UnicastAddress::e_iPAddress) {
		const H245_UnicastAddress_iPAddress & ipv4 = ip;
		return AsString(ipv4);
	} else if (ip.GetTag() == H245_UnicastAddress::e_iP6Address) {
		const H245_UnicastAddress_iP6Address & ipv6 = ip;
		return AsString(ipv6);
	} else {
		return "unsupported H.245 address (" + ip.GetTagName() + ")";
	}
}

PString AsString(const H245_UnicastAddress_iPAddress & ipv4)
{
	return AsString(
		PIPSocket::Address(ipv4.m_network.GetSize(), ipv4.m_network.GetValue()),
		ipv4.m_tsapIdentifier);
}

PString AsString(const H245_UnicastAddress_iP6Address & ipv6)
{
	return AsString(
		PIPSocket::Address(ipv6.m_network.GetSize(), ipv6.m_network.GetValue()),
		ipv6.m_tsapIdentifier);
}

WORD GetH245Port(const H245_UnicastAddress & addr)
{
	if (addr.GetTag() == H245_UnicastAddress::e_iPAddress) {
		const H245_UnicastAddress_iPAddress & ipv4 = addr;
		return ipv4.m_tsapIdentifier;
	} else if (addr.GetTag() == H245_UnicastAddress::e_iP6Address) {
		const H245_UnicastAddress_iP6Address & ipv6 = addr;
		return ipv6.m_tsapIdentifier;
	} else {
		return 0;
	}
}

void SetH245Port(H245_UnicastAddress & addr, WORD port)
{
	if (addr.GetTag() == H245_UnicastAddress::e_iPAddress) {
		H245_UnicastAddress_iPAddress & ipv4 = addr;
		ipv4.m_tsapIdentifier = port;
	} else if (addr.GetTag() == H245_UnicastAddress::e_iP6Address) {
		H245_UnicastAddress_iP6Address & ipv6 = addr;
		ipv6.m_tsapIdentifier = port;
	}
}

PString AsString(const H225_TransportAddress & ta)
{
	PStringStream stream;
	stream << ta;
	return stream;
}

PString AsDotString(const H225_TransportAddress & addr, bool showPort)
{
	PString result = "invalid address";
	PIPSocket::Address ip;
	WORD port = 0;
	if (GetIPAndPortFromTransportAddr(addr, ip, port)) {
		if (showPort)
			result = AsString(ip, port);
		else
			result = AsString(ip);
	}
	return result;
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

PString AsString(const H225_AliasAddress & terminalAlias, bool includeAliasType)
{
	if(!terminalAlias.IsValid())
		return includeAliasType ? "invalid:UnknownType" : "invalid";

	switch (terminalAlias.GetTag()) {
		case H225_AliasAddress::e_dialedDigits:
		case H225_AliasAddress::e_url_ID:
		case H225_AliasAddress::e_email_ID:
		case H225_AliasAddress::e_h323_ID:
		case H225_AliasAddress::e_transportID:
		case H225_AliasAddress::e_partyNumber:
			PString aliasString = H323GetAliasAddressString(terminalAlias);
			// OpenH323 prepends a special prefix to partyNumbers
			// to distinguish a number subtype - we don't need this
			if (terminalAlias.GetTag() == H225_AliasAddress::e_partyNumber) {
				const PINDEX prefixIndex = aliasString.Find(':');
				if (prefixIndex != P_MAX_INDEX)
					aliasString = aliasString.Mid(prefixIndex + 1);
			}
			if (includeAliasType) {
				aliasString += ":" + terminalAlias.GetTagName();
			}
			return aliasString;
			break;
	}

	return includeAliasType ? "none:UnknownType" : "none";
}


PString AsString(const H225_ArrayOf_AliasAddress & terminalAlias, bool includeAliasName)
{
	PString aliasListString = PString::Empty();

	for(PINDEX cnt = 0; cnt < terminalAlias.GetSize(); cnt++ )
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

PString AsString(const PBYTEArray & array)
{
	PString result;
	for (PINDEX i = 0; i < array.GetSize(); i++) {
		if (isprint(array[i]))
			result += array[i];
	}
	return result;
}

PString StripAliasType(const PString & alias)
{
	const PINDEX nameIndex = alias.FindLast(':');
	if (nameIndex != P_MAX_INDEX) {
		return alias.Left(nameIndex);
	} else {
		// nothing to strip
		return alias;
	}
}

H245_TransportAddress IPToH245TransportAddr(const PIPSocket::Address & ip, WORD Port)
{
	H245_TransportAddress Result;
	Result.SetTag(H245_TransportAddress::e_unicastAddress);
	H245_UnicastAddress & uniaddr = Result;

	if (ip.GetVersion() == 6) {
		uniaddr.SetTag(H245_UnicastAddress::e_iP6Address);
		H245_UnicastAddress_iP6Address & ipaddr = uniaddr;
		for (int i = 0; i < 16; ++i)
			ipaddr.m_network[i] = ip[i];
		ipaddr.m_tsapIdentifier = Port;
	} else {
		uniaddr.SetTag(H245_UnicastAddress::e_iPAddress);
		H245_UnicastAddress_iPAddress & ipaddr = uniaddr;
		for (int i = 0; i < 4; ++i)
			ipaddr.m_network[i] = ip[i];
		ipaddr.m_tsapIdentifier = Port;
	}

	return Result;
}

// convert a string (dot notation without port) into an H245 transport address
//H245_TransportAddress StringToH245TransportAddr(const PString & Addr, WORD Port)
//{
//	H245_TransportAddress Result;
//
//	Result.SetTag(H245_TransportAddress::e_unicastAddress);
//	H245_UnicastAddress & uniaddr = Result;
//	uniaddr.SetTag(H245_UnicastAddress::e_iPAddress);
//	H245_UnicastAddress_iPAddress & ipaddr = uniaddr;
//	PIPSocket::Address ip(Addr);
//	for (int i = 0; i < 4; ++i)
//		ipaddr.m_network[i] = ip[i];
//	ipaddr.m_tsapIdentifier = Port;
//
//	return Result;
//}

// convert a socket IP address into an H225 transport address
H225_TransportAddress SocketToH225TransportAddr(const PIPSocket::Address & Addr, WORD Port)
{
	H225_TransportAddress Result;

	if (Addr.GetVersion() == 6) {
		Result.SetTag( H225_TransportAddress::e_ip6Address );
		H225_TransportAddress_ip6Address & ResultIP = Result;
		for (int i = 0; i < 16; ++i)
			ResultIP.m_ip[i] = Addr[i];
		ResultIP.m_port = Port;
	} else {
		Result.SetTag( H225_TransportAddress::e_ipAddress );
		H225_TransportAddress_ipAddress & ResultIP = Result;

		for (int i = 0; i < 4; ++i)
			ResultIP.m_ip[i] = Addr[i];
		ResultIP.m_port = Port;
	}

	return Result;
}

bool GetTransportAddress(const PString & addr, WORD def_port, PIPSocket::Address & ip, WORD & port)
{
	PStringArray adr_parts = SplitIPAndPort(addr.Trim(), def_port);
	port = WORD(adr_parts[1].AsUnsigned());
	return PIPSocket::GetHostAddress(adr_parts[0], ip) != 0;
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
	if (!addr.IsValid())
		return false;
	if (addr.GetTag() == H225_TransportAddress::e_ipAddress) {
		const H225_TransportAddress_ipAddress & ipaddr = addr;
		ip = PIPSocket::Address(ipaddr.m_ip.GetSize(), (const BYTE*)ipaddr.m_ip);
		port = (WORD)ipaddr.m_port;
		return true;
	}
	if (addr.GetTag() == H225_TransportAddress::e_ip6Address) {
		const H225_TransportAddress_ip6Address & ipaddr = addr;
		ip = PIPSocket::Address(ipaddr.m_ip.GetSize(), (const BYTE*)ipaddr.m_ip);
		port = (WORD)ipaddr.m_port;
		return true;
	}
	 return false;
}

PStringArray SplitIPAndPort(const PString & str, WORD default_port)
{
	PStringArray result;
	if (!IsIPv6Address(str)) {
		result = str.Tokenise(":", FALSE);
		if (result.GetSize() == 1) {
			result.SetSize(2);
			result[1] = PString(PString::Unsigned, default_port);
		}
		return result;
	} else {
		if (str.Left(1) == "[") {
			result.SetSize(2);
			PINDEX n = str.FindLast(']');
			result[0] = str.Left(n);
			result[0].Replace("[", "", true);
			result[0].Replace("]", "", true);
			result[1] = str.Mid(n+2);
			if (result[1].GetLength() == 0)
				result[1] = PString(PString::Unsigned, default_port);
		} else {
			result.SetSize(2);
			result[0] = str;
			result[1] = PString(PString::Unsigned, default_port);
		}
		return result;
	}
}

void SetSockaddr(sockaddr_in & sin, const PIPSocket::Address & ip, WORD port)
{
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr = ip;
	sin.sin_port = htons(port);
}

void SetSockaddr(sockaddr_in & sin, const H323TransportAddress & addr)
{
	PIPSocket::Address ip;
	WORD port = 0;
	addr.GetIpAndPort(ip, port);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr = ip;
	sin.sin_port = htons(port);
}

void SetSockaddr(sockaddr_in & sin, const H245_UnicastAddress & addr)
{
	PStringArray parts = SplitIPAndPort(AsString(addr), 0);
	PIPSocket::Address ip(parts[0]);
	WORD port = (WORD)parts[1].AsUnsigned();
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr = ip;
	sin.sin_port = htons(port);
}

#ifdef hasIPV6
void SetSockaddr(sockaddr_in6 & sin6, const PIPSocket::Address & ip, WORD port)
{
	memset(&sin6, 0, sizeof(sin6));
	if (ip.GetVersion() == 6) {
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = ip;
		sin6.sin6_port = htons(port);
	} else {
		((struct sockaddr_in*)&sin6)->sin_family = AF_INET;
		((struct sockaddr_in*)&sin6)->sin_addr = ip;
		((struct sockaddr_in*)&sin6)->sin_port = htons(port);
	}
}

void SetSockaddr(sockaddr_in6 & sin6, const H323TransportAddress & addr)
{
	PIPSocket::Address ip;
	WORD port = 0;
	addr.GetIpAndPort(ip, port);
	memset(&sin6, 0, sizeof(sin6));
	if (ip.GetVersion() == 6) {
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = ip;
		sin6.sin6_port = htons(port);
	} else {
		((struct sockaddr_in*)&sin6)->sin_family = AF_INET;
		((struct sockaddr_in*)&sin6)->sin_addr = ip;
		((struct sockaddr_in*)&sin6)->sin_port = htons(port);
	}
}

void SetSockaddr(sockaddr_in6 & sin6, const H245_UnicastAddress & addr)
{
	PStringArray parts = SplitIPAndPort(AsString(addr), 0);
	PIPSocket::Address ip(parts[0]);
	WORD port = (WORD)parts[1].AsUnsigned();
	memset(&sin6, 0, sizeof(sin6));
	if (ip.GetVersion() == 6) {
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = ip;
		sin6.sin6_port = htons(port);
	} else {
		((struct sockaddr_in*)&sin6)->sin_family = AF_INET;
		((struct sockaddr_in*)&sin6)->sin_addr = ip;
		((struct sockaddr_in*)&sin6)->sin_port = htons(port);
	}
}
#endif

bool IsIPAddress(const PString & addr)
{
	return (IsIPv4Address(addr) || IsIPv6Address(addr));
}

bool IsIPv4Address(const PString & addr)
{
	static PRegularExpression ipPattern("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$", PRegularExpression::Extended);
	static PRegularExpression ipAndPortPattern("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+$", PRegularExpression::Extended);

	return ((addr.FindRegEx(ipPattern) != P_MAX_INDEX) || (addr.FindRegEx(ipAndPortPattern) != P_MAX_INDEX));
}

bool IsIPv6Address(PString addr)
{
	static PRegularExpression ipV6PortPattern("\\]:[0-9]+$", PRegularExpression::Extended);
	if (addr.Left(1) == "[") {
		if (addr.Right(1) == "]") {
			addr = addr.Mid(1, addr.GetLength() - 2);
		} else if (addr.FindRegEx(ipV6PortPattern) != P_MAX_INDEX) {
			addr = addr.Mid(1, addr.FindLast(']') - 1);
		}
	}
	struct addrinfo * result = NULL;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;
	bool isValid = (getaddrinfo((const char *)addr, NULL, &hints, &result) == 0);
	if (result)
		freeaddrinfo(result);
	return isValid;
}

unsigned GetVersion(const H225_TransportAddress & ta)
{
	if (ta.GetTag() == H225_TransportAddress::e_ipAddress) {
		return 4;
	}
	if (ta.GetTag() == H225_TransportAddress::e_ip6Address) {
		return 6;
	}
	return 0;
}

// convert an IPv4-mapped-IPv6 address into an IPv4 address, otherwise leave unchanged
void UnmapIPv4Address(PIPSocket::Address & addr)
{
#ifdef hasIPV6
	if ((addr.GetVersion() == 6) && addr.IsV4Mapped()) {
		PIPSocket::Address newAddr(addr[12], addr[13], addr[14], addr[15]);
		addr = newAddr;
	}
#endif
}

// convert an IPv4 address into an IPv4-mapped-IPv6 address,
// leave unchanged if IPv6 disabled or is already an IPv6 address
void MapIPv4Address(PIPSocket::Address & addr)
{
#ifdef hasIPV6
	if (addr.GetVersion() == 4) {
		BYTE mappedIP[16];
		memset(mappedIP, 0, sizeof(mappedIP));
		mappedIP[10] = 0xff;
		mappedIP[11] = 0xff;
		mappedIP[12] = addr[0];
		mappedIP[13] = addr[1];
		mappedIP[14] = addr[2];
		mappedIP[15] = addr[3];
		PIPSocket::Address newAddr(16, mappedIP);
		addr = newAddr;
	}
#endif
}


bool IsLoopback(const PIPSocket::Address & addr)
{
	return addr.IsLoopback() != 0;
}

bool IsSet(const H323TransportAddress & addr)
{
	return (addr != H323TransportAddress());
}

bool IsValidE164(const PString & s) 
{
	return (!s.IsEmpty() && strspn(s, "1234567890*#+,") == strlen(s));
}


PString GetGUIDString(
	const H225_GloballyUniqueID & id, /// 128-bit identifier to convert
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

/** convert a string into a call-id
 */
H225_CallIdentifier StringToCallId(PString CallId)
{
	H225_CallIdentifier result;
	CallId.Replace("-", "", true);
	CallId.Replace(" ", "", true);
	OpalGloballyUniqueID tmp_guid(CallId);
	result.m_guid = tmp_guid;
	return result;
}

PINDEX GetBestAliasAddressIndex(
	const H225_ArrayOf_AliasAddress & aliases, /// aliases to be searched
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
	const H225_ArrayOf_AliasAddress & aliases, /// aliases to be searched
	bool exactMatch, /// search only specified tags or find any alias
	unsigned primaryTags, /// ORed tag flags (BestAliasTagMask)
	unsigned secondaryTags /// ORed tag flags (BestAliasTagMask)
	)
{
	const PINDEX i = GetBestAliasAddressIndex(aliases, exactMatch, primaryTags, secondaryTags);
	if (i != P_MAX_INDEX)
		return AsString(aliases[i], FALSE);
	else
		return PString::Empty();
}

PINDEX FindAlias(
	const H225_ArrayOf_AliasAddress & aliases, /// the list of aliases to check
	const PString & alias /// alias to find on the list
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
	const PString & s, /// original string to rewrite
	const char* prefix, /// prefix string that matched
	const char* value /// new string that replaces the prefix string
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
			PTRACE(1, "GK\tInvalid rewrite rule (dots do not match) - "
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
