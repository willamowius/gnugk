/*
 * h323util.t.cxx
 *
 * unit tests for h323util.cxx
 *
 * Copyright (c) 2011-2024, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"
#include "h323util.h"
#include "gk_const.h"
#include "Toolkit.h"
#include <h323pdu.h>
#include "gtest/gtest.h"

namespace {

class H323UtilTest : public ::testing::Test {
protected:
	H323UtilTest() {
		// H.245 IPs
		h245unicast.SetTag(H245_UnicastAddress::e_iPAddress);
		H245_UnicastAddress_iPAddress & ip = h245unicast;
		ip.m_network.SetSize(4);
		ip.m_network[0] = 1;
		ip.m_network[1] = 2;
		ip.m_network[2] = 3;
		ip.m_network[3] = 4;
		ip.m_tsapIdentifier = 555;
		h245ipv4 = ip;
		// sockets
		ipv4socket = "3.4.5.6";
		ipv6socket = "2001:0db8:85a3:08d3:1319:8a2e:0370:7344";
		ipv6socket_localhost = "::1";
		ipv6socket_ipv4mapped = "::ffff:192.168.1.100";
		// H.225 IPs
		h225transport_withipv4 = SocketToH225TransportAddr(ipv4socket, 999);
		h225transport_withipv6 = SocketToH225TransportAddr(ipv6socket, 1111);
		h225transport_withipv6localhost = SocketToH225TransportAddr(ipv6socket_localhost, 1111);
		h323transport_withipv4 = H323TransportAddress(PIPSocket::Address("6.7.8.9"), 4567);
		h323transport_withipv6 = H323TransportAddress(PIPSocket::Address("2001:0db8:85a3:08d3:1319:8a2e:0370:7344"), 5678);
	}

	H245_UnicastAddress h245unicast;
	H245_UnicastAddress_iPAddress h245ipv4;
	PIPSocket::Address ipv4socket;
	PIPSocket::Address ipv6socket;
	PIPSocket::Address ipv6socket_localhost;
	PIPSocket::Address ipv6socket_ipv4mapped;
	H225_TransportAddress h225transport_withipv4;
	H225_TransportAddress h225transport_withipv6;
	H225_TransportAddress h225transport_withipv6localhost;
	H323TransportAddress h323transport_withipv4;
	H323TransportAddress h323transport_withipv6;
};


TEST_F(H323UtilTest, PIPSocketAddressAsString) {
	EXPECT_STREQ("3.4.5.6:777", AsString(ipv4socket, 777));
	EXPECT_STREQ("[2001:db8:85a3:8d3:1319:8a2e:370:7344]:888", AsString(ipv6socket, 888));
	EXPECT_STREQ("[::1]:888", AsString(ipv6socket_localhost, 888));
	EXPECT_STREQ("::1", AsString(ipv6socket_localhost));
}

TEST_F(H323UtilTest, H245UnicastIPAddressAsString) {
	EXPECT_STREQ("1.2.3.4:555", AsString(h245unicast));
	EXPECT_STREQ("1.2.3.4:555", AsString(h245ipv4));
}

TEST_F(H323UtilTest, H323ToH225TransportAddress) {
	EXPECT_STREQ("6.7.8.9:4567", AsDotString(H323ToH225TransportAddress(h323transport_withipv4)));
}

TEST_F(H323UtilTest, H245Port) {
	EXPECT_EQ(555, GetH245Port(h245unicast));
	SetH245Port(h245unicast, 999);
	EXPECT_EQ(999, GetH245Port(h245unicast));
}

TEST_F(H323UtilTest, H225TransportAddressAsString) {
	EXPECT_STREQ("3.4.5.6:999", AsString(h225transport_withipv4));
	//EXPECT_TRUE(AsString(h225transport_withipv4).Find("03 04 05 06") != P_MAX_INDEX); // behaviour changed!
	EXPECT_STREQ("3.4.5.6:999", AsDotString(h225transport_withipv4));
	EXPECT_STREQ("3.4.5.6:999", AsDotString(h225transport_withipv4));
	EXPECT_STREQ("3.4.5.6:999", AsDotString(h225transport_withipv4, true));
	EXPECT_STREQ("3.4.5.6",     AsDotString(h225transport_withipv4, false));
	EXPECT_STREQ("[2001:db8:85a3:8d3:1319:8a2e:370:7344]:1111", AsDotString(h225transport_withipv6));
	EXPECT_STREQ("[::1]:1111", AsDotString(h225transport_withipv6localhost));
	EXPECT_STREQ("[2001:db8:85a3:8d3:1319:8a2e:370:7344]:1111", AsDotString(h225transport_withipv6, true));
	EXPECT_STREQ("2001:db8:85a3:8d3:1319:8a2e:370:7344",        AsDotString(h225transport_withipv6, false));
}

TEST_F(H323UtilTest, H225Port) {
	EXPECT_EQ(999, GetH225Port(h225transport_withipv4));
	SetH225Port(h225transport_withipv4, 444);
	EXPECT_EQ(444, GetH225Port(h225transport_withipv4));
	EXPECT_EQ(1111, GetH225Port(h225transport_withipv6));
	SetH225Port(h225transport_withipv6, 3333);
	EXPECT_EQ(3333, GetH225Port(h225transport_withipv6));
}

TEST_F(H323UtilTest, H323TransportAddressAsString) {
	EXPECT_STREQ("", AsString(H323TransportAddress()));
	EXPECT_STREQ("6.7.8.9:4567", AsString(h323transport_withipv4));
	EXPECT_STREQ("[2001:db8:85a3:8d3:1319:8a2e:370:7344]:5678", AsString(h323transport_withipv6));
}

TEST_F(H323UtilTest, H225TransportAddressGetVersion) {
	EXPECT_EQ(4u, GetVersion(h225transport_withipv4));
	EXPECT_EQ(4u, GetVersion(H225_TransportAddress()));	// empty H225_TransportAddress defaults to IPv4
	EXPECT_EQ(6u, GetVersion(h225transport_withipv6));
	EXPECT_EQ(6u, GetVersion(h225transport_withipv6localhost));
}

TEST_F(H323UtilTest, EndpointTypeAsString) {
	H225_EndpointType ep_type;
	EXPECT_STREQ("unknown", AsString(ep_type));
	ep_type.IncludeOptionalField(H225_EndpointType::e_terminal);
	EXPECT_STREQ("terminal", AsString(ep_type));
	ep_type.IncludeOptionalField(H225_EndpointType::e_gateway);
	ep_type.IncludeOptionalField(H225_EndpointType::e_mcu);
	ep_type.IncludeOptionalField(H225_EndpointType::e_gatekeeper);
	EXPECT_STREQ("terminal,gateway,mcu,gatekeeper", AsString(ep_type));
}

TEST_F(H323UtilTest, AliasAsString) {
	H225_AliasAddress alias;
	EXPECT_STREQ("invalid:UnknownType", AsString(alias, true));
	EXPECT_STREQ("invalid", AsString(alias, false));
	H323SetAliasAddress(PString("jan"), alias);
	EXPECT_STREQ("jan:h323_ID", AsString(alias, true));
	EXPECT_STREQ("jan", AsString(alias, false));
	EXPECT_STREQ(AsString(alias, false), StripAliasType(AsString(alias, true)));
	H323SetAliasAddress(PString("1234"), alias);
	EXPECT_STREQ("1234:dialedDigits", AsString(alias, true));
	EXPECT_STREQ("1234", AsString(alias, false));
	EXPECT_STREQ(AsString(alias, false), StripAliasType(AsString(alias, true)));
	H323SetAliasAddress(PString("1234@example.com"), alias);
	EXPECT_STREQ("1234@example.com:url_ID", AsString(alias, true));
	EXPECT_STREQ("1234@example.com", AsString(alias, false));
	H323SetAliasAddress(PString("h323:1234@example.com"), alias);
	EXPECT_STREQ("1234@example.com:url_ID", AsString(alias, true));
	EXPECT_STREQ("1234@example.com", AsString(alias, false));
}

TEST_F(H323UtilTest, ArrayOfAliasAsString) {
	H225_ArrayOf_AliasAddress aliases;
	EXPECT_STREQ("", AsString(aliases, true));
	EXPECT_STREQ("", AsString(aliases, false));
	aliases.SetSize(1);
	H323SetAliasAddress(PString("jan"), aliases[0]);
	EXPECT_STREQ("jan:h323_ID", AsString(aliases, true));
	EXPECT_STREQ("jan", AsString(aliases, false));
	aliases.SetSize(2);
	H323SetAliasAddress(PString("1234"), aliases[1]);
	EXPECT_STREQ("jan:h323_ID=1234:dialedDigits", AsString(aliases, true));
	EXPECT_STREQ("jan=1234", AsString(aliases, false));
}

TEST_F(H323UtilTest, OctetStringAsString) {
	PASN_OctetString bytes;
	bytes.SetSize(4);
	bytes[0] = 1;
	bytes[1] = 2;
	bytes[2] = 3;
	bytes[3] = 10;
	EXPECT_STREQ("01 02 03 0a", AsString(bytes));
}

TEST_F(H323UtilTest, ByteArrayAsString) {
	PBYTEArray bytes;
	bytes.SetSize(4);
	bytes[0] = 'a';
	bytes[1] = 'b';
	bytes[2] = 07;
	bytes[3] = 'c';
	EXPECT_STREQ("abc", AsString(bytes));
}

TEST_F(H323UtilTest, Is10Dor11Dnumber) {
	H225_AliasAddress alias;
	H323SetAliasAddress(PString("jan"), alias);
	EXPECT_FALSE(Is10Dor11Dnumber(alias));
	H323SetAliasAddress(PString("123456789"), alias);
	EXPECT_FALSE(Is10Dor11Dnumber(alias));
	H323SetAliasAddress(PString("123456789012"), alias);
	EXPECT_FALSE(Is10Dor11Dnumber(alias));
	H323SetAliasAddress(PString("10000000000"), alias);
	EXPECT_FALSE(Is10Dor11Dnumber(alias));
	H323SetAliasAddress(PString("0000000000"), alias);
	EXPECT_FALSE(Is10Dor11Dnumber(alias));
	H323SetAliasAddress(PString("1238888777"), alias);
	EXPECT_FALSE(Is10Dor11Dnumber(alias));
	H323SetAliasAddress(PString("2238888777"), alias);
	EXPECT_TRUE(Is10Dor11Dnumber(alias));
	H323SetAliasAddress(PString("2008888777"), alias);
	EXPECT_TRUE(Is10Dor11Dnumber(alias));
	H323SetAliasAddress(PString("2008000000"), alias);
	EXPECT_TRUE(Is10Dor11Dnumber(alias));
}

TEST_F(H323UtilTest, SetSockaddr) {
	// H323TransportAddress IPv4 version
	struct sockaddr_in sin;
	SetSockaddr(sin, h323transport_withipv4);
	WORD port = ntohs(sin.sin_port);
	EXPECT_EQ(port, 4567);
	// H245_UnicastAddress IPv4 version
	SetSockaddr(sin, h245unicast);
	port = ntohs(sin.sin_port);
	EXPECT_EQ(port, 555);
	// PIPSocket::Address IPv4 version
	SetSockaddr(sin, ipv4socket, 333);
	port = ntohs(sin.sin_port);
	EXPECT_EQ(port, 333);
#ifdef hasIPV6
	// H323TransportAddress IPv6 version
	struct sockaddr_in6 sin6;
	SetSockaddr(sin6, h323transport_withipv4);
	port = ntohs(sin6.sin6_port);
	EXPECT_EQ(port, 4567);
	SetSockaddr(sin6, h323transport_withipv6);
	port = ntohs(sin6.sin6_port);
	EXPECT_EQ(port, 5678);
	// PIPSocket::Address IPv6 version
	SetSockaddr(sin6, ipv6socket, 444);
	port = ntohs(sin6.sin6_port);
	EXPECT_EQ(port, 444);
#endif
}

TEST_F(H323UtilTest, IsIPAddress) {
	EXPECT_TRUE(IsIPAddress("1.2.3.4"));
	EXPECT_TRUE(IsIPAddress("1.2.3.4:999"));
	EXPECT_TRUE(IsIPAddress("255.255.255.255"));
	EXPECT_TRUE(IsIPAddress("2001:0db8:85a3:08d3:1319:8a2e:0370:7344"));
	EXPECT_TRUE(IsIPAddress("::1"));
	EXPECT_FALSE(IsIPAddress("a.b.c.d"));
	EXPECT_FALSE(IsIPAddress("1.2.3.4.5"));
	EXPECT_FALSE(IsIPAddress("1.2.3.4:"));
}

TEST_F(H323UtilTest, IsIPv6Address) {
	EXPECT_TRUE(IsIPv6Address("2001:0db8:85a3:08d3:1319:8a2e:0370:7344"));
	EXPECT_TRUE(IsIPv6Address("2001:0db8:0000:08d3:0000:8a2e:0070:7344"));
	EXPECT_TRUE(IsIPv6Address("2001:db8:0:8d3:0:8a2e:70:7344"));
	EXPECT_TRUE(IsIPv6Address("[2001:0db8:85a3:08d3:1319:8a2e:0370:7344]"));
	EXPECT_TRUE(IsIPv6Address("[2001:0db8:85a3:08d3:1319:8a2e:0370:7344]:1234"));
	EXPECT_TRUE(IsIPv6Address("::1"));
	EXPECT_FALSE(IsIPv6Address("1.2.3.4"));
	EXPECT_FALSE(IsIPv6Address("abcd"));
	EXPECT_FALSE(IsIPv6Address(""));
}

TEST_F(H323UtilTest, UnmapIPv4Address) {
	PIPSocket::Address ip = ipv6socket_ipv4mapped;
	UnmapIPv4Address(ip);
	EXPECT_EQ(4u, ip.GetVersion());
	ip = ipv4socket;
	UnmapIPv4Address(ip);
	EXPECT_EQ(4u, ip.GetVersion());
	ip = ipv6socket;
	UnmapIPv4Address(ip);
	EXPECT_EQ(6u, ip.GetVersion());
}

TEST_F(H323UtilTest, MapIPv4Address) {
	PIPSocket::Address ip = ipv4socket;
	MapIPv4Address(ip);
	EXPECT_EQ(6u, ip.GetVersion());
	UnmapIPv4Address(ip);
	EXPECT_EQ(ip, ipv4socket);
	ip = ipv6socket;
	MapIPv4Address(ip);
	EXPECT_EQ(6u, ip.GetVersion());
}

TEST_F(H323UtilTest, IsLoopback) {
	PIPSocket::Address ip;
	EXPECT_TRUE(IsLoopback(ip));
}

TEST_F(H323UtilTest, IsLocal) {
	PIPSocket::Address ip4_1("192.168.1.12");// private
	PIPSocket::Address ip4_2("193.0.0.1");   // public
	PIPSocket::Address ip4_3("100.64.0.1");  // Shared Network Address
	PIPSocket::Address ip4_4("169.254.0.1"); // Zeroconf

	PIPSocket::Address ip6_1("fe80::1");    // link local
	PIPSocket::Address ip6_2("fec0::1");    // site local
	PIPSocket::Address ip6_2_n("ff00::1");  // NOT site local
	PIPSocket::Address ip6_3("fc00::1");    // unique local
	PIPSocket::Address ip6_3_n("ff00::1");  // NOT unique local
	PIPSocket::Address ip6_4("fd9e:21a7:a92c:2323::1");    // unique local
	PIPSocket::Address ip6_5("fb9e:21a7:a92c:2323::1");    // public

	EXPECT_TRUE(IsPrivate(ip4_1));
	EXPECT_FALSE(IsPrivate(ip4_2));
	EXPECT_TRUE(IsPrivate(ip4_3));
	EXPECT_TRUE(IsPrivate(ip4_4));

	EXPECT_TRUE(IsPrivate(ip6_1));
	EXPECT_TRUE(IsPrivate(ip6_2));
	EXPECT_FALSE(IsPrivate(ip6_2_n));
	EXPECT_TRUE(IsPrivate(ip6_3));
	EXPECT_FALSE(IsPrivate(ip6_3_n));
	EXPECT_TRUE(IsPrivate(ip6_4));
	EXPECT_FALSE(IsPrivate(ip6_5));
}

TEST_F(H323UtilTest, IsInNetwork) {
	PIPSocket::Address ip1("4.5.6.7");
	PIPSocket::Address ip2("4.5.7.1");
	PIPSocket::Address ip3("5.6.7.1");
	PIPSocket::Address ip4("192.168.86.48");
	PIPSocket::Address ip5("172.21.221.144");
    NetworkAddress net("4.5.6.0/24");
    NetworkAddress net2("5.6.7.0/24");
    NetworkAddress net3("172.21.0.0/16");
    list<NetworkAddress> net_list;
    net_list.push_back(net);
    net_list.push_back(net2);
    list<NetworkAddress> net_list2;
    net_list2.push_back(net3);
	EXPECT_TRUE(IsInNetwork(ip1, net));
	EXPECT_FALSE(IsInNetwork(ip2, net));
	EXPECT_TRUE(IsInNetwork(ip5, net3));
	EXPECT_TRUE(IsInNetworks(ip1, net_list));
	EXPECT_FALSE(IsInNetworks(ip2, net_list));
	EXPECT_TRUE(IsInNetworks(ip3, net_list));
	EXPECT_FALSE(IsInNetworks(ip4, net_list2));
	EXPECT_TRUE(IsInNetworks(ip5, net_list2));
}

TEST_F(H323UtilTest, IsSetH225) {
	PIPSocket::Address ip("4.5.6.7");
	WORD port = 123;
    H323TransportAddress h225addr;
	EXPECT_FALSE(IsSet(h225addr));
	h225addr = SocketToH225TransportAddr(ip, port);
	EXPECT_TRUE(IsSet(h225addr));
	h225addr = (DWORD)0;
	EXPECT_FALSE(IsSet(h225addr));
}

TEST_F(H323UtilTest, IsSetH323) {
	PIPSocket::Address ip("4.5.6.7");
	WORD port = 123;
    H323TransportAddress h323addr;
	EXPECT_FALSE(IsSet(h323addr));
	h323addr = H323TransportAddress(ip, port);
	EXPECT_TRUE(IsSet(h323addr));
}

TEST_F(H323UtilTest, SplitIPAndPort) {
	PStringArray parts;
	parts = SplitIPAndPort("1.2.3.4", 1234);
	EXPECT_STREQ(parts[0], "1.2.3.4");
	EXPECT_STREQ(parts[1], "1234");
	parts = SplitIPAndPort("1.2.3.4:1234", 1235);
	EXPECT_STREQ(parts[0], "1.2.3.4");
	EXPECT_STREQ(parts[1], "1234");
	parts = SplitIPAndPort("2001:0db8:85a3:08d3:1319:8a2e:0370:7344", 1234);
	EXPECT_STREQ(parts[0], "2001:0db8:85a3:08d3:1319:8a2e:0370:7344");
	EXPECT_STREQ(parts[1], "1234");
	parts = SplitIPAndPort("[2001:0db8:85a3:08d3:1319:8a2e:0370:7344]:1234", 1235);
	EXPECT_STREQ(parts[0], "2001:0db8:85a3:08d3:1319:8a2e:0370:7344");
	EXPECT_STREQ(parts[1], "1234");
}

TEST_F(H323UtilTest, GetIP) {
    PString str1 = "1.2.3.4";
    PString str2 = "4.5.6.7";
	PIPSocket::Address ip1("1.2.3.4");
	EXPECT_TRUE(GetIP(str1) == ip1);
	EXPECT_TRUE(AsString(GetIP(str2)) == "4.5.6.7");
	EXPECT_FALSE(AsString(GetIP(str1)) == "4.5.6.7");
}

TEST_F(H323UtilTest, GetGUIDString) {
	H225_GloballyUniqueID id;
	EXPECT_STREQ("00000000 00000000 00000000 00000000", GetGUIDString(id, true));
	EXPECT_STREQ("0 0 0 0", GetGUIDString(id, false));
	EXPECT_EQ(35, GetGUIDString(id, true).GetLength());
}

TEST_F(H323UtilTest, StringToCallId) {
	PString str = "00000000 00000000 00000000 00000000";
	H225_CallIdentifier callid = StringToCallId(str);
	EXPECT_STREQ("00000000 00000000 00000000 00000000", GetGUIDString(callid.m_guid, true));
	str = "00000001 00000020 00000300 00004000";
	callid = StringToCallId(str);
	EXPECT_STREQ("00000001 00000020 00000300 00004000", GetGUIDString(callid.m_guid, true));
}

TEST_F(H323UtilTest, FindAlias) {
	H225_ArrayOf_AliasAddress aliases;
	aliases.SetSize(2);
	H323SetAliasAddress(PString("jan"), aliases[0]);
	H323SetAliasAddress(PString("1234"), aliases[1]);
	EXPECT_EQ(0, FindAlias(aliases, "jan"));
	EXPECT_EQ(1, FindAlias(aliases, "1234"));
	EXPECT_EQ(P_MAX_INDEX, FindAlias(aliases, "9999"));
}

TEST_F(H323UtilTest, MatchPrefix) {
	EXPECT_EQ(0, MatchPrefix("123456789", "44"));
	EXPECT_EQ(3, MatchPrefix("123456789", "123"));
	EXPECT_EQ(-3, MatchPrefix("123456789", "!123"));
	EXPECT_EQ(3, MatchPrefix("123456789", "1.3"));
	EXPECT_EQ(0, MatchPrefix("123456789", "1.4"));
	EXPECT_EQ(3, MatchPrefix("123456789", "1%3"));
	EXPECT_EQ(0, MatchPrefix("123456789", "1%4"));
}

TEST_F(H323UtilTest, RewriteString) {
	PString unused;
	EXPECT_STREQ("1111497654321", RewriteString("497654321", "49", "111149", unused));
	EXPECT_STREQ("111149771777", RewriteString("49771777", "49..1", "111149..1", unused));
	EXPECT_STREQ("49123456", RewriteString("777749123456", "%%%%49", "49", unused));

	PString postdial;
	PString result = RewriteString("49123", "49...", "49...", postdial, true);
	EXPECT_STREQ("49", result);
	EXPECT_STREQ("123", postdial);
}

TEST_F(H323UtilTest, RewriteWildcard) {
	EXPECT_STREQ("12345678@mydomain.com", RewriteWildcard("12345678", "{\\1}@mydomain.com"));
	EXPECT_STREQ("1234@mydomain.com", RewriteWildcard("12345678", "{^\\d(4)}@mydomain.com"));
	EXPECT_STREQ("5678@mydomain.com", RewriteWildcard("12345678", "{\\d(4)$}@mydomain.com"));
}

TEST_F(H323UtilTest, ProtocolVersion) {
	EXPECT_EQ(0u, ProtocolVersion("invalid"));
	EXPECT_EQ(2u, ProtocolVersion(H225_ProtocolIDv2));
	EXPECT_EQ(4u, ProtocolVersion(H225_ProtocolIDv4));
	EXPECT_EQ(6u, ProtocolVersion(H225_ProtocolIDv6));
	EXPECT_EQ(7u, ProtocolVersion("0.0.8.2250.0.7"));
	EXPECT_EQ(3u, ProtocolVersion(H245_ProtocolIDv3));
}

TEST_F(H323UtilTest, IPAndPortAddress) {
	PIPSocket::Address ip1("1.2.3.4");
	PIPSocket::Address ip2("4.5.6.7");
	WORD port = 123;
    IPAndPortAddress addr1;
    IPAndPortAddress addr2(ip2, port);

    EXPECT_FALSE(IsSet(addr1));
    EXPECT_FALSE(addr1.IsSet());
    EXPECT_TRUE(IsSet(addr2));
    EXPECT_TRUE(addr2.IsSet());

    EXPECT_FALSE(addr1 == addr2);
    addr1.Set(ip1, port);
    EXPECT_FALSE(addr1 == addr2);
    EXPECT_TRUE(addr1 != addr2);
    addr1.Set(ip2, port);
    EXPECT_TRUE(addr1 == addr2);
    EXPECT_FALSE(addr1 != addr2);
}

TEST_F(H323UtilTest, OIDCompare) {
	PString oid1 = "1.2.9.4";
	PString oid2 = "1.2.10.4";
    EXPECT_TRUE(OIDCmp(oid1, oid1) == 0);
    EXPECT_TRUE(OIDCmp(oid1, oid2) < 0);
    EXPECT_TRUE(OIDCmp(oid2, oid1) > 0);
}

}  // namespace
