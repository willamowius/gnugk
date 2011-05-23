#include "h323util.h"
#include <h323pdu.h>
#include "gtest/gtest.h"

namespace {

TEST(H323UtilTest, PIPSocketAddressAsString) {
	PIPSocket::Address ip;
	EXPECT_STREQ("127.0.0.1:777", AsString(ip, 777));
}

TEST(H323UtilTest, H245UnicastIPAddressAsString) {
	H245_UnicastAddress_iPAddress ip;
	EXPECT_STREQ("0.0.0.0:0", AsString(ip));
}

TEST(H323UtilTest, H225TransportAddressAsString) {
	PIPSocket::Address ip;
	H225_TransportAddress transport = SocketToH225TransportAddr(ip, 999);
	const H225_TransportAddress_ipAddress & transport_ip = transport;
	EXPECT_TRUE(AsString(transport).Find("7f 00 00 01") != P_MAX_INDEX);
	EXPECT_STREQ("127.0.0.1:999", AsDotString(transport));
	EXPECT_STREQ("127.0.0.1:999", AsString(transport_ip));
	EXPECT_STREQ("127.0.0.1:999", AsString(transport_ip, true));
	EXPECT_STREQ("127.0.0.1",     AsString(transport_ip, false));
}

TEST(H323UtilTest, EndpointTypeAsString) {
	H225_EndpointType ep_type;
	EXPECT_STREQ("unknown", AsString(ep_type));
	ep_type.IncludeOptionalField(H225_EndpointType::e_terminal);
	EXPECT_STREQ("terminal", AsString(ep_type));
	ep_type.IncludeOptionalField(H225_EndpointType::e_gateway);
	ep_type.IncludeOptionalField(H225_EndpointType::e_mcu);
	ep_type.IncludeOptionalField(H225_EndpointType::e_gatekeeper);
	EXPECT_STREQ("terminal,gateway,mcu,gatekeeper", AsString(ep_type));
}

TEST(H323UtilTest, AliasAsString) {
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
}

TEST(H323UtilTest, ArrayOfAliasAsString) {
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

TEST(H323UtilTest, OctetStringAsString) {
	PASN_OctetString bytes;
	bytes.SetSize(4);
	bytes[0] = 1;
	bytes[1] = 2;
	bytes[2] = 3;
	bytes[3] = 10;
	EXPECT_STREQ("01 02 03 0a", AsString(bytes));
}

TEST(H323UtilTest, ByteArrayAsString) {
	PBYTEArray bytes;
	bytes.SetSize(4);
	bytes[0] = 'a';
	bytes[1] = 'b';
	bytes[2] = 07;
	bytes[3] = 'c';
	EXPECT_STREQ("abc", AsString(bytes));
}

TEST(H323UtilTest, IsIPAddress) {
	EXPECT_TRUE(IsIPAddress("1.2.3.4"));
	EXPECT_TRUE(IsIPAddress("1.2.3.4:999"));
	EXPECT_TRUE(IsIPAddress("255.255.255.255"));
	EXPECT_FALSE(IsIPAddress("a.b.c.d"));
	EXPECT_FALSE(IsIPAddress("1.2.3.4.5"));
	EXPECT_FALSE(IsIPAddress("1.2.3.4:"));
}

TEST(H323UtilTest, IsLoopback) {
	PIPSocket::Address ip;
	EXPECT_TRUE(IsLoopback(ip));
}

TEST(H323UtilTest, GetGUIDString) {
	H225_GloballyUniqueID id;
	EXPECT_STREQ("00000000 00000000 00000000 00000000", GetGUIDString(id, true));
	EXPECT_STREQ("0 0 0 0", GetGUIDString(id, false));
	EXPECT_EQ(35, GetGUIDString(id, true).GetLength());
}

TEST(H323UtilTest, StringToCallId) {
	PString str = "00000000 00000000 00000000 00000000";
	H225_CallIdentifier callid = StringToCallId(str);
	EXPECT_STREQ("00000000 00000000 00000000 00000000", GetGUIDString(callid.m_guid, true));
	str = "00000001 00000020 00000300 00004000";
	callid = StringToCallId(str);
	EXPECT_STREQ("00000001 00000020 00000300 00004000", GetGUIDString(callid.m_guid, true));
}

TEST(H323UtilTest, FindAlias) {
	H225_ArrayOf_AliasAddress aliases;
	aliases.SetSize(2);
	H323SetAliasAddress(PString("jan"), aliases[0]);
	H323SetAliasAddress(PString("1234"), aliases[1]);
	EXPECT_EQ(0, FindAlias(aliases, "jan"));
	EXPECT_EQ(1, FindAlias(aliases, "1234"));
	EXPECT_EQ(P_MAX_INDEX, FindAlias(aliases, "9999"));
}

TEST(H323UtilTest, MatchPrefix) {
	EXPECT_EQ(0, MatchPrefix("123456789", "44"));
	EXPECT_EQ(3, MatchPrefix("123456789", "123"));
	EXPECT_EQ(-3, MatchPrefix("123456789", "!123"));
	EXPECT_EQ(3, MatchPrefix("123456789", "1.3"));
	EXPECT_EQ(0, MatchPrefix("123456789", "1.4"));
	EXPECT_EQ(3, MatchPrefix("123456789", "1%3"));
	EXPECT_EQ(0, MatchPrefix("123456789", "1%4"));
}

TEST(H323UtilTest, RewriteString) {
	EXPECT_STREQ("1111497654321", RewriteString("497654321", "49", "111149"));
	EXPECT_STREQ("111149771777", RewriteString("49771777", "49..1", "111149..1"));
	EXPECT_STREQ("49123456", RewriteString("777749123456", "%%%%49", "49"));
}


}  // namespace

