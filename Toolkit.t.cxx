/*
 * Toolkit.t.cxx
 *
 * unit tests for Toolkit.cxx
 *
 * Copyright (c) 2013, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"
#include "Toolkit.h"
#include "gtest/gtest.h"

namespace {

class ToolkitTest : public ::testing::Test {
protected:
	ToolkitTest() { }
 };
 
TEST_F(ToolkitTest, NetworkAddress) {
    NetworkAddress na;
    EXPECT_STREQ("0.0.0.0/0", na.AsString());
    EXPECT_TRUE(na.IsAny());

    na = NetworkAddress("1.2.3.4/24");
    EXPECT_STREQ("1.2.3.0/24", na.AsString());
    EXPECT_EQ(24u, na.GetNetmaskLen());
    EXPECT_FALSE(na.IsAny());

    NetworkAddress na2("9.9.9.0/24");
    NetworkAddress na3("9.9.10.0/24");
    EXPECT_FALSE(na2 == na3);

    NetworkAddress na6("2001:db8:85a3:8d3:1319:8a2e:370:7344/128");
    EXPECT_STREQ("2001:db8:85a3:8d3:1319:8a2e:370:7344/128", na6.AsString());
}

TEST_F(ToolkitTest, IPv4PrefixBoundaries) {
    struct Case {
        const char *input;
        const char *expected;
        unsigned prefix;
    } cases[] = {
        {"192.168.1.123/0", "0.0.0.0/0", 0},
        {"192.168.1.123/1", "128.0.0.0/1", 1},
        {"192.168.1.123/8", "192.0.0.0/8", 8},
        {"192.168.1.123/16", "192.168.0.0/16", 16},
        {"192.168.1.123/24", "192.168.1.0/24", 24},
        {"192.168.1.123/31", "192.168.1.122/31", 31},
        {"192.168.1.123/32", "192.168.1.123/32", 32}
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        SCOPED_TRACE(cases[i].input);
        NetworkAddress address(cases[i].input);
        EXPECT_STREQ(cases[i].expected, address.AsString());
        EXPECT_EQ(cases[i].prefix, address.GetNetmaskLen());
    }
}

TEST_F(ToolkitTest, IPv4NetworkContainsAddressesAtBoundaries) {
    NetworkAddress network("192.168.10.0/24");
    EXPECT_TRUE(network >> PIPSocket::Address("192.168.10.0"));
    EXPECT_TRUE(network >> PIPSocket::Address("192.168.10.1"));
    EXPECT_TRUE(network >> PIPSocket::Address("192.168.10.255"));
    EXPECT_FALSE(network >> PIPSocket::Address("192.168.11.0"));
    EXPECT_FALSE(network >> PIPSocket::Address("192.168.9.255"));
}

TEST_F(ToolkitTest, IPv4HostAndNetworkEquality) {
    NetworkAddress host("192.168.10.7/32");
    PIPSocket::Address sameHost("192.168.10.7");
    PIPSocket::Address differentHost("192.168.10.8");

    EXPECT_TRUE(host == sameHost);
    EXPECT_FALSE(host == differentHost);
    EXPECT_TRUE(sameHost == host);

    NetworkAddress networkA("192.168.10.1/24");
    NetworkAddress networkB("192.168.10.200/24");
    EXPECT_TRUE(networkA == networkB);
    EXPECT_FALSE(networkA == host);
}


TEST_F(ToolkitTest, NetworkContainmentAndOrdering) {
    NetworkAddress broad("10.0.0.0/8");
    NetworkAddress narrow("10.20.0.0/16");
    NetworkAddress outside("11.0.0.0/8");

    EXPECT_TRUE(broad >> narrow);
    EXPECT_TRUE(narrow << broad);
    EXPECT_FALSE(narrow >> broad);
    EXPECT_FALSE(broad >> outside);

    EXPECT_TRUE(broad < narrow); // shorter prefix sorts first
    EXPECT_TRUE(narrow > broad);
    EXPECT_TRUE(broad <= narrow);
    EXPECT_TRUE(narrow >= broad);
    EXPECT_EQ(0, broad.Compare(NetworkAddress("10.0.0.0/8")));
}

TEST_F(ToolkitTest, IPv6PrefixNormalizationAndContainment) {
    NetworkAddress network("2001:db8:abcd:1234::1234/64");
    EXPECT_STREQ("2001:db8:abcd:1234::/64", network.AsString());
    EXPECT_EQ(64u, network.GetNetmaskLen());
    EXPECT_TRUE(network >> PIPSocket::Address("2001:db8:abcd:1234::1"));
    EXPECT_TRUE(network >> PIPSocket::Address("2001:db8:abcd:1234:ffff:ffff:ffff:ffff"));
    EXPECT_FALSE(network >> PIPSocket::Address("2001:db8:abcd:1235::1"));
}

TEST_F(ToolkitTest, IPv6PrefixBoundaries) {
    struct Case {
        const char *input;
       const char *expected;
        unsigned prefix;
    } cases[] = {
        {"2001:db8::1234/0", "::/0", 0},
        {"2001:db8::1234/1", "::/1", 1},
        {"2001:db8:abcd:1234::1234/64", "2001:db8:abcd:1234::/64", 64},
        {"2001:db8::1234/127", "2001:db8::1234/127", 127},
        {"2001:db8::1234/128", "2001:db8::1234/128", 128}
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        SCOPED_TRACE(cases[i].input);
        NetworkAddress address(cases[i].input);
        EXPECT_STREQ(cases[i].expected, address.AsString());
        EXPECT_EQ(cases[i].prefix, address.GetNetmaskLen());
    }
}

TEST_F(ToolkitTest, IPv4AndIPv6NetworksAreNotEqualOrContaining) {
    NetworkAddress ipv4("0.0.0.0/0");
    NetworkAddress ipv6("::/0");
    EXPECT_FALSE(ipv4 == ipv6);
    EXPECT_FALSE(ipv4 >> ipv6);
    EXPECT_FALSE(ipv6 >> ipv4);
}

}  // namespace
