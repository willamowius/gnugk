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

	NetworkAddress na;
	NetworkAddress na2;
	NetworkAddress na6;
};


TEST_F(ToolkitTest, NetworkAddress) {
	na = NetworkAddress();
	EXPECT_STREQ("0.0.0.0/0", na.AsString());
	EXPECT_TRUE(na.IsAny());
	na = NetworkAddress("1.2.3.4/24");
	EXPECT_STREQ("1.2.3.0/24", na.AsString());
	EXPECT_EQ(24u, na.GetNetmaskLen());
	EXPECT_FALSE(na.IsAny());
	na = NetworkAddress("9.9.9.0/24");
	na2 = NetworkAddress("9.9.10.0/24");
	EXPECT_FALSE(na == na2);
	na6 = NetworkAddress("2001:db8:85a3:8d3:1319:8a2e:370:7344/128");
	EXPECT_STREQ("2001:db8:85a3:8d3:1319:8a2e:370:7344/128", na6.AsString());
}

}  // namespace
