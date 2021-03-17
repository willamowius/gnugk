/*
 * ProxyChannel.t.cxx
 *
 * unit tests for ProxyChannel.cxx
 *
 * Copyright (c) 2021, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"
#include "Toolkit.h"
#define TEST_MODE
#include "ProxyChannel.h"
#include "gtest/gtest.h"

namespace {

class ProxyChannelTest : public ::testing::Test {
protected:
	ProxyChannelTest() { }
};


TEST_F(ProxyChannelTest, H46019Session) {
	H46019Session s1(0, INVALID_RTP_SESSION, NULL);
	H46019Session s2(0, INVALID_RTP_SESSION, NULL);
	EXPECT_FALSE(s1.IsValid());
	EXPECT_FALSE(s2.IsValid());

	s1.m_multiplexID_fromA = 1;
	s2.m_multiplexID_fromB = 2;
	s1.Merge(s2);
	EXPECT_TRUE(s1.m_multiplexID_fromA = 1 && s1.m_multiplexID_fromB == 2);
}

}  // namespace
