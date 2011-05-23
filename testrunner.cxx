/*
 * testrunner.cxx
 *
 * run all unit tests for the GNU Gatekeeper
 *
 * Copyright (c) 2011, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "gtest/gtest.h"

int main(int argc, char **argv) {
	// Disables elapsed time by default.
	::testing::GTEST_FLAG(print_time) = false;

	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

