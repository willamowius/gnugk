#include "gtest/gtest.h"

int main(int argc, char **argv) {
	// Disables elapsed time by default.
	::testing::GTEST_FLAG(print_time) = false;

	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

