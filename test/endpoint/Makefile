#
# Makefile for gktestep, the test endpoint of the GnuGk test harness
#
# needs PTLIBDIR and OPENH323DIR, build with: make optnoshared
#

PROG		= gktestep
SOURCES		:= main.cxx

ifndef OPENH323DIR
$(error OPENH323DIR must point to the H323Plus source directory)
endif

include $(OPENH323DIR)/openh323u.mak
