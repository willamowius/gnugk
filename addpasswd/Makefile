#
# Makefile
#
# Makefile for addpasswd
#
# Copyright (C) 2010 Jan Willamowius, jan@willamowius.de
#
# $Log$
# Revision 1.1  2004/12/14 07:04:05  csoutheren
# Initial version
#


PROG = addpasswd
SOURCES := addpasswd.cxx

ifndef PTLIBDIR
PTLIBDIR=${HOME}/ptlib
endif
include $(PTLIBDIR)/make/ptlib.mak

static:
	P_SHAREDLIB=0 LDFLAGS=-static $(MAKE) optnoshared

