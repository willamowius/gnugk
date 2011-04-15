#
# Makefile
#
# Makefile for addpasswd
#
# Copyright (C) 2010 Jan Willamowius, jan@willamowius.de
#
# $Log$
# Revision 1.1  2010/10/02 21:29:30  willamowius
# move addpasswd to subdir
#
# Revision 1.1  2004/12/14 07:04:05  csoutheren
# Initial version
#


PROG = addpasswd
SOURCES := addpasswd.cxx

ifndef PTLIBDIR
PTLIBDIR=${HOME}/ptlib
endif
include $(PTLIBDIR)/make/ptlib.mak

#ifeq ($(OSTYPE),solaris)
    ### Remove references to gcc 3.x libs that come with Solaris 10
    temp_ENDLDLIBS := $(subst -R/usr/sfw/lib,,$(ENDLDLIBS))
    ENDLDLIBS = $(temp_ENDLDLIBS)
    temp_ENDLDLIBS := $(subst -L/usr/sfw/lib,,$(ENDLDLIBS))
    ENDLDLIBS = $(temp_ENDLDLIBS)
    ENDLDLIBS += -L/opt/csw/lib
#endif # solaris

static:
	P_SHAREDLIB=0 LDFLAGS=-static $(MAKE) optnoshared

