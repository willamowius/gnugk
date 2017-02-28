#
# Makefile
#
# Makefile for addpasswd
#
# Copyright (C) 2010 Jan Willamowius, jan@willamowius.de
#
# $Log$
# Revision 1.2  2011/04/15 17:49:00  willamowius
# fix compile on Solaris 10
#
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

# remove -felide-constructors for Intel C++ compiler
ifeq "$(CXX)" "icpc"
	temp_STDCXXFLAGS := $(subst -felide-constructors,,$(STDCXXFLAGS))
	STDCXXFLAGS = $(temp_STDCXXFLAGS)
endif

# get gcc/g++ version
ifeq "$(CXX)" "g++"
	GCCMAJOREQ4 := $(shell expr 4 = `$(CXX) -dumpversion | cut -f1 -d.`)
	GCCMAJORGT4 := $(shell expr 4 \< `$(CXX) -dumpversion | cut -f1 -d.`)
	GCCMAJORGTEQ4 := $(shell expr 4 \<= `$(CXX) -dumpversion | cut -f1 -d.`)
	GCCMINORGTEQ4 := $(shell expr 4 \<= `$(CXX) -dumpversion | cut -f2 -d.`)
endif

# enable stack protection and RELRO + BIND_NOW on Linux with gcc >= 4.x.x
ifeq "$(OSTYPE)" "linux"
ifeq "$(GCCMAJORGTEQ4)" "1"
	# security flags
	STDCCFLAGS += -fstack-protector --param ssp-buffer-size=4
	LDFLAGS += -Wl,-z,relro,-z,now
endif # gcc >= 4.x.x
endif # linux

static:
	P_SHAREDLIB=0 LDFLAGS=-static $(MAKE) optnoshared

