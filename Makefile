# -*- mode: Makefile -*-
# Copyright (C) 2002 by its various Authors, see CVS-log
#
# PURPOSE OF THIS FILE: Make file for OpenH323 Gatekeeper
#
# - Automatic Version Information via RCS:
#   $Id$
#   $Source$
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

PROG	 = gnugk
SOURCES	 = main.cxx singleton.cxx job.cxx yasocket.cxx h323util.cxx \
           Toolkit.cxx SoftPBX.cxx GkStatus.cxx RasTbl.cxx          \
           Routing.cxx Neighbor.cxx GkClient.cxx gkauth.cxx         \
           RasSrv.cxx ProxyChannel.cxx gk.cxx version.cxx gkacct.cxx

# colon, the empty variable and a single space are special characters to
# MAKE and may cause trouble. Let's 'quote' the little bastards by
# assigning it to a variable
colon:=:
comma:=,
empty:=
space:=$(empty) $(empty)

# remove half updated or corrupt files
.DELETE_ON_ERROR:

# heuristic to make sure the libraries we depend on so heavily can be found
ifndef OPENH323DIR
  OPENH323DIR=$(HOME)/openh323
endif
ifndef PWLIBDIR
  PWLIBDIR=$(HOME)/pwlib
endif
ifndef TMP
  TMP=/tmp
endif

CWD:=$(shell pwd)

# having an own idea about default targets. This leads to nicly
# maintainable binaries with proper library dependence, libraries may be
# replaced on the fly.
.PHONY: bothdepend bothshared gkdefault
.DEFAULT: gkdefault
gkdefault: bothdepend bothshared

# LD_RUN_LIST is the list form of the LD_RUN_PATH
LD_RUN_LIST := $(subst $(colon),$(space),$(LD_RUN_PATH))
LD_RUN_LIST += $(PWLIBDIR)/lib $(OPENH323DIR)/lib


# the PWLib conform versioning file.
GNUGK_VERSION_FILE = version.h

ifndef MANUFACTURER
  MANUFACTURER = "GNU"
endif
ifndef PROGRAMMNAME
  PROGRAMMNAME = "Gatekeeper"
endif
ifndef GNUGK_MAJOR_VERSION
  GNUGK_MAJOR_VERSION = $(shell grep 'define GNUGK_MAJOR_VERSION' $(GNUGK_VERSION_FILE) | cut -d ' ' -f 4-)
endif
ifndef GNUGK_MINOR_VERSION
  GNUGK_MINOR_VERSION = $(shell grep 'define GNUGK_MINOR_VERSION' $(GNUGK_VERSION_FILE) | cut -d ' ' -f 4-)
endif
ifndef GNUGK_BUILD_TYPE
# might be: AlphaCode, BetaCode, ReleaseCode
  GNUGK_BUILD_TYPE = $(shell grep 'define GNUGK_BUILD_TYPE' $(GNUGK_VERSION_FILE) | cut -d ' ' -f 4-)
endif
ifndef GNUGK_BUILD_NUMBER
  GNUGK_BUILD_NUMBER = $(shell grep 'define GNUGK_BUILD_NUMBER' $(GNUGK_VERSION_FILE) | cut -d ' ' -f 4-)
endif

# Gatekeeper Global Version String to mark object with version info in such
# a way that it is retrievable by the std. version/revision control tools
XID=$$Id
GKGVS="@(\#) $(XID): $(GNUGK_BUILD_TYPE) of "$(PROGRAMMNAME)" v$(GNUGK_MAJOR_VERSION).$(GNUGK_MINOR_VERSION) build\#$(GNUGK_BUILD_NUMBER) by "${MANUFACTURER}" at " __DATE__ " "  __TIME__ " $$"

# use for versioning
STDCCFLAGS += -D'MANUFACTURER=${MANUFACTURER}'
STDCCFLAGS += -D'PROGRAMMNAME=${PROGRAMMNAME}'
STDCCFLAGS += -D'GKGVS=${GKGVS}'

# Recheck if the International Public Telecommunication Numbers (IPTNs)
# used for callING party number and callED party number are in
# international format (TON=international), as they should be
#STDCCFLAGS += -D'CDR_RECHECK'

# Should the dialed digit fields in the src. or dest. information fields of
# the CDR should be appended by an 'dialedDigits'-subfield containing the
# internationalized callING party number or callED party number
# respectively. Uncomment to use
#STDCCFLAGS += -D'CDR_MOD_INFO_FIELDS'

# use for Digit Analysis
#STDCCFLAGS += -D'HAVE_DIGIT_ANALYSIS'

# If the "newer" OpenH323lib is used, the H323SetAliasAddress can get a tag,
# so our overloaded H323SetAliasAddress is no longer needed.

#STDCCFLAGS +=-D'HAS_NEW_H323SETALIASADDRESS=1'

# automatically include debugging code or not
ifdef PASN_NOPRINT
  STDCCFLAGS += -DPASN_NOPRINT
else
  STDCCFLAGS += -DPTRACING
endif

# MySQL support
#
# Flags for MySQL:
# * NO_MYSQL:            Disable MySQL Support.

ifndef NO_MYSQL
NO_MYSQL := 0
endif

ifeq ($(NO_MYSQL),0)
  ifndef MYSQLINCDIR
    ifneq (,$(wildcard /usr/include/mysql/mysql.h))
      MYSQLINCDIR := /usr/include/mysql
    endif
  endif
  ifndef MYSQLLIBDIR
    ifneq (,$(wildcard /usr/lib/mysql/libmysqlclient.so))
      MYSQLLIBDIR := /usr/lib/mysql
    endif
  endif

  ifdef MYSQLINCDIR
    ifneq (,$(wildcard $(MYSQLINCDIR)))
      SOURCES	      += mysqlcon.cxx
      STDCCFLAGS_STUB := $(STDCCFLAGS)
      STDCCFLAGS       = -DHAS_MYSQL=1 -I$(MYSQLINCDIR) $(STDCCFLAGS_STUB)
      ENDLDLIBS	      += -lmysqlclient
      HAS_MYSQL	       = 1
      ifdef MYSQLLIBDIR
	LDFLAGS	      += -L$(MYSQLLIBDIR)
      endif
    endif
  endif
endif

# RADIUS support
#
# Flags for RADIUS:
# * NO_RADIUS:            Disable RADIUS Support.

ifndef NO_RADIUS
NO_RADIUS := 0
endif

ifeq ($(NO_RADIUS),0)
  SOURCES	      += radproto.cxx radauth.cxx radacct.cxx
  STDCCFLAGS_STUB := $(STDCCFLAGS)
  STDCCFLAGS       = -DHAS_RADIUS=1 $(STDCCFLAGS_STUB)
  HAS_RADIUS       = 1
endif

###
### Including the general make rules of OpenH323
###

VERSION_FILE := $(OPENH323DIR)/version.h

include $(OPENH323DIR)/openh323u.mak

### Remove -fdata-sections gcc option that cause problems during link step
temp_STDCCFLAGS := $(subst -fdata-sections,,$(STDCCFLAGS))
STDCCFLAGS = $(temp_STDCCFLAGS)

STDCCFLAGS	+= -DMAJOR_VERSION=$(MAJOR_VERSION) -DMINOR_VERSION=$(MINOR_VERSION) -DBUILD_NUMBER=$(BUILD_NUMBER)

ifdef LARGE_FDSET
  STDCCFLAGS_STUB := $(STDCCFLAGS)
  STDCCFLAGS	   = -DLARGE_FDSET=$(LARGE_FDSET) $(STDCCFLAGS_STUB)
endif

# delete corefiles (also the Linux-kind)
#CLEAN_FILES += $(wildcard core.*)

#### a need HACK to support gcc version > 3
ifeq (,$(findstring $(CPLUS),g++))
  GXXVERSION:=$(strip $(shell $(CPLUS) --version | tr '.' ' '))
  #$(warning found GCC <$(CPLUS)> <$(GXXVERSION)>)
  GXX_MAJOR_VERSION:=$(word 1,$(GXXVERSION))
  #GXX_MINOR_VERSION:=$(word 2,$(GXXVERSION))
  #GXX_BUILD_VERSION:=$(word 3,$(GXXVERSION))
  ifeq (,$(findstring $(GXX_MAJOR_VERSION), 0 1 2))
    #$(warning found GCC bigger 2 <$(GXX_MAJOR_VERSION)> special treatment enabled)
    # My MySQL is not gcc 3.0 compatible, remove this if yours is
    #NO_MYSQL=1
    #FILTERED_FLAGS:=$(filter-out %HAS_MYSQL,$(STDCCFLAGS))
    #STDCCFLAGS = $(FILTERED_FLAGS)
    # the stdio lib has some nonstd parts, you may have to uncomment
    # the following to use them (depricated)
    #STDCCFLAGS += -idirafter /usr/include/g++-3
  endif
endif


# extra targets
addpasswd: $(OBJDIR)/addpasswd.o
	$(CXX) -o $(OBJDIR)/addpasswd $(CFLAGS) $(OBJDIR)/addpasswd.o $(LDFLAGS) -l$(PTLIB_BASE)$(LIB_TYPE) $(ENDLDLIBS) $(ENDLDFLAGS)

doc:	docs/manual.sgml
	cd docs; sgml2html manual.sgml; \
	which bg5sgml2html > /dev/null 2>&1 && \
	bg5sgml2html manual-zh.sgml || true

#
# By this command the build number may be incremented
#
.PHONY: increment

# Use this to increment the build number
increment:
	-@BN=$(GNUGK_BUILD_NUMBER); \
        BNN=`expr "$$BN" + 1`; \
        echo "Upgrading from build $$BN to $$BNN"; \
        cp $(GNUGK_VERSION_FILE) $(TMP)/$(GNUGK_VERSION_FILE); \
        sed -e 's/BUILD_NUMBER.*'"$$BN"'/BUILD_NUMBER '"$$BNN/" \
                $(TMP)/$(GNUGK_VERSION_FILE) > $(GNUGK_VERSION_FILE); \
        rm -f $(TMP)/$(GNUGK_VERSION_FILE)

# end
