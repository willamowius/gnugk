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


PROG	 = gnugk
SOURCES  = Toolkit.cxx CountryCodeTables.cxx gk.cxx gkauth.cxx gkldap.cxx \
           gkDestAnalysis.cxx RasTbl.cxx GkClient.cxx MulticastGRQ.cxx	  \
           BroadcastListen.cxx SoftPBX.cxx h323util.cxx GkStatus.cxx	  \
           ProxyThread.cxx ProxyChannel.cxx singleton.cxx main.cxx	  \
           gkDatabase.cxx gkIniFile.cxx GkProfile.cxx RasListener.cxx     \
	   RasWorker.cxx Neighbor.cxx gklock.cxx

# the PWLib conform versioning file.
VERSION_FILE = version.h

ifndef MANUFACTURER
  MANUFACTURER = "Willamowius"
endif
ifndef PROGRAMMNAME
  PROGRAMMNAME = "Gatekeeper"
endif
ifndef MAJOR_VERSION
  MAJOR_VERSION = $(shell grep 'define MAJOR_VERSION' $(VERSION_FILE) | cut -d ' ' -f 3-)
endif
ifndef MINOR_VERSION
  MINOR_VERSION = $(shell grep 'define MINOR_VERSION' $(VERSION_FILE) | cut -d ' ' -f 3-)
endif
ifndef BUILD_TYPE
# might be: AlphaCode, BetaCode, ReleaseCode
  BUILD_TYPE = $(shell grep 'define BUILD_TYPE' $(VERSION_FILE) | cut -d ' ' -f 3-)
endif
ifndef BUILD_NUMBER
  BUILD_NUMBER = $(shell grep 'define BUILD_NUMBER' $(VERSION_FILE) | cut -d ' ' -f 3-)
endif

# Gatekeeper Global Version String to mark object with version info in such
# a way that it is retrievable by the std. version/revision control tools
XID=$$Id
GKGVS="@(\#) $(XID): $(BUILD_TYPE) of "$(PROGRAMMNAME)" v$(MAJOR_VERSION).$(MINOR_VERSION) build\#$(BUILD_NUMBER) by "${MANUFACTURER}" at " __DATE__ " "  __TIME__ " $$"

H323_INCDIR = ${OPENH323DIR}/include
H323_LIBDIR = ${OPENH323DIR}/lib
H323_LIB    = h323_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)

STDCCFLAGS := -I${H323_INCDIR}

# use for versioning
STDCCFLAGS += -D'MANUFACTURER=${MANUFACTURER}'
STDCCFLAGS += -D'PROGRAMMNAME=${PROGRAMMNAME}'
STDCCFLAGS += -D'GKGVS=${GKGVS}'

# Recheck if the International Public Telecommunication Numbers (IPTNs)
# used for callING party number and callED party number are in
# international format (TON=international), as they should be
STDCCFLAGS += -D'CDR_RECHECK'

# Should the dialed digit fields in the src. or dest. information fields of
# the CDR should be appended by an 'dialedDigits'-subfield containing the
# internationalized callING party number or callED party number
# respectively. Uncomment to use
#STDCCFLAGS += -D'CDR_MOD_INFO_FIELDS'

# use for Digit Analysis
STDCCFLAGS += -D'HAVE_DIGIT_ANALYSIS'

# If the "newer" OpenH323lib is used, the H323SetAliasAddress can get a tag,
# so our overloaded H323SetAliasAddress is no longer needed.

STDCCFLAGS +=-D'HAS_NEW_H323SETALIASADDRESS=1'

# automatically include debugging code or not
ifdef PASN_NOPRINT
  STDCCFLAGS += -DPASN_NOPRINT
else
  STDCCFLAGS += -DPTRACING
endif

# Flags for LDAP:
# * NO_LDAP:             Disable LDAP_Support.
# * USE_EXTERNAL_LDAP:   Use the LDAP-Client-library on the system. if not set
#                  	 the internal LDAP-client-library will be used.
# * LDAP_PROVIDES_CACHE: Explicitly switch of the gk_ldap-cache (i.e.: Use the
#			 caching provided by the client-library - none if the
#			 client-library won't provide one

# LDAP support
ifndef NO_LDAP
  ifdef USE_EXTERNAL_LDAP
    ifndef LDAP1823DIR
      LDAP1823DIR := /usr/include
    endif # LDAP1823DIR
  ifndef LDAP1823LIBDIR
    LDAP1823LIBDIR := /usr/lib
  endif # LDAP1823LIBDIR
# this is the file name of the lib. To the linker always flag (-l) with
# std. name 'ldap' is passed
  ifndef LDAP1823LIBNM
    LDAP1823LIBNM := libldap.so
  endif # LDAP1823LIBNM
  ifneq (,$(wildcard $(LDAP1823DIR)/ldap.h))
    HAVE_LDAP1823_HDRS = 1
  endif # LDAP1823DIR/ldap.h exists
  ifneq (,$(wildcard $(LDAP1823LIBDIR)/$(LDAP1823LIBNM)))
    HAVE_LDAP1823_LIBS = 1
  endif # LDAP1823DIR/LDAP1823LIBMN exits

# add test for HAS_LEVEL_TWO_LDAPAPI here
else  # USE_EXTERNAL_LDAP
  ifneq (,$(wildcard ldap/include/ldapapi.h))
    HAS_LEVEL_TWO_LDAPAPI = 1
  endif
endif # USE_EXTERNAL_LDAP

# This is needed for a locally used encoding lib.
ifdef HAS_MWBB1
  ifndef MWBB1DIR
    MWBB1DIR := $(CWD)
  endif				# MWBB1DIR
  ifndef MWBB1LIBDIR
    MWBB1LIBDIR := $(CWD)
  endif				# MWBB1LIBDIR
  ifndef MWBB1_TAG
    MWBB1_TAG := "{TAG}"
  endif
  STDCCFLAGS += -D'MWBB1_TAG="$(MWBB1_TAG)"' -I$(MWBB1DIR)
  LDFLAGS    += -L$(MWBB1LIBDIR)
  ENDLDLIBS  += -lmwc
  LD_RUN_LIST += $(strip $(MWBB1LIBDIR))
endif				# HAS_MWBB1

ifndef ANSI
  STDCCFLAGS += -DGK_NOANSI
endif

ifdef HAS_LEVEL_TWO_LDAPAPI
  SOURCES    += ldaplink.cxx gk_ldap_interface.cxx
  LDAP_LIBDIR = $(CWD)/ldap/lib
  LDAP_LIB    = $(LDAP_LIBDIR)/libldapapi_$(PLATFORM_TYPE)_$(OBJ_SUFFIX).$(LIB_SUFFIX)

  SUBDIRS    += ldap/src
  LDLIBS     += -lldapapi_$(PLATFORM_TYPE)_$(OBJ_SUFFIX) $(TMP_LDLIBS)
  LDFLAGS    += -L$(LDAP_LIBDIR)
  HAS_LDAP    = 1
  STDCCFLAGS += -I$(CWD)/ldap/include -D"HAS_LDAP=$(HAS_LDAP)" \
                -D"HAS_LEVEL_TWO_LDAPAPI=$(HAS_LEVEL_TWO_LDAPAPI)" -D"LDAPVERSION=2"
  LD_RUN_LIST += $(strip $(LDAP_LIBDIR))
else
  ifdef HAVE_LDAP1823_HDRS
    ifdef HAVE_LDAP1823_LIBS
      SOURCES   += ldaplink.cxx gk_ldap_interface.cxx
      ENDLDLIBS	+= -lldap
      HAS_LDAP	 = 1
# due to the unwise naming of the libH323 header, the std. header 'ldap.h'
# would be hooded, if the include search path would not PREpended
      STDCCFLAGS_STUB := $(STDCCFLAGS)
      STDCCFLAGS       = -D"HAS_LDAP=$(HAS_LDAP)" -I$(LDAP1823DIR) $(STDCCFLAGS_STUB)
      LDFLAGS         += -L$(LDAP1823LIBDIR)
      LD_RUN_LIST     += $(strip $(LDAP1823LIBDIR))
    endif
  endif
endif

endif
# end of LDAP configuration


# MySQL support
# has to be added after LDAP support because order of -I options is crucial
ifndef NO_MYSQL
  ifndef MYSQLDIR
    ifneq (,$(wildcard /usr/include/mysql/mysql++))
      MYSQLDIR := /usr/include/mysql
    endif
  endif

  ifdef MYSQLDIR
    ifneq (,$(wildcard $(MYSQLDIR)))
      STDCCFLAGS_STUB := $(STDCCFLAGS)
      STDCCFLAGS       = -DHAS_MYSQL -I$(MYSQLDIR) $(STDCCFLAGS_STUB)
      #LDFLAGS	      += -L$(MYSQLDIR)/lib
      ENDLDLIBS	      += -lsqlplus
      HAS_MYSQL	       = 1
    endif
  endif
endif

# adding the OpenH323 lib before the PWLib and its dependencies
LDFLAGS += -L$(H323_LIBDIR)
LDLIBS  += -l$(H323_LIB)

###
### Including the general make rules of PWLib
###
include $(PWLIBDIR)/make/ptlib.mak

ifdef HAS_LEVEL_TWO_LDAPAPI
  TARGET_LIBS += $(LDAP_LIB)
  $(LDAP_LIB):
	$(MAKE) -C ldap/src
#  ifdef DEBUG
#    $(LDAP_LIB):
#	$(MAKE) -C ldap/src debugshared
#  else
#    $(LDAP_LIB):
#	$(MAKE) -C ldap/src optshared
#  endif
# extra dependency to include the LDAPapi
  $(TARGET): $(OBJS) $(TARGET_LIBS)
endif

# delete time-stamp files on clean
CLEAN_FILES += gktimestamp.c ldaplibtimestamp.c

# delete corefiles (also the Linux-kind)
CLEAN_FILES += $(wildcard core.*)


addpasswd: $(OBJDIR)/addpasswd.o
	$(CPLUS) -o $(OBJDIR)/addpasswd $(CFLAGS) $(OBJDIR)/addpasswd.o $(LDFLAGS) $(LDLIBS) $(ENDLDLIBS)

#
# By this command the build number may be incremented
#
.PHONY: increment

# Use this to increment the build number
increment:
	-@BN=$(BUILD_NUMBER); \
        BNN=`expr "$$BN" + 1`; \
        echo "Upgrading from build $$BN to $$BNN"; \
        cp $(VERSION_FILE) $(TMP)/$(VERSION_FILE); \
        sed -e 's/BUILD_NUMBER.*'"$$BN"'/BUILD_NUMBER '"$$BNN/" \
                $(TMP)/$(VERSION_FILE) > $(VERSION_FILE); \
        rm -f $(TMP)/$(VERSION_FILE)

doc: docs/manual.sgml
	cd docs; sgml2html manual.sgml

# These files are dummys to control the dependency of the GK and its
# libraries like LDAP-API, OpenH323Lib and PWLib. The GKGVS
# variable here is helpfull to monitor the operation
TIMESTAMP_MARKER=$(OBJDIR)/gktimestamp.mark $(OBJDIR)/ldaplibtimestamp.mark
.SECONDARY: $(TIMESTAMP_MARKER) # Do not delete after action
$(TIMESTAMP_MARKER):
	-@echo '###=> Building time-stamp file $@ because of $? of $^'
	@echo '/* this file is autogenerated my make, editing is to no avail */\
               static const char * buildID=$(GKGVS); /* should not be empty */' > $@ ;\
        sleep 1

#
# Extra dependencies
#
$(TARGET): $(OBJDIR)/gktimestamp.mark
$(LDAP_LIB): $(OBJDIR)/ldaplibtimestamp.mark

#
# This models the dependencies between the GK and its
# libraries like LDAP-API, OpenH323Lib and PWLib.
#
SPECIAL_LIB_DEPENDENCIES:=$(wildcard $(PWLIBDIR)/lib/libpt_$(PLATFORM_TYPE)_$(OBJ_SUFFIX).$(LIB_SUFFIX)*) $(wildcard $(OPENH323DIR)/lib/libh323_$(PLATFORM_TYPE)_$(OBJ_SUFFIX).$(LIB_SUFFIX)*)
#$(warning DEPENDENCIES ARE $(SPECIAL_LIB_DEPENDENCIES))
$(OBJDIR)/gktimestamp.mark: $(SPECIAL_LIB_DEPENDENCIES)
$(OBJDIR)/gktimestamp.mark: $(wildcard ldap/lib/libldapapi_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)*)

$(OBJDIR)/ldaplibtimestamp.mark: $(SPECIAL_LIB_DEPENDENCIES)

# set the run path only once from the run-list
LD_RUN_PATH = $(subst $(space),$(colon),$(strip $(LD_RUN_LIST)))
#$(warning LD_RUN_PATH is <$(LD_RUN_PATH)>)

export LD_RUN_PATH
export LDAP1823DIR
export LDAP1823LIBDIR
export LDAP1823LIBNM
export HAS_LDAP
export MWBB1_TAG
export MYSQLDIR
export MEMORY_CHECK
# end
