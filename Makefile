#
# Makefile
#
# Make file for OpenH323 Gatekeeper
#

PROG		= gnugk
SOURCES		= gk.cxx gkauth.cxx gkldap.cxx gkDestAnalysis.cxx \
		  RasSrv.cxx RasTbl.cxx GkClient.cxx \
		  MulticastGRQ.cxx BroadcastListen.cxx \
		  SoftPBX.cxx Toolkit.cxx h323util.cxx GkStatus.cxx \
		  ProxyThread.cxx ProxyChannel.cxx \
		  singleton.cxx GkAuthorize.cxx main.cxx

ifndef OPENH323DIR
OPENH323DIR=$(HOME)/openh323
endif

H323_INCDIR	= ${OPENH323DIR}/include
H323_LIBDIR	= ${OPENH323DIR}/lib
H323_LIB	= h323_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)

STDCCFLAGS := -DLDAP_HAS_CACHE -I${H323_INCDIR} -DPTRACING#-DPASN_NOPRINT
#-DLDAP_HAS_CACHE : do not use ldap-cache (alpha)

# use destination analysis list
WITH_DEST_ANALYSIS_LIST=0
STDCCFLAGS += -D"WITH_DEST_ANALYSIS_LIST=$(WITH_DEST_ANALYSIS_LIST)"

# LDAP support
ifndef NO_LDAP
ifndef LDAP1823DIR
LDAP1823DIR := /usr/include
export LDAP1823DIR
endif
ifndef LDAP1823LIBDIR
LDAP1823LIBDIR := /usr/lib
export LDAP1823LIBDIR
endif
# this is the file name of the lib. To the linker always flag (-l) with
# std. name 'ldap' is passed
ifndef LDAP1823LIBNM
LDAP1823LIBNM := libldap.so
export LDAP1823LIBNM
endif
ifneq (,$(wildcard $(LDAP1823DIR)/ldap.h))
HAVE_LDAP1823_HDRS = 1
endif
ifneq (,$(wildcard $(LDAP1823LIBDIR)/$(LDAP1823LIBNM)))
HAVE_LDAP1823_LIBS = 1
endif

# add test for HAS_LEVEL_TWO_LDAPAPI here
ifneq (,$(wildcard ldap/include/ldapapi.h))
#ifneq (,$(wildcard ldap/lib/libldapapi_$(PLATFORM_TYPE)_$(OBJ_SUFFIX).$(LIB_SUFFIX)))
HAS_LEVEL_TWO_LDAPAPI=1
endif

# This is needed for a locally used encoding lib.
ifdef HAS_MWBB1
ifndef MWBB1DIR
MWBB1DIR := .
endif				# MWBB1DIR
ifndef MWBB1LIBDIR
MWBB1LIBDIR := .
endif				# MWBB1LIBDIR
ifndef MWBB1_TAG
MWBB1_TAG := "{TAG}"
export MWBB1_TAG
endif
STDCCFLAGS	+= -D'MWBB1_TAG=$(MWBB1_TAG)' -I$(MWBB1DIR)
LDFLAGS         += -L$(MWBB1LIBDIR)
ENDLDLIBS	+= -lMWCrypt
ifneq (,(LD_RUN_PATH))
LD_RUN_stub     := $(LD_RUN_PATH)
LD_RUN_PATH     += $(LD_RUN_stub):$(MWBB1LIBDIR)
else
LD_RUN_PATH     += $(MWBB1LIBDIR)
endif
export LD_RUN_PATH
endif				# HAS_MWBB1

ifndef ANSI
STDCCFLAGS	+= -DGK_NOANSI
endif

ifdef HAS_LEVEL_TWO_LDAPAPI
SOURCES += ldaplink.cxx 	  gk_ldap_interface.cxx
LDAP_LIB = ./ldap/lib/libldapapi_$(PLATFORM_TYPE)_$(OBJ_SUFFIX).$(LIB_SUFFIX)

SUBDIRS += ldap/src
LDLIBS	+= -lldapapi_$(PLATFORM_TYPE)_$(OBJ_SUFFIX) $(TMP_LDLIBS)
LDFLAGS += -L./ldap/lib/
HAS_LDAP	= 1
STDCCFLAGS	+= -I./ldap/include -D"HAS_LDAP=$(HAS_LDAP)" \
                   -D"HAS_LEVEL_TWO_LDAPAPI=$(HAS_LEVEL_TWO_LDAPAPI)" -D"LDAPVERSION=2"
else
ifdef HAVE_LDAP1823_HDRS
ifdef HAVE_LDAP1823_LIBS
SOURCES         += ldaplink.cxx gk_ldap_interface.cxx
ENDLDLIBS	+= -lldap
HAS_LDAP	= 1
export HAS_LDAP
# due to the unwise naming of the libH323 header, the std. header 'ldap.h'
# would be hooded, if the include search path would not PREpended
STDCCFLAGS_stub := $(STDCCFLAGS)
STDCCFLAGS	= -D"HAS_LDAP=$(HAS_LDAP)" -I$(LDAP1823DIR) $(STDCCFLAGS_stub)
LDFLAGS         += -L$(LDAP1823LIBDIR)
ifneq (,(LD_RUN_PATH))
LD_RUN_stub     := $(LD_RUN_PATH)
LD_RUN_PATH     += $(LD_RUN_stub):$(LDAP1823LIBDIR)
else
LD_RUN_PATH     += $(LDAP1823LIBDIR)
endif
export LD_RUN_PATH
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
export MYSQLDIR
endif
endif

ifdef MYSQLDIR
ifneq (,$(wildcard $(MYSQLDIR)))
STDCCFLAGS_stub := $(STDCCFLAGS)
STDCCFLAGS	= -DHAS_MYSQL -I$(MYSQLDIR) $(STDCCFLAGS_stub)
#LDFLAGS	+= -L$(MYSQLDIR)/lib
ENDLDLIBS	+= -lsqlplus
HAS_MYSQL	= 1
endif
endif
endif

LDFLAGS		+= -L$(H323_LIBDIR)
LDLIBS		+= -l$(H323_LIB)

ifndef PWLIBDIR
PWLIBDIR=$(HOME)/pwlib
endif

include $(PWLIBDIR)/make/ptlib.mak

ifdef HAS_LEVEL_TWO_LDAPAPI
TARGET_LIBS += $(LDAP_LIB)
ifdef DEBUG
$(LDAP_LIB): 
	$(MAKE) -C ldap/src debug
else
$(LDAP_LIB):
	$(MAKE) -C ldap/src opt
endif
$(TARGET):	$(OBJS) $(TARGET_LIBS)
	$(MAKE) $(TARGET_LIBS)
	$(CPLUS) -o $@ $(CFLAGS) $(LDFLAGS) $(OBJS) $(LDLIBS) $(ENDLDLIBS) $(ENDLDFLAGS)
endif

addpasswd: $(OBJDIR)/addpasswd.o
	$(CC) -s -o $(OBJDIR)/addpasswd $(OBJDIR)/addpasswd.o $(LDFLAGS) $(LDLIBS) $(ENDLDLIBS)


# Extra dependencies
RasSrv.o: RasSrv.cxx
RasSrv.cxx: RasSrv.h
RasSrv.cxx: RasTbl.h
RasTbl.cxx: RasTbl.h
RasTbl.o: RasTbl.cxx
BroadcastListen.cxx: BroadcastListen.h
GkAuthorize.o: GkAuthorize.cxx
GkAuthorize.cxx: GkAuthorize.h


# end
