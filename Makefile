#
# Makefile
#
# Make file for OpenH323 Gatekeeper
#

PROG		= gk
SOURCES		= gk.cxx gkauth.cxx RasSrv.cxx RasTbl.cxx \
		  MulticastGRQ.cxx BroadcastListen.cxx \
		  SignalChannel.cxx SignalConnection.cxx \
		  SoftPBX.cxx Toolkit.cxx h323util.cxx GkStatus.cxx \
		  singleton.cxx main.cxx

ifndef OPENH323DIR
OPENH323DIR=$(HOME)/openh323
endif

H323_INCDIR	= ${OPENH323DIR}/include
H323_LIBDIR	= ${OPENH323DIR}/lib
H323_LIB	= h323_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)

LDFLAGS		= -L$(H323_LIBDIR)
LDLIBS		= -l$(H323_LIB)

STDCCFLAGS := -I${H323_INCDIR} -DPTRACING#-DPASN_NOPRINT


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

ifdef HAS_LEVEL_TWO_LDAPAPI
SOURCES         += LDAP_SBindRequest_authentication.cxx      compare.cxx  \
		LDAP_SFilter.cxx  delete.cxx   init.cxx      options.cxx \
		abandon.cxx       free.cxx     parse.cxx     modify.cxx \
		add.cxx           getattr.cxx  result.cxx    getresults.cxx \
		bind.cxx          getdn.cxx    messages.cxx  search.cxx ldaplink.cxx

CLEAN_FILES     += LDAP_SBindRequest_authentication.cxx      compare.cxx  \
		LDAP_SFilter.cxx  delete.cxx   init.cxx      options.cxx \
		abandon.cxx       free.cxx     parse.cxx     modify.cxx \
		add.cxx           getattr.cxx  result.cxx    getresults.cxx \
		bind.cxx          getdn.cxx    messages.cxx  search.cxx 

HAS_LDAP	= 1
#STDCCFLAGS_stub := $(STDCCFLAGS)
STDCCFLAGS	+= -I./ -D"HAS_LDAP=$(HAS_LDAP)" \
                   -D"HAS_LEVEL_TWO_LDAPAPI=$(HAS_LEVEL_TWO_LDAPAPI)" -D"LDAPVERSION=2"

else
ifdef HAVE_LDAP1823_HDRS
ifdef HAVE_LDAP1823_LIBS
SOURCES         += ldaplink.cxx
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

ifndef PWLIBDIR
PWLIBDIR=$(HOME)/pwlib
endif

include $(PWLIBDIR)/make/ptlib.mak

addpasswd: $(OBJDIR)/addpasswd

# Extra dependencies
RasSrv.o: RasSrv.cxx
RasSrv.cxx: RasSrv.h
RasSrv.cxx: RasTbl.h
RasTbl.cxx: RasTbl.h
RasTbl.o: RasTbl.cxx
SignalChannel.o: SignalChannel.h
SignalConnection.o: SignalConnection.h
CallTbl.o: CallTbl.h
BroadcastListen.cxx: BroadcastListen.h

ifdef HAS_LEVEL_TWO_LDAPAPI
LDAP_SBindRequest_authentication.cxx: ldap/src/LDAP_SBindRequest_authentication.cxx LDAP_SBindRequest_authentication.h
	cp ldap/src/LDAP_SBindRequest_authentication.cxx .

LDAP_SBindRequest_authentication.h: ldap/src/LDAP_SBindRequest_authentication.h
	cp ldap/src/LDAP_SBindRequest_authentication.h .

ldap-int.h: ldap/src/ldap-int.h
	cp ldap/src/ldap-int.h .

ldapapi.h: ldap/include/ldapapi.h ber.h ldap_cdefs.h
	cp ldap/include/ldapapi.h .

ber.h: ldap/include/ber.h
	cp ldap/include/ber.h .

ldap_cdefs.h: ldap/include/ldap_cdefs.h
	cp ldap/include/ldap_cdefs.h .

compare.cxx: ldap/src/compare.cxx ldap-int.h ldapapi.h
	cp ldap/src/compare.cxx .

LDAP_SFilter.cxx: ldap/src/LDAP_SFilter.cxx LDAP_SFilter.h
	cp ldap/src/LDAP_SFilter.cxx .

LDAP_SFilter.h: ldap/src/LDAP_SFilter.h
	cp ldap/src/LDAP_SFilter.h .

delete.cxx: ldap/src/delete.cxx ldap-int.h ldapapi.h
	cp ldap/src/delete.cxx .

init.cxx: ldap/src/init.cxx ldap-int.h ldapapi.h
	cp ldap/src/init.cxx .

options.cxx: ldap/src/options.cxx ldap-int.h ldapapi.h
	cp ldap/src/options.cxx .

abandon.cxx: ldap/src/abandon.cxx ldap-int.h ldapapi.h
	cp ldap/src/abandon.cxx .

free.cxx: ldap/src/free.cxx ldap-int.h ldapapi.h
	cp ldap/src/free.cxx .

parse.cxx: ldap/src/parse.cxx ldap-int.h ldapapi.h
	cp ldap/src/parse.cxx .

modify.cxx: ldap/src/modify.cxx ldap-int.h ldapapi.h
	cp ldap/src/modify.cxx .

add.cxx: ldap/src/add.cxx ldap-int.h ldapapi.h
	cp ldap/src/add.cxx .

getattr.cxx: ldap/src/getattr.cxx ldap-int.h ldapapi.h
	cp ldap/src/getattr.cxx .

ldaptest.cxx: ldap/src/ldaptest.cxx ldap-int.h ldapapi.h
	cp ldap/src/ldaptest.cxx .

result.cxx: ldap/src/result.cxx ldap-int.h ldapapi.h
	cp ldap/src/result.cxx .

bind.cxx: ldap/src/bind.cxx ldap-int.h ldapapi.h
	cp ldap/src/bind.cxx .

getdn.cxx: ldap/src/getdn.cxx ldap-int.h ldapapi.h
	cp ldap/src/getdn.cxx .

messages.cxx: ldap/src/messages.cxx ldap-int.h ldapapi.h
	cp ldap/src/messages.cxx .

search.cxx: ldap/src/search.cxx ldap-int.h ldapapi.h
	cp ldap/src/search.cxx .

getresults.cxx: ldap/src/getresults.cxx ldap-int.h ldapapi.h
	cp ldap/src/getresults.cxx .
endif

# end
