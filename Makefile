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

ifdef HAS_LEVEL_TWO_LDAPAPI
SOURCES         += ldapapi.cxx
HAS_LDAP	= 1
STDCCFLAGS	+= -D"HAS_LDAP=$(HAS_LDAP)" \
                   -D"HAS_LEVEL_TWO_LDAPAPI=$(HAS_LEVEL_TWO_LDAPAPI)" 
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

addpasswd:	obj_linux_x86_r/addpasswd

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

# end
