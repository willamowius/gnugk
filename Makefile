#
# Makefile
#
# Make file for OpenH323 Gatekeeper
#

PROG		= gk
SOURCES		= gk.cxx gkauth.cxx RasSrv.cxx RasTbl.cxx \
		  MulticastGRQ.cxx BroadcastListen.cxx \
		  SignalChannel.cxx SignalConnection.cxx \
		  GkStatus.cxx SoftPBX.cxx Toolkit.cxx h323util.cxx \
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


# MySQL support
ifndef NO_MYSQL
ifndef MYSQLDIR

ifneq (,$(wildcard /usr/include/mysql))
MYSQLDIR := /usr/include/mysql
export MYSQLDIR
endif

endif

ifdef MYSQLDIR
ifneq (,$(wildcard $(MYSQLDIR)))
STDCCFLAGS	+= -DHAS_MYSQL -I$(MYSQLDIR)
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
 
