#
# Makefile
#
# Make file for OpenH323 Gatekeeper
#

PROG		= gk
SOURCES		= gk.cxx RasSrv.cxx RasTbl.cxx MulticastGRQ.cxx SignalChannel.cxx \
				SignalConnection.cxx GkStatus.cxx BroadcastListen.cxx \
				SoftPBX.cxx h323util.cxx Toolkit.cxx Toolkit_Mediaways.cxx main.cxx

ifndef OPENH323DIR
OPENH323DIR=$(HOME)/openh323
endif

H323_INCDIR	= ${OPENH323DIR}/include
H323_LIBDIR	= ${OPENH323DIR}/lib
H323_LIB	= h323_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)

LDFLAGS		= -L$(H323_LIBDIR)
LDLIBS		= -l$(H323_LIB)

STDCCFLAGS := -I${H323_INCDIR} -DPTRACING  #-DPASN_NOPRINT


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

