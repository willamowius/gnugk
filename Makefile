#
# Makefile
#
# Make file for OpenH323 Gatekeeper
#

# remove half updated or corrupt files
.DELETE_ON_ERROR:

PROG	 = gnugk
SOURCES  = Toolkit.cxx CountryCodeTables.cxx gk.cxx gkauth.cxx gkldap.cxx \
           gkDestAnalysis.cxx RasTbl.cxx GkClient.cxx MulticastGRQ.cxx	  \
           BroadcastListen.cxx SoftPBX.cxx h323util.cxx GkStatus.cxx	  \
           ProxyThread.cxx ProxyChannel.cxx singleton.cxx main.cxx	  \
           gkDatabase.cxx gkIniFile.cxx GkProfile.cxx RasListener.cxx     \
	   RasWorker.cxx Neighbor.cxx gklock.cxx

ifndef MANUFACTURER
MANUFACTURER = "Willamowius"
endif
ifndef PROGRAMMNAME
PROGRAMMNAME = "Gatekeeper"
endif
ifndef VERSION_MAJOR
VERSION_MAJOR = 2
endif
ifndef VERSION_MINOR
VERSION_MINOR = 1
endif
ifndef VERSION_STATUS
# might be: AlphaCode, BetaCode, ReleaseCode
VERSION_STATUS = AlphaCode
endif
ifndef VERSION_BUILD
VERSION_BUILD = 5
endif
ifndef OPENH323DIR
OPENH323DIR=$(HOME)/openh323
endif

# Gatekeeper Global Version String to mark object with version info in such
# a way that it is retrievable by the std. version/revision control tools
XID=$$Id
GKGVS="@(\#) $(XID): $(VERSION_STATUS) of "$(PROGRAMMNAME)" v$(VERSION_MAJOR).$(VERSION_MINOR) build\#$(VERSION_BUILD) by "${MANUFACTURER}" at " __DATE__ " "  __TIME__ " $$"

H323_INCDIR = ${OPENH323DIR}/include
H323_LIBDIR = ${OPENH323DIR}/lib
H323_LIB    = h323_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)

STDCCFLAGS := -I${H323_INCDIR}

# use for versioning
STDCCFLAGS += -D'MANUFACTURER=${MANUFACTURER}'
STDCCFLAGS += -D'PROGRAMMNAME=${PROGRAMMNAME}'
STDCCFLAGS += -D'VERSION_MAJOR=${VERSION_MAJOR}'
STDCCFLAGS += -D'VERSION_MINOR=${VERSION_MINOR}'
STDCCFLAGS += -D'VERSION_STATUS=${VERSION_STATUS}'
STDCCFLAGS += -D'VERSION_BUILD=${VERSION_BUILD}'
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
export LDAP1823DIR
endif # LDAP1823DIR
ifndef LDAP1823LIBDIR
LDAP1823LIBDIR := /usr/lib
export LDAP1823LIBDIR
endif # LDAP1823LIBDIR
# this is the file name of the lib. To the linker always flag (-l) with
# std. name 'ldap' is passed
ifndef LDAP1823LIBNM
LDAP1823LIBNM := libldap.so
export LDAP1823LIBNM
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
HAS_LEVEL_TWO_LDAPAPI=1
endif
endif # USE_EXTERNAL_LDAP

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
STDCCFLAGS	+= -D'MWBB1_TAG="$(MWBB1_TAG)"' -I$(MWBB1DIR)
LDFLAGS         += -L$(MWBB1LIBDIR)
ENDLDLIBS	+= -lmwc
ifneq (,$(LD_RUN_PATH))
LD_RUN_STUB     := $(LD_RUN_PATH)
LD_RUN_PATH     += $(LD_RUN_STUB):$(MWBB1LIBDIR)
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
LDAP_LIBDIR = ./ldap/lib
LDAP_LIB = $(LDAP_LIBDIR)/libldapapi_$(PLATFORM_TYPE)_$(OBJ_SUFFIX).$(LIB_SUFFIX)

SUBDIRS += ldap/src
LDLIBS	+= -lldapapi_$(PLATFORM_TYPE)_$(OBJ_SUFFIX) $(TMP_LDLIBS)
LDFLAGS += -L$(LDAP_LIBDIR)
HAS_LDAP	= 1
STDCCFLAGS	+= -I./ldap/include -D"HAS_LDAP=$(HAS_LDAP)" \
                   -D"HAS_LEVEL_TWO_LDAPAPI=$(HAS_LEVEL_TWO_LDAPAPI)" -D"LDAPVERSION=2"


ifneq (,$(LDAP_LIBDIR))
LD_RUN_STUB     := $(LD_RUN_PATH)
LD_RUN_PATH     += $(LD_RUN_STUB):$(LDAP_LIBDIR)
else
LD_RUN_PATH     += $(LDAP_LIBDIR)
endif
export LD_RUN_PATH


else
ifdef HAVE_LDAP1823_HDRS
ifdef HAVE_LDAP1823_LIBS
SOURCES         += ldaplink.cxx gk_ldap_interface.cxx
ENDLDLIBS	+= -lldap
HAS_LDAP	= 1
export HAS_LDAP
# due to the unwise naming of the libH323 header, the std. header 'ldap.h'
# would be hooded, if the include search path would not PREpended
STDCCFLAGS_STUB := $(STDCCFLAGS)
STDCCFLAGS	= -D"HAS_LDAP=$(HAS_LDAP)" -I$(LDAP1823DIR) $(STDCCFLAGS_STUB)
LDFLAGS         += -L$(LDAP1823LIBDIR)
ifneq (,$(LD_RUN_PATH))
LD_RUN_STUB     := $(LD_RUN_PATH)
LD_RUN_PATH     += $(LD_RUN_STUB):$(LDAP1823LIBDIR)
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
STDCCFLAGS_STUB := $(STDCCFLAGS)
STDCCFLAGS	= -DHAS_MYSQL -I$(MYSQLDIR) $(STDCCFLAGS_STUB)
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
# extra dependency to include the LDAPapi
$(TARGET):	$(OBJS) $(TARGET_LIBS)
endif

# delete time-stamp files on clean
CLEAN_FILES += gktimestamp.c ldaplibtimestamp.c

# delete corefiles (also the Linux-kind)
CLEAN_FILES += $(wildcard core.*)


addpasswd: $(OBJDIR)/addpasswd.o
	$(CPLUS) -o $(OBJDIR)/addpasswd $(CFLAGS) $(OBJDIR)/addpasswd.o $(LDFLAGS) $(LDLIBS) $(ENDLDLIBS)


doc: docs/manual.sgml
	cd docs; sgml2html manual.sgml

# These files are dummys to control the dependency of the GK and its
# libraries like LDAP-API, OpenH323Lib and PWLib. The VERSION_BUILD
# variable here is helpfull to monitor the operation
.SECONDARY: gktimestamp.c ldaplibtimestamp.c # Do not delete after creation
gktimestamp.c ldaplibtimestamp.c:
	-@echo '###=> Building time-stamp file $@'
	@echo '/* this file is autogenerated my make, editing is to no avail */\
               int buildID=$(VERSION_BUILD); /* should not be empty */' >  $@

# Extra dependencies
$(TARGET): gktimestamp.c
$(LDAP_LIB): ldaplibtimestamp.c
RasSrv.o: RasSrv.cxx
RasSrv.cxx: RasSrv.h
RasSrv.cxx: RasTbl.h
RasTbl.cxx: RasTbl.h
RasTbl.o: RasTbl.cxx
SignalChannel.o: SignalChannel.h
SignalConnection.o: SignalConnection.h
CallTbl.o: CallTbl.h
BroadcastListen.cxx: BroadcastListen.h

# probably needed!
OverlapSendingCallSignalSocket.o:  RasTbl.h
ProxyChannel.o: RasTbl.h
SignalConnection.o: RasTbl.h
SoftPBX.o: RasTbl.h
gkDestAnalysis.o: RasTbl.h
gkauth.o: RasTbl.h

# This models the dependencies between the GK and its
# libraries like LDAP-API, OpenH323Lib and PWLib.
gktimestamp.c: $(wildcard $(PWLIBDIR)/lib/libpt_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)*)
gktimestamp.c: $(wildcard $(OPENH323DIR)/lib/libh323_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)*)
gktimestamp.c: $(wildcard ldap/lib/libldapapi_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)*)

ldaplibtimestamp.c: $(wildcard $(PWLIBDIR)/lib/libpt_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)*)
ldaplibtimestamp.c: $(wildcard $(OPENH323DIR)/lib/libh323_$(PLATFORM_TYPE)_$(OBJ_SUFFIX)*)

# end
