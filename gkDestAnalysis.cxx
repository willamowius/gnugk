// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// gkDestAnalysis.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//      2002/01/23      initial version (Markus Muehlenbernd)
//
//////////////////////////////////////////////////////////////////

//#ifdef WITH_DEST_ANALYSIS_LIST

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include "gkDatabase.h"
#include "gkDestAnalysis.h"
#include "gkIniFile.h"
#include "stl_supp.h"
#include "Toolkit.h"
#include "h323util.h"
#include "ANSI.h"

#ifdef P_SOLARIS
#define map stl_map
#endif

#include <map>
#include <list>

using std::map;
using std::list;

const char *GK_DEST_ANALYSIS_SECTION_NAME = "Gatekeeper::DestAnalysis";

GkDestAnalysis *GkDestAnalysis::head = 0;

static GkDestAnalysisInit<GkDestAnalysis> _defaultGKDA_("default");

//////////////////////////////////////////////////////////////////////
// Definition of destination analysis rules

class OverlapSendDestAnalysis : public GkDestAnalysis {
public:
	OverlapSendDestAnalysis(PConfig *, const char *);
	virtual ~OverlapSendDestAnalysis();

protected:
	virtual int getDestination(const H225_AdmissionRequest &, list<EndpointRec *> & EPList,
	                           PReadWriteMutex & listLock, endptr & cgEP, endptr & cdEP, unsigned & reason);
	virtual int getDestination(const H225_LocationRequest &, list<EndpointRec *> & EPList,
	                           PReadWriteMutex & listLock, endptr & cgEP, endptr & cdEP, unsigned & reason);
	virtual int getDestination(const H225_AliasAddress & alias, list<EndpointRec *> & EPList,
	                           PReadWriteMutex & listLock, const endptr & cgEP, endptr & cdEP, unsigned & reason);

private:

	/** Adds country code from ini section RasSvr::GWCoutryCodes to
	    calledPN (dialedDigits)  and returns new PN + gwCC
	 */
	void AddCCToCdAlias(H225_AliasAddress &alias, const PString & gwCC);

	/** Matches the cdAlias left justified against voIPspecialDial-fields (in LDAP) of the caller
	    and returns the real called alias and the match status.
	 */
	PString MatchSpecialDial(const callptr &callRec, H225_AliasAddress &cdAlias,
				 bool &partialMatch, bool &fullMatch);

	/** Converts a called alias to international format. The function returns
	    #FALSE# if the conversion does not succeed.
	 */
	BOOL PrefixAnalysis(const CallingProfile &callingProfile, H225_AliasAddress &cdPN,
			    PString &internationalCdPN, unsigned int &reason);
};

static GkDestAnalysisInit<OverlapSendDestAnalysis> OSDA("OverlapSendDestAnalysis");

//////////////////////////////////////////////////////////////////////

OverlapSendDestAnalysis::OverlapSendDestAnalysis(PConfig *cfg, const char * destAnalysisName) : GkDestAnalysis(cfg, destAnalysisName)
{
}


OverlapSendDestAnalysis::~OverlapSendDestAnalysis()
{
}

void OverlapSendDestAnalysis::AddCCToCdAlias(H225_AliasAddress &alias, const PString & gwCC)
{
	// it makes no sence to add CC to an H323ID
	if (alias.GetTag() != H225_AliasAddress::e_dialedDigits) {
		return;
	}

        PString oldCdAlias = H323GetAliasAddressString(alias);
        PString newCdAlias = gwCC + oldCdAlias;

        H323SetAliasAddress(newCdAlias, alias);
        PTRACE(5, "\tRewriteCdAlias: " << oldCdAlias << " to " << newCdAlias);
}

PString OverlapSendDestAnalysis::MatchSpecialDial(const callptr &callRec, H225_AliasAddress &cdAlias, bool &partialMatch, bool &fullMatch)
{
        partialMatch = FALSE;
        fullMatch = FALSE;
	PString realCdAlias;

        PString cdAliasStr = H323GetAliasAddressString(cdAlias);
        unsigned int cdAliasStrLen = cdAliasStr.GetLength();

        const PStringToString &spDialMap = callRec->GetCallingProfile().getSpecialDials();

	PString key;
	for (PINDEX i=0; i < spDialMap.GetSize() && !partialMatch; i++) {
        // for all special dials (emergency calls)
		key = spDialMap.GetKeyAt(i);
                if ((key.GetLength() >= cdAliasStrLen) &&
				(cdAliasStr == key.Left(cdAliasStrLen))) {
			if (cdAliasStr == key) {
			// full match
				fullMatch = TRUE;
				PTRACE(4, "Full match with special dial");
			} else {
                        // partial match
				fullMatch = FALSE;
				partialMatch = TRUE;
				PTRACE(4, "Partial match with special dial");
			}
                        realCdAlias = spDialMap.GetDataAt(i);
		}
	}

        return realCdAlias;
}

BOOL OverlapSendDestAnalysis::PrefixAnalysis(const CallingProfile &callingProfile, H225_AliasAddress &cdAlias, PString &internationalCdAlias, unsigned int &reason)
{
        PString oldCdAlias = H323GetAliasAddressString(cdAlias);

	// it makes only sence to analyse dialedDigits
	if (cdAlias.GetTag() != H225_AliasAddress::e_dialedDigits) {
		internationalCdAlias = oldCdAlias;
		return TRUE;
	}

	// take first telephoneNumber from cgProfile and analyse it
	PString cgAlias;
	if (callingProfile.getTelephoneNumbers().GetSize() > 0) {
		cgAlias = callingProfile.getTelephoneNumbers()[0];
	}
	E164_AnalysedNumber tele(cgAlias);

	const PString lac = callingProfile.getLac();
	const PString prefixInternational = callingProfile.getInac();
	const PString subscriberNumber = callingProfile.getSubscriberNumber();
	const PString &countryCode = tele.GetCC().GetValue();
	PString prefixNational = callingProfile.getNac();
	const PString &areaCode = tele.GetNDC_IC().GetValue();
	bool bReject = FALSE;

	int oldCdAliasLen = oldCdAlias.GetLength();
	//inac match
	int len = prefixInternational.GetLength();
	//if full match
	if (prefixInternational == oldCdAlias.Left(len)) {
		//cut off international prefix
		internationalCdAlias = oldCdAlias.Right(oldCdAliasLen - len);
		PTRACE(5, "International call");
	//else if partial match
	} else if (oldCdAlias == prefixInternational.Left(oldCdAliasLen)) {
		//ARJ (incomplete address)
		reason = H225_AdmissionRejectReason::e_incompleteAddress;
		bReject = TRUE;
	//else if no match
	} else {
		//nac match
		len = prefixNational.GetLength();
		//if full match
		if (prefixNational == oldCdAlias.Left(len)) {
			//cut off national prefix and add country code of CgAlias
			internationalCdAlias = countryCode + oldCdAlias.Right(oldCdAliasLen - len);
			PTRACE(5, "National call");
		//else if partial match
		} else if (oldCdAlias == prefixNational.Left(oldCdAliasLen)) {
			//ARJ (incomplete address)
			reason = H225_AdmissionRejectReason::e_incompleteAddress;
			bReject = TRUE;
		//else if no match
		} else {
			//lac match
			len = lac.GetLength();
			//if full match
			if(lac == oldCdAlias.Left(len)) {
				//cut off lac and add country code, area code of CgAlias
				internationalCdAlias = countryCode + areaCode +
				          oldCdAlias.Right(oldCdAliasLen - len);
				PTRACE(5, "Local call");
			//else if partial match
			} else if (oldCdAlias == lac.Left(oldCdAliasLen)) {
				//ARJ (incomplete address)
				reason = H225_AdmissionRejectReason::e_incompleteAddress;
				bReject = TRUE;
			//else if no match
			} else {
				//add calling alias
//				internationalCdAlias = GkDatabase::Instance()->rmInvalidCharsFromTelNo(cgAlias) + oldCdAlias;
				internationalCdAlias =  countryCode + areaCode + subscriberNumber +
					oldCdAlias;
				PTRACE(5, "Internal call");
			}
		}
	}
	return !bReject;
}

int OverlapSendDestAnalysis::getDestination(const H225_AliasAddress & cdAlias, list<EndpointRec *> & EPList,
                                            PReadWriteMutex & listLock, const endptr & cgEP, endptr & cdEP, unsigned & reason)
{
/* returns:
     cdEP!=0 for ACF
     cdEP==0 for ARJ
 */
	// get callRec
	callptr callRec = CallTable::Instance()->FindCallRec(cgEP);

	H225_AliasAddress destAlias = cdAlias;

	// get srcH323ID from cgProfile (for searching cgEP in databases)
	PString srcH323IDStr = callRec->GetCallingProfile().getH323ID();
	// if srcH323ID was not found (destAnalysis is called the first time
	//   for this cgEP)
	if (srcH323IDStr.IsEmpty()) {
		//get first srcH323ID from endpointRec
		H225_AliasAddress srcH323ID;
		if (cgEP->GetH323ID(srcH323ID)) {
			srcH323IDStr = H323GetAliasAddressString(srcH323ID);
		} else {
			//ARJ
			PTRACE(4, "H323ID does not exist for calling endpoint " << cgEP->GetEndpointIdentifier());
			cdEP = endptr(0);
			return e_fail;
		}
	}

	GkDatabase *db = GkDatabase::Instance();

	using namespace dctn;
	DBTypeEnum dbType;

	//store data from database in cgProfile
	// if it is not done up to now
	if (callRec->GetCallingProfile().getH323ID().IsEmpty()) {
		// if no profile is found
		if (!db->getProfile(callRec->GetCallingProfile(), srcH323IDStr, dbType)) {
			// if section "Gatekeeper::Databases" exists in ini-file then a
			// profile must be found
			PStringList sections = GkConfig()->GetSections();
			PINDEX pos = sections.GetStringsIndex(PString(GK_DATABASES_SECTION_NAME));
			// if section is found
			if (P_MAX_INDEX != pos) {
				reason = H225_AdmissionRejectReason::e_callerNotRegistered;
				// ARJ
				cdEP = endptr(0);
				return e_fail;
			}
		}
	}

        // Checking for special dials or running the prefix analysis can only be done
	// if a profile exists
	if (!callRec->GetCallingProfile().getH323ID().IsEmpty()) {
		if (!callRec->GetCallingProfile().isCPE()) {
			PTRACE(4, "trunk GW");
			// add country code to calledPN
			AddCCToCdAlias(destAlias, callRec->GetCallingProfile().getCC());
		} else {
			PTRACE(4, "not trunk GW");
			// match CdPN left justified against voIPspecialDial
			bool partialMatch, fullMatch;
			// if MatchSpecialDial succeeds
			PString realCalledAlias = MatchSpecialDial(callRec, destAlias, partialMatch, fullMatch);
			if (fullMatch) {
				// set dialed cdPN and real cdPN in cdProfile
				PString destAliasStr = H323GetAliasAddressString(destAlias);
				callRec->GetCalledProfile().setDialedPN(destAliasStr);
				callRec->GetCalledProfile().setCalledPN(realCalledAlias);
				// rewrite destInfo
				PTRACE(5, "\tRewriteCdAlias: " << destAliasStr
					<< " to real called " << realCalledAlias);
				H323SetAliasAddress(realCalledAlias, destAlias);
			} else if (partialMatch) {
				reason = H225_AdmissionRejectReason::e_incompleteAddress;
				// ARJ/ACF
				cdEP = (callRec->GetCallingProfile().honorsARJincompleteAddress()) ? endptr(0) : cgEP;
				return e_fail;
			} else {
				PString internationalCdPN;
				// if prefix analysis succeeds
				if(PrefixAnalysis(callRec->GetCallingProfile(), destAlias,
						  internationalCdPN, reason)) {
					// set dialed cdPN and real cdPN in cdProfile
					PString destAliasStr = H323GetAliasAddressString(destAlias);
					callRec->GetCalledProfile().setDialedPN(destAliasStr);
					callRec->GetCalledProfile().setCalledPN(internationalCdPN);
					// rewrite destInfo
					PTRACE(1, "\tRewriteCdAlias: " << destAlias
						<< " to international " << internationalCdPN);
					H323SetAliasAddress(internationalCdPN, destAlias);
				} else {
					// ARJ
					cdEP = endptr(0);
					return e_fail;
				}
			}
		}
	}

	// apply rewrite rules
	Toolkit::Instance()->RewriteE164(destAlias);

	// now we have an international calledPN (if a profile exists)
	// and we can start with routing descision...

	GkDestAnalysis::Status statusRoutingDecision = e_fail;

	//check for full match and incomplete address
	BOOL partialMatchFound = FALSE;
	BOOL fullMatch = FALSE;
	listLock.StartRead();
	std::list<EndpointRec *>::const_iterator Iter = EPList.begin(), IterLast = EPList.end();
	for (; Iter != IterLast && !partialMatchFound; Iter++) {
		partialMatchFound = (*Iter)->AliasIsIncomplete(destAlias, fullMatch);
		if (!partialMatchFound && (*Iter)->IsGateway()) {
			partialMatchFound = dynamic_cast<GatewayRec *>(*Iter)->PrefixIsIncomplete(destAlias, fullMatch);
		}
		// if any match is found
		if (partialMatchFound || fullMatch) {
			PTRACE(3, "getDestination: " << (**Iter).PrintOn(true) << "\n full:" << fullMatch);
			cdEP = endptr(*Iter);
		}
	}
	listLock.EndRead();

	// if any match was found
	if (cdEP) {
		PTRACE(3, "getDestination2: "<< cdEP->PrintOn(true));
		if (partialMatchFound) {
			// ARJ/ACF (incompleteAddress)
			reason = H225_AdmissionRejectReason::e_incompleteAddress;
			// we sent an ARJ if no profile exists or the endpoint
			// accepts ARJ with reason "incompleteAddress"
			if (callRec->GetCallingProfile().getH323ID().IsEmpty() ||
			    callRec->GetCallingProfile().honorsARJincompleteAddress())
				cdEP = endptr(0);
			statusRoutingDecision = e_fail;
		} else {
			// ACF
			PTRACE(4, "Alias match for EP " << AsDotString(cdEP->GetCallSignalAddress()));
			statusRoutingDecision = e_ok;
		}
	} else {
		PTRACE(3, "not even 1 EP found in registration table");

		BOOL matchFound = FALSE;
		BOOL gwFound = FALSE;
		using namespace dctn;
		DBTypeEnum dbType;
		// if a profile exists we search for an endpoint in existing databases
		PTRACE(3, "searching for EP in databases");
		BOOL profileExists = !callRec->GetCallingProfile().getH323ID().IsEmpty();
		if (profileExists && !db->prefixMatch(destAlias, TelephoneNo, matchFound, fullMatch, gwFound, dbType)) {
			PTRACE(1, "Database access failed!");
		} else {
			if (profileExists) {
				PTRACE(3, "GkDatabase matches: " << matchFound << " " << fullMatch << " " << gwFound);
			}
			if (profileExists && fullMatch) {
				// ARJ (calledPartyNotRegistered)
				reason = H225_AdmissionRejectReason::e_calledPartyNotRegistered;
				cdEP = endptr(0);
				statusRoutingDecision = e_fail;
			// else if result is a prefix of a TelephoneNo attribute
			} else if (profileExists && matchFound && !fullMatch && !gwFound) {
				// ARJ/ACF (incompleteAddress)
				reason = H225_AdmissionRejectReason::e_incompleteAddress;
				cdEP = (callRec->GetCallingProfile().honorsARJincompleteAddress()) ? endptr(0) : cgEP;
				statusRoutingDecision = e_fail;
			// else if no match is found
			} else if (profileExists && !matchFound) {
				// ARJ (unreachable destination)
				reason = H225_AdmissionRejectReason::e_resourceUnavailable;
				cdEP = endptr(0);
				statusRoutingDecision = e_fail;
			// else if no profile exists or any gateway is found
			} else {
				// search for gw (longest match) in registration table
				int maxlen = 0;
				list<EndpointRec *> GWlist;
				H225_ArrayOf_AliasAddress destAliases;
				destAliases.SetSize(1);
				destAliases[0] = destAlias;
				listLock.StartRead();
				Iter = EPList.begin(), IterLast = EPList.end();
				while (Iter != IterLast) {
					if ((*Iter)->IsGateway()) {
						int len = dynamic_cast<GatewayRec *>(*Iter)->PrefixMatch(destAliases);
						if (maxlen < len) {
							GWlist.clear();
							maxlen = len;
						}
						if (maxlen == len)
							GWlist.push_back(*Iter);
					}
					++Iter;
				}
				listLock.EndRead();
				// if a gateway is found in registration table
				if (GWlist.size() > 0) {
					EndpointRec *e = GWlist.front();
					// if more than one longest match is found
					if (GWlist.size() > 1) {
						PTRACE(3, ANSI::DBG << "Prefix apply round robin" << ANSI::OFF);
						WriteLock lock(listLock);
						EPList.remove(e);
						EPList.push_back(e);
					}
					// ACF
					PTRACE(4, "Alias match for GW " << AsDotString(e->GetCallSignalAddress()));
					cdEP = endptr(e);
					statusRoutingDecision = e_ok;
				// else if no gateway is found in registration table
				} else {
					// ARJ (calledPartyNotRegisterd)
					reason = H225_AdmissionRejectReason::e_calledPartyNotRegistered;
					cdEP = endptr(0);
					statusRoutingDecision = e_fail;
				}
			}
		}
	}

	// if profile exists we set status "isCPE" in called profile
	if (!callRec->GetCallingProfile().getH323ID().IsEmpty() &&
			statusRoutingDecision == e_ok) {
		//TODO: get destH323ID from cdProfile
		//PString destH323IDStr = callRec->GetCalledProfile().getH323ID();
		PString destH323IDStr;
		// if destH323ID was not found (destAnalysis is called the first time
		//   for this calling EP)
		if (destH323IDStr.IsEmpty()) {
			//get first destH323ID from endpointRec
			H225_AliasAddress destH323ID;
			if (cdEP->GetH323ID(destH323ID)) {
				destH323IDStr = H323GetAliasAddressString(destH323ID);
			} else {
				//ARJ
				PTRACE(4, "H323ID does not exist for called endpoint " << cdEP->GetEndpointIdentifier());
				cdEP = endptr(0);
				statusRoutingDecision = e_fail;
			}
			// set CPE flag in the cdProfile
			callRec->GetCalledProfile().setIsCPE(db->isCPE(destH323IDStr, dbType));
		}
	}
	return statusRoutingDecision;
}

int OverlapSendDestAnalysis::getDestination(const H225_AdmissionRequest & arq, list<EndpointRec *> & EPList,
                                            PReadWriteMutex & listLock, endptr & cgEP, endptr & cdEP, unsigned & reason)
{
	if (!cgEP) {
		cgEP = RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier);
	}
	BOOL found = FALSE;
	int status=0;
	// check destAliases until a cdEP is found
	for (PINDEX i=0; i < arq.m_destinationInfo.GetSize() && !found; i++) {
		status = getDestination(arq.m_destinationInfo[i], EPList, listLock, cgEP, cdEP, reason);
		if (cdEP) {
			found = TRUE;
		}
	}
	return status;
}

int OverlapSendDestAnalysis::getDestination(const H225_LocationRequest & lrq, list<EndpointRec *> & EPList,
                                            PReadWriteMutex & listLock, endptr & cgEP, endptr & cdEP, unsigned & reason)
{
	if (!cgEP) {
		cgEP = RegistrationTable::Instance()->FindByEndpointId(lrq.m_endpointIdentifier);
	}
	BOOL found = FALSE;
	int status=0;
	// check destAliases until a cdEP is found
	for (PINDEX i=0; i < lrq.m_destinationInfo.GetSize() && !found; i++) {
		status = getDestination(lrq.m_destinationInfo[i], EPList, listLock, cgEP, cdEP, reason);
		if (cdEP) {
			found = TRUE;
		}
	}
	return status;
}


GkDestAnalysis::GkDestAnalysis(PConfig *cfg, const char *destAnalysisName) : config(cfg), name(destAnalysisName), checkFlag(e_ALL)
{
	PStringArray control(config->GetString(GK_DEST_ANALYSIS_SECTION_NAME, name, "").Tokenise(";,"));
	if (PString(name) == "default")
		controlFlag = e_Sufficient,
		defaultStatus = Toolkit::AsBool(control[0]) ? e_ok : e_fail;
	else if (control[0] *= "optional")
		controlFlag = e_Optional, defaultStatus = e_next;
	else if (control[0] *= "alternative")
		controlFlag = e_Alternative, defaultStatus = e_next;
	else if (control[0] *= "required")
		controlFlag = e_Required, defaultStatus = e_fail;
	else
		controlFlag = e_Sufficient, defaultStatus = e_fail;

	if (control.GetSize() > 1) {
		checkFlag = 0;
		map<PString, int> msgmap;
		msgmap["ARQ"] = e_ARQ;
		msgmap["LRQ"] = e_LRQ;
		for (PINDEX i=1; i < control.GetSize(); ++i) {
			if (msgmap.find(control[i]) != msgmap.end())
				checkFlag |= msgmap[control[i]];
		}
	}

	next = head;
	head = this;

	PTRACE(1, "GkDestAnalysis\tAdd " << name << " rule with flag " << hex << checkFlag << dec);
}

GkDestAnalysis::~GkDestAnalysis()
{
	deleteMutex.Wait();
	PTRACE(1, "GkDestAnalysis\tRemove " << name << " rule");
	delete next;  // delete whole list recursively
}

int GkDestAnalysis::getDestination(const H225_AdmissionRequest &, list<EndpointRec *> & EPList,
                                   PReadWriteMutex & listLock, endptr & cgEP, endptr & cdEP, unsigned & reason)
{
	PTRACE(1, "called GkDestAnalysis::getDestination()");
	return defaultStatus;
}

int GkDestAnalysis::getDestination(const H225_LocationRequest &, list<EndpointRec *> & EPList,
                                   PReadWriteMutex & listLock, endptr & cgEP, endptr & cdEP, unsigned & reason)
{
	PTRACE(1, "called GkDestAnalysis::getDestination()");
	return defaultStatus;
}

int GkDestAnalysis::getDestination(const H225_AliasAddress &, list<EndpointRec *> & EPList,
                                   PReadWriteMutex & listLock, const endptr & cgEP, endptr & cdEP, unsigned & reason)
{
	PTRACE(1, "called GkDestAnalysis::getDestination()");
	return defaultStatus;
}

static list<GkDestAnalysisInitializer *> *destAnalysisNameList;

GkDestAnalysisInitializer::GkDestAnalysisInitializer(const char *n) : name(n)
{
	static list<GkDestAnalysisInitializer *> aList;
	destAnalysisNameList = &aList;

	destAnalysisNameList->push_back(this);
}

GkDestAnalysisInitializer::~GkDestAnalysisInitializer()
{
}

bool GkDestAnalysisInitializer::Compare(PString n) const
{
	return n == name;
}

GkDestAnalysisList::GkDestAnalysisList(PConfig *cfg)
{
	PStringList destAnalysisList(cfg->GetKeys(GK_DEST_ANALYSIS_SECTION_NAME));

	for (PINDEX i=destAnalysisList.GetSize(); i-- > 0; ) {
		PString destAnalysisName(destAnalysisList[i]);
		std::list<GkDestAnalysisInitializer *>::iterator Iter =
			find_if(destAnalysisNameList->begin(), destAnalysisNameList->end(),
				bind2nd(mem_fun(&GkDestAnalysisInitializer::Compare), destAnalysisName));
		if (Iter != destAnalysisNameList->end())
			(*Iter)->CreateDestAnalysis(cfg);
#ifdef PTRACING
		else
			PTRACE(1, "GkDestAnalysis\tUnknown destAnalysis " << destAnalysisName << ", ignore!");
#endif
	}
}

GkDestAnalysisList::~GkDestAnalysisList()
{
	delete GkDestAnalysis::head;
	GkDestAnalysis::head = 0;
}

// Blacklist blocking feature

class BlackWhiteListAnalysis : public GkDestAnalysis {
public:
	BlackWhiteListAnalysis(PConfig *, const char *);
	virtual ~BlackWhiteListAnalysis();

protected:
	virtual int getDestination(const H225_AdmissionRequest &, list<EndpointRec *> & EPList,
                                   PReadWriteMutex & listLock, endptr & cgEP, endptr & cdEP, unsigned & reason)
		{
			PAssert(cgEP, "Cannot get List without CalledEndpoint");
			BOOL found=FALSE;
			callptr callRec = CallTable::Instance()->FindCallRec(cgEP);
			PString DialedDigits = callRec->GetCalledProfile().getCalledPN();
			CallingProfile cgpf = callRec->GetCallingProfile();
			PTRACE(5,"getDestination BlackWhiteList");
			found=CheckNumberInList(DialedDigits, cgpf, reason);
			if(found)
				cdEP=endptr(0);
			return e_ok;
		}

	virtual int getDestination(const H225_AliasAddress &, list<EndpointRec *> & EPList,
                                   PReadWriteMutex & listLock, endptr & cgEP, endptr & cdEP, unsigned & reason)
		{
			PAssert(cgEP, "Cannot get List without CalledEndpoint");
			BOOL found=FALSE;
			callptr callRec = CallTable::Instance()->FindCallRec(cgEP);
			PString DialedDigits = callRec->GetCalledProfile().getCalledPN();
			CallingProfile cgpf = callRec->GetCallingProfile();
			PTRACE(5,"getDestination BlackWhiteList");
			found=CheckNumberInList(DialedDigits, cgpf, reason);
			if(found)
				cdEP=endptr(0);
			return e_ok;
		}

private:
	BOOL CheckNumberInList(const PString CalledPartyNumber, const CallingProfile cgpf, unsigned & reason);

};

static GkDestAnalysisInit<BlackWhiteListAnalysis> BLDA("BlackWhiteListDestinationAnalysis");

BlackWhiteListAnalysis::BlackWhiteListAnalysis(PConfig *cfg, const char *destAnalysisName) : GkDestAnalysis(cfg, destAnalysisName)
{
}

BlackWhiteListAnalysis::~BlackWhiteListAnalysis()
{
}

BOOL BlackWhiteListAnalysis::CheckNumberInList(const PString CalledPartyNumber, const CallingProfile cgpf, unsigned & reason)
{
	BOOL found=FALSE;
	PStringList BlackList=cgpf.getBlackList();
	PStringList WhiteList=cgpf.getWhiteList();
	PTRACE(5,"Starting Blacklist-search");
	for(PINDEX i=0; i < BlackList.GetSize() && !found; i++) {
		PTRACE(6,"Checking for " << BlackList[i] << ":" <<  CalledPartyNumber << endl <<
		       BlackList[i].GetLength() << "," << CalledPartyNumber.GetLength());
		if(BlackList[i].GetLength() <= CalledPartyNumber.GetLength() && BlackList[i]==CalledPartyNumber.Left(BlackList[i].GetLength())) {
			PTRACE(5, "Hit Blacklist  " << BlackList[i]);
			found=TRUE;
			reason=H225_AdmissionRejectReason::e_invalidPermission;
		}
	}
	PTRACE(5,"Starting Whitelist-search");
	for(PINDEX i=0; i < WhiteList.GetSize() && found; i++) {
		PTRACE(6,"Checking for " << WhiteList[i]);
		if(WhiteList[i].GetLength() <= CalledPartyNumber.GetLength() && WhiteList[i]==CalledPartyNumber.Left(WhiteList[i].GetLength())) {
			PTRACE(5, "Hit Whitelist  " << WhiteList[i]);
			found=FALSE;
		}
	}
	return found;
}


class WhiteBlackListAnalysis : public GkDestAnalysis {
public:
	WhiteBlackListAnalysis(PConfig *, const char *);
	virtual ~WhiteBlackListAnalysis();

protected:
	virtual int getDestination(const H225_AdmissionRequest &a, list<EndpointRec *> & EPList,
                                   PReadWriteMutex & listLock, endptr & cgEP, endptr & cdEP, unsigned & reason)
		{
			PAssert(cgEP, "Cannot get List without CalledEndpoint");
			BOOL found=FALSE;
			callptr callRec = CallTable::Instance()->FindCallRec(cgEP);
			PString DialedDigits = callRec->GetCalledProfile().getCalledPN();
			CallingProfile cgpf = callRec->GetCallingProfile();
			PTRACE(5,"getDestination WhiteBlackList");
			found=CheckNumberInList(DialedDigits, cgpf, reason);
			if(found)
				cdEP=endptr(0);
			return e_ok;
		}

	virtual int getDestination(const H225_AliasAddress &a, list<EndpointRec *> & EPList,
                                   PReadWriteMutex & listLock, endptr & cgEP, endptr & cdEP, unsigned & reason)
		{
			PAssert(cgEP, "Cannot get List without CalledEndpoint");
			BOOL found=FALSE;
			callptr callRec = CallTable::Instance()->FindCallRec(cgEP);
			PString DialedDigits = callRec->GetCalledProfile().getCalledPN();
			CallingProfile cgpf = callRec->GetCallingProfile();
			PTRACE(5,"getDestination WhiteBlackList");
			found=CheckNumberInList(DialedDigits, cgpf, reason);
			if(found)
				cdEP=endptr(0);
			return e_ok;
		}

private:
	BOOL CheckNumberInList(const PString CalledPartyNumber, const CallingProfile cgpf, unsigned & reason);

};

static GkDestAnalysisInit<WhiteBlackListAnalysis> WLDA("WhiteBlackListDestinationAnalysis");

WhiteBlackListAnalysis::WhiteBlackListAnalysis(PConfig *cfg, const char *destAnalysisName) : GkDestAnalysis(cfg, destAnalysisName)
{
}

WhiteBlackListAnalysis::~WhiteBlackListAnalysis()
{
}

BOOL WhiteBlackListAnalysis::CheckNumberInList(const PString CalledPartyNumber, const CallingProfile cgpf, unsigned & reason)
{
	BOOL found=TRUE;
	PStringList BlackList=cgpf.getBlackList();
	PStringList WhiteList=cgpf.getWhiteList();
	PTRACE(5,"Starting Whitelist-search "<< WhiteList);
	for(PINDEX i=0; i < WhiteList.GetSize() && found; i++) {
		PTRACE(6,"Checking Whitelist for " << WhiteList[i]);
		if(WhiteList[i].GetLength() <= CalledPartyNumber.GetLength() && WhiteList[i]==CalledPartyNumber.Left(WhiteList[i].GetLength())) {
			PTRACE(5, "Found White hit: " << WhiteList[i] << ":" << CalledPartyNumber);
			found=FALSE;
		}
	}
	for(PINDEX i=0; i < BlackList.GetSize() && !found; i++) {
		PTRACE(6,"Checking Blacklist for " << BlackList[i]);
		if(BlackList[i].GetLength() <= CalledPartyNumber.GetLength() && BlackList[i]==CalledPartyNumber.Left(BlackList[i].GetLength())) {
			PTRACE(5, "Hit Blacklist  " << BlackList[i]);
			found=TRUE;
			reason=H225_AdmissionRejectReason::e_invalidPermission;
		}
	}
	return found;
}

//#endif // WITH_DEST_ANALYSIS_LIST
