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

#include "gkDestAnalysis.h"
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

const char *GkDestAnalysisSectionName = "Gatekeeper::DestAnalysis";

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
	                           PReadWriteMutex & listLock, endptr & ep, unsigned & reason);
	virtual int getDestination(const H225_LocationRequest &, list<EndpointRec *> & EPList, 
	                           PReadWriteMutex & listLock, endptr & ep, unsigned & reason);				   


private:		
	virtual int getDestination(const H225_ArrayOf_AliasAddress & alias, list<EndpointRec *> & EPList, 
	                           PReadWriteMutex & listLock, endptr & ep, unsigned & reason);
};

static GkDestAnalysisInit<OverlapSendDestAnalysis> OSDA("OverlapSendDestAnalysis");

//////////////////////////////////////////////////////////////////////

OverlapSendDestAnalysis::OverlapSendDestAnalysis(PConfig *cfg, const char * destAnalysisName) : GkDestAnalysis(cfg, destAnalysisName)
{
}


OverlapSendDestAnalysis::~OverlapSendDestAnalysis()
{
}

int OverlapSendDestAnalysis::getDestination(const H225_ArrayOf_AliasAddress & alias, list<EndpointRec *> & EPList,
                                            PReadWriteMutex & listLock, endptr & ep, unsigned & reason)
{
	//check if given aliases contain incomplete addresses
	//  (given aliases are prefixes of the aliases in registration table)
	bool partialMatch_found = 0;
	bool fullMatch;
	listLock.StartRead();
	std::list<EndpointRec *>::const_iterator Iter = EPList.begin(), IterLast = EPList.end();
	for (; Iter != IterLast && !partialMatch_found; Iter++) {
		if ((*Iter)->PrefixMatch_IncompleteAddress(alias, fullMatch)){
			if (!fullMatch) {
				partialMatch_found = 1;
			}
			ep = endptr(*Iter);
		}
	}
	listLock.EndRead();
	if (ep) {
		if (partialMatch_found) {
			// ARJ (incomplete address)
			reason = H225_AdmissionRejectReason::e_incompleteAddress;	    
		} else {
			// ACF
			PTRACE(4, "Alias match for EP " << AsDotString(ep->GetCallSignalAddress()));
			return e_ok;
		}
	} else {
		//TODO: LDAPSearch (alias is prefix or equal to number in LDAP voIP-schema 
		//        (default attribute: telephoneNumber)
		//TODO: if equal
		// ARJ (calledPartyNotRegistered)
		//reason = H225_AdmissionRejectReason::e_calledPartyNotRegistered;	    
		//TODO: else if result is a prefix of telephoneNumber
		// ARJ (incomplete alias)
		//reason = H225_AdmissionRejectReason::e_incompleteAddress;	    
		//TODO: else if no match
		// search for gw (longest match) in registration table
		int maxlen = 0;
		list<EndpointRec *> GWlist;
		listLock.StartRead();
		Iter = EPList.begin(), IterLast = EPList.end();
		while (Iter != IterLast) {
			if ((*Iter)->IsGateway()) {
	          		int len = dynamic_cast<GatewayRec *>(*Iter)->PrefixMatch(alias);
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
            	// if more than one longest match is found
	    	if (GWlist.size() > 0) {
			EndpointRec *e = GWlist.front();
	          	if (GWlist.size() > 1) {
				PTRACE(3, ANSI::DBG << "Prefix apply round robin" << ANSI::OFF);
				WriteLock lock(listLock);
				EPList.remove(e);
	          		EPList.push_back(e);
			}
	          	PTRACE(4, "Alias match for GW " << AsDotString(e->GetCallSignalAddress()));
	          	// TODO: reason -> ACF
			ep = endptr(e);
			return e_ok;
		}	    
		//TODO: else search for gw in ini-file
		//TODO: if found
			// ARJ (calledPartyNotRegisterd) This shall never happen. If we
			//   fail here, the last core gateway is broken.
			//reason = H225_AdmissionRejectReason::e_calledPartyNotRegistered;
		//TODO: else if not found
			// ARJ (unreachable destination)
			//reason = H225_AdmissionRejectReason::e_resourceUnavailable;	    	      
		}
	ep = endptr(0);
	return e_fail;	
}

int OverlapSendDestAnalysis::getDestination(const H225_AdmissionRequest & arq, list<EndpointRec *> & EPList,
                                            PReadWriteMutex & listLock, endptr & ep, unsigned & reason)
{
	return getDestination(arq.m_destinationInfo, EPList, listLock, ep, reason);
}

int OverlapSendDestAnalysis::getDestination(const H225_LocationRequest & lrq, list<EndpointRec *> & EPList,
                                            PReadWriteMutex & listLock, endptr & ep, unsigned & reason)
{
	return getDestination(lrq.m_destinationInfo, EPList, listLock, ep, reason);
}

GkDestAnalysis::GkDestAnalysis(PConfig *cfg, const char *destAnalysisName) : config(cfg), name(destAnalysisName), checkFlag(e_ALL)
{
	PStringArray control(config->GetString(GkDestAnalysisSectionName, name, "").Tokenise(";,"));
	if (PString(name) == "default")
		controlFlag = e_Sufficient,
		defaultStatus = Toolkit::AsBool(control[0]) ? e_ok : e_fail;
	else if (control[0] *= "optional")
		controlFlag = e_Optional, defaultStatus = e_next;
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
	PTRACE(1, "GkDestAnalysis\tRemove " << name << " rule");
	delete next;  // delete whole list recursively
}

int GkDestAnalysis::getDestination(const H225_AdmissionRequest &, list<EndpointRec *> & EPList,
                                   PReadWriteMutex & listLock, endptr & ep, unsigned & reason)
{
	return defaultStatus;
}

int GkDestAnalysis::getDestination(const H225_LocationRequest &, list<EndpointRec *> & EPList,
                                   PReadWriteMutex & listLock, endptr & ep, unsigned & reason)
{
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
	PStringList destAnalysisList(cfg->GetKeys(GkDestAnalysisSectionName));

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

