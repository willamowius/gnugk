//////////////////////////////////////////////////////////////////
//
// gkDestAnalysis.h
//
// Gatekeeper destination analysis modules
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//
// History:
//      2002/01/23      initial version (Markus Muehlenbernd)
//
//////////////////////////////////////////////////////////////////


#ifndef __gkDestAnalysis_h_
#define __gkDestAnalysis_h_


#ifndef _PTLIB_H
#include <ptlib.h>
#endif

#include "RasTbl.h"

class H225_AdmissionRequest;


class GkDestAnalysis {
public:
	enum Control {
		e_Optional,
		e_Required,
		e_Sufficient
	};

	enum Status {
		e_ok = 1,	// the request is ok
		e_fail = -1,	// the request should be rejected
		e_next = 0	// the request is undetermined
	};

        enum {
		e_ARQ = 0x0001,
		e_LRQ = 0x0002,
		e_ALL = 0x00FF
	};

	GkDestAnalysis(PConfig *, const char *authName = "default");
	virtual ~GkDestAnalysis();

	template<class MsgType> bool getMsgDestination(const MsgType & req, list<EndpointRec *> & EPList, 
	                                               PReadWriteMutex & listLock, endptr & ep, unsigned & reason)
	{
		if (checkFlag & MsgValue(req)) {
			int r = getDestination(req, EPList, listLock, ep, reason);
			if (r == e_ok) {
				PTRACE(4, "GkDestAnalysis\t" << name << " check ok");
				if (controlFlag != e_Required)
					return true;
			} else if (r == e_fail) {
				PTRACE(2, "GkDestAnalysis\t" << name << " check failed");
				return false;
			}
		}
		// try next rule
		return (next) ? next->getMsgDestination(req, EPList, listLock, ep, reason) : true;
	}

	const char *GetName() { return name; }
	


protected:
	virtual int getDestination(const H225_AdmissionRequest &, list<EndpointRec *> & EPList, 
	                           PReadWriteMutex & listLock, endptr & ep, unsigned & reason);
	virtual int getDestination(const H225_LocationRequest &, list<EndpointRec *> & EPList, 
	                           PReadWriteMutex & listLock, endptr & ep, unsigned & reason);				   

	int MsgValue(const H225_AdmissionRequest &)      { return e_ARQ; }
	int MsgValue(const H225_LocationRequest &)      { return e_LRQ; }

	Control controlFlag;
	Status defaultStatus;
	PConfig *config;

private:
	const char *name;
	int checkFlag;

	GkDestAnalysis *next;
	static GkDestAnalysis *head;

	GkDestAnalysis(const GkDestAnalysis &);
	GkDestAnalysis & operator=(const GkDestAnalysis &);
	
	friend class GkDestAnalysisList;
};


class GkDestAnalysisInitializer {
public:
	GkDestAnalysisInitializer(const char *);
	virtual ~GkDestAnalysisInitializer();
	// virtual constructor
	virtual GkDestAnalysis *CreateDestAnalysis(PConfig *) = 0;
	bool Compare(PString n) const;

protected:
	const char *name;
};

template<class GkDestAnalysisT> class GkDestAnalysisInit : public GkDestAnalysisInitializer {
public:
	GkDestAnalysisInit(const char *n) : GkDestAnalysisInitializer(n) {}
	virtual GkDestAnalysis *CreateDestAnalysis(PConfig *config)
	{ return new GkDestAnalysisT(config, name); }
};

class GkDestAnalysisList {
public:
	GkDestAnalysisList(PConfig *);
	virtual ~GkDestAnalysisList();

	template<class MsgType> bool getMsgDestination(const MsgType & req, 
	                                               list<EndpointRec *> & EPList, 
	                                               PReadWriteMutex & listLock,
						       endptr & ep, 
						       unsigned & reason)
	{
		return (GkDestAnalysis::head) ? GkDestAnalysis::head->getMsgDestination(req, EPList, listLock, ep, reason) : true;
	}

private:
	GkDestAnalysisList(const GkDestAnalysisList &);
	GkDestAnalysisList & operator=(const GkDestAnalysisList &);
};


#endif  // __gkDestAnalysis_h_

