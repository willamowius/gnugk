//////////////////////////////////////////////////////////////////
//
// gkauth.h
//
// Gatekeeper authentication modules
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//
// History:
//      2001/09/19      initial version (Chih-Wei Huang)
//
//////////////////////////////////////////////////////////////////


#ifndef __gkauth_h_
#define __gkauth_h_


#ifndef _PTLIB_H
#include <ptlib.h>
#endif


class H225_GatekeeperRequest;
class H225_RegistrationRequest;
class H225_UnregistrationRequest;
class H225_AdmissionRequest;
class H225_BandwidthRequest;
class H225_DisengageRequest;
class H225_LocationRequest;
class H225_InfoRequest;


class GkAuthenticator {
public:
	enum Control {
		e_Optional,
		e_Required,
		e_Sufficient
	};

	enum Status {
		e_ok = 1,	// the request is authenticated
		e_fail = -1,	// the request should be rejected
		e_next = 0	// the request is undetermined
	};

	enum {
		e_GRQ = 0x0001,
		e_RRQ = 0x0002,
		e_URQ = 0x0004,
		e_ARQ = 0x0008,
		e_BRQ = 0x0010,
		e_DRQ = 0x0020,
		e_LRQ = 0x0040,
		e_IRQ = 0x0080,
		e_ALL = 0x00FF
	};

	GkAuthenticator(PConfig *, const char *authName = "default");
	virtual ~GkAuthenticator();

	template<class RasType> bool CheckRas(const RasType & req, unsigned & reason)
	{
		if (checkFlag & RasValue(req)) {
			int r = Check(req, reason);
			if (r == e_ok) {
				PTRACE(4, "GkAuth\t" << name << " check ok");
				if (controlFlag != e_Required)
					return true;
			} else if (r == e_fail) {
				PTRACE(2, "GkAuth\t" << name << " check failed");
				return false;
			}
		}
		// try next rule
		return (next) ? next->CheckRas(req, reason) : true;
	}

	const char *GetName() { return name; }

protected:
	// the second argument is the reject reason, if any
	virtual int Check(const H225_GatekeeperRequest &, unsigned &);
	virtual int Check(const H225_RegistrationRequest &, unsigned &);
	virtual int Check(const H225_UnregistrationRequest &, unsigned &);
	virtual int Check(const H225_AdmissionRequest &, unsigned &);
	virtual int Check(const H225_BandwidthRequest &, unsigned &);
	virtual int Check(const H225_DisengageRequest &, unsigned &);
	virtual int Check(const H225_LocationRequest &, unsigned &);
	virtual int Check(const H225_InfoRequest &, unsigned &);

	int RasValue(const H225_GatekeeperRequest &)     { return e_GRQ; }
	int RasValue(const H225_RegistrationRequest &)   { return e_RRQ; }
	int RasValue(const H225_UnregistrationRequest &) { return e_URQ; }
	int RasValue(const H225_AdmissionRequest &)      { return e_ARQ; }
	int RasValue(const H225_BandwidthRequest &)      { return e_BRQ; }
	int RasValue(const H225_DisengageRequest &)      { return e_DRQ; }
	int RasValue(const H225_LocationRequest &)       { return e_LRQ; }
	int RasValue(const H225_InfoRequest &)           { return e_IRQ; }

	Control controlFlag;
	Status defaultStatus;
	PConfig *config;

private:
	const char *name;
	int checkFlag;

	GkAuthenticator *next;
	static GkAuthenticator *head;

	GkAuthenticator(const GkAuthenticator &);
	GkAuthenticator & operator=(const GkAuthenticator &);

	friend class GkAuthenticatorList;
};


class GkAuthInitializer {
public:
	GkAuthInitializer(const char *);
	virtual ~GkAuthInitializer();
	// virtual constructor
	virtual GkAuthenticator *CreateAuthenticator(PConfig *) = 0;
	bool Compare(PString n) const;

protected:
	const char *name;
};

template<class GkAuth> class GkAuthInit : public GkAuthInitializer {
public:
	GkAuthInit(const char *n) : GkAuthInitializer(n) {}
	virtual GkAuthenticator *CreateAuthenticator(PConfig *config)
	{ return new GkAuth(config, name); }
};

class GkAuthenticatorList {
public:
	GkAuthenticatorList(PConfig *);
	~GkAuthenticatorList();

	template<class RasType> bool Check(const RasType & req, unsigned & reason)
	{
		return (GkAuthenticator::head) ? GkAuthenticator::head->CheckRas(req, reason) : true;
	}

private:
	GkAuthenticatorList(const GkAuthenticatorList &);
	GkAuthenticatorList & operator=(const GkAuthenticatorList &);
};


#endif  // __gkauth_h_

