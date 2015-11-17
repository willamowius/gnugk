/*
 * ipauth.h
 *
 * IP based authentication modules
 *
 * Copyright (c) 2005, Michal Zygmuntowicz
 * Copyright (c) 2006-2013, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#ifndef IPAUTH_H
#define IPAUTH_H "@(#) $Id$"

#include "gkauth.h"

/// Generic IP based authentication
class IPAuthBase : public GkAuthenticator {
public:
	enum SupportedRasChecks {
		/// bitmask of RAS checks implemented by this module
		IPAuthRasChecks = RasInfo<H225_RegistrationRequest>::flag
			| RasInfo<H225_AdmissionRequest>::flag
			| RasInfo<H225_GatekeeperRequest>::flag
			| RasInfo<H225_UnregistrationRequest>::flag
			| RasInfo<H225_BandwidthRequest>::flag
			| RasInfo<H225_DisengageRequest>::flag
			| RasInfo<H225_LocationRequest>::flag
			| RasInfo<H225_InfoRequest>::flag
			| RasInfo<H225_ResourcesAvailableIndicate>::flag
	};
	enum SupportedMiscChecks {
		/// bitmask of Misc checks implemented by this module
        IPAuthMiscChecks = e_Setup
            | e_SetupUnreg
            | e_Connect
            | e_CallProceeding
            | e_Alerting
            | e_Information
            | e_ReleaseComplete
            | e_Facility
            | e_Progress
            | e_Empty
            | e_Status
            | e_StatusEnquiry
            | e_SetupAck
            | e_Notify
	};

	/// Destroy the authenticator
	virtual ~IPAuthBase();

	/** Authenticate using data from RRQ RAS message.
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// RRQ RAS message to be authenticated
		RasPDU<H225_RegistrationRequest> & rrqPdu,
		/// authorization data (reject reason, ...)
		RRQAuthData & authData
		);

	/** Authenticate using data from ARQ RAS message.
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// ARQ to be authenticated/authorized
		RasPDU<H225_AdmissionRequest> & request,
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData & authData
		);

	virtual int Check(RasPDU<H225_GatekeeperRequest> & grqPdu, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_UnregistrationRequest> & urqPdu, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_BandwidthRequest> & brqPdu, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_DisengageRequest> & drqPdu, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_LocationRequest> & lrqPdu, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_InfoRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_ResourcesAvailableIndicate> & req, unsigned & rejectReason);

	/** Authenticate using data from Q.931/H.225.0 Setup message.
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// Q.931/H.225 Setup message to be authenticated
		SetupMsg & setup,
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData & authData
		);

    virtual int Check(
		/// Q931 message to be authenticated/authorized
		Q931 & msg,
		/// authorization data
		Q931AuthData & authData
		);

protected:
	/// Create IP based authenticator
	IPAuthBase(
		/// authenticator name from Gatekeeper::Auth section
		const char * authName,
		/// bitmask with supported RAS checks
		unsigned supportedRasChecks = IPAuthRasChecks,
		/// bitmask with supported non-RAS checks
		unsigned supportedMiscChecks = IPAuthMiscChecks
		);

	/** Accepts/rejects the address. Implemented by derived classes.

	    @return
	    #GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int CheckAddress(
		const PIPSocket::Address & addr, /// IP address the request comes from
		WORD port, /// port number the request comes from
		const PString & number,
		bool overTLS = false
		) = 0;

private:
	IPAuthBase();
	/* No copy constructor allowed */
	IPAuthBase(const IPAuthBase &);
	/* No operator= allowed */
	IPAuthBase& operator=(const IPAuthBase&);
};

#endif /* #ifndef IPAUTH_H */
