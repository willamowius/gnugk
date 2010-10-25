/*
 * ipauth.h
 *
 * IP based authentication modules
 *
 * Copyright (c) 2005, Michal Zygmuntowicz
 * Copyright (c) 2006-2010, Jan Willamowius
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
	enum SupportedChecks {
		IPAuthRasChecks = RasInfo<H225_GatekeeperRequest>::flag
			| RasInfo<H225_RegistrationRequest>::flag
			| RasInfo<H225_LocationRequest>::flag,
		IPAuthMiscChecks = e_Setup | e_SetupUnreg
	};

	/// Destroy the authenticator
	virtual ~IPAuthBase();

	/** Authenticate using data from GRQ RAS message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// GRQ RAS message to be authenticated
		RasPDU<H225_GatekeeperRequest> &grqPdu, 
		/// gatekeeper request reject reason
		unsigned &rejectReason
		);

	/** Authenticate using data from RRQ RAS message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// RRQ RAS message to be authenticated
		RasPDU<H225_RegistrationRequest> &rrqPdu, 
		/// authorization data (reject reason, ...)
		RRQAuthData &authData
		);
		
	/** Authenticate using data from LRQ RAS message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// LRQ nessage to be authenticated
		RasPDU<H225_LocationRequest> &lrqPdu, 
		/// location request reject reason
		unsigned &rejectReason
		);

	/** Authenticate using data from Q.931/H.225.0 Setup message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// Q.931/H.225 Setup message to be authenticated
		SetupMsg &setup,
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData& authData
		);
	
protected:		
	/// Create IP based authenticator
	IPAuthBase( 
		/// authenticator name from Gatekeeper::Auth section
		const char *authName,
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
		const PIPSocket::Address &addr, /// IP address the request comes from
		WORD port, /// port number the request comes from
		const PString &number
		) = 0;

private:
	IPAuthBase();
	/* No copy constructor allowed */
	IPAuthBase(const IPAuthBase&);
	/* No operator= allowed */
	IPAuthBase& operator=(const IPAuthBase&);
};

#endif /* #ifndef IPAUTH_H */
