/*
 * radauth.h
 *
 * RADIUS protocol authenticator modules for GNU Gatekeeper. 
 * H.235 based and alias based authentication schemes are supported.
 * Please see docs/radauth.txt for more details.
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 * Copyright (c) 2005-2011, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#if HAS_RADIUS

#ifndef __RADAUTH_H
#define __RADAUTH_H "@(#) $Id$"

#include "gkauth.h"

// forward declaration of RADIUS classes (no need for radproto.h inclusion)
class RadiusPDU;
class RadiusClient;

/** Base abstract class for deriving specialized Radius authenticators.
	Derived classes have to override AppendUsernameAndPassword virtual
	functions in order to build working Radius authenticator.
	
	This class is multithread safe, so it is ok to call Check functions
	from multiple threads in parallel.
*/
class RadAuthBase : public GkAuthenticator 
{
public:
	enum SupportedChecks {
		RadAuthBaseRasChecks = RasInfo<H225_RegistrationRequest>::flag
			| RasInfo<H225_AdmissionRequest>::flag,
		RadAuthBaseMiscChecks = e_Setup | e_SetupUnreg
	};

	/// Create base authenticator for RADIUS protocol
	RadAuthBase( 
		/// authenticator name from Gatekeeper::Auth section
		const char* authName,
		/// name of the config section with settings for this authenticator
		const char* configSectionName,
		/// bitmask with supported RAS checks
		unsigned supportedRasChecks = RadAuthBaseRasChecks,
		/// bitmask with supported non-RAS checks
		unsigned supportedMiscChecks = RadAuthBaseMiscChecks
		);
		
	/// Destroy the authenticator
	virtual ~RadAuthBase();

	/** Authenticate using data from RRQ RAS message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// RRQ RAS message to be authenticated
		RasPDU<H225_RegistrationRequest>& rrqPdu, 
		/// authorization data (reject reason, ...)
		RRQAuthData& authData
		);
		
	/** Authenticate using data from ARQ RAS message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// ARQ nessage to be authenticated
		RasPDU<H225_AdmissionRequest> & arqPdu, 
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData& authData
		);

	/** Authenticate using data from ARQ RAS message.
	
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
	/** Hook for appending username/password attributes 
		proper for derived authenticators.
		
		@return
		#GkAuthenticator::Status enum#:
			e_ok - attributes appended,
			e_fail - corrupted or invalid authentication data,
			e_next - required data not found
	*/
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu, /// append attribues to this pdu
		RasPDU<H225_RegistrationRequest>& rrqPdu, /// extract data from this RAS msg
		RRQAuthData& authData, /// authorization data
		PString* username = NULL /// if not NULL, store the username on return
		) const;
	
	/** Hook for appending username/password attributes 
		proper for derived authenticators.
		
		@return
		#GkAuthenticator::Status enum#:
			e_ok - attributes appended,
			e_fail - corrupted or invalid authentication data,
			e_next - required data not found
	*/
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu, /// append attribues to this pdu
		RasPDU<H225_AdmissionRequest>& arqPdu, /// extract data from this RAS msg
		ARQAuthData& authData, /// authorization data 
		PString* username = NULL /// if not NULL, store the username on return
		) const;
	
	/** Hook for appending username/password attributes 
		proper for derived authenticators.
		
		@return
		#GkAuthenticator::Status enum#:
			e_ok - attributes appended,
			e_fail - corrupted or invalid authentication data,
			e_next - required data not found
	*/
	virtual int AppendUsernameAndPassword(
		RadiusPDU &pdu, /// append attribues to this pdu
		SetupMsg &setup, /// Q.931/H.225 Setup being processed
		endptr &callingEP, /// calling endpoint (if found in the registration table)
		SetupAuthData &authData, /// authorization data 
		PString *username = NULL /// if not NULL, store the username on return
		) const;
		
private:
	RadAuthBase();
	/* No copy constructor allowed */
	RadAuthBase(const RadAuthBase&);
	/* No operator= allowed */
	RadAuthBase& operator=(const RadAuthBase&);

private:
	/// if TRUE Cisco VSAs are appended to the RADIUS packets
	bool m_appendCiscoAttributes;
	/// if true an h323-ivr-out attribute will be sent with every alias
	/// found inside RRQ.m_terminalAlias
	bool m_includeTerminalAliases;
	/// RADIUS protocol client class associated with this authenticator
	RadiusClient* m_radiusClient;
	/// NAS identifier (GK name)
	PString m_nasIdentifier;
	/// NAS IP Address (local interface for RADIUS client)
	PIPSocket::Address m_nasIpAddress;
	/// false to use rewritten number, true to use the original one for Called-Station-Id
	bool m_useDialedNumber;
	/// radius attributes that do not change - performance boost
	RadiusAttr m_attrH323GwId;
	RadiusAttr m_attrH323CallType;
	RadiusAttr m_attrH323CallOriginOriginate;
	RadiusAttr m_attrH323CallOriginAnswer;
	RadiusAttr m_attrNasIdentifier;
};

/**
 * Gatekeeper authenticator module for RADIUS protocol.
 * Currently it supports user authentication through
 * CATs (Cisco Access Tokens) carried inside RRQ and ARQ
 * RAS messages. If your software does not support CATs,
 * please take a look at OpenH323 H235AuthCAT authenticator class
 * - it provides an implementation for CATs.
 * If your endpoints do not support CATs, you should consider 
 * using RadAliasAuth.
 */
class RadAuth : public RadAuthBase
{
public:
	/// Create authenticator for RADIUS protocol
	RadAuth( 
		/// authenticator name from Gatekeeper::Auth section
		const char* authName 
		);
		
	/// Destroy the authenticator
	virtual ~RadAuth();
	
protected:		

	/// Overridden from RadAuthBase
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		RasPDU<H225_RegistrationRequest>& rrqPdu,
		RRQAuthData& authData,
		PString* username = NULL 
		) const;
	
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		RasPDU<H225_AdmissionRequest>& arqPdu,
		ARQAuthData& authData,
		PString* username = NULL 
		) const;
		
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		SetupMsg &setup,
		endptr& callingEP,
		SetupAuthData& authData,
		PString* username = NULL
		) const;

	virtual int CheckTokens(
		RadiusPDU& pdu,
		const H225_ArrayOf_ClearToken& tokens,
		const H225_ArrayOf_AliasAddress* aliases = NULL,
		PString* username = NULL
		) const;

private:
	RadAuth();
	/* No copy constructor allowed */
	RadAuth(const RadAuth&);
	/* No operator= allowed */
	RadAuth& operator=( const RadAuth& );
	
protected:
	/// OID (Object Identifier) for CAT alghoritm
	static PString OID_CAT;
};

/** RADIUS Alias Authentication module.
	It authenticates endpoints/calls using non-H.235 
	attributes (alias,IP,etc).
*/
class RadAliasAuth : public RadAuthBase 
{
public:
	/// Create authenticator for RADIUS Alias authenticator
	RadAliasAuth( 
		/// authenticator name from Gatekeeper::Auth section
		const char* authName 
		);
		
	/// Destroy the authenticator
	virtual ~RadAliasAuth();
	
protected:		
	/// Overridden from RadAuthBase
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		RasPDU<H225_RegistrationRequest>& rrqPdu,
		RRQAuthData& authData,
		PString* username = NULL
		) const;
	
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		RasPDU<H225_AdmissionRequest>& arqPdu,
		ARQAuthData& authData,
		PString* username = NULL
		) const;
	
	virtual int AppendUsernameAndPassword(
		RadiusPDU &pdu,
		SetupMsg &setup,
		endptr &callingEP,
		SetupAuthData &authData,
		PString* username = NULL
		) const;
		
private:
	RadAliasAuth();
	/* No copy constructor allowed */
	RadAliasAuth(const RadAliasAuth&);
	/* No operator= allowed */
	RadAliasAuth& operator=(const RadAliasAuth&);
	
protected:
	/// fixed value for User-Name attribute, read from config
	PString m_fixedUsername;
	/// fixed value for User-Name attribute for unregistered calls with empty h323 id
	PString m_emptyUsername;
	/// fixed valud for User-Password attribute, read from config
	PString m_fixedPassword;
};

#endif /* __RADAUTH_H */

#endif /* HAS_RADIUS */
