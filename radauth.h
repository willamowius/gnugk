/*
 * radauth.h
 *
 * RADIUS protocol authenticator modules for GNU Gatekeeper. 
 * H.235 based and alias based authentication schemes are supported.
 * Please see docs/radauth.txt for more details.
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.11  2004/03/17 00:00:38  zvision
 * Conditional compilation to allow to control RADIUS on Windows just by setting HA_RADIUS macro
 *
 * Revision 1.10  2004/02/20 14:44:11  zvision
 * Changed API for GkAuthenticator class. Modified RadAuth/RadAliasAuth classes.
 * Added Q.931 Setup authentication for RadAuth module.
 *
 * Revision 1.9  2003/11/14 00:27:30  zvision
 * Q.931/H.225 Setup authentication added
 *
 * Revision 1.8  2003/10/31 00:01:28  zvision
 * Improved accounting modules stacking control, optimized radacct/radauth a bit
 *
 * Revision 1.7  2003/10/08 12:40:48  zvision
 * Realtime accounting updates added
 *
 * Revision 1.6  2003/09/29 16:11:44  zvision
 * Added cvs Id keyword to header #define macro
 *
 * Revision 1.5  2003/09/28 16:24:31  zvision
 * Introduced call duration limit feature for registered endpoints (ARQ)
 *
 * Revision 1.4  2003/08/25 12:53:38  zvision
 * Introduced includeTerminalAliases config option. Changed visibility
 * of some member variables to private.
 *
 * Revision 1.3  2003/08/20 14:46:19  zvision
 * Avoid PString reference copying. Small code improvements.
 *
 * Revision 1.2  2003/08/19 10:47:37  zvision
 * Initially added to 2.2 brach. Completely redesigned.
 * Redundant code removed. Added h323-return-code, h323-credit-time
 * and Session-Timeout respone attributes processing.
 *
 * Revision 1.1.2.7  2003/07/31 13:09:15  zvision
 * Added Q.931 Setup message authentication and call duration limit feature
 *
 * Revision 1.1.2.6  2003/07/07 12:02:55  zvision
 * Improved H.235 handling.
 *
 * Revision 1.1.2.5  2003/05/28 13:25:19  zvision
 * Added alias based authentication (RadAliasAuth)
 *
 * Revision 1.1.2.4  2003/05/26 23:08:18  zvision
 * New OnSend and OnReceive hooks.
 * LocalInterface config parameter Introduced.
 *
 * Revision 1.1.2.3  2003/05/13 17:48:43  zvision
 * Removed acctPort. New includeFramedIP feature.
 *
 * Revision 1.1.2.2  2003/04/29 14:56:26  zvision
 * Added H.235 capability matching
 *
 * Revision 1.1.2.1  2003/04/23 20:16:25  zvision
 * Initial revision
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
		RadAuthBaseMiscChecks = e_Setup
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
		/// reference to the variable, that can be set 
		/// to custom H225_RegistrationRejectReason
		/// if the check fails
		unsigned& rejectReason
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
		/// Q.931 Setup message to be authenticated
		Q931& q931pdu, 
		/// H.225 Setup UUIE to be authenticated
		H225_Setup_UUIE& setup, 
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData& authData
		);
	
protected:		
	/** Hook for adding/modifying pdu before it is sent.
		It can be used to add custom attributes, for example.
		
		@return
		true if PDU should be sent, false to reject RRQ
		(rejectReason can be set to indicate a particular reason).
	*/
	virtual bool OnSendPDU(
		RadiusPDU& pdu, /// PDU to be sent
		RasPDU<H225_RegistrationRequest>& rrqPdu, /// RRQ being processed
		unsigned& rejectReason /// reject reason on return FALSE
		);

	/** Hook for adding/modifying pdu before it is sent.
		It can be used to add custom attributes, for example.
		
		@return
		TRUE if PDU should be sent, FALSE to reject ARQ
		(rejectReason can be set to indicate a particular reason).
	*/
	virtual bool OnSendPDU(
		RadiusPDU& pdu, /// PDU to be sent
		RasPDU<H225_AdmissionRequest>& arqPdu, /// ARQ being processed
		ARQAuthData& authData /// authorization data 
		);

	/** Hook for adding/modifying pdu before it is sent.
		It can be used to add custom attributes, for example.
		
		@return
		TRUE if PDU should be sent, FALSE to reject the call
		(rejectReason can be set to indicate a particular reason).
	*/
	virtual bool OnSendPDU(
		RadiusPDU& pdu, /// PDU to be sent
		Q931& q931pdu, /// Q.931 Setup being processed
		H225_Setup_UUIE& setup, /// H.225 Setup UUIE being processed
		SetupAuthData& authData /// authorization data 
		);
		
	/** Hook for processing pdu after it is received.
		It can be used to process custom attributes, for example.
		
		@return
		TRUE if PDU should be accepted, FALSE to reject RRQ
		(rejectReason can be set to indicate a particular reason).
	*/
	virtual bool OnReceivedPDU(
		RadiusPDU& pdu, /// received PDU 
		RasPDU<H225_RegistrationRequest>& rrqPdu, /// RRQ being processed
		unsigned& rejectReason /// reject reason on return FALSE
		);

	/** Hook for processing pdu after it is received.
		It can be used to process custom attributes, for example.
		
		@return
		TRUE if PDU should be accepted, FALSE to reject ARQ
		(rejectReason can be set to indicate a particular reason).
	*/
	virtual bool OnReceivedPDU(
		RadiusPDU& pdu, /// received PDU
		RasPDU<H225_AdmissionRequest>& arqPdu, /// ARQ being processed
		ARQAuthData& authData /// authorization data 
		);
	
	/** Hook for processing pdu after it is received.
		It can be used to process custom attributes, for example.
		
		@return
		TRUE if PDU should be accepted, FALSE to reject the call
		(rejectReason can be set to indicate a particular reason).
	*/
	virtual bool OnReceivedPDU(
		RadiusPDU& pdu, /// received PDU
		Q931& q931pdu, /// Q.931 Setup being processed
		H225_Setup_UUIE& setup, /// H.225 Setup UUIE being processed
		SetupAuthData& authData /// authorization data 
		);
	
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
		unsigned& rejectReason, /// reject reason to be set on e_fail return code
		/// if not NULL and return status is e_ok, then the string is filled
		/// with appended username
		PString* username = NULL 
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
		endptr& originatingEP, /// endpoint that the ARQ originates from
		ARQAuthData& authData, /// authorization data 
		/// if not NULL and return status is e_ok, then the string is filled
		/// with appended username
		PString* username = NULL 
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
		Q931& q931pdu, /// Q.931 Setup being processed
		H225_Setup_UUIE& setup, /// H.225 Setup UUIE being processed
		endptr& callingEP, /// calling endpoint (if found in the registration table)
		SetupAuthData& authData, /// authorization data 
		/// if not NULL and return status is e_ok, then the string is filled
		/// with appended username
		PString* username = NULL 
		) const;
		
	/** Scan the array of 'aliases' for 'id' alias.
	
		@return
		TRUE if 'id' is found in the 'aliases' array.
	*/
	virtual bool CheckAliases( 
		/// array of aliases to be searched
		const H225_ArrayOf_AliasAddress& aliases, 
		/// alias to be searched for
		const PString& id 
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
	/// if TRUE endpoint IP is placed inside Framed-IP-Address attribute
	bool m_includeFramedIp;
	/// RADIUS protocol client class associated with this authenticator
	RadiusClient* m_radiusClient;
	/// NAS identifier (GK name)
	PString m_nasIdentifier;
	/// NAS IP Address (local interface for RADIUS client)
	PIPSocket::Address m_nasIpAddress;
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

	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		RasPDU<H225_RegistrationRequest>& rrqPdu,
		unsigned& rejectReason,
		PString* username = NULL 
		) const;
	
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		RasPDU<H225_AdmissionRequest>& arqPdu,
		endptr& originatingEP,
		ARQAuthData& authData,
		PString* username = NULL 
		) const;
		
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		Q931& q931pdu,
		H225_Setup_UUIE& setup,
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

	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		RasPDU<H225_RegistrationRequest>& rrqPdu,
		unsigned& rejectReason,
		PString* username = NULL
		) const;
	
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		RasPDU<H225_AdmissionRequest>& arqPdu,
		endptr& originatingEP,
		ARQAuthData& authData,
		PString* username = NULL
		) const;
	
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		Q931& q931pdu,
		H225_Setup_UUIE& setup,
		endptr& callingEP,
		SetupAuthData& authData,
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
	/// fixed valud for User-Password attribute, read from config
	PString m_fixedPassword;
};

#endif /* __RADAUTH_H */

#endif /* HAS_RADIUS */
