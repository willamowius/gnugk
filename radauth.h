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
#ifndef __RADAUTH_H
#define __RADAUTH_H

#include <ptlib.h>
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
	/// Create base authenticator for RADIUS protocol
	RadAuthBase( 
		/// authenticator name from Gatekeeper::Auth section
		const char* authName,
		/// name of the config section with settings for this authenticator
		const char* configSectionName
		);
		
	/// Destroy the authenticator
	virtual ~RadAuthBase();
	
protected:		
	/** Hook for adding/modifying pdu before it is sent.
		It can be used to add custom attributes, for example.
		
		@return
		TRUE if PDU should be sent, FALSE to reject RRQ
		(rejectReason can be set to indicate a particular reason).
	*/
	virtual bool OnSendPDU(
		RadiusPDU& pdu, /// PDU to be sent
		const H225_RegistrationRequest& rrq, /// RRQ being processed
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
		const H225_AdmissionRequest& rrq, /// ARQ being processed
		unsigned& rejectReason /// reject reason on return FALSE
		);

	/** Hook for processing pdu after it is received.
		It can be used to process custom attributes, for example.
		
		@return
		TRUE if PDU should be accepted, FALSE to reject RRQ
		(rejectReason can be set to indicate a particular reason).
	*/
	virtual bool OnReceivedPDU(
		RadiusPDU& pdu, /// received PDU 
		const H225_RegistrationRequest& rrq, /// RRQ being processed
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
		const H225_AdmissionRequest& rrq, /// ARQ being processed
		unsigned& rejectReason, /// reject reason on return FALSE
		long& durationLimit /// call duration limit to be set
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
		const H225_RegistrationRequest& rrq, /// extract data from this RAS msg
		unsigned& rejectReason, /// reject reason to be set on e_fail return code
		/// if not NULL and return status is e_ok, then the string is filled
		/// with appended username
		PString* username = NULL 
		) const = 0;
	
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
		const H225_AdmissionRequest& arq, /// extract data from this RAS msg
		unsigned& rejectReason, /// reject reason to be set on e_fail return code
		/// if not NULL and return status is e_ok, then the string is filled
		/// with appended username
		PString* username = NULL 
		) const = 0;
	
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
		
	/** Authenticate using data from RRQ RAS message.
	
		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// RRQ RAS message to be authenticated
		RasPDU<H225_RegistrationRequest>& rrq, 
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
		RasPDU<H225_AdmissionRequest> & arq, 
		/// reference to the variable, that can be set 
		/// to custom H225_AdmissionRejectReason
		/// if the check fails
		unsigned& rejectReason,
		/// call duration limit to be set for the call
		/// (-1 stands for no limit)
		long& callDurationLimit
		);

private:

	/// actual RRQ authentication implementation
	virtual int doCheck(
		/// RRQ RAS message to be authenticated
		const H225_RegistrationRequest& rrq, 
		/// reference to the variable, that can be set 
		/// to custom H225_RegistrationRejectReason
		/// if the check fails
		unsigned& rejectReason
		);
	
	/// actual ARQ authentication implementation
	virtual int doCheck(
		/// RRQ RAS message to be authenticated
		const H225_AdmissionRequest& rrq, 
		/// reference to the variable, that can be set 
		/// to custom H225_RegistrationRejectReason
		/// if the check fails
		unsigned& rejectReason,
		/// call duration limit to be set for the call
		/// (-1 stands for no limit)
		long& durationLimit
		);
		
	/* No copy constructor allowed */
	RadAuthBase( const RadAuthBase& );
	/* No operator= allowed */
	RadAuthBase& operator=( const RadAuthBase& );

protected:
	/// if TRUE Cisco VSAs are appended to the RADIUS packets
	bool appendCiscoAttributes;
	/// Local interface RADIUS client should be bound to (multihomed hosts)
	PString localInterface;	
	
private:
	/// array of configured RADIUS server names
	PStringArray radiusServers;
	/// shared secret for gk client<->RADIUS server authorization
	PString sharedSecret;
	/// default port that will be used for sending RADIUS auth
	/// requests
	WORD authPort;
	/// base port number for UDP client socket allocation
	WORD portBase;
	/// max port number for UDP client socket allocation
	WORD portMax;
	/// timeout (ms) for a single RADIUS request
	unsigned requestTimeout;
	/// timeout (ms) for RADIUS requests IDs to be unique
	unsigned idCacheTimeout;
	/// timeout (ms) for unused sockets to be deleted
	unsigned socketDeleteTimeout;
	/// how many times to transmit a single request (1==no retransmission)
	/// to a single RADIUS server
	unsigned numRequestRetransmissions;
	/// retransmission fashion: 
	/// 	FALSE - do #numRequestRetransmissions# for server A,
	///				then do #numRequestRetransmissions# for server B, etc.
	///		TRUE - transmit request to server A, then to server B, etc.
	///				the whole procedure repeat #numRequestRetransmissions# times
	bool roundRobin;
	/// if true an h323-ivr-out attribute will be sent with every alias
	/// found inside RRQ.m_terminalAlias
	bool includeTerminalAliases;
	/// if TRUE endpoint IP is placed inside Framed-IP-Address attribute
	bool includeFramedIp;
	/// RADIUS protocol client class associated with this authenticator
	RadiusClient* radiusClient;
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
	virtual ~RadAuth() {}
	
protected:		

	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		const H225_RegistrationRequest& rrq,
		unsigned& rejectReason,
		PString* username = NULL 
		) const;
	
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		const H225_AdmissionRequest& arq,
		unsigned& rejectReason,
		PString* username = NULL 
		) const;

private:
	/* No copy constructor allowed */
	RadAuth( const RadAuth& );
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
	virtual ~RadAliasAuth() {}
	
protected:		

	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		const H225_RegistrationRequest& rrq,
		unsigned& rejectReason,
		PString* username = NULL
		) const;
	
	virtual int AppendUsernameAndPassword(
		RadiusPDU& pdu,
		const H225_AdmissionRequest& arq,
		unsigned& rejectReason,
		PString* username = NULL
		) const;
		
private:
	/* No copy constructor allowed */
	RadAliasAuth( const RadAliasAuth& );
	/* No operator= allowed */
	RadAliasAuth& operator=( const RadAliasAuth& );
	
protected:
	/// fixed value for User-Name attribute, read from config
	PString fixedUsername;
	/// fixed valud for User-Password attribute, read from config
	PString fixedPassword;
};

#endif /* __RADAUTH_H */
