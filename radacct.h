/*
 * radacct.h
 *
 * RADIUS protocol accounting module for GNU Gatekeeper. 
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.6  2003/10/31 00:01:25  zvision
 * Improved accounting modules stacking control, optimized radacct/radauth a bit
 *
 * Revision 1.5  2003/10/08 12:40:48  zvision
 * Realtime accounting updates added
 *
 * Revision 1.4  2003/09/29 16:11:44  zvision
 * Added cvs Id keyword to header #define macro
 *
 * Revision 1.3  2003/09/14 21:10:34  zvision
 * Changes due to accounting API redesign.
 *
 * Revision 1.2  2003/09/12 16:31:16  zvision
 * Accounting initially added to the 2.2 branch
 *
 * Revision 1.1.2.3  2003/07/31 22:58:48  zvision
 * Added Framed-IP-Address attribute and improved h323-disconnect-cause handling
 *
 * Revision 1.1.2.2  2003/07/03 15:30:40  zvision
 * Added cvs Log keyword
 *
 */
#if HAS_RADIUS

#ifndef __RADACCT_H
#define __RADACCT_H "@(#) $Id$"

#include "RasTbl.h"
#include "gkacct.h"

class RadiusClient;
class RadiusPDU;

/** Accounting logger for RADIUS protocol. It sends
	accounting call start/stop/update and NAS on/off events
	to a remote RADIUS server.
*/
class RadAcct : public GkAcctLogger
{
public:
	enum Constants
	{
		/// events recognized by this module
		RadAcctEvents = AcctStart | AcctStop | AcctUpdate | AcctOn | AcctOff,
		CiscoVendorId = 9
	};
	
	/** Create GkAcctLogger for RADIUS protocol
	*/
	RadAcct( 
		/// name from Gatekeeper::Acct section
		const char* moduleName,
		/// config section name to be used with an instance of this module,
		/// pass NULL to use a default section (named "moduleName")
		const char* cfgSecName = NULL
		);
		
	/// Destroy the accounting logger
	virtual ~RadAcct();

protected:
	/// overriden from GkAcctLogger
	virtual Status Log(
		AcctEvent evt,
		callptr& call
		);
		
	/** Called before Accounting-Request PDU is send.
		Can be used to introduce additional attributes etc.
		
		@return
		True to proceed, false to fail and not send this pdu.
	*/
	virtual bool OnSendPDU(
		RadiusPDU& pdu, /// PDU to be sent
		AcctEvent evt, /// accounting event being processed
		callptr& call /// call associated with this request (if any)
		);

	/** Called after Accounting-Response PDU is received.
		Can be used to check for some additional attributes etc.
		
		@return
		True to accept the response, false to return failure for this event.
	*/
	virtual bool OnReceivedPDU(
		RadiusPDU& pdu, /// PDU received from RADIUS server
		AcctEvent evt, /// accounting event being processed
		callptr& call /// call associated with this response (if any)
		);
		
private:
	/* No copy constructor allowed */
	RadAcct( const RadAcct& );
	/* No operator= allowed */
	RadAcct& operator=( const RadAcct& );
	
private:
	/// array of configured RADIUS server names
	PStringArray radiusServers;
	/// shared secret for gk client<->RADIUS server authorization
	PString sharedSecret;
	/// default port that will be used for sending RADIUS acct
	/// requests
	WORD acctPort;
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
	/// 	false - do #numRequestRetransmissions# for server A,
	///				then do #numRequestRetransmissions# for server B, etc.
	///		true  - transmit request to server A, then to server B, etc.
	///				the whole procedure repeat #numRequestRetransmissions# times
	bool roundRobin;
	/// if true Cisco VSAs are appended to the RADIUS packets
	bool appendCiscoAttributes;
	/// append IP address of the calling endpoint
	bool includeFramedIp;
	/// local interface RADIUS client should be bound to (multihomed hosts)
	PString localInterface;	
	/// IP address for the local interface
	PIPSocket::Address localInterfaceAddr;
	/// NAS (GK) identifier
	PString NASIdentifier;
	/// Fixed value for User-Name attribute in outgoing requests
	PString fixedUsername;
	/// RADIUS protocol client class associated with this authenticator
	RadiusClient* radiusClient;
};

#endif /* __RADACCT_H */

#endif /* HAS_RADIUS */
