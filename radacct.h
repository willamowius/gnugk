/*
 * radacct.h
 *
 * RADIUS protocol accounting module for GNU Gatekeeper. 
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

	/// overriden from GkAcctLogger
	virtual Status Log(
		AcctEvent evt,
		const callptr& call
		);
		
protected:
	/** Called before Accounting-Request PDU is send.
		Can be used to introduce additional attributes etc.
		
		@return
		True to proceed, false to fail and not send this pdu.
	*/
	virtual bool OnSendPDU(
		RadiusPDU& pdu, /// PDU to be sent
		AcctEvent evt, /// accounting event being processed
		const callptr& call /// call associated with this request (if any)
		);

	/** Called after Accounting-Response PDU is received.
		Can be used to check for some additional attributes etc.
		
		@return
		True to accept the response, false to return failure for this event.
	*/
	virtual bool OnReceivedPDU(
		RadiusPDU& pdu, /// PDU received from RADIUS server
		AcctEvent evt, /// accounting event being processed
		const callptr& call /// call associated with this response (if any)
		);
		
private:
	RadAcct();
	/* No copy constructor allowed */
	RadAcct(const RadAcct&);
	/* No operator= allowed */
	RadAcct& operator=(const RadAcct&);
	
private:
	/// if true Cisco VSAs are appended to the RADIUS packets
	bool m_appendCiscoAttributes;
	/// NAS (GK) identifier
	PString m_nasIdentifier;
	/// NAS IP address (local interface for RADIUS client)
	PIPSocket::Address m_nasIpAddress;
	/// Fixed value for User-Name attribute in outgoing requests
	PString m_fixedUsername;
	/// timestamp formatting string
	PString m_timestampFormat;
	/// RADIUS protocol client class associated with this authenticator
	RadiusClient* m_radiusClient;
	/// false to use rewritten number, true to use the original one for Called-Station-Id
	bool m_useDialedNumber;
	/// radius attributes that do not change - x4 performance boost
	RadiusAttr m_attrNasIdentifier;
	RadiusAttr m_attrH323GwId;
	RadiusAttr m_attrH323CallOrigin;
	RadiusAttr m_attrH323CallType;
};

#endif /* __RADACCT_H */

#endif /* HAS_RADIUS */
