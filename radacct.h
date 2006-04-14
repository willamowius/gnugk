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
 * Revision 1.1.1.1  2005/11/21 20:20:00  willamowius
 *
 *
 * Revision 1.4  2005/11/15 19:52:56  jan
 * Michal v1 (works, but on in routed, not proxy mode)
 *
 * Revision 1.12  2004/11/15 23:57:42  zvision
 * Ability to choose between the original and the rewritten dialed number
 *
 * Revision 1.11  2004/11/10 18:30:41  zvision
 * Ability to customize timestamp strings
 *
 * Revision 1.10  2004/07/26 12:19:41  zvision
 * New faster Radius implementation, thanks to Pavel Pavlov for ideas!
 *
 * Revision 1.9.2.1  2004/07/07 23:11:07  zvision
 * Faster and more elegant handling of Cisco VSA
 *
 * Revision 1.9  2004/06/25 13:33:19  zvision
 * Better Username, Calling-Station-Id and Called-Station-Id handling.
 * New SetupUnreg option in Gatekeeper::Auth section.
 *
 * Revision 1.8  2004/04/17 11:43:43  zvision
 * Auth/acct API changes.
 * Header file usage more consistent.
 *
 * Revision 1.7  2004/03/17 00:00:38  zvision
 * Conditional compilation to allow to control RADIUS on Windows just by setting HA_RADIUS macro
 *
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
