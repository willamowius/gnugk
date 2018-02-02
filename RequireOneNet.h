/*
 * RequireOneNet.h
 *
 * accounting module for GNU Gatekeeper used for authentication - make sure one side of the call is within our network
 *
 * Copyright (c) 2016-2018, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#ifndef __REQUIREONENET_H
#define __REQUIREONENET_H "@(#) $Id$"

#include "gkacct.h"


/** Accounting module for the status port.
	It sends accounting call start/stop/update/connect events
	to the status port.
*/
class RequireOneNet : public GkAcctLogger
{
public:
	enum Constants
	{
		/// events recognized by this module
		StatusAcctEvents = AcctStart | AcctStop | AcctUpdate | AcctConnect | AcctAlert
	};

	RequireOneNet(
		/// name from Gatekeeper::Acct section
		const char* moduleName,
		/// config section name to be used with an instance of this module,
		/// pass NULL to use a default section (named "moduleName")
		const char* cfgSecName = NULL
		);

	/// Destroy the accounting logger
	virtual ~RequireOneNet();

	/// overridden from GkAcctLogger
	virtual Status Log(AcctEvent evt, const callptr & call);

private:
	RequireOneNet();
	/* No copy constructor allowed */
	RequireOneNet(const RequireOneNet &);
	/* No operator= allowed */
	RequireOneNet & operator=(const RequireOneNet &);

private:
	list<NetworkAddress> m_myNetworks;
};

#endif /* __REQUIREONENET_H */
