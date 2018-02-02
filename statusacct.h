/*
 * statusacct.h
 *
 * accounting module for GNU Gatekeeper that sends it's output to the status port.
 *
 * Copyright (c) 2005-2018, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#ifndef __STATUSACCT_H
#define __STATUSACCT_H "@(#) $Id$"

#include "gkacct.h"


/** Accounting module for the status port.
	It sends accounting call start/stop/update/connect events
	to the status port.
*/
class StatusAcct : public GkAcctLogger
{
public:
	enum Constants
	{
		/// events recognized by this module
		StatusAcctEvents = AcctStart | AcctStop | AcctUpdate | AcctConnect | AcctAlert | AcctRegister | AcctUnregister
	};

	StatusAcct(
		/// name from Gatekeeper::Acct section
		const char* moduleName,
		/// config section name to be used with an instance of this module,
		/// pass NULL to use a default section (named "moduleName")
		const char* cfgSecName = NULL
		);

	/// Destroy the accounting logger
	virtual ~StatusAcct();

	/// overridden from GkAcctLogger
	virtual Status Log(AcctEvent evt, const callptr & call);

	/// overridden from GkAcctLogger
	virtual Status Log(AcctEvent evt, const endptr & ep);

	/// overridden from GkAcctLogger
	virtual PString EscapeAcctParam(const PString & param) const;

	/// overridden from GkAcctLogger
	PString ReplaceAcctParams(
		/// parametrized accounting string
		const PString & cdrStr,
		/// parameter values
		const std::map<PString, PString> & params
	) const;

private:
	StatusAcct();
	/* No copy constructor allowed */
	StatusAcct(const StatusAcct &);
	/* No operator= allowed */
	StatusAcct & operator=(const StatusAcct &);

private:
	/// parametrized string for the call start event
	PString m_startEvent;
	/// parametrized string for the call stop (disconnect) event
	PString m_stopEvent;
	/// parametrized string for the call update event
	PString m_updateEvent;
	/// parametrized string for the call connect event
	PString m_connectEvent;
	/// parametrized string for the call alerting event
	PString m_alertEvent;
	/// parametrized string for the endpoint register event
	PString m_registerEvent;
	/// parametrized string for the endpoint un-register event
	PString m_unregisterEvent;
	/// timestamp formatting string
	PString m_timestampFormat;
};

#endif /* __STATUSACCT_H */
