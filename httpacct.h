/*
 * httpacct.h
 *
 * accounting module for GNU Gatekeeper that sends it's messages over HTTP
 *
 * Copyright (c) 2018, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#ifndef __HTTPACCT_H
#define __HTTPACCT_H "@(#) $Id$"

#include "config.h"

#if defined(P_HTTP) || defined (HAS_LIBCURL)

#include "gkacct.h"


class HttpAcct : public GkAcctLogger
{
public:
	enum Constants
	{
		/// events recognized by this module
		HttpAcctEvents = AcctStart | AcctStop | AcctUpdate | AcctConnect | AcctAlert | AcctRegister | AcctUnregister | AcctOn | AcctOff | AcctReject | AcctMediaFail
	};

	HttpAcct(
		/// name from Gatekeeper::Acct section
		const char* moduleName,
		/// config section name to be used with an instance of this module,
		/// pass NULL to use a default section (named "moduleName")
		const char* cfgSecName = NULL
		);

	/// Destroy the accounting logger
	virtual ~HttpAcct();

	/// overridden from GkAcctLogger
	virtual Status Log(AcctEvent evt, const callptr & call);

	/// overridden from GkAcctLogger
	virtual Status Log(AcctEvent evt, const endptr & ep);

protected:
	virtual Status HttpLog(PString url, PString body);

private:
	HttpAcct();
	/* No copy constructor allowed */
	HttpAcct(const HttpAcct &);
	/* No operator= allowed */
	HttpAcct & operator=(const HttpAcct &);

private:
	/// parametrized strings for the call start event
	PString m_startURL;
	PString m_startBody;
	/// parametrized strings for the call stop (disconnect) event
	PString m_stopURL;
	PString m_stopBody;
	/// parametrized strings for the call update event
	PString m_updateURL;
	PString m_updateBody;
	/// parametrized strings for the call connect event
	PString m_connectURL;
	PString m_connectBody;
	/// parametrized strings for the call alerting event
	PString m_alertURL;
	PString m_alertBody;
	/// parametrized strings for the endpoint register event
	PString m_registerURL;
	PString m_registerBody;
	/// parametrized strings for the endpoint un-register event
	PString m_unregisterURL;
	PString m_unregisterBody;
	/// parametrized strings for the ON event
	PString m_onURL;
	PString m_onBody;
	/// parametrized strings for the OFF event
	PString m_offURL;
	PString m_offBody;
	/// parametrized strings for the reject event
	PString m_rejectURL;
	PString m_rejectBody;
	/// parametrized strings for the mediafail event
	PString m_mediaFailURL;
	PString m_mediaFailBody;
	/// HTTP method: GET or POST
	PString m_method;
	/// timestamp formatting string
	PString m_timestampFormat;
};

#endif // defined(P_HTTP) || defined (HAS_LIBCURL)

#endif /* __HTTPACCT_H */
