/*
 * sqlacct.h
 *
 * SQL accounting module for GNU Gatekeeper
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 * Copyright (c) 2005-2016, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#ifndef SQLACCT_H
#define SQLACCT_H "@(#) $Id$"

#include "gkacct.h"

/** This accounting module stores call information directly to an SQL database.
    It uses generic SQL interface, so different SQL backends are supported.
    Queries to store accounting information are parametrized using named
    parameters.
*/
class GkSQLConnection;
class SQLAcct : public GkAcctLogger
{
public:
	enum Constants {
		/// events recognized by this module
		SQLAcctEvents = AcctOn | AcctOff | AcctStart | AcctUpdate | AcctStop | AcctConnect | AcctAlert | AcctRegister | AcctUnregister
	};

	/// Create a logger that sends accounting to an SQL database
	SQLAcct(
		/// name from Gatekeeper::Acct section
		const char* moduleName,
		/// name for a config section with logger settings
		/// pass NULL to use the moduleName as the section name
		const char* cfgSecName = NULL
		);

	/// Destroy the accounting logger
	virtual ~SQLAcct();

	/** Log call accounting event.

		@return
		Status of this logging operation (see #Status enum#)
	*/
	virtual Status Log(
		AcctEvent evt, /// accounting event to log
		const callptr& call /// additional data for the event
		);

	/** Log endpoint accounting event.

		@return
		Status of this logging operation (see #Status enum#)
	*/
	virtual Status Log(
		AcctEvent evt, /// accounting event to log
		const endptr& ep /// additional data for the event
		);

	virtual PString GetInfo();

private:
	/* No copy constructor allowed */
	SQLAcct(const SQLAcct &);
	/* No operator= allowed */
	SQLAcct & operator=(const SQLAcct &);

private:
	/// connection to the SQL database
	GkSQLConnection* m_sqlConn;
	/// parametrized query string for the call start event
	PString m_startQuery;
	/// parametrized alternative query string for the call start event
	PString m_startQueryAlt;
	/// parametrized query string for the call update event
	PString m_updateQuery;
	/// parametrized query string for the call stop event
	PString m_stopQuery;
	/// parametrized alternative query string for the call stop event
	PString m_stopQueryAlt;
	/// parametrized query string for call alerting
	PString m_alertQuery;
	/// parametrized query string for endpoint registration
	PString m_registerQuery;
	/// parametrized query string for endpoint un-registration
	PString m_unregisterQuery;
	/// parametrized query string for gatekeeper coming online
	PString m_onQuery;
	/// parametrized query string for gatekeeper going offline
	PString m_offQuery;
	/// timestamp formatting string
	PString m_timestampFormat;
};

#endif /* SQLACCT_H */
