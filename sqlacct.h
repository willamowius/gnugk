/*
 * sqlacct.h
 *
 * SQL accounting module for GNU Gatekeeper
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.3  2004/11/10 18:30:41  zvision
 * Ability to customize timestamp strings
 *
 * Revision 1.2  2004/07/09 22:11:36  zvision
 * SQLAcct module ported from 2.0 branch
 *
 * Revision 1.1.2.1  2004/04/23 16:01:16  zvision
 * New direct SQL accounting module (SQLAcct)
 *
 */
#ifndef SQLACCT_H
#define SQLACCT_H "@(#) $Id$"

#include "gkacct.h"

/** This accounting module stores call information directly to an SQL database.
    It uses generic SQL interface, so different SQL backends are supported.
    Queries to store accounting information are parametrized using named 
    parameters. Currently, the following are supported:
	%g - gatekeeper name
	%n - call number (not unique after gatekeeper restart)
	%d - call duration (seconds)
	%c - Q.931 disconnect cause (hexadecimal integer)
	%s - unique (for this gatekeeper) call (Acct-Session-Id)
	%u - H.323 ID of the calling party
	%{gkip} - gatekeeper IP
	%{CallId} - H.323 call identifier (16 hex 8-bit digits)
	%{ConfId} - H.323 conference identifier (16 hex 8-bit digits)
	%{setup-time} - timestamp string for Q.931 Setup message
	%{connect-time} - timestamp string for a call connected event
	%{disconnect-time} - timestamp string for a call disconnect event
	%{caller-ip} - signaling IP addres of the caller
	%{caller-port} - signaling port of the caller
	%{callee-ip} - signaling IP addres of the called party
	%{callee-port} - signaling port of the called party
	%{src-info} - a colon separated list of source aliases
	%{dest-info} - a colon separated list of destination aliases
	%{Calling-Station-Id} - calling party number
	%{Called-Station-Id} - called party number
*/
class GkSQLConnection;
class SQLAcct : public GkAcctLogger
{
public:
	enum Constants {
		/// events recognized by this module
		SQLAcctEvents = AcctStart | AcctUpdate | AcctStop
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

	/** Log accounting event.
	
		@return
		Status of this logging operation (see #Status enum#)
	*/
	virtual Status Log( 
		AcctEvent evt, /// accounting event to log
		const callptr& call /// additional data for the event
		);

private:
	/* No copy constructor allowed */
	SQLAcct(const SQLAcct&);
	/* No operator= allowed */
	SQLAcct& operator=(const SQLAcct&);

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
	/// timestamp formatting string
	PString m_timestampFormat;
	PIPSocket::Address m_gkAddr;
};

#endif /* SQLACCT_H */
