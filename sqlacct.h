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
 * Revision 1.7  2006/04/14 13:56:19  willamowius
 * call failover code merged
 *
 * Revision 1.1.1.1  2005/11/21 20:19:58  willamowius
 *
 *
 * Revision 1.4  2005/11/15 19:52:56  jan
 * Michal v1 (works, but on in routed, not proxy mode)
 *
 * Revision 1.6  2005/03/08 14:31:13  zvision
 * Support for Connect event added
 *
 * Revision 1.5  2005/01/12 17:55:07  willamowius
 * fix gkip accounting parameter
 *
 * Revision 1.4  2005/01/05 15:42:41  willamowius
 * new accounting event 'connect', parameter substitution unified in parent class
 *
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
    parameters.
*/
class GkSQLConnection;
class SQLAcct : public GkAcctLogger
{
public:
	enum Constants {
		/// events recognized by this module
		SQLAcctEvents = AcctStart | AcctUpdate | AcctStop | AcctConnect
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

	virtual PString GetInfo();
	
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
};

#endif /* SQLACCT_H */
