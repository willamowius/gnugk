//////////////////////////////////////////////////////////////////
//
// Call Forwarding Poliy for GNU Gatekeeper
//
// Copyright (c) 2012, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <h323pdu.h>
#include "Routing.h"
#include "Toolkit.h"
#include "gksql.h"
#include "gk_const.h"
#include "h323util.h"

// forwards are handled in ascending order of their type
enum ForwardingTypes {
	FORWARD_UNCONDITIONAL=1,
	FORWARD_BUSY=2,
	FORWARD_NOANSWER=3,
	FORWARD_ERROR=4 };

const unsigned MAX_RECURSION_DEPTH = 25;
const unsigned DEFAULT_PRIORITY = 1;
const unsigned NO_ANSWER_PRIORITY = 900;

namespace Routing {

// a policy to route calls via an SQL database
class ForwardingPolicy : public DynamicPolicy {
public:
	ForwardingPolicy();
	virtual ~ForwardingPolicy();

protected:
	virtual void RunPolicy(
		/*in */
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType,
		const PString & clientauthid,
		/* out: */
		DestinationRoutes & destination);

	// called recursively
	virtual bool FindEPForwardingRules(
		/* in */
		std::map<PString, PString> params,
		unsigned recursionDepth,
		unsigned priority,
		/* out: */
		DestinationRoutes & destination);

protected:
	// connection to the SQL database
	GkSQLConnection* m_sqlConn;
	// parametrized query string for the routing query
	PString m_query;
	// query timeout
	long m_timeout;
};

ForwardingPolicy::ForwardingPolicy()
{
	m_active = false;
	m_sqlConn = NULL;
#if HAS_DATABASE
	m_active = true;
	static const char *sqlsection = "Routing::Forwarding";
	m_name = "Forwarding";
	m_timeout = -1;

	PConfig* cfg = GkConfig();

	const PString driverName = cfg->GetString(sqlsection, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(2, m_name << "\tmodule creation failed: no SQL driver selected");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		m_active = false;
		return;
	}

	m_sqlConn = GkSQLConnection::Create(driverName, m_name);
	if (m_sqlConn == NULL) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"could not find " << driverName << " database driver");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		m_active = false;
		return;
	}

	m_query = cfg->GetString(sqlsection, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"no query configured");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		m_active = false;
		return;
	} else
		PTRACE(4, m_name << "\tQuery: " << m_query);

	if (!m_sqlConn->Initialize(cfg, sqlsection)) {
		PTRACE(2, m_name << "\tmodule creation failed: "
			"could not connect to the database");
		SNMP_TRAP(4, SNMPError, Database, PString(m_name) + " creation failed");
		m_active = false;
		return;
	}
#else
	PTRACE(1, m_name << " not available - no database driver compiled into GnuGk");
#endif // HAS_DATABASE
}

ForwardingPolicy::~ForwardingPolicy()
{
	delete m_sqlConn;
}

void ForwardingPolicy::RunPolicy(
		/* in */
		const PString & source,
		const PString & calledAlias,
		const PString & calledIP,
		const PString & caller,
		const PString & callingStationId,
		const PString & callid,
		const PString & messageType,
		const PString & clientauthid,
		/* out: */
		DestinationRoutes & destination)
{
#if HAS_DATABASE
	std::map<PString, PString> params;
	params["s"] = source;
	params["c"] = calledAlias;
	params["p"] = calledIP;
	params["r"] = caller;
	params["Calling-Station-Id"] = callingStationId;
	params["i"] = callid;
	params["m"] = messageType;
	params["client-auth-id"] = clientauthid;

	// if IP called, check if its an internal EP and change calledAlias/calledIP
	if (calledAlias.IsEmpty() && IsIPAddress(calledIP)) {
		PStringArray adr_parts = calledIP.Tokenise(":", FALSE);
		PString ip = adr_parts[0];
		WORD port = (WORD)(adr_parts[1].AsInteger());
		if (port == 0)
			port = GK_DEF_ENDPOINT_SIGNAL_PORT;
		endptr ep = RegistrationTable::Instance()->FindBySignalAdr(SocketToH225TransportAddr(ip, port));
		if (ep) {
			// call goes to an internal endpoint, use the first alias instead
			H225_ArrayOf_AliasAddress aliases = ep->GetAliases();
			if (aliases.GetSize() > 0) {
				params["c"] = AsString(aliases[0], false);
				params["p"] = "";
			}
		}
	}

	FindEPForwardingRules(params, 0, DEFAULT_PRIORITY, destination);

	PTRACE(5, "Fwd\t" << destination.m_routes.size() << " routes added");
	for(std::list<Route>::iterator it = destination.m_routes.begin(); it !=destination.m_routes.end(); ++it) {
		PTRACE(5, "Fwd\tRoute=" << it->AsString());
	}
	if (destination.ChangeAliases()) {
		PTRACE(5, "Fwd\tAliases changed to " << destination.GetNewAliases());
	}
#endif // HAS_DATABASE
}


bool ForwardingPolicy::FindEPForwardingRules(
		/* in */
		std::map<PString, PString> params,	// pass copies so they can be modified in recursion
		unsigned recursionDepth,
		unsigned priority,
		/* out: */
		DestinationRoutes & destination)
{
	bool skipOrginalForward = false;

	// make sure we don't produce infinite loops
	if (recursionDepth > MAX_RECURSION_DEPTH)
		return false;

#if HAS_DATABASE
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, params, m_timeout);
	if (result == NULL) {
		PTRACE(2, m_name << ": query failed - timeout or fatal error");
		SNMP_TRAP(5, SNMPError, Database, PString(m_name) + " query failed");
		return false;
	}

	if (!result->IsValid()) {
		PTRACE(2, m_name << ": query failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage());
		SNMP_TRAP(5, SNMPError, Database, PString(m_name) + " query failed");
		delete result;
		return false;
	}

	if (result->GetNumRows() < 1) {
		PTRACE(5, m_name << ": query returned no rows");
		return false;
	} else if (result->GetNumFields() != 2) {
		PTRACE(2, m_name << ": bad query - didn't return 2 fields");
		SNMP_TRAP(5, SNMPError, Database, PString(m_name) + " query failed");
		return false;
	} else {
		// fetch all rows now, recursive checks will invalidate result set
		std::vector<GkSQLResult::ResultRow> rows(result->GetNumRows());
		for (long i = 0; i < result->GetNumRows(); ++i) {
			if (!result->FetchRow(rows[i]) || rows[i].empty()) {
				PTRACE(2, m_name << ": query failed - could not fetch the result row");
				SNMP_TRAP(5, SNMPError, Database, PString(m_name) + " query failed");
				break;
			}
		}

		// look at all rules (ordered by forwarding type)
		for (unsigned i = 0; i < rows.size(); ++i) {
			unsigned forwardType = rows[i][0].first.AsInteger();
			PString forwardDestination = rows[i][1].first;
			PTRACE(4, "Fwd\tForward type=" << forwardType << " for call to " << params["c"] << ": new dest=" << forwardDestination);
			if (forwardDestination.IsEmpty()) {
				// skip rule, if forwardDestination is empty
				continue;
			}
			if ( (forwardType == FORWARD_UNCONDITIONAL)
				|| (forwardType == FORWARD_BUSY) ) {
				if (IsIPAddress(forwardDestination)) {
					// set a route if forward to IP
					PString destinationIp = forwardDestination;
					PStringArray adr_parts = destinationIp.Tokenise(":", FALSE);
					PString ip = adr_parts[0];
					WORD port = (WORD)(adr_parts[1].AsInteger());
					if (port == 0)
						port = GK_DEF_ENDPOINT_SIGNAL_PORT;
					//PTRACE(0, "JW forward destination to " << forwardDestination << " prio=" << priority + recursionDepth);
					Route route("ForwardUnconditionalOrBusy", SocketToH225TransportAddr(ip, port), priority + recursionDepth);
					route.m_destEndpoint = RegistrationTable::Instance()->FindBySignalAdr(route.m_destAddr);
					if ((forwardType == FORWARD_UNCONDITIONAL)
						|| (route.m_destEndpoint && CallTable::Instance()->FindCallRec(route.m_destEndpoint))) {
						route.m_destNumber = forwardDestination;
						route.m_destOutNumber = forwardDestination;
						destination.AddRoute(route, false);
						skipOrginalForward = true;
					}
				} else {
					// check if we have an EPRec for the new destination (to check for current call or forwards)
					H225_ArrayOf_AliasAddress called;
					called.SetSize(1);
					H323SetAliasAddress(params["c"], called[0]);
					endptr ep = RegistrationTable::Instance()->FindByAliases(called);
					//PTRACE(0, "JW call to " << AsString(called, false) << " ep=" << ep << " call=" << CallTable::Instance()->FindCallRec(ep));
					if ((forwardType == FORWARD_UNCONDITIONAL)
						|| (ep && CallTable::Instance()->FindCallRec(ep))) {
						// check if new destination is also forwarded
						params["c"] = forwardDestination;
						params["p"] = "";
						if (FindEPForwardingRules(params, recursionDepth+1, DEFAULT_PRIORITY, destination)) {
							PTRACE(5, "Fwd\tSkipping forward to " << forwardDestination << " (also redirected uncond/busy)");
							//PTRACE(0, "JW destination aliases=" << destination.GetNewAliases());
						} else {
							if (priority <= 1) {
								// just rewrite the destination if forward to alias
								//PTRACE(0, "JW rewriting destination to " << forwardDestination);
								H225_ArrayOf_AliasAddress newAliases;
								newAliases.SetSize(1);
								H323SetAliasAddress(forwardDestination, newAliases[0]);
								destination.SetNewAliases(newAliases);
							} else {
								//PTRACE(0, "JW forward destination to " << forwardDestination << " prio=" << priority);
								// replace an NoAnswer or Error forward
								if (ep) {
									Route route("ForwardNoAnswerOrError", ep, priority + recursionDepth);
									route.m_destNumber = forwardDestination;
									route.m_destOutNumber = forwardDestination;
									destination.AddRoute(route, false);
								} else {
									PTRACE(3, "Fwd\tUnconditional Forward or on Busy to non-local or currently not registered alias " << forwardDestination);
								}
							}
						}
						skipOrginalForward = true;
					}
				}
			} else if ((forwardType == FORWARD_NOANSWER) || (forwardType == FORWARD_ERROR)) {
				if (IsIPAddress(forwardDestination)) {
					// set a route if forward to IP
					PString destinationIp = forwardDestination;
					PStringArray adr_parts = destinationIp.Tokenise(":", FALSE);
					PString ip = adr_parts[0];
					WORD port = (WORD)(adr_parts[1].AsInteger());
					if (port == 0)
						port = GK_DEF_ENDPOINT_SIGNAL_PORT;
					Route route("ForwardNoAnswerOrError", SocketToH225TransportAddr(ip, port), NO_ANSWER_PRIORITY + recursionDepth);
					route.m_destNumber = forwardDestination;
					route.m_destOutNumber = forwardDestination;
					destination.AddRoute(route);
				} else {
					H225_ArrayOf_AliasAddress forwardAliases;
					forwardAliases.SetSize(1);
					H323SetAliasAddress(forwardDestination, forwardAliases[0]);
					endptr ep = RegistrationTable::Instance()->FindByAliases(forwardAliases);
					//PTRACE(0, "JW forwarding NoAnswer to " << forwardDestination << " ep=" << ep);
					// check if destination also has uncond/busy forwarding rules
					params["c"] = forwardDestination;
					params["p"] = "";
					if (FindEPForwardingRules(params, recursionDepth+1, NO_ANSWER_PRIORITY, destination)) {
						PTRACE(5, "Fwd\tSkipping forward to " << forwardDestination << " (also redirected uncond/busy)");
					} else {
						if (ep) {
							// add a NoAnswer route, lower recursion depth is given more priority
							Route route("ForwardNoAnswerOrError", ep, NO_ANSWER_PRIORITY + recursionDepth);
							route.m_destNumber = forwardDestination;
							route.m_destOutNumber = forwardDestination;
							destination.AddRoute(route, false);
						} else {
							PTRACE(3, "Fwd\tForward on NoAnswer or Error to non-local or currently not registered alias " << forwardDestination);
						}
					}
				}
			} else {
				PTRACE(1, "Fwd\tUnsupported forward type " << forwardType);
			}
		}
	}
	delete result;
#endif // HAS_DATABASE
	return skipOrginalForward;
}


namespace { // anonymous namespace
	SimpleCreator<ForwardingPolicy> ForwardingPolicyCreator("forwarding");
}


} // end of namespace Routing

