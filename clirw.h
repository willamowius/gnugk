/*
 * clirw.h
 *
 * Module for CLI/ANI manipulation.
 *
 * Copyright (c) 2005, Michal Zygmuntowicz
 * Copyright (c) 2007-2010, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#ifndef CLIRW_H
#define CLIRW_H "#(@) $Id$"

#include <string>
#include <vector>
#include "Toolkit.h"

struct SetupAuthData;
class SignalingMsg;
template <class> class H225SignalingMsg;
class H225_Setup_UUIE;
typedef H225SignalingMsg<H225_Setup_UUIE> SetupMsg;
class GkSQLConnection;

/// Perform Calling-Party-Number-IE/Setup-UUIE.sourceAddress rewritting
class CLIRewrite {
public:
	/// a single CLI/ANI rewrite rule
	struct RewriteRule {

		RewriteRule();
		PString AsString() const;

		/// match condition to apply the rule
		enum MatchType {
			MatchDialedNumber, /// dialed number before any rewrite
			MatchDestinationNumber, /// dailed number after global rewrite
			MatchCallerNumber /// CLI/ANI
		};

		/// how to perform number matching and rewritting
		enum RewriteType {
			PrefixToNumber, /// match by a prefix, replace with a complete number
			PrefixToPrefix, /// match by a prefix, replace only the prefix part
			NumberToNumber, /// match by a complete number, replace with a complete number
			PrefixToH323Id, /// match by a prefix, replace H.323 ID only with a complete number
			NumberToH323Id  /// match by a complete number, replace H.323 ID only with a complete number
		};

		/// how to hide caller's number
		enum ScreeningType {
			NoScreening, /// leave as it is
			HideFromTerminals, /// hide only if a callee is a terminal
			AlwaysHide /// always hide
		};

		/// manual CLIR (presentation indicator) control
		enum CLIRType {
			CLIRPassthrough, /// leave PI as received from a caller
			RestrictPresentation, /// set PI to restricted
			AllowPresentation /// set PI to allowed
		};

		/// how to process received CLIR (PI) information
		enum CLIRRule {
			IgnoreCLIR, /// use the global settings to make the decission
			ForwardCLIR, /// do nothing, just forward as received
			ApplyCLIRForTerminals, /// hide caller's number, if the callee is a terminal and PI=restricted
			AlwaysApplyCLIR /// always hide caller's number, if PI=restricted
		};

		int m_matchType; /// match condition
		int m_rewriteType; /// number matching/rewritting rule
		int m_screeningType; /// caller's number hiding
		int m_manualCLIR; /// CLIR settings override
		int m_CLIRPolicy; /// how to process CLIR
		std::string m_prefix; /// the prefix to match
		std::vector<std::string> m_cli; /// list of new CLIs
	};

	typedef std::vector<RewriteRule> RewriteRules;
	typedef std::pair<NetworkAddress, RewriteRules> SingleIpRule;
	typedef std::vector<SingleIpRule> SingleIpRules;
	typedef std::pair<NetworkAddress, SingleIpRules> DoubleIpRule;
	typedef std::vector<DoubleIpRule> DoubleIpRules;

	CLIRewrite();

	/// Rewrite CLI before any Setup message processing, like auth & routing
	void InRewrite(
		SetupMsg &msg /// Q.931 Setup message to be rewritten
		);

	/** Rewrite CLI before the Setup is sent to the terminating party
	    and after auth/acct/routing is performed.
	*/
	void OutRewrite(
		SetupMsg &msg, /// Q.931 Setup message to be rewritten
		SetupAuthData &authData, /// additional data
		const PIPSocket::Address &destAddr /// destination address
		);

protected:
	void Rewrite(
		SetupMsg &msg, /// Q.931 Setup message to be rewritten
		const SingleIpRule &ipRule, /// rule to use for rewrite
		bool inbound, /// rule type
		SetupAuthData *authData /// additional data for outbound rules
		) const;

	// process inbound or outbound SQL queries and return a rule
	SingleIpRule * RunQuery(const PString & query, const SetupMsg & msg);

	CLIRewrite(const CLIRewrite &);
	CLIRewrite & operator=(const CLIRewrite &);

private:
	SingleIpRules m_inboundRules; /// a set of inbound CLI/ANI rewrite rules
	DoubleIpRules m_outboundRules; /// a set of outbound CLI/ANI rewrite rules
	bool m_processSourceAddress; /// true to rewrite numbers in sourceAddress Setup-UUIE
	bool m_removeH323Id; /// true to put in the sourceAddress Setup-UUIE field only rewritten ANI/CLI
	int m_CLIRPolicy; /// how to process CLIR

	// RewriteCLI::SQL parameters
	GkSQLConnection * m_sqlConn;
	PString m_inboundQuery;
	PString m_outboundQuery;
};

#endif
