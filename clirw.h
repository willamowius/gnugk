/*
 * clirw.h
 *
 * Module for CLI/ANI manipulation.
 *
 * Copyright (c) 2005, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
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
		int m_matchType; /// match condition
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
		
private:
	void Rewrite(
		SetupMsg &msg, /// Q.931 Setup message to be rewritten
		const SingleIpRule &ipRule, /// rule to use for rewrite
		bool inbound, /// rule type
		SetupAuthData *authData /// additional data for outbound rules
		) const;

	CLIRewrite(const CLIRewrite &);
	CLIRewrite & operator=(const CLIRewrite &);
	
private:
	SingleIpRules m_inboundRules; /// a set of inbound CLI/ANI rewrite rules
	DoubleIpRules m_outboundRules; /// a set of outbound CLI/ANI rewrite rules
	bool m_processSourceAddress; /// true to rewrite numbers in sourceAddress Setup-UUIE
	bool m_removeH323Id; /// true to put in the sourceAddress Setup-UUIE field only rewritten ANI/CLI
};

#endif
