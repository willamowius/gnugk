/*
 * clirw.cxx
 *
 * Module for CLI/ANI manipulation.
 *
 * $Id$
 *
 * Copyright (c) 2005, Michal Zygmuntowicz
 * Copyright (c) 2007-2023, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include <ptlib.h>
#include <ptlib/ipsock.h>
#include "clirw.h"
#include <h225.h>
#include <h323pdu.h>
#include <q931.h>
#include "sigmsg.h"
#include "stl_supp.h"
#include "h323util.h"
#include "RasTbl.h"
#include "RasPDU.h"
#include "gkauth.h"
#include "Toolkit.h"
#include "gksql.h"

namespace {
const char * const CLIRewriteSection = "RewriteCLI";
const char * const CLIRewriteSQLSection = "RewriteCLI::SQL";
const char * const ProcessSourceAddress = "ProcessSourceAddress";
const char * const RemoveH323Id = "RemoveH323Id";
const char * const CLIRPolicy = "CLIRPolicy";
const char * const ReservedKeys[] = { ProcessSourceAddress, RemoveH323Id, CLIRPolicy, NULL };
}

CLIRewrite::RewriteRule::RewriteRule()
	: m_matchType(MatchDialedNumber), m_rewriteType(PrefixToNumber),
	m_screeningType(NoScreening), m_manualCLIR(CLIRPassthrough),
	m_CLIRPolicy(IgnoreCLIR)
{
}

PString CLIRewrite::RewriteRule::AsString() const
{
	PString s;

	if (m_manualCLIR == RestrictPresentation)
		s = "restrict";
	else if (m_manualCLIR == AllowPresentation)
		s = "allow";

	if (m_CLIRPolicy != IgnoreCLIR) {
		if (!s)
			s += ",";
		if (m_CLIRPolicy == ForwardCLIR)
			s += "forward";
 		else if (m_CLIRPolicy == ApplyCLIRForTerminals)
			s += "applyforterminals";
		else
			s += "apply";
	}
	if (!s)
		s = "pi=" + s + " ";
	
	if (m_matchType == MatchDialedNumber)
		s += "dialed number: ";
	else if (m_matchType == MatchDestinationNumber)
		s += "destination number: ";
	else
		s += "caller number: ";

	s += m_prefix.empty() ? "any" : m_prefix.c_str();
	if (m_rewriteType == PrefixToNumber)
		s += " = ";
	else if (m_rewriteType == PrefixToPrefix)
		s += " *= ";
	else if (m_rewriteType == NumberToNumber)
		s += " ~= ";
	else if (m_rewriteType == PrefixToH323Id)
		s += " ^= ";
	else if (m_rewriteType == NumberToH323Id)
		s += " /= ";
	else
		s += " ?unknown rewrite rule type? ";

	std::vector<std::string>::const_iterator cli = m_cli.begin();
	while (cli != m_cli.end()) {
		s += cli->c_str();
		if (++cli != m_cli.end())
			s += ", ";
	}
	if (m_cli.empty())
		s += (m_screeningType == HideFromTerminals) ? "hide from terminals only" : "hide";

	return s;
}

namespace {
#if (__cplusplus >= 201703L) // C++17
struct RewriteRule_greater {
	typedef CLIRewrite::RewriteRule first_argument_type;
	typedef CLIRewrite::RewriteRule second_argument_type;
	typedef bool result_type;
#else
struct RewriteRule_greater : public std::binary_function<CLIRewrite::RewriteRule, CLIRewrite::RewriteRule, bool> {
#endif

	bool operator()(const CLIRewrite::RewriteRule &e1, const CLIRewrite::RewriteRule &e2) const
	{
		long long int diff = e1.m_matchType - e2.m_matchType;
		if (diff != 0)
			return diff < 0;
		diff = e1.m_prefix.length() - e2.m_prefix.length();
		if (diff != 0)
			return diff > 0;
		return e1.m_prefix.compare(e2.m_prefix) > 0;
	}
};

#if (__cplusplus >= 201703L) // C++17
struct SingleIpRule_greater {
	typedef CLIRewrite::SingleIpRule first_argument_type;
	typedef CLIRewrite::SingleIpRule second_argument_type;
	typedef bool result_type;
#else
struct SingleIpRule_greater : public std::binary_function<CLIRewrite::SingleIpRule, CLIRewrite::SingleIpRule, bool> {
#endif

	bool operator()(const CLIRewrite::SingleIpRule &e1, const CLIRewrite::SingleIpRule &e2) const
	{
		if (e1.first.IsAny()) {
			if (!e2.first.IsAny())
				return false;
		} else {
			if (e2.first.IsAny())
				return true;
			int diff = e1.first.Compare(e2.first);
			if (diff != 0)
				return diff > 0;
		}
		return false;
	}
};

#if (__cplusplus >= 201703L) // C++17
struct DoubleIpRule_greater {
	typedef CLIRewrite::DoubleIpRule first_argument_type;
	typedef CLIRewrite::DoubleIpRule second_argument_type;
	typedef bool result_type;
#else
struct DoubleIpRule_greater : public std::binary_function<CLIRewrite::DoubleIpRule, CLIRewrite::DoubleIpRule, bool> {
#endif

	bool operator()(const CLIRewrite::DoubleIpRule &e1, const CLIRewrite::DoubleIpRule &e2) const
	{
		if (e1.first.IsAny()) {
			if (!e2.first.IsAny())
				return false;
		} else {
			if (e2.first.IsAny())
				return true;
			int diff = e1.first.Compare(e2.first);
			if (diff != 0)
				return diff > 0;
		}
		return false;
	}
};
} /* namespace */

CLIRewrite::CLIRewrite()
	: m_processSourceAddress(true), m_removeH323Id(false),
	m_CLIRPolicy(RewriteRule::IgnoreCLIR), m_sqlConn(NULL)
{
	PConfig * cfg = GkConfig();

	unsigned inboundRules = 0, outboundRules = 0;
	SingleIpRules::iterator siprule = m_inboundRules.end();
	DoubleIpRules::iterator diprule = m_outboundRules.end();
	
	const PStringToString kv = cfg->GetAllKeyValues(CLIRewriteSection);
	for (PINDEX i = 0; i < kv.GetSize(); i++) {
		PString key = kv.GetKeyAt(i);

		unsigned j = 0;
		while (ReservedKeys[j] != NULL) {
			if (key == ReservedKeys[j++]) {
				break;
			}
		}
		if (ReservedKeys[j] != NULL)
			continue;

		if (key[0] == '%') {
			const PINDEX sepIndex = key.Find('%', 1);
			if (sepIndex != P_MAX_INDEX)
				key = key.Mid(sepIndex + 1).Trim();
		}

		// on Unix multiple entries for the same key are concatenated
		// to one string and separated by a new line
		PStringArray dataLines = kv.GetDataAt(i).Tokenise("\n", FALSE);
		for (PINDEX d = 0; d < dataLines.GetSize(); d++) {
			PString data = dataLines[d];
			RewriteRules *rules = NULL;
			bool newsiprule = false, newdiprule = false, inbound = false;
			NetworkAddress addr;

			// check the rule type (inbound/outbound)		
			if (key.Find("in:") == 0) {
				const PString ip = key.Mid(3).Trim();
				inbound = true;
			
				if (!(ip == "*" || ip == "any"))
					addr = NetworkAddress(ip);

				// check if the IP is already on the list
				siprule = m_inboundRules.begin();
				while (siprule != m_inboundRules.end()) {
					if (siprule->first.m_address.IsAny() || addr.m_address.IsAny()) {
						if (siprule->first.m_address.IsAny() && addr.m_address.IsAny())
							break;
					} else if (siprule->first == addr)
						break;
					++siprule;
				}

				// append the new IP to the list	
				if (siprule == m_inboundRules.end()) {
					m_inboundRules.resize(m_inboundRules.size() + 1);
					siprule = m_inboundRules.end() - 1;
					siprule->first = addr;
					newsiprule = true;
				}
	
				rules = &(siprule->second);
			} else if (key.Find("out:") == 0) {
				const PString ip = key.Mid(4).Trim();
				inbound = false;

				if (!(ip == "*" || ip == "any"))
					addr = NetworkAddress(ip);
				
				// check if the IP is already on the list
				diprule = m_outboundRules.begin();
				while (diprule != m_outboundRules.end()) {
					if (diprule->first.m_address.IsAny() || addr.m_address.IsAny()) {
						if (diprule->first.m_address.IsAny() && addr.m_address.IsAny())
							break;
					} else if (diprule->first == addr)
						break;
					++diprule;
				}
	
				// append the new IP to the list	
				if (diprule == m_outboundRules.end()) {
					m_outboundRules.resize(m_outboundRules.size() + 1);
					diprule = m_outboundRules.end() - 1;
					diprule->first = addr;
					newdiprule = true;
				}
				
				// separate and extract callee IP address, if present
				// no address means wildcard "match any"
				addr = NetworkAddress();
				
				PINDEX sepIndex = data.Find('=');
				if (sepIndex != P_MAX_INDEX) {
					PString lhs = data.Left(sepIndex).Trim();
					sepIndex = lhs.FindOneOf(" \t");
					if (sepIndex != P_MAX_INDEX) {
						lhs = lhs.Left(sepIndex).Trim();
						data = data.Mid(sepIndex + 1);
						if (!(lhs == "*" || lhs == "any"))
							addr = NetworkAddress(lhs);
					}
				}
				// check if the address is already on the list
				siprule = diprule->second.begin();
				while (siprule != diprule->second.end()) {
					if (siprule->first.m_address.IsAny() || addr.m_address.IsAny()) {
						if (siprule->first.m_address.IsAny() && addr.m_address.IsAny())
							break;
					} else if (siprule->first == addr)
						break;
					++siprule;
				}
	
				// append the new callee address, if not found
				if (siprule == diprule->second.end()) {
					diprule->second.resize(diprule->second.size() + 1);
					siprule = diprule->second.end() - 1;
					siprule->first = addr;
					newsiprule = true;
				}
				
				rules = &(siprule->second);
			} else {
				PTRACE(1, "CLIRW\tUknown CLI rewrite rule: " << key << '='
					<< kv.GetDataAt(i)
					);
				continue;
			}

			// process CLIR options
			int manualCLIR = RewriteRule::CLIRPassthrough;
			int CLIRPolicy = RewriteRule::IgnoreCLIR;
			
			data = data.Trim();
			if (data.Find("pi=") == 0) {
				data = data.Mid(3);
				PINDEX sepIndex = data.FindOneOf(" \t");
				if (sepIndex != P_MAX_INDEX) {
					PString lhs = data.Left(sepIndex).Trim();
					data = data.Mid(sepIndex + 1).Trim();
					PStringArray tokens = lhs.Tokenise(",;", FALSE);
					for (PINDEX k = 0; k < tokens.GetSize(); ++k)
						if (tokens[k] *= "allow")
							manualCLIR = RewriteRule::AllowPresentation;
						else if (tokens[k] *= "restrict")
							manualCLIR = RewriteRule::RestrictPresentation;
						else if (tokens[k] *= "forward")
							CLIRPolicy = RewriteRule::ForwardCLIR;
						else if (tokens[k] *= "apply")
							CLIRPolicy = RewriteRule::AlwaysApplyCLIR;
						else if (tokens[k] *= "applyforterminals")
							CLIRPolicy = RewriteRule::ApplyCLIRForTerminals;
						else
							PTRACE(1, "CLIRW\tInvalid CLI rewrite rule syntax: " << key << '='
								<< kv.GetDataAt(k) << ", unreconized pi option '" << tokens[k]
								<< "'"
								);
				}
			}
			// process CLI/ANI rewrite rule
			
			const PINDEX sepIndex = data.Find('=');
			if (sepIndex == P_MAX_INDEX) {
				PTRACE(1, "CLIRW\tInvalid CLI rewrite rule syntax: " << key << '='
					<< kv.GetDataAt(i)
					);
				if (newsiprule) {
					if (inbound) {
						m_inboundRules.erase(siprule);
					} else {
						diprule->second.erase(siprule);
					}
				}
				if (newdiprule)
					m_outboundRules.erase(diprule);
				continue;
			}
	
			// extract match condition
			
			PINDEX keyIndex = 0;
			int matchType = inbound ? RewriteRule::MatchDialedNumber : RewriteRule::MatchDestinationNumber;
			if (!inbound && data.Find("cno:") == 0) {
				matchType = RewriteRule::MatchDestinationNumber;
				keyIndex += 4;
			} else if (data.Find("dno:") == 0) {
				matchType = RewriteRule::MatchDialedNumber;
				keyIndex += 4;
			} else if (data.Find("cli:") == 0) {
				matchType = RewriteRule::MatchCallerNumber;
				keyIndex += 4;
			}
	
			// extract prefix to be matched
			PINDEX keyChars = sepIndex - keyIndex;
			int rewriteType = RewriteRule::PrefixToNumber;
			if (sepIndex > keyIndex) {
				if (data[sepIndex-1] == '*') {
					rewriteType = RewriteRule::PrefixToPrefix;
					--keyChars;
				} else if (data[sepIndex-1] == '~') {
					rewriteType = RewriteRule::NumberToNumber;
					--keyChars;
				} else if (data[sepIndex-1] == '^') {
					rewriteType = RewriteRule::PrefixToH323Id;
					--keyChars;
				} else if (data[sepIndex-1] == '/') {
					rewriteType = RewriteRule::NumberToH323Id;
					--keyChars;
				}
			}
					
			if (rewriteType == RewriteRule::PrefixToPrefix && matchType != RewriteRule::MatchCallerNumber) {
				PTRACE(1, "CLIRW\tInvalid CLI rewrite rule syntax - cannot perform "
					"*= rewrite on non 'cli:' rules: " << key << '='
					<< kv.GetDataAt(i)
					);
				if (newsiprule) {
					if (inbound) {
						m_inboundRules.erase(siprule);
					} else {
						diprule->second.erase(siprule);
					}
				}
				if (newdiprule)
					m_outboundRules.erase(diprule);
				continue;
			}
			
			std::string prefix((const char*)(data.Mid(keyIndex, keyChars).Trim()));
			if (prefix == "any")
				prefix.erase();

			// check if the rule already exists			
			RewriteRules::iterator rule = rules->begin();
			while (rule != rules->end())
				if (rule->m_matchType == matchType && rule->m_rewriteType == rewriteType
						&& rule->m_prefix.compare(prefix) == 0)
					break;
				else
					++rule;
	
			if (rule == rules->end()) {
				rules->resize(rules->size() + 1);
				rule = rules->end() - 1;
			}
	
			rule->m_screeningType = RewriteRule::NoScreening;
			rule->m_matchType = matchType;
			rule->m_rewriteType = rewriteType;
			rule->m_prefix = prefix;		
			rule->m_manualCLIR = manualCLIR;
			rule->m_CLIRPolicy = CLIRPolicy;

			// get RHS of the rewrite rule, multiple targets will be selected
			// in random order
			PStringArray clis = data.Mid(sepIndex + 1).Tokenise(", ", FALSE);
			if (clis.GetSize() < 1)
				rule->m_screeningType = RewriteRule::AlwaysHide;
			else if (clis[0] *= PString("hide"))
				rule->m_screeningType = RewriteRule::AlwaysHide;
			else if (clis[0] *= PString("hidefromterminals"))
				rule->m_screeningType = RewriteRule::HideFromTerminals;
			
			if (rule->m_screeningType == RewriteRule::NoScreening) {
				rule->m_cli.resize(clis.GetSize());
				for (PINDEX k = 0; k < clis.GetSize(); k++)
					rule->m_cli[k] = (string)((const char *)(clis[k]));
			} else
				rule->m_cli.clear();

			if (inbound)
				inboundRules++;
			else
				outboundRules++;
		} /* for (d) */
	} /* for (i) */

	// sort rules by IP network mask length	
	std::stable_sort(m_inboundRules.begin(), m_inboundRules.end(), SingleIpRule_greater());
	std::stable_sort(m_outboundRules.begin(), m_outboundRules.end(), DoubleIpRule_greater());

	siprule = m_inboundRules.begin();
	while (siprule != m_inboundRules.end()) {
		std::stable_sort(siprule->second.begin(), siprule->second.end(), RewriteRule_greater());
		++siprule;
	}

	diprule = m_outboundRules.begin();	
	while (diprule != m_outboundRules.end()) {
		std::stable_sort(diprule->second.begin(), diprule->second.end(), SingleIpRule_greater());
		siprule = diprule->second.begin();
		while (siprule != diprule->second.end()) {
			std::stable_sort(siprule->second.begin(), siprule->second.end(), RewriteRule_greater());
			++siprule;
		}
		++diprule;
	}
	
	PTRACE(5, "CLIRW\t" << inboundRules << " inbound rules loaded");
	if (PTrace::CanTrace(6)) {
		ostream &strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << "Inbound CLI rewrite rules:" << endl;
		for (unsigned i = 0; i < m_inboundRules.size(); i++) {
			strm << "\tsrc " << m_inboundRules[i].first.AsString() << ":" << endl;
			for (unsigned j = 0; j < m_inboundRules[i].second.size(); j++)
				strm << "\t\t" << m_inboundRules[i].second[j].AsString() << endl;
		}
		PTrace::End(strm);
	}

	PTRACE(5, "CLIRW\t" << outboundRules << " outbound rules loaded");
	if (PTrace::CanTrace(6)) {
		ostream &strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << "Outbound CLI rewrite rules:" << endl;
		for (unsigned i = 0; i < m_outboundRules.size(); i++)
			for (unsigned j = 0; j < m_outboundRules[i].second.size(); j++) {
				strm << "\tsrc " << m_outboundRules[i].first.AsString() << " dst "
					<< m_outboundRules[i].second[j].first.AsString() << ":" << endl;
				for (unsigned k = 0; k < m_outboundRules[i].second[j].second.size(); k++)
					strm << "\t\t" << m_outboundRules[i].second[j].second[k].AsString() << endl;
			}
		PTrace::End(strm);
	}

	m_processSourceAddress = Toolkit::AsBool(cfg->GetString(CLIRewriteSection, ProcessSourceAddress, "1"));
	m_removeH323Id = Toolkit::AsBool(cfg->GetString(CLIRewriteSection, RemoveH323Id, "1"));
	
	const PString clirPolicy = cfg->GetString(CLIRewriteSection, CLIRPolicy, "");
	if (clirPolicy *= "applyforterminals")
		m_CLIRPolicy = RewriteRule::ApplyCLIRForTerminals;
	else if (clirPolicy *= "apply")
		m_CLIRPolicy = RewriteRule::AlwaysApplyCLIR;
	else if (clirPolicy *= "forward")
		m_CLIRPolicy = RewriteRule::ForwardCLIR;
	else if (clirPolicy.IsEmpty())
		m_CLIRPolicy = RewriteRule::IgnoreCLIR;
	else {
		PTRACE(1, "CLIRW\tSyntax error in the config - an unrecognized "
			"CLIRPolicy value: '" << clirPolicy << "'");
		SNMP_TRAP(7, SNMPError, Configuration, "Invalid CLIRW rule");
	}


	// read [RewriteCLI::SQL]
#if HAS_DATABASE
	m_inboundQuery = cfg->GetString(CLIRewriteSQLSection, "InboundQuery", "");
	if (!m_inboundQuery.IsEmpty()) {
		PTRACE(4, CLIRewriteSQLSection << "\tInboundQuery: " << m_inboundQuery);
	}
	m_outboundQuery = cfg->GetString(CLIRewriteSQLSection, "OutboundQuery", "");
	if (!m_outboundQuery.IsEmpty()) {
		PTRACE(4, CLIRewriteSQLSection << "\tOutboundQuery: " << m_outboundQuery);
	}

	if (!(m_inboundQuery.IsEmpty() && m_outboundQuery.IsEmpty())) {
		// if we have either Inbound or Outboudnd query, read DB parameters
		const PString driverName = cfg->GetString(CLIRewriteSQLSection, "Driver", "");
		if (driverName.IsEmpty()) {
			PTRACE(1, CLIRewriteSQLSection << ": no SQL driver selected - disabled");
			SNMP_TRAP(4, SNMPError, Database, PString(CLIRewriteSQLSection) + ": no SQL driver selected");
			m_inboundQuery = m_outboundQuery = "";
			return;
		}
		m_sqlConn = GkSQLConnection::Create(driverName, CLIRewriteSQLSection);
		if (m_sqlConn == NULL) {
			PTRACE(1, CLIRewriteSQLSection << ": could not find " << driverName << " database driver - disabled");
			SNMP_TRAP(4, SNMPError, Database, PString(CLIRewriteSQLSection) + ": could not find " + driverName + " database driver");
			m_inboundQuery = m_outboundQuery = "";
			return;
		}

		if (!m_sqlConn->Initialize(cfg, CLIRewriteSQLSection)) {
			PTRACE(1, CLIRewriteSQLSection << ": could not connect to the database - disabled");
			SNMP_TRAP(4, SNMPError, Database, PString(CLIRewriteSQLSection) + ": could not connect to the database");
			m_inboundQuery = m_outboundQuery = "";
			delete m_sqlConn;
			m_sqlConn = NULL;
			return;
		}
	}
#endif // HAS_DATABASE
}

void CLIRewrite::InRewrite(
	SetupMsg & msg /// Q.931 Setup message to be rewritten
	)
{
	PIPSocket::Address addr;
	msg.GetPeerAddr(addr);

	// apply [RewriteCLI::SQL] InboundQuery
	if (!m_inboundQuery.IsEmpty()) {
		SingleIpRule * rule = CLIRewrite::RunQuery(m_inboundQuery, msg);
		if (rule) {
			Rewrite(msg, *rule, true, NULL);
			delete rule;
		}
	}

	// find a config file rule that matches caller's IP	
	SingleIpRules::const_iterator i = m_inboundRules.begin();
	while (i != m_inboundRules.end())
		if (i->first.IsAny() || (addr << i->first))
			break;
		else
			++i;

	if (i == m_inboundRules.end())
		return;

	Rewrite(msg, *i, true, NULL);
}

void CLIRewrite::OutRewrite(
	SetupMsg & msg, /// Q.931 Setup message to be rewritten
	SetupAuthData & authData, /// additional data
	const PIPSocket::Address & destAddr /// destination address
	)
{
	PIPSocket::Address addr;
	msg.GetPeerAddr(addr);

	// apply [RewriteCLI::SQL] OutboundQuery
	if (!m_outboundQuery.IsEmpty()) {
		SingleIpRule * rule = CLIRewrite::RunQuery(m_inboundQuery, msg);
		if (rule) {
			Rewrite(msg, *rule, false, &authData);
			delete rule;
		}
	}

	// find a config file rule that matches caller's IP	
	DoubleIpRules::const_iterator diprule = m_outboundRules.begin();
	while (diprule != m_outboundRules.end())
		if (diprule->first.IsAny() || (addr << diprule->first))
			break;
		else
			++diprule;

	if (diprule == m_outboundRules.end())
		return;

	// now find a rule that also matches callee's IP	
	SingleIpRules::const_iterator siprule = diprule->second.begin();
	while (siprule != diprule->second.end())
		if (siprule->first.IsAny() || (destAddr << siprule->first))
			break;
		else
			++siprule;

	if (siprule == diprule->second.end())
		return;

	Rewrite(msg, *siprule, false, &authData);
}

void CLIRewrite::Rewrite(
	SetupMsg & msg, /// Q.931 Setup message to be rewritten
	const SingleIpRule & ipRule,
	bool inbound,
	SetupAuthData * authData
	) const
{
	unsigned plan = Q931::ISDNPlan, type = Q931::UnknownType;
	unsigned presentation = (unsigned)-1, screening = (unsigned)-1;
	PString cli, dno, cno;

	// get ANI/CLI
	msg.GetQ931().GetCallingPartyNumber(cli, &plan, &type, &presentation, &screening, (unsigned)-1, (unsigned)-1);
	if (cli.IsEmpty() && msg.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_sourceAddress))
		cli = GetBestAliasAddressString(msg.GetUUIEBody().m_sourceAddress, true,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

	// get dialed number
	if (inbound) {
		msg.GetQ931().GetCalledPartyNumber(dno);
		if (dno.IsEmpty() && msg.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
			dno = GetBestAliasAddressString(msg.GetUUIEBody().m_destinationAddress, true,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
	} else if (authData != NULL)
		dno = authData->m_dialedNumber;

	// get destination number
	if (!inbound) {
		msg.GetQ931().GetCalledPartyNumber(cno);
		if (cno.IsEmpty() && msg.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
			cno = GetBestAliasAddressString(msg.GetUUIEBody().m_destinationAddress, true,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
	}

	// find ANI/CLI condition/prefix match
	PString newcli;
	RewriteRules::const_iterator rule = ipRule.second.begin();
	while (rule != ipRule.second.end()) {
		if (!rule->m_prefix.empty()) {
			int matchLen = 0;
			const char *number = NULL;
			if (rule->m_matchType == RewriteRule::MatchCallerNumber)
				number = cli;
			else if (rule->m_matchType == RewriteRule::MatchDialedNumber)
				number = dno;
			else if (!inbound && rule->m_matchType == RewriteRule::MatchDestinationNumber)
				number = cno;
			if (number != NULL) {
				matchLen = MatchPrefix(number, rule->m_prefix.c_str());
				if (matchLen > 0 && rule->m_rewriteType == RewriteRule::NumberToNumber
						&& strlen(number) != (unsigned)matchLen)
					matchLen = 0;
			}
			if (matchLen <= 0) {
				++rule;
				continue;
			}
		}
		if (rule->m_screeningType != RewriteRule::NoScreening)
			break;
		if (!rule->m_cli.empty()) {
			// get the new ANI/CLI
			newcli = rule->m_cli[rand() % rule->m_cli.size()].c_str();
			// if this is a number range, choose the new ANI/CLI from the range
			const PINDEX sepIndex = newcli.Find('-');
			if (sepIndex != P_MAX_INDEX) {
				PString lowStr(newcli.Left(sepIndex).Trim());
				PString highStr(newcli.Mid(sepIndex + 1).Trim());
				PUInt64 low = lowStr.AsUnsigned64();
				PUInt64 high = highStr.AsUnsigned64();
				PUInt64 diff = (low < high) ? (high - low) : (low - high);

				int numLeadingZeros1 = 0;
				while (numLeadingZeros1 < lowStr.GetLength()
						&& lowStr[numLeadingZeros1] == '0')
					++numLeadingZeros1;
						
				int numLeadingZeros2 = 0;
				while (numLeadingZeros2 < highStr.GetLength()
						&& highStr[numLeadingZeros2] == '0')
					++numLeadingZeros2;
				
				if (diff >= RAND_MAX)
					diff = PUInt64(rand());
				else
					diff = PUInt64(rand() % ((unsigned)diff + 1));
					
				diff = (low < high) ? (low + diff) : (high + diff);
				newcli = PString(diff);

				if (lowStr.GetLength() == highStr.GetLength() && (numLeadingZeros1 > 0 || numLeadingZeros2 > 0)) {
					while (newcli.GetLength() < highStr.GetLength())
						newcli = PString("0") + newcli;
				}

				PTRACE(5, "CLIRW\t" << (inbound ? "Inbound" : "Outbound")
					<< " CLI range rewrite target is '" << newcli << "' selected by the rule "
					<< rule->AsString()
					);
			}
			if (rule->m_rewriteType == RewriteRule::PrefixToPrefix
					&& rule->m_matchType == RewriteRule::MatchCallerNumber) {
				PString unused;
				newcli = RewriteString(cli, rule->m_prefix.c_str(), newcli, unused);
			}

			PTRACE(5, "CLIRW\t" << (inbound ? "Inbound" : "Outbound")
				<< " CLI rewrite to '" << newcli << "' by the rule " << rule->AsString()
				);
			break;
		}
		++rule;
	}

	if (rule == ipRule.second.end())
		return;

	bool isTerminal = false;	
	if (authData && authData->m_call) {
		endptr callee = authData->m_call->GetCalledParty();
		if (callee && callee->GetEndpointType().HasOptionalField(H225_EndpointType::e_terminal))
			isTerminal = true;
	}

	if (rule->m_manualCLIR == RewriteRule::RestrictPresentation) {
		presentation = 1;
		PTRACE(5, "CLIRW\tCLIR forced to 'restricted' by the " << (inbound ? "inbound" : "outbound")
			<< " rule " << rule->AsString()
			);
	} else if (rule->m_manualCLIR == RewriteRule::AllowPresentation) {
		presentation = 0;
		PTRACE(5, "CLIRW\tCLIR forced to 'allowed' by the " << (inbound ? "inbound" : "outbound")
			<< " rule " << rule->AsString()
			);
	}
	
	int screeningType = rule->m_screeningType;
	if (rule->m_CLIRPolicy == RewriteRule::AlwaysApplyCLIR
			|| (rule->m_CLIRPolicy == RewriteRule::ApplyCLIRForTerminals
				&& isTerminal)) {
		if (presentation == 1)
			screeningType = RewriteRule::AlwaysHide;
		else if (presentation == (unsigned)-1)
			if (msg.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_presentationIndicator)
					&& msg.GetUUIEBody().m_presentationIndicator.GetTag() == H225_PresentationIndicator::e_presentationRestricted)
			screeningType = RewriteRule::AlwaysHide;
	}
	
	if (screeningType == RewriteRule::AlwaysHide) {
		presentation = 1;
		screening = 3;
		newcli = "";
		plan = Q931::UnknownPlan;
		type = Q931::UnknownType;
		if (msg.GetQ931().HasIE((Q931::InformationElementCodes)0x6d)) // calling party subaddress IE
			msg.GetQ931().RemoveIE((Q931::InformationElementCodes)0x6d);
		if (msg.GetQ931().HasIE(Q931::DisplayIE))
			msg.GetQ931().RemoveIE(Q931::DisplayIE);
		PTRACE(5, "CLIRW\tCLI hidden by the " << (inbound ? "inbound" : "outbound")
			<< " rule " << rule->AsString()
			);
	} else if (screeningType == RewriteRule::HideFromTerminals) {
		presentation = 1;
		msg.GetQ931().GetCallingPartyNumber(newcli);
		if (isTerminal) {
			isTerminal = true;
			screening = 3;
			newcli = "";
			plan = Q931::UnknownPlan;
			type = Q931::UnknownType;
			if (msg.GetQ931().HasIE((Q931::InformationElementCodes)0x6d)) // calling party subaddress IE
				msg.GetQ931().RemoveIE((Q931::InformationElementCodes)0x6d);
			if (msg.GetQ931().HasIE(Q931::DisplayIE))
				msg.GetQ931().RemoveIE(Q931::DisplayIE);
			PTRACE(5, "CLIRW\tCLI hidden by the " << (inbound ? "inbound" : "outbound")
				<< " rule " << rule->AsString()
				);
		}
	} else if (newcli.IsEmpty())
		return;

	if (presentation != (unsigned)-1 && screening == (unsigned)-1)
		screening = 0;

	if (rule->m_rewriteType != RewriteRule::PrefixToH323Id
			&& rule->m_rewriteType != RewriteRule::NumberToH323Id) {
		msg.GetQ931().SetCallingPartyNumber(newcli, plan, type, presentation, screening);
		msg.SetChanged();
	}
	if (m_processSourceAddress && msg.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		H225_ArrayOf_AliasAddress & sourceAddress = msg.GetUUIEBody().m_sourceAddress;
		if (m_removeH323Id)
			sourceAddress.SetSize(1);
		else {
			PINDEX aliasIndex = 0;
			while (aliasIndex < sourceAddress.GetSize())
				if (sourceAddress[aliasIndex].GetTag() == H225_AliasAddress::e_h323_ID) {
					if (rule->m_rewriteType == RewriteRule::PrefixToH323Id
							|| rule->m_rewriteType == RewriteRule::NumberToH323Id) {
						sourceAddress.RemoveAt(aliasIndex);
					} else {
						aliasIndex++;
						continue;
					}
				} else if (sourceAddress[aliasIndex].GetTag() == H225_AliasAddress::e_url_ID
						|| sourceAddress[aliasIndex].GetTag() == H225_AliasAddress::e_email_ID) {
					aliasIndex++;
					continue;
				} else
					sourceAddress.RemoveAt(aliasIndex);
			sourceAddress.SetSize(sourceAddress.GetSize() + 1);
		}
		
		if (presentation != (unsigned)-1) {
			msg.GetUUIEBody().IncludeOptionalField(H225_Setup_UUIE::e_presentationIndicator);
			msg.GetUUIEBody().m_presentationIndicator.SetTag(presentation);
			msg.GetUUIEBody().IncludeOptionalField(H225_Setup_UUIE::e_screeningIndicator);
			msg.GetUUIEBody().m_screeningIndicator.SetValue(screening);
		}
		
		if (screeningType == RewriteRule::AlwaysHide) {
			msg.GetUUIEBody().IncludeOptionalField(H225_Setup_UUIE::e_presentationIndicator);
			msg.GetUUIEBody().m_presentationIndicator.SetTag(H225_PresentationIndicator::e_presentationRestricted);
			msg.GetUUIEBody().IncludeOptionalField(H225_Setup_UUIE::e_screeningIndicator);
			msg.GetUUIEBody().m_screeningIndicator.SetValue(H225_ScreeningIndicator::e_networkProvided);
			msg.GetUUIEBody().RemoveOptionalField(H225_Setup_UUIE::e_sourceAddress);
		} else if (screeningType == RewriteRule::HideFromTerminals) {
			msg.GetUUIEBody().IncludeOptionalField(H225_Setup_UUIE::e_presentationIndicator);
			msg.GetUUIEBody().m_presentationIndicator.SetTag(H225_PresentationIndicator::e_presentationRestricted);
			if (isTerminal && !newcli) {
				msg.GetUUIEBody().IncludeOptionalField(H225_Setup_UUIE::e_screeningIndicator);
				msg.GetUUIEBody().m_screeningIndicator.SetValue(H225_ScreeningIndicator::e_networkProvided);
				if (rule->m_rewriteType == RewriteRule::PrefixToH323Id
						|| rule->m_rewriteType == RewriteRule::NumberToH323Id)
					H323SetAliasAddress(newcli, sourceAddress[sourceAddress.GetSize() - 1], H225_AliasAddress::e_h323_ID);
				else
					H323SetAliasAddress(newcli, sourceAddress[sourceAddress.GetSize() - 1]);
			} else
				msg.GetUUIEBody().RemoveOptionalField(H225_Setup_UUIE::e_sourceAddress);
		} else {
			if (rule->m_rewriteType == RewriteRule::PrefixToH323Id
					|| rule->m_rewriteType == RewriteRule::NumberToH323Id)
				H323SetAliasAddress(newcli, sourceAddress[sourceAddress.GetSize() - 1], H225_AliasAddress::e_h323_ID);
			else
				H323SetAliasAddress(newcli, sourceAddress[sourceAddress.GetSize() - 1]);
		}
		msg.SetUUIEChanged();
	}
	
	if (!msg.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_sourceAddress)
			&& (rule->m_rewriteType == RewriteRule::PrefixToH323Id || rule->m_rewriteType == RewriteRule::NumberToH323Id)) {
		msg.GetUUIEBody().IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
		msg.GetUUIEBody().m_sourceAddress.SetSize(1);
		H323SetAliasAddress(newcli, msg.GetUUIEBody().m_sourceAddress[0], H225_AliasAddress::e_h323_ID);
		msg.SetUUIEChanged();
	}
}

CLIRewrite::SingleIpRule * CLIRewrite::RunQuery(const PString & query, const SetupMsg & msg)
{
#if HAS_DATABASE
	GkSQLResult::ResultRow resultRow;
	std::map<PString, PString> params;
	PIPSocket::Address addr;
	unsigned plan = Q931::ISDNPlan, type = Q931::UnknownType;
	unsigned presentation = (unsigned)-1, screening = (unsigned)-1;
	PString cli, called;

	msg.GetPeerAddr(addr);
	params["callerip"] = addr.AsString();
	msg.GetQ931().GetCalledPartyNumber(called);
	params["called"] = called;
	msg.GetQ931().GetCallingPartyNumber(cli, &plan, &type, &presentation, &screening, (unsigned)-1, (unsigned)-1);
	if (cli.IsEmpty()
		&& msg.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_sourceAddress)
		&& msg.GetUUIEBody().m_sourceAddress.GetSize() > 0) {
		cli = AsString(msg.GetUUIEBody().m_sourceAddress[0], false);
	}
	params["cli"] = cli;

	GkSQLResult * result = m_sqlConn->ExecuteQuery(query, params, -1);
	if (result == NULL) {
		PTRACE(2, CLIRewriteSQLSection << ": query failed - timeout or fatal error");
		SNMP_TRAP(4, SNMPError, Database, PString(CLIRewriteSQLSection) + " query failed");
		return NULL;
	}

	if (!result->IsValid()) {
		PTRACE(2, CLIRewriteSQLSection << ": query failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage());
		SNMP_TRAP(4, SNMPError, Database, PString(CLIRewriteSQLSection) + " query failed");
		delete result;
		return NULL;
	}
	
	if (result->GetNumRows() != 1)
		PTRACE(3, CLIRewriteSQLSection << ": query returned no rows");
	else if (result->GetNumFields() < 1)
		PTRACE(2, CLIRewriteSQLSection << ": bad query - no columns found in the result set");
	else if (!result->FetchRow(resultRow) || resultRow.empty()) {
		PTRACE(2, CLIRewriteSQLSection << ": query failed - could not fetch the result row");
		SNMP_TRAP(4, SNMPError, Database, PString(CLIRewriteSQLSection) + " query failed");
	} else {
		PString newCLI = resultRow[0].first;
		PTRACE(5, CLIRewriteSQLSection << "\tQuery result : " << newCLI);

		RewriteRules rules;
		RewriteRule rule;
		//if ((result->GetNumFields() == 1)
//		rule.m_manualCLIR = CLIRPassthrough;
//		rule.m_CLIRPolicy = IgnoreCLIR;
		rule.m_cli.push_back(newCLI);
		rules.push_back(rule);
		delete result;
		return new SingleIpRule(addr, rules);
	}
	delete result;
#endif // HAS_DATABASE
	return NULL;
}
