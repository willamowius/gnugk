/*
 * clirw.cxx
 *
 * Module for CLI/ANI manipulation.
 *
 * $Id$
 *
 * Copyright (c) 2005, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
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

namespace {
const char * const CLIRewriteSection = "RewriteCLI";
const char * const ProcessSourceAddress = "ProcessSourceAddress";
const char * const RemoveH323Id = "RemoveH323Id";
const char * const ReservedKeys[] = { ProcessSourceAddress, RemoveH323Id, NULL };
}

CLIRewrite::RewriteRule::RewriteRule() : m_matchType(MatchDialedNumber) {}

PString CLIRewrite::RewriteRule::AsString() const
{
	PString s;
	if (m_matchType == MatchDialedNumber)
		s += "dialed number: ";
	else if (m_matchType == MatchDestinationNumber)
		s += "destination number: ";
	else
		s += "caller number: ";

	s += m_prefix.empty() ? "any" : m_prefix.c_str();
	s += " => ";

	std::vector<std::string>::const_iterator cli = m_cli.begin();
	while (cli != m_cli.end()) {
		s += *cli++;
		if (cli != m_cli.end())
			s += ", ";
	}
	return s;
}

namespace {
struct RewriteRule_greater : public binary_function<CLIRewrite::RewriteRule, CLIRewrite::RewriteRule, bool> {

	bool operator()(const CLIRewrite::RewriteRule &e1, const CLIRewrite::RewriteRule &e2) const
	{
		int diff = e1.m_matchType - e2.m_matchType;
		if (diff != 0)
			return diff < 0;
		 diff = e1.m_prefix.length() - e2.m_prefix.length();
		if (diff != 0)
			return diff > 0;
		return e1.m_prefix.compare(e2.m_prefix) > 0;
	}
};

struct SingleIpRule_greater : public binary_function<CLIRewrite::SingleIpRule, CLIRewrite::SingleIpRule, bool> {

	bool operator()(const CLIRewrite::SingleIpRule &e1, const CLIRewrite::SingleIpRule &e2) const 
	{
		int diff;
		if (e1.first.IsAny()) {
			if (!e2.first.IsAny())
				return false;
		} else {
			if (e2.first.IsAny())
				return true;
			diff = e1.first.Compare(e2.first);
			if (diff != 0)
				return diff > 0;
		}
		return false;
	}
};

struct DoubleIpRule_greater : public binary_function<CLIRewrite::DoubleIpRule, CLIRewrite::DoubleIpRule, bool> {

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
	: m_processSourceAddress(true), m_removeH323Id(false)
{
	PConfig *cfg = GkConfig();

	unsigned inboundRules = 0, outboundRules = 0;
	SingleIpRules::iterator siprule = m_inboundRules.end();
	DoubleIpRules::iterator diprule = m_outboundRules.end();
	
	const PStringToString kv = cfg->GetAllKeyValues(CLIRewriteSection);
	for (PINDEX i = 0; i < kv.GetSize(); i++) {
		PString key = kv.GetKeyAt(i);

		unsigned j = 0;
		while (ReservedKeys[j] != NULL)
			if(key == ReservedKeys[j++])
				break;
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
				
				PStringArray dataTokens = data.Tokenise(", ", FALSE);
				if (dataTokens.GetSize() > 1) {
					data = dataTokens[1];
					if (!(dataTokens[0] == "*" || dataTokens[0] == "any"))
						addr = NetworkAddress(dataTokens[0]);
				}
				
				// check if the address is already on the list
				siprule = diprule->second.begin();
				while (siprule != diprule->second.end()) {
					if (siprule->first.m_address.IsAny() || addr.m_address.IsAny()) {
						if (siprule->first.m_address.IsAny() && addr.m_address.IsAny())
							break;
					} else if (siprule->first == addr)
						break;
					siprule++;
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

			// process CLI/ANI rewrite rule
			
			const PINDEX sepIndex = data.Find('=');
			if (sepIndex == P_MAX_INDEX) {
				PTRACE(1, "CLIRW\tInvalid CLI rewrite rule syntax: " << key << '=' 
					<< kv.GetDataAt(i)
					);
				if (newsiprule)
					if (inbound)
						m_inboundRules.erase(siprule);
					else
						diprule->second.erase(siprule);
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
			
			std::string prefix((const char*)(data.Mid(keyIndex, sepIndex - keyIndex)));
			if (prefix == "any")
				prefix.clear();
	
			// get RHS of the rewrite rule, multiple targets will be selected
			// in random order
			PStringArray clis = data.Mid(sepIndex + 1).Tokenise(", ", FALSE);
			if (clis.GetSize() < 1) {
				PTRACE(1, "CLIRW\tInvalid CLI rewrite rule syntax: " << key << '=' 
					<< kv.GetDataAt(i)
					);
				if (newsiprule)
					if (inbound)
						m_inboundRules.erase(siprule);
					else
						diprule->second.erase(siprule);
				if (newdiprule)
					m_outboundRules.erase(diprule);
				continue;
			}

			// check if the rule already exists			
			RewriteRules::iterator rule = rules->begin();
			while (rule != rules->end())
				if (rule->m_matchType == matchType && rule->m_prefix.compare(prefix) == 0)
					break;
				else
					++rule;
	
			if (rule == rules->end()) {
				rules->resize(rules->size() + 1);
				rule = rules->end() - 1;
			}
	
			rule->m_matchType = matchType;
			rule->m_prefix = prefix;		
			rule->m_cli.resize(clis.GetSize());
			for (PINDEX j = 0; j < clis.GetSize(); j++)
				rule->m_cli[j] = clis[j];

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
#if PTRACING
	if (PTrace::CanTrace(6)) {
		ostream &strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << "Inbound CLI rewrite rules:" << endl;
		for (unsigned i = 0; i < m_inboundRules.size(); i++) {
			strm << "\tsrc " << m_inboundRules[i].first << ":" << endl;
			for (unsigned j = 0; j < m_inboundRules[i].second.size(); j++)
				strm << "\t\t" << m_inboundRules[i].second[j].AsString() << endl;
		}
		PTrace::End(strm);
	}
#endif

	PTRACE(5, "CLIRW\t" << outboundRules << " outbound rules loaded");
#if PTRACING
	if (PTrace::CanTrace(6)) {
		ostream &strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << "Outbound CLI rewrite rules:" << endl;
		for (unsigned i = 0; i < m_outboundRules.size(); i++)
			for (unsigned j = 0; j < m_outboundRules[i].second.size(); j++) {
				strm << "\tsrc " << m_outboundRules[i].first << " dst " 
					<< m_outboundRules[i].second[j].first << ":" << endl;
				for (unsigned k = 0; k < m_outboundRules[i].second[j].second.size(); k++)
					strm << "\t\t" << m_outboundRules[i].second[j].second[k].AsString() << endl;
			}
		PTrace::End(strm);
	}
#endif

	m_processSourceAddress = Toolkit::AsBool(
		cfg->GetString(CLIRewriteSection, "ProcessSourceAddress", "1")
		);
	m_removeH323Id = Toolkit::AsBool(
		cfg->GetString(CLIRewriteSection, "RemoveH323Id", "1")
		);
}

void CLIRewrite::InRewrite(
	SetupMsg &msg /// Q.931 Setup message to be rewritten
	)
{
	PIPSocket::Address addr;
	msg.GetPeerAddr(addr);

	// find a rule that matches caller's IP	
	SingleIpRules::const_iterator i = m_inboundRules.begin();
	while (i != m_inboundRules.end())
		if (i->first.IsAny() || (addr << i->first))
			break;
		else
			i++;

	if (i == m_inboundRules.end())
		return;

	Rewrite(msg, *i, true, NULL);
}
		
void CLIRewrite::OutRewrite(
	SetupMsg &msg, /// Q.931 Setup message to be rewritten
	SetupAuthData &authData, /// additional data
	const PIPSocket::Address& destAddr /// destination address
	)
{
	PIPSocket::Address addr;
	msg.GetPeerAddr(addr);
	
	// find a rule that matches caller's IP	
	DoubleIpRules::const_iterator diprule = m_outboundRules.begin();
	while (diprule != m_outboundRules.end())
		if (diprule->first.IsAny() || (addr << diprule->first))
			break;
		else
			diprule++;

	if (diprule == m_outboundRules.end())
		return;

	// now find a rule that also matches callee's IP	
	SingleIpRules::const_iterator siprule = diprule->second.begin();
	while (siprule != diprule->second.end())
		if (siprule->first.IsAny() || (destAddr << siprule->first))
			break;
		else
			siprule++;

	if (siprule == diprule->second.end())
		return;

	Rewrite(msg, *siprule, false, &authData);
}

void CLIRewrite::Rewrite(
	SetupMsg &msg, /// Q.931 Setup message to be rewritten
	const SingleIpRule &ipRule,
	bool inbound,
	SetupAuthData *authData
	) const
{
	unsigned plan = Q931::ISDNPlan, type = Q931::UnknownType;	
	PString cli, dno, cno;

	// get ANI/CLI	
	msg.GetQ931().GetCallingPartyNumber(cli, &plan, &type);
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
		const RewriteRule &r = *rule++;
		if (!r.m_prefix.empty()) {
			if (r.m_matchType == RewriteRule::MatchCallerNumber) {
				if (cli.IsEmpty() || MatchPrefix(cli, r.m_prefix.c_str()) <= 0)
					continue;
			} else if (r.m_matchType == RewriteRule::MatchDialedNumber) {
				if (dno.IsEmpty() || MatchPrefix(dno, r.m_prefix.c_str()) <= 0)
					continue;
			} else if (!inbound && r.m_matchType == RewriteRule::MatchDestinationNumber) {
				if (cno.IsEmpty() || MatchPrefix(cno, r.m_prefix.c_str()) <= 0)
					continue;
			} else
				continue;
		}
		if (!r.m_cli.empty()) {
			// get the new ANI/CLI
			newcli = r.m_cli[rand() % r.m_cli.size()].c_str();
			PTRACE(5, "CLIRW\t" << (inbound ? "Inbound" : "Outbound")
				<< " CLI rewrite to '" << newcli << "' by the rule " << r.AsString()
				);
			// if this is a number range, choose the new ANI/CLI from the range
			const PINDEX sepIndex = newcli.Find('-');
			if (sepIndex != P_MAX_INDEX) {
				PUInt64 low = newcli.Left(sepIndex).AsUnsigned64();
				PUInt64 high = newcli.Mid(sepIndex + 1).AsUnsigned64();
				PUInt64 diff = (low < high) ? (high - low) : (low - high);
				
				if (diff >= RAND_MAX)
					diff = PUInt64(rand());
				else
					diff = PUInt64(rand() % ((unsigned)diff + 1));
					
				diff = (low < high) ? (low + diff) : (high + diff);
				newcli = PString(diff);
				PTRACE(5, "CLIRW\t" << (inbound ? "Inbound" : "Outbound")
					<< " CLI range rewrite to '" << newcli << "' by the rule "
					<< r.AsString()
					);
			}
			break;
		}
	}
	
	if (newcli.IsEmpty())
		return;

	msg.GetQ931().SetCallingPartyNumber(newcli, plan, type);
	msg.SetChanged();
	if (m_processSourceAddress && msg.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		H225_ArrayOf_AliasAddress &sourceAddress = msg.GetUUIEBody().m_sourceAddress;
		PINDEX aliasIndex = 0;
		if (m_removeH323Id)
			sourceAddress.SetSize(1);
		else {
			while (aliasIndex < sourceAddress.GetSize())
				if (sourceAddress[aliasIndex].GetTag() == H225_AliasAddress::e_h323_ID
						|| sourceAddress[aliasIndex].GetTag() == H225_AliasAddress::e_url_ID
						|| sourceAddress[aliasIndex].GetTag() == H225_AliasAddress::e_email_ID) {
					aliasIndex++;
					continue;
				} else
					sourceAddress.RemoveAt(aliasIndex);
			sourceAddress.SetSize(sourceAddress.GetSize() + 1);
		}
		H323SetAliasAddress(newcli, sourceAddress[sourceAddress.GetSize() - 1]);
		msg.SetUUIEChanged();
	}
}
