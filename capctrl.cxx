/*
 * capctrl.cxx
 *
 * Module for accoutning per IP/H.323 ID/CLI/prefix inbound call volume
 *
 * $Id$
 *
 * Copyright (c) 2006, Michal Zygmuntowicz
 * Copyright (c) 2008-2023, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"
#include <ptlib.h>
#include <ptlib/ipsock.h>
#include <h225.h>
#include <h323pdu.h>
#include "h323util.h"
#include "RasTbl.h"
#include "RasPDU.h"
#include "sigmsg.h"
#include "gkacct.h"
#include "gkauth.h"
#include "capctrl.h"

namespace {
// greater operators for sorting route lists

#if (__cplusplus >= 201703L)
struct IpRule_greater {
	typedef CapacityControl::IpCallVolume first_argument_type;
	typedef CapacityControl::IpCallVolume second_argument_type;
	typedef bool result_type;
#else
struct IpRule_greater : public std::binary_function<CapacityControl::IpCallVolume, CapacityControl::IpCallVolume, bool> {
#endif

	bool operator()(const CapacityControl::IpCallVolume &e1, const CapacityControl::IpCallVolume &e2) const
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

#if (__cplusplus >= 201703L)
struct H323IdRule_greater {
	typedef CapacityControl::H323IdCallVolume first_argument_type;
	typedef CapacityControl::H323IdCallVolume second_argument_type;
	typedef bool result_type;
#else
struct H323IdRule_greater : public std::binary_function<CapacityControl::H323IdCallVolume, CapacityControl::H323IdCallVolume, bool> {
#endif

	bool operator()(const CapacityControl::H323IdCallVolume & e1, const CapacityControl::H323IdCallVolume & e2) const
	{
		return H323GetAliasAddressString(e1.first) > H323GetAliasAddressString(e2.first);
	}
};

#if (__cplusplus >= 201703L)
struct CLIRule_greater {
	typedef CapacityControl::CLICallVolume first_argument_type;
	typedef CapacityControl::CLICallVolume second_argument_type;
	typedef bool result_type;
#else
struct CLIRule_greater : public std::binary_function<CapacityControl::CLICallVolume, CapacityControl::CLICallVolume, bool> {
#endif

	bool operator()(const CapacityControl::CLICallVolume & e1, const CapacityControl::CLICallVolume & e2) const
	{
		return e1.first.compare(e2.first) > 0;
	}
};

} // end of anonymous namespace

CapacityControl::InboundCallVolume::InboundCallVolume()
	: m_maxVolume(0)
{
}

CapacityControl::InboundCallVolume::~InboundCallVolume()
{
}

PString CapacityControl::InboundCallVolume::AsString() const
{
	return PString("pfx: ") + (m_prefix.empty() ? "*" : m_prefix.c_str())
		+ ", vol (cur/max): " + PString(m_calls.size()) + "/" + PString(m_maxVolume);
}

bool CapacityControl::InboundCallVolume::operator==(const InboundCallVolume & obj) const
{
	return m_prefix == obj.m_prefix;
}

bool CapacityControl::InboundIPCallVolume::operator==(const InboundIPCallVolume & obj) const
{
	return m_sourceAddress == obj.m_sourceAddress && ((InboundCallVolume &)*this) == ((InboundCallVolume &)obj);
}

bool CapacityControl::InboundH323IdCallVolume::operator==(const InboundH323IdCallVolume &obj) const
{
	return m_sourceH323Id == obj.m_sourceH323Id && ((InboundCallVolume &)*this) == ((InboundCallVolume &)obj);
}

bool CapacityControl::InboundCLICallVolume::operator==(const InboundCLICallVolume &obj) const
{
	return m_sourceCLI == obj.m_sourceCLI && ((InboundCallVolume &)*this) == ((InboundCallVolume &)obj);
}

CapacityControl::CapacityControl(
	) : Singleton<CapacityControl>("CapacityControl")
{
	LoadConfig();
}

void CapacityControl::LoadConfig()
{
	IpCallVolumes ipCallVolumes;
	H323IdCallVolumes h323IdCallVolumes;
	CLICallVolumes cliCallVolumes;

	PConfig* cfg = GkConfig();
	const PString cfgSec("CapacityControl");

	unsigned ipRules = 0, h323IdRules = 0, cliRules = 0;

	const PStringToString kv = cfg->GetAllKeyValues(cfgSec);
	for (PINDEX i = 0; i < kv.GetSize(); ++i) {
		PString key = kv.GetKeyAt(i);

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
			InboundCallVolume *rule = NULL;
			bool newIpRule = false, newH323IdRule = false, newCLIRule = false;

			// check the rule type (ip/h323id/cli)
			if (key.Find("ip:") == 0) {
				const PString ip = key.Mid(3).Trim();

				NetworkAddress addr;
				if (!(ip == "*" || ip == "any"))
					addr = NetworkAddress(ip);

				ipCallVolumes.push_back(IpCallVolume(addr, InboundIPCallVolume(addr)));
				newIpRule = true;

				rule = &(ipCallVolumes.back().second);
			} else if (key.Find("h323id:") == 0) {
				H225_AliasAddress alias;
				const PString h323id = key.Mid(7).Trim();
				H323SetAliasAddress(h323id, alias, H225_AliasAddress::e_h323_ID);

				h323IdCallVolumes.push_back(H323IdCallVolume(alias, InboundH323IdCallVolume(alias)));
				newH323IdRule = true;

				rule = &(h323IdCallVolumes.back().second);
			} else if (key.Find("cli:") == 0) {
				const std::string cli((const char*)(key.Mid(4).Trim()));

				cliCallVolumes.push_back(CLICallVolume(cli, InboundCLICallVolume(cli)));
				newCLIRule = true;

				rule = &(cliCallVolumes.back().second);
			} else {
				PTRACE(1, "CAPCTRL\tUknown CapacityControl rule: " << key << '=' << kv.GetDataAt(i));
				continue;
			}

			PStringArray tokens(data.Tokenise(" \t", FALSE));
			if (tokens.GetSize() < 1) {
				PTRACE(1, "CAPCTRL\tInvalid CapacityControl rule syntax: " << key << '=' << kv.GetDataAt(i));
				if (newIpRule)
					ipCallVolumes.pop_back();
				else if (newH323IdRule)
					h323IdCallVolumes.pop_back();
				else if (newCLIRule)
					cliCallVolumes.pop_back();
				continue;
			}

			unsigned tno = 0;
			if (tokens.GetSize() >= 2)
				rule->m_prefix = string((const char*)(tokens[tno++]));
			rule->m_maxVolume = tokens[tno++].AsUnsigned();

			if (newIpRule)
				++ipRules;
			else if (newH323IdRule)
				++h323IdRules;
			else if (newCLIRule)
				++cliRules;
		} /* for (d) */
	} /* for (i) */

	// sort rules by IP network mask length
	std::stable_sort(ipCallVolumes.begin(), ipCallVolumes.end(), IpRule_greater());
	std::stable_sort(h323IdCallVolumes.begin(), h323IdCallVolumes.end(), H323IdRule_greater());
	std::stable_sort(cliCallVolumes.begin(), cliCallVolumes.end(), CLIRule_greater());

	PWaitAndSignal lock(m_updateMutex);

	// update route entries that have not changed
	{
		IpCallVolumes::const_iterator rule = m_ipCallVolumes.begin();
		while (rule != m_ipCallVolumes.end()) {
			IpCallVolumes::iterator matchingRule = find(ipCallVolumes.begin(), ipCallVolumes.end(), *rule);
			if (matchingRule != ipCallVolumes.end() && matchingRule->second == rule->second) {
				matchingRule->second.m_calls = rule->second.m_calls;
			}
			++rule;
		}
	}

	{
		H323IdCallVolumes::const_iterator rule = m_h323IdCallVolumes.begin();
		while (rule != m_h323IdCallVolumes.end()) {
			H323IdCallVolumes::iterator matchingRule = find(h323IdCallVolumes.begin(), h323IdCallVolumes.end(), *rule);
			if (matchingRule != h323IdCallVolumes.end() && matchingRule->second == rule->second) {
				matchingRule->second.m_calls = rule->second.m_calls;
			}
			++rule;
		}
	}

	{
		CLICallVolumes::const_iterator rule = m_cliCallVolumes.begin();
		while (rule != m_cliCallVolumes.end()) {
			CLICallVolumes::iterator matchingRule = find(cliCallVolumes.begin(), cliCallVolumes.end(), *rule);
			if (matchingRule != cliCallVolumes.end() && matchingRule->second == rule->second) {
				matchingRule->second.m_calls = rule->second.m_calls;
			}
			++rule;
		}
	}

	m_ipCallVolumes.clear();
	m_h323IdCallVolumes.clear();
	m_cliCallVolumes.clear();

	m_ipCallVolumes = ipCallVolumes;
	m_h323IdCallVolumes = h323IdCallVolumes;
	m_cliCallVolumes = cliCallVolumes;

	PTRACE(5, "CAPCTRL\t" << ipRules << " IP rules loaded");
	if (PTrace::CanTrace(6)) {
		ostream & strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << "Per IP call volume rules:" << endl;
		for (unsigned i = 0; i < m_ipCallVolumes.size(); ++i) {
			strm << "\tsrc " << m_ipCallVolumes[i].first.AsString() << ":" << endl;
			strm << "\t\t" << m_ipCallVolumes[i].second.AsString() << endl;
		}
		PTrace::End(strm);
	}

	PTRACE(5, "CAPCTRL\t" << h323IdRules << " H.323 ID rules loaded");
	if (PTrace::CanTrace(6)) {
		ostream & strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << "Per H.323 ID call volume rules:" << endl;
		for (unsigned i = 0; i < m_h323IdCallVolumes.size(); i++) {
			strm << "\tsrc " << H323GetAliasAddressString(m_h323IdCallVolumes[i].first) << ":" << endl;
			strm << "\t\t" << m_h323IdCallVolumes[i].second.AsString() << endl;
		}
		PTrace::End(strm);
	}

	PTRACE(5, "CAPCTRL\t" << cliRules << " CLI rules loaded");
	if (PTrace::CanTrace(6)) {
		ostream & strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << "Per CLI call volume rules:" << endl;
		for (unsigned i = 0; i < m_cliCallVolumes.size(); i++) {
			strm << "\tsrc " << m_cliCallVolumes[i].first << ":" << endl;
			strm << "\t\t" << m_cliCallVolumes[i].second.AsString() << endl;
		}
		PTrace::End(strm);
	}
}

PString CapacityControl::PrintRules()
{
//	std::stringstream strm; // VS2005 version leaks memory!!
	PStringStream strm;

	strm << "Per IP call volume rules:" << endl;
	for (unsigned i = 0; i < m_ipCallVolumes.size(); ++i) {
		strm << "  src " << m_ipCallVolumes[i].first.AsString() << ":" << endl;
		strm << "    " << m_ipCallVolumes[i].second.AsString() << endl;
	}

	strm << "Per H.323 ID call volume rules:" << endl;
	for (unsigned i = 0; i < m_h323IdCallVolumes.size(); i++) {
		strm << "  src " << H323GetAliasAddressString(m_h323IdCallVolumes[i].first) << ":" << endl;
		strm << "    " << m_h323IdCallVolumes[i].second.AsString() << endl;
	}

	strm << "Per CLI call volume rules:" << endl;
	for (unsigned i = 0; i < m_cliCallVolumes.size(); i++) {
		strm << "  src " << m_cliCallVolumes[i].first << ":" << endl;
		strm << "    " << m_cliCallVolumes[i].second.AsString() << endl;
	}

	return strm;
}

CapacityControl::IpCallVolumes::iterator CapacityControl::FindByIp(
	const NetworkAddress & srcIp,
	const PString & calledStationId)
{
	unsigned netmaskLen = 0;
	PINDEX matchLen = P_MAX_INDEX;

	const IpCallVolumes::iterator ipEnd = m_ipCallVolumes.end();
	IpCallVolumes::iterator bestIpMatch = ipEnd, i = m_ipCallVolumes.begin();
	while (i != ipEnd) {
		if (bestIpMatch != ipEnd && i->first.GetNetmaskLen() < netmaskLen)
			break;
		if (i->first.IsAny() || srcIp << i->first) {
			PINDEX offset, len;
			if (i->second.m_prefix.empty())
				len = 0;
			else if (!calledStationId.FindRegEx(
					PRegularExpression(i->second.m_prefix.c_str(), PRegularExpression::Extended), offset, len))
				len = P_MAX_INDEX;
			if (len != P_MAX_INDEX && (matchLen == P_MAX_INDEX || len > matchLen)) {
				bestIpMatch = i;
				netmaskLen = i->first.GetNetmaskLen();
				matchLen = len;
			}
		}
		++i;
	}

	return bestIpMatch;
}

CapacityControl::H323IdCallVolumes::iterator CapacityControl::FindByH323Id(
	const PString & h323Id,
	const PString & calledStationId)
{
	PINDEX matchLen = P_MAX_INDEX;
	const H323IdCallVolumes::iterator h323IdEnd = m_h323IdCallVolumes.end();
	H323IdCallVolumes::iterator bestH323IdMatch = h323IdEnd, i = m_h323IdCallVolumes.begin();
	while (i != h323IdEnd) {
		if (h323Id.IsEmpty())
			break;
		PString alias = H323GetAliasAddressString(i->first);
		if (bestH323IdMatch != h323IdEnd && alias != h323Id)
			break;
		if (alias == h323Id) {
			PINDEX offset, len;
			if (i->second.m_prefix.empty())
				len = 0;
			else if (!calledStationId.FindRegEx(PRegularExpression(i->second.m_prefix.c_str(), PRegularExpression::Extended), offset, len))
				len = P_MAX_INDEX;
			if (len != P_MAX_INDEX && (matchLen == P_MAX_INDEX || len > matchLen)) {
				bestH323IdMatch = i;
				matchLen = len;
			}
		}
		++i;
	}

	return bestH323IdMatch;
}

CapacityControl::CLICallVolumes::iterator CapacityControl::FindByCli(
	const std::string & cli,
	const PString & calledStationId)
{
	PINDEX matchLen = P_MAX_INDEX;
	const CLICallVolumes::iterator cliEnd = m_cliCallVolumes.end();
	CLICallVolumes::iterator bestCliMatch = cliEnd, i = m_cliCallVolumes.begin();
	while (i != cliEnd) {
		if (cli.empty())
			break;
		if (bestCliMatch != cliEnd && i->first != cli)
			break;
		if (i->first == cli) {
			PINDEX offset, len;
			if (i->second.m_prefix.empty())
				len = 0;
			else if (!calledStationId.FindRegEx(PRegularExpression(i->second.m_prefix.c_str(), PRegularExpression::Extended), offset, len))
				len = P_MAX_INDEX;
			if (len != P_MAX_INDEX && (matchLen == P_MAX_INDEX || len > matchLen)) {
				bestCliMatch = i;
				matchLen = len;
			}
		}
		++i;
	}

	return bestCliMatch;
}

void CapacityControl::LogCall(
	const NetworkAddress &srcIp,
	const PString &srcAlias,
	const std::string &srcCli,
	const PString &calledStationId,
	PINDEX callNumber,
	bool callStart
	)
{
	if (callStart) {
		if (callNumber < 1) {
			PTRACE(1, "CAPCTRL\tInvalid call number used (" << callNumber << ")");
		}

		// find longest matching rule by ip/h323id/cli
		IpCallVolumes::iterator bestIpMatch = FindByIp(srcIp, calledStationId);
		if (bestIpMatch != m_ipCallVolumes.end()) {
			PTRACE(5, "CAPCTRL\tCall #" << callNumber
				<< " to " << calledStationId << " matched IP rule " << bestIpMatch->first.AsString()
				<< "\t" << bestIpMatch->second.AsString());
			PWaitAndSignal lock(m_updateMutex);
			bestIpMatch->second.m_calls.insert(callNumber);
			return;
		}

		H323IdCallVolumes::iterator bestH323IdMatch = FindByH323Id(srcAlias, calledStationId);
		if (bestH323IdMatch != m_h323IdCallVolumes.end()) {
			PTRACE(5, "CAPCTRL\tCall #" << callNumber
				<< " to " << calledStationId << " matched H323.ID rule " << H323GetAliasAddressString(bestH323IdMatch->first)
				<< "\t" << bestH323IdMatch->second.AsString());
			PWaitAndSignal lock(m_updateMutex);
			bestH323IdMatch->second.m_calls.insert(callNumber);
			return;
		}

		CLICallVolumes::iterator bestCliMatch = FindByCli(srcCli, calledStationId);
		if (bestCliMatch != m_cliCallVolumes.end()) {
			PTRACE(5, "CAPCTRL\tCall #" << callNumber
				<< " to " << calledStationId << " matched CLI rule " << bestCliMatch->first
				<< "\t" << bestCliMatch->second.AsString());
			PWaitAndSignal lock(m_updateMutex);
			bestCliMatch->second.m_calls.insert(callNumber);
			return;
		}
	} else { // call stop
		PWaitAndSignal lock(m_updateMutex);

		// find the right counter by GnuGk call number
		IpCallVolumes::iterator bestIpMatch = m_ipCallVolumes.begin();
		while (bestIpMatch != m_ipCallVolumes.end()) {
			std::set<PINDEX>::iterator i = find(bestIpMatch->second.m_calls.begin(), bestIpMatch->second.m_calls.end(), callNumber);
			if (i != bestIpMatch->second.m_calls.end()) {
				bestIpMatch->second.m_calls.erase(i);
				return;
			}
			++bestIpMatch;
		}

		H323IdCallVolumes::iterator bestH323IdMatch = m_h323IdCallVolumes.begin();
		while (bestH323IdMatch != m_h323IdCallVolumes.end()) {
			std::set<PINDEX>::iterator i = find(bestH323IdMatch->second.m_calls.begin(), bestH323IdMatch->second.m_calls.end(), callNumber);
			if (i != bestH323IdMatch->second.m_calls.end()) {
				bestH323IdMatch->second.m_calls.erase(i);
				return;
			}
			++bestH323IdMatch;
		}

		CLICallVolumes::iterator bestCliMatch = m_cliCallVolumes.begin();
		while (bestCliMatch != m_cliCallVolumes.end()) {
			std::set<PINDEX>::iterator i = find(bestCliMatch->second.m_calls.begin(), bestCliMatch->second.m_calls.end(), callNumber);
			if (i != bestCliMatch->second.m_calls.end()) {
				bestCliMatch->second.m_calls.erase(i);
				return;
			}
			++bestCliMatch;
		}
	}
}

bool CapacityControl::CheckCall(const NetworkAddress & srcIp, const PString & srcAlias,
                                const std::string & srcCli, const PString & calledStationId)
{
	IpCallVolumes::iterator bestIpMatch = FindByIp(srcIp, calledStationId);
	if (bestIpMatch != m_ipCallVolumes.end()) {
		PTRACE(5, "CAPCTRL\tCall from IP " << srcIp.AsString()
			<< " to " << calledStationId << " matched IP rule " << bestIpMatch->first.AsString()
			<< "\t" << bestIpMatch->second.AsString());
		PWaitAndSignal lock(m_updateMutex);
		return bestIpMatch->second.m_calls.size() < bestIpMatch->second.m_maxVolume;
	}

	H323IdCallVolumes::iterator bestH323IdMatch = FindByH323Id(srcAlias, calledStationId);
	if (bestH323IdMatch != m_h323IdCallVolumes.end()) {
		PTRACE(5, "CAPCTRL\tCall to " << calledStationId << " matched H323.ID rule "
			<< H323GetAliasAddressString(bestH323IdMatch->first) << "\t" << bestH323IdMatch->second.AsString());
		PWaitAndSignal lock(m_updateMutex);
		return bestH323IdMatch->second.m_calls.size() < bestH323IdMatch->second.m_maxVolume;
	}

	CLICallVolumes::iterator bestCliMatch = FindByCli(srcCli, calledStationId);
	if (bestCliMatch != m_cliCallVolumes.end()) {
		PTRACE(5, "CAPCTRL\tCall to " << calledStationId << " matched CLI rule "
			<< bestCliMatch->first << "\t" << bestCliMatch->second.AsString());
		PWaitAndSignal lock(m_updateMutex);
		return bestCliMatch->second.m_calls.size() < bestCliMatch->second.m_maxVolume;
	}

	return true;
}

namespace {

class CapCtrlAcct : public GkAcctLogger
{
public:
	enum Constants {
		/// events recognized by this module
		CapCtrlAcctEvents = AcctStart | AcctStop
	};

	/// Create a logger that updates information about inbound traffic
	CapCtrlAcct(
		/// name from Gatekeeper::Acct section
		const char* moduleName
		);

	/** Log accounting event.

		@return
		Status of this logging operation (see #Status enum#)
	*/
	virtual Status Log(
		AcctEvent evt, /// accounting event to log
		const callptr & call /// additional data for the event
		);

private:
	/* No copy constructor allowed */
	CapCtrlAcct(const CapCtrlAcct &);
	/* No operator= allowed */
	CapCtrlAcct& operator=(const CapCtrlAcct &);

private:
	CapacityControl * m_capacityControl;
};

} // end of anonymous namespace

CapCtrlAcct::CapCtrlAcct(
	const char* moduleName
	) : GkAcctLogger(moduleName), m_capacityControl(CapacityControl::Instance())
{
	SetSupportedEvents(CapCtrlAcctEvents);
}

GkAcctLogger::Status CapCtrlAcct::Log(GkAcctLogger::AcctEvent evt, const callptr & call)
{
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;
	if (!call) {
		PTRACE(1, "GKACCT\t" << GetName() << " - missing call info for event " << evt);
		return Fail;
	}

	PIPSocket::Address addr;
	WORD port;
	call->GetSrcSignalAddr(addr, port);

	PString h323Id = GetBestAliasAddressString(call->GetSourceAddress(), true, AliasAddressTagMask(H225_AliasAddress::e_h323_ID));
	if (h323Id.IsEmpty() && call->GetCallingParty()) {
		h323Id = GetBestAliasAddressString(call->GetCallingParty()->GetAliases(), true, AliasAddressTagMask(H225_AliasAddress::e_h323_ID));
    }

	std::string cli((const char*)(GetCallingStationId(call)));

	m_capacityControl->LogCall(addr, h323Id, cli, GetCalledStationId(call), call->GetCallNumber(), evt == AcctStart);

	return Ok;
}

namespace {

/// Authenticator module for controlling inbound traffic
/// To be used together with CapacityControl accounting module
class CapCtrlAuth : public GkAuthenticator
{
public:
	enum SupportedChecks {
		CapCtrlAuthMiscChecks = e_Setup | e_SetupUnreg
	};

	/// build authenticator reading settings from the config
	CapCtrlAuth(
		/// name for this authenticator and for the config section to read settings from
		const char* authName,
		/// RAS check events supported by this module
		unsigned supportedRasChecks = 0,
		/// Misc check events supported by this module
		unsigned supportedMiscChecks = CapCtrlAuthMiscChecks
		);
	virtual ~CapCtrlAuth() { }

	/** Authenticate using data from Q.931 Setup message.

		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// Q.931/H.225 Setup message to be authenticated
		SetupMsg & setup,
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData & authData
		);

private:
	CapCtrlAuth();
	CapCtrlAuth(const CapCtrlAuth &);
	CapCtrlAuth & operator=(const CapCtrlAuth &);

private:
	CapacityControl * m_capacityControl;
};

} // end of anonymous namespace

CapCtrlAuth::CapCtrlAuth(
	const char* authName,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks
	)
	:
	GkAuthenticator(authName, supportedRasChecks, supportedMiscChecks),
	m_capacityControl(CapacityControl::Instance())
{
}

int CapCtrlAuth::Check(
	/// Q.931/H.225 Setup message to be authenticated
	SetupMsg & setup,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData & authData
	)
{
	PString h323Id;
	PIPSocket::Address addr;
	setup.GetPeerAddr(addr);

	if (authData.m_call) {
		h323Id = GetBestAliasAddressString(authData.m_call->GetSourceAddress(), true, AliasAddressTagMask(H225_AliasAddress::e_h323_ID));
		if (h323Id.IsEmpty() && authData.m_call->GetCallingParty())
			h323Id = GetBestAliasAddressString(authData.m_call->GetCallingParty()->GetAliases(), true,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID));
	} else if (setup.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		h323Id = GetBestAliasAddressString(setup.GetUUIEBody().m_sourceAddress, true, AliasAddressTagMask(H225_AliasAddress::e_h323_ID));
	}

	if (!m_capacityControl->CheckCall(addr, h323Id, (const char*)(authData.m_callingStationId), authData.m_calledStationId)) {
		authData.m_rejectCause = Q931::NoCircuitChannelAvailable;
		return e_fail;
	} else
		return e_ok;
}

namespace {
GkAcctLoggerCreator<CapCtrlAcct> CapCtrlAcctLoggerCreator("CapacityControl");
GkAuthCreator<CapCtrlAuth> CapCtrlAuthCreator("CapacityControl");
}
