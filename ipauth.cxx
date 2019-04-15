/*
 * ipauth.cxx
 *
 * IP based authentication modules
 *
 * @(#) $Id$
 *
 * Copyright (c) 2005, Michal Zygmuntowicz
 * Copyright (c) 2006-2016, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include <ptlib.h>
#include <h225.h>

#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "RasPDU.h"
#include "RasTbl.h"
#include "sigmsg.h"
#include "ipauth.h"

class IPAuthPrefix {
public:
	IPAuthPrefix();
	IPAuthPrefix(bool a, const PString &, bool tls = false);
	IPAuthPrefix(const IPAuthPrefix &);

	void AddPrefix(const PString &);
	void SortPrefix(bool greater = true);
	int PrefixMatch(const PString &) const;
	std::string PrintOn() const;
	std::string PrintPrefix() const;

	IPAuthPrefix& operator=(const IPAuthPrefix&);
	IPAuthPrefix& operator=(bool);

	typedef std::vector<std::string>::iterator prefix_iterator;
	typedef std::vector<std::string>::const_iterator const_prefix_iterator;

	bool auth;
	bool onlyTLS;

protected:
	std::vector<std::string> Prefixs;
};

/// Text file based IP authentication
class FileIPAuth : public IPAuthBase {
public:
	typedef std::pair<NetworkAddress, IPAuthPrefix> IPAuthEntry;

	/// Create text file based authenticator
	FileIPAuth(
		/// authenticator name from Gatekeeper::Auth section
		const char * authName
		);

	/// Destroy the authenticator
	virtual ~FileIPAuth();

protected:
	/// Overridden from IPAuthBase
	virtual int CheckAddress(
		const PIPSocket::Address & addr, /// IP address the request comes from
		WORD port, /// port number the request comes from
		const PString & number,
		bool overTLS);

private:
	FileIPAuth();
	/* No copy constructor allowed */
	FileIPAuth(const FileIPAuth &);
	/* No operator= allowed */
	FileIPAuth & operator=(const FileIPAuth &);

private:
	typedef std::vector<IPAuthEntry> IPAuthList;

	IPAuthList m_authList;
};


IPAuthBase::IPAuthBase(
	/// authenticator name from Gatekeeper::Auth section
	const char * authName,
	/// bitmask with supported RAS checks
	unsigned supportedRasChecks,
	/// bitmask with supported non-RAS checks
	unsigned supportedMiscChecks
	) : GkAuthenticator(authName, supportedRasChecks, supportedMiscChecks)
{
}

IPAuthBase::~IPAuthBase()
{
}

int IPAuthBase::Check(
	/// RRQ RAS message to be authenticated
	RasPDU<H225_RegistrationRequest> & rrqPdu,
	/// authorization data (reject reason, ...)
	RRQAuthData & /*authData*/)
{
	return CheckAddress(rrqPdu->m_peerAddr, rrqPdu->m_peerPort, PString::Empty());
}

int IPAuthBase::Check(
	/// ARQ to be authenticated/authorized
	RasPDU<H225_AdmissionRequest> & arqPdu,
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData & /*authData*/)
{
    H225_AdmissionRequest & arq = arqPdu;
	PString number;
	if (arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)
        && arq.m_destinationInfo.GetSize() > 0) {
        number = AsString(arq.m_destinationInfo[0], false);
    }

	return CheckAddress(arqPdu->m_peerAddr, arqPdu->m_peerPort, number);
}

int IPAuthBase::Check(RasPDU<H225_GatekeeperRequest> & pdu, unsigned & /* rejectReason */)
{
	return CheckAddress(pdu->m_peerAddr, pdu->m_peerPort, PString::Empty());
}

int IPAuthBase::Check(RasPDU<H225_UnregistrationRequest> & pdu, unsigned & /* rejectReason */)
{
	return CheckAddress(pdu->m_peerAddr, pdu->m_peerPort, PString::Empty());
}

int IPAuthBase::Check(RasPDU<H225_BandwidthRequest> & pdu, unsigned & /* rejectReason */)
{
	return CheckAddress(pdu->m_peerAddr, pdu->m_peerPort, PString::Empty());
}

int IPAuthBase::Check(RasPDU<H225_DisengageRequest> & pdu, unsigned & /*rejectReason*/)
{
	return CheckAddress(pdu->m_peerAddr, pdu->m_peerPort, PString::Empty());
}

int IPAuthBase::Check(RasPDU<H225_LocationRequest> & pdu, unsigned & /*rejectReason*/)
{
	return CheckAddress(pdu->m_peerAddr, pdu->m_peerPort, PString::Empty());
}

int IPAuthBase::Check(RasPDU<H225_InfoRequest> & pdu, unsigned & /* rejectReason */)
{
	return CheckAddress(pdu->m_peerAddr, pdu->m_peerPort, PString::Empty());
}

int IPAuthBase::Check(RasPDU<H225_ResourcesAvailableIndicate> & pdu, unsigned & /* rejectReason */)
{
	return CheckAddress(pdu->m_peerAddr, pdu->m_peerPort, PString::Empty());
}

int IPAuthBase::Check(
	/// Q.931/H.225 Setup message to be authenticated
	SetupMsg & setup,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData & authData)
{
	PIPSocket::Address addr;
	WORD port = 0;
	setup.GetPeerAddr(addr, port);
	PString number;
	setup.GetQ931().GetCalledPartyNumber(number);

	return CheckAddress(addr, port, number, authData.m_overTLS);
}

int IPAuthBase::Check(
	/// Q.931 message to be authenticated/authorized
	Q931 & msg,
	/// authorization data
	Q931AuthData & authData)
{
	return CheckAddress(authData.m_peerAddr, authData.m_peerPort, PString::Empty());
}


/////////////
// FileIPAuth
/////////////

namespace {
const char *FileIPAuthSecName = "FileIPAuth";

struct IPAuthEntry_greater : public binary_function<FileIPAuth::IPAuthEntry, FileIPAuth::IPAuthEntry, bool> {

	bool operator()(
		const FileIPAuth::IPAuthEntry & a,
		const FileIPAuth::IPAuthEntry & b
		) const
	{
		const int diff = a.first.Compare(b.first);
		if (diff == 0)
			return !a.second.auth;
		return diff > 0;
	}
};

} /* anonymous namespace */

FileIPAuth::FileIPAuth(
	/// authenticator name from Gatekeeper::Auth section
	const char * authName
	) : IPAuthBase(authName)
{
	bool dynamicCfg = false;
	PConfig * cfg = GkConfig();

	if (cfg->HasKey(FileIPAuthSecName, "include")) {
		const PFilePath fp(cfg->GetString(FileIPAuthSecName, "include", ""));
		if (!PFile::Exists(fp)) {
			PTRACE(1, GetName() << "\tCould not read the include file '"
				<< fp << "': the file does not exist");
			return;
		}
		cfg = new PConfig(fp, authName);
		dynamicCfg = true;
	}

	PStringToString kv = cfg->GetAllKeyValues(FileIPAuthSecName);

	m_authList.reserve(kv.GetSize());

	for (PINDEX i = 0; i < kv.GetSize(); i++) {
		const PString & key = kv.GetKeyAt(i);
		int position = 0;
		if (key[0] == '#')
			continue;

		IPAuthEntry entry;

		entry.first = (key == "*" || key == "any") ? NetworkAddress() : NetworkAddress(key);

		PString auth(kv.GetDataAt(i));
		PString prefix(".");

		if ((position = auth.Find(';', position)) != P_MAX_INDEX) {
			position++;
			prefix = auth(position, auth.GetLength());
			position--;
			auth.Delete(position, auth.GetLength() - position);
		}

		entry.second.auth = PCaselessString("allow") == auth;
		entry.second.AddPrefix(prefix);
		entry.second.SortPrefix(false);
		if (PCaselessString("onlyTLS") == auth) {
			entry.second.auth = true;
			entry.second.onlyTLS = true;
		}

		m_authList.push_back(entry);
	}

	std::stable_sort(m_authList.begin(), m_authList.end(), IPAuthEntry_greater());

	PTRACE(m_authList.empty() ? 1 : 5, GetName() << "\t" << m_authList.size() << " entries loaded");

	if (PTrace::CanTrace(6)) {
		ostream &strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << GetName() << " entries:\n";
		IPAuthList::const_iterator entry = m_authList.begin();
		while (entry != m_authList.end()) {
			strm << "\t" << entry->first.AsString() << " = "
				<< (entry->second.auth ? "allow" : "reject")
				<< (entry->second.auth ? entry->second.PrintOn() : "") << endl;
			++entry;
		}
		PTrace::End(strm);
	}

	if (dynamicCfg) {
		delete cfg;
		cfg = NULL;
	}
}

FileIPAuth::~FileIPAuth()
{
}

int FileIPAuth::CheckAddress(
	const PIPSocket::Address & addr, /// IP address the request comes from
	WORD /*port*/, /// port number the request comes from
	const PString & number, bool overTLS)
{
	IPAuthList::const_iterator entry = m_authList.begin();
	while (entry != m_authList.end()) {
		if (entry->first.IsAny() || addr << entry->first) {
			if (entry->second.onlyTLS && !overTLS) {
				PTRACE(5, GetName() << "\tIP " << addr.AsString() << " rejected (no TLS)");
				return e_fail;
			}
			if (entry->second.auth && !number.IsEmpty()) {
				int len = entry->second.PrefixMatch(number);
				PTRACE(5, GetName() << "\tIP " << addr.AsString()
					<< (len ? " accepted" : " rejected")
					<< " for Called " << number);
				return len ? e_ok : e_fail;
			}
			return entry->second.auth ? e_ok : e_fail;
		}
		++entry;
	}
	PTRACE(5, GetName() << "\tReturns default for " << addr.AsString() << " => " << StatusAsString(GetDefaultStatus()));
	return GetDefaultStatus();
}


IPAuthPrefix::IPAuthPrefix() : auth(false), onlyTLS(false)
{
}

IPAuthPrefix::IPAuthPrefix(bool a, const PString & prefixes, bool tls)
{
	auth = a;
	AddPrefix(prefixes);
	onlyTLS = tls;
}

IPAuthPrefix::IPAuthPrefix(const IPAuthPrefix & obj)
{
	auth = obj.auth;
	onlyTLS = obj.onlyTLS;

	const_prefix_iterator Iter = obj.Prefixs.begin();
	const_prefix_iterator eIter = obj.Prefixs.end();
	while (Iter != eIter) {
		Prefixs.push_back(Iter->c_str());
		++Iter;
	}
}

IPAuthPrefix& IPAuthPrefix::operator=(const IPAuthPrefix & obj)
{
	if (this != &obj) {
		auth = obj.auth;
		onlyTLS = obj.onlyTLS;
		Prefixs.clear();

		const_prefix_iterator Iter = obj.Prefixs.begin();
		const_prefix_iterator eIter = obj.Prefixs.end();
		while (Iter != eIter) {
			Prefixs.push_back(Iter->c_str());
			++Iter;
		}
	}

	return *this;
}

IPAuthPrefix& IPAuthPrefix::operator=(bool a)
{
	auth = a;
	return *this;
}

void IPAuthPrefix::AddPrefix(const PString & prefixes)
{
	PStringArray p(prefixes.Tokenise(" ,;\t\n", false));
	for (PINDEX i = 0; i < p.GetSize(); ++i)
		Prefixs.push_back((const char *)p[i]);
}

void IPAuthPrefix::SortPrefix(bool greater)
{
	// remove duplicate aliases
	if (greater)
		sort(Prefixs.begin(), Prefixs.end(), str_prefix_greater());
	else
		sort(Prefixs.begin(), Prefixs.end(), str_prefix_lesser());
	prefix_iterator Iter = std::unique(Prefixs.begin(), Prefixs.end());
	Prefixs.erase(Iter, Prefixs.end());
}

int IPAuthPrefix::PrefixMatch(const PString & number) const
{
	if (number.IsEmpty())
		return 0;

	const char * alias = (const char*)(number);

	if (!alias)
		return 0;

	const_prefix_iterator Iter = Prefixs.begin();
	const_prefix_iterator eIter = Prefixs.end();

	if (Iter == eIter)
		return 1;

	while (Iter != eIter) {
		const int len = MatchPrefix(alias, Iter->c_str());
		if (len > 0) {
			return len;
		}
		++Iter;
	}

	return 0;
}

std::string IPAuthPrefix::PrintOn() const
{
	if (!auth)
		return std::string(" to called any");

	std::string prefix = PrintPrefix();

	if (prefix == ".")
		prefix = "any";
	std::string ret(" to called ");
	ret += prefix;
	if (onlyTLS)
		ret += " (only TLS)";
	return ret;
}

std::string IPAuthPrefix::PrintPrefix() const
{
	std::string prefix;
	const_prefix_iterator Iter = Prefixs.begin();
	const_prefix_iterator eIter = Prefixs.end();
	while (Iter != eIter) {
		prefix += *Iter;
		prefix += ",";
		++Iter;
	}

	return prefix;
}

namespace { // anonymous namespace
	GkAuthCreator<FileIPAuth> FileIPAuthCreator("FileIPAuth");
} // end of anonymous namespace
