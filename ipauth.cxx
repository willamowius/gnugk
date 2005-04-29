/*
 * ipauth.cxx
 *
 * IP based authentication modules
 *
 * @(#) $Id$
 *
 * Copyright (c) 2005, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 */
#include <ptlib.h>
#include <h225.h>

#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "Toolkit.h"
#include "RasPDU.h"
#include "RasTbl.h"
#include "sigmsg.h"
#include "ipauth.h"

/// Text file based IP authentication
class FileIPAuth : public IPAuthBase {
public:
	typedef std::pair<NetworkAddress, bool> IPAuthEntry;

	
	/// Create text file based authenticator
	FileIPAuth( 
		/// authenticator name from Gatekeeper::Auth section
		const char *authName
		);

	/// Destroy the authenticator
	virtual ~FileIPAuth();

protected:
	/// Overriden from IPAuthBase
	virtual int CheckAddress(
		const PIPSocket::Address &addr, /// IP address the request comes from
		WORD port /// port number the request comes from
		);
				
private:
	FileIPAuth();
	/* No copy constructor allowed */
	FileIPAuth(const FileIPAuth&);
	/* No operator= allowed */
	FileIPAuth& operator=(const FileIPAuth&);
	
private:
	typedef std::vector<IPAuthEntry> IPAuthList;

	IPAuthList m_authList;
};


IPAuthBase::IPAuthBase( 
	/// authenticator name from Gatekeeper::Auth section
	const char *authName,
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
	/// GRQ RAS message to be authenticated
	RasPDU<H225_GatekeeperRequest> &grqPdu, 
	/// gatekeeper request reject reason
	unsigned &rejectReason
	)
{
	return CheckAddress(grqPdu->m_peerAddr, grqPdu->m_peerPort);
}

int IPAuthBase::Check(
	/// RRQ RAS message to be authenticated
	RasPDU<H225_RegistrationRequest> &rrqPdu, 
	/// authorization data (reject reason, ...)
	RRQAuthData &authData
	)
{
	return CheckAddress(rrqPdu->m_peerAddr, rrqPdu->m_peerPort);
}
		
int IPAuthBase::Check(
	/// LRQ nessage to be authenticated
	RasPDU<H225_LocationRequest> &lrqPdu, 
	/// location request reject reason
	unsigned &rejectReason
	)
{
	return CheckAddress(lrqPdu->m_peerAddr, lrqPdu->m_peerPort);
}

int IPAuthBase::Check(
	/// Q.931/H.225 Setup message to be authenticated
	SetupMsg &setup,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData& authData
	)
{
	PIPSocket::Address addr;
	WORD port = 0;
	setup.GetPeerAddr(addr, port);
	
	return CheckAddress(addr, port);
}


/////////////
// FileIPAuth
/////////////

namespace {
const char *FileIPAuthSecName = "FileIPAuth";

struct IPAuthEntry_greater : public binary_function<FileIPAuth::IPAuthEntry, FileIPAuth::IPAuthEntry, bool> {

	bool operator()(
		const FileIPAuth::IPAuthEntry &a,
		const FileIPAuth::IPAuthEntry &b
		) const 
	{
		const int diff = a.first.Compare(b.first);
		if (diff == 0)
			return !a.second;
		return diff > 0;
	}
};

} /* anonymous namespace */

FileIPAuth::FileIPAuth( 
	/// authenticator name from Gatekeeper::Auth section
	const char *authName
	) : IPAuthBase(authName)
{
	bool dynamicCfg = false;
	PConfig *cfg = GkConfig();
	
	if (cfg->HasKey(FileIPAuthSecName, "include")) {
		const PFilePath fp(cfg->GetString(FileIPAuthSecName, "include", ""));
		if (!PFile::Exists(fp)) {
			PTRACE(0, GetName() << "\tCould not read the include file '"
				<< fp << "': the file does not exist"
				);
			return;
		}
		cfg = new PConfig(fp, authName);
		dynamicCfg = true;
	}

	PStringToString kv = cfg->GetAllKeyValues(FileIPAuthSecName);
	
	m_authList.reserve(kv.GetSize());
	
	for (PINDEX i = 0; i < kv.GetSize(); i++) {
		const PString &key = kv.GetKeyAt(i);
		if (key[0] == '#')
			continue;
		
		IPAuthEntry entry;
		
		entry.first = (key == "*" || key == "any") ? NetworkAddress() : NetworkAddress(key);
		entry.second = PCaselessString("allow") == kv.GetDataAt(i);
		
		m_authList.push_back(entry);
	}

	std::stable_sort(m_authList.begin(), m_authList.end(), IPAuthEntry_greater());
	
	PTRACE(5, GetName() << "\t" << m_authList.size() << " entries loaded");

#if PTRACING
	if (PTrace::CanTrace(6)) {
		ostream &strm = PTrace::Begin(6, __FILE__, __LINE__);
		strm << GetName() << " entries:\n";
		IPAuthList::const_iterator entry = m_authList.begin();
		while (entry != m_authList.end()) {
			strm << "\t" << entry->first.AsString() << " = " 
				<< (entry->second ? "allow" : "reject") << endl;
			entry++;
		}
		PTrace::End(strm);
	}
#endif

	if (dynamicCfg)
		delete cfg;
}


FileIPAuth::~FileIPAuth()
{
}

int FileIPAuth::CheckAddress(
	const PIPSocket::Address &addr, /// IP address the request comes from
	WORD port /// port number the request comes from
	)
{
	IPAuthList::const_iterator entry = m_authList.begin();
	while (entry != m_authList.end()) {
		if (entry->first.IsAny() || addr << entry->first) {
			PTRACE(5, GetName() << "\tIP " << addr.AsString() 
				<< (entry->second ? " accepted" : " rejected")
				<< " by the rule " << entry->first.AsString()
				);
			return entry->second ? e_ok : e_fail;
		}
		entry++;
	}
	return GetDefaultStatus();
}
				
namespace { // anonymous namespace
	GkAuthCreator<FileIPAuth> FileIPAuthCreator("FileIPAuth");
} // end of anonymous namespace
