//////////////////////////////////////////////////////////////////
//
// Toolkit base class for the GnuGK
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	991227  initial version (Torsten Will, mediaWays)
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include "Toolkit.h"
#include "stl_supp.h"
#include <h323pdu.h>
#include <ptclib/cypher.h>

#ifdef P_SOLARIS
#define map stl_map
#endif
#include <map>


extern const char *ProxySection;

// class Toolkit::RouteTable::RouteEntry
Toolkit::RouteTable::RouteEntry::RouteEntry(
	const PString & net
) : PIPSocket::RouteEntry(0)
{
	destination = net.Tokenise("/", FALSE)[0];
	GetNetworkFromString(net, network, net_mask);
}

Toolkit::RouteTable::RouteEntry::RouteEntry(
	const PIPSocket::RouteEntry & re,
	const InterfaceTable & it
) : PIPSocket::RouteEntry(re)
{
	PINDEX i;
	for (i = 0; i < it.GetSize(); ++i) {
		const Address & ip = it[i].GetAddress();
		if (Compare(&ip)) {
			destination = ip;
			return;
		}
	}
	for (i = 0; i < it.GetSize(); ++i)
		if (it[i].GetName() == interfaceName) {
			destination = it[i].GetAddress();
			return;
		}
}

inline bool Toolkit::RouteTable::RouteEntry::Compare(const Address *ip) const
{
	return (*ip == destination) || ((*ip & net_mask) == network);
}

// class Toolkit::RouteTable
void Toolkit::RouteTable::InitTable()
{
	// Workaround for OS doesn't support GetRouteTable
	PIPSocket::GetHostAddress(defAddr);

	ClearTable();
	if (!CreateTable())
		return;

	// Set default IP according to route table
	PIPSocket::Address defGW;
	PIPSocket::GetGatewayAddress(defGW);
	defAddr = GetLocalAddress(defGW);

#if PTRACING
	for (RouteEntry *entry = rtable_begin; entry != rtable_end; ++entry)
		PTRACE(2, "Network=" << entry->GetNetwork() << '/' << entry->GetNetMask() <<
			  ", IP=" << entry->GetDestination());
	PTRACE(2, "Default IP=" << defAddr);
#endif
}

void Toolkit::RouteTable::ClearTable()
{
	if (rtable_begin) {
		for (RouteEntry *r = rtable_begin; r != rtable_end; ++r)
			r->~RouteEntry();
		::free(rtable_begin);
		rtable_begin = 0;
	}
}

// can't pass a reference of Address, or STL complains...
PIPSocket::Address Toolkit::RouteTable::GetLocalAddress(const Address & addr) const
{
	RouteEntry *entry = find_if(rtable_begin, rtable_end,
			bind2nd(mem_fun_ref(&RouteEntry::Compare), &addr));
	return (entry != rtable_end) ? entry->GetDestination() : defAddr;
}

bool Toolkit::RouteTable::CreateTable()
{
	InterfaceTable if_table;
	if (!PIPSocket::GetInterfaceTable(if_table)) {
		PTRACE(1, "Error: Can't get interface table");
		return false;
	}
	PTRACE(4, "InterfaceTable:\n" << setfill('\n') << if_table << setfill(' '));
	PIPSocket::RouteTable r_table;
	if (!PIPSocket::GetRouteTable(r_table)) {
		PTRACE(1, "Error: Can't get route table");
		return false;
	}

	int i = r_table.GetSize();
	rtable_end = rtable_begin = static_cast<RouteEntry *>(::malloc(i * sizeof(RouteEntry)));
	for (PINDEX r = 0; r < i ; ++r) {
		PIPSocket::RouteEntry & r_entry = r_table[r];
		if (r_entry.GetNetMask() != INADDR_ANY)
			// placement operator
			::new (rtable_end++) RouteEntry(r_entry, if_table);
	}
	return true;
}

bool Toolkit::VirtualRouteTable::CreateTable()
{
	PString nets = GkConfig()->GetString("NetworkInterfaces", "");
	if (nets.IsEmpty())
		return false;
	PStringArray networks(nets.Tokenise(" ,;\t", FALSE));
	int i = networks.GetSize();
	if (i > 0) {
		rtable_end = rtable_begin = static_cast<RouteEntry *>(::malloc(i * sizeof(RouteEntry)));
		for (PINDEX r = 0; r < i ; ++r)
			::new (rtable_end++) RouteEntry(networks[r]);
	}
	return true;
}

// class Toolkit::ProxyCriterion
void Toolkit::ProxyCriterion::LoadConfig(PConfig *config)
{
	ClearTable();
	if (!AsBool(config->GetString(ProxySection, "Enable", "0"))) {
		PTRACE(2, "GK\tH.323 Proxy disabled");
		size = -1;
		return;
	}

	PTRACE(2, "GK\tH.323 Proxy enabled");

	PStringArray networks(config->GetString(ProxySection, "InternalNetwork", "").Tokenise(" ,;\t", FALSE));
	if ((size = networks.GetSize()) == 0) {
		// no internal networks specified, always use proxy
		return;
	}

	network = new Address[size * 2];
	netmask = network + size;
	for (int i = 0; i < size; ++i) {
		GetNetworkFromString(networks[i], network[i], netmask[i]);
		PTRACE(2, "GK\tInternal Network " << i << " = " <<
			   network[i] << '/' << netmask[i]);
	}
}

void Toolkit::ProxyCriterion::ClearTable()
{
	size = 0;
	delete [] network;
	network = 0;
}

bool Toolkit::ProxyCriterion::Required(const Address & ip1, const Address & ip2) const
{
	return (size >= 0) ? ((size == 0) || (IsInternal(ip1) != IsInternal(ip2))) : false;
}

bool Toolkit::ProxyCriterion::IsInternal(const Address & ip) const
{
	for (int i = 0; i < size; ++i)
		if ((ip & netmask[i]) == network[i])
			return true;
	return false;
}

// class Toolkit::RewriteTool

static const char *RewriteSection = "RasSrv::RewriteE164";

Toolkit::RewriteData::RewriteData(PConfig *config, const PString & section) : m_RewriteKey(0)
{
	PStringToString cfgs(config->GetAllKeyValues(section));
	m_size = cfgs.GetSize();
	if (m_size > 0) {
		std::map<PString, PString> rules;
		for (PINDEX i = 0; i < m_size; ++i) {
			PString key = cfgs.GetKeyAt(i);
			if (!key && (isdigit(key[0]) || key[0]=='!'))
				rules[key] = cfgs.GetDataAt(i);
		}
		// now the rules are ascendantly sorted by the keys
		if ((m_size = rules.size()) > 0) {
			m_RewriteKey = new PString[m_size * 2];
			m_RewriteValue = m_RewriteKey + m_size;
			std::map<PString, PString>::iterator iter = rules.begin();
			// reverse the order
			for (PINDEX i = m_size; i-- > 0 ; ++iter) {
				m_RewriteKey[i] = iter->first;
				m_RewriteValue[i] = iter->second;
			}
		}
	}
}

void Toolkit::RewriteTool::LoadConfig(PConfig *config)
{
	m_RewriteFastmatch = config->GetString(RewriteSection, "Fastmatch", "");
	m_TrailingChar = config->GetString("RasSrv::ARQFeatures", "RemoveTrailingChar", " ")[0];
	delete m_Rewrite;
	m_Rewrite = new RewriteData(config, RewriteSection);
}

bool Toolkit::RewriteTool::RewritePString(PString & s) const
{
	bool changed = false;
	bool do_rewrite = false; // marker if a rewrite has to be done.

	// remove trailing character
	if (s.GetLength() > 1 && s[s.GetLength() - 1] == m_TrailingChar) {
		s = s.Left(s.GetLength() - 1);
		changed = true;
	}
	// startsWith?
	if (strncmp(s, m_RewriteFastmatch, m_RewriteFastmatch.GetLength()) != 0)
		return changed;

	PString t;
	for (PINDEX i = 0; i < m_Rewrite->Size(); ++i) {
		bool inverted;
		PString key = m_Rewrite->Key(i);
		if ((inverted = (key[0] == '!')))
			key = key.Mid(1);
		// try a prefix match through all keys
		if ((strncmp(s, key, key.GetLength()) == 0) ^ inverted) {
			// Rewrite to #t#. Append the suffix, too.
			// old:  01901234999
			//               999 Suffix
			//       0190        Fastmatch
			//       01901234    prefix, Config-Rule: 01901234=0521321
			// new:  0521321999
			t = m_Rewrite->Value(i);
			// multiple targets possible
			if (!t) {
				const PStringArray ts = t.Tokenise(",:;&|\t ", FALSE);
				if (ts.GetSize() > 1) {
					PINDEX j = rand() % ts.GetSize();
					PTRACE(5, "GK\tRewritePString: randomly chosen [" << j << "] of " << t << "");
					t = ts[j];
				}
			}

			// append the suffix
			int striplen = (inverted) ? 0 : key.GetLength();
			t += s.Mid(striplen);

			do_rewrite = true;
			break;
		}
	}
	
	// 
	// Do the rewrite. 
	// @param #t# will be written to #s#
	//
	if (do_rewrite) {
		PTRACE(2, "\tRewritePString: " << s << " to " << t);
		s = t;
		changed = true;
	}
	
	return changed;
}

Toolkit::Toolkit() : Singleton<Toolkit>("Toolkit")
{
	m_Config = 0;
	m_ConfigDirty = false;
	srand(time(0));
}

Toolkit::~Toolkit()
{
	if (m_Config) {
		delete m_Config;
		PFile::Remove(m_tmpconfig);
	}
}

Toolkit::RouteTable *Toolkit::GetRouteTable(bool real)
{
	return real ? &m_RouteTable : m_VirtualRouteTable.IsEmpty() ? &m_RouteTable : &m_VirtualRouteTable;
}

PConfig* Toolkit::Config()
{
	// Make sure the config would not be called before SetConfig
	PAssert(!m_ConfigDefaultSection, "Error: Call Config() before SetConfig()!");
	return (m_Config == NULL) ? ReloadConfig() : m_Config;
}

PConfig* Toolkit::Config(const char *section)
{
	Config()->SetDefaultSection(section);
	return m_Config;
}

PConfig* Toolkit::SetConfig(const PFilePath &fp, const PString &section)
{ 
	m_ConfigFilePath = fp;
	m_ConfigDefaultSection = section;

	return ReloadConfig();
}

void Toolkit::SetConfig(int act, const PString & sec, const PString & key, const PString & value)
{
	// the original config
	PConfig cfg(m_ConfigFilePath, m_ConfigDefaultSection);
	switch (act)
	{
		case 1:
			cfg.SetString(sec, key, value);
			m_Config->SetString(sec, key, value);
			break;
		case 2:
			cfg.DeleteKey(sec, key);
			m_Config->DeleteKey(sec, key);
			break;
		case 3:
			cfg.DeleteSection(sec);
			m_Config->DeleteSection(sec);
			break;
	}

	m_ConfigDirty = true;
}

void Toolkit::CreateConfig()
{
	if (m_Config != NULL) {
		delete m_Config;
		PFile::Remove(m_tmpconfig);
	}

	// generate a unique name
	do {
#ifdef WIN32
		m_tmpconfig = m_ConfigFilePath + "-" + PString(PString::Unsigned, rand()%10000);
#else
		m_tmpconfig = "/tmp/gnugk.ini-" + PString(PString::Unsigned, rand()%10000);
#endif
		PTRACE(5, "Try name "<< m_tmpconfig);
	} while (PFile::Exists(m_tmpconfig));

#ifdef WIN32
	// Does WIN32 support symlink?
	if (PFile::Copy(m_ConfigFilePath, m_tmpconfig))
#else
	if (symlink(m_ConfigFilePath, m_tmpconfig)==0)
#endif
		m_Config = new PConfig(m_tmpconfig, m_ConfigDefaultSection);
	else // Oops! Create temporary config file failed, use the original one
		m_Config = new PConfig(m_ConfigFilePath, m_ConfigDefaultSection);
}

PConfig* Toolkit::ReloadConfig()
{
	if (!m_ConfigDirty)
		CreateConfig();
	else // the config have been changed via status port, use it directly
		m_ConfigDirty = false;

	m_RouteTable.InitTable();
	m_VirtualRouteTable.InitTable();
	m_ProxyCriterion.LoadConfig(m_Config);
	m_Rewrite.LoadConfig(m_Config);
	PString GKHome(m_Config->GetString("Home", ""));
	if (m_GKHome.empty() || !GKHome)
		SetGKHome(GKHome.Tokenise(",:;", false));

	return m_Config; 
}

BOOL Toolkit::MatchRegex(const PString &str, const PString &regexStr)
{
	PINDEX pos=0;
	PRegularExpression regex(regexStr, PRegularExpression::Extended);
	if(regex.GetErrorCode() != PRegularExpression::NoError) {
		PTRACE(2, "Errornous '"<< regex.GetErrorText() <<"' compiling regex: " << regexStr);
		return FALSE;
	}
	if(!regex.Execute(str, pos)) {
		PTRACE(5, "Gk\tRegex '"<<regexStr<<"' did not match '"<<str<<"'");
		return FALSE;
	}
	return TRUE;
}



bool Toolkit::RewriteE164(H225_AliasAddress &alias)
{ 
	if (alias.GetTag() != H225_AliasAddress::e_dialedDigits) 
		return FALSE;
	
	PString E164 = H323GetAliasAddressString(alias);

	bool changed = RewritePString(E164);
	if (changed)
		H323SetAliasAddress(E164, alias);
	
	return changed;
}

bool Toolkit::RewriteE164(H225_ArrayOf_AliasAddress & aliases)
{
	bool changed = false;
	for (PINDEX n = 0; n < aliases.GetSize(); ++n)
		changed |= RewriteE164(aliases[n]);
	return changed;
}

PString Toolkit::GetGKHome(std::vector<PIPSocket::Address> & GKHome) const
{
	GKHome = m_GKHome;
	PString result;
	int hsize = GKHome.size();
	for (int i = 0; i < hsize; ++i) {
		result += GKHome[i].AsString();
		if (i < hsize - 1)
			result += ",";
	}
	return result;
}

void Toolkit::SetGKHome(const PStringArray & home)
{
	std::vector<PIPSocket::Address>::iterator begin;
	m_GKHome.clear();
	int n, i, size = home.GetSize();
	if (size > 0)
		for (n = 0; n < size; ++n)
			m_GKHome.push_back(home[n]);

	PIPSocket::InterfaceTable it;
	if (PIPSocket::GetInterfaceTable(it)) {
		int is = it.GetSize();
		if (size > 0) {
			// check if the interface is valid
			for (n = 0; n < size; ++n) {
				for (i = 0; i < is; ++i)
					if (m_GKHome[n] == it[i].GetAddress())
						break;
				if (i == is) {
					begin = m_GKHome.begin();
					copy(begin + n + 1, begin + size, begin + n);
					--size, --n;
				}
			}
		} 
		if (size == 0) {
			m_GKHome.clear();
			size = is;
			for (n = 0; n < size; ++n)
				m_GKHome.push_back(it[n].GetAddress());
		}
		// remove INADDR_ANY
		for (n = 0; n < size; ++n)
			if (m_GKHome[n] == INADDR_ANY) {
				begin = m_GKHome.begin();
				copy(begin + n + 1, begin + size, begin + n);
				--size, --n;
			}
	}

	// remove duplicate interfaces
	for (n = 0; n < size; ++n)
		for (i = 0; i < n; ++i)
			if (m_GKHome[n] == m_GKHome[i]) {
				begin = m_GKHome.begin();
				copy(begin + n + 1, begin + size, begin + n);
				--size, --n;
				break;
			}

	m_GKHome.resize(size);
	// put the default IP to the first
	begin = find(m_GKHome.begin(), m_GKHome.end(), m_RouteTable.GetLocalAddress());
	if (begin != m_GKHome.end())
		swap(m_GKHome[0], *begin);
}

const PString Toolkit::GKName() 
{
	return GkConfig()->GetString("Name", "GNU Gatekeeper"); //use default section (MM 06.11.01)
}

int
Toolkit::GetInternalExtensionCode( const unsigned &country, 
				   const unsigned &extension, 
				   const unsigned &manufacturer) const 
{
	switch(country) {
	case t35cOpenOrg: 
		switch(manufacturer) {
		case t35mOpenOrg:
			switch(extension) {
				case t35eFailoverRAS: return iecFailoverRAS;
			}
		}
	}

	// default for all other cases
	return iecUnknown;
}

int Toolkit::GetInternalExtensionCode(const H225_H221NonStandard& data) const
{
	return GetInternalExtensionCode(data.m_t35CountryCode,
			data.m_t35Extension,
			data.m_manufacturerCode);
}

bool Toolkit::AsBool(const PString & str) 
{
	if (str.IsEmpty())
		return false;
	const unsigned char c = tolower(str[0]);
	return ( c=='t' || c=='1' || c=='y' || c=='a' );
}

void Toolkit::GetNetworkFromString(const PString & cfg, PIPSocket::Address & network, PIPSocket::Address & netmask)
{
	if (cfg *= "ALL") {
		network = netmask = INADDR_ANY;
		return;
	}
	PStringArray net = cfg.Tokenise("/", FALSE);
	if (net.GetSize() < 2) {
		netmask = (DWORD(~0));
	} else if (net[1].Find('.') == P_MAX_INDEX) {
		// CIDR notation
		DWORD n = (DWORD(~0) >> net[1].AsInteger());
		netmask = PIPSocket::Host2Net(~n);
	} else {
		// decimal dot notation
		netmask = net[1];
	}
	network = PIPSocket::Address(net[0]) & netmask; // normalize
}

PString Toolkit::CypherDecode(const PString & key, const PString & crypto, int s)
{
	size_t sz = key.GetLength();
	if (sz > sizeof(PTEACypher::Key))
		sz = sizeof(PTEACypher::Key);
	PTEACypher::Key thekey;
	memset(&thekey, s, sizeof(PTEACypher::Key));
	memcpy(&thekey, (const char *)key, sz);
	PTEACypher cypher(thekey);

	return cypher.Decode(crypto);
}
