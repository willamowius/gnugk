//////////////////////////////////////////////////////////////////
//
// Toolkit base class for the OpenGK
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


#include <ptlib.h>
#include "h323pdu.h"
#include "Toolkit.h"
#include "ANSI.h"
#include "stl_supp.h"


const char *ProxySection = "Proxy";

// class Toolkit::RouteTable::RouteEntry
Toolkit::RouteTable::RouteEntry::RouteEntry(
	PIPSocket::RouteEntry & re,
	InterfaceTable & it
) : PIPSocket::RouteEntry(re)
{
	for (PINDEX i = 0; i < it.GetSize(); ++i) {
		if (it[i].GetName() == interfaceName) {
			destination = it[i].GetAddress();
			break;
		}
	}
}

inline bool Toolkit::RouteTable::RouteEntry::Compare(Address ip) const
{
	return ((ip & net_mask) == network);
}

// class Toolkit::RouteTable
void Toolkit::RouteTable::InitTable()
{
	// Workaround for OS doesn't support GetRouteTable
	PIPSocket::GetHostAddress(defAddr);

	ClearTable();
	InterfaceTable if_table;
	if (!PIPSocket::GetInterfaceTable(if_table)) {
		PTRACE(1, "Error: Can't get interface table");
		return;
	}
	PIPSocket::RouteTable r_table;
	if (!PIPSocket::GetRouteTable(r_table)) {
		PTRACE(1, "Error: Can't get route table");
		return;
	}
	for (PINDEX r = 0; r < r_table.GetSize(); r++) {
		PIPSocket::RouteEntry & r_entry = r_table[r];
		if (!r_entry.GetInterface())
			rTable.push_back(new RouteEntry(r_entry, if_table));
	}

	// Set default IP according to route table
	defAddr = GetLocalAddress(INADDR_ANY);

#ifdef PTRACING
	typedef std::list<RouteEntry *>::iterator iterator;
	for (iterator i = rTable.begin(); i != rTable.end(); ++i)
		PTRACE(2, "Network=" << (*i)->GetNetwork() << '/' <<
			  (*i)->GetNetMask() <<
			  ", IP=" << (*i)->GetDestination());
	PTRACE(2, "Default IP=" << defAddr);
#endif
}

void Toolkit::RouteTable::ClearTable()
{
	for_each(rTable.begin(), rTable.end(), delete_entry);
	rTable.clear();
}

PIPSocket::Address Toolkit::RouteTable::GetLocalAddress(Address addr) const
{
	typedef std::list<RouteEntry *>::const_iterator const_iterator;
	const_iterator iter = find_if(rTable.begin(), rTable.end(),
			bind2nd(mem_fun(&RouteEntry::Compare), addr));
	return (iter != rTable.end()) ? (*iter)->GetDestination() : defAddr;
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
		PStringArray net = networks[i].Tokenise("/", FALSE);
		if (net[1].Find('.') == P_MAX_INDEX) {
			// CIDR notation
			DWORD n = (DWORD(~0) >> net[1].AsInteger());
			netmask[i] = PIPSocket::Host2Net(~n);
		} else {
			// decimal dot notation
			netmask[i] = net[1];
		}
		network[i] = Address(net[0]) & netmask[i]; // normalize
		PTRACE(2, "GK\tInternal Network " << i << " = " <<
			   network[i] << '/' << netmask[i]);
	}
}

void Toolkit::ProxyCriterion::ClearTable()
{
	size = 0;
	delete [] network;
}

bool Toolkit::ProxyCriterion::Required(Address ip1, Address ip2) const
{
	return (size >= 0) ? ((size == 0) || (IsInternal(ip1) != IsInternal(ip2))) : false;
}

bool Toolkit::ProxyCriterion::IsInternal(Address ip) const
{
	for (int i = 0; i < size; ++i)
		if ((ip & netmask[i]) == network[i])
			return true;
	return false;
}

Toolkit::Toolkit() : m_Config(0)
{
//	PTRACE(1, "Toolkit::Toolkit");
}

Toolkit::~Toolkit()
{
	if (m_Config) {
		delete m_Config;
		PFile::Remove(m_tmpconfig);
	}
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


PConfig* Toolkit::ReloadConfig()
{
	if (m_Config != NULL) {
		delete m_Config;
		PFile::Remove(m_tmpconfig);
	}

	// generate a unique name
	do {
		m_tmpconfig = m_ConfigFilePath + "-" + PString(PString::Unsigned, rand()%10000);
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
	m_RewriteFastmatch = m_Config->GetString("RasSvr::RewriteE164", "Fastmatch", "");

	m_RouteTable.InitTable();
	m_ProxyCriterion.LoadConfig(m_Config);

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



BOOL  
Toolkit::RewriteE164(H225_AliasAddress &alias)
{ 
	if (alias.GetTag() != H225_AliasAddress::e_dialedDigits) 
		return FALSE;
	
	PString oldE164 = H323GetAliasAddressString(alias);
	PString newE164 = oldE164;

	BOOL changed = RewritePString(newE164);
	if (changed) {
		H323SetAliasAddress(newE164, alias);
		PTRACE(5, "\tRewriteE164: " << oldE164 << " to " << newE164);
	}
	
	return changed;
}



BOOL 
Toolkit::RewritePString(PString &s)
{
	BOOL changed = FALSE;
	BOOL do_rewrite = FALSE; // marker if a rewrite has to be done.

	// startsWith?
	if(strncmp(s, m_RewriteFastmatch, m_RewriteFastmatch.GetLength()) != 0)
		return changed;

	// get the number to rewrite from config entry
	PString t = Config()->GetString("RasSvr::RewriteE164",s, "");
	if(t != "") {
		// number found in config exactly => rewrite it.
		// #t# is just right now!
		do_rewrite = TRUE;
	} else {
		// not found directly, try a prefix match through all keys
		const PStringList &keys = Config()->GetKeys("RasSvr::RewriteE164");
		for(PINDEX i=0; i < keys.GetSize(); i++) {
			if(s.Find(keys[i]) == 0) { // startWith
				// Rewrite to #t#. Append the suffix, too.
				// old:  01901234999
				//               999 Suffix
				//       0190        Fastmatch
				//       01901234    prefix, Config-Rule: 01901234=0521321
				// new:  0521321999    
				t = Config()->GetString("RasSvr::RewriteE164",keys[i], "");

				// multiple targets possible
				if (t != "") {
					const PStringArray ts = t.Tokenise(",:;&|\t ", FALSE);
					if(ts.GetSize() > 1) {
						PINDEX i = rand()%ts.GetSize();
						PTRACE(5, "\tRewritePString: randomly chosen [" << i << "] of " << t << "");
						t = ts[i];
					}
				}
				
				// append the suffix
				t += s.Mid(keys[i].GetLength());

				do_rewrite = TRUE;
				break;
			}
		}
	}
	
	// 
	// Do the rewrite. 
	// @param #t# will be written to #s#
	//
	if(do_rewrite) {
		PTRACE(2, "\tRewritePString: " << s << " to " << t << "");
		s = t;
		changed = TRUE;
	}
	
	return changed;
}


const PString 
Toolkit::GKName() 
{
  return GkConfig()->GetString("Name", "OpenH323GK"); //use default section (MM 06.11.01)
}



// a int to print
#ifdef P_PTHREADS
static const int INT_PTHREADS = 1;
#else
static const int INT_PTHREADS = 0;
#endif

const PString 
Toolkit::GKVersion() 
{
	return PString(PString::Printf,
				   "Gatekeeper(%s) Version(%s) Ext(pthreads=%d) Build(%s, %s) Sys(%s %s %s)\r\n",
				   (const unsigned char*)(PProcess::Current().GetManufacturer()),
				   (const unsigned char*)(PProcess::Current().GetVersion(TRUE)),
				   INT_PTHREADS,
				   __DATE__, __TIME__,
				   (const unsigned char*)(PProcess::GetOSName()),
				   (const unsigned char*)(PProcess::GetOSHardware()),
				   (const unsigned char*)(PProcess::GetOSVersion())
				   );
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



BOOL 
Toolkit::AsBool(const PString &str) 
{
	if (str.GetLength() < 1) return FALSE;
	const unsigned char c = tolower(str[0]);
	return ( c=='t' || c=='1' || c=='y' || c=='a' );
}
