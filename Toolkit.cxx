//////////////////////////////////////////////////////////////////
//
// Toolkit base class for the GnuGk
//
// Copyright (c) 2000-2023, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "config.h"
#include <ptlib.h>
#include <ptclib/pdns.h>
#include <ptclib/cypher.h>
#include <ptclib/http.h>
#include <h323pdu.h>
#include <map>
#include <vector>
#include <cstdlib>
#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#endif // _WIN32
#if (__cplusplus >= 201703L) // C++17
#include <random>
#endif
#include "stl_supp.h"
#include "gktimer.h"
#include "h323util.h"
#include "GkStatus.h"
#include "gkconfig.h"
#if HAS_DATABASE
#include "gksql.h"
#endif
#include "clirw.h"
#include "capctrl.h"
#include "RasSrv.h"
#include "Toolkit.h"
#include "gk_const.h"
#include "SoftPBX.h"
#include "snmp.h"
#include "gk.h"

#ifdef H323_H350
const char * H350Section = "GkH350::Settings";
#include <ptclib/pldap.h>
#include "h350/h350.h"
#endif

#ifdef HAS_LIBCURL
#include <curl/curl.h>
#endif // HAS_LIBCURL

#ifdef HAS_OLM
#include "api/license++.h"
#include "pc-identifiers.h"
#endif

#if (!_WIN32) && (GCC_VERSION >= 40600)
#pragma GCC diagnostic ignored "-Wstrict-overflow"
#endif

using namespace std;

PIPSocket::Address GNUGK_INADDR_ANY(INADDR_ANY);

PReadWriteMutex ConfigReloadMutex;
PSemaphore ShutdownMutex(1, 1);
bool ShutdownFlag = false;	// you may only set this flag if you own the ShutdownMutex, once it is set, it can never be cleared!
bool g_disableSettingUDPSourceIP = false;

extern const char *ProxySection;
extern const char *RoutedSec;
extern const char *TLSSec;

extern int g_maxSocketQueue;

bool IsGatekeeperShutdown()
{
    return ShutdownFlag;
}

namespace {

const PString paddingByteConfigKey("KeyFilled");
const BYTE AnyRawAddress[16] = {
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255
};

} /* namespace */

NetworkAddress::NetworkAddress() : m_address(0), m_netmask(0)
{
}

NetworkAddress::NetworkAddress(
	const PIPSocket::Address & addr
	) : m_address(addr), m_netmask(addr.GetSize(), AnyRawAddress)
{
}

NetworkAddress::NetworkAddress(
	const PIPSocket::Address & addr,
	const PIPSocket::Address & nm
	) : m_netmask(nm)
{
	// normalize the address
	if (addr.GetSize() == nm.GetSize()) {
		BYTE rawdata[16];
		const unsigned sz = addr.GetSize();
		for (unsigned i = 0; i < sz; i++)
			rawdata[i] = addr[i] & nm[i];
		m_address = PIPSocket::Address(sz, rawdata);
	} else {
		PTRACE(1, "Error: Non-matching network and netmask");
	}
}

NetworkAddress::NetworkAddress(
	const PString & str /// an address in a form A.B.C.D, A.B.C.D/24 or A.B.C.D/255.255.255.0
	)
{
	Toolkit::GetNetworkFromString(str, m_address, m_netmask);
}

unsigned NetworkAddress::GetNetmaskLen() const
{
	unsigned len = 0;
	const unsigned sz = m_netmask.GetSize() * 8;
	const char *rawdata = m_netmask.GetPointer();


	for (int b = sz - 1; b >= 0; b--)
		if (rawdata[b >> 3] & (0x80 >> (b & 7)))
			break;
		else
			len++;

	return sz - len;
}

bool NetworkAddress::operator==(const NetworkAddress & addr) const
{
	if (m_address.GetSize() != addr.m_address.GetSize())
		return false;

	const unsigned sz = m_address.GetSize();
	for (unsigned i = 0; i < sz; i++)
		if (m_address[i] != addr.m_address[i] || m_netmask[i] != addr.m_netmask[i])
			return false;

	return true;
}

bool NetworkAddress::operator==(const PIPSocket::Address & addr) const
{
	if (m_address.GetSize() != addr.GetSize())
		return false;

	const unsigned sz = m_address.GetSize();
	for (unsigned i = 0; i < sz; i++)
		if (m_netmask[i] != 255 || m_address[i] != addr[i])
			return false;

	return true;
}

bool NetworkAddress::operator>>(const NetworkAddress & addr) const
{
	if (m_address.GetSize() != addr.m_address.GetSize())
		return false;

	const unsigned sz = m_address.GetSize();
	for (unsigned i = 0; i < sz; i++)
		if (m_netmask[i] != (addr.m_netmask[i] & m_netmask[i])
				|| m_address[i] != (addr.m_address[i] & m_netmask[i]))
			return false;

	return true;
}

bool NetworkAddress::operator<<(const NetworkAddress & addr) const
{
	return addr >> *this;
}

bool NetworkAddress::operator>>(const PIPSocket::Address & addr) const
{
	if (m_address.GetSize() != addr.GetSize())
		return false;

	const unsigned sz = m_address.GetSize();
	for (unsigned i = 0; i < sz; i++)
		if (m_address[i] != (addr[i] & m_netmask[i]))
			return false;

	return true;
}

int NetworkAddress::Compare(const NetworkAddress & addr) const
{
	int diff = m_address.GetSize() - addr.m_address.GetSize();
	if (diff == 0) {
		diff = GetNetmaskLen() - addr.GetNetmaskLen();
		if (diff == 0) {
			const unsigned sz = m_address.GetSize();
			for (unsigned i = 0; i < sz; i++) {
				diff = m_address[i] - addr.m_address[i];
				if (diff != 0)
					break;
			}
		}
	}
	return diff;
}

PString NetworkAddress::AsString() const
{
	return m_address.AsString() + "/" + PString(GetNetmaskLen());
}

bool NetworkAddress::IsAny() const
{
	return m_address.IsAny() && (GetNetmaskLen() == 0);
}

bool NetworkAddress::operator<(const NetworkAddress & addr) const
{
	return Compare(addr) < 0;
}

bool NetworkAddress::operator<=(const NetworkAddress & addr) const
{
	return Compare(addr) <= 0;
}

bool NetworkAddress::operator>(const NetworkAddress & addr) const
{
	return Compare(addr) > 0;
}

bool NetworkAddress::operator>=(const NetworkAddress & addr) const
{
	return Compare(addr) >= 0;
}

bool operator==(const PIPSocket::Address & addr, const NetworkAddress & net)
{
	return net == addr;
}

bool operator<<(const PIPSocket::Address & addr, const NetworkAddress & net)
{
	return net >> addr;
}


// class Toolkit::RouteTable::RouteEntry
Toolkit::RouteTable::RouteEntry::RouteEntry(const PString & net) : PIPSocket::RouteEntry(0)
{
	if (net.Find('-') != P_MAX_INDEX) {
		// format: net/mask-dest eg. 10.0.0.0/8-20.1.1.1
		destination = net.Tokenise("-", FALSE)[1];
		GetNetworkFromString(net.Tokenise("-", FALSE)[0], network, net_mask);
	} else {
		// format: net/mask-dest eg. 10.1.1.1/8
		destination = net.Tokenise("/", FALSE)[0];
		GetNetworkFromString(net, network, net_mask);
	}
}

Toolkit::RouteTable::RouteEntry::RouteEntry(
	const PIPSocket::RouteEntry & re,
	const InterfaceTable & it
) : PIPSocket::RouteEntry(re)
{
	// look at the interface table which local IP to use for this route entry
	PINDEX i;
	// try to select outgoing IP from network - check if IP is valid with netmask
	for (i = 0; i < it.GetSize(); ++i) {
		const Address & ip = it[i].GetAddress();
	    if (Toolkit::Instance()->IsGKHome(ip) && CompareWithMask(&ip)) {
	        destination = ip;
	        return;
	    }
	}
	for (i = 0; i < it.GetSize(); ++i) {
		const Address & ip = it[i].GetAddress();
		if (Toolkit::Instance()->IsGKHome(ip) && CompareWithoutMask(&ip)) {    // skip IPs we don't listen to
			destination = ip;
			return;
		}
	}
	for (i = 0; i < it.GetSize(); ++i) {
		if ((it[i].GetName() == interfaceName) && Toolkit::Instance()->IsGKHome(it[i].GetAddress())) {
			destination = it[i].GetAddress();
			return;
		}
	}
}

inline bool Toolkit::RouteTable::RouteEntry::CompareWithoutMask(const Address *ip) const
{
	return (*ip == destination) || (((*ip & net_mask) == network) && (ip->GetVersion() == network.GetVersion()));
}

bool Toolkit::RouteTable::RouteEntry::CompareWithMask(const Address *ip) const
{
	if (ip->GetVersion() != network.GetVersion())
		return false;

#if P_HAS_IPV6
    PINDEX mmax = ip->GetVersion() == 6 ? 16 : 4;
#else
    PINDEX mmax = 4;
#endif
    bool maskValid = true;
    bool networkStarted = false; // this is a non-zero network byte
    for (PINDEX m = mmax - 1; m >= 0 ; --m) {
        BYTE ipByte = (*ip)[m];
        BYTE maskByte = net_mask[m];
        if (maskByte == 0) {
            if (networkStarted && (ipByte > 0)){
                return false;
            }
            // mask non-zero bits not reached yet
            continue;
        }
        networkStarted = true;
        BYTE match = (unsigned char)ipByte & (unsigned char)maskByte;
        if ((unsigned char)match != (unsigned char)network[m]){
            maskValid = false;
            break;
        }
    }
    return (maskValid);
}

// class Toolkit::RouteTable
void Toolkit::RouteTable::InitTable()
{
	// workaround for OS that don't support GetRouteTable
	PIPSocket::GetHostAddress(defAddr);
#ifdef hasIPV6
	PIPSocket::GetHostAddress(defAddrV6);
#endif

	ClearTable();
	if (!CreateTable())
		return;

	// get Home IPs (all detected IPs or set through config file)
	std::vector<PIPSocket::Address> home;
	Toolkit::Instance()->GetGKHome(home);
	// if we only have 1 Home IP, then thats also the default IP
	if (home.size() == 1) {
		defAddr = home[0];
#ifdef hasIPV6
		defAddrV6 = home[0];
#endif
	}
	// Bind= always sets the default IP
	PString bind = GkConfig()->GetString("Bind", "");
	if (!bind.IsEmpty()) {
		defAddr = bind;
#ifdef hasIPV6
		defAddrV6 = bind;
#endif
	}

	// if we do not already have a valid entry, try and retrieve the default interface
	if ((defAddr.GetVersion() != 4) || defAddr.IsLoopback() || !defAddr.IsValid()) {
		// Set default IP according to route table
		defAddr = GetDefaultIP(4);
		if ((defAddr.GetVersion() != 4) || defAddr.IsLoopback() || !defAddr.IsValid()) {
			// no default gateway, use first interface as default
			PIPSocket::GetNetworkInterface(defAddr);
		}
	}
#ifdef hasIPV6
	// if we do not already have a valid entry, try and retrieve the default interface
	if ((defAddrV6.GetVersion() != 6) || defAddrV6.IsLoopback() || !defAddrV6.IsValid()) {
		// Set default IP according to route table
		defAddrV6 = GetDefaultIP(6);
		if ((defAddrV6.GetVersion() != 6) || defAddrV6.IsLoopback() || !defAddrV6.IsValid()) {
			// no default gateway, use first interface as default
			PIPSocket::GetNetworkInterface(defAddrV6);
		}
	}
#endif

	// if we have a list of Home IPs and the default address is not in it, use the first IPv4 Home IP,
	// unless the default IP was explicitly specified in Bind=
	if (bind.IsEmpty() &&
		!home.empty() && (find(home.begin(), home.end(), defAddr) == home.end())) {
		for (unsigned i = 0; i < home.size(); ++i) {
			if (home[i].GetVersion() == 4) {
				defAddr = home[i];
				break;
			}
		}
	}
#ifdef hasIPV6
	if (bind.IsEmpty() &&
		!home.empty() && (find(home.begin(), home.end(), defAddrV6) == home.end())) {
		for (unsigned i = 0; i < home.size(); ++i) {
			if (home[i].GetVersion() == 6) {
				defAddrV6 = home[i];
				break;
			}
		}
	}
#endif

	for (RouteEntry *entry = rtable_begin; entry != rtable_end; ++entry) {
		PTRACE(2, "Network=" << NetworkAddress(entry->GetNetwork(), entry->GetNetMask()).AsString() <<
				", IP=" << entry->GetDestination());
	}
#ifdef hasIPV6
	if (Toolkit::Instance()->IsIPv6Enabled())
		PTRACE(2, "Default IP IPv4=" << defAddr << " IPv6=" << defAddrV6);
	else
#endif
	{
		PTRACE(2, "Default IP=" << defAddr);
	}
	if (defAddr.IsLoopback()) {
		PTRACE(1, "WARNING: Your default IP=" << defAddr << " is a loopback address. That probably won't work!");
	}
}

// get default route from route table, because GetGatewayAddress() is broken until PTLib 2.11.1
PIPSocket::Address Toolkit::RouteTable::GetDefaultIP(unsigned version) const
{
	for (RouteEntry *entry = rtable_begin; entry != rtable_end; ++entry) {
		if ((entry->GetNetMask() == 0) && (entry->GetDestination().GetVersion() == version))
			return GetLocalAddress(entry->GetDestination());
	}
	return Address(0);
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

void Toolkit::RouteTable::ClearInternalNetworks()
{
    m_internalnetworks.clear();
}

void Toolkit::RouteTable::AddInternalNetwork(const NetworkAddress & network)
{
	if (find(m_internalnetworks.begin(), m_internalnetworks.end(), network) == m_internalnetworks.end())
		m_internalnetworks.push_back(network);
}

PIPSocket::Address Toolkit::RouteTable::GetLocalAddress(unsigned version) const
{
#ifdef hasIPV6
	if (version == 6)
		return defAddrV6;
#endif
	return defAddr;
}

PIPSocket::Address Toolkit::RouteTable::GetLocalAddress(const Address & addr) const
{
	// look through internal networks and make sure we don't return the external IP for them
	for (unsigned j = 0; j < m_internalnetworks.size(); ++j) {
		if (addr << m_internalnetworks[j]) {
			// check if internal network is in route table, but don't use the default route
			RouteEntry *entry = find_if(rtable_begin, rtable_end,
#if (__cplusplus >= 201703L) // C++17
				bind(mem_fn(&RouteEntry::CompareWithoutMask), std::placeholders::_1, &addr));
#else
				bind2nd(mem_fun_ref(&RouteEntry::CompareWithoutMask), &addr));
#endif
			if ((entry != rtable_end) && (entry->GetNetMask() != INADDR_ANY)
#ifdef hasIPV6
				&& (entry->GetNetMask() != in6addr_any)
#endif
				) {
				return entry->GetDestination();
			}
			else {
#ifdef hasIPV6
				if (addr.GetVersion() == 6)
					return defAddrV6;
#endif
				return defAddr;
			}
		}
	}

	// if external IP is configured
	if (!ExtIP.IsEmpty()) {
		if (DynExtIP) {  // if dynamic resolve DNS entry
			PIPSocket::Address extip;
			H323TransportAddress ex = H323TransportAddress(ExtIP);
			ex.GetIpAddress(extip);
			if (extip.IsValid()) {
				return extip;
			} else {
				PTRACE(2, "NAT\tERROR: External IP " << ExtIP << " unresolvable." );
				SNMP_TRAP(10, SNMPError, Configuration, "External IP " + ExtIP + " unresolvable");
			}
		} else {  // If valid IP then use the ExtIP value
			PIPSocket::Address extip(ExtIP);
			if (extip.IsValid()) {
				return extip;
			} else {
				PTRACE(2, "NAT\tERROR: ExtIP " << ExtIP << " unusable." );
				SNMP_TRAP(10, SNMPError, Configuration, "External IP " + ExtIP + " unusable");
			}
		}
	}
	RouteEntry *entry = find_if(rtable_begin, rtable_end,
#if (__cplusplus >= 201703L) // C++17
		bind(mem_fn(&RouteEntry::CompareWithMask), std::placeholders::_1, &addr));
#else
		bind2nd(mem_fun_ref(&RouteEntry::CompareWithMask), &addr));
#endif
	if (entry != rtable_end) {
		return entry->GetDestination();
	}
#ifdef hasIPV6
	if (addr.GetVersion() == 6) {
		return defAddrV6;
	}
#endif
	return defAddr;
}

bool Toolkit::RouteTable::CreateRouteTable(const PString & extroute)
{
	InterfaceTable if_table;
	if (!PIPSocket::GetInterfaceTable(if_table)) {
		PTRACE(1, "Error: Can't get interface table");
		SNMP_TRAP(10, SNMPError, Configuration, "Error fetching interface table");
		return false;
	}

	PTRACE(4, "InterfaceTable:\n" << setfill('\n') << if_table << setfill(' '));
	PIPSocket::RouteTable r_table;
	if (!PIPSocket::GetRouteTable(r_table)) {
		PTRACE(1, "Error: Can't get route table");
		SNMP_TRAP(10, SNMPError, Configuration, "Error fetching route table");
		return false;
	}
	// filter out route with destination localhost
	// we can't use those for routing calls, unless the net itself is localhost
	for(PINDEX i = 0; i < r_table.GetSize(); ++i) {
		if ((r_table[i].GetDestination().IsLoopback())
			&& !r_table[i].GetNetwork().IsLoopback()) {
				r_table.RemoveAt(i--);
		}
	}
	// filter out IPv6 networks if IPv6 is not enabled
	for(PINDEX i = 0; i < r_table.GetSize(); ++i) {
		if ((r_table[i].GetNetwork().GetVersion() == 6)
			&& !Toolkit::Instance()->IsIPv6Enabled()) {
				r_table.RemoveAt(i--);
		}
	}

	if (AsBool(GkConfig()->GetString(ProxySection, "Enable", "0"))) {
		for (PINDEX i = 0; i < r_table.GetSize(); ++i) {
			if (IsPrivate(r_table[i].GetNetwork())
				&& (r_table[i].GetNetMask().AsString() != "255.255.255.255")
				&& (r_table[i].GetNetMask().AsString() != "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) {
				m_internalnetworks.resize( m_internalnetworks.size() + 1);
				m_internalnetworks[m_internalnetworks.size() - 1] = NetworkAddress(r_table[i].GetNetwork(), r_table[i].GetNetMask());
				PTRACE(2, "Internal Network Detected " << m_internalnetworks.back().AsString());
			}
		}
	}

	PString tmpRoutes = GkConfig()->GetString(ProxySection, "ExplicitRoutes", "");
	PStringArray explicitRoutes;
	if (!tmpRoutes.IsEmpty()) {
		explicitRoutes = tmpRoutes.Tokenise(",", false);
		PString defaultRoute;
		PINDEX e = 0;
		while (e < explicitRoutes.GetSize()) {
			PString explicitRoute = explicitRoutes[e].Trim();
			if (explicitRoute.Left(9) == "0.0.0.0/0" || PCaselessString(explicitRoute.Left(7)) == "default") {
				explicitRoutes.RemoveAt(e);
				defaultRoute = explicitRoute;
			} else {
				RouteEntry entry(explicitRoute);
				if (Toolkit::Instance()->IsGKHome(entry.GetDestination())) {
					PTRACE(2, "Adding explicit route: " << entry.GetNetwork() << "/" << entry.GetNetMask() << "->" << entry.GetDestination());
					e++;
				} else {
					PTRACE(1, "Ignoring explicit route (invalid source IP): "
						<< entry.GetNetwork() << "/" << entry.GetNetMask() << "->" << entry.GetDestination());
					explicitRoutes.RemoveAt(e);
				}
			}
		}
		if (!defaultRoute.IsEmpty()) {
			// replace 0.0.0.0/0 or "default" with 2 routes (0.0.0.0/1 + 128.0.0.0/1), because "0.0.0.0/0" is also treated as invalid network
			if (PCaselessString(defaultRoute.Left(7)) == "default") {
				defaultRoute = PString("0.0.0.0/0") + defaultRoute.Mid(7);
			}
			defaultRoute.Replace("0.0.0.0/0", "0.0.0.0/1");	// 1st part
			// check if source is a Home= IP
			RouteEntry entry(defaultRoute);
			if (Toolkit::Instance()->IsGKHome(entry.GetDestination())) {
				explicitRoutes.AppendString(defaultRoute);
				defaultRoute.Replace("0.0.0.0/1", "128.0.0.0/1");	// 2nd part
				explicitRoutes.AppendString(defaultRoute);
			} else {
				PTRACE(1, "Ignoring explicit default route: Invalid source IP " << entry.GetDestination());
			}
		}
	}

	int i = (!extroute) ? r_table.GetSize()+1 : r_table.GetSize();
	i += explicitRoutes.GetSize();

	rtable_end = rtable_begin = static_cast<RouteEntry *>(::malloc(i * sizeof(RouteEntry)));
	// prepend explicit routes
	for (PINDEX e = 0; e < explicitRoutes.GetSize(); ++e) {
		::new (rtable_end++) RouteEntry(explicitRoutes[e]);
	}
	for (PINDEX r = 0; r < (i - explicitRoutes.GetSize()); ++r) {
		if (!extroute && (r==r_table.GetSize())) {
			::new (rtable_end++) RouteEntry(extroute);
		} else {
			PIPSocket::RouteEntry & r_entry = r_table[r];
			if (!r_entry.GetNetMask().IsAny()) {
				::new (rtable_end++) RouteEntry(r_entry, if_table);
			}
		}
	}

	return true;
}

bool Toolkit::VirtualRouteTable::CreateTable()
{
	PString nets = GkConfig()->GetString("NetworkInterfaces", "");
	if (!nets) {
		PStringArray networks(nets.Tokenise(" ,;\t", FALSE));
		int i = networks.GetSize();
		if (i > 0) {
			rtable_end = rtable_begin = static_cast<RouteEntry *>(::malloc(i * sizeof(RouteEntry)));
			for (PINDEX r = 0; r < i; ++r) {
				::new (rtable_end++) RouteEntry(networks[r]);
			}
		}
	}

	// If we have an external IP setting then load the detected Route Table and add a route for the external IP
	// If dynamic IP then only store the PString value and resolve the DNS when required.
	PString extip = Toolkit::Instance()->GetExternalIP();
    if (!extip.IsEmpty()) {
        DynExtIP = AsBool(GkConfig()->GetString("ExternalIsDynamic", "0"));

        PIPSocket::Address ext((DWORD)0);
        H323TransportAddress ex = H323TransportAddress(extip);
        ex.GetIpAddress(ext);
        if (ext.IsValid()) {
            ExtIP = extip;
            PString extroute;
            if (!DynExtIP)
                extroute = ext.AsString() + "/0";

            CreateRouteTable(extroute);
            PTRACE(1, "External IP=" << ExtIP << " dynamic=" << DynExtIP);
            return true;
        } else
            DynExtIP = false;
    }

	return false;
}

bool Toolkit::VirtualRouteTable::IsMasquerade(PIPSocket::Address & addr) const
{
	if (!ExtIP) {
		H323TransportAddress ex = H323TransportAddress(ExtIP);
		ex.GetIpAddress(addr);
		return true;
	}

	return false;
}

// class Toolkit::ProxyCriterion
Toolkit::ProxyCriterion::ProxyCriterion() : m_enable(false)
{
}

Toolkit::ProxyCriterion::~ProxyCriterion()
{
}

void Toolkit::ProxyCriterion::LoadConfig(PConfig *config)
{
	// read switch for default proxy mode
	m_enable = AsBool(config->GetString(ProxySection, "Enable", "0"));
	if (!m_enable) {
		PTRACE(2, "GK\tH.323 Proxy not enabled by default");
	} else {
		PTRACE(2, "GK\tH.323 Proxy enabled");
	}

	m_internalnetworks.clear();
	m_modeselection.clear();

	PStringArray networks(config->GetString(ProxySection, "InternalNetwork", "").Tokenise(" ,;\t", FALSE));

	// if no networks specified then use the detected values
	int signalRoutingMode = CallRec::Undefined;
	if (RasServer::Instance()->IsGKRouted()) {
		if (RasServer::Instance()->IsH245Routed()) {
			signalRoutingMode = CallRec::H245Routed;
		} else {
			signalRoutingMode = CallRec::SignalRouted;
		}
	}
	NetworkModes internal_netmode;
	internal_netmode.fromExternal = m_enable ? CallRec::Proxied : signalRoutingMode;
	internal_netmode.insideNetwork = signalRoutingMode;
	if (networks.GetSize() == 0) {
		m_internalnetworks = Toolkit::Instance()->GetInternalNetworks();
		for (unsigned j = 0; j < m_internalnetworks.size(); ++j) {
			m_modeselection[m_internalnetworks[j]] = internal_netmode;
			PTRACE(2, "GK\tInternal Network " << j << " = " << m_internalnetworks[j].AsString()
					<< " (" << internal_netmode.fromExternal << "," << internal_netmode.insideNetwork << ")");
		}
	} else {
        m_internalnetworks.clear();
        Toolkit::Instance()->GetRouteTable()->ClearInternalNetworks();
		for (PINDEX i = 0; i < networks.GetSize(); ++i) {
			m_internalnetworks.push_back(networks[i]);
			Toolkit::Instance()->GetRouteTable()->AddInternalNetwork(networks[i]);
			m_modeselection[networks[i]] = internal_netmode;
			PTRACE(2, "GK\tINI Internal Network " << i << " = " << m_internalnetworks[i].AsString()
					<< " (" << internal_netmode.fromExternal << "," << internal_netmode.insideNetwork << ")");
		}
	}

	// read [ModeSelection] section
	PStringToString mode_rules(config->GetAllKeyValues("ModeSelection"));
	if (mode_rules.GetSize() > 0) {
		// if we have ModeSelection rules, only use those, don't try to merge them with detected
		m_modeselection.clear();
	}
	for (PINDEX i = 0; i < mode_rules.GetSize(); ++i) {
		PString network = mode_rules.GetKeyAt(i);
		if (!network.IsEmpty()) {
			PStringArray modes((mode_rules.GetDataAt(i)).Tokenise(" ,;\t", FALSE));
			if (modes.GetSize() >= 1 && modes.GetSize() <= 2) {
				NetworkAddress addr = NetworkAddress(network);
				NetworkModes netmode;
				netmode.fromExternal = ToRoutingMode(modes[0].Trim());
				netmode.insideNetwork = netmode.fromExternal;
				if (modes.GetSize() == 2)
					netmode.insideNetwork = ToRoutingMode(modes[1].Trim());
				// replace 0.0.0.0/0 with 2 rules (0.0.0.0/1 + 128.0.0.0/1), because 0.0.0.0/0 is also treated as invalid network
				if (network == "0.0.0.0/0" || network == PCaselessString("default")) {
					m_modeselection[NetworkAddress("0.0.0.0/1")] = netmode;
					PTRACE(2, "GK\tModeSelection rule: 0.0.0.0/1=" << netmode.fromExternal << "," << netmode.insideNetwork);
					m_modeselection[NetworkAddress("128.0.0.0/1")] = netmode;
					PTRACE(2, "GK\tModeSelection rule: 128.0.0.0/1=" << netmode.fromExternal << "," << netmode.insideNetwork);
				} else {
					m_modeselection[addr] = netmode;
					PTRACE(2, "GK\tModeSelection rule: " << addr.AsString() << "=" << netmode.fromExternal << "," << netmode.insideNetwork);
				}
			} else {
				PTRACE(1, "GK\tInvalid ModeSelection rule: " << mode_rules.GetKeyAt(i) << "=" << mode_rules.GetDataAt(i) );
			}
		}
	}
}

int Toolkit::ProxyCriterion::ToRoutingMode(const PCaselessString & mode) const
{
	if (mode == "Routed")
		return CallRec::SignalRouted;
	else if (mode == "H245Routed")
		return CallRec::H245Routed;
	else if (mode == "Proxy")
		return CallRec::Proxied;
	else
		return CallRec::Undefined;
}

// returns network for the rule or IsAny() when no is rule found
NetworkAddress Toolkit::ProxyCriterion::FindModeRule(const NetworkAddress & ip) const
{
	NetworkAddress bestmatch;

	std::map<NetworkAddress, NetworkModes>::const_iterator iter = m_modeselection.begin();
	while (iter != m_modeselection.end()) {
		if ((ip << iter->first) && (iter->first.GetNetmaskLen() >= bestmatch.GetNetmaskLen())) {
			bestmatch = iter->first;
		}
		++iter;
	}

	return bestmatch;
}

int Toolkit::ProxyCriterion::SelectRoutingMode(const Address & ip1, const Address & ip2) const
{
	// default mode
	int mode = m_enable ? CallRec::Proxied : CallRec::SignalRouted;
	if (mode == CallRec::SignalRouted && RasServer::Instance()->IsH245Routed())
		mode = CallRec::H245Routed;
	PTRACE(5, "ModeSelection for " << ip1.AsString() << " -> " << ip2.AsString() << " default=" << mode);

	// check if we have a more specific setting
	NetworkAddress bestMatchIP1 = FindModeRule(ip1);
	NetworkAddress bestMatchIP2 = FindModeRule(ip2);

	std::map<NetworkAddress, NetworkModes>::const_iterator iter;
	// check for same network
	if (!bestMatchIP1.IsAny() && !bestMatchIP2.IsAny()) {
		// rules for both IPs
		if (bestMatchIP1.Compare(bestMatchIP2) == 0) {
			// both on same network
			iter = m_modeselection.find(bestMatchIP1);
			if (iter != m_modeselection.end()) {
				mode = iter->second.insideNetwork;
				PTRACE(5, "ModeSelection: Both IPs on same network: mode=" << mode);
			}
		} else {
			// on different networks, use maximum proxying
			iter = m_modeselection.find(bestMatchIP1);
			int mode1 = iter->second.fromExternal;	// no check, must exist
			iter = m_modeselection.find(bestMatchIP2);
			int mode2 = iter->second.fromExternal;	// no check, must exist
			mode = max(mode1, mode2);
			PTRACE(5, "ModeSelection: Both IPs on different networks: mode1=" << mode1 << " mode2=" << mode2 << " => " << mode);
		}
	} else {
		// only one rule, use that
		if (!bestMatchIP1.IsAny()) {
			iter = m_modeselection.find(bestMatchIP1);
			if (iter != m_modeselection.end()) {
				mode = iter->second.fromExternal;
				PTRACE(5, "ModeSelection: Only rule for IP 1 = " << ip1.AsString() << " mode=" << mode);
			}
		}
		if (!bestMatchIP2.IsAny()) {
			iter = m_modeselection.find(bestMatchIP2);
			if (iter != m_modeselection.end()) {
				mode = iter->second.fromExternal;
				PTRACE(5, "ModeSelection: Only rule for IP 2 = " << ip2.AsString() << " mode=" << mode);
			}
		}
	}

	return mode;
}

int Toolkit::ProxyCriterion::IsInternal(const Address & ip) const
{
	// Return the network Id. Addresses may be on different internal networks
	int retval = 0;
	std::vector<NetworkAddress>::const_iterator i = m_internalnetworks.begin();
	while (i != m_internalnetworks.end()) {
		retval++;
		if (ip << *i++)
			return retval;
	}
	return 0;
}

// class Toolkit::RewriteTool

static const char *RewriteSection = "RasSrv::RewriteE164";
static const char *AliasRewriteSection = "RasSrv::RewriteAlias";
static const char *AssignedAliasSection = "RasSrv::AssignedAlias";
#ifdef h323v6
static const char *AssignedGatekeeperSection = "RasSrv::AssignedGatekeeper";
#endif
static const char *ModeVendorSection = "ModeVendorSelection";

void Toolkit::RewriteData::AddSection(PConfig * config, const PString & section)
{
	PStringToString cfgs(config->GetAllKeyValues(section));
	PINDEX n_size = cfgs.GetSize();
	if (n_size > 0) {
		std::map<PString, PString, pstr_prefix_lesser> rules;
		for (PINDEX i = 0; i < n_size; ++i) {
			PString key = cfgs.GetKeyAt(i);
			PCaselessString first = PCaselessString(key[0]);
			if (!key && (isdigit(static_cast<unsigned char>(key[0])) || (first.FindOneOf("+!.%*#ABCDEFGHIGKLMNOPQRSTUVWXYZ") != P_MAX_INDEX)))
				rules[key] = cfgs.GetDataAt(i);
		}
		// now the rules are ascendantly sorted by the keys
		if ((n_size = rules.size()) > 0) {
			// add any existing rules to be resorted
			if (m_size > 0) {
				for (PINDEX j = 0; j < m_size; ++j) {
					rules[Key(j)] = Value(j);
				}
			}
			m_size = m_size + n_size;
			// replace array constructor with explicit memory allocation
			// and in-place new operators - workaround for VC compiler
			m_RewriteKey = (PString*)(new BYTE[sizeof(PString) * m_size * 2]);
			m_RewriteValue = m_RewriteKey + m_size;
			std::map<PString, PString, pstr_prefix_lesser>::iterator iter = rules.begin();

			// reverse the order
			for (int i = m_size; i-- > 0; ++iter) {
				::new(m_RewriteKey + i) PString(iter->first);
				::new(m_RewriteValue + i) PString(iter->second);
			}
		}
	}
}
Toolkit::RewriteData::RewriteData(PConfig *config, const PString & section)
{
	m_RewriteKey = NULL;
	m_RewriteValue = NULL;
	m_size = 0;
    AddSection(config, section);
}

Toolkit::RewriteData::~RewriteData()
{
	if (m_RewriteKey) {
		for (int i = 0; i < m_size * 2; i++) {
			(m_RewriteKey+i)->~PString();
		}
	}
	delete[] ((BYTE*)m_RewriteKey);
}

void Toolkit::RewriteTool::LoadConfig(PConfig *config)
{
	m_RewriteFastmatch = config->GetString(RewriteSection, "Fastmatch", "");
	m_TrailingChar = config->GetString("RasSrv::ARQFeatures", "RemoveTrailingChar", " ")[0];
	PString defDomain = config->GetString("Gatekeeper::Main", "DefaultDomain", "");
	m_defaultDomain = defDomain.Tokenise(",");
	m_externalIP = config->GetString("Gatekeeper::Main", "ExternalIP", "");
	delete m_Rewrite;
	m_Rewrite = new RewriteData(config, RewriteSection);
	m_Rewrite->AddSection(config,AliasRewriteSection);
}

bool Toolkit::RewriteTool::RewritePString(PString & s) const
{
	bool changed = false;

	// remove trailing character TODO: loop and replace multiple chars ?
	if (s.GetLength() > 1 && s[s.GetLength() - 1] == m_TrailingChar) {
		s = s.Left(s.GetLength() - 1);
		changed = true;
	}

	// if URL remove the domain if default domain
	PINDEX at = s.Find('@');
	if (at != P_MAX_INDEX) {
		PString num = s.Left(at);
		if (num.Left(5) *= "h323:") num = num.Mid(5);
		PString domain = s.Mid(at+1);
		PIPSocket::Address domIP(domain);

		// Check if we have a default domain and strip it
		for (PINDEX i = 0; i < m_defaultDomain.GetSize(); i++) {
			if (domain == m_defaultDomain[i]) {
				PTRACE(2, "\tRewriteDomain (default domain): " << s << " to " << num);
				s = num;
				changed = true;
				break;
			}
		}

		// Check that the domain is not a local IP address.
		if (!changed && domIP.IsValid() && Toolkit::Instance()->IsGKHome(domIP)) {
			PTRACE(2, "\tRemoveDomain (local IP): " << domain << " to " << num);
			s = num;
			changed = true;
		}
		if (!changed && domIP.IsValid() && !m_externalIP.IsEmpty() && domIP.AsString() == m_externalIP) {
			PTRACE(2, "\tRemoveDomain (external IP): " << domain << " to " << num);
			s = num;
			changed = true;
		}
	}

	// startsWith?
	if (strncmp(s, m_RewriteFastmatch, m_RewriteFastmatch.GetLength()) != 0)
		return changed;

	PString t;
	for (PINDEX i = 0; i < m_Rewrite->Size(); ++i) {
		const char *prefix = m_Rewrite->Key(i);
		if (prefix == s){
			s = m_Rewrite->Value(i);
			return true;
		}
		const int len = MatchPrefix(s, prefix);
		// try a prefix match through all keys
		if (len > 0 || (len == 0 && prefix[0] == '!')) {
			// Rewrite to #t#. Append the suffix, too.
			// old:  01901234999
			//               999 Suffix
			//       0190        Fastmatch
			//       01901234    prefix, Config-Rule: 01901234=0521321
			// new:  0521321999

			const char *newprefix = m_Rewrite->Value(i);

			PString result;
			if (len > 0) {
				PString unused;
				result = RewriteString(s, prefix, newprefix, unused);
			} else
				result = newprefix + s;

			PTRACE(2, "\tRewritePString: " << s << " to " << result);
			s = result;
			changed = true;

			break;
		}
	}

	return changed;
}

// class Toolkit::GWRewriteTool

static const char *GWRewriteSection = "RasSrv::GWRewriteE164";

Toolkit::GWRewriteTool::~GWRewriteTool()
{
	for (PINDEX i = 0; i < m_GWRewrite.GetSize(); ++i) {
		delete &(m_GWRewrite.GetDataAt(i));
	}
	m_GWRewrite.RemoveAll();
}

bool Toolkit::GWRewriteTool::RewritePString(const PString & gw, bool direction, PString & data, callptr call)
{
	// First lookup the GW in the dictionary
	GWRewriteEntry * gw_entry = m_GWRewrite.GetAt(gw);

	if (gw_entry == NULL)
		return false;

	std::vector<pair<PString, PString> >::iterator rule_iterator = direction
		? gw_entry->m_entry_data.first.begin() : gw_entry->m_entry_data.second.begin();
	std::vector<pair<PString, PString> >::iterator end_iterator = direction
		? gw_entry->m_entry_data.first.end() : gw_entry->m_entry_data.second.end();

	PString key, value;
	for (; rule_iterator != end_iterator; ++rule_iterator) {
		key = (*rule_iterator).first;

		bool postdialmatch = false;
		if (key.Find("I") != P_MAX_INDEX) {
			postdialmatch = true;
			key.Replace("I", ".", true);
		}

		const int len = MatchPrefix(data, key);
		if (len > 0 || (len == 0 && key[0] == '!')) {
			// Start rewrite
			value = (*rule_iterator).second;

			PString postdialdigits;
			if (postdialmatch) {
				value.Replace("P", ".", true);
			}

			if (len > 0) {
				value = RewriteString(data, key, value, postdialdigits, postdialmatch);
				if (call && postdialmatch && !postdialdigits.IsEmpty()) {
					call->SetPostDialDigits(postdialdigits);
				}
			} else
				value = value + data;

			// Log
			PTRACE(2, "\tGWRewriteTool::RewritePString: " << data << " to " << value << " post dial digits=" << postdialdigits);

			// Finish rewrite
			data = value;
			return true;
		}
	}

	return false;
}

void Toolkit::GWRewriteTool::PrintData()
{
	std::vector<pair<PString,PString> >::iterator rule_iterator;

	PTRACE(2, "GK\tLoaded per GW rewrite data:");

	if (m_GWRewrite.GetSize() == 0) {
		PTRACE(2, "GK\tNo per GW data loaded");
		return;
	}

	if (PTrace::CanTrace(3) && (m_GWRewrite.GetSize() < 100)) {
		for (PINDEX i = 0; i < m_GWRewrite.GetSize(); ++i) {
			// In
			for (rule_iterator = m_GWRewrite.GetDataAt(i).m_entry_data.first.begin(); rule_iterator != m_GWRewrite.GetDataAt(i).m_entry_data.first.end(); ++rule_iterator) {
				PTRACE(3, "GK\t" << m_GWRewrite.GetKeyAt(i) << " (in): " << (*rule_iterator).first << " = " << (*rule_iterator).second);
			}

			// Out
			for (rule_iterator = m_GWRewrite.GetDataAt(i).m_entry_data.second.begin(); rule_iterator != m_GWRewrite.GetDataAt(i).m_entry_data.second.end(); ++rule_iterator) {
				PTRACE(3, "GK\t" << m_GWRewrite.GetKeyAt(i) << " (out): " << (*rule_iterator).first << " = " << (*rule_iterator).second);
			}
		}
	}
	PTRACE(2, "GK\tLoaded " << m_GWRewrite.GetSize() << " GW entries with rewrite info");
}


void Toolkit::GWRewriteTool::LoadConfig(PConfig * config)
{
	std::map<PString, PString> in_strings, out_strings;
	vector<std::pair<PString, PString> > sorted_in_strings, sorted_out_strings;
	std::map<PString, PString>::reverse_iterator strings_iterator;
	pair<PString, PString> rule;

	PStringToString cfgs(config->GetAllKeyValues(GWRewriteSection));

	// Clear old config
	for (PINDEX i = 0; i < m_GWRewrite.GetSize(); ++i) {
		delete &(m_GWRewrite.GetDataAt(i));
	}
	m_GWRewrite.RemoveAll();

	PINDEX gw_size = cfgs.GetSize();
	if (gw_size > 0) {
		for (PINDEX i = 0; i < gw_size; ++i) {
			// Get the config keys
			PString key = cfgs.GetKeyAt(i);
			PString cfg_value = cfgs[key];

			in_strings.clear();
			out_strings.clear();
			sorted_in_strings.clear();
			sorted_out_strings.clear();

			// Split the config data into separate lines
			PStringArray lines = cfg_value.Tokenise(PString(";"));
			PINDEX lines_size = lines.GetSize();

			for (PINDEX j = 0; j < lines_size; ++j) {
				// Split the config line into three strings, direction, from string, to string
				PStringArray tokenised_line = lines[j].Tokenise(PString("="));

				if (tokenised_line.GetSize() < 3) {
					PTRACE(1, "GK\tSyntax error in the GWRewriteE164 rule - missing =, rule: "
						<< key << " => " << lines[j]);
					SNMP_TRAP(7, SNMPError, Configuration, "Invalid [GWRewriteE164] configuration");
					continue;
				}

				// Put into appropriate std::map
				if (tokenised_line[0] == "in")
					in_strings[tokenised_line[1]] = tokenised_line[2];
				else if (tokenised_line[0] == "out")
					out_strings[tokenised_line[1]] = tokenised_line[2];
				else {
					PTRACE(1, "GK\tSyntax error in the GWRewriteE164 rule - unknown rule type ("
						<< tokenised_line[0] << ", rule: " << key << " => " << lines[j]);
					SNMP_TRAP(7, SNMPError, Configuration, "Invalid [GWRewriteE164] configuration");
				}
			}

			// Put the map contents into reverse sorted vectors
			for (strings_iterator = in_strings.rbegin(); strings_iterator != in_strings.rend(); ++strings_iterator) {
				rule = *strings_iterator;
				sorted_in_strings.push_back(rule);
			}
			for (strings_iterator = out_strings.rbegin(); strings_iterator != out_strings.rend(); ++strings_iterator) {
				rule = *strings_iterator;
				sorted_out_strings.push_back(rule);
			}

			// Create the entry
			GWRewriteEntry * gw_entry = new GWRewriteEntry();
			gw_entry->m_entry_data.first = sorted_in_strings;
			gw_entry->m_entry_data.second = sorted_out_strings;

			// Add to PDictionary hash table
			m_GWRewrite.Insert(key, gw_entry);
		}
	}

	PrintData();
}

// class Toolkit::VendorModeTool

void Toolkit::VendorModeTool::LoadConfig(PConfig * config)
{
	delete m_vendorInfo;
	m_vendorInfo = new Toolkit::VendorData(config, ModeVendorSection);
}

int Toolkit::VendorModeTool::ModeSelection(const PString & str) const
{
	if (str.IsEmpty())
		return CallRec::Undefined;

	for (PINDEX i = 0; i < m_vendorInfo->Size(); ++i) {
		PString match = m_vendorInfo->Key(i);
		if (str.Find(match) != P_MAX_INDEX) {
			PCaselessString mode = m_vendorInfo->Value(i);
			if (mode == "Routed")
				return CallRec::SignalRouted;
			 else if (mode == "H245Routed")
				return CallRec::H245Routed;
			else if (mode == "Proxy")
				return CallRec::Proxied;
		}
	}
	return CallRec::Undefined;
}

Toolkit::VendorData::VendorData(PConfig *config, const PString & section)
    : m_VendorKey(NULL), m_VendorValue(NULL), m_size(0)
{
	AddSection(config, section);
}

void Toolkit::VendorData::AddSection(PConfig * config, const PString & section)
{
	PStringToString cfgs(config->GetAllKeyValues(section));
	PINDEX n_size = cfgs.GetSize();
	if (n_size > 0) {
		std::map<PString, PString, pstr_prefix_lesser> rules;
		for (PINDEX i = 0; i < n_size; ++i) {
			PString key = cfgs.GetKeyAt(i);
			PCaselessString first = PCaselessString(key[0]);
			rules[key] = cfgs.GetDataAt(i);
		}
		// now the rules are ascendantly sorted by the keys
		if ((n_size = rules.size()) > 0) {
			// Add any existing rules to be resorted
			if (m_size > 0) {
				for (PINDEX j = 0; j < m_size; ++j) {
					rules[Key(j)] = Value(j);
				}
			}
			m_size = m_size + n_size;
			m_VendorKey = (PString*)(new BYTE[sizeof(PString) * m_size * 2]);
			m_VendorValue = m_VendorKey + m_size;
			std::map<PString, PString, pstr_prefix_lesser>::iterator iter = rules.begin();

			// reverse the order
			for (int i = m_size; i-- > 0; ++iter) {
				::new(m_VendorKey + i) PString(iter->first);
				::new(m_VendorValue + i) PString(iter->second);
			}
		}
	}
}

Toolkit::VendorData::~VendorData()
{
	if (m_VendorKey) {
		for (int i = 0; i < m_size * 2; i++) {
			(m_VendorKey+i)->~PString();
		}
	}
	delete[] ((BYTE*)m_VendorKey);
}



Toolkit::Toolkit() : Singleton<Toolkit>("Toolkit"),
	m_Config(NULL), m_ConfigDirty(false),
	m_acctSessionCounter(0), m_acctSessionBase((long)time(NULL)),
    m_maintenanceMode(false), m_timerManager(new GkTimerManager()),
	m_timestampFormatStr("Cisco"),
	m_encKeyPaddingByte(-1), m_encryptAllPasswords(false),
	m_cliRewrite(NULL), m_causeCodeTranslationActive(false),
	m_H46026Enabled(false), m_licenseValid(false),
	m_snmpEnabled(false), m_ipv6Enabled(false)
{
	srand((unsigned int)time(NULL));
#ifdef P_SSL
	m_OpenSSLInitialized = false;
#endif // P_SSL
#ifdef HAS_TLS
	m_sslCtx = NULL;
#endif
    // real values are set in ReloadConfig()
    m_alwaysRemoveH235Tokens = false;
#ifdef HAS_H235_MEDIA
	m_H235HalfCallMediaEnabled = false;
	m_H235HalfCallMediaKeyUpdatesEnabled = false;
#endif
	// is H460.18 enabled ?
#ifdef HAS_H46018
	m_H46018Enabled = false;
#endif
	// is H460.23 enabled ?
#ifdef HAS_H46023
	m_H46023Enabled = false;
#endif // HAS_H46023
#ifdef HAS_LIBCURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif // HAS_LIBCURL
}

Toolkit::~Toolkit()
{
#ifdef HAS_H460P
	m_presence.Stop();
#endif
#ifdef HAS_TLS
	if (m_sslCtx)
		SSL_CTX_free(m_sslCtx);
#endif
#ifdef HAS_LIBCURL
    curl_global_cleanup();
#endif // HAS_LIBCURL
	if (m_Config) {
		delete m_Config;
		PFile::Remove(m_tmpconfig);
		PFile::Remove(m_extConfigFilePath);
	}
	delete m_timerManager;
	delete m_cliRewrite;
}

Toolkit::RouteTable * Toolkit::GetRouteTable(bool real)
{
	return real ? &m_RouteTable : m_VirtualRouteTable.IsEmpty() ? &m_RouteTable : &m_VirtualRouteTable;
}

PConfig * Toolkit::Config()
{
	// Make sure the config would not be called before SetConfig
	if (m_ConfigDefaultSection.IsEmpty()) {
		PTRACE(0, "Error: Call Config() before SetConfig()!");
		return NULL;
	}
	return (m_Config == NULL) ? ReloadConfig() : m_Config;
}

PConfig * Toolkit::Config(const char * section)
{
	Config()->SetDefaultSection(section);
	return m_Config;
}

PConfig* Toolkit::SetConfig(const PFilePath & fp, const PString &section)
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

PString Toolkit::GetTempDir() const
{
	PString tmpdir;

#if !defined(_WIN32) && !defined(_WIN64)
	// check if the directory exists and is accessible (access rights)
	if (PFile::Exists("/tmp") && PFile::Access("/tmp", PFile::ReadWrite))
		tmpdir = "/tmp";
	else
#endif
	{
		PConfig cfg(PConfig::Environment);

		if (cfg.HasKey("TMP"))
			tmpdir = cfg.GetString("TMP");
		else if (cfg.HasKey("TEMP"))
			tmpdir = cfg.GetString("TEMP");
		else if (cfg.HasKey("TMPDIR"))
			tmpdir = cfg.GetString("TMPDIR");
	}

	if (!tmpdir.IsEmpty()) {
		// strip trailing separator
		if (tmpdir[tmpdir.GetLength()-1] == PDIR_SEPARATOR)
			tmpdir = tmpdir.Left(tmpdir.GetLength()-1);

		// check if the directory exists and is accessible (access rights)
		if (!(PFile::Exists(tmpdir) && PFile::Access(tmpdir, PFile::ReadWrite)))
			tmpdir = PString::Empty();
	}

	return tmpdir;
}

void Toolkit::CreateConfig()
{
	if (m_Config != NULL)
		PFile::Remove(m_tmpconfig);

	PString tmpdir = GetTempDir();

#if _WIN32 || _WIN64
	if (tmpdir.IsEmpty())
		if (PFile::Access(".", PFile::ReadWrite))
			tmpdir = ".";
		else {
			const PFilePath fpath(m_ConfigFilePath);
			tmpdir = fpath.GetDirectory();
		}
#else
	if (tmpdir.IsEmpty())
		tmpdir = ".";
#endif

	// generate a unique name
	do {
		m_tmpconfig = tmpdir + PDIR_SEPARATOR + "gnugk.ini-" + PString(PString::Unsigned, rand() % 10000);
		PTRACE(5, "GK\tTrying file name "<< m_tmpconfig << " for temp config");
	} while (PFile::Exists(m_tmpconfig));

#if _WIN32 || _WIN64
	if (PFile::Copy(m_ConfigFilePath, m_tmpconfig)) {
#else
	if (symlink(m_ConfigFilePath, m_tmpconfig) == 0) {
#endif
		PConfig * testConfig = new PConfig(m_tmpconfig, m_ConfigDefaultSection);
		if (testConfig->GetSections().GetSize() > 0) {
			delete m_Config;
			m_Config = testConfig;
		} else {
			if (m_Config) {	// reload
				PTRACE(0, "CONFIG\tFailed to read valid config - keeping old config");
				SNMP_TRAP(6, SNMPError, General, "Failed to read config");
				GkStatus::Instance()->SignalStatus("Failed to read valid config - keeping old config\r\n", MIN_STATUS_TRACE_LEVEL);
			} else {	// startup
				m_Config = testConfig;	// warning will be printed a bit later
			}
		}
	} else { // Oops! Create temporary config file failed, use the original one
		if (PFile::Exists(m_ConfigFilePath)) {
			PTRACE(0, "CONFIG\tCould not create/link config to a temporary file " << m_tmpconfig);
			SNMP_TRAP(6, SNMPError, General, "Failed to load config");
		}
		delete m_Config;
		m_Config = new PConfig(m_ConfigFilePath, m_ConfigDefaultSection);
	}

	if (!m_extConfigFilePath)
		PFile::Remove(m_extConfigFilePath);

	// generate a unique name
	do {
		m_extConfigFilePath = tmpdir + PDIR_SEPARATOR + "gnugk.ini-" + PString(PString::Unsigned, rand() % 10000);
		PTRACE(5, "GK\tTrying file name "<< m_extConfigFilePath << " for external config");
	} while (PFile::Exists(m_extConfigFilePath));

	m_Config = new GatekeeperConfig(m_extConfigFilePath, m_ConfigDefaultSection, m_Config);
}

void Toolkit::ReloadSQLConfig()
{
#if HAS_DATABASE
	if (m_Config->GetSections().GetStringsIndex("SQLConfig") == P_MAX_INDEX)
		return;

	// TODO: if SQLConfig is configured, but we can't connect to DB, should we shut down GnuGk ?
	const PString driverName = m_Config->GetString("SQLConfig", "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(1, "SQLCONF\tFailed to read config settings from SQL: no driver specified");
		SNMP_TRAP(5, SNMPError, Database, "SQLConfig: no driver");
		return;
	}

	GkSQLConnection *sqlConn = GkSQLConnection::Create(driverName, "SQLCONF");
	if (sqlConn == NULL) {
		PTRACE(1, "SQLCONF\tFailed to create a connection: no driver found for "
				<< driverName << " database");
		SNMP_TRAP(5, SNMPError, Database, "SQLConfig: no driver");
		return;
	}

	if (!sqlConn->Initialize(m_Config, "SQLConfig")) {
		delete sqlConn;
		sqlConn = NULL;
		PTRACE(1, "SQLCONF\tFailed to read config settings from SQL: could not connect to the database");
		SNMP_TRAP(5, SNMPError, Database, "SQLConfig: can't connect to DB");
		return;
	}

	PTRACE(3, "SQLCONF\tSQL config connection established");

	PString query;
	GkSQLResult * queryResult = NULL;

	query = m_Config->GetString("SQLConfig", "ConfigQuery", "");
	if (!query.IsEmpty()) {
		PTRACE(4, "SQLCONF\tLoading config key=>value pairs from SQL database");
		PStringArray params;
		params += GKName();
		queryResult = sqlConn->ExecuteQuery(query, &params);
		if (queryResult == NULL) {
			PTRACE(1, "SQLCONF\tFailed to load config key=>value pairs from SQL database: timeout or fatal error");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: query failed");
		} else if (!queryResult->IsValid()) {
			PTRACE(1, "SQLCONF\tFailed to load config key=>value pairs from SQL database (" << queryResult->GetErrorCode() << "): "
				<< queryResult->GetErrorMessage());
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: query failed");
		} else if (queryResult->GetNumRows() > 0 && queryResult->GetNumFields() < 3) {
			PTRACE(1, "SQLCONF\tFailed to load config key=>value pairs from SQL database: at least 3 columns must be present in the result set");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: query failed");
		} else {
			while (queryResult->FetchRow(params))
				if (params[0].IsEmpty() || params[1].IsEmpty()) {
					PTRACE(1, "SQLCONF\tInvalid config key=>value pair entry found in the SQL database: '[" << params[0] << "] "
						<< params[1] << '=' << params[1] << '\'');
					SNMP_TRAP(5, SNMPError, Database, "SQLConfig: query failed");
				} else {
					m_Config->SetString(params[0], params[1], params[2]);
					PTRACE(6, "SQLCONF\tConfig entry read: '[" << params[0] << "] " << params[1] << '=' << params[2] << '\'');
				}
			PTRACE(4, "SQLCONF\t" << queryResult->GetNumRows() << " config key=>value pairs loaded from SQL database");
		}
		delete queryResult;
		queryResult = NULL;
	}

	// Rewrite E164
	query = m_Config->GetString("SQLConfig", "RewriteE164Query", "");
	if (!query.IsEmpty()) {
		PTRACE(4, "SQLCONF\tLoading E164 rewrite rules from SQL database");
		PStringArray params;
		params += GKName();
		queryResult = sqlConn->ExecuteQuery(query, &params);
		if (queryResult == NULL) {
			PTRACE(1, "SQLCONF\tFailed to load E164 rewrite rules from SQL database: timeout or fatal error");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: E.164 query failed");
		} else if (!queryResult->IsValid()) {
			PTRACE(1, "SQLCONF\tFailed to load E164 rewrite rules from SQL database ("
				<< queryResult->GetErrorCode() << "): " << queryResult->GetErrorMessage());
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: E.164 query failed");
		} else if (queryResult->GetNumRows() > 0 && queryResult->GetNumFields() < 2) {
			PTRACE(1, "SQLCONF\tFailed to load E164 rewrite rules from SQL database: "
				"at least 2 columns must be present in the result set");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: E.164 query failed");
		} else {
			while (queryResult->FetchRow(params))
				if (params[0].IsEmpty()) {
					PTRACE(1, "SQLCONF\tInvalid E164 rewrite rule found in the SQL "
						"database: '" << params[0] << '=' << params[1] << '\'');
					SNMP_TRAP(5, SNMPError, Database, "SQLConfig: E.164 query failed");
				} else {
					m_Config->SetString("RasSrv::RewriteE164", params[0], params[1]);
					PTRACE(6, "SQLCONF\tRewriteE164 rule read: '" << params[0]
						<< '=' << params[1] << '\'');
				}
			PTRACE(4, "SQLCONF\t" << queryResult->GetNumRows() << " E164 rewrite rules loaded from SQL database");
		}
		delete queryResult;
		queryResult = NULL;
	}

	// Rewrite Alias Query
	query = m_Config->GetString("SQLConfig", "RewriteAliasQuery", "");
	if (!query.IsEmpty()) {
		PTRACE(4, "SQLCONF\tLoading rewrite rules from SQL database");
		PStringArray params;
		params += GKName();
		queryResult = sqlConn->ExecuteQuery(query, &params);
		if (queryResult == NULL) {
			PTRACE(1, "SQLCONF\tFailed to load Alias rewrite rules from SQL database: timeout or fatal error");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Alias rewrite query failed");
		} else if (!queryResult->IsValid()) {
			PTRACE(1, "SQLCONF\tFailed to load Alias rewrite rules from SQL database ("
				<< queryResult->GetErrorCode() << "): " << queryResult->GetErrorMessage());
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Alias rewrite query failed");
		} else if (queryResult->GetNumRows() > 0 && queryResult->GetNumFields() < 2) {
			PTRACE(1, "SQLCONF\tFailed to load Alias rewrite rules from SQL database: "
				"at least 2 columns must be present in the result set");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Alias rewrite query failed");
		} else {
			while (queryResult->FetchRow(params))
				if (params[0].IsEmpty()) {
					PTRACE(1, "SQLCONF\tInvalid Alias rewrite rule found in the SQL "
						"database: '" << params[0] << '=' << params[1] << '\'');
					SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Alias rewrite query failed");
				} else {
					m_Config->SetString("RasSrv::RewriteAlias", params[0], params[1]);
					PTRACE(6, "SQLCONF\tRewriteAlias rule read: '" << params[0] << '=' << params[1] << '\'');
				}
			PTRACE(4, "SQLCONF\t" << queryResult->GetNumRows() << " Alias rewrite rules loaded from SQL database");
		}
		delete queryResult;
		queryResult = NULL;
	}

	// Assigned Alias Query
	query = m_Config->GetString("SQLConfig", "AssignedAliasQuery", "");
	if (!query.IsEmpty()) {
		PTRACE(4, "SQLCONF\tLoading Assigned Alias rules from SQL database");
		PStringArray params;
		params += GKName();
		queryResult = sqlConn->ExecuteQuery(query, &params);
		if (queryResult == NULL) {
			PTRACE(1, "SQLCONF\tFailed to load Assigned Alias rules from SQL database: timeout or fatal error");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Assigned Alias rewrite query failed");
		} else if (!queryResult->IsValid()) {
			PTRACE(1, "SQLCONF\tFailed to load Assigned Alias rules from SQL database ("
				<< queryResult->GetErrorCode() << "): " << queryResult->GetErrorMessage());
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Assigned Alias rewrite query failed");
		} else if (queryResult->GetNumRows() > 0 && queryResult->GetNumFields() < 2) {
			PTRACE(1, "SQLCONF\tFailed to load Assigned Alias rules from SQL database: "
				"at least 2 columns must be present in the result set");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Assigned Alias rewrite query failed");
		} else {
			while (queryResult->FetchRow(params))
				if (params[0].IsEmpty()) {
					PTRACE(1, "SQLCONF\tInvalid Assigned Alias rule found in the SQL "
						"database: '" << params[0] << '=' << params[1] << '\'');
					SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Assigned Alias rewrite query failed");
				} else {
					m_Config->SetString("RasSrv::AssignedAlias", params[0], params[1]);
					PTRACE(6, "SQLCONF\tAssignedAlias rule read: '" << params[0] << '=' << params[1] << '\'');
				}
			PTRACE(4, "SQLCONF\t" << queryResult->GetNumRows() << " Assigned Alias rules loaded from SQL database");
		}
		delete queryResult;
		queryResult = NULL;
	}
	// Neighbor Query (old style)
	query = m_Config->GetString("SQLConfig", "NeighborsQuery", "");
	if (!query.IsEmpty()) {
		PTRACE(4, "SQLCONF\tLoading neighbors from SQL database");
		PStringArray params;
		params += GKName();
		queryResult = sqlConn->ExecuteQuery(query, &params);
		if (queryResult == NULL) {
			PTRACE(1, "SQLCONF\tFailed to load neighbors from SQL database: timeout or fatal error");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Neighbor query failed");
		} else if (!queryResult->IsValid()) {
			PTRACE(1, "SQLCONF\tFailed to load neighbors from SQL database ("
				<< queryResult->GetErrorCode() << "): " << queryResult->GetErrorMessage());
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Neighbor query failed");
		} else if (queryResult->GetNumRows() > 0 && queryResult->GetNumFields() < 6) {
			PTRACE(1, "SQLCONF\tFailed to load neighbors from SQL database: "
				"at least 6 columns must be present in the result set");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Neighbor query failed");
		} else {
			while (queryResult->FetchRow(params)) {
				PString value;
				if (!params[5])
					value = ";" + params[5];
				if (!(params[4].IsEmpty() && value.IsEmpty()))
					value = ";" + params[4] + value;
				if (!(params[3].IsEmpty() && value.IsEmpty()))
					value = ";" + params[3] + value;
				if (!params[2])
					value = params[1] + ":" + params[2] + value;
				else
					value = params[1] + value;
				if (params[0].IsEmpty() || params[1].IsEmpty()) {
					PTRACE(1, "SQLCONF\tInvalid neighbor entry found in the SQL "
						"database: '" << params[0] << '=' << value << '\'');
					SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Neighbor query failed");
				} else {
					m_Config->SetString("RasSrv::Neighbors", params[0], value);
					PTRACE(6, "SQLCONF\tNeighbor entry read: '" << params[0] << '=' << value << '\'');
				}
			}
			PTRACE(4, "SQLCONF\t" << queryResult->GetNumRows() << " neighbor entries loaded from SQL database");
		}
		delete queryResult;
		queryResult = NULL;
	}
	// Neighbor Query (new style)
	query = m_Config->GetString("SQLConfig", "NeighborsQuery2", "");
	if (!query.IsEmpty()) {
		PTRACE(4, "SQLCONF\tLoading neighbors from SQL database");
		PStringArray params;
		params += GKName();
		queryResult = sqlConn->ExecuteQuery(query, &params);
		if (queryResult == NULL) {
			PTRACE(1, "SQLCONF\tFailed to load neighbors from SQL database: timeout or fatal error");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Neighbor query failed");
		} else if (!queryResult->IsValid()) {
			PTRACE(1, "SQLCONF\tFailed to load neighbors from SQL database ("
				<< queryResult->GetErrorCode() << "): " << queryResult->GetErrorMessage());
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Neighbor query failed");
		} else if (queryResult->GetNumRows() > 0 && queryResult->GetNumFields() < 3) {
			PTRACE(1, "SQLCONF\tFailed to load neighbors from SQL database: "
				"at least 6 columns must be present in the result set");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Neighbor query failed");
		} else {
			// H46018 Traversal Support
			int h460id = 8;
			int h46018traverse = 0;
			while (queryResult->FetchRow(params)) {
				// GkID, Gatekeeper Identifier and Gatekeeper Type must not be empty
				if (params[0].IsEmpty() || params[1].IsEmpty() || params[2].IsEmpty()) {
					PTRACE(1, "SQLCONF\tInvalid neighbor entry found in the SQL "
						"database: '" << params[0] << '=' << params[0] << '\'');
					SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Neighbor query failed");
				} else {
					m_Config->SetString("RasSrv::Neighbors", params[0], params[1]);
					PString neighborSection = "Neighbor::" + params[0];
					if (queryResult->GetNumFields() > h460id) {
						h46018traverse = params[h460id].AsInteger();
						if (h46018traverse) {
							if (h46018traverse == 1)
							   m_Config->SetString(neighborSection, "H46018Server", "1");
							else if (h46018traverse == 2)
							   m_Config->SetString(neighborSection, "H46018Client", "1");

							if (queryResult->GetNumFields() > (h460id+2)) {
								if (!params[h460id+1]) m_Config->SetString(neighborSection, "SendAuthUser", params[h460id+1]);
								if (!params[h460id+2]) m_Config->SetString(neighborSection, "SendPassword", params[h460id+2]);
							}
						}
					}
					// General Neighbor settings
					for (PINDEX i = 0; i < queryResult->GetNumFields(); ++i) {
					  if (!params[i]) {
						switch (i) {
							case 0 : m_Config->SetString(neighborSection, "GatekeeperIdentifier", params[i]); break;
							case 2 : m_Config->SetString(neighborSection, "Host", params[i]); break;
							case 3 : m_Config->SetString(neighborSection, "SendPrefixes", params[i]); break;
							case 4 : m_Config->SetString(neighborSection, "AcceptPrefixes", params[i]); break;
							case 5 : m_Config->SetString(neighborSection, "ForwardHopCount", params[i]); break;
							case 6 : m_Config->SetString(neighborSection, "AcceptForwardedLRQ", params[i]); break;
							case 7 : m_Config->SetString(neighborSection, "ForwardResponse", params[i]); break;
							default: break;
						}
					  }
					}
					PTRACE(4, "SQLCONF\t" << neighborSection << " neighbor loaded from SQL database");
				}
			}
		}
		delete queryResult;
		queryResult = NULL;
	}

	query = m_Config->GetString("SQLConfig", "PermanentEndpointsQuery", "");
	if (!query.IsEmpty()) {
		PTRACE(4, "SQLCONF\tLoading permanent endpoints from SQL database");
		PStringArray params;
		params += GKName();
		queryResult = sqlConn->ExecuteQuery(query, &params);
		if (queryResult == NULL) {
			PTRACE(1, "SQLCONF\tFailed to load permanent endpoints from SQL database: timeout or fatal error");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Permanent EP query failed");
		} else if (!queryResult->IsValid()) {
			PTRACE(1, "SQLCONF\tFailed to load permanent endpoints from SQL database "
				"("	<< queryResult->GetErrorCode() << "): "
				<< queryResult->GetErrorMessage());
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Permanent EP query failed");
		} else if (queryResult->GetNumRows() > 0 && queryResult->GetNumFields() < 4) {
			PTRACE(1, "SQLCONF\tFailed to load permanent endpoints from SQL database: "
				"at least 4 columns must be present in the result set");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Permanent EP query failed");
		} else {
			PString key;
			PString value;
			while (queryResult->FetchRow(params)) {
				key = params[0];				// IP
				if (!params[1].IsEmpty())		// port
					key += ":" + params[1];
				value = params[2];				// alias
				if (params.GetSize() >=4)
					value += ";" + params[3];	// prefixes (+ priorities)
				if (params.GetSize() > 5)
					value += ";" + params[4] + "," + params[5];	// vendor info
				if (key.IsEmpty() || value.IsEmpty()) {
					PTRACE(1, "SQLCONF\tInvalid permanent endpoint entry found "
						"in the SQL database: '" << key << '=' << value << '\'');
					SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Permanent EP query failed");
				} else {
					m_Config->SetString("RasSrv::PermanentEndpoints", key, value);
					PTRACE(6, "SQLCONF\tPermanent endpoint read: '" << key << '=' << value << '\'');
				}
			}
			PTRACE(4, "SQLCONF\t" << queryResult->GetNumRows() << " permanent endpoints loaded from SQL database");
		}
		delete queryResult;
		queryResult = NULL;
	}

	query = m_Config->GetString("SQLConfig", "GWPrefixesQuery", "");
	if (!query.IsEmpty()) {
		PTRACE(4, "SQLCONF\tLoading gateway prefixes from SQL database");
		PStringArray params;
		params += GKName();
		queryResult = sqlConn->ExecuteQuery(query, &params);
		if (queryResult == NULL) {
			PTRACE(1, "SQLCONF\tFailed to load gateway prefixes from SQL database: timeout or fatal error");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Gateway query failed");
		} else if (!queryResult->IsValid()) {
			PTRACE(1, "SQLCONF\tFailed to load gateway prefixes from SQL database ("
				<< queryResult->GetErrorCode() << "): " << queryResult->GetErrorMessage());
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Gateway query failed");
		} else if (queryResult->GetNumRows() > 0 && queryResult->GetNumFields() < 2) {
			PTRACE(1, "SQLCONF\tFailed to load gateway prefixes from SQL database: "
				"at least 2 columns must be present in the result set");
			SNMP_TRAP(5, SNMPError, Database, "SQLConfig: Gateway query failed");
		} else {
			while (queryResult->FetchRow(params))
				if (params[0].IsEmpty() || params[1].IsEmpty())
					PTRACE(1, "SQLCONF\tInvalid gateway prefixes entry found "
						"in the SQL database: '" << params[0] << '='  << params[1] << '\'');
				else {
					m_Config->SetString("RasSrv::GWPrefixes", params[0], params[1]);
					PTRACE(6, "SQLCONF\tGateway prefixes read: '" << params[0]
						<< '=' << params[1] << '\'');
				}
			PTRACE(4, "SQLCONF\t" << queryResult->GetNumRows() << " gateway prefixes loaded from SQL database");
		}
		delete queryResult;
		queryResult = NULL;
	}
	// TODO: add support for missing special section

	delete sqlConn;
	sqlConn = NULL;
	PTRACE(3, "SQLCONF\tSQL config connection closed");
#endif // HAS_DATABASE
}

void Toolkit::PrepareReloadConfig()
{
	if (!m_ConfigDirty)
		CreateConfig();
	else // the config has been changed via status port, use it directly
		m_ConfigDirty = false;
}

PConfig* Toolkit::ReloadConfig()
{
	// make a new symlink if needed
	PrepareReloadConfig();

	CheckLicense();

	// read the toolkit config values

	// read the gatekeeper name from the config file, because it might be used as a key into the SQL config
	m_GKName = Config()->GetString("Name", "GnuGk");

	PTrace::SetLevel(GkConfig()->GetInteger("TraceLevel", PTrace::GetLevel()));

	g_workerIdleTimeout = GkConfig()->GetInteger("WorkerThreadIdleTimeout", DEFAULT_WORKER_IDLE_TIMEOUT);

	int minH323Version = GkConfig()->GetInteger("MinH323Version", 2);
	if (minH323Version < 1)
        minH323Version = 1;
	if (minH323Version > MAX_H323_VERSION)
        minH323Version = MAX_H323_VERSION;
	strncpy(H225_ProtocolID, H225_Protocol_Version[minH323Version], ProtocolID_BufferSize-1);
	H225_ProtocolID[ProtocolID_BufferSize-1] = '\0';
	PTRACE(3, "Minimum H.225 version for GK generated messages: " << PString(H225_ProtocolID));
	strncpy(H245_ProtocolID, H245_Protocol_Version[minH323Version], ProtocolID_BufferSize-1);
	H245_ProtocolID[ProtocolID_BufferSize-1] = '\0';
	PTRACE(3, "Minimum H.245 version for GK generated messages: " << PString(H245_ProtocolID));

#ifdef hasIPV6
	m_ipv6Enabled = AsBool(GkConfig()->GetString("EnableIPv6", "0"));
#endif

	// set the max size of an array in an ASN encoded message (eg. max length of alias list)
	PINDEX maxArraySize = GkConfig()->GetInteger("MaxASNArraySize", 0);
	if (maxArraySize > 0) {
        PTRACE(3, "Setting ASN.1 max array size to " << maxArraySize);
		PASN_Object::SetMaximumArraySize(maxArraySize);
    }

	// set max bytes to queue for a socket, before assuming its dead (probably only an issue with H.460.17)
	int maxSocketQueue = GkConfig()->GetInteger("MaxSocketQueue", 100);
	if (maxSocketQueue > 0)
		g_maxSocketQueue = maxSocketQueue;

    g_disableSettingUDPSourceIP = GkConfig()->GetBoolean(RoutedSec, "DisableSettingUDPSourceIP", false);

	m_encryptAllPasswords = Toolkit::AsBool(
		Config()->GetString("EncryptAllPasswords", "0")
		);
	if (Config()->HasKey(paddingByteConfigKey))
		m_encKeyPaddingByte = Config()->GetInteger(paddingByteConfigKey, 0);
	else
		m_encKeyPaddingByte = m_encryptAllPasswords ? 0 : -1;

	ReloadSQLConfig();

	// update the gatekeeper name, in case it was set in the SQL config
	m_GKName = m_Config->GetString("Name", "GnuGk");

	PString removeH235Call = m_Config->GetString(RoutedSec, "RemoveH235Call", "0");
	m_alwaysRemoveH235Tokens = (removeH235Call.AsUnsigned() == 1);
	m_removeH235TokensfromNetwork.clear();
	if (removeH235Call.GetLength() >= 7) {
		PStringArray networks = removeH235Call.Tokenise(",", FALSE);
		for (PINDEX n = 0; n < networks.GetSize(); ++n) {
			if (networks[n].Find('/') == P_MAX_INDEX) {
                if (IsIPv4Address(networks[n])) {
                    networks[n] += "/32";	// add netmask to pure IPs
                } else {
                    networks[n] += "/128";	// add netmask to pure IPs
                }
            }
			NetworkAddress net = NetworkAddress(networks[n]);
			m_removeH235TokensfromNetwork.push_back(net);
		}
	}
#ifdef HAS_H235_MEDIA
	m_H235HalfCallMediaEnabled = m_Config->GetBoolean(RoutedSec, "EnableH235HalfCallMedia", false)
		|| m_Config->GetBoolean(RoutedSec, "RequireH235HalfCallMedia", false);
	m_H235HalfCallMediaKeyUpdatesEnabled = m_Config->GetBoolean(RoutedSec, "EnableH235HalfCallMediaKeyUpdates", false);
#endif
#ifdef HAS_H46018
	m_H46018Enabled	= m_Config->GetBoolean(RoutedSec, "EnableH46018", false);
#endif
#ifdef HAS_H46023
	m_H46023Enabled	= (m_Config->GetBoolean(RoutedSec, "EnableH46023", false) &&
						!m_Config->GetString(RoutedSec, "H46023STUN", ""));
#endif
    m_H46026Enabled = m_Config->GetBoolean(RoutedSec, "EnableH46026", false);

	PString GKHome(m_Config->GetString("Home", ""));
	if (GKHome == "0.0.0.0") {
		PTRACE(1, "Config error: Invalid Home setting (0.0.0.0), ignoring");
		SNMP_TRAP(10, SNMPError, Configuration, "Invalid Home setting (0.0.0.0)");
		GKHome = "";
	}
	// always call SetGKHome() on reload to detect new IPs
	SetGKHome(GKHome.Tokenise(",;", false));

	m_RouteTable.InitTable();
	m_VirtualRouteTable.InitTable();
	m_ProxyCriterion.LoadConfig(m_Config);
#ifdef HAS_H46023
	if (m_H46023Enabled)
		LoadH46023STUN();
#endif
#ifdef HAS_H460P
	m_presence.LoadConfig(m_Config);
#endif
	m_Rewrite.LoadConfig(m_Config);
	m_GWRewrite.LoadConfig(m_Config);
	m_AssignedEPAliases.LoadConfig(m_Config);
#ifdef h323v6
	m_AssignedGKs.LoadConfig(m_Config);
#endif
#if HAS_DATABASE
	m_AlternateGKs.LoadConfig(m_Config);
	m_GnuGkAssignedGKs.LoadConfig(m_Config);
	m_qosMonitor.LoadConfig(m_Config);
#ifdef HAS_LANGUAGE
	m_assignedLanguage.LoadSQL(m_Config);
#endif
#endif
	m_venderMode.LoadConfig(m_Config);

	m_timestampFormatStr = m_Config->GetString("TimestampFormat", "Cisco");

	delete m_cliRewrite;
	m_cliRewrite = new CLIRewrite();

	CapacityControl::Instance()->LoadConfig();

	LoadCauseMap(m_Config);

	LoadReasonMap(m_Config);

	ParseTranslationMap(m_receivedCauseMap, m_Config->GetString(RoutedSec, "TranslateReceivedQ931Cause", ""));
	ParseTranslationMap(m_sentCauseMap, m_Config->GetString(RoutedSec, "TranslateSentQ931Cause", ""));

	// read [PortNotifications]
	m_portOpenNotifications[RASPort] = m_Config->GetString("PortNotifications", "RASPortOpen", "");
	m_portOpenNotifications[Q931Port] = m_Config->GetString("PortNotifications", "Q931PortOpen", "");
	m_portOpenNotifications[H245Port] = m_Config->GetString("PortNotifications", "H245PortOpen", "");
	m_portOpenNotifications[RTPPort] = m_Config->GetString("PortNotifications", "RTPPortOpen", "");
	m_portOpenNotifications[T120Port] = m_Config->GetString("PortNotifications", "T120PortOpen", "");
	m_portOpenNotifications[StatusPort] = m_Config->GetString("PortNotifications", "StatusPortOpen", "");
	m_portOpenNotifications[RadiusPort] = m_Config->GetString("PortNotifications", "RadiusPortOpen", "");

	m_portCloseNotifications[RASPort] = m_Config->GetString("PortNotifications", "RASPortClose", "");
	m_portCloseNotifications[Q931Port] = m_Config->GetString("PortNotifications", "Q931PortClose", "");
	m_portCloseNotifications[H245Port] = m_Config->GetString("PortNotifications", "H245PortClose", "");
	m_portCloseNotifications[RTPPort] = m_Config->GetString("PortNotifications", "RTPPortClose", "");
	m_portCloseNotifications[T120Port] = m_Config->GetString("PortNotifications", "T120PortClose", "");
	m_portCloseNotifications[StatusPort] = m_Config->GetString("PortNotifications", "StatusPortClose", "");
	m_portCloseNotifications[RadiusPort] = m_Config->GetString("PortNotifications", "RadiusPortClose", "");

#ifdef HAS_SNMP
	m_snmpEnabled = AsBool(GkConfig()->GetString(SNMPSection, "EnableSNMP", "0"));
#endif

	return m_Config;
}

void Toolkit::LoadCauseMap(
	PConfig *cfg
	)
{
	memset(m_causeMap, 0, 16);

	if (! Toolkit::AsBool(cfg->GetString(RoutedSec, "ActivateFailover", "0")))
		return;

	PStringArray causes(cfg->GetString(RoutedSec, "FailoverCauses", "1-15,21-127").Tokenise(", \t", FALSE));

	for (PINDEX i = 0; i < causes.GetSize(); ++i)
		if (causes[i].Find('-') == P_MAX_INDEX) {
			unsigned c = causes[i].AsUnsigned() & 0x7f;
			m_causeMap[c >> 3] |= (1UL << (c & 7));
		} else {
			PStringArray causeRange(causes[i].Tokenise("- ", FALSE));
			if (causeRange.GetSize() == 2) {
				unsigned cmin = causeRange[0].AsUnsigned() & 0x7f;
				unsigned cmax = causeRange[1].AsUnsigned() & 0x7f;
				for (; cmin <= cmax; ++cmin)
					m_causeMap[(cmin >> 3) & 0x0f] |= (1UL << (cmin & 7));
			}
		}
}

// load H.225 reason to Q.931 cause mapping
void Toolkit::LoadReasonMap(PConfig * cfg)
{
	// default to ITU-T Recommendation H.225 clause 7.2.2.8, table 5
	unsigned DefaultH225ReasonToQ931Cause[] =	{
		34, 47, 3, 16, 88, 111, 38, 42, 28, 41, 17, 31, 16, 31, 20, 31, 47, 127, 31, 31, 31, 127
	};
	m_H225ReasonToQ931Cause.assign(&DefaultH225ReasonToQ931Cause[0], &DefaultH225ReasonToQ931Cause[22]);

	for(int reason = 0; reason < H225_ReleaseCompleteReason::e_tunnelledSignallingRejected; reason++) {
		PString cause = cfg->GetString("H225toQ931", PString(reason), "");
		if (!cause.IsEmpty()) {
			m_H225ReasonToQ931Cause[reason] = cause.AsInteger();
		}
	}

}

bool Toolkit::MatchRegex(const PString & str, const PString & regexStr)
{
	if (regexStr.IsEmpty())
		return false;	// nothing matches an empty regex and it triggers a PTLib assertion
	PINDEX pos = 0;
	PRegularExpression regex(regexStr, PRegularExpression::Extended);
	if(regex.GetErrorCode() != PRegularExpression::NoError) {
		PTRACE(2, "Error '"<< regex.GetErrorText() <<"' compiling regex: " << regexStr);
		SNMP_TRAP(7, SNMPError, Configuration, "Invalid RegEx");
		return FALSE;
	}
	if(!regex.Execute(str, pos)) {
		return FALSE;
	}
	return TRUE;
}

#if HAS_DATABASE
Toolkit::AssignedAliases::AssignedAliases()
  : m_sqlactive(false), m_sqlConn(NULL), m_timeout(-1)
{
}

Toolkit::AssignedAliases::~AssignedAliases()
{
}

bool Toolkit::AssignedAliases::LoadSQL(PConfig * cfg)
{
	delete m_sqlConn;
	PString authName = "AssignedAliases::SQL";

   if (cfg->GetSections().GetStringsIndex(authName) == P_MAX_INDEX)
		return false;

	const PString driverName = cfg->GetString(authName, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(1, "AliasSQL\tModule creation failed: no SQL driver selected");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "AliasSQL\tFATAL: Shutting down");
		return false;
	}

	m_sqlConn = GkSQLConnection::Create(driverName, authName);
	if (m_sqlConn == NULL) {
		PTRACE(1, "AliasSQL\tModule creation failed: "
			"Could not find " << driverName << " database driver");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "AliasSQL\tFATAL: Shutting down");
		return false;
	}

	m_query = cfg->GetString(authName, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(1, "AliasSQL\tModule creation failed: No query configured");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "AliasSQL\tFATAL: Shutting down");
		return false;
	} else
		PTRACE(4, "AliasSQL\tQuery: " << m_query);

	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(1, "AliasSQL\tModule creation failed: Could not connect to the database");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		return false;
	}

	return true;
}

bool Toolkit::AssignedAliases::DatabaseLookup(
		const PString & alias,
		PStringArray & newAliases)
{
	if (!m_sqlactive)
		return false;

	std::map<PString, PString> params;
	params["u"] = alias;
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, params, m_timeout);
	if (result == NULL) {
		PTRACE(2, "AliasSQL\tQuery failed - timeout or fatal error");
		SNMP_TRAP(5, SNMPError, Database, "AssignedAliases query failed");
		return false;
	}

	if (!result->IsValid()) {
		PTRACE(2, "AliasSQL\tQuery failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage());
		SNMP_TRAP(5, SNMPError, Database, "AssignedAliases query failed");
		delete result;
		return false;
	}

	bool success = false;

	if (result->GetNumRows() < 1)
		PTRACE(3, "AliasSQL\tQuery returned no rows");
	else if (result->GetNumRows() > 0 && result->GetNumFields() < 1) {
		PTRACE(2, "AliasSQL\tBad-formed query - no columns found in the result set");
		SNMP_TRAP(5, SNMPError, Database, "AssignedAliases query failed");
	} else {
		PStringArray retval;
		while (result->FetchRow(retval)) {
			if (retval[0].IsEmpty()) {
				PTRACE(1, "AliasSQL\tQuery Invalid value found.");
				SNMP_TRAP(5, SNMPError, Database, "AssignedAliases query failed");
				continue;
			}
		    if (!success) success = true;
		    PTRACE(5, "AliasSQL\tQuery result: " << retval[0]);

		    newAliases.AppendString(retval[0]);
		}
	}
	delete result;

   return success;
}
#endif   // HAS_DATABASE

void Toolkit::AssignedAliases::LoadConfig(PConfig * m_config)
{
	gkAssignedAliases.clear();

#if HAS_DATABASE
	if (LoadSQL(m_config)) {
		m_sqlactive = true;
	} else
#endif
	{
		const PStringToString kv = m_config->GetAllKeyValues(AssignedAliasSection);
		for (PINDEX i = 0; i < kv.GetSize(); i++) {
			PString data = kv.GetDataAt(i);
			PStringArray datalines = data.Tokenise(" ,;\t");
			for (PINDEX j = 0; j < datalines.GetSize(); j++)
				gkAssignedAliases.push_back(std::pair<PString, PString>(kv.GetKeyAt(i),datalines[j]));
		}
	}
}

#ifdef H323_H350

bool Toolkit::CreateH350Session(H350_Session * session)
{
	PString ldap = GkConfig()->GetString(H350Section, "ServerName", "127.0.0.1");
	PString port = GkConfig()->GetString(H350Section, "ServerPort", "389");
	PString server = ldap + ":" + port;	// IPv4
	if (IsIPv6Address(ldap))
		server = "[" + ldap + "]:" + port;	// IPv6

	PString user = GkConfig()->GetString(H350Section, "BindUserDN", "");
	PString password = Toolkit::Instance()->ReadPassword(H350Section, "BindUserPW");
    PCaselessString mode = GkConfig()->GetString(H350Section, "BindAuthMode", "simple");

	PLDAPSession::AuthenticationMethod authMethod = PLDAPSession::AuthSimple;
	if (mode == "sasl")
		authMethod = PLDAPSession::AuthSASL;
	else if (mode == "kerberos")
		authMethod = PLDAPSession::AuthKerberos;

	bool startTLS = GkConfig()->GetBoolean(H350Section, "StartTLS", false);

	if (!session->Open(server)) {
		PTRACE(1, "H350\tCannot locate H.350 Server " << server);
		return false;
	}
	if (startTLS) {
#ifdef hasLDAPStartTLS
		if (!session->StartTLS()) {
			PTRACE(1, "H350\tStartTLS failed");
			SNMP_TRAP(7, SNMPWarning, Database, "H.350 StartTLS failed");
			return false;
		}
#else
		PTRACE(1, "H350\tError: LDAP StartTLS not supported in this version");
		SNMP_TRAP(7, SNMPWarning, Database, "H.350 StartTLS not supported");
#endif
	}
	if (!user.IsEmpty())
	    session->Bind(user, password, authMethod);

	return true;
}

bool Toolkit::AssignedAliases::QueryH350Directory(const PString & alias, PStringArray & aliases)
{
	// support Assigned Aliases
    if (!Toolkit::AsBool(GkConfig()->GetString(H350Section, "AssignedAliases", "0")))
		return false;

	// search the directory
	PString search = GkConfig()->GetString(H350Section, "SearchBaseDN", "");

	H225_AliasAddress aliasaddress;
	H323SetAliasAddress(alias, aliasaddress);

	PString filter;
	switch (aliasaddress.GetTag()) {
	  case H225_AliasAddress::e_dialedDigits:
            filter = "h323IdentitydialedDigits=" + alias;
            break;
	  case H225_AliasAddress::e_h323_ID:
            filter = "h323Identityh323-ID=" + alias;
            break;
	  case H225_AliasAddress::e_url_ID:
		    filter = "h323IdentityURL-ID=" + alias;
		    break;
	  default:
		  PTRACE(4, "H350\tAssigned Alias: unhandled alias type " << aliasaddress.GetTagName());
		  return false;
	}

	H350_Session session;
	if (!Toolkit::Instance()->CreateH350Session(&session)) {
		PTRACE(1, "H350\tAssigned Alias: Could not connect to directory server");
		return false;
	}

	H350_Session::LDAP_RecordList rec;
	int count = session.Search(search, filter, rec);
	if (count <= 0) {
		PTRACE(4, "H350\tAssigned Alias: No Record Found");
		session.Close();
		return false;
	}

	// locate the record
	for (H350_Session::LDAP_RecordList::const_iterator x = rec.begin(); x != rec.end(); ++x) {
		H350_Session::LDAP_Record entry = x->second;
		PString al;
		PINDEX i;
		if (session.GetAttribute(entry, "h323Identityh323-ID", al)) {
			PStringList als = al.Lines();
			for (i = 0; i< als.GetSize(); i++)
				aliases.AppendString(als[i]);
		}
		if (session.GetAttribute(entry, "h323IdentitydialedDigits", al)) {
			PStringList als = al.Lines();
			for (i = 0; i< als.GetSize(); i++)
				aliases.AppendString(als[i]);
		}
		if (session.GetAttribute(entry, "h323IdentityURL-ID", al)) {
			PStringList als = al.Lines();
			for (i = 0; i< als.GetSize(); i++)
				aliases.AppendString(als[i]);
		}
		session.Close();
		if (aliases.GetSize() > 0) {
			PTRACE(2, "H350\tAssigned Alias: Located " << aliases.GetSize() << " aliases");
			session.Close();
			return true;
		}
	}

	PTRACE(4, "H350\tAssigned Alias: No valid Assigned Alias found");
	session.Close();
	return false;
}
#endif

#ifdef P_SSL
void Toolkit::InitOpenSSL()
{
    if (!m_OpenSSLInitialized) {
		// init OpenSSL exactly once and in application
        PTRACE(1, "Initializing OpenSSL");
		if (!SSL_library_init()) {
			PTRACE(1, "TLS\tOpenSSL init failed");
			return;
		}
		SSL_load_error_strings();
		OpenSSL_add_all_algorithms();	// needed for OpenSSL < 1.0
		if (!RAND_status()) {
			PTRACE(3, "TLS\tPRNG needs seeding");
#if defined(P_LINUX) || defined (P_FREEBSD)
			RAND_load_file("/dev/urandom", 1024);
#else
			BYTE seed[1024];
			for (size_t i = 0; i < sizeof(seed); i++)
				seed[i] = (BYTE)rand();
			RAND_seed(seed, sizeof(seed));
#endif
		}

        m_OpenSSLInitialized = true;    // don't do again
    }
}
#endif

#ifdef HAS_TLS

void apps_ssl_info_callback(const SSL * s, int where, int ret)
{
	const char * funcname = NULL;
	int w = where & ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT)
	    funcname = "SSL_connect";
	else if (w & SSL_ST_ACCEPT)
	    funcname = "SSL_accept";
	else
	    funcname = "unknown_function";

	if (where & SSL_CB_LOOP) {
		PTRACE(6, "TLS\t" << funcname << ": " << SSL_state_string_long(s));
	} else if (where & SSL_CB_ALERT) {
		funcname = (where & SSL_CB_READ) ? "read" : "write";
		PTRACE(5, "TLS\tSSL3 alert " <<	funcname << ": " << SSL_alert_type_string_long(ret) << ": " << SSL_alert_desc_string_long(ret));
	} else if (where & SSL_CB_EXIT) {
		if (ret == 0)
			PTRACE(5, funcname << ": failed in " << SSL_state_string_long(s));
		else if (ret < 0) {
			//PTRACE(5, "TLS\t" << funcname << ": error in " << SSL_state_string_long(s));	// huge volume of messages when using async sockets
		}
	}
}

int pem_passwd_cb(char * buf, int size, int rwflag, void * password)
{
	strncpy(buf, (char *)(password), size);
	buf[size - 1] = '\0';
	return(strlen(buf));
}

int verify_callback(int ok, X509_STORE_CTX * store)
{
	if (!ok)
	{
        X509 * cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);
        const unsigned MSG_LEN = 256;
		char data[MSG_LEN];

        PTRACE(5, "TLS\tError with certificate at depth " << depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, MSG_LEN);
        PTRACE(5, "TLS\t  issuer  = " << data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, MSG_LEN);
        PTRACE(5, "TLS\t  subject = " << data);
        PTRACE(5, "TLS\t  err " << err << ": " << X509_verify_cert_error_string(err));

        if (!Toolkit::Instance()->Config()->GetBoolean(TLSSec, "RequireRemoteCertificate", true)) {
            PTRACE(5, "TLS\tAccepting invalid client certificate");
            return 1;
        }
    }

    return ok;
}

bool Toolkit::IsTLSEnabled() const
{
	return Toolkit::AsBool(GkConfig()->GetString(TLSSec, "EnableTLS", "0"));
}

SSL_CTX * Toolkit::GetTLSContext()
{
	if (!m_sslCtx) {
        InitOpenSSL(); // makes sure  OpenSSL gets initialized exactly once for the whole application

		m_sslCtx = SSL_CTX_new(SSLv23_method());	// allow only TLS (SSLv2+v3 are removed below)
		SSL_CTX_set_options(m_sslCtx, SSL_OP_NO_SSLv2);	// remove unsafe SSLv2 (eg. due to DROWN)
		SSL_CTX_set_options(m_sslCtx, SSL_OP_NO_SSLv3);	// remove unsafe SSLv3 (eg. due to POODLE)
		SSL_CTX_set_options(m_sslCtx, SSL_OP_NO_COMPRESSION);	// remove unsafe SSL compression (eg. due to CRIME)
		SSL_CTX_set_mode(m_sslCtx, SSL_MODE_AUTO_RETRY); // handle re-negotiations automatically
		// exclude insecure / broken ciphers
		// no anonymous DH (ADH), no <= 64 bit (LOW), no export ciphers (EXP), no MD5 + RC4 + SHA1
		PString cipherList = m_Config->GetString(TLSSec, "CipherList", "ALL:!ADH:!LOW:!EXP:!MD5:!RC4:!SHA1:@STRENGTH");
		SSL_CTX_set_cipher_list(m_sslCtx, cipherList);

		SSL_CTX_set_info_callback(m_sslCtx, apps_ssl_info_callback);
		SSL_CTX_set_default_passwd_cb(m_sslCtx, pem_passwd_cb);
		m_passphrase = m_Config->GetString(TLSSec, "Passphrase", "");
		SSL_CTX_set_default_passwd_cb_userdata(m_sslCtx, (void *)(const char *)m_passphrase);
		PString caFile = m_Config->GetString(TLSSec, "CAFile", "");
		PString caDir = m_Config->GetString(TLSSec, "CADir", "");
		const char * caFilePtr = caFile.IsEmpty() ? NULL : (const char *)caFile;
		const char * caDirPtr = caDir.IsEmpty() ? NULL : (const char *)caDir;
		char msg[256];
		if (caFilePtr || caDirPtr) {
			if (SSL_CTX_load_verify_locations(m_sslCtx, caFilePtr, caDirPtr) != 1) {
				PTRACE(1, "TLS\tError loading CA file or directory (" << caFile << " / " << caDir << ")");
				ERR_error_string(ERR_get_error(), msg);
				PTRACE(1, "TLS\tOpenSSL error: " << msg);
			}
		}
		if (SSL_CTX_use_certificate_chain_file(m_sslCtx, m_Config->GetString(TLSSec, "Certificates", "tls_certificate.pem")) != 1) {
			PTRACE(1, "TLS\tError loading certificate file: " << m_Config->GetString(TLSSec, "Certificates", "tls_certificate.pem"));
			ERR_error_string(ERR_get_error(), msg);
			PTRACE(1, "TLS\tOpenSSL error: " << msg);
		}
		if (SSL_CTX_use_PrivateKey_file(m_sslCtx, m_Config->GetString(TLSSec, "PrivateKey", "tls_private_key.pem"), SSL_FILETYPE_PEM) != 1) {
			PTRACE(1, "TLS\tError loading private key file: " << m_Config->GetString(TLSSec, "PrivateKey", "tls_private_key.pem"));
			ERR_error_string(ERR_get_error(), msg);
			PTRACE(1, "TLS\tOpenSSL error: " << msg);
		}

		if (!m_Config->GetBoolean(TLSSec, "RequireRemoteCertificate", true)) {
			SSL_CTX_set_verify(m_sslCtx, SSL_VERIFY_PEER, verify_callback); // do not require a client certificate
		} else {
			SSL_CTX_set_verify(m_sslCtx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback); // context is used both in client and server mode
		}

		SSL_CTX_set_verify_depth(m_sslCtx, 5);
	}

	return m_sslCtx;
}

bool Toolkit::MatchHostCert(SSL * ssl, PIPSocket::Address addr)
{
	bool found = false;

	if (!GkConfig()->GetBoolean(TLSSec, "CheckCertificateIP", false))
		return true;	// check disabled

	X509 * cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		PTRACE(1, "TLS\tError: Certificate didn't match IP: No peer certificate");
		SNMP_TRAP(8, SNMPError, Authentication, ::AsString(addr) + " didn't provide a TLS certificate");
		return false;
	}

	// do a reverse lookup of the peer IP
	char reverseLookup[256];
#ifdef hasIPV6
	if (addr.GetVersion() == 6) {
		struct sockaddr_in6 inaddr;
		SetSockaddr(inaddr, addr, 0);
		getnameinfo((const sockaddr*)&inaddr, sizeof(inaddr), reverseLookup, sizeof(reverseLookup), NULL, 0, 0);
	} else
#endif
	{
		struct sockaddr_in inaddr;
		SetSockaddr(inaddr, addr, 0);
		getnameinfo((const sockaddr*)&inaddr, sizeof(inaddr), reverseLookup, sizeof(reverseLookup), NULL, 0, 0);
	}

	// check all subjectAltName elements
	STACK_OF( GENERAL_NAME ) * altnames = (STACK_OF( GENERAL_NAME ) *) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (altnames) {
		for (int i = 0; i < sk_GENERAL_NAME_num(altnames); i++) {
			GENERAL_NAME * gn = sk_GENERAL_NAME_value(altnames, i);
			if (gn && (gn->type == GEN_DNS)) {
				char * dns = (char *)ASN1_STRING_data(gn->d.ia5);
				if (dns) {
					PTRACE(5, "TLS\tChecking Certificate DNS " << dns);
					if (::AsString(addr) == dns) {
						found = true;	// IP matched
					} else if ((strlen(reverseLookup) > 0) && (strcasecmp(reverseLookup, dns) == 0)) {
						found = true;	// FQDN matched
					} else {
						struct addrinfo *result = NULL;
					    if (getaddrinfo(dns, NULL, NULL, &result) == 0) {
							for (struct addrinfo * res = result; res != NULL; res = res->ai_next) {
								PIPSocket::Address lookup;
#ifdef hasIPV6
								if (res->ai_addr->sa_family == AF_INET6) {
									lookup = ((struct sockaddr_in6*)(res->ai_addr))->sin6_addr;
								} else
#endif
								{
									lookup = ((struct sockaddr_in*)(res->ai_addr))->sin_addr;
								}
								if (addr == lookup) {
									found = true;	// DNS lookup matched
								}
							}
						    freeaddrinfo(result);
						}
					}
				}
			}
			if (found)
				break;
		}
	}
	sk_GENERAL_NAME_free(altnames);

	if (!found) {
		// check commonName, too
		X509_NAME * subject = X509_get_subject_name(cert);
		if (subject) {
			char commonname[256];
			if (X509_NAME_get_text_by_NID(subject, NID_commonName, commonname, 256) > 0) {
				PTRACE(5, "TLS\tChecking Certificate commonName " << commonname);
				if (::AsString(addr) == commonname) {
					found = true;	// IP matched
				} else if ((strlen(reverseLookup) > 0) && (strcasecmp(reverseLookup, commonname) == 0)) {
					found = true;	// FQDN matched
				} else {
					struct addrinfo *result = NULL;
				    if (getaddrinfo(commonname, NULL, NULL, &result) == 0) {
						for (struct addrinfo * res = result; res != NULL; res = res->ai_next) {
							PIPSocket::Address lookup;
#ifdef hasIPV6
							if (res->ai_addr->sa_family == AF_INET6) {
								lookup = ((struct sockaddr_in6*)(res->ai_addr))->sin6_addr;
							} else
#endif
							{
								lookup = ((struct sockaddr_in*)(res->ai_addr))->sin_addr;
							}
							if (addr == lookup) {
								found = true;	// DNS lookup matched
							}
						}
					    freeaddrinfo(result);
					}
				}
			}
		}
	}
	X509_free(cert);

	if (!found) {
		PTRACE(1, "TLS\tError: Certificate didn't match IP " << ::AsString(addr) << " (" << reverseLookup << ")");
		SNMP_TRAP(8, SNMPError, Authentication, ::AsString(addr) + " failed TLS certificate IP check");
	}
	return found;	// check failed
}

#endif

void Toolkit::CheckLicense()
{
#ifdef HAS_OLM
	map<EVENT_TYPE, string> stringByEventType;
    stringByEventType[LICENSE_OK                      ] = "OK";
    stringByEventType[LICENSE_FILE_NOT_FOUND          ] = "license file not found";
    stringByEventType[LICENSE_SERVER_NOT_FOUND        ] = "license server can't be contacted";
    stringByEventType[ENVIRONMENT_VARIABLE_NOT_DEFINED] = "environment variable not defined";
    stringByEventType[FILE_FORMAT_NOT_RECOGNIZED      ] = "license file has invalid format (not .ini file)";
    stringByEventType[LICENSE_MALFORMED               ] = "some mandatory field are missing, or data can't be fully read";
    stringByEventType[PRODUCT_NOT_LICENSED            ] = "this product was not licensed";
    stringByEventType[PRODUCT_EXPIRED                 ] = "license expired";
    stringByEventType[LICENSE_CORRUPTED               ] = "license signature doesn't match";
    stringByEventType[IDENTIFIERS_MISMATCH            ] = "calculated identifier and the one provided in license didn't match";
    stringByEventType[LICENSE_FILE_FOUND              ] = "license file not found";
    stringByEventType[LICENSE_VERIFIED                ] = "license verified";

	LicenseInfo licenseInfo;
	PString licenseFile = GkConfig()->GetString("LicenseFile", "gnugk.lic");
    LicenseLocation licenseLocation;
    licenseLocation.openFileNearModule = false;
    licenseLocation.licenseFileLocation = licenseFile;
    licenseLocation.environmentVariableName = "";
    EVENT_TYPE result = acquire_license("gnugk", licenseLocation, &licenseInfo);

	if (result == LICENSE_OK) {
		PConfig licenseIni(PFilePath(licenseFile), "gnugk");
		PString IDinLicense = licenseIni.GetString("client_signature");
		if (IDinLicense != GetServerID()) {
			m_licenseValid = false;
			m_licenseError = "Server ID doesn't match";
			m_licenseType = "Invalid license";
			return;
		}
	}

	if (result != LICENSE_OK) {
		m_licenseValid = false;
        m_licenseError = stringByEventType[result].c_str();
		m_licenseType = "Invalid license";
		return;
    }
    else {
		m_licenseValid = true;
		m_licenseError = "OK";
		if (licenseInfo.has_expiry) {
			m_licenseType = "Time limited license, valid until " + PString(licenseInfo.expiry_date);
		} else {
			m_licenseType = "Unlimited license";
		}
		return;
	}
#else
	m_licenseValid = true;
	m_licenseError = "OK";
	m_licenseType = "GPLv2";
#endif
}

bool Toolkit::IsLicenseValid(PString & message) const
{
	message = m_licenseError;
	return m_licenseValid;
}

PString Toolkit::GetServerID() const
{
#ifdef HAS_OLM
	PcSignature signature;
	FUNCTION_RETURN generate_ok = generate_user_pc_signature(signature, DEFAULT);
	return signature;
#else
	return "";
#endif
}

// Trial until X, unlimited license etc.
PString Toolkit::GetLicenseType() const
{
	return m_licenseType;
}


bool Toolkit::AssignedAliases::QueryAssignedAliases(const PString & alias, PStringArray & aliases)
{
#if HAS_DATABASE
	if (DatabaseLookup(alias, aliases))
		return true;
#endif
#ifdef H323_H350
	if (QueryH350Directory(alias, aliases))
		return true;
#endif

	return false;
}

bool Toolkit::AssignedAliases::GetAliases(const H225_ArrayOf_AliasAddress & alias, H225_ArrayOf_AliasAddress & aliaslist)
{
	if (alias.GetSize() == 0)
		return false;

	PStringArray newaliases;
	bool found = false;
	for (PINDEX h = 0; h < alias.GetSize(); h++) {
		if (QueryAssignedAliases(H323GetAliasAddressString(alias[h]), newaliases))
			found = true;
	}

	if (!found) {
		for (PINDEX i = 0; i < alias.GetSize(); i++) {
			PString search = H323GetAliasAddressString(alias[i]);
			for (unsigned j = 0; j < gkAssignedAliases.size(); j++) {
				PTRACE(5, "Alias\tCompare " << gkAssignedAliases[j].first << " to " << search);
				if (gkAssignedAliases[j].first == search) {
					newaliases.AppendString(gkAssignedAliases[j].second);
					if (!found) found = true;
				}
			}
		}
	}

	// Create the Assigned Alias List
	if (found) {
		// add existing items to the end of the list
		if (aliaslist.GetSize() > 0) {
			for (PINDEX l = 0; l < aliaslist.GetSize(); l++) {
				PString a = H323GetAliasAddressString(aliaslist[l]);
				bool located = false;
			    for (PINDEX m = 0; m < newaliases.GetSize(); m++) {
					if (newaliases[m] == a) located = true;
				}
				if (!located)
					newaliases.AppendString(a);
			}
		}

		aliaslist.RemoveAll();

		for (PINDEX k = 0; k < newaliases.GetSize(); k++) {
			H225_AliasAddress * aliasaddress = new H225_AliasAddress();
			H323SetAliasAddress(newaliases[k], *aliasaddress);
			aliaslist.Append(aliasaddress);
		}
	}

	return found;
}

////////////////////////////////////////////////////////////////////////

#ifdef h323v6
#if HAS_DATABASE
Toolkit::AssignedGatekeepers::AssignedGatekeepers()
  : m_sqlactive(false), m_sqlConn(NULL), m_timeout(-1)
{
}

Toolkit::AssignedGatekeepers::~AssignedGatekeepers()
{
}

bool Toolkit::AssignedGatekeepers::LoadSQL(PConfig * cfg)
{
	delete m_sqlConn;
	PString authName = "AssignedGatekeepers::SQL";

	if (cfg->GetSections().GetStringsIndex(authName) == P_MAX_INDEX)
		return false;

	const PString driverName = cfg->GetString(authName, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(1, "AssignSQL\tModule creation failed: no SQL driver selected");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "AssignSQL\tFATAL: Shutting down");
		return false;
	}

	m_sqlConn = GkSQLConnection::Create(driverName, authName);
	if (m_sqlConn == NULL) {
		PTRACE(1, "AssignSQL\tModule creation failed: "
			"Could not find " << driverName << " database driver");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "AssignSQL\tFATAL: Shutting down");
		return false;
	}

	m_query = cfg->GetString(authName, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(1, "AssignSQL\tModule creation failed: No query configured");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "AssignSQL\tFATAL: Shutting down");
		return false;
	} else
		PTRACE(4, "AssignSQL\tQuery: " << m_query);

	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(1, "AssignSQL\tModule creation failed: Could not connect to the database");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		return false;
	}

	return true;
}

bool Toolkit::AssignedGatekeepers::DatabaseLookup(
		const PString & alias,
		const PIPSocket::Address & ipaddr,
		PStringArray & newGks
        )
{
	if (!m_sqlactive)
		return false;

	std::map<PString, PString> params;
	params["u"] = alias;
	params["i"] = ipaddr.AsString();
	params["g"] = GKName();
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, params, m_timeout);
	if (result == NULL) {
		PTRACE(2, "AssignSQL\tQuery failed - timeout or fatal error");
		SNMP_TRAP(4, SNMPError, Database, "AssignedGatekeepers query failed");
		return false;
	}

	if (!result->IsValid()) {
		PTRACE(2, "AssignSQL\tQuery failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage());
		SNMP_TRAP(4, SNMPError, Database, "AssignedGatekeepers query failed");
		delete result;
		return false;
	}

	bool success = false;

	if (result->GetNumRows() < 1)
		PTRACE(3, "AssignSQL\tQuery returned no rows");
	else if (result->GetNumRows() > 0 && result->GetNumFields() < 1) {
		PTRACE(2, "AssignSQL\tBad-formed query - no columns found in the result set");
		SNMP_TRAP(4, SNMPError, Database, "AssignedGatekeepers query failed");
	} else {
		PStringArray retval;
		while (result->FetchRow(retval)) {
			if (retval[0].IsEmpty()) {
				PTRACE(1, "AssignSQL\tQuery Invalid value found.");
				SNMP_TRAP(4, SNMPError, Database, "AssignedGatekeepers query failed");
				continue;
			}
			success = true;
		    PTRACE(5, "AssignSQL\tQuery result: " << retval[0]);

			PStringArray adr_parts = SplitIPAndPort(retval[0],GK_DEF_UNICAST_RAS_PORT);
			PIPSocket::Address ip;
			if (!IsIPAddress(adr_parts[0]))
				PIPSocket::GetHostAddress(adr_parts[0],ip);
			else
				ip = adr_parts[0];
			WORD port = (WORD)(adr_parts[1].AsInteger());

			H323TransportAddress addr(ip,port);
			if (addr == H323TransportAddress(RasServer::Instance()->GetRasAddress(ip))) {
				PTRACE(5, "AssignSQL\tIGNORE " << retval[0] << " LRQ loop detected.");
				continue;
			}
			newGks.AppendString(retval[0]);
		}
	}
	delete result;

	return success;
}
#endif	// HAS_DATABASE

void Toolkit::AssignedGatekeepers::LoadConfig(PConfig * m_config)
{
	assignedGKList.clear();

#if HAS_DATABASE
	if (LoadSQL(m_config)) {
		m_sqlactive = true;
	} else
#endif
	{
		const PStringToString kv = m_config->GetAllKeyValues(AssignedGatekeeperSection);
		for (PINDEX i = 0; i < kv.GetSize(); i++)
			assignedGKList.push_back(std::pair<PString, PString>(kv.GetKeyAt(i),kv.GetDataAt(i)));
	}
}

#ifdef H323_H350
bool Toolkit::AssignedGatekeepers::QueryH350Directory(const PString & alias, const PIPSocket::Address & ip, PStringArray & addresses)
{
	// support gatekeeper discovery
	if (!Toolkit::AsBool(GkConfig()->GetString(H350Section, "GatekeeperDiscovery", "0")))
		return false;

	// search the directory
	PString search = GkConfig()->GetString(H350Section, "SearchBaseDN", "");

	H225_AliasAddress aliasaddress;
	H323SetAliasAddress(alias, aliasaddress);

	PString filter;
	switch (aliasaddress.GetTag()) {
		case H225_AliasAddress::e_dialedDigits:
            filter = "h323IdentitydialedDigits=" + alias;
			break;
		case H225_AliasAddress::e_h323_ID:
            filter = "h323Identityh323-ID=" + alias;
			break;
		case H225_AliasAddress::e_url_ID:
		    filter = "h323IdentityURL-ID=" + alias;
			break;
		default:
			PTRACE(4, "H350\tAssigned GK: unhandled alias type " << aliasaddress.GetTagName());
			return false;
	}

	H350_Session session;
	if (!Toolkit::Instance()->CreateH350Session(&session)) {
		PTRACE(1, "H350\tAssigned GK: Could not connect to Server.");
		return false;
	}

	H350_Session::LDAP_RecordList rec;
	int count = session.Search(search, filter, rec);
	if (count <= 0) {
		PTRACE(4, "H350\tAssigned GK: No Record Found");
		session.Close();
		return false;
	}

	// locate the record
	for (H350_Session::LDAP_RecordList::const_iterator x = rec.begin(); x != rec.end(); ++x) {
		H350_Session::LDAP_Record entry = x->second;
		PString gk;
		if (session.GetAttribute(entry, "h323IdentityGKDomain", gk)) {
			PTRACE(2, "H350\tAssigned GK: GK located " << gk);
			addresses = gk.Lines();
			session.Close();
			return true;
		}
	}

	PTRACE(4, "H350\tAssigned GK: No valid Assigned GK found");
	session.Close();
	return false;
}
#endif

bool Toolkit::AssignedGatekeepers::QueryAssignedGK(const PString & alias, const PIPSocket::Address & ip, PStringArray & addresses)
{
#if HAS_DATABASE
	if (DatabaseLookup(alias, ip, addresses))
		return true;
#endif
#ifdef H323_H350
	if (QueryH350Directory(alias, ip, addresses))
		return true;
#endif

	return false;
}

#ifdef hasSRV
static PString DNStoIP(const PString & dns)
{
	H323TransportAddress iface(dns);
	PIPSocket::Address ip;
	WORD port = GK_DEF_UNICAST_RAS_PORT;
	iface.GetIpAndPort(ip, port);
	return AsString(ip, port);
}
#endif

bool Toolkit::AssignedGatekeepers::GetAssignedGK(const PString & alias, const PIPSocket::Address & ip, H225_ArrayOf_AlternateGK & gklist)
{
	PStringArray assignedGK;
	bool found = QueryAssignedGK(alias, ip, assignedGK);

	if (!found) {
		for (unsigned j = 0; j < assignedGKList.size(); j++) {
			PString match = assignedGKList[j].first.Trim();
			if (match.Left(1) != "^") {
				// prefix match
				if (MatchPrefix(alias,assignedGKList[j].first)) {
					assignedGK.AppendString(assignedGKList[j].second);
					found = true;
				}
			} else {
				// regex match for IP address
				if (MatchRegex(ip.AsString(), match)) {
					assignedGK.AppendString(assignedGKList[j].second);
					found = true;
				}
			}
		}
	}

	if (found) {
		PStringArray ipaddresses;
		for (PINDEX k = 0; k < assignedGK.GetSize(); k++) {
			PString number = assignedGK[k];

			if (IsIPAddress(number))
				ipaddresses.AppendString(number);
#ifdef hasSRV
			else {
				PString xnum = assignedGK[k];
				if (xnum.Left(5) != "h323:")
					xnum = "h323:user@" + xnum;

				PStringList str;
				if (PDNS::LookupSRV(xnum, "_h323rs._udp.",str)) {
					PTRACE(4, "AssignGK\t" << str.GetSize() << " SRV Records found" );
					for (PINDEX i = 0; i < str.GetSize(); i++) {
						PString newhost = str[i].Right(str[i].GetLength()-5);
						PTRACE(4, "AssignedGK\tDNS SRV converted GK address " << number << " to " << newhost );
						ipaddresses.AppendString(newhost);
					}
				} else {
					ipaddresses.AppendString(DNStoIP(number));
				}
			}
#endif
		}

		for (PINDEX k = 0; k < ipaddresses.GetSize(); k++) {
			PString num = ipaddresses[k];
			PStringArray tokens = SplitIPAndPort(num, GK_DEF_UNICAST_RAS_PORT);
			WORD port = (WORD)tokens[1].AsUnsigned();

			int sz = gklist.GetSize();
			gklist.SetSize(sz+1);
			H225_AlternateGK & alt = gklist[sz];
			alt.m_rasAddress = SocketToH225TransportAddr(PIPSocket::Address(tokens[0]), port);
			alt.m_needToRegister = true;
			alt.m_priority = k;
		}
	}

	return found;
}
#endif

/////////////////////////////////////////////////////////////////////////////////////////

#if HAS_DATABASE
Toolkit::AlternateGatekeepers::AlternateGatekeepers()
	: m_sqlactive(false), m_sqlConn(NULL), m_timeout(-1)
{
}

Toolkit::AlternateGatekeepers::~AlternateGatekeepers()
{
}

void Toolkit::AlternateGatekeepers::LoadConfig(PConfig * cfg)
{
	delete m_sqlConn;
	const PString authName = "AlternateGatekeepers::SQL";

	if (cfg->GetSections().GetStringsIndex(authName) == P_MAX_INDEX)
		return;

	const PString driverName = cfg->GetString(authName, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(1, "AltGKSQL\tModule creation failed: no SQL driver selected");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "AltGKSQL\tFATAL: Shutting down");
		return;
	}

	m_sqlConn = GkSQLConnection::Create(driverName, authName);
	if (m_sqlConn == NULL) {
		PTRACE(1, "AltGKSQL\tModule creation failed: "
			"Could not find " << driverName << " database driver");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "AltGKSQL\tFATAL: Shutting down");
		return;
	}

	m_query = cfg->GetString(authName, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(1, "AltGKSQL\tModule creation failed: No query configured");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "AltGKSQL\tFATAL: Shutting down");
		return;
	} else
		PTRACE(4, "AltGKSQL\tQuery: " << m_query);

	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(1, "AltGKSQL\tModule creation failed: Could not connect to the database");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		return;
	}

	m_sqlactive = true;
}

bool Toolkit::AlternateGatekeepers::GetAlternateGK(const PIPSocket::Address & ip, H225_ArrayOf_AlternateGK & gklist)
{
    PStringArray addresses;
    if (QueryAlternateGK(ip, addresses)) {
		for (PINDEX k = 0; k < addresses.GetSize(); k++) {
			PString num = addresses[k];
			PStringArray tokens = SplitIPAndPort(num, GK_DEF_UNICAST_RAS_PORT);
			WORD port = (WORD)tokens[1].AsUnsigned();
			PIPSocket::Address ipAddress;
			PIPSocket::GetHostAddress(tokens[0], ipAddress);
			int sz = gklist.GetSize();
			gklist.SetSize(sz+1);
			H225_AlternateGK & alt = gklist[sz];
			alt.m_rasAddress = SocketToH225TransportAddr(ipAddress,port);
			alt.m_needToRegister = true;
			alt.m_priority = k;
		}
        return true;
    }
    return false;
}

bool Toolkit::AlternateGatekeepers::QueryAlternateGK(const PIPSocket::Address & ip, PStringArray & addresses)
{
	if (!m_sqlactive)
		return false;

	std::map<PString, PString> params;
	params["i"] = ip.AsString();
    params["g"] = GKName();
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, params, m_timeout);
	if (result == NULL) {
		PTRACE(2, "AltGKSQL\tQuery failed - timeout or fatal error");
		SNMP_TRAP(5, SNMPError, Database, "AlternateGatekeepers query failed");
		return false;
	}

	if (!result->IsValid()) {
		PTRACE(2, "AltGKSQL\tQuery failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage());
		SNMP_TRAP(5, SNMPError, Database, "AlternateGatekeepers query failed");
		delete result;
		return false;
	}

	bool success = false;

	if (result->GetNumRows() < 1)
		PTRACE(3, "AltGKSQL\tQuery returned no rows");
	else if (result->GetNumRows() > 0 && result->GetNumFields() < 1) {
		PTRACE(2, "AltGKSQL\tBad-formed query - no columns found in the result set");
		SNMP_TRAP(5, SNMPError, Database, "AlternateGatekeepers query failed");
	} else {
		PStringArray retval;
		while (result->FetchRow(retval)) {
			if (retval[0].IsEmpty()) {
				PTRACE(1, "AltGKSQL\tQuery Invalid value found.");
				SNMP_TRAP(5, SNMPError, Database, "AlternateGatekeepers query failed");
				continue;
			}
			success = true;
		    PTRACE(5, "AltGKSQL\tQuery result: " << retval[0]);
			addresses.AppendString(retval[0]);
		}
	}
	delete result;

	return success;
}
#endif

/////////////////////////////////////////////////////////////////////////////////////////

#if HAS_DATABASE
Toolkit::GnuGkAssignedGatekeepers::GnuGkAssignedGatekeepers()
	: m_sqlactive(false), m_sqlConn(NULL), m_timeout(-1)
{
}

Toolkit::GnuGkAssignedGatekeepers::~GnuGkAssignedGatekeepers()
{
}

void Toolkit::GnuGkAssignedGatekeepers::LoadConfig(PConfig * cfg)
{
	delete m_sqlConn;
	const PString authName = "GnuGkAssignedGatekeepers::SQL";

	if (cfg->GetSections().GetStringsIndex(authName) == P_MAX_INDEX)
		return;

	const PString driverName = cfg->GetString(authName, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(1, "GnuGkAssignedGkSQL\tModule creation failed: no SQL driver selected");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "GnuGkAssignedGkSQL\tFATAL: Shutting down");
		return;
	}

	m_sqlConn = GkSQLConnection::Create(driverName, authName);
	if (m_sqlConn == NULL) {
		PTRACE(1, "GnuGkAssignedGkSQL\tModule creation failed: "
			"Could not find " << driverName << " database driver");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "GnuGkAssignedGkSQL\tFATAL: Shutting down");
		return;
	}

	m_query = cfg->GetString(authName, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(1, "GnuGkAssignedGkSQL\tModule creation failed: No query configured");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "GnuGkAssignedGkSQL\tFATAL: Shutting down");
		return;
	} else
		PTRACE(4, "GnuGkAssignedGkSQL\tQuery: " << m_query);

	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(1, "GnuGkAssignedGkSQL\tModule creation failed: Could not connect to the database");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		return;
	}

	m_sqlactive = true;
}


bool Toolkit::GnuGkAssignedGatekeepers::HasAssignedGk(endptr ep, const PIPSocket::Address & ip)
{
	if (!m_sqlactive)
		return false;

	std::map<PString, PString> params;
	if (ep->GetAliases().GetSize() > 0) {
        params["u"] = ::AsString((ep->GetAliases()[0]), false);  // TODO: repeat query for all aliases ???
	}
	params["i"] = ip.AsString();
	params["g"] = GKName();
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, params, m_timeout);
	if (result == NULL) {
		PTRACE(2, "GnuGkAssignedGkSQL\tQuery failed - timeout or fatal error");
		SNMP_TRAP(5, SNMPError, Database, "GnuGkAssignedGatekeeper query failed");
		return false;
	}

	if (!result->IsValid()) {
		PTRACE(2, "GnuGkAssignedGkSQL\tQuery failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage());
		SNMP_TRAP(5, SNMPError, Database, "GnuGkAssignedGatekeeper query failed");
		delete result;
		return false;
	}

	bool found = false;

	if (result->GetNumRows() < 1)
		PTRACE(3, "GnuGkAssignedGkSQL\tQuery returned no rows");
	else if (result->GetNumRows() > 0 && result->GetNumFields() < 1) {
		PTRACE(2, "GnuGkAssignedGkSQL\tBad-formed query - no columns found in the result set");
		SNMP_TRAP(5, SNMPError, Database, "GnuGkAssignedGatekeeper query failed");
	} else {
		PStringArray retval;
		while (result->FetchRow(retval)) {  // TODO: if instead of while ?
		    PTRACE(5, "GnuGkAssignedGkSQL\tQuery result: " << retval[0]);
		    PIPSocket::Address gkip;
		    WORD port_unused;
		    if (!retval[0].IsEmpty() && GetTransportAddress(retval[0], 0, gkip, port_unused) && !Toolkit::Instance()->IsGKHome(gkip)) {
                // if an assigned GK IP is set and it is not one of our IPs, then save it in the EpRec and throw the endpoint back once the assigned gk is ready
                ep->SetGnuGkAssignedGk(gkip);
                found = true;
		    }
		}
	}
	delete result;

	return found;
}
#endif

///////////////////////////////////////////////////////////////////////////////////////

#ifdef HAS_LANGUAGE
#if HAS_DATABASE
Toolkit::AssignedLanguage::AssignedLanguage()
  : m_sqlactive(false), m_sqlConn(NULL), m_timeout(-1)
{
}

Toolkit::AssignedLanguage::~AssignedLanguage()
{
}

bool Toolkit::AssignedLanguage::LoadSQL(PConfig * cfg)
{
	delete m_sqlConn;
	PString authName = "AssignedLanguage::SQL";

	if (cfg->GetSections().GetStringsIndex(authName) == P_MAX_INDEX)
		return false;

	const PString driverName = cfg->GetString(authName, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(0, "AssignSQL\tModule creation failed: no SQL driver selected");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		return false;
	}

	m_sqlConn = GkSQLConnection::Create(driverName, authName);
	if (m_sqlConn == NULL) {
		PTRACE(0, "AssignSQL\tModule creation failed: "
			"Could not find " << driverName << " database driver");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		return false;
	}

	m_query = cfg->GetString(authName, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(0, "AssignSQL\tModule creation failed: No query configured");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		return false;
	} else
		PTRACE(4, "AssignSQL\tQuery: " << m_query);

	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(0, "AssignSQL\tModule creation failed: Could not connect to the database");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		return false;
	}

	m_sqlactive = true;
	return true;
}

bool Toolkit::AssignedLanguage::DatabaseLookup(
		const PString & alias,
		PStringArray & languages
		)
{
	if (!m_sqlactive)
		return false;

	std::map<PString, PString> params;
	params["u"] = alias;
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, params, m_timeout);
	if (result == NULL) {
		PTRACE(2, "LangSQL\tQuery failed - timeout or fatal error");
		SNMP_TRAP(4, SNMPError, Database, "AssignedLanguage query failed");
		return false;
	}

	if (!result->IsValid()) {
		PTRACE(2, "LangSQL\tQuery failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage());
		SNMP_TRAP(4, SNMPError, Database, "AssignedLanguage query failed");
		delete result;
		return false;
	}

	bool success = false;

	if (result->GetNumRows() < 1)
		PTRACE(3, "LangSQL\tQuery returned no rows");
	else if (result->GetNumRows() > 0 && result->GetNumFields() < 1) {
		PTRACE(2, "LangSQL\tBad-formed query - no columns found in the result set");
		SNMP_TRAP(4, SNMPError, Database, "AssignedLanguage query failed");
	} else {
		PStringArray retval;
		while (result->FetchRow(retval)) {
			if (retval[0].IsEmpty()) {
				PTRACE(1, "LangSQL\tQuery Invalid value found.");
				SNMP_TRAP(4, SNMPError, Database, "AssignedLanguage query failed");
				continue;
			}
			if (!success) success = true;
			PTRACE(5, "LangSQL\tQuery result: " << retval[0]);

			languages.AppendString(retval[0]);
		}
	}
	delete result;

	return success;
}
#endif	// HAS_DATABASE

bool Toolkit::AssignedLanguage::QueryAssignedLanguage(const PString & alias, PStringArray & languages)
{
#if HAS_DATABASE
	if (DatabaseLookup(alias, languages))
		return true;
#endif
	return false;
}

bool Toolkit::AssignedLanguage::GetLanguage(const H225_ArrayOf_AliasAddress & alias, PStringArray & aliaslist)
{
	for (PINDEX i = 0; i < alias.GetSize(); ++i) {
		QueryAssignedLanguage(H323GetAliasAddressString(alias[i]),aliaslist);
	}
	return (aliaslist.GetSize() > 0);

}
#endif  // HAS_LANGUAGE

//////////////////////////////////////////////////////////////////////////////////////

#if HAS_DATABASE
Toolkit::QoSMonitor::QoSMonitor()
  : m_sqlactive(false), m_sqlConn(NULL), m_timeout(-1)
{
}

Toolkit::QoSMonitor::~QoSMonitor()
{
}

void Toolkit::QoSMonitor::LoadConfig(PConfig * cfg)
{
	delete m_sqlConn;
	PString authName = "GkQoSMonitor::SQL";

	if (cfg->GetSections().GetStringsIndex(authName) == P_MAX_INDEX)
		return;

	const PString driverName = cfg->GetString(authName, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(1, "QoSSQL\tModule creation failed: no SQL driver selected");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "QoSSQL\tFATAL: Shutting down");
		return;
	}

	m_sqlConn = GkSQLConnection::Create(driverName, authName);
	if (m_sqlConn == NULL) {
		PTRACE(1, "QoSSQL\tModule creation failed: "
			"Could not find " << driverName << " database driver");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "QoSSQL\tFATAL: Shutting down");
		return;
	}

	m_query = cfg->GetString(authName, "Query", "");
	if (m_query.IsEmpty()) {
		PTRACE(1, "QoSSQL\tModule creation failed: No query configured");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		PTRACE(0, "QoSSQL\tFATAL: Shutting down");
		return;
	} else
		PTRACE(4, "QoSSQL\tQuery: " << m_query);

	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(1, "QoSSQL\tModule creation failed: Could not connect to the database");
		SNMP_TRAP(4, SNMPError, Database, authName + " creation failed");
		return;
	}

	m_sqlactive = true;

}

bool Toolkit::QoSMonitor::PostRecord(const std::map<PString, PString>& params)
{
	if (!m_sqlactive)
		return false;

	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_query, params, m_timeout);

	if (result == NULL) {
		PTRACE(2, "QoSSQL\tFailed to store QoS Data: Timeout or fatal error");
		SNMP_TRAP(5, SNMPError, Database, "QoSMonitor query failed");
		return false;
	}

	if (result) {
		if (result->IsValid()) {
			if (result->GetNumRows() < 1) {
				PTRACE(4, "QoSSQL\tFailed to store QoS Data: No rows have been updated");
				SNMP_TRAP(5, SNMPError, Database, "QoSMonitor query failed");
				delete result;
				return false;
			}
		} else {
			PTRACE(2, "QoSSQL\tfailed to store QoS Data: Err(" << result->GetErrorCode() << ") "
				<< result->GetErrorMessage() );
			SNMP_TRAP(5, SNMPError, Database, "QoSMonitor query failed");
			delete result;
			return false;
		}
	}

	delete result;
	return true;
}
#endif

bool Toolkit::PASNEqual(PASN_OctetString *str1, PASN_OctetString *str2)
{
	if (str1 && str2) {
		if (str1->GetSize() < str2->GetSize()) return false;
		const unsigned char *s1 = *str1;
		const unsigned char *s2 = *str2;
		for (int i = 0; i < str2->GetSize(); i++) {
			if (s1[i] != s2[i]) return false;
		}
		return true;
	}
	return false;
}

bool Toolkit::RewriteE164(H225_AliasAddress & alias)
{
	if ((alias.GetTag() != H225_AliasAddress::e_dialedDigits) &&
		(alias.GetTag() != H225_AliasAddress::e_h323_ID) &&
		(alias.GetTag() != H225_AliasAddress::e_url_ID) &&
		(alias.GetTag() != H225_AliasAddress::e_email_ID)) {
		if (alias.GetTag() != H225_AliasAddress::e_partyNumber)
			return false;
		H225_PartyNumber & partyNumber = alias;
		if (partyNumber.GetTag() != H225_PartyNumber::e_e164Number && partyNumber.GetTag() != H225_PartyNumber::e_privateNumber)
			return false;
	}

	PString E164 = ::AsString(alias, FALSE);

	bool changed = RewritePString(E164);
	if (changed) {
		if (E164.Find("@") != P_MAX_INDEX)
			H323SetAliasAddress(E164, alias,H225_AliasAddress::e_url_ID);
		else if (IsValidE164(E164))
			H323SetAliasAddress(E164, alias, H225_AliasAddress::e_dialedDigits);
		else if (alias.GetTag() != H225_AliasAddress::e_partyNumber)
			H323SetAliasAddress(E164, alias, H225_AliasAddress::e_h323_ID);
		else {
			H225_PartyNumber & partyNumber = alias;
			if (partyNumber.GetTag() == H225_PartyNumber::e_e164Number) {
				H225_PublicPartyNumber &number = partyNumber;
				number.m_publicNumberDigits = E164;
			} else if (partyNumber.GetTag() == H225_PartyNumber::e_privateNumber) {
				H225_PrivatePartyNumber &number = partyNumber;
				number.m_privateNumberDigits = E164;
			}
		}
	}

	return changed;
}

bool Toolkit::RewriteE164(H225_ArrayOf_AliasAddress & aliases)
{
	bool changed = false;
	for (PINDEX n = 0; n < aliases.GetSize(); ++n)
		changed |= RewriteE164(aliases[n]);
	return changed;
}

bool Toolkit::GWRewriteE164(const PString & gw, bool direction, H225_AliasAddress & alias, callptr call)
{
	if (alias.GetTag() != H225_AliasAddress::e_dialedDigits) {
		if (alias.GetTag() != H225_AliasAddress::e_partyNumber)
			return false;
		H225_PartyNumber & partyNumber = alias;
		if (partyNumber.GetTag() != H225_PartyNumber::e_e164Number && partyNumber.GetTag() != H225_PartyNumber::e_privateNumber)
			return false;
	}

	PString E164 = ::AsString(alias, FALSE);
	bool changed = GWRewritePString(gw, direction, E164, call);

	if (changed) {
		if (alias.GetTag() == H225_AliasAddress::e_dialedDigits)
			H323SetAliasAddress(E164, alias, alias.GetTag());
		else {
			H225_PartyNumber &partyNumber = alias;
			if (partyNumber.GetTag() == H225_PartyNumber::e_e164Number) {
				H225_PublicPartyNumber &number = partyNumber;
				number.m_publicNumberDigits = E164;
			} else if (partyNumber.GetTag() == H225_PartyNumber::e_privateNumber) {
				H225_PrivatePartyNumber &number = partyNumber;
				number.m_privateNumberDigits = E164;
			}
		}
	}

	return changed;
}

bool Toolkit::GWRewriteE164(const PString & gw, bool direction, H225_ArrayOf_AliasAddress & aliases, callptr call)
{
	bool changed = false;

	for (PINDEX n = 0; n < aliases.GetSize(); ++n) {
		changed |= GWRewriteE164(gw, direction, aliases[n], call);
	}

	return changed;
}

bool Toolkit::RemoveH235TokensFrom(const PIPSocket::Address & addr) const
{
	if (m_alwaysRemoveH235Tokens)
		return true;
	for (unsigned i = 0; i < m_removeH235TokensfromNetwork.size(); ++i) {
		if (addr << m_removeH235TokensfromNetwork[i])
			return true;
	}
	return false;
}

bool Toolkit::isBehindNAT(PIPSocket::Address & externalIP) const
{
	return (m_VirtualRouteTable.IsMasquerade(externalIP));
}

#ifdef HAS_H46023
bool Toolkit::IsH46023Enabled() const
{
	return (m_H46023Enabled && (		// is enabled and
#ifdef HAS_H46018
			m_H46018Enabled ||			// used with H.460.18 or
#endif
			m_Config->GetBoolean(RoutedSec, "SupportCallingNATedEndpoints", true))); // GnuGk Native NAT Support
}
#endif

#ifdef HAS_H46023
void Toolkit::LoadH46023STUN()
{
	m_H46023STUN.clear();

	PString stun = m_Config->GetString(RoutedSec, "H46023STUN", "");
	PStringArray stunlist = stun.Tokenise(",");

	for (PINDEX i = 0; i < stunlist.GetSize(); i++) {
		PStringList addresses;
		PStringList x = stunlist[i].Tokenise(":");
		PString number = "h323:user@" + x[0];
#ifdef P_DNS
		if (!PDNS::LookupSRV(number, "_stun._udp.", addresses))
			addresses.AppendString("h323:" + stunlist[i]);
#endif

		for (PINDEX j = 0; j < addresses.GetSize(); ++j) {
			PString newhost = addresses[j].Mid(5);
			PIPSocket::Address ip;
			WORD port;
			(void)GetTransportAddress(newhost, GK_DEF_STUN_PORT, ip, port);
			if (ip.IsValid()) {
				int intID = m_ProxyCriterion.IsInternal(ip);
				std::map<int, std::vector<H323TransportAddress> >::iterator inf = m_H46023STUN.find(intID);
				if (inf == m_H46023STUN.end()) {
					std::vector<H323TransportAddress> addrs;
					addrs.push_back(H323TransportAddress(ip, port));
					m_H46023STUN.insert(pair<int, std::vector<H323TransportAddress> >(intID, addrs));
				} else
					inf->second.push_back(H323TransportAddress(ip, port));

				PTRACE(4, "Std23\tSTUN Server added if:" << intID << " " << newhost);
			}
		}
	}
}

bool Toolkit::GetH46023STUN(const PIPSocket::Address & addr, H323TransportAddress & stun)
{
	 PWaitAndSignal m(m_stunMutex);

	 int intID = m_ProxyCriterion.IsInternal(addr);
	 std::map<int, std::vector<H323TransportAddress> >::iterator inf = m_H46023STUN.find(intID);
	 if (inf != m_H46023STUN.end()) {
		 if (inf->second.size() > 1) {
#if (__cplusplus >= 201703L) // C++17
            std::random_device rd;
            std::mt19937 g(rd());
			std::shuffle(inf->second.begin(), inf->second.end(), g);
#else
			std::random_shuffle(inf->second.begin(), inf->second.end());
#endif
         }
		 stun = inf->second.front();
		 return true;
	 }
	PTRACE(2, "Std23\tNo STUNserver for Interface " << intID << " disabling H.460.23");
	return false;
}

bool Toolkit::H46023SameNetwork(const PIPSocket::Address & addr1, const PIPSocket::Address & addr2)
{
	return (m_ProxyCriterion.IsInternal(addr1) == m_ProxyCriterion.IsInternal(addr2));
}
#endif

#ifdef HAS_H460P
bool Toolkit::IsH460PEnabled() const
{
	return m_presence.IsEnabled();
}

GkPresence & Toolkit::GetPresenceHandler()
{
	return m_presence;
}
#endif

std::vector<NetworkAddress> Toolkit::GetInternalNetworks() const
{
	return !Toolkit::Instance()->GetExternalIP().IsEmpty() ? m_VirtualRouteTable.GetInternalNetworks() : m_RouteTable.GetInternalNetworks();
}

bool Toolkit::IsPortNotificationActive()	// not const to allow simple map access
{
	// the feature is active if at least one action is defined
	return !m_portOpenNotifications[RASPort].IsEmpty()
		|| !m_portOpenNotifications[Q931Port].IsEmpty()
		|| !m_portOpenNotifications[H245Port].IsEmpty()
		|| !m_portOpenNotifications[RTPPort].IsEmpty()
		|| !m_portOpenNotifications[T120Port].IsEmpty()
		|| !m_portOpenNotifications[StatusPort].IsEmpty()
		|| !m_portOpenNotifications[RadiusPort].IsEmpty()
		|| !m_portCloseNotifications[RASPort].IsEmpty()
		|| !m_portCloseNotifications[Q931Port].IsEmpty()
		|| !m_portCloseNotifications[H245Port].IsEmpty()
		|| !m_portCloseNotifications[RTPPort].IsEmpty()
		|| !m_portCloseNotifications[T120Port].IsEmpty()
		|| !m_portCloseNotifications[StatusPort].IsEmpty()
		|| !m_portCloseNotifications[RadiusPort].IsEmpty();
}

void Toolkit::PortNotification(PortType type, PortAction action, const PString & protocol,
								const PIPSocket::Address & addr, WORD port, PINDEX callNo)
{
	PTRACE(5, "Port Notification " << ((action == PortOpen) ? "OPEN " : "CLOSE ") << PortTypeAsString(type) << " " << protocol << " " << ::AsString(addr, port));

	// book keeping for status port command
	if (callNo != 0) {
        callptr call = CallTable::Instance()->FindCallRec(callNo);
        if (call) {
            if (action == PortOpen)
                call->AddDynamicPort(DynamicPort(type, addr, port));
            else
                call->RemoveDynamicPort(DynamicPort(type, addr, port));
        }
	}

	// execute notification command
	PString cmd;
	if (action == PortOpen) {
		cmd = m_portOpenNotifications[type];
	} else if (action == PortClose) {
		cmd = m_portCloseNotifications[type];
	}

	if (cmd.IsEmpty())
		return;

	// set port arguments
	cmd.Replace("%p", protocol);
	cmd.Replace("%n", PString(port));
	cmd.Replace("%i", ::AsString(addr));
	cmd.Replace("%t", PortTypeAsString(type));

	if(system(cmd) == -1) {
		PTRACE(1, "Error executing port notification: " << cmd);
		SNMP_TRAP(6, SNMPError, General, "Error executing port notification: " + cmd);
	}
}

PString Toolkit::GetGKHome(vector<PIPSocket::Address> & GKHome) const
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
	m_GKHome.clear();
	for (PINDEX n = 0; n < home.GetSize(); ++n)
		m_GKHome.push_back(PIPSocket::Address(home[n]));

	PIPSocket::InterfaceTable it;
	if (PIPSocket::GetInterfaceTable(it)) {
		int is = it.GetSize();
		// check if the interface is valid
		for (size_t n = 0; n < m_GKHome.size(); ++n) {
			PINDEX i = 0;
			for (i = 0; i < is; ++i)
				if (m_GKHome[n] == it[i].GetAddress())
					break;
			if (i == is) {
				// just warn, secondary IPs or IPv6 IPs (w older PTLib) aren't found this way
				PTRACE(1, "GK\tAddress " << m_GKHome[n] << " not found"
					" in the PTLib interface table");
			}
		}

		// if no home interfaces specified, set all IPs from interface table
		// except INADDR_ANY
		if (m_GKHome.empty()) {
			for (PINDEX n = 0; n < it.GetSize(); ++n) {
				m_GKHome.push_back(it[n].GetAddress());
			}
		}
		// remove INADDR_ANY
		for (size_t n = 0; n < m_GKHome.size(); ++n) {
			if ((m_GKHome[n] == INADDR_ANY)
#ifdef hasIPV6
				|| m_GKHome[n].IsLinkLocal()
				|| ((m_GKHome[n].GetVersion() == 6) && m_GKHome[n].IsLoopback())
#endif
				) {
				m_GKHome.erase(m_GKHome.begin() + n);
				--n;	// re-test the new element on position n
			}
		}
		// if IPv6 is not enabled, remove _all_ IPv6 addresses
		if (!IsIPv6Enabled()) {
			for (size_t n = 0; n < m_GKHome.size(); ++n) {
				if (m_GKHome[n].GetVersion() == 6) {
					m_GKHome.erase(m_GKHome.begin() + n);
					--n;	// re-test the new element on position n
				}
			}
		}
	}

	// remove duplicate interfaces
	sort(m_GKHome.begin(), m_GKHome.end());
	std::vector<PIPSocket::Address>::iterator end_unique = unique(m_GKHome.begin(), m_GKHome.end());
	m_GKHome.erase(end_unique, m_GKHome.end());

	// move loopback interfaces to the end
	std::list<PIPSocket::Address> sortedHomes;
	for (unsigned j = 0; j < m_GKHome.size(); j++) {
		if (m_GKHome[j].IsLoopback()) {
			sortedHomes.push_back(m_GKHome[j]);
		} else {
			sortedHomes.push_front(m_GKHome[j]);
		}
	}
	m_GKHome.assign(sortedHomes.begin(), sortedHomes.end());
}

bool Toolkit::IsGKHome(const PIPSocket::Address & addr) const
{
	for (std::vector<PIPSocket::Address>::const_iterator i = m_GKHome.begin(); i != m_GKHome.end(); ++i) {
		if (*i == addr) {
			return true;
		}
	}
	return false;
}

H225_ArrayOf_AlternateGK Toolkit::GetMaintenanceAlternate() const
{
    H225_ArrayOf_AlternateGK gklist;
    gklist.SetSize(0);
    if (!m_maintenanceAlternate.IsEmpty()) {
        gklist.SetSize(1);
        PStringArray tokens = SplitIPAndPort(m_maintenanceAlternate, GK_DEF_UNICAST_RAS_PORT);
        WORD port = (WORD)tokens[1].AsUnsigned();
        PIPSocket::Address ipAddress;
        PIPSocket::GetHostAddress(tokens[0], ipAddress);
        H225_AlternateGK & alt = gklist[0];
        alt.m_rasAddress = SocketToH225TransportAddr(ipAddress,port);
        alt.m_needToRegister = true;
        alt.m_priority = 1;
    }
    return gklist;
}


PString Toolkit::GetExternalIP() const
{

    PCaselessString ext = m_Config->GetString("ExternalIP", "");
#ifdef P_HTTP
    if (ext == "AlibabaPublicIP" || ext == "AWSPublicIP" || ext == "AzurePublicIP" || ext == "GooglePublicIP") {
        // fetch public / elastic IP from meta data
        PHTTPClient http;	// TODO: add libcurl version ?
        PString result;
        PMIMEInfo outMIME, replyMIME;
        PString url = "http://169.254.169.254/latest/meta-data/public-ipv4"; // AWS
        if (ext == "AlibabaPublicIP")
            url = "http://100.100.100.200/latest/meta-data/eipv4"; // Alibaba TODO: when use public-ipv4 instead ?
        if (ext == "AzurePublicIP") {
            url = "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-08-01&format=text"; // Azure
            outMIME.SetAt("Metadata", "true");
        }
        if (ext == "GooglePublicIP") {
            url = "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"; // Google Cloud
            outMIME.SetAt("Metadata-Flavor", "Google");
        }
        if (http.GetDocument(url, outMIME, replyMIME) && http.ReadContentBody(replyMIME, result)) {
            ext = result.Trim();
        } else {
            ext = "";
        }
        PTRACE(2, "Cloud\tSetting ExternalIP to " << ext);
        // write to config so we don't have to re-do the HTTP request next time
        m_Config->SetString("ExternalIP", ext);
    }
#endif // P_HTTP
    return ext;
}

PString Toolkit::ReplaceGlobalParams(const PString & str)
{
    PString result = str;
    vector<PIPSocket::Address> interfaces;
	GetGKHome(interfaces);

    if (interfaces.empty())
		result.Replace("%{gkip}", "", true);
	else
		result.Replace("%{gkip}", interfaces.front().AsString(), true);
    result.Replace("%{external-ip}", GetExternalIP(), true);

    result.Replace("%{registrations}", RegistrationTable::Instance()->Size(), true);
    result.Replace("%{calls}", CallTable::Instance()->Size(), true);
    result.Replace("%{allocated-bandwidth}", CallTable::Instance()->GetTotalAllocatedBandwidth(), true);
    result.Replace("%{total-calls}", CallTable::Instance()->TotalCallCount(), true);
    result.Replace("%{successful-calls}", CallTable::Instance()->SuccessfulCallCount(), true);

    result.Replace("%{env1}", ::getenv("GNUGK_ENV1"), true);
    result.Replace("%{env2}", ::getenv("GNUGK_ENV2"), true);
    result.Replace("%{env3}", ::getenv("GNUGK_ENV3"), true);
    result.Replace("%{env4}", ::getenv("GNUGK_ENV4"), true);
    result.Replace("%{env5}", ::getenv("GNUGK_ENV5"), true);
    result.Replace("%{env6}", ::getenv("GNUGK_ENV6"), true);
    result.Replace("%{env7}", ::getenv("GNUGK_ENV7"), true);
    result.Replace("%{env8}", ::getenv("GNUGK_ENV8"), true);
    result.Replace("%{env9}", ::getenv("GNUGK_ENV9"), true);

    return result;
}

int Toolkit::GetInternalExtensionCode(const unsigned & country,
				   const unsigned & extension,
				   const unsigned & manufacturer) const
{
	switch (country) {
	case t35cOpenOrg:
		switch (manufacturer) {
		case t35mOpenOrg:
			switch (extension) {
				case t35eFailoverRAS: return iecFailoverRAS;
			}
			break;
		}
		break;

	case t35cPoland:
		switch (manufacturer) {
		case t35mGnuGk:
			switch (extension) {
			case t35eNeighborId:
				return iecNeighborId;
			case t35eNATTraversal:
				return iecNATTraversal;
			}
			break;
		}
		break;
	}

	// default for all other cases
	return iecUnknown;
}

int Toolkit::GetInternalExtensionCode(const H225_H221NonStandard & data) const
{
	return GetInternalExtensionCode(data.m_t35CountryCode,
			data.m_t35Extension,
			data.m_manufacturerCode);
}

bool Toolkit::AsBool(const PString & str)
{
	if (str.IsEmpty())
		return false;
	const unsigned char c = (unsigned char)tolower(str[0]);
	return ( c=='t' || c=='1' || c=='y' || c=='a' );
}

void Toolkit::GetNetworkFromString(
	const PString & s,
	PIPSocket::Address & network,
	PIPSocket::Address & netmask)
{
	if (s *= "ALL") {
		network = netmask = GNUGK_INADDR_ANY;
		return;
	}

	PINDEX slashPos = s.Find('/');
	if (slashPos == P_MAX_INDEX) {
		// a single IP
		static BYTE fullNetMask[16] = {
			255, 255, 255, 255, 255, 255, 255, 255,
			255, 255, 255, 255, 255, 255, 255, 255
			};
		network = PIPSocket::Address(s);
		netmask = PIPSocket::Address(network.GetSize(), fullNetMask);
	} else {
		network = PIPSocket::Address(s.Left(slashPos));

		const PString netmaskString = s.Mid(slashPos + 1);
		BYTE rawData[16];
		memset(&rawData, 0, sizeof(rawData));

		if (netmaskString.FindOneOf(".:") != P_MAX_INDEX) {
			// netmask as a network address
			netmask = PIPSocket::Address(netmaskString);
		} else {
			// netmask as an integer
			const DWORD netmaskLen = netmaskString.AsUnsigned();
			for (unsigned b = 0; b < (unsigned)(network.GetSize() * 8); b++)
				if (b < netmaskLen)
					rawData[b >> 3] |= 0x80U >> (b & 7);
				else
					rawData[b >> 3] &= ~(0x80U >> (b & 7));
			netmask = PIPSocket::Address(network.GetSize(), rawData);
		}

		// normalize the address
		for (unsigned b = 0; b < (unsigned)(network.GetSize()); b++)
			rawData[b] = network[b] & netmask[b];

		network = PIPSocket::Address(network.GetSize(), rawData);
	}
}

PString Toolkit::GenerateAcctSessionId()
{
	PWaitAndSignal lock(m_acctSessionMutex);
	return psprintf(PString("%08x%08x"), m_acctSessionBase, ++m_acctSessionCounter);
}

PString Toolkit::AsString(
	const PTime & tm, /// timestamp to convert into a string
	const PString & formatStr /// format string to use
	) const
{
	PString fmtStr = !formatStr ? formatStr : m_timestampFormatStr;
	if (fmtStr.IsEmpty())
		return PString::Empty();

	if (fmtStr *= "Cisco")
		fmtStr = "%H:%M:%S.%u %Z %a %b %d %Y";
	else if (fmtStr *= "ISO8601")
		return tm.AsString(PTime::LongISO8601);
	else if (fmtStr *= "RFC822")
		return tm.AsString(PTime::RFC1123);
	else if (fmtStr *= "MySQL")
		fmtStr = "%Y-%m-%d %H:%M:%S";
	else if (fmtStr *= "Oracle")
		fmtStr = "%d-%b-%Y %I:%M:%S %P";

	struct tm _tm;
	struct tm* tmptr = &_tm;
	time_t t = tm.GetTimeInSeconds();

#if !defined(_WIN32) && !defined(_WIN64)
	if (localtime_r(&t, tmptr) != tmptr) {
#else
	tmptr = localtime(&t);
	if (tmptr == NULL) {
#endif
		SNMP_TRAP(7, SNMPError, Configuration, "Invalid timestamp format - using default");
		PTRACE(1, "TOOLKIT\tCould not apply timestamp formatting - using default");
		return tm.AsString( "hh:mm:ss.uuu z www MMM d yyyy" );
	}

	// replace %u with microseconds - this is our extension
	PINDEX i = 0;
	PINDEX length = fmtStr.GetLength();
	do {
		i = fmtStr.Find("%u", i);
		if (i != P_MAX_INDEX) {
			if (i > 0 && fmtStr[i-1] == '%') {
				i += 2;
				continue;
			}
			const PString us(PString::Printf, "%03d", (unsigned)tm.GetMicrosecond());
			fmtStr.Splice(us, i, 2);
			length += us.GetLength();
			i += us.GetLength();
			length -= 2;
		}
	} while (i != P_MAX_INDEX && i < length);

	char buf[128];
	if (strftime(buf, sizeof(buf), (const char*)fmtStr, tmptr) == 0) {
		SNMP_TRAP(7, SNMPError, Configuration, "Invalid timestamp format - using default");
		PTRACE(1, "TOOLKIT\tCould not apply timestamp formatting - using default");
		return tm.AsString( "hh:mm:ss.uuu z www MMM d yyyy" );
	}

	return buf;
}

PString Toolkit::ReadPassword(
	const PString & cfgSection, /// config section to read
	const PString & cfgKey, /// config key to read an encrypted password from
	bool forceEncrypted
	)
{
	if (cfgSection.IsEmpty() || cfgKey.IsEmpty())
		return PString::Empty();

	PConfig * const cfg = Config();
	if (!cfg->HasKey(cfgSection, cfgKey))
		return PString::Empty();

	int paddingByte = m_encKeyPaddingByte;
	if (cfg->HasKey(cfgSection, paddingByteConfigKey)) {
		paddingByte = cfg->GetInteger(cfgSection, paddingByteConfigKey, 0);
	}

	if (paddingByte == -1) {
		if (forceEncrypted || m_encryptAllPasswords) {
			paddingByte = 0;
		} else {
			return cfg->GetString(cfgSection, cfgKey, "");
		}
	}

	PTEACypher::Key encKey;
	memset(&encKey, paddingByte, sizeof(encKey));

	const size_t keyLen = cfgKey.GetLength();
	if (keyLen > 0) {
		memcpy(&encKey, (const char*)cfgKey, min(keyLen, sizeof(encKey)));
	}

	PTEACypher cypher(encKey);
	PString s;
	if (!cypher.Decode(cfg->GetString(cfgSection, cfgKey, ""), s)) {
		PTRACE(1, "GK\tFailed to decode config password for [" << cfgSection << "] => " << cfgKey);
		SNMP_TRAP(7, SNMPError, General, "Password decode failed");
	}
	return s;
}

void Toolkit::RewriteCLI(SetupMsg & msg) const
{
	m_cliRewrite->InRewrite(msg);
}

void Toolkit::RewriteCLI(SetupMsg & msg, SetupAuthData & authData, const PIPSocket::Address & addr) const
{
	m_cliRewrite->OutRewrite(msg, authData, addr);
}

void Toolkit::RewriteSourceAddress(SetupMsg & setup) const
{
	// Read RewriteSourceAddress settings
	PString rewriteChar = m_Config->GetString("RewriteSourceAddress", "ReplaceChar", "");
	PString rules       = m_Config->GetString("RewriteSourceAddress", "Rules", "");
	bool matchSource    = m_Config->GetBoolean("RewriteSourceAddress", "MatchSourceTypeToDestination", false);
	bool onlyE164       = m_Config->GetBoolean("RewriteSourceAddress", "OnlyE164", false);
	bool only10Dand11D  = m_Config->GetBoolean("RewriteSourceAddress", "OnlyValid10Dand11D", false);
	bool treatNumberURIDialedDigits = m_Config->GetBoolean("RewriteSourceAddress", "TreatNumberURIDialedDigits", false);
	int aliasForceType  = m_Config->GetString("RewriteSourceAddress", "ForceAliasType", "-1").AsInteger();
	if (aliasForceType > 2)
        aliasForceType = -1;  // Limited only to support dialedDigits, h323_ID, url_ID,

	H225_Setup_UUIE & setupBody = setup.GetUUIEBody();
	unsigned destType = H225_AliasAddress::e_h323_ID;
	if (matchSource) {
		if (setup.GetQ931().HasIE(Q931::CalledPartyNumberIE)) {
				destType = H225_AliasAddress::e_dialedDigits;
		} else if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) &&
			setupBody.m_destinationAddress.GetSize() > 0) {
				destType = setupBody.m_destinationAddress[0].GetTag();
		}

		if (treatNumberURIDialedDigits && destType == H225_AliasAddress::e_url_ID) {
			PString destination = ::AsString(setupBody.m_destinationAddress[0],false);
			PINDEX at = destination.Find('@');
			PString d = destination.Left(at);
			if (strspn(d, "1234567890") == strlen(d)) {  // all digits
				PString sdigits;
				PINDEX j = 0;
				while(j < setupBody.m_sourceAddress.GetSize()) {  // Find longest DialedDigits
					if (setupBody.m_sourceAddress[j].GetTag() == H225_AliasAddress::e_dialedDigits) {
						PString s = ::AsString(setupBody.m_sourceAddress[j],false);
						if (s.GetLength() > sdigits.GetLength())
							sdigits = s;
					}
					++j;
				}
				if (!sdigits) {  // replace the URI with the dialedDigits URI
					j = 0;
					while(j < setupBody.m_sourceAddress.GetSize()) {  // Find longest DialedDigits
						if (setupBody.m_sourceAddress[j].GetTag() == H225_AliasAddress::e_url_ID) {
							PString s = ::AsString(setupBody.m_sourceAddress[j],false);
							PINDEX a = s.Find('@');
							PString dom = s.Mid(a);
							H323SetAliasAddress(sdigits+dom,setupBody.m_sourceAddress[j],H225_AliasAddress::e_url_ID);
					}
						++j;
					}
					setup.GetQ931().SetDisplayName(sdigits);
					setup.GetQ931().RemoveIE(Q931::CallingPartyNumberIE);
				}
			}
		}

		if (aliasForceType > -1) {
			PString destination = PString();
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) &&
				setupBody.m_destinationAddress.GetSize() > 0) {
				destination = ::AsString(setupBody.m_destinationAddress[0],false);
				if (!rewriteChar) {
					PStringArray rewrite  = rewriteChar.Tokenise(";");
					for (PINDEX i = 0; i < rewrite.GetSize(); ++i) {
						PStringArray cRule = rewrite[i].Tokenise(",");
						if (cRule.GetSize() == 2)
							destination.Replace(cRule[0],cRule[1],true);
					}
				}
				H323SetAliasAddress(destination,setupBody.m_destinationAddress[0],aliasForceType);
			}
			if (!destination && aliasForceType == H225_AliasAddress::e_dialedDigits)
				setup.GetQ931().SetCalledPartyNumber(destination);

			destType = aliasForceType;
		}
	}

	PINDEX i = 0;
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		while(i < setupBody.m_sourceAddress.GetSize()) {
			bool remove = false;
			if (matchSource && setupBody.m_sourceAddress[i].GetTag() != destType)
				remove = true;
			if (onlyE164 && setupBody.m_sourceAddress[i].GetTag() != H225_AliasAddress::e_dialedDigits)
				remove = true;
			if (only10Dand11D && !Is10Dor11Dnumber(setupBody.m_sourceAddress[i]))
				remove = true;

			if (remove)
				setupBody.m_sourceAddress.RemoveAt(i);
			else {
				if (aliasForceType > -1 &&
					setupBody.m_sourceAddress[i].GetTag() != (unsigned)aliasForceType) {
						PString source = ::AsString(setupBody.m_sourceAddress[i], false);
						H323SetAliasAddress(source, setupBody.m_sourceAddress[i], aliasForceType);
				}
				++i;
			}
		}
	}

	PBoolean changed = false;
	PString source = PString();
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress) && (setupBody.m_sourceAddress.GetSize() > 0)) {
		source = ::AsString(setupBody.m_sourceAddress[0], false);
	} else {
		setup.GetQ931().GetCallingPartyNumber(source);
	}

	if (!rewriteChar) {
		PStringArray rewrite  = rewriteChar.Tokenise(";");
		for (PINDEX j = 0; i < rewrite.GetSize(); ++j) {
			PStringArray cRule = rewrite[j].Tokenise(",");
			if (cRule.GetSize() == 2) {
				source.Replace(cRule[0], cRule[1],true);
				changed = true;
			}
		}
	}
	if (!rules) {
		PStringArray sRules = rules.Tokenise(";");
		if (sRules.GetSize() > 0 && IsValidE164(source)) {  // only support E164 for now
			for (PINDEX i = 0; i < sRules.GetSize(); ++i) {
				PStringArray cRule = sRules[i].Tokenise(",");
				if (cRule.GetSize() == 2 && cRule[0] == source.Left(cRule[0].GetLength())) {
					PTRACE(4, "SWRITE\tSource Address " << source << " rewritten to " << cRule[1]);
					source = cRule[1];
					changed = true;
					break;
				}
			}
		}
	}
	// TODO: Add Database rewrite here
	if (changed) {
		setupBody.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
		setupBody.m_sourceAddress.SetSize(1);
		H323SetAliasAddress(source, setupBody.m_sourceAddress[0]);

		if (IsValidE164(source))
			setup.GetQ931().SetCallingPartyNumber(source);
		else
			setup.GetQ931().RemoveIE(Q931::CallingPartyNumberIE);
	}
}

void Toolkit::SetRerouteCauses(unsigned char *causeMap)
{
	memcpy(causeMap, m_causeMap, 128/8);
}


unsigned Toolkit::MapH225ReasonToQ931Cause(int reason)
{
	if( reason < 0 || reason > H225_ReleaseCompleteReason::e_tunnelledSignallingRejected )
		return 0;
	else
		return m_H225ReasonToQ931Cause[reason];
}

void Toolkit::ParseTranslationMap(std::map<unsigned, unsigned> & cause_map, const PString & ini) const
{
	cause_map.clear();
	PStringArray pairs(ini.Tokenise(",", false));
	for (PINDEX i = 0; i < pairs.GetSize(); ++i) {
		PStringArray causes(pairs[i].Tokenise(":=", false));
		if (causes.GetSize() == 2) {
			cause_map.insert(pair<unsigned, unsigned>(causes[0].AsInteger(), causes[1].AsInteger()));
		} else {
			PTRACE(1, "Syntax error in cause mapping: " << causes[i]);
			SNMP_TRAP(7, SNMPError, Configuration, "Invalid cause translation configuration");
		}
	}
	if (!cause_map.empty()) {
		// note: do not set to false, because feature might be active globally or for another endpoint
		Toolkit::Instance()->SetCauseCodeTranslationActive(true);
	}
}

unsigned Toolkit::TranslateReceivedCause(unsigned cause) const
{
	std::map<unsigned, unsigned>::const_iterator i = m_receivedCauseMap.find(cause);
	if (i != m_receivedCauseMap.end())
		return i->second;
	else
		return cause;
}

unsigned Toolkit::TranslateSentCause(unsigned cause) const
{
	std::map<unsigned, unsigned>::const_iterator i = m_sentCauseMap.find(cause);
	if (i != m_sentCauseMap.end())
		return i->second;
	else
		return cause;
}

PStringList Toolkit::GetAuthenticatorList() const
{
	PString auth = GkConfig()->GetString("Gatekeeper::Main", "Authenticators", "");
	PStringArray authlist(auth.Tokenise(" ,;\t"));

	return authlist;
}

bool Toolkit::IsAuthenticatorEnabled(const PString & algo) const
{
	PString algolist = GkConfig()->GetString("Gatekeeper::Main", "Authenticators", "");
    if (algolist.IsEmpty()) {
        return true;    // all algos enabled by default
    } else {
        return algolist.Find(algo) != P_MAX_INDEX;
    }
}
