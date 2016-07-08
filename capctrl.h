/*
 * capctrl.h
 *
 * Module for accoutning per IP/H.323 ID/CLI/prefix inbound call volume
 *
 * Copyright (c) 2006, Michal Zygmuntowicz
 * Copyright (c) 2008-2016, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#ifndef CAPCTRL_H
#define CAPCTRL_H "#(@) $Id$"

#include <string>
#include <vector>
#include <set>
#include "Toolkit.h"

class CallRec;
template<class> class SmartPtr;
typedef SmartPtr<CallRec> callptr;

/// Perform per IP/H.323 ID/CLI/prefix inbound call volume accounting/control
class CapacityControl : public Singleton<CapacityControl> {
public:
	/// a single call volume accounting entry
	struct InboundCallVolume {
		InboundCallVolume();
		virtual ~InboundCallVolume();
		virtual PString AsString() const;

		bool operator==(const InboundCallVolume &) const;

		std::string m_prefix; /// destination prefix to match (regex)
		unsigned m_maxVolume; /// maximum allowed call volume
		std::set<PINDEX> m_calls; /// active calls
	};

	struct InboundIPCallVolume : public InboundCallVolume {
		InboundIPCallVolume(const NetworkAddress & addr) : m_sourceAddress(addr) { }

		bool operator==(const InboundIPCallVolume &) const;

		NetworkAddress m_sourceAddress; /// source IP address to match
	};

	struct InboundH323IdCallVolume : public InboundCallVolume {
		InboundH323IdCallVolume(const H225_AliasAddress & alias) : m_sourceH323Id(alias) { }

		bool operator==(const InboundH323IdCallVolume &) const;

		H225_AliasAddress m_sourceH323Id; /// source alias to match
	};

	struct InboundCLICallVolume : public InboundCallVolume {
		InboundCLICallVolume() {}	//default c'tor needed for VS 2008 SP1
		InboundCLICallVolume(const std::string & cli) : m_sourceCLI(cli) { }

		bool operator==(const InboundCLICallVolume &) const;

		std::string m_sourceCLI; /// source CLI to match
	};

	typedef std::pair<NetworkAddress, InboundIPCallVolume> IpCallVolume;
	typedef std::vector<IpCallVolume> IpCallVolumes;
	typedef std::pair<H225_AliasAddress, InboundH323IdCallVolume> H323IdCallVolume;
	typedef std::vector<H323IdCallVolume> H323IdCallVolumes;
	typedef std::pair<std::string, InboundCLICallVolume> CLICallVolume;
	typedef std::vector<CLICallVolume> CLICallVolumes;

	/// Create object instance and call LoadConfig()
	CapacityControl();

	/// Load/Update settings from the config
	void LoadConfig();

	/// @return	a string containing all active rules and their current capacity values
	PString PrintRules();

	/// Record call start/stop events for a matching inbound route
	void LogCall(
		const NetworkAddress & srcIp, /// caller's IP
		const PString & srcAlias, /// caller's H.323 ID
		const std::string & srcCli, /// caller's CLI
		const PString & calledStationId, /// called number
		PINDEX callNumber, /// internal gk call number
		bool callStart /// true - call start, false - call stop
		);

	/** Check if there is enough capacity to accept a new call.

	    @return	true if there is available capacity, false otherwise
	*/
	bool CheckCall(
		const NetworkAddress & srcIp, /// caller's IP
		const PString & srcAlias, /// caller's H.323 ID
		const std::string & srcCli, /// caller's CLI
		const PString & calledStationId /// called number
		);

private:
	// should not be used
	CapacityControl(const CapacityControl &);
	CapacityControl & operator=(const CapacityControl &);

	// helper functions
	IpCallVolumes::iterator FindByIp(const NetworkAddress & srcIp, const PString & calledStationId);
	H323IdCallVolumes::iterator FindByH323Id(const PString & h323Id, const PString & calledStationId);
	CLICallVolumes::iterator FindByCli(const std::string & cli, const PString & calledStationId);

private:
	IpCallVolumes m_ipCallVolumes; /// per-IP inbound routes
	H323IdCallVolumes m_h323IdCallVolumes; /// per-H.323 ID inbound routes
	CLICallVolumes m_cliCallVolumes; /// per-CLI inbound routes
	PMutex m_updateMutex; /// for atomic route read/update operations
};

#endif /// CAPCTRL_H
