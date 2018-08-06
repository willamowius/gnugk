/*
 * RequireOneNet.cxx
 *
 * accounting module for GNU Gatekeeper used for authentication - make sure one side of the call is within our network
 *
 * Copyright (c) 2016-2018, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"
#include "RequireOneNet.h"
#include "Toolkit.h"
#include "h323util.h"

RequireOneNet::RequireOneNet(const char* moduleName, const char* cfgSecName)
    : GkAcctLogger(moduleName, cfgSecName)
{
	// set which type of accounting events are supported, otherwise the Log() method will no get called
	SetSupportedEvents(StatusAcctEvents);

	PConfig* cfg = GetConfig();
	const PString & cfgSec = GetConfigSectionName();
	PString myNetworkList = cfg->GetString(cfgSec, "Networks", "");
	PStringArray nets = myNetworkList.Tokenise(",", FALSE);
	for (PINDEX i = 0; i < nets.GetSize(); ++i) {
        if (nets[i].Find('/') == P_MAX_INDEX) {
            // add netmask to pure IPs
            if (IsIPv4Address(nets[i])) {
                nets[i] += "/32";
            } else {
                nets[i] += "/128";
            }
        }
        m_myNetworks.push_back(NetworkAddress(nets[i]));
	}
}

RequireOneNet::~RequireOneNet()
{
}

GkAcctLogger::Status RequireOneNet::Log(GkAcctLogger::AcctEvent evt, const callptr & call)
{
	// a workaround to prevent processing end on "sufficient" module
	// if it is not interested in this event type
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;

	if (call) {
        PIPSocket::Address fromIP, toIP;
        WORD unused = 0;
        call->GetSrcSignalAddr(fromIP, unused);
        if (IsInNetworks(fromIP, m_myNetworks))
            return Ok;
        call->GetDestSignalAddr(toIP, unused);
        if (IsInNetworks(toIP, m_myNetworks))
            return Ok;

        // all other fail
        PTRACE(1, "RequireOneNet\tRejecting call from " << AsString(fromIP) << " to " << AsString(toIP));
	} else {
		PTRACE(1, "RequireOneNet\tRejecting call with missing call info for event " << evt);
		return Fail;
	}

	return Fail;
}


namespace {
	// append the new accounting logger to the global list of loggers
	GkAcctLoggerCreator<RequireOneNet> RequireOneNetAcctCreator("RequireOneNet");
}
