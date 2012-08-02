//////////////////////////////////////////////////////////////////
//
// MakeCall.cxx
//
// Copyright (c) 2007-2012, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "MakeCall.h"
#include "Toolkit.h"
#include "snmp.h"
#include "config.h"

MakeCallEndPoint::MakeCallEndPoint() : Singleton<MakeCallEndPoint>("MakeCallEndPoint")
{
	SetLocalUserName(GkConfig()->GetString("CTI::MakeCall", "EndpointAlias", "InternalMakeCallEP"));
	isRegistered = FALSE;
	transferMethod = GkConfig()->GetString("CTI::MakeCall", "TransferMethod", "FacilityForward");
	// compatibility with old switch
	if (Toolkit::AsBool(GkConfig()->GetString("CTI::MakeCall", "UseH450", "0"))) {
		transferMethod = "H.450.2";
	}

	// Set the various options
	DisableFastStart(Toolkit::AsBool(GkConfig()->GetString("CTI::MakeCall", "DisableFastStart", "0")));
	DisableH245Tunneling(Toolkit::AsBool(GkConfig()->GetString("CTI::MakeCall", "DisableH245Tunneling", "0")));

	// Set the default codecs
	AddAllCapabilities(0, 0, "G.711");

	// Start the listener thread for incoming calls.
	H323TransportAddress iface = GkConfig()->GetString("CTI::MakeCall", "Interface", "*:1722");
	if (!StartListener(iface)) {
		PTRACE(1, "MakeCallEndpoint: Could not open H.323 listener port on \"" << iface << '"');
	}

	// Establish link with gatekeeper
	H323TransportUDP * rasChannel;
	if (GkConfig()->GetString("CTI::MakeCall", "Interface", "").IsEmpty())
		rasChannel = new H323TransportUDP(*this, GNUGK_INADDR_ANY, 1722);
	else {
		PIPSocket::Address interfaceAddress(GkConfig()->GetString("CTI::MakeCall", "Interface", ""));
		rasChannel = new H323TransportUDP(*this, interfaceAddress);
	}

	PString gkName = GkConfig()->GetString("CTI::MakeCall", "Gatekeeper", "127.0.0.1");
	if (SetGatekeeper(gkName, rasChannel)) {
		PTRACE(3, "MakeCallEndpoint: Gatekeeper set: " << *gatekeeper);
		isRegistered = TRUE;
	} else {
		PTRACE(1, "MakeCallEndpoint: Error registering with gatekeeper at \"" << gkName << '"');
		SNMP_TRAP(7, SNMPError, Network, "MakeCall endpoint failed to register with gatekeeper " + gkName);
		isRegistered = FALSE;
	}
#ifdef H323_H46018
	H46018Enable(PFalse);
#endif
}

void MakeCallEndPoint::ThirdPartyMakeCall(const PString & user1, const PString & user2)
{
	if (!IsRegisteredWithGk()) {
		PTRACE(1, "MakeCallEndpoint: Can't MakeCall when not registered with gatekeeper");
		return;
	}
	PString newToken;
	MakeCall(user1, newToken);
	AddDestination(newToken, user2);
}

PBoolean MakeCallEndPoint::IsRegisteredWithGk() const
{
	return isRegistered;
}	

void MakeCallEndPoint::AddDestination(PString token, PString alias)
{
	PWaitAndSignal lock(destinationMutex);
	destinations.insert(pair<PString, PString>(token, alias));
}

// get and remove the destination for this token ('' if not found)
PString MakeCallEndPoint::GetDestination(PString token)
{
	PString dest;
	PWaitAndSignal lock(destinationMutex);
	std::map<PString, PString>::iterator it = destinations.find(token);
	if (it != destinations.end()) {
		dest = it->second;
		// remove token from list
		destinations.erase(it);
	} else {
		PTRACE(1, "MakeCallEndpoint: ERROR: No destination for call token " << token);
		SNMP_TRAP(7, SNMPError, Network, "No destination for MakeCall found");
	}
	return dest;
}


PBoolean MakeCallEndPoint::OnIncomingCall(H323Connection & connection,
                                        const H323SignalPDU &,
                                        H323SignalPDU &)
{
	PTRACE(2, "MakeCallEndpoint: Incoming call from \"" << connection.GetRemotePartyName() << "\" rejected");
	return FALSE;
}


PBoolean MakeCallEndPoint::OnConnectionForwarded(H323Connection & connection,
                                               const PString & forwardParty,
                                               const H323SignalPDU & /*pdu*/)
{
	PString oldToken = connection.GetCallToken();
	PString destination = GetDestination(oldToken);
	PString newToken;
	if (MakeCall(forwardParty, newToken)) {
		PTRACE(2, "MakeCallEndpoint: Call is being forwarded to host " << forwardParty);
		AddDestination(newToken, destination);
		return TRUE;
	}

	PTRACE(1, "MakeCallEndpoint: Error forwarding call to \"" << forwardParty << '"');
	SNMP_TRAP(7, SNMPError, Network, "MakeCall to " + forwardParty + " failed");
	return FALSE;
}


void MakeCallEndPoint::OnConnectionEstablished(H323Connection & connection,
                                                 const PString & token)
{
	// find second party by call token
	PString second_party = GetDestination(token);
	PTRACE(1, "MakeCallEndpoint: Transferring call to 2nd party " << second_party);

	if (transferMethod == "H.450.2") {
#ifdef HAS_H450
		PTRACE(3, "MakeCallEndpoint: Using H.450.2 to transfer call");
		connection.TransferCall(second_party);
#else
		PTRACE(3, "MakeCallEndpoint: H.450.2 Not supported recompile");
#endif
#ifdef HAS_ROUTECALLTOMC
	} else if (transferMethod == "FacilityRouteCallToMC") {
		PTRACE(3, "MakeCallEndpoint: Using Facility(routeCalltoMC) to transfer call");
		H225_ConferenceIdentifier confId;
		connection.RouteCallToMC(second_party, confId);
#endif
	} else {
		PTRACE(3, "MakeCallEndpoint: Using Facility(callForwarded) to transfer call");
		connection.ForwardCall(second_party);
	}
}

void MakeCallEndPoint::OnRegistrationConfirm(const H323TransportAddress & /* rasAddress */)
{
	isRegistered = TRUE;
}

void MakeCallEndPoint::OnRegistrationReject()
{
	isRegistered = FALSE;
}

PBoolean MakeCallEndPoint::OpenAudioChannel(H323Connection & /* connection */,
                                          PBoolean /* isEncoding */,
                                          unsigned /* bufferSize */,
                                          H323AudioCodec & /* codec */)
{
	// don't open audio connection, we need this connection just to do the transfer
	return FALSE;
}
