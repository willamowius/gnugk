//////////////////////////////////////////////////////////////////
//
// MakeCall.cxx
//
// Copyright (c) 2007-2017, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "MakeCall.h"
#include "Toolkit.h"
#include "gk_const.h"
#include "snmp.h"
#include "config.h"
#include <math.h>

MakeCallEndPoint::MakeCallEndPoint() : Singleton<MakeCallEndPoint>("MakeCallEndPoint")
{
	SetLocalUserName(GkConfig()->GetString("CTI::MakeCall", "EndpointAlias", "InternalMakeCallEP"));
	isRegistered = FALSE;
	globalTransferMethod = GkConfig()->GetString("CTI::MakeCall", "TransferMethod", "FacilityForward");
	// compatibility with old switch
	if (Toolkit::AsBool(GkConfig()->GetString("CTI::MakeCall", "UseH450", "0"))) {
		globalTransferMethod = "H.450.2";
	}

	// Set the various options
	DisableFastStart(true);
	DisableH245Tunneling(GkConfig()->GetBoolean("CTI::MakeCall", "DisableH245Tunneling", false));
	m_bandwidth = GkConfig()->GetInteger("CTI::MakeCall", "Bandwidth", 384);
	m_rateMultiplier = ceil((float)m_bandwidth / 64);

	// Set the default codecs
	AddAllCapabilities(0, 0, "G.711");

	// Start the listener thread for incoming calls.
	// TODO: disable IPv6 when disabled in GnuGk, use list of Home IPs to listen ?
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

    // disable H.460.18 and .23 - not needed for local signaling connection
#ifdef H323_H46018
	H46018Enable(PFalse);
#endif
#ifdef H323_H46023
	H46023Enable(PFalse);
#endif

	m_gkAddress = GkConfig()->GetString("CTI::MakeCall", "Gatekeeper", "127.0.0.1");
	if (SetGatekeeper(m_gkAddress, rasChannel)) {
		PTRACE(3, "MakeCallEndpoint: Gatekeeper set: " << *gatekeeper);
		isRegistered = TRUE;
	} else {
		PTRACE(1, "MakeCallEndpoint: Error registering with gatekeeper at \"" << m_gkAddress << '"');
		SNMP_TRAP(7, SNMPError, Network, "MakeCall endpoint failed to register with gatekeeper " + m_gkAddress);
		isRegistered = FALSE;
	}
}

MakeCallEndPoint::~MakeCallEndPoint()
{
    rasRequestTimeout = 10;    // on shutdown wait 10 msec for UCF max.
}

void MakeCallEndPoint::ThirdPartyMakeCall(const PString & user1, const PString & user2, const PString & transferMethod)
{
	if (!IsRegisteredWithGk()) {
		PTRACE(1, "MakeCallEndpoint: Can't initiate MakeCall when not registered with gatekeeper");
		return;
	}
	PString newToken;
	MakeCall(user1, newToken);
	AddDestination(newToken, user2, transferMethod);
}

PBoolean MakeCallEndPoint::IsRegisteredWithGk() const
{
	return isRegistered;
}

void MakeCallEndPoint::AddDestination(const PString & token, const PString & alias, const PString & transferMethod)
{
	PWaitAndSignal lock(destinationMutex);
	destinations.insert(pair<PString, PString>(token, alias));
	methods.insert(pair<PString, PString>(token, transferMethod));
}

// get the destination for this token ('' if not found)
PString MakeCallEndPoint::GetDestination(const PString & token)
{
	PWaitAndSignal lock(destinationMutex);
	std::map<PString, PString>::iterator it = destinations.find(token);
	if (it != destinations.end()) {
		return it->second;
	}
	return "";
}

// get and remove the destination for this token ('' if not found)
PString MakeCallEndPoint::GetRemoveDestination(const PString & token)
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

// get and remove the destination for this token ('' if not found)
PString MakeCallEndPoint::GetRemoveTransferMethod(const PString & token)
{
	PString method;
	PWaitAndSignal lock(methodMutex);
	std::map<PString, PString>::iterator it = methods.find(token);
	if (it != methods.end()) {
		method = it->second;
		// remove token from list
		methods.erase(it);
	}
	return method;
}

PBoolean MakeCallEndPoint::OnIncomingCall(H323Connection & connection, const H323SignalPDU &, H323SignalPDU &)
{
	PTRACE(2, "MakeCallEndpoint: Incoming call from \"" << connection.GetRemotePartyName() << "\" rejected");
	return FALSE;
}


PBoolean MakeCallEndPoint::OnConnectionForwarded(H323Connection & connection,
                                               const PString & forwardParty,
                                               const H323SignalPDU & /*pdu*/)
{
	PString oldToken = connection.GetCallToken();
	PString destination = GetRemoveDestination(oldToken);
	PString method = GetRemoveTransferMethod(oldToken);
	PString newToken;
	if (MakeCall(forwardParty, newToken)) {
		PTRACE(2, "MakeCallEndpoint: Call is being forwarded to host " << forwardParty);
		AddDestination(newToken, destination, method);
		return TRUE;
	}

	PTRACE(1, "MakeCallEndpoint: Error forwarding call to \"" << forwardParty << '"');
	SNMP_TRAP(7, SNMPError, Network, "MakeCall to " + forwardParty + " failed");
	return FALSE;
}

// TODO: check if we should move this to Connection::OnReceivedSignalConnect() to speed up the transfer
void MakeCallEndPoint::OnConnectionEstablished(H323Connection & connection, const PString & token)
{
	// find second party by call token
	PString second_party = GetRemoveDestination(token);
	PCaselessString transferMethod = GetRemoveTransferMethod(token);
	if (transferMethod.IsEmpty())
        transferMethod = globalTransferMethod;
	PTRACE(1, "MakeCallEndpoint: Transferring call to 2nd party " << second_party << " method=" << transferMethod);

	if (transferMethod == "H.450.2") {
#ifdef HAS_H450
		PTRACE(3, "MakeCallEndpoint: Using H.450.2 to transfer call");
		connection.TransferCall(second_party);
#else
		PTRACE(1, "MakeCallEndpoint: H.450.2 Not supported, please recompile");
#endif
	} else if (transferMethod == "Reroute") {
        PTRACE(3, "MakeCallEndpoint: Using Reroute to transfer call");
        // TODO: fork a thread to start the reroute like we do for RerouteOnFacility
        PTCPSocket client(m_gkAddress, GkConfig()->GetInteger("StatusPort", GK_DEF_STATUS_PORT));
        PString callid = connection.GetCallIdentifier().AsString();
        callid.Replace(" ", "-", true);
        PString cmd = "RerouteCall " + callid + " CALLED " + second_party + "\r\n";
        client.Write((const char *)cmd, cmd.GetLength());
        cmd = "quit\r\n";
        client.Write((const char *)cmd, cmd.GetLength());
        // wait for GnuGk to send a response to avoid error in trace, wait 1/2 sec max.
        char buffer[64];
        client.SetReadTimeout(500);
        client.read(buffer, 20);
        client.Close();
	} else if (transferMethod == "FacilityRouteCallToMC") {
#ifdef HAS_ROUTECALLTOMC
		PTRACE(3, "MakeCallEndpoint: Using Facility(routeCalltoMC) to transfer call");
		H225_ConferenceIdentifier confId = connection.GetConferenceIdentifier();
		connection.RouteCallToMC(second_party, confId);
#else
		PTRACE(1, "MakeCallEndpoint: FacilityRouteCallToMC Not supported, please recompile");
#endif
	} else {
        if (transferMethod != "FacilityForward") {
            PTRACE(1, "MakeCallEndpoint: Unknown transfer method (" << transferMethod << "), defaulting to FacilityForward");
        }
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
	// don't open audio connection, we only need the signaling connection to do the transfer
	return FALSE;
}

H323Connection * MakeCallEndPoint::CreateConnection(unsigned callReference)
{
	unsigned options = 0;
    return new MakeCallConnection(*this, callReference, options);
}


MakeCallConnection::MakeCallConnection(MakeCallEndPoint & _ep, unsigned _callReference, unsigned _options)
  : H323Connection(_ep, _callReference, _options), m_ep(_ep)
{
}

PBoolean MakeCallConnection::OnSendSignalSetup(H323SignalPDU & setupPDU)
{
    // set outgoing bearer capability to unrestricted information transfer + transfer rate
	PBYTEArray caps;
	caps.SetSize(4);
	caps[0] = 0x88;
	caps[1] = 0x18;
	caps[2] = 0x80 | m_ep.GetRateMultiplier();
	caps[3] = 0xa5;
	setupPDU.GetQ931().SetIE(Q931::BearerCapabilityIE, caps);

	// set DisplayIE to MakeCall destination
	PString transferDest = m_ep.GetDestination(GetCallToken());
    setupPDU.GetQ931().SetDisplayName(transferDest);

    // set GnuGk as vendor
    H225_Setup_UUIE & setup = setupPDU.m_h323_uu_pdu.m_h323_message_body;
	H225_VendorIdentifier & vendor = setup.m_sourceInfo.m_vendor;
	vendor.m_vendor.m_t35CountryCode = Toolkit::t35cPoland;
	vendor.m_vendor.m_manufacturerCode = Toolkit::t35mGnuGk;
	vendor.m_vendor.m_t35Extension = 0;

    return H323Connection::OnSendSignalSetup(setupPDU);
}

PBoolean MakeCallConnection::OpenAudioChannel(PBoolean isEncoding, unsigned bufferSize, H323AudioCodec & codec)
{
    PIndirectChannel * channel = new SilentChannel();
    codec.AttachChannel(channel);
    return true;
}


PBoolean SilentChannel::Read(void * buf, PINDEX len)
{
  memset(buf, 0, len);
  lastReadCount = len;
  readDelay.Delay(len/2/8);	// assuming G.711 !
  return true;
}

PBoolean SilentChannel::Write(const void *buf, PINDEX len)
{
  lastWriteCount = len;
  writeDelay.Delay(len/2/8); // assuming G.711 !
  return true;
}

PBoolean SilentChannel::Close()
{
  return true;
}

