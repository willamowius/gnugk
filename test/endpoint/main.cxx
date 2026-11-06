//////////////////////////////////////////////////////////////////
//
// gktestep: minimal H.323 endpoint for the GnuGk test harness
//
// Registers with a gatekeeper (optionally with H.235 MD5 tokens and/or
// H.460.18/.19), places or answers one call, sends a generated tone as
// G.711 audio and reports what happened as JSON.
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <ptlib/pprocess.h>
#include <h323.h>
#include <h323pdu.h>
#include <gkclient.h>
#include <h235auth.h>
#include <math.h>
#include <set>
#include <vector>

////////////////////////////////////////////////////////////////
// audio channel that produces a paced 440 Hz tone and discards what it gets

class ToneChannel : public PChannel
{
	PCLASSINFO(ToneChannel, PChannel)
public:
	ToneChannel() : m_open(true), m_phase(0) { }

	virtual PBoolean IsOpen() const { return m_open; }
	virtual PBoolean Close() { m_open = false; return true; }

	virtual PBoolean Read(void * buf, PINDEX len)
	{
		if (!m_open)
			return false;
		short * samples = (short *)buf;
		for (PINDEX i = 0; i < len / 2; ++i) {
			samples[i] = (short)(8000 * sin(m_phase));
			m_phase += 2 * M_PI * 440 / 8000;
		}
		lastReadCount = len;
		m_pacing.Delay(len / 16);	// 8 kHz, 16 bit
		return true;
	}

	virtual PBoolean Write(const void *, PINDEX len)
	{
		if (!m_open)
			return false;
		lastWriteCount = len;
		m_pacing.Delay(len / 16);
		return true;
	}

private:
	bool m_open;
	double m_phase;
	PAdaptiveDelay m_pacing;
};

////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
// MD5 authenticator that leaves the token out of some RAS messages, like endpoints that only sign
// RRQ and ARQ (eg. Cisco Access Token endpoints)

class SelectiveMD5 : public H235AuthSimpleMD5
{
	PCLASSINFO(SelectiveMD5, H235AuthSimpleMD5)
public:
	SelectiveMD5(const std::set<unsigned> & unsignedRAS) : m_unsignedRAS(unsignedRAS) { }

	virtual PObject * Clone() const { return new SelectiveMD5(*this); }

	virtual PBoolean IsSecuredPDU(unsigned rasPDU, PBoolean received) const
	{
		if (!received && m_unsignedRAS.count(rasPDU) > 0)
			return false;
		return H235AuthSimpleMD5::IsSecuredPDU(rasPDU, received);
	}

private:
	std::set<unsigned> m_unsignedRAS;
};

static bool RASTag(const PString & name, unsigned & tag)
{
	static const struct { const char * name; unsigned tag; } tags[] = {
		{ "RRQ", H225_RasMessage::e_registrationRequest },
		{ "URQ", H225_RasMessage::e_unregistrationRequest },
		{ "ARQ", H225_RasMessage::e_admissionRequest },
		{ "BRQ", H225_RasMessage::e_bandwidthRequest },
		{ "DRQ", H225_RasMessage::e_disengageRequest },
		{ "IRR", H225_RasMessage::e_infoRequestResponse },
	};
	for (unsigned i = 0; i < PARRAYSIZE(tags); ++i)
		if (name *= tags[i].name) {
			tag = tags[i].tag;
			return true;
		}
	return false;
}

// gatekeeper client that can turn its next keep-alive RRQ into an additive registration
class TestGatekeeper : public H323Gatekeeper
{
	PCLASSINFO(TestGatekeeper, H323Gatekeeper)
public:
	TestGatekeeper(H323EndPoint & ep, H323Transport * transport) : H323Gatekeeper(ep, transport) { }

	void AddAliasesOnNextRRQ(const PStringArray & aliases) { PWaitAndSignal lock(m_addMutex); m_addAliases = aliases; }
	bool AdditiveRRQSent() { PWaitAndSignal lock(m_addMutex); return m_additiveSent; }

	virtual void OnSendingPDU(PASN_Object & rawPDU)
	{
		H323Gatekeeper::OnSendingPDU(rawPDU);
		H225_RasMessage & ras = (H225_RasMessage &)rawPDU;
		if (ras.GetTag() != H225_RasMessage::e_registrationRequest)
			return;
		H225_RegistrationRequest & rrq = ras;
		PWaitAndSignal lock(m_addMutex);
		if (m_addAliases.IsEmpty() || !rrq.m_keepAlive)
			return;
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_additiveRegistration);
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_terminalAlias);
		rrq.m_terminalAlias.SetSize(m_addAliases.GetSize());
		for (PINDEX i = 0; i < m_addAliases.GetSize(); ++i)
			H323SetAliasAddress(m_addAliases[i], rrq.m_terminalAlias[i]);
		PTRACE(1, "GKTESTEP\tSending additive registration for " << setfill(',') << m_addAliases);
		m_addAliases.SetSize(0);
		m_additiveSent = true;
	}

private:
	PMutex m_addMutex;
	PStringArray m_addAliases;
	bool m_additiveSent = false;
};

struct CallStats {
	CallStats() : connected(false), cleared(false), h245Tunneling(false), rtpSent(0), rtpReceived(0), durationMs(0) { }
	PString calledNumber;	// callee: called party number of the incoming Setup
	PString callingNumber;	// callee: calling party number of the incoming Setup
	bool connected;
	bool h245Tunneling;
	bool cleared;
	PString endReason;
	unsigned q931Cause;
	DWORD rtpSent;
	DWORD rtpReceived;
	PInt64 durationMs;
	PString txCodec;	// audio codec we send, eg. "G.711-uLaw-64k"
	PString rxCodec;	// audio codec we receive
};

// T.120 test support (H323Plus is built without T.120): with --t120 the endpoint puts a T.120 capability into
// its capability set and opens a T.120 data channel (separate LAN stack) once the call is established.
// Both sides record what they saw of it.
static PMutex t120Mutex;
static bool t120Offer = false;
static bool t120CapReceived = false;	// the remote capability set had a T.120 capability
static bool t120OlcReceived = false;	// the remote opened a T.120 channel
static bool t120OlcRejected = false;	// our T.120 channel was rejected
static const unsigned T120ChannelNumber = 4000;	// away from the numbers H323Plus uses
static const unsigned T120CapabilityNumber = 4000;

static bool IsT120Data(const H245_DataType & dataType)
{
	if (dataType.GetTag() != H245_DataType::e_data)
		return false;
	const H245_DataApplicationCapability & data = dataType;
	return data.m_application.GetTag() == H245_DataApplicationCapability_application::e_t120;
}

static void SetT120Data(H245_DataApplicationCapability & data)
{
	data.m_application.SetTag(H245_DataApplicationCapability_application::e_t120);
	H245_DataProtocolCapability & protocol = data.m_application;
	protocol.SetTag(H245_DataProtocolCapability::e_separateLANStack);
	data.m_maxBitRate = 640;
}

class TestConnection : public H323Connection
{
	PCLASSINFO(TestConnection, H323Connection)
public:
	TestConnection(H323EndPoint & ep, unsigned callReference) : H323Connection(ep, callReference) { }

	virtual void OnSendCapabilitySet(H245_TerminalCapabilitySet & pdu)
	{
		H323Connection::OnSendCapabilitySet(pdu);
		if (!t120Offer)
			return;
		pdu.IncludeOptionalField(H245_TerminalCapabilitySet::e_capabilityTable);
		PINDEX n = pdu.m_capabilityTable.GetSize();
		pdu.m_capabilityTable.SetSize(n + 1);
		H245_CapabilityTableEntry & entry = pdu.m_capabilityTable[n];
		entry.m_capabilityTableEntryNumber = T120CapabilityNumber;
		entry.IncludeOptionalField(H245_CapabilityTableEntry::e_capability);
		entry.m_capability.SetTag(H245_Capability::e_receiveAndTransmitDataApplicationCapability);
		SetT120Data(entry.m_capability);
		if (pdu.HasOptionalField(H245_TerminalCapabilitySet::e_capabilityDescriptors)
			&& pdu.m_capabilityDescriptors.GetSize() > 0) {
			H245_CapabilityDescriptor & descriptor = pdu.m_capabilityDescriptors[0];
			descriptor.IncludeOptionalField(H245_CapabilityDescriptor::e_simultaneousCapabilities);
			PINDEX a = descriptor.m_simultaneousCapabilities.GetSize();
			descriptor.m_simultaneousCapabilities.SetSize(a + 1);
			descriptor.m_simultaneousCapabilities[a].SetSize(1);
			descriptor.m_simultaneousCapabilities[a][0] = T120CapabilityNumber;
		}
	}

	virtual PBoolean OnH245Request(const H323ControlPDU & pdu)
	{
		const H245_RequestMessage & request = pdu;
		if (request.GetTag() == H245_RequestMessage::e_terminalCapabilitySet) {
			const H245_TerminalCapabilitySet & tcs = request;
			for (PINDEX i = 0; i < tcs.m_capabilityTable.GetSize(); ++i) {
				const H245_CapabilityTableEntry & entry = tcs.m_capabilityTable[i];
				if (entry.HasOptionalField(H245_CapabilityTableEntry::e_capability)
					&& entry.m_capability.GetTag() == H245_Capability::e_receiveAndTransmitDataApplicationCapability) {
					const H245_DataApplicationCapability & data = entry.m_capability;
					if (data.m_application.GetTag() == H245_DataApplicationCapability_application::e_t120) {
						PWaitAndSignal lock(t120Mutex);
						t120CapReceived = true;
					}
				}
			}
		} else if (request.GetTag() == H245_RequestMessage::e_openLogicalChannel) {
			const H245_OpenLogicalChannel & olc = request;
			if (IsT120Data(olc.m_forwardLogicalChannelParameters.m_dataType)) {
				PTRACE(1, "GKTESTEP\tReceived T.120 OpenLogicalChannel " << olc.m_forwardLogicalChannelNumber);
				PWaitAndSignal lock(t120Mutex);
				t120OlcReceived = true;
			}
		}
		return H323Connection::OnH245Request(pdu);
	}

	virtual PBoolean OnH245Response(const H323ControlPDU & pdu)
	{
		const H245_ResponseMessage & response = pdu;
		// the answer to our own T.120 channel, which H323Plus doesn't know about
		if (response.GetTag() == H245_ResponseMessage::e_openLogicalChannelReject) {
			const H245_OpenLogicalChannelReject & olcr = response;
			if (olcr.m_forwardLogicalChannelNumber == T120ChannelNumber) {
				PTRACE(1, "GKTESTEP\tT.120 channel rejected");
				PWaitAndSignal lock(t120Mutex);
				t120OlcRejected = true;
				return true;
			}
		}
		if (response.GetTag() == H245_ResponseMessage::e_openLogicalChannelAck) {
			const H245_OpenLogicalChannelAck & olca = response;
			if (olca.m_forwardLogicalChannelNumber == T120ChannelNumber)
				return true;
		}
		return H323Connection::OnH245Response(pdu);
	}

	// open a T.120 data channel (with a separate LAN stack address nobody listens on, no T.120 data is sent)
	void OpenT120Channel()
	{
		H323ControlPDU pdu;
		H245_OpenLogicalChannel & olc = pdu.BuildOpenLogicalChannel(T120ChannelNumber);
		olc.m_forwardLogicalChannelParameters.m_dataType.SetTag(H245_DataType::e_data);
		SetT120Data(olc.m_forwardLogicalChannelParameters.m_dataType);
		olc.m_forwardLogicalChannelParameters.m_multiplexParameters.SetTag(
			H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters);
		H245_H2250LogicalChannelParameters & params = olc.m_forwardLogicalChannelParameters.m_multiplexParameters;
		params.m_sessionID = 3;
		olc.IncludeOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters);
		olc.m_reverseLogicalChannelParameters.m_dataType = olc.m_forwardLogicalChannelParameters.m_dataType;
		olc.IncludeOptionalField(H245_OpenLogicalChannel::e_separateStack);
		olc.m_separateStack.m_networkAddress.SetTag(H245_NetworkAccessParameters_networkAddress::e_localAreaAddress);
		PIPSocket::Address ip;
		WORD port;
		GetSignallingChannel()->GetLocalAddress().GetIpAndPort(ip, port);
		H323TransportAddress(ip, 1503).SetPDU((H245_TransportAddress &)olc.m_separateStack.m_networkAddress);
		PTRACE(1, "GKTESTEP\tOpening T.120 channel " << T120ChannelNumber);
		WriteControlPDU(pdu);
	}
};

class TestEndPoint : public H323EndPoint
{
	PCLASSINFO(TestEndPoint, H323EndPoint)
public:
	enum TokenType { NoTokens, MD5Tokens, H2351Tokens };

	TestEndPoint() : m_rrqConfirmed(false), m_rrqRejected(false), m_tokens(NoTokens), m_fullQ931(false), m_answerDelay(0) { }

	// how to refuse incoming calls: "busy" (user busy, Q.931 cause 17), "denied" (call rejected, 21) or empty
	void SetReject(const PString & reject) { m_reject = reject; }
	// ring for this long before answering
	void SetAnswerDelay(unsigned ms) { m_answerDelay = ms; }

	// answer a pending call once its answer delay is over, called regularly from the main loop
	void Poll()
	{
		PString token;
		{
			PWaitAndSignal lock(m_mutex);
			if (m_pendingAnswer.IsEmpty() || PTime() < m_answerAt)
				return;
			token = m_pendingAnswer;
			m_pendingAnswer = PString::Empty();
		}
		H323Connection * connection = FindConnectionWithLock(token);
		if (connection != NULL) {
			PTRACE(1, "GKTESTEP\tAnswering call " << token << " after the delay");
			connection->AnsweringCall(H323Connection::AnswerCallNow);
			connection->Unlock();
		}
	}

	void UseTokens(TokenType tokens, bool fullQ931) { m_tokens = tokens; m_fullQ931 = fullQ931; }
	void SetUnsignedRAS(const std::set<unsigned> & unsignedRAS) { m_unsignedRAS = unsignedRAS; }

	virtual H323Connection * CreateConnection(unsigned callReference)
	{
		return new TestConnection(*this, callReference);
	}

	virtual H323Gatekeeper * CreateGatekeeper(H323Transport * transport)
	{
		return new TestGatekeeper(*this, transport);
	}

	// RAS: only offer the selected token type, the harness tests that and nothing else
	virtual H235Authenticators CreateAuthenticators()
	{
		H235Authenticators auths;
		if (m_tokens == MD5Tokens)
			auths.Append(new SelectiveMD5(m_unsignedRAS));
#ifdef H323_SSL
		if (m_tokens == H2351Tokens)
			auths.Append(NewH2351());
#endif
		return auths;
	}

	// call signaling: H.235.1 tokens (Setup, or all Q.931 messages with --full-q931), nothing for MD5.
	// Builds the authenticator itself instead of calling H323EndPoint::CreateEPAuthenticators(): that
	// one instantiates every registered authenticator, including H.235.6 media encryption, which spends
	// many seconds generating Diffie-Hellman parameters for each call when H323Plus has H.235 enabled.
	virtual H235Authenticators CreateEPAuthenticators()
	{
		H235Authenticators auths;
#ifdef H323_SSL
		if (m_tokens == H2351Tokens && !m_epPassword.IsEmpty()) {
			H235Authenticator * auth = NewH2351();
			H323Gatekeeper * gk = GetGatekeeper();
			if (gk != NULL && IsRegisteredWithGatekeeper()) {	// same IDs as H323EndPoint::CreateEPAuthenticators()
				auth->SetLocalId(gk->GetEndpointIdentifier());
				PString gkID = gk->GetName();
				if (gkID.Find('@') != P_MAX_INDEX)
					gkID = gkID.Left(gkID.Find('@'));
				auth->SetRemoteId(gkID);
			} else {
				auth->SetLocalId(GetLocalUserName());
			}
			auth->SetPassword(m_epPassword);
			auths.Append(auth);
		}
#endif
		return auths;
	}

	void SetEPPassword(const PString & password) { m_epPassword = password; }

	// H.235.1 on the call signaling is hop by hop: messages from the gatekeeper are signed with our own
	// password and the gatekeeper's ID as sendersID
	virtual PBoolean OnCallAuthentication(const PString & username, PString & password)
	{
		H323Gatekeeper * gk = GetGatekeeper();
		PString gkID = gk ? gk->GetName() : PString::Empty();	// eg. "GnuGkTest@ip$10.99.0.1:1719"
		if (gkID.Find('@') != P_MAX_INDEX)
			gkID = gkID.Left(gkID.Find('@'));
		if (m_epPassword.IsEmpty() || username != gkID) {
			PTRACE(1, "GKTESTEP\tNo password for call authentication of " << username);
			return false;
		}
		password = m_epPassword;
		return true;
	}

	virtual void OnRegistrationConfirm(const H323TransportAddress & rasAddress)
	{
		H323EndPoint::OnRegistrationConfirm(rasAddress);
		PWaitAndSignal lock(m_mutex);
		m_rrqConfirmed = true;
	}

	virtual void OnRegistrationReject()
	{
		H323EndPoint::OnRegistrationReject();
		PWaitAndSignal lock(m_mutex);
		m_rrqRejected = true;
	}

	virtual H323Connection::AnswerCallResponse OnAnswerCall(H323Connection & connection, const PString & caller,
		const H323SignalPDU & setup, H323SignalPDU &)
	{
		{
			PWaitAndSignal lock(m_mutex);
			setup.GetQ931().GetCalledPartyNumber(m_stats.calledNumber);
			setup.GetQ931().GetCallingPartyNumber(m_stats.callingNumber);
		}
		if (m_reject == "busy") {
			PTRACE(1, "GKTESTEP\tRejecting call from " << caller << " as busy");
			connection.SetCallEndReason(H323Connection::EndedByLocalBusy);
			return H323Connection::AnswerCallDenied;
		}
		if (m_reject == "denied") {
			PTRACE(1, "GKTESTEP\tRejecting call from " << caller);
			return H323Connection::AnswerCallDenied;
		}
		if (m_answerDelay > 0) {
			PTRACE(1, "GKTESTEP\tRinging, answering call from " << caller << " in " << m_answerDelay << " ms");
			PWaitAndSignal lock(m_mutex);
			m_pendingAnswer = connection.GetCallToken();
			m_answerAt = PTime() + PTimeInterval(m_answerDelay);
			return H323Connection::AnswerCallPending;
		}
		PTRACE(1, "GKTESTEP\tAnswering call from " << caller);
		return H323Connection::AnswerCallNow;
	}

	virtual void OnConnectionEstablished(H323Connection & connection, const PString & token)
	{
		PTRACE(1, "GKTESTEP\tCall established " << token);
		PWaitAndSignal lock(m_mutex);
		m_token = token;
		m_stats.connected = true;
		// without a separate H.245 channel the control channel is the signaling channel
		m_stats.h245Tunneling = (&connection.GetControlChannel() == connection.GetSignallingChannel());
		m_connectTime = PTime();
		if (t120Offer) {
			TestConnection * testConnection = dynamic_cast<TestConnection *>(&connection);
			if (testConnection)
				testConnection->OpenT120Channel();
		}
	}

	virtual void OnConnectionCleared(H323Connection & connection, const PString & token)
	{
		PWaitAndSignal lock(m_mutex);
		if (m_token.IsEmpty())
			m_token = token;	// call failed before it was established
		if (token != m_token)
			return;
		m_stats.cleared = true;
		PStringStream reason;
		reason << connection.GetCallEndReason();
		m_stats.endReason = reason;
		m_stats.q931Cause = connection.GetQ931Cause();
		if (m_stats.connected)
			m_stats.durationMs = (PTime() - m_connectTime).GetMilliSeconds();
		PTRACE(1, "GKTESTEP\tCall cleared: " << m_stats.endReason);
	}

	virtual PBoolean OpenAudioChannel(H323Connection &, PBoolean, unsigned, H323AudioCodec & codec)
	{
		codec.SetSilenceDetectionMode(H323AudioCodec::NoSilenceDetection);
		return codec.AttachChannel(new ToneChannel, true);
	}

	// remember the RTP counters while the call is up, the sessions are gone after clearing
	void UpdateRTPStats()
	{
		PString token;
		{
			PWaitAndSignal lock(m_mutex);
			if (!m_stats.connected || m_stats.cleared)
				return;
			token = m_token;
		}
		H323Connection * connection = FindConnectionWithLock(token);
		if (connection == NULL)
			return;
		RTP_Session * session = connection->GetSession(RTP_Session::DefaultAudioSessionID);
		if (session != NULL) {
			PWaitAndSignal lock(m_mutex);
			m_stats.rtpSent = session->GetPacketsSent();
			m_stats.rtpReceived = session->GetPacketsReceived();
		}
		H323Channel * tx = connection->FindChannel(RTP_Session::DefaultAudioSessionID, false);
		H323Channel * rx = connection->FindChannel(RTP_Session::DefaultAudioSessionID, true);
		{
			PWaitAndSignal lock(m_mutex);
			if (tx != NULL)
				m_stats.txCodec = tx->GetCapability().GetFormatName();
			if (rx != NULL)
				m_stats.rxCodec = rx->GetCapability().GetFormatName();
		}
		connection->Unlock();
	}

	// a call is over: keep its stats and get ready for the next one
	void FinishCall()
	{
		PWaitAndSignal lock(m_mutex);
		m_finished.push_back(m_stats);
		m_stats = CallStats();
		m_token = PString::Empty();
	}
	std::vector<CallStats> GetFinished() { PWaitAndSignal lock(m_mutex); return m_finished; }

	bool IsConfirmed() { PWaitAndSignal lock(m_mutex); return m_rrqConfirmed; }
	bool IsRejected() { PWaitAndSignal lock(m_mutex); return m_rrqRejected; }
	CallStats GetStats() { PWaitAndSignal lock(m_mutex); return m_stats; }
	PString GetToken() { PWaitAndSignal lock(m_mutex); return m_token; }

private:
	PMutex m_mutex;
	bool m_rrqConfirmed;
	bool m_rrqRejected;
	TokenType m_tokens;
	bool m_fullQ931;
	std::set<unsigned> m_unsignedRAS;
	PString m_epPassword;
	PString m_reject;
	unsigned m_answerDelay;
	PString m_pendingAnswer;
	PTime m_answerAt;

#ifdef H323_SSL
	H235Authenticator * NewH2351()
	{
		H2351_Authenticator * auth = new H2351_Authenticator;
		auth->FullQ931Checking(m_fullQ931);
		return auth;
	}
#endif
	PString m_token;
	PTime m_connectTime;
	CallStats m_stats;
	std::vector<CallStats> m_finished;
};

////////////////////////////////////////////////////////////////

class GkTestEp : public PProcess
{
	PCLASSINFO(GkTestEp, PProcess)
public:
	GkTestEp() : PProcess("GnuGk", "gktestep", 1, 0, AlphaCode, 1) { }
	void Main();
};

PCREATE_PROCESS(GkTestEp);

static PString JSONString(const PString & s)
{
	PString r = "\"";
	for (PINDEX i = 0; i < s.GetLength(); ++i) {
		char c = s[i];
		if (c == '"' || c == '\\')
			r += '\\';
		if ((unsigned char)c >= 0x20)
			r += c;
	}
	return r + "\"";
}

static bool WaitFor(bool (*cond)(TestEndPoint &), TestEndPoint & ep, unsigned ms)
{
	for (unsigned waited = 0; waited < ms; waited += 50) {
		if (cond(ep))
			return true;
		PThread::Sleep(50);
		ep.Poll();
		ep.UpdateRTPStats();
	}
	return cond(ep);
}

static bool Registered(TestEndPoint & ep) { return ep.IsConfirmed() || ep.IsRejected(); }
static bool Connected(TestEndPoint & ep) { CallStats s = ep.GetStats(); return s.connected || s.cleared; }
static bool Cleared(TestEndPoint & ep) { return ep.GetStats().cleared; }

void GkTestEp::Main()
{
	PArgList & args = GetArguments();
	args.Parse(
		"-gk:"
		"-alias:"
		"-listen:"
		"-password:"
		"-h46018."
		"-h46019m."
		"-t120."
		"-no-faststart."
		"-h2351."
		"-full-q931."
		"-md5-unsigned:"
		"-reject:"
		"-hangup-after:"
		"-answer-delay:"
		"-calls:"
		"-add-alias:"
		"-gateway."
		"-no-tunneling."
		"-no-gk."
		"-ras-port:"
		"-rtp-ports:"
		"-bandwidth:"
		"-brq:"
		"-call:"
		"-duration:"
		"-timeout:"
		"-result:"
		"-trace:"
		"-log:"
		"h-help.", false);

	if (args.HasOption('h') || !(args.HasOption("gk") || args.HasOption("no-gk")) || !args.HasOption("alias") || !args.HasOption("result")) {
		cout << "usage: gktestep --gk ip[:port]|--no-gk --alias name[,name...] --result file.json [options]\n"
			"  --no-gk              don't use a gatekeeper (calls go to the address given with --call)\n"
			"  --ras-port port      local RAS port (default 1719)\n"
			"  --rtp-ports min-max  local RTP/RTCP port range\n"
			"  --bandwidth n        bandwidth to ask for in ARQs (units of 100 bit/s)\n"
			"  --brq n              caller: send a BRQ for this bandwidth 1 second into the call\n"
			"  --listen ip[:port]   signaling listener (default *:1720), [ipv6]:port for IPv6\n"
			"  --password pw        register with H.235 MD5 tokens\n"
			"  --h2351              use H.235.1 (Procedure I) tokens instead of MD5, also in the call Setup\n"
			"  --full-q931          with --h2351: put tokens into all Q.931 messages, not only the Setup\n"
			"  --md5-unsigned list  send these RAS messages without MD5 token (RRQ,URQ,ARQ,BRQ,DRQ,IRR)\n"
			"  --h46018             use H.460.18/.19 NAT traversal\n"
			"  --h46019m            with --h46018: use H.460.19 RTP multiplexing (receive and send)\n"
			"  --t120               offer T.120 in the capability set and open a T.120 channel when the call is up\n"
			"  --no-faststart       open media with H.245 only\n"
			"  --no-tunneling       use a separate H.245 channel instead of H.245 tunneling\n"
			"  --call alias         call this alias, otherwise answer one call\n"
			"  --calls n            caller: make n calls one after the other, callee: answer up to n calls\n"
			"  --add-alias a[,b]    add these aliases with an additive registration (sent with the next keep-alive RRQ)\n"
			"  --gateway            register as gateway (prefixes come from the gatekeeper config)\n"
			"  --reject busy|denied refuse incoming calls as busy (cause 17) or rejected (cause 21)\n"
			"  --hangup-after sec   callee: hang up an answered call after this time\n"
			"  --answer-delay sec   callee: ring this long before answering\n"
			"  --duration sec       how long to keep the call up (caller) or to wait for a call (callee)\n"
			"  --timeout sec        max. time for registration and call setup (default 10)\n"
			"  --trace n --log file PTLib trace output\n";
		SetTerminationValue(2);
		return;
	}

	if (args.HasOption("trace"))
		PTrace::Initialise(args.GetOptionString("trace").AsInteger(),
			args.HasOption("log") ? (const char *)args.GetOptionString("log") : NULL,
			PTrace::Timestamp | PTrace::Thread | PTrace::FileAndLine);

	const unsigned timeoutMs = args.GetOptionString("timeout", "10").AsUnsigned() * 1000;
	const unsigned durationMs = args.GetOptionString("duration", "5").AsUnsigned() * 1000;
	// a comma separated list: the first one is the local user name, numbers become dialedDigits aliases
	const PStringArray aliases = args.GetOptionString("alias").Tokenise(",", false);
	const PString alias = aliases[0];

	TestEndPoint * ep = new TestEndPoint;
	ep->SetLocalUserName(alias);
	for (PINDEX i = 1; i < aliases.GetSize(); ++i)
		ep->AddAliasName(aliases[i]);
	if (args.HasOption("reject")) {
		PString reject = args.GetOptionString("reject");
		if (reject != "busy" && reject != "denied") {
			cerr << "--reject must be busy or denied" << endl;
			SetTerminationValue(2);
			return;
		}
		ep->SetReject(reject);
	}
	ep->SetAnswerDelay(args.GetOptionString("answer-delay", "0").AsUnsigned() * 1000);
	if (args.HasOption("gateway"))
		ep->SetTerminalType(H323EndPoint::e_GatewayOnly);
	if (args.HasOption("bandwidth"))
		ep->SetInitialBandwidth(args.GetOptionString("bandwidth").AsUnsigned());
	t120Offer = args.HasOption("t120");
	ep->DisableFastStart(args.HasOption("no-faststart"));
	ep->DisableH245Tunneling(args.HasOption("no-tunneling"));
	ep->SetSilenceDetectionMode(H323AudioCodec::NoSilenceDetection);

	// G.711 only, it's built into H323Plus and needs no plugins
	ep->SetCapability(0, 0, new H323_G711Capability(H323_G711Capability::muLaw));
	ep->SetCapability(0, 0, new H323_G711Capability(H323_G711Capability::ALaw));
	ep->AddAllUserInputCapabilities(0, P_MAX_INDEX);

#ifdef H323_H460
	if (args.HasOption("h46018")) {
		ep->H46018Enable(true);
#ifdef H323_H46019M
		ep->H46019MEnable(args.HasOption("h46019m"));
		ep->H46019MSending(args.HasOption("h46019m"));
#else
		if (args.HasOption("h46019m")) {
			cerr << "H323Plus was built without H.460.19 multiplexing" << endl;
			SetTerminationValue(2);
			return;
		}
#endif
#ifdef H323_H46023
		ep->H46023Enable(false);
#endif
#ifdef H323_H46026
		ep->H46026Enable(false);
#endif
		// the application has to load the base feature set, otherwise the H.460 features of a call have no
		// endpoint (H.460.19 isn't offered in the Setup, H323Plus crashes on a multiplexing Connect)
		ep->LoadBaseFeatureSet();
	} else {
		ep->FeatureSetDisable();	// no H.460 features at all
	}
#else
	if (args.HasOption("h46018")) {
		cerr << "H323Plus was built without H.460 support" << endl;
		SetTerminationValue(2);
		return;
	}
#endif

	if (args.HasOption("rtp-ports")) {
		PStringArray range = args.GetOptionString("rtp-ports").Tokenise("-", false);
		if (range.GetSize() == 2)
			ep->SetRtpIpPorts(range[0].AsUnsigned(), range[1].AsUnsigned());
	}

	// ip:port, or [ipv6]:port
	PString listen = args.GetOptionString("listen", "*:1720");
	PString listenIP;
	WORD listenPort = 1720;
	const bool ipv6 = (listen.Left(1) == "[");
	if (ipv6) {
		listenIP = listen(1, listen.Find(']') - 1);
		if (listen.Find("]:") != P_MAX_INDEX)
			listenPort = (WORD)listen.Mid(listen.Find("]:") + 2).AsUnsigned();
		PIPSocket::SetDefaultIpAddressFamilyV6();
	} else {
		listenIP = listen.Left(listen.Find(':'));
		if (listen.Find(':') != P_MAX_INDEX)
			listenPort = (WORD)listen.Mid(listen.Find(':') + 1).AsUnsigned();
	}
	PIPSocket::Address listenAddr = (listenIP == "*" || listenIP.IsEmpty()) ? PIPSocket::Address::GetAny(4) : PIPSocket::Address(listenIP);
	if (!ep->StartListener(new H323ListenerTCP(*ep, listenAddr, listenPort))) {
		cerr << "Could not start listener on " << listen << endl;
		SetTerminationValue(2);
		return;
	}

	if (args.HasOption("password")) {
		if (args.HasOption("h2351")) {
#ifdef H323_SSL
			ep->UseTokens(TestEndPoint::H2351Tokens, args.HasOption("full-q931"));
			ep->SetEPPassword(args.GetOptionString("password"));	// for the call signaling
#else
			cerr << "H323Plus was built without SSL, no H.235.1 support" << endl;
			SetTerminationValue(2);
			return;
#endif
		} else {
			ep->UseTokens(TestEndPoint::MD5Tokens, false);
			PStringArray names = args.GetOptionString("md5-unsigned").Tokenise(",", false);
			std::set<unsigned> unsignedRAS;
			for (PINDEX i = 0; i < names.GetSize(); ++i) {
				unsigned tag;
				if (!RASTag(names[i].Trim(), tag)) {
					cerr << "Unknown RAS message " << names[i] << endl;
					SetTerminationValue(2);
					return;
				}
				unsignedRAS.insert(tag);
			}
			ep->SetUnsignedRAS(unsignedRAS);
		}
		ep->SetGatekeeperPassword(args.GetOptionString("password"));
	}

	const bool noGk = args.HasOption("no-gk");
	bool registered = false;
	if (!noGk) {
		PString gk = args.GetOptionString("gk");
		PString localRAS = (listenIP == "*" || listenIP.IsEmpty()) ? PString::Empty() : (ipv6 ? "[" + listenIP + "]" : listenIP);
		if (!localRAS.IsEmpty() && args.HasOption("ras-port"))
			localRAS += ":" + args.GetOptionString("ras-port");
		ep->UseGatekeeper(gk, PString::Empty(), localRAS);	// the result is reported by the RCF/RRJ callbacks
		registered = WaitFor(Registered, *ep, timeoutMs) && ep->IsConfirmed();
	}

	TestGatekeeper * testGk = dynamic_cast<TestGatekeeper *>(ep->GetGatekeeper());
	if (registered && args.HasOption("add-alias") && testGk != NULL)
		testGk->AddAliasesOnNextRRQ(args.GetOptionString("add-alias").Tokenise(",", false));

	bool callAttempted = false;
	int brqResult = -1;	// -1: no BRQ sent, 0: BRJ, 1: BCF
	if (registered || noGk) {
		const unsigned calls = args.GetOptionString("calls", "1").AsUnsigned();
		if (args.HasOption("call")) {
			callAttempted = true;
			for (unsigned i = 0; i < calls; ++i) {
				if (i > 0)
					PThread::Sleep(200);
				PString token;
				ep->MakeCall(args.GetOptionString("call"), token);
				if (WaitFor(Connected, *ep, timeoutMs) && ep->GetStats().connected) {
					if (args.HasOption("brq") && !WaitFor(Cleared, *ep, 1000)) {
						H323Connection * connection = ep->FindConnectionWithLock(ep->GetToken());
						if (connection != NULL) {
							brqResult = ep->GetGatekeeper()->BandwidthRequest(*connection, args.GetOptionString("brq").AsUnsigned()) ? 1 : 0;
							connection->Unlock();
						}
					}
					WaitFor(Cleared, *ep, durationMs);	// keep the call up (unless the other side hangs up)
					ep->UpdateRTPStats();
					ep->ClearCall(ep->GetToken());
				} else if (!ep->GetStats().cleared) {
					PTRACE(1, "GKTESTEP\tNot answered within the timeout, hanging up");
					ep->ClearCall(token);
				}
				WaitFor(Cleared, *ep, timeoutMs);
				ep->FinishCall();
			}
		} else {
			// wait for calls (up to --calls) and stay until they end or the time is up
			const PTime deadline = PTime() + PTimeInterval(durationMs);
			for (unsigned i = 0; i < calls; ++i) {
				PInt64 remaining = (deadline - PTime()).GetMilliSeconds();
				if (remaining <= 0 || !WaitFor(Connected, *ep, (unsigned)remaining))
					break;
				callAttempted = true;
				if (ep->GetStats().connected) {
					if (args.HasOption("hangup-after")) {
						WaitFor(Cleared, *ep, args.GetOptionString("hangup-after").AsUnsigned() * 1000);
						ep->UpdateRTPStats();
						ep->ClearCall(ep->GetToken());
					}
					WaitFor(Cleared, *ep, durationMs + timeoutMs);
				}
				ep->FinishCall();
			}
		}
	}

	// the top level fields describe the last call, "calls" has all of them
	std::vector<CallStats> finished = ep->GetFinished();
	if (finished.empty())
		finished.push_back(ep->GetStats());
	CallStats stats = finished.back();
	unsigned connectedCalls = 0;
	for (size_t i = 0; i < finished.size(); ++i)
		if (finished[i].connected)
			++connectedCalls;

	bool unregistered = false;
	if (registered) {
		H323Gatekeeper * gatekeeper = ep->GetGatekeeper();
		unregistered = (gatekeeper != NULL) && gatekeeper->UnregistrationRequest(H225_UnregRequestReason::e_maintenance);
	}

	PTextFile out;
	if (!out.Open(args.GetOptionString("result"), PFile::WriteOnly)) {
		cerr << "Can't write " << args.GetOptionString("result") << endl;
		SetTerminationValue(2);
	} else {
		out << "{\n"
			<< "  \"alias\": " << JSONString(alias) << ",\n"
			<< "  \"registered\": " << (registered ? "true" : "false") << ",\n"
			<< "  \"registrationRejected\": " << (ep->IsRejected() ? "true" : "false") << ",\n"
			<< "  \"callAttempted\": " << (callAttempted ? "true" : "false") << ",\n"
			<< "  \"connected\": " << (stats.connected ? "true" : "false") << ",\n"
			<< "  \"cleared\": " << (stats.cleared ? "true" : "false") << ",\n"
			<< "  \"endReason\": " << JSONString(stats.endReason) << ",\n"
			<< "  \"q931Cause\": " << (stats.cleared ? stats.q931Cause : 0) << ",\n"
			<< "  \"durationMs\": " << stats.durationMs << ",\n"
			<< "  \"h245Tunneling\": " << (stats.h245Tunneling ? "true" : "false") << ",\n"
			<< "  \"calledNumber\": " << JSONString(stats.calledNumber) << ",\n"
			<< "  \"callingNumber\": " << JSONString(stats.callingNumber) << ",\n"
			<< "  \"rtpSent\": " << stats.rtpSent << ",\n"
			<< "  \"rtpReceived\": " << stats.rtpReceived << ",\n"
			<< "  \"txCodec\": " << JSONString(stats.txCodec) << ",\n"
			<< "  \"rxCodec\": " << JSONString(stats.rxCodec) << ",\n"
			<< "  \"brqConfirmed\": " << (brqResult < 0 ? "null" : (brqResult ? "true" : "false")) << ",\n"
			<< "  \"unregistered\": " << (unregistered ? "true" : "false") << ",\n"
			<< "  \"additiveRRQSent\": " << ((testGk != NULL && testGk->AdditiveRRQSent()) ? "true" : "false") << ",\n"
			<< "  \"callsConnected\": " << connectedCalls << ",\n"
			<< "  \"t120CapReceived\": " << (t120CapReceived ? "true" : "false") << ",\n"
			<< "  \"t120OlcReceived\": " << (t120OlcReceived ? "true" : "false") << ",\n"
			<< "  \"t120OlcRejected\": " << (t120OlcRejected ? "true" : "false") << ",\n"
			<< "  \"calls\": [\n";
		for (size_t i = 0; i < finished.size(); ++i)
			out << "    {\"connected\": " << (finished[i].connected ? "true" : "false")
				<< ", \"calledNumber\": " << JSONString(finished[i].calledNumber)
				<< ", \"callingNumber\": " << JSONString(finished[i].callingNumber)
				<< ", \"endReason\": " << JSONString(finished[i].endReason)
				<< ", \"rtpSent\": " << finished[i].rtpSent << ", \"rtpReceived\": " << finished[i].rtpReceived
				<< "}" << (i + 1 < finished.size() ? "," : "") << "\n";
		out << "  ]\n"
			<< "}\n";
		out.Close();
	}

	ep->RemoveGatekeeper();
	delete ep;
}
