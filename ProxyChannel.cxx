//////////////////////////////////////////////////////////////////
//
// ProxyChannel.cxx
//
// Copyright (c) Citron Network Inc. 2001-2002
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 12/19/2001
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4355 ) // warning about using 'this' in initializer
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include "ANSI.h"
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "stl_supp.h"
#include "ProxyChannel.h"
#include <q931.h>
#include <h245.h>

const char *RoutedSec = "RoutedMode";

class H245Socket : public TCPProxySocket {
public:
	PCLASSINFO ( H245Socket, TCPProxySocket )

	H245Socket(CallSignalSocket *);
	H245Socket(H245Socket *, CallSignalSocket *);
	~H245Socket();

	// override from class ProxySocket
        virtual Result ReceiveData();
	virtual bool EndSession();

	// override from class TCPProxySocket
	virtual TCPProxySocket *ConnectTo();

	bool SetH245Address(H225_TransportAddress & h245addr, Address);
	void OnSignalingChannelClosed() { sigSocket = 0; }
	
private:
	CallSignalSocket *sigSocket;
	H225_TransportAddress peerH245Addr;
	PTCPSocket *listener;
};

class UDPProxySocket : public PUDPSocket, public ProxySocket {
public:
	PCLASSINFO( UDPProxySocket, PUDPSocket )

	UDPProxySocket(const char *);
	virtual ~UDPProxySocket() {}

	void SetDestination(H245_UnicastAddress_iPAddress &);

	bool Bind(Address ip, WORD pt);

private:
	Address localAddr;
	WORD localPort;
};

class T120ProxySocket : public TCPProxySocket {
public:
	PCLASSINFO ( T120ProxySocket, TCPProxySocket )

	T120ProxySocket(T120ProxySocket * = 0, WORD = 0);

	void SetDestination(Address, WORD);

	// override from class ProxySocket
	virtual bool ForwardData() { return WriteData(remote); }
	virtual bool TransmitData() { return WriteData(this); }

	// override from class TCPProxySocket
	virtual TCPProxySocket *ConnectTo();

private:
	Address peerAddr;
	WORD peerPort;
};

class LogicalChannel {
public:
	LogicalChannel(WORD flcn) : channelNumber(flcn), used(false) {}
	virtual ~LogicalChannel() {}

	bool IsUsed() const { return used; }
	bool Compare(WORD lcn) const { return channelNumber == lcn; }
	WORD GetPort() const { return port; }
	WORD GetChannelNumber() const { return channelNumber; }

	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *) = 0;
	virtual void StartReading(ProxyHandleThread *) = 0;

protected:
	WORD channelNumber;
	WORD port;
	bool used;
};

class RTPLogicalChannel : public LogicalChannel {
public:
	RTPLogicalChannel(PIPSocket::Address, WORD);
	virtual ~RTPLogicalChannel();

	// override from class LogicalChannel
	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *);
	virtual void StartReading(ProxyHandleThread *);

	class NoPortAvailable {};

private:
	static WORD GetPortNumber();
	static WORD portNumber;
	static PMutex mutex;

	UDPProxySocket *rtp, *rtcp;
};

class T120LogicalChannel : public LogicalChannel {
public:
	T120LogicalChannel(WORD);
	virtual ~T120LogicalChannel();

	// override from class LogicalChannel
	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *);
	virtual void StartReading(ProxyHandleThread *);

	void AcceptCall();
	bool OnSeparateStack(H245_NetworkAccessParameters &, H245Handler *);

private:
	class T120Listener : public MyPThread {
	public:
		PCLASSINFO ( T120Listener, MyPThread )

		T120Listener(T120LogicalChannel *lc) : t120lc(lc) { Resume(); }
		// override from class MyPThread
		virtual void Exec() { t120lc->AcceptCall(); }

	private:
		T120LogicalChannel *t120lc;
	};

	T120Listener *listenThread;
	PTCPSocket listener;
	T120ProxySocket *t120socket;
	ProxyHandleThread *handler;
	PIPSocket::Address peerAddr;
	WORD peerPort;
};

inline bool UDPProxySocket::Bind(Address ip, WORD pt)
{
	localAddr = ip, localPort = pt;
	return Listen(0, pt);
}

inline void T120ProxySocket::SetDestination(Address ip, WORD pt)
{
	peerAddr = ip, peerPort = pt;
}

// class CallSignalSocket
CallSignalSocket::CallSignalSocket()
      : TCPProxySocket("Q931s"), m_h245handler(0), m_h245socket(0)
{
	localAddr = peerAddr = INADDR_ANY;
}

CallSignalSocket::CallSignalSocket(CallSignalSocket *socket, WORD port)
      : TCPProxySocket("Q931d", socket, port), m_h245handler(0), m_h245socket(0)
{
	m_call = socket->m_call;
	m_call->SetSocket(socket, this);
	m_crv = (socket->m_crv & 0x7fffu);
	socket->GetLocalAddress(localAddr);
	socket->GetPeerAddress(peerAddr, peerPort);
	SetHandler(socket->GetHandler());
	// enable proxy if required, no matter whether H.245 routed
	if (Toolkit::Instance()->ProxyRequired(peerAddr, socket->peerAddr)) {
		H245ProxyHandler *proxyhandler = new H245ProxyHandler(socket, socket->localAddr);
		socket->m_h245handler = proxyhandler;
		m_h245handler = new H245ProxyHandler(this, localAddr, proxyhandler);
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled");
	} else if (m_call->IsH245Routed()) {
		socket->m_h245handler = new H245Handler(socket->localAddr);
		m_h245handler = new H245Handler(localAddr);
	}
}

CallSignalSocket::~CallSignalSocket()
{
	delete m_h245handler;
	if (m_h245socket) {
		m_h245socket->EndSession();
		m_h245socket->OnSignalingChannelClosed();
		m_h245socket->SetDeletable();
	}
}

ProxySocket::Result CallSignalSocket::ReceiveData()
{
	if (!ReadTPKT())
		return NoData;

	Q931 q931pdu;
	q931pdu.Decode(buffer);

	PTRACE(3, "Q931\t" << Name() << " Message type: " << q931pdu.GetMessageTypeName());
	PTRACE(4, "Q931\t" << Name() << " Call reference: " << q931pdu.GetCallReference());
	PTRACE(4, "Q931\t" << Name() << " From destination " << q931pdu.IsFromDestination());
	PTRACE(6, ANSI::BYEL << "Q931\nMessage received: " << setprecision(2) << q931pdu << ANSI::OFF);

	if (q931pdu.HasIE(Q931::UserUserIE)) {
		H225_H323_UserInformation signal;
		PPER_Stream q = q931pdu.GetIE(Q931::UserUserIE);
		if (!signal.Decode(q)) {
			PTRACE(4, "Q931\t" << Name() << " ERROR DECODING UUIE!");
			return Error;
		}

		H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
		H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;

		PTRACE(6, ANSI::BYEL << "Q931\nUUIE received: " << setprecision(2) << pdu << ANSI::OFF);

		switch (body.GetTag())
		{
		case H225_H323_UU_PDU_h323_message_body::e_setup:
			m_crv = (q931pdu.GetCallReference() | 0x8000u);
			OnSetup(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_callProceeding:
			OnCallProceeding(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_connect:
			OnConnect(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_alerting:
			OnAlerting(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_information:
			OnInformation(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_releaseComplete:
			OnReleaseComplete(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_facility:
			OnFacility(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_progress:
			OnProgress(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_empty:
			OnEmpty(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_status:
			OnStatus(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_statusInquiry:
			OnStatusInquiry(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_setupAcknowledge:
			OnSetupAcknowledge(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_notify:
			OnNotify(body);
			break;
		default:
			PTRACE(4, "Q931\t" << Name() << " UNKNOWN Q.931");
			break;
		}
		
		if (pdu.HasOptionalField(H225_H323_UU_PDU::e_nonStandardControl)) {
			for (PINDEX n = 0; n < pdu.m_nonStandardControl.GetSize(); ++n)
				OnNonStandardData(pdu.m_nonStandardControl[n].m_data);
			PTRACE(5, "Q931\t" << Name() << " Rewriting nonStandardControl\n" << setprecision(2) << pdu);
		}
		if (pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control) && m_h245handler)
			OnTunneledH245(pdu.m_h245Control);

		PTRACE(5, ANSI::BGRE << "Q931\nUUIE to sent: " << setprecision(2) << pdu << ANSI::OFF);

		PPER_Stream sb;
		signal.Encode(sb);
		sb.CompleteEncoding();
		q931pdu.SetIE(Q931::UserUserIE, sb);
	} 
/*
   Note: Openh323 1.7.9 or later required.
   The older version has an out of memory bug in Q931::GetCalledPartyNumber.
*/
	if (q931pdu.HasIE(Q931::CalledPartyNumberIE)) {
		unsigned plan, type;
		PString calledNumber;
		if (q931pdu.GetCalledPartyNumber(calledNumber, &plan, &type) &&
		    Toolkit::Instance()->RewritePString(calledNumber))
			q931pdu.SetCalledPartyNumber(calledNumber, plan, type);
	}
/*
	if (q931pdu.HasIE(Q931::CalledPartyNumberIE)) {
		PBYTEArray n_array = q931pdu.GetIE(Q931::CalledPartyNumberIE);
		if (n_array.GetSize() > 0) {
			const char* n_bytes = (const char*) (n_array.GetPointer());
			PString n_string(n_bytes+1, n_array.GetSize()-1);
			if (Toolkit::Instance()->RewritePString(n_string))
				q931pdu.SetCalledPartyNumber(n_string, Q931::ISDNPlan, Q931::NationalType);
		}
	}
*/

	q931pdu.Encode(buffer);
	PTRACE(5, ANSI::BGRE << "Q931\nMessage to sent: " << setprecision(2) << q931pdu << ANSI::OFF);

	switch (q931pdu.GetMessageType())
	{
		case Q931::SetupMsg:
			break;
		case Q931::StatusMsg:
			// don't forward status messages mm-30.04.2001
			return NoData;
		case Q931::ReleaseCompleteMsg:
			if (m_call)
				CallTable::Instance()->RemoveCall(m_call);
			return Closing;
		default:
			return Forwarding;
	}
	
	if (!m_call) {
		PTRACE(3, "Q931\t" << Name() << " Setup destination not found!");
		EndSession();
		SetDeletable();
		return Error;
	}
	if (peerAddr == INADDR_ANY) {
		PTRACE(3, "Q931\t" << Name() << " INVALID ADDRESS");
		EndSession();
		CallTable::Instance()->RemoveCall(m_call);
		return Error;
	}

	return Connecting;
}

void CallSignalSocket::BuildReleasePDU(Q931 & ReleasePDU) const
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
	H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_releaseComplete);
	H225_ReleaseComplete_UUIE & uuie = body;
	uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_callIdentifier);
	uuie.m_callIdentifier = m_call->GetCallIdentifier();
	PPER_Stream sb;
	signal.Encode(sb);
	sb.CompleteEncoding();

	ReleasePDU.BuildReleaseComplete(m_crv, m_crv & 0x8000u);
	ReleasePDU.SetIE(Q931::UserUserIE, sb);
}

bool CallSignalSocket::EndSession()
{
	if (m_call && IsOpen()) {
		Q931 ReleasePDU;
		BuildReleasePDU(ReleasePDU);
		ReleasePDU.Encode(buffer);
		TransmitData();
		PTRACE(4, "GK\tSend Release Complete to " << Name());
//		PTRACE(5, "GK\tRelease Complete: " << ReleasePDU);
	}
	return TCPProxySocket::EndSession();
}

TCPProxySocket *CallSignalSocket::ConnectTo()
{
	if (remote->Connect(peerAddr)) {
		PTRACE(3, "Q931(" << getpid() << ") Connect to " << peerAddr << " successful");
		SetConnected(true);
		remote->SetConnected(true);
		ForwardData();
		return remote;
	} else {
		PTRACE(3, "Q931\t" << peerAddr << " DIDN'T ACCEPT THE CALL");
		EndSession();
		MarkBlocked(true);
		delete remote; // would close myself
		CallTable::Instance()->RemoveCall(m_call);
		MarkBlocked(false);
		return 0;
	}
}

void CallSignalSocket::OnSetup(H225_Setup_UUIE & Setup)
{
	if (!Setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
		PTRACE(1, "Q931\tSetup_UUIE doesn't contain CallIdentifier!");
		return;
	}
	m_call = CallTable::Instance()->FindCallRec(Setup.m_callIdentifier);
	if (!m_call) {
		PTRACE(3, "Q931\tOnSetup() didn't find the call: " << AsString(Setup.m_callIdentifier.m_guid));
		return;
	}
	const H225_TransportAddress *addr = m_call->GetCalledAddress();
	if (!addr || addr->GetTag() != H225_TransportAddress::e_ipAddress)
		return;

	const H225_TransportAddress_ipAddress & ip = *addr;
	peerAddr = PIPSocket::Address(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
	peerPort = ip.m_port;
	localAddr = Toolkit::Instance()->GetRouteTable()->GetLocalAddress(peerAddr);
	remote = new CallSignalSocket(this, peerPort);

	// re-route called endpoint signalling messages to gatekeeper	
	Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
	Setup.m_sourceCallSignalAddress = SocketToH225TransportAddr(localAddr, GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_CALL_SIGNAL_PORT));

	// in routed mode the caller may have put the GK address in destCallSignalAddress
	// since it is optional, we just remove it (we could alternativly insert the real destination SignalAdr)
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress))
		Setup.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);

	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
		for (PINDEX n = 0; n < Setup.m_destinationAddress.GetSize(); ++n)
			Toolkit::Instance()->RewriteE164(Setup.m_destinationAddress[n]);

	// to compliance to MediaRing VR, we have to setup our H323ID
	PString H323ID = GkConfig()->GetString("H323ID");
	if (!H323ID) {
		PINDEX s = 0;
		if (Setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress))
			s = Setup.m_sourceAddress.GetSize();
		else
			Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
		Setup.m_sourceAddress.SetSize(s+1);
		H225_AliasAddress & alias = Setup.m_sourceAddress[s];
		alias.SetTag(H225_AliasAddress::e_h323_ID);
		(PASN_BMPString &)alias = H323ID;
	}

	HandleH245Address(Setup);
	HandleFastStart(Setup);
}
 
void CallSignalSocket::OnCallProceeding(H225_CallProceeding_UUIE & CallProceeding)
{
	HandleH245Address(CallProceeding);
	HandleFastStart(CallProceeding);
}

void CallSignalSocket::OnConnect(H225_Connect_UUIE & Connect)
{
	if (m_call) // hmm... it should not be null
		m_call->SetConnected(true);
#ifndef NDEBUG
	if (!Connect.HasOptionalField(H225_Connect_UUIE::e_callIdentifier)) {
		PTRACE(1, "Q931\tConnect_UUIE doesn't contain CallIdentifier!");
	} else if (m_call->GetCallIdentifier() != Connect.m_callIdentifier) {
		PTRACE(1, "Q931\tWarning: CallIdentifier doesn't match?");
	}
#endif
	HandleH245Address(Connect);
	HandleFastStart(Connect);
}

void CallSignalSocket::OnAlerting(H225_Alerting_UUIE & Alerting)
{
	HandleH245Address(Alerting);
	HandleFastStart(Alerting);
}

void CallSignalSocket::OnInformation(H225_Information_UUIE &)
{
	// do nothing
}

void CallSignalSocket::OnReleaseComplete(H225_ReleaseComplete_UUIE & ReleaseComplete)
{
	// do nothing
}

void CallSignalSocket::OnFacility(H225_Facility_UUIE & Facility)
{
	HandleH245Address(Facility);
	HandleFastStart(Facility);
}

void CallSignalSocket::OnProgress(H225_Progress_UUIE & Progress)
{
	HandleH245Address(Progress);
	HandleFastStart(Progress);
}

void CallSignalSocket::OnEmpty(H225_H323_UU_PDU_h323_message_body &)
{
	// do nothing
}

void CallSignalSocket::OnStatus(H225_Status_UUIE &)
{
	// do nothing
}

void CallSignalSocket::OnStatusInquiry(H225_StatusInquiry_UUIE &)
{
	// do nothing
}

void CallSignalSocket::OnSetupAcknowledge(H225_SetupAcknowledge_UUIE &)
{
	// do nothing
}

void CallSignalSocket::OnNotify(H225_Notify_UUIE &)
{
	// do nothing
}

void CallSignalSocket::OnNonStandardData(PASN_OctetString & octs)
{
	BOOL changed = FALSE;
	BYTE buf[5000];
	BYTE *pBuf  = buf;               // write pointer
	BYTE *pOcts = octs.GetPointer(); // read pointer
	BYTE *mOcts = pOcts + octs.GetSize();
	PString *CalledPN;
	
	while (pOcts < mOcts) {
		BYTE type  = pOcts[0];
		BYTE len   = pOcts[1];
		switch (type) { 
		case 0x70: // called party
			CalledPN = new PString( (char*) (&(pOcts[3])), len-1); 
			if (Toolkit::Instance()->RewritePString(*CalledPN)) {
				// change
				const char* s = *CalledPN;
				pBuf[0] = type;
				pBuf[1] = strlen(s)+1;
				pBuf[2] = pOcts[2];  // type of number, numbering plan id
				memcpy(&(pBuf[3]), s, strlen(s));
				pBuf += strlen(s)+3; 
				changed = TRUE;
			} else { 
				// leave unchanged
				memcpy(pBuf, pOcts, (len+2)*sizeof(BYTE));
				pBuf += len+2;  // incr write pointer
			}
			delete CalledPN;
			break;
		case 0x6c: // calling party
		default: // copy through
			memcpy(pBuf, pOcts, (len+2)*sizeof(BYTE));
			pBuf += len+2;  // incr write pointer
		}
		
		// increment read pointer
		pOcts += len+2;
	}
	
	// set new value if necessary
	if (changed)
		octs.SetValue(buf, pBuf-buf);
}

void CallSignalSocket::OnTunneledH245(H225_ArrayOf_PASN_OctetString & h245Control)
{
	for(PINDEX i = 0; i < h245Control.GetSize(); ++i) {
		PPER_Stream strm = h245Control[i].GetValue();
		if (HandleH245Mesg(strm))
			h245Control[i].SetValue(strm);
	}
}

void CallSignalSocket::OnFastStart(H225_ArrayOf_PASN_OctetString & fastStart)
{
	for(PINDEX i = 0; i < fastStart.GetSize(); ++i) {
		PPER_Stream strm = fastStart[i].GetValue();
		H245_OpenLogicalChannel olc;
		olc.Decode(strm);
		PTRACE(5, "Q931\nfastStart = " << setprecision(2) << olc);
	}
}

bool CallSignalSocket::SetH245Address(H225_TransportAddress & h245addr)
{
	CallSignalSocket *ret = dynamic_cast<CallSignalSocket *>(remote);
	if (!ret) {
		PTRACE(2, "H245\t" << Name() << " no remote party?");
		return false;
	}
	if (m_h245socket) {
		if (m_h245socket->IsConnected()) {
			PTRACE(4, "H245\t" << Name() << " H245 channel already established");
			return false;
		} else {
			if (m_h245socket->SetH245Address(h245addr, localAddr))
				std::swap(m_h245socket, ret->m_h245socket);
			return true;
		}
	}
	m_h245socket = new H245Socket(this);
	ret->m_h245socket = new H245Socket(m_h245socket, ret);
	m_h245socket->SetH245Address(h245addr, localAddr);
	GetHandler()->ConnectTo(m_h245socket);
	return true;
}

// class H245Handler
bool H245Handler::HandleMesg(PPER_Stream & mesg)
{
	H245_MultimediaSystemControlMessage h245msg;
	h245msg.Decode(mesg);
	PTRACE(6, ANSI::BYEL << "H245\nMessage received: " << setprecision(2) << h245msg << ANSI::OFF);

	bool changed = false;
	switch (h245msg.GetTag())
	{
		case H245_MultimediaSystemControlMessage::e_request:
			changed = HandleRequest(h245msg);
			break;
		case H245_MultimediaSystemControlMessage::e_response:
			changed = HandleResponse(h245msg);
			break;
		case H245_MultimediaSystemControlMessage::e_command:
			changed = HandleCommand(h245msg);
		//	if (((H245_CommandMessage &)h245msg).GetTag() == H245_CommandMessage::e_endSessionCommand)
		//		res = ProxySocket::Closing;
			break;
		case H245_MultimediaSystemControlMessage::e_indication:
			changed = HandleIndication(h245msg);
			break;
		default:
			PTRACE(2, "H245\tUnknown H245 message: " << h245msg.GetTag());
			break;
	}
	if (changed) {
		PPER_Stream sm;
		h245msg.Encode(sm);
		sm.CompleteEncoding();
		mesg = sm;
	}

	PTRACE(5, ANSI::BGRE << "H245\nMessage to sent: " << setprecision(2) << h245msg << ANSI::OFF);
	return changed;
}

bool H245Handler::HandleRequest(H245_RequestMessage & Request)
{
	PTRACE(4, "H245\tRequest: " << Request.GetTagName());
	return false;
}

bool H245Handler::HandleResponse(H245_ResponseMessage & Response)
{
	PTRACE(4, "H245\tResponse: " << Response.GetTagName());
	return false;
}

bool H245Handler::HandleIndication(H245_IndicationMessage & Indication)
{
	PTRACE(4, "H245\tIndication: " << Indication.GetTagName());
	return false;
}

bool H245Handler::HandleCommand(H245_CommandMessage & Command)
{
	PTRACE(4, "H245\tCommand: " << Command.GetTagName());
	return false;
}

// class H245Socket
H245Socket::H245Socket(CallSignalSocket *sig)
      : TCPProxySocket("H245s"), sigSocket(sig), listener(new PTCPSocket)
{
	listener->Listen(1);
	SetHandler(sig->GetHandler());
}

H245Socket::H245Socket(H245Socket *socket, CallSignalSocket *sig)
      : TCPProxySocket("H245d", socket), sigSocket(sig), listener(0)
{
	socket->remote = this;
}

H245Socket::~H245Socket()
{
	delete listener;
	if (sigSocket)
		sigSocket->OnH245ChannelClosed();
}

ProxySocket::Result H245Socket::ReceiveData()
{
	if (!ReadTPKT())
		return NoData;

	PPER_Stream strm(buffer);
	if (sigSocket->HandleH245Mesg(strm))
		buffer = strm;

	return Forwarding;
}

bool H245Socket::EndSession()
{
	if (listener)
		listener->Close();
	return TCPProxySocket::EndSession();
}

TCPProxySocket *H245Socket::ConnectTo()
{
	if (remote->Accept(*listener)) {
		PTRACE(3, "H245\tConnected from " << remote->Name());
		listener->Close(); // don't accept other connection
		if (peerH245Addr.GetTag() != H225_TransportAddress::e_ipAddress) {
			PTRACE(3, "H245\tINVALID ADDRESS");
			return false;
		}
		H225_TransportAddress_ipAddress & ip = peerH245Addr;
		PIPSocket::Address peerAddr(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
		SetPort(ip.m_port);
		if (Connect(peerAddr)) {
			PTRACE(3, "H245(" << getpid() << ") Connect to " << Name() << " successful");
			GetHandler()->Insert(this);
			SetConnected(true);
			remote->SetConnected(true);
			return remote;
		}
		PTRACE(3, "H245\t" << peerAddr << " DIDN'T ACCEPT THE CALL");
	}
	GetHandler()->Insert(this);
	GetHandler()->Insert(remote);
	SetDeletable();
	return 0;
}

bool H245Socket::SetH245Address(H225_TransportAddress & h245addr, Address myip)
{
	bool swapped;
	H245Socket *socket;
	if (listener) {
		socket = this;
		swapped = false;
	} else {
		socket = dynamic_cast<H245Socket *>(remote);
		swapped = true;
		std::swap(this->sigSocket, socket->sigSocket);
	}
	socket->peerH245Addr = h245addr;
	h245addr = SocketToH225TransportAddr(myip, socket->listener->GetPort());
	PTRACE(3, "H245\tSet h245Address to " << AsDotString(h245addr));
	return swapped;
}


namespace { // anonymous namespace

H245_UnicastAddress_iPAddress *GetH245UnicastAddress(H245_TransportAddress & tsap)
{
	if (tsap.GetTag() == H245_TransportAddress::e_unicastAddress) {
		H245_UnicastAddress & uniaddr = tsap;
		if (uniaddr.GetTag() == H245_UnicastAddress::e_iPAddress)
			return &((H245_UnicastAddress_iPAddress &)uniaddr);
	}
	return 0;
}

void SetH245UnicastAddress(H245_UnicastAddress_iPAddress & addr, PIPSocket::Address ip, WORD port)
{
	for (int i = 0; i < 4; ++i)
		addr.m_network[i] = ip[i];
	addr.m_tsapIdentifier = port;
}

bool IsSeparateLANStack(const H245_DataType & data)
{
	if (data.GetTag() == H245_DataType::e_data ) { 
		const H245_DataApplicationCapability & cap = data;
		if (cap.m_application.GetTag() == H245_DataApplicationCapability_application::e_t120) {
			const H245_DataProtocolCapability & proto_cap = cap.m_application;
			return (proto_cap.GetTag() == H245_DataProtocolCapability::e_separateLANStack);
		}
	}
	return false;
}

bool IsT120Channel(const H245_OpenLogicalChannel & olc)
{
	return  IsSeparateLANStack(olc.m_forwardLogicalChannelParameters.m_dataType) &&
		olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters) &&
		IsSeparateLANStack(olc.m_reverseLogicalChannelParameters.m_dataType);
}

inline void delete_lc(std::pair<const WORD, LogicalChannel *> & p)
{
	delete p.second;
}

} // end of anonymous namespace


// class UDPProxySocket
const WORD BufferSize = 2048;

UDPProxySocket::UDPProxySocket(const char *t) : ProxySocket(this, t)
{
	SetReadTimeout(PTimeInterval(50));
        SetWriteTimeout(PTimeInterval(50));
	SetMinBufSize(BufferSize);
}

void UDPProxySocket::SetDestination(H245_UnicastAddress_iPAddress & addr)
{
	Address peerAddr = PIPSocket::Address(addr.m_network[0], addr.m_network[1], addr.m_network[2], addr.m_network[3]);
	WORD peerPort = addr.m_tsapIdentifier;
	SetSendAddress(peerAddr, peerPort);
	SetName(peerAddr, peerPort);

	SetH245UnicastAddress(addr, localAddr, localPort);
	PTRACE(5, "UDP\tListen to " << localAddr << ':' << localPort << ", Destination: " << name);
	SetConnected(true);
}

// class T120ProxySocket
T120ProxySocket::T120ProxySocket(T120ProxySocket *socket, WORD pt)
      : TCPProxySocket("T120", socket, pt)
{
}

TCPProxySocket *T120ProxySocket::ConnectTo()
{
	remote = new T120ProxySocket(this, peerPort);
	if (remote->Connect(peerAddr)) {
		PTRACE(3, "T120\tConnect to " << Name() << " successful");
		SetConnected(true);
		remote->SetConnected(true);
	} else {
		PTRACE(3, "T120\t" << peerAddr << " DIDN'T ACCEPT THE CALL");
		delete remote; // would close myself
	}
	return remote;
}

// class RTPLogicalChannel
const WORD RTPPortLowerLimit = 10000u;
const WORD RTPPortUpperLimit = 60000u;

WORD RTPLogicalChannel::portNumber = RTPPortUpperLimit;
PMutex RTPLogicalChannel::mutex;

RTPLogicalChannel::RTPLogicalChannel(PIPSocket::Address ip, WORD flcn)
      : LogicalChannel(flcn)
{
	rtp = new UDPProxySocket("RTP");
	rtcp = new UDPProxySocket("RTCP");

	// try to get an available port 10 times
	for (int i = 0; i < 10; ++i) {
		port = GetPortNumber();
		// try to bind rtp to an even port and rtcp to the next one port
		if (rtp->Bind(ip, port) && rtcp->Bind(ip, port + 1)) {
			PTRACE(4, "RTP\tOpen RTP logical channel " << flcn << ' ' << ip << ':' << port);
			return;
		}

		PTRACE(3, "RTP\tPort " << port << " not available");
		rtp->Close(), rtcp->Close();
		// try next...
	}
	delete rtp;
	delete rtcp;
	// Oops...
	throw NoPortAvailable();
}

RTPLogicalChannel::~RTPLogicalChannel()
{
	if (used) {
		// the sockets will be deleted by ProxyHandler,
		// so we don't need to delete it here
		rtp->EndSession();
		rtp->SetDeletable();
		rtcp->EndSession();
		rtcp->SetDeletable();
		PTRACE(5, "RTP\tClose RTP logical channel " << channelNumber);
	} else {
		delete rtp;
		delete rtcp;
		PTRACE(4, "RTP\tDelete RTP logical channel " << channelNumber);
	}
}

bool RTPLogicalChannel::SetDestination(H245_OpenLogicalChannelAck & olca, H245Handler *)
{
	if (!olca.HasOptionalField(H245_OpenLogicalChannelAck::e_forwardMultiplexAckParameters))
		return false;
	H245_OpenLogicalChannelAck_forwardMultiplexAckParameters & ackparams = olca.m_forwardMultiplexAckParameters;
	if (ackparams.GetTag() != H245_OpenLogicalChannelAck_forwardMultiplexAckParameters::e_h2250LogicalChannelAckParameters)
		return false;
	H245_H2250LogicalChannelAckParameters & h225Params = ackparams;

	bool hasMediaChannel = false, hasMediaControlChannel = false;
	if (h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaChannel)) {
		H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(h225Params.m_mediaChannel);
		if (addr) {
			rtp->SetDestination(*addr);
			hasMediaChannel = true;
		}
	}
	if (h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaControlChannel)) {
		H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(h225Params.m_mediaControlChannel);
		if (addr) {
			rtcp->SetDestination(*addr);
			hasMediaControlChannel = true;
		}
	}
	return (hasMediaControlChannel && hasMediaChannel);
}

void RTPLogicalChannel::StartReading(ProxyHandleThread *handler)
{
	if (!used) {
		handler->InsertLC(rtp);
		handler->InsertLC(rtcp);
		used = true;
#ifdef PTRACING
	} else {
		PTRACE(2, "RTP\tWarning: channel already be used");
#endif
	}
}

WORD RTPLogicalChannel::GetPortNumber()
{
	PWaitAndSignal lock(mutex);
	portNumber += 2;
	if (portNumber > RTPPortUpperLimit)
		portNumber = RTPPortLowerLimit;
	return portNumber;
}

// class T120LogicalChannel
T120LogicalChannel::T120LogicalChannel(WORD flcn)
      : LogicalChannel(flcn), t120socket(0)
{
	listener.Listen(1);
	port = listener.GetPort();
	PTRACE(4, "T120\tOpen T.120 logical channel " << flcn << " port " << port);
}

T120LogicalChannel::~T120LogicalChannel()
{
	if (used) {
		listener.Close();
		listenThread->Destroy();
		if (t120socket)
			t120socket->SetDeletable();
	}
}

bool T120LogicalChannel::SetDestination(H245_OpenLogicalChannelAck & olca, H245Handler *handler)
{
	return (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_separateStack)) ?
		OnSeparateStack(olca.m_separateStack, handler) : false;
}

void T120LogicalChannel::StartReading(ProxyHandleThread *h)
{
	if (!used) {
		handler = h;
		used = true;
		listenThread = new T120Listener(this);
	}
}

void T120LogicalChannel::AcceptCall()
{
	if (!listener.IsOpen())
		return;

	T120ProxySocket *socket = new T120ProxySocket;
	if (socket->Accept(listener)) {
		PTRACE(4, "T120\tConnected from " << socket->Name());
		socket->SetDestination(peerAddr, peerPort);
		TCPProxySocket *remote = socket->ConnectTo();
		if (remote) {
			if (t120socket)
				t120socket->SetDeletable();
			t120socket = socket;
			handler->InsertLC(t120socket);
			handler->InsertLC(remote);
			return;
		}
	}

	PChannel::Errors err = socket->GetErrorCode();
	PTRACE_IF(3, err != PChannel::Interrupted,
		  "T120\tError: " << PChannel::GetErrorText(err));
	delete socket;
}

bool T120LogicalChannel::OnSeparateStack(H245_NetworkAccessParameters & sepStack, H245Handler *handler)
{
	bool changed = false;
	if (sepStack.m_networkAddress.GetTag() == H245_NetworkAccessParameters_networkAddress::e_localAreaAddress) {
		H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(sepStack.m_networkAddress);
		if (addr) {
			peerAddr = PIPSocket::Address(addr->m_network[0], addr->m_network[1], addr->m_network[2], addr->m_network[3]);
			peerPort = addr->m_tsapIdentifier;
			SetH245UnicastAddress(*addr, handler->GetLocalAddr(), port);
			changed = true;
		}
	}
	return changed;
}

// class H245ProxyHandler
H245ProxyHandler::H245ProxyHandler(CallSignalSocket *sig, PIPSocket::Address local, H245ProxyHandler *pr)
      : H245Handler(local), handler(sig->GetHandler()), peer(pr)
{
	if (peer)
		peer->peer = this;
}

H245ProxyHandler::~H245ProxyHandler()
{
	for_each(logicalChannels.begin(), logicalChannels.end(), delete_lc);
}

bool H245ProxyHandler::HandleRequest(H245_RequestMessage & Request)
{
	PTRACE(4, "H245\tRequest: " << Request.GetTagName());
	switch (Request.GetTag())
	{
		case H245_RequestMessage::e_openLogicalChannel:
			return HandleOpenLogicalChannel(Request);
		case H245_RequestMessage::e_closeLogicalChannel:
			return HandleCloseLogicalChannel(Request);
		default:
			break;
	}
	return false;
}

bool H245ProxyHandler::HandleResponse(H245_ResponseMessage & Response)
{
	PTRACE(4, "H245\tResponse: " << Response.GetTagName());
	switch (Response.GetTag())
	{
		case H245_ResponseMessage::e_openLogicalChannelAck:
			return HandleOpenLogicalChannelAck(Response);
		case H245_ResponseMessage::e_openLogicalChannelReject:
			return HandleOpenLogicalChannelReject(Response);
			break;
		default:
			break;
	}
	return false;
}

bool H245ProxyHandler::HandleOpenLogicalChannel(H245_OpenLogicalChannel & olc)
{
	WORD flcn = olc.m_forwardLogicalChannelNumber;
	if (IsT120Channel(olc)) {
		T120LogicalChannel *lc = new T120LogicalChannel(flcn);
		logicalChannels[flcn] = lc;
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_separateStack)
			&& lc->OnSeparateStack(olc.m_separateStack, this)) {
			lc->StartReading(handler);
			return true;
		}
		return false;
	}

	H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters & params = olc.m_forwardLogicalChannelParameters.m_multiplexParameters;
	if (params.GetTag() != H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters)
		return false;
	H245_H2250LogicalChannelParameters & h225Params = params;

	bool changed = false;
	RTPLogicalChannel *lc = 0;
	if (h225Params.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel)) {
		H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(h225Params.m_mediaControlChannel);
		if (addr) {
			if (!(lc = CreateRTPLogicalChannel(flcn)))
				return false;
			SetH245UnicastAddress(*addr, GetLocalAddr(), lc->GetPort() + 1);
			changed = true;
		}
	}
	if (h225Params.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)) {
		H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(h225Params.m_mediaChannel);
		if (addr) {
			if (!lc && !(lc = CreateRTPLogicalChannel(olc.m_forwardLogicalChannelNumber)))
				return false;
			SetH245UnicastAddress(*addr, GetLocalAddr(), lc->GetPort());
			changed = true;
		}
	}
	return changed;
}

bool H245ProxyHandler::HandleOpenLogicalChannelReject(H245_OpenLogicalChannelReject & olcr)
{
	peer->RemoveLogicalChannel(olcr.m_forwardLogicalChannelNumber);
	return false; // nothing changed :)
}

bool H245ProxyHandler::HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck & olca)
{
	WORD flcn = olca.m_forwardLogicalChannelNumber;
	LogicalChannel *lc = peer->FindLogicalChannel(flcn);
	if (!lc) {
		PTRACE(2, "Proxy\tWarning: logical channel " << flcn << " not found");
		if (!(lc = peer->CreateRTPLogicalChannel(flcn)))
			return false;
	}
	bool result = lc->SetDestination(olca, this);
	if (result)
		lc->StartReading(handler);
	return result;
}

bool H245ProxyHandler::HandleCloseLogicalChannel(H245_CloseLogicalChannel & clc) 
{
	if (clc.m_source.GetTag() == H245_CloseLogicalChannel_source::e_user)
		RemoveLogicalChannel(clc.m_forwardLogicalChannelNumber);
	else
		peer->RemoveLogicalChannel(clc.m_forwardLogicalChannelNumber);
	return false; // nothing changed :)
}       

LogicalChannel *H245ProxyHandler::FindLogicalChannel(WORD flcn)
{
	iterator Iter = logicalChannels.find(flcn);
	return (Iter != logicalChannels.end()) ? Iter->second : 0;
}

RTPLogicalChannel *H245ProxyHandler::CreateRTPLogicalChannel(WORD flcn)
{
	RTPLogicalChannel *lc = 0;
	try {
		lc = new RTPLogicalChannel(peer->GetLocalAddr(), flcn);
		logicalChannels[flcn] = lc;
	} catch (RTPLogicalChannel::NoPortAvailable) {
		PTRACE(2, "Proxy\tError: Can't create RTP logical channel " << flcn);
	}
	return lc;
}

void H245ProxyHandler::RemoveLogicalChannel(WORD flcn)
{
	iterator Iter = logicalChannels.find(flcn);
	if (Iter != logicalChannels.end()) {
		delete Iter->second;
		logicalChannels.erase(Iter);
#ifdef PTRACING
	} else {
		PTRACE(3, "Proxy\tLogical channel " << flcn << " not found");
#endif
	}
}

// to avoid ProxyThread.cxx to include the large h225.h,
// put the method here...
// class ProxyListener
TCPProxySocket *ProxyListener::CreateSocket()
{
	return new CallSignalSocket;
}

// class HandlerList
void HandlerList::LoadConfig()
{
	WORD port = GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_CALL_SIGNAL_PORT);
	if (!listenerThread || (GKPort != port)) {
		CloseListener();
		unsigned queueSize = GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH);
		listenerThread = new ProxyListener(this, GKHome, port, queueSize);
		GKPort = listenerThread->GetPort();
	}

	// the handler number can only be increased
	int s = GkConfig()->GetInteger(RoutedSec, "CallSignalHandlerNumber", 1);
	for (int i = handlers.size(); i < s; ++i)
		handlers.push_back(new ProxyHandleThread(i));
}

