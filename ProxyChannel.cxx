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

#include "gk_const.h"
#include "h323util.h"
#include "h323pdu.h"
#include "Toolkit.h"
#include "stl_supp.h"
#include "RasSrv.h"
#include "GkClient.h"
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
	void SetForwardDestination(Address, WORD, const H245_UnicastAddress_iPAddress &);
	void SetReverseDestination(Address, WORD, const H245_UnicastAddress_iPAddress &);
	typedef void (UDPProxySocket::*pMem)(Address, WORD, const H245_UnicastAddress_iPAddress &);

	bool Bind(WORD pt) { return Listen(0, pt); }

	// override from class ProxySocket
	virtual Result ReceiveData();

private:
	Address fSrcIP, fDestIP, rSrcIP, rDestIP;
	WORD fSrcPort, fDestPort, rSrcPort, rDestPort;
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
	LogicalChannel(WORD flcn = 0) : channelNumber(flcn), used(false) {}
	virtual ~LogicalChannel() {}

	bool IsUsed() const { return used; }
	bool Compare(WORD lcn) const { return channelNumber == lcn; }
	WORD GetPort() const { return port; }
	WORD GetChannelNumber() const { return channelNumber; }
	void SetChannelNumber(WORD cn) { channelNumber = cn; }

	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *) = 0;
	virtual void StartReading(ProxyHandleThread *) = 0;

protected:
	WORD channelNumber;
	WORD port;
	bool used;
};

class RTPLogicalChannel : public LogicalChannel {
public:
	RTPLogicalChannel(WORD);
	RTPLogicalChannel(RTPLogicalChannel *, WORD);
	virtual ~RTPLogicalChannel();

	void SetSource(const H245_UnicastAddress_iPAddress &);
	void HandleMediaChannel(H245_UnicastAddress_iPAddress *, H245_UnicastAddress_iPAddress *, PIPSocket::Address, bool);
	bool OnLogicalChannelParameters(H245_H2250LogicalChannelParameters &, PIPSocket::Address, bool);

	// override from class LogicalChannel
	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *);
	virtual void StartReading(ProxyHandleThread *);

	class NoPortAvailable {};

private:
	bool reversed;
	RTPLogicalChannel *peer;
	UDPProxySocket *rtp, *rtcp;
	PIPSocket::Address SrcIP;
	WORD SrcPort;

	static WORD GetPortNumber();
	static WORD portNumber;
	static PMutex mutex;
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

	static void delete_s(T120ProxySocket *s) { s->SetDeletable(); }

	std::list<T120ProxySocket *> sockets;
	T120Listener *listenThread;
	PTCPSocket listener;
	ProxyHandleThread *handler;
	PIPSocket::Address peerAddr;
	WORD peerPort;
};

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
		Address calling, called;
		int type = m_call->GetNATType(calling, called);
		if (type & CallRec::calledParty)
			socket->peerAddr = called;
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " has NAT type " << type);
		socket->m_h245handler = (type & CallRec::callingParty) ? new NATHandler(socket->localAddr, peerAddr) : new H245Handler(socket->localAddr);
		m_h245handler = (type & CallRec::calledParty) ? new NATHandler(localAddr, socket->peerAddr) : new H245Handler(localAddr);
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

namespace { // anonymous namespace
#if PTRACING
void PrintQ931(int tlevel, const PString & msg, const Q931 *q931, const H225_H323_UserInformation *uuie)
{
	PStringStream pstrm;
	pstrm << "Q931\t" << msg << " {\n  q931pdu = " << setprecision(2) << *q931;
	if (uuie)
		pstrm << "\n  h225pdu = " << setprecision(2) << *uuie;
	pstrm << "\n}";
	PTRACE(tlevel, pstrm);
}
#else
inline void PrintQ931(int, const PString &, const Q931 *, const H225_H323_UserInformation *)
{
	// nothing to do
}
#endif
} // end of anonymous namespace

ProxySocket::Result CallSignalSocket::ReceiveData()
{
	if (!ReadTPKT())
		return NoData;

	Q931 q931pdu;
	if (!q931pdu.Decode(buffer)) {
		PTRACE(4, "Q931\t" << Name() << " ERROR DECODING Q.931!");
		return Error;
	}
	m_receivedQ931 = &q931pdu;

	PTRACE(3, "Q931\t" << "Received: " << q931pdu.GetMessageTypeName() << " CRV=" << q931pdu.GetCallReference());

	H225_H323_UserInformation signal, *psignal = 0;
	if (q931pdu.HasIE(Q931::UserUserIE)) {
		PPER_Stream q = q931pdu.GetIE(Q931::UserUserIE);
		if (!signal.Decode(q)) {
			PTRACE(4, "Q931\t" << Name() << " ERROR DECODING UUIE!");
			return Error;
		}

		H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
		H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;

		m_h245Tunneling = (pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling) && pdu.m_h245Tunneling.GetValue());

		PrintQ931(6, "Received:", &q931pdu, psignal = &signal);

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
			PTRACE(5, "Q931\t" << Name() << " Rewriting nonStandardControl");
		}
		if (pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control) && m_h245handler)
			OnTunneledH245(pdu.m_h245Control);

		PBYTEArray wtbuf(4096);
		PPER_Stream wtstrm(wtbuf);
		signal.Encode(wtstrm);
		wtstrm.CompleteEncoding();
		q931pdu.SetIE(Q931::UserUserIE, wtstrm);
	} else { // not have UUIE
		PrintQ931(6, "Received:", &q931pdu, 0);
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

	q931pdu.Encode(buffer);

#if PTRACING
	if (remote)
		PrintQ931(5, "Send to " + remote->Name(), &q931pdu, psignal);
#endif

	switch (q931pdu.GetMessageType())
	{
		case Q931::SetupMsg:
			break;
		/* why don't forward Status? - by cwhuang 16.04.2002
		case Q931::StatusMsg:
			// don't forward status messages mm-30.04.2001
			return NoData;
		*/
		case Q931::ReleaseCompleteMsg:
			if (m_call)
				CallTable::Instance()->RemoveCall(m_call);
			return Closing;
		default:
			return Forwarding;
	}
	
	if (!m_call) {
		EndSession();
		SetDeletable();
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
	if (m_call) {
		uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_callIdentifier);
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	}
	PPER_Stream strm;
	signal.Encode(strm);
	strm.CompleteEncoding();

	ReleasePDU.BuildReleaseComplete(m_crv, m_crv & 0x8000u);
	ReleasePDU.SetIE(Q931::UserUserIE, strm);
}

bool CallSignalSocket::EndSession()
{
	if (IsOpen()) {
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
		PTRACE(3, "Q931(" << getpid() << ") Connect to " << remote->Name() << " successful");
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
	if (!Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		unsigned plan, type;
		PString destination;
		if (GetReceivedQ931()->GetCalledPartyNumber(destination, &plan, &type)) {
			// Setup_UUIE doesn't contain any destination information, but Q.931 has CalledPartyNumber
			// We create the destinationAddress according to it
			Setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			Setup.m_destinationAddress.SetSize(1);
			H323SetAliasAddress(destination, Setup.m_destinationAddress[0]);
		}
	}
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
		for (PINDEX n = 0; n < Setup.m_destinationAddress.GetSize(); ++n)
			Toolkit::Instance()->RewriteE164(Setup.m_destinationAddress[n]);

	PString callid;
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
		m_call = CallTable::Instance()->FindCallRec(Setup.m_callIdentifier);
#ifdef PTRACING
		callid = AsString(Setup.m_callIdentifier.m_guid);
#endif
	} else { // try CallReferenceValue
		PTRACE(3, "Q931\tSetup_UUIE doesn't contain CallIdentifier!");
		H225_CallIdentifier callIdentifier; // empty callIdentifier
		H225_CallReferenceValue crv;
		crv.SetValue(m_crv & 0x7fffu);
		m_call = CallTable::Instance()->FindCallRec(crv);
		callid = AsString(callIdentifier.m_guid);
	}
	GkClient *gkClient = RasThread->GetGkClient();
	if (m_call) {
		if (m_call->IsRegistered())
			gkClient->RewriteE164(*GetReceivedQ931(), Setup, true);
	} else {
		bool fromParent;
		Address fromIP;
		GetPeerAddress(fromIP);
		if (!RasThread->AcceptUnregisteredCalls(fromIP, fromParent)) {
			PTRACE(3, "Q931\tNo CallRec found in CallTable for callid " << callid);
			return;
		}
		if (fromParent)
			gkClient->RewriteE164(*GetReceivedQ931(), Setup, false);

		endptr called;
		PString destinationString;

		if (Setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
			called = RegistrationTable::Instance()->FindBySignalAdr(Setup.m_destCallSignalAddress);
			destinationString = AsDotString(Setup.m_destCallSignalAddress);
		}
		if (!called && Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
			called = RegistrationTable::Instance()->FindEndpoint(Setup.m_destinationAddress);
			destinationString = AsString(Setup.m_destinationAddress);
		}

		if (!called) {
			PTRACE(3, "Q931\tDestination not found for the unregistered call " << callid);
			return;
		}

		// TODO: check the Setup_UUIE by gkauth modules

		PString sourceString(Setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress) ? AsString(Setup.m_sourceAddress) : PString());
		CallRec *call = new CallRec(Setup.m_callIdentifier, Setup.m_conferenceID, destinationString, sourceString, 0, RasThread->IsGKRoutedH245());
		call->SetCalled(called, m_crv);

		CallTable::Instance()->Insert(call);
		m_call = callptr(call);
		if (fromParent) {
			call->SetRegistered(true);
			gkClient->SendARQ(Setup, m_crv, m_call);
		}
	}

	const H225_TransportAddress *addr = m_call->GetCalledAddress();
	if (!addr || addr->GetTag() != H225_TransportAddress::e_ipAddress) {
		CallTable::Instance()->RemoveCall(m_call);
		m_call = callptr(0);
		PTRACE(3, "Q931\t" << Name() << " INVALID ADDRESS");
		return;
	}

	const H225_TransportAddress_ipAddress & ip = *addr;
	peerAddr = PIPSocket::Address(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
	peerPort = ip.m_port;
	Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
	Setup.m_sourceCallSignalAddress = RasThread->GetCallSignalAddress(peerAddr);
	H225_TransportAddress_ipAddress & cip = Setup.m_sourceCallSignalAddress;
	localAddr = PIPSocket::Address(cip.m_ip[0], cip.m_ip[1], cip.m_ip[2], cip.m_ip[3]);
	remote = new CallSignalSocket(this, peerPort);

	// in routed mode the caller may have put the GK address in destCallSignalAddress
	// since it is optional, we just remove it (we could alternativly insert the real destination SignalAdr)
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress))
		Setup.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);

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
	HandleFastStart(Setup, true);
}
 
void CallSignalSocket::OnCallProceeding(H225_CallProceeding_UUIE & CallProceeding)
{
	HandleH245Address(CallProceeding);
	HandleFastStart(CallProceeding, false);
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
	HandleFastStart(Connect, false);
}

void CallSignalSocket::OnAlerting(H225_Alerting_UUIE & Alerting)
{
	HandleH245Address(Alerting);
	HandleFastStart(Alerting, false);
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
	HandleFastStart(Facility, false);
}

void CallSignalSocket::OnProgress(H225_Progress_UUIE & Progress)
{
	HandleH245Address(Progress);
	HandleFastStart(Progress, false);
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

void CallSignalSocket::OnFastStart(H225_ArrayOf_PASN_OctetString & fastStart, bool fromCaller)
{
	PINDEX sz = fastStart.GetSize();
	for(PINDEX i = 0; i < sz; ++i) {
//	for(PINDEX i = sz; i-- > 0; ) {
		PPER_Stream strm = fastStart[i].GetValue();
		H245_OpenLogicalChannel olc;
		if (!olc.Decode(strm)) {
			PTRACE(4, "Q931\t" << Name() << " ERROR DECODING FAST START ELEMENT " << i);
			return;
		}
		PTRACE(6, "Q931\nfastStart[" << i << "] received: " << setprecision(2) << olc);
		H245Handler::pMem handlefs = (fromCaller) ? &H245Handler::HandleFastStartSetup : &H245Handler::HandleFastStartResponse;
		if ((m_h245handler->*handlefs)(olc)) {
			PBYTEArray wtbuf(4096);
			PPER_Stream wtstrm(wtbuf);
			olc.Encode(wtstrm);
			wtstrm.CompleteEncoding();
			fastStart[i].SetValue(wtstrm);
		}
		PTRACE(5, "Q931\nfastStart[" << i << "] to send " << setprecision(2) << olc);
	}
}

bool CallSignalSocket::SetH245Address(H225_TransportAddress & h245addr)
{
	if (m_h245Tunneling && Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveH245AddressOnTunneling", "0")))
		return false;
	CallSignalSocket *ret = dynamic_cast<CallSignalSocket *>(remote);
	if (!ret) {
		PTRACE(2, "H245\t" << Name() << " no remote party?");
		return false;
	}
	m_h245handler->OnH245Address(h245addr);
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
	if (!h245msg.Decode(mesg)) {
		PTRACE(4, "H245\tERROR DECODING H.245");
		return false;
	}
	PTRACE(6, "H245\tReceived: " << setprecision(2) << h245msg);

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
		PBYTEArray wtbuf(4096);
		PPER_Stream wtstrm(wtbuf);
		h245msg.Encode(wtstrm);
		wtstrm.CompleteEncoding();
		mesg = wtstrm;
	}

	PTRACE(5, "H245\tTo send: " << setprecision(2) << h245msg);
	return changed;
}

bool H245Handler::HandleFastStartSetup(H245_OpenLogicalChannel &)
{
	return false;
}

bool H245Handler::HandleFastStartResponse(H245_OpenLogicalChannel &)
{
	return false;
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

H245_H2250LogicalChannelParameters *GetLogicalChannelParameters(H245_OpenLogicalChannel & olc, bool & isReverseLC)
{
	if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)) {
		if (!olc.m_reverseLogicalChannelParameters.HasOptionalField(H245_OpenLogicalChannel_reverseLogicalChannelParameters::e_multiplexParameters))
			return 0;
		H245_OpenLogicalChannel_reverseLogicalChannelParameters_multiplexParameters & params = olc.m_reverseLogicalChannelParameters.m_multiplexParameters;
		isReverseLC = true;
		return (params.GetTag() == H245_OpenLogicalChannel_reverseLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters) ?  &((H245_H2250LogicalChannelParameters &)params) : 0;
	} else {
		H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters & params = olc.m_forwardLogicalChannelParameters.m_multiplexParameters;
		isReverseLC = false;
		return (params.GetTag() == H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters) ?  &((H245_H2250LogicalChannelParameters &)params) : 0;
	}
}

bool GetChannelsFromOLCA(H245_OpenLogicalChannelAck & olca, H245_UnicastAddress_iPAddress * & mediaControlChannel, H245_UnicastAddress_iPAddress * & mediaChannel)
{
	if (!olca.HasOptionalField(H245_OpenLogicalChannelAck::e_forwardMultiplexAckParameters))
		return false;
	H245_OpenLogicalChannelAck_forwardMultiplexAckParameters & ackparams = olca.m_forwardMultiplexAckParameters;
	if (ackparams.GetTag() != H245_OpenLogicalChannelAck_forwardMultiplexAckParameters::e_h2250LogicalChannelAckParameters)
		return false;
	H245_H2250LogicalChannelAckParameters & h225Params = ackparams;
	if (!h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaControlChannel))
		return false;
	mediaControlChannel = GetH245UnicastAddress(h225Params.m_mediaControlChannel);
	if (!mediaControlChannel)
		return false;
	mediaChannel = h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaChannel) ? GetH245UnicastAddress(h225Params.m_mediaChannel) : 0;
	return true;
}

inline H245_UnicastAddress_iPAddress & operator<<(H245_UnicastAddress_iPAddress & addr, PIPSocket::Address ip)
{
	for (int i = 0; i < 4; ++i)
		addr.m_network[i] = ip[i];
	return addr;
}

inline H245_UnicastAddress_iPAddress & operator<<(H245_UnicastAddress_iPAddress & addr, WORD port)
{
	addr.m_tsapIdentifier = port;
	return addr;
}

inline const H245_UnicastAddress_iPAddress & operator>>(const H245_UnicastAddress_iPAddress & addr, PIPSocket::Address & ip)
{
	ip = PIPSocket::Address(addr.m_network[0], addr.m_network[1], addr.m_network[2], addr.m_network[3]);
	return addr;
}

inline const H245_UnicastAddress_iPAddress & operator>>(const H245_UnicastAddress_iPAddress & addr, WORD & port)
{
	port = addr.m_tsapIdentifier;
	return addr;
}

inline void delete_lc(std::pair<const WORD, LogicalChannel *> & p)
{
	delete p.second;
}

inline void delete_rtplc(std::pair<const WORD, RTPLogicalChannel *> & p)
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

void UDPProxySocket::SetForwardDestination(Address srcIP, WORD srcPort, const H245_UnicastAddress_iPAddress & addr)
{
	fSrcIP = srcIP, fSrcPort = srcPort;
	addr >> fDestIP >> fDestPort;

	SetName(srcIP, srcPort);
	PTRACE(5, "UDP\tForward " << name << " to " << fDestIP << ':' << fDestPort);
	SetConnected(true);
}

void UDPProxySocket::SetReverseDestination(Address srcIP, WORD srcPort, const H245_UnicastAddress_iPAddress & addr)
{
	rSrcIP = srcIP, rSrcPort = srcPort;
	addr >> rDestIP >> rDestPort;

	PTRACE(5, "UDP\tReverse " << srcIP << ':' << srcPort << " to " << rDestIP << ':' << rDestPort);
	SetConnected(true);
}

ProxySocket::Result UDPProxySocket::ReceiveData()
{
	Address fromIP;
	WORD fromPort;
	if (!ReadFrom(wbuffer, maxbufsize, fromIP, fromPort)) {
		ErrorHandler(this, LastReadError);
		return NoData;
	}
	PTRACE(6, type << "\tReading from " << fromIP << ':' << fromPort);
	buflen = GetLastReadCount();

//	if (fromIP == rSrcIP && (fromPort == rSrcPort || abs(fromPort - rSrcPort) == 2))
	// Workaround: some bad endpoints don't send packets from the specified port
	if (fromIP == rSrcIP && (fromIP != fSrcIP || fromPort == rSrcPort))
	//	PTRACE(5, "UDP\tfrom " << fromIP << ':' << fromPort << " to " << rDestIP << ':' << rDestPort),
		SetSendAddress(rDestIP, rDestPort);
	else
	//	PTRACE(5, "UDP\tfrom " << fromIP << ':' << fromPort << " to " << fDestIP << ':' << fDestPort),
		SetSendAddress(fDestIP, fDestPort);
	return Forwarding;
}

// class T120ProxySocket
T120ProxySocket::T120ProxySocket(T120ProxySocket *socket, WORD pt)
      : TCPProxySocket("T120", socket, pt)
{
	SetMinBufSize(BufferSize);
}

TCPProxySocket *T120ProxySocket::ConnectTo()
{
	remote = new T120ProxySocket(this, peerPort);
	if (remote->Connect(peerAddr)) {
		PTRACE(3, "T120\tConnect to " << remote->Name() << " successful");
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

RTPLogicalChannel::RTPLogicalChannel(WORD flcn) : LogicalChannel(flcn), reversed(false), peer(0)
{
	rtp = new UDPProxySocket("RTP");
	rtcp = new UDPProxySocket("RTCP");

	// try to get an available port 10 times
	for (int i = 0; i < 10; ++i) {
		port = GetPortNumber();
		// try to bind rtp to an even port and rtcp to the next one port
		if (rtp->Bind(port) && rtcp->Bind(port + 1))
			return;

		PTRACE(3, "RTP\tPort " << port << " not available");
		rtp->Close(), rtcp->Close();
		// try next...
	}
	delete rtp;
	delete rtcp;
	// Oops...
	throw NoPortAvailable();
}

RTPLogicalChannel::RTPLogicalChannel(RTPLogicalChannel *flc, WORD flcn)
{
	memcpy(this, flc, sizeof(RTPLogicalChannel)); // bitwise copy :)
	reversed = !flc->reversed;
	peer = flc, flc->peer = this;
	SetChannelNumber(flcn);
}

RTPLogicalChannel::~RTPLogicalChannel()
{
	if (peer) {
		peer->peer = 0;
	} else {
		if (used) {
			// the sockets will be deleted by ProxyHandler,
			// so we don't need to delete it here
			rtp->EndSession();
			rtp->SetDeletable();
			rtcp->EndSession();
			rtcp->SetDeletable();
		} else {
			delete rtp;
			delete rtcp;
		}
	}
	PTRACE(4, "RTP\tDelete logical channel " << channelNumber);
}

void RTPLogicalChannel::SetSource(const H245_UnicastAddress_iPAddress & addr)
{
	addr >> SrcIP >> SrcPort;
	--SrcPort; // get the RTP port
}

void RTPLogicalChannel::HandleMediaChannel(H245_UnicastAddress_iPAddress *mediaControlChannel, H245_UnicastAddress_iPAddress *mediaChannel, PIPSocket::Address local, bool rev)
{
	// mediaControlChannel should be non-zero.
	H245_UnicastAddress_iPAddress tmp, tmpmedia, *dest = mediaControlChannel;
	PIPSocket::Address tmpSrcIP = SrcIP;
	WORD tmpSrcPort = SrcPort + 1;
	if (rev) { // from a reverseLogicalChannelParameters
		tmp << tmpSrcIP << tmpSrcPort;
		dest = &tmp;
		*mediaControlChannel >> tmpSrcIP >> tmpSrcPort;
		if (!mediaChannel) {
			tmpmedia = *mediaControlChannel;
			tmpmedia.m_tsapIdentifier = tmpmedia.m_tsapIdentifier - 1;
			mediaChannel = &tmpmedia;
		}
	}
	UDPProxySocket::pMem SetDest = (reversed) ? &UDPProxySocket::SetReverseDestination : &UDPProxySocket::SetForwardDestination;
	(rtcp->*SetDest)(tmpSrcIP, tmpSrcPort, *dest);
	*mediaControlChannel << local << (port + 1);

	if (mediaChannel) {
		if (rev)
			tmp.m_tsapIdentifier = tmp.m_tsapIdentifier - 1;
		else
			dest = mediaChannel;
		(rtp->*SetDest)(tmpSrcIP, tmpSrcPort - 1, *dest);
		*mediaChannel << local << port;
	}
}

bool RTPLogicalChannel::OnLogicalChannelParameters(H245_H2250LogicalChannelParameters & h225Params, PIPSocket::Address local, bool rev)
{
	if (!h225Params.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel))
		return false;
	H245_UnicastAddress_iPAddress *mediaControlChannel = GetH245UnicastAddress(h225Params.m_mediaControlChannel);
	H245_UnicastAddress_iPAddress *mediaChannel = h225Params.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel) ? GetH245UnicastAddress(h225Params.m_mediaChannel) : 0;
	HandleMediaChannel(mediaControlChannel, mediaChannel, local, rev);
	return true;
}

bool RTPLogicalChannel::SetDestination(H245_OpenLogicalChannelAck & olca, H245Handler *handler)
{
	H245_UnicastAddress_iPAddress *mediaControlChannel, *mediaChannel;
	if (GetChannelsFromOLCA(olca, mediaControlChannel, mediaChannel)) {
		HandleMediaChannel(mediaControlChannel, mediaChannel, handler->GetLocalAddr(), false);
		return true;
	}
	return false;
}

void RTPLogicalChannel::StartReading(ProxyHandleThread *handler)
{
	if (!used) {
		handler->InsertLC(rtp);
		handler->InsertLC(rtcp);
		used = true;
		if (peer)
			peer->used = true;
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
T120LogicalChannel::T120LogicalChannel(WORD flcn) : LogicalChannel(flcn)
{
	listener.Listen(1);
	port = listener.GetPort();
	PTRACE(4, "T120\tOpen logical channel " << flcn << " port " << port);
}

T120LogicalChannel::~T120LogicalChannel()
{
	if (used) {
		listener.Close();
		listenThread->Destroy();
		for_each(sockets.begin(), sockets.end(), delete_s);
	}
	PTRACE(4, "T120\tDelete logical channel " << channelNumber);
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
			handler->InsertLC(socket);
			handler->InsertLC(remote);
			sockets.push_back(socket);
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
			*addr >> peerAddr >> peerPort;
			*addr << handler->GetLocalAddr() << port;
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
	for_each(fastStartLCs.begin(), fastStartLCs.end(), delete_rtplc);
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

bool H245ProxyHandler::OnLogicalChannelParameters(H245_H2250LogicalChannelParameters *h225Params, WORD flcn)
{
	if (!h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel))
		return false;
	H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(h225Params->m_mediaControlChannel);
	if (!addr)
		return false;
	RTPLogicalChannel *lc = (flcn) ?
		CreateRTPLogicalChannel(h225Params->m_sessionID, flcn) :
		CreateFastStartLogicalChannel(h225Params->m_sessionID);
	if (!lc)
		return false;
	lc->SetSource(*addr);
	*addr << GetLocalAddr() << (lc->GetPort() + 1);
	if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)) {
		H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(h225Params->m_mediaChannel);
		if (addr)
			*addr << GetLocalAddr() << lc->GetPort();
	}
	return true;
}

bool H245ProxyHandler::HandleOpenLogicalChannel(H245_OpenLogicalChannel & olc)
{
	WORD flcn = olc.m_forwardLogicalChannelNumber;
	if (IsT120Channel(olc)) {
		T120LogicalChannel *lc = CreateT120LogicalChannel(flcn);
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_separateStack)
			&& lc && lc->OnSeparateStack(olc.m_separateStack, this)) {
			lc->StartReading(handler);
			return true;
		}
		return false;
	} else {
		bool nouse;
		H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse);
		return (h225Params) ? OnLogicalChannelParameters(h225Params, flcn) : false;
	}
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

bool H245ProxyHandler::HandleFastStartSetup(H245_OpenLogicalChannel & olc)
{
	bool nouse;
	H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse);
	return (h225Params) ? OnLogicalChannelParameters(h225Params, 0) : false;
}

bool H245ProxyHandler::HandleFastStartResponse(H245_OpenLogicalChannel & olc)
{
	WORD flcn = olc.m_forwardLogicalChannelNumber;
	bool changed = false, isReverseLC;
	H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, isReverseLC);
	if (!h225Params)
		return false;
	WORD id = h225Params->m_sessionID;
	siterator iter = peer->fastStartLCs.find(id);
	RTPLogicalChannel *lc = (iter != peer->fastStartLCs.end()) ? iter->second : 0;
	if (isReverseLC) {
		if (lc) {
			if (!FindLogicalChannel(flcn)) {
				logicalChannels[flcn] = sessionIDs[id] = lc;
				lc->SetChannelNumber(flcn);
				peer->fastStartLCs.erase(iter);
			}
		} else if ((lc = peer->FindRTPLogicalChannelBySessionID(id))) {
			LogicalChannel *akalc = FindLogicalChannel(flcn);
			if (akalc)
				lc = dynamic_cast<RTPLogicalChannel *>(akalc);
			else
				logicalChannels[flcn] = sessionIDs[id] = lc = new RTPLogicalChannel(lc, flcn);
		}
	} else {
		if (lc) {
			if (!peer->FindLogicalChannel(flcn)) {
				peer->logicalChannels[flcn] = peer->sessionIDs[id] = lc;
				lc->SetChannelNumber(flcn);
				peer->fastStartLCs.erase(iter);
			}
		} else if ((lc = FindRTPLogicalChannelBySessionID(id))) {
			LogicalChannel *akalc = peer->FindLogicalChannel(flcn);
			if (akalc)
				lc = dynamic_cast<RTPLogicalChannel *>(akalc);
			else
				peer->logicalChannels[flcn] = peer->sessionIDs[id] = lc = new RTPLogicalChannel(lc, flcn);
		}
	}
	if (lc && (changed = lc->OnLogicalChannelParameters(*h225Params, GetLocalAddr(), isReverseLC)))
		lc->StartReading(handler);
	return changed;
}

LogicalChannel *H245ProxyHandler::FindLogicalChannel(WORD flcn)
{
	iterator iter = logicalChannels.find(flcn);
	return (iter != logicalChannels.end()) ? iter->second : 0;
}

RTPLogicalChannel *H245ProxyHandler::FindRTPLogicalChannelBySessionID(WORD id)
{
	siterator iter = sessionIDs.find(id);
	return (iter != sessionIDs.end()) ? iter->second : 0;
}

RTPLogicalChannel *H245ProxyHandler::CreateRTPLogicalChannel(WORD id, WORD flcn)
{
	if (FindLogicalChannel(flcn)) {
		PTRACE(3, "Proxy\tRTP logical channel " << flcn << " already exist?");
		return 0;
	}
	RTPLogicalChannel *lc;
	// if H.245 OpenLogicalChannel is received, the fast connect procedure
	// should be disable. So we reuse the fast start logical channel here
	if (!fastStartLCs.empty()) {
		siterator iter = fastStartLCs.begin();
		(lc = iter->second)->SetChannelNumber(flcn);
		fastStartLCs.erase(iter);
	} else if (!peer->fastStartLCs.empty()){
		siterator iter = peer->fastStartLCs.begin();
		(lc = iter->second)->SetChannelNumber(flcn);
		peer->fastStartLCs.erase(iter);
	} else if ((lc = peer->FindRTPLogicalChannelBySessionID(id))) {
		lc = new RTPLogicalChannel(lc, flcn);
	} else {
		try {
			lc = new RTPLogicalChannel(flcn);
		} catch (RTPLogicalChannel::NoPortAvailable) {
			PTRACE(2, "Proxy\tError: Can't create RTP logical channel " << flcn);
			return 0;
		}
	}

	logicalChannels[flcn] = sessionIDs[id] = lc;
	PTRACE(4, "RTP\tOpen logical channel " << flcn << " port " << lc->GetPort());
	return lc;
}

RTPLogicalChannel *H245ProxyHandler::CreateFastStartLogicalChannel(WORD id)
{
	siterator iter = fastStartLCs.find(id);
	RTPLogicalChannel *lc = (iter != fastStartLCs.end()) ? iter->second : 0;
	if (!lc) {
		try {
			// the LogicalChannelNumber of a fastStart logical channel is irrelevant
			// it may be set later
			lc = new RTPLogicalChannel(0);
		} catch (RTPLogicalChannel::NoPortAvailable) {
			PTRACE(2, "Proxy\tError: Can't create fast start logical channel id " << id);
			return 0;
		}
		fastStartLCs[id] = lc;
		PTRACE(4, "RTP\tOpen fast start logical channel id " << id << " port " << lc->GetPort());
	}
	return lc;
}

T120LogicalChannel *H245ProxyHandler::CreateT120LogicalChannel(WORD flcn)
{
	if (FindLogicalChannel(flcn)) {
		PTRACE(3, "Proxy\tT120 logical channel " << flcn << " already exist?");
		return 0;
	}
	T120LogicalChannel *lc = new T120LogicalChannel(flcn);
	logicalChannels[flcn] = lc;
	return lc;
}

void H245ProxyHandler::RemoveLogicalChannel(WORD flcn)
{
	iterator iter = logicalChannels.find(flcn);
	if (iter != logicalChannels.end()) {
		delete iter->second;
		logicalChannels.erase(iter);
#ifdef PTRACING
	} else {
		PTRACE(3, "Proxy\tLogical channel " << flcn << " not found");
#endif
	}
}

// class NATHandler
NATHandler::NATHandler(PIPSocket::Address local, PIPSocket::Address remote)
      : H245Handler(local), remoteAddr(remote)
{
}

void NATHandler::OnH245Address(H225_TransportAddress & h245addr)
{
	if (h245addr.GetTag() == H225_TransportAddress::e_ipAddress) {
		H225_TransportAddress_ipAddress & addr = h245addr;
		h245addr = SocketToH225TransportAddr(remoteAddr, addr.m_port);
	}
}

bool NATHandler::HandleFastStartSetup(H245_OpenLogicalChannel & olc)
{
	return HandleOpenLogicalChannel(olc);
}

bool NATHandler::HandleFastStartResponse(H245_OpenLogicalChannel & olc)
{
	return HandleOpenLogicalChannel(olc);
}

bool NATHandler::HandleRequest(H245_RequestMessage & Request)
{
	PTRACE(4, "H245\tRequest: " << Request.GetTagName());
	if (Request.GetTag() == H245_RequestMessage::e_openLogicalChannel)
		return HandleOpenLogicalChannel(Request);
	else
		return false;
}

bool NATHandler::HandleResponse(H245_ResponseMessage & Response)
{
	PTRACE(4, "H245\tResponse: " << Response.GetTagName());
	if (Response.GetTag() == H245_ResponseMessage::e_openLogicalChannelAck)
		return HandleOpenLogicalChannelAck(Response);
	else
		return false;
}

bool NATHandler::HandleOpenLogicalChannel(H245_OpenLogicalChannel & olc)
{
	bool changed = false;
	if (IsT120Channel(olc) && olc.HasOptionalField(H245_OpenLogicalChannel::e_separateStack)) {
		if (olc.m_separateStack.m_networkAddress.GetTag() == H245_NetworkAccessParameters_networkAddress::e_localAreaAddress) {
			H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(olc.m_separateStack.m_networkAddress);
			if (addr) {
				*addr << remoteAddr << addr->m_tsapIdentifier;
				changed = true;
			}
		}
	} else {
		bool nouse;
		if (H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse)) {
			if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel)) {
				H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(h225Params->m_mediaControlChannel);
				if (addr) {
					*addr << remoteAddr << addr->m_tsapIdentifier;
					changed = true;
				}
			}
			if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)) {
				H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(h225Params->m_mediaChannel);
				if (addr) {
					*addr << remoteAddr << addr->m_tsapIdentifier;
					changed = true;
				}
			}
		}
	}
	return changed;
}

bool NATHandler::HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck & olca)
{
	H245_UnicastAddress_iPAddress *mediaControlChannel, *mediaChannel;
	if (GetChannelsFromOLCA(olca, mediaControlChannel, mediaChannel)) {
		*mediaControlChannel << remoteAddr << mediaControlChannel->m_tsapIdentifier;
		if (mediaChannel)
			*mediaChannel << remoteAddr << mediaChannel->m_tsapIdentifier;
		return true;
	}
	return false;
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
		GKPort = port;
	}

	// the handler number can only be increased
	int s = GkConfig()->GetInteger(RoutedSec, "CallSignalHandlerNumber", 1);
	for (int i = handlers.size(); i < s; ++i)
		handlers.push_back(new ProxyHandleThread(i));
}

