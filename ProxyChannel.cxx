// -*- mode: c++; eval: (c-set-style "linux"); -*-
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
#include "h323pdu.h"
#include "Toolkit.h"
#include "stl_supp.h"
#include "RasSrv.h"
#include "GkClient.h"
#include "ProxyChannel.h"
#include <q931.h>
#include <h245.h>
#include "RasTbl.h"
#include "gkDestAnalysis.h"
#include "gkldap.h"
#include "gkDatabase.h"

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

TCPProxySocket *ProxyListener::CreateSocket()
{
	return new CallSignalSocket();
}

class NATHandler {
public:
	NATHandler(PIPSocket::Address remote) : remoteAddr(remote) {}

	void TranslateH245Address(H225_TransportAddress &);
	bool HandleOpenLogicalChannel(H245_OpenLogicalChannel &);
	bool HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck &);

private:
	PIPSocket::Address remoteAddr;
};


endptr CallSignalSocket::GetCgEP(Q931 &q931pdu)
{
//	PTRACE(1, "CallSignalSocket::GetCgEP start");
	PString CallingPN;
	H225_AliasAddress CallingEPA;
	H225_ArrayOf_AliasAddress ACallingPN;
	if(q931pdu.GetCallingPartyNumber(CallingPN)) {
		H323SetAliasAddress(CallingPN,CallingEPA);
//		PTRACE(1, "CallSignalSocket::GetCgEP CallingPN:" << CallingPN);
 		ACallingPN.SetSize(1);
		ACallingPN[0]=CallingEPA;
//		PTRACE(1, "CallSignalSocket::GetCgEP CallingEP: " << RegistrationTable::Instance()->FindByAliases(ACallingPN));
		if (RegistrationTable::Instance()->FindByAliases(ACallingPN)!=endptr(NULL))
			return RegistrationTable::Instance()->FindByAliases(ACallingPN);
	}
	if (q931pdu.HasIE(Q931::UserUserIE)) {
		H225_H323_UserInformation signal;
		PPER_Stream q = q931pdu.GetIE(Q931::UserUserIE);
		if (!signal.Decode(q)) {
			PTRACE(4, "Q931\t" << Name() << " ERROR DECODING UUIE!");
			return endptr(0); // Urgs...
		}
		H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
		H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;
		H225_Setup_UUIE & Setup = body;
		if (!Setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
			PTRACE(1, "Q931\tOnSetup() no callIdentifier!");
			return endptr(0);
		}
		callptr m_call = CallTable::Instance()->FindCallRec(Setup.m_callIdentifier);
		if (m_call)
			return RegistrationTable::Instance()->FindBySignalAdr(*(m_call->GetCallingAddress()));
	}
	PTRACE(1, "Something nasty happened");
	return endptr(0);
}

CallSignalSocket::CallSignalSocket()
	: TCPProxySocket("Q931s"), m_h245handler(0), m_h245socket(0)
{
	localAddr = peerAddr = INADDR_ANY;
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

CallSignalSocket::CallSignalSocket(CallSignalSocket *socket, WORD peerPort)
	: TCPProxySocket("Q931d", socket, peerPort), m_h245handler(0), m_h245socket(0), isRoutable(FALSE)
{
	m_call = socket->m_call;
	m_call->SetSocket(socket, this);
	m_crv = (socket->m_crv & 0x7fffu);
	socket->GetLocalAddress(localAddr);
	socket->GetPeerAddress(peerAddr, peerPort);
	SetHandler(socket->GetHandler());

	Address calling = INADDR_ANY, called = INADDR_ANY;
	int type = m_call->GetNATType(calling, called);
	PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " has NAT type " << type);
	if (type & CallRec::calledParty)
		socket->peerAddr = called;

	// enable proxy if required, no matter whether H.245 routed
	if (Toolkit::Instance()->ProxyRequired(peerAddr, socket->peerAddr)) {
		H245ProxyHandler *proxyhandler = new H245ProxyHandler(socket, socket->localAddr, calling);
		socket->m_h245handler = proxyhandler;
		m_h245handler = new H245ProxyHandler(this, localAddr, called, proxyhandler);
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled");
	} else if (m_call->IsH245Routed()) {
		socket->m_h245handler = new H245Handler(socket->localAddr, calling);
		m_h245handler = new H245Handler(localAddr, called);
	}
	m_SetupPDU = new Q931(*(socket->m_SetupPDU));
	for(PINDEX i=0; socket->Q931InformationMessages.GetSize(); i++)
		Q931InformationMessages.Append(socket->Q931InformationMessages[i]);
}

namespace { // end of anonymous namespace
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
inline void PrintQ931(int, const PString &, const Q931 *, const H225_H323_UserI
nformation *)
{
	// Nothing to do
}
#endif
} // end of anonymous namespace

void CallSignalSocket::DoRoutingDecision() {
	endptr CalledEP(NULL);
	H225_AliasAddress h225address;
	endptr CallingEP = m_call->GetCallingEP();

	unsigned rsn;
	isRoutable=FALSE;
	H323SetAliasAddress(DialedDigits,h225address);

	CalledEP = RegistrationTable::Instance()->getMsgDestination(h225address, CallingEP, rsn);
	if(H225_AdmissionRejectReason::e_incompleteAddress == rsn) {
		PTRACE(5, "DoRoutingDecision() incomplete");
		return;
	}
	if(CalledEP) {
		PTRACE(5, "DoRoutingDecision() complete");
		isRoutable=TRUE;
		// Do CgPNConversion. We need the setup pdu and the setup UUIE (stored in m_SetupPDU)
		Q931 setup = *(GetSetupPDU());
		H225_H323_UserInformation signal;
		PPER_Stream q = setup.GetIE(Q931::UserUserIE);
		if (signal.Decode(q)) {
			H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
			H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;
			H225_Setup_UUIE & setup_UUIE = body;
			CgPNConversion(setup, setup_UUIE);
		} else {
			PTRACE(4, "Q931\t" << Name() << " ERROR DECODING UUIE!");
		}
		const H225_TransportAddress &ad  = CalledEP->GetCallSignalAddress();
		if (ad.GetTag() == H225_TransportAddress::e_ipAddress) { // IP Address known?
			const H225_TransportAddress_ipAddress & ip = ad;
			peerAddr = PIPSocket::Address(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
			peerPort = ip.m_port;
			localAddr = Toolkit::Instance()->GetRouteTable()->GetLocalAddress(peerAddr);
			//SetPort(peerPort);
			BuildConnection();
		}
		return;
	}
	if (H225_AdmissionRejectReason::e_incompleteAddress != rsn) {
		PTRACE(1, "DoRoutingDecision() Error");
		if(remote) {
			remote->SetDeletable();
			remote->CloseSocket();
		}
		SetDeletable();
		CloseSocket();

		// Disconnect
	}
}

void CallSignalSocket::SendInformationMessages() {
	GetSetupPDU()->Encode(buffer);
	if(!ForwardData())
		return;
	PTRACE(5,"fake setup sent" << *GetSetupPDU());
	buffer.SetSize(0); // empty Buffer
	PINDEX end=Q931InformationMessages.GetSize();
	for(PINDEX i=0; i<end; i++) {
		Q931InformationMessages[i]->Encode(buffer);
		if(!ForwardData())
			return;
		PTRACE(5, "Sent: " << *(Q931InformationMessages[i]));
		delete Q931InformationMessages[i];
		Q931InformationMessages[i]=NULL;
	}
	Q931InformationMessages.SetSize(0);
}

void CallSignalSocket::BuildConnection() {
	unsigned plan,type;
	Q931 * pdu=GetSetupPDU();// Q931InformationMessages[0];
	PString calledDigit;
	pdu->GetCalledPartyNumber(calledDigit, &plan, &type);
	pdu->SetCalledPartyNumber(DialedDigits,plan,type);
	m_SetupPDU=pdu;
	//Q931InformationMessages.RemoveAt(0); // delete first element (is now used)
//	delete pdu;
	// Cannot determin the CallingAddress from a CallRec
	remote=new CallSignalSocket(this, peerPort);
	ConnectTo();
//	SendInformationMessages();
}

TCPProxySocket *CallSignalSocket::ConnectTo()
{
	if (peerAddr == Address("0.0.0.0")) {
		if (remote)
			remote->SetConnected(false);
		SetConnected(true);
		Q931 & pdu = *(GetSetupPDU());
		FakeSetupACK(pdu);
		MarkBlocked(false);
		return NULL;
	}
	if (remote->Connect(peerAddr)) {
#ifdef WIN32
		PTRACE(3, "Q931(" << GetCurrentThreadId() << ") Connect to " << peerAddr << " successful");
#else
		PTRACE(3, "Q931(" << getpid() << ") Connect to " << peerAddr << " successful");
#endif
		SetConnected(true);
		remote->SetConnected(true);
		SendInformationMessages();
		ForwardData();
	} else {
		PTRACE(3, "Q931\t" << peerAddr << " DIDN'T ACCEPT THE CALL");
		EndSession();
		delete remote; // would close myself
		// remote = 0; // already detached
	}
	return remote;
}

bool CallSignalSocket::FakeSetupACK(Q931 &setup) {
	Q931 pdu;
	H225_H323_UserInformation calledSignal;
	H225_H323_UU_PDU  & uu = calledSignal.m_h323_uu_pdu;
	pdu.BuildSetupAcknowledge(setup.GetCallReference());
 	// Old message
	H225_H323_UserInformation signal;
	PPER_Stream q = setup.GetIE(Q931::UserUserIE);
	signal.Decode(q);
	H225_H323_UU_PDU & callingpdu = signal.m_h323_uu_pdu;
	H225_Setup_UUIE & callingUUIE = callingpdu.m_h323_message_body;
	// Old Message
	H225_H323_UU_PDU_h323_message_body &mb = uu.m_h323_message_body;
	mb.SetTag(H225_H323_UU_PDU_h323_message_body::e_setupAcknowledge);
	H225_SetupAcknowledge_UUIE &uuie = mb;
	uuie.m_protocolIdentifier = callingUUIE.m_protocolIdentifier;
	uuie.m_callIdentifier = callingUUIE.m_callIdentifier;
	PPER_Stream b;
	b.SetSize(0);
	b.SetPosition(0);
	calledSignal.Encode(b);
	b.CompleteEncoding();
	pdu.SetIE(Q931::UserUserIE, b);
	buffer.SetSize(0); // Clear Buffer
	pdu.Encode(buffer);
	return TransmitData();
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

void CallSignalSocket::SendReleaseComplete()
{
       if (IsOpen()) {
               Q931 ReleasePDU;
               BuildReleasePDU(ReleasePDU);
               ReleasePDU.Encode(buffer);
               TransmitData();
	       PTRACE(5, "GK\tSend Release Complete to " << Name());
	       PrintQ931(6, "Sending ", &ReleasePDU, 0);
       }
}

bool CallSignalSocket::EndSession()
{
	SendReleaseComplete();
	return TCPProxySocket::EndSession();
}

ProxySocket::Result CallSignalSocket::ReceiveData() {
	if (!ReadTPKT())
		return NoData;

	Q931 q931pdu;
	if (!q931pdu.Decode(buffer)) {
		PTRACE(4, "Q931\t" << Name() << " ERROR DECODING Q.931!");
		return Error;
	}

	m_receivedQ931 = &q931pdu;

	PTRACE(1, "Q931\t" << Name() << " Message type: " << q931pdu.GetMessageTypeName());
	PTRACE(3, "Q931\t" << "Received: " << q931pdu.GetMessageTypeName() << " CRV=" << q931pdu.GetCallReference() << " from " << Name());
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

		unsigned ton=0,
			plan=0;
		switch (body.GetTag()){
		case H225_H323_UU_PDU_h323_message_body::e_setup:
			m_crv = (q931pdu.GetCallReference() | 0x8000u);
			q931pdu.GetCalledPartyNumber(DialedDigits,&ton,&plan);
			m_SetupPDU = new Q931(*(GetReceivedQ931()));
			OnSetup(body);
			CgPNConversion(q931pdu,body);
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

	// NB: Rewriting Number!
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
 	if (!isRoutable && q931pdu.GetMessageType()==Q931::InformationMsg) {
		OnInformationMsg(q931pdu);
	} else {
		q931pdu.Encode(buffer);
		PTRACE(5, ANSI::BGRE << "Q931\nMessage to sent: " << setprecision(2) << q931pdu << ANSI::OFF);
		{
			unsigned int plan, ton;
			PString calledNumber;
			if(q931pdu.GetCalledPartyNumber(calledNumber, &plan, &ton)) {
				calledNumber += " Numbering Plan: ";
				if (plan==Q931::ISDNPlan)
					calledNumber += "ISDN";
				calledNumber += " TON: ";
				if(ton==Q931::NationalType)
					calledNumber += "national call";
				if(ton==Q931::InternationalType)
					calledNumber += "international call";
				if(ton==Q931::SubscriberType)
					calledNumber += "Subscriber Type";
				PTRACE(5, ANSI::BGRE << "Q931-CalledPartyNumberIE: " << calledNumber << ANSI::OFF);
			}
			if(q931pdu.GetCallingPartyNumber(calledNumber, &plan, &ton)) {
				calledNumber += " Numbering Plan: ";
				if (plan==Q931::ISDNPlan)
					calledNumber += "ISDN";
				calledNumber += " TON: ";
				if(ton==Q931::NationalType)
					calledNumber += "national call";
				if(ton==Q931::InternationalType)
					calledNumber += "international call";
				if(ton==Q931::SubscriberType)
					calledNumber += "Subscriber Type";
				PTRACE(5, ANSI::BGRE << "Q931-CallingPartyNumberIE: " << calledNumber << ANSI::OFF);
			}

		}


		switch (q931pdu.GetMessageType()) {
		case Q931::SetupMsg:
			break;
		/* why don't forward Status? - see ProxyChannel.cxx
		case Q931::StatusMsg:
			// don't forward status messages mm-30.04.2001
			return NoData;
		*/
		case Q931::ReleaseCompleteMsg:
			if (m_call) {
				CallTable::Instance()->RemoveCall(m_call);
				m_call = callptr(0);
			}
			return Closing;
		default:
			return Forwarding;
		}

		if (!m_call) {
			PTRACE(3, "Q931\t" << Name() << " Setup destination not found!");
			EndSession();
			return Error;
		}

		// NB: Check for routable number
		if ((peerAddr == INADDR_ANY) && (isRoutable)) {
			PTRACE(3, "Q931\t" << Name() << " INVALID ADDRESS");
			EndSession();
			return Error;
		}

		//return (isRoutable) ? Connecting : NoData;
		return Connecting;
	}
	return NoData;
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

	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		PINDEX last = Setup.m_destinationAddress.GetSize();
		for( PINDEX i = 0; i<last; i++) {
			Toolkit::Instance()->RewriteE164(Setup.m_destinationAddress[i]);
		}
	}
	PString callid;
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
		m_call = CallTable::Instance()->FindCallRec(Setup.m_callIdentifier);
		callid = AsString(Setup.m_callIdentifier.m_guid);
	} else {
		PTRACE(3, "Q931\tSetup_UUIE doesn't contain CallIdentifier!");
		H225_CallIdentifier callIdentifier; // empty callIdentifier
		H225_CallReferenceValue crv;
		crv.SetValue(m_crv & 0x7fffu);
		m_call = CallTable::Instance()->FindCallRec(crv);
		callid = AsString(callIdentifier.m_guid);
	}
	GkClient *gkClient = RasThread->GetGkClient();
	Address fromIP;
	GetPeerAddress(fromIP);

	bool bOverlapSending = FALSE;
	isRoutable=FALSE;

	if (m_call) {
		if (m_call->IsRegistered()) {
			if (gkClient->CheckGKIP(fromIP)) {
				PTRACE(2, "Q931\tWarning: a registered call from my GK(" << Name() << ')');
				m_call = callptr(0);  // reject it
				return;
			}
			gkClient->RewriteE164(*GetReceivedQ931(), Setup, true);
		}
	} else {
		bool fromParent;
		if (!RasThread->AcceptUnregisteredCalls(fromIP, fromParent)) {
			PTRACE(3, "Q931\tNo CallRec found in CallTable for callid " << callid);
			PTRACE(3, "Call was " << (fromParent ? "" : "not " ) << "from Parent");
			return;
		}
		if (fromParent)
			gkClient->RewriteE164(*GetReceivedQ931(), Setup, false);

		endptr called;
		PString destinationString;

		endptr callingEP = GetCgEP(*GetSetupPDU());
		if (endptr(NULL)==callingEP) {
			if (Setup.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress)) {
				callingEP = RegistrationTable::Instance()->FindBySignalAdr(Setup.m_sourceCallSignalAddress);
			}
		}
		// TODO: check the Setup_UUIE by gkauth modules

		if (!callingEP) {
			PTRACE(1, "Unknown Calling Party -- giving up");
			return ;
		}


		// Rewrite sourceString

		PString sourceString(Setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress) ? AsString(Setup.m_sourceAddress) : PString());
		CallRec *call = new CallRec(Setup.m_callIdentifier, Setup.m_conferenceID, destinationString, sourceString, 0, RasThread->IsGKRoutedH245());

		call->SetCalling(callingEP);
		CallTable::Instance()->Insert(call);
		m_call = callptr(call);

		unsigned int reason;

		if (Setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
			called = RegistrationTable::Instance()->FindBySignalAdr(Setup.m_destCallSignalAddress);
			destinationString = AsDotString(Setup.m_destCallSignalAddress);
		}
		if (!called && Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
			if (callingEP)
				called = RegistrationTable::Instance()->getMsgDestination(Setup.m_destinationAddress[0], // should check all
										  callingEP, reason);
			destinationString = AsString(Setup.m_destinationAddress);

		}
		if (!called && reason!=H225_AdmissionRejectReason::e_incompleteAddress) {
			PTRACE(3, "Q931\tDestination not found for the unregistered call " << callid);
			return;
		}

		if(called) {
			call->SetCalled(called, m_crv);
		} else {
			bOverlapSending=TRUE;
		}
		if (fromParent) {
			call->SetRegistered(true);
			gkClient->SendARQ(Setup, m_crv, m_call);
		}
	}

	const H225_TransportAddress *addr = m_call->GetCalledAddress();

	if (addr && Setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
		// in routed mode the caller may have put the GK address in destCallSignalAddress
		// since it is optional, we just remove it if it contains the GK address (we could alternativly insert the real destinationAddress/destinationCallSignalAddress)
		if (addr && Setup.m_destCallSignalAddress != *addr) {
			Setup.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
			isRoutable = FALSE;
		} else {
			PTRACE(1, "OnSetup: call should be routable");
			isRoutable = TRUE;
		}
	}

	if(!isRoutable && Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)){
		// in routed mode the caller may have put the GK address in destCallSignalAddress
		// since it is optional, we just remove it if it contains the GK address (we could alternativly insert the real destinationAddress/destinationCallSignalAddress)
		//FIXME: the first destAlias need not be the name of gk!
		if (H323GetAliasAddressString(Setup.m_destinationAddress[0]) == Toolkit::GKName()) {
			Setup.RemoveOptionalField(H225_Setup_UUIE::e_destinationAddress);
		} else {
        		// if real destination address is given then check for incomplete address
			//FIXME: the first destAlias need not be dialed digits!
			DialedDigits = H323GetAliasAddressString(Setup.m_destinationAddress[0]);
			H225_AliasAddress h225address;
			H323SetAliasAddress(DialedDigits,h225address);
			unsigned rsn;
			endptr CalledEP = RegistrationTable::Instance()->getMsgDestination(h225address, m_call->GetCallingEP(), rsn);
			if(CalledEP && (H225_AdmissionRejectReason::e_incompleteAddress != rsn) ) {
				isRoutable=TRUE;
				H323SetAliasAddress(m_call->GetCalledPartyNumber(), Setup.m_destinationAddress[0]);
			} else {
				bOverlapSending = TRUE;
			}
			DialedDigits = H323GetAliasAddressString(Setup.m_destinationAddress[0]);
			PTRACE(5,"DialedDigits: " << DialedDigits );
		}
	}
	if (addr && addr->GetTag() == H225_TransportAddress::e_ipAddress) {
		isRoutable = TRUE;
	}
	if (isRoutable) {
		CgPNConversion(*m_SetupPDU, Setup);
		const H225_TransportAddress_ipAddress & ip = *addr;
		peerAddr = PIPSocket::Address(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
		peerPort = ip.m_port;
		Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
		Setup.m_sourceCallSignalAddress = RasThread->GetCallSignalAddress(peerAddr);
		H225_TransportAddress_ipAddress & cip = Setup.m_sourceCallSignalAddress;
		localAddr = PIPSocket::Address(cip.m_ip[0], cip.m_ip[1], cip.m_ip[2], cip.m_ip[3]);
		remote = new CallSignalSocket(this, peerPort);
	} else { // Overlap Sending
		// re-route called endpoint signalling messages to gatekeeper
		Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
		Setup.m_sourceCallSignalAddress = SocketToH225TransportAddr(localAddr, GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_CALL_SIGNAL_PORT));
		//remote = new CallSignalSocket(this, GetReceivedQ931());
		if(DialedDigits.IsEmpty() && GetSetupPDU()->HasIE(Q931::CalledPartyNumberIE)) {
			unsigned plan,type;
			GetSetupPDU()->GetCalledPartyNumber(DialedDigits,&plan,&type);
		}
		remote=NULL;
	}

	if (Setup.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress))
		Setup.RemoveOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);

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
	HandleFastStart(Setup,true);
	//SetBlocked(false);
//	PTRACE(4, "GK\tSetup_UUIE:\n" << setprecision(2) << Setup);
}

void CallSignalSocket::OnInformationMsg(Q931 &pdu){
	// Collect digits
	if (pdu.HasIE(Q931::CalledPartyNumberIE)) {
		PString calledDigit;
		unsigned plan,type;
		if(pdu.GetCalledPartyNumber(calledDigit, &plan, &type)) {
			DialedDigits+=calledDigit;
			if(Toolkit::Instance()->RewritePString(DialedDigits))
				GetSetupPDU()->SetCalledPartyNumber(DialedDigits,plan,type);
			DoRoutingDecision();
		}
	} else {
		if(!isRoutable)
			Q931InformationMessages.Append(new Q931(pdu));
	}
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
//     for(PINDEX i = sz; i-- > 0; ) {
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
	if (!m_h245handler) // no H245 routed
                return true;
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

PString MatchCgAlias(const callptr &callRec, H225_AliasAddress &alias, bool &partialMatch, bool &fullMatch) {
// match CgPN right justified against voIPtelephoneNumbers and returns the
// complete calling PN
        partialMatch = FALSE;
        fullMatch = FALSE;
	int number_of_matches = 0;
	PString completeCgPN;

	PString aliasStr = H323GetAliasAddressString(alias);

        unsigned int aliasStrLen = aliasStr.GetLength();
        const PStringList &telNos = callRec->GetCallingProfile().getTelephoneNumbers();

        // for all telephone numbers (emergency calls)
        for (PINDEX i=0; i < telNos.GetSize() && !partialMatch; i++) {
		if ((telNos[i].GetLength() >= aliasStrLen)) {
			int telNoLen = telNos[i].GetLength();

			// get amount of points
			unsigned int amountPoints = 0;
			int posFirstPoint = telNos[i].Find('.');
			if (posFirstPoint != P_MAX_INDEX && posFirstPoint >= 0) {
		        	amountPoints = telNoLen - posFirstPoint;
			}

                        PTRACE(5,"posFirstPoint: " << posFirstPoint);
                        PTRACE(5,"amountPoints: " << amountPoints);
			// if no points exist and alias matches right justified
			if (amountPoints == 0 &&
					aliasStr == telNos[i].Right(aliasStrLen)) {
                                PTRACE(5, "Full match");
				fullMatch = TRUE;
				number_of_matches++;
				completeCgPN = telNos[i];
                                PTRACE(5,"completeCgPN: " << completeCgPN);
			// else if points exist
			} else if (amountPoints > 0) {
				if (aliasStrLen < amountPoints) {
					partialMatch = TRUE;
				} else if (aliasStrLen == amountPoints) {
					fullMatch = TRUE;
					number_of_matches++;
					completeCgPN = telNos[i].Left(
						telNoLen - amountPoints) + aliasStr;
				} else {
				//aliasStrLen > amountPoints
					int amountOverlap = (aliasStrLen - amountPoints);
					//if aliasStrOverlap == telNoOverlap
					if (aliasStr.Left(amountOverlap) ==
                                            telNos[i].Mid(posFirstPoint - amountOverlap, amountOverlap)) {
						fullMatch = TRUE;
						number_of_matches++;
						completeCgPN = telNos[i].Left(
							telNoLen - amountPoints)
							+ aliasStr.Right(amountPoints);
					} else {
						//no match
					}
				}
			}

			if (partialMatch) {
				PTRACE(1, "Partial match " << aliasStr
					<< " with telephone number "
					<< telNos[i]);
			} else if (fullMatch) {
				PTRACE(1, "Full match " << aliasStr
					<< " with telephone number "
				       << telNos[i]);
			}
		}
	}
        if (completeCgPN == "") {
                PTRACE(1, "Error: couldn't find complete CgPN!");
		completeCgPN=callRec->GetCallingProfile().getMainTelephoneNumber();
        }
	if(number_of_matches>1) {
		completeCgPN=callRec->GetCallingProfile().getMainTelephoneNumber();
	}
        return completeCgPN;
}

// rkeil {
static BOOL TestAnalysedNumber(E164_AnalysedNumber &an, PString &n);
static BOOL TestAnalysedNumber(E164_AnalysedNumber &an, PString &n)
{
	BOOL result = (E164_AnalysedNumber::IPTN_unknown != an.GetIPTN_kind());
	if(!result) {	// 'an' could not be analysed
		PTRACE(6, ANSI::RED << "Q931\tCould not analyse: "  << ANSI::BRED
		       << n << ANSI::OFF);
		GkStatus::Instance()->
			SignalStatus(PString("Q931\tCould not analyse: '")
				     + n + "'");
	} // 'an' could not be analysed
	return result;
}

static BOOL prependCallbackAC(const callptr &callRec, PString &nac, PString &inac);
static BOOL prependCallbackAC(const callptr &callRec, PString &nac, PString &inac)
{
        H225_AliasAddress destH323ID;
	PString destH323IDStr;

        endptr cdEP = callRec->GetCalledEP(); // get called EP
        if (cdEP && cdEP->GetH323ID(destH323ID)) {
        // found dest H323ID
                DBAttributeValueClass attrMap;
                destH323IDStr = H323GetAliasAddressString(destH323ID);

		using namespace dctn;
		DBTypeEnum dbType;
                // get dest attributes from database
                GkDatabase *db = GkDatabase::Instance();
                if (db->getAttributes(destH323IDStr,  attrMap, dbType)) {
                        using namespace dctn;
                        if (attrMap[db->attrNameAsString(NationalAccessCode)].GetSize() > 0) {
                                nac = attrMap[db->attrNameAsString(NationalAccessCode)][0];
                        }
                        if (attrMap[db->attrNameAsString(InternationalAccessCode)].GetSize() > 0) {
                                inac = attrMap[db->attrNameAsString(InternationalAccessCode)][0];
                        }
                        if (attrMap[db->attrNameAsString(PrependCallbackAC)].GetSize() > 0) {
                                return Toolkit::Instance()->AsBool(attrMap[db->attrNameAsString(PrependCallbackAC)][0]);
                        }
                } else {
                        PTRACE(5, "Can't find attributes for destH323IDStr: " << destH323IDStr);
                }
        }
        return FALSE;
}
// { rkeil


void PrintCallingPartyNumber(PString callingPN, unsigned npi, unsigned ton, unsigned pi, unsigned si) {

	PString out = "\t\t\t\t\t\t\t\t\tcallingPN: " + callingPN;
	out += "\n\t\t\t\t\t\t\t\t\tNumberingPlanIndicator: " + PString(npi) + " (";
	switch (npi) {
		case Q931::UnknownPlan:
			out += "unknown";
			break;
		case Q931::ISDNPlan:
			out += "ISDN";
			break;
		default:
			out += "i don't know this value";
			break;
	}
	out += ")\n\t\t\t\t\t\t\t\t\tTypeOfNumber: " + PString(ton) + " (";
	switch (ton) {
		case Q931::UnknownType:
			out += "unknown";
			break;
		case Q931::NationalType:
			out += "national";
			break;
		case Q931::InternationalType:
			out += "international";
			break;
		default:
			out += "i don't know this value";
			break;
	}
	out += ")\n\t\t\t\t\t\t\t\t\tPresentation Indicator: " + PString(pi) + " (";
	switch (pi) {
		case H225_PresentationIndicator::e_presentationAllowed:
			out += "allowed";
			break;
		case H225_PresentationIndicator::e_presentationRestricted:
			out += "restricted";
			break;
		case H225_PresentationIndicator::e_addressNotAvailable:
			out += "address not available";
			break;
		default:
			out += "i don't know this value";
			break;
	}
	out += ")\n\t\t\t\t\t\t\t\t\tScreening Indicator: " + PString(si) + " (";
	switch (si) {
		case H225_ScreeningIndicator::e_networkProvided:
			out += "network provided";
			break;
		case H225_ScreeningIndicator::e_userProvidedVerifiedAndPassed:
			out += "User Provided, Verified and Passed";
			break;
		case H225_ScreeningIndicator::e_userProvidedVerifiedAndFailed:
			out += "User Provided, Verified and Failed";
			break;
		case H225_ScreeningIndicator::e_userProvidedNotScreened:
			out += "User Provided, Not Screened";
			break;
		default:
			out += "i don't know this value";
			break;
	}
	out += ")";

        PTRACE(5, "SetCallingPartyNumber" << endl << out);
}


void CallSignalSocket::CgPNConversion(Q931 &q931pdu, H225_Setup_UUIE &setup) {

	PTRACE(1, "Begin of CgPNConversion");
	callptr callRec = CallTable::Instance()->FindCallRec(setup.m_callIdentifier);

	if(callRec==callptr(NULL))
		return;

	PString srcH323IDStr=callRec->GetCallingProfile().getH323ID();

	// if a profile exists
	if (!srcH323IDStr.IsEmpty()) {
        	PTRACE(1,"Start CgPNConversion");

		// some bools to code the tricky flow chart
		bool cgPNIncludedNotFromCPE = TRUE;
		bool cgPNIncludedFromCPE = TRUE;
		bool cgPNmatched = TRUE;

		// vars for q931pdu.SetCallingPartyNumber
		PString  callingPN;
		unsigned npi = Q931::ISDNPlan;
		unsigned ton = Q931::InternationalType;
		unsigned pi;
		unsigned si;

		// get the original calling party number settings
		BOOL cgPNIncluded = q931pdu.GetCallingPartyNumber(
					    callingPN,
					    &npi,
					    &ton,
					    &pi,
					    &si
				    );

		if (callRec && !callRec->GetCallingProfile().isCPE()) {
			PTRACE(5, "EP not from CPE");

			if (cgPNIncluded) {
				// CgPNs included
				// select a cgPN to set
				// Is there more than 1 CgPN?
				// convert cgPN to interternational format
				PTRACE(5, "CgPN included:" << callingPN);
#ifdef DO_NATIONAL_CALL
				if(ton != Q931::InternationalType) {
					callingPN = callRec->GetCallingProfile().getCC() + callingPN;
					npi = Q931::ISDNPlan;
					ton = Q931::InternationalType;
				}
#else
				ton = Q931::InternationalType;
#endif DO_NATIONAL_CALL

				cgPNIncludedNotFromCPE = TRUE;
			} else {
			// CgPNs not included
				// nothing to do here yet
				cgPNIncludedNotFromCPE = FALSE;
				PTRACE(5, "CgPN not included");
			}
		} else {
			PTRACE(5, "From CPE");

			if (cgPNIncluded) {
			// CgPN included (only one CgPN possible)
				cgPNIncludedFromCPE = TRUE;
				PTRACE(5, "CgPN included:" << callingPN);

				// match CgPN right justified...
				bool partialMatch, fullMatch;
				H225_AliasAddress cgPN;
				H323SetAliasAddress(callingPN, cgPN);

				callingPN = MatchCgAlias(callRec, cgPN, partialMatch, fullMatch);

				if (fullMatch) {
				// CgPN does match
					cgPNmatched = TRUE;
					PTRACE(5, "CgPN does match");
					si  = H225_ScreeningIndicator::e_userProvidedVerifiedAndPassed;
// nilsb
					ton = Q931::InternationalType;
					npi = Q931::ISDNPlan;
					PTRACE(5, "SI = e_userProvidedVerifiedAndPassed");
					PString clir = callRec->GetCallingProfile().getClir();

					if (clir.IsEmpty()) {
						PTRACE(5, "No CLIR in calling profile --> leave PI unchanged");
					} else {
					// set PI according to clir flag
						pi = Toolkit::AsBool(clir) ? H225_PresentationIndicator::e_presentationRestricted
							: H225_PresentationIndicator::e_presentationAllowed;
						PTRACE(5, "PI = " << pi);
					}
				} else {
				// CgPN does not match
					cgPNmatched = FALSE;
					PTRACE(5, "CgPN does not match");
				}
			} else {
			// CgPN not included
				cgPNIncludedFromCPE = FALSE;
				PTRACE(5, "CgPN not included");
			}

			if (!cgPNIncludedFromCPE || !cgPNmatched) {
				// insert main callingPN from CallTable
				// SI = network provided
				// get CLIR from callTable
				// no CLIR PI = restricted ....
				PTRACE(5, "Insert main callingPN from CallTable");
				callingPN = callRec->GetCallingProfile().getMainTelephoneNumber();
				PTRACE(5, "callingPN = " << callingPN);
				si = H225_ScreeningIndicator::e_networkProvided;
				PTRACE(5, "SI = e_networkProvided");
				PString clir = callRec->GetCallingProfile().getClir();
				if (clir.IsEmpty()) {
					pi = H225_PresentationIndicator::e_presentationRestricted;
				} else {
				// set PI according to clir flag
					pi = Toolkit::AsBool(clir) ? H225_PresentationIndicator::e_presentationRestricted
						: H225_PresentationIndicator::e_presentationAllowed;
				}
				PTRACE(5, "PI = " << pi);
			}
		}

#ifdef DO_NATIONAL_CALL
		if (cgPNIncludedNotFromCPE || callRec->GetCallingProfile().isCPE()) {
			npi = Q931::ISDNPlan;
			PTRACE(5, "NPI = ISDNPlan");
			ton = Q931::InternationalType;
			PTRACE(5, "TON = InternationalType");

			// store cgPN for CDR generation
		}
#endif
		callRec->GetCallingProfile().setCgPN(callingPN);

		// get CdPN
		PString calledPN = callRec->GetCalledProfile().getCalledPN();
		// CdPN TON = international
		// CdPN NPI = ISDN
		PString originalCalledPN;
		unsigned ocdpn=0,
			ocdt=0;
		q931pdu.GetCalledPartyNumber(
			originalCalledPN,
			&ocdpn,
			&ocdt);
		q931pdu.SetCalledPartyNumber(
			calledPN,
			Q931::ISDNPlan,
			Q931::InternationalType
		);

#if 1				/* FIXME: Untested code */
		E164_AnalysedNumber tele(calledPN); // analyse
		if(!TestAnalysedNumber(tele,calledPN))// check if valid
			q931pdu.SetCalledPartyNumber(
				originalCalledPN,
				ocdpn,
				ocdt);

		const PString &cdPNCC = tele.GetCC().GetValue(); // get CC of CdPN

		PString telestr = tele;
		PTRACE(5, "calledPN: " << calledPN);
		PTRACE(5, "tele: " << telestr);
		PTRACE(5, "CC: " << cdPNCC);

		BOOL nationalCall = FALSE;
#ifdef DO_NATIONAL_CALL
		if ((cdPNCC!="") && (P_MAX_INDEX != callingPN.Find(cdPNCC))) { // aka 'contains' CC
		// CgPN and CdPN have the same country code --> national call
			nationalCall = TRUE;
			PTRACE(5, "CgPN and CdPN have the same country code --> national call");

			// convert CgPN to national format
			E164_AnalysedNumber cgTele(callingPN); // analyse
			TestAnalysedNumber(cgTele,callingPN); // check if valid
			callingPN.Replace(cgTele.GetCC().GetValue(),""); // remove CC
			PTRACE(5, "callingPN = " << callingPN);
			ton = Q931::NationalType;
			PTRACE(5, "TON = NationalType");

			// convert CdPN to national format
			PString  cdPN;
			unsigned cdNpi = 0; // called numbering plan
			unsigned cdTon = 0; // called number type
			q931pdu.GetCalledPartyNumber(cdPN, &cdNpi, &cdTon);
			calledPN.Replace(tele.GetCC().GetValue(),""); // remove CC
			q931pdu.SetCalledPartyNumber(calledPN, cdNpi, Q931::NationalType); // set CdPN
			PTRACE(5, "calledPN = " << calledPN);
			PTRACE(5, "calledTON = NationalType");
		}
#endif // DO_NATIONAL_CALL

		PString nac;
		PString inac;
		if (prependCallbackAC(callRec, nac, inac)) {
		// PrependCallbackAC is TRUE
			ton = Q931::UnknownType; // set TON = unknown

			if (nationalCall) {
			// national call --> prepend nac to CgPN
				PTRACE(5, "national call --> prepend nac to CgPN");
				PTRACE(5, callingPN << " --> " << nac + callingPN);
				callingPN = nac + callingPN;
			} else {
			// international call --> prepend inac to CgPN
				PTRACE(5, "international call --> prepend inac to CgPN");
				PTRACE(5, callingPN << " --> " << inac + callingPN);
				callingPN = inac + callingPN;
			}
		} else {
			PTRACE(5, "PrependCallbackAC == FALSE");
		}
#endif

		// apply changes
		q931pdu.RemoveIE(Q931::CallingPartyNumberIE);
		q931pdu.SetCallingPartyNumber(
			callingPN,
			npi,
			ton,
			pi,
			si
		);

		PrintCallingPartyNumber(callingPN, npi, ton, pi, si);
		callRec->GetCalledProfile().setDialedPN_TON((enum Q931::TypeOfNumberCodes)ton); // for CDR use mainly

		if (callRec->GetCalledProfile().isCPE()) {
		// call goes to CPE
			PTRACE(5, "Call goes to CPE");
			// remove cgPNs with: PI = restricted
			//                    SI = user provided, not screened
			//                    SI = user provided, verrified and failed
			if((si == H225_ScreeningIndicator::e_userProvidedNotScreened)       ||
			   (si == H225_ScreeningIndicator::e_userProvidedVerifiedAndFailed) ||
			   (pi == H225_PresentationIndicator::e_presentationRestricted)) {
				q931pdu.RemoveIE(Q931::CallingPartyNumberIE);
				q931pdu.SetCallingPartyNumber(
					"",
					Q931::UnknownPlan,
					Q931::UnknownType,
					H225_PresentationIndicator::e_presentationRestricted,
					si
				);

				PString out = "Calling party number removed, reason: ";
				if(si == H225_ScreeningIndicator::e_userProvidedNotScreened)
					out += "SI == e_userProvidedNotScreened";
				if(si == H225_ScreeningIndicator::e_userProvidedVerifiedAndFailed)
					out += "SI == e_userProvidedVerifiedAndFailed";
				if(pi == H225_PresentationIndicator::e_presentationRestricted)
					out += "PI == e_presentationRestricted";
				PTRACE(4, out);

			}
		}
		if(setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) { // THIS IS AGAINST Q.931
			H323SetAliasAddress(calledPN, setup.m_destinationAddress[0], H225_AliasAddress::e_dialedDigits);
		}
	}
}

// class H245Handler
H245Handler::H245Handler(PIPSocket::Address local, PIPSocket::Address remote)
      : localAddr(local), remoteAddr(remote)
{
	hnat = (remoteAddr != INADDR_ANY) ? new NATHandler(remoteAddr) : 0;
}

H245Handler::~H245Handler()
{
	delete hnat;
}

void H245Handler::OnH245Address(H225_TransportAddress & addr)
{
	if (hnat)
		hnat->TranslateH245Address(addr);
}

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
			//if (((H245_CommandMessage &)h245msg).GetTag() == H245_CommandMessage::e_endSessionCommand)
			//	res = ProxySocket::Closing;
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

	PTRACE(5, ANSI::BGRE << "H245\nMessage to sent: " << h245msg << ANSI::OFF);
	return changed;
}

bool H245Handler::HandleFastStartSetup(H245_OpenLogicalChannel & olc)
{
       return hnat ? hnat->HandleOpenLogicalChannel(olc) : false;
}

bool H245Handler::HandleFastStartResponse(H245_OpenLogicalChannel & olc)
{
       return hnat ? hnat->HandleOpenLogicalChannel(olc) : false;
}

bool H245Handler::HandleRequest(H245_RequestMessage & Request)
{
	PTRACE(4, "H245\tRequest: " << Request.GetTagName());
	if (hnat && Request.GetTag() == H245_RequestMessage::e_openLogicalChannel)
		return hnat->HandleOpenLogicalChannel(Request);
	else
		return false;
}

bool H245Handler::HandleResponse(H245_ResponseMessage & Response)
{
	PTRACE(4, "H245\tResponse: " << Response.GetTagName());
	if (hnat && Response.GetTag() == H245_ResponseMessage::e_openLogicalChannelAck)
		return hnat->HandleOpenLogicalChannelAck(Response);
	else
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
#ifdef WIN32
			PTRACE(3, "H245(" << GetCurrentThreadId() << ") Connect to " << Name() << " successful");
#else
			PTRACE(3, "H245(" << getpid() << ") Connect to " << Name() << " successful");
#endif
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

	PTRACE(5, "UDP\tReverse " <<  srcIP << ':' << srcPort << " to " << rDestIP << ':' << rDestPort);
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

	buflen = GetLastReadCount();

//     if (fromIP == rSrcIP && (fromPort == rSrcPort || abs(fromPort - rSrcPort) == 2))
       // Workaround: some bad endpoints don't send packets from the specified port
	if ((fromIP == rSrcIP || fromIP == fDestIP) && (fromIP != fSrcIP || fromPort == rSrcPort)) {
		PTRACE(6, "UDP\tforward " << fromIP << ':' << fromPort << " to " << rDestIP << ':' << rDestPort);
		SetSendAddress(rDestIP, rDestPort);               SetSendAddress(rDestIP, rDestPort);
	} else {
		PTRACE(6, "UDP\tforward " << fromIP << ':' << fromPort << " to " << fDestIP << ':' << fDestPort);
		SetSendAddress(fDestIP, fDestPort);
	}
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
H245ProxyHandler::H245ProxyHandler(CallSignalSocket *sig, PIPSocket::Address local, PIPSocket::Address remote, H245ProxyHandler *pr)
	: H245Handler(local, remote), handler(sig->GetHandler()), peer(pr)
{
	if (peer)
		peer->peer = this;
}

H245ProxyHandler::~H245ProxyHandler()
{
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
	if (hnat)
		hnat->HandleOpenLogicalChannel(olc);
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
	if (hnat)
		hnat->HandleOpenLogicalChannelAck(olca);
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
	if (hnat)
		hnat->HandleOpenLogicalChannel(olc);
	bool nouse;
	H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse);
	return (h225Params) ? OnLogicalChannelParameters(h225Params, 0) : false;
}

bool H245ProxyHandler::HandleFastStartResponse(H245_OpenLogicalChannel & olc)
{
	if (hnat)
		hnat->HandleOpenLogicalChannel(olc);

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
void NATHandler::TranslateH245Address(H225_TransportAddress & h245addr)
{
	if (h245addr.GetTag() == H225_TransportAddress::e_ipAddress) {
		H225_TransportAddress_ipAddress & addr = h245addr;
		h245addr = SocketToH225TransportAddr(remoteAddr, addr.m_port);
	}
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
	if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_separateStack)) {
		H245_NetworkAccessParameters & sepStack = olca.m_separateStack;
		if (sepStack.m_networkAddress.GetTag() == H245_NetworkAccessParameters_networkAddress::e_localAreaAddress) {
			H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(sepStack.m_networkAddress);
			if (addr) {
				*addr << remoteAddr << addr->m_tsapIdentifier;
				return true;
			}
		}
	} else {
		H245_UnicastAddress_iPAddress *mediaControlChannel, *mediaChannel;
		if (GetChannelsFromOLCA(olca, mediaControlChannel, mediaChannel)) {
			*mediaControlChannel << remoteAddr << mediaControlChannel->m_tsapIdentifier;
			if (mediaChannel)
				*mediaChannel << remoteAddr << mediaChannel->m_tsapIdentifier;
			return true;
		}
	}
	return false;
}

// to avoid ProxyThread.cxx to include the large h225.h,
// to avoid ProxyThread.cxx to include the large h225.h,
// put the method here...

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
