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
#include "GkClient.h"
#include "ProxyChannel.h"
#include <q931.h>
#include <h245.h>
#include "RasListener.h"
#include "RasTbl.h"
#include "gkDestAnalysis.h"
#include "gkldap.h"
#include "gkDatabase.h"

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = PROXYCHANNEL_H;
#endif /* lint */

const char *RoutedSec = "RoutedMode";
const char *ProxySection = "Proxy";

class PortRange {
public:
       WORD GetPort();
       void LoadConfig(const char *, const char *, const char * = "");

private:
       WORD port, minport, maxport;
       PMutex mutex;
};

WORD PortRange::GetPort()
{
       WORD result = port;
       if (port > 0) {
               PWaitAndSignal lock(mutex);
               ++port;
               if (port > maxport)
                       port = minport;
       }
       return result;
}

void PortRange::LoadConfig(const char *sec, const char *setting, const char *def)
{
       PStringArray cfgs = GkConfig()->GetString(sec, setting, def).Tokenise(",.:-/'", FALSE);
       PWaitAndSignal lock(mutex);
       if (cfgs.GetSize() >= 2) // no such a setting in config
               port = minport = cfgs[0].AsUnsigned(), maxport = cfgs[1].AsUnsigned();
       else
               port = 0;
       PTRACE_IF(2, port, setting << ": " << minport << '-' << maxport);
}

static PortRange Q931PortRange;
static PortRange H245PortRange;
static PortRange T120PortRange;
static PortRange RTPPortRange;

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
	// locking methods
	virtual void Lock();
	virtual void Unlock();

private:

	CallSignalSocket *sigSocket;
	H225_TransportAddress peerH245Addr;
	PTCPSocket *listener;
	mutable PMutex m_lock;
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
	bool IsAttached() const { return (peer != 0); }

	class NoPortAvailable {};

private:
	bool reversed;
	RTPLogicalChannel *peer;
	UDPProxySocket *rtp, *rtcp;
	PIPSocket::Address SrcIP;
	WORD SrcPort;

	static WORD GetPortNumber();
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


// CallSignalSocket

const endptr CallSignalSocket::GetCgEP(Q931 &q931pdu)
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
			return endptr(NULL); // Urgs...
		}
		H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
		H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;
		H225_Setup_UUIE & Setup = body;
		if (!Setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
			PTRACE(1, "Q931\tOnSetup() no callIdentifier!");
			return endptr(NULL);
		}
		m_call = CallTable::Instance()->FindCallRec(Setup.m_callIdentifier);
		if (m_call) {
			if (endptr(NULL)!=RegistrationTable::Instance()->FindBySignalAdr(*(m_call->GetCallingAddress())))
				return RegistrationTable::Instance()->FindBySignalAdr(*(m_call->GetCallingAddress()));
		}
		if(Setup.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress)) {
			if(endptr(NULL)!=RegistrationTable::Instance()->FindBySignalAdr(Setup.m_sourceCallSignalAddress))
				return RegistrationTable::Instance()->FindBySignalAdr(Setup.m_sourceCallSignalAddress);
		}
	}
	PTRACE(1, "No endpoint found");
	return endptr(NULL);
}

CallSignalSocket::CallSignalSocket()
	: TCPProxySocket("Q931s"), m_h245handler(NULL), m_h245socket(NULL), isRoutable(FALSE), m_numbercomplete(FALSE),
	  m_StatusEnquiryTimer(NULL), m_StatusTimer(NULL), m_replytoStatusMessage(TRUE)
{
	m_call=callptr(NULL);
	localAddr = peerAddr = INADDR_ANY;
	m_receivedQ931 = NULL;
	m_SetupPDU = NULL;
}


CallSignalSocket::~CallSignalSocket()
{
	PTRACE(1,"Trying Deletion CallSignalSocket " << this << " with condition: " << PString(m_usedCondition.Condition() ? "TRUE" : "FALSE"));
	PTRACE(1, "Name(): " << Name());

	m_lock.Wait();

	if(callptr(NULL)!=m_call) {
		PTRACE(5, "Deleting Call " << m_call->GetCallIdentifier());
		m_call->RemoveSocket();
		CallTable::Instance()->RemoveCall(m_call);

	}

	if(NULL!=remote) {
		CallSignalSocket *rem=dynamic_cast<CallSignalSocket *>(remote);
		if(NULL!=rem){
			m_lock.Signal();
			rem->m_lock.Wait();
			PTRACE(5, "deleteing remote socket");
			if(NULL!=rem->remote) {
				PAssert(rem->remote==this, "remote->remote != this");
				rem->UnlockUse("CallSignalSocket " + Name() + type);
				remote->SetDeletable();
			}
			rem->m_lock.Signal();
			m_lock.Wait();
		}
		remote=NULL;
	}
	m_lock.Signal();
	PTRACE(5, "Waiting for Condition to come true");
	m_usedCondition.WaitCondition();
	m_lock.Wait();
	if(remote!=NULL)
		remote->remote=NULL;
	remote=NULL;
	m_lock.Signal();

	PTRACE(1,"Deleteing CallSignalSocket " << this);

	delete m_h245handler;
	delete m_receivedQ931;
	delete m_SetupPDU;
	delete m_StatusEnquiryTimer;
	delete m_StatusTimer;

	if (NULL!=m_h245socket) {
		m_h245socket->EndSession();
		m_h245socket->OnSignalingChannelClosed();
		m_h245socket->SetDeletable();
		m_h245socket->UnlockUse("CallSignalSocket " + Name() + type);
		m_h245socket=NULL;
	}

}

CallSignalSocket::CallSignalSocket(CallSignalSocket *socket, WORD peerPort)
	: TCPProxySocket("Q931d", socket, peerPort), m_h245handler(NULL), m_h245socket(NULL), isRoutable(TRUE),
	  m_numbercomplete(FALSE), m_StatusEnquiryTimer(NULL), m_StatusTimer(NULL), m_replytoStatusMessage(TRUE)
{
	m_call = socket->m_call;
	socket->m_lock.Signal();
	m_call->SetSocket(socket, this);
	socket->m_lock.Wait();
	m_crv = (socket->m_crv & 0x7fffu);
	m_receivedQ931 = NULL;
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
	m_SetupPDU = NULL;
	remote->LockUse("CallSignalSocket " + Name() + static_cast<PString>(type));
}

// void
// CallSignalSocket::Lock()
// {
// 	m_lock.Wait();
// }

// void
// CallSignalSocket::Unlock()
// {
// 	m_lock.Signal();
// }

void
CallSignalSocket::LockUse(const PString &name)
{
	PTRACE(5, "Locking " << this << " " << Name());
	PWaitAndSignal lock(m_lock);
	m_usedCondition.Lock(name);
}

void CallSignalSocket::UnlockUse(const PString &name)
{
	PTRACE(5, "UnLocking " << this << " " << Name());
//	PWaitAndSignal lock(m_lock);
	m_usedCondition.Unlock(name);
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
inline void PrintQ931(int, const PString &, const Q931 *, const H225_H323_UserInformation *)
{
	// Nothing to do
}
#endif
} // end of anonymous namespace

void CallSignalSocket::DoRoutingDecision() {
	endptr CalledEP(NULL);
	H225_AliasAddress h225address;
	endptr CallingEP = endptr(NULL);
	if(callptr(NULL)!=m_call)
		CallingEP = m_call->GetCallingEP();

	unsigned rsn;
	isRoutable=FALSE;
	H323SetAliasAddress(CalledNumber,h225address);

	CalledEP = RegistrationTable::Instance()->getMsgDestination(h225address, CallingEP, rsn);
	if(H225_AdmissionRejectReason::e_incompleteAddress == rsn) {
		PTRACE(5, "DoRoutingDecision() incomplete");
		return;
	}
	if(CalledEP) {
		PTRACE(5, "DoRoutingDecision() complete");
		isRoutable=TRUE;
		// Do CgPNConversion. We need the setup pdu and the setup UUIE (stored in m_SetupPDU)
		CgPNConversion();
		const H225_TransportAddress &ad  = CalledEP->GetCallSignalAddress();
		if (ad.GetTag() == H225_TransportAddress::e_ipAddress) { // IP Address known?
			const H225_TransportAddress_ipAddress & ip = ad;
			peerAddr = PIPSocket::Address(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
			peerPort = ip.m_port;
			localAddr = Toolkit::Instance()->GetRouteTable()->GetLocalAddress(peerAddr);
			//SetPort(peerPort);
			BuildConnection();
		}
		PTRACE(5, "Setting Profile.Number");
		if(callptr(NULL)!=m_call) {
			m_call->GetCalledProfile().SetCalledPN(CalledNumber); // are the dialed digits in international format?
			m_call->GetCalledProfile().SetDialedPN(DialedDigits);
		}
		return;
	}
	if (H225_AdmissionRejectReason::e_incompleteAddress != rsn) {
		PTRACE(1, "DoRoutingDecision() Error");
		if(NULL!=remote) {
			remote->SetDeletable();
			remote->CloseSocket();
			CallSignalSocket *rem = dynamic_cast<CallSignalSocket *>(remote);
			if (NULL!=rem)
				rem->UnlockUse("CallSignalSocket " + Name() + type);
			remote=NULL;
		}
		SetDeletable();
		CloseSocket();

		// Disconnect
	}
}

void CallSignalSocket::SendInformationMessages() {
	if (NULL !=GetSetupPDU()) {
		GetSetupPDU()->Encode(buffer);
		if(!ForwardData())
			return;
		PTRACE(5, "fake setup sent" << *GetSetupPDU());
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
//		delete m_SetupPDU;
//		m_SetupPDU = NULL;
	}
}

void CallSignalSocket::BuildConnection() {
	unsigned plan,type;
	Q931 * pdu=GetSetupPDU();// Q931InformationMessages[0];
	PString calledDigit;
	pdu->GetCalledPartyNumber(calledDigit, &plan, &type);
	pdu->SetCalledPartyNumber(DialedDigits,plan,type);
	m_SetupPDU=pdu;
	remote=new CallSignalSocket(this, peerPort);
	CallSignalSocket *rem = dynamic_cast<CallSignalSocket *> (remote);
	if(NULL!=rem)
		rem->LockUse("CallSignalSocket " + Name() + type);
}

TCPProxySocket *CallSignalSocket::ConnectTo()
{
	if (peerAddr == Address("0.0.0.0")) {
		if (NULL!=remote) {
			CallSignalSocket *rem = dynamic_cast<CallSignalSocket *>(remote);
			if(NULL!=rem)
				rem->SetConnected(false);
			else
				remote->SetConnected(false);
		}
		SetConnected(true);
		Q931 & pdu = *(GetSetupPDU());
		FakeSetupACK(pdu);
		MarkBlocked(false);
		return NULL;
	}
	if(NULL==remote) {
		SetDeletable();
		if(callptr(NULL)!=m_call) {
			m_call->RemoveSocket();
			CallTable::Instance()->RemoveCall(m_call);
		}
		m_call=callptr(NULL);
		return NULL;
	}
	if(!remote->IsConnected()) { // ignore already connected calls
		if (remote->Connect(Q931PortRange.GetPort(),peerAddr)) {
#ifdef WIN32
			PTRACE(3, "Q931(" << GetCurrentThreadId() << ") Connect to " << peerAddr << " successful");
#else
			PTRACE(3, "Q931(" << getpid() << ") Connect to " << peerAddr << " successful");
#endif
			SetConnected(true);
			CallSignalSocket *rem = dynamic_cast<CallSignalSocket *>(remote);
			if(NULL!=rem)
				rem->SetConnected(false);
			else
				remote->SetConnected(true);
			SendInformationMessages();
		} else {
			PTRACE(3, "Q931\t" << peerAddr << " DIDN'T ACCEPT THE CALL");
			InternalEndSession();
			remote->SetDeletable(); // do not delete.
			CallSignalSocket *rem = dynamic_cast<CallSignalSocket *> (remote);
			if (NULL!=rem)
				rem->UnlockUse("CallSignalSocket " + Name() + type);
			remote=NULL;
			if(callptr(NULL)!=m_call) {
				m_call->RemoveSocket();
				CallTable::Instance()->RemoveCall(m_call);
			}
			m_call=callptr(NULL);
			MarkBlocked(false);
			SetDeletable();
			return NULL;
		}
	}
       	if (remote->IsConnected())
		ForwardData();
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
       if (callptr(NULL)!=m_call) {
	       uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_callIdentifier);
               uuie.m_callIdentifier = m_call->GetCallIdentifier();
       }
       PPER_Stream strm;
       signal.Encode(strm);
       strm.CompleteEncoding();

       ReleasePDU.BuildReleaseComplete(m_crv, m_crv & 0x8000u);
       ReleasePDU.SetIE(Q931::UserUserIE, strm);
       if(callptr(NULL)!=m_call && m_call->GetCalledProfile().ReleaseCauseIsSet())
	       ReleasePDU.SetCause(m_call->GetCalledProfile().GetReleaseCause());
}

void CallSignalSocket::SendReleaseComplete(const enum Q931::CauseValues cause)
{
	PTRACE(5, "void CallSignalSocket::SendReleaseComplete(const enum Q931::CauseValues cause)");
	PWaitAndSignal lock(m_lock);
	InternalSendReleaseComplete(cause);
}

void
CallSignalSocket::InternalSendReleaseComplete(const enum Q931::CauseValues cause)
{
	PTRACE(5, "void CallSignalSocket::InternalSendReleaseComplete(const enum Q931::CauseValues cause)");
	if (IsOpen()) {
		Q931 ReleasePDU;
		BuildReleasePDU(ReleasePDU);
		ReleasePDU.SetCause(cause);
		ReleasePDU.Encode(buffer);
		PTRACE(5, "GK\tSend Release Complete to " << Name());
		TransmitData();
		PrintQ931(6, "Sending ", &ReleasePDU, 0);
	}
}

bool CallSignalSocket::EndSession()
{
	PWaitAndSignal lock(m_lock);
	return InternalEndSession();
}

bool
CallSignalSocket::InternalEndSession()
{
	PTRACE(5, "Endsession");
	if(callptr(NULL)!=m_call  && m_call->GetCalledProfile().ReleaseCauseIsSet())
		InternalSendReleaseComplete(m_call->GetCalledProfile().GetReleaseCause());
	else
		InternalSendReleaseComplete(Q931::NormalCallClearing);

	m_call=callptr(NULL);
	return TCPProxySocket::EndSession();
}


ProxySocket::Result CallSignalSocket::ReceiveData() {
	PWaitAndSignal lock(m_lock);
	if (!ReadTPKT())
		return NoData;

	Q931 q931pdu;
	if (!q931pdu.Decode(buffer)) {
		PTRACE(4, "Q931\t" << Name() << " ERROR DECODING Q.931!");
		return Error;
	}

	m_receivedQ931 = new Q931(q931pdu);

	PTRACE(1, "Q931\t" << Name() << " Message type: " << q931pdu.GetMessageTypeName());
	PTRACE(3, "Q931\t" << "Received: " << q931pdu.GetMessageTypeName() << " CRV=" << q931pdu.GetCallReference() << " from " << Name());
	PTRACE(4, "Q931\t" << Name() << " Call reference: " << q931pdu.GetCallReference());
	PTRACE(4, "Q931\t" << Name() << " From destination " << q931pdu.IsFromDestination());
	PTRACE(5, "Q931\t" << Name() << " IsRoutable " << isRoutable);
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

		switch (body.GetTag()){
		case H225_H323_UU_PDU_h323_message_body::e_setup:
			m_crv = (q931pdu.GetCallReference() | 0x8000u);
			q931pdu.GetCalledPartyNumber(DialedDigits,&m_calledPLAN, &m_calledTON);
			if (NULL==GetSetupPDU()) {
				m_SetupPDU = new Q931(*(GetReceivedQ931()));
				OnSetup(body);
			}
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
			PTRACE(5, "onstatus");
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
		if(q931pdu.GetMessageType()==Q931::SetupMsg) {
			m_SetupPDU->SetIE(Q931::UserUserIE, sb);
			PPER_Stream fakesetup;
			GetSetupPDU()->Encode(fakesetup);
			q931pdu.Decode(fakesetup);
		}
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
 	if (q931pdu.GetMessageType()==Q931::InformationMsg)
		OnInformationMsg(q931pdu);
	if(isRoutable) {
		q931pdu.Encode(buffer);
		PTRACE(5, ANSI::BGRE << "Q931\nMessage to sent to " << setprecision(2) << q931pdu << ANSI::OFF);
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
			if (callptr(NULL)!=m_call) {
				PTRACE(5, "Removing Call");
				m_call->RemoveSocket();
				CallTable::Instance()->RemoveCall(m_call);
				m_call=callptr(NULL);
				if(NULL!=remote)
					dynamic_cast<CallSignalSocket *> (remote)->m_call=callptr(NULL);
			}
			return Closing;
		case Q931::StatusMsg:
			if(!m_replytoStatusMessage) {
				PTRACE(5, "Not replying StatusMsg");
				m_replytoStatusMessage=TRUE;
				return NoData;
			}
		default:
			return Forwarding;
		}

		if (callptr(NULL)==m_call) {
			PTRACE(3, "Q931\t" << Name() << " Setup destination not found!");
			InternalEndSession();
			SetDeletable();
 			if(NULL!=remote) {
				remote->SetDeletable();
				CallSignalSocket *rem = dynamic_cast<CallSignalSocket *> (remote);
				if (NULL!=rem)
					rem->UnlockUse("CallSignalSocket " + Name() + type);
				remote=NULL;
			}
			return Error;
		}

		// NB: Check for routable number
		if ((peerAddr == INADDR_ANY) && (isRoutable)) {
			PTRACE(3, "Q931\t" << Name() << " INVALID ADDRESS");
			m_call->GetCalledProfile().SetReleaseCause(Q931::NoRouteToDestination);
			InternalEndSession();
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
		if (GetReceivedQ931()->GetCalledPartyNumber(DialedDigits, &m_calledPLAN, &m_calledTON)) {
			// Setup_UUIE doesn't contain any destination information, but Q.931 has CalledPartyNumber
			// We create the destinationAddress according to it
			Setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			Setup.m_destinationAddress.SetSize(1);
			H323SetAliasAddress(DialedDigits, Setup.m_destinationAddress[0]);
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
	Address fromIP;
	GetPeerAddress(fromIP);

	isRoutable=FALSE;

	if (m_call) {
		if (m_call->IsRegistered()) {
			if (Toolkit::Instance()->GkClientIsRegistered() && Toolkit::Instance()->GetGkClient().CheckGKIP(fromIP)) {
				PTRACE(2, "Q931\tWarning: a registered call from my GK(" << Name() << ')');
				m_call = callptr(NULL);  // reject it
				return;
			}
			Toolkit::Instance()->GetGkClient().RewriteE164(*GetReceivedQ931(), Setup, true);
		}
	} else {
		bool fromParent;
		if (!Toolkit::Instance()->GetMasterRASListener().AcceptUnregisteredCalls(fromIP, fromParent)) {
			PTRACE(3, "Q931\tNo CallRec found in CallTable for callid " << callid);
			PTRACE(3, "Call was " << (fromParent ? "" : "not " ) << "from Parent");
			return;
		}
		if (fromParent)
			Toolkit::Instance()->GetGkClient().RewriteE164(*GetReceivedQ931(), Setup, false);

		endptr called;
		PString destinationString;

		endptr callingEP = GetCgEP(*GetSetupPDU());

		if (endptr(NULL)==callingEP) {
			PTRACE(1, "Unknown Calling Party -- giving up");
			return ;
		}

		// Rewrite sourceString

		PString sourceString(Setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress) ? AsString(Setup.m_sourceAddress) : PString());
		CallRec *call = new CallRec(Setup.m_callIdentifier, Setup.m_conferenceID, destinationString, sourceString, 0, Toolkit::Instance()->GetMasterRASListener().IsGKRoutedH245());

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
			m_call->RemoveSocket();
			CallTable::Instance()->RemoveCall(m_call);
			m_call=callptr(NULL); // delete callrec

			PTRACE(3, "Q931\tDestination not found for the unregistered call " << callid);
			return;
		}

		if(called) {
			call->SetCalled(called, m_crv);
		} else {
			m_numbercomplete = FALSE;
		}
		if (fromParent) {
			call->SetRegistered(true);
			Toolkit::Instance()->GetGkClient().SendARQ(Setup, m_crv, m_call);
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
			PTRACE(5, "OnSetup: call should be routable");
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

			for (PINDEX i=0; i<Setup.m_destinationAddress.GetSize() && !isRoutable; i++) {
				PTRACE(5, "Setup.m_destinationAddress[" << i << "]: " << Setup.m_destinationAddress[i]);

				DialedDigits = H323GetAliasAddressString(Setup.m_destinationAddress[i]);
 				H225_AliasAddress h225address;
 				H323SetAliasAddress(DialedDigits,h225address);
				unsigned rsn;
				endptr CalledEP = RegistrationTable::Instance()->getMsgDestination(h225address, m_call->GetCallingEP(), rsn);
				if(CalledEP && (H225_AdmissionRejectReason::e_incompleteAddress != rsn) ) {
					isRoutable=TRUE;
					H323SetAliasAddress(m_call->GetCalledPartyNumber(), Setup.m_destinationAddress[i]);
				} else {
					m_numbercomplete = FALSE;
				}
				PTRACE(5,"isRoutable: " << isRoutable);
				PTRACE(5,"DialedDigits: " << DialedDigits );
			}
		}
	}
	if (addr && addr->GetTag() == H225_TransportAddress::e_ipAddress) {
		isRoutable = TRUE;
	}
	if (isRoutable) {
 		if(m_call->GetCallingProfile().GetH323ID().IsEmpty()) {
			PTRACE(5, "m_call->GetCallingProfile() " <<" H323ID: " << m_call->GetCallingProfile().GetH323ID());
			m_call->GetCallingProfile().debugPrint();
			PTRACE(1, "Removing unknown call");
			m_call->GetCallingProfile().debugPrint();
			m_call->RemoveSocket();
			CallTable::Instance()->RemoveCall(m_call);
			m_call=callptr(NULL);
			return;
		}
		CgPNConversion();
		m_call->GetCallingProfile().debugPrint();
		if(callptr(NULL)==m_call) {
			PTRACE(1, "Removing unknown call");
			return;
		}
		if(NULL==addr) {
			m_call->RemoveSocket();
			m_call=callptr(NULL);
			return;
		}
		const H225_TransportAddress_ipAddress & ip = *addr;
		peerAddr = PIPSocket::Address(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
		peerPort = ip.m_port;
		Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
		Setup.m_sourceCallSignalAddress = Toolkit::Instance()->GetMasterRASListener().GetCallSignalAddress(peerAddr);
		H225_TransportAddress_ipAddress & cip = Setup.m_sourceCallSignalAddress;
		localAddr = PIPSocket::Address(cip.m_ip[0], cip.m_ip[1], cip.m_ip[2], cip.m_ip[3]);
		remote = new CallSignalSocket(this, peerPort);
		CallSignalSocket *rem = dynamic_cast<CallSignalSocket*>(remote);
		if(NULL!=rem)
			rem->LockUse("CallSignalSocket " + Name() + type);
	} else { // Overlap Sending
		// re-route called endpoint signalling messages to gatekeeper
		Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
		Setup.m_sourceCallSignalAddress = SocketToH225TransportAddr(localAddr, GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_CALL_SIGNAL_PORT));
		if(GetSetupPDU()->HasIE(Q931::CalledPartyNumberIE)) {
			GetSetupPDU()->GetCalledPartyNumber(DialedDigits,&m_calledPLAN,&m_calledTON);
		}
		remote=NULL;
	}

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
}

void CallSignalSocket::OnInformationMsg(Q931 &pdu){
	// Collect digits
	if (!m_numbercomplete && pdu.HasIE(Q931::CalledPartyNumberIE)) {
		PString calledDigit;
		unsigned plan,type;
		if(pdu.GetCalledPartyNumber(calledDigit, &plan, &type)) {
			DialedDigits+=calledDigit;
			CalledNumber=DialedDigits;
			Toolkit::Instance()->RewritePString(CalledNumber);
			GetSetupPDU()->SetCalledPartyNumber(DialedDigits,m_calledPLAN,m_calledTON);
			if(!isRoutable)
				DoRoutingDecision();
			else {
				PTRACE(5, "Setting Profile.Number");
				m_call->GetCalledProfile().SetCalledPN(CalledNumber); // are the dialed digits in international format?
				m_call->GetCalledProfile().SetDialedPN(DialedDigits, static_cast <Q931::NumberingPlanCodes> (m_calledPLAN),
								       static_cast<Q931::TypeOfNumberCodes> (m_calledTON));
			}
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
	PTRACE(5, "Got ConnectIE");
#ifndef NDEBUG
	if (!Connect.HasOptionalField(H225_Connect_UUIE::e_callIdentifier)) {
		PTRACE(1, "Q931\tConnect_UUIE doesn't contain CallIdentifier!");
	} else if (m_call!=callptr(NULL) && m_call->GetCallIdentifier() != Connect.m_callIdentifier) {
		PTRACE(1, "Q931\tWarning: CallIdentifier doesn't match?");
	}
#endif
	if (!m_numbercomplete) {
		if (callptr(NULL)==m_call) {// hmm... it should not be null
			SetDeletable();
			if(NULL!=remote) {
				remote->SetDeletable();
				CallSignalSocket *rem = dynamic_cast<CallSignalSocket *> (remote);
				if (NULL!=rem)
					rem->UnlockUse("CallSignalSocket " + Name() + type);
				remote=NULL;
			}
			return;
		}
		m_call->SetConnected(true);

		// Stop collecting numbers. the telno is complete
		m_numbercomplete = TRUE;
		CallSignalSocket *rem = dynamic_cast<CallSignalSocket *> (remote);
		if(NULL!=rem) {
			rem->LockUse("CallSignalSocket " + Name() + type);
			rem->CgPNConversion();
			PTRACE(5, "Setting DialedPN");
			m_call->GetCalledProfile().SetDialedPN(rem->DialedDigits, static_cast<Q931::NumberingPlanCodes> (rem->m_calledPLAN),
							       static_cast<Q931::TypeOfNumberCodes> (rem->m_calledTON));
			rem->UnlockUse("CallSignalSocket " + Name() + type);
		}
	}
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
	PTRACE(5, "releaseComplete");
	if(callptr(NULL)!=m_call) {
		m_call->GetCalledProfile().SetReleaseCause(static_cast<Q931::CauseValues> (ReleaseComplete.m_reason.GetTag()));
		m_call->SetDisconnected();
	}
	PTRACE(5, "releaseComplete");
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
	// reset timer
	PTRACE(5, "OnStatus: " << *m_StatusTimer << ": " << this);
	if(NULL != m_StatusTimer) {
		m_replytoStatusMessage=FALSE;
		PTRACE(5, "StatusTimer stopped" << this);
		m_StatusTimer->Stop();
		delete m_StatusTimer;
		m_StatusTimer=NULL;
	}
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
	if (NULL==ret) {
		ret->LockUse("CallSignalSocket " + Name() + type);
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
		ret->UnlockUse("CallSignalSocket " + Name() + type);
		m_h245socket->SetH245Address(h245addr, localAddr);
		GetHandler()->ConnectTo(m_h245socket);
	} else {
		PTRACE(2, "H245\t" << Name() << " no remote party?");
		return false;
	}

	return true;
}

void CallSignalSocket::SetTimer(PTimeInterval timer) {
	if(NULL!=m_StatusEnquiryTimer)
		delete m_StatusEnquiryTimer;
	m_StatusEnquiryTimer = new PTimer();
	m_timeout=timer;
}

void CallSignalSocket::StartTimer() {
	if(NULL != m_StatusEnquiryTimer) {
		m_StatusEnquiryTimer->SetNotifier(PCREATE_NOTIFIER(OnTimeout));
		m_StatusEnquiryTimer->RunContinuous(m_timeout);
	}
}

void CallSignalSocket::StopTimer() {
	if(NULL != m_StatusEnquiryTimer)
		m_StatusEnquiryTimer->Stop();
}

void CallSignalSocket::OnTimeout() {
	// Simply do nothing?
}

void CallSignalSocket::SendStatusEnquiryMessage() {
	PTRACE(1, "Sending Message" << this);
	PWaitAndSignal lock(m_lock);
	m_StatusEnquiryTimer->Pause();
	Q931 pdu;
	pdu.BuildStatusEnquiry(m_crv, NULL==GetSetupPDU());
	pdu.Encode(buffer);
	if(TransmitData()) {
		m_StatusTimer = new PTimer(0,4); // This is Q.931 timer T322
		m_StatusTimer->SetNotifier(PCREATE_NOTIFIER(OnTimeout));
	} else {
		if(NULL!=remote)
			dynamic_cast<CallSignalSocket *> (remote)->InternalSendReleaseComplete(Q931::DestinationOutOfOrder);
		if(callptr(NULL)!=m_call) {
			m_call->GetCalledProfile().SetReleaseCause(Q931::DestinationOutOfOrder);
			if(NULL!=remote) {
				remote->SetDeletable();
				CallSignalSocket *rem = dynamic_cast<CallSignalSocket *> (remote);
				if (NULL!=rem)
					rem->UnlockUse("CallSignalSocket " + Name() + type);
			}
			remote=NULL;
		}
		if(callptr(NULL)!=m_call) {
			m_call->RemoveSocket();
			CallTable::Instance()->RemoveCall(m_call);
		}
		m_call=callptr(NULL);
		return;
	}
	m_StatusEnquiryTimer->Resume();
}

void CallSignalSocket::OnTimeout(PTimer & timer, int extra) {
	PTRACE(5, "timer reached" << this);
	PWaitAndSignal lock(m_lock);
	if (NULL!=m_StatusEnquiryTimer && timer==*m_StatusEnquiryTimer) {
		SendStatusEnquiryMessage();
	}
	if (NULL!= m_StatusTimer && timer==*m_StatusTimer) {
		if(NULL!=remote)
			dynamic_cast<CallSignalSocket *> (remote)->InternalSendReleaseComplete(Q931::NoRouteToDestination);
		if(callptr(NULL)!=m_call) {
			PTRACE(5, "setting failure codes");
			m_call->GetCalledProfile().SetReleaseCause(Q931::NoRouteToDestination);
			PTRACE(5, "setting failure codes");
		}
		PTRACE(5, "removing Call");
		if(callptr(NULL)!=m_call) {
			m_call->RemoveSocket();
			CallTable::Instance()->RemoveCall(m_call);
		}
		m_call=callptr(NULL);
		if (NULL!=remote) {
			remote->SetDeletable();
			CallSignalSocket *rem = dynamic_cast<CallSignalSocket *> (remote);
			if (NULL!=rem)
				rem->UnlockUse("CallSignalSocket " + Name() + type);
		}
		remote=NULL;
	}
	if(!IsConnected()) {
		dynamic_cast<CallSignalSocket *> (remote)->SendReleaseComplete();
		if(callptr(NULL)!=m_call) {
			m_call->RemoveSocket();
			CallTable::Instance()->RemoveCall(m_call);
		}
		m_call=callptr(NULL);
	}
}

void CallSignalSocket::SetConnected(bool c) {
	ProxySocket::SetConnected(c);
	if (c) {
		PTRACE(5, "Setting Timer" << this);
		PTimeInterval timer  = (NULL==GetSetupPDU() ?
					m_call->GetCalledProfile().GetStatusEnquiryInterval() :
					m_call->GetCallingProfile().GetStatusEnquiryInterval());
		SetTimer(timer);
		StartTimer();
	} else {
		StopTimer();
	}
}

void PrintCallingPartyNumber(PString callingPN, unsigned npi, unsigned ton, unsigned pi, unsigned si) {

	PString out = "\t\t\t\t\t\t\t\t\tPN: " + callingPN;
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

        PTRACE(5, "Set PartyNumber" << endl << out);
}



static BOOL MatchAlias(const CallProfile &profile, const PString number);
static BOOL ConvertNumberInternational(PString & number, unsigned int &TON, unsigned int & plan, unsigned int & SI, const CallProfile & profile);

BOOL CallSignalSocket::CgPNConversion() {
	// The variables to store the needed information:
	PString CallingPartyNumber;
	PString CalledPartyNumber;
	PString CalledPartyNumberDD; // Not necessary Dialed Digits, but the Number from the Setup/Information messages
	unsigned int CallingTON    = 0;
	unsigned int CalledTON     = 0;
	unsigned int CallingPLAN   = 0;
	unsigned int CalledPLAN    = 0;
	unsigned int CallingSI     = 0;
	unsigned int CalledSI      = 0;
	unsigned int CallingPI     = 0;

	if(callptr(NULL) == m_call)
		return FALSE;
	PTRACE(5, "Beginning CgPNConversion()");
	CallingProfile & cgpf = m_call->GetCallingProfile();
	CalledProfile & cdpf = m_call->GetCalledProfile();
	// Check if CallingPartyNumber is provided.
	if (GetSetupPDU()->GetCallingPartyNumber(CallingPartyNumber, &CallingPLAN, &CallingTON, &CallingPI,&CallingSI)) {
		// Convert CallingPartyNumber to international Format.
		CallingTON=((cgpf.TreatCallingPartyNumberAs()==CallProfile::LeaveUntouched) ? CallingTON : cgpf.TreatCallingPartyNumberAs());
		ConvertNumberInternational(CallingPartyNumber, CallingPLAN, CallingTON, CallingSI, cgpf);
		PTRACE(5, "CgPNConversion converted CallingPartyNumber to int: " << CallingPartyNumber << " with TON: " << CallingTON);

		// If number is provided by peer network all our work is done now.
		// If the call is initiated by a CPE, we'll have to check the number
		if(cgpf.IsCPE()) {
			// Match agains the telephonenumber in Profile
			PTRACE(5, "Calling EP is CPE");
			if(!MatchAlias(cgpf, CallingPartyNumber)) {
				// The number is not possible / right, so we have to provide a number.
				CallingPartyNumber=cgpf.GetMainTelephoneNumber();
				CallingTON=Q931::InternationalType;
				CallingPLAN=Q931::ISDNPlan;
				CallingSI=H225_ScreeningIndicator::e_networkProvided;
			} else {
				CallingSI=H225_ScreeningIndicator::e_userProvidedVerifiedAndPassed;
			}
		}
	} else {
		// No CallingPartyNumber provided
		CallingPartyNumber=cgpf.GetMainTelephoneNumber();
		if(CallingPartyNumber.IsEmpty()) {
			// we cannot provide any number
			CallingTON=Q931::UnknownType;
			CallingPLAN=Q931::UnknownPlan;
			CallingSI=H225_ScreeningIndicator::e_userProvidedVerifiedAndFailed;
		} else {
			CallingTON=Q931::InternationalType;
			CallingPLAN=Q931::ISDNPlan;
			CallingSI=H225_ScreeningIndicator::e_networkProvided;
		}
	}

	if(!(cgpf.GetClir().IsEmpty())) {
		if(cgpf.GetClir() == "TRUE") {
			CallingPI=H225_PresentationIndicator::e_presentationRestricted;
		} else {
			CallingPI=H225_PresentationIndicator::e_presentationAllowed;
		}
	}
	// we are done with converting the CallingPN to international.

	if (! GetSetupPDU()->GetCalledPartyNumber(CalledPartyNumber, &CalledPLAN, &CalledTON)) {
		PTRACE(1, "Could not get CalledPartyNumberIE from setup PDU. \t Aborting NumberConversion");
		return false;
	}
	if(DialedDigits.IsEmpty()) { // The initial Setup did not contain any number. This should not happen.
		DialedDigits = CalledPartyNumber;
		m_calledPLAN = CalledPLAN;
		m_calledTON = CalledTON;
	}
	PTRACE(5, "CgPNConversion read CalledPartyNumber: " << CalledPartyNumber << " with TON: " << CalledTON << "preparing to change: " << cgpf.TreatCalledPartyNumberAs());
	CalledTON=((cgpf.TreatCalledPartyNumberAs()==CallProfile::LeaveUntouched) ? CalledTON : cgpf.TreatCalledPartyNumberAs());
	PTRACE(5, "CgPNConversion read CalledPartyNumber: " << CalledPartyNumber << " with TON: " << CalledTON);
	ConvertNumberInternational(CalledPartyNumber, CalledPLAN, CalledTON, CalledSI, cgpf);
	PTRACE(5, "CgPNConversion converted CalledPartyNumber to int: " << CalledPartyNumber << " with TON: " << CalledTON);
	// Check wether we are fooled with different ARQ-Number.
	// we check only the left part we already have, because the ARQ could have provided one digit less than
	// the setup.
	// Sorry for the awful truth value...
#if (PARANOIA_CHECK_REDIRECT==1)
	if((!cdpf.GetCalledPN().IsEmpty()) && (cdpf.GetCalledPN().GetLength() > CalledPartyNumber.GetLength()) && // shrink of Number
	     (cdpf.GetCalledPN() != CalledPartyNumber.Left(cdpf.GetCalledPN().GetSize()))) {
		// Is the call redirected by network?
		if(GetSetupPDU()->HasIE(Q931::RedirectingNumberIE)) {
			PString redirectionPN;
			unsigned int redirectionPLAN, redirectionTON, redirectionPI, redirectionSI, redirectionReason;
			GetSetupPDU()->GetRedirectingNumber(redirectionPN, &redirectionPLAN, &redirectionTON, &redirectionPI, &redirectionSI, &redirectionReason);
			PTRACE(5, "Redirected Call received. Redirection: " << redirectionPN << "numeric Reason: " << redirectionReason);
			if((cdpf.GetCalledPN().GetSize() <=  redirectionPN.GetSize()) &&
			   (cdpf.GetCalledPN() == redirectionPN.Left(cdpf.GetCalledPN().GetSize()))) {
				// Ok, redirection is done by the right party
				// Not yet implemented
				PAssertAlways("Sorry, implementation missing");
				// cdpf.SetRedirection(redirectionPN, redirectionPLAN, redirectionTON, redirectionPI, redirectionSI, redirectionReason);
			} else {
				// redirection is faked!
				PTRACE(1, "Redirection is faked by " << redirectionPN << ". Aborting call");
				m_call=callptr(NULL);
				return FALSE;
			}
		} else {
			PTRACE(1, "Mismatch between ARQ and Setup. Aborting Call");
			PTRACE(1, "Profile says: " << cdpf.GetCalledPN() << "is empty: " <<
			       cdpf.GetCalledPN().IsEmpty() << "dialed Number: " << CalledPartyNumber);
			m_call=callptr(NULL);
			return FALSE;
		}
	}
#endif
	E164_AnalysedNumber CalledE164Number=CalledPartyNumber;
	E164_AnalysedNumber CallingE164Number=CallingPartyNumber;
	if (cdpf.ConvertToLocal() && CalledE164Number.GetCC() == CallingE164Number.GetCC()) {
		if (CalledE164Number.GetNDC_IC() == CallingE164Number.GetNDC_IC()) {
			// Convert to local
			CalledPartyNumber = CalledE164Number.GetGSN_SN();
			CalledTON = Q931::SubscriberType;
			CallingPartyNumber = CalledE164Number.GetGSN_SN();
			CallingTON = Q931::SubscriberType;

		} else {
			// Convert to National
			CalledPartyNumber = PString(CalledE164Number.GetNDC_IC()) + PString(CalledE164Number.GetGSN_SN());
			CalledTON = Q931::NationalType;
			CallingPartyNumber = PString(CallingE164Number.GetNDC_IC()) + PString(CalledE164Number.GetGSN_SN());
			CallingTON = Q931::NationalType;
		}
	}
	// Convert PartyNumber to dialable Digits
	if(cdpf.GetPrependCallbackAC()) {
		switch (CalledTON) {
		case Q931::InternationalType:
			CalledPartyNumber = cdpf.GetInac() + CalledPartyNumber;
			CalledTON=Q931::UnknownType;
			break;
		case Q931::NationalType:
			CalledPartyNumber = cdpf.GetNac() + CalledPartyNumber;
			CalledTON=Q931::UnknownType;
			break;
		default:
			// simply do nothing
			break;
		}
	}
	// Do CallingPartyNumber suppression
	if(cdpf.IsCPE() && ((CallingPI == H225_PresentationIndicator::e_presentationRestricted) ||
			    (CallingSI == H225_ScreeningIndicator::e_userProvidedVerifiedAndFailed) ||
			    (CallingSI == H225_ScreeningIndicator::e_userProvidedNotScreened))) {
		CallingPartyNumber = "";
		CallingPLAN = Q931::UnknownPlan;
		CallingTON = Q931::UnknownType;
	}

	// Now reassemble the Setup PDU
//	m_SetupPDU->RemoveIE(Q931::CallingPartyNumberIE);
	m_SetupPDU->SetCallingPartyNumber(CallingPartyNumber,
					  CallingPLAN,
					  CallingTON,
					  CallingPI,
					  CallingSI);
	PTRACE(5, "CallingPN");
	PrintCallingPartyNumber(CallingPartyNumber, CallingPLAN, CallingTON, CallingPI, CallingSI);
//	m_SetupPDU->RemoveIE(Q931::CalledPartyNumberIE);
	m_SetupPDU->SetCalledPartyNumber(CalledPartyNumber,
					 CalledPLAN,
					 CalledTON);
	PTRACE(5, "CalledPN");
	PrintCallingPartyNumber(CalledPartyNumber, CalledPLAN, CalledTON, 0, 0);
	cdpf.SetCallingPN(CallingPartyNumber, static_cast<Q931::NumberingPlanCodes> (CallingPLAN),
			  static_cast<Q931::TypeOfNumberCodes> (CallingTON),
			  static_cast<H225_ScreeningIndicator::Enumerations> (CallingSI),
			  static_cast<H225_PresentationIndicator::Choices> (CallingPI));
	m_call->GetCalledProfile().SetDialedPN(DialedDigits, static_cast<Q931::NumberingPlanCodes> (m_calledPLAN),
					       static_cast<Q931::TypeOfNumberCodes> (m_calledTON));
	PString dd(DialedDigits);
	Q931::TypeOfNumberCodes assumed_ton = static_cast<Q931::TypeOfNumberCodes>(m_calledTON);
	assumed_ton = static_cast<Q931::TypeOfNumberCodes>((cgpf.TreatCalledPartyNumberAs()==CallProfile::LeaveUntouched) ?
							   static_cast<int>(assumed_ton) : cgpf.TreatCalledPartyNumberAs());
	if(assumed_ton==Q931::UnknownType)
		assumed_ton = Toolkit::Instance()->GetRewriteTool().PrefixAnalysis(dd, cgpf);
	m_call->GetCalledProfile().SetAssumedDialedPN(dd, static_cast<Q931::NumberingPlanCodes> (m_calledPLAN), assumed_ton);
	m_call->GetCalledProfile().SetCalledPN(CalledPartyNumber);
	CalledNumber=CalledPartyNumber;
	return TRUE;
}

BOOL MatchAlias(const CallProfile &profile, PString number) {
	PStringList telephonenumbers = profile.GetTelephoneNumbers();
	PString complete_number = number ;
	int matches=0;

	for(PINDEX i=0; i< telephonenumbers.GetSize(); i++) {
		if(telephonenumbers[i].GetLength() >= number.GetLength()) {
			unsigned int amountPoints = 0;
			int first_point = telephonenumbers[i].Find('.');
			if( first_point != P_MAX_INDEX && first_point >= 0)
				amountPoints = telephonenumbers[i].GetLength() - first_point;

			PTRACE(5,"amountPoints: " << amountPoints);
			if(0 == amountPoints && number == telephonenumbers[i].Right(number.GetLength())) {
				// we found a match -- let's do a sanity check, wether is in international format
				PTRACE(5,"matches nubmer " << telephonenumbers[i]);
				if (number.GetLength() == telephonenumbers[i].GetLength()) {
					PTRACE(5, "fullmatch");
					return TRUE;
				} else {
					PTRACE(5, "partial match");
					complete_number=telephonenumbers[i];
					matches++;
				}
			} else if(0 < amountPoints) {
				if(number.GetLength()>amountPoints) {
					int overlap_digits = number.GetLength() - amountPoints; // the "significant" numbers
					if (number.Left(overlap_digits) == telephonenumbers[i].Mid(first_point-overlap_digits, overlap_digits)) {
						// Some of the mid overlaps. we have a match
						matches++;
						complete_number = telephonenumbers[i].Left(telephonenumbers[i].GetLength() - amountPoints)
							+ number.Right(amountPoints);
					}
				} else if (number.GetLength()==amountPoints) {
					// This matches in any case.
					matches++;
					complete_number = telephonenumbers[i].Left(telephonenumbers[i].GetLength() - amountPoints)
						+ number;
				} // else no match
			}
		}
	}
	// now check if exatly 1 match was found.

	if(1==matches) {
		number=complete_number;
		return TRUE;
	}
	return FALSE;
}

BOOL
ConvertNumberInternational(PString & number, unsigned int & plan, unsigned int &TON, unsigned int & SI, const CallProfile & profile)
{
	Q931::NumberingPlanCodes pl = static_cast <Q931::NumberingPlanCodes> (plan);
	Q931::TypeOfNumberCodes tn  = static_cast <Q931::TypeOfNumberCodes> (TON);
	H225_ScreeningIndicator::Enumerations screening = static_cast <H225_ScreeningIndicator::Enumerations> (SI);
	BOOL result = Toolkit::Instance()->GetRewriteTool().PrefixAnalysis(number, pl, tn, screening, profile);
	plan=pl;
	TON=tn;
	SI=screening;
	return result;
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
	listener->Listen(1, H245PortRange.GetPort());
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
	PWaitAndSignal lock(m_lock);
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
		if (Connect(H245PortRange.GetPort(), peerAddr)) {
#ifdef WIN32
			PTRACE(3, "H245(" << GetCurrentThreadId() << ") Connect to " << Name() << " successful");
#else
			PTRACE(3, "H245(" << getpid() << ") Connect to " << Name() << " successful");
#endif
			GetHandler()->Insert(this);
			SetConnected(true);
			CallSignalSocket *rem=dynamic_cast<CallSignalSocket *> (remote);
			if(NULL!=rem) {
				rem->SetConnected(true);
			} else {
				remote->SetConnected(true);
			}
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

void
H245Socket::Lock()
{
	m_lock.Wait();
}

void
H245Socket::Unlock()
{
	m_lock.Signal();
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

inline bool compare_lc(std::pair<const WORD, RTPLogicalChannel *> p, LogicalChannel *lc)
{
       return p.second == lc;
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
	PTRACE(5, type << "UDP\tForward " << name << " to " << fDestIP << ':' << fDestPort);
	SetConnected(true);
}


void UDPProxySocket::SetReverseDestination(Address srcIP, WORD srcPort, const H245_UnicastAddress_iPAddress & addr)
{
	rSrcIP = srcIP, rSrcPort = srcPort;
	addr >> rDestIP >> rDestPort;

	PTRACE(5, type << "UDP\tReverse " <<  srcIP << ':' << srcPort << " to " << rDestIP << ':' << rDestPort);
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
		PTRACE(6, type << "\tforward " << fromIP << ':' << fromPort << " to " << rDestIP << ':' << rDestPort);
		SetSendAddress(rDestIP, rDestPort);               SetSendAddress(rDestIP, rDestPort);
	} else {
		PTRACE(6, type << "\tforward " << fromIP << ':' << fromPort << " to " << fDestIP << ':' << fDestPort);
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
	if (remote->Connect(T120PortRange.GetPort(), peerAddr)) {
		PTRACE(3, "T120\tConnect to " << remote->Name() << " successful");
		SetConnected(true);
		remote->SetConnected(true);
	} else {
		PTRACE(3, "T120\t" << peerAddr << " DIDN'T ACCEPT THE CALL");
		// delete remote; // would close myself
		remote->SetDeletable();
	}
	return remote;
}

// class RTPLogicalChannel
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
		// don't close the sockets, or it causes crashing
			rtp->SetDeletable();
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
 	WORD port = RTPPortRange.GetPort();
	if (port & 1) // make sure it is even
		port = RTPPortRange.GetPort();
	RTPPortRange.GetPort(); // skip one
	return port;
}

// class T120LogicalChannel
T120LogicalChannel::T120LogicalChannel(WORD flcn) : LogicalChannel(flcn)
{
	listener.Listen(1, T120PortRange.GetPort());
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
	for_each(logicalChannels.begin(), logicalChannels.end(), delete_lc);
	for_each(fastStartLCs.begin(), fastStartLCs.end(), delete_rtplc);
	if (peer)
		peer->peer = 0;

}

bool H245ProxyHandler::HandleRequest(H245_RequestMessage & Request)
{
	PTRACE(4, "H245\tRequest: " << Request.GetTagName());
	if(peer)
		switch (Request.GetTag()) {
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
	if(peer)
		switch (Response.GetTag()) {
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
	if(!peer)
		return false;
	if (hnat)
		hnat->HandleOpenLogicalChannel(olc);
	bool nouse;
	H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse);
	return (h225Params) ? OnLogicalChannelParameters(h225Params, 0) : false;
}

bool H245ProxyHandler::HandleFastStartResponse(H245_OpenLogicalChannel & olc)
{
	if(!peer)
		return false;
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
		} else if ((lc = peer->FindRTPLogicalChannelBySessionID(id)) && !lc->IsAttached()) {
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
	} else if ((lc = peer->FindRTPLogicalChannelBySessionID(id)) && !lc->IsAttached()) {
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
		LogicalChannel *lc = iter->second;
               siterator i = find_if(sessionIDs.begin(), sessionIDs.end(), bind2nd(ptr_fun(compare_lc), lc));
               if (i != sessionIDs.end())
                       sessionIDs.erase(i);
               logicalChannels.erase(iter);
	       delete lc;
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
	Q931PortRange.LoadConfig(RoutedSec, "Q931PortRange");
	H245PortRange.LoadConfig(RoutedSec, "H245PortRange");
	T120PortRange.LoadConfig(ProxySection, "T120PortRange");
	RTPPortRange.LoadConfig(ProxySection, "RTPPortRange", "10000-59999");

	WORD port = GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_CALL_SIGNAL_PORT);
	if (!listenerThread || (GKPort != port)) {
		CloseListener();
		unsigned queueSize = GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH);
		listenerThread = new ProxyListener(this, GKHome, port ? port : Q931PortRange.GetPort(), queueSize);
		GKPort = port;
	}

	// the handler number can only be increased
	int s = GkConfig()->GetInteger(RoutedSec, "CallSignalHandlerNumber", 1);
	for (int i = handlers.size(); i < s; ++i)
		handlers.push_back(new ProxyHandleThread(i));
}
