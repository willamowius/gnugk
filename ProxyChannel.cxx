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

#include <ptlib.h>
#include <q931.h>
#include <h245.h>
#include <h323pdu.h>
#include "gk.h"
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "stl_supp.h"
#include "RasTbl.h"
#include "gkacct.h"
#include "RasSrv.h"
#include "GkClient.h"
#include "Neighbor.h"
#include "ProxyChannel.h"

namespace {
// default timeout (ms) for initial Setup message,
// if not specified in the config file
const long DEFAULT_SETUP_TIMEOUT = 8000;
}

const char* RoutedSec = "RoutedMode";
const char* ProxySection = "Proxy";
const char* H225_ProtocolID = "0.0.8.2250.0.2";

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
	if (port == 0)
		return 0;
	PWaitAndSignal lock(mutex);
	WORD result = port++;
	if (port > maxport)
		port = minport;
	return result;
}

void PortRange::LoadConfig(const char *sec, const char *setting, const char *def)
{
	PStringArray cfgs = GkConfig()->GetString(sec, setting, def).Tokenise(",.:-/'", FALSE);
	if (cfgs.GetSize() >= 2) // no such a setting in config
		port = minport = (WORD)cfgs[0].AsUnsigned(), maxport = (WORD)cfgs[1].AsUnsigned();
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
#ifndef LARGE_FDSET
	PCLASSINFO ( H245Socket, TCPProxySocket )
#endif

	H245Socket(CallSignalSocket *);
	H245Socket(H245Socket *, CallSignalSocket *);
	~H245Socket();

	void ConnectTo();

	// override from class ProxySocket
        virtual Result ReceiveData();
	virtual bool EndSession();

	void SendEndSessionCommand();
	H225_TransportAddress GetH245Address(const Address &);
	bool SetH245Address(H225_TransportAddress & h245addr, const Address &);
	bool Reverting(const H225_TransportAddress &);
	void OnSignalingChannelClosed() { sigSocket = 0; }
	void SetSigSocket(CallSignalSocket *socket) { sigSocket = socket; }

protected:
	// override from class TCPProxySocket
#ifdef LARGE_FDSET
	virtual bool Accept(YaTCPSocket &);
#else
	virtual BOOL Accept(PSocket &);
#endif
	// new virtual function
	virtual bool ConnectRemote();

	CallSignalSocket *sigSocket;
	H225_TransportAddress *peerH245Addr;
	TCPSocket *listener;

private:
	// override from class ServerSocket
	virtual void Dispatch() { /* useless */ }
};

class NATH245Socket : public H245Socket {
public:
#ifndef LARGE_FDSET
	PCLASSINFO ( NATH245Socket, H245Socket )
#endif
	NATH245Socket(CallSignalSocket *sig) : H245Socket(sig) {}

private:
	// override from class H245Socket
	virtual bool ConnectRemote();
};

class UDPProxySocket : public UDPSocket, public ProxySocket {
public:
#ifndef LARGE_FDSET
	PCLASSINFO( UDPProxySocket, UDPSocket )
#endif

	UDPProxySocket(const char *);

	void SetDestination(H245_UnicastAddress_iPAddress &);
	void SetForwardDestination(const Address &, WORD, const H245_UnicastAddress_iPAddress &);
	void SetReverseDestination(const Address &, WORD, const H245_UnicastAddress_iPAddress &);
	typedef void (UDPProxySocket::*pMem)(const Address &, WORD, const H245_UnicastAddress_iPAddress &);

	bool Bind(WORD pt);
	void SetNAT(bool);
	void OnHandlerSwapped() { std::swap(fnat, rnat); }

	// override from class ProxySocket
	virtual Result ReceiveData();

protected:
	virtual bool WriteData(const BYTE *, int);
	virtual bool Flush();
	virtual bool ErrorHandler(PSocket::ErrorGroup);

private:
	Address fSrcIP, fDestIP, rSrcIP, rDestIP;
	WORD fSrcPort, fDestPort, rSrcPort, rDestPort;
	bool fnat, rnat;
};

class T120LogicalChannel;

class T120ProxySocket : public TCPProxySocket {
public:
#ifndef LARGE_FDSET
	PCLASSINFO ( T120ProxySocket, TCPProxySocket )
#endif

	T120ProxySocket(T120LogicalChannel *);
	T120ProxySocket(T120ProxySocket * = 0, WORD = 0);

	// override from class ProxySocket
	virtual bool ForwardData();

private:
	// override from class ServerSocket
	virtual void Dispatch();

	T120LogicalChannel *t120lc;
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
	virtual void StartReading(ProxyHandler *) = 0;

protected:
	WORD channelNumber;
	WORD port;
	bool used;
};

class RTPLogicalChannel : public LogicalChannel {
public:
	RTPLogicalChannel(WORD, bool);
	RTPLogicalChannel(RTPLogicalChannel *, WORD, bool);
	virtual ~RTPLogicalChannel();

	void SetMediaChannelSource(const H245_UnicastAddress_iPAddress &);
	void SetMediaControlChannelSource(const H245_UnicastAddress_iPAddress &);
	void HandleMediaChannel(H245_UnicastAddress_iPAddress *, H245_UnicastAddress_iPAddress *, const PIPSocket::Address &, bool);
	bool OnLogicalChannelParameters(H245_H2250LogicalChannelParameters &, const PIPSocket::Address &, bool);

	// override from class LogicalChannel
	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *);
	virtual void StartReading(ProxyHandler *);
	bool IsAttached() const { return (peer != 0); }
	void OnHandlerSwapped(bool);

	class NoPortAvailable {};

private:
	void SetNAT(bool);

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
	virtual void StartReading(ProxyHandler *);

	void Create(T120ProxySocket *);
	bool OnSeparateStack(H245_NetworkAccessParameters &, H245Handler *);

private:
	class T120Listener : public TCPListenSocket {
	public:
		T120Listener(T120LogicalChannel *lc);

	private:
		// override from class TCPListenSocket
		virtual ServerSocket *CreateAcceptor() const;

		T120LogicalChannel *t120lc;
	};

	T120Listener *listener;
	ProxyHandler *handler;
	PIPSocket::Address peerAddr;
	WORD peerPort;
	std::list<T120ProxySocket *> sockets;
	PMutex m_smutex;
};

class NATHandler {
public:
	NATHandler(const PIPSocket::Address & remote) : remoteAddr(remote) {}

	void TranslateH245Address(H225_TransportAddress &);
	bool HandleOpenLogicalChannel(H245_OpenLogicalChannel &);
	bool HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck &);

private:
	bool SetAddress(H245_UnicastAddress_iPAddress *);
	PIPSocket::Address remoteAddr;
};

class H245Handler {
// This class handles H.245 messages which can either be transmitted on their
// own TCP connection or can be tunneled in the Q.931 connection
public:
	H245Handler(const PIPSocket::Address & local, const PIPSocket::Address & remote);
	virtual ~H245Handler();

	virtual void OnH245Address(H225_TransportAddress &);
	virtual bool HandleMesg(PPER_Stream &);
	virtual bool HandleFastStartSetup(H245_OpenLogicalChannel &);
	virtual bool HandleFastStartResponse(H245_OpenLogicalChannel &);
	typedef bool (H245Handler::*pMem)(H245_OpenLogicalChannel &);

	PIPSocket::Address GetLocalAddr() const { return localAddr; }
	void SetLocalAddr(const PIPSocket::Address & local) { localAddr = local; }
	bool IsSessionEnded() const { return isH245ended; }

protected:
	virtual bool HandleRequest(H245_RequestMessage &);
	virtual bool HandleResponse(H245_ResponseMessage &);
	virtual bool HandleCommand(H245_CommandMessage &);
	virtual bool HandleIndication(H245_IndicationMessage &);

	NATHandler *hnat;

private:
	PIPSocket::Address localAddr, remoteAddr;
	bool isH245ended;
};

class H245ProxyHandler : public H245Handler {
public:
	typedef std::map<WORD, LogicalChannel *>::iterator iterator;
	typedef std::map<WORD, LogicalChannel *>::const_iterator const_iterator;
	typedef std::map<WORD, RTPLogicalChannel *>::iterator siterator;
	typedef std::map<WORD, RTPLogicalChannel *>::const_iterator const_siterator;

	H245ProxyHandler(const PIPSocket::Address &, const PIPSocket::Address &, H245ProxyHandler * = 0);
	virtual ~H245ProxyHandler();

	// override from class H245Handler
	virtual bool HandleFastStartSetup(H245_OpenLogicalChannel &);
	virtual bool HandleFastStartResponse(H245_OpenLogicalChannel &);

	void SetHandler(ProxyHandler *);
	LogicalChannel *FindLogicalChannel(WORD);
	RTPLogicalChannel *FindRTPLogicalChannelBySessionID(WORD);

private:
	// override from class H245Handler
	virtual bool HandleRequest(H245_RequestMessage &);
	virtual bool HandleResponse(H245_ResponseMessage &);

	bool OnLogicalChannelParameters(H245_H2250LogicalChannelParameters *, WORD);
	bool HandleOpenLogicalChannel(H245_OpenLogicalChannel &);
	bool HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck &);
	bool HandleOpenLogicalChannelReject(H245_OpenLogicalChannelReject &);
	bool HandleCloseLogicalChannel(H245_CloseLogicalChannel &);

	RTPLogicalChannel *CreateRTPLogicalChannel(WORD, WORD);
	RTPLogicalChannel *CreateFastStartLogicalChannel(WORD);
	T120LogicalChannel *CreateT120LogicalChannel(WORD);
	bool RemoveLogicalChannel(WORD flcn);

	std::map<WORD, LogicalChannel *> logicalChannels;
	std::map<WORD, RTPLogicalChannel *> sessionIDs;
	std::map<WORD, RTPLogicalChannel *> fastStartLCs;
	ProxyHandler *handler;
	H245ProxyHandler *peer;
};


// class ProxySocket
ProxySocket::ProxySocket(IPSocket *s, const char *t) : USocket(s, t)
{
	wbufsize = 1536; // 1.5KB
	wbuffer = new BYTE[wbufsize];
	buflen = 0;
	connected = deletable = false;
}

ProxySocket::~ProxySocket()
{
	delete [] wbuffer;
}

ProxySocket::Result ProxySocket::ReceiveData()
{
	if (!self->Read(wbuffer, wbufsize)) {
		ErrorHandler(PSocket::LastReadError);
		return NoData;
	}
	PTRACE(6, Type() << "\tReading from " << Name());
	buflen = (WORD)self->GetLastReadCount();
	return Forwarding;
}

bool ProxySocket::ForwardData()
{
	return WriteData(wbuffer, buflen);
}

bool ProxySocket::EndSession()
{
	MarkBlocked(false);
//	SetConnected(false);
	return CloseSocket();
}


struct TPKTV3 {
	TPKTV3() {}
	TPKTV3(WORD);

	BYTE header, padding;
	WORD length;
};

inline TPKTV3::TPKTV3(WORD len)
	: header(3), padding(0)
{
	length = PIPSocket::Host2Net(WORD(len + sizeof(TPKTV3)));
}

// class TCPProxySocket
TCPProxySocket::TCPProxySocket(const char *t, TCPProxySocket *s, WORD p)
      : ServerSocket(p), ProxySocket(this, t), remote(s)
{
}

TCPProxySocket::~TCPProxySocket()
{
	if (remote) {
		remote->remote = 0; // detach myself from remote
		remote->SetDeletable();
	}
}

bool TCPProxySocket::ForwardData()
{
	return (remote) ? remote->InternalWrite(buffer) : false;
}

bool TCPProxySocket::TransmitData(const PBYTEArray & buf)
{
	return InternalWrite(buf);
}

#ifndef LARGE_FDSET
BOOL TCPProxySocket::Accept(PSocket & socket)
{
//	SetReadTimeout(PMaxTimeInterval);
	BOOL result = PTCPSocket::Accept(socket);
	PTimeInterval timeout(100);
	SetReadTimeout(timeout);
	SetWriteTimeout(timeout);
	// since GetName() may not work if socket closed,
	// we save it for reference
	Address ip;
	WORD pt;
	GetPeerAddress(ip, pt);
	SetName(AsString(ip, pt));
	return result;
}

BOOL TCPProxySocket::Connect(const Address & iface, WORD localPort, const Address & addr)
{
	SetName(AsString(addr, GetPort()));
	SetReadTimeout(PTimeInterval(6000)); // TODO: read from config...
	BOOL result = PTCPSocket::Connect(iface, localPort, addr);
	PTimeInterval timeout(100);
	SetReadTimeout(timeout);
	SetWriteTimeout(timeout);
	return result;
}

BOOL TCPProxySocket::Connect(const Address & addr)
{
	return Connect(INADDR_ANY, 0, addr);
}

#endif

bool TCPProxySocket::ReadTPKT()
{
	PTRACE(5, Type() << "\tReading from " << GetName());
	if (buflen == 0) {
		TPKTV3 tpkt;
		if (!ReadBlock(&tpkt, sizeof(TPKTV3)))
			return ErrorHandler(PSocket::LastReadError);
		//if (tpkt.header != 3 || tpkt.padding != 0)
		// some bad endpoints don't set padding to 0, e.g., Cisco AS5300
		if (tpkt.header != 3) {
			PTRACE(2, "Proxy\t" << GetName() << " NOT TPKT PACKET!");
			return false; // Only support version 3
		}
		buflen = PIPSocket::Net2Host(tpkt.length) - sizeof(TPKTV3);
		if (buflen < 1) {
			PTRACE(3, "Proxy\t" << GetName() << " PACKET TOO SHORT!");
			buflen = 0;
			return false;
		}
		if (!SetMinBufSize(buflen))
			return false;
		buffer = PBYTEArray(bufptr = wbuffer, buflen, false);
	}

#ifdef LARGE_FDSET
	// some endpoints may send TPKT header and payload in separate
	// packets, so we have to check again if data available
	if (!YaSelectList(this).Select(YaSelectList::Read, 0))
		return false;
#endif
	if (!Read(bufptr, buflen))
		return ErrorHandler(PSocket::LastReadError);

	if (!(buflen -= GetLastReadCount()))
		return true;

	bufptr += GetLastReadCount();
	PTRACE(3, "Proxy\t" << GetName() << " read timeout?");
	return false;
}

bool TCPProxySocket::InternalWrite(const PBYTEArray & buf)
{
	WORD len = (WORD)buf.GetSize(), tlen = len + sizeof(TPKTV3);
	PBYTEArray tbuf(tlen);
	BYTE *bptr = tbuf.GetPointer();
	new (bptr) TPKTV3(len); // placement operator
	memcpy(bptr + sizeof(TPKTV3), buf, len);
	return WriteData(bptr, tlen);
}

bool TCPProxySocket::SetMinBufSize(WORD len)
{
	if (wbufsize < len) {
		delete [] wbuffer;
		wbuffer = new BYTE[wbufsize = len];
	}
	return (wbuffer != 0);
}


// class CallSignalSocket
CallSignalSocket::CallSignalSocket() : TCPProxySocket("Q931s")
{
	InternalInit();
	localAddr = peerAddr = INADDR_ANY;
	m_h245Tunneling = true;
	SetHandler(RasServer::Instance()->GetSigProxyHandler());
}

CallSignalSocket::CallSignalSocket(CallSignalSocket *socket) : TCPProxySocket("Q931d", socket)
{
	InternalInit();
	remote = socket;
	m_call = socket->m_call;
}

CallSignalSocket::CallSignalSocket(CallSignalSocket *socket, WORD port) : TCPProxySocket("Q931d", socket, port)
{
	InternalInit();
	SetRemote(socket);
}

void CallSignalSocket::InternalInit()
{
	m_h245handler = 0;
	m_h245socket = 0;
	m_isnatsocket = false;
	m_lastQ931 = new Q931;
	m_setupUUIE = 0;
}

void CallSignalSocket::SetRemote(CallSignalSocket *socket)
{
	remote = socket;
	m_call = socket->m_call;
	m_call->SetSocket(socket, this);
	m_crv = (socket->m_crv & 0x7fffu);
	m_h245Tunneling = socket->m_h245Tunneling;
	socket->GetPeerAddress(peerAddr, peerPort);
	localAddr = RasServer::Instance()->GetLocalAddress(peerAddr); //TODO
	SetHandler(socket->GetHandler());
	SetName(AsString(socket->peerAddr, GetPort()));

	Address calling = INADDR_ANY, called = INADDR_ANY;
	int type = m_call->GetNATType(calling, called);
	if (type & CallRec::calledParty)
		socket->peerAddr = called;

	if (m_call->GetProxyMode() != CallRec::ProxyEnabled
		&& type == CallRec::both && calling == called)
		if (!Toolkit::AsBool(GkConfig()->GetString(ProxySection, "ProxyForSameNAT", "0"))) {
			m_call->SetProxyMode(CallRec::ProxyDisabled);
			return;
		}

	// enable proxy if required, no matter whether H.245 routed
	if (m_call->GetProxyMode() == CallRec::ProxyEnabled
		|| (m_call->GetProxyMode() == CallRec::ProxyDetect
			&& (Toolkit::Instance()->ProxyRequired(peerAddr, socket->peerAddr) 
				|| ((type != CallRec::none) && Toolkit::AsBool(GkConfig()->GetString(ProxySection, "ProxyForNAT", "1")))))) {
		H245ProxyHandler *proxyhandler = new H245ProxyHandler(socket->localAddr, calling);
		socket->m_h245handler = proxyhandler;
		m_h245handler = new H245ProxyHandler(localAddr, called, proxyhandler);
		proxyhandler->SetHandler(GetHandler());
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled");
		m_call->SetProxyMode(CallRec::ProxyEnabled);
	} else if (m_call->IsH245Routed()) {
		socket->m_h245handler = new H245Handler(socket->localAddr, calling);
		m_h245handler = new H245Handler(localAddr, called);
		m_call->SetProxyMode(CallRec::ProxyDisabled);
	}
}

CallSignalSocket::~CallSignalSocket()
{
	if (m_h245socket) {
		if (CallSignalSocket *ret = static_cast<CallSignalSocket *>(remote)) {
			if (!m_h245handler->IsSessionEnded() && ret->m_h245socket)
				ret->m_h245socket->SendEndSessionCommand();
			if (!ret->m_h245handler->IsSessionEnded())
				m_h245socket->SendEndSessionCommand();
		}
		m_h245socket->OnSignalingChannelClosed();
		m_h245socket->EndSession();
		m_h245socket->SetDeletable();
	}
	delete m_h245handler;
	delete m_lastQ931;
	delete m_setupUUIE;
	
	if (m_call) {
		if (m_call->GetCallSignalSocketCalling() == this) {
			PTRACE(1, "Q931\tWARNING: Calling socket " << GetName() 
				<< " not removed from CallRec before deletion"
				);
			m_call->SetCallSignalSocketCalling(NULL);
		} else if (m_call->GetCallSignalSocketCalled() == this) {
			m_call->SetCallSignalSocketCalled(NULL);
			PTRACE(1, "Q931\tWARNING: Called socket " << GetName() 
				<< " not removed from CallRec before deletion"
				);
		}
	}
}

#ifdef LARGE_FDSET
bool CallSignalSocket::Connect(const Address & addr)
#else
BOOL CallSignalSocket::Connect(const Address & addr)
#endif
{
	Address local = RasServer::Instance()->GetLocalAddress(addr); // TODO
	return TCPProxySocket::Connect(local, Q931PortRange.GetPort(), addr);
}

namespace { // anonymous namespace
#if PTRACING
void PrintQ931(int tlevel, const char *msg1, const char *msg2, const Q931 *q931, const H225_H323_UserInformation *uuie)
{
	PStringStream pstrm;
	pstrm << "Q931\t" << msg1 << msg2 << " {\n  q931pdu = " << setprecision(2) << *q931;
	if (uuie)
		pstrm << "\n  h225pdu = " << setprecision(2) << *uuie;
	pstrm << "\n}";
	PTRACE(tlevel, pstrm);
}
#else
inline void PrintQ931(int, const char *, const char *, const Q931 *, const H225_H323_UserInformation *)
{
	// nothing to do
}
#endif

bool GetUUIE(const Q931 & q931, H225_H323_UserInformation & uuie, const char *name)
{
	if (q931.HasIE(Q931::UserUserIE)) {
		PPER_Stream strm(q931.GetIE(Q931::UserUserIE));
		if (uuie.Decode(strm))
			return true;
		PTRACE(3, "Q931\t" << name << " ERROR DECODING UUIE!");
	}
	return false;
}

void SetUUIE(Q931 & q931, const H225_H323_UserInformation & uuie)
{
	PPER_Stream strm;
	uuie.Encode(strm);
	strm.CompleteEncoding();
	q931.SetIE(Q931::UserUserIE, strm);
}

} // end of anonymous namespace

void CallSignalSocket::RemoveCall()
{
	if (m_call)
		CallTable::Instance()->RemoveCall(m_call);
}

ProxySocket::Result CallSignalSocket::ReceiveData()
{

	PString in_rewrite_id,out_rewrite_id;

	if (!ReadTPKT())
		return IsOpen() ? NoData : Error;

	Q931* q931pdu = new Q931();

	if (!q931pdu->Decode(buffer)) {
		PTRACE(2, "Q931\t" << GetName() << " ERROR DECODING Q.931!");
		delete q931pdu;
		return Error;
	}

	bool changed = false;
	PTRACE(3, Type() << "\tReceived: " << q931pdu->GetMessageTypeName() << " CRV=" << q931pdu->GetCallReference() << " from " << GetName());

	m_result = Forwarding;

	H225_H323_UserInformation signal, *psignal = 0;
	if (GetUUIE(*q931pdu, signal, GetName())) {
		H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
		H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;

		PrintQ931(4, "Received:", "", q931pdu, psignal = &signal);

		if (remote && body.GetTag() == H225_H323_UU_PDU_h323_message_body::e_setup) {
			const WORD newcrv = (WORD)q931pdu->GetCallReference();
			if (m_crv && newcrv == (m_crv & 0x7fffu))
				PTRACE(2, "Q931\tWarning: duplicate Setup - ignored!");
			else {
				PTRACE(4, "Q931\tMultiple calls over single signalling channel not supported - new connection needed");

				Q931 releasePDU;
				H225_H323_UserInformation userInfo;
				H225_H323_UU_PDU_h323_message_body& msgBody = userInfo.m_h323_uu_pdu.m_h323_message_body;
				msgBody.SetTag(H225_H323_UU_PDU_h323_message_body::e_releaseComplete);
				H225_ReleaseComplete_UUIE& uuie = msgBody;
				uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
				uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_reason);
				uuie.m_reason.SetTag(H225_ReleaseCompleteReason::e_newConnectionNeeded);
				if (((H225_Setup_UUIE&)body).HasOptionalField(H225_Setup_UUIE::e_callIdentifier))
					uuie.m_callIdentifier = ((H225_Setup_UUIE&)body).m_callIdentifier;
				releasePDU.BuildReleaseComplete(newcrv, TRUE);
				SetUUIE(releasePDU, userInfo);
				PrintQ931(5, "Send to ", remote->GetName(), &releasePDU, &userInfo);

				PBYTEArray buf;
				if( releasePDU.Encode(buf) )
					TransmitData(buf);
				else
					PTRACE(3,"Q931\tFailed to encode message "<<releasePDU);
			}
			delete q931pdu;
			return NoData;
		} else {
			delete m_lastQ931;
			m_lastQ931 = q931pdu;
		}

		if (m_h245Tunneling)
#if H225_PROTOCOL_VERSION >= 4
			if(!pdu.HasOptionalField(H225_H323_UU_PDU::e_provisionalRespToH245Tunneling))
#endif
			m_h245Tunneling = (pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling) && pdu.m_h245Tunneling.GetValue());


		switch (body.GetTag())
		{
		case H225_H323_UU_PDU_h323_message_body::e_setup:
			if (remote || m_setupUUIE) {
				PTRACE(3, "Warning: duplicate Setup? ignored!");
				return NoData;
			}
			m_crv = (WORD)(m_lastQ931->GetCallReference() | 0x8000u);
			m_setupUUIE = new H225_H323_UserInformation(signal);
			changed = OnSetup(body, in_rewrite_id, out_rewrite_id);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_callProceeding:
			changed = OnCallProceeding(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_connect:
			changed = OnConnect(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_alerting:
			changed = OnAlerting(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_information:
			changed = OnInformation(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_releaseComplete:
			changed = OnReleaseComplete(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_facility:
			changed = OnFacility(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_progress:
			changed = OnProgress(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_empty:
			changed = OnEmpty(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_status:
			changed = OnStatus(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_statusInquiry:
			changed = OnStatusInquiry(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_setupAcknowledge:
			changed = OnSetupAcknowledge(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_notify:
			changed = OnNotify(body);
			break;
		default:
			PTRACE(4, "Q931\t" << GetName() << " UNKNOWN Q.931");
			break;
		}
		/* buggy
		if (pdu.HasOptionalField(H225_H323_UU_PDU::e_nonStandardControl)) {
			for (PINDEX n = 0; n < pdu.m_nonStandardControl.GetSize(); ++n)
				if (OnNonStandardData(pdu.m_nonStandardControl[n].m_data))
					changed = true;
			PTRACE(5, "Q931\t" << GetName() << " Rewriting nonStandardControl");
		}
		*/
		if (pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control) && m_h245handler)
			if (OnTunneledH245(pdu.m_h245Control))
				changed = true;

		if (changed)
			SetUUIE(*m_lastQ931, signal);
	} else { // not have UUIE
		delete m_lastQ931;
		m_lastQ931 = q931pdu;
		PrintQ931(4, "Received:", "", m_lastQ931, 0);
	}
/*
   Note: Openh323 1.7.9 or later required.
   The older version has an out of memory bug in Q931::GetCalledPartyNumber.
*/

	PString display = GkConfig()->GetString(RoutedSec, "ScreenDisplayIE", "");
	if (!display) {
		m_lastQ931->SetDisplayName(display);
		changed = true;
	}
	
	PString cli = GkConfig()->GetString(RoutedSec, "ScreenCallingPartyNumberIE", "");
	if (!cli) {
		unsigned plan = Q931::ISDNPlan, type = Q931::InternationalType;
		if (m_lastQ931->HasIE(Q931::CallingPartyNumberIE)) {
			PString dummy;
			m_lastQ931->GetCallingPartyNumber(dummy, &plan, &type);
		}
		m_lastQ931->SetCallingPartyNumber(cli, plan, type);
		changed = true;
	}

	if (changed) {
		m_lastQ931->Encode(buffer);
#if PTRACING
		if (remote)
			PrintQ931(5, "Send to ", remote->GetName(), m_lastQ931, psignal);
#endif
	}

	switch (m_lastQ931->GetMessageType())
	{
		case Q931::SetupMsg:
			if( m_result == Error ) {
				CallTable::Instance()->RemoveCall(m_call);
				EndSession();
			}
			break;
		/* why don't forward Status? - by cwhuang 16.04.2002
		case Q931::StatusMsg:
			// don't forward status messages mm-30.04.2001
			m_result = NoData;
		*/
		case Q931::InformationMsg:
			OnInformationMsg(*m_lastQ931);
			break;
		case Q931::ReleaseCompleteMsg:
			CallTable::Instance()->RemoveCall(m_call);
			m_result = Closing;
			break;
		default:
			break;
	}
	return m_result;
}

void CallSignalSocket::BuildReleasePDU(Q931 & ReleasePDU, const H225_CallTerminationCause *cause) const
{
	ReleasePDU.BuildReleaseComplete(m_crv, m_crv & 0x8000u);
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_releaseComplete);
	H225_ReleaseComplete_UUIE & uuie = body;
	uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (m_call) {
		uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_callIdentifier);
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	}
	if (cause) {
		if (cause->GetTag() == H225_CallTerminationCause::e_releaseCompleteReason) {
			uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_reason);
			uuie.m_reason = *cause;
			// remember disconnect cause for billing purposes
			if( m_call && m_call->GetDisconnectCause() == 0 )
				m_call->SetDisconnectCause(
					MapH225ReasonToQ931Cause(uuie.m_reason.GetTag())
					);
		} else { // H225_CallTerminationCause::e_releaseCompleteCauseIE
			PPER_Stream strm;
			cause->Encode(strm);
			strm.CompleteEncoding();
			ReleasePDU.SetIE(Q931::CauseIE, strm);
			// remember the cause for billing purposes
			if( m_call && m_call->GetDisconnectCause() == 0 )
				m_call->SetDisconnectCause(ReleasePDU.GetCause());
		}
	} else { // either CauseIE or H225_ReleaseComplete_UUIE is mandatory
		if( m_call && m_call->GetDisconnectCause() )
			// extract the stored disconnect cause, if not specified directly
			ReleasePDU.SetCause( (Q931::CauseValues)(m_call->GetDisconnectCause()) );
		else {
			uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_reason);
			uuie.m_reason = H225_ReleaseCompleteReason(H225_ReleaseCompleteReason::e_undefinedReason);
		}
	}

	SetUUIE(ReleasePDU, signal);

	PrintQ931(5, "Send to ", GetName(), &ReleasePDU, &signal);
}

void CallSignalSocket::SendReleaseComplete(const H225_CallTerminationCause *cause)
{
	if (IsOpen()) {
		Q931 ReleasePDU;
		BuildReleasePDU(ReleasePDU, cause);
		PBYTEArray buf;
		ReleasePDU.Encode(buf);
		TransmitData(buf);
	}
}

void CallSignalSocket::SendReleaseComplete(H225_ReleaseCompleteReason::Choices reason)
{
	H225_CallTerminationCause cause;
	cause.SetTag(H225_CallTerminationCause::e_releaseCompleteReason);
	H225_ReleaseCompleteReason & releaseReason = cause;
	releaseReason.SetTag(reason);
	SendReleaseComplete(&cause);
}

bool CallSignalSocket::HandleH245Mesg(PPER_Stream & strm)
{
	return m_h245handler->HandleMesg(strm);
}

void CallSignalSocket::SetPeerAddress(const Address & ip, WORD pt)
{
	peerAddr = ip, peerPort = pt;
}

bool CallSignalSocket::EndSession()
{
	SendReleaseComplete();
	return TCPProxySocket::EndSession();
}

void CallSignalSocket::OnError()
{
	if( m_call ) {
		m_call->SetDisconnectCause(Q931::ProtocolErrorUnspecified);
		CallTable::Instance()->RemoveCall(m_call);
	}
	EndSession();
	if (remote)
		remote->EndSession();
}

void CallSignalSocket::ForwardCall()
{
	MarkSocketBlocked lock(this);

	H225_H323_UserInformation fuuie;
	GetUUIE(*m_lastQ931, fuuie, GetName());
	H225_Facility_UUIE & Facility = fuuie.m_h323_uu_pdu.m_h323_message_body;

	endptr forwarded;
	Routing::FacilityRequest request(Facility, m_lastQ931, forwarded);
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	if (aliases) // TODO: use rewritten as a policy
		Toolkit::Instance()->RewriteE164(*aliases);
	if (H225_TransportAddress *dest = request.Process()) {
		PString forwarder;
		if (Facility.HasOptionalField(H225_Facility_UUIE::e_featureSet) && Facility.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)) {
			// get the forwarder
			H225_ArrayOf_FeatureDescriptor & fd = Facility.m_featureSet.m_neededFeatures;
			if ((fd.GetSize() > 0) && fd[0].HasOptionalField(H225_FeatureDescriptor::e_parameters))
				if (fd[0].m_parameters.GetSize() > 0) {
					H225_EnumeratedParameter & parm = fd[0].m_parameters[0];
					if (parm.HasOptionalField(H225_EnumeratedParameter::e_content))
						if (parm.m_content.GetTag() == H225_Content::e_alias)
							forwarder = AsString((const H225_AliasAddress&)parm.m_content, FALSE) + ":forward";
				}
		}
		PString altDestInfo(aliases ? AsString(*aliases) : AsDotString(*dest));
		CallSignalSocket *fsocket = (Facility.m_reason.GetTag() == H225_FacilityReason::e_callForwarded) ? this : 0;
		m_call->SetForward(fsocket, *dest, forwarded, forwarder, altDestInfo);
		if (request.GetFlags() & Routing::SetupRequest::e_toParent)
			m_call->SetToParent(true);
		PTRACE(3, "Q931\tCall " << m_call->GetCallNumber() << " is forwarded to " << altDestInfo << (!forwarder ? (" by " + forwarder) : PString()));
	} else {
		ForwardData();
		return;
	}

	// disconnect from forwarder
	SendReleaseComplete(H225_ReleaseCompleteReason::e_facilityCallDeflection);
	Close();

	CallSignalSocket *ret = static_cast<CallSignalSocket *>(remote);
	if (!ret) {
		PTRACE(2, "Warning: " << GetName() << " has no remote party?");
		return;
	}
	MarkSocketBlocked rlock(ret);
	if (!ret->m_setupUUIE) {
		PTRACE(1, "Error: " << GetName() << " no SetupUUIE!");
		return;
	}

	Q931 fakeSetup, *Setup = ret->m_lastQ931;
	H225_H323_UserInformation suuie = *ret->m_setupUUIE;
	if (Setup->GetMessageType() != Q931::SetupMsg) {
		fakeSetup.BuildSetup(m_crv);
		Setup = &fakeSetup;
	}
	H225_Setup_UUIE & SetupUUIE = suuie.m_h323_uu_pdu.m_h323_message_body;
	if (Facility.HasOptionalField(H225_Facility_UUIE::e_cryptoTokens)) {
		SetupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_cryptoTokens);
		SetupUUIE.m_cryptoTokens = Facility.m_cryptoTokens;
	}
	if (aliases) {
		const H225_ArrayOf_AliasAddress & a = *aliases;
		for (PINDEX n = 0; n < a.GetSize(); ++n)
			if (a[n].GetTag() == H225_AliasAddress::e_dialedDigits) {
				Setup->SetCalledPartyNumber(AsString(a[n], FALSE));
				break;
			}
		SetupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
		SetupUUIE.m_destinationAddress = a;
	}
	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "ShowForwarderNumber", "0")))
		if (endptr forwarder = m_call->GetForwarder()) {
			const H225_ArrayOf_AliasAddress & a = forwarder->GetAliases();
			for (PINDEX n = 0; n < a.GetSize(); ++n)
				if (a[n].GetTag() == H225_AliasAddress::e_dialedDigits) {
					PString callingNumber(AsString(a[n], FALSE));
					Setup->SetCallingPartyNumber(callingNumber);
					SetupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
					SetupUUIE.m_sourceAddress.SetSize(1);
					H323SetAliasAddress(callingNumber, SetupUUIE.m_sourceAddress[0]);
					break;
				}
		}

	// detach from the call
	m_call->SetSocket(0, 0);
	remote = ret->remote = 0;
	delete ret->m_h245handler;
	ret->m_h245handler = 0;

	if (ret->CreateRemote(SetupUUIE)) {
		SetUUIE(*Setup, suuie);
		Setup->Encode(ret->buffer);
		PrintQ931(5, "Forward Setup to ", ret->remote->GetName(), Setup, &suuie);
		if (ret->m_result == Forwarding || ret->InternalConnectTo()) {
			CallSignalSocket *result = static_cast<CallSignalSocket *>(ret->remote);
			if (m_h245socket) {
				m_h245socket->SetSigSocket(result);
				result->m_h245socket = m_h245socket;
				m_h245socket = 0;
			}
			if (ret->m_result == Forwarding)
				ret->ForwardData();
			else
				GetHandler()->Insert(result);
		}
	} else {
		ret->EndSession();
		ret->SetConnected(false);
		CallTable::Instance()->RemoveCall(m_call);
	}

	// let the socket be deletable
	SetDeletable();
}

PString CallSignalSocket::GetCallingStationId(
	/// Q.931 Setup message with additional data
	const Q931& q931pdu,
	/// Setup-UUIE element extracted from the Q.931 Setup message
	const H225_Setup_UUIE& setup,
	/// additional data
	SetupAuthData& authData
	) const
{
	if (!authData.m_callingStationId)
		return authData.m_callingStationId;

	const bool hasCall = authData.m_call.operator->() != NULL;		
	PString id;
	
	q931pdu.GetCallingPartyNumber(id);

	if (id.IsEmpty() && hasCall)
		id = authData.m_call->GetCallingStationId();

	
	if (!id)
		return id;

	if (id.IsEmpty() && setup.HasOptionalField(setup.e_sourceAddress)) 
		id = GetBestAliasAddressString(setup.m_sourceAddress, false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

	if (hasCall) {
		if (id.IsEmpty())
			id = GetBestAliasAddressString(
				authData.m_call->GetSourceAddress(), false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);

		if (id.IsEmpty()) {
			const endptr callingEP = authData.m_call->GetCallingParty();
			if (callingEP)
				id = GetBestAliasAddressString(callingEP->GetAliases(), false,
					AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
						| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
					);
		}
	}
	
	return id;
}

PString CallSignalSocket::GetCalledStationId(
	/// Q.931 Setup message with additional data
	const Q931& q931pdu,
	/// Setup-UUIE element extracted from the Q.931 Setup message
	const H225_Setup_UUIE& setup,
	/// additional data
	SetupAuthData& authData
	) const
{
	if (!authData.m_calledStationId)
		return authData.m_calledStationId;
		
	const bool hasCall = authData.m_call.operator->() != NULL;
	PString id;
	
	q931pdu.GetCalledPartyNumber(id);
	
	if (id.IsEmpty() && hasCall)
		id = authData.m_call->GetCalledStationId();

	if (!id)
		return id;
		
	if (id.IsEmpty() && setup.HasOptionalField(setup.e_destinationAddress))
		id = GetBestAliasAddressString(setup.m_destinationAddress, false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

	if (id.IsEmpty() && hasCall)
		id = GetBestAliasAddressString(
			authData.m_call->GetDestinationAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

	if (id.IsEmpty()) {
		PIPSocket::Address addr;
		WORD port = 0;
		if (hasCall && authData.m_call->GetDestSignalAddr(addr, port))
			id = AsString(addr, port);
		// this does not work well in routed mode, when destCallSignalAddress
		// is usually the gatekeeper address
		else if (setup.HasOptionalField(setup.e_destCallSignalAddress) 
			&& GetIPAndPortFromTransportAddr(setup.m_destCallSignalAddress, addr, port) 
			&& addr.IsValid())
			id = AsString(addr, port);
	}
	
	return id;
}

bool CallSignalSocket::OnSetup(H225_Setup_UUIE & Setup, PString &in_rewrite_id, PString &out_rewrite_id)
{
	// record the timestamp here since processing may take much time
	time_t setupTime = time(0);

	RasServer *RasSrv = RasServer::Instance();
	m_result = Error;

	if (!Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) || (Setup.m_destinationAddress.GetSize() < 1)) {
		unsigned plan, type;
		PString destination;
		if (m_lastQ931->GetCalledPartyNumber(destination, &plan, &type)) {
			// Setup_UUIE doesn't contain any destination information, but Q.931 has CalledPartyNumber
			// We create the destinationAddress according to it
			Setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			Setup.m_destinationAddress.SetSize(1);
			H323SetAliasAddress(destination, Setup.m_destinationAddress[0]);
		}
	}


	PString callid;
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
		m_call = CallTable::Instance()->FindCallRec(Setup.m_callIdentifier);
		callid = AsString(Setup.m_callIdentifier.m_guid);
	} else { // try CallReferenceValue
		PTRACE(3, "Q931\tSetup_UUIE doesn't contain CallIdentifier!");
		H225_CallReferenceValue crv;
		crv.SetValue(m_crv & 0x7fffu);
		m_call = CallTable::Instance()->FindCallRec(crv);
		H225_CallIdentifier callIdentifier; // empty callIdentifier
		callid = AsString(callIdentifier.m_guid);
	}

	PString dialedNumber;
	
	m_lastQ931->GetCalledPartyNumber(dialedNumber);
	
	if (dialedNumber.IsEmpty()) {
		if (Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
			dialedNumber = GetBestAliasAddressString(
				Setup.m_destinationAddress, false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);

		if (dialedNumber.IsEmpty() && m_call)
			dialedNumber = m_call->GetDialedNumber();
		
		if (dialedNumber.IsEmpty() && m_call)
			dialedNumber = GetBestAliasAddressString(
				m_call->GetDestinationAddress(), false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
	}

	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {

		// Do inbound per GWRewrite if we can before global rewrite

		PString source;
		#if PTRACING
		PString rewrite_type;
		#endif

		// Try lookup on neighbor list for rewrite source first
		source = RasSrv->GetNeighbors()->GetNeighborIdBySigAdr(Setup.m_sourceCallSignalAddress);
		#if PTRACING
		if (!source.IsEmpty()) {
			rewrite_type = "neighbor or explicit IP";
		}
		#endif

		// Try call record rewrite identifier next
		if (source.IsEmpty() && m_call) {
			source = m_call->GetInboundRewriteId();
			#if PTRACING
			if (!source.IsEmpty()) {
				rewrite_type = "call record";
			}
			#endif
		}


		// Try the Setup's source field if this exists
		if (source.IsEmpty() && Setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress) && Setup.m_sourceAddress.GetSize() > 0) {
			source = GetBestAliasAddressString(
				Setup.m_sourceAddress, false,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID), 
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
			#if PTRACING
			if (!source.IsEmpty()) {
				rewrite_type = "setup H323 ID or E164";
			}
			#endif
		}


		if (!source.IsEmpty()) {
			#if PTRACING
			PTRACE(4, "\tGWRewrite source: " << rewrite_type);
			#endif

			Toolkit::Instance()->GWRewriteE164(source,true,Setup.m_destinationAddress);
            in_rewrite_id = source;
		}


		// Normal rewrite
		Toolkit::Instance()->RewriteE164(Setup.m_destinationAddress);
	}

	if (m_lastQ931->HasIE(Q931::CalledPartyNumberIE)) {
		unsigned plan, type;
		PString calledNumber;

		// Do per GW inbound rewrite before global rewrite
		if (m_lastQ931->GetCalledPartyNumber(calledNumber, &plan, &type) &&
			Toolkit::Instance()->GWRewritePString(in_rewrite_id,true,calledNumber))
			m_lastQ931->SetCalledPartyNumber(calledNumber, plan, type);

		// Normal rewrite
		if (m_lastQ931->GetCalledPartyNumber(calledNumber, &plan, &type) &&
		    Toolkit::Instance()->RewritePString(calledNumber))
			m_lastQ931->SetCalledPartyNumber(calledNumber, plan, type);
	}


	Address fromIP;
	WORD fromPort = 1720;
	GetPeerAddress(fromIP,fromPort);
	GkClient *gkClient = RasSrv->GetGkClient();
	bool rejectCall = false;
	
	if (m_call) {
		if (m_call->IsSocketAttached()) {
			PTRACE(2, "Q931\tWarning: socket already attached for callid " << callid);
			m_call->SetDisconnectCause(Q931::CallRejected);
			rejectCall = true;
		} else if (m_call->IsToParent() && !m_call->IsForwarded()) {
			if (gkClient->CheckFrom(fromIP)) {
				// looped call
				PTRACE(2, "Q931\tWarning: a registered call from my GK(" << GetName() << ')');
				m_call->SetDisconnectCause(Q931::CallRejected);
				rejectCall = true;
			} else
				gkClient->RewriteE164(*m_lastQ931, Setup, true);
		}
		// TODO: check for facility
		const H225_ArrayOf_CryptoH323Token & tokens = m_call->GetAccessTokens();
		if (!rejectCall && tokens.GetSize() > 0) {
			Setup.IncludeOptionalField(H225_Setup_UUIE::e_cryptoTokens);
			Setup.m_cryptoTokens = tokens;
		}

		m_call->SetSetupTime(setupTime);

		SetupAuthData authData(m_call, true, fromIP, fromPort);
		authData.m_dialedNumber = dialedNumber;
		authData.SetRouteToAlias(m_call->GetRouteToAlias());
		authData.m_callingStationId = GetCallingStationId(*m_lastQ931, Setup, authData);
		authData.m_calledStationId = GetCalledStationId(*m_lastQ931, Setup, authData);
		
		// authenticate the call
		if (!rejectCall && !RasSrv->ValidatePDU(*m_lastQ931, Setup, authData)) {
			PTRACE(4,"Q931\tDropping call #"<<m_call->GetCallNumber()
				<<" due to Setup authentication failure"
				);
			if (authData.m_rejectCause >= 0)
				m_call->SetDisconnectCause(authData.m_rejectCause);
			else if (authData.m_rejectReason >= 0)
				m_call->SetDisconnectCause(MapH225ReasonToQ931Cause(authData.m_rejectReason));
			else
				m_call->SetDisconnectCause(Q931::CallRejected);
			rejectCall = true;
		}

		if (!rejectCall && authData.m_routeToAlias != NULL) {
			Setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			Setup.m_destinationAddress.SetSize(1);
			Setup.m_destinationAddress[0] = *authData.m_routeToAlias;
			const PString alias = H323GetAliasAddressString(Setup.m_destinationAddress[0]);
			if (m_lastQ931->HasIE(Q931::CalledPartyNumberIE)) {
				if (!alias && strspn(alias, "1234567890*#") == strlen(alias)) {
					unsigned plan, type;
					PString calledNumber;
					if (m_lastQ931->GetCalledPartyNumber(calledNumber, &plan, &type))
						m_lastQ931->SetCalledPartyNumber(alias, plan, type);
				} else
					m_lastQ931->RemoveIE(Q931::CalledPartyNumberIE);
			}
			authData.m_calledStationId = alias;
			PTRACE(2, "Q931\tSetup destination set to " << alias);
		}
		if (!rejectCall && authData.m_callDurationLimit > 0)
			m_call->SetDurationLimit(authData.m_callDurationLimit);
		if (!authData.m_callingStationId)
			m_call->SetCallingStationId(authData.m_callingStationId);
		if (!authData.m_calledStationId)
			m_call->SetCalledStationId(authData.m_calledStationId);
		if (!authData.m_dialedNumber)
			m_call->SetDialedNumber(authData.m_dialedNumber);
					
		// log AcctStart accounting event
		if( !RasSrv->LogAcctEvent(GkAcctLogger::AcctStart, m_call) ) {
			PTRACE(4,"Q931\tDropping call #"<<m_call->GetCallNumber()
				<<" due to accounting failure"
				);
			m_call->SetDisconnectCause(Q931::TemporaryFailure);
			rejectCall = true;
		}
		
		if (rejectCall)
			return false;
	} else {
		SetupAuthData authData(m_call, false, fromIP, fromPort);
		authData.m_dialedNumber = dialedNumber;
		authData.m_callingStationId = GetCallingStationId(*m_lastQ931, Setup, authData);
		authData.m_calledStationId = GetCalledStationId(*m_lastQ931, Setup, authData);

		if (!RasSrv->ValidatePDU(*m_lastQ931,Setup, authData)) {
			PTRACE(4,"Q931\tDropping call from " << fromIP << ':' << fromPort
				<<" due to Setup authentication failure"
				);
			if (authData.m_rejectCause == -1 && authData.m_rejectReason == -1)
				authData.m_rejectCause = Q931::CallRejected;
			rejectCall = true;
		}

		if (!rejectCall && authData.m_routeToAlias != NULL) {
			Setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			Setup.m_destinationAddress.SetSize(1);
			Setup.m_destinationAddress[0] = *authData.m_routeToAlias;
			const PString alias = H323GetAliasAddressString(Setup.m_destinationAddress[0]);
			if (m_lastQ931->HasIE(Q931::CalledPartyNumberIE)) {
				if (!alias && strspn(alias, "1234567890*#") == strlen(alias)) {
					unsigned plan, type;
					PString calledNumber;
					if (m_lastQ931->GetCalledPartyNumber(calledNumber, &plan, &type))
						m_lastQ931->SetCalledPartyNumber(alias, plan, type);
				} else
					m_lastQ931->RemoveIE(Q931::CalledPartyNumberIE);
			}
			authData.m_calledStationId = alias;
			PTRACE(2, "Q931\tSetup destination set to " << alias);
		}

		endptr called;
		bool destFound = false;
		H225_TransportAddress calledAddr;
		Routing::SetupRequest request(Setup, m_lastQ931, called);
		
		if (!rejectCall && authData.m_routeToIP != NULL) {
			request.SetDestination(calledAddr, true);
			calledAddr = *authData.m_routeToIP;
			destFound = true;
			Setup.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
			Setup.m_destCallSignalAddress = calledAddr;
			PTRACE(2, "Q931\tSetup destination address set to " << AsDotString(Setup.m_destCallSignalAddress));
		}

		bool useParent = gkClient->IsRegistered() && gkClient->CheckFrom(fromIP);
		if (!rejectCall && useParent) {
			gkClient->RewriteE164(*m_lastQ931, Setup, false);
			if (!gkClient->SendARQ(request, true)) { // send answered ARQ
				PTRACE(2, "Q931\tGot ARJ from parent for " << GetName());
				authData.m_rejectCause = Q931::CallRejected;
				rejectCall = true;
			} else
				request.SetFlag(Routing::RoutingRequest::e_fromParent);
		}

		if (!rejectCall && !destFound && Setup.HasOptionalField(H225_Setup_UUIE::e_cryptoTokens) && Setup.m_cryptoTokens.GetSize() > 0) {
			PINDEX s = Setup.m_cryptoTokens.GetSize() - 1;
			destFound = Neighbors::DecodeAccessToken(Setup.m_cryptoTokens[s], fromIP, calledAddr);
			if (destFound) {
				called = RegistrationTable::Instance()->FindBySignalAdr(calledAddr);
				PTRACE(3, "Q931\tGot destination " << AsDotString(calledAddr));
				if (s > 0)
					Setup.m_cryptoTokens.SetSize(s);
				else
					Setup.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);

				if (!useParent) {
					Address toIP;
					GetIPFromTransportAddr(calledAddr, toIP);
					useParent = gkClient->IsRegistered() && gkClient->CheckFrom(toIP);
					if (useParent && !gkClient->SendARQ(request)) {
						PTRACE(2, "Q931\tGot ARJ from parent for " << GetName());
						authData.m_rejectCause = Q931::CallRejected;
						rejectCall = true;
					}
				}
			}
		}
		
		if (!rejectCall && !destFound) {
			// for compatible to old version
			if (!(useParent || RasSrv->AcceptUnregisteredCalls(fromIP))) {
				PTRACE(3, "Q931\tReject unregistered call " << callid);
				authData.m_rejectCause = Q931::CallRejected;
				rejectCall = true;
			} else {
				if (Setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress))
					if (RasSrv->GetCallSignalAddress(fromIP) == Setup.m_destCallSignalAddress)
						Setup.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);

				if (H225_TransportAddress *dest = request.Process()) {
					destFound = true;
					calledAddr = *dest;
					if (!useParent)
						useParent = request.GetFlags() & Routing::SetupRequest::e_toParent;
				} else {
					PTRACE(3, "Q931\tNo destination for unregistered call " << callid);
					authData.m_rejectReason = request.GetRejectReason();
					rejectCall = true;
				}
			}
		}

		PString destinationString(Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) ? AsString(Setup.m_destinationAddress) : AsDotString(calledAddr));

		// if I'm behind NAT and the call is from parent, always use H.245 routed
		bool h245Routed = RasSrv->IsH245Routed() || (useParent && gkClient->IsNATed());
		// workaround for bandwidth, as OpenH323 library :p
		CallRec* call = new CallRec(*m_lastQ931, Setup, h245Routed, 
			destinationString, authData.m_proxyMode
			);
		call->SetSrcSignalAddr(SocketToH225TransportAddr(fromIP,fromPort));
		if (called)
			call->SetCalled(called);
		else
			call->SetDestSignalAddr(calledAddr);

		if (useParent)
			call->SetToParent(true);

		m_call = callptr(call);
		m_call->SetSetupTime(setupTime);
		CallTable::Instance()->Insert(call);

		if (!rejectCall && authData.m_callDurationLimit > 0)
			m_call->SetDurationLimit(authData.m_callDurationLimit);
		if (!authData.m_callingStationId)
			m_call->SetCallingStationId(authData.m_callingStationId);
		if (!authData.m_calledStationId)
			m_call->SetCalledStationId(authData.m_calledStationId);
		if (!authData.m_dialedNumber)
			m_call->SetDialedNumber(authData.m_dialedNumber);

		if( !RasSrv->LogAcctEvent(GkAcctLogger::AcctStart, m_call) ) {
			PTRACE(4,"Q931\tDropping call #"<<call->GetCallNumber()
				<<" due to accounting failure"
				);
			authData.m_rejectCause = Q931::TemporaryFailure;
			rejectCall = true;
		}
		
		if (rejectCall) {
			if (authData.m_rejectCause >= 0)
				m_call->SetDisconnectCause(authData.m_rejectCause);
			else if (authData.m_rejectReason >= 0)
				m_call->SetDisconnectCause(MapH225ReasonToQ931Cause(authData.m_rejectReason));
			else
				m_call->SetDisconnectCause(Q931::CallRejected);
			return false;
		}
	}

	// Do outbound per GW rewrite
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {

		PIPSocket::Address neighbor_addr;
		WORD port;
		PString source;
		#if PTRACING
		PString rewrite_type;
		#endif

		// Try neighbor list first
		if (m_call->GetDestSignalAddr(neighbor_addr,port)) {
			source = RasSrv->GetNeighbors()->GetNeighborIdBySigAdr(neighbor_addr);
			#if PTRACING
			if (!source.IsEmpty()) {
				rewrite_type = "neighbor or explicit IP";
			}
			#endif
		}

		// Try call record rewrite id
		if (source.IsEmpty()) {
			source = m_call->GetOutboundRewriteId();
			#if PTRACING
			if (!source.IsEmpty()) {
				rewrite_type = "call record";
			}
			#endif
		}

		// Try configured endpoint
		if (source.IsEmpty()) {
			endptr rewriteEndPointOut = m_call->GetCalledParty();
			if (rewriteEndPointOut && rewriteEndPointOut->GetAliases().GetSize() > 0 ) {
		 		source = GetBestAliasAddressString(
					rewriteEndPointOut->GetAliases(), false,
					AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
					AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
						| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
					);
				#if PTRACING
				if (!source.IsEmpty()) {
					rewrite_type = "setup H323 ID or E164";
				}
				#endif
			}
		}

		if (!source.IsEmpty()) {
			#if PTRACING
			PTRACE(4, "\tGWRewrite source: " << rewrite_type);
			#endif
		    Toolkit::Instance()->GWRewriteE164(source,false,Setup.m_destinationAddress);
			out_rewrite_id = source;
		}

	}

	if (m_lastQ931->HasIE(Q931::CalledPartyNumberIE)) {
		unsigned plan, type;
		PString calledNumber;

		// Do per GW outbound rewrite after global rewrite
		if (m_lastQ931->GetCalledPartyNumber(calledNumber, &plan, &type) &&
			Toolkit::Instance()->GWRewritePString(out_rewrite_id,false,calledNumber))
			m_lastQ931->SetCalledPartyNumber(calledNumber, plan, type);
	}

	if (Setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		const PString screenSourceAddress = GkConfig()->GetString(RoutedSec, "ScreenSourceAddress", "");
		if (!screenSourceAddress) {
			Setup.m_sourceAddress.SetSize(1);
			H323SetAliasAddress(screenSourceAddress, Setup.m_sourceAddress[0]);
		}
	}
	// in routed mode the caller may have put the GK address in destCallSignalAddress
	// since it is optional, we just remove it (we could alternativly insert the real destination SignalAdr)
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress))
		Setup.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);

	if (Setup.HasOptionalField(H225_Setup_UUIE::e_multipleCalls)
		&& Setup.m_multipleCalls)
		Setup.m_multipleCalls = FALSE;
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_maintainConnection)
		&& Setup.m_maintainConnection)
		Setup.m_maintainConnection = FALSE;

	return CreateRemote(Setup);
}

bool CallSignalSocket::CreateRemote(H225_Setup_UUIE & Setup)
{
	if (!m_call->GetDestSignalAddr(peerAddr, peerPort)) {
		PTRACE(3, "Q931\t" << GetName() << " INVALID ADDRESS");
		m_call->SetDisconnectCause(Q931::IncompatibleDestination);
		return false;
	}
	Address calling = INADDR_ANY;
	int type = m_call->GetNATType(calling, peerAddr);

	localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
	Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
	Setup.m_sourceCallSignalAddress = SocketToH225TransportAddr(localAddr, GetPort());

	PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " is NAT type " << type);
	if (type & CallRec::calledParty) {
		// m_call->GetCalledParty() should not be null in the case
		if (CallSignalSocket *socket = m_call->GetCalledParty()->GetSocket()) {
			PTRACE(3, "Q931\tUsing NAT socket " << socket->GetName());

			// it's dangerous if the remote socket has
			// different handler than this
			// so we move this socket to other handler
			GetHandler()->MoveTo(socket->GetHandler(), this);

			remote = socket;
			socket->SetRemote(this);
			SetConnected(true);
			socket->SetConnected(true);
			m_result = Forwarding;
		}
	}
	if (!remote) {
		remote = new CallSignalSocket(this, peerPort);
		m_result = Connecting;
	}

	HandleH245Address(Setup);
	HandleFastStart(Setup, true);

#if H225_PROTOCOL_VERSION >= 4
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_parallelH245Control) && m_h245handler)
		OnTunneledH245(Setup.m_parallelH245Control);
#endif
	return true;
}

bool CallSignalSocket::OnCallProceeding(H225_CallProceeding_UUIE & CallProceeding)
{
	bool changed = HandleH245Address(CallProceeding);
	if (CallProceeding.HasOptionalField(H225_CallProceeding_UUIE::e_multipleCalls)
		&& CallProceeding.m_multipleCalls) {
		CallProceeding.m_multipleCalls = FALSE;
		changed = true;
	}
	if (CallProceeding.HasOptionalField(H225_CallProceeding_UUIE::e_maintainConnection)
		&& CallProceeding.m_maintainConnection) {
		CallProceeding.m_maintainConnection = FALSE;
		changed = true;
	}
	return HandleFastStart(CallProceeding, false) || changed;
}

bool CallSignalSocket::OnConnect(H225_Connect_UUIE & Connect)
{
	if (m_call) {// hmm... it should not be null
		m_call->SetConnected();
		RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctConnect, m_call);
	}
#ifndef NDEBUG
	if (!Connect.HasOptionalField(H225_Connect_UUIE::e_callIdentifier)) {
		PTRACE(1, "Q931\tConnect_UUIE doesn't contain CallIdentifier!");
	} else if (m_call->GetCallIdentifier() != Connect.m_callIdentifier) {
		PTRACE(1, "Q931\tWarning: CallIdentifier doesn't match?");
	}
#endif
	bool changed = HandleH245Address(Connect);
	if (Connect.HasOptionalField(H225_Connect_UUIE::e_multipleCalls)
		&& Connect.m_multipleCalls) {
		Connect.m_multipleCalls = FALSE;
		changed = true;
	}
	if (Connect.HasOptionalField(H225_Connect_UUIE::e_maintainConnection)
		&& Connect.m_maintainConnection) {
		Connect.m_maintainConnection = FALSE;
		changed = true;
	}
	return HandleFastStart(Connect, false) || changed;
}

bool CallSignalSocket::OnAlerting(H225_Alerting_UUIE & Alerting)
{
	bool changed = HandleH245Address(Alerting);
	if (Alerting.HasOptionalField(H225_Alerting_UUIE::e_multipleCalls)
		&& Alerting.m_multipleCalls) {
		Alerting.m_multipleCalls = FALSE;
		changed = true;
	}
	if (Alerting.HasOptionalField(H225_Alerting_UUIE::e_maintainConnection)
		&& Alerting.m_maintainConnection) {
		Alerting.m_maintainConnection = FALSE;
		changed = true;
	}
	return HandleFastStart(Alerting, false) || changed;
}

bool CallSignalSocket::OnInformation(H225_Information_UUIE &)
{
	return false; // do nothing
}

bool CallSignalSocket::OnReleaseComplete(H225_ReleaseComplete_UUIE & ReleaseComplete)
{
	if( m_call ) {
		m_call->SetDisconnectTime(time(NULL));
		if( m_lastQ931 && m_lastQ931->HasIE(Q931::CauseIE) )
			m_call->SetDisconnectCause(m_lastQ931->GetCause());
		else if( ReleaseComplete.HasOptionalField(H225_ReleaseComplete_UUIE::e_reason) )
			m_call->SetDisconnectCause(
				MapH225ReasonToQ931Cause(ReleaseComplete.m_reason.GetTag())
				);
	}
	return false; // do nothing
}

bool CallSignalSocket::OnFacility(H225_Facility_UUIE & Facility)
{
	bool changed = false;
	
	if (Facility.HasOptionalField(H225_Facility_UUIE::e_multipleCalls)
		&& Facility.m_multipleCalls) {
		Facility.m_multipleCalls = FALSE;
		changed = true;
	}
	if (Facility.HasOptionalField(H225_Facility_UUIE::e_maintainConnection)
		&& Facility.m_maintainConnection) {
		Facility.m_maintainConnection = FALSE;
		changed = true;
	}

	switch (Facility.m_reason.GetTag())
	{
		case H225_FacilityReason::e_startH245:
			if (Facility.HasOptionalField(H225_Facility_UUIE::e_h245Address) && Facility.m_protocolIdentifier.GetValue().IsEmpty())
				if (m_h245socket && m_h245socket->Reverting(Facility.m_h245Address))
					m_result = NoData;
			break;
		case H225_FacilityReason::e_callForwarded:
		case H225_FacilityReason::e_routeCallToGatekeeper:
		case H225_FacilityReason::e_routeCallToMC:
			if (!Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "ForwardOnFacility", "1")))
				break;
			// to avoid complicated handling of H.245 channel on forwarding,
			// we only do forward if forwarder is the called party and
			// H.245 channel is not established yet
			if (m_setupUUIE || (m_h245socket && m_h245socket->IsConnected()))
				break;
			// make sure the call is still active
			if (m_call && CallTable::Instance()->FindCallRec(m_call->GetCallNumber())) {
				MarkBlocked(true);
				CreateJob(this, &CallSignalSocket::ForwardCall, "ForwardCall");
				m_result = NoData;
				return false;
			}
			break;
	}
	if (m_result != NoData)
		changed = HandleH245Address(Facility) || changed;
	return HandleFastStart(Facility, false) || changed;
}

bool CallSignalSocket::OnProgress(H225_Progress_UUIE & Progress)
{
	bool changed = HandleH245Address(Progress);
	if (Progress.HasOptionalField(H225_Progress_UUIE::e_multipleCalls)
		&& Progress.m_multipleCalls) {
		Progress.m_multipleCalls = FALSE;
		changed = true;
	}
	if (Progress.HasOptionalField(H225_Progress_UUIE::e_maintainConnection)
		&& Progress.m_maintainConnection) {
		Progress.m_maintainConnection = FALSE;
		changed = true;
	}
	return HandleFastStart(Progress, false) || changed;
}

bool CallSignalSocket::OnEmpty(H225_H323_UU_PDU_h323_message_body &)
{
	return false; // do nothing
}

bool CallSignalSocket::OnStatus(H225_Status_UUIE &)
{
	return false; // do nothing
}

bool CallSignalSocket::OnStatusInquiry(H225_StatusInquiry_UUIE &)
{
	return false; // do nothing
}

bool CallSignalSocket::OnSetupAcknowledge(H225_SetupAcknowledge_UUIE &)
{
	return false; // do nothing
}

bool CallSignalSocket::OnNotify(H225_Notify_UUIE &)
{
	return false; // do nothing
}

/*
bool CallSignalSocket::OnNonStandardData(PASN_OctetString & octs)
{
	bool changed = false;
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
				changed = true;
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
	return changed;
}
*/

bool CallSignalSocket::OnTunneledH245(H225_ArrayOf_PASN_OctetString & h245Control)
{
	bool changed = false;
	for (PINDEX i = 0; i < h245Control.GetSize(); ++i) {
		PPER_Stream strm = h245Control[i].GetValue();
		if (HandleH245Mesg(strm)) {
			h245Control[i].SetValue(strm);
			changed = true;
		}
	}
	return changed;
}

bool CallSignalSocket::OnFastStart(H225_ArrayOf_PASN_OctetString & fastStart, bool fromCaller)
{
	bool changed = false;
	PINDEX sz = fastStart.GetSize();
	for (PINDEX i = 0; i < sz; ++i) {
		PPER_Stream strm = fastStart[i].GetValue();
		H245_OpenLogicalChannel olc;
		if (!olc.Decode(strm)) {
			PTRACE(4, "Q931\t" << GetName() << " ERROR DECODING FAST START ELEMENT " << i);
			return false;
		}
		PTRACE(4, "Q931\nfastStart[" << i << "] received: " << setprecision(2) << olc);
		H245Handler::pMem handlefs = (fromCaller) ? &H245Handler::HandleFastStartSetup : &H245Handler::HandleFastStartResponse;
		if ((m_h245handler->*handlefs)(olc)) {
			PPER_Stream wtstrm;
			olc.Encode(wtstrm);
			wtstrm.CompleteEncoding();
			fastStart[i].SetValue(wtstrm);
			changed = true;
			PTRACE(5, "Q931\nfastStart[" << i << "] to send " << setprecision(2) << olc);
		}
	}
	return changed;
}

bool CallSignalSocket::OnInformationMsg(Q931 & q931pdu)
{
	PBYTEArray buf = q931pdu.GetIE(Q931::FacilityIE);
	if (!remote && buf.GetSize() > 0) {
		H225_EndpointIdentifier id;
		PString epid((const char *)buf.GetPointer(), buf.GetSize());
		id = epid;
		PTRACE(3, "Q931\tEPID = " << epid);
		endptr ep = RegistrationTable::Instance()->FindByEndpointId(id);
		buf = q931pdu.GetIE(Q931::CallStateIE);
		if (buf.GetSize() > 0 && buf[0] == Q931::CallState_DisconnectRequest) {
			if (ep) {
				ep->GetSocket();
				SetDeletable();
				PTRACE(3, "Q931\tClose NAT socket " << GetName());
			}
			Close();
		} else if (ep) {
			m_isnatsocket = true;
			ep->SetSocket(this);
			SetConnected(true); // avoid the socket be deleted
		}
		m_result = NoData;
	}
	return false; // unchanged
}

void CallSignalSocket::BuildFacilityPDU(Q931 & FacilityPDU, int reason, const PObject *parm)
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_facility);
	H225_Facility_UUIE & uuie = body;
	// Don't set protocolID intentionally so the remote
	// can determine whether this is a message generate by GnuGK
	// uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (m_call) {
		uuie.IncludeOptionalField(H225_Facility_UUIE::e_conferenceID);
		uuie.m_conferenceID = m_call->GetConferenceIdentifier();
		uuie.IncludeOptionalField(H225_Facility_UUIE::e_callIdentifier);
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	}
	uuie.m_reason.SetTag(reason);
	switch (reason)
	{
		case H225_FacilityReason::e_startH245:
			uuie.IncludeOptionalField(H225_Facility_UUIE::e_h245Address);
			if (CallSignalSocket *ret = static_cast<CallSignalSocket *>(remote))
				uuie.m_h245Address = m_h245socket->GetH245Address(ret->localAddr);
			else
				PTRACE(2, "Warning: " << GetName() << " has no remote party?");
			break;

		case H225_FacilityReason::e_callForwarded:
			uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
			if (const H225_TransportAddress *addr = dynamic_cast<const H225_TransportAddress *>(parm)) {
				uuie.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAddress);
				uuie.m_alternativeAddress = *addr;
			} else if (const PString *dest = dynamic_cast<const PString *>(parm)) {
				uuie.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress);
				uuie.m_alternativeAliasAddress.SetSize(1);
				H323SetAliasAddress(*dest, uuie.m_alternativeAliasAddress[0]);
			}
			if (m_call) {
				uuie.IncludeOptionalField(H225_Facility_UUIE::e_callIdentifier);
				uuie.m_callIdentifier = m_call->GetCallIdentifier();
			}
			break;
	}

	FacilityPDU.BuildFacility(m_crv, m_crv & 0x8000u);
	SetUUIE(FacilityPDU, signal);

	PrintQ931(5, "Send to ", GetName(), &FacilityPDU, &signal);
}

void CallSignalSocket::Dispatch()
{
	const PTime channelStart;
	const int setupTimeout = PMAX(GkConfig()->GetInteger(RoutedSec,"SetupTimeout",DEFAULT_SETUP_TIMEOUT),1000);
	int timeout = setupTimeout;

	if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
		Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
			GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "1")) ? 1 : 0, 
			SOL_SOCKET
			);

	while (timeout > 0) {

		if (!IsReadable(timeout)) {
			PTRACE(3, "Q931\tTimed out waiting for initial Setup message from " << GetName());
			break;
		}

		switch (ReceiveData())
		{
			case NoData:
				if (m_isnatsocket) {
					GetHandler()->Insert(this);
					return;
				}
				// update timeout to reflect remaing time
				timeout = setupTimeout - (PTime() - channelStart).GetInterval();
				break;

			case Connecting:
				if (InternalConnectTo()) {
					if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
						remote->Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
							GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "1")) ? 1 : 0, 
							SOL_SOCKET
							);
					if (!remote->IsReadable(2*setupTimeout)) {
						PTRACE(3, "Q931\tTimed out waiting for a response to Setup message from " << remote->GetName());
						if( m_call ) {
							m_call->SetDisconnectCause(Q931::TimerExpiry);
							CallTable::Instance()->RemoveCall(m_call);
						}
					}
					GetHandler()->Insert(this, remote);
					return;
				}

			case Forwarding:
				if (remote && remote->IsConnected()) { // remote is NAT socket
					if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
						remote->Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
							GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "1")) ? 1 : 0, 
							SOL_SOCKET
							);
					ForwardData();
// in case of NAT socket, IsReadable cause race condition if the remote socket
// is selected by its proxy handler, thanks to Daniel Liu
//
//					if (!remote->IsReadable(2*setupTimeout)) {
//						PTRACE(3, "Q931\tTimed out waiting for a response to Setup message from " << remote->GetName());
//						if( m_call ) {
//							m_call->SetDisconnectCause(Q931::TimerExpiry);
//							CallTable::Instance()->RemoveCall(m_call);
//						}
//					}
					return;
				}

			default:
				timeout = 0;
				break;
		}
	}
	if (m_call)
		m_call->SetSocket(NULL, NULL);
	delete this; // oh!
}

bool CallSignalSocket::SetH245Address(H225_TransportAddress & h245addr)
{
	if (m_h245Tunneling && Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveH245AddressOnTunneling", "0")))
		return false;
	if (!m_h245handler) // no H245 routed
		return true;

	CallSignalSocket *ret = static_cast<CallSignalSocket *>(remote);
	if (!ret) {
		PTRACE(2, "Warning: " << GetName() << " has no remote party?");
		return false;
	}
	m_h245handler->OnH245Address(h245addr);
	if (m_h245socket) {
		if (m_h245socket->IsConnected()) {
			PTRACE(4, "H245\t" << GetName() << " H245 channel already established");
			return false;
		} else {
			if (m_h245socket->SetH245Address(h245addr, localAddr))
				std::swap(m_h245socket, ret->m_h245socket);
			return true;
		}
	}
	bool userevert = m_isnatsocket || ((m_crv & 0x8000u) && (m_call->GetNATType() & CallRec::citronNAT));
	m_h245socket = userevert ? new NATH245Socket(this) : new H245Socket(this);
	ret->m_h245socket = new H245Socket(m_h245socket, ret);
	m_h245socket->SetH245Address(h245addr, localAddr);
	CreateJob(m_h245socket, &H245Socket::ConnectTo, "H245Connector");
	return true;
}

bool CallSignalSocket::InternalConnectTo()
{
	if (remote->Connect(localAddr, Q931PortRange.GetPort(), peerAddr)) {
		PTRACE(3, "Q931\tConnect to " << remote->GetName() << " successful");
		SetConnected(true);
		remote->SetConnected(true);
		ForwardData();
		return true;
	} else {
		PTRACE(3, "Q931\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");
		SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
		if (m_call)
			m_call->SetCallSignalSocketCalled(NULL);
		CallTable::Instance()->RemoveCall(m_call);
		delete remote;
		remote = NULL;
		return false;
	}
}


// class H245Handler
H245Handler::H245Handler(const PIPSocket::Address & local, const PIPSocket::Address & remote)
      : localAddr(local), remoteAddr(remote), isH245ended(false)
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
	PTRACE(4, "H245\tReceived: " << setprecision(2) << h245msg);

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
			break;
		case H245_MultimediaSystemControlMessage::e_indication:
			changed = HandleIndication(h245msg);
			break;
		default:
			PTRACE(2, "H245\tUnknown H245 message: " << h245msg.GetTag());
			break;
	}
	if (changed) {
		mesg.BeginEncoding();
		h245msg.Encode(mesg);
		mesg.CompleteEncoding();
		PTRACE(5, "H245\tTo send: " << setprecision(2) << h245msg);
	}

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
	if (Command.GetTag() == H245_CommandMessage::e_endSessionCommand)
		isH245ended = true;
	return false;
}

// class H245Socket
H245Socket::H245Socket(CallSignalSocket *sig)
      : TCPProxySocket("H245d"), sigSocket(sig), listener(new TCPSocket)
{
	peerH245Addr = 0;
	listener->Listen(1, H245PortRange.GetPort(), PSocket::CanReuseAddress);
	SetHandler(sig->GetHandler());
}

H245Socket::H245Socket(H245Socket *socket, CallSignalSocket *sig)
      : TCPProxySocket("H245s", socket), sigSocket(sig), listener(0)
{
	peerH245Addr = 0;
	socket->remote = this;
}

H245Socket::~H245Socket()
{
	delete listener;
	delete peerH245Addr;
	if (sigSocket)
		sigSocket->OnH245ChannelClosed();
}

void H245Socket::ConnectTo()
{
	if (remote->Accept(*listener)) {
		if (ConnectRemote()) {
			SetConnected(true);
			remote->SetConnected(true);
			GetHandler()->Insert(this, remote);
			return;
		}
	}
	// establish H.245 channel failed, disconnect the call
	if (sigSocket) {
		sigSocket->SetConnected(false);
		sigSocket->RemoveCall();
		if (!sigSocket->IsBlocked())
		    sigSocket->SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
		sigSocket->CloseSocket();
	}
	if (H245Socket *ret = static_cast<H245Socket *>(remote))
		if (ret->sigSocket) {
			if (ret->sigSocket->IsConnected() && !ret->sigSocket->IsBlocked())
				ret->sigSocket->SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
			ret->sigSocket->SetConnected(false);
			ret->sigSocket->CloseSocket();
		}
	GetHandler()->Insert(this, remote);
}

ProxySocket::Result H245Socket::ReceiveData()
{
	if (!ReadTPKT())
		return NoData;

	PPER_Stream strm(buffer);

	if (sigSocket && sigSocket->HandleH245Mesg(strm))
		buffer = strm;

	return Forwarding;
}

bool H245Socket::EndSession()
{
	if (listener)
		listener->Close();
	return TCPProxySocket::EndSession();
}

void H245Socket::SendEndSessionCommand()
{
	if (!IsConnected())
		return;
	// generate EndSessionCommand
	H245_MultimediaSystemControlMessage h245msg;
	h245msg.SetTag(H245_MultimediaSystemControlMessage::e_command);
	H245_CommandMessage & h245cmd = h245msg;
	h245cmd.SetTag(H245_CommandMessage::e_endSessionCommand);
	H245_EndSessionCommand & endcmd = h245cmd;
	endcmd.SetTag(H245_EndSessionCommand::e_disconnect);
	PPER_Stream wtstrm;
	h245msg.Encode(wtstrm);
	wtstrm.CompleteEncoding();
	TransmitData(wtstrm);
	PTRACE(4, "H245\tSend endSessionCommand to " << GetName());
}

#ifdef LARGE_FDSET
bool H245Socket::Accept(YaTCPSocket & socket)
#else
BOOL H245Socket::Accept(PSocket & socket)
#endif
{
	bool result = TCPProxySocket::Accept(socket);
	if (result) {
		PTRACE(3, "H245\tConnected from " << GetName());
	} else if (peerH245Addr) {
		result = H245Socket::ConnectRemote();
	}
	return result;
}

bool H245Socket::ConnectRemote()
{
	if (listener)
		listener->Close(); // don't accept other connection
	PIPSocket::Address peerAddr;
	WORD peerPort;
	if (!peerH245Addr || !GetIPAndPortFromTransportAddr(*peerH245Addr, peerAddr, peerPort)) {
		PTRACE(3, "H245\tINVALID ADDRESS");
		return false;
	}
	SetPort(peerPort);
	bool result = Connect(INADDR_ANY, H245PortRange.GetPort(), peerAddr); // TODO
	if (result) {
		PTRACE(3, "H245\tConnect to " << GetName() << " successful");
	} else {
		PTRACE(3, "H245\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");
	}
	return result;
}

H225_TransportAddress H245Socket::GetH245Address(const Address & myip)
{
	return SocketToH225TransportAddr(myip, listener ? listener->GetPort() : 0);
}

bool H245Socket::SetH245Address(H225_TransportAddress & h245addr, const Address & myip)
{
	bool swapped;
	H245Socket *socket;
	if (listener) {
		socket = this;
		swapped = false;
	} else {
		socket = static_cast<H245Socket *>(remote);
		swapped = true;
		std::swap(this->sigSocket, socket->sigSocket);
	}
	if (socket->peerH245Addr)
		*socket->peerH245Addr = h245addr;
	else
		socket->peerH245Addr = new H225_TransportAddress(h245addr);
	h245addr = SocketToH225TransportAddr(myip, socket->listener->GetPort());
	PTRACE(3, "H245\tSet h245Address to " << AsDotString(h245addr));
	return swapped;
}

bool H245Socket::Reverting(const H225_TransportAddress & h245addr)
{
	PTRACE(3, "H245\tH.245 Reverting detected");
	TCPSocket *socket = static_cast<H245Socket *>(remote)->listener;
	if (socket && socket->IsOpen()) {
		peerH245Addr = new H225_TransportAddress(h245addr);
		socket->Close();
		return true;
	}
	return false;
}

// class NATH245Socket
bool NATH245Socket::ConnectRemote()
{
	if (!sigSocket || !listener)
		return false;

	Q931 q931;
	sigSocket->BuildFacilityPDU(q931, H225_FacilityReason::e_startH245);
	q931.Encode(buffer);
	sigSocket->TransmitData(buffer);
	bool result = Accept(*listener);
	PTRACE_IF(3, result, "H245\tChannel established for NAT EP");
	listener->Close();
	return result;
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
	mediaChannel = NULL;
	mediaControlChannel = NULL;

	if (!olca.HasOptionalField(H245_OpenLogicalChannelAck::e_forwardMultiplexAckParameters))
		return false;
	H245_OpenLogicalChannelAck_forwardMultiplexAckParameters & ackparams = olca.m_forwardMultiplexAckParameters;
	if (ackparams.GetTag() != H245_OpenLogicalChannelAck_forwardMultiplexAckParameters::e_h2250LogicalChannelAckParameters)
		return false;
	H245_H2250LogicalChannelAckParameters & h225Params = ackparams;

	if (h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaControlChannel))
		mediaControlChannel = GetH245UnicastAddress(h225Params.m_mediaControlChannel);
	if (h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaChannel))
		mediaChannel =  GetH245UnicastAddress(h225Params.m_mediaChannel);

	return mediaControlChannel != NULL;
}

inline H245_UnicastAddress_iPAddress & operator<<(H245_UnicastAddress_iPAddress & addr, const PIPSocket::Address & ip)
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
	port = (WORD)addr.m_tsapIdentifier;
	return addr;
}

inline bool compare_lc(std::pair<const WORD, RTPLogicalChannel *> p, LogicalChannel *lc)
{
	return p.second == lc;
}

} // end of anonymous namespace


#ifndef IPTOS_PREC_CRITIC_ECP
#define IPTOS_PREC_CRITIC_ECP (5 << 5)
#endif

#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY 0x10
#endif

// class UDPProxySocket
UDPProxySocket::UDPProxySocket(const char *t) 
	: ProxySocket(this, t), fDestPort(0), rDestPort(0)
{
	SetReadTimeout(PTimeInterval(50));
	SetWriteTimeout(PTimeInterval(50));
	fnat = rnat = false;
}

bool UDPProxySocket::Bind(WORD pt)
{
	if (!Listen(0, pt))
		return false;

	// Set the IP Type Of Service field for prioritisation of media UDP packets
#ifdef WIN32
	// Windows MultMedia stuff seems to need greater depth due to enormous
	// latencies in its operation, need to use DirectSound maybe?
	int rtpIpTypeofService = IPTOS_PREC_CRITIC_ECP | IPTOS_LOWDELAY;
#else
	// Don't use IPTOS_PREC_CRITIC_ECP on Unix platforms as then need to be root
	int rtpIpTypeofService = IPTOS_LOWDELAY;
#endif
	if (!ConvertOSError(::setsockopt(os_handle, IPPROTO_IP, IP_TOS, (char *)&rtpIpTypeofService, sizeof(int)))) {
		PTRACE(1, Type() << "\tCould not set TOS field in IP header: " << GetErrorText(PSocket::LastGeneralError));
	}
	return true;
}

void UDPProxySocket::SetNAT(bool rev)
{
	fSrcIP = 0;
	fSrcPort = 0;
	rSrcIP = 0;
	rSrcPort = 0;

	// if the handler of lc is NATed,
	// the destination of reverse direction should be changed
	(rev ? fnat : rnat) = true;
	PTRACE(5, Type() << "\tfnat=" << fnat << " rnat=" << rnat);
}

void UDPProxySocket::SetForwardDestination(const Address & srcIP, WORD srcPort, const H245_UnicastAddress_iPAddress & addr)
{
	if( (DWORD)srcIP != 0 )
		fSrcIP = srcIP, fSrcPort = srcPort;
	addr >> fDestIP >> fDestPort;

	if( (DWORD)srcIP )
		SetName(AsString(srcIP, srcPort));
	else
		SetName("(To be autodetected)");
	PTRACE(5, Type() << "\tForward " << GetName() << " to " << fDestIP << ':' << fDestPort);
	SetConnected(true);
}

void UDPProxySocket::SetReverseDestination(const Address & srcIP, WORD srcPort, const H245_UnicastAddress_iPAddress & addr)
{
	if( (DWORD)srcIP != 0 )
		rSrcIP = srcIP, rSrcPort = srcPort;

	addr >> rDestIP >> rDestPort;

	PTRACE(5, Type() << "\tReverse " << srcIP << ':' << srcPort << " to " << rDestIP << ':' << rDestPort);
	SetConnected(true);
}

ProxySocket::Result UDPProxySocket::ReceiveData()
{
	if (!Read(wbuffer, wbufsize)) {
		ErrorHandler(PSocket::LastReadError);
		return NoData;
	}
	Address fromIP;
	WORD fromPort;
	GetLastReceiveAddress(fromIP, fromPort);
	buflen = (WORD)GetLastReadCount();

	/* autodetect channel source IP:PORT that was not specified by OLCs */
	if( rSrcIP == 0 && fromIP == fDestIP )
		rSrcIP = fromIP, rSrcPort = fromPort;
	if( fSrcIP == 0 && fromIP == rDestIP ) {
		fSrcIP = fromIP, fSrcPort = fromPort;
		SetName(AsString(fSrcIP, fSrcPort));
	}

	// Workaround: some bad endpoints don't send packets from the specified port
	if ((fromIP == fSrcIP && fromPort == fSrcPort)
		|| (fromIP == rDestIP && fromIP != rSrcIP)) {
		if (fDestPort) {
			PTRACE(6, Type() << "\tforward " << fromIP << ':' << fromPort << " to " << fDestIP << ':' << fDestPort);
			SetSendAddress(fDestIP, fDestPort);
		} else
			PTRACE(6, Type() << "\tForward from " << fromIP << ':' << fromPort 
				<< " blocked, remote socket (" << fDestIP << ':' << fDestPort
				<< ") not yet known or ready"
				);

		if (rnat)
			rDestIP = fromIP, rDestPort = fromPort;
	} else {
		if (rDestPort) {
			PTRACE(6, Type() << "\tForward " << fromIP << ':' << fromPort << 
				" to " << rDestIP << ':' << rDestPort
				);
			SetSendAddress(rDestIP, rDestPort);
		} else 
			PTRACE(6, Type() << "\tForward from " << fromIP << ':' << fromPort 
				<< " blocked, remote socket (" << rDestIP << ':' << rDestPort
				<< ") not yet known or ready"
				);
		if (fnat)
			fDestIP = fromIP, fDestPort = fromPort;
	}
	return Forwarding;
}

bool UDPProxySocket::WriteData(const BYTE *buffer, int len)
{
	if (!IsSocketOpen())
		return false;

	const int queueSize = GetQueueSize();
	if (queueSize > 0)
		if (queueSize < 50) {
			QueuePacket(buffer, len);
			PTRACE(3, Type() << '\t' << Name() << " socket is busy, " << len << " bytes queued");
			return false;
		} else {
			ClearQueue();
			PTRACE(3, Type() << '\t' << Name() << " socket queue overflow, dropping queued packets");
		}
	
	// check if the remote address to send data to has been already determined
	PIPSocket::Address addr;
	WORD port = 0;
	GetSendAddress(addr, port);
	if (port == 0) {
		QueuePacket(buffer, len);
		PTRACE(3, Type() << '\t' << Name() << " socket has no destination address yet, " << len << " bytes queued");
		return false;
	}
	
	return InternalWriteData(buffer, len);
}

bool UDPProxySocket::Flush()
{
	// check if the remote address to send data to has been already determined
	PIPSocket::Address addr;
	WORD port = 0;
	GetSendAddress(addr, port);
	if (port == 0) {
		PTRACE(3, Type() << '\t' << Name() << " socket has no destination address yet, flush ignored");
		return false;
	}

	bool result = true;
	while (result && GetQueueSize() > 0) {
		PBYTEArray* const pdata = PopQueuedPacket();
		if (pdata) {
			result = InternalWriteData(*pdata, pdata->GetSize());
			PTRACE_IF(4, result, Type() << '\t' << pdata->GetSize() << " bytes flushed to " << Name());
			delete pdata;
		} else
			break;
	}
	return result;
}

bool UDPProxySocket::ErrorHandler(PSocket::ErrorGroup group)
{
	const PString msg = PString(Type()) + "\t" + Name();
	const PSocket::Errors e = GetErrorCode(group);
	
	switch (e)
	{
	//	case PSocket::NoError:
	//	// I don't know why there is error with code NoError
	//		PTRACE(4, msg << " Error(" << group << "): No error?");
	//		break;
		case PSocket::Timeout:
			PTRACE(4, msg << " Error(" << group << "): Timeout");
			break;
		case PSocket::NotOpen:
			CloseSocket();
		default:
			PTRACE(3, msg << " Error(" << group << "): " 
				<< PSocket::GetErrorText(e) << " (" << e << ':' 
				<< GetErrorNumber(group) << ')'
				);
			break;
	}
	return false;
}


// class T120ProxySocket
T120ProxySocket::T120ProxySocket(T120LogicalChannel *lc)
      : TCPProxySocket("T120s"), t120lc(lc)
{
}

T120ProxySocket::T120ProxySocket(T120ProxySocket *socket, WORD pt)
      : TCPProxySocket("T120d", socket, pt)
{
	socket->remote = this;
}

bool T120ProxySocket::ForwardData()
{
	return remote ? remote->ProxySocket::TransmitData(wbuffer, buflen) : false;
}

void T120ProxySocket::Dispatch()
{
	PTRACE(4, "T120\tConnected from " << GetName());
	t120lc->Create(this);
}


// class RTPLogicalChannel
RTPLogicalChannel::RTPLogicalChannel(WORD flcn, bool nated) : LogicalChannel(flcn), reversed(false), peer(0)
{
	SrcIP = 0;
	SrcPort = 0;

	rtp = new UDPProxySocket("RTP");
	rtcp = new UDPProxySocket("RTCP");
	SetNAT(nated);

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

RTPLogicalChannel::RTPLogicalChannel(RTPLogicalChannel *flc, WORD flcn, bool nated)
{
	memcpy(this, flc, sizeof(RTPLogicalChannel)); // bitwise copy :)
	reversed = !flc->reversed;
	peer = flc, flc->peer = this;
	SetChannelNumber(flcn);
	SetNAT(nated);
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

void RTPLogicalChannel::SetMediaControlChannelSource(const H245_UnicastAddress_iPAddress & addr)
{
	addr >> SrcIP >> SrcPort;
	--SrcPort; // get the RTP port
}

void RTPLogicalChannel::SetMediaChannelSource(const H245_UnicastAddress_iPAddress & addr)
{
	addr >> SrcIP >> SrcPort;
}

void RTPLogicalChannel::HandleMediaChannel(H245_UnicastAddress_iPAddress *mediaControlChannel, H245_UnicastAddress_iPAddress *mediaChannel, const PIPSocket::Address & local, bool rev)
{
	// mediaControlChannel should be non-zero.
	H245_UnicastAddress_iPAddress tmp, tmpmedia, tmpmediacontrol, *dest = mediaControlChannel;
	PIPSocket::Address tmpSrcIP = SrcIP;
	WORD tmpSrcPort = SrcPort + 1;

	if (mediaControlChannel == NULL)
		if (mediaChannel == NULL)
			return;
		else {
			tmpmediacontrol = *mediaChannel;
			tmpmediacontrol.m_tsapIdentifier = tmpmediacontrol.m_tsapIdentifier + 1;
			mediaControlChannel = &tmpmediacontrol;
			dest = mediaControlChannel;
		}

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

bool RTPLogicalChannel::OnLogicalChannelParameters(H245_H2250LogicalChannelParameters & h225Params, const PIPSocket::Address & local, bool rev)
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
	GetChannelsFromOLCA(olca, mediaControlChannel, mediaChannel);
	if (mediaControlChannel == NULL && mediaChannel == NULL)
		return false;
	HandleMediaChannel(mediaControlChannel, mediaChannel, handler->GetLocalAddr(), false);
	return true;
}

void RTPLogicalChannel::StartReading(ProxyHandler *handler)
{
	if (!used) {
		RasServer::Instance()->GetRtpProxyHandler()->Insert(rtp, rtcp);
		used = true;
		if (peer)
			peer->used = true;
	}
}

void RTPLogicalChannel::OnHandlerSwapped(bool nated)
{
	rtp->OnHandlerSwapped();
	rtcp->OnHandlerSwapped();
	SetNAT(nated);
}

void RTPLogicalChannel::SetNAT(bool nated)
{
	if (nated)
		rtp->SetNAT(reversed), rtcp->SetNAT(reversed);
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
	listener = new T120Listener(this);
	port = listener->GetPort();
	PTRACE(4, "T120\tOpen logical channel " << flcn << " port " << port);
}

T120LogicalChannel::~T120LogicalChannel()
{
	if (used) {
		RasServer::Instance()->CloseListener(listener);
		ForEachInContainer(sockets, mem_vfun(&T120ProxySocket::SetDeletable));
	} else {
		delete listener;
	}
	PTRACE(4, "T120\tDelete logical channel " << channelNumber);
}

bool T120LogicalChannel::SetDestination(H245_OpenLogicalChannelAck & olca, H245Handler *handler)
{
	return (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_separateStack)) ?
		OnSeparateStack(olca.m_separateStack, handler) : false;
}

void T120LogicalChannel::StartReading(ProxyHandler *h)
{
	if (!used) {
		used = true;
		handler = h;
		RasServer::Instance()->AddListener(listener);
	}
}

T120LogicalChannel::T120Listener::T120Listener(T120LogicalChannel *lc) : t120lc(lc)
{
	Listen(5, T120PortRange.GetPort(), PSocket::CanReuseAddress);
	SetName("T120:" + PString(GetPort()));
}

ServerSocket *T120LogicalChannel::T120Listener::CreateAcceptor() const
{
	return new T120ProxySocket(t120lc);
}

void T120LogicalChannel::Create(T120ProxySocket *socket)
{
	T120ProxySocket *remote = new T120ProxySocket(socket, peerPort);
	if (remote->Connect(INADDR_ANY, T120PortRange.GetPort(), peerAddr)) { // TODO
		PTRACE(3, "T120\tConnect to " << remote->GetName() << " successful");
		socket->SetConnected(true);
		remote->SetConnected(true);
		handler->Insert(socket, remote);
		PWaitAndSignal lock(m_smutex);
		sockets.push_back(socket);
		sockets.push_back(remote);
	} else {
		PTRACE(3, "T120\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");
		delete remote;
		delete socket;
	}
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
H245ProxyHandler::H245ProxyHandler(const PIPSocket::Address & local, const PIPSocket::Address & remote, H245ProxyHandler *pr)
      : H245Handler(local, remote), peer(pr)
{
	if (peer)
		peer->peer = this;
}

H245ProxyHandler::~H245ProxyHandler()
{
	DeleteObjectsInMap(logicalChannels);
	DeleteObjectsInMap(fastStartLCs);
	if (peer)
		peer->peer = 0;
}

bool H245ProxyHandler::HandleRequest(H245_RequestMessage & Request)
{
	PTRACE(4, "H245\tRequest: " << Request.GetTagName());
	if (peer)
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
	if (peer)
		switch (Response.GetTag())
		{
			case H245_ResponseMessage::e_openLogicalChannelAck:
				return HandleOpenLogicalChannelAck(Response);
			case H245_ResponseMessage::e_openLogicalChannelReject:
				return HandleOpenLogicalChannelReject(Response);
			default:
				break;
		}
	return false;
}

bool H245ProxyHandler::OnLogicalChannelParameters(H245_H2250LogicalChannelParameters *h225Params, WORD flcn)
{
	RTPLogicalChannel *lc = (flcn) ?
		CreateRTPLogicalChannel((WORD)h225Params->m_sessionID, flcn) :
		CreateFastStartLogicalChannel((WORD)h225Params->m_sessionID);
	if (!lc)
		return false;

	H245_UnicastAddress_iPAddress *addr;
	bool changed = false;

	if( h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel)
		&& (addr = GetH245UnicastAddress(h225Params->m_mediaControlChannel)) ) {

		lc->SetMediaControlChannelSource(*addr);
		*addr << GetLocalAddr() << (lc->GetPort() + 1);
		changed = true;
	}
	if( h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)
		&& (addr = GetH245UnicastAddress(h225Params->m_mediaChannel)) ) {

		lc->SetMediaChannelSource(*addr);
		*addr << GetLocalAddr() << lc->GetPort();
		changed = true;
	}

	return changed;
}

bool H245ProxyHandler::HandleOpenLogicalChannel(H245_OpenLogicalChannel & olc)
{
	if (hnat)
		hnat->HandleOpenLogicalChannel(olc);
	WORD flcn = (WORD)olc.m_forwardLogicalChannelNumber;
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
	peer->RemoveLogicalChannel((WORD)olcr.m_forwardLogicalChannelNumber);
	return false; // nothing changed :)
}

bool H245ProxyHandler::HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck & olca)
{
	if (hnat)
		hnat->HandleOpenLogicalChannelAck(olca);
	WORD flcn = (WORD)olca.m_forwardLogicalChannelNumber;
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
	// due to bad implementation of some endpoints, we check the
	// forwardLogicalChannelNumber on both sides
	H245ProxyHandler *first, *second;
	if (clc.m_source.GetTag() == H245_CloseLogicalChannel_source::e_lcse)
		first = this, second = peer;
	else
		first = peer, second = this;
	first->RemoveLogicalChannel((WORD)clc.m_forwardLogicalChannelNumber)
		|| second->RemoveLogicalChannel((WORD)clc.m_forwardLogicalChannelNumber);
	return false; // nothing changed :)
}

bool H245ProxyHandler::HandleFastStartSetup(H245_OpenLogicalChannel & olc)
{
	if (!peer)
		return false;
	if (hnat)
		hnat->HandleOpenLogicalChannel(olc);
	bool nouse;
	H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse);
	return (h225Params) ? OnLogicalChannelParameters(h225Params, 0) : false;
}

bool H245ProxyHandler::HandleFastStartResponse(H245_OpenLogicalChannel & olc)
{
	if (!peer)
		return false;
	if (hnat)
		hnat->HandleOpenLogicalChannel(olc);
	WORD flcn = (WORD)olc.m_forwardLogicalChannelNumber;
	bool changed = false, isReverseLC;
	H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, isReverseLC);
	if (!h225Params)
		return false;
	WORD id = (WORD)h225Params->m_sessionID;
	siterator iter = peer->fastStartLCs.find(id);
	RTPLogicalChannel *lc = (iter != peer->fastStartLCs.end()) ? iter->second : 0;
	if (isReverseLC) {
		if (lc) {
			if (!FindLogicalChannel(flcn)) {
				logicalChannels[flcn] = sessionIDs[id] = lc;
				lc->SetChannelNumber(flcn);
				lc->OnHandlerSwapped(hnat != 0);
				peer->fastStartLCs.erase(iter);
			}
		} else if ((lc = peer->FindRTPLogicalChannelBySessionID(id))) {
			LogicalChannel *akalc = FindLogicalChannel(flcn);
			if (akalc)
				lc = static_cast<RTPLogicalChannel *>(akalc);
			else
				logicalChannels[flcn] = sessionIDs[id] = lc = new RTPLogicalChannel(lc, flcn, hnat != 0);
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
				lc = static_cast<RTPLogicalChannel *>(akalc);
			else
				peer->logicalChannels[flcn] = peer->sessionIDs[id] = lc = new RTPLogicalChannel(lc, flcn, hnat != 0);
		}
	}
	if (lc && (changed = lc->OnLogicalChannelParameters(*h225Params, GetLocalAddr(), isReverseLC)))
		lc->StartReading(handler);
	return changed;
}

void H245ProxyHandler::SetHandler(ProxyHandler *h)
{
	handler = h;
	if (peer)
		peer->handler = h;
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
	RTPLogicalChannel *lc = peer->FindRTPLogicalChannelBySessionID(id);
	if (lc && !lc->IsAttached()) {
		lc = new RTPLogicalChannel(lc, flcn, hnat != 0);
	// if H.245 OpenLogicalChannel is received, the fast connect procedure
	// should be disable. So we reuse the fast start logical channel here
	} else if (!fastStartLCs.empty()) {
		siterator iter = fastStartLCs.begin();
		(lc = iter->second)->SetChannelNumber(flcn);
		fastStartLCs.erase(iter);
	} else if (!peer->fastStartLCs.empty()){
		siterator iter = peer->fastStartLCs.begin();
		(lc = iter->second)->SetChannelNumber(flcn);
		lc->OnHandlerSwapped(hnat != 0);
		peer->fastStartLCs.erase(iter);
	} else {
		try {
			lc = new RTPLogicalChannel(flcn, hnat != 0);
		} catch (RTPLogicalChannel::NoPortAvailable) {
			PTRACE(2, "Proxy\tError: Can't create RTP logical channel " << flcn);
			return 0;
		}
	}

	logicalChannels[flcn] = sessionIDs[id] = lc;
	PTRACE(4, "RTP\tOpen logical channel " << flcn << " id " << id << " port " << lc->GetPort());
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
			lc = new RTPLogicalChannel(0, hnat != 0);
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

bool H245ProxyHandler::RemoveLogicalChannel(WORD flcn)
{
	iterator iter = logicalChannels.find(flcn);
	if (iter == logicalChannels.end()) {
		PTRACE(3, "Proxy\tLogical channel " << flcn << " not found");
		return false;
	}
	LogicalChannel *lc = iter->second;
	siterator i = find_if(sessionIDs.begin(), sessionIDs.end(), bind2nd(ptr_fun(compare_lc), lc));
	if (i != sessionIDs.end())
		sessionIDs.erase(i);
	logicalChannels.erase(iter);
	delete lc;
	return true;
}

// class NATHandler
void NATHandler::TranslateH245Address(H225_TransportAddress & h245addr)
{
	if (h245addr.GetTag() == H225_TransportAddress::e_ipAddress) {
		H225_TransportAddress_ipAddress & addr = h245addr;
		for (int i = 0; i < 4; ++i)
			addr.m_ip[i] = remoteAddr[i];
	}
}

bool NATHandler::HandleOpenLogicalChannel(H245_OpenLogicalChannel & olc)
{
	bool changed = false;
	if (IsT120Channel(olc) && olc.HasOptionalField(H245_OpenLogicalChannel::e_separateStack)) {
		if (olc.m_separateStack.m_networkAddress.GetTag() == H245_NetworkAccessParameters_networkAddress::e_localAreaAddress)
			changed = SetAddress(GetH245UnicastAddress(olc.m_separateStack.m_networkAddress));
	} else {
		bool nouse;
		if (H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse)) {
			if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel))
				changed = SetAddress(GetH245UnicastAddress(h225Params->m_mediaControlChannel));
			if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel))
				changed |= SetAddress(GetH245UnicastAddress(h225Params->m_mediaChannel));
		}
	}
	return changed;
}

bool NATHandler::HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck & olca)
{
	if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_separateStack)) {
		H245_NetworkAccessParameters & sepStack = olca.m_separateStack;
		if (sepStack.m_networkAddress.GetTag() == H245_NetworkAccessParameters_networkAddress::e_localAreaAddress)
			return SetAddress(GetH245UnicastAddress(sepStack.m_networkAddress));
	} else {
		H245_UnicastAddress_iPAddress *mediaControlChannel, *mediaChannel;
		GetChannelsFromOLCA(olca, mediaControlChannel, mediaChannel);
		bool changed = SetAddress(mediaChannel);
		changed = SetAddress(mediaControlChannel) || changed;
		return changed;
	}
	return false;
}

bool NATHandler::SetAddress(H245_UnicastAddress_iPAddress * addr)
{
	return addr ? (*addr << remoteAddr, true) : false;
}


// class CallSignalListener
CallSignalListener::CallSignalListener(const Address & addr, WORD pt)
{
	unsigned queueSize = GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH);
	Listen(addr, queueSize, pt, PSocket::CanReuseAddress);
	SetName(AsString(addr, GetPort()));
}

ServerSocket *CallSignalListener::CreateAcceptor() const
{
	return new CallSignalSocket;
}


// class ProxyHandler
ProxyHandler::ProxyHandler(
	const PString& name
	) 
	: SocketsReader(100)
{
	SetName(name);
	Execute();
}

ProxyHandler::~ProxyHandler()
{
	DeleteObjectsInContainer(m_removedTime);
}

void ProxyHandler::Insert(TCPProxySocket *socket)
{
	socket->SetHandler(this);
	AddSocket(socket);
}

void ProxyHandler::Insert(TCPProxySocket *first, TCPProxySocket *second)
{
	first->SetHandler(this);
	second->SetHandler(this);
	AddPairSockets(first, second);
}

void ProxyHandler::Insert(UDPProxySocket *rtp, UDPProxySocket *rtcp)
{
	//rtp->SetHandler(this);
	//rtcp->SetHandler(this);
	AddPairSockets(rtp, rtcp);
}

void ProxyHandler::MoveTo(ProxyHandler *dest, TCPProxySocket *socket)
{
	m_listmutex.StartWrite();
	m_sockets.remove(socket);
	m_listmutex.EndWrite();
	dest->Insert(socket);
}

void ProxyHandler::OnStart()
{
	PThread::Current()->SetPriority(PThread::HighPriority);
}

bool ProxyHandler::BuildSelectList(SocketSelectList & slist)
{
	FlushSockets();
	WriteLock lock(m_listmutex);
	iterator i = m_sockets.begin(), j = m_sockets.end();
	while (i != j) {
		iterator k=i++;
		ProxySocket *socket = dynamic_cast<ProxySocket *>(*k);
		if (!socket->IsBlocked()) {
			if (socket->IsSocketOpen())
				slist.Append(*k);
			else if (!socket->IsConnected()) {
				Remove(k);
				continue;
			}
			if (socket->IsDeletable())
				Remove(k);
		}
	}
	return slist.GetSize() > 0;
}

void ProxyHandler::ReadSocket(IPSocket *socket)
{
	ProxySocket *psocket = dynamic_cast<ProxySocket *>(socket);
	switch (psocket->ReceiveData())
	{
		case ProxySocket::Connecting:
			PTRACE(1, "Error\tcheck the code " << psocket->Type());
			break;
		case ProxySocket::Forwarding:
			if (!psocket->ForwardData()) {
				PTRACE(3, "Proxy\t" << psocket->Name() << " forward blocked");
			}
			break;
		case ProxySocket::Closing:
			psocket->ForwardData();
			socket->Close();
			break;
		case ProxySocket::Error:
			psocket->OnError();
			socket->Close();
			break;
		default:
			break;
	}
}

void ProxyHandler::CleanUp()
{
	if (m_rmsize > 0) {
		PTime now;
		PWaitAndSignal lock(m_rmutex);
		iterator i = m_removed.begin();
		std::list<PTime *>::iterator ti = m_removedTime.begin();
		while ((i != m_removed.end()) && ((now - **ti).GetSeconds() > 5)) {
			IPSocket * s = *i;
			PTime * t = *ti;
			m_removed.erase(i);
			m_removedTime.erase(ti);
			delete s;
			delete t;
			i = m_removed.begin();
			ti = m_removedTime.begin();
			--m_rmsize;
		}
	}
}

void ProxyHandler::AddPairSockets(IPSocket *first, IPSocket *second)
{
	m_listmutex.StartWrite();
	m_sockets.push_back(first);
	m_sockets.push_back(second);
	m_socksize += 2;
	m_listmutex.EndWrite();
	Signal();
	PTRACE(5, GetName() << " total sockets " << m_socksize);
}

void ProxyHandler::FlushSockets()
{
	SocketSelectList wlist;
	m_listmutex.StartRead();
	iterator i = m_sockets.begin(), j = m_sockets.end();
	while (i != j) {
		if (dynamic_cast<ProxySocket *>(*i)->CanFlush())
			wlist.Append(*i);
		++i;
	}
	m_listmutex.EndRead();
	if (wlist.IsEmpty())
		return;

	if (!wlist.Select(SocketSelectList::Write, PTimeInterval(10)))
	       return;

	PTRACE(5, "Proxy\t" << wlist.GetSize() << " sockets to flush...");
	for (int k = 0; k < wlist.GetSize(); ++k) {
		ProxySocket *socket = dynamic_cast<ProxySocket *>(wlist[k]);
		if (socket->Flush()) {
			PTRACE(4, "Proxy\t" << socket->Name() << " flush ok");
		}
	}
}

void ProxyHandler::Remove(iterator i)
{
	// assume the list is locked for writing
	IPSocket *socket = *i;
	m_sockets.erase(i);
	--m_socksize;
	PWaitAndSignal lock(m_rmutex);
	m_removed.push_back(socket);
	m_removedTime.push_back(new PTime);
	++m_rmsize;
}


// class HandlerList
HandlerList::HandlerList() : m_numSigHandlers(0), m_numRtpHandlers(0),
	m_currentSigHandler(0), m_currentRtpHandler(0)
{
	LoadConfig();
}

HandlerList::~HandlerList()
{
	PWaitAndSignal lock(m_handlerMutex);
	ForEachInContainer(m_sigHandlers, mem_vfun(&ProxyHandler::Stop));
	ForEachInContainer(m_rtpHandlers, mem_vfun(&ProxyHandler::Stop));
}

ProxyHandler *HandlerList::GetSigHandler()
{
	PWaitAndSignal lock(m_handlerMutex);
	ProxyHandler* const result = m_sigHandlers[m_currentSigHandler];
	if (++m_currentSigHandler >= m_numSigHandlers)
		m_currentSigHandler = 0;
	return result;
}

ProxyHandler *HandlerList::GetRtpHandler()
{
	PWaitAndSignal lock(m_handlerMutex);
	ProxyHandler* const result = m_rtpHandlers[m_currentRtpHandler];
	if (++m_currentRtpHandler >= m_numRtpHandlers)
		m_currentRtpHandler = 0;
	return result;
}

void HandlerList::LoadConfig()
{
	PWaitAndSignal lock(m_handlerMutex);
	
	Q931PortRange.LoadConfig(RoutedSec, "Q931PortRange");
	H245PortRange.LoadConfig(RoutedSec, "H245PortRange");
	T120PortRange.LoadConfig(ProxySection, "T120PortRange");
	RTPPortRange.LoadConfig(ProxySection, "RTPPortRange", "10000-59999");

	m_numSigHandlers = GkConfig()->GetInteger(RoutedSec, "CallSignalHandlerNumber", 1);
	if (m_numSigHandlers < 1)
		m_numSigHandlers = 1;
	if (m_numSigHandlers > 200)
		m_numSigHandlers = 200;
	unsigned hs = m_sigHandlers.size();
	if (hs <= m_numSigHandlers) {
		for (unsigned i = hs; i < m_numSigHandlers; ++i)
			m_sigHandlers.push_back(
				new ProxyHandler(psprintf("ProxyH(%d)", i))
				);
	} else {
//		int ds = hs - m_numSigHandlers;
//		for (int i = 0; i < hs && ds > 0; ++i) {
			// TODO
//		}
		m_currentSigHandler = 0;
	}

	m_numRtpHandlers = GkConfig()->GetInteger(RoutedSec, "RtpHandlerNumber", 1);
	if (m_numRtpHandlers < 1)
		m_numRtpHandlers = 1;
	if (m_numRtpHandlers > 200)
		m_numRtpHandlers = 200;
	hs = m_rtpHandlers.size();
	if (hs <= m_numRtpHandlers) {
		for (unsigned i = hs; i < m_numRtpHandlers; ++i)
			m_rtpHandlers.push_back(
				new ProxyHandler(psprintf("ProxyRTP(%d)", i))
				);
	} else {
//		unsigned ds = hs - m_numRtpHandlers;
//		for (int i = 0; i < hs && ds > 0; ++i) {
			// TODO
//		}
		m_currentRtpHandler = 0;
	}
}
