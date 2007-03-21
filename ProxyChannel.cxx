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

#if defined(_WIN32) && (_MSC_VER <= 1200)
#pragma warning(disable:4786) // warning about too long debug symbol off
#pragma warning(disable:4284)
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
#include "sigmsg.h"
#include "ProxyChannel.h"

using namespace std;
using Routing::Route;

namespace {
// default timeout (ms) for initial Setup message,
// if not specified in the config file
const long DEFAULT_SETUP_TIMEOUT = 8000;
// time to wait before deleting a closed socket
const long DEFAULT_SOCKET_CLEANUP_TIMEOUT = 5000;
// if socket bind fails, try next DEFAULT_NUM_SEQ_PORTS subsequent port numbers
const int DEFAULT_NUM_SEQ_PORTS = 500;

template <class UUIE>
inline unsigned GetH225Version(const UUIE &uuie)
{
	if (uuie.m_protocolIdentifier.GetSize() < 6)
		return 0;
	else
		return uuie.m_protocolIdentifier[5];
}


H245_UnicastAddress_iPAddress *GetH245UnicastAddress(H245_TransportAddress & tsap)
{
	if (tsap.GetTag() == H245_TransportAddress::e_unicastAddress) {
		H245_UnicastAddress & uniaddr = tsap;
		if (uniaddr.GetTag() == H245_UnicastAddress::e_iPAddress)
			return &((H245_UnicastAddress_iPAddress &)uniaddr);
	}
	return 0;
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

PString GetH245CodecName(const H245_AudioCapability &cap)
{
	switch (cap.GetTag()) {
	case H245_AudioCapability::e_g711Alaw64k:
	case H245_AudioCapability::e_g711Alaw56k:
	case H245_AudioCapability::e_g711Ulaw64k:
	case H245_AudioCapability::e_g711Ulaw56k:
		return "G711";
	case H245_AudioCapability::e_g722_64k:
	case H245_AudioCapability::e_g722_56k:
	case H245_AudioCapability::e_g722_48k:
		return "G722";
	case H245_AudioCapability::e_g7231:
		return "G7231";
	case H245_AudioCapability::e_g728:
		return "G728";
	case H245_AudioCapability::e_g729:
		return "G729";
	case H245_AudioCapability::e_g729AnnexA:
		return "G729A";
	case H245_AudioCapability::e_g729wAnnexB:
		return "G729B";
	case H245_AudioCapability::e_g729AnnexAwAnnexB:
		return "G729AB";
	case H245_AudioCapability::e_g7231AnnexCCapability:
		return "G7231C";
	case H245_AudioCapability::e_gsmFullRate:
	case H245_AudioCapability::e_gsmHalfRate:
	case H245_AudioCapability::e_gsmEnhancedFullRate:
		return "GSM";
	}
	return "Unknown";
}

} // end of anonymous namespace 

const char* RoutedSec = "RoutedMode";
const char* ProxySection = "Proxy";
const char* H225_ProtocolID = "0.0.8.2250.0.2";

struct PortRange {
	PortRange() : port(0), minport(0), maxport(0) {}
	
	WORD GetPort();
	int GetNumPorts() const;
	void LoadConfig(const char *, const char *, const char * = "");

private:
	PortRange(const PortRange&);
	PortRange& operator=(const PortRange&);
	
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
	if (port < minport) // special case to check for 16-bit wrap around
		port = minport;
	if (port == 0)
		port = 1;
	return result;
}

int PortRange::GetNumPorts() const
{
	return maxport - minport + 1;
}

void PortRange::LoadConfig(const char *sec, const char *setting, const char *def)
{
	PStringArray cfgs = GkConfig()->GetString(sec, setting, def).Tokenise(",.:-/'", FALSE);
	if (cfgs.GetSize() >= 2) {
		minport = (WORD)cfgs[0].AsUnsigned(), maxport = (WORD)cfgs[1].AsUnsigned();
		if (port < minport || port > maxport)
			port = minport;
	} else
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
	void OnSignalingChannelClosed();
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

private:
	H245Socket();
	H245Socket(const H245Socket&);
	H245Socket& operator=(const H245Socket&);

	// override from class ServerSocket
	virtual void Dispatch() { /* useless */ }

protected:
	CallSignalSocket *sigSocket;
	H225_TransportAddress *peerH245Addr;
	TCPSocket *listener;
	/// to avoid race condition inside calls between this socket and its signaling socket
	PMutex m_signalingSocketMutex;
};

class NATH245Socket : public H245Socket {
public:
#ifndef LARGE_FDSET
	PCLASSINFO ( NATH245Socket, H245Socket )
#endif
	NATH245Socket(CallSignalSocket *sig) : H245Socket(sig) {}

private:
	NATH245Socket();
	NATH245Socket(const NATH245Socket&);
	NATH245Socket& operator=(const NATH245Socket&);

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
	bool Bind(const Address &localAddr, WORD pt);
	void SetNAT(bool);
	bool isMute() { return mute; };
	void SetMute(bool toMute) { mute = toMute; }
	void OnHandlerSwapped() { std::swap(fnat, rnat); }

	// override from class ProxySocket
	virtual Result ReceiveData();

protected:
	virtual bool WriteData(const BYTE *, int);
	virtual bool Flush();
	virtual bool ErrorHandler(PSocket::ErrorGroup);

private:
	UDPProxySocket();
	UDPProxySocket(const UDPProxySocket&);
	UDPProxySocket& operator=(const UDPProxySocket&);

private:
	Address fSrcIP, fDestIP, rSrcIP, rDestIP;
	WORD fSrcPort, fDestPort, rSrcPort, rDestPort;
	bool fnat, rnat;
	bool mute;
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
	T120ProxySocket(const T120ProxySocket&);
	T120ProxySocket& operator=(const T120ProxySocket&);

	// override from class ServerSocket
	virtual void Dispatch();

private:
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
	virtual void SetRTPMute(bool toMute) = 0;

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
	virtual void SetRTPMute(bool toMute);
	bool IsAttached() const { return (peer != 0); }
	void OnHandlerSwapped(bool);

	bool IsOpen() const;

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
	virtual void SetRTPMute(bool toMute) {};   /// We do not Mute T.120 Channels

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
    bool ChangeAddress(H245_UnicastAddress_iPAddress * addr);
	PIPSocket::Address remoteAddr;
};

class H245Handler {
// This class handles H.245 messages which can either be transmitted on their
// own TCP connection or can be tunneled in the Q.931 connection
public:
	H245Handler(const PIPSocket::Address & local, const PIPSocket::Address & remote,
		             const PIPSocket::Address & masq);
	virtual ~H245Handler();

	virtual void OnH245Address(H225_TransportAddress &);
	virtual bool HandleMesg(H245_MultimediaSystemControlMessage &);
	virtual bool HandleFastStartSetup(H245_OpenLogicalChannel &);
	virtual bool HandleFastStartResponse(H245_OpenLogicalChannel &);
	typedef bool (H245Handler::*pMem)(H245_OpenLogicalChannel &);

	PIPSocket::Address GetLocalAddr() const { return localAddr; }
    PIPSocket::Address GetRemoteAddr() const { return remoteAddr; }
    PIPSocket::Address GetMasqAddr() const { return masqAddr; }

	void SetLocalAddr(const PIPSocket::Address & local) { localAddr = local; }
	bool IsSessionEnded() const { return isH245ended; }

protected:
	virtual bool HandleRequest(H245_RequestMessage &);
	virtual bool HandleResponse(H245_ResponseMessage &);
	virtual bool HandleCommand(H245_CommandMessage &);
	virtual bool HandleIndication(H245_IndicationMessage &);

	NATHandler *hnat;

private:
	PIPSocket::Address localAddr, remoteAddr, masqAddr;
	bool isH245ended;
};

class H245ProxyHandler : public H245Handler {
public:
	typedef std::map<WORD, LogicalChannel *>::iterator iterator;
	typedef std::map<WORD, LogicalChannel *>::const_iterator const_iterator;
	typedef std::map<WORD, RTPLogicalChannel *>::iterator siterator;
	typedef std::map<WORD, RTPLogicalChannel *>::const_iterator const_siterator;

	H245ProxyHandler(const PIPSocket::Address &, const PIPSocket::Address &, const PIPSocket::Address &, H245ProxyHandler * = 0);
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
	virtual bool HandleIndication(H245_IndicationMessage &);

	bool OnLogicalChannelParameters(H245_H2250LogicalChannelParameters *, WORD);
	bool HandleOpenLogicalChannel(H245_OpenLogicalChannel &);
	bool HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck &);
	bool HandleOpenLogicalChannelReject(H245_OpenLogicalChannelReject &);
	bool HandleCloseLogicalChannel(H245_CloseLogicalChannel &);
	void HandleMuteRTPChannel();

	RTPLogicalChannel *CreateRTPLogicalChannel(WORD, WORD);
	RTPLogicalChannel *CreateFastStartLogicalChannel(WORD);
	T120LogicalChannel *CreateT120LogicalChannel(WORD);
	bool RemoveLogicalChannel(WORD flcn);

	std::map<WORD, LogicalChannel *> logicalChannels;
	std::map<WORD, RTPLogicalChannel *> sessionIDs;
	std::map<WORD, RTPLogicalChannel *> fastStartLCs;
	ProxyHandler *handler;
	H245ProxyHandler *peer;
	bool isMute;
};


// class ProxySocket
ProxySocket::ProxySocket(
	IPSocket *s,
	const char *t,
	WORD buffSize
	) : USocket(s, t), wbuffer(new BYTE[buffSize]), wbufsize(buffSize), buflen(0),
	connected(false), deletable(false), handler(NULL)
{
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
	Address raddr;
	WORD rport = 0;
	GetPeerAddress(raddr, rport);
	SetName(AsString(raddr, rport));
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
	if (this->GetHandle() < FD_SETSIZE)
		if (!YaSelectList(GetName(), this).Select(YaSelectList::Read, 0))
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

void TCPProxySocket::RemoveRemoteSocket()
{
	remote = NULL;
}


// class CallSignalSocket
CallSignalSocket::CallSignalSocket()
	: TCPProxySocket("Q931s"), m_callerSocket(true)
{
	InternalInit();
	localAddr = peerAddr = masqAddr = INADDR_ANY;
	m_h245Tunneling = true;
	SetHandler(RasServer::Instance()->GetSigProxyHandler());
}

CallSignalSocket::CallSignalSocket(CallSignalSocket *socket)
	: TCPProxySocket("Q931d", socket), m_callerSocket(false)
{
	InternalInit();
	remote = socket;
	m_call = socket->m_call;
}

CallSignalSocket::CallSignalSocket(CallSignalSocket *socket, WORD port)
	: TCPProxySocket("Q931d", socket, port), m_callerSocket(false)
{
	InternalInit();
	SetRemote(socket);
}

void CallSignalSocket::InternalInit()
{
	m_crv = 0;
	m_h245handler = NULL;
	m_h245socket = NULL;
	m_isnatsocket = false;
	m_result = NoData;
	m_setupPdu = NULL;
	// m_callerSocket is always initialized in init list
	m_h225Version = 0;
}

void CallSignalSocket::SetRemote(CallSignalSocket *socket)
{
	remote = socket;
	m_call = socket->m_call;
	m_call->SetSocket(socket, this);
	m_crv = (socket->m_crv & 0x7fffu);
	m_h245Tunneling = socket->m_h245Tunneling;
	socket->GetPeerAddress(peerAddr, peerPort);
	localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
    masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
	
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
	if (m_call->GetProxyMode() == CallRec::ProxyDetect)
		if (Toolkit::Instance()->ProxyRequired(peerAddr, socket->peerAddr) 
				|| (type != CallRec::none && Toolkit::AsBool(GkConfig()->GetString(ProxySection, "ProxyForNAT", "1"))))
			m_call->SetProxyMode(CallRec::ProxyEnabled);
		else
			m_call->SetProxyMode(CallRec::ProxyDisabled);
			
	if (m_call->GetProxyMode() == CallRec::ProxyEnabled) {
		H245ProxyHandler *proxyhandler = new H245ProxyHandler(socket->localAddr, calling, socket->masqAddr);
		socket->m_h245handler = proxyhandler;
		m_h245handler = new H245ProxyHandler(localAddr, called, masqAddr, proxyhandler);
		proxyhandler->SetHandler(GetHandler());
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled");
	} else if (m_call->IsH245Routed()) {
		socket->m_h245handler = new H245Handler(socket->localAddr, calling, socket->masqAddr);
		m_h245handler = new H245Handler(localAddr, called, masqAddr);
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
	}
	
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

	delete m_h245handler;
	m_h245handler = NULL;
	delete m_setupPdu;
	m_setupPdu = NULL;
}

#ifdef LARGE_FDSET
bool CallSignalSocket::Connect(const Address & addr)
#else
BOOL CallSignalSocket::Connect(const Address & addr)
#endif
{
	Address local = RasServer::Instance()->GetLocalAddress(addr);
	int numPorts = min(Q931PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = Q931PortRange.GetPort();
		if (TCPProxySocket::Connect(local, pt, addr))
			return true;
		int errorNumber = GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, Type() << "\tCould not open/connect Q.931 socket at " << local << ':' << pt
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << GetErrorText(PSocket::LastGeneralError)
			);
		Close();
#ifdef _WIN32
		if ((errorNumber & PWIN32ErrorFlag) == 0
				|| (errorNumber & ~PWIN32ErrorFlag) != WSAEADDRINUSE)
			break;
#else
		if (!(errorNumber == EADDRINUSE || errorNumber == EINVAL))
			break;
#endif
	}
	return false;
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

bool GetUUIE(const Q931 & q931, H225_H323_UserInformation & uuie)
{
	if (q931.HasIE(Q931::UserUserIE)) {
		PPER_Stream strm(q931.GetIE(Q931::UserUserIE));
		if (uuie.Decode(strm))
			return true;
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
	if (m_call) {
		m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
		CallTable::Instance()->RemoveCall(m_call);
	}
}

ProxySocket::Result CallSignalSocket::ReceiveData()
{
	if (!ReadTPKT())
		return IsOpen() ? NoData : Error;

	H225_H323_UserInformation *uuie = NULL;
	Q931 *q931pdu = new Q931();

	if (!q931pdu->Decode(buffer)) {
		PTRACE(1, Type() << "\t" << GetName() << " ERROR DECODING Q.931!");
		delete q931pdu;
		q931pdu = NULL;
		return m_result = Error;
	}

	PIPSocket::Address _localAddr, _peerAddr;
	WORD _localPort = 0, _peerPort = 0;
	GetLocalAddress(_localAddr, _localPort);
	GetPeerAddress(_peerAddr, _peerPort);
	
	PTRACE(3, Type() << "\tReceived: " << q931pdu->GetMessageTypeName()
		<< " CRV=" << q931pdu->GetCallReference() << " from " << GetName()
		);

	if (q931pdu->HasIE(Q931::UserUserIE)) {
		uuie = new H225_H323_UserInformation();
		if (!GetUUIE(*q931pdu, *uuie)) {
			PTRACE(1, Type() << "\tCould not decode User-User IE for message " 
				<< q931pdu->GetMessageTypeName() << " CRV=" 
				<< q931pdu->GetCallReference() << " from " << GetName()
				);
			if (q931pdu->GetMessageType() == Q931::NotifyMsg) {
				PTRACE(1, "Unknown User-User IE in Notify, continuing");
				uuie = NULL;
				m_result = Forwarding;
			} else {
				delete uuie;
				uuie = NULL;
				delete q931pdu;
				q931pdu = NULL;
				return m_result = Error;
			}
		}
	}
	
	m_result = Forwarding;
	
	PrintQ931(4, "Received:", "", q931pdu, uuie);

	SignalingMsg *msg = SignalingMsg::Create(q931pdu, uuie, 
		_localAddr, _localPort, _peerAddr, _peerPort
		);

	if (m_h245Tunneling && uuie != NULL)
#if H225_PROTOCOL_VERSION >= 4
		if(!uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_provisionalRespToH245Tunneling))
#endif
		m_h245Tunneling = (uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling)
			&& uuie->m_h323_uu_pdu.m_h245Tunneling.GetValue());

	switch (msg->GetTag()) {
	case Q931::SetupMsg:
		m_rawSetup = buffer;
		m_rawSetup.MakeUnique();
		OnSetup(msg);
		break;
	case Q931::CallProceedingMsg:
		OnCallProceeding(msg);
		break;
	case Q931::ConnectMsg:
		OnConnect(msg);
		break;
	case Q931::AlertingMsg:
		OnAlerting(msg);
		break;
	case Q931::ReleaseCompleteMsg:
		OnReleaseComplete(msg);
		break;
	case Q931::FacilityMsg:
		OnFacility(msg);
		break;
	case Q931::ProgressMsg:
		OnProgress(msg);
		break;
	case Q931::InformationMsg:
		OnInformation(msg);
		break;
	}

	if (!m_callerSocket && m_call && msg->GetTag() != Q931::CallProceedingMsg)
		m_call->SetCallInProgress();

	if (m_result == Error || m_result == NoData) {
		delete msg;
		return m_result;
	}
	
	if (msg->GetUUIE() != NULL && msg->GetUUIE()->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control)) {
		if (m_h245handler && OnTunneledH245(msg->GetUUIE()->m_h323_uu_pdu.m_h245Control))
			msg->SetUUIEChanged();
		if (!m_callerSocket && m_call)
			m_call->SetH245ResponseReceived();
	}
	
	if (msg->GetQ931().HasIE(Q931::DisplayIE)) {
		const PString s = GkConfig()->GetString(RoutedSec, "ScreenDisplayIE", "");
		if (!s) {
			msg->GetQ931().SetDisplayName(s);
			msg->SetChanged();
		}
	}

	// just copy unknow IEs in Notify
	if ((q931pdu->GetMessageType() == Q931::NotifyMsg)
		&& (q931pdu->HasIE(Q931::UserUserIE))
		&& (uuie == NULL)) {
		PTRACE(1, "Copy unknown User-User IE in Notify");
		msg->GetQ931().SetIE(Q931::UserUserIE, q931pdu->GetIE(Q931::UserUserIE));
	}

	if (msg->IsChanged() && !msg->Encode(buffer))
		m_result = Error;
	else if (remote)
		PrintQ931(4, "Send to ", remote->GetName(), &msg->GetQ931(), msg->GetUUIE());

	delete msg;
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
					Toolkit::Instance()->MapH225ReasonToQ931Cause(uuie.m_reason.GetTag())
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

	PrintQ931(4, "Send to ", GetName(), &ReleasePDU, &signal);
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
	H245_MultimediaSystemControlMessage h245msg;
	if (!h245msg.Decode(strm)) {
		PTRACE(4, "H245\tERROR DECODING H.245");
		return false;
	}
	PTRACE(4, "H245\tReceived: " << setprecision(2) << h245msg);

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_request
			&& ((H245_RequestMessage&)h245msg).GetTag() == H245_RequestMessage::e_openLogicalChannel) {
		H245_OpenLogicalChannel &olc = (H245_RequestMessage&)h245msg;
		if (m_callerSocket) {
			if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
					&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData
					&& olc.m_reverseLogicalChannelParameters.HasOptionalField(H245_OpenLogicalChannel_reverseLogicalChannelParameters::e_multiplexParameters)
					&& olc.m_reverseLogicalChannelParameters.m_multiplexParameters.GetTag() == H245_OpenLogicalChannel_reverseLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters) {
				H245_H2250LogicalChannelParameters *channel = &((H245_H2250LogicalChannelParameters&)olc.m_reverseLogicalChannelParameters.m_multiplexParameters);
				if (channel != NULL && channel->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)) {
					H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(channel->m_mediaChannel);
					if (addr != NULL && m_call) {
						PIPSocket::Address ip;
						*addr >> ip;
						m_call->SetMediaOriginatingIp(ip);
					}
				}
			}
		}
		H245_AudioCapability *audioCap = NULL;
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
				&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData) {
			audioCap = &((H245_AudioCapability&)olc.m_reverseLogicalChannelParameters.m_dataType);
		} else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData) {
			audioCap = &((H245_AudioCapability&)olc.m_forwardLogicalChannelParameters.m_dataType);
		}
		if (audioCap != NULL && m_call)
			m_call->SetCodec(GetH245CodecName(*audioCap));
	}

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_response
			&& ((H245_ResponseMessage&)h245msg).GetTag() == H245_ResponseMessage::e_openLogicalChannelAck) {
		H245_OpenLogicalChannelAck &olcack = (H245_ResponseMessage&)h245msg;
		if (m_callerSocket) {
			if (olcack.HasOptionalField(H245_OpenLogicalChannelAck::e_forwardMultiplexAckParameters)
					&& olcack.m_forwardMultiplexAckParameters.GetTag() == H245_OpenLogicalChannelAck_forwardMultiplexAckParameters::e_h2250LogicalChannelAckParameters) {
				H245_H2250LogicalChannelAckParameters *channel = &((H245_H2250LogicalChannelAckParameters&)olcack.m_forwardMultiplexAckParameters);
				if (channel != NULL && channel->HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaChannel)) {
					H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(channel->m_mediaChannel);
					if (addr != NULL && m_call) {
						PIPSocket::Address ip;
						*addr >> ip;
						m_call->SetMediaOriginatingIp(ip);
					}
				}
			}
		}
	}
	
	if (!m_h245handler->HandleMesg(h245msg))
		return false;

	strm.BeginEncoding();
	h245msg.Encode(strm);
	strm.CompleteEncoding();
	PTRACE(5, "H245\tTo send: " << setprecision(2) << h245msg);

	return true;
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

void CallSignalSocket::RemoveH245Handler()
{
	H245Handler *h = m_h245handler;
	m_h245handler = NULL;
	delete h;
}

void CallSignalSocket::OnError()
{
	if (m_call) {
		m_call->SetDisconnectCause(Q931::ProtocolErrorUnspecified);
		RemoveCall();
	}
	EndSession();
	if (remote)
		remote->EndSession();
}

void CallSignalSocket::ForwardCall(
	FacilityMsg *msg
	)
{
	ReadLock configLock(ConfigReloadMutex);
	MarkSocketBlocked lock(this);

	H225_Facility_UUIE &facilityBody = msg->GetUUIEBody();

	endptr forwarded;
	Routing::FacilityRequest request(facilityBody, msg);
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	if (aliases)
		Toolkit::Instance()->RewriteE164(*aliases);
		
	request.Process();
	Route route;
	if (!request.GetFirstRoute(route)) {
		ForwardData();
		delete msg;
		msg = NULL;
		return;
	}

	forwarded = route.m_destEndpoint;
	
	PString forwarder;
	if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_featureSet) 
			&& facilityBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)) {
		// get the forwarder
		H225_ArrayOf_FeatureDescriptor &fd = facilityBody.m_featureSet.m_neededFeatures;
		if (fd.GetSize() > 0 && fd[0].HasOptionalField(H225_FeatureDescriptor::e_parameters))
			if (fd[0].m_parameters.GetSize() > 0) {
				H225_EnumeratedParameter &parm = fd[0].m_parameters[0];
				if (parm.HasOptionalField(H225_EnumeratedParameter::e_content))
					if (parm.m_content.GetTag() == H225_Content::e_alias)
						forwarder = AsString((const H225_AliasAddress&)parm.m_content, FALSE) + ":forward";
			}
	}
	PString altDestInfo(aliases ? AsString(*aliases) : AsDotString(route.m_destAddr));
	CallSignalSocket *fsocket = (facilityBody.m_reason.GetTag() == H225_FacilityReason::e_callForwarded) 
		? this : NULL;
	m_call->SetForward(fsocket, route.m_destAddr, forwarded, forwarder, altDestInfo);
	if (route.m_flags & Route::e_toParent)
		m_call->SetToParent(true);

	PTRACE(3, Type() << "\tCall " << m_call->GetCallNumber() << " is forwarded to "
		<< altDestInfo << (!forwarder ? (" by " + forwarder) : PString())
		);

	// disconnect from forwarder
	SendReleaseComplete(H225_ReleaseCompleteReason::e_facilityCallDeflection);
	Close();

	CallSignalSocket *remoteSocket = static_cast<CallSignalSocket *>(remote);
	if (!remoteSocket) {
		PTRACE(1, Type() << "\tWarning: " << GetName() << " has no remote party?");
		delete msg;
		msg = NULL;
		return;
	}
	MarkSocketBlocked rlock(remoteSocket);
	if (!remoteSocket->m_setupPdu) {
		PTRACE(1, Type() << "\tError: " << GetName() << " has no Setup message stored!");
		delete msg;
		msg = NULL;
		return;
	}

	Q931 fakeSetup(*remoteSocket->m_setupPdu);
	H225_H323_UserInformation suuie;
	if (!GetUUIE(fakeSetup, suuie)
			|| suuie.m_h323_uu_pdu.m_h323_message_body.GetTag() !=  H225_H323_UU_PDU_h323_message_body::e_setup) {
		PTRACE(1, Type() << "\tError: " << GetName() << " has no Setup UUIE found!");
		delete msg;
		msg = NULL;
		return;
	}
	
	H225_Setup_UUIE &setupUUIE = suuie.m_h323_uu_pdu.m_h323_message_body;
	if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_cryptoTokens)) {
		setupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_cryptoTokens);
		setupUUIE.m_cryptoTokens = facilityBody.m_cryptoTokens;
	}
	if (aliases) {
		const H225_ArrayOf_AliasAddress & a = *aliases;
		for (PINDEX n = 0; n < a.GetSize(); ++n)
			if (a[n].GetTag() == H225_AliasAddress::e_dialedDigits) {
				fakeSetup.SetCalledPartyNumber(AsString(a[n], FALSE));
				break;
			}
		setupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
		setupUUIE.m_destinationAddress = a;
	}
	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "ShowForwarderNumber", "0")))
		if (endptr forwarder = m_call->GetForwarder()) {
			const H225_ArrayOf_AliasAddress & a = forwarder->GetAliases();
			for (PINDEX n = 0; n < a.GetSize(); ++n)
				if (a[n].GetTag() == H225_AliasAddress::e_dialedDigits) {
					PString callingNumber(AsString(a[n], FALSE));
					fakeSetup.SetCallingPartyNumber(callingNumber);
					setupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
					setupUUIE.m_sourceAddress.SetSize(1);
					H323SetAliasAddress(callingNumber, setupUUIE.m_sourceAddress[0]);
					break;
				}
		}

	// detach from the call
	m_call->SetSocket(NULL, NULL);
	remote = remoteSocket->remote = NULL;
	delete remoteSocket->m_h245handler;
	remoteSocket->m_h245handler = NULL;

	if (remoteSocket->CreateRemote(setupUUIE)) {
		SetUUIE(fakeSetup, suuie);
		fakeSetup.Encode(remoteSocket->buffer);
		PrintQ931(5, "Forward Setup to ", remoteSocket->remote->GetName(), &fakeSetup, &suuie);
		if (remoteSocket->m_result == Forwarding || remoteSocket->ForwardCallConnectTo()) {
			CallSignalSocket *result = static_cast<CallSignalSocket *>(remoteSocket->remote);
			if (m_h245socket) {
				m_h245socket->SetSigSocket(result);
				result->m_h245socket = m_h245socket;
				m_h245socket = 0;
			}
			if (remoteSocket->m_result == Forwarding)
				remoteSocket->ForwardData();
			else
				GetHandler()->Insert(result);
		}
	} else {
		remoteSocket->EndSession();
		remoteSocket->SetConnected(false);
		if (m_call)
			m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
		CallTable::Instance()->RemoveCall(m_call);
	}

	// let the socket be deletable
	SetDeletable();
	delete msg;
	msg = NULL;
}

PString CallSignalSocket::GetCallingStationId(
	/// Q.931/H.225 Setup message with additional data
	const SetupMsg &setup,
	/// additional data
	SetupAuthData &authData
	) const
{
	if (!authData.m_callingStationId)
		return authData.m_callingStationId;

	const bool hasCall = authData.m_call.operator->() != NULL;		
	PString id;
	
	setup.GetQ931().GetCallingPartyNumber(id);

	if (id.IsEmpty() && hasCall)
		id = authData.m_call->GetCallingStationId();

	if (!id)
		return id;

	H225_Setup_UUIE &setupBody = setup.GetUUIEBody();
	
	if (id.IsEmpty() && setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) 
		id = GetBestAliasAddressString(setupBody.m_sourceAddress, false,
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
	/// Q.931/H.225 Setup message with additional data
	const SetupMsg &setup,
	/// additional data
	SetupAuthData &authData
	) const
{
	if (!authData.m_calledStationId)
		return authData.m_calledStationId;
		
	const bool hasCall = authData.m_call.operator->() != NULL;
	PString id;
	
	setup.GetQ931().GetCalledPartyNumber(id);
	
	if (id.IsEmpty() && hasCall)
		id = authData.m_call->GetCalledStationId();

	if (!id)
		return id;

	H225_Setup_UUIE &setupBody = setup.GetUUIEBody();
			
	if (id.IsEmpty() && setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
		id = GetBestAliasAddressString(setupBody.m_destinationAddress, false,
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
		else if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress) 
				&& GetIPAndPortFromTransportAddr(setupBody.m_destCallSignalAddress, addr, port)
				&& addr.IsValid())
			id = AsString(addr, port);
	}
	
	return id;
}

PString CallSignalSocket::GetDialedNumber(
	const SetupMsg &setup
	) const
{
	PString dialedNumber;
	
	setup.GetQ931().GetCalledPartyNumber(dialedNumber);
	
	if (!dialedNumber)
		return dialedNumber;

	H225_Setup_UUIE &setupBody = setup.GetUUIEBody();
			
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
		dialedNumber = GetBestAliasAddressString(
			setupBody.m_destinationAddress, false,
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
			
	return dialedNumber;
}

void CallSignalSocket::OnSetup(
	SignalingMsg *msg
	)
{
	SetupMsg* setup = dynamic_cast<SetupMsg*>(msg);
	if (setup == NULL) {
		PTRACE(2, Type() << "\tError: Setup message from " << GetName() << " without associated UUIE");
		m_result = Error;
		return;
	}

	Q931 &q931 = msg->GetQ931();
	H225_Setup_UUIE &setupBody = setup->GetUUIEBody();
	
	m_h225Version = GetH225Version(setupBody);
	
	// prevent from multiple calls over the same signaling channel	
	if (remote) {
		const WORD newcrv = (WORD)setup->GetCallReference();
		if (m_crv && newcrv == (m_crv & 0x7fffu))
			PTRACE(2, Type() << "\tWarning: duplicate Setup received from " << Name());
		else {
			PTRACE(2, Type() << "\tWarning: multiple calls over single "
				"signalling channel not supported - new connection needed "
				"(from " << Name() << ')'
				);

			/// we should perform accounting here for this new call
			H225_H323_UserInformation userInfo;
			H225_H323_UU_PDU_h323_message_body &msgBody = userInfo.m_h323_uu_pdu.m_h323_message_body;
			msgBody.SetTag(H225_H323_UU_PDU_h323_message_body::e_releaseComplete);

			H225_ReleaseComplete_UUIE &uuie = msgBody;
			uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
			uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_reason);
			uuie.m_reason.SetTag(H225_ReleaseCompleteReason::e_newConnectionNeeded);
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_callIdentifier))
				uuie.m_callIdentifier = setupBody.m_callIdentifier;

			Q931 releasePDU;
			releasePDU.BuildReleaseComplete(newcrv, TRUE);
			SetUUIE(releasePDU, userInfo);
			PrintQ931(5, "Send to ", remote->GetName(), &releasePDU, &userInfo);

			PBYTEArray buf;
			if (releasePDU.Encode(buf))
				TransmitData(buf);
			else
				PTRACE(3, Type() << "\tFailed to encode ReleaseComplete message " << releasePDU);
		}
		m_result = NoData;
		return;
	}

	RasServer *rassrv = RasServer::Instance();
	Toolkit *toolkit = Toolkit::Instance();
	time_t setupTime = time(0); // record the timestamp here since processing may take much time

	m_crv = (WORD)(setup->GetCallReference() | 0x8000u);
	if (Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "ForwardOnFacility", "1")) && m_setupPdu == NULL)
		m_setupPdu = new Q931(q931);

	if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)
			|| setupBody.m_destinationAddress.GetSize() < 1) {
		unsigned plan, type;
		PString destination;
		if (q931.GetCalledPartyNumber(destination, &plan, &type)) {
			// Setup_UUIE doesn't contain any destination information, but Q.931 has CalledPartyNumber
			// We create the destinationAddress according to it
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setupBody.m_destinationAddress.SetSize(1);
			H323SetAliasAddress(destination, setupBody.m_destinationAddress[0]);
		}
	}

	PString callid;
	if (!m_call) {
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
			m_call = CallTable::Instance()->FindCallRec(setupBody.m_callIdentifier);
			callid = AsString(setupBody.m_callIdentifier.m_guid);
		} else { // try CallReferenceValue
			PTRACE(3, Type() << "\tSetup_UUIE from " << Name() << " doesn't contain CallIdentifier!");
			H225_CallReferenceValue crv;
			crv.SetValue(msg->GetCallReference());
			m_call = CallTable::Instance()->FindCallRec(crv);
			H225_CallIdentifier callIdentifier; // empty callIdentifier
			callid = AsString(callIdentifier.m_guid);
		}
	} else
		callid = AsString(m_call->GetCallIdentifier().m_guid);
	
	Address _peerAddr, _localAddr;
	WORD _peerPort = 0, _localPort = 0;
	msg->GetPeerAddr(_peerAddr, _peerPort);
	msg->GetLocalAddr(_localAddr, _localPort);
	
	// perform inbound ANI/CLI rewrite
	toolkit->RewriteCLI(*setup);
	
	// store dialed number
	const PString dialedNumber = GetDialedNumber(*setup);

	// endpoint alias to find an inbound rewrite rule
	PString in_rewrite_id;
	
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		// Do inbound per GWRewrite if we can before global rewrite
		#if PTRACING
		PString rewrite_type;
		#endif

		// Try lookup on neighbor list for rewrite source first
		in_rewrite_id = rassrv->GetNeighbors()->GetNeighborIdBySigAdr(_peerAddr);
		#if PTRACING
		if (!in_rewrite_id)
			rewrite_type = "neighbor or explicit IP";
		#endif

		// Try call record rewrite identifier next
		if (in_rewrite_id.IsEmpty() && m_call) {
			in_rewrite_id = m_call->GetInboundRewriteId();
			#if PTRACING
			if (!in_rewrite_id)
				rewrite_type = "call record";
			#endif
		}

		// Try the Setup's source field if this exists
		if (in_rewrite_id.IsEmpty() && setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)
				&& setupBody.m_sourceAddress.GetSize() > 0) {
			in_rewrite_id = GetBestAliasAddressString(
				setupBody.m_sourceAddress, false,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID), 
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
			#if PTRACING
			if (!in_rewrite_id)
				rewrite_type = "setup H323 ID or E164";
			#endif
		}

		if (in_rewrite_id.IsEmpty() && q931.GetCallingPartyNumber(in_rewrite_id)) {
			#if PTRACING
			if (!in_rewrite_id)
				rewrite_type = "setup CLI";
			#endif
		}

		if (!in_rewrite_id) {
			#if PTRACING
			PTRACE(4, Type() << "\tGWRewrite source for " << Name() << ": " << rewrite_type);
			#endif

			toolkit->GWRewriteE164(in_rewrite_id, true, setupBody.m_destinationAddress);
		}

		// Normal rewrite
		toolkit->RewriteE164(setupBody.m_destinationAddress);
	}

	if (q931.HasIE(Q931::CalledPartyNumberIE)) {
		unsigned plan, type;
		PString calledNumber;
		bool rewritten = false;
		
		if (q931.GetCalledPartyNumber(calledNumber, &plan, &type)) {
			// Do per GW inbound rewrite before global rewrite
			if (!in_rewrite_id)
				rewritten = toolkit->GWRewritePString(in_rewrite_id, true, calledNumber);
			
			// Normal rewrite
		    rewritten = toolkit->RewritePString(calledNumber) || rewritten;
			
			if (rewritten)
				q931.SetCalledPartyNumber(calledNumber, plan, type);
		}
	}

	// remove the destination signaling address of the gatekeeper
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
		PIPSocket::Address _destAddr;
		WORD _destPort = 0;
		if (GetIPAndPortFromTransportAddr(setupBody.m_destCallSignalAddress, _destAddr, _destPort)
				&& _destAddr == _localAddr && _destPort == _localPort)
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
	}
	
	GkClient *gkClient = rassrv->GetGkClient();
	bool rejectCall = false;
	SetupAuthData authData(m_call, m_call ? true : false);
	
	if (m_call) {
		// existing CallRec
		m_call->SetSetupTime(setupTime);
		
		if (m_call->IsSocketAttached()) {
			PTRACE(2, Type() << "\tWarning: socket (" << Name() << ") already attached for callid " << callid);
			m_call->SetDisconnectCause(Q931::CallRejected);
			rejectCall = true;
		} else if (m_call->IsToParent() && !m_call->IsForwarded()) {
			if (gkClient->CheckFrom(_peerAddr)) {
				// looped call
				PTRACE(2, Type() << "\tWarning: a registered call from my GK(" << GetName() << ')');
				m_call->SetDisconnectCause(Q931::CallRejected);
				rejectCall = true;
			} else
				gkClient->RewriteE164(*setup, true);
		}

		const H225_ArrayOf_CryptoH323Token & tokens = m_call->GetAccessTokens();
		if (!rejectCall && tokens.GetSize() > 0) {
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_cryptoTokens);
			setupBody.m_cryptoTokens = tokens;
		}

		authData.m_dialedNumber = dialedNumber;
		authData.SetRouteToAlias(m_call->GetRouteToAlias());
		authData.m_callingStationId = GetCallingStationId(*setup, authData);
		authData.m_calledStationId = GetCalledStationId(*setup, authData);
		
		// authenticate the call
		if (!rejectCall && !rassrv->ValidatePDU(*setup, authData)) {
			PTRACE(3, Type() << "\tDropping call #" << m_call->GetCallNumber()
				<< " due to Setup authentication failure"
				);
			if (authData.m_rejectCause >= 0)
				m_call->SetDisconnectCause(authData.m_rejectCause);
			else if (authData.m_rejectReason >= 0)
				m_call->SetDisconnectCause(Toolkit::Instance()->MapH225ReasonToQ931Cause(authData.m_rejectReason));
			else
				m_call->SetDisconnectCause(Q931::CallRejected);
			rejectCall = true;
		}

		if (!rejectCall && authData.m_routeToAlias != NULL) {
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setupBody.m_destinationAddress.SetSize(1);
			setupBody.m_destinationAddress[0] = *authData.m_routeToAlias;

			const PString alias = AsString(setupBody.m_destinationAddress[0], FALSE);
			if (q931.HasIE(Q931::CalledPartyNumberIE)) {
				if (!alias && strspn(alias, "1234567890*#+,") == strlen(alias)) {
					unsigned plan, type;
					PString calledNumber;
					if (q931.GetCalledPartyNumber(calledNumber, &plan, &type))
						q931.SetCalledPartyNumber(alias, plan, type);
				} else
					q931.RemoveIE(Q931::CalledPartyNumberIE);
			}
			authData.m_calledStationId = alias;
			PTRACE(3, Type() << "\tSetup CRV=" << msg->GetCallReference() 
				<< " destination set to " << alias
				);
		}
		if (!rejectCall && authData.m_callDurationLimit > 0)
			m_call->SetDurationLimit(authData.m_callDurationLimit);
		if (!authData.m_callingStationId)
			m_call->SetCallingStationId(authData.m_callingStationId);
		if (!authData.m_calledStationId)
			m_call->SetCalledStationId(authData.m_calledStationId);
		if (!authData.m_dialedNumber)
			m_call->SetDialedNumber(authData.m_dialedNumber);
		
		if (m_call->GetFailedRoutes().empty() || !m_call->SingleFailoverCDR()) {
			// log AcctStart accounting event
			if (!rassrv->LogAcctEvent(GkAcctLogger::AcctStart, m_call)) {
				PTRACE(2, Type() << "\tDropping call #" << m_call->GetCallNumber()
					<< " due to accounting failure"
					);
				m_call->SetDisconnectCause(Q931::TemporaryFailure);
				rejectCall = true;
			}
		} else
			PTRACE(5, Type() << "\tSupressing accounting start event for call #"
				<< m_call->GetCallNumber() << ", failover active"
				);
	} else {
		// no existing CallRec
		authData.m_dialedNumber = dialedNumber;
		authData.m_callingStationId = GetCallingStationId(*setup, authData);
		authData.m_calledStationId = GetCalledStationId(*setup, authData);

		if (!rassrv->ValidatePDU(*setup, authData)) {
			PTRACE(3, Type() << "\tDropping call CRV=" << msg->GetCallReference()
				<< " from " << Name() << " due to Setup authentication failure"
				);
			if (authData.m_rejectCause == -1 && authData.m_rejectReason == -1)
				authData.m_rejectCause = Q931::CallRejected;
			rejectCall = true;
		}

		if (!rejectCall && authData.m_routeToAlias != NULL) {
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setupBody.m_destinationAddress.SetSize(1);
			setupBody.m_destinationAddress[0] = *authData.m_routeToAlias;

			const PString alias = AsString(setupBody.m_destinationAddress[0], FALSE);
			if (q931.HasIE(Q931::CalledPartyNumberIE)) {
				if (!alias && strspn(alias, "1234567890*#+,") == strlen(alias)) {
					unsigned plan, type;
					PString calledNumber;
					if (q931.GetCalledPartyNumber(calledNumber, &plan, &type))
						q931.SetCalledPartyNumber(alias, plan, type);
				} else
					q931.RemoveIE(Q931::CalledPartyNumberIE);
			}
			authData.m_calledStationId = alias;
			PTRACE(3, Type() << "\tSetup CRV=" << msg->GetCallReference() 
				<< " destination set to " << alias
				);
		}

		endptr called;
		bool destFound = false;
		H225_TransportAddress calledAddr;
		Routing::SetupRequest request(setupBody, setup);
		
		if (!rejectCall && !authData.m_destinationRoutes.empty()) {
			list<Route>::const_iterator i = authData.m_destinationRoutes.begin();
			while (i != authData.m_destinationRoutes.end())
				request.AddRoute(*i++);
			calledAddr = authData.m_destinationRoutes.front().m_destAddr;
			called = authData.m_destinationRoutes.front().m_destEndpoint;
			destFound = true;
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
			setupBody.m_destCallSignalAddress = calledAddr;
			PTRACE(3, Type() << "\tSetup CRV=" << msg->GetCallReference() 
				<< " destination address set to " << AsDotString(setupBody.m_destCallSignalAddress)
				);
		}

		bool useParent = gkClient->IsRegistered() && gkClient->CheckFrom(_peerAddr);
		if (!rejectCall && useParent) {
			gkClient->RewriteE164(*setup, false);
			if (!gkClient->SendARQ(request, true)) { // send answered ARQ
				PTRACE(2, Type() << "\tGot ARJ from parent for " << GetName());
				authData.m_rejectCause = Q931::CallRejected;
				rejectCall = true;
			} else
				request.SetFlag(Routing::RoutingRequest::e_fromParent);
		}

		if (!rejectCall && !destFound 
				&& setupBody.HasOptionalField(H225_Setup_UUIE::e_cryptoTokens) 
				&& setupBody.m_cryptoTokens.GetSize() > 0) {
			PINDEX s = setupBody.m_cryptoTokens.GetSize() - 1;
			destFound = Neighbors::DecodeAccessToken(setupBody.m_cryptoTokens[s], _peerAddr, calledAddr);
			if (destFound) {
				called = RegistrationTable::Instance()->FindBySignalAdr(calledAddr);
				PTRACE(3, Type() << "\tGot destination " << AsDotString(calledAddr));
				if (s > 0)
					setupBody.m_cryptoTokens.SetSize(s);
				else
					setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);

				Route route("nbtoken", calledAddr);
				route.m_destEndpoint = called;
				request.AddRoute(route);
				
				if (!useParent) {
					Address toIP;
					GetIPFromTransportAddr(calledAddr, toIP);
					useParent = gkClient->IsRegistered() && gkClient->CheckFrom(toIP);
					if (useParent && !gkClient->SendARQ(request)) {
						PTRACE(2, Type() << "\tGot ARJ from parent for " << GetName());
						authData.m_rejectCause = Q931::CallRejected;
						rejectCall = true;
					}
				}
			}
		}

		if (!rejectCall && !destFound) {
			// for compatible to old version
			if (!(useParent || rassrv->AcceptUnregisteredCalls(_peerAddr))) {
				PTRACE(3, Type() << "\tReject unregistered call " << callid
					<< " from " << Name()
					);
				authData.m_rejectCause = Q931::CallRejected;
				rejectCall = true;
			} else {
				Route route;
				request.Process();
				// check if destination has changed in the routing process
				// eg. via canMapAlias in LRQ
				if (request.GetFlags() & Routing::SetupRequest::e_aliasesChanged) {
					setupBody.m_destinationAddress = request.GetRequest().m_destinationAddress;
					const PString newCalledParty = AsString(setupBody.m_destinationAddress[0], FALSE);
					if (q931.HasIE(Q931::CalledPartyNumberIE)) {
						if (!newCalledParty && strspn(newCalledParty, "1234567890*#+,") == strlen(newCalledParty)) {
							unsigned plan, type;
							PString calledNumber;
							if (q931.GetCalledPartyNumber(calledNumber, &plan, &type))
								q931.SetCalledPartyNumber(newCalledParty, plan, type);
							else
								q931.RemoveIE(Q931::CalledPartyNumberIE);
						}
						authData.m_calledStationId = newCalledParty;
					}
				}
				if (request.GetFirstRoute(route)) {
					destFound = true;
					calledAddr = route.m_destAddr;
					called = route.m_destEndpoint;
					if (authData.m_proxyMode == CallRec::ProxyDetect)
						authData.m_proxyMode = route.m_proxyMode;
					if (!useParent)
						useParent = route.m_flags & Route::e_toParent;
				} else {
					PTRACE(3, Type() << "\tNo destination for unregistered call "
						<< callid << " from " << Name()
						);
					authData.m_rejectReason = request.GetRejectReason();
					rejectCall = true;
				}
			}
		}

		PString destinationString(setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) 
			? AsString(setupBody.m_destinationAddress) : AsDotString(calledAddr)
			);

		// if I'm behind NAT and the call is from parent, always use H.245 routed
		bool h245Routed = rassrv->IsH245Routed() || (useParent && gkClient->IsNATed());
		// workaround for bandwidth, as OpenH323 library :p
		CallRec* call = new CallRec(q931, setupBody, h245Routed, 
			destinationString, authData.m_proxyMode
			);
		call->SetSrcSignalAddr(SocketToH225TransportAddr(_peerAddr, _peerPort));

		// if the peer address is a public address, but the advertised source address is a private address
		// then there is a good chance the remote endpoint is behind a NAT.
		PIPSocket::Address srcAddr;
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress)) {
			H323TransportAddress sourceAddress(setupBody.m_sourceCallSignalAddress);
			sourceAddress.GetIpAddress(srcAddr);

			if (!_peerAddr.IsRFC1918() && srcAddr.IsRFC1918()) {
				if (Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "SupportNATedEndpoints", "0"))) {
					PTRACE(4, Type() << "\tSource address " <<  srcAddr
						<< " peer address " << _peerAddr << " caller is behind NAT");
					call->SetSrcNATed(srcAddr);
				} else {
					// If unregistered caller is NATed & no policy then reject.
					PTRACE(4, Type() << "\tUnregistered party is NATed. Not supported by policy.");
					authData.m_rejectReason = Q931::NoRouteToDestination;
					rejectCall = true;
				}
				// If the called Party is not NATed then the called EP must support NAT'd callers
				// latter versions of OpenH323 and GnomeMeeting do also allow this condition.
			} else {
                PTRACE(4, Type() << "\tUnregistered party is not NATed"); 
			}
		} else {
			   // If the party cannot be determined if behind NAT and we have support then just Treat as being NAT
			     if (Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "SupportNATedEndpoints", "0")) &&
				    Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "TreatUnregisteredNAT", "0"))) {
					PTRACE(4, Type() << "\tUnregistered party " << _peerAddr << " cannot detect if NATed. Treated as if NATed");
					srcAddr = "192.168.1.1";  // Just an arbitory internal address.
					call->SetSrcNATed(srcAddr);
				} else {
					PTRACE(4, Type() << "\tWARNING: Unregistered party " << _peerAddr << " cannot detect if NATed");
				}
		}

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
		if (!rejectCall && destFound)
			m_call->SetNewRoutes(request.GetRoutes());

		if (!rassrv->LogAcctEvent(GkAcctLogger::AcctStart, m_call)) {
			PTRACE(2, Type() << "\tDropping call #" << call->GetCallNumber()
				<< " due to accounting failure"
				);
			authData.m_rejectCause = Q931::TemporaryFailure;
			rejectCall = true;
		}
		
		if (rejectCall) {
			if (authData.m_rejectCause >= 0)
				m_call->SetDisconnectCause(authData.m_rejectCause);
			else if (authData.m_rejectReason >= 0)
				m_call->SetDisconnectCause(Toolkit::Instance()->MapH225ReasonToQ931Cause(authData.m_rejectReason));
			else
				m_call->SetDisconnectCause(Q931::CallRejected);
		}
	}	// else: no CallRec

	if (rejectCall) {
		m_result = Error;
		return;
	}

	// perform outbound rewrite
	PIPSocket::Address calleeAddr;
	WORD calleePort = 0;
	m_call->GetDestSignalAddr(calleeAddr, calleePort);
	toolkit->RewriteCLI(*setup, authData, calleeAddr);

	PString out_rewrite_id;
	// Do outbound per GW rewrite
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		PIPSocket::Address neighbor_addr;
		WORD port;
		#if PTRACING
		PString rewrite_type;
		#endif

		// Try neighbor list first
		if (m_call->GetDestSignalAddr(neighbor_addr, port)) {
			out_rewrite_id = rassrv->GetNeighbors()->GetNeighborIdBySigAdr(neighbor_addr);
			#if PTRACING
			if (!out_rewrite_id)
				rewrite_type = "neighbor or explicit IP";
			#endif
		}

		// Try call record rewrite id
		if (out_rewrite_id.IsEmpty()) {
			out_rewrite_id = m_call->GetOutboundRewriteId();
			#if PTRACING
			if (!out_rewrite_id)
				rewrite_type = "call record";
			#endif
		}

		// Try configured endpoint
		if (out_rewrite_id.IsEmpty()) {
			endptr rewriteEndPointOut = m_call->GetCalledParty();
			if (rewriteEndPointOut && rewriteEndPointOut->GetAliases().GetSize() > 0) {
		 		out_rewrite_id = GetBestAliasAddressString(
					rewriteEndPointOut->GetAliases(), false,
					AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
					AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
						| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
					);
				#if PTRACING
				if (!out_rewrite_id)
					rewrite_type = "setup H323 ID or E164";
				#endif
			}
		}

		if (!out_rewrite_id) {
			#if PTRACING
			PTRACE(4, Type() << "\tGWRewrite source for " << Name() << ": " << rewrite_type);
			#endif
		    toolkit->GWRewriteE164(out_rewrite_id, false, setupBody.m_destinationAddress);
		}
	}

	if (q931.HasIE(Q931::CalledPartyNumberIE)) {
		unsigned plan, type;
		PString calledNumber;

		// Do per GW outbound rewrite after global rewrite
		if (q931.GetCalledPartyNumber(calledNumber, &plan, &type))
			if (toolkit->GWRewritePString(out_rewrite_id, false, calledNumber))
				q931.SetCalledPartyNumber(calledNumber, plan, type);
	}

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		const PString screenSourceAddress = GkConfig()->GetString(RoutedSec, "ScreenSourceAddress", "");
		if (!screenSourceAddress) {
			setupBody.m_sourceAddress.SetSize(1);
			H323SetAliasAddress(screenSourceAddress, setupBody.m_sourceAddress[0]);
		}
	}

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_multipleCalls)
			&& setupBody.m_multipleCalls)
		setupBody.m_multipleCalls = FALSE;

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_maintainConnection)
			&& setupBody.m_maintainConnection)
		setupBody.m_maintainConnection = FALSE;

	const PString cli = toolkit->Config()->GetString(RoutedSec, "ScreenCallingPartyNumberIE", "");
	if (!cli) {
		unsigned plan = Q931::ISDNPlan, type = Q931::InternationalType;
		unsigned presentation = (unsigned)-1, screening = (unsigned)-1;
		if (q931.HasIE(Q931::CallingPartyNumberIE)) {
			PString dummy;
			q931.GetCallingPartyNumber(dummy, &plan, &type, &presentation, &screening, (unsigned)-1, (unsigned)-1);
		}
		q931.SetCallingPartyNumber(cli, plan, type, presentation, screening);
	}
	
	SetCallTypePlan(&q931);
	CreateRemote(setupBody);
	msg->SetUUIEChanged();
}

bool CallSignalSocket::CreateRemote(
	H225_Setup_UUIE &setupBody
	)
{
	if (!m_call->GetDestSignalAddr(peerAddr, peerPort)) {
		PTRACE(3, Type() << "\tINVALID DESTINATION ADDRESS for call from " << Name());
		m_call->SetDisconnectCause(Q931::IncompatibleDestination);
		m_result = Error;
		return false;
	}
	
	Address calling = INADDR_ANY;
	int type = m_call->GetNATType(calling, peerAddr);

	localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
    masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);

	setupBody.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
	setupBody.m_sourceCallSignalAddress = SocketToH225TransportAddr(masqAddr, GetPort());

	// For compatibility with endpoints which do not support large Setup messages
	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveH235Call", "0"))) {
		 setupBody.RemoveOptionalField(H225_Setup_UUIE::e_tokens);
		 setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);
	}

	// For compatibility to call pre-H323v4 devices that do not support H.460
	// This strips the Feature Advertisements from the PDU.
	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveH460Call", "0"))) {
		   setupBody.RemoveOptionalField(H225_Setup_UUIE::e_desiredFeatures);
		   setupBody.RemoveOptionalField(H225_Setup_UUIE::e_supportedFeatures);
		   setupBody.RemoveOptionalField(H225_Setup_UUIE::e_neededFeatures);
	}
	
	PTRACE(3, Type() << "\tCall " << m_call->GetCallNumber() << " is NAT type " << type);
	endptr calledep = m_call->GetCalledParty();
	if (calledep) {
		// m_call->GetCalledParty() should not be null in the case
		if (CallSignalSocket *socket = calledep->GetSocket()) {
			PTRACE(3, Type() << "\tUsing NAT socket " << socket->GetName());

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

	HandleH245Address(setupBody);
	HandleFastStart(setupBody, true);

#if H225_PROTOCOL_VERSION >= 4
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_parallelH245Control) && m_h245handler)
		OnTunneledH245(setupBody.m_parallelH245Control);
#endif
	return true;
}

void CallSignalSocket::OnCallProceeding(
	SignalingMsg *msg
	)
{
	CallProceedingMsg *callProceeding = dynamic_cast<CallProceedingMsg*>(msg);
	if (callProceeding == NULL) {
		PTRACE(2, Type() << "\tError: CallProceeding message from " << Name() << " without associated UUIE");
		m_result = Error;
		return;
	}

	H225_CallProceeding_UUIE &cpBody = callProceeding->GetUUIEBody();

	m_h225Version = GetH225Version(cpBody);
	
	if (HandleH245Address(cpBody))
		msg->SetUUIEChanged();

	if (cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_multipleCalls)
			&& cpBody.m_multipleCalls) {
		cpBody.m_multipleCalls = FALSE;
		msg->SetUUIEChanged();
	}
	if (cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_maintainConnection)
			&& cpBody.m_maintainConnection) {
		cpBody.m_maintainConnection = FALSE;
		msg->SetUUIEChanged();
	}
	
	if (HandleFastStart(cpBody, false))
		msg->SetUUIEChanged();
}

void CallSignalSocket::OnConnect(
	SignalingMsg *msg
	)
{
	ConnectMsg *connect = dynamic_cast<ConnectMsg*>(msg);
	if (connect == NULL) {
		PTRACE(2, Type() << "\tError: Connect message from " << Name() << " without associated UUIE");
		m_result = Error;
		return;
	}

	H225_Connect_UUIE &connectBody = connect->GetUUIEBody();

	m_h225Version = GetH225Version(connectBody);
	
	if (m_call) {// hmm... it should not be null
		m_call->SetConnected();
		RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctConnect, m_call);
	}

	if (HandleH245Address(connectBody))
		msg->SetUUIEChanged();
		
	if (connectBody.HasOptionalField(H225_Connect_UUIE::e_multipleCalls)
			&& connectBody.m_multipleCalls) {
		connectBody.m_multipleCalls = FALSE;
		msg->SetUUIEChanged();
	}
	if (connectBody.HasOptionalField(H225_Connect_UUIE::e_maintainConnection)
			&& connectBody.m_maintainConnection) {
		connectBody.m_maintainConnection = FALSE;
		msg->SetUUIEChanged();
	}
	
	if (HandleFastStart(connectBody, false))
		msg->SetUUIEChanged();
}

void CallSignalSocket::OnAlerting(
	SignalingMsg* msg
	)
{
	m_call->SetAlertingTime(time(NULL));
	
	AlertingMsg *alerting = dynamic_cast<AlertingMsg*>(msg);
	if (alerting == NULL) {
		PTRACE(2, Type() << "\tError: Alerting message from " << Name() << " without associated UUIE");
		m_result = Error;
		return;
	}

	H225_Alerting_UUIE &alertingBody = alerting->GetUUIEBody();
	
	m_h225Version = GetH225Version(alertingBody);
	
	if (HandleH245Address(alertingBody))
		msg->SetUUIEChanged();
		
	if (alertingBody.HasOptionalField(H225_Alerting_UUIE::e_multipleCalls)
			&& alertingBody.m_multipleCalls) {
		alertingBody.m_multipleCalls = FALSE;
		msg->SetUUIEChanged();
	}
	if (alertingBody.HasOptionalField(H225_Alerting_UUIE::e_maintainConnection)
			&& alertingBody.m_maintainConnection) {
		alertingBody.m_maintainConnection = FALSE;
		msg->SetUUIEChanged();
	}
	
	if (HandleFastStart(alertingBody, false))
		msg->SetUUIEChanged();
}

void CallSignalSocket::OnInformation(
	SignalingMsg *msg
	)
{

	if (remote != NULL)
		return;

	m_result = Error;
	
    // If NAT support disabled then ignore the message.
	if (!Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "SupportNATedEndpoints", "0")))
		return;

   // If calling NAT support disabled then ignore the message. 
   // Use this to block errant gateways that don't support NAT mechanism properly.
	if (!Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "SupportCallingNATedEndpoints", "1")))
		return;

	Q931 &q931 = msg->GetQ931();

	// We are only interested in the GnuGK NAT message everything else ignore.
	if (!q931.HasIE(Q931::FacilityIE))
		return;

	PWaitAndSignal m(infomutex);

	PBYTEArray buf = q931.GetIE(Q931::FacilityIE);
	if (buf.GetSize() > 0) {
		H225_EndpointIdentifier id;
		PString epid((const char *)buf.GetPointer(), buf.GetSize());
		id = epid;
		PTRACE(3, Type() << "\t" << GetName() << " NAT Information message from EPID = " << epid);
		endptr ep = RegistrationTable::Instance()->FindByEndpointId(id);
		if ((ep) && (!ep->IsNATed()))	// Fix for poor or bad implementations which send Facility message
			return;						// without checking the RCF message first

		if (q931.HasIE(Q931::CallStateIE)) {
			buf = q931.GetIE(Q931::CallStateIE);
			if (buf.GetSize() > 0 && buf[0] == Q931::CallState_DisconnectRequest) {
				if (ep) {
					CallSignalSocket *natsocket = ep->GetSocket();
					if (natsocket != NULL && natsocket != this) {
						natsocket->SetDeletable();
						natsocket->Close();
					}
					SetDeletable();
					PTRACE(3, Type() << "\tRequest to close NAT socket " << GetName());
				}
				Close();
			} else if (ep) {
				m_isnatsocket = true;
				ep->SetSocket(this);
				SetConnected(true); // avoid the socket be deleted
			}
			m_result = NoData;
		}
	}
}

void CallSignalSocket::OnReleaseComplete(
	SignalingMsg *msg
	)
{
	ReleaseCompleteMsg *rc = dynamic_cast<ReleaseCompleteMsg*>(msg);
	if (rc == NULL)
		PTRACE(2, Type() << "\tWarning: ReleaseComplete message from " << Name() << " without associated UUIE");
	
	unsigned cause = 0;
	if (m_call) {
		// regular ReleaseComplete processing
		m_call->SetDisconnectTime(time(NULL));
		m_call->SetReleaseSource(m_callerSocket
			? CallRec::ReleasedByCaller : CallRec::ReleasedByCallee
			);
		if (msg->GetQ931().HasIE(Q931::CauseIE)) {
			cause = msg->GetQ931().GetCause();
			m_call->SetDisconnectCause(cause);
		} else if (rc != NULL) {
			H225_ReleaseComplete_UUIE& rcBody = rc->GetUUIEBody();
			if (rcBody.HasOptionalField(H225_ReleaseComplete_UUIE::e_reason)) {
				cause = Toolkit::Instance()->MapH225ReasonToQ931Cause(rcBody.m_reason.GetTag());
				m_call->SetDisconnectCause(cause);
			}
		}
	}

	if (m_callerSocket)
		if (remote != NULL)
			remote->RemoveRemoteSocket();

	if (m_call && remote != NULL && !m_callerSocket && m_call->GetReleaseSource() == CallRec::ReleasedByCallee
		&& m_call->MoveToNextRoute()) {
		if (!m_call->DisableRetryChecks() &&
			(m_call->IsCallInProgress() || m_call->IsFastStartResponseReceived()
				|| m_call->IsH245ResponseReceived() || m_h245socket != NULL)) {
			PTRACE(5, "Q931\tFailover disabled for call " << m_call->GetCallNumber());
		} else if (m_call->GetFailedRoutes().back().IsFailoverActive(cause)) {
			TryNextRoute();
			return;
		} else 
			PTRACE(5, "Q931\tFailover inactive for call " << m_call->GetCallNumber() << ", Q931 cause " << cause);
	}
	
	if (m_call)
		CallTable::Instance()->RemoveCall(m_call);
		
	m_result = Closing;
}

void CallSignalSocket::TryNextRoute()
{
	PTRACE(3, "Q931\tTrying next route: " << m_call->GetNewRoutes().front().AsString());

	CallRec *newCall = new CallRec(m_call.operator ->());
	CallTable::Instance()->RemoveFailedLeg(m_call);
	
	CallSignalSocket *callingSocket = static_cast<CallSignalSocket*>(remote);
	if (callingSocket != NULL) {
		callingSocket->RemoveRemoteSocket();
		callingSocket->RemoveH245Handler();
		if (callingSocket->GetHandler()->Detach(callingSocket))
			PTRACE(6, "Q931\tSocket " << callingSocket->GetName() << " detached from its handler");
		else
			PTRACE(1, "Q931\tFailed to detach socket " << callingSocket->GetName() << " from its handler");

		callingSocket->m_call = callptr(newCall);
		callingSocket->buffer = callingSocket->m_rawSetup;
		callingSocket->buffer.MakeUnique();
	}
	
	const Route &newRoute = newCall->GetNewRoutes().front();
	PTRACE(1, "MZ\tNew route: " << 	newRoute.AsString());
	if (newRoute.m_destEndpoint)
		newCall->SetCalled(newRoute.m_destEndpoint);
	else
		newCall->SetDestSignalAddr(newRoute.m_destAddr);
				
	if (newRoute.m_flags & Route::e_toParent)
		newCall->SetToParent(true);
				
	CallTable::Instance()->Insert(newCall);
	
	remote = NULL;
	
	TCPProxySocket::EndSession();
	GetHandler()->Remove(this);
	
	PTRACE(5, GetName() << "\tDispatching new call leg to " << newRoute.AsString());
	CreateJob(callingSocket, &CallSignalSocket::DispatchNextRoute, "Failover");

	m_result = NoData;				
}

void CallSignalSocket::OnFacility(
	SignalingMsg *msg
	)
{
	FacilityMsg *facility = dynamic_cast<FacilityMsg*>(msg);
	if (facility == NULL)
		return;

	H225_Facility_UUIE &facilityBody = facility->GetUUIEBody();
	
	if (m_h225Version == 0)
		m_h225Version = GetH225Version(facilityBody);
	
	if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_multipleCalls)
			&& facilityBody.m_multipleCalls) {
		facilityBody.m_multipleCalls = FALSE;
		msg->SetUUIEChanged();
	}
	if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_maintainConnection)
			&& facilityBody.m_maintainConnection) {
		facilityBody.m_maintainConnection = FALSE;
		msg->SetUUIEChanged();
	}

	switch (facilityBody.m_reason.GetTag()) {
	case H225_FacilityReason::e_startH245:
		if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_h245Address) 
				&& facilityBody.m_protocolIdentifier.GetValue().IsEmpty())
			if (m_h245socket && m_h245socket->Reverting(facilityBody.m_h245Address))
				m_result = NoData;
		break;
	case H225_FacilityReason::e_callForwarded:
	case H225_FacilityReason::e_routeCallToGatekeeper:
	case H225_FacilityReason::e_routeCallToMC:
		if (!Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "ForwardOnFacility", "0")))
			break;

		// to avoid complicated handling of H.245 channel on forwarding,
		// we only do forward if forwarder is the called party and
		// H.245 channel is not established yet
		if (m_setupPdu || (m_h245socket && m_h245socket->IsConnected()))
			break;
		// make sure the call is still active
		if (m_call && CallTable::Instance()->FindCallRec(m_call->GetCallNumber())) {
			MarkBlocked(true);
			CreateJob(this, &CallSignalSocket::ForwardCall,
				dynamic_cast<FacilityMsg*>(facility->Clone()), "ForwardCall"
				);
			m_result = NoData;
			return;
		}
		break;

	case H225_FacilityReason::e_transportedInformation:
		if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "TranslateFacility", "0"))) {
			CallSignalSocket *sigSocket = dynamic_cast<CallSignalSocket*>(remote);
			if (sigSocket != NULL && sigSocket->m_h225Version > 0 
					&& sigSocket->m_h225Version < 4) {
				H225_H323_UserInformation *uuie = facility->GetUUIE();
				uuie->m_h323_uu_pdu.m_h323_message_body.SetTag(
					H225_H323_UU_PDU_h323_message_body::e_empty
					);
				msg->SetUUIEChanged();
				return;
			}
		}
		break;
	}
	
	if (m_result != NoData)
		if (HandleH245Address(facilityBody))
			msg->SetUUIEChanged();

	if (HandleFastStart(facilityBody, false))
		msg->SetUUIEChanged();
}

void CallSignalSocket::OnProgress(
	SignalingMsg *msg
	)
{
	ProgressMsg *progress = dynamic_cast<ProgressMsg*>(msg);
	if (progress == NULL) {
		PTRACE(2, Type() << "\tError: Progress message from " << Name() << " without associated UUIE");
		m_result = Error;
		return;
	}

	H225_Progress_UUIE &progressBody = progress->GetUUIEBody();

	m_h225Version = GetH225Version(progressBody);
	
	if (HandleH245Address(progressBody))
		msg->SetUUIEChanged();
		
	if (progressBody.HasOptionalField(H225_Progress_UUIE::e_multipleCalls)
			&& progressBody.m_multipleCalls) {
		progressBody.m_multipleCalls = FALSE;
		msg->SetUUIEChanged();
	}
	if (progressBody.HasOptionalField(H225_Progress_UUIE::e_maintainConnection)
			&& progressBody.m_maintainConnection) {
		progressBody.m_maintainConnection = FALSE;
		msg->SetUUIEChanged();
	}
	
	if (HandleFastStart(progressBody, false))
		msg->SetUUIEChanged();
}

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
		if (fromCaller) {
			if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
					&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData
					&& olc.m_reverseLogicalChannelParameters.HasOptionalField(H245_OpenLogicalChannel_reverseLogicalChannelParameters::e_multiplexParameters)
					&& olc.m_reverseLogicalChannelParameters.m_multiplexParameters.GetTag() == H245_OpenLogicalChannel_reverseLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters) {
				H245_H2250LogicalChannelParameters *channel = &((H245_H2250LogicalChannelParameters&)olc.m_reverseLogicalChannelParameters.m_multiplexParameters);
				if (channel != NULL && channel->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)) {
					H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(channel->m_mediaChannel);
					if (addr != NULL && m_call) {
						PIPSocket::Address ip;
						*addr >> ip;
						m_call->SetMediaOriginatingIp(ip);
					}
				}
			}
		} else {
			H245_AudioCapability *audioCap = NULL;
			if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
					&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData) {
				audioCap = &((H245_AudioCapability&)olc.m_reverseLogicalChannelParameters.m_dataType);
			} else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData) {
				audioCap = &((H245_AudioCapability&)olc.m_forwardLogicalChannelParameters.m_dataType);
			}
			if (audioCap != NULL && m_call)
				m_call->SetCodec(GetH245CodecName(*audioCap));
		}
	}
	return changed;
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
	ReadLock lock(ConfigReloadMutex);
	
	const PTime channelStart;
	const int setupTimeout = PMAX(GkConfig()->GetInteger(RoutedSec,"SetupTimeout",DEFAULT_SETUP_TIMEOUT),1000);
	int timeout = setupTimeout;

	if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
		Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
			GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "1")) ? 1 : 0, 
			SOL_SOCKET
			);

	while (timeout > 0) {

		ConfigReloadMutex.EndRead();
		if (!IsReadable(timeout)) {
			PTRACE(3, "Q931\tTimed out waiting for initial Setup message from " << GetName());
			ConfigReloadMutex.StartRead();
			break;
		}
		ConfigReloadMutex.StartRead();
		
		switch (ReceiveData()) {
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
							
				ConfigReloadMutex.EndRead();
				const bool isReadable = remote->IsReadable(2*setupTimeout);
				ConfigReloadMutex.StartRead();
				if (!isReadable) {
					PTRACE(3, "Q931\tTimed out waiting for a response to Setup message from " << remote->GetName());
					if( m_call )
						m_call->SetDisconnectCause(Q931::TimerExpiry);
					OnError();
				}
				GetHandler()->Insert(this, remote);
				return;
			} else if (m_call && m_call->MoveToNextRoute() && m_h245socket == NULL) {
				PTRACE(3, "Q931\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");
				if (m_call) {
					m_call->SetCallSignalSocketCalled(NULL);
					m_call->SetDisconnectCause(Q931::NoRouteToDestination);
					m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
					m_call->SetDisconnectTime(time(NULL));
				}
				
				RemoveH245Handler();

				const Route &newRoute = m_call->GetNewRoutes().front();
				PTRACE(1, "MZ\tNew route: " << 	newRoute.AsString());
				
				CallRec *newCall = new CallRec(m_call.operator ->());
				CallTable::Instance()->RemoveFailedLeg(m_call);
				m_call = callptr(newCall);
				
				if (newRoute.m_destEndpoint)
					m_call->SetCalled(newRoute.m_destEndpoint);
				else
					m_call->SetDestSignalAddr(newRoute.m_destAddr);
				
				if (newRoute.m_flags & Route::e_toParent)
					m_call->SetToParent(true);
				
				CallTable::Instance()->Insert(newCall);
				
				if (remote != NULL) {
					remote->RemoveRemoteSocket();
					delete remote;
					remote = NULL;
				}
				
				buffer = m_rawSetup;
				buffer.MakeUnique();
				
				ReadUnlock unlock(ConfigReloadMutex);
				DispatchNextRoute();
				return;
			} else {
				PTRACE(3, "Q931\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");
				SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
				if (m_call) {
					m_call->SetCallSignalSocketCalled(NULL);
					m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
				}
				CallTable::Instance()->RemoveCall(m_call);
				delete remote;
				remote = NULL;
				TCPProxySocket::EndSession();
				timeout = 0;
				break;
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
			OnError();
			timeout = 0;
			break;
		} /* switch */
	} /* while */
	
	if (m_call)
		m_call->SetSocket(NULL, NULL);
	delete this; // oh!
}

ProxySocket::Result CallSignalSocket::RetrySetup()
{
	H225_H323_UserInformation *uuie = NULL;
	Q931 *q931pdu = new Q931();

	if (!q931pdu->Decode(buffer)) {
		PTRACE(1, Type() << "\t" << GetName() << " ERROR DECODING Q.931!");
		delete q931pdu;
		q931pdu = NULL;
		return m_result = Error;
	}

	PIPSocket::Address _localAddr, _peerAddr;
	WORD _localPort = 0, _peerPort = 0;
	GetLocalAddress(_localAddr, _localPort);
	GetPeerAddress(_peerAddr, _peerPort);
	
	PTRACE(3, Type() << "\tRetrying " << q931pdu->GetMessageTypeName()
		<< " CRV=" << q931pdu->GetCallReference() << " from " << GetName()
		);

	if (q931pdu->HasIE(Q931::UserUserIE)) {
		uuie = new H225_H323_UserInformation();
		if (!GetUUIE(*q931pdu, *uuie)) {
			PTRACE(1, Type() << "\tCould not decode User-User IE for message " 
				<< q931pdu->GetMessageTypeName() << " CRV=" 
				<< q931pdu->GetCallReference() << " from " << GetName()
				);
			delete uuie;
			uuie = NULL;
			delete q931pdu;
			q931pdu = NULL;
			return m_result = Error;
		}
	}
	
	m_result = Forwarding;
	
	SignalingMsg *msg = SignalingMsg::Create(q931pdu, uuie, 
		_localAddr, _localPort, _peerAddr, _peerPort
		);

	if (m_h245Tunneling && uuie != NULL)
#if H225_PROTOCOL_VERSION >= 4
		if(!uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_provisionalRespToH245Tunneling))
#endif
		m_h245Tunneling = (uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling)
			&& uuie->m_h323_uu_pdu.m_h245Tunneling.GetValue());

	switch (msg->GetTag()) {
	case Q931::SetupMsg:
		OnSetup(msg);
		break;
	default:
		PTRACE(1, Type() << "\t" << GetName() << " decoded message is not a Setup");
		delete msg;
		return m_result = Error;
	}

	if (m_result == Error || m_result == NoData) {
		delete msg;
		return m_result;
	}
	
	if (msg->GetUUIE() != NULL && msg->GetUUIE()->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control)
			&& m_h245handler)
		if (OnTunneledH245(msg->GetUUIE()->m_h323_uu_pdu.m_h245Control))
			msg->SetUUIEChanged();

	if (msg->GetQ931().HasIE(Q931::DisplayIE)) {
		const PString s = GkConfig()->GetString(RoutedSec, "ScreenDisplayIE", "");
		if (!s) {
			msg->GetQ931().SetDisplayName(s);
			msg->SetChanged();
		}
	}
	
	if (msg->IsChanged() && !msg->Encode(buffer))
		m_result = Error;
	else if (remote)
		PrintQ931(4, "Send to ", remote->GetName(), &msg->GetQ931(), msg->GetUUIE());

	delete msg;
	return m_result;
}

void CallSignalSocket::DispatchNextRoute()
{
	const int setupTimeout = PMAX(GkConfig()->GetInteger(RoutedSec,"SetupTimeout",DEFAULT_SETUP_TIMEOUT),1000);
	ReadLock lock(ConfigReloadMutex);
	
	const PTime channelStart;

	switch (RetrySetup()) {
	case Connecting:
		if (InternalConnectTo()) {
			if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
				remote->Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
					GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "1")) ? 1 : 0, 
					SOL_SOCKET
					);
							
			ConfigReloadMutex.EndRead();
			const bool isReadable = remote->IsReadable(2*setupTimeout);
			ConfigReloadMutex.StartRead();
			if (!isReadable) {
				PTRACE(3, "Q931\tTimed out waiting for a response to Setup message from " << remote->GetName());
				if( m_call )
					m_call->SetDisconnectCause(Q931::TimerExpiry);
				OnError();
			}
			GetHandler()->Insert(this, remote);
			return;
		} else if (m_call && m_call->MoveToNextRoute()) {
			PTRACE(3, "Q931\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");

			m_call->SetCallSignalSocketCalled(NULL);
			m_call->SetDisconnectCause(Q931::NoRouteToDestination);
			m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
				
			const Route &newRoute = m_call->GetNewRoutes().front();
			PTRACE(1, "MZ\tNew route: " << 	newRoute.AsString());
				
			CallRec *newCall = new CallRec(m_call.operator ->());
			CallTable::Instance()->RemoveFailedLeg(m_call);
			m_call = callptr(newCall);

			if (newRoute.m_destEndpoint)
				m_call->SetCalled(newRoute.m_destEndpoint);
			else
				m_call->SetDestSignalAddr(newRoute.m_destAddr);
				
			if (newRoute.m_flags & Route::e_toParent)
				m_call->SetToParent(true);
				
			CallTable::Instance()->Insert(newCall);
				
			if (remote != NULL) {
				remote->RemoveRemoteSocket();
				delete remote;
				remote = NULL;
			}
				
			buffer = m_rawSetup;
			buffer.MakeUnique();
				
			ReadUnlock unlock(ConfigReloadMutex);
			DispatchNextRoute();
			return;
		} else {
			PTRACE(3, "Q931\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");
			SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
			if (m_call) {
				m_call->SetCallSignalSocketCalled(NULL);
				m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
			}
			CallTable::Instance()->RemoveCall(m_call);
			delete remote;
			remote = NULL;
			TCPProxySocket::EndSession();
			break;
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
		OnError();
		break;
	} /* switch */
	
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
			if (m_h245socket->SetH245Address(h245addr, masqAddr))
				std::swap(m_h245socket, ret->m_h245socket);
			return true;
		}
	}
	bool userevert = m_isnatsocket || ((m_crv & 0x8000u) && (m_call->GetNATType() & CallRec::citronNAT));
	m_h245socket = userevert ? new NATH245Socket(this) : new H245Socket(this);
	ret->m_h245socket = new H245Socket(m_h245socket, ret);
	m_h245socket->SetH245Address(h245addr,masqAddr);
	CreateJob(m_h245socket, &H245Socket::ConnectTo, "H245Connector");
	return true;
}

bool CallSignalSocket::InternalConnectTo()
{
	int numPorts = min(Q931PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = Q931PortRange.GetPort();
		if (remote->Connect(localAddr, pt, peerAddr)) {
			PTRACE(3, "Q931\tConnect to " << remote->GetName() << " from "
				<< localAddr << ':' << pt << " successful"
				);
			SetConnected(true);
			remote->SetConnected(true);
			ForwardData();
			return true;
		}
		int errorNumber = remote->GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, remote->Type() << "\tCould not open/connect Q.931 socket at "
			<< localAddr << ':' << pt
			<< " - error " << remote->GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << remote->GetErrorText(PSocket::LastGeneralError)
			);
		remote->Close();
#ifdef _WIN32
		if ((errorNumber & PWIN32ErrorFlag) == 0
				|| (errorNumber & ~PWIN32ErrorFlag) != WSAEADDRINUSE)
			break;
#else
		if (!(errorNumber == EADDRINUSE || errorNumber == EINVAL))
			break;
#endif
	}

	return false;
}

bool CallSignalSocket::ForwardCallConnectTo()
{
	int numPorts = min(Q931PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = Q931PortRange.GetPort();
		if (remote->Connect(localAddr, pt, peerAddr)) {
			PTRACE(3, "Q931\tConnect to " << remote->GetName() << " from "
				<< localAddr << ':' << pt << " successful"
				);
			SetConnected(true);
			remote->SetConnected(true);
			ForwardData();
			return true;
		}
		int errorNumber = remote->GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, remote->Type() << "\tCould not open/connect Q.931 socket at "
			<< localAddr << ':' << pt
			<< " - error " << remote->GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << remote->GetErrorText(PSocket::LastGeneralError)
			);
		remote->Close();
#ifdef _WIN32
		if ((errorNumber & PWIN32ErrorFlag) == 0
				|| (errorNumber & ~PWIN32ErrorFlag) != WSAEADDRINUSE)
			break;
#else
		if (!(errorNumber == EADDRINUSE || errorNumber == EINVAL))
			break;
#endif
	}

	PTRACE(3, "Q931\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");
	SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
	if (m_call) {
		m_call->SetCallSignalSocketCalled(NULL);
		m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
	}
	CallTable::Instance()->RemoveCall(m_call);
	delete remote;
	remote = NULL;
	return false;
}

void CallSignalSocket::SetCallTypePlan(Q931 *q931)
{
	if (!q931 || !m_call)
		return;

	unsigned plan, type;
	int dtype;
	PIPSocket::Address calleeAddr;
	WORD calleePort = 0;
	PString Number;
	Toolkit* toolkit = Toolkit::Instance();
	m_call->GetDestSignalAddr(calleeAddr, calleePort);
	H225_TransportAddress callerAddr = SocketToH225TransportAddr(calleeAddr, calleePort);
	endptr called = RegistrationTable::Instance()->FindBySignalAdr(callerAddr);
	const char* TypeOfNumber = " Type Of Number ";

	if (q931->HasIE(Q931::CalledPartyNumberIE)) {
		if (q931->GetCalledPartyNumber(Number, &plan, &type)) {
			dtype = -1;
			if (called) {
				int proxy = called->GetProxyType();
				if (proxy > 0) {
					m_call->SetProxyMode(proxy);
					#if PTRACING
					PTRACE(4, Type() << "Proxy mode set " << proxy);
					#endif
				}
				dtype = called->GetCallTypeOfNumber(true);
				if (dtype != -1)
					type = dtype;
			}
			if (dtype == -1) {
				dtype = toolkit->Config()->GetInteger(RoutedSec, "CalledTypeOfNumber", -1);
				if (dtype != -1)
					type = dtype;
			}
			q931->SetCalledPartyNumber(Number, plan, type);
			#if PTRACING
			PTRACE(4, Type() << "Set Called Numbering Plan " << plan << TypeOfNumber << type);
			#endif
		}
	}

	if (q931->HasIE(Q931::CallingPartyNumberIE)) {
		unsigned presentation = (unsigned)-1, screening = (unsigned)-1;
		if (q931->GetCallingPartyNumber(Number, &plan, &type, &presentation, &screening, (unsigned)-1, (unsigned)-1)) {
			dtype = -1;
			if (called) {
				dtype = called->GetCallTypeOfNumber(false);
				if (dtype != -1)
					type = dtype;
			}
			if (dtype == -1) {
				dtype = toolkit->Config()->GetInteger(RoutedSec, "CallingTypeOfNumber", -1);
				if (dtype != -1)
					type = dtype;
			}
			q931->SetCallingPartyNumber(Number, plan, type, presentation, screening);
			#if PTRACING
			PTRACE(4, Type() << "Set Calling Numbering Plan " << plan << TypeOfNumber << type);
			#endif
		}
	}
}

// class H245Handler
H245Handler::H245Handler(const PIPSocket::Address & local, const PIPSocket::Address & remote,const PIPSocket::Address & masq)
      : localAddr(local), remoteAddr(remote), masqAddr(masq), isH245ended(false)
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

bool H245Handler::HandleMesg(H245_MultimediaSystemControlMessage &h245msg)
{
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
	const int numPorts = min(H245PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = H245PortRange.GetPort();
		if (listener->Listen(1, pt, PSocket::CanReuseAddress))
			break;
		int errorNumber = listener->GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, Type() << "\tCould not open H.245 listener at 0.0.0.0:" << pt
			<< " - error " << listener->GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << listener->GetErrorText(PSocket::LastGeneralError)
			);
		listener->Close();
#ifdef _WIN32
		if ((errorNumber & PWIN32ErrorFlag) == 0
				|| (errorNumber & ~PWIN32ErrorFlag) != WSAEADDRINUSE)
			break;
#else
		if (!(errorNumber == EADDRINUSE || errorNumber == EINVAL))
			break;
#endif
	}
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
	PWaitAndSignal lock(m_signalingSocketMutex);
	if (sigSocket)
		sigSocket->OnH245ChannelClosed();
}

void H245Socket::OnSignalingChannelClosed()
{
	PWaitAndSignal lock(m_signalingSocketMutex);
	sigSocket = NULL;
	EndSession();
	SetDeletable();
}

void H245Socket::ConnectTo()
{
	if (remote->Accept(*listener)) {
		if (ConnectRemote()) {
			ConfigReloadMutex.StartRead();
			SetConnected(true);
			remote->SetConnected(true);
			GetHandler()->Insert(this, remote);
			ConfigReloadMutex.EndRead();
			return;
		}
	}

	ReadLock lockConfig(ConfigReloadMutex);

	m_signalingSocketMutex.Wait();
	// establish H.245 channel failed, disconnect the call
	CallSignalSocket *socket = sigSocket; // use a copy to avoid race conditions with OnSignalingChannelClosed
	if (socket) {
		socket->SetConnected(false);
		socket->RemoveCall();
		if (!socket->IsBlocked())
		    socket->SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
		socket->CloseSocket();
	}
	m_signalingSocketMutex.Signal();
	
	if (H245Socket *ret = static_cast<H245Socket *>(remote)) {
		ret->m_signalingSocketMutex.Wait();
		socket = ret->sigSocket;
		if (socket) {
			if (socket->IsConnected() && !socket->IsBlocked())
				socket->SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
			socket->SetConnected(false);
			socket->CloseSocket();
		}
		ret->m_signalingSocketMutex.Signal();
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
	PIPSocket::Address peerAddr, localAddr(0);
	WORD peerPort;

	// peerH245Addr may be accessed from multiple threads
	m_signalingSocketMutex.Wait();
	if (!peerH245Addr || !GetIPAndPortFromTransportAddr(*peerH245Addr, peerAddr, peerPort)) {
		m_signalingSocketMutex.Signal();
		PTRACE(3, "H245\tINVALID ADDRESS");
		return false;
	}
	SetPort(peerPort);	
	if (sigSocket != NULL)
		sigSocket->GetLocalAddress(localAddr);
	m_signalingSocketMutex.Signal();
	
	int numPorts = min(H245PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = H245PortRange.GetPort();
		if (Connect(localAddr, pt, peerAddr)) {
			PTRACE(3, "H245\tConnect to " << GetName() << " from " 
				<< localAddr << ':' << pt << " successful"
				);
			return true;
		}
		int errorNumber = GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, Type() << "\tCould not open/connect H.245 socket at " << localAddr << ':' << pt
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << GetErrorText(PSocket::LastGeneralError)
			);
		Close();
		PTRACE(3, "H245\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");
#ifdef _WIN32
		if ((errorNumber & PWIN32ErrorFlag) == 0
				|| (errorNumber & ~PWIN32ErrorFlag) != WSAEADDRINUSE)
			break;
#else
		if (!(errorNumber == EADDRINUSE || errorNumber == EINVAL))
			break;
#endif
	}
	return false;
}

H225_TransportAddress H245Socket::GetH245Address(const Address & myip)
{
	return SocketToH225TransportAddr(myip, listener ? listener->GetPort() : 0);
}

bool H245Socket::SetH245Address(H225_TransportAddress & h245addr, const Address & myip)
{
	bool swapped;
	H245Socket *socket;

	// peerH245Address may be accessed from multiple threads
	m_signalingSocketMutex.Wait();
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
	m_signalingSocketMutex.Signal();
	
	h245addr = SocketToH225TransportAddr(myip, socket->listener->GetPort());
	PTRACE(3, "H245\tSet h245Address to " << AsDotString(h245addr));
	return swapped;
}

bool H245Socket::Reverting(const H225_TransportAddress & h245addr)
{
	PTRACE(3, "H245\tH.245 Reverting detected");
	PWaitAndSignal lock(m_signalingSocketMutex); // peerH245Address may be accessed from multiple threads
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
	m_signalingSocketMutex.Wait();
	if (!sigSocket || !listener) {
		m_signalingSocketMutex.Signal();
		return false;
	}

	Q931 q931;
	sigSocket->BuildFacilityPDU(q931, H225_FacilityReason::e_startH245);
	q931.Encode(buffer);
	sigSocket->TransmitData(buffer);
	m_signalingSocketMutex.Signal();
	
	bool result = Accept(*listener);
	PTRACE_IF(3, result, "H245\tChannel established for NAT EP");
	listener->Close();
	return result;
}

namespace { // anonymous namespace

inline bool compare_lc(pair<const WORD, RTPLogicalChannel *> p, LogicalChannel *lc)
{
	return p.second == lc;
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
	fnat = rnat = mute = false;
}

bool UDPProxySocket::Bind(WORD pt)
{
	return Bind(INADDR_ANY, pt);
}

bool UDPProxySocket::Bind(const Address &localAddr, WORD pt)
{
	if (!Listen(localAddr, 0, pt))
		return false;

	// Set the IP Type Of Service field for prioritisation of media UDP packets
#ifdef _WIN32
	// Windows MultMedia stuff seems to need greater depth due to enormous
	// latencies in its operation, need to use DirectSound maybe?
	int rtpIpTypeofService = IPTOS_PREC_CRITIC_ECP | IPTOS_LOWDELAY;
#else
	// Don't use IPTOS_PREC_CRITIC_ECP on Unix platforms as then need to be root
	int rtpIpTypeofService = IPTOS_LOWDELAY;
#endif
	if (!ConvertOSError(::setsockopt(os_handle, IPPROTO_IP, IP_TOS, (char *)&rtpIpTypeofService, sizeof(int)))) {
		PTRACE(1, Type() << "\tCould not set TOS field in IP header: "
			<< GetErrorCode(PSocket::LastGeneralError) << '/'
			<< GetErrorNumber(PSocket::LastGeneralError) << ": "
			<< GetErrorText(PSocket::LastGeneralError)
			);
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
	if ((DWORD)srcIP != 0)
		fSrcIP = srcIP, fSrcPort = srcPort;
	addr >> fDestIP >> fDestPort;

	if ((DWORD)srcIP) {
		Address laddr;
		WORD lport = 0;
		GetLocalAddress(laddr, lport);
		SetName(AsString(srcIP, srcPort) + "<=>" + AsString(laddr, lport) + "<=>" + AsString(fDestIP, fDestPort));
	} else
		SetName("(To be autodetected)");
	PTRACE(5, Type() << "\tForward " << AsString(srcIP, srcPort) 
		<< " to " << fDestIP << ':' << fDestPort
		);
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
	if (rSrcIP == 0 && fromIP == fDestIP)
		rSrcIP = fromIP, rSrcPort = fromPort;
	if (fSrcIP == 0 && fromIP == rDestIP) {
		fSrcIP = fromIP, fSrcPort = fromPort;
		Address laddr;
		WORD lport = 0;
		GetLocalAddress(laddr, lport);
		SetName(AsString(fSrcIP, fSrcPort) + "=>" + AsString(laddr, lport));
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

	if (isMute())
		return true;

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
	ReadLock lock(ConfigReloadMutex);
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

	// if Home specifies only one local address, we want to bind
	// only to this specified local address
	PIPSocket::Address laddr(INADDR_ANY);
	std::vector<PIPSocket::Address> home;
	Toolkit::Instance()->GetGKHome(home);
	if (home.size() == 1)
		laddr = home[0];

	int numPorts = min(RTPPortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS*2);
	for (int i = 0; i < numPorts; i += 2) {
		port = GetPortNumber();
		// try to bind rtp to an even port and rtcp to the next one port
		if (!rtp->Bind(laddr, port)) {
			PTRACE(1, "RTP\tRTP socket " << AsString(laddr, port) << " not available - error "
				<< rtp->GetErrorCode(PSocket::LastGeneralError) << '/'
				<< rtp->GetErrorNumber(PSocket::LastGeneralError) << ": " 
				<< rtp->GetErrorText(PSocket::LastGeneralError)
				);
			rtp->Close();
			continue;
		}
		if (!rtcp->Bind(laddr, port+1)) {
			PTRACE(1, "RTP\tRTCP socket " << AsString(laddr, port + 1) << " not available - error "
				<< rtcp->GetErrorCode(PSocket::LastGeneralError) << '/'
				<< rtcp->GetErrorNumber(PSocket::LastGeneralError) << ": " 
				<< rtcp->GetErrorText(PSocket::LastGeneralError)
				);
			rtcp->Close();
			rtp->Close();
			continue;
		}
		return;
	}

	PTRACE(2, "RTP\tLogical channel " << flcn << " could not be established - out of RTP sockets");
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

bool RTPLogicalChannel::IsOpen() const
{
	return rtp->IsOpen() && rtcp->IsOpen();
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

void RTPLogicalChannel::SetRTPMute(bool toMute)
{
	if (rtp)
		rtp->SetMute(toMute);
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
	HandleMediaChannel(mediaControlChannel, mediaChannel, handler->GetMasqAddr(), false);
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
	RTPPortRange.GetPort(); // skip odd port
	return port;
}


// class T120LogicalChannel
T120LogicalChannel::T120LogicalChannel(WORD flcn) : LogicalChannel(flcn)
{
	listener = new T120Listener(this);
	port = listener->GetPort();
	if (listener->IsOpen())
		PTRACE(4, "T120\tOpen logical channel " << flcn << " port " << port);
	else
		PTRACE(4, "T120\tFailed to open logical channel " << flcn << " port " << port);
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
	int numPorts = min(T120PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = T120PortRange.GetPort();
		SetName("T120:" + PString(pt));
		if (Listen(5, pt, PSocket::CanReuseAddress))
			break;
		int errorNumber = GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, GetName() << "Could not open listening T.120 socket at 0.0.0.0:" << pt
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << GetErrorText(PSocket::LastGeneralError)
			);
		Close();
#ifdef _WIN32
		if ((errorNumber & PWIN32ErrorFlag) == 0
				|| (errorNumber & ~PWIN32ErrorFlag) != WSAEADDRINUSE)
			break;
#else
		if (!(errorNumber == EADDRINUSE || errorNumber == EINVAL))
			break;
#endif
	}
}

ServerSocket *T120LogicalChannel::T120Listener::CreateAcceptor() const
{
	return new T120ProxySocket(t120lc);
}

void T120LogicalChannel::Create(T120ProxySocket *socket)
{
	T120ProxySocket *remote = new T120ProxySocket(socket, peerPort);
	int numPorts = min(T120PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = T120PortRange.GetPort();
		if (remote->Connect(INADDR_ANY, pt, peerAddr)) { // TODO
			PTRACE(3, "T120\tConnect to " << remote->GetName()
				<< " from 0.0.0.0:" << pt << " successful"
				);
			socket->SetConnected(true);
			remote->SetConnected(true);
			handler->Insert(socket, remote);
			PWaitAndSignal lock(m_smutex);
			sockets.push_back(socket);
			sockets.push_back(remote);
			return;
		}
		int errorNumber = remote->GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, remote->Type() << "\tCould not open/connect T.120 socket at 0.0.0.0:" << pt
			<< " - error " << remote->GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << remote->GetErrorText(PSocket::LastGeneralError)
			);
		remote->Close();
		PTRACE(3, "T120\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");
#ifdef _WIN32
		if ((errorNumber & PWIN32ErrorFlag) == 0
				|| (errorNumber & ~PWIN32ErrorFlag) != WSAEADDRINUSE)
			break;
#else
		if (!(errorNumber == EADDRINUSE || errorNumber == EINVAL))
			break;
#endif
	}
	delete remote;
	remote = NULL;
	delete socket;
	socket = NULL;
}

bool T120LogicalChannel::OnSeparateStack(H245_NetworkAccessParameters & sepStack, H245Handler *handler)
{
	bool changed = false;
	if (sepStack.m_networkAddress.GetTag() == H245_NetworkAccessParameters_networkAddress::e_localAreaAddress) {
		H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(sepStack.m_networkAddress);
		if (addr) {
			*addr >> peerAddr >> peerPort;
			*addr << handler->GetMasqAddr() << port;
			changed = true;
		}
	}
	return changed;
}


// class H245ProxyHandler
H245ProxyHandler::H245ProxyHandler(const PIPSocket::Address & local, const PIPSocket::Address & remote, const PIPSocket::Address & masq, H245ProxyHandler *pr)
      : H245Handler(local, remote, masq), peer(pr)
{
	if (peer)
		peer->peer = this;
	isMute = false;
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
		*addr << GetMasqAddr() << (lc->GetPort() + 1);
		changed = true;
	}
	if( h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)
		&& (addr = GetH245UnicastAddress(h225Params->m_mediaChannel))) {

		if (addr->m_tsapIdentifier != 0) {
			lc->SetMediaChannelSource(*addr);
			*addr << GetMasqAddr() << lc->GetPort();
		} else {
			*addr << GetMasqAddr() << (WORD)0;
		}
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

bool H245ProxyHandler::HandleIndication(H245_IndicationMessage & Indication)
{
	PString value = PString();

	if (Indication.GetTag() != H245_IndicationMessage::e_userInput)
		return false;

	const H245_UserInputIndication & ind = Indication;

	switch (ind.GetTag()) {
		case H245_UserInputIndication::e_alphanumeric :
			value = (const PASN_GeneralString &)ind;
			break;

		case H245_UserInputIndication::e_signal :
		{
			const H245_UserInputIndication_signal & sig = ind;
			value = PString(sig.m_signalType[0]);
			break;
		}
	}
	PTRACE(3, "Received Input: " << value);

	if ((value == "*") &&
		Toolkit::AsBool(GkConfig()->GetString(ProxySection, "EnableRTPMute", "0"))) {  // now we have to do something
		HandleMuteRTPChannel();
	}
	return false;
}

void H245ProxyHandler::HandleMuteRTPChannel()
{
	isMute = !isMute;

	iterator eIter = logicalChannels.end();
	for (iterator Iter = logicalChannels.begin(); Iter != eIter; ++Iter) {
		LogicalChannel * lc = Iter->second;
		lc->SetRTPMute(isMute);
		PTRACE(3, (isMute ? "Mute": "Release") << " RTP Channel " << lc->GetChannelNumber() );
	}
// handler->SetMute(isMute);
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

	bool changed = false;
	if (Toolkit::AsBool(GkConfig()->GetString(ProxySection, "RemoveMCInFastStartTransmitOffer", "0"))) {
		// for unicast transmit channels, mediaChannel should not be sent on offer
		// it is responsibility of callee to provide mediaChannel in an answer
		H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters &params = olc.m_forwardLogicalChannelParameters.m_multiplexParameters;
		if (params.GetTag() == H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters) {
			H245_H2250LogicalChannelParameters &h225Params = (H245_H2250LogicalChannelParameters &)params;
			if (h225Params.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)) {
				h225Params.RemoveOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel);
				changed = true;
			}
		}
	}
	
	bool nouse;
	H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse);
	return ((h225Params) ? OnLogicalChannelParameters(h225Params, 0) : false) || changed;
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
			else {
				logicalChannels[flcn] = sessionIDs[id] = lc = new RTPLogicalChannel(lc, flcn, hnat != 0);
				if (!lc->IsOpen())
					PTRACE(1, "Proxy\tError: Can't create RTP logical channel " << flcn);
			}
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
	if (lc && (changed = lc->OnLogicalChannelParameters(*h225Params, GetMasqAddr(), isReverseLC)))
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
		lc = new RTPLogicalChannel(flcn, hnat != 0);
		if (!lc->IsOpen()) {
			PTRACE(1, "Proxy\tError: Can't create RTP logical channel " << flcn);
			return NULL;
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
		// the LogicalChannelNumber of a fastStart logical channel is irrelevant
		// it may be set later
		lc = new RTPLogicalChannel(0, hnat != 0);
		if (!lc->IsOpen()) {
			PTRACE(1, "Proxy\tError: Can't create fast start logical channel id " << id);
			return NULL;
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
	siterator i = find_if(sessionIDs.begin(), sessionIDs.end(), bind2nd(std::ptr_fun(compare_lc), lc));
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
	if (!ChangeAddress(addr))
	    return addr ? (*addr << remoteAddr, true) : false;
	else
		return TRUE;
}

bool NATHandler::ChangeAddress(H245_UnicastAddress_iPAddress * addr)
{
   PIPSocket::Address olcAddr = 
	   PIPSocket::Address(addr->m_network.GetSize(), addr->m_network.GetValue());

   // Is NATed Endpoint
   if (olcAddr.IsRFC1918())
	   return FALSE;

   // if the OLC address differs from the remote NAT address
   if (remoteAddr != olcAddr) 
      remoteAddr = olcAddr;

   return true;
}


// class CallSignalListener
CallSignalListener::CallSignalListener(const Address & addr, WORD pt)
{
	unsigned queueSize = GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH);
	if (!Listen(addr, queueSize, pt, PSocket::CanReuseAddress)) {
		PTRACE(1, "Q931\tCould not open Q.931 listening socket at " << addr << ':' << pt
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< GetErrorNumber(PSocket::LastGeneralError) << ": " 
			<< GetErrorText(PSocket::LastGeneralError)
			);
		Close();
	}
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
	: SocketsReader(100), m_socketCleanupTimeout(DEFAULT_SOCKET_CLEANUP_TIMEOUT)
{
	SetName(name);
	Execute();
}

ProxyHandler::~ProxyHandler()
{
	DeleteObjectsInContainer(m_removedTime);
}

void ProxyHandler::LoadConfig()
{
	m_socketCleanupTimeout = GkConfig()->GetInteger(
		RoutedSec, "SocketCleanupTimeout", DEFAULT_SOCKET_CLEANUP_TIMEOUT
		);
}

void ProxyHandler::Insert(TCPProxySocket *socket)
{
	ProxyHandler *h = socket->GetHandler();
	if (h == NULL) {
		socket->SetHandler(this);
		AddSocket(socket);
	} else
	h->MoveTo(this, socket);
}

void ProxyHandler::Insert(TCPProxySocket *first, TCPProxySocket *second)
{
	ProxyHandler *h = first->GetHandler();
	if (h != NULL && h != this)
		h->DetachSocket(first);
	first->SetHandler(this);
	h = second->GetHandler();
	if (h != NULL && h != this)
		h->DetachSocket(second);
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
	iterator iter = find(m_sockets.begin(), m_sockets.end(), socket);
	if (iter != m_sockets.end()) {
		m_sockets.erase(iter);
		--m_socksize;
	}
	m_listmutex.EndWrite();
	socket->SetHandler(dest);
	dest->AddSocket(socket);
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
			if (socket->IsSocketOpen()) {
#ifdef _WIN32
				if (slist.GetSize() >= FD_SETSIZE)
					PTRACE(0, "Proxy\tToo many sockets in this proxy handler "
						"(FD_SETSIZE=" << ((int)FD_SETSIZE) << ")"
						);
#else
#ifdef LARGE_FDSET
				const int large_fdset = (int)LARGE_FDSET;
				if (socket->Self()->GetHandle() >= large_fdset)
					PTRACE(0, "Proxy\tToo many opened file handles, skipping handle #"
						<< socket->Self()->GetHandle() << " (limit=" << 
						large_fdset	<< ")"
						);
#else
				if (socket->Self()->GetHandle() >= (int)FD_SETSIZE)
					PTRACE(0, "Proxy\tToo many opened file handles, skipping handle #"
						<< socket->Self()->GetHandle() << " (limit=" << 
						((int)FD_SETSIZE) << ")"
						);
#endif
#endif
				else
					slist.Append(*k);
			} else if (!socket->IsConnected()) {
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
		while (i != m_removed.end() && (now - **ti) >= m_socketCleanupTimeout) {
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
	iterator iter = find(m_sockets.begin(), m_sockets.end(), first);
	if (iter == m_sockets.end()) {
		m_sockets.push_back(first);
		++m_socksize;
	} else
		PTRACE(1, GetName() << "\tTrying to add an already existing socket to the handler");
	iter = find(m_sockets.begin(), m_sockets.end(), second);
	if (iter == m_sockets.end()) {
		m_sockets.push_back(second);
		++m_socksize;
	} else
		PTRACE(1, GetName() << "\tTrying to add an already existing socket to the handler");
	m_listmutex.EndWrite();
	Signal();
	PTRACE(5, GetName() << " total sockets " << m_socksize);
}

void ProxyHandler::FlushSockets()
{
	SocketSelectList wlist(GetName());
	m_listmutex.StartRead();
	iterator i = m_sockets.begin(), j = m_sockets.end();
	while (i != j) {
		if (dynamic_cast<ProxySocket *>(*i)->CanFlush()) {
#ifdef _WIN32
			if (wlist.GetSize() >= FD_SETSIZE)
				PTRACE(0, "Proxy\tToo many sockets in this proxy handler "
					"(limit=" << ((int)FD_SETSIZE) << ")"
					);
#else
#ifdef LARGE_FDSET
			const int large_fdset = (int)LARGE_FDSET;
			if ((*i)->GetHandle() >= large_fdset)
				PTRACE(0, "Proxy\tToo many opened file handles, skipping handle #"
					<< (*i)->GetHandle() << " (limit=" << large_fdset << ")"
					);
#else
			if ((*i)->GetHandle() >= (int)FD_SETSIZE)
				PTRACE(0, "Proxy\tToo many opened file handles, skipping handle #"
					<< (*i)->GetHandle() << " (limit=" << ((int)FD_SETSIZE) << ")"
					);
#endif
#endif
			else
				wlist.Append(*i);
		}
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
	// avoid double insert
	if (find(m_removed.begin(), m_removed.end(), socket) == m_removed.end()) {
		m_removed.push_back(socket);
		m_removedTime.push_back(new PTime);
		++m_rmsize;
	}
}

void ProxyHandler::Remove(TCPProxySocket *socket)
{
	m_listmutex.StartWrite();
	iterator i = find(m_sockets.begin(), m_sockets.end(), socket);
	if (i != m_sockets.end()) {
		m_sockets.erase(i);
		--m_socksize;
	}
	m_listmutex.EndWrite();
	
	PWaitAndSignal lock(m_rmutex);
	// avoid double insert
	if (find(m_removed.begin(), m_removed.end(), socket) == m_removed.end()) {
		m_removed.push_back(socket);
		m_removedTime.push_back(new PTime);
		++m_rmsize;
	}
}

bool ProxyHandler::Detach(TCPProxySocket *socket)
{
	bool detached = false;
	
	m_listmutex.StartWrite();
	iterator i = find(m_sockets.begin(), m_sockets.end(), socket);
	if (i != m_sockets.end()) {
		m_sockets.erase(i);
		--m_socksize;
		detached = true;
	}
	m_listmutex.EndWrite();
	
	return detached;
}

void ProxyHandler::DetachSocket(IPSocket *socket)
{
	m_listmutex.StartWrite();
	iterator iter = find(m_sockets.begin(), m_sockets.end(), socket);
	if (iter != m_sockets.end()) {
		dynamic_cast<ProxySocket*>(socket)->SetHandler(NULL);
		m_sockets.erase(iter);
		--m_socksize;
	} else
		PTRACE(1, GetName() << "\tTrying to detach a socket that does not belong to any handler");
	m_listmutex.EndWrite();
	Signal();
	PTRACE(5, GetName() << "\tTotal sockets: " << m_socksize);
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
	RTPPortRange.LoadConfig(ProxySection, "RTPPortRange", "1024-65535");

	m_numSigHandlers = GkConfig()->GetInteger(RoutedSec, "CallSignalHandlerNumber", 5);
	if (m_numSigHandlers < 1)
		m_numSigHandlers = 1;
	if (m_numSigHandlers > 200)
		m_numSigHandlers = 200;
	unsigned hs = m_sigHandlers.size();
	if (hs <= m_numSigHandlers) {
		for (unsigned i = hs; i < m_numSigHandlers; ++i)
			m_sigHandlers.push_back(
				new ProxyHandler(psprintf(PString("ProxyH(%d)"), i))
				);
	} else {
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
				new ProxyHandler(psprintf(PString("ProxyRTP(%d)"), i))
				);
	} else {
		m_currentRtpHandler = 0;
	}
	
	std::vector<ProxyHandler *>::const_iterator i = m_sigHandlers.begin();
	while (i != m_sigHandlers.end())
		(*i++)->LoadConfig();

	i = m_rtpHandlers.begin();
	while (i != m_rtpHandlers.end())
		(*i++)->LoadConfig();
}
