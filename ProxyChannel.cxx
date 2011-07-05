//////////////////////////////////////////////////////////////////
//
// ProxyChannel.cxx
//
// Copyright (c) Citron Network Inc. 2001-2002
// Copyright (c) 2002-2011, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <q931.h>
#include <h245.h>
#include <h323pdu.h>
#include "gk.h"
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "stl_supp.h"
#include "gkacct.h"
#include "RasSrv.h"
#include "GkClient.h"
#include "Neighbor.h"
#include "sigmsg.h"
#include "ProxyChannel.h"
#include "config.h"

#ifdef H323_H450
 #ifdef h323pluslib
   #include "h450/h4501.h"
   #include "h450/h4502.h"
 #else
   #include "h4501.h"
   #include "h4502.h"
 #endif
#include "SoftPBX.h"
#endif

#ifdef HAS_H460
	#include <h460/h4601.h>
	#ifdef HAS_H46018
		#include <h460/h46018.h>
		#include <h460/h46019.h>
	#endif
#endif
 
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
const char* H245_ProtocolID = "0.0.8.245.0.3";

#ifdef HAS_H46018
#define H46018OID	"0.0.8.460.18.0.1"
#define H46019OID	"0.0.8.460.19.0.1"
#define H46019_UNDEFINED_PAYLOAD_TYPE	-1

void AddH460Feature(H225_ArrayOf_FeatureDescriptor & desc, const H460_Feature & newFeat)
{
	PINDEX lastpos = desc.GetSize();
	desc.SetSize(lastpos+1);
	desc[lastpos] = newFeat;    
}
#endif

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
	virtual ~H245Socket();

	void ConnectTo();
	void ConnectToRerouteDestination();

	// override from class ProxySocket
    virtual Result ReceiveData();
	virtual bool EndSession();

	void SendEndSessionCommand();
	void SendTCS(H245_TerminalCapabilitySet * tcs);
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
	virtual PBoolean Accept(PSocket &);
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

	void SetDestination(H245_UnicastAddress_iPAddress &,callptr &);
	void SetForwardDestination(const Address &, WORD, const H245_UnicastAddress_iPAddress &, callptr &);
	void SetReverseDestination(const Address &, WORD, const H245_UnicastAddress_iPAddress &, callptr &);
	typedef void (UDPProxySocket::*pMem)(const Address &, WORD, const H245_UnicastAddress_iPAddress &, callptr &);

	bool Bind(const Address &localAddr, WORD pt);
	void SetNAT(bool);
	bool isMute() { return mute; }
	void SetMute(bool toMute) { mute = toMute; }
	void OnHandlerSwapped() { std::swap(fnat, rnat); }
	void SetRTPSessionID(WORD id) { m_sessionID = id; }
#ifdef HAS_H46018
	void SetUsesH46019fc(bool fc) { m_h46019fc = fc; }
	void SetUsesH46019(bool val) { m_useH46019 = val; }
	bool UsesH46019() const { return m_useH46019; }
#endif

	// override from class ProxySocket
	virtual Result ReceiveData();

protected:
	virtual bool WriteData(const BYTE *, int);
	virtual bool Flush();
	virtual bool ErrorHandler(PSocket::ErrorGroup);

	// RTCP handler
	void BuildReceiverReport(const RTP_ControlFrame & frame, PINDEX offset, bool dst);

	callptr * m_call;

private:
	UDPProxySocket();
	UDPProxySocket(const UDPProxySocket&);
	UDPProxySocket& operator=(const UDPProxySocket&);

private:
	Address fSrcIP, fDestIP, rSrcIP, rDestIP;
	WORD fSrcPort, fDestPort, rSrcPort, rDestPort;
	bool fnat, rnat;
	bool mute;
	bool m_isRTPType;
	bool m_isRTCPType;
	bool m_dontQueueRTP;
	bool m_EnableRTCPStats;
	WORD m_sessionID;
#ifdef HAS_H46018
	bool m_h46019fc;
	bool m_useH46019;
	bool m_h46019DetectionDone;
	PMutex m_h46019DetectionLock;
#endif
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

	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *,callptr &) = 0;
	virtual void StartReading(ProxyHandler *) = 0;
	virtual void SetRTPMute(bool toMute) = 0;

protected:
	WORD channelNumber;
	WORD port;
	bool used;
};

class RTPLogicalChannel : public LogicalChannel {
public:
	RTPLogicalChannel(H225_CallIdentifier id,WORD flcn, bool nated);
	RTPLogicalChannel(RTPLogicalChannel *flc, WORD flcn, bool nated);
	virtual ~RTPLogicalChannel();

	void SetMediaChannelSource(const H245_UnicastAddress_iPAddress &);
	void SetMediaControlChannelSource(const H245_UnicastAddress_iPAddress &);
	void HandleMediaChannel(H245_UnicastAddress_iPAddress *, H245_UnicastAddress_iPAddress *, const PIPSocket::Address &, bool, callptr &);
	bool OnLogicalChannelParameters(H245_H2250LogicalChannelParameters &, const PIPSocket::Address &, bool, callptr &);

	// override from class LogicalChannel
	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *,callptr &);
	virtual void StartReading(ProxyHandler *);
	virtual void SetRTPMute(bool toMute);

	bool IsAttached() const { return (peer != 0); }
	void OnHandlerSwapped(bool);

	bool IsOpen() const;
	void SetUsesH46019fc(bool);
	void SetH46019Direction(int dir);
	void SetRTPSessionID(WORD id);

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
	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *,callptr &);
	virtual void StartReading(ProxyHandler *);
	virtual void SetRTPMute(bool /*toMute*/) {};   /// We do not Mute T.120 Channels

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
	virtual bool HandleMesg(H245_MultimediaSystemControlMessage &, bool & suppress, callptr & mcall);
	virtual bool HandleFastStartSetup(H245_OpenLogicalChannel &, callptr &);
	virtual bool HandleFastStartResponse(H245_OpenLogicalChannel &, callptr &);
	typedef bool (H245Handler::*pMem)(H245_OpenLogicalChannel &,callptr &);

	PIPSocket::Address GetLocalAddr() const { return localAddr; }
    PIPSocket::Address GetMasqAddr() const { return masqAddr; }
    PIPSocket::Address GetRemoteAddr() const { return remoteAddr; }

	bool IsSessionEnded() const { return isH245ended; }

protected:
	virtual bool HandleRequest(H245_RequestMessage &);
	virtual bool HandleResponse(H245_ResponseMessage &,callptr &);
	virtual bool HandleCommand(H245_CommandMessage &);
	virtual bool HandleIndication(H245_IndicationMessage &, bool & suppress);

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

	H245ProxyHandler(const H225_CallIdentifier &,const PIPSocket::Address &, const PIPSocket::Address &, const PIPSocket::Address &, H245ProxyHandler * = 0);
	virtual ~H245ProxyHandler();

	// override from class H245Handler
	virtual bool HandleFastStartSetup(H245_OpenLogicalChannel &,callptr &);
	virtual bool HandleFastStartResponse(H245_OpenLogicalChannel &,callptr &);

	void SetHandler(ProxyHandler *);
	LogicalChannel *FindLogicalChannel(WORD);
	RTPLogicalChannel *FindRTPLogicalChannelBySessionID(WORD);
	void SetUsesH46019(bool use) { m_useH46019 = use; }
	bool UsesH46019() const { return m_useH46019; }
	void SetUsesH46019fc(bool use) { m_useH46019fc = use; }
	bool UsesH46019fc() const { return m_useH46019fc; }
	void SetH46019fcState(int use) { m_H46019fcState = use; }
	int GetH46019fcState() const { return m_H46019fcState; }
	void SetH46019Direction(int dir) { m_H46019dir = dir; }
	int GetH46019Direction() const { return m_H46019dir; }

private:
	// override from class H245Handler
	virtual bool HandleRequest(H245_RequestMessage &);
	virtual bool HandleResponse(H245_ResponseMessage &, callptr &);
	virtual bool HandleIndication(H245_IndicationMessage &, bool & suppress);

	bool OnLogicalChannelParameters(H245_H2250LogicalChannelParameters *, WORD);
	bool HandleOpenLogicalChannel(H245_OpenLogicalChannel &);
	bool HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck &, callptr &);
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
	H225_CallIdentifier callid;
	bool isMute;
	bool m_useH46019;
	bool m_useH46019fc;
	int m_H46019fcState;
	int m_H46019dir;
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

inline TCPProxySocket::TPKTV3::TPKTV3(WORD len)
	: header(3), padding(0)
{
	length = PIPSocket::Host2Net(WORD(len + sizeof(TPKTV3)));
}

// class TCPProxySocket
TCPProxySocket::TCPProxySocket(const char *t, TCPProxySocket *s, WORD p)
      : ServerSocket(p), ProxySocket(this, t), remote(s), bufptr(NULL), tpktlen(0)
{
}

TCPProxySocket::~TCPProxySocket()
{
	if (remote) {
		remote->remote = NULL; // detach myself from remote
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
PBoolean TCPProxySocket::Accept(PSocket & socket)
{
//	SetReadTimeout(PMaxTimeInterval);
	PBoolean result = PTCPSocket::Accept(socket);
	if (result) {
		PTimeInterval timeout(100);
		SetReadTimeout(timeout);
		SetWriteTimeout(timeout);
		// since GetName() may not work if socket closed,
		// we save it for reference
		Address raddr;
		WORD rport = 0;
		GetPeerAddress(raddr, rport);
		SetName(AsString(raddr, rport));
	}
	return result;
}

PBoolean TCPProxySocket::Connect(const Address & iface, WORD localPort, const Address & addr)
{
	SetName(AsString(addr, GetPort()));
	SetReadTimeout(PTimeInterval(6000));
	PBoolean result = PTCPSocket::Connect(iface, localPort, addr);
	if (result) {
		PTimeInterval timeout(100);
		SetReadTimeout(timeout);
		SetWriteTimeout(timeout);
	}
	return result;
}

PBoolean TCPProxySocket::Connect(const Address & addr)
{
	return Connect(INADDR_ANY, 0, addr);
}

#endif

bool TCPProxySocket::ReadTPKT()
{
	PTRACE(5, Type() << "\tReading from " << GetName());
	if (tpktlen < sizeof(tpkt)) {
		if (!Read(reinterpret_cast<BYTE*>(&tpkt) + tpktlen, sizeof(tpkt) - tpktlen))
			return ErrorHandler(PSocket::LastReadError);
		tpktlen += GetLastReadCount();
		if (tpktlen < sizeof(tpkt)) {
			PTRACE(3, Type() << "\t" << GetName() << " fragmented TPKT header, will wait for more data");
			return false;
		}

		// accept malformed Tandberg MXP keep-alive		
		if (tpkt.header == 0 && tpkt.padding == 3 && tpkt.length == 1024) {
			PTRACE(3, Type() << "\tignoring empty Tandberg TPKT from " << GetName() << " (keep-alive)");
			buflen = 0;
			tpktlen = 0;
			return false;
		}
		// some endpoints don't set padding to 0, e.g. Cisco AS5300 (setting it to 0 is only required in H.323v3 or later)
		if (tpkt.header != 3) {
			PTRACE(2, Type() << "\t" << GetName() << " NOT A TPKT PACKET!"
				<< " header=" << (int)tpkt.header << " padding=" << (int)tpkt.padding << " length=" << (int)tpkt.length);
			tpktlen = 0;
			errno = EINVAL;
			ConvertOSError(-1, PSocket::LastReadError);
			return ErrorHandler(PSocket::LastReadError);
		}
		buflen = PIPSocket::Net2Host(tpkt.length) - sizeof(TPKTV3);
		if (buflen < 1) {
			PTRACE(3, Type() << "\tignoring empty TPKT from " << GetName() << " (keep-alive)");
			buflen = 0;
			tpktlen = 0;
			return false;
		}
		if (!SetMinBufSize(buflen)) {
			PTRACE(1, Type() << "\t" << GetName() << " could not set new buffer size: " << buflen);
			errno = ENOMEM;
			ConvertOSError(-1, PSocket::LastReadError);
			return ErrorHandler(PSocket::LastReadError);
		}
		buffer = PBYTEArray(bufptr = wbuffer, buflen, false);
	}

#ifdef LARGE_FDSET
	// some endpoints may send TPKT header and payload in separate
	// packets, so we have to check again if data available
	if (this->GetHandle() < (int)FD_SETSIZE)
		if (!YaSelectList(GetName(), this).Select(YaSelectList::Read, 0))
			return false;
#endif
	if (!Read(bufptr, buflen))
		return ErrorHandler(PSocket::LastReadError);

	buflen -= GetLastReadCount();
	if (buflen == 0) {
		tpktlen = 0;
		return true;
	}
	
	bufptr += GetLastReadCount();
	PTRACE(3, Type() << "\t" << GetName() << " TPKT fragmented, will wait for more data");
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
	m_h245Tunneling = socket->m_h245Tunneling;
}

CallSignalSocket::CallSignalSocket(CallSignalSocket *socket, WORD _port)
	: TCPProxySocket("Q931d", socket, _port), m_callerSocket(false)
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
	int nat_type = m_call->GetNATType(calling, called);
	if (nat_type & CallRec::calledParty) {
		socket->peerAddr = called;
	}

	if (m_call->GetProxyMode() != CallRec::ProxyEnabled
		&& nat_type == CallRec::both && calling == called) {
		if (!Toolkit::AsBool(GkConfig()->GetString(ProxySection, "ProxyForSameNAT", "1"))) {
            PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy DISABLED. (Same NAT)");
			m_call->SetProxyMode(CallRec::ProxyDisabled);
			return;
		}
	}

	if (Toolkit::AsBool(GkConfig()->GetString(ProxySection, "ProxyAlways", "0"))) {
		m_call->SetProxyMode(CallRec::ProxyEnabled);
		m_call->SetH245Routed(true);
	}

	// enable proxy if required, no matter whether H.245 routed
	if (m_call->GetProxyMode() == CallRec::ProxyDetect) {
		if ((nat_type != CallRec::none && Toolkit::AsBool(GkConfig()->GetString(ProxySection, "ProxyForNAT", "1"))) ) {
			// must proxy
			m_call->SetProxyMode(CallRec::ProxyEnabled);
		} else {
			// check if we have a [ModeSelection] rule matching for this call
			int mode = Toolkit::Instance()->SelectRoutingMode(peerAddr, socket->peerAddr);
			switch (mode) {
				case CallRec::SignalRouted:
					m_call->SetProxyMode(CallRec::ProxyDisabled);
					m_call->SetH245Routed(false);
					break;
				case CallRec::H245Routed:
					m_call->SetProxyMode(CallRec::ProxyDisabled);
					m_call->SetH245Routed(true);
					break;
				case CallRec::Proxied:
					m_call->SetProxyMode(CallRec::ProxyEnabled);
					m_call->SetH245Routed(true);
					break;
				default:
					m_call->SetProxyMode(CallRec::ProxyDisabled);
					break;
			}
		}
	}
	PTRACE(1, "Call " << m_call->GetCallNumber() << ": h245Routed=" << m_call->IsH245Routed() << " proxy=" << ((m_call->GetProxyMode() == CallRec::ProxyEnabled) ? 1 : 0));

	if (m_call->GetProxyMode() == CallRec::ProxyEnabled) {
		H245ProxyHandler *proxyhandler = new H245ProxyHandler(m_call->GetCallIdentifier(), socket->localAddr, calling, socket->masqAddr);
#ifdef HAS_H46018
		if (m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46018()) 
			proxyhandler->SetUsesH46019(true);
		proxyhandler->SetH46019Direction(m_call->GetH46019Direction());
#endif
		socket->m_h245handler = proxyhandler;
		m_h245handler = new H245ProxyHandler(m_call->GetCallIdentifier(),localAddr, called, masqAddr, proxyhandler);
#ifdef HAS_H46018
		if (m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46018()) 
			((H245ProxyHandler*)m_h245handler)->SetUsesH46019(true);	
		((H245ProxyHandler*)m_h245handler)->SetH46019Direction(m_call->GetH46019Direction());
#endif
		proxyhandler->SetHandler(GetHandler());
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled");
	} else {
		if (m_call->IsH245Routed()) {
			socket->m_h245handler = new H245Handler(socket->localAddr, calling, socket->masqAddr);
			m_h245handler = new H245Handler(localAddr, called, masqAddr);
		}
	}
}

CallSignalSocket::~CallSignalSocket()
{
	if (m_h245socket) {
		if (CallSignalSocket *ret = static_cast<CallSignalSocket *>(remote)) {
			if (m_h245handler && !m_h245handler->IsSessionEnded() && ret->m_h245socket) {
				ret->m_h245socket->SendEndSessionCommand();
			}
			if (ret->m_h245handler && !ret->m_h245handler->IsSessionEnded()) {
				m_h245socket->SendEndSessionCommand();
			}
		}
		m_h245socket->OnSignalingChannelClosed();
	}

	if (m_call) {
		if (m_call->GetCallSignalSocketCalling() == this) {
			m_call->SetCallSignalSocketCalling(NULL);
			PTRACE(1, "Q931\tWARNING: Calling socket " << GetName() 
				<< " not removed from CallRec before deletion"
				);
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
PBoolean CallSignalSocket::Connect(const Address & addr)
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

#ifdef H323_H450
	// Enable H.450.2 Call Transfer Emulator
	if (m_call
		&& uuie
		&& Toolkit::AsBool(Toolkit::Instance()->Config()->GetString(RoutedSec, "EnableH450.2", "0"))
		&& uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h4501SupplementaryService)) {
			// Process H4501SupplementaryService APDU
			if (OnH450PDU(uuie->m_h323_uu_pdu.m_h4501SupplementaryService))  {
				delete msg;
				return NoData;   // don't forward
			}
    }
#endif

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

	if (!m_callerSocket && m_call
		&& ((msg->GetTag() == Q931::AlertingMsg) || (msg->GetTag() == Q931::ConnectMsg))) {
		m_call->SetCallInProgress();
	}

	if (m_result == Error || m_result == NoData) {
		delete msg;
		return m_result;
	}
	
	if (msg->GetUUIE() != NULL && msg->GetUUIE()->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control)) {
		bool suppress = false;
		if (m_h245handler && OnTunneledH245(msg->GetUUIE()->m_h323_uu_pdu.m_h245Control, suppress))
			msg->SetUUIEChanged();

        if (suppress) {
		    m_result = NoData;	// don't forward anything 
		    PTRACE(2, "Not forwarding " << msg->GetTagName());
		    delete msg;
		    return m_result;
        }

		if (!m_callerSocket && m_call)
			m_call->SetH245ResponseReceived();
	}

	if (m_call && (m_call->GetRerouteState() == RerouteInitiated) && (msg->GetTag() == Q931::ReleaseCompleteMsg)) {
		PTRACE(1, "Q931\tReroute failed, terminating call");
		// don't end reroute on RC to dropped party		m_call->SetRerouteState(NoReroute);
	}

	if (m_call && (m_call->GetRerouteState() == RerouteInitiated) && (msg->GetTag() != Q931::SetupMsg) && (msg->GetTag() != Q931::ConnectMsg)) {
		m_result = NoData;	// don't forward anything until reroute is through
		PTRACE(2, "Call in reroute: won't forward " << msg->GetTagName());
		delete msg;
		return m_result;
	}

	if (m_call && m_call->GetRerouteState() == RerouteInitiated && (msg->GetTag() == Q931::ConnectMsg)) {
		m_result = NoData;	// process messages, but don't forward anything until reroute is through
		PTRACE(2, "Call in reroute: won't forward " << msg->GetTagName() << " switching to Rerouting state");
		m_call->SetRerouteState(Rerouting);

		// forward saved TCS
		// TODO: if have saved TCS
		if (m_h245Tunneling) {
			// WARNING: this code for h245tunneled mode is hardly tested
			// when tunneling, forward the TCS here (we probably got it in the connect)
			// when call is not tunneled, the TCS comes later and goes through automatically

			// build TCS
			Q931 q931;
			H225_H323_UserInformation uuie;
			PBYTEArray lBuffer;
			BuildFacilityPDU(q931, 0);
			GetUUIE(q931, uuie);
			uuie.m_h323_uu_pdu.m_h323_message_body.SetTag(H225_H323_UU_PDU_h323_message_body::e_empty);
			uuie.m_h323_uu_pdu.m_h245Tunneling = TRUE;	// for new this only works with tunneling
			uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Control);
			uuie.m_h323_uu_pdu.m_h245Control.SetSize(1);
			H245_MultimediaSystemControlMessage h245msg;
			h245msg.SetTag(H245_MultimediaSystemControlMessage::e_request);
			H245_RequestMessage & h245req = h245msg;
			h245req.SetTag(H245_RequestMessage::e_terminalCapabilitySet);
			H245_TerminalCapabilitySet & tcs = h245req;
			tcs = GetSavedTCS();	// TODO: is this the right side, or should we use remote->GetSavedTCS() ?
			tcs.m_protocolIdentifier.SetValue(H245_ProtocolID);
			uuie.m_h323_uu_pdu.m_h245Control[0].EncodeSubType(h245msg);
			SetUUIE(q931, uuie);
			q931.Encode(lBuffer);

			// send TCS to forwarded party
			if (m_call->GetRerouteDirection() == Called) {
				PrintQ931(3, "Send to ", m_call->GetCallSignalSocketCalled()->GetName(), &q931, &uuie);
				m_call->GetCallSignalSocketCalled()->TransmitData(lBuffer);
			} else {
				PrintQ931(3, "Send to ", m_call->GetCallSignalSocketCalling()->GetName(), &q931, &uuie);
				m_call->GetCallSignalSocketCalling()->TransmitData(lBuffer);
			}
		}

		delete msg;
		return m_result;
	}

	if (msg->GetQ931().HasIE(Q931::DisplayIE)) {
		PString newDisplayIE;
		if (m_call && !m_call->GetCallerID().IsEmpty() && (m_crv & 0x8000u)) {	// only rewrite DisplayIE from caller
			newDisplayIE = m_call->GetCallerID();
		} else {
			newDisplayIE = GkConfig()->GetString(RoutedSec, "ScreenDisplayIE", "");
		}
		if (!newDisplayIE.IsEmpty()) {
			msg->GetQ931().SetDisplayName(newDisplayIE);
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
	else if (remote && (m_result != DelayedConnecting))
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
			ReleasePDU.SetCause(Q931::CauseValues(m_call->GetDisconnectCause()));
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

bool CallSignalSocket::HandleH245Mesg(PPER_Stream & strm, bool & suppress, H245Socket * h245sock)
{
	bool changed = false;
	H245_MultimediaSystemControlMessage h245msg;
	if (!h245msg.Decode(strm)) {
		PTRACE(3, "H245\tERROR DECODING H.245 from " << GetName());
		return false;
	}

	PTRACE(4, "H245\tReceived from " << GetName() << ": " << setprecision(2) << h245msg);

	// remove t38FaxUdpOptions from t38FaxProfile eg. for Avaya Communication Manager
	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_request
		&& ((H245_RequestMessage &) h245msg).GetTag() == H245_RequestMessage::e_requestMode
	&& Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveFaxUDPOptionsFromRM", "0"))
	) {
			H245_RequestMode & rm = (H245_RequestMessage &) h245msg;
			for(PINDEX i = 0; i < rm.m_requestedModes.GetSize(); i++) {
					for(PINDEX j = 0; j < rm.m_requestedModes[i].GetSize(); j++) {
							if(rm.m_requestedModes[i][j].m_type.GetTag() == H245_ModeElementType::e_dataMode) {
									H245_DataMode & dm = (H245_DataMode &) rm.m_requestedModes[i][j].m_type;
									if(dm.m_application.GetTag() == H245_DataMode_application::e_t38fax) {
											H245_DataMode_application_t38fax & t38fax = (H245_DataMode_application_t38fax &) dm.m_application;
											if(
													t38fax.m_t38FaxProtocol.GetTag() == H245_DataProtocolCapability::e_udp
													&& t38fax.m_t38FaxProfile.HasOptionalField(H245_T38FaxProfile::e_t38FaxUdpOptions)
											) {
													PTRACE(2, "H245\tRemoving t38FaxUdpOptions received in RM from " << GetName());
													t38fax.m_t38FaxProfile.RemoveOptionalField(H245_T38FaxProfile::e_t38FaxUdpOptions);
											}
									}
							}
					}
			}
	}

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

    if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_indication) {
#ifdef HAS_H46024B
		    H245_IndicationMessage & imsg  = h245msg;
		    if (imsg.GetTag() == H245_IndicationMessage::e_genericIndication) {
			    const char * H46024B_OID = "0.0.8.460.24.2";
 			    H245_GenericMessage & gmsg = imsg;
			    H245_CapabilityIdentifier & id = gmsg.m_messageIdentifier;
				    if (id.GetTag() == H245_CapabilityIdentifier::e_standard) {
					    PASN_ObjectId & val = id;
					    if (val.AsString() == H46024B_OID) {
                            // TBD Signal to shutdown proxy support - SH
						    suppress = true;
						    return false;
					    }
				    }
            }
#endif
    }

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_response) {
		H245_ResponseMessage & rmsg  = h245msg;
#ifdef HAS_H46024B
		if (rmsg.GetTag() == H245_ResponseMessage::e_genericResponse) {
			const char * H46024B_OID = "0.0.8.460.24.2";
 			H245_GenericMessage & gmsg = rmsg;
			H245_CapabilityIdentifier & id = gmsg.m_messageIdentifier;
				if (id.GetTag() == H245_CapabilityIdentifier::e_standard) {
					PASN_ObjectId & val = id;
					if (val.AsString() == H46024B_OID) {
						m_call->H46024BRespond();
						suppress = true;
						return false;
					}
				}
		}
#endif
		if (rmsg.GetTag() == H245_ResponseMessage::e_openLogicalChannelAck) {
			H245_OpenLogicalChannelAck &olcack = rmsg;
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
	}

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_response
		&& ((H245_ResponseMessage&)h245msg).GetTag() == H245_ResponseMessage::e_terminalCapabilitySetAck) {
		H245_TerminalCapabilitySetAck & ack = (H245_ResponseMessage&)h245msg;

		if (m_call && m_call->GetRerouteState() == RerouteInitiated) {
			PTRACE(2, "H245\tReroute: Filtering out TCSAck received from " << GetName());
			suppress = true;
		}

		if (m_call && m_call->GetRerouteState() == Rerouting) {
			CallSignalSocket * forwarded = (m_call->GetRerouteDirection() == Caller) ? m_call->GetCallSignalSocketCalling() : m_call->GetCallSignalSocketCalled();
			if (forwarded) {
				if (forwarded->CompareH245Socket(h245sock)) {
					// rewrite seq of ack, because we rewrite seq of TCS
					ack.m_sequenceNumber = 1;
					changed = true;
				} else {
					PTRACE(2, "H245\tReroute: Filtering out TCSAck received from " << GetName());
					suppress = true;
				}
			}
		}

	}

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_request
		&& ((H245_RequestMessage&)h245msg).GetTag() == H245_RequestMessage::e_terminalCapabilitySet) {

		H245_TerminalCapabilitySet & tcs = (H245_RequestMessage&)h245msg;
		H245_ArrayOf_CapabilityTableEntry & CapabilityTables = tcs.m_capabilityTable;

		// save TCS (only works for non-tunneled right now)
		if (m_call && h245sock && tcs.m_capabilityTable.GetSize() > 0) {
			if (m_call->GetCallSignalSocketCalling()
				&& m_call->GetCallSignalSocketCalling()->CompareH245Socket(h245sock)) {
				m_call->GetCallSignalSocketCalling()->SaveTCS(tcs);
			} else if (m_call->GetCallSignalSocketCalled()) {
				m_call->GetCallSignalSocketCalled()->SaveTCS(tcs);
			}
		}
		// rewrite seq of TCS, must rewrite ACK, too!
		if (m_call && m_call->GetRerouteState() == Rerouting) {
			CallSignalSocket * forwarded = (m_call->GetRerouteDirection() == Caller) ? m_call->GetCallSignalSocketCalling() : m_call->GetCallSignalSocketCalled();
			if (forwarded && !(forwarded->CompareH245Socket(h245sock))) {
				tcs.m_sequenceNumber = 3;
				changed = true;
			}
		}

		// filter the audio capabilities
		for (PINDEX i = 0; i < CapabilityTables.GetSize(); i++) {
			// PTRACE(4, "CapabilityTable: " << setprecision(2) << CapabilityTables[i]);
			unsigned int cten = CapabilityTables[i].m_capabilityTableEntryNumber.GetValue();
			H245_Capability & H245Capability = CapabilityTables[i].m_capability;

			if (H245Capability.GetTag() == H245_Capability::e_receiveAudioCapability ) {
				H245_AudioCapability & H245AudioCapability = H245Capability;
				if (m_call->GetDisabledCodecs().Find(H245AudioCapability.GetTagName() + ";", 0) != P_MAX_INDEX) {
					PTRACE(4, "Delete audio capability " << H245AudioCapability.GetTagName());
					changed = true;
					CapabilityTables.RemoveAt(i);
					i--;
					H245_ArrayOf_CapabilityDescriptor & CapabilityDescriptor = tcs.m_capabilityDescriptors;
					for (PINDEX n = 0; n < CapabilityDescriptor.GetSize(); n++){
						H245_ArrayOf_AlternativeCapabilitySet & AlternativeCapabilitySet = CapabilityDescriptor[n].m_simultaneousCapabilities;
						for (PINDEX j = 0; j < AlternativeCapabilitySet.GetSize(); j++) {
							for (PINDEX m = 0; m < AlternativeCapabilitySet[j].GetSize(); m++) {
								if (cten == AlternativeCapabilitySet[j][m].GetValue()) {
									PTRACE(4, "Capability Descriptors Number");
									AlternativeCapabilitySet[j].RemoveAt(m);
								}
							}
						}
					}
				}
			}
		}

		// filter the video capabilities
		for (PINDEX i = 0; i < CapabilityTables.GetSize(); i++) {
			// PTRACE(4, "CapabilityTable: " << setprecision(2) << CapabilityTables[i]);
			unsigned int cten = CapabilityTables[i].m_capabilityTableEntryNumber.GetValue();
			H245_Capability & H245Capability = CapabilityTables[i].m_capability;

			if (H245Capability.GetTag() == H245_Capability::e_receiveVideoCapability ) {
				H245_VideoCapability & H245VideoCapability = H245Capability;
				if (m_call->GetDisabledCodecs().Find(H245VideoCapability.GetTagName() + ";", 0) != P_MAX_INDEX) {
					PTRACE(4, "Delete video capability " << H245VideoCapability.GetTagName());
					changed = true;
					CapabilityTables.RemoveAt(i);
					i--;
					H245_ArrayOf_CapabilityDescriptor & CapabilityDescriptor = tcs.m_capabilityDescriptors;
					for (PINDEX n = 0; n < CapabilityDescriptor.GetSize(); n++){
						H245_ArrayOf_AlternativeCapabilitySet & AlternativeCapabilitySet = CapabilityDescriptor[n].m_simultaneousCapabilities;
						for (PINDEX j = 0; j < AlternativeCapabilitySet.GetSize(); j++) {
							for (PINDEX m = 0; m < AlternativeCapabilitySet[j].GetSize(); m++) {
								if (cten == AlternativeCapabilitySet[j][m].GetValue()) {
									PTRACE(4, "Capability Descriptors Number");
									AlternativeCapabilitySet[j].RemoveAt(m);
								}
							}
						}
					}
				}
			}
		}

		if (changed) {
			PTRACE(4, "New Capability Table: " << setprecision(2) << tcs);
		}
	}

	if ((!m_h245handler || !m_h245handler->HandleMesg(h245msg, suppress, m_call)) && !changed)
		return false;

	strm.BeginEncoding();
	h245msg.Encode(strm);
	strm.CompleteEncoding();
	PTRACE(5, "H245\tTo send: " << setprecision(2) << h245msg);

	return true;
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

void CallSignalSocket::ForwardCall(FacilityMsg * msg)
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
	m_call->SetBindHint(request.GetSourceIP());
	m_call->SetCallerID(request.GetCallerID());

	PTRACE(3, Type() << "\tCall " << m_call->GetCallNumber() << " is forwarded to "
		<< altDestInfo << (!forwarder ? (" by " + forwarder) : PString::Empty())
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
		if (endptr fwd = m_call->GetForwarder()) {
			const H225_ArrayOf_AliasAddress & a = fwd->GetAliases();
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
				m_h245socket = NULL;
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
		PIPSocket::Address daddr;
		WORD dport = 0;
		if (hasCall && authData.m_call->GetDestSignalAddr(daddr, dport))
			id = AsString(daddr, dport);
		// this does not work well in routed mode, when destCallSignalAddress
		// is usually the gatekeeper address
		else if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress) 
				&& GetIPAndPortFromTransportAddr(setupBody.m_destCallSignalAddress, daddr, dport)
				&& daddr.IsValid())
			id = AsString(daddr, dport);
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

void CallSignalSocket::OnSetup(SignalingMsg *msg)
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
				"signaling channel not supported - new connection needed "
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

	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "GenerateCallProceeding", "0"))
		&& !Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "UseProvisionalRespToH245Tunneling", "0"))) {
		// disable H.245 tunneling when the gatekeeper generates the CP
		H225_H323_UserInformation * uuie = msg->GetUUIE();
		if ((uuie != NULL) && uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling)) {
			msg->GetUUIE()->m_h323_uu_pdu.m_h245Tunneling.SetValue(false);
		}
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_parallelH245Control)) {
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_parallelH245Control);
		}
		m_h245Tunneling = false;
	}

	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "TranslateSorensonSourceInfo", "0"))) {
		if (setupBody.m_sourceInfo.HasOptionalField(H225_EndpointType::e_terminal)
			&&  setupBody.m_sourceInfo.m_terminal.HasOptionalField(H225_TerminalInfo::e_nonStandardData)) {
			if (setupBody.m_sourceInfo.m_terminal.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
				H225_H221NonStandard h221nst = setupBody.m_sourceInfo.m_terminal.m_nonStandardData.m_nonStandardIdentifier;
				if (h221nst.m_manufacturerCode == 21334) {
					PString sinfo = setupBody.m_sourceInfo.m_terminal.m_nonStandardData.m_data.AsString();
					sinfo.Replace("SInfo:", "SInfo|");
					if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
						setupBody.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
						setupBody.m_sourceAddress.SetSize(0);
					}
					PStringArray tokens = sinfo.Tokenise("|", FALSE);
					for (PINDEX i = 0; i < tokens.GetSize(); ++i) {
						int sourceAdrSize = setupBody.m_sourceAddress.GetSize();
						if (tokens[i].Left(4) == "0007") {
							PString e164 = tokens[i].Mid(4);
							if (strspn(e164, "1234567890*#+,") == strlen(e164)) {
								setupBody.m_sourceAddress.SetSize( sourceAdrSize + 1 );
								H323SetAliasAddress(e164, setupBody.m_sourceAddress[sourceAdrSize], H225_AliasAddress::e_dialedDigits);
								sourceAdrSize++;
								setupBody.m_sourceAddress.SetSize( sourceAdrSize + 1 );
								H323SetAliasAddress(e164, setupBody.m_sourceAddress[sourceAdrSize], H225_AliasAddress::e_h323_ID);
								// fill calling number IE
								if (!q931.HasIE(Q931::CallingPartyNumberIE)) {
									unsigned plan = Q931::ISDNPlan, type = Q931::InternationalType;
									unsigned presentation = (unsigned)-1, screening = (unsigned)-1;
									q931.SetCallingPartyNumber(e164, plan, type, presentation, screening);
								}
							} else {
								PTRACE(1, "Invalid character in Sorensen source info: " << e164);
							}
						} else if (tokens[i].Left(4) == "0008") {
							PString ip = tokens[i].Mid(4);
							// check format of IP to avoid runtime error
							if (ip.FindRegEx(PRegularExpression("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$", PRegularExpression::Extended)) != P_MAX_INDEX) {
								setupBody.m_sourceAddress.SetSize( sourceAdrSize + 1 );
								H323SetAliasAddress(ip, setupBody.m_sourceAddress[sourceAdrSize], H225_AliasAddress::e_transportID);
							} else {
								PTRACE(1, "Invalid IP in Sorensen source info: " << ip);
							}
						}
					}
				}
			}
		}
	}

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

			toolkit->GWRewriteE164(in_rewrite_id, GW_REWRITE_IN, setupBody.m_destinationAddress);
		}

		// Normal rewrite
		toolkit->RewriteE164(setupBody.m_destinationAddress);
	}

	// rewrite existing CalledPartyNumberIE
	if (q931.HasIE(Q931::CalledPartyNumberIE)) {
		unsigned plan, type;
		PString calledNumber;
		bool rewritten = false;
		
		if (q931.GetCalledPartyNumber(calledNumber, &plan, &type)) {
			// Do per GW inbound rewrite before global rewrite
			if (!in_rewrite_id)
				rewritten = toolkit->GWRewritePString(in_rewrite_id, GW_REWRITE_IN, calledNumber);
			
			// Normal rewrite
		    rewritten = toolkit->RewritePString(calledNumber) || rewritten;
			
			if (rewritten)
				q931.SetCalledPartyNumber(calledNumber, plan, type);
		}
	}

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
		// rewrite destination IP here (can't do it in Explicit policy, because local IPs are removed before they get there)
		Routing::ExplicitPolicy::MapDestination(setupBody.m_destCallSignalAddress);
		// remove the destination signaling address of the gatekeeper
		PIPSocket::Address _destAddr;
		WORD _destPort = 0;
		if (GetIPAndPortFromTransportAddr(setupBody.m_destCallSignalAddress, _destAddr, _destPort)
				&& _destAddr == _localAddr && _destPort == _localPort) {
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		}
		//  also remove destCallSigAddr if its the ExternalIP
		PString extip = GkConfig()->GetString("ExternalIP", "");
		if (!extip.IsEmpty()) {
			PIPSocket::Address ext((DWORD)0);
			H323TransportAddress ex = H323TransportAddress(extip);
			ex.GetIpAddress(ext);
			if (GetIPAndPortFromTransportAddr(setupBody.m_destCallSignalAddress, _destAddr, _destPort)
					&& _destAddr == ext) {
				PTRACE(1, "Removing External IP from callDestSignalAddr in Setup");
				setupBody.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
			}
		}
	}

	// send a CallProceeding (to avoid caller timeouts)
	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "GenerateCallProceeding", "0"))) {
		PTRACE(4, "Q931\tGatekeeper generated CallProceeding");
		Q931 proceedingQ931;
		PBYTEArray lBuffer;
		BuildProceedingPDU(proceedingQ931, setupBody.m_callIdentifier, m_crv | 0x8000u);
		proceedingQ931.Encode(lBuffer);
		TransmitData(lBuffer);
	}
	
	GkClient *gkClient = rassrv->GetGkClient();
	bool rejectCall = false;
	bool secondSetup = false;	// second Setup with same call-id detected (avoid new acct start and overwriting acct data)
	SetupAuthData authData(m_call, m_call ? true : false);

	if (m_call) {
		// existing CallRec
		m_call->SetSetupTime(setupTime);
		m_call->SetSrcSignalAddr(SocketToH225TransportAddr(_peerAddr, _peerPort));
		
		if (m_call->IsSocketAttached() && !m_call->GetRerouteState() == RerouteInitiated) {
			PTRACE(2, Type() << "\tWarning: socket (" << Name() << ") already attached for callid " << callid);
			m_call->SetDisconnectCause(Q931::CallRejected);
			rejectCall = true;
			// suppress 2nd AcctStart for same callid
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
				secondSetup = (AsString(m_call->GetCallIdentifier().m_guid) == AsString(setupBody.m_callIdentifier.m_guid));
			}
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

		if (!rejectCall && authData.m_routeToAlias.GetSize() > 0) {
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setupBody.m_destinationAddress = authData.m_routeToAlias;

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
		if (!authData.m_calledStationId && !secondSetup)
			m_call->SetCalledStationId(authData.m_calledStationId);
		if (!authData.m_dialedNumber)
			m_call->SetDialedNumber(authData.m_dialedNumber);
		if (authData.m_clientAuthId > 0)
			m_call->SetClientAuthId(authData.m_clientAuthId);
		
		if (!secondSetup && (m_call->GetFailedRoutes().empty() || !m_call->SingleFailoverCDR())) {
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
				<< m_call->GetCallNumber());
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

		if (!rejectCall && authData.m_routeToAlias.GetSize() > 0) {
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setupBody.m_destinationAddress = authData.m_routeToAlias;

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
		Routing::SetupRequest request(setupBody, setup, authData.m_callingStationId, authData.m_clientAuthId);

		// delete routes with no capacity
		for (list<Route>::iterator i = authData.m_destinationRoutes.begin(); i != authData.m_destinationRoutes.end(); /* nothing */ ) {
			H225_ArrayOf_AliasAddress destinationAliases;
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
				destinationAliases = setupBody.m_destinationAddress;
			}
			if ((*i).m_destEndpoint && !((*i).m_destEndpoint->HasAvailableCapacity(destinationAliases))) {
				authData.m_destinationRoutes.erase(i++);	// delete route
			} else {
				++i;	// check next
			}
		}

		if (!rejectCall && !authData.m_destinationRoutes.empty()) {
			list<Route>::const_iterator i = authData.m_destinationRoutes.begin();
			while (i != authData.m_destinationRoutes.end()) {
				request.AddRoute(*i++);
			}
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
 
#ifdef HAS_H46023
		CallRec::NatStrategy natoffloadsupport = CallRec::e_natUnknown;
	if (Toolkit::Instance()->IsH46023Enabled()
		&& setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)
		&& authData.m_proxyMode != CallRec::ProxyDisabled) {
		H225_ArrayOf_FeatureDescriptor & data = setupBody.m_supportedFeatures;
		for (PINDEX i =0; i < data.GetSize(); i++) {
          H460_Feature & feat = (H460_Feature &)data[i];	// TODO/BUG: this probably triggeres the H323Plus bug, too
          /// Std 24
		  if (feat.GetFeatureID() == H460_FeatureID(24)) {
			 H460_FeatureStd & std24 = (H460_FeatureStd &)feat;
			 if (std24.Contains(Std24_NATInstruct)) {
			   unsigned natstat = std24.Value(Std24_NATInstruct);
			   natoffloadsupport = (CallRec::NatStrategy)natstat;
			 }
		  }
		}
 
	    // If not already set disable the proxy support function for this call
		// if using Parent you must proxy...
		if (!useParent &&
			(natoffloadsupport == CallRec::e_natLocalMaster || 
			  natoffloadsupport == CallRec::e_natRemoteMaster ||
			  natoffloadsupport == CallRec::e_natNoassist ||
			  natoffloadsupport == CallRec::e_natRemoteProxy)) {
			    PTRACE(4,"RAS\tNAT Proxy disabled due to offload support"); 
				authData.m_proxyMode = CallRec::ProxyDisabled;
	    }
	}
#else
	int natoffloadsupport = 0;
#endif
 
		if (!rejectCall && useParent) {
			gkClient->RewriteE164(*setup, false);
			if (!gkClient->SendARQ(request, true, natoffloadsupport)) { // send answered ARQ
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

		bool proceedingSent = false;
		if (!rejectCall && !destFound) {
			// for compatible to old version
			if (!(useParent || rassrv->AcceptUnregisteredCalls(_peerAddr))) {
				PTRACE(3, Type() << "\tReject unregistered call " << callid
					<< " from " << Name()
					);
				authData.m_rejectCause = Q931::CallRejected;
				rejectCall = true;
			} else {
				PreliminaryCall * tmpCall = new PreliminaryCall(this, setupBody.m_callIdentifier, m_crv);
				PreliminaryCallTable::Instance()->Insert(tmpCall);
				request.Process();
				proceedingSent = tmpCall->IsProceedingSent();
				PreliminaryCallTable::Instance()->Remove(setupBody.m_callIdentifier);
				delete tmpCall;
				// check if destination has changed in the routing process
				// eg. via canMapAlias in LRQ
				if (request.GetFlags() & Routing::SetupRequest::e_aliasesChanged) {
					if (request.GetFlags() & Routing::SetupRequest::e_Reject) {
						PTRACE(3, Type() << "\tRejecting unregistered call "
							<< callid << " from " << Name()
							);
						authData.m_rejectReason = request.GetRejectReason();
						rejectCall = true;
					} else {
						if (request.GetAliases() && request.GetAliases()->GetSize() > 0) {
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
					}
				}
				if (!rejectCall) {
					Route route;
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
		}

		PString destinationString(setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) 
			? AsString(setupBody.m_destinationAddress) : AsDotString(calledAddr)
			);

		// if I'm behind NAT and the call is from parent, always use H.245 routed,
		// also make sure all calls from endpoints with H.460.18 are H.245 routed
		bool h245Routed = rassrv->IsH245Routed() || (useParent && gkClient->IsNATed());
#ifdef HAS_H46018
		if (m_call && m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46018())
			h245Routed = true;
#endif
 
		CallRec* call = new CallRec(q931, setupBody, h245Routed, 
			destinationString, authData.m_proxyMode
			);
		call->SetProceedingSent(proceedingSent);
		call->SetSrcSignalAddr(SocketToH225TransportAddr(_peerAddr, _peerPort));
#ifdef HAS_H46023
		call->SetNATStrategy(natoffloadsupport);
#endif
		call->SetBindHint(request.GetSourceIP());
		call->SetCallerID(request.GetCallerID());

		// if the peer address is a public address, but the advertised source address is a private address
		// then there is a good chance the remote endpoint is behind a NAT.
		PIPSocket::Address srcAddr;
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress)) {
			H323TransportAddress sourceAddress(setupBody.m_sourceCallSignalAddress);
			sourceAddress.GetIpAddress(srcAddr);

			if (_peerAddr != srcAddr) {  // do we have a NAT?
				if (Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "SupportNATedEndpoints", "0"))) {
					PTRACE(4, Type() << "\tSource address " <<  srcAddr
						<< " peer address " << _peerAddr << " caller is behind NAT");
					call->SetSrcNATed(srcAddr);
				} else {
					// if unregistered caller is NATed & no policy then reject.
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
			   // If the party cannot be determined if behind NAT and we have support then just treat as being NAT
			     if (Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "SupportNATedEndpoints", "0")) &&
				    Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "TreatUnregisteredNAT", "0"))) {
					PTRACE(4, Type() << "\tUnregistered party " << _peerAddr << " cannot detect if NATed. Treated as if NATed");
					srcAddr = "192.168.1.1";  // just an arbitrary internal address
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
		if (authData.m_clientAuthId > 0)
			m_call->SetClientAuthId(authData.m_clientAuthId);

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

	if (!rejectCall && strlen(authData.m_disabledcodecs) > 0)
		m_call->SetDisabledCodecs(authData.m_disabledcodecs);

	// perform outbound rewrite
	PIPSocket::Address calleeAddr;
	WORD calleePort = 0;
	m_call->GetDestSignalAddr(calleeAddr, calleePort);
	toolkit->RewriteCLI(*setup, authData, calleeAddr);

	PString out_rewrite_id;
	// Do outbound per GW rewrite
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		if (!m_call->GetNewRoutes().empty() && !m_call->GetNewRoutes().front().m_destOutNumber.IsEmpty()) {
			#if PTRACING
			PTRACE(4, Type() << "\tGWRewrite source for " << Name() << ": auth module");
			#endif
			for (PINDEX i = 0; i < setupBody.m_destinationAddress.GetSize(); ++i)
				if (setupBody.m_destinationAddress[i].GetTag() == H225_AliasAddress::e_dialedDigits) {
					PTRACE(2, Type() << "\tAuth out rewrite: " << ::AsString(setupBody.m_destinationAddress[i]) << " to " << m_call->GetNewRoutes().front().m_destOutNumber);
					H323SetAliasAddress(m_call->GetNewRoutes().front().m_destOutNumber, setupBody.m_destinationAddress[i], setupBody.m_destinationAddress[i].GetTag());
				} else if (setupBody.m_destinationAddress[i].GetTag() == H225_AliasAddress::e_partyNumber) {
					H225_PartyNumber &partyNumber = setupBody.m_destinationAddress[i];
					if (partyNumber.GetTag() == H225_PartyNumber::e_e164Number) {
						H225_PublicPartyNumber &number = partyNumber;
						number.m_publicNumberDigits = m_call->GetNewRoutes().front().m_destOutNumber;
						PTRACE(2, Type() << "\tAuth out rewrite: " << ::AsString(setupBody.m_destinationAddress[i]) << " to " << m_call->GetNewRoutes().front().m_destOutNumber);
					} else if (partyNumber.GetTag() == H225_PartyNumber::e_privateNumber) {
						H225_PrivatePartyNumber &number = partyNumber;
						number.m_privateNumberDigits = m_call->GetNewRoutes().front().m_destOutNumber;
						PTRACE(2, Type() << "\tAuth out rewrite: " << ::AsString(setupBody.m_destinationAddress[i]) << " to " << m_call->GetNewRoutes().front().m_destOutNumber);
					}
				}
		} else {
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
			    toolkit->GWRewriteE164(out_rewrite_id, GW_REWRITE_OUT, setupBody.m_destinationAddress);
			}
		}
	}

	if (q931.HasIE(Q931::CalledPartyNumberIE)) {
		unsigned plan, type;
		PString calledNumber;

		// Do per GW outbound rewrite after global rewrite
		if (q931.GetCalledPartyNumber(calledNumber, &plan, &type)) {
			if (!m_call->GetNewRoutes().empty() && !m_call->GetNewRoutes().front().m_destOutNumber.IsEmpty()) {
				PTRACE(4, Type() << "\tGWRewrite source for " << Name() << ": auth module");
				PTRACE(2, Type() << "\tAuth out rewrite Called-Party-Number IE: " << calledNumber << " to " << m_call->GetNewRoutes().front().m_destOutNumber);
				calledNumber = m_call->GetNewRoutes().front().m_destOutNumber;
				q931.SetCalledPartyNumber(calledNumber, plan, type);
			} else if (toolkit->GWRewritePString(out_rewrite_id, GW_REWRITE_OUT, calledNumber))
				q931.SetCalledPartyNumber(calledNumber, plan, type);
		}
	}
	// set forced CallingPartyNumberIE
	if (!m_call->GetCallerID().IsEmpty()) {
		unsigned plan = Q931::ISDNPlan, type = Q931::InternationalType;
		// unsigned presentation = (unsigned)-1;	// presentation and screening not included, if presentation=-1
		unsigned presentation = H225_PresentationIndicator::e_presentationAllowed;
		unsigned screening = H225_ScreeningIndicator::e_networkProvided;
		q931.SetCallingPartyNumber(m_call->GetCallerID(), plan, type, presentation, screening);
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

	// add destination alias (for Swyx trunk)
	if (m_call->GetCalledParty()) {
		PString addAlias = m_call->GetCalledParty()->GetAdditionalDestinationAlias();
		if (!addAlias.IsEmpty()) {
			if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
				setupBody.m_destinationAddress.SetSize(0);
			}
			bool found = false; // see if already there
			for(PINDEX i = 0; i < setupBody.m_destinationAddress.GetSize(); i++) {
				if (AsString(setupBody.m_destinationAddress[i], false) == addAlias) {
					found = true;
					break;
				}
			}
			if (!found) {
				setupBody.m_destinationAddress.SetSize(setupBody.m_destinationAddress.GetSize()+1);
				H323SetAliasAddress(addAlias,
					setupBody.m_destinationAddress[setupBody.m_destinationAddress.GetSize() - 1]);
			}
		}
	}

#ifdef HAS_H46018
	// proxy if calling or called use H.460.18
	if (m_call->H46019Required() && ((m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46018())
		|| (m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46018()))) {
		m_call->SetProxyMode(CallRec::ProxyEnabled);
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled (H.460.18/.19)");
	}

	// use delayed connecting if called party uses H.460.18
	if (!m_call->H46019Required() || (!(m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46018())))
#endif
	{
#ifdef HAS_H460
		// remove H.460.19 indicator
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
			int numRemoved = -1;
			int sz = setupBody.m_supportedFeatures.GetSize();
			for (PINDEX i = 0; i < sz; i++) {
				if (setupBody.m_supportedFeatures[i].m_id == H460_FeatureID(19)) {
					numRemoved = i;
					break;
				}
			}
			if (numRemoved > -1) {
				for (PINDEX i = numRemoved; i < sz-1; i++) 
					setupBody.m_supportedFeatures[i] = setupBody.m_supportedFeatures[i+1];

				setupBody.m_supportedFeatures.SetSize(sz-1);
				if (setupBody.m_supportedFeatures.GetSize() == 0)
					setupBody.RemoveOptionalField(H225_Setup_UUIE::e_supportedFeatures);
			}
		}
#endif
		CreateRemote(setupBody);
	}
#ifdef HAS_H46018
	else {
		// can't connect the 2 sockets now, remember the calling socket until the called has pinholed throuth the NAT
		localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
		masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
		m_call->SetCallSignalSocketCalling(this);
		SetConnected(true);	// avoid deletion

		// only rewrite sourceCallSignalAddress if we are proxying,
		// otherwise leave the receiving endpoint the option to deal with NATed caller itself
		if (m_call->GetProxyMode() == CallRec::ProxyEnabled
			|| Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AlwaysRewriteSourceCallSignalAddress", "1"))) {
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
			setupBody.m_sourceCallSignalAddress = SocketToH225TransportAddr(masqAddr, GetPort());
		}

		// For compatibility with endpoints which do not support large Setup messages
		if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveH235Call", "0"))) {
			 setupBody.RemoveOptionalField(H225_Setup_UUIE::e_tokens);
			 setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);
		}

		H460_FeatureStd feat = H460_FeatureStd(19);
		// starting with H323Plus 1.21.0 we can create a feature by a numeric ID and this code can get simplified
		H460_FeatureID * feat_id = new H460_FeatureID(2);
		feat.AddParameter(feat_id);	// we are a server
		delete feat_id;
		if (Toolkit::Instance()->IsH46018Enabled())
		{
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
					int numRemoved = -1;
					for (PINDEX i =0; i < setupBody.m_supportedFeatures.GetSize(); i++) {
						if (setupBody.m_supportedFeatures[i].m_id == H460_FeatureID(19)) {
							numRemoved = i;
							break;
						}
					}
					if (numRemoved > 0) {
						for (PINDEX j = numRemoved; j > 0; j--) { 
							setupBody.m_supportedFeatures[j] = setupBody.m_supportedFeatures[j-1];
						}						
					} else if (numRemoved < 0) {
						setupBody.m_supportedFeatures.SetSize(setupBody.m_supportedFeatures.GetSize()+1);
						for (PINDEX j = setupBody.m_supportedFeatures.GetSize()-1; j > 0; j--) {
							setupBody.m_supportedFeatures[j] = setupBody.m_supportedFeatures[j-1];
						}
					}
					setupBody.m_supportedFeatures[0] = feat;  // always set H.460.19 in position 0
			} else {
				// add H.460.19 indicator to Setups
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_supportedFeatures);
				setupBody.m_supportedFeatures.SetSize(0);
				AddH460Feature(setupBody.m_supportedFeatures, feat);
			}
		}
	}
#endif
	msg->SetUUIEChanged();
	
#ifdef HAS_H46018
	// if destination route/endpoint uses H.460.18
	if (m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46018()) {
		// send SCI
		RasServer *RasSrv = RasServer::Instance();
		H225_RasMessage sci_ras;
		sci_ras.SetTag(H225_RasMessage::e_serviceControlIndication);
		H225_ServiceControlIndication & sci = sci_ras;
		sci.m_requestSeqNum = RasSrv->GetRequestSeqNum();
		// Tandberg GK adds open here, the standard doesn't mention this
		H225_ServiceControlSession controlOpen;
		controlOpen.m_sessionId = 0;
		controlOpen.m_reason = H225_ServiceControlSession_reason::e_open;
		sci.m_serviceControl.SetSize(1);
		sci.m_serviceControl[0] = controlOpen;

		H46018_IncomingCallIndication incoming;
		incoming.m_callID = setupBody.m_callIdentifier;

		// send GK's signal addr on the best interface for this endpoint
		if (!m_call->GetDestSignalAddr(peerAddr, peerPort)) {
			PTRACE(3, Type() << "\tINVALID DESTINATION ADDRESS for call from " << Name());
			m_call->SetDisconnectCause(Q931::IncompatibleDestination);
			m_result = Error;
			return;
		}
		incoming.m_callSignallingAddress = RasServer::Instance()->GetCallSignalAddress(peerAddr);

		H460_FeatureStd feat = H460_FeatureStd(18);
		PASN_OctetString rawIndication;
		rawIndication.EncodeSubType(incoming);
		feat.Add(1, H460_FeatureContent(rawIndication));
		sci.IncludeOptionalField(H225_ServiceControlIndication::e_genericData);
		H225_ArrayOf_GenericData & gd = sci.m_genericData;
		gd.SetSize(1);
		gd[0] = feat;
		RasSrv->SendRas(sci_ras, m_call->GetCalledParty()->GetRasAddress());

		// store Setup
		m_call->StoreSetup(msg);
		m_result = DelayedConnecting;	// don't forward now, wait for endpoint to send Facility
	}
#endif
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
	int nat_type = m_call->GetNATType(calling, peerAddr);

	WORD notused;
	if (!m_call->GetBindHint().IsEmpty() && GetTransportAddress(m_call->GetBindHint(), 0, localAddr, notused)) {
		masqAddr = localAddr;
		PTRACE(5, "Using BindHint=" << localAddr);
	} else {
		localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
		masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
	}

	// only rewrite sourceCallSignalAddress if we are proxying,
	// otherwise leave the receiving endpoint the option to deal with NATed caller itself
	if (m_call->GetProxyMode() == CallRec::ProxyEnabled
		|| Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AlwaysRewriteSourceCallSignalAddress", "1"))) {
		setupBody.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
		setupBody.m_sourceCallSignalAddress = SocketToH225TransportAddr(masqAddr, GetPort());
	}

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

#ifdef HAS_H46023
	} else {		
		if (Toolkit::Instance()->IsH46023Enabled() && m_call->GetCalledParty()) {
			// Add NAT offload support to older non supporting Endpoints (>H323v4)
			// This will allow NAT endpoints who support the NAT offload feature
			// to avoid proxying twice (remote and local) 
			bool m_calledh46023 = m_call->GetCalledParty()->UsesH46023();
			
				bool natfound = false;
				PINDEX id = 0;
				H225_ArrayOf_FeatureDescriptor & fsn = setupBody.m_supportedFeatures;
				if (setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
					for (PINDEX i=0; i < fsn.GetSize(); i++) {
						if (fsn[i].m_id == H460_FeatureID(24))  {
							natfound = true;
							id = i;
							break;
						}
					}
				}

				if (m_calledh46023 && !natfound) {
					PTRACE(5, Type() << "Added NAT Support to Outbound Call.");
		            setupBody.IncludeOptionalField(H225_Setup_UUIE::e_supportedFeatures);
					H460_FeatureStd std24 = H460_FeatureStd(24);
					CallRec::NatStrategy strat = m_call->GetNATStrategy();

					if (strat == CallRec::e_natRemoteMaster)     strat = CallRec::e_natLocalMaster;
					else if (strat == CallRec::e_natLocalMaster) strat = CallRec::e_natRemoteMaster;
					else if (strat == CallRec::e_natRemoteProxy) strat = CallRec::e_natLocalProxy;
					else if (strat == CallRec::e_natLocalProxy)  strat = CallRec::e_natRemoteProxy;

					std24.Add(Std24_NATInstruct,H460_FeatureContent((int)strat,8));
					PINDEX lastpos = fsn.GetSize();
					fsn.SetSize(lastpos+1);
					fsn[lastpos] = std24;
				} else if (!m_calledh46023 && natfound) {  // Remove H460.23 from Supported Features.
					for (PINDEX j=id; j < fsn.GetSize()-1; ++j) {
						fsn[j] == fsn[j+1];
					}
					fsn.SetSize(fsn.GetSize()-1);
					if (fsn.GetSize() == 0)
						setupBody.RemoveOptionalField(H225_Setup_UUIE::e_supportedFeatures);
				}
		}
#endif
	}
	
	PTRACE(3, Type() << "\tCall " << m_call->GetCallNumber() << " is NAT type " << nat_type);
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
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_parallelH245Control) && m_h245handler) {
		bool suppress = false;	// ignore for now
		OnTunneledH245(setupBody.m_parallelH245Control, suppress);
	}
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

	if (HandleFastStart(cpBody, false))
		msg->SetUUIEChanged();

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
	
#ifdef HAS_H46018
	if (Toolkit::Instance()->IsH46018Enabled()) {
		// remove H.460.19 indicator from sender TODO: leave other features intact
		if (cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_featureSet)) {
			cpBody.m_featureSet.m_supportedFeatures.SetSize(0);
			cpBody.RemoveOptionalField(H225_CallProceeding_UUIE::e_featureSet);
		}
		if (m_call->GetCallingParty()
			&& m_call->GetCallingParty()->UsesH46018())
		{
			H460_FeatureStd feat = H460_FeatureStd(19);
			H460_FeatureID * feat_id = new H460_FeatureID(2);
			feat.AddParameter(feat_id);	// we are a server
			delete feat_id;
			// add H.460.19 indicator to CallProceeding
			cpBody.IncludeOptionalField(H225_CallProceeding_UUIE::e_featureSet);
			cpBody.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
			cpBody.m_featureSet.m_supportedFeatures.SetSize(0);
			AddH460Feature(cpBody.m_featureSet.m_supportedFeatures, feat);
		}
		msg->SetUUIEChanged();
	}
#endif
	
	if (m_call) {
		if (m_call->IsProceedingSent()) {
			// translate 2nd CallProceeding to Facility or Progress
			PTRACE(2, Type() << "\tTranslate CallProceeding to Facility/Progress");
			Q931 q931;
			H225_H323_UserInformation uuie;
			H225_CallProceeding_UUIE & cp_uuie = msg->GetUUIE()->m_h323_uu_pdu.m_h323_message_body;
			if ((cp_uuie.HasOptionalField(H225_CallProceeding_UUIE::e_fastStart)
				|| cp_uuie.HasOptionalField(H225_CallProceeding_UUIE::e_fastConnectRefused))
				&& (m_h225Version >= 2)) {
				BuildProgressPDU(q931, msg->GetQ931().IsFromDestination());
				GetUUIE(q931, uuie);
				H225_Progress_UUIE & progress_uuie = uuie.m_h323_uu_pdu.m_h323_message_body;
				progress_uuie.m_protocolIdentifier = cp_uuie.m_protocolIdentifier;
				if (msg->GetQ931().HasIE(Q931::DisplayIE))
					q931.SetIE(Q931::DisplayIE, msg->GetQ931().GetIE(Q931::DisplayIE));
				// copy over H.245 elements
				if (cp_uuie.HasOptionalField(H225_CallProceeding_UUIE::e_fastStart)) {
					progress_uuie.IncludeOptionalField(H225_Progress_UUIE::e_fastStart);
					progress_uuie.m_fastStart = cp_uuie.m_fastStart;
				}
				if (cp_uuie.HasOptionalField(H225_CallProceeding_UUIE::e_fastConnectRefused)) {
					progress_uuie.IncludeOptionalField(H225_Progress_UUIE::e_fastConnectRefused);
				}
			} else {
				BuildFacilityPDU(q931, H225_FacilityReason::e_transportedInformation);
				GetUUIE(q931, uuie);
				H225_Facility_UUIE & facility_uuie = uuie.m_h323_uu_pdu.m_h323_message_body;
				facility_uuie.m_protocolIdentifier = cp_uuie.m_protocolIdentifier;
				if (msg->GetQ931().HasIE(Q931::DisplayIE))
					q931.SetIE(Q931::DisplayIE, msg->GetQ931().GetIE(Q931::DisplayIE));
				if (m_h225Version > 0 && m_h225Version < 4)
					uuie.m_h323_uu_pdu.m_h323_message_body.SetTag(H225_H323_UU_PDU_h323_message_body::e_empty);
			}
			uuie.m_h323_uu_pdu.m_h245Tunneling = msg->GetUUIE()->m_h323_uu_pdu.m_h245Tunneling;
			msg->GetQ931() = q931;
			*msg->GetUUIE() = uuie;
			msg->SetUUIEChanged();
		}
		else
			m_call->SetProceedingSent(true);
	}
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

	if (HandleFastStart(connectBody, false))
		msg->SetUUIEChanged();

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
	
#ifdef HAS_H46018
	if (m_call->H46019Required() && Toolkit::Instance()->IsH46018Enabled()) {
		// remove H.460.19 indicator from sender TODO: leave other features intact
		if (connectBody.HasOptionalField(H225_Connect_UUIE::e_featureSet)) {
			connectBody.m_featureSet.m_supportedFeatures.SetSize(0);
			connectBody.RemoveOptionalField(H225_Connect_UUIE::e_featureSet);
		}
		if (m_call->GetCallingParty()
			&& m_call->GetCallingParty()->UsesH46018())
		{
			// add H.460.19 indicator
			H460_FeatureStd feat = H460_FeatureStd(19);
			H460_FeatureID * feat_id = new H460_FeatureID(2);
			feat.AddParameter(feat_id);	// we are a server
			delete feat_id;
			connectBody.IncludeOptionalField(H225_Connect_UUIE::e_featureSet);
			connectBody.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
			connectBody.m_featureSet.m_supportedFeatures.SetSize(0);
			AddH460Feature(connectBody.m_featureSet.m_supportedFeatures, feat);
		}
		msg->SetUUIEChanged();
	}
#endif
}

void CallSignalSocket::OnAlerting(
	SignalingMsg* msg
	)
{
	if (!m_call)
		return;

	m_call->SetAlertingTime(time(NULL));
	
	AlertingMsg *alerting = dynamic_cast<AlertingMsg*>(msg);
	if (alerting == NULL) {
		PTRACE(2, Type() << "\tError: Alerting message from " << Name() << " without associated UUIE");
		m_result = Error;
		return;
	}

	H225_Alerting_UUIE &alertingBody = alerting->GetUUIEBody();
	
	m_h225Version = GetH225Version(alertingBody);

	RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctAlert, m_call);	// ignore success/failiure

	if (HandleFastStart(alertingBody, false))
		msg->SetUUIEChanged();

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

#ifdef HAS_H46018
	if (m_call->H46019Required() && Toolkit::Instance()->IsH46018Enabled()) {
		// remove H.460.19 indicator from sender TODO: leave other features intact
		if (alertingBody.HasOptionalField(H225_Alerting_UUIE::e_featureSet)) {
			alertingBody.m_featureSet.m_supportedFeatures.SetSize(0);
			alertingBody.RemoveOptionalField(H225_Alerting_UUIE::e_featureSet);
		}
		if (m_call->GetCallingParty()
			&& m_call->GetCallingParty()->UsesH46018())
		{
			// add H.460.19 indicator
			H460_FeatureStd feat = H460_FeatureStd(19);
			H460_FeatureID * feat_id = new H460_FeatureID(2);
			feat.AddParameter(feat_id);	// we are a server
			delete feat_id;
			alertingBody.IncludeOptionalField(H225_Alerting_UUIE::e_featureSet);
			alertingBody.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
			alertingBody.m_featureSet.m_supportedFeatures.SetSize(0);
			AddH460Feature(alertingBody.m_featureSet.m_supportedFeatures, feat);
		}
		msg->SetUUIEChanged();
	}
#endif
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

	// We are only interested in the GnuGk NAT message everything else ignore.
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

#if H323_H450
bool CallSignalSocket::OnH450PDU(H225_ArrayOf_PASN_OctetString & supplementary)
{
  bool result = false;

  for (PINDEX i = 0; i < supplementary.GetSize(); i++) {
    H4501_SupplementaryService supplementaryService;

    // Decode the supplementary service PDU from the PPER Stream
    if (supplementary[i].DecodeSubType(supplementaryService)) {
      PTRACE(4, "H450\tReceived supplementary service PDU:\n  "
             << setprecision(2) << supplementaryService);
    }
    else {
      PTRACE(1, "H450\tInvalid supplementary service PDU decode:\n  "
             << setprecision(2) << supplementaryService);
      continue;
    }

    H4501_InterpretationApdu & interpretation = supplementaryService.m_interpretationApdu;

    if (supplementaryService.m_serviceApdu.GetTag() == H4501_ServiceApdus::e_rosApdus) {
      H4501_ArrayOf_ROS& operations = (H4501_ArrayOf_ROS&) supplementaryService.m_serviceApdu;

      for (PINDEX j = 0; j < operations.GetSize(); j ++) {
        X880_ROS& operation = operations[j];
        switch (operation.GetTag()) {
          case X880_ROS::e_invoke:
            result = OnH450Invoke((X880_Invoke &)operation, interpretation);
            break;

          case X880_ROS::e_returnResult:
          case X880_ROS::e_returnError:
          case X880_ROS::e_reject:
          default :
            break;
        }
      }
    }
  }
  return result;
}

bool CallSignalSocket::OnH450Invoke(X880_Invoke & invoke, H4501_InterpretationApdu & interpretation)
{
	bool result = false;

	// Get the invokeId
	// int invokeId = invoke.m_invokeId.GetValue();

	// Get the linkedId if present
	// int linkedId = -1;
	// if (invoke.HasOptionalField(X880_Invoke::e_linkedId)) {
	//		linkedId = invoke.m_linkedId.GetValue();
	// }

	// Get the argument if present
	PASN_OctetString * argument = NULL;
	if (invoke.HasOptionalField(X880_Invoke::e_argument)) {
		argument = &invoke.m_argument;
	}

	// Get the opcode
	if (invoke.m_opcode.GetTag() == X880_Code::e_local) {
		int opcode = ((PASN_Integer&) invoke.m_opcode).GetValue();

		switch (opcode) {
			case H4502_CallTransferOperation::e_callTransferInitiate:
				result = OnH450CallTransfer(argument);
				break;
			default:
				break;
		}
	}

	return result;
}

static PString ParseEndpointAddress(H4501_EndpointAddress& endpointAddress)
{
	H4501_ArrayOf_AliasAddress& destinationAddress = endpointAddress.m_destinationAddress;

	PString alias;
	PString remoteParty = PString::Empty();
	H323TransportAddress transportAddress;

	for (PINDEX i = 0; i < destinationAddress.GetSize(); i++) {
		H225_AliasAddress& aliasAddress = destinationAddress[i];

		if (aliasAddress.GetTag() == H225_AliasAddress::e_transportID) {
			transportAddress = (H225_TransportAddress &)aliasAddress;
			transportAddress.Replace("ip$", "");
			transportAddress.Replace("*", "");
		} else {
			alias = ::H323GetAliasAddressString(aliasAddress);
			alias.Replace("E164:", "");
			alias.Replace("Private:", "");
			alias.Replace("Data:", "");
			alias.Replace("Telex:", "");
			alias.Replace("NSP:", "");
		}
	}
	if (alias.IsEmpty()) {
		remoteParty = transportAddress;
	}
	else if (transportAddress.IsEmpty()) {
		remoteParty = alias;
	}
	else {
		remoteParty = alias + '@' + transportAddress;
	}

	return remoteParty;
}

bool CallSignalSocket::OnH450CallTransfer(PASN_OctetString * argument)
{
	H4502_CTInitiateArg ctInitiateArg;
	PPER_Stream argStream(*argument);
	if (ctInitiateArg.Decode(argStream)) {
		PString remoteParty = ParseEndpointAddress(ctInitiateArg.m_reroutingNumber);
		if (remoteParty.IsEmpty()) {
			PTRACE(1, "H.450.2 Emulator: Empty destination");
			return false;
		}
		// ignored for now
		//H225_CallIdentifier callid;
		//callid.m_guid = H225_GloballyUniqueID(ctInitiateArg.m_callIdentity.GetValue());
		if (!m_call) {
			PTRACE(1, "H.450.2 Emulator: No call to transfer");
			return false;
		}
		if (!(m_call->GetCallSignalSocketCalling() && m_call->GetCallSignalSocketCalled())) {
			PTRACE(1, "H.450.2 Emulator: Must have 2 connected parties on call for transfer");
			return false;
		}
		PCaselessString method = Toolkit::Instance()->Config()->GetString(RoutedSec, "H4502EmulatorTransferMethod", "callForwarded");
		PTRACE(2, "H.450.2 Emulator Transfer call to " << remoteParty << " using method " << method);
		if (method == "Reroute") {
			// fork another thread for the reroute, so this socket doesn't block
			remoteParty.MakeUnique();
			if (this == m_call->GetCallSignalSocketCalling()) {
				CreateJob(this, &CallSignalSocket::RerouteCalled, remoteParty, "Reroute to " + remoteParty);
			} else {
				CreateJob(m_call->GetCallSignalSocketCalling(), &CallSignalSocket::RerouteCaller, remoteParty, "Reroute to " + remoteParty);
			}
		} else {
			PString callid = AsString(m_call->GetCallIdentifier().m_guid);
			callid.Replace(" ", "-", true);
			PCaselessString which = (this == m_call->GetCallSignalSocketCalling()) ? "called" : "calling";
			SoftPBX::TransferCall(callid, which, remoteParty, method);
		}
		return true;
	}
	return false;
}

#endif	// H323_H450

// helper method to start a thread with only one parameter (which would be 2nd)
void CallSignalSocket::RerouteCaller(PString destination)
{
	RerouteCall(Caller, destination, true);
}

void CallSignalSocket::RerouteCalled(PString destination)
{
	RerouteCall(Called, destination, true);
}

// to be called on the remaining socket !!!
bool CallSignalSocket::RerouteCall(CallLeg which, const PString & destination, bool h450transfer)
{
	CallSignalSocket * droppedSocket = NULL;
	CallSignalSocket * remainingSocket = NULL;

	// check if we have access to signalling channel of endpoint to be transferred
	if (which == Called) {
		droppedSocket = m_call->GetCallSignalSocketCalling();
		remainingSocket = m_call->GetCallSignalSocketCalled();
	} else {
		droppedSocket = m_call->GetCallSignalSocketCalled();
		remainingSocket = m_call->GetCallSignalSocketCalling();
	}
	if (this != remainingSocket) {
		PTRACE(1, "Error: RerouteCall() called on wrong socket" << this);
		return false;
	}

	// build Setup
	Q931 q931;
	H225_H323_UserInformation uuie;
	PBYTEArray perBuffer;
	bool tunneling = (which == Called) ? m_call->GetCallSignalSocketCalled()->m_h245Tunneling : m_call->GetCallSignalSocketCalling()->m_h245Tunneling;
	if (which == Caller) {
		// use saved Setup and just change the destination
		q931.Decode(m_rawSetup);
		GetUUIE(q931, uuie);
		H225_Setup_UUIE & setup = uuie.m_h323_uu_pdu.m_h323_message_body;
		uuie.m_h323_uu_pdu.m_h245Tunneling = tunneling;
		// remove old destination
		setup.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		setup.RemoveOptionalField(H225_Setup_UUIE::e_destinationAddress);
		// TODO: unify code to set destination between BuildSetup and here (just here ?)
		// check if destination contain IP to set destCallSigAdr
		PString alias;
		PString destip;
		PINDEX at = destination.Find("@");
		if (at != P_MAX_INDEX) {
			alias = destination.Left(at);
			destip = destination.Mid(at+1);
			if (!IsIPAddress(destip)) {
				// use as URL_ID
				destip = "";
				alias = destination;
			}
		} else {
			if (IsIPAddress(destination)) {
				destip = destination;
			} else {
				alias = destination;
			}
		}
		if (!destip.IsEmpty()) {
			setup.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
			PStringArray adr_parts = destip.Tokenise(":", FALSE);
			PString ip = adr_parts[0];
			WORD port = (WORD)(adr_parts[1].AsInteger());
			if (port == 0)
				port = GK_DEF_ENDPOINT_SIGNAL_PORT;
			setup.m_destCallSignalAddress = SocketToH225TransportAddr(ip, port);
		}
		if (!alias.IsEmpty()) {
			setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setup.m_destinationAddress.SetSize(1);
			H323SetAliasAddress(alias, setup.m_destinationAddress[0]);
			if (setup.m_destinationAddress[0].GetTag() == H225_AliasAddress::e_dialedDigits) {
				q931.SetCalledPartyNumber(alias);
			}
		}
	} else {
		BuildSetupPDU(q931, m_call->GetCallIdentifier(), m_call->GetCallRef(), destination, tunneling);
		GetUUIE(q931, uuie);
		H225_Setup_UUIE & setup_uuie = uuie.m_h323_uu_pdu.m_h323_message_body;
		setup_uuie.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
		setup_uuie.m_sourceAddress.SetSize(1);
		if (which == Called) {
			H323SetAliasAddress(m_call->GetCalledStationId(), setup_uuie.m_sourceAddress[0]);
		} else {
			H323SetAliasAddress(m_call->GetCallingStationId(), setup_uuie.m_sourceAddress[0]);
		}
	}
	SetUUIE(q931, uuie);
	q931.Encode(perBuffer);
	m_rawSetup = perBuffer;
	m_rawSetup.MakeUnique();

	PrintQ931(3, "Setup for Reroute ", GetName(), &q931, &uuie);

	PIPSocket::Address dummyAddr;
	SignalingMsg *msg = SignalingMsg::Create(&q931, &uuie, dummyAddr, 0, dummyAddr, 0);
	SetupMsg* setup = dynamic_cast<SetupMsg*>(msg);
	if (setup == NULL) {
		PTRACE(1, "Can't cast Setup");	// should never happen
		return false;
	}
	H225_Setup_UUIE &setupBody = setup->GetUUIEBody();

	// invoke authentication
	SetupAuthData authData(m_call, m_call ? true : false);
	authData.m_callingStationId = GetCallingStationId(*setup, authData);
	authData.m_calledStationId = GetCalledStationId(*setup, authData);
	if (!RasServer::Instance()->ValidatePDU(*setup, authData)) {
		PTRACE(1, "Q931\tAutentication of reroute destination failed");
		return false;
	}
	// invoke routing policies for destination
	Routing::SetupRequest request(setupBody, setup, authData.m_callingStationId, authData.m_clientAuthId);
	request.Process();
	Route route;
	if (!request.GetFirstRoute(route)) {
		PTRACE(1, "Q931\tCan't find reroute destination");
		return false;
	}
	PTRACE(1, "Q931\tRerouting route: " << route.AsString());

	m_call->SetRerouteState(RerouteInitiated);
	m_call->SetRerouteDirection(which);
	
	PBYTEArray lBuffer;
	if (!m_h245socket || droppedSocket->m_h245socket) {
		// build TCS0 for tunneled H.245 connection
		BuildFacilityPDU(q931, 0);
		GetUUIE(q931, uuie);
		uuie.m_h323_uu_pdu.m_h323_message_body.SetTag(H225_H323_UU_PDU_h323_message_body::e_empty);
		uuie.m_h323_uu_pdu.m_h245Tunneling = tunneling;
		uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Control);
		uuie.m_h323_uu_pdu.m_h245Control.SetSize(1);
		H245_MultimediaSystemControlMessage h245msg;
		h245msg.SetTag(H245_MultimediaSystemControlMessage::e_request);
		H245_RequestMessage & h245req = h245msg;
		h245req.SetTag(H245_RequestMessage::e_terminalCapabilitySet);
		H245_TerminalCapabilitySet & tcs0 = h245req;
		tcs0.m_protocolIdentifier.SetValue(H245_ProtocolID);
		uuie.m_h323_uu_pdu.m_h245Control[0].EncodeSubType(h245msg);
		SetUUIE(q931, uuie);
		q931.Encode(lBuffer);
	}
	// send TCS0 to forwarded party
	if (m_h245socket) {
		m_h245socket->SendTCS(NULL);
	} else {
		PrintQ931(1, "Q931\tSending TCS0 to forwarded ", GetName(), &q931, &uuie);
		TransmitData(lBuffer);
	}

	// send TCS0 to dropping party
	if (droppedSocket->m_h245socket) {
		droppedSocket->m_h245socket->SendTCS(NULL);
	} else {
		PrintQ931(1, "Q931\tSending TCS0 to dropped ", droppedSocket->GetName(), &q931, &uuie);
		droppedSocket->TransmitData(lBuffer);
	}

	PThread::Sleep(1000);	// wait for all CLCs to be exchanged: TODO: better criteria

	// drop party from call
	if (which == Called) {
		m_call->RerouteDropCalling();
	} else {
		m_call->RerouteDropCalled();
	}

	droppedSocket->RemoveRemoteSocket();
	droppedSocket->RemoveH245Handler();
	if (droppedSocket->m_h245socket) {
		droppedSocket->m_h245socket->RemoveRemoteSocket();
	}
	if (droppedSocket->GetHandler()->Detach(this))
		PTRACE(1, "Q931\tSocket " << droppedSocket->GetName() << " detached from its handler");
	else
		PTRACE(1, "Q931\tFailed to detach socket " << droppedSocket->GetName() << " from its handler");
	remote = NULL;
	if (m_h245socket)
		m_h245socket->RemoveRemoteSocket();
	GetHandler()->Remove(droppedSocket);

	// TODO: ReleaseComplete answer from dropped party causes deletion of signalling socket of remaining party
	// because its only 1 call record - solution: 2 call records or check if forwarder set when RC comes in ?
	// TODO: if (h450transfer): include H450 returnResult in RC
	//droppedSocket->SendReleaseComplete(H225_ReleaseCompleteReason::e_undefinedReason);

	// TODO: send CLC for all open channels to remaining party, instead of Sleep() above, but that info is only collected in proxy mode

	if (route.m_destEndpoint)
		m_call->SetCalled(route.m_destEndpoint);
	else
		m_call->SetDestSignalAddr(route.m_destAddr);

	if (route.m_flags & Route::e_toParent)
		m_call->SetToParent(true);

	if(!route.m_destNumber.IsEmpty()) {
		H225_ArrayOf_AliasAddress destAlias;
		destAlias.SetSize(1);
		H323SetAliasAddress(route.m_destNumber, destAlias[0]);
		m_call->SetRouteToAlias(destAlias);
	}

	// send Setup
	buffer = m_rawSetup;
	buffer.MakeUnique();
	// delete msg;	// TODO: crash or leak
	PTRACE(5, GetName() << "\tRerouting call to " << route.AsString());
	CreateJob(this, &CallSignalSocket::DispatchNextRoute, "Reroute");
	
	return true;
}

void CallSignalSocket::OnReleaseComplete(SignalingMsg *msg)
{
	ReleaseCompleteMsg *rc = dynamic_cast<ReleaseCompleteMsg*>(msg);
	if (rc == NULL) {
		PTRACE(2, Type() << "\tWarning: ReleaseComplete message from " << Name() << " without associated UUIE");
	}

	unsigned cause = 0;
	if (m_call) {
		// regular ReleaseComplete processing
		m_call->SetDisconnectTime(time(NULL));
		m_call->SetReleaseSource(m_callerSocket
			? CallRec::ReleasedByCaller : CallRec::ReleasedByCallee
			);
		if (msg->GetQ931().HasIE(Q931::CauseIE)) {
			cause = msg->GetQ931().GetCause();
			// translate cause codes
			unsigned new_cause = cause;
			// global translation first
			new_cause = Toolkit::Instance()->TranslateReceivedCause(new_cause);
			new_cause = Toolkit::Instance()->TranslateSentCause(new_cause);
			endptr calling = m_call->GetCallingParty();
			if (!calling)
				calling = RegistrationTable::Instance()->FindBySignalAdr(m_call->GetSrcSignalAddr());
			if (!calling)
				calling = RegistrationTable::Instance()->FindByAliases(m_call->GetSourceAddress());
			if (!calling) {
				// if all fails, search on default port
				PIPSocket::Address addr;
				WORD port;
				if (m_call->GetSrcSignalAddr(addr, port))
					calling = RegistrationTable::Instance()->FindBySignalAdr(SocketToH225TransportAddr(addr, GK_DEF_ENDPOINT_SIGNAL_PORT));
			}
			endptr called = m_call->GetCalledParty();
			if (!called)
				called = RegistrationTable::Instance()->FindBySignalAdr(m_call->GetDestSignalAddr());
			if (!called)
				called = RegistrationTable::Instance()->FindByAliases(m_call->GetDestinationAddress());
			if (!called) {
				// if all fails, search on default port
				PIPSocket::Address addr;
				WORD port;
				if (m_call->GetDestSignalAddr(addr, port))
					called = RegistrationTable::Instance()->FindBySignalAdr(SocketToH225TransportAddr(addr, GK_DEF_ENDPOINT_SIGNAL_PORT));
			}
			if (msg->GetQ931().IsFromDestination()) {
				if (called)
					new_cause = called->TranslateReceivedCause(new_cause);
				if (calling)
					new_cause = calling->TranslateSentCause(new_cause);
			} else {
				if (calling)
					new_cause = calling->TranslateReceivedCause(new_cause);
				if (called)
					new_cause = called->TranslateSentCause(new_cause);
			}
			if (new_cause != cause) {
				PTRACE(4, "Q931\tTranslated cause code " << cause << " to " << new_cause);
				msg->GetQ931().SetCause(Q931::CauseValues(new_cause));
				msg->SetChanged();
				m_call->SetDisconnectCauseTranslated(new_cause);
			}

			m_call->SetDisconnectCause(cause);
		} else if (rc != NULL) {
			H225_ReleaseComplete_UUIE& rcBody = rc->GetUUIEBody();
			if (rcBody.HasOptionalField(H225_ReleaseComplete_UUIE::e_reason)) {
				cause = Toolkit::Instance()->MapH225ReasonToQ931Cause(rcBody.m_reason.GetTag());
				m_call->SetDisconnectCause(cause);
			}
		}
	}

	if (m_callerSocket) {
		if (remote != NULL) {
			remote->RemoveRemoteSocket();
		}
	}

	if (m_call && remote != NULL && !m_callerSocket
		&& ((m_call->GetReleaseSource() == CallRec::ReleasedByCallee) || (m_call->GetReleaseSource() == CallRec::ReleasedByGatekeeper))
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
	CallRec *newCall = new CallRec(m_call.operator ->());
	CallTable::Instance()->RemoveFailedLeg(m_call);
	
	CallSignalSocket *callingSocket = static_cast<CallSignalSocket*>(remote);
	if (callingSocket != NULL) {
		callingSocket->RemoveRemoteSocket();
		if (callingSocket->m_h245socket) {
			callingSocket->m_h245socket->SetSigSocket(NULL);
			callingSocket->m_h245socket = NULL;
		}
		callingSocket->RemoveH245Handler();
		if (callingSocket->GetHandler()->Detach(callingSocket))
			PTRACE(6, "Q931\tSocket " << callingSocket->GetName() << " detached from its handler");
		else
			PTRACE(1, "Q931\tFailed to detach socket " << callingSocket->GetName() << " from its handler");

		callingSocket->m_call = callptr(newCall);
		callingSocket->buffer = callingSocket->m_rawSetup;
		callingSocket->buffer.MakeUnique();
	}

	if (newCall->GetNewRoutes().empty()) {
		PTRACE(1, "Q931\tERROR: TryNextRoute() without a route");
		return;
	}
	const Route & newRoute = newCall->GetNewRoutes().front();
	PTRACE(1, "Q931\tNew route: " << newRoute.AsString());
	if (newRoute.m_destEndpoint)
		newCall->SetCalled(newRoute.m_destEndpoint);
	else
		newCall->SetDestSignalAddr(newRoute.m_destAddr);

	if (newRoute.m_flags & Route::e_toParent)
		newCall->SetToParent(true);

	if(!newRoute.m_destNumber.IsEmpty()) {
		H225_ArrayOf_AliasAddress destAlias;
		destAlias.SetSize(1);
		H323SetAliasAddress(newRoute.m_destNumber, destAlias[0]);
		newCall->SetRouteToAlias(destAlias);
	}
				
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
				&& facilityBody.m_protocolIdentifier.GetValue().IsEmpty()) {
			if (m_h245socket && m_h245socket->Reverting(facilityBody.m_h245Address))
				m_result = NoData;
		}
		break;
	case H225_FacilityReason::e_routeCallToGatekeeper:
        // include orginal destination as an alternativeAlias if none is provided (fix for VCS)
        if (!facilityBody.HasOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress)) {
              facilityBody.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress);
              facilityBody.m_alternativeAliasAddress.SetSize(1);
              H323SetAliasAddress(m_call->GetDestSignalAddr(),facilityBody.m_alternativeAliasAddress[0]);
        }
        // fall through intended
	case H225_FacilityReason::e_callForwarded:
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

#ifdef HAS_H46018
	case H225_FacilityReason::e_undefinedReason:
		if (Toolkit::Instance()->IsH46018Enabled()
			&& facilityBody.HasOptionalField(H225_Facility_UUIE::e_callIdentifier)) {
			H225_CallIdentifier callIdentifier = facilityBody.m_callIdentifier;
			m_call = CallTable::Instance()->FindCallRec(callIdentifier);
			if (m_call) {
				m_call->SetCallSignalSocketCalled(this);
				PBYTEArray rawSetup = m_call->RetrieveSetup();
				CallSignalSocket * callingSocket = m_call->GetCallSignalSocketCalling();
				if (callingSocket && (rawSetup.GetSize() > 0)) {
					m_callerSocket = false;
					remote = callingSocket;
					remote->GetPeerAddress(peerAddr, peerPort);
					localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
					masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
					callingSocket->remote = this;
					callingSocket->SetConnected(true);
					SetConnected(true);
					GetHandler()->MoveTo(callingSocket->GetHandler(), this);

					if (!m_call->H46019Required()) {  // we are using H.460.23/24
						this->TransmitData(rawSetup);
						m_result = DelayedConnecting;
						return;
					}
					// always proxy H.245 for H.460.18/19
					Address calling = INADDR_ANY, called = INADDR_ANY;
					/*int nat_type = */ m_call->GetNATType(calling, called);
					H245ProxyHandler *proxyhandler = new H245ProxyHandler(m_call->GetCallIdentifier(), callingSocket->localAddr, calling, callingSocket->masqAddr);
					proxyhandler->SetUsesH46019(true);
					proxyhandler->SetH46019Direction(m_call->GetH46019Direction());
					if (m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46018()) 
						proxyhandler->SetUsesH46019(true);
					callingSocket->m_h245handler = proxyhandler;
					m_h245handler = new H245ProxyHandler(m_call->GetCallIdentifier(), localAddr, called, masqAddr, proxyhandler);
					proxyhandler->SetHandler(GetHandler());
					((H245ProxyHandler*)m_h245handler)->SetUsesH46019(true);
					((H245ProxyHandler*)m_h245handler)->SetH46019Direction(m_call->GetH46019Direction());

					H225_H323_UserInformation *uuie = NULL;
					Q931 *q931pdu = new Q931();
					if (!q931pdu->Decode(rawSetup)) {
						PTRACE(1, Type() << "\t" << GetName() << " ERROR DECODING saved Setup!");
						delete q931pdu;
						q931pdu = NULL;
						return;
					}
					if (q931pdu->HasIE(Q931::UserUserIE)) {
						uuie = new H225_H323_UserInformation();
						if (!GetUUIE(*q931pdu, *uuie)) {
						}
					}
					PIPSocket::Address _localAddr, _peerAddr;
					WORD _localPort = 0, _peerPort = 0;
					SetupMsg *setup = (SetupMsg *)SetupMsg::Create(q931pdu, uuie, _localAddr, _localPort, _peerAddr, _peerPort);
					setup->Decode(rawSetup);
					H225_Setup_UUIE & setupBody = setup->GetUUIEBody();

					if (HandleH245Address(setupBody))  
							setup->SetUUIEChanged();

					if (HandleFastStart(setupBody, true))
							setup->SetUUIEChanged();

#if H225_PROTOCOL_VERSION >= 4
				if (setupBody.HasOptionalField(H225_Setup_UUIE::e_parallelH245Control) && m_h245handler) {
					bool suppress = false;	// ignore for now
					if (OnTunneledH245(setupBody.m_parallelH245Control, suppress))
							setup->SetUUIEChanged();
				}
#endif
					// re-encode with changes made here
					if (setup->IsChanged())
							SetUUIE(*q931pdu,*uuie);

					PrintQ931(4, "Send to ", this->GetName(), &setup->GetQ931(), setup->GetUUIE());

					if (q931pdu->Encode(rawSetup))
						this->TransmitData(rawSetup);

					// deleting setup also disposes q931pdu and uuie
					if (setup)
						delete setup;
				}
				m_result = DelayedConnecting;	// don't forward, this was just to open the connection
			} else {
				PTRACE(1, "No matching call found for callid " << facilityBody.m_callIdentifier.m_guid << " will forward");
			}
		}
		break;

	case H225_FacilityReason::e_forwardedElements:
		if (Toolkit::Instance()->IsH46018Enabled()) {
			// remove H.460.19 indicator from sender TODO: leave other features intact
			if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_featureSet)) {
				facilityBody.m_featureSet.m_supportedFeatures.SetSize(0);
				facilityBody.RemoveOptionalField(H225_Facility_UUIE::e_featureSet);
			}
			if (m_call->GetCallingParty()
				&& m_call->GetCallingParty()->UsesH46018())
			{
				// add H.460.19 indicator to Facility with reason forwardedElements
				H460_FeatureStd feat = H460_FeatureStd(19);
				H460_FeatureID * feat_id = new H460_FeatureID(2);
				feat.AddParameter(feat_id);	// we are a server
				delete feat_id;
				facilityBody.IncludeOptionalField(H225_Facility_UUIE::e_featureSet);
				facilityBody.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				facilityBody.m_featureSet.m_supportedFeatures.SetSize(0);
				AddH460Feature(facilityBody.m_featureSet.m_supportedFeatures, feat);
			}
			msg->SetUUIEChanged();
		}
		break;
#endif	// HAS_H46018
	}
	
	if (HandleFastStart(facilityBody, false))
		msg->SetUUIEChanged();

	if (m_result != NoData)
		if (HandleH245Address(facilityBody))
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
	
	if (HandleFastStart(progressBody, false))
		msg->SetUUIEChanged();

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
	
}

bool CallSignalSocket::OnTunneledH245(H225_ArrayOf_PASN_OctetString & h245Control, bool & suppress)
{
	bool changed = false;
	for (PINDEX i = 0; i < h245Control.GetSize(); ++i) {
		PPER_Stream strm = h245Control[i].GetValue();
		if (HandleH245Mesg(strm, suppress)) {
			h245Control[i].SetValue(strm);
			changed = true;
		}
	}
	return changed;
}

bool CallSignalSocket::OnFastStart(H225_ArrayOf_PASN_OctetString & fastStart, bool fromCaller)
{
	bool changed = false;
	for (PINDEX i = 0; i < fastStart.GetSize(); ++i) {
		PPER_Stream strm = fastStart[i].GetValue();
		H245_OpenLogicalChannel olc;
		if (!olc.Decode(strm)) {
			PTRACE(4, "Q931\t" << GetName() << " ERROR DECODING FAST START ELEMENT " << i);
			return false;
		}
		PTRACE(4, "Q931\nfastStart[" << i << "] received: " << setprecision(2) << olc);

		// remove disabled audio codecs
		if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData && olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() != H245_DataType::e_nullData) {
			H245_AudioCapability & ac = olc.m_forwardLogicalChannelParameters.m_dataType;
			if (m_call->GetDisabledCodecs().Find(ac.GetTagName() + ";", 0) != P_MAX_INDEX) {
				PTRACE(4, "Delete Audio Forward Logical Channel " << ac.GetTagName());
				fastStart.RemoveAt(i);
				i--;
				continue;
			}
		}
		if (olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData && olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() != H245_DataType::e_nullData) {
			H245_AudioCapability & ac = olc.m_reverseLogicalChannelParameters.m_dataType;
			if (m_call->GetDisabledCodecs().Find(ac.GetTagName() + ";", 0) != P_MAX_INDEX) {
				PTRACE(4, "Delete Audio Reverse Logical Channel "  << ac.GetTagName());
				fastStart.RemoveAt(i);
				i--;
				continue;
			}
		}

		// remove disabled video codecs
		if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_videoData && olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() != H245_DataType::e_nullData) {
			H245_VideoCapability & vc = olc.m_forwardLogicalChannelParameters.m_dataType;
			if (m_call->GetDisabledCodecs().Find(vc.GetTagName() + ";", 0) != P_MAX_INDEX) {
				PTRACE(4, "Delete Video Forward Logical Channel " << vc.GetTagName());
				fastStart.RemoveAt(i);
				i--;
				continue;
			}
		}
		if (olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_videoData && olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() != H245_DataType::e_nullData) {
			H245_VideoCapability & vc = olc.m_reverseLogicalChannelParameters.m_dataType;
			if (m_call->GetDisabledCodecs().Find(vc.GetTagName() + ";", 0) != P_MAX_INDEX) {
				PTRACE(4, "Delete Video Reverse Logical Channel "  << vc.GetTagName());
				fastStart.RemoveAt(i);
				i--;
				continue;
			}
		}

		bool altered = false;
		if (fromCaller) {
			altered = m_h245handler->HandleFastStartSetup(olc, m_call);
		} else {
#ifdef HAS_H46018
			if (m_call->H46019Required() && PIsDescendant(m_h245handler, H245ProxyHandler) && ((H245ProxyHandler*)m_h245handler)->UsesH46019())
				altered = ((H245ProxyHandler*)m_h245handler)->HandleFastStartResponse(olc, m_call);
			else
#endif
				altered = m_h245handler->HandleFastStartResponse(olc, m_call);
		}
		if (altered) {
			PPER_Stream wtstrm;
			olc.Encode(wtstrm);
			wtstrm.CompleteEncoding();
			fastStart[i].SetValue(wtstrm);
			changed = true;
			PTRACE(5, "Q931\nfastStart[" << i << "] to send " << setprecision(2) << olc);
		}

		// save originating media IP and codec for accounting
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
	if (changed) {
		PTRACE(4, "New FastStart: " << setprecision(2) << fastStart);
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
	// can determine whether this is a message generate by GnuGk
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
		case H225_FacilityReason::e_transportedInformation:
			break;
		case H225_FacilityReason::e_startH245:
			uuie.IncludeOptionalField(H225_Facility_UUIE::e_h245Address);
			if (CallSignalSocket *ret = dynamic_cast<CallSignalSocket *>(remote)) {
				uuie.m_h245Address = m_h245socket->GetH245Address(ret->localAddr);
			} else {
				PTRACE(2, "Warning: " << GetName() << " has no remote party?");
			}
#ifdef HAS_H46018
			// add H.460.19 indicator if this is sent out to an endpoint that uses it
			if (m_call && m_call->GetCalledParty() && m_call->H46019Required() && m_call->GetCalledParty()->UsesH46018()) {
				m_crv = m_call->GetCallRef();	// make sure m_crv is set
				uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
				uuie.RemoveOptionalField(H225_Facility_UUIE::e_conferenceID);
				H460_FeatureStd feat = H460_FeatureStd(19);
				H460_FeatureID * feat_id = new H460_FeatureID(2);
				feat.AddParameter(feat_id);	// we are a server
				delete feat_id;
				uuie.IncludeOptionalField(H225_Facility_UUIE::e_featureSet);
				uuie.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				AddH460Feature(uuie.m_featureSet.m_supportedFeatures, feat);
			}
#endif
			break;

		case H225_FacilityReason::e_callForwarded:
		case H225_FacilityReason::e_routeCallToMC:
			uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
			if (const H225_TransportAddress *addr = dynamic_cast<const H225_TransportAddress *>(parm)) {
				uuie.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAddress);
				uuie.m_alternativeAddress = *addr;
			} else if (const PString *dest = dynamic_cast<const PString *>(parm)) {
				PString destination = *dest;
				PString alias = "";
				PString ip = "";
				WORD destport = GK_DEF_ENDPOINT_SIGNAL_PORT;
				PINDEX at = destination.Find('@');
				if (at != P_MAX_INDEX) {
					alias = destination.Left(at);
					destination = destination.Right(destination.GetLength() - (at + 1));
				}
				if (destination.FindRegEx(PRegularExpression("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$", PRegularExpression::Extended)) != P_MAX_INDEX) {
					ip = destination;
				} else if (destination.FindRegEx(PRegularExpression("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+$", PRegularExpression::Extended)) != P_MAX_INDEX) {
					PINDEX colon = destination.Find(':');
					ip = destination.Left(colon);
					destport = (WORD)destination.Right(destination.GetLength() - (colon + 1)).AsInteger();
				}

				if (!ip.IsEmpty()) {
					H225_TransportAddress destaddr;
					if (GetTransportAddress(ip, destport, destaddr)) {
						uuie.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAddress);
						uuie.m_alternativeAddress = destaddr;
					} else {
						PTRACE(2, "Warning: Invalid transport address (" << ip << ":" << destport << ")");
					}
				} else {
					alias = destination;
				}
				if (!alias.IsEmpty()) {
					uuie.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress);
					uuie.m_alternativeAliasAddress.SetSize(1);
					H323SetAliasAddress(alias, uuie.m_alternativeAliasAddress[0]);
				}
				if (reason == H225_FacilityReason::e_routeCallToMC) {
					uuie.IncludeOptionalField(H225_Facility_UUIE::e_conferenceID);
				}
			}
			break;
	}

	FacilityPDU.BuildFacility(m_crv, m_crv & 0x8000u);
	SetUUIE(FacilityPDU, signal);
}

void CallSignalSocket::BuildProgressPDU(Q931 & ProgressPDU, PBoolean fromDestination)
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_progress);
	H225_Progress_UUIE & uuie = body;
	uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (m_call) {
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	}

	ProgressPDU.BuildProgress(m_crv, fromDestination, Q931::ProgressInbandInformationAvailable);
	SetUUIE(ProgressPDU, signal);
}

void CallSignalSocket::BuildProceedingPDU(Q931 & ProceedingPDU, const H225_CallIdentifier & callId, unsigned crv)
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_callProceeding);
	H225_CallProceeding_UUIE & uuie = body;
	uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	uuie.m_callIdentifier = callId;
	uuie.m_destinationInfo.IncludeOptionalField(H225_EndpointType::e_gatekeeper);
	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "UseProvisionalRespToH245Tunneling", "0"))) {
		signal.m_h323_uu_pdu.RemoveOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
		signal.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_provisionalRespToH245Tunneling);
	} else {
		signal.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
		signal.m_h323_uu_pdu.m_h245Tunneling.SetValue(false);
	}
	ProceedingPDU.BuildCallProceeding(crv);
	SetUUIE(ProceedingPDU, signal);

	PrintQ931(5, "Send to ", GetName(), &ProceedingPDU, &signal);
}

void CallSignalSocket::BuildSetupPDU(Q931 & SetupPDU, const H225_CallIdentifier & callid, unsigned crv, const PString & destination, bool h245tunneling)
{
	SetupPDU.BuildSetup(crv);
	H225_H323_UserInformation signal;
	signal.m_h323_uu_pdu.m_h245Tunneling = h245tunneling;
	signal.m_h323_uu_pdu.m_h323_message_body.SetTag(H225_H323_UU_PDU_h323_message_body::e_setup);
	H225_Setup_UUIE & setup = signal.m_h323_uu_pdu.m_h323_message_body;
	setup.m_protocolIdentifier.SetValue(H225_ProtocolID);
	setup.m_conferenceID = callid.m_guid; // generate new: OpalGloballyUniqueID();
	setup.m_callIdentifier.m_guid = setup.m_conferenceID;
	// TODO: consider m_call->BindHint ?
	masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
	setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
	setup.m_sourceCallSignalAddress = SocketToH225TransportAddr(masqAddr, GetPort());
	// check if destination contain IP to set destCallSigAdr
	PString alias;
	PString destip;
	PINDEX at = destination.Find("@");
	if (at != P_MAX_INDEX) {
		alias = destination.Left(at);
		destip = destination.Mid(at+1);
		if (!IsIPAddress(destip)) {
			// use as URL_ID
			destip = "";
			alias = destination;
		}
	} else {
		if (IsIPAddress(destination)) {
			destip = destination;
		} else {
			alias = destination;
		}
	}
	if (!destip.IsEmpty()) {
		setup.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		PStringArray adr_parts = destip.Tokenise(":", FALSE);
		PString ip = adr_parts[0];
		WORD port = (WORD)(adr_parts[1].AsInteger());
		if (port == 0)
			port = GK_DEF_ENDPOINT_SIGNAL_PORT;
		setup.m_destCallSignalAddress = SocketToH225TransportAddr(ip, port);
	}
	if (!alias.IsEmpty()) {
		setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
		setup.m_destinationAddress.SetSize(1);
		H323SetAliasAddress(alias, setup.m_destinationAddress[0]);
		if (setup.m_destinationAddress[0].GetTag() == H225_AliasAddress::e_dialedDigits) {
			SetupPDU.SetCalledPartyNumber(alias);
		}
	}
	// set bearer capability to unrestricted information transfer + huge transfer rate
	PBYTEArray caps;
	caps.SetSize(4);
	caps[0] = 0x88;
	caps[1] = 0x18;
	caps[2] = 0x86;
	caps[3] = 0xa5;
	SetupPDU.SetIE(Q931::BearerCapabilityIE, caps);
	SetUUIE(SetupPDU, signal);
}

// handle a new message on a new connection
void CallSignalSocket::Dispatch()
{
	ReadLock lock(ConfigReloadMutex);
	
	const PTime channelStart;
	const int setupTimeout = PMAX(GkConfig()->GetInteger(RoutedSec,"SetupTimeout",DEFAULT_SETUP_TIMEOUT),1000);
	int timeout = setupTimeout;

	if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
		Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
			GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "0")) ? 1 : 0, 
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
						GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "0")) ? 1 : 0, 
						SOL_SOCKET
						);
							
				ConfigReloadMutex.EndRead();
				const bool isReadable = remote->IsReadable(2*setupTimeout);
				ConfigReloadMutex.StartRead();
				if (!isReadable) {
					PTRACE(3, "Q931\tTimed out waiting for a response to Setup or SCI message from " << remote->GetName());
					if( m_call )
						m_call->SetDisconnectCause(Q931::TimerExpiry);
					OnError();
				}
				GetHandler()->Insert(this, remote);
				return;
			} else if (m_call && m_call->MoveToNextRoute() && (m_h245socket == NULL || m_call->DisableRetryChecks())) {
				PTRACE(3, "Q931\t" << peerAddr << ':' << peerPort << " DIDN'T ACCEPT THE CALL");
				if (m_call) {
					m_call->SetCallSignalSocketCalled(NULL);
					m_call->SetDisconnectCause(Q931::NoRouteToDestination);
					m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
					m_call->SetDisconnectTime(time(NULL));
				}
				
				RemoveH245Handler();

				if (m_call->GetNewRoutes().empty()) {
					PTRACE(1, "Q931\tERROR: Call retry without a route");
					return;
				}

				CallRec * newCall = new CallRec(m_call.operator ->());
				CallTable::Instance()->RemoveFailedLeg(m_call);
				Route newRoute = m_call->GetNewRoutes().front();
				PTRACE(1, "Q931\tNew route: " << newRoute.AsString());
				m_call = callptr(newCall);

				if (newRoute.m_destEndpoint)
					m_call->SetCalled(newRoute.m_destEndpoint);
				else
					m_call->SetDestSignalAddr(newRoute.m_destAddr);

				if (newRoute.m_flags & Route::e_toParent)
					m_call->SetToParent(true);

				if(!newRoute.m_destNumber.IsEmpty()) {
					H225_ArrayOf_AliasAddress destAlias;
					destAlias.SetSize(1);
					H323SetAliasAddress(newRoute.m_destNumber, destAlias[0]);
					newCall->SetRouteToAlias(destAlias);
				}
				
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

#ifdef HAS_H46018
		case DelayedConnecting:
			GetHandler()->Insert(this);
			return;
#endif

		case Forwarding:
			if (remote && remote->IsConnected()) { // remote is NAT socket
				if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
					remote->Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
						GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "0")) ? 1 : 0, 
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

	buffer = m_rawSetup;
	buffer.MakeUnique();

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
			&& m_h245handler) {
		bool suppress = false;	// ignore for now
		if (OnTunneledH245(msg->GetUUIE()->m_h323_uu_pdu.m_h245Control, suppress))
			msg->SetUUIEChanged();
	}

	if (msg->GetQ931().HasIE(Q931::DisplayIE)) {
		PString newDisplayIE;
		if (!m_call->GetCallerID().IsEmpty()) {
			newDisplayIE = m_call->GetCallerID();
		} else {
			newDisplayIE = GkConfig()->GetString(RoutedSec, "ScreenDisplayIE", "");
		}
		if (!newDisplayIE.IsEmpty()) {
			msg->GetQ931().SetDisplayName(newDisplayIE);
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
	ReadLock lock(ConfigReloadMutex);
	const int setupTimeout = PMAX(GkConfig()->GetInteger(RoutedSec,"SetupTimeout",DEFAULT_SETUP_TIMEOUT),1000);
	
	const PTime channelStart;

	switch (RetrySetup()) {
	case Connecting:
		if (InternalConnectTo()) {
			if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
				remote->Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
					GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "0")) ? 1 : 0, 
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
				
			if (m_call->GetNewRoutes().empty()) {
				PTRACE(1, "Q931\tERROR: Call retry without a route");
				return;
			}
			const Route &newRoute = m_call->GetNewRoutes().front();
			PTRACE(1, "Q931\tNew route: " << newRoute.AsString());
				
			CallRec *newCall = new CallRec(m_call.operator ->());
			CallTable::Instance()->RemoveFailedLeg(m_call);
			m_call = callptr(newCall);

			if (newRoute.m_destEndpoint)
				m_call->SetCalled(newRoute.m_destEndpoint);
			else
				m_call->SetDestSignalAddr(newRoute.m_destAddr);

			if (newRoute.m_flags & Route::e_toParent)
				m_call->SetToParent(true);

			if(!newRoute.m_destNumber.IsEmpty()) {
				H225_ArrayOf_AliasAddress destAlias;
				destAlias.SetSize(1);
				H323SetAliasAddress(newRoute.m_destNumber, destAlias[0]);
				newCall->SetRouteToAlias(destAlias);
			}

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
					GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "0")) ? 1 : 0, 
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
	if (!m_h245handler) // not H.245 routed
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
	bool userevert = m_isnatsocket;
#ifdef HAS_H46018
	if (m_call->H46019Required() && m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46018())
		userevert = true;
#endif
	m_h245socket = userevert ? new NATH245Socket(this) : new H245Socket(this);
	if (!m_call->GetRerouteState() == RerouteInitiated)
		ret->m_h245socket = new H245Socket(m_h245socket, ret);
	m_h245socket->SetH245Address(h245addr, masqAddr);
	// if in reroute, don't listen, actively connect to the other side, half of the H.245 connection is already up
	if (m_call->GetRerouteState() == RerouteInitiated) {
		m_h245socket->SetRemoteSocket(ret->m_h245socket);
		ret->m_h245socket->SetRemoteSocket(m_h245socket);
		CreateJob(m_h245socket, &H245Socket::ConnectToRerouteDestination, "H245RerouteConnector");
	} else {
		CreateJob(m_h245socket, &H245Socket::ConnectTo, "H245Connector");	// start a listener
	}
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
	int dplan;
	PIPSocket::Address calleeAddr;
	WORD calleePort = 0;
	PString Number;
	Toolkit* toolkit = Toolkit::Instance();
	m_call->GetDestSignalAddr(calleeAddr, calleePort);
	H225_TransportAddress callerAddr = SocketToH225TransportAddr(calleeAddr, calleePort);
	endptr called = RegistrationTable::Instance()->FindBySignalAdr(callerAddr);

	if (q931->HasIE(Q931::CalledPartyNumberIE)) {
		if (q931->GetCalledPartyNumber(Number, &plan, &type)) {
			dtype = -1;
			dplan = -1;
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
				dplan = called->GetCallPlanOfNumber(true);
				if (dplan != -1)
					plan = dplan;
			}
			if (dtype == -1) {
				dtype = toolkit->Config()->GetInteger(RoutedSec, "CalledTypeOfNumber", -1);
				if (dtype != -1)
					type = dtype;
			}
			if (dplan == -1) {
				dplan = toolkit->Config()->GetInteger(RoutedSec, "CalledPlanOfNumber", -1);
				if (dplan != -1)
					plan = dplan;
			}
			q931->SetCalledPartyNumber(Number, plan, type);
			#if PTRACING
			PTRACE(4, Type() << "\tSet Called Numbering Plan " << plan << " Type Of Number " << type);
			#endif
		}
	}

	if (q931->HasIE(Q931::CallingPartyNumberIE)) {
		unsigned presentation = (unsigned)-1, screening = (unsigned)-1;
		if (q931->GetCallingPartyNumber(Number, &plan, &type, &presentation, &screening, (unsigned)-1, (unsigned)-1)) {
			dtype = -1;
			dplan = -1;
			if (called) {
				dtype = called->GetCallTypeOfNumber(false);
				if (dtype != -1)
					type = dtype;
				dplan = called->GetCallPlanOfNumber(false);
				if (dplan != -1)
					plan = dplan;
			}
			if (dtype == -1) {
				dtype = toolkit->Config()->GetInteger(RoutedSec, "CallingTypeOfNumber", -1);
				if (dtype != -1)
					type = dtype;
			}
			if (dplan == -1) {
				dplan = toolkit->Config()->GetInteger(RoutedSec, "CallingPlanOfNumber", -1);
				if (dplan != -1)
					plan = dplan;
			}
			q931->SetCallingPartyNumber(Number, plan, type, presentation, screening);
			#if PTRACING
			PTRACE(4, Type() << "\tSet Calling Numbering Plan " << plan << " Type Of Number " << type);
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

bool H245Handler::HandleMesg(H245_MultimediaSystemControlMessage & h245msg, bool & suppress, callptr & mcall)
{
	bool changed = false;

	switch (h245msg.GetTag())
	{
		case H245_MultimediaSystemControlMessage::e_request:
			changed = HandleRequest(h245msg);
			break;
		case H245_MultimediaSystemControlMessage::e_response:
			changed = HandleResponse(h245msg, mcall);
			break;
		case H245_MultimediaSystemControlMessage::e_command:
			changed = HandleCommand(h245msg);
			break;
		case H245_MultimediaSystemControlMessage::e_indication:
			changed = HandleIndication(h245msg, suppress);
			break;
		default:
			PTRACE(2, "H245\tUnknown H245 message: " << h245msg.GetTag());
			break;
	}
	return changed;
}

bool H245Handler::HandleFastStartSetup(H245_OpenLogicalChannel & olc,callptr & mcall)
{
	return hnat ? hnat->HandleOpenLogicalChannel(olc) : false;
}

bool H245Handler::HandleFastStartResponse(H245_OpenLogicalChannel & olc, callptr & mcall)
{
	return hnat ? hnat->HandleOpenLogicalChannel(olc) : false;
}

bool H245Handler::HandleRequest(H245_RequestMessage & Request)
{
	PTRACE(4, "H245\tRequest: " << Request.GetTagName());
	if (hnat && Request.GetTag() == H245_RequestMessage::e_openLogicalChannel) {
		return hnat->HandleOpenLogicalChannel(Request);
	} else if  (Request.GetTag() == H245_RequestMessage::e_terminalCapabilitySet) {
       return true;
	} else if  (Request.GetTag() == H245_RequestMessage::e_requestMode) {
		return true;
	} else {
		return false;
	}
}

bool H245Handler::HandleResponse(H245_ResponseMessage & Response, callptr & mcall)
{
	PTRACE(4, "H245\tResponse: " << Response.GetTagName());
	if (hnat && Response.GetTag() == H245_ResponseMessage::e_openLogicalChannelAck)
		return hnat->HandleOpenLogicalChannelAck(Response);
	else
		return false;
}

bool H245Handler::HandleIndication(H245_IndicationMessage & Indication, bool & suppress)
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

// called when in Reroute, don't listen, but connect directly and re-send TCS
void H245Socket::ConnectToRerouteDestination()
{
			PTRACE(0, "ConnectToRerouteDestination()");
		if (ConnectRemote()) {
			ConfigReloadMutex.StartRead();
			SetConnected(true);
			remote->SetConnected(true);
			GetHandler()->Insert(this, remote);
			ConfigReloadMutex.EndRead();

			// re-send TCS
			H245Socket * remote_h245socket = dynamic_cast<H245Socket*>(remote);
			if (remote_h245socket && remote_h245socket->sigSocket) {
				H245_TerminalCapabilitySet tcs = remote_h245socket->sigSocket->GetSavedTCS();
				SendTCS(&tcs);
			} else {
				PTRACE(1, "Reroute: Can't retrieve TCS to re-send");
			}
			return;
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

	bool suppress = false;
	if (sigSocket && sigSocket->HandleH245Mesg(strm, suppress, (H245Socket *)this))
		buffer = strm;

	if (suppress)
		return NoData;	// eg. H.460.18 genericIndication
	else {
		return Forwarding;
	}
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
	if (!TransmitData(wtstrm)) {
		PTRACE(1, "H245\tSending of endSessionCommand to " << GetName() << " failed");
	}
	PTRACE(4, "H245\tSend endSessionCommand to " << GetName());
}

void H245Socket::SendTCS(H245_TerminalCapabilitySet * tcs)
{
	if (!IsConnected()) {
		return;
	}
	H245_MultimediaSystemControlMessage h245msg;
	h245msg.SetTag(H245_MultimediaSystemControlMessage::e_request);
	H245_RequestMessage & h245req = h245msg;
	h245req.SetTag(H245_RequestMessage::e_terminalCapabilitySet);
	H245_TerminalCapabilitySet & newTCS = h245req;
	// saved capabilities, otherwise empty
	if (tcs) {
		newTCS = *tcs;
		newTCS.m_sequenceNumber = 1;
	} else {
		newTCS.m_sequenceNumber = 2;
		newTCS.m_protocolIdentifier.SetValue(H245_ProtocolID);
	}
	PPER_Stream wtstrm;
	h245msg.Encode(wtstrm);
	wtstrm.CompleteEncoding();
	if (!TransmitData(wtstrm)) {
		PTRACE(1, "H245\tSending of TerminalCapabilitySet to " << GetName() << " failed");
	}
	PTRACE(4, "H245\tSend TerminalCapabilitySet to " << GetName());
}

#ifdef LARGE_FDSET
bool H245Socket::Accept(YaTCPSocket & socket)
#else
PBoolean H245Socket::Accept(PSocket & socket)
#endif
{
	bool result = TCPProxySocket::Accept(socket);
	if (result) {
		Address addr;
		WORD p;
		GetLocalAddress(addr, p);
		PTRACE(3, "H245\tConnected from " << GetName() << " on " << addr << ":" << p);
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
	H225_H323_UserInformation uuie;
	GetUUIE(q931, uuie);
	PrintQ931(5, "Send to ", sigSocket->GetName(), &q931, &uuie);
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
	: ProxySocket(this, t),
		m_call(NULL), fSrcIP(0), fDestIP(0), rSrcIP(0), rDestIP(0),
		fSrcPort(0), fDestPort(0), rSrcPort(0), rDestPort(0), m_sessionID(0)
#ifdef HAS_H46018
	, m_h46019fc(false), m_useH46019(false), m_h46019DetectionDone(false)
#endif
{
	// set flags for RTP/RTCP to avoid string compares later on
	m_isRTPType = PString(t) == "RTP";
	m_isRTCPType = PString(t) == "RTCP";
	SetReadTimeout(PTimeInterval(50));
	SetWriteTimeout(PTimeInterval(50));
	fnat = rnat = mute = false;
	m_dontQueueRTP = Toolkit::AsBool(GkConfig()->GetString(ProxySection, "DisableRTPQueueing", "0"));
	m_EnableRTCPStats = Toolkit::AsBool(GkConfig()->GetString(ProxySection, "EnableRTCPStats", "0"));
}

bool UDPProxySocket::Bind(const Address &localAddr, WORD pt)
{
	if (!Listen(localAddr, 0, pt))
		return false;

	// Set the IP Type Of Service field for prioritisation of media UDP / RTP packets
#ifdef _WIN32
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

void UDPProxySocket::SetForwardDestination(const Address & srcIP, WORD srcPort, const H245_UnicastAddress_iPAddress & addr, callptr & mcall)
{
	if ((DWORD)srcIP != 0) {
		fSrcIP = srcIP, fSrcPort = srcPort;
	}
	addr >> fDestIP >> fDestPort;

	if ((DWORD)srcIP) {
		Address laddr;
		WORD lport = 0;
		GetLocalAddress(laddr, lport);
		SetName(AsString(srcIP, srcPort) + "<=>" + AsString(laddr, lport) + "<=>" + AsString(fDestIP, fDestPort));
	} else {
		SetName("(To be autodetected)");
	}
	PTRACE(5, Type() << "\tForward " << AsString(srcIP, srcPort) 
		<< " to " << fDestIP << ':' << fDestPort
		);

	SetConnected(true);

	if (m_isRTCPType) {
	    mcall->SetSRC_media_control_IP(fDestIP.AsString());
	    mcall->SetDST_media_control_IP(srcIP.AsString());
	}
	if (m_isRTPType) {
	    mcall->SetSRC_media_IP(fDestIP.AsString());
	    mcall->SetDST_media_IP(srcIP.AsString());
	}

#if defined(HAS_H46018) && defined(HAS_H46024B)
	// If required begin Annex B probing
	if (mcall->GetNATStrategy() == CallRec::e_natAnnexB) {
		mcall->H46024BSessionFlag(m_sessionID);
	}
#endif
	
	m_call = &mcall;		
}

void UDPProxySocket::SetReverseDestination(const Address & srcIP, WORD srcPort, const H245_UnicastAddress_iPAddress & addr, callptr & mcall)
{
	if ( (DWORD)srcIP != 0 )
		rSrcIP = srcIP, rSrcPort = srcPort;

	addr >> rDestIP >> rDestPort;

	PTRACE(5, Type() << "\tReverse " << srcIP << ':' << srcPort << " to " << rDestIP << ':' << rDestPort);
	SetConnected(true);
	if (m_isRTCPType) {
	    mcall->SetSRC_media_control_IP(srcIP.AsString());
	    mcall->SetDST_media_control_IP(rDestIP.AsString());
	}
	if (m_isRTPType) {
	    mcall->SetSRC_media_IP(srcIP.AsString());
	    mcall->SetDST_media_IP(rDestIP.AsString());
	}
	m_call = &mcall;
}

// this method handles either RTP, RTCP or T.38 data
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
	unsigned int version = 0;	// RTP version
	if (buflen >= 1)
		version = (((int)wbuffer[0] & 0xc0) >> 6);
	bool isRTCP = m_isRTCPType && (version == 2);
#if (HAS_H46018 || HAS_H46023)
	bool isRTP = m_isRTPType && (version == 2);
#endif
#ifdef HAS_H46018
	bool isRTPKeepAlive = isRTP && (buflen == 12);

#ifdef RTP_DEBUG
	int payloadType = H46019_UNDEFINED_PAYLOAD_TYPE;
	if ((buflen >= 2) && isRTP)
		payloadType = (int)wbuffer[1] & 0x7f;
	Address localaddr;
	WORD localport = 0;
	GetLocalAddress(localaddr, localport);
	unsigned int seq = 0;
	unsigned int timestamp = 0;
	if (buflen >= 4)
		seq = (((int)wbuffer[2] << 8) & 0x7f) + ((int)wbuffer[3] & 0x7f);
	if (buflen >= 8)
		timestamp = ((int)wbuffer[4] * 16777216) + ((int)wbuffer[5] * 65536) + ((int)wbuffer[6] * 256) + (int)wbuffer[7];
	PTRACE(0, "JW RTP IN on " << localport << " from " << fromIP << ":" << fromPort << " pType=" << payloadType
		<< " seq=" << seq << " timestamp=" << timestamp << " len=" << buflen
		<< " fSrc=" << fSrcIP << ":" << fSrcPort << " fDest=" << fDestIP <<":" << fDestPort
		<< " rSrc=" << rSrcIP << ":" << rSrcPort << " rDest=" << rDestIP <<":" << rDestPort
		);
	PTRACE(0, "JW RTP DB on " << localport << " type=" << Type() << " this=" << this << " H.460.19=" << UsesH46019() << " fc=" << m_h46019fc << " isRTP=" << m_isRTPType << " isRTCP=" << m_isRTCPType);
#endif // RTP_DEBUG

	// detecting ports for H.460.19
	if (!m_h46019DetectionDone) {
		if (!UsesH46019()) {
			m_h46019DetectionDone = true;	// skip port detection if H.460.19 isn't used
		}
		if ((isRTCP || isRTPKeepAlive) && UsesH46019()) {
			PWaitAndSignal mutexWait (m_h46019DetectionLock);
			PTRACE(5, "H46018\tRTP/RTCP keepAlive from " << fromIP << ":" << fromPort);
			if ((fDestIP == 0) && (fromIP != rDestIP) && (fromPort != rDestPort)) {
				// fwd dest was unset and packet didn't come from other side
				PTRACE(5, "H46018\tSetting forward destination to " << fromIP << ":" << fromPort << " based on " << Type() << " keepAlive");
				fDestIP = fromIP; fDestPort = fromPort;
				rSrcIP = fromIP; rSrcPort = fromPort;
			}
			if ((rDestIP == 0) && (fromIP != fDestIP) && (fromPort != fDestPort)) {
				// reverse dest was unset and packet didn't come from other side
				PTRACE(5, "H46018\tSetting reverse destination to " << fromIP << ":" << fromPort << " based on " << Type() << " keepAlive");
				rDestIP = fromIP; rDestPort = fromPort;
				fSrcIP = fromIP; fSrcPort = fromPort;
			}
			if ((fDestIP != 0) && (rDestIP != 0)) {
				m_h46019DetectionDone = true;
				// note: we don't do port switching at this time, once the ports are set they stay
#ifdef HAS_H46024B
				// If required begin Annex B probing
				if (isRTPKeepAlive && m_call && (*m_call)->GetNATStrategy() == CallRec::e_natAnnexB) {
					(*m_call)->H46024BInitiate(m_sessionID, H323TransportAddress(fDestIP, fDestPort), H323TransportAddress(rDestIP, rDestPort));
				}
#endif	// HAS_H46024B
			}
#ifdef RTP_DEBUG
			PTRACE(0, "JW RTP IN2 on " << localport << " from " << fromIP << ":" << fromPort
				<< " fSrc=" << fSrcIP << ":" << fSrcPort << " fDest=" << fDestIP <<":" << fDestPort
				<< " rSrc=" << rSrcIP << ":" << rSrcPort << " rDest=" << rDestIP <<":" << rDestPort
			);
#endif // RTP_DEBUG
		}
	}
	if (isRTPKeepAlive) {
		return NoData;	// don't forward RTP keepAlive (RTCP uses first data packet which must be forwarded)
	}
#endif	// HAS_H46018

	// fSrcIP = forward-Source-IP, fDest-IP = forward destination IP, rDestIP = reverse destination IP (reverse = fastStart ?)
	/* autodetect channel source IP:PORT that was not specified by OLCs */
	if (rSrcIP == 0 && fromIP == fDestIP) {
		rSrcIP = fromIP, rSrcPort = fromPort;
	}
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
#ifdef HAS_H46024B
            if (isRTP && m_call && (*m_call)->GetNATStrategy() == CallRec::e_natAnnexB) {
#ifdef HAS_H46018
                m_h46019DetectionDone = true;  // We missed the probe packets but detection is done
#endif
			    (*m_call)->H46024BInitiate(m_sessionID, H323TransportAddress(fDestIP, fDestPort), H323TransportAddress(fromIP, fromPort));
            }
#endif
			SetSendAddress(fDestIP, fDestPort);
		} else {
			PTRACE(6, Type() << "\tForward from " << fromIP << ':' << fromPort 
				<< " blocked, remote socket (" << fDestIP << ':' << fDestPort
				<< ") not yet known or ready"
				);
			if (m_dontQueueRTP)
				return NoData;
		}
		if (rnat) {
			rDestIP = fromIP, rDestPort = fromPort;
		}
	} else {
		if (rDestPort) {
			PTRACE(6, Type() << "\tForward " << fromIP << ':' << fromPort << 
				" to " << rDestIP << ':' << rDestPort
				);
			SetSendAddress(rDestIP, rDestPort);
		} else {
			PTRACE(6, Type() << "\tForward from " << fromIP << ':' << fromPort 
				<< " blocked, remote socket (" << rDestIP << ':' << rDestPort
				<< ") not yet known or ready"
				);
			if (m_dontQueueRTP)
				return NoData;
		}
		if (fnat) {
			fDestIP = fromIP, fDestPort = fromPort;
		}
	}
	if (isRTCP && m_call && (*m_call) && m_EnableRTCPStats) {
		bool direct = ((*m_call)->GetSRC_media_control_IP() == fromIP.AsString());
		PIPSocket::Address addr = (DWORD)0;
		(*m_call)->GetMediaOriginatingIp(addr);
		if (buflen < 4) {
			PTRACE(1, "RTCP\tInvalid RTCP frame");
			return NoData;
		}

		RTP_ControlFrame frame(2048);
		frame.Attach(wbuffer, buflen);
		do {
			BYTE * payload = frame.GetPayloadPtr();
			unsigned size = frame.GetPayloadSize();	// TODO: check size against buflen ?
			if ((payload == NULL) || (size == 0)
				|| (frame.GetVersion() != 2)
				|| ((payload + size) > (frame.GetPointer() + frame.GetSize()))) {
				// TODO: test for a maximum size ? what is the max size ?
				PTRACE(1, "RTCP\tInvalid RTCP frame");
				return NoData;
			}
			switch (frame.GetPayloadType()) {
			case RTP_ControlFrame::e_SenderReport :
				PTRACE(5, "RTCP\tSenderReport packet");
				if (size >= (sizeof(RTP_ControlFrame::SenderReport) + frame.GetCount() * sizeof(RTP_ControlFrame::ReceiverReport))) {
					const RTP_ControlFrame::SenderReport & sr = *(const RTP_ControlFrame::SenderReport *)(payload);
					if (direct) {
						if (m_sessionID == RTP_Session::DefaultAudioSessionID) {
							(*m_call)->SetRTCP_DST_packet_count(sr.psent);
							PTRACE(5, "RTCP\tSetRTCP_DST_packet_count:" << sr.psent);
						}
						if (m_sessionID == RTP_Session::DefaultVideoSessionID) {
							(*m_call)->SetRTCP_DST_video_packet_count(sr.psent);
							PTRACE(5, "RTCP\tSetRTCP_DST_video_packet_count:" << sr.psent);
						}
					} else {
						if (m_sessionID == RTP_Session::DefaultAudioSessionID) {
							(*m_call)->SetRTCP_SRC_packet_count(sr.psent);
							PTRACE(5, "RTCP\tSetRTCP_SRC_packet_count:" << sr.psent);
						}
						if (m_sessionID == RTP_Session::DefaultVideoSessionID) {
							(*m_call)->SetRTCP_SRC_video_packet_count(sr.psent);
							PTRACE(5, "RTCP\tSetRTCP_SRC_video_packet_count:" << sr.psent);
						}
					}
					BuildReceiverReport(frame, sizeof(RTP_ControlFrame::SenderReport), direct);
				} else {
					PTRACE(5, "RTCP\tSenderReport packet truncated");
				}
				break;
			case RTP_ControlFrame::e_ReceiverReport:
				PTRACE(5, "RTCP\tReceiverReport packet");
				if (size >= (frame.GetCount()*sizeof(RTP_ControlFrame::ReceiverReport))) {
					BuildReceiverReport(frame, sizeof(PUInt32b), direct);
				} else {
					PTRACE(5, "RTCP\tReceiverReport packet truncated");
				}
				break;
			case RTP_ControlFrame::e_SourceDescription :
				PTRACE(5, "RTCP\tSourceDescription packet");		    
				if ((!(*m_call)->GetRTCP_SRC_sdes_flag() && direct) || (!(*m_call)->GetRTCP_DST_sdes_flag() && !direct))
					if (size >= (frame.GetCount()*sizeof(RTP_ControlFrame::SourceDescription))) {
						const RTP_ControlFrame::SourceDescription * sdes = (const RTP_ControlFrame::SourceDescription *)payload;
						for (PINDEX srcIdx = 0; srcIdx < (PINDEX)frame.GetCount(); srcIdx++) {
							const RTP_ControlFrame::SourceDescription::Item * item = sdes->item;
							while ((item != NULL)
									&& (((BYTE*)item + sizeof(RTP_ControlFrame::SourceDescription::Item)) <= (payload + size))
									&& (item->type != RTP_ControlFrame::e_END)) {
								if (item->length != 0) {
									switch (item->type) {
									case RTP_ControlFrame::e_CNAME:
										(*m_call)->SetRTCP_sdes(direct, "cname="+((PString)(item->data)).Left(item->length));
										break;
									case RTP_ControlFrame::e_NAME:
										(*m_call)->SetRTCP_sdes(direct, "name="+((PString)(item->data)).Left(item->length));
										break;
									case RTP_ControlFrame::e_EMAIL:
										(*m_call)->SetRTCP_sdes(direct, "email="+((PString)(item->data)).Left(item->length));
										break;
									case RTP_ControlFrame::e_PHONE:
										(*m_call)->SetRTCP_sdes(direct, "phone="+((PString)(item->data)).Left(item->length));
										break;
									case RTP_ControlFrame::e_LOC:
										(*m_call)->SetRTCP_sdes(direct, "loc="+((PString)(item->data)).Left(item->length));
										break;
									case RTP_ControlFrame::e_TOOL:
										(*m_call)->SetRTCP_sdes(direct, "tool="+((PString)(item->data)).Left(item->length));
										break;
									case RTP_ControlFrame::e_NOTE:
										(*m_call)->SetRTCP_sdes(direct, "note="+((PString)(item->data)).Left(item->length));
										break;
									default:
										PTRACE(5,"RTCP\tSourceDescription unknown item type " << item->type);
										break;
									}
								}
								item = item->GetNextItem();
							}
							/* RTP_ControlFrame::e_END doesn't have a length field, so do NOT call item->GetNextItem()
							otherwise it reads over the buffer */
							if((item == NULL)
								|| (item->type == RTP_ControlFrame::e_END)
								|| ((sdes = (const RTP_ControlFrame::SourceDescription *)item->GetNextItem()) == NULL)){
								break;
						}
					}
				}
				break;
			case RTP_ControlFrame::e_Goodbye:
				PTRACE(5, "RTCP\tGoodbye packet");
				break;
			case RTP_ControlFrame::e_ApplDefined:
				PTRACE(5, "RTCP\tApplDefined packet");
				break;
			default:
				PTRACE(5, "RTCP\tUnknown control payload type: " << frame.GetPayloadType());
				break;
			}
		} while (frame.ReadNextCompound());
	}
	return Forwarding;
}

void UDPProxySocket::BuildReceiverReport(const RTP_ControlFrame & frame, PINDEX offset, bool dst)
{
	const RTP_ControlFrame::ReceiverReport * rr = (const RTP_ControlFrame::ReceiverReport *)(frame.GetPayloadPtr()+offset);
	for (PINDEX repIdx = 0; repIdx < (PINDEX)frame.GetCount(); repIdx++) {
		if (dst) {
			if (m_sessionID == RTP_Session::DefaultAudioSessionID) {
				(*m_call)->SetRTCP_DST_packet_lost(rr->GetLostPackets());
				(*m_call)->SetRTCP_DST_jitter(rr->jitter / 8);
				PTRACE(5, "RTCP\tSetRTCP_DST_packet_lost:" << rr->GetLostPackets());
				PTRACE(5, "RTCP\tSetRTCP_DST_jitter:" << (rr->jitter / 8));
			}
			if (m_sessionID == RTP_Session::DefaultVideoSessionID) {
				(*m_call)->SetRTCP_DST_video_packet_lost(rr->GetLostPackets());
				(*m_call)->SetRTCP_DST_video_jitter(rr->jitter / 90);
				PTRACE(5, "RTCP\tSetRTCP_DST_video_packet_lost:" << rr->GetLostPackets());
				PTRACE(5, "RTCP\tSetRTCP_DST_video_jitter:" << (rr->jitter / 90));
			}
		} else {
			if (m_sessionID == RTP_Session::DefaultAudioSessionID) {
				(*m_call)->SetRTCP_SRC_packet_lost(rr->GetLostPackets());
				(*m_call)->SetRTCP_SRC_jitter(rr->jitter / 8);
				PTRACE(5, "RTCP\tSetRTCP_SRC_packet_lost:" << rr->GetLostPackets());
				PTRACE(5, "RTCP\tSetRTCP_SRC_jitter:" << (rr->jitter / 8));
			}
			if (m_sessionID == RTP_Session::DefaultVideoSessionID) {
				(*m_call)->SetRTCP_SRC_video_packet_lost(rr->GetLostPackets());
				(*m_call)->SetRTCP_SRC_video_jitter(rr->jitter / 90);
				PTRACE(5, "RTCP\tSetRTCP_SRC_video_packet_lost:" << rr->GetLostPackets());
				PTRACE(5, "RTCP\tSetRTCP_SRC_video_jitter:" << (rr->jitter / 90));
			}
		}
		rr++;
	}
}

bool UDPProxySocket::WriteData(const BYTE *buffer, int len)
{
	if (!IsSocketOpen())
		return false;

	if (isMute())
		return true;

	// TODO: since we have to send data in 2 directions (fDestIP + rDestIP),
	// we should have 2 queues to avoid loopback
	const int queueSize = GetQueueSize();
	if (queueSize > 0) {
		if (queueSize < 50) {
			QueuePacket(buffer, len);
			PTRACE(3, Type() << '\t' << Name() << " socket is busy, " << len << " bytes queued");
			return false;
		} else {
			ClearQueue();
			PTRACE(3, Type() << '\t' << Name() << " socket queue overflow, dropping queued packets");
		}
	}
	
	// check if the remote address to send data to has been already determined
	PIPSocket::Address addr;
	WORD wport = 0;
	GetSendAddress(addr, wport);
	if (wport == 0) {
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
	WORD fport = 0;
	GetSendAddress(addr, fport);
	if (fport == 0) {
		PTRACE(3, Type() << '\t' << Name() << " socket has no destination address yet, flush ignored");
		return false;
	}

	// TODO: since we have to send data in 2 directions (fDestIP + rDestIP),
	// we should have 2 queues to avoid loopback
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
RTPLogicalChannel::RTPLogicalChannel(H225_CallIdentifier id,WORD flcn, bool nated) : LogicalChannel(flcn), reversed(false), peer(0)
{
	SrcIP = 0;
	SrcPort = 0;
	rtp = NULL;
	rtcp = NULL;

#ifdef HAS_H46023
	// If we do not have a GKClient (no parent) and we 
	// don't create the socket pair by STUN then
	// create the socket pair here
	GkClient *gkClient = RasServer::Instance()->GetGkClient();
	if (!nated || !gkClient->H46023_CreateSocketPair(id,rtp,rtcp,nated)) 
#endif
	{
			rtp = new UDPProxySocket("RTP");
			rtcp = new UDPProxySocket("RTCP");
	}
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
	port = flc->port;
	used = flc->used;
	rtp = flc->rtp;
	rtcp = flc->rtcp;
	SrcIP = flc->SrcIP;
	SrcPort = flc->SrcPort;
	reversed = !flc->reversed;
	peer = flc, flc->peer = this;
	SetChannelNumber(flcn);
	SetNAT(nated);
}

RTPLogicalChannel::~RTPLogicalChannel()
{
	if (peer) {
		peer->peer = NULL;
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

#ifdef HAS_H46018
void RTPLogicalChannel::SetUsesH46019fc(bool fc)
{
	if (rtp)
		rtp->SetUsesH46019fc(fc);
	if (rtcp)
		rtcp->SetUsesH46019fc(fc);	
}

void RTPLogicalChannel::SetH46019Direction(int dir)
{
	if (rtp)
		rtp->SetUsesH46019(dir > H46019_NONE);
	if (rtcp)
		rtcp->SetUsesH46019(dir > H46019_NONE);	
}
#endif

void RTPLogicalChannel::SetRTPSessionID(WORD id)
{
	if (rtp)
		rtp->SetRTPSessionID(id);
	if (rtcp)
		rtcp->SetRTPSessionID(id);	
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

void RTPLogicalChannel::HandleMediaChannel(H245_UnicastAddress_iPAddress *mediaControlChannel, H245_UnicastAddress_iPAddress *mediaChannel, const PIPSocket::Address & local, bool rev, callptr & mcall)
{
	// mediaControlChannel should be non-zero.
	H245_UnicastAddress_iPAddress tmp, tmpmedia, tmpmediacontrol, *dest = mediaControlChannel;
	PIPSocket::Address tmpSrcIP = SrcIP;
	WORD tmpSrcPort = SrcPort + 1;

	if (mediaControlChannel == NULL) {
		if (mediaChannel == NULL) {
			return;
		} else {
			tmpmediacontrol = *mediaChannel;
			tmpmediacontrol.m_tsapIdentifier = tmpmediacontrol.m_tsapIdentifier + 1;
			mediaControlChannel = &tmpmediacontrol;
			dest = mediaControlChannel;
		}
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
	(rtcp->*SetDest)(tmpSrcIP, tmpSrcPort, *dest, mcall);
	*mediaControlChannel << local << (port + 1);

	if (mediaChannel) {
		if (rev) {
			tmp.m_tsapIdentifier = tmp.m_tsapIdentifier - 1;
		} else {
			dest = mediaChannel;
		}
		(rtp->*SetDest)(tmpSrcIP, tmpSrcPort - 1, *dest, mcall);
		*mediaChannel << local << port;
	}
}

void RTPLogicalChannel::SetRTPMute(bool toMute)
{
	if (rtp)
		rtp->SetMute(toMute);
}

bool RTPLogicalChannel::OnLogicalChannelParameters(H245_H2250LogicalChannelParameters & h225Params, const PIPSocket::Address & local, bool rev, callptr & mcall)
{
	if (!h225Params.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel))
		return false;
	H245_UnicastAddress_iPAddress *mediaControlChannel = GetH245UnicastAddress(h225Params.m_mediaControlChannel);
	H245_UnicastAddress_iPAddress *mediaChannel = h225Params.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel) ? GetH245UnicastAddress(h225Params.m_mediaChannel) : 0;
	HandleMediaChannel(mediaControlChannel, mediaChannel, local, rev,mcall);
	return true;
}

bool RTPLogicalChannel::SetDestination(H245_OpenLogicalChannelAck & olca, H245Handler *handler, callptr & mcall)
{
	H245_UnicastAddress_iPAddress *mediaControlChannel, *mediaChannel;
	GetChannelsFromOLCA(olca, mediaControlChannel, mediaChannel);
	if (mediaControlChannel == NULL && mediaChannel == NULL) {
		return false;
	}
	HandleMediaChannel(mediaControlChannel, mediaChannel, handler->GetMasqAddr(), false,mcall);
	return true;
}

void RTPLogicalChannel::StartReading(ProxyHandler * /*handler*/)
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
	if (nated) {
		rtp->SetNAT(reversed);
		rtcp->SetNAT(reversed);
	}
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

bool T120LogicalChannel::SetDestination(H245_OpenLogicalChannelAck & olca, H245Handler * _handler, callptr & mcall)
{
	return (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_separateStack)) ?
		OnSeparateStack(olca.m_separateStack, _handler) : false;
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
		if (remote->Connect(INADDR_ANY, pt, peerAddr)) {
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

bool T120LogicalChannel::OnSeparateStack(H245_NetworkAccessParameters & sepStack, H245Handler * _handler)
{
	bool changed = false;
	if (sepStack.m_networkAddress.GetTag() == H245_NetworkAccessParameters_networkAddress::e_localAreaAddress) {
		H245_UnicastAddress_iPAddress *addr = GetH245UnicastAddress(sepStack.m_networkAddress);
		if (addr) {
			*addr >> peerAddr >> peerPort;
			*addr << _handler->GetMasqAddr() << port;
			changed = true;
		}
	}
	return changed;
}


// class H245ProxyHandler
H245ProxyHandler::H245ProxyHandler(const H225_CallIdentifier & id, const PIPSocket::Address & local, const PIPSocket::Address & remote, const PIPSocket::Address & masq, H245ProxyHandler *pr)
      : H245Handler(local, remote, masq), peer(pr),callid(id), isMute(false), m_useH46019(false), m_useH46019fc(false), m_H46019fcState(0), m_H46019dir(0)
{
	if (peer)
		peer->peer = this;
}

H245ProxyHandler::~H245ProxyHandler()
{
	if (peer) {
		if (peer->UsesH46019fc())
			return;
		peer->peer = 0;
	}
	if (UsesH46019fc())
		return;

	DeleteObjectsInMap(logicalChannels);
	DeleteObjectsInMap(fastStartLCs);
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

bool H245ProxyHandler::HandleResponse(H245_ResponseMessage & Response, callptr & mcall)
{
	PTRACE(4, "H245\tResponse: " << Response.GetTagName());
	if (peer)
		switch (Response.GetTag())
		{
			case H245_ResponseMessage::e_openLogicalChannelAck:
				return HandleOpenLogicalChannelAck(Response, mcall);
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

#ifdef HAS_H46018
	lc->SetH46019Direction(m_H46019dir);
#endif
	lc->SetRTPSessionID((WORD)h225Params->m_sessionID);

	H245_UnicastAddress_iPAddress *addr;
	bool changed = false;

	if( h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel)
		&& (addr = GetH245UnicastAddress(h225Params->m_mediaControlChannel)) ) {

		lc->SetMediaControlChannelSource(*addr);
		*addr << GetMasqAddr() << (lc->GetPort() + 1);
#ifdef HAS_H46018
		if (UsesH46019()) {
			PTRACE(5, "H46018\tSetting control port to 0");
			lc->SetMediaControlChannelSource(0);
		}
#endif
		changed = true;
	}
	if( h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)
		&& (addr = GetH245UnicastAddress(h225Params->m_mediaChannel))) {

		if (addr->m_tsapIdentifier != 0) {
			lc->SetMediaChannelSource(*addr);
			*addr << GetMasqAddr() << lc->GetPort();
#ifdef HAS_H46018
			if (UsesH46019()) {
				PTRACE(5, "H46018\tSetting media port to 0");
				lc->SetMediaChannelSource(0);
			}
#endif
		} else {
			*addr << GetMasqAddr() << (WORD)0;
		}
		changed = true;
	}

	return changed;
}

bool H245ProxyHandler::HandleOpenLogicalChannel(H245_OpenLogicalChannel & olc)
{
	bool changed = false;
	if (hnat && !UsesH46019())
		changed = hnat->HandleOpenLogicalChannel(olc);

	if (UsesH46019fc()) {
		switch (GetH46019fcState()) {
			case 1:							// Initiating
				SetH46019fcState(2);
				break;
			case 2:							// Waiting for reply (switching)
				SetUsesH46019fc(false);
				break;
			default:
				break;
		}
	}

	WORD flcn = (WORD)olc.m_forwardLogicalChannelNumber;
	if (IsT120Channel(olc)) {
		T120LogicalChannel *lc = CreateT120LogicalChannel(flcn);
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_separateStack)
			&& lc && lc->OnSeparateStack(olc.m_separateStack, this)) {
			lc->StartReading(handler);
			return changed;
		}
		return false;
	} else {
		bool isReverseLC = false;
		H245_H2250LogicalChannelParameters * h225Params = GetLogicalChannelParameters(olc, isReverseLC);

	    if (UsesH46019fc()) {
			changed |= (h225Params) ? OnLogicalChannelParameters(h225Params, 0) : false;
		} else {
			changed |= (h225Params) ? OnLogicalChannelParameters(h225Params, flcn) : false;
		}

#ifdef HAS_H46018
		// add traversal parameters if using H.460.19
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_genericInformation)) {
			// remove traversal parameters from sender before forwarding
			for(PINDEX i = 0; i < olc.m_genericInformation.GetSize(); i++) {
				PASN_ObjectId & gid = olc.m_genericInformation[i].m_messageIdentifier;
				if (gid == H46019OID) {
					// Get the keepalive payload (if present)
					H46019_TraversalParameters params;
					PASN_OctetString & raw = olc.m_genericInformation[i].m_messageContent[0].m_parameterValue;
					if (raw.DecodeSubType(params)) {
						if (params.HasOptionalField(H46019_TraversalParameters::e_keepAlivePayloadType)) {
							unsigned payloadtype = params.m_keepAlivePayloadType;
							PTRACE(5, "H46018\tReceived KeepAlive PayloadType=" << payloadtype);
						}
					}
					// move remaining elements down
					for(PINDEX j = i+1; j < olc.m_genericInformation.GetSize(); j++) {
						olc.m_genericInformation[j-1] = olc.m_genericInformation[j];
					}
					olc.m_genericInformation.SetSize(olc.m_genericInformation.GetSize()-1);	
				}
			}
			if (olc.m_genericInformation.GetSize() == 0)
				olc.RemoveOptionalField(H245_OpenLogicalChannel::e_genericInformation);
		}

		// We don't put the generic identifier on the reverse OLC.
		if (UsesH46019fc() && isReverseLC)
			return true;

		if (peer && peer->UsesH46019()) {
			// We need to move any generic Information messages up 1 so H.460.19 will ALWAYS be in position 0.
			if (olc.HasOptionalField(H245_OpenLogicalChannel::e_genericInformation)) {
				olc.m_genericInformation.SetSize(olc.m_genericInformation.GetSize()+1);	
				for(PINDEX j = 0; j < olc.m_genericInformation.GetSize()-1; j++) {
					olc.m_genericInformation[j+1] = olc.m_genericInformation[j];
				}
			} else {
				olc.IncludeOptionalField(H245_OpenLogicalChannel::e_genericInformation);
				olc.m_genericInformation.SetSize(1);
			}
			H245_CapabilityIdentifier & id = olc.m_genericInformation[0].m_messageIdentifier;
            id.SetTag(H245_CapabilityIdentifier::e_standard);
            PASN_ObjectId & gid = id;
            gid.SetValue(H46019OID);
			olc.m_genericInformation[0].IncludeOptionalField(H245_GenericMessage::e_messageContent);
			olc.m_genericInformation[0].m_messageContent.SetSize(1);
			H245_GenericParameter genericParameter;
			H245_ParameterIdentifier & ident = genericParameter.m_parameterIdentifier;
			ident.SetTag(H245_ParameterIdentifier::e_standard);
			PASN_Integer & n = ident;
			n = 1;
			H46019_TraversalParameters params;
			params.IncludeOptionalField(H46019_TraversalParameters::e_keepAliveChannel);
			LogicalChannel * lc;
			if (UsesH46019fc()) {
				WORD sessionID = (WORD)h225Params->m_sessionID;
				lc = fastStartLCs[sessionID];
			} else { 
				lc = FindLogicalChannel(flcn);
			}
			if (lc) {
				params.m_keepAliveChannel = IPToH245TransportAddr(GetMasqAddr(), lc->GetPort()); // use RTP port for keepAlives
				((RTPLogicalChannel*)lc)->SetUsesH46019fc(UsesH46019fc());
				((RTPLogicalChannel*)lc)->SetH46019Direction(GetH46019Direction());
				((RTPLogicalChannel*)lc)->SetRTPSessionID((WORD)h225Params->m_sessionID);
			} else {
				PTRACE(1, "Can't find RTP port for logical channel " << flcn);
			}
			params.IncludeOptionalField(H46019_TraversalParameters::e_keepAliveInterval);
			params.m_keepAliveInterval = 19;
			H245_ParameterValue & octetValue = genericParameter.m_parameterValue;
			octetValue.SetTag(H245_ParameterValue::e_octetString);
			PASN_OctetString & raw = octetValue;
			raw.EncodeSubType(params);
			olc.m_genericInformation[0].m_messageContent[0] = genericParameter;
			changed = true;
		}
#endif
		return changed;
	}
}

bool H245ProxyHandler::HandleOpenLogicalChannelReject(H245_OpenLogicalChannelReject & olcr)
{
	peer->RemoveLogicalChannel((WORD)olcr.m_forwardLogicalChannelNumber);
	return false; // nothing changed :)
}

bool H245ProxyHandler::HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck & olca, callptr & mcall)
{
	if (hnat)
		hnat->HandleOpenLogicalChannelAck(olca);
	WORD flcn = (WORD)olca.m_forwardLogicalChannelNumber;
	LogicalChannel *lc = peer->FindLogicalChannel(flcn);
	if (!lc) {
		PTRACE(2, "Proxy\tWarning: logical channel " << flcn << " not found for opening");
		return false;
	}

#ifdef HAS_H46018
	// parse traversal parameters for PayloadType used by client
	if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_genericInformation)) {
		for (PINDEX i = 0; i < olca.m_genericInformation.GetSize(); i++) {
			if (olca.m_genericInformation[i].m_messageContent.GetSize() > 0) {
				PASN_ObjectId & gid = olca.m_genericInformation[i].m_messageIdentifier;
				H245_ParameterIdentifier & ident = olca.m_genericInformation[i].m_messageContent[0].m_parameterIdentifier;
				PASN_Integer & n = ident;
				if (gid == H46019OID && n == 1) {
					H46019_TraversalParameters params;
					PASN_OctetString & raw = olca.m_genericInformation[i].m_messageContent[0].m_parameterValue;
					if (raw.DecodeSubType(params)) {
						if (params.HasOptionalField(H46019_TraversalParameters::e_keepAlivePayloadType)) {
							PTRACE(5, "H46018\tExpecting KeepAlive PayloadType=" << params.m_keepAlivePayloadType << " for channel " << flcn);
						}
					}
				}
			}
		}
		// remove traversal parameters before forwarding OLCA
		if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_genericInformation)) {
			for(PINDEX i = 0; i < olca.m_genericInformation.GetSize(); i++) {
				PASN_ObjectId & gid = olca.m_genericInformation[i].m_messageIdentifier;
				if (gid == H46019OID) {
					// move remaining elements down
					for(PINDEX j = i+1; j < olca.m_genericInformation.GetSize(); j++) {
						olca.m_genericInformation[j-1] = olca.m_genericInformation[j];
					}
					olca.m_genericInformation.SetSize(olca.m_genericInformation.GetSize()-1);
				}
			}
			if (olca.m_genericInformation.GetSize() == 0)
				olca.RemoveOptionalField(H245_OpenLogicalChannelAck::e_genericInformation);
		}
	}
#endif

	bool result = lc->SetDestination(olca, this, mcall);
	if (result)
		lc->StartReading(handler);
	return result;
}

bool H245ProxyHandler::HandleIndication(H245_IndicationMessage & Indication, bool & suppress)
{
	PString value = PString::Empty();

#ifdef HAS_H46018
	// filter out genericIndications for H.460.18
	if (Indication.GetTag() == H245_IndicationMessage::e_genericIndication) {
		H245_GenericMessage generic = Indication;
		PASN_ObjectId & gid = generic.m_messageIdentifier;
		if (gid == H46018OID) {
			suppress = true;
			return false;
		}
	}
#endif

	/// userInput handling
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
}

bool H245ProxyHandler::HandleCloseLogicalChannel(H245_CloseLogicalChannel & clc)
{
	H245ProxyHandler *first, *second;
	if (clc.m_source.GetTag() == H245_CloseLogicalChannel_source::e_user)
		first = this, second = peer;
	else
		first = peer, second = this;
	bool found = first && first->RemoveLogicalChannel((WORD)clc.m_forwardLogicalChannelNumber);
	if (!found && Toolkit::AsBool(GkConfig()->GetString(ProxySection, "SearchBothSidesOnCLC", "0"))) {
		// due to bad implementation of some endpoints, we check the
		// forwardLogicalChannelNumber on both sides
		if (second)
			second->RemoveLogicalChannel((WORD)clc.m_forwardLogicalChannelNumber);
	}
	return false; // nothing changed
}

bool H245ProxyHandler::HandleFastStartSetup(H245_OpenLogicalChannel & olc,callptr & mcall)
{
	if (!peer)
		return false;

	bool changed = false;
	if (hnat && !UsesH46019()) {
		changed |= hnat->HandleOpenLogicalChannel(olc);
	}

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

	if (UsesH46019()) {
		SetUsesH46019fc(true);
		SetH46019fcState(1);
	}

	if (UsesH46019() && mcall->GetCalledParty() && mcall->GetCalledParty()->UsesH46018())
		return (HandleOpenLogicalChannel(olc) || changed);
	else {
		bool nouse;
		H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse);
		return ((h225Params) ? OnLogicalChannelParameters(h225Params, 0) : false) || changed;
	}
}

bool H245ProxyHandler::HandleFastStartResponse(H245_OpenLogicalChannel & olc,callptr & mcall)
{
	if (!peer)
		return false;

	if (UsesH46019()) {
		SetUsesH46019fc(true);
		SetH46019fcState(3);
    }

	bool changed = false, isReverseLC;
	if (hnat && !peer->UsesH46019()) 
		changed = hnat->HandleOpenLogicalChannel(olc);

	if (peer->UsesH46019() && mcall->GetCallingParty()->UsesH46018())
		changed |= HandleOpenLogicalChannel(olc);

	WORD flcn = (WORD)olc.m_forwardLogicalChannelNumber;
	H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, isReverseLC);
	if (!h225Params)
		return changed;
	WORD id = (WORD)h225Params->m_sessionID;
	RTPLogicalChannel *lc = NULL;
	siterator iter;
	if (UsesH46019()) {
	   iter = fastStartLCs.find(id);
	   lc = (iter != fastStartLCs.end()) ? iter->second : 0;
	} else {
	   iter = peer->fastStartLCs.find(id);
	   lc = (iter != peer->fastStartLCs.end()) ? iter->second : 0;
	}
	if (isReverseLC) {
		if (lc) {
			if (!FindLogicalChannel(flcn)) {
				logicalChannels[flcn] = sessionIDs[id] = lc;
				lc->SetChannelNumber(flcn);
				lc->OnHandlerSwapped(hnat != 0);
				if (!UsesH46019())
					peer->fastStartLCs.erase(iter);
			}
		} else if ((lc = peer->FindRTPLogicalChannelBySessionID(id))) {
			LogicalChannel *akalc = FindLogicalChannel(flcn);
			if (akalc) {
				lc = static_cast<RTPLogicalChannel *>(akalc);
			} else {
				logicalChannels[flcn] = sessionIDs[id] = lc = new RTPLogicalChannel(lc, flcn, hnat != 0);
				if (!lc->IsOpen()) {
					PTRACE(1, "Proxy\tError: Can't create RTP logical channel " << flcn);
				}
			}
		}
	} else {
		if (lc) {
			if (!peer->FindLogicalChannel(flcn)) {
				peer->logicalChannels[flcn] = peer->sessionIDs[id] = lc;
				lc->SetChannelNumber(flcn);
				if (!UsesH46019())
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
	if (lc && (changed = lc->OnLogicalChannelParameters(*h225Params, GetMasqAddr(), isReverseLC, mcall)))
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
		if (!(iter->second)) {
			PTRACE(1, "Proxy\tError: Can't create RTP logical channel " << flcn << ": Invalid fastStart LC");
			return NULL;
		}
		(lc = iter->second)->SetChannelNumber(flcn);
		fastStartLCs.erase(iter);
	} else if (!peer->fastStartLCs.empty()){
		siterator iter = peer->fastStartLCs.begin();
		if (!(iter->second)) {
			PTRACE(1, "Proxy\tError: Can't create RTP logical channel " << flcn << ": Invalid fastStart peer LC");
			return NULL;
		}
		(lc = iter->second)->SetChannelNumber(flcn);
		lc->OnHandlerSwapped(hnat != 0);
		peer->fastStartLCs.erase(iter);
	} else {
		lc = new RTPLogicalChannel(callid, flcn, hnat != 0);
		if (!lc->IsOpen()) {
			PTRACE(1, "Proxy\tError: Can't create RTP logical channel " << flcn);
			delete lc;
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
		lc = new RTPLogicalChannel(callid, 0, hnat != 0);
		if (!lc->IsOpen()) {
			PTRACE(1, "Proxy\tError: Can't create fast start logical channel id " << id);
			delete lc;
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
		PTRACE(3, "Proxy\tLogical channel " << flcn << " not found for removing");
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
			if (socket->IsDeletable()) {
				Remove(k);
			}
		}
	}
	return slist.GetSize() > 0;
}

// handle a new message on an existing connection
void ProxyHandler::ReadSocket(IPSocket *socket)
{
	ProxySocket *psocket = dynamic_cast<ProxySocket *>(socket);
	if (psocket == NULL) {
		PTRACE(1, "Error\tInvalid socket");
		return;
	}
	switch (psocket->ReceiveData())
	{
		case ProxySocket::Connecting:
			PTRACE(1, "Error\tcheck the code " << psocket->Type());
			break;
		case ProxySocket::DelayedConnecting:
			// do nothing - H.460.18 Facility
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
		case ProxySocket::NoData:
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
		while (!m_removed.empty() && (now - **m_removedTime.begin()) >= m_socketCleanupTimeout) {
			IPSocket * s = *m_removed.begin();
			PTime * t = *m_removedTime.begin();
			m_removed.erase(m_removed.begin());
			m_removedTime.erase(m_removedTime.begin());
			delete s;
			delete t;
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
	} else {
		PTRACE(1, GetName() << "\tTrying to add an already existing socket to the handler");
	}
	iter = find(m_sockets.begin(), m_sockets.end(), second);
	if (iter == m_sockets.end()) {
		m_sockets.push_back(second);
		++m_socksize;
	} else {
		PTRACE(1, GetName() << "\tTrying to add an already existing socket to the handler");
	}
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
		ProxySocket * s = dynamic_cast<ProxySocket *>(*i);
		if (s == NULL) {
			PTRACE(1, "Proxy\tCast of proxy socket failed");
			continue;
		}
		if (s->CanFlush()) {
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
