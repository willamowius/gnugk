//////////////////////////////////////////////////////////////////
//
// ProxyChannel.h
//
// Copyright (c) Citron Network Inc. 2001-2002
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chin-Wei Huang <cwhuang@linux.org.tw>
// initial version: 12/7/2001
//
//////////////////////////////////////////////////////////////////

#ifndef __proxychannel_h__
#define __proxychannel_h__

#include "RasTbl.h"
#include "ProxyThread.h"

#ifdef P_SOLARIS
#define map stl_map
#endif

#include <map>

extern const char *RoutedSec;

class Q931;
class H245_UnicastAddress_iPAddress;

class H245Handler;
class CallSignalSocket;
class H245Socket;
class UDPProxySocket;
class T120ProxySocket;
class LogicalChannel;
class RTPLogicalChannel;
class TCPLogicalChannel;
class H245ProxyHandler;


// abstract class of a proxy thread
class H245Handler {
// This class handles H.245 messages which can either be transmitted on their
// own TCP connection or can be tunneled in the Q.931 connection
public:
	H245Handler(PIPSocket::Address l) : localAddr(l) {}
	virtual ~H245Handler() {}

	virtual bool HandleMesg(PPER_Stream &);
	PIPSocket::Address GetLocalAddr() const { return localAddr; }
	void SetLocalAddr(PIPSocket::Address local) { localAddr = local; }

protected:
	virtual bool HandleRequest(H245_RequestMessage &);
	virtual bool HandleResponse(H245_ResponseMessage &);
	virtual bool HandleCommand(H245_CommandMessage &);
	virtual bool HandleIndication(H245_IndicationMessage &);

private:
	PIPSocket::Address localAddr;
};

class CallSignalSocket : public TCPProxySocket {
public:
	PCLASSINFO ( CallSignalSocket, TCPProxySocket )

	CallSignalSocket();
	CallSignalSocket(CallSignalSocket *, WORD);
	~CallSignalSocket();

	// override from class ProxySocket
        virtual Result ReceiveData();
	virtual bool EndSession();

	// override from class TCPProxySocket
	virtual TCPProxySocket *ConnectTo();

	bool HandleH245Mesg(PPER_Stream &);
	void OnH245ChannelClosed() { m_h245socket = 0; }

protected:
	// localAddr is NOT the local address the socket bind to,
	// but the local address that remote socket bind to
	// they may be different in multi-homed environment
	Address localAddr, peerAddr;
	WORD peerPort;

private:
	void OnSetup(H225_Setup_UUIE &);
	void OnCallProceeding(H225_CallProceeding_UUIE &);
	void OnConnect(H225_Connect_UUIE &);
	void OnAlerting(H225_Alerting_UUIE &);
	void OnInformation(H225_Information_UUIE &);
	void OnReleaseComplete(H225_ReleaseComplete_UUIE &);
	void OnFacility(H225_Facility_UUIE &);
	void OnProgress(H225_Progress_UUIE &);
	void OnEmpty(H225_H323_UU_PDU_h323_message_body &);
	void OnStatus(H225_Status_UUIE &);
	void OnStatusInquiry(H225_StatusInquiry_UUIE &);
	void OnSetupAcknowledge(H225_SetupAcknowledge_UUIE &);
	void OnNotify(H225_Notify_UUIE &);
	void OnNonStandardData(PASN_OctetString &);
	void OnTunneledH245(H225_ArrayOf_PASN_OctetString &);
	void OnFastStart(H225_ArrayOf_PASN_OctetString &);

	void BuildReleasePDU(Q931 &) const;
	template<class UUIE> void SetH245Address(UUIE & uu)
	{
		if (m_h245handler && uu.HasOptionalField(UUIE::e_h245Address))
			if (!InternalSetH245Address(uu.m_h245Address))
				uu.RemoveOptionalField(UUIE::e_h245Address);
	}
	bool InternalSetH245Address(H225_TransportAddress &);
	
	callptr m_call;
	WORD m_crv;
	H245Handler *m_h245handler;
	H245Socket *m_h245socket;
};

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

	T120ProxySocket(TCPLogicalChannel *);
	T120ProxySocket(TCPLogicalChannel *, T120ProxySocket *);
	virtual ~T120ProxySocket();

	void SetDestination(H245_UnicastAddress_iPAddress &);
	WORD GetListenPort() const { return listener->GetPort(); }

	// override from class ProxySocket
	virtual bool ForwardData() { return WriteData(remote); }
	virtual bool TransmitData() { return WriteData(this); }
	virtual bool EndSession();

	// override from class TCPProxySocket
	virtual TCPProxySocket *ConnectTo();

private:
	TCPLogicalChannel *tcplc;
	PTCPSocket *listener;
	Address peerAddr;
	WORD peerPort;
};

class H245_OpenLogicalChannelAck;

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

class H245_H2250LogicalChannelAckParameters;

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

class TCPLogicalChannel : public LogicalChannel {
public:
	TCPLogicalChannel(WORD);
	virtual ~TCPLogicalChannel();

	// override from class LogicalChannel
	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *);
	virtual void StartReading(ProxyHandleThread *);

	bool OnSeparateStack(H245_NetworkAccessParameters &, H245Handler *);
	void RemoveSocket(T120ProxySocket *socket);

private:
	T120ProxySocket *caller, *callee;
};

class H245ProxyHandler : public H245Handler {
public:
	typedef std::map<WORD, LogicalChannel *>::iterator iterator;
	typedef std::map<WORD, LogicalChannel *>::const_iterator const_iterator;

	H245ProxyHandler(CallSignalSocket *, PIPSocket::Address, H245ProxyHandler * = 0);
	virtual ~H245ProxyHandler();

	LogicalChannel *FindLogicalChannel(WORD);
	
private:
	// override from class H245Handler
	virtual bool HandleRequest(H245_RequestMessage &);
	virtual bool HandleResponse(H245_ResponseMessage &);

	bool HandleOpenLogicalChannel(H245_OpenLogicalChannel &);
	bool HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck &);
	bool HandleOpenLogicalChannelReject(H245_OpenLogicalChannelReject &);
	bool HandleCloseLogicalChannel(H245_CloseLogicalChannel &);

	RTPLogicalChannel *CreateRTPLogicalChannel(WORD);
	void RemoveLogicalChannel(WORD flcn);

	ProxyHandleThread *handler;
	std::map<WORD, LogicalChannel *> logicalChannels;
	H245ProxyHandler *peer;
};

inline bool CallSignalSocket::HandleH245Mesg(PPER_Stream & strm)
{
	return m_h245handler->HandleMesg(strm);
}

inline bool UDPProxySocket::Bind(Address ip, WORD pt)
{
	localAddr = ip, localPort = pt;
	return Listen(0, pt);
}

#endif // __proxychannel_h__

