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


extern const char *RoutedSec;

class Q931;
class H245_UnicastAddress_iPAddress;

class H245Handler;
class CallSignalSocket;
class H245Socket;
class UDPProxySocket;
class RTPLogicalChannel;
class H245ProxyHandler;


// abstract class of a proxy thread
class H245Handler {
// This class handles H.245 messages which can either be transmitted on their
// own TCP connection or can be tunneled in the Q.931 connection
public:
	H245Handler(PIPSocket::Address l) : localAddr(l) {}
	virtual ~H245Handler() {}

	virtual bool HandleMesg(PPER_Stream &, ProxySocket::Result &);
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
	CallSignalSocket(WORD, CallSignalSocket *);
	~CallSignalSocket();

	// override from class ProxySocket
        virtual Result ReceiveData();
	virtual bool EndSession();

	// override from class TCPProxySocket
	virtual TCPProxySocket *ConnectTo();

	bool HandleH245Mesg(PPER_Stream &, Result &);
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
	void OnSignalingChannelClosed();
	
private:
	CallSignalSocket *sigSocket;
	H225_TransportAddress peerH245Addr;
	PTCPSocket *listener;
};

class UDPProxySocket : public PUDPSocket, public ProxySocket {
public:
	PCLASSINFO( UDPProxySocket, PUDPSocket )

	UDPProxySocket(RTPLogicalChannel *);
	virtual ~UDPProxySocket();

	void SetDestination(H245_UnicastAddress_iPAddress &);

	// override from class ProxySocket
	virtual Result ReceiveData();
	virtual bool ForwardData();
	virtual bool TransmitData();
	virtual bool EndSession();

	bool Bind(Address ip, WORD pt);

private:
	RTPLogicalChannel *rtplc;
	Address localAddr;
	WORD localPort;
};

class H245_H2250LogicalChannelAckParameters;

class RTPLogicalChannel {
public:
	RTPLogicalChannel(PIPSocket::Address, WORD);
	~RTPLogicalChannel();

	bool IsUsed() const { return used; }
	bool Compare(WORD lcn) const { return channelNumber == lcn; }
	bool SetDestination(H245_H2250LogicalChannelAckParameters &);
	void StartReading(ProxyHandleThread *);
	void RemoveSocket(UDPProxySocket *socket);

	WORD GetPort() const { return port; }

	class NoPortAvailable {};

private:
	static WORD GetPortNumber();
	static WORD portNumber;
	static PMutex mutex;

	UDPProxySocket *rtp, *rtcp;
	WORD channelNumber;
	WORD port;
	bool used;
};

class H245ProxyHandler : public H245Handler {
public:
	typedef std::list<RTPLogicalChannel *>::iterator iterator;
	typedef std::list<RTPLogicalChannel *>::const_iterator const_iterator;

	H245ProxyHandler(CallSignalSocket *, PIPSocket::Address, H245ProxyHandler * = 0);
	virtual ~H245ProxyHandler();

	void RemoveSocket(ProxySocket *);
	RTPLogicalChannel *FindRTPLogicalChannel(WORD);
	
private:
	virtual bool HandleRequest(H245_RequestMessage &);
	virtual bool HandleResponse(H245_ResponseMessage &);

	bool HandleOpenLogicalChannel(H245_OpenLogicalChannel &);
	bool HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck &);
	bool HandleOpenLogicalChannelConfirm(H245_OpenLogicalChannelConfirm &);
	bool HandleOpenLogicalChannelReject(H245_OpenLogicalChannelReject &);
	bool HandleCloseLogicalChannel(H245_CloseLogicalChannel &);

	RTPLogicalChannel *CreateRTPLogicalChannel(WORD);
	void RemoveRTPLogicalChannel(WORD flcn);
	iterator InternalFindLC(WORD flcn);

	ProxyHandleThread *handler;
	std::list<RTPLogicalChannel *> logicalChannels;
	H245ProxyHandler *peer;

	static void delete_lc(RTPLogicalChannel *lc) { delete lc; }
};

inline bool CallSignalSocket::HandleH245Mesg(PPER_Stream & strm, Result & res)
{
	return m_h245handler->HandleMesg(strm, res);
}

inline void H245Socket::OnSignalingChannelClosed()
{
	sigSocket = 0;
	EndSession();
}

inline bool UDPProxySocket::Bind(Address ip, WORD pt)
{
	localAddr = ip, localPort = pt;
	return Listen(0, pt);
}

inline H245ProxyHandler::iterator H245ProxyHandler::InternalFindLC(WORD flcn)
{
	return find_if(logicalChannels.begin(), logicalChannels.end(),
			bind2nd(mem_fun(&RTPLogicalChannel::Compare), flcn));
}

#endif // __proxychannel_h__

