//////////////////////////////////////////////////////////////////
//
// ProxyChannel.h
//
// Copyright (c) Citron Network Inc. 2001-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chin-Wei Huang <cwhuang@linux.org.tw>
// initial version: 12/07/2001
//
//////////////////////////////////////////////////////////////////

#ifndef PROXYCHANNEL_H
#define PROXYCHANNEL_H "@(#) $Id$"

#include <vector>
#include <list>
#include "yasocket.h"
#include "RasTbl.h"


class Q931;
class PASN_OctetString;
class H225_CallTerminationCause;
class H225_H323_UserInformation;
class H225_H323_UU_PDU_h323_message_body;
class H225_Setup_UUIE;
class H225_CallProceeding_UUIE;
class H225_Connect_UUIE;
class H225_Alerting_UUIE;
class H225_Information_UUIE;
class H225_ReleaseComplete_UUIE;
class H225_Facility_UUIE;
class H225_Progress_UUIE;
class H225_Status_UUIE;
class H225_StatusInquiry_UUIE;
class H225_SetupAcknowledge_UUIE;
class H225_Notify_UUIE;
class H225_TransportAddress;

class H245Handler;
class H245Socket;
class UDPProxySocket;
class ProxyHandler;
class HandlerList;

extern const char *RoutedSec;

class ProxySocket : public USocket {
public:
	enum Result {
		NoData,
		Connecting,
		Forwarding,
		Closing,
		Error
	};

	ProxySocket(IPSocket *, const char *);
	~ProxySocket() = 0; // abstract class

	// new virtual function
	virtual Result ReceiveData();
	virtual bool ForwardData();
	virtual bool EndSession();
	virtual void OnError() {}

	bool IsConnected() const { return connected; }
	void SetConnected(bool c) { connected = c; }
	bool IsDeletable() const { return deletable; }
	void SetDeletable() { deletable = true; }
	ProxyHandler *GetHandler() const { return handler; }
	void SetHandler(ProxyHandler *h) { handler = h; }

protected:
	BYTE *wbuffer;
	WORD wbufsize, buflen;

private:
	bool connected, deletable;
	ProxyHandler *handler;
};

class TCPProxySocket : public ServerSocket, public ProxySocket {
public:
	TCPProxySocket(const char *, TCPProxySocket * = 0, WORD = 0);
	virtual ~TCPProxySocket();

#ifndef LARGE_FDSET
	PCLASSINFO( TCPProxySocket, ServerSocket )

	// override from class PTCPSocket
	virtual BOOL Accept(PSocket &);
	virtual BOOL Connect(const Address &, WORD, const Address &);
	virtual BOOL Connect(const Address &);
#endif
	// override from class ProxySocket
	virtual bool ForwardData();
	virtual bool TransmitData(const PBYTEArray &);

protected:
	bool ReadTPKT();

	TCPProxySocket *remote;
	PBYTEArray buffer;

private:
	bool InternalWrite(const PBYTEArray &);
	bool SetMinBufSize(WORD);

	BYTE *bufptr;
};

class CallSignalSocket : public TCPProxySocket {
public:
	CallSignalSocket();
	CallSignalSocket(CallSignalSocket *, WORD);
	~CallSignalSocket();

#ifdef LARGE_FDSET
	// override from class TCPProxySocket
	virtual bool Connect(const Address &);
#else
	PCLASSINFO ( CallSignalSocket, TCPProxySocket )
	// override from class TCPProxySocket
	virtual BOOL Connect(const Address &);
#endif

	// override from class ProxySocket
        virtual Result ReceiveData();
	virtual bool EndSession();
	virtual void OnError();

	void SendReleaseComplete(const H225_CallTerminationCause * = 0);
	void SendReleaseComplete(H225_ReleaseCompleteReason::Choices);

	bool HandleH245Mesg(PPER_Stream &);
	bool IsNATSocket() const { return m_isnatsocket; }
	void OnH245ChannelClosed() { m_h245socket = 0; }
	void SetPeerAddress(const Address &, WORD);
	void BuildFacilityPDU(Q931 &, int, const PObject * = 0);
	void RemoveCall();

	// override from class ServerSocket
	virtual void Dispatch();

protected:
	CallSignalSocket(CallSignalSocket *);
	void SetRemote(CallSignalSocket *);
	bool CreateRemote(H225_Setup_UUIE &);
	void ForwardCall();

	bool OnSetup(H225_Setup_UUIE &, PString &in_rewrite_id, PString &out_rewrite_id);
	bool OnCallProceeding(H225_CallProceeding_UUIE &);
	bool OnConnect(H225_Connect_UUIE &);
	bool OnAlerting(H225_Alerting_UUIE &);
	bool OnInformation(H225_Information_UUIE &);
	bool OnReleaseComplete(H225_ReleaseComplete_UUIE &);
	bool OnFacility(H225_Facility_UUIE &);
	bool OnProgress(H225_Progress_UUIE &);
	bool OnEmpty(H225_H323_UU_PDU_h323_message_body &);
	bool OnStatus(H225_Status_UUIE &);
	bool OnStatusInquiry(H225_StatusInquiry_UUIE &);
	bool OnSetupAcknowledge(H225_SetupAcknowledge_UUIE &);
	bool OnNotify(H225_Notify_UUIE &);
//	bool OnNonStandardData(PASN_OctetString &);
	bool OnTunneledH245(H225_ArrayOf_PASN_OctetString &);
	bool OnFastStart(H225_ArrayOf_PASN_OctetString &, bool);

	bool OnInformationMsg(Q931 &);

	template<class UUIE> bool HandleH245Address(UUIE & uu)
	{
		if (uu.HasOptionalField(UUIE::e_h245Address)) {
			if (SetH245Address(uu.m_h245Address))
				return (m_h245handler != 0);
			uu.RemoveOptionalField(UUIE::e_h245Address);
			return true;
		}
		return false;
	}
	template<class UUIE> bool HandleFastStart(UUIE & uu, bool fromCaller)
	{
		return (m_h245handler && uu.HasOptionalField(UUIE::e_fastStart)) ?
			OnFastStart(uu.m_fastStart, fromCaller) : false;
	}

	callptr m_call;

	// localAddr is NOT the local address the socket bind to,
	// but the local address that remote socket bind to
	// they may be different in multi-homed environment
	Address localAddr, peerAddr;
	WORD peerPort;

private:
	void InternalInit();
	void BuildReleasePDU(Q931 &, const H225_CallTerminationCause *) const;
	// if return false, the h245Address field will be removed
	bool SetH245Address(H225_TransportAddress &);
	bool InternalConnectTo();

	WORD m_crv;
	H245Handler *m_h245handler;
	H245Socket *m_h245socket;
	bool m_h245Tunneling, m_isnatsocket;
	Result m_result;
	Q931 *m_lastQ931;
	H225_H323_UserInformation *m_setupUUIE;
};

class CallSignalListener : public TCPListenSocket {
#ifndef LARGE_FDSET
	PCLASSINFO ( CallSignalListener, TCPListenSocket )
#endif
public:
	CallSignalListener(const Address &, WORD);

	// override from class TCPListenSocket
	virtual ServerSocket *CreateAcceptor() const;
};

class ProxyHandler : public SocketsReader {
public:
	ProxyHandler(const PString& name);
	~ProxyHandler();

	void Insert(TCPProxySocket *);
	void Insert(TCPProxySocket *, TCPProxySocket *);
	void Insert(UDPProxySocket *, UDPProxySocket *);
	void MoveTo(ProxyHandler *, TCPProxySocket *);
	bool IsEmpty() const { return m_socksize == 0; }

private:
	// override from class RegularJob
	virtual void OnStart();

	// override from class SocketsReader
	virtual bool BuildSelectList(SocketSelectList &);
	virtual void ReadSocket(IPSocket *);
	virtual void CleanUp();

	void AddPairSockets(IPSocket *, IPSocket *);
	void FlushSockets();
	void Remove(iterator);
	void Remove(ProxySocket *socket);

	ProxyHandler();
	ProxyHandler(const ProxyHandler&);
	ProxyHandler& operator=(const ProxyHandler&);
	
private:
	std::list<PTime *> m_removedTime;
};

class HandlerList {
public:
	HandlerList();
	~HandlerList();

	/** @return
	    Signaling proxy thread to handle a new signaling/H.245/T.120 socket.
	*/
	ProxyHandler* GetSigHandler();

	/** @return
	    RTP proxy thread to handle a pair of new RTP sockets.
	*/
	ProxyHandler* GetRtpHandler();

	void LoadConfig();

private:
	HandlerList(const HandlerList&);
	HandlerList& operator=(const HandlerList&);
	
private:
	/// signaling/H.245/T.120 proxy handling threads
	std::vector<ProxyHandler *> m_sigHandlers;
	/// RTP proxy handling threads
	std::vector<ProxyHandler *> m_rtpHandlers;
	/// number of signaling handlers
	unsigned m_numSigHandlers;
	/// number of RTP handlers
	unsigned m_numRtpHandlers;
	/// next available signaling handler
	unsigned m_currentSigHandler;
	/// next available RTP handler
	unsigned m_currentRtpHandler;
	/// atomic access to the handler lists
	PMutex m_handlerMutex;
};

#endif // PROXYCHANNEL_H
