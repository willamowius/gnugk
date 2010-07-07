//////////////////////////////////////////////////////////////////
//
// ProxyChannel.h
//
// Copyright (c) Citron Network Inc. 2001-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitly grant the right to link this code
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
class SignalingMsg;
template <class> class H225SignalingMsg;
typedef H225SignalingMsg<H225_Setup_UUIE> SetupMsg;
typedef H225SignalingMsg<H225_Facility_UUIE> FacilityMsg;
struct SetupAuthData;

extern const char *RoutedSec;

void PrintQ931(int, const char *, const char *, const Q931 *, const H225_H323_UserInformation *);

bool GetUUIE(const Q931 & q931, H225_H323_UserInformation & uuie);

void SetUUIE(Q931 & q931, const H225_H323_UserInformation & uuie);

class ProxySocket : public USocket {
public:
	enum Result {
		NoData,
		Connecting,
		Forwarding,
		Closing,
		Error,
		DelayedConnecting	// H.460.18
	};

	ProxySocket(
		IPSocket *self,
		const char *type,
		WORD buffSize = 1536
	);
	virtual ~ProxySocket() = 0; // abstract class

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

private:
	ProxySocket();
	ProxySocket(const ProxySocket&);
	ProxySocket& operator=(const ProxySocket&);

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
	virtual PBoolean Accept(PSocket &);
	virtual PBoolean Connect(const Address &, WORD, const Address &);
	virtual PBoolean Connect(const Address &);
#endif
	// override from class ProxySocket
	virtual bool ForwardData();
	virtual bool TransmitData(const PBYTEArray &);

	void RemoveRemoteSocket();
	void SetRemoteSocket(TCPProxySocket * ret) { remote=ret; }
	TCPProxySocket * GetRemoteSocket() const { return remote; }

private:
	TCPProxySocket();
	TCPProxySocket(const TCPProxySocket&);
	TCPProxySocket& operator=(const TCPProxySocket&);

protected:
	struct TPKTV3 {
		TPKTV3() {}
		TPKTV3(WORD);

		BYTE header, padding;
		WORD length;
	};

	bool ReadTPKT();

	TCPProxySocket *remote;
	PBYTEArray buffer;

private:
	bool InternalWrite(const PBYTEArray &);
	bool SetMinBufSize(WORD);

	BYTE *bufptr;
	TPKTV3 tpkt;
	unsigned tpktlen;
};

#if H323_H450
class X880_Invoke;
class H4501_InterpretationApdu;
#endif

class CallSignalSocket : public TCPProxySocket {
public:
	CallSignalSocket();
	CallSignalSocket(CallSignalSocket *, WORD _port);
	virtual ~CallSignalSocket();

#ifdef LARGE_FDSET
	// override from class TCPProxySocket
	virtual bool Connect(const Address &);
#else
	PCLASSINFO ( CallSignalSocket, TCPProxySocket )
	// override from class TCPProxySocket
	virtual PBoolean Connect(const Address &);
#endif

	// override from class ProxySocket
	virtual Result ReceiveData();
	virtual bool EndSession();
	virtual void OnError();

	void SendReleaseComplete(const H225_CallTerminationCause * = 0);
	void SendReleaseComplete(H225_ReleaseCompleteReason::Choices);

	bool HandleH245Mesg(PPER_Stream &, bool & suppress, H245Socket * h245sock = NULL);
	bool IsNATSocket() const { return m_isnatsocket; }
	void OnH245ChannelClosed() { m_h245socket = 0; }
	void SetPeerAddress(const Address &, WORD);
	Address GetLocalAddr() { return localAddr; }
	Address GetPeerAddr() { return peerAddr; }
	Address GetMasqAddr() { return masqAddr; }
	void BuildFacilityPDU(Q931 &, int, const PObject * = 0);
	void BuildProgressPDU(Q931 &, PBoolean fromDestination);
	void BuildProceedingPDU(Q931 & ProceedingPDU, const H225_CallIdentifier & callId, unsigned crv);
	void BuildSetupPDU(Q931 &, const H225_CallIdentifier & callid, unsigned crv, const PString & destination, bool h245tunneling);
	void RemoveCall();
	bool RerouteCall(CallLeg which, const PString & destination, bool h450transfer);
	void RerouteCaller(PString destination);
	void RerouteCalled(PString destination);

	// override from class ServerSocket
	virtual void Dispatch();
	void DispatchNextRoute();
	Result RetrySetup();
	void TryNextRoute();
	void RemoveH245Handler();
	void SaveTCS(const H245_TerminalCapabilitySet & tcs) { m_savedTCS = tcs; }
	H245_TerminalCapabilitySet GetSavedTCS() const { return m_savedTCS; }
	bool CompareH245Socket(H245Socket * sock) const { return sock == m_h245socket; }	// compare pointers !
	
protected:
	CallSignalSocket(CallSignalSocket *);
	
	void SetRemote(CallSignalSocket *);
	bool CreateRemote(H225_Setup_UUIE &setupBody);
	CallSignalSocket * GetRemote() const { return (CallSignalSocket *)remote; }

	void ForwardCall(FacilityMsg *msg);

	/// signaling message handlers
	void OnSetup(SignalingMsg *msg);
	void OnCallProceeding(SignalingMsg *msg);
	void OnConnect(SignalingMsg *msg);
	void OnAlerting(SignalingMsg *msg);
	void OnReleaseComplete(SignalingMsg *msg);
	void OnFacility(SignalingMsg *msg);
	void OnProgress(SignalingMsg *msg);
	void OnInformation(SignalingMsg *msg);

	bool OnTunneledH245(H225_ArrayOf_PASN_OctetString &, bool & suppress);
	bool OnFastStart(H225_ArrayOf_PASN_OctetString &, bool);

#if H323_H450
	bool OnH450PDU(H225_ArrayOf_PASN_OctetString &);
	bool OnH450Invoke(X880_Invoke &, H4501_InterpretationApdu &);
	bool OnH450CallTransfer(PASN_OctetString *);
#endif

	template<class UUIE> bool HandleH245Address(UUIE & uu)
	{
		if (uu.HasOptionalField(UUIE::e_h245Address)) {
			 if (m_call)
				m_call->SetH245ResponseReceived();
			 if (SetH245Address(uu.m_h245Address))
				return (m_h245handler != 0);
			uu.RemoveOptionalField(UUIE::e_h245Address);
			return true;
		}
		return false;
	}
	
	template<class UUIE> bool HandleFastStart(UUIE & uu, bool fromCaller)
	{
		if (!uu.HasOptionalField(UUIE::e_fastStart))
			return false;
			
		if (!fromCaller && m_call)
			m_call->SetFastStartResponseReceived();
			
		return m_h245handler != NULL ? OnFastStart(uu.m_fastStart, fromCaller) : false;
	}

private:
	CallSignalSocket(const CallSignalSocket&);
	CallSignalSocket& operator=(const CallSignalSocket&);
	
	void InternalInit();
	void BuildReleasePDU(Q931 &, const H225_CallTerminationCause *) const;
	// if return false, the h245Address field will be removed
	bool SetH245Address(H225_TransportAddress &);
	bool InternalConnectTo();
	bool ForwardCallConnectTo();

	/** @return
	    A string that can be used to identify a calling number.
	*/
	PString GetCallingStationId(
		/// Q.931/H.225 Setup message with additional data
		const SetupMsg& setup,
		/// additional data
		SetupAuthData& authData
		) const;

	/** @return
	    A string that can be used to identify a calling number.
	*/
	PString GetCalledStationId(
		/// Q.931/H.225 Setup message with additional data
		const SetupMsg& setup,
		/// additional data
		SetupAuthData& authData
		) const;

	/// @return	a number dialed by the user
	PString GetDialedNumber(
		/// Q.931/H.225 Setup message with additional data
		const SetupMsg& setup
		) const;

	void SetCallTypePlan(Q931 *q931);

protected:
	callptr m_call;
	// localAddr is NOT the local address the socket bind to,
	// but the local address that remote socket bind to
	// they may be different in multi-homed environment
	Address localAddr, peerAddr, masqAddr;
	WORD peerPort;

private:
	WORD m_crv;
	H245Handler *m_h245handler;
	H245Socket *m_h245socket;
	bool m_h245Tunneling;
	bool m_isnatsocket;
	Result m_result;
	/// stored for use by ForwardCall, NULL if ForwardOnFacility is disabled
	Q931 *m_setupPdu;
	/// true if the socket is connected to the caller, false if to the callee
	bool m_callerSocket;
	/// H.225.0 protocol version in use by the remote party
	unsigned m_h225Version;
	/// raw Setup data as received from the caller (for failover)
	PBYTEArray m_rawSetup;
	PMutex infomutex;    // Information PDU processing Mutex
	H245_TerminalCapabilitySet m_savedTCS;	// saved tcs to re-send
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
	virtual ~ProxyHandler();

	void Insert(TCPProxySocket *);
	void Insert(TCPProxySocket *, TCPProxySocket *);
	void Insert(UDPProxySocket *, UDPProxySocket *);
	void MoveTo(ProxyHandler *, TCPProxySocket *);
	bool IsEmpty() const { return m_socksize == 0; }
	void LoadConfig();
	bool Detach(TCPProxySocket *);
	void Remove(TCPProxySocket *);
	
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
	void DetachSocket(IPSocket *socket);

	ProxyHandler();
	ProxyHandler(const ProxyHandler&);
	ProxyHandler& operator=(const ProxyHandler&);
	
private:
	std::list<PTime *> m_removedTime;
	/// time to wait before deleting a closed socket
	PTimeInterval m_socketCleanupTimeout;
};

class HandlerList {
public:
	HandlerList();
	virtual ~HandlerList();

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
