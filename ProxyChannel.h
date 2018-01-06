//////////////////////////////////////////////////////////////////
//
// ProxyChannel.h
//
// Copyright (c) Citron Network Inc. 2001-2003
// Copyright (c) 2002-2018, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef PROXYCHANNEL_H
#define PROXYCHANNEL_H "@(#) $Id$"

#include <vector>
#include <list>
#include <map>
#include "yasocket.h"
#include "RasTbl.h"
#include "gktimer.h"
#include "config.h"

#ifdef HAS_H46026
	#include <h460/h46026.h>
	#include <h460/h46026mgr.h>
#endif


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

#ifdef _WIN32
typedef int ssize_t;
#endif

extern const char *RoutedSec;
extern const char *TLSSec;
extern const char *ProxySection;

const WORD DEFAULT_PACKET_BUFFER_SIZE = 2048;

void PrintQ931(int, const char *, const char *, const Q931 *, const H225_H323_UserInformation *);

ssize_t UDPSendWithSourceIP(int fd, void * data, size_t len, const IPAndPortAddress & toAddress);
ssize_t UDPSendWithSourceIP(int fd, void * data, size_t len, const PIPSocket::Address & ip, WORD port);


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
		WORD buffSize = DEFAULT_PACKET_BUFFER_SIZE
	);
	virtual ~ProxySocket() = 0; // abstract class

	// new virtual function
	virtual Result ReceiveData();
	virtual bool ForwardData();
	virtual bool EndSession();
	virtual void OnError() { }

	bool IsConnected() const { return connected; }
	void SetConnected(bool c) { connected = c; }
	bool IsDeletable() const { return deletable; }
	void SetDeletable() { deletable = true; }
	ProxyHandler * GetHandler() const { return handler; }
	void SetHandler(ProxyHandler * h) { handler = h; }

private:
	ProxySocket();
	ProxySocket(const ProxySocket &);
	ProxySocket& operator=(const ProxySocket &);

protected:
	BYTE *wbuffer;
	WORD wbufsize, buflen;

private:
	bool connected, deletable;
	ProxyHandler *handler;
};

class TCPProxySocket : public ServerSocket, public ProxySocket {
public:
    enum H225KeepAliveMethod { TPKTH225, EmptyFacility, Information, Notify, Status, StatusInquiry, NoneH225 };
    enum H245KeepAliveMethod { TPKTH245, UserInput, NoneH245 };

	TCPProxySocket(const char * t, TCPProxySocket * s = NULL, WORD p = 0);
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

	void DetachRemote();
  	void RemoveRemoteSocket();
	void SetRemoteSocket(TCPProxySocket * ret) { remote = ret; }
	void LockRemote() { m_remoteLock.Wait(); }
	void UnlockRemote() { m_remoteLock.Signal(); }

private:
	TCPProxySocket();
	TCPProxySocket(const TCPProxySocket &);
	TCPProxySocket& operator=(const TCPProxySocket &);

protected:
	struct TPKTV3 {
		TPKTV3(WORD);

		BYTE header, padding;
		WORD length;
	};

	bool ReadTPKT();

	PMutex m_remoteLock;	// protect the remote member
	TCPProxySocket *remote;
	PBYTEArray buffer;

public:
	bool InternalWrite(const PBYTEArray & buf);
	void SendKeepAlive(GkTimer * timer);
	void SendEmptyTPKTKeepAlive();
	void RegisterKeepAlive(int h46018_interval = 0);
	void UnregisterKeepAlive();
	bool UsesH460KeepAlive() const { return (m_keepAliveTimer != GkTimerManager::INVALID_HANDLE) && m_h46018KeepAlive; }

protected:
	bool SetMinBufSize(WORD);

	BYTE *bufptr;
	TPKTV3 tpkt;
	unsigned tpktlen;

	bool m_h46018KeepAlive;
	H225KeepAliveMethod m_h460KeepAliveMethodH225;
	H245KeepAliveMethod m_h460KeepAliveMethodH245;
	H225KeepAliveMethod m_nonStdKeepAliveMethodH225;
	H245KeepAliveMethod m_nonStdKeepAliveMethodH245;
	int m_keepAliveInterval;
	GkTimerManager::GkTimerHandle m_keepAliveTimer;
};

class RTPLogicalChannel;
class UDPProxySocket : public UDPSocket, public ProxySocket {
public:
#ifndef LARGE_FDSET
	PCLASSINFO( UDPProxySocket, UDPSocket )
#endif

	UDPProxySocket(const char * t, const H225_CallIdentifier & id);
	~UDPProxySocket();

	void UpdateSocketName();
	void RemoveCallPtr() { m_call = NULL; }
	void SetDestination(H245_UnicastAddress &, callptr &);
	void SetForwardDestination(const Address & srcIP, WORD srcPort, H245_UnicastAddress * dstAddr, callptr & call);
	void SetReverseDestination(const Address & srcIP, WORD srcPort, H245_UnicastAddress * dstAddr, callptr & call);
	typedef void (UDPProxySocket::*pMem)(const Address & srcIP, WORD srcPort, H245_UnicastAddress * dstAddr, callptr & call);

	bool Bind(const Address & localAddr, WORD pt);
	int GetOSSocket() const { return os_handle; }
	void SetNAT(bool);
	bool isMute() { return mute; }
	void SetMute(bool toMute) { mute = toMute; }
	void OnHandlerSwapped() { std::swap(fnat, rnat); }
	void SetRTPSessionID(WORD id) { m_sessionID = id; }
#ifdef HAS_H235_MEDIA
	void SetEncryptingRTPChannel(RTPLogicalChannel * lc) { m_encryptingLC = lc; }
	void RemoveEncryptingRTPChannel(RTPLogicalChannel * lc) { if (m_encryptingLC == lc) m_encryptingLC = NULL; }
	void SetDecryptingRTPChannel(RTPLogicalChannel * lc) { m_decryptingLC = lc; }
	void RemoveDecryptingRTPChannel(RTPLogicalChannel * lc) { if (m_decryptingLC == lc) m_decryptingLC = NULL; }
#endif
#ifdef HAS_H46018
	void SetUsesH46019fc(bool fc) { m_h46019fc = fc; }
	// same socket is used for all directions; set if at least one side uses H.460.19
	void SetUsesH46019() { m_useH46019 = true; }
	bool UsesH46019() const { return m_useH46019; }
	void SetH46019UniDirectional(bool val) { m_h46019uni = val; }
	void AddKeepAlivePT(BYTE pt);
	void SetMultiplexDestination(const IPAndPortAddress & toAddress, H46019Side side);
	void SetMultiplexID(DWORD multiplexID, H46019Side side);
	void SetMultiplexSocket(int multiplexSocket, H46019Side side);
#endif

	// override from class ProxySocket
	virtual Result ReceiveData();
	virtual bool OnReceiveData(void *, PINDEX, Address &, WORD &) { return true; }

    void GetPorts(PIPSocket::Address & _fSrcIP, PIPSocket::Address & _fDestIP, PIPSocket::Address & _rSrcIP, PIPSocket::Address & _rDestIP,
                    WORD & _fSrcPort, WORD & _fDestPort, WORD & _rSrcPort, WORD & _rDestPort) const;
    void ZeroAllIPs();
    void ForwardAndReverseSeen() { PTRACE(7, "JW RTP ForwardAndReverseSeen"); m_forwardAndReverseSeen = true; }


protected:
	virtual bool WriteData(const BYTE *, int);
	virtual bool Flush();
	virtual bool ErrorHandler(PSocket::ErrorGroup);

	void SetMediaIP(bool isSRC, const Address & ip);

	// RTCP handler
	void BuildReceiverReport(const RTP_ControlFrame & frame, PINDEX offset, bool dst);

	H225_CallIdentifier m_callID;
	callptr * m_call;

private:
	UDPProxySocket();
	UDPProxySocket(const UDPProxySocket &);
	UDPProxySocket& operator=(const UDPProxySocket &);

protected:
	Address fSrcIP, fDestIP, rSrcIP, rDestIP;
	WORD fSrcPort, fDestPort, rSrcPort, rDestPort;
	bool fnat, rnat;
	bool mute;
	bool m_isRTPType;
	bool m_isRTCPType;
	bool m_dontQueueRTP;
	bool m_EnableRTCPStats;
	WORD m_sessionID;
	RTPLogicalChannel * m_encryptingLC;
	RTPLogicalChannel * m_decryptingLC;
#ifdef HAS_H46018
	bool m_h46019fc;
	bool m_useH46019;
	bool m_h46019uni;
	PMutex m_h46019DetectionLock;
	bool m_checkH46019KeepAlivePT;
	WORD m_keepAlivePT_1;
	WORD m_keepAlivePT_2;
	PTime m_channelStartTime;
	// two (!), one or zero parties in a call through a UDPProxySocket may by multiplexed
	// UDPProxySocket always receives regular RTP, but may send out multiplexed
	IPAndPortAddress m_multiplexDestination_A;	// OLC side of first logical channel in this session
	DWORD m_multiplexID_A;	// ID _to_ A side (only valid if m_multiplexDestination_A is set)
	int m_multiplexSocket_A;	// only valid if m_multiplexDestination_A is set
	IPAndPortAddress m_multiplexDestination_B;	// OLCAck side of first logical channel in this session
	DWORD m_multiplexID_B;	// ID _to_ B side (only valid if m_multiplexDestination_B is set)
	int m_multiplexSocket_B;	// only valid if m_multiplexDestination_ is set)
	PMutex m_multiplexMutex;	// protect multiplex IDs, addresses and sockets against access from concurrent threads
#endif
#ifdef HAS_H235_MEDIA
	bool m_haveShownPTWarning;	// flag to show the PayloadType warning only once (not for every RTP packet)
#endif
    bool m_ignoreSignaledIPs;   // ignore all RTP/RTCP IPs in signalling, do full auto-detect
    bool m_ignoreSignaledPrivateH239IPs;   // also ignore private IPs signaled in H239 streams
    list<NetworkAddress> m_keepSignaledIPs;   // don't do auto-detect on this network
    bool m_restrictRTPSources;
    NetworkAddress m_restrictRTPNetwork_A;
    NetworkAddress m_restrictRTPNetwork_B;
	bool m_portDetectionDone;
	bool m_forwardAndReverseSeen;   // did we see logical channels for both directions, yet ?
	bool m_legacyPortDetection;
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

	// override from TCPProxySocket
	virtual bool ForwardData();

	void SendReleaseComplete(const H225_CallTerminationCause * = NULL);
	void SendReleaseComplete(H225_ReleaseCompleteReason::Choices);

	bool IsH245Tunneling() const { return m_h245Tunneling; }
	bool IsH245TunnelingTranslation() const { return m_h245TunnelingTranslation; }
	PASN_OctetString * GetNextQueuedH245Message();
	unsigned GetH245MessageQueueSize() const { return  m_h245Queue.size(); }
	bool HandleH245Mesg(PPER_Stream &, bool & suppress, H245Socket * h245sock = NULL);
	void SendPostDialDigits();
	void OnH245ChannelClosed() { m_h245socket = NULL; }
	Address GetLocalAddr() { return localAddr; }
	Address GetPeerAddr() { return peerAddr; }
	Address GetMasqAddr() { return masqAddr; }
	PINDEX GetCallNumber() const { return m_call ? m_call->GetCallNumber() : 0; }
	H225_CallIdentifier GetCallIdentifier() const { return m_call ? m_call->GetCallIdentifier() : 0; }
	PString GetCallIdentifierAsString() const { return m_call ? AsString(m_call->GetCallIdentifier().m_guid) : "unknown"; }
	void BuildFacilityPDU(Q931 &, int, const PObject * = NULL, bool h46017 = false);
	void BuildProgressPDU(Q931 &, PBoolean fromDestination);
	void BuildNotifyPDU(Q931 &, PBoolean fromDestination);
	void BuildStatusPDU(Q931 &, PBoolean fromDestination);
	void BuildStatusInquiryPDU(Q931 &, PBoolean fromDestination);
	void BuildInformationPDU(Q931 &, PBoolean fromDestination);
	void BuildProceedingPDU(Q931 & ProceedingPDU, const H225_CallIdentifier & callId, unsigned crv);
	void BuildSetupPDU(Q931 &, const H225_CallIdentifier & callid, unsigned crv, const PString & destination, bool h245tunneling);
	void RemoveCall();
	bool RerouteCall(CallLeg which, const PString & destination, bool h450transfer);
	void RerouteCaller(PString destination);
	void RerouteCalled(PString destination);
	void PerformConnecting();

	// override from class ServerSocket
	virtual void Dispatch();
	void DispatchNextRoute();
	Result RetrySetup();
	void TryNextRoute();
	void RemoveH245Handler();
	H245_TerminalCapabilitySet GetSavedTCS() const { return m_savedTCS; }
	unsigned GetNextTCSSeq() { return ++m_tcsRecSeq; }
	bool SendTunneledH245(const PPER_Stream & strm);
	bool SendTunneledH245(const H245_MultimediaSystemControlMessage & h245msg);
    void SendFacilityKeepAlive();
    void SendInformationKeepAlive();
    void SendNotifyKeepAlive();
    void SendStatusKeepAlive();
    void SendStatusInquiryKeepAlive();

#ifdef HAS_H235_MEDIA
	bool IsH245Master() const { return m_isH245Master; }
    bool HandleH235TCS(H245_TerminalCapabilitySet & tcs);
    bool HandleH235OLC(H245_OpenLogicalChannel & olc);
	void SendEncryptionUpdateCommand(WORD flcn, BYTE oldPT, BYTE plainPT);
	void SendEncryptionUpdateRequest(WORD flcn, BYTE oldPT, BYTE plainPT);
#endif
	H245Socket * GetH245Socket() const { return m_h245socket; }
	void SetH245Socket(H245Socket * sock) { m_h245socket = sock; }
	bool CompareH245Socket(H245Socket * sock) const { return sock == m_h245socket; }	// intentionally comparing pointers

protected:
	void SetRemote(CallSignalSocket *);
	bool CreateRemote(H225_Setup_UUIE &setupBody);

public:
#ifdef HAS_H46017
	bool SendH46017Message(H225_RasMessage ras, GkH235Authenticators * authenticators);
	void CleanupCall();
#endif
#ifdef HAS_H46026
	bool SendH46026RTP(unsigned sessionID, bool isRTP, const void * data, unsigned len);
	void PollPriorityQueue();
#endif
	bool MaintainConnection() const { return m_maintainConnection; }

#ifdef HAS_H46018
	bool IsCaller() const { return m_callerSocket; }
	bool IsTraversalClient() const;
	bool IsTraversalServer() const;
	bool CreateRemote(const H225_TransportAddress & addr);
	bool OnSCICall(const H225_CallIdentifier & callID, H225_TransportAddress sigAdr, bool useTLS);
	bool IsCallFromTraversalServer() const { return m_callFromTraversalServer; }
	bool IsCallToTraversalServer() const { return m_callToTraversalServer; }
	void SetSessionMultiplexDestination(WORD session, bool isRTCP, const IPAndPortAddress & toAddress, H46019Side side);
	const H245Handler * GetH245Handler() const { return m_h245handler; }
#endif
	void LockH245Handler() { m_h245handlerLock.Wait(); }
	void UnlockH245Handler() { m_h245handlerLock.Signal(); }

#ifdef HAS_H46023
	bool IsH46024Call(const H225_Setup_UUIE & setupBody);
#endif

	bool SetupResponseTokens(SignalingMsg * msg, GkH235Authenticators * auth, const endptr & ep);

	CallSignalSocket * GetRemote() const { return dynamic_cast<CallSignalSocket *>(remote); }

protected:
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
	void OnStatus(SignalingMsg *msg);

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
				return (m_h245handler != NULL);
			uu.RemoveOptionalField(UUIE::e_h245Address);
			return true;
		}
		return false;
	}

	template<class UUIE> bool HandleFastStart(UUIE & uu, bool fromCaller)
	{
		if (!uu.HasOptionalField(UUIE::e_fastStart))
			return false;

        if (GkConfig()->GetBoolean(RoutedSec, "DisableFastStart", false)) {
            uu.RemoveOptionalField(UUIE::e_fastStart);
            return true;
        }

		if (!fromCaller && m_call)
			m_call->SetFastStartResponseReceived();

		return m_h245handler != NULL ? OnFastStart(uu.m_fastStart, fromCaller) : false;
	}

private:
	CallSignalSocket(const CallSignalSocket &);
	CallSignalSocket & operator=(const CallSignalSocket &);

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
		const SetupMsg & setup,
		/// additional data
		SetupAuthData & authData
		) const;

	/** @return
	    A string that can be used to identify a calling number.
	*/
	PString GetCalledStationId(
		/// Q.931/H.225 Setup message with additional data
		const SetupMsg & setup,
		/// additional data
		SetupAuthData & authData
		) const;

	/// @return	a number dialed by the user
	PString GetDialedNumber(
		/// Q.931/H.225 Setup message with additional data
		const SetupMsg & setup
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
	PMutex m_h245handlerLock;
	H245Handler * m_h245handler;
	H245Socket * m_h245socket;
	bool m_h245Tunneling;
	bool m_h245TunnelingTranslation;
	std::queue<PASN_OctetString> m_h245Queue;
	bool m_isnatsocket;
	bool m_maintainConnection;	// eg. for H.460.17
	Result m_result;
	/// stored for use by ForwardCall, NULL if ForwardOnFacility is disabled
	Q931 * m_setupPdu;
#ifdef HAS_H235_MEDIA
	H225_ArrayOf_ClearToken * m_setupClearTokens;
#endif
	/// true if the socket is connected to the caller, false if to the callee
	bool m_callerSocket;
	/// H.225.0 protocol version in use by the remote party
	unsigned m_h225Version;
	/// raw Setup data as received from the caller (for failover)
	PBYTEArray m_rawSetup;
	PMutex infomutex;    // Information PDU processing Mutex
	H245_TerminalCapabilitySet m_savedTCS;	// saved tcs to re-send
	unsigned m_tcsRecSeq;
	unsigned m_tcsAckRecSeq;
#ifdef HAS_H46017
	bool m_h46017Enabled;
	TCPProxySocket * rc_remote; // copy of the remote pointer that may be only used to send RC on call end
#endif
#ifdef HAS_H46018
	bool m_callFromTraversalServer; // is this call from a traversal server ?
	bool m_callToTraversalServer;
	bool m_senderSupportsH46019Multiplexing;
#endif
#ifdef HAS_H235_MEDIA
	bool m_isH245Master;
#endif
#ifdef HAS_H46026
	H46026ChannelManager * m_h46026PriorityQueue;
#endif
};

class CallSignalListener : public TCPListenSocket {
#ifndef LARGE_FDSET
	PCLASSINFO ( CallSignalListener, TCPListenSocket )
#endif
public:
	CallSignalListener(const Address &, WORD);
	~CallSignalListener();

	// override from class TCPListenSocket
	virtual ServerSocket *CreateAcceptor() const;

protected:
	Address m_addr;
};


#ifdef HAS_TLS

class TLSCallSignalListener : public CallSignalListener {
public:
	TLSCallSignalListener(const Address &, WORD);
	~TLSCallSignalListener();

	// override from class CallSignalListener
	virtual ServerSocket *CreateAcceptor() const;
};

class TLSCallSignalSocket : public CallSignalSocket {
public:
	TLSCallSignalSocket();
	TLSCallSignalSocket(CallSignalSocket * s, WORD port);
	virtual ~TLSCallSignalSocket();

	virtual bool Connect(const Address & addr);
	virtual PBoolean Connect(const Address & iface, WORD localPort, const Address & addr);	// override from TCPProxySocket
	virtual bool Read(void * buf, int sz);
	virtual int GetLastReadCount() const { return m_lastReadCount; }
	virtual bool Write(const void * buf, int sz);
	virtual int GetLastWriteCount() const { return m_lastWriteCount; }
	virtual void Dispatch();

protected:
	SSL * m_ssl;
	int m_lastReadCount, m_lastWriteCount;
};

#endif // HAS_TLS


#ifdef HAS_H46018

class MultiplexRTPListener : public UDPSocket {
#ifndef LARGE_FDSET
	PCLASSINFO ( MultiplexRTPListener, UDPSocket )
#endif
public:
	MultiplexRTPListener(WORD pt, WORD buffSize = DEFAULT_PACKET_BUFFER_SIZE);
	virtual ~MultiplexRTPListener();

	virtual int GetOSSocket() const { return os_handle; }

	virtual void ReceiveData();
protected:
	BYTE * wbuffer;
	WORD wbufsize;
};

class RTPLogicalChannel;

// class for a H.460.19 session: it includes both directions (the full RTP session)
// when stored in the channel list in MultiplexedRTPHandler,
// side A is the OLC side, side B is the OLCAck side of the first channel in the session
// when the channel is handed out via GetChannelSwapped(), side A is the OLC side of _that_ channel
class H46019Session
{
public:
	H46019Session(const H225_CallIdentifier & callid, WORD session, void * openedBy);
    ~H46019Session();

	H46019Session(const H46019Session & other);
	H46019Session & operator=(const H46019Session & other);

	void Dump() const;

	bool IsValid() const { return !m_deleted && ((m_session != INVALID_RTP_SESSION) || (m_flcn > 0)); }
	bool sideAReady(bool isRTCP) const { return isRTCP ? m_addrA_RTCP.IsSet() : m_addrA.IsSet(); }
	bool sideBReady(bool isRTCP) const { return isRTCP ? m_addrB_RTCP.IsSet() : m_addrB.IsSet(); }
	H46019Session SwapSides() const; // return a copy with side A and B swapped

	static bool IsKeepAlive(unsigned len, bool isRTCP) { return isRTCP ? true : (len == 12); }

	void HandlePacket(DWORD receivedMultiplexID, const IPAndPortAddress & fromAddress, void * data, unsigned len, bool isRTCP);
	static void Send(DWORD sendMultiplexID, const IPAndPortAddress & toAddress, int ossocket, void * data, unsigned len, bool bufferHasRoomForID = false);

public:
	//mutable PTimedMutex m_usedLock;
    bool m_deleted; // logically deleted, but still in list so other threads can leave methods
    PTime m_deleteTime;
	H225_CallIdentifier m_callid;
	WORD m_session;     // RTP session ID
	WORD m_flcn;		// only used to assign master assigned RTP session IDs
	void * m_openedBy;	// side A (pointer to H245ProxyHandler used as an ID)
	void * m_otherSide;	// side B (pointer to H245ProxyHandler used as an ID)
	IPAndPortAddress m_addrA;
	IPAndPortAddress m_addrA_RTCP;
	IPAndPortAddress m_addrB;
	IPAndPortAddress m_addrB_RTCP;
	DWORD m_multiplexID_fromA;
	DWORD m_multiplexID_toA;
	DWORD m_multiplexID_fromB;
	DWORD m_multiplexID_toB;
	int m_osSocketToA;
	int m_osSocketToA_RTCP;
	int m_osSocketToB;
	int m_osSocketToB_RTCP;
	bool m_EnableRTCPStats;
#ifdef HAS_H235_MEDIA
	RTPLogicalChannel * m_encryptingLC;
	RTPLogicalChannel * m_decryptingLC;
	DWORD m_encryptMultiplexID;
	DWORD m_decryptMultiplexID;
#endif
};

class MultiplexedRTPReader : public SocketsReader {
public:
	MultiplexedRTPReader();
	virtual ~MultiplexedRTPReader();

	virtual int GetRTPOSSocket() const { return m_multiplexRTPListener ? m_multiplexRTPListener->GetOSSocket() : INVALID_OSSOCKET; }
	virtual int GetRTCPOSSocket() const { return m_multiplexRTCPListener ? m_multiplexRTCPListener->GetOSSocket() : INVALID_OSSOCKET; }

protected:
	virtual void OnStart();
	virtual void ReadSocket(IPSocket * socket);

	MultiplexRTPListener * m_multiplexRTPListener;
	MultiplexRTPListener * m_multiplexRTCPListener;
};

// handles multiplexed RTP and keepAlives
class MultiplexedRTPHandler : public Singleton<MultiplexedRTPHandler> {
public:
	MultiplexedRTPHandler();
	virtual ~MultiplexedRTPHandler();

	virtual void OnReload() { /* currently not runtime changable */ }

	virtual void AddChannel(const H46019Session & cha);
	virtual void UpdateChannelSession(const H225_CallIdentifier & callid, WORD flcn, void * openedBy, WORD session);
	virtual void UpdateChannel(const H46019Session & cha);
	virtual H46019Session GetChannel(const H225_CallIdentifier & callid, WORD session) const;
	virtual H46019Session GetChannelSwapped(const H225_CallIdentifier & callid, WORD session, void * openedBy) const;
	virtual void RemoveChannels(H225_CallIdentifier callid);	// pass by value in case call gets removed
#ifdef HAS_H235_MEDIA
	virtual void RemoveChannel(H225_CallIdentifier callid, RTPLogicalChannel * rtplc);
#endif
	virtual void DumpChannels(const PString & msg = "") const;

	virtual bool HandlePacket(DWORD receivedMultiplexID, const IPAndPortAddress & fromAddress, void * data, unsigned len, bool isRTCP);
#ifdef HAS_H46026
	virtual bool HandlePacket(const H225_CallIdentifier & callid, const H46026_UDPFrame & data);
#endif

	virtual int GetRTPOSSocket() const { return m_reader ? m_reader->GetRTPOSSocket() : INVALID_OSSOCKET; }
	virtual int GetRTCPOSSocket() const { return m_reader ? m_reader->GetRTCPOSSocket() : INVALID_OSSOCKET; }

	virtual DWORD GetMultiplexID(const H225_CallIdentifier & callid, WORD session, void * to);
	virtual DWORD GetNewMultiplexID();

	bool GetDetectedMediaIP(const H225_CallIdentifier & callID, WORD sessionID, bool forCaller, /* out */ PIPSocket::Address & addr, WORD & port) const;

	// delete sessions marked as deleted
	void SessionCleanup(GkTimer* timer);

protected:
	MultiplexedRTPReader * m_reader;
	mutable PReadWriteMutex m_listLock;
	list<H46019Session> m_h46019channels;
	DWORD idCounter; // we should make sure this counter is _not_ reset on reload
	GkTimerManager::GkTimerHandle m_cleanupTimer;
	PTimeInterval m_deleteDelay;    // how long to wait before deleting a session marked for delete
};
#endif


#ifdef HAS_H46026

// class for a H.460.26 session: it includes only the plain RTP side (multiplexed RTP is handled in H46019Session
class H46026Session
{
public:
	H46026Session() : m_isValid(false) { }
	H46026Session(const H225_CallIdentifier & callid, WORD session, int osRTPSocket, int osRTCPSocket,
					const IPAndPortAddress & toRTP, const IPAndPortAddress & toRTCP);

	void Send(void * data, unsigned len, bool isRTCP);
	bool IsValid() const { return m_isValid; }
	void Dump() const;

	bool m_isValid;
	H225_CallIdentifier m_callid;
	WORD m_session;
	int m_osRTPSocket;
	int m_osRTCPSocket;
	IPAndPortAddress m_toAddressRTP;
	IPAndPortAddress m_toAddressRTCP;

#ifdef HAS_H235_MEDIA
	RTPLogicalChannel * m_encryptingLC;
	RTPLogicalChannel * m_decryptingLC;
#endif
};

// handles stores H.460.26 RTP sessions
class H46026RTPHandler : public Singleton<H46026RTPHandler> {
public:
	H46026RTPHandler();
	virtual ~H46026RTPHandler();

	virtual void OnReload() { /* currently not runtime changable */ }

	virtual void AddChannel(const H46026Session & chan);
	virtual void ReplaceChannel(const H46026Session & chan);
	virtual void UpdateChannelRTP(const H225_CallIdentifier & callid, WORD session, IPAndPortAddress toRTP);
	virtual void UpdateChannelRTCP(const H225_CallIdentifier & callid, WORD session, IPAndPortAddress toRTCP);
	virtual void RemoveChannels(H225_CallIdentifier callid);	// pass by value in case call gets removed
	H46026Session FindSession(const H225_CallIdentifier & callid, WORD session) const;
#ifdef HAS_H235_MEDIA
	virtual void UpdateChannelEncryptingLC(const H225_CallIdentifier & callid, WORD session, RTPLogicalChannel * lc);
	virtual void UpdateChannelDecryptingLC(const H225_CallIdentifier & callid, WORD session, RTPLogicalChannel * lc);
#endif
	virtual void DumpChannels(const PString & msg = "") const;

	virtual bool HandlePacket(const H225_CallIdentifier & callid, H46026_UDPFrame & data);

protected:
	mutable PReadWriteMutex m_listLock;
	list<H46026Session> m_h46026channels;
};

#endif


class ProxyHandler : public SocketsReader {
public:
	ProxyHandler(const PString & name);
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
	ProxyHandler(const ProxyHandler &);
	ProxyHandler& operator=(const ProxyHandler &);

private:
	std::list<PTime *> m_removedTime;
	/// time to wait before deleting a closed socket
	PTimeInterval m_socketCleanupTimeout;
#ifdef HAS_H46017
	bool m_h46017Enabled;
#endif
	bool m_proxyHandlerHighPrio;
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
	HandlerList(const HandlerList &);
	HandlerList& operator=(const HandlerList &);

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
