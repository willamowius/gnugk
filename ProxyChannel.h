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

class H245Handler;
class CallSignalSocket;
class H245Socket;


class H245Handler {
// This class handles H.245 messages which can either be transmitted on their
// own TCP connection or can be tunneled in the Q.931 connection
public:
	H245Handler(PIPSocket::Address, bool);
	virtual ~H245Handler();

	virtual bool HandleMesg(PPER_Stream &, ProxySocket::Result &);
	PIPSocket::Address GetLocalAddr() const { return localAddr; }
	void SetLocalAddr(PIPSocket::Address local) { localAddr = local; }

protected:
	virtual bool HandleRequest(H245_RequestMessage & Request);
	virtual bool HandleResponse(H245_ResponseMessage & Response);
	virtual bool HandleCommand(H245_CommandMessage & Command);
	virtual bool HandleIndication(H245_IndicationMessage & Indication);

private:
	PIPSocket::Address localAddr;
	bool bFromCaller;
};

class CallSignalSocket : public ProxySocket {
public:
	PCLASSINFO ( CallSignalSocket, ProxySocket )

	CallSignalSocket();
	CallSignalSocket(WORD, CallSignalSocket *);
	~CallSignalSocket();

	virtual ProxySocket *ConnectTo();
        virtual Result ReceiveData();
	virtual bool CloseConnection();

	bool HandleH245Mesg(PPER_Stream &, Result &);
	bool SetH245Address(H225_TransportAddress &);
	void DetachH245Socket() { h245socket = 0; }

protected:
	virtual void OnSetup(H225_Setup_UUIE &);
	virtual void OnCallProceeding(H225_CallProceeding_UUIE &);
	virtual void OnConnect(H225_Connect_UUIE &);
	virtual void OnAlerting(H225_Alerting_UUIE &);
	virtual void OnInformation(H225_Information_UUIE &);
	virtual void OnReleaseComplete(H225_ReleaseComplete_UUIE &);
	virtual void OnFacility(H225_Facility_UUIE &);
	virtual void OnProgress(H225_Progress_UUIE &);
	virtual void OnEmpty(H225_H323_UU_PDU_h323_message_body &);
	virtual void OnStatus(H225_Status_UUIE &);
	virtual void OnStatusInquiry(H225_StatusInquiry_UUIE &);
	virtual void OnSetupAcknowledge(H225_SetupAcknowledge_UUIE &);
	virtual void OnNotify(H225_Notify_UUIE &);
	virtual void OnNonStandardData(PASN_OctetString &);
	virtual void OnTunneledH245(H225_H323_UU_PDU &);

protected:
	// localAddr is NOT the local address the socket bind to,
	// but the local address that remote socket bind to
	// they may be different in multi-homed situation
	Address localAddr, peerAddr;
	WORD peerPort;

private:
	void BuildReleasePDU(Q931 &) const;
	template<class UUIE> void InternalSetH245Address(UUIE & uu)
	{
		if (uu.HasOptionalField(UUIE::e_h245Address) && m_h245handler)
			if (!SetH245Address(uu.m_h245Address))
				uu.RemoveOptionalField(UUIE::e_h245Address);
	}
	
	callptr m_call;
	WORD m_crv;
	H245Handler *m_h245handler;
	H245Socket *h245socket;
};

class H245Socket : public ProxySocket {
public:
	PCLASSINFO ( H245Socket, ProxySocket )

	H245Socket(CallSignalSocket *);
	H245Socket(H245Socket *, CallSignalSocket *);
	~H245Socket();

	virtual ProxySocket *ConnectTo();
        virtual Result ReceiveData();
	virtual bool CloseConnection();

	void SetH245Address(H225_TransportAddress & h245addr, Address);

private:
	CallSignalSocket *sigSocket;
	H225_TransportAddress peerH245Addr;
	PTCPSocket *listener;
};

inline bool CallSignalSocket::HandleH245Mesg(PPER_Stream & strm, Result & res)
{
	return m_h245handler->HandleMesg(strm, res);
}

#endif // __proxychannel_h__

