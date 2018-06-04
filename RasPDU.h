//////////////////////////////////////////////////////////////////
//
// RasPDU.h
//
// Define RAS PDU for GNU Gatekeeper
// Avoid including large h225.h in RasSrv.h
//
// Copyright (c) Citron Network Inc. 2001-2003
// Copyright (c) 2006-2015, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef RASPDU_H
#define RASPDU_H "@(#) $Id$"

#include <list>
#include <utility>
#include "yasocket.h"
#include "factory.h"
#include "rasinfo.h"
#include "gkh235.h"
#include <h235auth.h>
#include "RasTbl.h"
#include "Toolkit.h"


class RasListener;
class MulticastListener;
class CallSignalListener;
class TLSCallSignalListener;
class StatusListener;
class MultiplexRTPListener;
class RasServer;
class CallSignalSocket;

const unsigned MaxRasTag = H225_RasMessage::e_serviceControlResponse;

class GatekeeperMessage {
public:
	GatekeeperMessage() : m_peerPort(0), m_socket(NULL)
#ifdef HAS_H46017
		, m_h46017Socket(NULL)
#endif
		{ }
	unsigned GetTag() const { return m_recvRAS.GetTag(); }
	const char *GetTagName() const;
	bool Read(RasListener *);
#ifdef HAS_H46017
	bool Read(const PBYTEArray & buffer);
#endif
	bool Reply(GkH235Authenticators * authenticators);

	PPER_Stream m_rasPDU;
	H225_RasMessage m_recvRAS;
	H225_RasMessage m_replyRAS;
	PIPSocket::Address m_peerAddr;
	WORD m_peerPort;
	PIPSocket::Address m_localAddr;
	RasListener * m_socket;
#ifdef HAS_H46017
	CallSignalSocket * m_h46017Socket;
#endif
};

class RasListener : public UDPSocket {
public:
	RasListener(const Address &, WORD);
	virtual ~RasListener();

	GatekeeperMessage *ReadRas();
	bool SendRas(H225_RasMessage &, const Address &, WORD, GkH235Authenticators * auth);

	WORD GetSignalPort() const { return m_signalPort; }
	void SetSignalPort(WORD pt) { m_signalPort = pt; }
#ifdef HAS_TLS
	WORD GetTLSSignalPort() const { return m_tlsSignalPort; }
	void SetTLSSignalPort(WORD pt) { m_tlsSignalPort = pt; }
#endif

	Address GetLocalAddr(const Address &) const;
	Address GetPhysicalAddr(const Address & addr) const;
	H225_TransportAddress GetRasAddress(const Address &) const;
	H225_TransportAddress GetCallSignalAddress(const Address &) const;

	// new virtual function
	// filter out unwanted message to the listener by returning false
	virtual bool Filter(GatekeeperMessage *) const;

protected:
	Address m_ip;
	PMutex m_wmutex;
	WORD m_signalPort;
#ifdef HAS_TLS
	WORD m_tlsSignalPort;
#endif
	bool m_virtualInterface;
};

class RasMsg : public Task {
public:
	virtual ~RasMsg() { delete m_msg; }

	// new virtual function
	virtual bool Process() = 0;

	virtual int GetSeqNum() const = 0;
	virtual H225_NonStandardParameter *GetNonStandardParam() = 0;

	// override from class Task
	virtual void Exec();

	bool IsFrom(const PIPSocket::Address & addr, WORD pt) const;
	unsigned GetTag() const { return m_msg->GetTag(); }
	const char *GetTagName() const { return m_msg->GetTagName(); }

	/// Get an address the message has been received from
	void GetPeerAddr(PIPSocket::Address & addr, WORD & port) const;
	void GetPeerAddr(PIPSocket::Address & addr) const;

	void GetRasAddress(H225_TransportAddress &) const;
	void GetCallSignalAddress(H225_TransportAddress &) const;

	bool EqualTo(const RasMsg *) const;
	bool operator==(const RasMsg & other) const { return EqualTo(&other); }

	bool Reply(GkH235Authenticators * authenticators) const { return m_msg->Reply(authenticators); }

	GatekeeperMessage *operator->() { return m_msg; }
	const GatekeeperMessage *operator->() const { return m_msg; }
	GatekeeperMessage * GetMsg() const { return m_msg; }

	static void Initialize();
protected:
	RasMsg(GatekeeperMessage * m) : m_msg(m), m_authenticators(NULL) { }
	RasMsg(const RasMsg &);

	static bool PrintStatus(const PString &);

	GatekeeperMessage * m_msg;
	GkH235Authenticators * m_authenticators;

	// just pointers to global singleton objects
	// cache for faster access
	static RegistrationTable *EndpointTbl;
	static CallTable *CallTbl;
	static RasServer *RasSrv;
};

template<class RAS>
class RasPDU : public RasMsg {
public:
	typedef RAS RasClass;

	RasPDU(GatekeeperMessage *m) : RasMsg(m), request(m->m_recvRAS) { }
	virtual ~RasPDU() { }

	// override from class RasMsg
	virtual bool Process() { return false; }
	virtual int GetSeqNum() const { return request.m_requestSeqNum; }
	virtual H225_NonStandardParameter *GetNonStandardParam();

	operator RAS & () { return request; }
	operator const RAS & () const { return request; }

	H225_RasMessage & BuildConfirm();
	H225_RasMessage & BuildReject(unsigned reason);

	void SetupResponseTokens(H225_RasMessage & responsePdu, const endptr & requestingEP);

	typedef Factory<RasMsg, unsigned>::Creator1<GatekeeperMessage *> RasCreator;
	struct Creator : public RasCreator {
		Creator() : RasCreator(RasInfo<RAS>::tag) { }
		virtual RasMsg *operator()(GatekeeperMessage *m) const { return new RasPDU<RAS>(m); }
	};

protected:
	RAS & request;
};

template<class RAS>
void RasPDU<RAS>::SetupResponseTokens(H225_RasMessage & responsePdu, const endptr & requestingEP)
{
	if (m_authenticators == NULL && requestingEP)
		m_authenticators = requestingEP->GetH235Authenticators();

	if (m_authenticators == NULL) {
		return;
	}

	if (GkConfig()->GetBoolean("H235", "UseEndpointIdentifier", true) && requestingEP) {
		m_authenticators->SetProcedure1RemoteId(requestingEP->GetEndpointIdentifier().GetValue());
	}

	typedef typename RasInfo<RAS>::ConfirmTag ConfirmTag;
	typedef typename RasInfo<RAS>::ConfirmType ConfirmType;
	typedef typename RasInfo<RAS>::RejectTag RejectTag;
	typedef typename RasInfo<RAS>::RejectType RejectType;
	if (responsePdu.GetTag() == ConfirmTag()) {
        ConfirmType & confirm = responsePdu;
        m_authenticators->PrepareTokens(responsePdu, confirm.m_tokens, confirm.m_cryptoTokens);

        if (confirm.m_tokens.GetSize() > 0)
            confirm.IncludeOptionalField(ConfirmType::e_tokens);
        if (confirm.m_cryptoTokens.GetSize() > 0)
            confirm.IncludeOptionalField(ConfirmType::e_cryptoTokens);
	} else {
        if (responsePdu.GetTag() != RejectTag())
            responsePdu.SetTag(RejectTag());   // create a Ronfirm if not set
        RejectType & reject = responsePdu;
        m_authenticators->PrepareTokens(responsePdu, reject.m_tokens, reject.m_cryptoTokens);

        if (reject.m_tokens.GetSize() > 0)
            reject.IncludeOptionalField(RejectType::e_tokens);
        if (reject.m_cryptoTokens.GetSize() > 0)
            reject.IncludeOptionalField(RejectType::e_cryptoTokens);
	}
}


// abstract factory for listeners
class GkInterface {
public:
	typedef PIPSocket::Address Address;

	GkInterface(const Address &);
	virtual ~GkInterface();

	// we can't call virtual functions in constructor
	// so initialize here
	virtual bool CreateListeners(RasServer *);

	bool IsBoundTo(const Address *addr) const { return m_address == *addr; }
	bool IsReachable(const Address *) const;

	RasListener *GetRasListener() const { return m_rasListener; }

	WORD GetRasPort() const { return m_rasPort; }
	WORD GetSignalPort() const { return m_signalPort; }
	Address GetAddress() const { return m_address; }

protected:
	bool ValidateSocket(IPSocket *, WORD &);

	template <class Listener> bool SetListener(WORD nport, WORD & oport, Listener *& listener, Listener *(GkInterface::*creator)())
	{
		if (!listener || !oport || oport != nport) {
			oport = nport;
			if (listener)
				listener->Close();
			listener = (this->*creator)();
			if (ValidateSocket(listener, oport))
				return true;
			else
				listener = NULL;
		}
		return false;
	}

	Address m_address;
	RasListener *m_rasListener;
	MulticastListener *m_multicastListener;
	CallSignalListener *m_callSignalListener;
	StatusListener *m_statusListener;
	WORD m_rasPort, m_multicastPort, m_signalPort, m_statusPort;
#ifdef HAS_TLS
	TLSCallSignalListener *m_tlsCallSignalListener;
	WORD m_tlsSignalPort;
#endif
	RasServer *m_rasSrv;

private:
	virtual RasListener *CreateRasListener();
	virtual MulticastListener *CreateMulticastListener();
	virtual CallSignalListener *CreateCallSignalListener();
#ifdef HAS_TLS
	virtual TLSCallSignalListener *CreateTLSCallSignalListener();
#endif
	virtual StatusListener *CreateStatusListener();
};

class RasHandler {
public:
	typedef PIPSocket::Address Address;

	RasHandler();
	virtual ~RasHandler() { }

	// new virtual function

	// check if the message is the expected one
	// default behavior: check if the tag is in m_tagArray
	virtual bool IsExpected(const RasMsg *) const;

	// process the RasMsg object
	// the object must be deleted after processed
	virtual void Process(RasMsg *) = 0;

	// give the derived class an opportunity to create customized PDU
	// default behavior: return the original one
	virtual RasMsg *CreatePDU(RasMsg *ras) { return ras; }

	// stop the handler
	virtual void Stop() {}

protected:
	void AddFilter(unsigned);

	RasServer *m_rasSrv;

private:
	bool m_tagArray[MaxRasTag + 1];
};

// encapsulate a gatekeeper request and reply
class RasRequester : public RasHandler {
public:
	RasRequester() : m_request(NULL) { Init(); }
	// note the H225_RasMessage object must have
	// longer lifetime than this object
	RasRequester(H225_RasMessage &);
	RasRequester(H225_RasMessage &, const Address &);
	virtual ~RasRequester();

	WORD GetSeqNum() const { return m_seqNum; }
	bool WaitForResponse(int timeout);
	RasMsg *GetReply();

	// override from class RasHandler
	virtual bool IsExpected(const RasMsg *) const;
	virtual void Process(RasMsg *);
	virtual void Stop();

	// new virtual function
	virtual bool SendRequest(const Address &, WORD, int retry = 2);
	virtual bool OnTimeout();

protected:
	void AddReply(RasMsg *);

	H225_RasMessage *m_request;
	WORD m_seqNum;
	Address m_txAddr, m_loAddr;
	WORD m_txPort;
	PTime m_sentTime;
	int m_timeout, m_retry;
	PSyncPoint m_sync;

private:
	void Init();

	PMutex m_qmutex;
	std::list<RasMsg *> m_queue;
	std::list<RasMsg *>::iterator m_iterator;
};

template<class RAS>
class Requester : public RasRequester {
public:
	typedef typename RasInfo<RAS>::Tag Tag;
	typedef typename RasInfo<RAS>::ConfirmTag ConfirmTag;
	typedef typename RasInfo<RAS>::RejectTag RejectTag;
	Requester(H225_RasMessage &, const Address &);
	virtual ~Requester()
	{
		typedef typename std::pair< RasServer*, RAS* >::first_type RasServerPtr;
		static_cast< RasServerPtr >(this->m_rasSrv)->UnregisterHandler(this); // fix for GCC 3.4.2
	}
};

template<class RAS>
Requester<RAS>::Requester(H225_RasMessage & obj_ras, const Address & ip) : RasRequester(obj_ras, ip)
{
	obj_ras.SetTag(Tag());
	RAS & ras = obj_ras;
	ras.m_requestSeqNum = GetSeqNum();
	AddFilter(ConfirmTag());
	AddFilter(RejectTag());

	typedef typename std::pair< RasServer*, RAS* >::first_type RasServerPtr;
	static_cast< RasServerPtr >(this->m_rasSrv)->RegisterHandler(this); // fix for GCC 3.4.2
}

#endif // RASPDU_H
