//////////////////////////////////////////////////////////////////
//
// RasPDU.h
//
// Define RAS PDU for GNU Gatekeeper
// Avoid including large h225.h in RasSrv.h
//
// Copyright (c) Citron Network Inc. 2001-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 05/02/2003
//
//////////////////////////////////////////////////////////////////

#ifndef RASPDU_H
#define RASPDU_H "@(#) $Id$"

#include "yasocket.h"
#include "factory.h"
#include "rasinfo.h"


class Toolkit;
class GkStatus;
class RegistrationTable;
class CallTable;
class RasListener;
class MulticastListener;
class CallSignalListener;
class StatusListener;
class RasServer;

const unsigned MaxRasTag = H225_RasMessage::e_serviceControlResponse;

struct GatekeeperMessage {
	PPER_Stream m_rasPDU;
	H225_RasMessage m_recvRAS;
	H225_RasMessage m_replyRAS;
	PIPSocket::Address m_peerAddr;
	WORD m_peerPort;
	PIPSocket::Address m_localAddr;
	RasListener *m_socket;

	unsigned GetTag() const { return m_recvRAS.GetTag(); }
	const char *GetTagName() const;
	bool Read(RasListener *);
	bool Reply() const;
};

class RasListener : public UDPSocket {
public:
	RasListener(const Address &, WORD);
	~RasListener();

	GatekeeperMessage *ReadRas();
	bool SendRas(const H225_RasMessage &, const Address &, WORD);

	WORD GetSignalPort() const { return m_signalPort; }
	void SetSignalPort(WORD pt) { m_signalPort = pt; }

	Address GetLocalAddr(const Address &) const;
	H225_TransportAddress GetRasAddress(const Address &) const;
	H225_TransportAddress GetCallSignalAddress(const Address &) const;

	// new virtual function
	// filter out unwanted message to the listener by returning false
	virtual bool Filter(GatekeeperMessage *) const;

protected:
	Address m_ip;
	PMutex m_wmutex;
	WORD m_signalPort;
	bool m_virtualInterface;
};

class RasMsg : public Task {
public:
	virtual ~RasMsg() { delete m_msg; } //PTRACE(1, "Delete " << m_msg->GetTagName()); }

	// new virtual function
	virtual bool Process() = 0;

	virtual int GetSeqNum() const = 0;
	virtual H225_NonStandardParameter *GetNonStandardParam() = 0;

	// override from class Task
	virtual void Exec();

	bool IsFrom(const PIPSocket::Address &, WORD) const;
	void GetRecvAddress(PIPSocket::Address &, WORD &) const;
	unsigned GetTag() const { return m_msg->GetTag(); }
	const char *GetTagName() const { return m_msg->GetTagName(); }

	void GetRasAddress(H225_TransportAddress &) const;
	void GetCallSignalAddress(H225_TransportAddress &) const;

	bool EqualTo(const RasMsg *) const;
	bool operator==(const RasMsg & other) const { return EqualTo(&other); }

	bool Reply() const { return m_msg->Reply(); }

	GatekeeperMessage *operator->() { return m_msg; }
	const GatekeeperMessage *operator->() const { return m_msg; }
	void Release();

	static void Initialize();

protected:
	RasMsg(GatekeeperMessage *m) : m_msg(m) {}
	RasMsg(const RasMsg &);

	static bool PrintStatus(const PString &);
	
	GatekeeperMessage *m_msg;

	// just pointers to global singleton objects
	// cache for faster access
	static Toolkit *Kit;
	static GkStatus *StatusPort;
	static RegistrationTable *EndpointTbl;
	static CallTable *CallTbl; 
	static RasServer *RasSrv;
};

template<class RAS>
class RasPDU : public RasMsg {
public:
	RasPDU(GatekeeperMessage *m) : RasMsg(m), request(m->m_recvRAS) {}

	// override from class RasMsg
	virtual bool Process() { return false; }
	virtual int GetSeqNum() const { return request.m_requestSeqNum; }
	virtual H225_NonStandardParameter *GetNonStandardParam();

	operator RAS & () { return request; }
	operator const RAS & () const { return request; }

	H225_RasMessage & BuildConfirm();
	H225_RasMessage & BuildReject(unsigned);

	typedef Factory<RasMsg, unsigned>::Creator1<GatekeeperMessage *> RasCreator;
	struct Creator : public RasCreator {
		Creator() : RasCreator(RasInfo<RAS>::tag) {}
		virtual RasMsg *operator()(GatekeeperMessage *m) const { return new RasPDU<RAS>(m); }
	};

protected:
	RAS & request;
};

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
	MulticastListener *GetMulticastListener() const { return m_multicastListener; }
	CallSignalListener *GetCallSignalListener() const { return m_callSignalListener; }
	StatusListener *GetStatusListener() const { return m_statusListener; }

	WORD GetRasPort() const { return m_rasPort; }
	WORD GetMulticastPort() const { return m_multicastPort; }
	WORD GetSignalPort() const { return m_signalPort; }
	WORD GetStatusPort() const { return m_statusPort; }

protected:
	bool ValidateSocket(IPSocket *, WORD &);

	template <class Listener> void SetListener(WORD nport, WORD & oport, Listener *& listener, Listener *(GkInterface::*creator)())
	{
		if (!oport || oport != nport) {
			oport = nport;
			if (listener)
				listener->Close();
			listener = (this->*creator)();
			if (ValidateSocket(listener, oport))
				m_rasSrv->AddListener(listener);
			else
				listener = 0;
		}
	}

	Address m_address;
	RasListener *m_rasListener;
	MulticastListener *m_multicastListener;
	CallSignalListener *m_callSignalListener;
	StatusListener *m_statusListener;
	WORD m_rasPort, m_multicastPort, m_signalPort, m_statusPort;
	RasServer *m_rasSrv;

private:
	virtual RasListener *CreateRasListener();
	virtual MulticastListener *CreateMulticastListener();
	virtual CallSignalListener *CreateCallSignalListener();
	virtual StatusListener *CreateStatusListener();
};

class RasHandler {
public:
	typedef PIPSocket::Address Address;

	RasHandler();
	virtual ~RasHandler() {}

	// new virtual function

	// check if the message is the expected one
	// default behavior: check if the tag is in m_tagArray
	virtual bool IsExpected(const RasMsg *) const;

	// process the RasMsg object
	// the object must be deleted after processed
	virtual void Process(RasMsg *) = 0;

	// give the derived class an opportunity to create customized PDU
	// default behavior: return the original one
	// Note: call RasMsg::Release() if new one is created
	virtual RasMsg *CreatePDU(RasMsg *ras) { return ras; }

	// stop the handler
	virtual void Stop() {}

protected:
	void AddFilter(unsigned);

	RasServer *m_rasSrv;

private:
	// delete the object after running RasMsg::Exec()
	static void ProcessRAS(RasMsg *);

	bool m_tagArray[MaxRasTag + 1];
};

// encapsulate a gatekeeper request and reply
class RasRequester : public RasHandler {
public:
	RasRequester() { Init(); }
	// note the H225_RasMessage object must have
	// longer lifetime than this object
	RasRequester(H225_RasMessage &);
	RasRequester(H225_RasMessage &, const Address &);
	~RasRequester();

	WORD GetSeqNum() const { return m_seqNum; }
	bool WaitForResponse(int);
	RasMsg *GetReply();

	// override from class RasHandler
	virtual bool IsExpected(const RasMsg *) const;
	virtual void Process(RasMsg *);
	virtual void Stop();

	// new virtual function
	virtual bool SendRequest(const Address &, WORD, int = 2);
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
	~Requester() { m_rasSrv->UnregisterHandler(this); }
};

template<class RAS>
Requester<RAS>::Requester(H225_RasMessage & obj_ras, const Address & ip) : RasRequester(obj_ras, ip)
{
	obj_ras.SetTag(Tag());
	RAS & ras = obj_ras;
	ras.m_requestSeqNum = GetSeqNum();
	AddFilter(ConfirmTag());
	AddFilter(RejectTag());
	m_rasSrv->RegisterHandler(this);
}

/*****************************************************************

The template class let you to modify the default handler of a
given RAS message. Just explicitly specialize the Process method.
For example,

template<> bool HookedPDU<H225_RegistrationRequest>::Process()
{
	do_something_before_process();
	// call the default handler
	bool result = m_opdu->Process();
	do_something_after_process();
	return result;
}

Then add a creator to hook the interested messages

	HookedPDU<H225_RegistrationRequest>::Creator HookedRRQ;

Note the creator must be executed after RasServer::Run().

*****************************************************************/

template<class RAS>
class HookedPDU : public RasPDU<RAS> {
public:
	HookedPDU(GatekeeperMessage *m, RasMsg *p) : RasPDU<RAS>(m), m_opdu(p) {}
	~HookedPDU() { m_opdu->Release(); }

	virtual bool Process() { return m_opdu->Process(); }

	struct Creator : public RasPDU<RAS>::Creator {
		Creator() { PAssert(m_old, "Error: Hook failed"); }
		virtual RasMsg *operator()(GatekeeperMessage *m) const
		{ return new HookedPDU<RAS>(m, dynamic_cast<RasCreator &>(*m_old)(m)); }
	};

private:
	RasMsg *m_opdu;
};

#endif // RASPDU_H
