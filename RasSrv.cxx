//////////////////////////////////////////////////////////////////
//
// New RAS Server for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2001-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 03/14/2003
//
//////////////////////////////////////////////////////////////////

#if defined(_WIN32) && (_MSC_VER <= 1200)
#pragma warning(disable:4786) // warning about too long debug symbol off
#pragma warning(disable:4284)
#endif

#include <ptlib.h>
#include <ptlib/sockets.h>
#include <h225.h>
#include <h323pdu.h>
#include "gk.h"
#include "gk_const.h"
#include "stl_supp.h"
#include "RasPDU.h"
#include "RasTbl.h"
#include "SoftPBX.h"
#include "Routing.h"
#include "GkClient.h"
#include "GkStatus.h"
#include "Neighbor.h"
#include "ProxyChannel.h"
#include "gkauth.h"
#include "gkacct.h"
#include "gktimer.h"
#include "RasSrv.h"
#include "pwlib_compat.h"

#ifdef hasH460
  #include <h460/h4601.h>
#endif

const char *LRQFeaturesSection = "RasSrv::LRQFeatures";
const char *RRQFeatureSection = "RasSrv::RRQFeatures";
using namespace std;
using Routing::Route;

#ifndef NEED_BROADCASTLISTENER
#if (defined P_LINUX) || (defined P_FREEBSD) || (defined P_HPUX9) || (defined P_SOLARIS)
// On some OS we don't get broadcasts on a socket that is
// bound to a specific interface. For those we have to start
// a listener just for those broadcasts.
// On Windows NT we get all messages on the RAS socket, even
// if it's bound to a specific interface and thus don't have
// to start a listener for broadcast.
#define NEED_BROADCASTLISTENER 1
#else
#define NEED_BROADCASTLISTENER 0
#endif
#endif


class RegistrationRequestPDU : public RasPDU<H225_RegistrationRequest> {
public:
	RegistrationRequestPDU(GatekeeperMessage *m) : RasPDU<H225_RegistrationRequest>(m) {}

	// override from class RasPDU<H225_RegistrationRequest>
	virtual bool Process();

	struct Creator : public RasPDU<H225_RegistrationRequest>::Creator {
		virtual RasMsg *operator()(GatekeeperMessage *m) const { return new RegistrationRequestPDU(m); }
	};
private:
	bool BuildRCF(const endptr &);
	bool BuildRRJ(unsigned, bool = false);
};

class AdmissionRequestPDU : public RasPDU<H225_AdmissionRequest> {
public:
	AdmissionRequestPDU(GatekeeperMessage *m) : RasPDU<H225_AdmissionRequest>(m) {}

	// override from class RasPDU<H225_AdmissionRequest>
	virtual bool Process();

	struct Creator : public RasPDU<H225_AdmissionRequest>::Creator {
		virtual RasMsg *operator()(GatekeeperMessage *m) const { return new AdmissionRequestPDU(m); }
	};
private:
	enum {
		e_acf = -1,
		e_routeRequest = -2
	};
	bool BuildReply(int);

	/** @return
	    A string that can be used to identify a calling number.
	*/
	PString GetCallingStationId(
		/// additional data, like call record and requesting endpoint
		ARQAuthData& authData
		) const;

	/** @return
	    A string that can be used to identify a calling number.
	*/
	PString GetCalledStationId(
		/// additional data, like call record and requesting endpoint
		ARQAuthData& authData
		) const;

	/** @return
	    A string that can be used to identify the billing number.
	*/
	PString GetCallLinkage(
		/// additional data, like call record and requesting endpoint
		ARQAuthData& authData
		) const;

	endptr RequestingEP, CalledEP;
	PString destinationString;
};

template<> H225_NonStandardParameter *RasPDU<H225_UnknownMessageResponse>::GetNonStandardParam()
{
	return 0;
}

// RAS message abbreviations
const char *RasName[] = {
	"GRQ",				// Gatekeeper Request
	"GCF",				// Gatekeeper Confirm
	"GRJ",				// Gatekeeper Reject
	"RRQ",				// Registration Request
	"RCF",				// Registration Confirm
	"RRJ",				// Registration Reject
	"URQ",				// Unregistration Request
	"UCF",				// Unregistration Confirm
	"URJ",				// Unregistration Reject
	"ARQ",				// Admission Request
	"ACF",				// Admission Confirm
	"ARJ",				// Admission Reject
	"BRQ",				// Bandwidth Request
	"BCF",				// Bandwidth Confirm
	"BRJ",				// Bandwidth Reject
	"DRQ",				// Disengage Request
	"DCF",				// Disengage Confirm
	"DRJ",				// Disengage Reject
	"LRQ",				// Location Request
	"LCF",				// Location Confirm
	"LRJ",				// Location Reject
	"IRQ",				// Infomation Request
	"IRR",				// Infomation Request Response
	"NonStandardMessage",
	"UnknownMessageResponse",
	"RIP",				// Request In Progress
	"RAI",				// Resources Available Indicate
	"RAC",				// Resources Available Confirm
	"IACK",				// Infomation Request Acknowledgement
	"INAK",				// Infomation Request Negative Acknowledgement
	"SCI",				// Service Control Indication
	"SCR",				// Service Control Response
	"NotRecognized"		// for new messages not recognized by the supported
						// H.323 version
};

// struct GatekeeperMessage
const char *GatekeeperMessage::GetTagName() const
{
	return (GetTag() <= MaxRasTag) ? RasName[GetTag()] : RasName[MaxRasTag+1];
}

bool GatekeeperMessage::Read(RasListener *socket)
{
	m_socket = socket;
	const int buffersize = 4096;
	BYTE buffer[buffersize];
	if (!socket->Read(buffer, buffersize)) {
		PTRACE(1, "RAS\tRead error " << socket->GetErrorCode(PSocket::LastReadError)
			<< '/' << socket->GetErrorNumber(PSocket::LastReadError) << ": "
			<< socket->GetErrorText(PSocket::LastReadError)
			);
		return false;
	}
	socket->GetLastReceiveAddress(m_peerAddr, m_peerPort);
	PTRACE(2, "RAS\tRead from " << m_peerAddr << ':' << m_peerPort);
	m_rasPDU = PPER_Stream(buffer, socket->GetLastReadCount());
	bool result = m_recvRAS.Decode(m_rasPDU);
	PTRACE_IF(1, !result, "RAS\tCould not decode message from " << m_peerAddr << ':' << m_peerPort);
	return result;
}

bool GatekeeperMessage::Reply() const
{
	return m_socket->SendRas(m_replyRAS, m_peerAddr, m_peerPort);
}


// class RasListener
RasListener::RasListener(const Address & addr, WORD pt) : m_ip(addr)
{
	if (!Listen(addr, 0, pt, PSocket::CanReuseAddress)) {
		PTRACE(1, "RAS\tCould not open listening socket at " << addr << ':' << pt
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< GetErrorNumber(PSocket::LastGeneralError) << ": " 
			<< GetErrorText(PSocket::LastGeneralError)
			);
		Close();
	}
	SetWriteTimeout(1000); // TODO: read from config
	SetName(AsString(addr, pt) + "(U)");
	m_signalPort = 0;
	// note: this won't be affected by reloading
	m_virtualInterface = GkConfig()->HasKey("NetworkInterfaces");
    // Check if we have external IP setting 
	if (!m_virtualInterface)  
		m_virtualInterface = GkConfig()->HasKey("ExternalIP");
}

RasListener::~RasListener()
{
	PTRACE(1, "RAS\tDelete listener " << GetName());
}

GatekeeperMessage *RasListener::ReadRas()
{
	PTRACE(4, "RAS\tReceiving on " << GetName());
	GatekeeperMessage *msg = new GatekeeperMessage;
	if (!(msg->Read(this) && Filter(msg))) {
		delete msg;
		return 0;
	}
#if PTRACING
	if (PTrace::CanTrace(3))
		PTRACE(3, "RAS\n" << setprecision(2) << msg->m_recvRAS);
	else
		PTRACE(2, "RAS\tReceived " << msg->GetTagName());
#endif
	msg->m_localAddr = GetLocalAddr(msg->m_peerAddr);
	return msg;
}

bool RasListener::SendRas(const H225_RasMessage & rasobj, const Address & addr, WORD pt)
{
#if PTRACING
	if (PTrace::CanTrace(3))
		PTRACE(3, "RAS\tSend to " << addr << ':' << pt << '\n' << setprecision(2) << rasobj);
	else
		PTRACE(2, "RAS\tSend " << RasName[rasobj.GetTag()] << " to " << addr << ':' << pt);
#endif

	PPER_Stream wtstrm;
	rasobj.Encode(wtstrm);
	wtstrm.CompleteEncoding();

	m_wmutex.Wait();
	bool result = WriteTo(wtstrm.GetPointer(), wtstrm.GetSize(), addr, pt);
	m_wmutex.Signal();
#if PTRACING
	if (result)
		PTRACE(5, "RAS\tSent Successful");
	else
		PTRACE(1, "RAS\tWrite error " << GetErrorCode(PSocket::LastWriteError) << '/'
			<< GetErrorNumber(PSocket::LastWriteError) << ": "
			<< GetErrorText(PSocket::LastWriteError)
			);
#endif
	return result;
}

PIPSocket::Address RasListener::GetPhysicalAddr(const Address & addr) const
{
	// Return the physical address. This is used when setting sockets
	return m_ip;
}

PIPSocket::Address RasListener::GetLocalAddr(const Address & addr) const
{
	return m_virtualInterface ? Toolkit::Instance()->GetRouteTable()->GetLocalAddress(addr) : m_ip;
}

H225_TransportAddress RasListener::GetRasAddress(const Address & addr) const
{
	return SocketToH225TransportAddr(GetLocalAddr(addr), GetPort());
}

H225_TransportAddress RasListener::GetCallSignalAddress(const Address & addr) const
{
	return SocketToH225TransportAddr(GetLocalAddr(addr), m_signalPort);
}

bool RasListener::Filter(GatekeeperMessage *msg) const
{
	unsigned tag = msg->GetTag();
	if (tag <= MaxRasTag)
		return true;
	PTRACE(1, "RAS\tInvalid RAS message tag " << tag);
	return false;
}


// class BroadcastListener
class BroadcastListener : public RasListener {
public:
	BroadcastListener(WORD);

	// override from class RasListener
	virtual bool Filter(GatekeeperMessage *) const;
};

BroadcastListener::BroadcastListener(WORD pt) : RasListener(INADDR_ANY, pt)
{
	SetName(AsString(INADDR_ANY, pt) + "(Bcast)");
	m_virtualInterface = true;
}

bool BroadcastListener::Filter(GatekeeperMessage *msg) const
{
	const unsigned tag = msg->GetTag();
	if (tag == H225_RasMessage::e_gatekeeperRequest
		|| tag == H225_RasMessage::e_locationRequest)
		return true;
	PTRACE(1, "RAS\tUnknown broadcasted RAS message tag " << tag);
	return false;
}


// class MulticastListener
class MulticastListener : public RasListener {
public:
	MulticastListener(const Address &, WORD, WORD);

	// override from class RasListener
	virtual bool Filter(GatekeeperMessage *) const;
};

MulticastListener::MulticastListener(const Address & addr, WORD pt, WORD upt) : RasListener(addr, pt)
{
	SetName(AsString(addr, pt) + "(Mcast)");
	Address multiaddr(GkConfig()->GetString("MulticastGroup", GK_DEF_MULTICAST_GROUP));
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = multiaddr;
	mreq.imr_interface.s_addr = addr;
	if (::setsockopt(GetHandle(), IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
		PTRACE(1, "RAS\tCan't join multicast group " << multiaddr);
		Close();
	}
	port = upt; // unicast port
}

bool MulticastListener::Filter(GatekeeperMessage *msg) const
{
	unsigned tag = msg->GetTag();
	if (tag == H225_RasMessage::e_gatekeeperRequest
		|| tag == H225_RasMessage::e_locationRequest)
		return true;
	PTRACE(1, "RAS\tInvalid multicasted RAS message tag " << tag);
	return false;
}


// class RasMsg
void RasMsg::Exec()
{
	PTRACE(1, "RAS\t" << m_msg->GetTagName() << " Received");
	if (Process())
		Reply();
}

bool RasMsg::IsFrom(const PIPSocket::Address & addr, WORD pt) const
{
	return (addr == m_msg->m_peerAddr) && (pt == 0 || pt == m_msg->m_peerPort);
}

void RasMsg::GetRecvAddress(PIPSocket::Address & addr, WORD & pt) const
{
	addr = m_msg->m_peerAddr, pt = m_msg->m_peerPort;
}

void RasMsg::GetRasAddress(H225_TransportAddress & result) const
{
	result = SocketToH225TransportAddr(m_msg->m_localAddr, m_msg->m_socket->GetPort());
}

void RasMsg::GetCallSignalAddress(H225_TransportAddress & result) const
{
	result = SocketToH225TransportAddr(m_msg->m_localAddr, m_msg->m_socket->GetSignalPort());
}

bool RasMsg::EqualTo(const RasMsg *other) const
{
	if (GetTag() != other->GetTag())
		return false;
	if (GetSeqNum() != other->GetSeqNum())
		return false;
	if ((m_msg->m_peerPort != other->m_msg->m_peerPort) || (m_msg->m_peerAddr != other->m_msg->m_peerAddr))
		return false;
	// should we check the whole PDU?
	return true;
}

void RasMsg::Release()
{
	m_msg = 0;
	delete this;
}

bool RasMsg::PrintStatus(const PString & log)
{
	PTRACE(2, log);
	StatusPort->SignalStatus(log + "\r\n", STATUS_TRACE_LEVEL_RAS);
	return true; // reply after logged
}


template<class ORAS, class DRAS>
inline void CopyNonStandardData(const ORAS & omsg, DRAS & dmsg)
{
	if (omsg.HasOptionalField(ORAS::e_nonStandardData)) {
		dmsg.IncludeOptionalField(DRAS::e_nonStandardData);
		dmsg.m_nonStandardData = omsg.m_nonStandardData;
	}
}


// template class RasPDU
template<class RAS>
H225_NonStandardParameter *RasPDU<RAS>::GetNonStandardParam()
{
	return request.HasOptionalField(RAS::e_nonStandardData) ? &request.m_nonStandardData : 0;
}

template<class RAS>
inline H225_RasMessage & RasPDU<RAS>::BuildConfirm()
{
	typedef typename RasInfo<RAS>::ConfirmTag ConfirmTag;
	typedef typename RasInfo<RAS>::ConfirmType ConfirmType;
	unsigned tag = ConfirmTag();
	if (m_msg->m_replyRAS.GetTag() != tag)
		m_msg->m_replyRAS.SetTag(tag);
	ConfirmType & confirm = m_msg->m_replyRAS;
	confirm.m_requestSeqNum = request.m_requestSeqNum;
//	CopyNonStandardData(request, confirm);
	return m_msg->m_replyRAS;
}

template<class RAS>
inline H225_RasMessage & RasPDU<RAS>::BuildReject(unsigned reason)
{
	typedef typename RasInfo<RAS>::RejectTag RejectTag;
	typedef typename RasInfo<RAS>::RejectType RejectType;
	unsigned tag = RejectTag();
	if (m_msg->m_replyRAS.GetTag() != tag)
		m_msg->m_replyRAS.SetTag(tag);
	RejectType & reject = m_msg->m_replyRAS;
	reject.m_requestSeqNum = request.m_requestSeqNum;
	reject.m_rejectReason.SetTag(reason);
//	CopyNonStandardData(request, reject);
	return m_msg->m_replyRAS;
}


// class GkInterface
GkInterface::GkInterface(const PIPSocket::Address & addr) : m_address(addr)
{
	m_rasPort = m_multicastPort = m_signalPort = m_statusPort = 0;
	m_rasListener = 0;
	m_multicastListener = 0;
	m_callSignalListener = 0;
	m_statusListener = 0;
}

GkInterface::~GkInterface()
{
	if (m_rasListener)
		m_rasListener->Close();
	if (m_multicastListener)
		m_multicastListener->Close();
	if (m_callSignalListener)
		m_rasSrv->CloseListener(m_callSignalListener);
	if (m_statusListener)
		m_rasSrv->CloseListener(m_statusListener);
}

bool GkInterface::CreateListeners(RasServer *RasSrv)
{
	m_rasSrv = RasSrv;

	WORD rasPort = (WORD)GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT);
	WORD multicastPort = (WORD)(Toolkit::AsBool(GkConfig()->GetString("UseMulticastListener", "1")) ?
		GkConfig()->GetInteger("MulticastPort", GK_DEF_MULTICAST_PORT) : 0);
	WORD signalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_CALL_SIGNAL_PORT);
	WORD statusPort = (WORD)GkConfig()->GetInteger("StatusPort", GK_DEF_STATUS_PORT);

	if (SetListener(rasPort, m_rasPort, m_rasListener, &GkInterface::CreateRasListener))
		m_rasSrv->AddListener(m_rasListener);
	if (SetListener(multicastPort, m_multicastPort, m_multicastListener, &GkInterface::CreateMulticastListener))
		m_rasSrv->AddListener(m_multicastListener);
	if (SetListener(signalPort, m_signalPort, m_callSignalListener, &GkInterface::CreateCallSignalListener))
		m_rasSrv->AddListener(m_callSignalListener);
	if (SetListener(statusPort, m_statusPort, m_statusListener, &GkInterface::CreateStatusListener))
		m_rasSrv->AddListener(m_statusListener);

	// MulticastListener::GetPort() didn't return the real multicast port
	m_multicastPort = multicastPort;
	if (m_rasListener && m_callSignalListener)
		if (RasSrv->IsGKRouted()) {
			m_rasListener->SetSignalPort(m_signalPort);
			if (m_multicastListener)
				m_multicastListener->SetSignalPort(m_signalPort);
		} else
			RasSrv->CloseListener(m_callSignalListener), m_callSignalListener = 0;

	return m_rasListener != 0;
}

bool GkInterface::IsReachable(const Address *addr) const
{
	return Toolkit::Instance()->GetRouteTable(true)->GetLocalAddress(*addr) == m_address;
}

bool GkInterface::ValidateSocket(IPSocket *socket, WORD & port)
{
	if (socket) {
		if (socket->IsOpen()) {
			PTRACE(1, "Listening to " << socket->GetName());
			// get the real bound port
			port = socket->GetPort();
			return true;
		} else {
			PTRACE(1, "Can't listen to " << socket->GetName());
			delete socket;
			socket = NULL;
		}
	}
	return false;
}

RasListener *GkInterface::CreateRasListener()
{
	return new RasListener(m_address, m_rasPort);
}

MulticastListener *GkInterface::CreateMulticastListener()
{
	return (m_multicastPort && !IsLoopback(m_address)) ? new MulticastListener(m_address, m_multicastPort, m_rasPort) : 0;
}

CallSignalListener *GkInterface::CreateCallSignalListener()
{
	return m_rasSrv->IsGKRouted() ? new CallSignalListener(m_address, m_signalPort) : 0;
}

StatusListener *GkInterface::CreateStatusListener()
{
	return new StatusListener(m_address, m_statusPort);
}


// class RasHandler
RasHandler::RasHandler()
{
	m_rasSrv = RasServer::Instance();
	fill(m_tagArray, m_tagArray + MaxRasTag + 1, false);
	// can't register now since virtual function table is not ready
	//m_rasSrv->RegisterHandler(this);
}

bool RasHandler::IsExpected(const RasMsg *ras) const
{
	return m_tagArray[ras->GetTag()];
}

void RasHandler::AddFilter(unsigned tag)
{
	m_tagArray[tag] = true;
}

void RasHandler::ProcessRAS(RasMsg *ras)
{
	ras->Exec();
	delete ras;
	ras = NULL;
}

// class RasRequester
RasRequester::RasRequester(H225_RasMessage & req) : m_request(&req), m_loAddr(INADDR_ANY)
{
	Init();
}

RasRequester::RasRequester(H225_RasMessage & req, const Address & addr) : m_request(&req), m_loAddr(addr)
{
	Init();
}

void RasRequester::Init()
{
	m_seqNum = m_rasSrv->GetRequestSeqNum();
	m_iterator = m_queue.end();
	AddFilter(H225_RasMessage::e_requestInProgress);
}

RasRequester::~RasRequester()
{
	m_sync.Signal();
	DeleteObjectsInContainer(m_queue);
}

bool RasRequester::WaitForResponse(int timeout)
{
	m_timeout = timeout;
	while (m_iterator == m_queue.end()) {
		int passed = (int)((PTime() - m_sentTime).GetMilliSeconds());
		if (m_timeout > passed && m_sync.Wait(m_timeout - passed))
			if (m_timeout > 0)
				continue;
			else
				break;
		if (!OnTimeout())
			break;
	}
	return m_iterator != m_queue.end();
}

RasMsg *RasRequester::GetReply()
{
	PWaitAndSignal lock(m_qmutex);
	return m_iterator != m_queue.end() ? *m_iterator++ : 0;
}

bool RasRequester::IsExpected(const RasMsg *ras) const
{
	return RasHandler::IsExpected(ras) && (ras->GetSeqNum() == m_seqNum) && ras->IsFrom(m_txAddr, m_txPort);
}

void RasRequester::Process(RasMsg *ras)
{
	if (ras->GetTag() == H225_RasMessage::e_requestInProgress) {
		H225_RequestInProgress & rip = (*ras)->m_recvRAS;
		m_timeout = rip.m_delay;
		m_sentTime = PTime();
		delete ras;
		ras = NULL;
	} else {
		AddReply(ras);
		m_timeout = 0;
	}

	m_sync.Signal();
}

void RasRequester::Stop()
{
	m_timeout = 0;
	m_iterator = m_queue.end();
	m_sync.Signal();
}

bool RasRequester::SendRequest(const PIPSocket::Address & addr, WORD pt, int r)
{
	m_txAddr = addr, m_txPort = pt, m_retry = r;
	m_sentTime = PTime();
	return m_rasSrv->SendRas(*m_request, m_txAddr, m_txPort, m_loAddr);
}

bool RasRequester::OnTimeout()
{
	return m_retry > 0 ? SendRequest(m_txAddr, m_txPort, --m_retry) : false;
}

void RasRequester::AddReply(RasMsg *ras)
{
	PWaitAndSignal lock(m_qmutex);
	m_queue.push_back(ras);
	if (m_iterator == m_queue.end())
		--m_iterator;
}


// class RasServer
RasServer::RasServer() : Singleton<RasServer>("RasSrv"), requestSeqNum(0),
	acctList(NULL)
{
	SetName("RasSrv");

	authList = 0;
	sigHandler = 0;
	broadcastListener = 0;
	GKRoutedSignaling = false;
	GKRoutedH245 = false;
	altGKs = new H225_ArrayOf_AlternateGK;
}

RasServer::~RasServer()
{
	delete vqueue;
	delete authList;
	delete acctList;
	delete neighbors;
	delete gkClient;
	delete altGKs;
	DeleteObjectsInContainer(requests);
}

void RasServer::Stop()
{
	PTRACE(1, "GK\tStopping RasServer...");
	PWaitAndSignal lock(m_deletionPreventer);
	ForEachInContainer(handlers, mem_vfun(&RasHandler::Stop));
	RegularJob::Stop();
}

// set the signaling mode according to the config file
// don't change it if not specified in the config
void RasServer::SetRoutedMode()
{
	if (GkConfig()->HasKey(RoutedSec, "GKRouted"))
		GKRoutedSignaling = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "GKRouted", "0"));
	if (GkConfig()->HasKey(RoutedSec, "H245Routed"))
		GKRoutedH245 = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "H245Routed", "0"));
	SetRoutedMode(GKRoutedSignaling, GKRoutedH245);
}

void RasServer::SetRoutedMode(bool routedSignaling, bool routedH245)
{
	GKRoutedSignaling = routedSignaling;
	if (GKRoutedSignaling) {
		if (sigHandler)
			sigHandler->LoadConfig();
		else
			sigHandler = new HandlerList;
	} else {
		// warning: dangerous
		delete sigHandler;
		sigHandler = NULL;
	}
	GKRoutedH245 = GKRoutedSignaling ? routedH245 : false;

#if PTRACING
	const char *modemsg = GKRoutedSignaling ? "Routed" : "Direct";
	const char *h245msg = GKRoutedH245 ? "Enabled" : "Disabled";
	PTRACE(2, "GK\tUsing " << modemsg << " Signalling");
	PTRACE(2, "GK\tH.245 Routed " << h245msg);
#endif
}

bool RasServer::AcceptUnregisteredCalls(const PIPSocket::Address & addr) const
{
	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AcceptUnregisteredCalls", "0")))
		return true;
	return Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AcceptNeighborsCalls", "1")) ? neighbors->CheckIP(addr) : false;
}

bool RasServer::RegisterHandler(RasHandler *handler)
{
	PWaitAndSignal lock(hmutex);
	handlers.push_front(handler);
	return true;
}

bool RasServer::UnregisterHandler(RasHandler *handler)
{
	PWaitAndSignal lock(hmutex);
	handlers.remove(handler);
	return true;
}

void RasServer::Check()
{
	gkClient->CheckRegistration();
}

void RasServer::LoadConfig()
{
	GetAlternateGK();

	vector<Address> GKHome;
	PString Home(Toolkit::Instance()->GetGKHome(GKHome));
	PTRACE(2, "GK\tHome = " << Home);

	bool bUseBroadcastListener = Toolkit::AsBool(GkConfig()->GetString("UseBroadcastListener", "1"));
	int hsize = GKHome.size();
	if (hsize == 0) {
		PTRACE(1, "Error: No interface for RAS?");
		return;
	}

	SocketsReader::CleanUp();
	ifiterator biter = interfaces.begin();
	while (biter != interfaces.end()) {
		ifiterator iter = biter++;
		int i = -1;
		while (++i < hsize)
			if ((*iter)->IsBoundTo(&GKHome[i]))
				break;
		if (i == hsize) {
			// close unused listeners
			GkInterface * r = *iter;
			interfaces.erase(iter);
			delete r;
			biter = interfaces.begin();
		}
	}
	if (broadcastListener && !bUseBroadcastListener) {
		broadcastListener->Close();
		broadcastListener = 0;
	}

	RemoveClosed(false); // delete the closed sockets next time

	for (int i = 0; i < hsize; ++i) {
		Address addr(GKHome[i]);
		biter = interfaces.begin();
		ifiterator iter = find_if(biter, interfaces.end(), bind2nd(mem_fun(&GkInterface::IsBoundTo), &addr));
		if (iter == interfaces.end()) {
			GkInterface *gkif = CreateInterface(addr);
			if (gkif->CreateListeners(this))
				interfaces.push_back(gkif);
			else {
				delete gkif;
				gkif = NULL;
			}
		} else {
			GkInterface *gkif = *iter;
			// re-create if changed
			if (!gkif->CreateListeners(this)) {
				interfaces.erase(iter);
				delete gkif;
				gkif = NULL;
			}
		}
	}
	if ((m_socksize == 0) || (interfaces.size() == 0)) {
		PTRACE(1, "Error: No valid RAS socket!");
		return;
	}

#if NEED_BROADCASTLISTENER
	if (bUseBroadcastListener && !broadcastListener) {
		broadcastListener = new BroadcastListener(interfaces.front()->GetRasPort());
		if (broadcastListener->IsOpen()) {
			PTRACE(1, "RAS\tBroadcast listener listening at " << broadcastListener->GetName());
			AddSocket(broadcastListener);
		} else {
			PTRACE(1, "RAS\tCannot start broadcast listener at " << broadcastListener->GetName());
			delete broadcastListener;
			broadcastListener = NULL;
		}
	}
#endif

	gkClient->OnReload();
	neighbors->OnReload();
	authList->OnReload();
	acctList->OnReload();
	vqueue->OnReload();
	Routing::Analyzer::Instance()->OnReload();

	bRemoveCallOnDRQ = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveCallOnDRQ", 1));
}

void RasServer::AddListener(RasListener *socket)
{
	AddSocket(socket);
}

void RasServer::AddListener(TCPListenSocket *socket)
{
	if (socket->IsOpen())
		listeners->AddListener(socket);
	else {
		delete socket;
		socket = NULL;
	}
}

bool RasServer::CloseListener(TCPListenSocket *socket)
{
	return listeners->CloseListener(socket);
}

WORD RasServer::GetRequestSeqNum()
{
	PWaitAndSignal lock(seqNumMutex);
	return ++requestSeqNum;
}

GkInterface *RasServer::SelectInterface(const Address & addr)
{
	ifiterator iter, eiter = interfaces.end();
	iter = find_if(interfaces.begin(), eiter, bind2nd(mem_fun(&GkInterface::IsReachable), &addr));
	return (iter != eiter) ? *iter : interfaces.front();
}

const GkInterface *RasServer::SelectInterface(const Address & addr) const
{
	return const_cast<RasServer *>(this)->SelectInterface(addr);
}

PIPSocket::Address RasServer::GetLocalAddress(const Address & addr) const
{
	return SelectInterface(addr)->GetRasListener()->GetPhysicalAddr(addr);
}

PIPSocket::Address RasServer::GetMasqAddress(const Address & addr) const
{
	return SelectInterface(addr)->GetRasListener()->GetLocalAddr(addr);	
}

H225_TransportAddress RasServer::GetRasAddress(const Address & addr) const
{
	return SelectInterface(addr)->GetRasListener()->GetRasAddress(addr);
}

H225_TransportAddress RasServer::GetCallSignalAddress(const Address & addr) const
{
	return SelectInterface(addr)->GetRasListener()->GetCallSignalAddress(addr);
}

bool RasServer::SendRas(const H225_RasMessage & rasobj, const Address & addr, WORD pt, RasListener *socket)
{
	if (socket == 0)
		socket = SelectInterface(addr)->GetRasListener();
	return socket->SendRas(rasobj, addr, pt);
}

bool RasServer::SendRas(const H225_RasMessage & rasobj, const H225_TransportAddress & dest, RasListener *socket)
{
	PIPSocket::Address addr;
	WORD pt;
	if (GetIPAndPortFromTransportAddr(dest, addr, pt))
		return SendRas(rasobj, addr, pt, socket);
	PTRACE(1, "RAS\tInvalid address");
	return false;
}

bool RasServer::SendRas(const H225_RasMessage & rasobj, const Address & addr, WORD pt, const Address & local)
{
	return SelectInterface(local)->GetRasListener()->SendRas(rasobj, addr, pt);
}

bool RasServer::IsRedirected(unsigned tag) const
{
	if (redirectGK != e_noRedirect)
		return true;
	if (tag == H225_RasMessage::e_registrationRequest)
		return RegistrationTable::Instance()->Size() >= epLimit;
	if (tag == H225_RasMessage::e_admissionRequest)
		return CallTable::Instance()->Size() >= callLimit;
	return false;
}

bool RasServer::IsForwardedMessage(const H225_NonStandardParameter *nonStandardParam, const Address & rxAddr) const
{
	// mechanism 1: forwarding detection per "flag"
	if (nonStandardParam && nonStandardParam->m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
		const H225_H221NonStandard & nonStandard = nonStandardParam->m_nonStandardIdentifier;
		if (Toolkit::Instance()->GetInternalExtensionCode(nonStandard) == Toolkit::iecFailoverRAS) {
			PTRACE(5, "RAS\tForwarded RAS detected!");
			return true;
		}
	// mechanism 2: forwarding detection per "from"
	}
	if (find(skipAddr.begin(), skipAddr.end(), rxAddr) != skipAddr.end()) {
		PTRACE(5, "RAS\tSkip forwarded RAS");
		return true;
	}
	return false;
}

void RasServer::ForwardRasMsg(H225_RasMessage & msg)
{
	if (altGKsSize <= 0)
		return;

	H225_NonStandardParameter oldParam, *nonStandardParam;
	bool hasStandardParam;
	PASN_Sequence *sobj;
	unsigned tag;
	H225_RequestSeqNum oldReqNum, *reqNum;

	// ATS 2004-01-16 Forward messages to alternates using our own sequence numbers
	// instead of using those supplied by the originator of the message, this will
	// result in clashes in RasMSG::EqualTo() by the receiver of this message

	switch (msg.GetTag())
	{
		case H225_RasMessage::e_gatekeeperRequest: {
			tag = H225_GatekeeperRequest::e_nonStandardData;
			H225_GatekeeperRequest & o = msg;
			nonStandardParam = &o.m_nonStandardData;
			sobj = &o;

			// Get a pointer to the current sequence number
			reqNum = &o.m_requestSeqNum;
			// Make a copy of the old sequence number
			oldReqNum = *reqNum;
			// Set a new value in the sequence number
			o.m_requestSeqNum = GetRequestSeqNum();

			break;
		}
		case H225_RasMessage::e_registrationRequest: {
			tag = H225_RegistrationRequest::e_nonStandardData;
			H225_RegistrationRequest & o = msg;
			nonStandardParam = &o.m_nonStandardData;
			sobj = &o;
			if (o.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier))
				nonStandardParam->m_data = o.m_endpointIdentifier;

			reqNum = &o.m_requestSeqNum;
			oldReqNum = *reqNum;

			o.m_requestSeqNum = GetRequestSeqNum();
			break;
		}
		case H225_RasMessage::e_unregistrationRequest: {
			tag = H225_UnregistrationRequest::e_nonStandardData;
			H225_UnregistrationRequest & o = msg;
			nonStandardParam = &o.m_nonStandardData;
			sobj = &o;

			reqNum = &o.m_requestSeqNum;
			oldReqNum = *reqNum;

			o.m_requestSeqNum = GetRequestSeqNum();
			break;
		}
		default:
			PTRACE(2,"Warning: unsupported RAS message type for forwarding: " << msg.GetTagName());
			return;
	}

	hasStandardParam = sobj->HasOptionalField(tag);
	if (hasStandardParam)
		oldParam = *nonStandardParam;
	else
		sobj->IncludeOptionalField(tag);

	// include the "this is a forwared message" tag (could be a static variable to increase performance)
	H225_NonStandardIdentifier & id = nonStandardParam->m_nonStandardIdentifier;
	id.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
	H225_H221NonStandard & h221 = id;
	h221.m_t35CountryCode   = Toolkit::t35cOpenOrg;
	h221.m_t35Extension     = Toolkit::t35eFailoverRAS;
	h221.m_manufacturerCode = Toolkit::t35mOpenOrg;

	for (int i = 0; i < altGKsSize; ++i) {
		PTRACE(4, "Forwarding RAS to " << altGKsAddr[i] << ':' << altGKsPort[i]);
		SendRas(msg, altGKsAddr[i], altGKsPort[i]);
	}

	// restore the old nonstandard field
	if (hasStandardParam)
		*nonStandardParam = oldParam;
	else
		sobj->RemoveOptionalField(tag);

	// restore the old sequence number
	// using the pointer and the old value.
	*reqNum = oldReqNum;
}

PString RasServer::GetParent() const
{
	return gkClient->GetParent();
}

ProxyHandler *RasServer::GetSigProxyHandler()
{
	return sigHandler ? sigHandler->GetSigHandler() : NULL;
}

ProxyHandler *RasServer::GetRtpProxyHandler()
{
	return sigHandler ? sigHandler->GetRtpHandler() : NULL;
}

void RasServer::SelectH235Capability(const H225_GatekeeperRequest & grq, H225_GatekeeperConfirm & gcf) const
{
	authList->SelectH235Capability(grq, gcf);
}

bool RasServer::LogAcctEvent(
	int evt,
	callptr& call,
	time_t now
	)
{
	return acctList->LogAcctEvent((GkAcctLogger::AcctEvent)evt,call,now);
}

void RasServer::Run()
{
	RasMsg::Initialize();

	RasPDU<H225_GatekeeperRequest>::Creator GRQCreator;
	RasPDU<H225_GatekeeperConfirm>::Creator GCFCreator;
	RasPDU<H225_GatekeeperReject>::Creator GRJCreator;
	RegistrationRequestPDU::Creator RRQCreator;
	RasPDU<H225_RegistrationConfirm>::Creator RCFCreator;
	RasPDU<H225_RegistrationReject>::Creator RRJCreator;
	RasPDU<H225_UnregistrationRequest>::Creator URQCreator;
	RasPDU<H225_UnregistrationConfirm>::Creator UCFCreator;
	RasPDU<H225_UnregistrationReject>::Creator URJCreator;
	AdmissionRequestPDU::Creator ARQCreator;
	RasPDU<H225_AdmissionConfirm>::Creator ACFCreator;
	RasPDU<H225_AdmissionReject>::Creator ARJCreator;
	RasPDU<H225_BandwidthRequest>::Creator BRQCreator;
	RasPDU<H225_BandwidthConfirm>::Creator BCFCreator;
	RasPDU<H225_BandwidthReject>::Creator BRJCreator;
	RasPDU<H225_DisengageRequest>::Creator DRQCreator;
	RasPDU<H225_DisengageConfirm>::Creator DCFCreator;
	RasPDU<H225_DisengageReject>::Creator DRJCreator;
	RasPDU<H225_LocationRequest>::Creator LRQCreator;
	RasPDU<H225_LocationConfirm>::Creator LCFCreator;
	RasPDU<H225_LocationReject>::Creator LRJCreator;
	RasPDU<H225_InfoRequest>::Creator IRQCreator;
	RasPDU<H225_InfoRequestResponse>::Creator IRRCreator;
	RasPDU<H225_UnknownMessageResponse>::Creator UMRCreator;
	RasPDU<H225_RequestInProgress>::Creator RIPCreator;
	RasPDU<H225_ResourcesAvailableIndicate>::Creator RAICreator;
	RasPDU<H225_ServiceControlIndication>::Creator SCICreator;
	RasPDU<H225_ServiceControlResponse>::Creator SCRCreator;

	listeners = new TCPServer;
	gkClient = new GkClient;
	neighbors = new NeighborList;
	authList = new GkAuthenticatorList;
	acctList = new GkAcctLoggerList;
	vqueue = new VirtualQueue;

	LoadConfig();

	if ((m_socksize > 0) && (interfaces.size() > 0)) {
		callptr nullcall;
		acctList->LogAcctEvent(GkAcctLogger::AcctOn,nullcall);

		CreateJob(this, &RasServer::HouseKeeping, "HouseKeeping");
		RegularJob::Run();

		acctList->LogAcctEvent(GkAcctLogger::AcctOff,nullcall);
	} else {
		cerr << "FATAL: No valid interfaces to listen! Shutdown!" << endl;
		PTRACE(0, "FATAL: No valid interfaces to listen! Shutdown!");
	}
}

void RasServer::OnStop()
{
	if (gkClient->IsRegistered())
		gkClient->SendURQ();

	// clear all calls and unregister all endpoints
	SoftPBX::UnregisterAllEndpoints();

	// close all listeners immediately
	if (broadcastListener)
		broadcastListener->Close();
	DeleteObjectsInContainer(interfaces);
	interfaces.clear();

	listeners->Stop();

	delete sigHandler;
	sigHandler = NULL;

	delete Routing::Analyzer::Instance();

	PTRACE(1, "GK\tRasServer stopped");
}

void RasServer::GetAlternateGK()
{
	ClearAltGKsTable();

	PString redirect(GkConfig()->GetString("RedirectGK", ""));
	if (redirect *= "temporary")
		redirectGK = e_temporaryRedirect;
	else if (redirect *= "permanent")
		redirectGK = e_permanentRedirect;
	else {
		PStringArray limits(redirect.Tokenise("|,;&", FALSE));
		for (PINDEX i = 0; i < limits.GetSize(); ++i) {
			PINDEX gr = limits[i].Find('>');
			if (gr != P_MAX_INDEX) {
				PCaselessString tkn(limits[i].Left(gr));
				if (tkn.Find("endpoints") != P_MAX_INDEX) {
					epLimit = limits[i].Mid(gr + 1).AsInteger();
					PTRACE(2, "GK\tSet registration limit to " << epLimit);
				} else if (tkn.Find("calls") != P_MAX_INDEX) {
					callLimit = limits[i].Mid(gr + 1).AsInteger();
					PTRACE(2, "GK\tSet call limit to " << callLimit);
				}
			}
		}
	}

	PString skips(GkConfig()->GetString("SkipForwards", ""));
	PStringArray skipips(skips.Tokenise(" ,;\t", FALSE));
	PINDEX skipSize = skipips.GetSize();
	if (skipSize > 0)
		for (PINDEX i = 0; i < skipSize; ++i)
			skipAddr.push_back(Address(skipips[i]));

	PString param(GkConfig()->GetString("AlternateGKs", ""));
	if (param.IsEmpty())
		return;

	PStringArray altgks(param.Tokenise(" ,;\t", FALSE));
	altGKs->SetSize(altgks.GetSize());

	for (PINDEX idx = 0; idx < altgks.GetSize(); ++idx) {
		const PStringArray tokens = altgks[idx].Tokenise(":", FALSE);
		if (tokens.GetSize() < 4) {
			PTRACE(1,"GK\tFormat error in AlternateGKs");
			continue;
		}

		H225_AlternateGK & alt = (*altGKs)[idx];
		alt.m_rasAddress = SocketToH225TransportAddr(Address(tokens[0]), (WORD)tokens[1].AsUnsigned());
		alt.m_needToRegister = Toolkit::AsBool(tokens[2]);
		alt.m_priority = tokens[3].AsInteger();
		if (tokens.GetSize() > 4) {
			alt.IncludeOptionalField(H225_AlternateGK::e_gatekeeperIdentifier);
			alt.m_gatekeeperIdentifier = tokens[4];
		}
	}

	PString sendto(GkConfig()->GetString("SendTo", ""));
	PStringArray svrs(sendto.Tokenise(" ,;\t", FALSE));
	if ((altGKsSize = svrs.GetSize()) > 0)
		for (PINDEX i = 0; i < altGKsSize; ++i) {
			PStringArray tokens(svrs[i].Tokenise(":", FALSE));
			altGKsAddr.push_back(Address(tokens[0]));
			altGKsPort.push_back((tokens.GetSize() > 1) ? WORD(tokens[1].AsUnsigned()) : GK_DEF_UNICAST_RAS_PORT);
		}
}

void RasServer::ClearAltGKsTable()
{
	redirectGK = e_noRedirect;
	altGKs->SetSize(0);
	altGKsAddr.clear();
	skipAddr.clear();
	altGKsPort.clear();
	altGKsSize = 0;
	epLimit = callLimit = P_MAX_INDEX;
}

void RasServer::HouseKeeping()
{
#if PTRACING
  PTime startUp;
#endif

	for (unsigned count = 0; IsRunning(); ++count)
		if (!Wait(1000)) {
			if( !IsRunning() )
				break;

			ReadLock lock(ConfigReloadMutex);

			if (!(count % 60)) // one minute
				RegistrationTable::Instance()->CheckEndpoints();

			CallTable::Instance()->CheckCalls(this);

			gkClient->CheckRegistration();

			Toolkit::Instance()->GetTimerManager()->CheckTimers();
		}
}

void RasServer::ReadSocket(IPSocket *socket)
{
	typedef Factory<RasMsg, unsigned> RasFactory;
	RasListener *listener = static_cast<RasListener *>(socket);
	if (GatekeeperMessage *msg = listener->ReadRas()) {
		unsigned tag = msg->GetTag();
		PWaitAndSignal lock(hmutex);
		if (RasMsg *ras = RasFactory::Create(tag, msg)) {
			std::list<RasHandler *>::iterator iter = find_if(handlers.begin(), handlers.end(), bind2nd(mem_fun(&RasHandler::IsExpected), ras));
			if (iter == handlers.end()) {
				std::list<RasMsg *>::iterator i = find_if(requests.begin(), requests.end(), bind2nd(mem_fun(&RasMsg::EqualTo), ras));
				if (i != requests.end() && !(*i)->IsDone()) {
					PTRACE(2, "RAS\tDuplicate " << msg->GetTagName() << ", deleted");
//					(*i)->SetNext(ras);
					delete ras;
					ras = NULL;
				} else {
					requests.push_back(ras);
					Job *job = new Jobs(ras);
					job->SetName(msg->GetTagName());
					job->Execute();
				}
			} else {
				PTRACE(2, "RAS\tTrapped " << msg->GetTagName());
				// re-create RasMsg object by the handler
				ras = (*iter)->CreatePDU(ras);
				(*iter)->Process(ras);
			}
		} else {
			PTRACE(1, "RAS\tUnknown RAS message " << msg->GetTagName());
			delete msg;
		}
	}
}

void RasServer::CleanUp()
{
	if (!requests.empty()) {
		std::list<RasMsg *>::iterator iter = partition(requests.begin(), requests.end(), mem_fun(&RasMsg::IsDone));
		DeleteObjects(requests.begin(), iter);
		requests.erase(requests.begin(), iter);
	}
}

GkInterface *RasServer::CreateInterface(const Address & addr)
{
	return new GkInterface(addr);
}


Toolkit *RasMsg::Kit;
GkStatus *RasMsg::StatusPort;
RegistrationTable *RasMsg::EndpointTbl;
CallTable *RasMsg::CallTbl;
RasServer *RasMsg::RasSrv;

void RasMsg::Initialize()
{
	Kit = Toolkit::Instance();
	StatusPort = GkStatus::Instance();
	EndpointTbl = RegistrationTable::Instance();
	CallTbl = CallTable::Instance();
	RasSrv = RasServer::Instance();
}

template<> bool RasPDU<H225_GatekeeperRequest>::Process()
{
	// OnGRQ
	// reply only if GK-ID matches
	if (request.HasOptionalField(H225_GatekeeperRequest::e_gatekeeperIdentifier))
		if (request.m_gatekeeperIdentifier.GetValue() != Toolkit::GKName()) {
			PTRACE(2, "RAS\tGRQ is not meant for this gatekeeper");
			return false;
		}

	bool bShellSendReply = !RasSrv->IsForwardedRas(request, m_msg->m_peerAddr);

	PString log;
	PString alias(request.HasOptionalField(H225_GatekeeperRequest::e_endpointAlias)
		? AsString(request.m_endpointAlias) : PString(" ")
		);

	unsigned rsn = H225_GatekeeperRejectReason::e_securityDenial;
	bool bReject = !RasSrv->ValidatePDU(*this, rsn);
	if (!bReject && RasSrv->IsRedirected()) {
		bReject = true;
		rsn = H225_GatekeeperRejectReason::e_resourceUnavailable;
	}
	if (bReject) {
		H225_GatekeeperReject & grj = BuildReject(rsn);
		grj.m_protocolIdentifier = request.m_protocolIdentifier;
		grj.IncludeOptionalField(H225_GatekeeperReject::e_gatekeeperIdentifier);
		grj.m_gatekeeperIdentifier = Toolkit::GKName();
		if (rsn == H225_GatekeeperRejectReason::e_resourceUnavailable)
			RasSrv->SetAltGKInfo(grj);
		log = PString(PString::Printf, "GRJ|%s|%s|%s|%s;",
			inet_ntoa(m_msg->m_peerAddr),
			(const unsigned char *) alias,
			(const unsigned char *) AsString(request.m_endpointType),
			(const unsigned char *) grj.m_rejectReason.GetTagName()
		      );
	} else {
		H225_GatekeeperConfirm & gcf = BuildConfirm();
		gcf.m_protocolIdentifier = request.m_protocolIdentifier;
		GetRasAddress(gcf.m_rasAddress);
		gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_gatekeeperIdentifier);
		gcf.m_gatekeeperIdentifier = Toolkit::GKName();
		if (request.HasOptionalField(H225_GatekeeperRequest::e_supportsAltGK))
			RasSrv->SetAlternateGK(gcf);

		RasSrv->SelectH235Capability(request, gcf);

		log = PString(PString::Printf, "GCF|%s|%s|%s;",
			inet_ntoa(m_msg->m_peerAddr),
			(const unsigned char *) alias,
			(const unsigned char *) AsString(request.m_endpointType)
		      );
	}

	PrintStatus(log);
	return bShellSendReply;
}

bool RegistrationRequestPDU::Process()
{
	// OnRRQ
	H225_TransportAddress SignalAddr;
	const PIPSocket::Address & rx_addr = m_msg->m_peerAddr;
	bool bShellSendReply, bShellForwardRequest;
	bShellSendReply = bShellForwardRequest = !RasSrv->IsForwardedRas(request, rx_addr);

	PINDEX i;
	/// remove invalid/unsupported entries from RAS and signaling addresses
	for (i = 0; i < request.m_callSignalAddress.GetSize(); i++) {
		PIPSocket::Address addr;
		WORD port = 0;
		if (!GetIPAndPortFromTransportAddr(request.m_callSignalAddress[i], addr, port)
				|| !addr.IsValid() || port == 0) {
			PTRACE(5, "RAS\tRemoving signaling address " 
				<< AsString(request.m_callSignalAddress[i]) << " from RRQ"
				);
			request.m_callSignalAddress.RemoveAt(i--);
		}
	}
	for (i = 0; i < request.m_rasAddress.GetSize(); i++) {
		PIPSocket::Address addr;
		WORD port = 0;
		if (!GetIPAndPortFromTransportAddr(request.m_rasAddress[i], addr, port)
				|| !addr.IsValid() || port == 0) {
			PTRACE(5, "RAS\tRemoving RAS address " 
				<< AsString(request.m_rasAddress[i]) << " from RRQ"
				);
			request.m_rasAddress.RemoveAt(i--);
		}
	}

///////////////////////////////////////////////////////////////////////////////////////////
// H460 support Code
	BOOL supportNAT = false;
	int RegPrior =0;
	bool preemptsupport = false;
	BOOL preempt = false;

#ifdef hasH460

// Registration Priority and Pre-emption
// This allows the unregistration of duplicate aliases with lower priority 
	OpalOID rPriFS = OpalOID(OID6);    

	if (request.HasOptionalField(H225_RegistrationRequest::e_featureSet)) {
		H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);

		if (fs.HasFeature(rPriFS)) {
			H460_FeatureOID * feat = (H460_FeatureOID *)fs.GetFeature(rPriFS);
			if (feat->Contains(priorityOID)) {
				unsigned prior = feat->Value(priorityOID);
				RegPrior = (int)prior;  
			}
			if (feat->Contains(preemptOID)) {
				preemptsupport = true;
                preempt = feat->Value(preemptOID);
			}
		}
	}
#endif
///////////////////////////////////////////////////////////////////////////////////////////////

   // If calling NAT support disabled. 
   // Use this to block errant gateways that don't support NAT mechanism properly.
	bool supportcallingNAT = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "SupportCallingNATedEndpoints", "1"));
	
	// lightweight registration update
	if (request.HasOptionalField(H225_RegistrationRequest::e_keepAlive) && request.m_keepAlive) {
		endptr ep = request.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier) ?
			EndpointTbl->FindByEndpointId(request.m_endpointIdentifier) :
			(request.m_callSignalAddress.GetSize() >= 1) ?
			EndpointTbl->FindBySignalAdr(request.m_callSignalAddress[0], rx_addr) : endptr(0);
		bool bReject = !ep;
		// check if the RRQ was sent from the registered endpoint
		if (ep && bShellSendReply) { // not forwarded RRQ
			if (ep->IsNATed()) {
				// for nated endpoint, only check rx_addr
			    bReject = (ep->GetNATIP() != rx_addr);
			} else {
				PIPSocket::Address oaddr, raddr;
				WORD oport, rport;
				if (request.m_callSignalAddress.GetSize() >= 1) {
					GetIPAndPortFromTransportAddr(ep->GetCallSignalAddress(), oaddr, oport);
					for (int s = 0; s < request.m_callSignalAddress.GetSize(); ++s) {
						GetIPAndPortFromTransportAddr(request.m_callSignalAddress[s], raddr, rport);
						if (oaddr == raddr && oport == rport)
							break;
					}
				} else if (request.m_rasAddress.GetSize() >= 1) {
					GetIPAndPortFromTransportAddr(ep->GetRasAddress(), oaddr, oport),
					GetIPAndPortFromTransportAddr(request.m_rasAddress[0], raddr, rport);
				} else {
					GetIPAndPortFromTransportAddr(ep->GetCallSignalAddress(), oaddr, oport),
					raddr = oaddr, rport = oport;
				}
				 bReject = (oaddr != raddr) || (oport != rport) || (raddr != rx_addr);
			}
		} 
		if (bReject) {
			if (ep && bShellSendReply) {
			 PTRACE(1, "RAS\tWarning: Possibly endpointId collide,security attack or IP change");
			   if (Toolkit::AsBool(Kit->Config()->GetString(RRQFeatureSection, "SupportDynamicIP", "0"))) {
			     PTRACE(1, "RAS\tDynamic IP? Removing existing Endpoint record and force reregistration.");
   						while (callptr call = CallTbl->FindCallRec(ep)) {
							call->Disconnect();
							CallTbl->RemoveCall(call);
						}
						EndpointTbl->RemoveByEndptr(ep);                              
			   }
			}
			// endpoint was NOT registered and force Full Registration
			return BuildRRJ(H225_RegistrationRejectReason::e_fullRegistrationRequired);
		} else {
			// forward lightweights, too
			if (bShellForwardRequest)
				RasSrv->ForwardRasMsg(m_msg->m_recvRAS);
			// endpoint was already registered
			ep->Update(m_msg->m_recvRAS);
			return bShellSendReply ? BuildRCF(ep) : false;
		}
	}

	if (request.m_rasAddress.GetSize() == 0)
		return BuildRRJ(H225_RegistrationRejectReason::e_invalidRASAddress);

	bool nated = false, validaddress = false;
	if (request.m_callSignalAddress.GetSize() >= 1) {
		PIPSocket::Address ipaddr;
		for (int s = 0; s < request.m_callSignalAddress.GetSize(); ++s) {
			SignalAddr = request.m_callSignalAddress[s];
			if (GetIPFromTransportAddr(SignalAddr, ipaddr)) {
				validaddress = (rx_addr == ipaddr);
				if (validaddress)
					break;
			}
		}
		//validaddress = PIPSocket::IsLocalHost(rx_addr.AsString());
		if (!bShellSendReply) // is forwarded RRQ?
			validaddress = true;
		else if (!validaddress && !IsLoopback(ipaddr)) // do not allow nated from loopback
			nated = true, validaddress = Toolkit::AsBool(Kit->Config()->GetString(RoutedSec, "SupportNATedEndpoints", "0"));
	}
	if (!validaddress)
		return BuildRRJ(H225_RegistrationRejectReason::e_invalidCallSignalAddress, nated);

	// Check if the endpoint has specified the EndpointIdentifier.
	// The GK will accept the EndpointIdentifier if
	// the EndpointIdentifier doesn't exist in the RegistrationTable,
	// or the request is sent from the original endpoint that has
	// this EndpointIdentifier. Otherwise the request will be rejected.
	if (request.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier)) {

	// Alternate Gatekeepers based on rules
//	   if (ResolveAlternateGatekeeper(request.m_endpointIdentifier,rx_addr))
//		  return BuildRRJ(H225_RegistrationRejectReason::e_invalidRASAddress);


		endptr ep = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier);
		if (ep && ep->GetCallSignalAddress() != SignalAddr)
			// no reason named invalidEndpointIdentifier? :(
			return BuildRRJ(H225_RegistrationRejectReason::e_securityDenial);
	}

	RRQAuthData authData;
	authData.m_rejectReason = H225_RegistrationRejectReason::e_securityDenial;
	if (!RasSrv->ValidatePDU(*this, authData))
		return BuildRRJ(authData.m_rejectReason);

	bool bNewEP = true;
	if (request.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) && (request.m_terminalAlias.GetSize() >= 1)) {
		H225_ArrayOf_AliasAddress Alias, & Aliases = request.m_terminalAlias;
		Alias.SetSize(1);
		for (int i = 0; i < Aliases.GetSize(); ++i) {
			Alias[0] = Aliases[i];
			bool skip = false;
			for (int j = 0; j < i; ++j) {
				skip = (Alias[0] == Aliases[j]);
				if (skip)
					break;
			}
			if (skip) { // remove duplicate alias
				Aliases.RemoveAt(i--);
				continue;
			}

			const endptr ep = EndpointTbl->FindByAliases(Alias);
			if (ep) {
				bNewEP = (ep->GetCallSignalAddress() != SignalAddr); 
				if (bNewEP) {
					if ((RegPrior > ep->Priority()) || (preempt) ||
					  (Toolkit::AsBool(Kit->Config()->GetString("RasSrv::RRQFeatures", "OverwriteEPOnSameAddress", "0")))) {
						// If the operators policy allows this case:
						// 1a) terminate all calls on active ep and
						// 1b) unregister the active ep - sends URQ and
						// 2) remove the ep from the EndpointTable, then
						// 3) allow the new ep to register - see below
						while (callptr call = CallTbl->FindCallRec(ep)) {
							call->Disconnect();
							CallTbl->RemoveCall(call);
						}
						if (RegPrior > ep->Priority())
						   ep->Unregisterpreempt(1);   // Unregistered by high priority
						else if (preempt)
						   ep->Unregisterpreempt(2);   // Unregistered by preempt notification 
						else
						   ep->Unregister();

						EndpointTbl->RemoveByEndptr(ep);
					} else {
						BuildRRJ(H225_RegistrationRejectReason::e_duplicateAlias);
						H225_RegistrationReject & rrj = m_msg->m_replyRAS;
#ifdef hasH460
						// notify that EP can pre-empt previous registration
						if ((preemptsupport) && (RegPrior == ep->Priority())) {  
							rrj.IncludeOptionalField(H225_RegistrationReject::e_genericData);
							H460_FeatureOID pre = H460_FeatureOID(rPriFS);
                            pre.Add(preNotOID,H460_FeatureContent(TRUE));
		                    H225_ArrayOf_GenericData & data = rrj.m_genericData;
				               PINDEX lastPos = data.GetSize();
				               data.SetSize(lastPos+1);
				               data[lastPos] = pre;
						}
#endif
						H225_ArrayOf_AliasAddress & duplicateAlias = rrj.m_rejectReason;
						duplicateAlias = Alias;
						return true;
					}
				}
			}
			PString s = AsString(Alias[0], FALSE);
			// reject the empty string
			//if (s.GetLength() < 1 || !(isalnum(s[0]) || s[0]=='#') )
			if (s.GetLength() < 1)
				return BuildRRJ(H225_RegistrationRejectReason::e_invalidAlias);
			if (!nated && !s)
				nated = Kit->Config()->HasKey("NATedEndpoints", s);
		}
	} else {
		// reject gw without alias
		switch (request.m_terminalType.GetTag()) {
			case H225_EndpointType::e_gatekeeper:
			case H225_EndpointType::e_gateway:
			case H225_EndpointType::e_mcu:
				return BuildRRJ(H225_RegistrationRejectReason::e_invalidAlias);
			/* only while debugging
			default:
				return BuildRRJ(H225_RegistrationRejectReason::e_invalidAlias);
			 */
		}
	}

	if (bNewEP && RasSrv->IsRedirected(H225_RasMessage::e_registrationRequest)) {
		PTRACE(1, "RAS\tWarning: Exceed registration limit!!");
		return BuildRRJ(H225_RegistrationRejectReason::e_resourceUnavailable);
	}

	if (!nated && request.HasOptionalField(H225_RegistrationRequest::e_nonStandardData)) {
		int iec = Toolkit::iecUnknown;
		if (request.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
			iec = Toolkit::Instance()->GetInternalExtensionCode(request.m_nonStandardData.m_nonStandardIdentifier);
		} else if (request.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_object) {
			PASN_ObjectId &oid = request.m_nonStandardData.m_nonStandardIdentifier;
			if (oid.GetDataLength() == 0)
				iec = Toolkit::iecNATTraversal;
		}
		if (iec == Toolkit::iecNATTraversal) {
			PString ipdata = request.m_nonStandardData.m_data.AsString();
			if (strncmp(ipdata, "IP=", 3) == 0) {
				PStringArray ips(ipdata.Mid(3).Tokenise(",:;", false));
				PINDEX i;
				for (i = 0; i < ips.GetSize(); ++i)
					if (PIPSocket::Address(ips[i]) == rx_addr)
						break;
				nated = (i >= ips.GetSize());
				request.RemoveOptionalField(H225_RegistrationRequest::e_nonStandardData);
			}
		}
	}
	request.m_callSignalAddress.SetSize(1);
	request.m_callSignalAddress[0] = SignalAddr;

	endptr ep = EndpointTbl->InsertRec(m_msg->m_recvRAS, nated ? rx_addr : PIPSocket::Address(INADDR_ANY));
	if (!ep) {
		PTRACE(3, "RAS\tRRQ rejected by unknown reason from " << rx_addr);
		return BuildRRJ(H225_RegistrationRejectReason::e_undefinedReason);
	}

#ifdef h323v6
	if (request.HasOptionalField(H225_RegistrationRequest::e_assignedGatekeeper)) 
             ep->SetAssignedGatekeeper(request.m_assignedGatekeeper);
#endif

	if (nated)
		ep->SetNATAddress(rx_addr);
	else {
		ep->SetNAT(false);
		if (supportNAT)
		  ep->SetSupportNAT(true);
	}

	ep->SetPriority(RegPrior);
	ep->SetPreemption(preemptsupport);

	if (bShellSendReply) {
		//
		// OK, now send RCF
		//
		BuildRCF(ep);
		H225_RegistrationConfirm & rcf = m_msg->m_replyRAS;
		if (supportcallingNAT && nated) {
			// tell the endpoint its translated address
			rcf.IncludeOptionalField(H225_RegistrationConfirm::e_nonStandardData);
		    rcf.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
			H225_H221NonStandard &t35 = rcf.m_nonStandardData.m_nonStandardIdentifier;
			t35.m_t35CountryCode = Toolkit::t35cPoland;
			t35.m_manufacturerCode = Toolkit::t35mGnuGk;
			t35.m_t35Extension = Toolkit::t35eNATTraversal;
			rcf.m_nonStandardData.m_data = "NAT=" + rx_addr.AsString();
		}

#ifdef hasH460
		   H225_ArrayOf_GenericData & gd = rcf.m_genericData;

		   // if the client supports Registration PreEmption then notify the client that we do too
		   if ((preemptsupport) &&
			  (request.HasOptionalField(H225_RegistrationRequest::e_keepAlive) && (!request.m_keepAlive))) {
              H460_FeatureOID pre = H460_FeatureOID(rPriFS);
			  PINDEX lPos = gd.GetSize();
			  gd.SetSize(lPos+1);
			  gd[lPos] = pre;
			}
			if (gd.GetSize() > 0)		  
				rcf.IncludeOptionalField(H225_RegistrationConfirm::e_genericData);
#endif

		// Alternate GKs
		if (request.HasOptionalField(H225_RegistrationRequest::e_supportsAltGK))
			RasSrv->SetAlternateGK(rcf);
		if (ep->HasCallCreditCapabilities()) {
			rcf.IncludeOptionalField(H225_RegistrationConfirm::e_serviceControl);
			ep->AddCallCreditServiceControl(rcf.m_serviceControl, 
				authData.m_amountString, authData.m_billingMode, -1
				);
		}
	} else {
		PIPSocket::Address rasip, sigip;
		if (GetIPFromTransportAddr(request.m_rasAddress[0], rasip) && GetIPFromTransportAddr(SignalAddr, sigip) && rasip != sigip)
			// this is an nated endpoint
			ep->SetNATAddress(rasip);
	}
	// forward heavyweight
	if (bShellForwardRequest) {
		request.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
		request.m_endpointIdentifier = ep->GetEndpointIdentifier();
		if (nated) {
			request.m_rasAddress.SetSize(1);
			request.m_rasAddress[0] = ep->GetRasAddress(); // translated address
		}
		RasSrv->ForwardRasMsg(m_msg->m_recvRAS);
	}

	// Note that the terminalAlias is not optional here as we pass the auto generated alias if not were provided from
	// the endpoint itself
	PString log(PString::Printf, "RCF|%s|%s|%s|%s;",
		    (const unsigned char *) AsDotString(SignalAddr),
		    (const unsigned char *) AsString(ep->GetAliases()),
		    (const unsigned char *) AsString(request.m_terminalType),
		    (const unsigned char *) ep->GetEndpointIdentifier().GetValue()
		);
	PrintStatus(log);
	return bShellSendReply;
}

bool RegistrationRequestPDU::BuildRCF(const endptr & ep)
{
	H225_RegistrationConfirm & rcf = BuildConfirm();
	rcf.m_protocolIdentifier = request.m_protocolIdentifier;
	rcf.m_callSignalAddress.SetSize(1);
	GetCallSignalAddress(rcf.m_callSignalAddress[0]);
	rcf.IncludeOptionalField(H225_RegistrationConfirm::e_terminalAlias);
	rcf.m_terminalAlias = ep->GetAliases();
	rcf.m_endpointIdentifier = ep->GetEndpointIdentifier();
	rcf.IncludeOptionalField(H225_RegistrationConfirm::e_gatekeeperIdentifier);
	rcf.m_gatekeeperIdentifier = Toolkit::GKName();
	if (ep->GetTimeToLive() > 0) {
		rcf.IncludeOptionalField(H225_RegistrationConfirm::e_timeToLive);
		rcf.m_timeToLive = ep->GetTimeToLive();
	}
	return true;
}

bool RegistrationRequestPDU::BuildRRJ(unsigned reason, bool alt)
{
	H225_RegistrationReject & rrj = BuildReject(reason);
	rrj.m_protocolIdentifier = request.m_protocolIdentifier;
	rrj.IncludeOptionalField(H225_RegistrationReject::e_gatekeeperIdentifier);
	rrj.m_gatekeeperIdentifier = Toolkit::GKName();
	if (alt)
		RasSrv->SetAltGKInfo(rrj);

	if (request.HasOptionalField(H225_RegistrationRequest::e_nonStandardData)
		&& request.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
		const H225_H221NonStandard& nonStandard = request.m_nonStandardData.m_nonStandardIdentifier;
		if (Toolkit::Instance()->GetInternalExtensionCode(nonStandard) == Toolkit::iecFailoverRAS)
			CopyNonStandardData(request, rrj);
	}
	
	PString alias(request.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) ? AsString(request.m_terminalAlias) : PString(" "));
	PString log(PString::Printf, "RRJ|%s|%s|%s|%s;",
			inet_ntoa(m_msg->m_peerAddr),
			(const unsigned char *) alias,
			(const unsigned char *) AsString(request.m_terminalType),
			(const unsigned char *) rrj.m_rejectReason.GetTagName()
		    );

	return PrintStatus(log);
}

template<> bool RasPDU<H225_UnregistrationRequest>::Process()
{
	// OnURQ
	PString log;

	bool bShellSendReply, bShellForwardRequest;
	bShellSendReply = bShellForwardRequest = !RasSrv->IsForwardedRas(request, m_msg->m_peerAddr);

	PString endpointId(request.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier) ? request.m_endpointIdentifier.GetValue() : PString(" "));
	endptr ep = request.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier) ?
		EndpointTbl->FindByEndpointId(request.m_endpointIdentifier) :
		request.m_callSignalAddress.GetSize() ? EndpointTbl->FindBySignalAdr(request.m_callSignalAddress[0], m_msg->m_peerAddr) : endptr(0);
	if (ep) {
		// Disconnect all calls of the endpoint
		SoftPBX::DisconnectEndpoint(ep);
		// Remove from the table
		EndpointTbl->RemoveByEndptr(ep);

		// Return UCF
		BuildConfirm();

		log = PString(PString::Printf, "UCF|%s|%s;",
			inet_ntoa(m_msg->m_peerAddr),
			(const unsigned char *) endpointId
		      );
	} else {
		// Return URJ
		H225_UnregistrationReject & urj = BuildReject(H225_UnregRejectReason::e_notCurrentlyRegistered);
		log = PString(PString::Printf, "URJ|%s|%s|%s;",
			inet_ntoa(m_msg->m_peerAddr),
			(const unsigned char *) endpointId,
			(const unsigned char *) urj.m_rejectReason.GetTagName()
		      );
	}

	if (bShellForwardRequest)
		RasSrv->ForwardRasMsg(m_msg->m_recvRAS);
	PrintStatus(log);
	return bShellSendReply;
}

PString AdmissionRequestPDU::GetCallingStationId(
	/// additional data
	ARQAuthData& authData
	) const
{
	if (!authData.m_callingStationId)
		return authData.m_callingStationId;
		
	const H225_AdmissionRequest& arq = request;
	const bool hasCall = authData.m_call.operator->() != NULL;
	PString id;

	// Calling-Station-Id
	if (!arq.m_answerCall) // srcInfo is meaningful only in an originating ARQ
		id = GetBestAliasAddressString(arq.m_srcInfo, false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);
	else if (hasCall)
		id = authData.m_call->GetCallingStationId();

	if (!id)
		return id;
		
	if (id.IsEmpty() && hasCall)
		id = GetBestAliasAddressString(authData.m_call->GetSourceAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

	if (id.IsEmpty() && authData.m_requestingEP && !arq.m_answerCall)
		id = GetBestAliasAddressString(
			authData.m_requestingEP->GetAliases(), false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);
			
	if (id.IsEmpty() && arq.m_answerCall && hasCall) {
		const endptr callingEP = authData.m_call->GetCallingParty();
		if (callingEP)
			id = GetBestAliasAddressString(
				callingEP->GetAliases(), false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
	}
				
	if (id.IsEmpty() && hasCall) {
		PIPSocket::Address addr(0);
		WORD port = 0;
		if (authData.m_call->GetSrcSignalAddr(addr, port) && addr.IsValid())
			id = AsString(addr, port);
	}
	
	return id;
}

PString AdmissionRequestPDU::GetCalledStationId(
	/// additional data
	ARQAuthData& authData
	) const
{
	if (!authData.m_calledStationId)
		return authData.m_calledStationId;

	const H225_AdmissionRequest& arq = request;
	const bool hasCall = authData.m_call.operator->() != NULL;
	PString id;
				
	if (!arq.m_answerCall) {
		if (arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
			id = GetBestAliasAddressString(arq.m_destinationInfo, false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
	} else if (hasCall)
		id = authData.m_call->GetCalledStationId();

	if (!id)
		return id;

	if (id.IsEmpty() && hasCall)
		id = GetBestAliasAddressString(
			authData.m_call->GetDestinationAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

	if (id.IsEmpty() && arq.m_answerCall) {
		if (arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
			id = GetBestAliasAddressString(arq.m_destinationInfo, false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);

		if (id.IsEmpty() && authData.m_requestingEP)
			id = GetBestAliasAddressString(
				authData.m_requestingEP->GetAliases(), false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);

		PIPSocket::Address addr;
		if (id.IsEmpty() && authData.m_requestingEP
			&& GetIPFromTransportAddr(authData.m_requestingEP->GetCallSignalAddress(), addr) 
			&& addr.IsValid())
			id = addr.AsString();
	}
		
	// this does not work well in routed mode, when destCallSignalAddress
	// is usually the gatekeeper address
	if (id.IsEmpty() 
		&& arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
		const H225_TransportAddress& tsap = arq.m_destCallSignalAddress;
		id = AsDotString(tsap);
	}
	
	return id;
}

PString AdmissionRequestPDU::GetCallLinkage( 
	/// additional data
	ARQAuthData& authData
	) const
{
		if (!authData.m_callLinkage)
		return authData.m_callLinkage;

	const H225_AdmissionRequest& arq = request;
	const bool hasCall = authData.m_call.operator->() != NULL;
	PString id;
				
	if (!arq.m_answerCall) {
		if (arq.HasOptionalField(H225_AdmissionRequest::e_callLinkage)) {
			const H225_CallLinkage & cl = arq.m_callLinkage;
			if (cl.HasOptionalField(H225_CallLinkage::e_globalCallId))
			   id = cl.m_globalCallId.AsString();
		}
	} else if (hasCall)
		id = authData.m_call->GetCallLinkage();

	if (!id)
		return id;
	else
		return PString();  // No Call Linkage detected.

}

bool AdmissionRequestPDU::Process()
{
	// OnARQ
	bool bReject = false;
	bool answer = request.m_answerCall;
	PString in_rewrite_source, out_rewrite_source;

	// find the caller
	RequestingEP = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier);
	if (!RequestingEP)
		return BuildReply(H225_AdmissionRejectReason::e_callerNotRegistered/*was :e_invalidEndpointIdentifier*/);

	if (RasSrv->IsRedirected(H225_RasMessage::e_admissionRequest) && !answer) {
		PTRACE(1, "RAS\tWarning: Exceed call limit!!");
		return BuildReply(H225_AdmissionRejectReason::e_resourceUnavailable);
	}

	bool aliasesChanged = false;
	bool hasDestInfo = request.HasOptionalField(H225_AdmissionRequest::e_destinationInfo) 
		&& request.m_destinationInfo.GetSize() > 0;
	// CallRecs should be looked for using callIdentifier instead of callReferenceValue
	// callIdentifier is globally unique, callReferenceValue is just unique per-endpoint.
	callptr pExistingCallRec = request.HasOptionalField(H225_AdmissionRequest::e_callIdentifier) ?
		CallTbl->FindCallRec(request.m_callIdentifier) :
		// since callIdentifier is optional, we might have to look for the callReferenceValue as well
		CallTbl->FindCallRec(request.m_callReferenceValue);

	ARQAuthData authData(RequestingEP, pExistingCallRec);

	if (answer && pExistingCallRec)
		authData.m_dialedNumber = pExistingCallRec->GetDialedNumber();
		
	if (authData.m_dialedNumber.IsEmpty()) {
		if (!answer && hasDestInfo)
			authData.m_dialedNumber = GetBestAliasAddressString(
				request.m_destinationInfo, false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
	}
		
	if (hasDestInfo) { // apply rewriting rules

		in_rewrite_source = GetBestAliasAddressString(
			RequestingEP->GetAliases(), false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

     	if(in_rewrite_source.IsEmpty() && request.m_srcInfo.GetSize() > 0) {
        	in_rewrite_source = GetBestAliasAddressString(request.m_srcInfo, false,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID), 
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
		}

	 	if (!in_rewrite_source.IsEmpty())
	 		if (Kit->GWRewriteE164(in_rewrite_source, true, request.m_destinationInfo[0])
				&& !RasSrv->IsGKRouted())
				aliasesChanged = true;

		// Normal rewriting
		if (Kit->RewriteE164(request.m_destinationInfo[0]) && !RasSrv->IsGKRouted())
			aliasesChanged = true;
	}

	destinationString = hasDestInfo ? AsString(request.m_destinationInfo) :
		request.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress) ?
		AsDotString(request.m_destCallSignalAddress) : PString("unknown");

	authData.m_callingStationId = GetCallingStationId(authData);
	authData.m_calledStationId = GetCalledStationId(authData);
	authData.m_callLinkage = GetCallLinkage(authData);
	
	if (!RasSrv->ValidatePDU(*this, authData)) {
		if (authData.m_rejectReason < 0)
			authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		return BuildReply(authData.m_rejectReason);
	}

	if (authData.m_routeToAlias != NULL) {
		request.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
		request.m_destinationInfo.SetSize(1);
		request.m_destinationInfo[0] = *authData.m_routeToAlias;
		authData.m_calledStationId = AsString(*authData.m_routeToAlias, FALSE);
		PTRACE(2, "RAS\tARQ destination set to " << authData.m_calledStationId);
		hasDestInfo = true;
		destinationString = AsString(request.m_destinationInfo);
		if (!RasSrv->IsGKRouted())
			aliasesChanged = true;
	}
	
	if (RasSrv->IsGKRouted() && answer && !pExistingCallRec) {
		if (Toolkit::AsBool(Kit->Config()->GetString("RasSrv::ARQFeatures", "ArjReasonRouteCallToGatekeeper", "1"))) {
			bReject = true;
			if (request.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress)) {
				PIPSocket::Address ipaddress;
				if (GetIPFromTransportAddr(request.m_srcCallSignalAddress, ipaddress))
					bReject = !RasSrv->IsForwardedMessage(0, ipaddress);
			}
			if (bReject)
				return BuildReply(H225_AdmissionRejectReason::e_routeCallToGatekeeper);
		}
	}

	//
	// Bandwidth
	// and GkManager admission
	//
	int BWRequest = request.m_bandWidth.GetValue();
	// hack for Netmeeting 3.0x
	if ((BWRequest > 0) && (BWRequest < 100))
		BWRequest = 1280;
	// check if it is the first arrived ARQ
	if (pExistingCallRec) {
		// request more bandwidth?
		if (BWRequest > pExistingCallRec->GetBandwidth())
			if (CallTbl->GetAdmission(BWRequest, pExistingCallRec))
				pExistingCallRec->SetBandwidth(BWRequest);
			else
				bReject = true;
	} else {
		bReject = (!CallTbl->GetAdmission(BWRequest));
	}
	PTRACE(3, "GK\tARQ will request bandwith of " << BWRequest);
	if (bReject)
		return BuildReply(H225_AdmissionRejectReason::e_requestDenied); // what the spec says

	if (request.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
		H225_TransportAddress tmp;
		GetCallSignalAddress(tmp);
		if (tmp == request.m_destCallSignalAddress)
			request.RemoveOptionalField(H225_AdmissionRequest::e_destCallSignalAddress);
	}

	// routing decision
	bool toParent = false;
	H225_TransportAddress CalledAddress;
	Routing::AdmissionRequest arq(request, this);
	if (!answer) {
		if (!authData.m_destinationRoutes.empty()) {
			list<Route>::const_iterator i = authData.m_destinationRoutes.begin();
			while (i != authData.m_destinationRoutes.end())
				arq.AddRoute(*i++);
		} else
			arq.Process();
			
		if (arq.GetRoutes().empty())
			return BuildReply(arq.GetRejectReason());
			
		list<Route>::iterator r = arq.GetRoutes().begin();
		while (r != arq.GetRoutes().end()) {
			// PTRACE(1, "route = " << r->AsString() );
			if (authData.m_proxyMode != CallRec::ProxyDetect)
				r->m_proxyMode = authData.m_proxyMode;
			++r;
		}
		
		Route route;
		arq.GetFirstRoute(route);
		
		if ((arq.GetRoutes().size() == 1 || !Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "ActivateFailover", "0")))
				&& route.m_destEndpoint	&& !route.m_destEndpoint->HasAvailableCapacity())
			return BuildReply(H225_AdmissionRejectReason::e_resourceUnavailable);

		CalledEP = route.m_destEndpoint;
		CalledAddress = route.m_destAddr;
		toParent = route.m_flags & Route::e_toParent;
		aliasesChanged = aliasesChanged || (arq.GetFlags() & Routing::AdmissionRequest::e_aliasesChanged);
	
		// record neighbor used for rewriting purposes
		if (route.m_flags & Route::e_toNeighbor)
			out_rewrite_source = route.m_routeId;
		
		authData.m_proxyMode = route.m_proxyMode;
	}

	// new connection admitted
	H225_AdmissionConfirm & acf = BuildConfirm();
	acf.m_bandWidth = BWRequest;

	// Per GW outbound rewrite
	if (hasDestInfo && CalledEP && (RequestingEP != CalledEP)) {

		if(CalledEP->GetAliases().GetSize() > 0) {
			out_rewrite_source = GetBestAliasAddressString(
				CalledEP->GetAliases(), false,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID), 
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
		}

		if (!out_rewrite_source.IsEmpty())
			if (Kit->GWRewriteE164(out_rewrite_source,false,request.m_destinationInfo[0])
				&& !RasSrv->IsGKRouted())
				aliasesChanged = true;

	}

	if (pExistingCallRec) {
		// duplicate or answer ARQ
		PTRACE(3, "GK\tACF: found existing call no " << pExistingCallRec->GetCallNumber());
		if (authData.m_callDurationLimit > 0)
			pExistingCallRec->SetDurationLimit(authData.m_callDurationLimit);
		if (!authData.m_callingStationId)
			pExistingCallRec->SetCallingStationId(authData.m_callingStationId);
		if (!authData.m_calledStationId)
			pExistingCallRec->SetCalledStationId(authData.m_calledStationId);
	} else {

		// the call is not in the table
		CallRec *pCallRec = new CallRec(*this, BWRequest, destinationString, authData.m_proxyMode);

		if (CalledEP)
			pCallRec->SetCalled(CalledEP);
		else {
			if (answer)
				pCallRec->SetCalled(RequestingEP);
			pCallRec->SetDestSignalAddr(CalledAddress);
		}
		if (!answer)
			pCallRec->SetCalling(RequestingEP);
		if (toParent)
			pCallRec->SetToParent(true);

		pCallRec->SetNewRoutes(arq.GetRoutes());
		
		if (authData.m_callDurationLimit > 0)
			pCallRec->SetDurationLimit(authData.m_callDurationLimit);
		if (!authData.m_callingStationId)
			pCallRec->SetCallingStationId(authData.m_callingStationId);
		if (!authData.m_calledStationId)
			pCallRec->SetCalledStationId(authData.m_calledStationId);
		if (!authData.m_dialedNumber)
			pCallRec->SetDialedNumber(authData.m_dialedNumber);
			
		if (authData.m_routeToAlias != NULL)
			pCallRec->SetRouteToAlias(*authData.m_routeToAlias);

		if (!RasSrv->IsGKRouted())
			pCallRec->SetConnected();
		else if (acf.HasOptionalField(H225_AdmissionConfirm::e_cryptoTokens))
			pCallRec->SetAccessTokens(acf.m_cryptoTokens);
		CallTbl->Insert(pCallRec);

		// Put rewriting information into call record
		pCallRec->SetInboundRewriteId(in_rewrite_source);
		pCallRec->SetOutboundRewriteId(out_rewrite_source);

	}

	if (RasSrv->IsGKRouted()) {
		acf.m_callModel.SetTag(H225_CallModel::e_gatekeeperRouted);
		GetCallSignalAddress(acf.m_destCallSignalAddress);
	} else {
		acf.m_callModel.SetTag(H225_CallModel::e_direct);
		acf.m_destCallSignalAddress = CalledAddress;
	}

	long irrFrq = GkConfig()->GetInteger("CallTable", "IRRFrequency", 120);
	if (irrFrq > 0) {
		acf.IncludeOptionalField ( H225_AdmissionConfirm::e_irrFrequency );
		acf.m_irrFrequency.SetValue( irrFrq );
	}

	if( !answer && aliasesChanged 
		&& request.HasOptionalField(H225_AdmissionRequest::e_canMapAlias)
		&& request.m_canMapAlias
		&& request.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)
		&& request.m_destinationInfo.GetSize() > 0 ) {
		acf.IncludeOptionalField(H225_AdmissionConfirm::e_destinationInfo);
		acf.m_destinationInfo = request.m_destinationInfo;
	}

	if (RequestingEP->HasCallCreditCapabilities()) {
		acf.IncludeOptionalField(H225_AdmissionConfirm::e_serviceControl);
		RequestingEP->AddCallCreditServiceControl(acf.m_serviceControl, 
			authData.m_amountString, authData.m_billingMode, 
			authData.m_callDurationLimit
			);
	}
	return BuildReply(e_acf);
}

bool AdmissionRequestPDU::BuildReply(int reason)
{
	PString source = RequestingEP ? AsDotString(RequestingEP->GetCallSignalAddress()) : PString(" ");
	PString srcInfo = AsString(request.m_srcInfo);
	const char *answerCall = request.m_answerCall ? "true" : "false";

	PString log;
	if (reason == e_routeRequest) {
		log = PString(PString::Printf, "RouteRequest|%s|%s|%u|%s|%s",
				(const unsigned char *) source,
				(const unsigned char *) RequestingEP->GetEndpointIdentifier().GetValue(),
				(unsigned) request.m_callReferenceValue,
				(const unsigned char *) destinationString,
				(const unsigned char *) srcInfo
		      	);
		if (Toolkit::AsBool(GkConfig()->GetString("Gatekeeper::Main", "SignalCallId", 0))) {
			PString callid = AsString(request.m_callIdentifier.m_guid);
			callid.Replace(" ", "-", true);
			log += PString("|") + callid;
		}
		log += PString(";");
	} else if (reason < 0) {
		log = PString(PString::Printf, "ACF|%s|%s|%u|%s|%s|%s",
				(const unsigned char *) source,
				(const unsigned char *) RequestingEP->GetEndpointIdentifier().GetValue(),
				(unsigned) request.m_callReferenceValue,
				(const unsigned char *) destinationString,
				(const unsigned char *) srcInfo,
				answerCall
		      	);
		if (Toolkit::AsBool(GkConfig()->GetString("Gatekeeper::Main", "SignalCallId", 0))) {
			PString callid = AsString(request.m_callIdentifier.m_guid);
			callid.Replace(" ", "-", true);
			log += PString("|") + callid;
		}
		log += PString(";");
	} else {
		H225_AdmissionReject & arj = BuildReject(reason);
		if (reason == H225_AdmissionRejectReason::e_resourceUnavailable)
			RasSrv->SetAltGKInfo(arj);
		log = PString(PString::Printf, "ARJ|%s|%s|%s|%s|%s",
				(const unsigned char *) source,
				(const unsigned char *) destinationString,
				(const unsigned char *) srcInfo,
				answerCall,
				(const unsigned char *) arj.m_rejectReason.GetTagName()
		      	);
		if (Toolkit::AsBool(GkConfig()->GetString("Gatekeeper::Main", "SignalCallId", 0))) {
			PString callid = AsString(request.m_callIdentifier.m_guid);
			callid.Replace(" ", "-", true);
			log += PString("|") + callid;
		}
		log += PString(";");
	}
	return PrintStatus(log);
}

template<> bool RasPDU<H225_BandwidthRequest>::Process()
{
	// OnBRQ
	int bandwidth = request.m_bandWidth.GetValue();
	// hack for Netmeeting 3.0x
	if ((bandwidth > 0) && (bandwidth < 100))
		bandwidth = 1280;

	callptr pCall = request.HasOptionalField(H225_BandwidthRequest::e_callIdentifier) ?
		CallTbl->FindCallRec(request.m_callIdentifier) :
		CallTbl->FindCallRec(request.m_callReferenceValue);

	PString log;
	unsigned rsn = H225_BandRejectReason::e_securityDenial;
	bool bReject = !RasSrv->ValidatePDU(*this, rsn);
	if (!bReject && !pCall) {
		bReject = true;
		rsn = H225_BandRejectReason::e_invalidConferenceID;
	} else if (!CallTbl->GetAdmission(bandwidth, pCall)) {
		bReject = true;
		rsn = H225_BandRejectReason::e_insufficientResources;
	}
	if (bReject) {
		H225_BandwidthReject & brj = BuildReject(rsn);
		if (rsn == H225_BandRejectReason::e_insufficientResources) {
			brj.m_allowedBandWidth = CallTbl->GetAvailableBW();
			// ask the endpoint to try alternate gatekeepers
			RasSrv->SetAltGKInfo(brj);
		}
		log = PString(PString::Printf, "BRJ|%s|%s|%u|%s;",
			inet_ntoa(m_msg->m_peerAddr),
			(const unsigned char *) request.m_endpointIdentifier.GetValue(),
			bandwidth,
			(const unsigned char *) brj.m_rejectReason.GetTagName()
		      );
	} else {
		pCall->SetBandwidth(bandwidth);
		H225_BandwidthConfirm & bcf = BuildConfirm();
		bcf.m_bandWidth = bandwidth;
		log = PString(PString::Printf, "BCF|%s|%s|%u;",
			inet_ntoa(m_msg->m_peerAddr),
			(const unsigned char *) request.m_endpointIdentifier.GetValue(),
			bandwidth
		      );
	}

	return PrintStatus(log);
}

template<> bool RasPDU<H225_DisengageRequest>::Process()
{
	// OnDRQ
	bool bReject = false;

	endptr ep;
	unsigned rsn = H225_DisengageRejectReason::e_securityDenial;
	if ((ep = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier))) {
		PTRACE(4, "GK\tDRQ: closed conference");
		bReject = !RasSrv->ValidatePDU(*this, rsn);
	} else {
		bReject = true;
		rsn = H225_DisengageRejectReason::e_notRegistered;
	}

	PString log;
	if (bReject) {
		H225_DisengageReject & drj = BuildReject(rsn);
		log = PString(PString::Printf, "DRJ|%s|%s|%u|%s",
				inet_ntoa(m_msg->m_peerAddr),
				(const unsigned char *) request.m_endpointIdentifier.GetValue(),
				(unsigned) request.m_callReferenceValue,
				(const unsigned char *) drj.m_rejectReason.GetTagName()
		      	);
		if (Toolkit::AsBool(GkConfig()->GetString("Gatekeeper::Main", "SignalCallId", 0))) {
			PString callid = AsString(request.m_callIdentifier.m_guid);
			callid.Replace(" ", "-", true);
			log += PString("|") + callid;
		}
		log += PString(";");
	} else {
		BuildConfirm();
		// always signal DCF
		log = PString(PString::Printf, "DCF|%s|%s|%u|%s",
				inet_ntoa(m_msg->m_peerAddr),
				(const unsigned char *) request.m_endpointIdentifier.GetValue(),
				(unsigned) request.m_callReferenceValue,
				(const unsigned char *) request.m_disengageReason.GetTagName()
		      	);
		if (Toolkit::AsBool(GkConfig()->GetString("Gatekeeper::Main", "SignalCallId", 0))) {
			PString callid = AsString(request.m_callIdentifier.m_guid);
			callid.Replace(" ", "-", true);
			log += PString("|") + callid;
		}
		log += PString(";");

		if (!RasSrv->IsGKRouted() || RasSrv->RemoveCallOnDRQ())
			CallTbl->RemoveCall(request, ep);
	}

	return PrintStatus(log);
}

template<> bool RasPDU<H225_LocationRequest>::Process()
{
	// OnLRQ
	PString log,neighbor_alias;

	if (request.m_destinationInfo.GetSize() > 0) {

		// per GW rewrite first
		neighbor_alias = RasSrv->GetNeighbors()->GetNeighborIdBySigAdr(request.m_replyAddress);

		if (neighbor_alias != "") {
			Kit->GWRewriteE164(neighbor_alias,true,request.m_destinationInfo[0]);
		}

		// Normal rewrite
		Kit->RewriteE164(request.m_destinationInfo[0]);
	}


	unsigned reason = H225_LocationRejectReason::e_securityDenial;
	PIPSocket::Address ipaddr;
	WORD port;
	bool fromRegEndpoint = false;
	bool replyAddrMatch = GetIPAndPortFromTransportAddr(request.m_replyAddress, ipaddr, port) && (ipaddr == m_msg->m_peerAddr && port == m_msg->m_peerPort);
	if (request.HasOptionalField(H225_LocationRequest::e_endpointIdentifier))
		if (endptr ep = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier))
			fromRegEndpoint = replyAddrMatch ? true : ep->IsNATed();

    // Neighbors do not need Validation
	bool bReject = !(fromRegEndpoint || RasSrv->GetNeighbors()->CheckLRQ(this));

	// If not Neighbor and support non neighbor LRQ's then validate the PDU
	if (bReject && (Toolkit::AsBool(GkConfig()->GetString(LRQFeaturesSection, "AcceptNonNeighborLRQ", "0"))))
		                   bReject = !RasSrv->ValidatePDU(*this, reason);


	PString sourceInfoString(fromRegEndpoint ? request.m_endpointIdentifier.GetValue() : request.HasOptionalField(H225_LocationRequest::e_gatekeeperIdentifier) ? request.m_gatekeeperIdentifier.GetValue() : m_msg->m_peerAddr.AsString());

	if (!bReject) {
		endptr WantedEndPoint;
		Route route;
		Routing::LocationRequest lrq(request, this);
		lrq.Process();
		if (lrq.GetFirstRoute(route)) {
			WantedEndPoint = route.m_destEndpoint;
			if ((lrq.GetRoutes().size() == 1 || !Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "ActivateFailover", "0")))
					&& WantedEndPoint && !WantedEndPoint->HasAvailableCapacity()) {
				bReject = true;
				reason = H225_LocationRejectReason::e_resourceUnavailable;
			} else {
				H225_LocationConfirm & lcf = BuildConfirm();
				GetRasAddress(lcf.m_rasAddress);
				if (RasSrv->IsGKRouted()) {
					GetCallSignalAddress(lcf.m_callSignalAddress);
/* The access token should be standarized somehow and use a correct object 
   identifier. As it does not (currently), we disable it to remove interop problems.
				PINDEX s = 0;
				if (lcf.HasOptionalField(H225_LocationConfirm::e_cryptoTokens))
					s = lcf.m_cryptoTokens.GetSize();
				else
					lcf.IncludeOptionalField(H225_LocationConfirm::e_cryptoTokens);
				lcf.m_cryptoTokens.SetSize(s + 1);
				lcf.m_cryptoTokens[s] = Neighbors::BuildAccessToken(*dest, ipaddr);
*/
				} else {
					lcf.m_callSignalAddress = route.m_destAddr;
				}

				// canMapAlias: include destinationInfo if it has been changed
				if (lrq.GetFlags() & Routing::LocationRequest::e_aliasesChanged
					&& request.HasOptionalField(H225_LocationRequest::e_canMapAlias)
					&& request.m_canMapAlias) {
					if (!lcf.HasOptionalField(H225_LocationConfirm::e_destinationInfo)) {
						lcf.IncludeOptionalField(H225_LocationConfirm::e_destinationInfo);
						lcf.m_destinationInfo.SetSize(1);
					}
					lcf.m_destinationInfo = request.m_destinationInfo;
				}

				log = PString(PString::Printf, "LCF|%s|%s|%s|%s;",
					inet_ntoa(m_msg->m_peerAddr),
					(const unsigned char *) (WantedEndPoint ? WantedEndPoint->GetEndpointIdentifier().GetValue() : AsDotString(route.m_destAddr)),
					(const unsigned char *) AsString(request.m_destinationInfo),
					(const unsigned char *) sourceInfoString
					);
			}
		} else {
			if (m_msg->m_replyRAS.GetTag() == H225_RasMessage::e_requestInProgress) {
				// LRQ is forwarded
				H225_RequestInProgress & rip = m_msg->m_replyRAS;
				PString ripData;
				if (rip.HasOptionalField(H225_RequestInProgress::e_nonStandardData)) {
					int iec = Toolkit::iecUnknown;
					if (rip.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
						iec = Toolkit::Instance()->GetInternalExtensionCode(rip.m_nonStandardData.m_nonStandardIdentifier);
					} else if (rip.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_object) {
						PASN_ObjectId &oid = rip.m_nonStandardData.m_nonStandardIdentifier;
						if (oid.GetDataLength() == 0)
							iec = Toolkit::iecNeighborId;
					}
					if (iec == Toolkit::iecNeighborId)
						ripData = rip.m_nonStandardData.m_data.AsString();
				}
				log = PString(PString::Printf, "RIP|%s|%s|%s|%s;",
					inet_ntoa(m_msg->m_peerAddr),
					(const unsigned char *) ripData,
					(const unsigned char *) AsString(request.m_destinationInfo),
					(const unsigned char *) sourceInfoString
				      );
			} else {
				bReject = true;
				reason = lrq.GetRejectReason();
			}
		}
	}

	if (bReject) {
		// Alias not found
		H225_LocationReject & lrj = BuildReject(reason);
		log = PString(PString::Printf, "LRJ|%s|%s|%s|%s;",
			inet_ntoa(m_msg->m_peerAddr),
			(const unsigned char *) AsString(request.m_destinationInfo),
			(const unsigned char *) sourceInfoString,
			(const unsigned char *) lrj.m_rejectReason.GetTagName()
		      );
	}

	// for a regsistered endpoint, reply to the sent address
	if (!(fromRegEndpoint || replyAddrMatch))
		m_msg->m_peerAddr = ipaddr, m_msg->m_peerPort = port;

	PrintStatus(log);
	return true;
}

template<> bool RasPDU<H225_InfoRequestResponse>::Process()
{
	// OnIRR
	if (endptr ep = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier)) {
		ep->Update(m_msg->m_recvRAS);
		callptr call;
		if (request.HasOptionalField(H225_InfoRequestResponse::e_perCallInfo) && request.m_perCallInfo.GetSize() > 0)
			call = CallTbl->FindCallRec(request.m_perCallInfo[0].m_callIdentifier);
		else if (request.m_callSignalAddress.GetSize() > 0)
			call = CallTbl->FindBySignalAdr(request.m_callSignalAddress[0]);
		if (call)
			call->Update(request);
		if (request.HasOptionalField(H225_InfoRequestResponse::e_needResponse) && request.m_needResponse) {
			BuildConfirm();
			PrintStatus(PString(PString::Printf, "IACK|%s;", inet_ntoa(m_msg->m_peerAddr)));
			return true;
		}
	}
	// otherwise don't respond
	return false;
}

template<> bool RasPDU<H225_ResourcesAvailableIndicate>::Process()
{
	// OnRAI
	// accept all RAIs
	H225_ResourcesAvailableConfirm & rac = BuildConfirm();
	rac.m_protocolIdentifier = request.m_protocolIdentifier;

	PrintStatus(PString(PString::Printf, "RAC|%s;", inet_ntoa(m_msg->m_peerAddr)));
	return true;
}

template<> bool RasPDU<H225_RegistrationReject>::Process()
{
	// OnRRJ
	if (request.HasOptionalField(H225_RegistrationReject::e_nonStandardData)
		&& request.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard
		&& Toolkit::Instance()->GetInternalExtensionCode((const H225_H221NonStandard&)request.m_nonStandardData.m_nonStandardIdentifier) == Toolkit::iecFailoverRAS) {

		// RRJ from alternateGKs
		H225_EndpointIdentifier id;
		id = request.m_nonStandardData.m_data.AsString();

		if (endptr ep = EndpointTbl->FindByEndpointId(id))  {
			m_msg->m_replyRAS = ep->GetCompleteRegistrationRequest();
			if (m_msg->m_replyRAS.GetTag() == H225_RasMessage::e_registrationRequest) {
				CopyNonStandardData(request, (H225_RegistrationRequest &)m_msg->m_replyRAS);
				PTRACE(3, "RAS\tSending full RRQ to " << m_msg->m_peerAddr);
				return true;
			}
		}
	}

	return false;
}
