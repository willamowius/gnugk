//////////////////////////////////////////////////////////////////
//
// RAS Server for GNU Gatekeeper
//
// Copyright (c) 2000-2023, Jan Willamowius
// Copyright (c) Citron Network Inc. 2001-2003
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "config.h"
#ifdef __GNU_LIBRARY__
#include <malloc.h> // for  malloc_trim()
#endif
#include <ptlib.h>
#include <ptlib/sockets.h>
#include <ptclib/enum.h>
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
#include "h323util.h"
#include "gkauth.h"
#include "gkacct.h"
#include "gktimer.h"
#include "RasSrv.h"

#ifdef HAS_AVAYA_SUPPORT
#include "avaya.h"
#endif

#ifdef HAS_H460
	#include <h460/h4601.h>
	#ifdef HAS_H46018
		#include <h460/h46018.h>
	#endif
#endif

const char * OID_TSSM = "0.0.8.235.0.4.79";

const char *LRQFeaturesSection = "RasSrv::LRQFeatures";
const char *RRQFeatureSection = "RasSrv::RRQFeatures";
using namespace std;
using Routing::Route;

class RegistrationRequestPDU : public RasPDU<H225_RegistrationRequest> {
public:
	RegistrationRequestPDU(GatekeeperMessage *m) : RasPDU<H225_RegistrationRequest>(m) { }

	// override from class RasPDU<H225_RegistrationRequest>
	virtual bool Process();

	struct Creator : public RasPDU<H225_RegistrationRequest>::Creator {
		virtual RasMsg *operator()(GatekeeperMessage *m) const { return new RegistrationRequestPDU(m); }
	};
private:
	bool BuildRCF(const endptr & ep, bool additiveRegistration = false);
	bool BuildRRJ(unsigned reason, bool alt = false);
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
	bool BuildReply(int reason, bool h460 = false, CallRec * rec = NULL);

	/** @return
	    A string that can be used to identify a calling number.
	*/
	PString GetCallingStationId(
		/// additional data, like call record and requesting endpoint
		ARQAuthData & authData
		) const;

	/** @return
	    A string that can be used to identify a calling number.
	*/
	PString GetCalledStationId(
		/// additional data, like call record and requesting endpoint
		ARQAuthData & authData
		) const;

	/** @return
	    A string that can be used to identify the billing number.
	*/
	PString GetCallLinkage(
		/// additional data, like call record and requesting endpoint
		ARQAuthData & authData
		) const;

	endptr RequestingEP, CalledEP;
	PString destinationString;
	PStringList Language;
};

template<> H225_NonStandardParameter *RasPDU<H225_UnknownMessageResponse>::GetNonStandardParam()
{
	return NULL;
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
	"IRQ",				// Information Request
	"IRR",				// Information Request Response
	"NonStandardMessage",		// Non Standard Message
	"UnknownMessageResponse",	// Unknown Message Response
	"RIP",				// Request In Progress
	"RAI",				// Resources Available Indicate
	"RAC",				// Resources Available Confirm
	"IACK",				// Information Request Acknowledgment
	"INAK",				// Information Request Negative Acknowledgment
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

bool GatekeeperMessage::Read(RasListener * socket)
{
	m_socket = socket;
	const int buffersize = 4096;
	BYTE buffer[buffersize];
	if (!socket->Read(buffer, buffersize)) {
        if (socket->GetErrorCode(PSocket::LastReadError) != PSocket::NoError) {
            PTRACE(1, "RAS\tRead error " << socket->GetErrorCode(PSocket::LastReadError)
                << '/' << socket->GetErrorNumber(PSocket::LastReadError) << ": "
                << socket->GetErrorText(PSocket::LastReadError));
            SNMP_TRAP(10, SNMPError, Network, "RAS read error : " + socket->GetErrorText(PSocket::LastReadError));
        }
		return false;
	}
	socket->GetLastReceiveAddress(m_peerAddr, m_peerPort);
	UnmapIPv4Address(m_peerAddr);
	PTRACE(2, "RAS\tRead from " << AsString(m_peerAddr, m_peerPort));
	m_rasPDU = PPER_Stream(buffer, socket->GetLastReadCount());
	bool result = m_recvRAS.Decode(m_rasPDU);
	PTRACE_IF(1, !result, "RAS\tError: Could not decode message from " << AsString(m_peerAddr, m_peerPort));
	return result;
}

#ifdef HAS_H46017
bool GatekeeperMessage::Read(const PBYTEArray & buffer)
{
	m_rasPDU = PPER_Stream(buffer);
	bool result = m_recvRAS.Decode(m_rasPDU);
	PTRACE_IF(1, !result, "RAS\tCould not decode H.460.17 message");
	return result;
}
#endif

bool GatekeeperMessage::Reply(GkH235Authenticators * authenticators)
{
#ifdef HAS_H46017
	if (m_h46017Socket) {
		return m_h46017Socket->SendH46017Message(m_replyRAS, authenticators);
	}
#endif
	if (m_socket) {
		return m_socket->SendRas(m_replyRAS, m_peerAddr, m_peerPort, authenticators);
	} else {
		return false;
	}
}


// class RasListener
RasListener::RasListener(const Address & addr, WORD pt) : UDPSocket(0, addr.GetVersion() == 6 ? AF_INET6 : AF_INET), m_ip(addr)
{
	if (!Listen(addr, 0, pt, PSocket::CanReuseAddress)) {
		PTRACE(1, "RAS\tCould not open listening socket at " << AsString(addr, pt)
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< GetErrorNumber(PSocket::LastGeneralError) << ": "
			<< GetErrorText(PSocket::LastGeneralError)
			);
		Close();
	}
	SetWriteTimeout(1000);
	SetName(AsString(addr, pt) + "(U)");
	if (Toolkit::Instance()->IsPortNotificationActive())
		Toolkit::Instance()->PortNotification(RASPort, PortOpen, "udp", addr, pt);
	m_signalPort = 0;
#ifdef HAS_TLS
	m_tlsSignalPort = 0;
#endif
	// note: this won't be affected by reloading
	m_virtualInterface = (!GkConfig()->GetString("NetworkInterfaces", "").IsEmpty());
	// Check if we have external IP setting
	if (!m_virtualInterface) {
		m_virtualInterface = (!Toolkit::Instance()->GetExternalIP().IsEmpty());
	}
}

RasListener::~RasListener()
{
	if (Toolkit::Instance()->IsPortNotificationActive())
		Toolkit::Instance()->PortNotification(RASPort, PortClose, "udp", m_ip, GetPort());
	PTRACE(1, "RAS\tDelete listener " << GetName());
}

GatekeeperMessage *RasListener::ReadRas()
{
	PTRACE(4, "RAS\tReceiving on " << GetName());
	GatekeeperMessage *msg = new GatekeeperMessage();
	if (!(msg->Read(this) && Filter(msg))) {
		delete msg;
		return NULL;
	}
	if ((msg->GetTag() != H225_RasMessage::e_serviceControlIndication && msg->GetTag() != H225_RasMessage::e_serviceControlResponse)
		||  PTrace::CanTrace(5)) {
	if (PTrace::CanTrace(3))
		PTRACE(3, "RAS\n" << setprecision(2) << msg->m_recvRAS);
	else
		PTRACE(2, "RAS\tReceived " << msg->GetTagName() << " from " << AsString(msg->m_peerAddr, msg->m_peerPort));
	}
	msg->m_localAddr = GetLocalAddr(msg->m_peerAddr);
	return msg;
}

bool RasListener::SendRas(H225_RasMessage & rasobj, const Address & addr, WORD pt, GkH235Authenticators * auth)
{
	if ( ((rasobj.GetTag() != H225_RasMessage::e_serviceControlIndication && rasobj.GetTag() != H225_RasMessage::e_serviceControlResponse) && PTrace::CanTrace(3))
		|| PTrace::CanTrace(5))
		PTRACE(3, "RAS\tSend to " << AsString(addr, pt) << '\n' << setprecision(2) << rasobj);
	else
		PTRACE(2, "RAS\tSend " << RasName[rasobj.GetTag()] << " to " << AsString(addr, pt));

	PBYTEArray wtbuf(1024); // buffer with initial size 1024
	PPER_Stream wtstrm(wtbuf);
	rasobj.Encode(wtstrm);
	wtstrm.CompleteEncoding();

	// make sure buffer gets shrunk to size of encoded message, because we'll write it instead of the PPER_Stream
	wtbuf.SetSize(wtstrm.GetSize());
	if (auth != NULL)
		auth->Finalise(rasobj, wtbuf);

	m_wmutex.Wait();
	//bool result = WriteTo(wtstrm.GetPointer(), wtstrm.GetSize(), addr, pt);
    // must send PByteArray, with the updated H.235 hash; PPER_Stream doesn't seem to change
	bool result = WriteTo(wtbuf.GetPointer(), wtbuf.GetSize(), addr, pt);
	m_wmutex.Signal();
	if (result)
		PTRACE(5, "RAS\tSent Successful");
	else {
		PTRACE(1, "RAS\tWrite error " << GetErrorCode(PSocket::LastWriteError) << '/'
			<< GetErrorNumber(PSocket::LastWriteError) << ": "
			<< GetErrorText(PSocket::LastWriteError)
			);
		SNMP_TRAP(10, SNMPError, Network, "RAS write error: " + GetErrorText(PSocket::LastWriteError));
	}
	return result;
}

PIPSocket::Address RasListener::GetPhysicalAddr(const Address & /* addr */) const
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
	PTRACE(1, "RAS\tIgnoring broadcasted RAS message " << msg->GetTagName());
	return false;
}


// class MulticastListener
class MulticastListener : public RasListener {
public:
	MulticastListener(const Address &, WORD);

	// override from class RasListener
	virtual bool Filter(GatekeeperMessage *) const;
};

// we must listen to INADDR_ANY to get multicast packets, but we need to
// call setsockopt() for each IP so all interfaces join the multicast group (tested on Linux 2.6.x)
MulticastListener::MulticastListener(const Address & addr, WORD pt) : RasListener(INADDR_ANY, pt)
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
	port = pt;
}

bool MulticastListener::Filter(GatekeeperMessage * msg) const
{
	unsigned tag = msg->GetTag();
	if (tag == H225_RasMessage::e_gatekeeperRequest
		|| tag == H225_RasMessage::e_locationRequest)
		return true;
	PTRACE(1, "RAS\tInvalid multicasted RAS message: " << msg->GetTagName());
	return false;
}


// class RasMsg
void RasMsg::Exec()
{
	PTRACE(1, "RAS\t" << m_msg->GetTagName() << " Received from " << AsString(m_msg->m_peerAddr, m_msg->m_peerPort));
	if (Process()) {
		Reply(m_authenticators);
	}
}

bool RasMsg::IsFrom(const PIPSocket::Address & addr, WORD pt) const
{
	return (addr == m_msg->m_peerAddr) && (pt == 0 || pt == m_msg->m_peerPort);
}

void RasMsg::GetRasAddress(H225_TransportAddress & result) const
{
	result = SocketToH225TransportAddr(m_msg->m_localAddr, m_msg->m_socket ? m_msg->m_socket->GetPort() : 0);
}

void RasMsg::GetCallSignalAddress(H225_TransportAddress & result) const
{
#ifdef HAS_H46017
	if (m_msg->m_h46017Socket)
		result = SocketToH225TransportAddr(m_msg->m_localAddr, m_msg->m_h46017Socket->GetPort());
	else
#endif
		result = SocketToH225TransportAddr(m_msg->m_localAddr, m_msg->m_socket ? m_msg->m_socket->GetSignalPort() : 0);
}

/// Get an address the message has been received from
void RasMsg::GetPeerAddr(PIPSocket::Address & addr, WORD & port) const
{
    addr = m_msg->m_peerAddr;
    port = m_msg->m_peerPort;
}

void RasMsg::GetPeerAddr(PIPSocket::Address & addr) const
{
    addr = m_msg->m_peerAddr;
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

bool RasMsg::PrintStatus(const PString & log)
{
	PTRACE(2, log);
	// avoid printing on an already deleted status port
	if (!IsGatekeeperShutdown()) {
		GkStatus::Instance()->SignalStatus(log + "\r\n", STATUS_TRACE_LEVEL_RAS);
	}
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
H225_NonStandardParameter * RasPDU<RAS>::GetNonStandardParam()
{
	return request.HasOptionalField(RAS::e_nonStandardData) ? &request.m_nonStandardData : NULL;
}

// template specialization for H225_NonStandardMessage which doesn't have e_nonStandardData
template<>
H225_NonStandardParameter * RasPDU<H225_NonStandardMessage>::GetNonStandardParam()
{
	return NULL;
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
	return m_msg->m_replyRAS;
}

// class GkInterface
GkInterface::GkInterface(const PIPSocket::Address & addr) : m_address(addr)
{
	m_rasPort = m_multicastPort = m_signalPort = m_statusPort = 0;
	m_rasListener = NULL;
	m_multicastListener = NULL;
	m_callSignalListener = NULL;
	m_statusListener = NULL;
	m_rasSrv = NULL;
#ifdef HAS_TLS
	m_tlsSignalPort = 0;
	m_tlsCallSignalListener = NULL;
#endif
#ifdef HAS_H46018
	m_h245MultiplexPort = 0;
	m_multiplexH245Listener = NULL;
#endif
}

GkInterface::~GkInterface()
{
	// TODO/BUG: without LARGE_FDSET, closing RAS sockets may hang on ConfigReloadMutex
	if (m_rasListener)
		m_rasListener->Close();
	if (m_multicastListener)
		m_multicastListener->Close();
	if (m_callSignalListener)
		m_rasSrv->CloseListener(m_callSignalListener);
#ifdef HAS_TLS
	if (m_tlsCallSignalListener)
		m_rasSrv->CloseListener(m_tlsCallSignalListener);
#endif
#ifdef HAS_H46018
	if (m_multiplexH245Listener)
		m_rasSrv->CloseListener(m_multiplexH245Listener);
#endif
	if (m_statusListener)
		m_rasSrv->CloseListener(m_statusListener);
}

bool GkInterface::CreateListeners(RasServer *RasSrv)
{
	m_rasSrv = RasSrv;

	WORD rasPort = (WORD)GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT);
	WORD multicastPort = (WORD)(GkConfig()->GetBoolean("UseMulticastListener", true) ?
		GkConfig()->GetInteger("MulticastPort", GK_DEF_MULTICAST_PORT) : 0);
	WORD signalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_CALL_SIGNAL_PORT);
#ifdef HAS_TLS
	WORD tlsSignalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT);
#endif
#ifdef HAS_H46018
	WORD h245MultiplexPort = (WORD)GkConfig()->GetInteger(RoutedSec, "H245MultiplexPort", GK_DEF_MULTIPLEX_H245_PORT);
#endif
	WORD statusPort = (WORD)GkConfig()->GetInteger("StatusPort", GK_DEF_STATUS_PORT);

	if (SetListener(rasPort, m_rasPort, m_rasListener, &GkInterface::CreateRasListener))
		m_rasSrv->AddListener(m_rasListener);
	if (SetListener(multicastPort, m_multicastPort, m_multicastListener, &GkInterface::CreateMulticastListener))
		m_rasSrv->AddListener(m_multicastListener);
	if (SetListener(signalPort, m_signalPort, m_callSignalListener, &GkInterface::CreateCallSignalListener))
		m_rasSrv->AddListener(m_callSignalListener);
#ifdef HAS_TLS
	if (Toolkit::Instance()->IsTLSEnabled()) {
		if (SetListener(tlsSignalPort, m_tlsSignalPort, m_tlsCallSignalListener, &GkInterface::CreateTLSCallSignalListener)) {
			m_rasSrv->AddListener(m_tlsCallSignalListener);
		}
	}
#endif
#ifdef HAS_H46018
	if (GkConfig()->GetBoolean(RoutedSec, "EnableH245Multiplexing", false)) {
		if (SetListener(h245MultiplexPort, m_h245MultiplexPort, m_multiplexH245Listener, &GkInterface::CreateMultiplexH245Listener)) {
			m_rasSrv->AddListener(m_multiplexH245Listener);
		}
	}
#endif
	if (statusPort > 0 && SetListener(statusPort, m_statusPort, m_statusListener, &GkInterface::CreateStatusListener))
		m_rasSrv->AddListener(m_statusListener);

	if (m_rasListener && m_callSignalListener) {
		if (RasSrv->IsGKRouted()) {
			m_rasListener->SetSignalPort(m_signalPort);
#ifdef HAS_TLS
			if (m_tlsCallSignalListener)
				m_rasListener->SetTLSSignalPort(m_tlsSignalPort);
#endif
			if (m_multicastListener) {
				m_multicastListener->SetSignalPort(m_signalPort);
			}
		} else {
			RasSrv->CloseListener(m_callSignalListener);
			m_callSignalListener = NULL;
#ifdef HAS_TLS
			RasSrv->CloseListener(m_tlsCallSignalListener);
			m_tlsCallSignalListener = NULL;
#endif
		}
	}
	// TODO: implement switch for additional listen ports here

	if (RasSrv->IsGKRouted()) {
		return (m_rasListener != NULL) && (m_callSignalListener != NULL);
	} else {
		return m_rasListener != NULL;
	}
}

bool GkInterface::IsReachable(const Address *addr) const
{
	return Toolkit::Instance()->GetRouteTable(false)->GetLocalAddress(*addr) == m_address;
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
	return (m_multicastPort && !IsLoopback(m_address) && (m_address.GetVersion() != 6)) ? new MulticastListener(m_address, m_multicastPort) : 0;
}

CallSignalListener *GkInterface::CreateCallSignalListener()
{
	return m_rasSrv->IsGKRouted() ? new CallSignalListener(m_address, m_signalPort) : NULL;
}

#ifdef HAS_TLS
TLSCallSignalListener *GkInterface::CreateTLSCallSignalListener()
{
	return m_rasSrv->IsGKRouted() ? new TLSCallSignalListener(m_address, m_tlsSignalPort) : NULL;
}
#endif

#ifdef HAS_H46018
MultiplexH245Listener *GkInterface::CreateMultiplexH245Listener()
{
	return m_rasSrv->IsGKRouted() ? new MultiplexH245Listener(m_address, m_h245MultiplexPort) : NULL;
}
#endif

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

// class RasRequester
RasRequester::RasRequester(H225_RasMessage & req) : m_request(&req), m_loAddr(GNUGK_INADDR_ANY)
{
	Init();
}

RasRequester::RasRequester(H225_RasMessage & req, const Address & addr) : m_request(&req), m_loAddr(addr)
{
	Init();
}

void RasRequester::Init()
{
	m_txPort = 0;
	m_seqNum = m_rasSrv->GetRequestSeqNum();
	m_timeout = 0;
	m_retry = 0;
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
		if (m_timeout > passed && m_sync.Wait(m_timeout - passed)) {
			if (m_timeout > 0) {
				continue;
			} else {
				break;
			}
		}
		if (!OnTimeout()) {
			break;
		}
	}
	return m_iterator != m_queue.end();
}

RasMsg * RasRequester::GetReply()
{
	PWaitAndSignal lock(m_qmutex);
	return m_iterator != m_queue.end() ? *m_iterator++ : NULL;
}

bool RasRequester::IsExpected(const RasMsg * ras) const
{
	return RasHandler::IsExpected(ras) && (ras->GetSeqNum() == m_seqNum) && ras->IsFrom(m_txAddr, m_txPort);
}

void RasRequester::Process(RasMsg * ras)
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

bool RasRequester::SendRequest(const PIPSocket::Address & addr, WORD pt, int retry)
{
	m_txAddr = addr, m_txPort = pt, m_retry = retry;
	m_sentTime = PTime();
	return m_rasSrv->SendRas(*m_request, m_txAddr, m_txPort, m_loAddr, NULL);   // TODO235
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
RasServer::RasServer() : Singleton<RasServer>("RasSrv")
{
	SetName("RasSrv");

	requestSeqNum = 0;
	listeners = NULL;
	broadcastListener = NULL;
	sigHandler = NULL;
	authList = NULL;
	acctList = NULL;
	gkClient = NULL;
	neighbors = NULL;
	vqueue = NULL;
	GKRoutedSignaling = false;
	GKRoutedH245 = false;
	bRemoveCallOnDRQ = true;
	altGKsSize = 0;
	epLimit = callLimit = P_MAX_INDEX;
	redirectGK = e_noRedirect;
}

RasServer::~RasServer()
{
	delete authList;
	delete acctList;
	delete neighbors;
	delete gkClient;
	PWaitAndSignal lock(requests_mutex);
	DeleteObjectsInContainer(requests);
}

void RasServer::Stop()
{
#ifndef hasPTLibTraceOnShutdownBug
	PTRACE(1, "GK\tStopping RasServer...");
#endif
	SNMP_TRAP(2, SNMPInfo, General, "GnuGk stopping");
	PWaitAndSignal lock(m_deletionPreventer);
	ForEachInContainer(handlers, mem_vfun(&RasHandler::Stop));
	delete vqueue;	// delete virtual queues before Jobs, otherwise the jobs will wait for the queues
	vqueue = NULL;
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
			sigHandler = new HandlerList();
	} else {
		// warning: dangerous
		delete sigHandler;
		sigHandler = NULL;
	}
	GKRoutedH245 = GKRoutedSignaling ? routedH245 : false;

	const char *modemsg = GKRoutedSignaling ? "Routed" : "Direct";
	const char *h245msg = GKRoutedH245 ? "Enabled" : "Disabled";
	PTRACE(2, "GK\tUsing " << modemsg << " Signaling");
	PTRACE(2, "GK\tH.245 Routed " << h245msg);
	const char * h245tunnelingmsg = GkConfig()->GetBoolean("RoutedMode", "H245TunnelingTranslation", false) ? "Enabled" : "Disabled";
	PTRACE(2, "GK\tH.245 tunneling translation " << h245tunnelingmsg);
#ifdef HAS_H46017
	const char * h46017msg = GkConfig()->GetBoolean("RoutedMode", "EnableH46017", false) ? "Enabled" : "Disabled";
	PTRACE(2, "GK\tH.460.17 Registrations " << h46017msg);
#endif
#ifdef HAS_H46018
	const char * h46018msg = GkConfig()->GetBoolean("RoutedMode", "EnableH46018", false) ? "Enabled" : "Disabled";
	PTRACE(2, "GK\tH.460.18 Registrations " << h46018msg);
#endif
}

void RasServer::SetENUMServers()
{
#if hasSETENUMSERVERS
  PString servers = GkConfig()->GetString(RoutedSec, "ENUMservers", "");
  PStringArray serverlist(servers.Tokenise(",", false));

  if (serverlist.GetSize() > 0) {
	   PDNS::SetENUMServers(serverlist);
       PTRACE(2, "GK\tLoaded ENUM servers " << serverlist);
  } else {
	   PTRACE(2, "GK\tNo ENUMservers set, using defaults");
  }
#else
#if P_DNS
	   PTRACE(2, "GK\tSetENUMServers not available, using defaults");
#else
	   PTRACE(2, "GK\tNo ENUM Routing policy available.");
#endif
#endif
}

void RasServer::SetRDSServers()
{
#if hasRDS
  PString servers = GkConfig()->GetString(RoutedSec, "RDSservers", "");
  PStringArray serverlist(servers.Tokenise(",", false));

  if (serverlist.GetSize() > 0) {
	   PDNS::SetRDSServers(serverlist);
       PTRACE(2, "GK\tLoaded RDS servers " << serverlist);
  } else {
 	   PTRACE(2, "GK\tNo RDSservers set, using defaults");
  }
#else
	   PTRACE(2, "GK\tNo RDS Routing policy available.");
#endif
}

bool RasServer::AcceptUnregisteredCalls(const PIPSocket::Address & addr) const
{
	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AcceptUnregisteredCalls", "0")))
		return true;
	return Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AcceptNeighborsCalls", "1")) ? neighbors->CheckIP(addr) : false;
}

bool RasServer::AcceptPregrantedCalls(const H225_Setup_UUIE & setupBody, const PIPSocket::Address & addr) const
{
	if (!GkConfig()->GetBoolean(RoutedSec, "PregrantARQ", false))
		return false;

	if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_endpointIdentifier))
		return false;

	endptr ep = RegistrationTable::Instance()->FindByEndpointId(setupBody.m_endpointIdentifier);
	if (ep) {
		PIPSocket::Address epIP;
		WORD epPort = 0;
		if (GetIPAndPortFromTransportAddr(ep->GetCallSignalAddress(), epIP, epPort) && epIP == addr) {
			PTRACE(3, "Q931\tAccepting pre-granted Call");
			return true;
		}
	}
	return false;
}

bool RasServer::IsCallFromTraversalClient(const PIPSocket::Address & addr) const
{
	return neighbors->IsTraversalClient(addr);
}

bool RasServer::IsCallFromTraversalServer(const PIPSocket::Address & addr) const
{
	return neighbors->IsTraversalServer(addr);
}

bool RasServer::RegisterHandler(RasHandler *handler)
{
	PWaitAndSignal lock(handlers_mutex);
	handlers.push_front(handler);
	return true;
}

bool RasServer::UnregisterHandler(RasHandler *handler)
{
	PWaitAndSignal lock(handlers_mutex);
	handlers.remove(handler);
	return true;
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
		SNMP_TRAP(10, SNMPError, Configuration, "No RAS interface");
		return;
	}

	SocketsReader::CleanUp();
	ifiterator it = interfaces.begin();
	while (it != interfaces.end()) {
		int i = -1;
		while (++i < hsize)
			if ((*it)->IsBoundTo(&GKHome[i]))
				break;
		if (i == hsize) {
			// close unused listeners
			GkInterface * r = *it;
			it = interfaces.erase(it);
			delete r;
		}
		else ++it;
	}
	if (broadcastListener && !bUseBroadcastListener) {
		broadcastListener->Close();
		broadcastListener = NULL;
	}

	RemoveClosed(false); // delete the closed sockets next time

	for (int i = 0; i < hsize; ++i) {
		Address addr(GKHome[i]);
#if (__cplusplus >= 201703L) // C++17
		ifiterator iter = find_if(interfaces.begin(), interfaces.end(), bind(mem_fn(&GkInterface::IsBoundTo), std::placeholders::_1, &addr));
#else
		ifiterator iter = find_if(interfaces.begin(), interfaces.end(), bind2nd(mem_fun(&GkInterface::IsBoundTo), &addr));
#endif
		if (iter == interfaces.end()) {
			GkInterface *gkif = CreateInterface(addr);
			if (gkif->CreateListeners(this)) {
				interfaces.push_back(gkif);
			} else {
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
	if ((m_socksize == 0) || (interfaces.empty())) {
		PTRACE(1, "Error: No valid RAS socket!");
		SNMP_TRAP(10, SNMPError, Configuration, "No RAS socket");
		return;
	}

#if NEED_BROADCASTLISTENER
	if (bUseBroadcastListener && !broadcastListener) {
		WORD rasPort = (WORD)GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT);
		broadcastListener = new BroadcastListener(rasPort);
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

#ifdef HAS_H46018
	// create multiplex RTP listeners
	if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)) {
		if (Toolkit::Instance()->IsH46018Enabled()) {
			MultiplexedRTPHandler::Instance()->OnReload();
		} else {
			PTRACE(1, "Warning: Must enable H.460.19 for RTP multiplexing");
		}
	} else {
		// if we had a multiplex listener configured before the reload, but not anymore, then delete it
		if (MultiplexedRTPHandler::InstanceExists())
			delete MultiplexedRTPHandler::Instance();
	}
#endif
#ifdef HAS_H46026
	if (Toolkit::Instance()->IsH46026Enabled()) {
		H46026RTPHandler::Instance()->OnReload();
	}
#endif

	if (listeners)
		listeners->LoadConfig();
	if (gkClient)
		gkClient->OnReload();
	if (neighbors)
		neighbors->OnReload();
	if (authList)
		authList->OnReload();
	if (acctList)
		acctList->OnReload();
	if (vqueue)
		vqueue->OnReload();
	Routing::Analyzer::Instance()->OnReload();
	Routing::ExplicitPolicy::OnReload();

	bRemoveCallOnDRQ = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveCallOnDRQ", "1"));

	// read [ReplyToRasAddress] section
	m_replyras.clear();
	PStringToString ras_rules(GkConfig()->GetAllKeyValues("ReplyToRasAddress"));
	for (PINDEX i = 0; i < ras_rules.GetSize(); ++i) {
		PString network = ras_rules.GetKeyAt(i);
		bool setting = Toolkit::AsBool(ras_rules.GetDataAt(i));
		if (!network.IsEmpty()) {
			NetworkAddress addr = NetworkAddress(network);
			m_replyras[addr] = setting;
		}
	}
}
bool RasServer::ReplyToRasAddress(const NetworkAddress & ip) const
{
	NetworkAddress bestmatch;
	bool result = false;

	std::map<NetworkAddress, bool>::const_iterator iter = m_replyras.begin();
	while (iter != m_replyras.end()) {
		if ((ip << iter->first) && (iter->first.GetNetmaskLen() >= bestmatch.GetNetmaskLen())) {
			bestmatch = iter->first;
			result = iter->second;
		}
		++iter;
	}

	return result;
}

void RasServer::AddListener(RasListener * socket)
{
	AddSocket(socket);
}

void RasServer::AddListener(TCPListenSocket * socket)
{
	if (socket->IsOpen())
		listeners->AddListener(socket);
	else {
		delete socket;
	}
}

bool RasServer::CloseListener(TCPListenSocket * socket)
{
	return listeners->CloseListener(socket);
}

WORD RasServer::GetRequestSeqNum()
{
	PWaitAndSignal lock(seqNumMutex);
	return ++requestSeqNum;
}

GkInterface *RasServer::SelectDefaultInterface(unsigned version)
{
	if (interfaces.empty())
		return NULL;

    PIPSocket::Address defIP = Toolkit::Instance()->GetRouteTable(false)->GetLocalAddress(version);
    ifiterator iter = interfaces.begin();
	while (iter != interfaces.end()) {
		GkInterface * intface = *iter++;
		if (intface->GetRasListener()->GetPhysicalAddr(defIP) == defIP)
			return intface;
	}
    PTRACE(1, "RasSrv\tWARNING: No route detected using first interface");
    return interfaces.front();
}

GkInterface *RasServer::SelectInterface(const Address & addr)
{
	if (interfaces.empty())
		return NULL;
    // prefer the interface that actually has the IP bound to it
#if (__cplusplus >= 201703L) // C++17
	ifiterator iter = find_if(interfaces.begin(), interfaces.end(), bind(mem_fn(&GkInterface::IsBoundTo), std::placeholders::_1, &addr));
#else
	ifiterator iter = find_if(interfaces.begin(), interfaces.end(), bind2nd(mem_fun(&GkInterface::IsBoundTo), &addr));
#endif
	if (iter != interfaces.end()) {
        return *iter;
	}
	// otherwise use an interface that can reach the IP
#if (__cplusplus >= 201703L) // C++17
	iter = find_if(interfaces.begin(), interfaces.end(), bind(mem_fn(&GkInterface::IsReachable), std::placeholders::_1, &addr));
#else
	iter = find_if(interfaces.begin(), interfaces.end(), bind2nd(mem_fun(&GkInterface::IsReachable), &addr));
#endif
	if (iter != interfaces.end()) {
        return *iter;
	}
    else
        return SelectDefaultInterface(addr.GetVersion());
}

const GkInterface *RasServer::SelectInterface(const Address & addr) const
{
	return const_cast<RasServer *>(this)->SelectInterface(addr);	// cast away const
}

RasListener * RasServer::GetRasListener(const Address & addr) const
{
	const GkInterface * interf = SelectInterface(addr);
	return interf ? interf->GetRasListener() : NULL;
}

PIPSocket::Address RasServer::GetLocalAddress(const Address & addr) const
{
	RasListener * listener = GetRasListener(addr);
	return listener ? listener->GetPhysicalAddr(addr) : PIPSocket::Address(0);
}

PIPSocket::Address RasServer::GetMasqAddress(const Address & addr) const
{
	RasListener * listener = GetRasListener(addr);
	return listener ? listener->GetLocalAddr(addr) : PIPSocket::Address(0);
}

H225_TransportAddress RasServer::GetRasAddress(const Address & addr) const
{
	RasListener * listener = GetRasListener(addr);
	return listener ? listener->GetRasAddress(addr) : H225_TransportAddress(0);
}

H225_TransportAddress RasServer::GetCallSignalAddress(const Address & addr) const
{
	RasListener * listener = GetRasListener(addr);
	return listener ? listener->GetCallSignalAddress(addr) : H225_TransportAddress(0);
}

bool RasServer::SendRas(H225_RasMessage & rasobj, const Address & addr, WORD pt, RasListener *socket, GkH235Authenticators * auth)
{
	if (socket == NULL) {
		GkInterface * inter = SelectInterface(addr);
		if (inter == NULL)
			return false;
		else
			socket = inter->GetRasListener();
	}
	return socket->SendRas(rasobj, addr, pt, auth);
}

bool RasServer::SendRas(H225_RasMessage & rasobj, const H225_TransportAddress & dest, RasListener *socket, GkH235Authenticators * auth)
{
	PIPSocket::Address addr;
	WORD pt;
	if (GetIPAndPortFromTransportAddr(dest, addr, pt))
		return SendRas(rasobj, addr, pt, socket, auth);
	PTRACE(1, "RAS\tInvalid address when trying to send " << rasobj.GetTagName());
	return false;
}

bool RasServer::SendRas(H225_RasMessage & rasobj, const Address & addr, WORD pt, const Address & local, GkH235Authenticators * auth)
{
	GkInterface * inter = SelectInterface(local);
	if (inter == NULL)
		return false;
	RasListener * listener = inter->GetRasListener();
	if (listener == NULL)
		return false;
	return listener->SendRas(rasobj, addr, pt, auth);
}

bool RasServer::SendRas(H225_RasMessage & rasobj, const H225_TransportAddress & dest, const Address & local, GkH235Authenticators * auth)
{
	PIPSocket::Address addr;
	WORD pt;
	if (GetIPAndPortFromTransportAddr(dest, addr, pt))
		return SendRas(rasobj, addr, pt, local, auth);
	PTRACE(1, "RAS\tInvalid address when trying to send " << rasobj.GetTagName());
	return false;
}

bool RasServer::SendRIP(H225_RequestSeqNum seqNum, unsigned ripDelay, const Address & addr, WORD port, GkH235Authenticators * auth)
{
	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_requestInProgress);
	H225_RequestInProgress & rip = ras_msg;
	rip.m_requestSeqNum.SetValue(seqNum);
	rip.m_delay = ripDelay;
	return SendRas(ras_msg, addr, port, NULL, auth);
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

	H225_NonStandardParameter oldParam;
	H225_NonStandardParameter *nonStandardParam = NULL;
	PASN_Sequence *sobj = NULL;
	unsigned tag = 0;
	H225_RequestSeqNum oldReqNum;
	H225_RequestSeqNum *reqNum = NULL;

	// ATS 2004-01-16 Forward messages to alternates using our own sequence numbers
	// instead of using those supplied by the originator of the message, this will
	// result in clashes in RasMsg::EqualTo() by the receiver of this message

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
			PTRACE(2, "Warning: unsupported RAS message type for forwarding: " << msg.GetTagName());
			return;
	}

	bool hasStandardParam = sobj->HasOptionalField(tag);
	if (hasStandardParam)
		oldParam = *nonStandardParam;
	else
		sobj->IncludeOptionalField(tag);

	// include the "this is a forwarded message" tag (could be a static variable to increase performance)
	H225_NonStandardIdentifier & id = nonStandardParam->m_nonStandardIdentifier;
	id.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
	H225_H221NonStandard & h221 = id;
	h221.m_t35CountryCode   = Toolkit::t35cOpenOrg;
	h221.m_t35Extension     = Toolkit::t35eFailoverRAS;
	h221.m_manufacturerCode = Toolkit::t35mOpenOrg;

	for (int i = 0; i < altGKsSize; ++i) {
		PTRACE(4, "Forwarding RAS to " << AsString(altGKsAddr[i], altGKsPort[i]));
		SendRas(msg, altGKsAddr[i], altGKsPort[i], NULL);   // TODO235
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

bool RasServer::IsPassThroughRegistrant()
{
	return (gkClient && gkClient->UsesAdditiveRegistration());
}

bool RasServer::RemoveAdditiveRegistration(const H225_ArrayOf_AliasAddress & aliases)
{
	return (gkClient && gkClient->AdditiveUnRegister(aliases));
}

ProxyHandler * RasServer::GetSigProxyHandler()
{
	return sigHandler ? sigHandler->GetSigHandler() : NULL;
}

ProxyHandler * RasServer::GetRtpProxyHandler()
{
	return sigHandler ? sigHandler->GetRtpHandler() : NULL;
}

void RasServer::SelectH235Capability(const H225_GatekeeperRequest & grq, H225_GatekeeperConfirm & gcf) const
{
	authList->SelectH235Capability(grq, gcf);
}

bool RasServer::ValidateAdditivePDU(RasPDU<H225_RegistrationRequest> & ras, RRQAuthData & authData)
{
	H225_RegistrationRequest & rrq = (ras)->m_recvRAS;
	H225_ArrayOf_ClearToken * tokens = rrq.HasOptionalField(H225_RegistrationRequest::e_tokens) ? &rrq.m_tokens : NULL;
	H225_ArrayOf_CryptoH323Token * cryptotokens = rrq.HasOptionalField(H225_RegistrationRequest::e_cryptoTokens) ? &rrq.m_cryptoTokens : NULL;
	return (gkClient && gkClient->AdditiveRegister(rrq.m_terminalAlias, authData.m_rejectReason, tokens, cryptotokens));
}

bool RasServer::LogAcctEvent(int evt, const callptr & call, time_t now)
{
	return acctList->LogAcctEvent((GkAcctLogger::AcctEvent)evt, call, now);
}

bool RasServer::LogAcctEvent(int evt, const endptr & ep)
{
	return acctList->LogAcctEvent((GkAcctLogger::AcctEvent)evt, ep);
}

PString RasServer::GetAuthInfo(const PString & moduleName)
{
	return authList->GetInfo(moduleName);
}

PString RasServer::GetAcctInfo(const PString & moduleName)
{
	return acctList->GetInfo(moduleName);
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
#ifndef HAS_AVAYA_SUPPORT
	RasPDU<H225_NonStandardMessage>::Creator NonStandardCreator;
#else
	RasPDU<H225_NonStandardMessage>::Creator NSMCreator;
#endif

	listeners = new TCPServer();
	gkClient = new GkClient();
	neighbors = new NeighborList();
	authList = new GkAuthenticatorList();
	acctList = new GkAcctLoggerList();
	vqueue = new VirtualQueue();

	LoadConfig();

	if ((m_socksize > 0) && (!interfaces.empty())) {
		acctList->LogAcctEvent(GkAcctLogger::AcctOn, callptr(NULL));

		CreateJob(this, &RasServer::HouseKeeping, "HouseKeeping");

#ifdef HAS_SNMP
		if (Toolkit::Instance()->IsSNMPEnabled()) {
			StartSNMPAgent();
		}
#endif

		RegularJob::Run();

		acctList->LogAcctEvent(GkAcctLogger::AcctOff, callptr(NULL));
	} else {
		SNMP_TRAP(10, SNMPError, Network, "No valid interfaces to listen! Shutdown!");
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

#ifdef HAS_SNMP
	StopSNMPAgent();
#endif

	PTRACE(1, "GK\tRasServer stopped");
}

// load configuration for alternate gatekeepers
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


	// read [RasSrv::AlternateGatekeeper] section
	m_altGkRules.clear();
	PStringToString altgk_rules(GkConfig()->GetAllKeyValues("RasSrv::AlternateGatekeeper"));
	for (PINDEX i = 0; i < altgk_rules.GetSize(); ++i) {
		PString network = altgk_rules.GetKeyAt(i);
		PString setting = altgk_rules.GetDataAt(i);
		if (!network.IsEmpty()) {
			NetworkAddress addr = NetworkAddress(network);
			m_altGkRules[addr] = ParseAltGKConfig(setting);
		}
	}

	// parse global alt gk config
	PString altGkSetting = GkConfig()->GetString("AlternateGKs", "");
	if (!altGkSetting.IsEmpty())
		altGKs = ParseAltGKConfig(altGkSetting);

	PString sendto(GkConfig()->GetString("SendTo", ""));
	PStringArray svrs(sendto.Tokenise(" ,;\t", FALSE));
	if ((altGKsSize = svrs.GetSize()) > 0)
		for (PINDEX i = 0; i < altGKsSize; ++i) {
			PStringArray tokens = SplitIPAndPort(svrs[i], GK_DEF_UNICAST_RAS_PORT);
			altGKsAddr.push_back(Address(tokens[0]));
			altGKsPort.push_back(WORD(tokens[1].AsUnsigned()));
		}
}

H225_ArrayOf_AlternateGK RasServer::ParseAltGKConfig(const PString & altGkSetting) const
{
	PStringArray altgks(altGkSetting.Tokenise(",", FALSE));
	H225_ArrayOf_AlternateGK alternateGKs;
	alternateGKs.SetSize(altgks.GetSize());

	for (PINDEX idx = 0; idx < altgks.GetSize(); ++idx) {
		const PStringArray tokens = altgks[idx].Tokenise(";", FALSE);
		if (tokens.GetSize() < 4 || tokens.GetSize() > 5) {
			PTRACE(1, "GK\tFormat error in AlternateGKs");
			SNMP_TRAP(7, SNMPError, Configuration, "Invalid AlternateGK config");
			continue;
		}

		H225_AlternateGK & alt = alternateGKs[idx];
		alt.m_rasAddress = SocketToH225TransportAddr(Address(tokens[0]), (WORD)tokens[1].AsUnsigned());
		alt.m_needToRegister = Toolkit::AsBool(tokens[2]);
		alt.m_priority = tokens[3].AsInteger();
		if (tokens.GetSize() > 4) {
			alt.IncludeOptionalField(H225_AlternateGK::e_gatekeeperIdentifier);
			alt.m_gatekeeperIdentifier = tokens[4];
		}
	}

	return alternateGKs;
}

H225_ArrayOf_AlternateGK RasServer::GetAltGKForIP(const NetworkAddress & ip) const
{
	// find alternate gatekeeper rule by IP address
	H225_ArrayOf_AlternateGK result;
	NetworkAddress bestmatch;
	std::map<NetworkAddress, H225_ArrayOf_AlternateGK>::const_iterator iter = m_altGkRules.begin();
	while (iter != m_altGkRules.end()) {
		if ((ip << iter->first) && (iter->first.GetNetmaskLen() >= bestmatch.GetNetmaskLen())) {
			bestmatch = iter->first;
			result = iter->second;
		}
		++iter;
	}
	return result;
}

void RasServer::ClearAltGKsTable()
{
	redirectGK = e_noRedirect;
	altGKs.SetSize(0);
	altGKsAddr.clear();
	skipAddr.clear();
	altGKsPort.clear();
	altGKsSize = 0;
	epLimit = callLimit = P_MAX_INDEX;
}

void RasServer::HouseKeeping()
{
    bool loopDetection = GkConfig()->GetBoolean("RasSrv::LRQFeatures", "LoopDetection", false);
	for (unsigned count = 0; IsRunning(); ++count) {
		if (!Wait(1000)) {
			if( !IsRunning() )
				break;

			ReadLock lock(ConfigReloadMutex);

			if (!(count % 60)) { // one minute
				RegistrationTable::Instance()->CheckEndpoints();
                CallTable::Instance()->CheckRTPInactive();
#ifdef __GNU_LIBRARY__
                // give unused memory back to OS
                malloc_trim(0);
#endif
			}
			if (!(count % 10)) { // every 10 sec
                if (loopDetection)
                    CallLoopTable::Instance()->Expire();
			}

			CallTable::Instance()->CheckCalls(this);

			gkClient->CheckRegistration();

			Toolkit::Instance()->GetTimerManager()->CheckTimers();
		}
	}
}

void RasServer::ReadSocket(IPSocket *socket)
{
	RasListener *listener = static_cast<RasListener *>(socket);
	if (GatekeeperMessage *msg = listener->ReadRas()) {
		CreateRasJob(msg);
	}
}

#ifdef HAS_H46017
void RasServer::ReadH46017Message(const PBYTEArray & ras, const PIPSocket::Address & fromIP, WORD fromPort, const PIPSocket::Address & localAddr, CallSignalSocket * s)
{
	GatekeeperMessage * msg = new GatekeeperMessage();
	if (msg->Read(ras)) {
		msg->m_peerAddr = fromIP;
		msg->m_peerPort = fromPort;
		msg->m_localAddr = localAddr;
		msg->m_h46017Socket = s;
		PTRACE(3, "RAS\tH460.17 RAS\n" << setprecision(2) << msg->m_recvRAS);
		// execute job synchronously, so we don't return to signaling thread before processing is done
		CreateRasJob(msg, true);
	}
}
#endif

void RasServer::CreateRasJob(GatekeeperMessage * msg, bool syncronous)
{
	typedef Factory<RasMsg, unsigned> RasFactory;
	unsigned tag = msg->GetTag();
	PWaitAndSignal rlock(requests_mutex);
	PWaitAndSignal hlock(handlers_mutex);
	if (RasMsg *ras = RasFactory::Create(tag, msg)) {
#if (__cplusplus >= 201703L) // C++17
		std::list<RasHandler *>::iterator iter = find_if(handlers.begin(), handlers.end(), bind(mem_fn(&RasHandler::IsExpected), std::placeholders::_1, ras));
#else
		std::list<RasHandler *>::iterator iter = find_if(handlers.begin(), handlers.end(), bind2nd(mem_fun(&RasHandler::IsExpected), ras));
#endif
		if (iter == handlers.end()) {
#if (__cplusplus >= 201703L) // C++17
			std::list<RasMsg *>::iterator i = find_if(requests.begin(), requests.end(), bind(mem_fn(&RasMsg::EqualTo), std::placeholders::_1, ras));
#else
			std::list<RasMsg *>::iterator i = find_if(requests.begin(), requests.end(), bind2nd(mem_fun(&RasMsg::EqualTo), ras));
#endif
			if (i != requests.end() && !(*i)->IsDone()) {
				PTRACE(2, "RAS\tDuplicate " << msg->GetTagName() << ", deleted");
				delete ras;
				ras = NULL;
			} else {
				if (syncronous) {
					ras->Exec();
					delete ras;
					ras = NULL;
				} else {
					requests.push_back(ras);
					Job *job = new Jobs(ras);
					job->SetName(msg->GetTagName());
					job->Execute();
				}
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

void RasServer::CleanUp()
{
	PWaitAndSignal lock(requests_mutex);
	if (!requests.empty()) {
#if (__cplusplus >= 201703L) // C++17
		std::list<RasMsg *>::iterator iter = partition(requests.begin(), requests.end(), mem_fn(&RasMsg::IsDone));
#else
		std::list<RasMsg *>::iterator iter = partition(requests.begin(), requests.end(), mem_fun(&RasMsg::IsDone));
#endif
		DeleteObjects(requests.begin(), iter);
		requests.erase(requests.begin(), iter);
	}
}

GkInterface *RasServer::CreateInterface(const Address & addr)
{
	return new GkInterface(addr);
}


RegistrationTable *RasMsg::EndpointTbl;
CallTable *RasMsg::CallTbl;
RasServer *RasMsg::RasSrv;

void RasMsg::Initialize()
{
	EndpointTbl = RegistrationTable::Instance();
	CallTbl = CallTable::Instance();
	RasSrv = RasServer::Instance();
}

#ifdef HAS_AVAYA_SUPPORT
template<> bool RasPDU<H225_NonStandardMessage>::Process()
{
	/* Avaya hack NSM */
	bool bSend = false;
	const PASN_ObjectId & id = request.m_nonStandardData.m_nonStandardIdentifier;
	if (id.AsString() == OID_AVAYA_H221nonStandardId) {
		if (request.m_nonStandardData.m_data[0] == CCMS_switchInfoRequest_Id) {
			PTRACE(5, "NSM\tAvaya: CCMS switchInfoRequest");
			unsigned tag = H225_RasMessage::e_nonStandardMessage;
			if (m_msg->m_replyRAS.GetTag() != tag) m_msg->m_replyRAS.SetTag(tag); // ?
			H225_NonStandardMessage & nsm = m_msg->m_replyRAS;
//			nsm.m_protocolIdentifier = request.m_protocolIdentifier;
			nsm.m_requestSeqNum = request.m_requestSeqNum;
			PASN_ObjectId & nsm_id = nsm.m_nonStandardData.m_nonStandardIdentifier;
			nsm_id.SetValue(OID_AVAYA_H221nonStandardId);
			/* TODO: proper button assignment from endpoint IP+port registration table NEW */
			H225_TransportAddress _peerAddress = SocketToH225TransportAddr(m_msg->m_peerAddr, m_msg->m_peerPort);
			endptr ep;
			ep = RegistrationTable::Instance()->FindBySignalAdrIgnorePort(_peerAddress);
			if (ep && ep->IsAvaya()) {
				H225_ArrayOf_AliasAddress aliases = ep->GetAliases();
				if (aliases.GetSize()) {
					PString alias = AsString(aliases[0], false);
					if (alias.GetLength() == 4) {
						unsigned char CCMS_switchInfoResponse_Current[sizeof(CCMS_switchInfoResponse_1000_Complete)];
						memcpy(CCMS_switchInfoResponse_Current, CCMS_switchInfoResponse_1000_Complete, sizeof(CCMS_switchInfoResponse_1000_Complete));
						memcpy(&CCMS_switchInfoResponse_Current[8], (const unsigned char *) alias, 4);
						nsm.m_nonStandardData.m_data = PASN_OctetString((const char *) CCMS_switchInfoResponse_Current, sizeof(CCMS_switchInfoResponse_1000_Complete));
						bSend = true;
					}
				}

			}
			if (bSend) PTRACE(5, "NSM\tAvaya: switchInfoResponse Complete"); else PTRACE(5, "NSM\tAvaya: Unable to find endpoint or inconsistent extension");
		}
	} else
	PTRACE(5, "NSM\tUnknown ID " + id.AsString());
	return bSend;
}
#endif

template<> bool RasPDU<H225_GatekeeperRequest>::Process()
{
	// OnGRQ
	// reply only if GK-ID matches
	if (request.HasOptionalField(H225_GatekeeperRequest::e_gatekeeperIdentifier))
		if (request.m_gatekeeperIdentifier.GetValue() != Toolkit::GKName()) {
			PTRACE(2, "RAS\tGRQ is not meant for this gatekeeper");
			return false;
		}

	bool bSendReply = !RasSrv->IsForwardedRas(request, m_msg->m_peerAddr);

	if (RasSrv->ReplyToRasAddress(m_msg->m_peerAddr)) {
		PIPSocket::Address rasIP;
		WORD rasPort;
		if (GetIPAndPortFromTransportAddr(request.m_rasAddress, rasIP, rasPort)) {
			PTRACE(3, "Reply to rasAddress from request:" << AsString(rasIP, rasPort));
			m_msg->m_peerAddr = rasIP;
			m_msg->m_peerPort = rasPort;
		} else {
			PTRACE(1, "Unable to parse rasAddress " << request.m_rasAddress);
		}
	}

	PString log;
	PString alias((request.HasOptionalField(H225_GatekeeperRequest::e_endpointAlias) && request.m_endpointAlias.GetSize() > 0)
		? AsString(request.m_endpointAlias[0], false) : PString(" "));

	unsigned rsn = H225_GatekeeperRejectReason::e_securityDenial;
	bool bReject = !RasSrv->ValidatePDU(*this, rsn);
	if (!bReject && RasSrv->IsRedirected()) {
		bReject = true;
		rsn = H225_GatekeeperRejectReason::e_resourceUnavailable;
	}
	if (Toolkit::Instance()->IsMaintenanceMode()) {
        PTRACE(1, "Rejecting GRQ in maintenance mode");
		bReject = true;
		rsn = H225_GatekeeperRejectReason::e_resourceUnavailable;
	}

	if (bReject) {
		H225_GatekeeperReject & grj = BuildReject(rsn);
		grj.m_protocolIdentifier = request.m_protocolIdentifier;
		grj.IncludeOptionalField(H225_GatekeeperReject::e_gatekeeperIdentifier);
		grj.m_gatekeeperIdentifier = Toolkit::GKName();
		if (rsn == H225_GatekeeperRejectReason::e_resourceUnavailable)
			RasSrv->SetAltGKInfo(grj, m_msg->m_peerAddr);
		log = "GRJ|" + m_msg->m_peerAddr.AsString()
				+ "|" + alias
				+ "|" + AsString(request.m_endpointType)
				+ "|" + grj.m_rejectReason.GetTagName()
				+ ";";
	} else {
		H225_GatekeeperConfirm & gcf = BuildConfirm();
		gcf.m_protocolIdentifier = request.m_protocolIdentifier;
		GetRasAddress(gcf.m_rasAddress);
		// make sure we respond with the unicast RAS IP and port, even if the GRQ came in through multicast
		// or doesn't have a rasAddress set for any other reason
		WORD unicastRasPort = (WORD)GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT);
		if (gcf.m_rasAddress.GetTag() == H225_TransportAddress::e_ipAddress) {
            H225_TransportAddress_ipAddress & rasip = gcf.m_rasAddress;
			if (rasip.m_ip[0] == 0 && rasip.m_ip[1] == 0 && rasip.m_ip[2] == 0 && rasip.m_ip[3] == 0) {
				gcf.m_rasAddress = SocketToH225TransportAddr(Toolkit::Instance()->GetRouteTable()->GetLocalAddress(m_msg->m_peerAddr), unicastRasPort);
			}
            rasip.m_port = unicastRasPort;
		} else if (gcf.m_rasAddress.GetTag() == H225_TransportAddress::e_ip6Address) {
            H225_TransportAddress_ip6Address & rasip = gcf.m_rasAddress;
			unsigned sum = 0;
			for (unsigned i = 0; i < 15; i++)
				sum +=  rasip.m_ip[i];
			if (sum == 0) {
				gcf.m_rasAddress = SocketToH225TransportAddr(Toolkit::Instance()->GetRouteTable()->GetLocalAddress(m_msg->m_peerAddr), unicastRasPort);
			}
            rasip.m_port = unicastRasPort;
		}
		gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_gatekeeperIdentifier);
		gcf.m_gatekeeperIdentifier = Toolkit::GKName();

        // H.235.TSSM
        if (request.HasOptionalField(H225_GatekeeperRequest::e_authenticationCapability) &&
            request.HasOptionalField(H225_GatekeeperRequest::e_algorithmOIDs)) {
            for (PINDEX i = 0; i < request.m_authenticationCapability.GetSize(); i++) {
                if (request.m_authenticationCapability[i].GetTag() == H235_AuthenticationMechanism::e_keyExch) {
                    const PASN_ObjectId & oid = request.m_authenticationCapability[i];
                    if (oid == OID_TSSM) {
                        // add TSSM token
                        gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_tokens);
                        // don't overwrite pwdSymEnc token
                        gcf.m_tokens.SetSize(gcf.m_tokens.GetSize() + 1);
                        gcf.m_tokens[gcf.m_tokens.GetSize() - 1].m_tokenOID = OID_TSSM;
                        gcf.m_tokens[gcf.m_tokens.GetSize() - 1].IncludeOptionalField(H235_ClearToken::e_timeStamp);
                        gcf.m_tokens[gcf.m_tokens.GetSize() - 1].m_timeStamp = (unsigned)time(NULL);
                    }
                }
            }
        }

#ifdef HAS_H46018
		if (Toolkit::Instance()->IsH46018Enabled()) {
			// check if client supports H.460.18
			if (request.HasOptionalField(H225_GatekeeperRequest::e_featureSet)) {
				H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);
				if (fs.HasFeature(18)) {
					PIPSocket::Address remoteRAS;
					const PIPSocket::Address & rx_addr = m_msg->m_peerAddr;
					if (GetIPFromTransportAddr(request.m_rasAddress, remoteRAS)) {
						bool h46018nat = ((rx_addr != remoteRAS) && !IsLoopback(rx_addr));
						if (h46018nat || GkConfig()->GetBoolean(RoutedSec, "H46018NoNAT", true)) {
							// include H.460.18 in supported features
							gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_featureSet);
							H460_FeatureStd H46018 = H460_FeatureStd(18);
							gcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
							H225_ArrayOf_FeatureDescriptor & desc = gcf.m_featureSet.m_supportedFeatures;
							desc.SetSize(1);
							desc[0] = H46018;
						}
					}
				}
			}
		}
#endif // HAS_H46018

#ifdef HAS_H460
		// H.460.22
		if (request.HasOptionalField(H225_GatekeeperRequest::e_featureSet)) {
			H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);
			if (fs.HasFeature(22)) {
				// include H.460.22 in supported features
				gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_featureSet);
				H460_FeatureStd h46022 = H460_FeatureStd(22);
				gcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				H225_ArrayOf_FeatureDescriptor & desc = gcf.m_featureSet.m_supportedFeatures;
				PINDEX lPos = desc.GetSize();
				desc.SetSize(lPos+1);
				desc[lPos] = h46022;
			}
		}
#endif // HAS_H460

#ifdef HAS_H46023
		if (Toolkit::Instance()->IsH46023Enabled()) {
			// check if client supports H.460.23
			if (request.HasOptionalField(H225_GatekeeperRequest::e_featureSet)) {
				H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);
				if (fs.HasFeature(23)) {
					// include H.460.23 in supported features
					gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_featureSet);
					H460_FeatureStd h46023 = H460_FeatureStd(23);
					gcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
					H225_ArrayOf_FeatureDescriptor & desc = gcf.m_featureSet.m_supportedFeatures;
					PINDEX lPos = desc.GetSize();
					desc.SetSize(lPos+1);
					desc[lPos] = h46023;
				}
			}
		}
#endif // HAS_H46023

#ifdef HAS_H460P
		if (Toolkit::Instance()->IsH460PEnabled()) {
			// check if client supports presence
			if (request.HasOptionalField(H225_GatekeeperRequest::e_featureSet)) {
				H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);
				if (fs.HasFeature(OpalOID(OID3))) {
					gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_featureSet);
					H460_FeatureOID oid = H460_FeatureOID(OID3);
					gcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
					H225_ArrayOf_FeatureDescriptor & desc = gcf.m_featureSet.m_supportedFeatures;
					PINDEX lPos = desc.GetSize();
					desc.SetSize(lPos + 1);
					desc[lPos] = oid;
				}
			}
		}
#endif // HAS_H460P

#ifdef HAS_H460PRE
		// check if client supports preemption
		if (request.HasOptionalField(H225_GatekeeperRequest::e_featureSet)) {
			H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);
			if (fs.HasFeature(OpalOID(OID6))) {
				gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_featureSet);
				H460_FeatureOID oid = H460_FeatureOID(OID6);
				gcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				H225_ArrayOf_FeatureDescriptor & desc = gcf.m_featureSet.m_supportedFeatures;
				PINDEX lPos = desc.GetSize();
				desc.SetSize(lPos + 1);
				desc[lPos] = oid;
			}
		}
#endif // HAS_H460PRE

#ifdef HAS_AVAYA_SUPPORT
		// Avaya hack GRQ
		if (request.HasOptionalField(H225_GatekeeperRequest::e_nonStandardData)
		&& request.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_object) {
			const PASN_ObjectId & id = request.m_nonStandardData.m_nonStandardIdentifier;
			if (id.AsString() == OID_AVAYA_H221nonStandardId) {
				PASN_OctetString osDiscoveryReq((const char *)CCMS_discoveryRequest, sizeof(CCMS_discoveryRequest));
				PASN_OctetString osCCMS = request.m_nonStandardData.m_data;
				if (Toolkit::Instance()->PASNEqual(&osCCMS, &osDiscoveryReq)) {
					PTRACE(5, "GRQ\tAvaya: CCMS discoveryRequest");
				}

				gcf.RemoveOptionalField(H225_GatekeeperConfirm::e_gatekeeperIdentifier); // Avaya crashes when GCF contains gatekeeper ID

				if (!gcf.HasOptionalField(H225_GatekeeperConfirm::e_featureSet))
					gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_featureSet);

				gcf.m_featureSet.m_replacementFeatureSet = true;

				if (!gcf.m_featureSet.HasOptionalField(H225_FeatureSet::e_desiredFeatures))
					gcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_desiredFeatures);

				H460_FeatureOID feat = H460_FeatureOID(OID_AVAYA_Feature10);
				H460_FeatureID feat_id(1);		// Generic extensible framework
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(2);	// Number portability interworking of H.323 and circuit-switched nets
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(3);	// Circuit maps
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(5);	// H.225.0 transport of multiple Q.931 IE
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(6);	// Extended fast connect feature
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(7);	// Digits maps
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(9);	// Support for online QoS
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(10);	// Call party category
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(11);	// Delayed call establishment
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(17);	// Using H.225.0 call signaling for H.323 RAS
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(18);	// Traversal of H.323 signaling across NAT/FW
				feat.AddParameter(&feat_id);
				feat_id = H460_FeatureID(19);	// Traversal of H.323 media across NAT/FW
				feat.AddParameter(&feat_id);
				AddH460Feature(gcf.m_featureSet.m_desiredFeatures, feat);

				H460_FeatureOID feat2 = H460_FeatureOID(OID_AVAYA_Feature9);
				feat_id = H460_FeatureID(1);
				feat2.AddParameter(&feat_id, H460_FeatureContent(1, 8));
				feat_id = H460_FeatureID(2);
				feat2.AddParameter(&feat_id, H460_FeatureContent(60, 16));
				feat_id = H460_FeatureID(3);
				feat2.AddParameter(&feat_id, H460_FeatureContent(0, 16));
				feat_id = H460_FeatureID(4);	// Call priority designation and country/international network of call origination identification for priority call
				feat2.AddParameter(&feat_id, H460_FeatureContent(true));
				feat_id = H460_FeatureID(5);
				feat2.AddParameter(&feat_id, H460_FeatureContent(true));
				AddH460Feature(gcf.m_featureSet.m_desiredFeatures, feat2);

				H460_Feature feat3 = H460_Feature(6);
				AddH460Feature(gcf.m_featureSet.m_desiredFeatures, feat3);

				// Supported = Desired
				if (!gcf.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures))
					gcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				gcf.m_featureSet.m_supportedFeatures = gcf.m_featureSet.m_desiredFeatures;

				// featureSets for CM18 software
				PTRACE(5, "GCF\tAvaya: Added featureSets");
			}
		}
#endif

#ifdef h323v6
	    if (request.HasOptionalField(H225_GatekeeperRequest::e_supportsAssignedGK) &&
            RasSrv->HasAssignedGK(alias, m_msg->m_peerAddr, gcf)) {
			PTRACE(2, "GCF\t" << alias << " informed of assigned gatekeeper");
		}
#endif

        if (request.HasOptionalField(H225_GatekeeperRequest::e_supportsAltGK))
		    RasSrv->SetAlternateGK(gcf, m_msg->m_peerAddr);

		RasSrv->SelectH235Capability(request, gcf);

/*      TODO: set up temp EP if we want to add tokens to GCF
        EndpointRec * tmpep = new EndpointRec(m_msg->m_recvRAS);
        tmpep->SetH235Authenticators( xxx );
        // set H.235.1 tokens
		SetupResponseTokens(m_msg->m_replyRAS, endptr(tmpep));
		delete tmpep;
*/

		log = "GCF|" + m_msg->m_peerAddr.AsString()
				+ "|" + alias
				+ "|" + AsString(request.m_endpointType)
				+ ";";
	}

	PrintStatus(log);
	return bSendReply;
}


bool RegistrationRequestPDU::Process()
{
	// OnRRQ
	H225_TransportAddress SignalAddr;
	const PIPSocket::Address & rx_addr = m_msg->m_peerAddr;
	const WORD rx_port = m_msg->m_peerPort;
	bool bSendReply, bForwardRequest;
#ifdef HAS_AVAYA_SUPPORT
	bool bAvayaHack = false;
#endif
	bSendReply = bForwardRequest = !RasSrv->IsForwardedRas(request, rx_addr);
#ifdef HAS_H46017
	PBoolean usesH46017 = (m_msg->m_h46017Socket != NULL);
	if (usesH46017) {
		PTRACE(3, "RAS\tEndpoint uses H.460.17");
		// add RAS and signal IP eg. for status port display, but they will never be used
		request.m_rasAddress.SetSize(1);
		request.m_rasAddress[0] = SocketToH225TransportAddr(rx_addr, rx_port);
		request.m_callSignalAddress.SetSize(1);
		request.m_callSignalAddress[0] = SocketToH225TransportAddr(rx_addr, rx_port);
	}
#endif

	/// remove invalid/unsupported entries from RAS and signaling addresses
	for (PINDEX i = 0; i < request.m_callSignalAddress.GetSize(); i++) {
		PIPSocket::Address addr;
		WORD port = 0;
		if (!GetIPAndPortFromTransportAddr(request.m_callSignalAddress[i], addr, port)
				|| !addr.IsValid() || port == 0) {
			PTRACE(5, "RAS\tRemoving signaling address "
				<< AsString(request.m_callSignalAddress[i]) << " from RRQ");
			request.m_callSignalAddress.RemoveAt(i--);
		} else if ((addr.GetVersion() == 6) && !Toolkit::Instance()->IsIPv6Enabled()) {
            PTRACE(5, "RAS\tRemoving IPv6 signaling address " << AsString(addr, port) << " from RRQ");
            request.m_callSignalAddress.RemoveAt(i--);
        }
	}
	for (PINDEX i = 0; i < request.m_rasAddress.GetSize(); i++) {
		PIPSocket::Address addr;
		WORD port = 0;
		if (!GetIPAndPortFromTransportAddr(request.m_rasAddress[i], addr, port)
				|| !addr.IsValid() || port == 0) {
			PTRACE(5, "RAS\tRemoving RAS address " << AsString(request.m_rasAddress[i]) << " from RRQ");
			request.m_rasAddress.RemoveAt(i--);
		}
	}

	///////////////////////////////////////////////////////////////////////////////////////////
	// H.460 NAT support code
	PBoolean h46018nat = false;
	PBoolean supportH46024 = false;
	PBoolean supportH46024A = false;
	PBoolean supportH46024B = false;
	unsigned ntype = 100;  // UnAllocated NAT Type
#ifdef HAS_H46018
	PBoolean supportH46018 = false;
#endif
#ifdef HAS_H46023
	PBoolean supportH46023 = false;
#endif
#if (HAS_H46018 || HAS_H46023)
	H225_TransportAddress originalCallSigAddress;	// original call signal address (to restore if H.460.18 is disabled)
#endif

    // H.460 Registration pre-emption
	int RegPrior = 0;
	bool preemptsupport = false;
	PBoolean preempt = false;

#ifdef HAS_H460
	bool EPSupportsQoSReporting = false;
	PBoolean supportH46022 = false;
	PBoolean supportH46022TLS = false;
	PBoolean supportH46022IPSec = false;
	H323TransportAddress tlsAddr;
#ifdef HAS_H460P
	// Presence Support
	PBoolean presenceSupport = false;
	OpalOID rPreFS = OpalOID(OID3);
	PBoolean presencePDU = false;
	PASN_OctetString preFeature;
#endif // HAS_H460P

#ifdef HAS_H460PRE
	// Registration Priority and Pre-emption
	// This allows the unregistration of duplicate aliases with lower priority
	OpalOID rPriFS = OpalOID(OID6);
#endif // HAS_H460PRE

	if (request.HasOptionalField(H225_RegistrationRequest::e_featureSet)) {
		H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);

#ifdef HAS_H46018
		// H.460.18
		if (Toolkit::Instance()->IsH46018Enabled()) {
			if (fs.HasFeature(18)) {
				PIPSocket::Address remoteRAS;
				if (request.m_rasAddress.GetSize() > 0)
					GetIPFromTransportAddr(request.m_rasAddress[0], remoteRAS);	// ignore possible errors, will be overwritten anyway
				h46018nat = ((rx_addr != remoteRAS) && !IsLoopback(rx_addr));
				if (h46018nat || GkConfig()->GetBoolean(RoutedSec, "H46018NoNAT", true)) {
					supportH46018 = true;
					// ignore rasAddr and use apparent address
					request.m_rasAddress.SetSize(1);
					request.m_rasAddress[0] = SocketToH225TransportAddr(rx_addr, rx_port);
					if (request.m_callSignalAddress.GetSize() > 0)
						originalCallSigAddress = request.m_callSignalAddress[0];
					request.m_callSignalAddress.SetSize(1);
					request.m_callSignalAddress[0] = SocketToH225TransportAddr(rx_addr, rx_port);
				}
			}
		}
#endif // HAS_H46018

		// H.460.22
		supportH46022 = fs.HasFeature(22);
		if (supportH46022) {
			H460_FeatureStd * secfeat = (H460_FeatureStd *)fs.GetFeature(22);
			supportH46022TLS = secfeat->Contains(Std22_TLS);
			if (supportH46022TLS) {
				H460_FeatureParameter & tlsparam = secfeat->Value(Std22_TLS);
				H460_FeatureStd settings;
				settings.SetCurrentTable(tlsparam);
				if (settings.Contains(Std22_ConnectionAddress)) {
					tlsAddr = settings.Value(Std22_ConnectionAddress);
				} else {
					PTRACE(1, "TLS\tError: H.460.22 TLS address missing");
				}
			}
			supportH46022IPSec = secfeat->Contains(Std22_IPSec);
			PTRACE(1, "RAS\tEP supports H.460.22: TLS=" << supportH46022TLS << " IPSec=" << supportH46022IPSec);
		}

#ifdef HAS_H46023
		if (Toolkit::Instance()->IsH46023Enabled()) {
			supportH46023 = fs.HasFeature(23);
			if (supportH46023) {
				H460_FeatureStd * natfeat = (H460_FeatureStd *)fs.GetFeature(23);
				// Check whether the endpoint supports Remote Nat directly (NATOffload)
				if (natfeat->Contains(Std23_RemoteNAT))
					supportH46024 = natfeat->Value(Std23_RemoteNAT);
				// Check whether the endpoint supports SameNAT H.460.24AnnexA
				if (natfeat->Contains(Std23_AnnexA))
					supportH46024A = natfeat->Value(Std23_AnnexA);
				// Check whether the endpoint supports offload H.460.24AnnexB
				if (natfeat->Contains(Std23_AnnexB))
					supportH46024B = natfeat->Value(Std23_AnnexB);
				// Check if the endpoint is notifying the Gk the type of NAT detected
				if (natfeat->Contains(Std23_NATdet))
					ntype = natfeat->Value(Std23_NATdet);
			}
		}
#endif

#ifdef HAS_H460P
		if (Toolkit::Instance()->IsH460PEnabled()) {
			presenceSupport = fs.HasFeature(rPreFS);
			if (presenceSupport) {
				H460_FeatureOID * feat = (H460_FeatureOID *)fs.GetFeature(rPreFS);
				presencePDU = feat->Contains(OID3_PDU);
				if (presencePDU) {
					PASN_OctetString & prePDU = feat->Value(OID3_PDU);
					preFeature = prePDU;
				}
			}
		}
#endif // HAS_H460P

#ifdef HAS_H460PRE
		if (fs.HasFeature(rPriFS)) {
			H460_FeatureOID * feat = (H460_FeatureOID *)fs.GetFeature(rPriFS);
			if (feat->Contains(OID6_Priority)) {
				unsigned prior = feat->Value(PString(OID6_Priority));
				RegPrior = (int)prior;
			}
			if (feat->Contains(OID6_Preempt)) {
				preemptsupport = true;
				preempt = feat->Value(PString(OID6_Preempt));
			}
		}
#endif // HAS_H460PRE

		// H.460.9
		if (fs.HasFeature(9)) {
			EPSupportsQoSReporting = true;
		}
	}
#endif // HAS_H460

	///////////////////////////////////////////////////////////////////////////////////////////////

	// If calling NAT support disabled.
	// Use this to block errant gateways that don't support NAT mechanism properly.
	bool supportcallingNAT = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "SupportCallingNATedEndpoints", "1"));

	if (RasSrv->ReplyToRasAddress(m_msg->m_peerAddr) && request.m_rasAddress.GetSize() > 0) {
		PIPSocket::Address rasIP;
		WORD rasPort;
		if (GetIPAndPortFromTransportAddr(request.m_rasAddress[0], rasIP, rasPort)) {
			PTRACE(3, "Reply to rasAddress from request:" << AsString(rasIP, rasPort));
			m_msg->m_peerAddr = rasIP;
			m_msg->m_peerPort = rasPort;
		} else {
			PTRACE(1, "Unable to parse rasAddress " << request.m_rasAddress[0]);
		}
	}

	// lightweight registration update
	if (request.HasOptionalField(H225_RegistrationRequest::e_keepAlive) && request.m_keepAlive) {
		endptr ep = request.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier) ?
			EndpointTbl->FindByEndpointId(request.m_endpointIdentifier) :
			(request.m_callSignalAddress.GetSize() >= 1) ?
			EndpointTbl->FindBySignalAdr(request.m_callSignalAddress[0], rx_addr) : endptr(NULL);
		bool bReject = !ep;
		if (Toolkit::Instance()->IsMaintenanceMode()) {
            callptr call = CallTbl->FindCallRec(ep);
            if (!call) {
                PTRACE(1, "Rejecting registration update in maintenance mode, endpoint not in call");
                EndpointTbl->RemoveByEndptr(ep);
                return BuildRRJ(H225_RegistrationRejectReason::e_resourceUnavailable, true);
            }
        }
	    if (bReject) {
			PString epid = request.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier) ?
				request.m_endpointIdentifier.GetValue() : "<none>";
			PTRACE(3, "RAS\tLightweight registration rejected, because endpoint isn't found (EPID=" << epid << ", IP=" << rx_addr << ")");
		}
		// check if the RRQ was sent from the registered endpoint
		if (ep && bSendReply) { // not forwarded RRQ
			if (ep->IsNATed() || ep->IsTraversalClient() || ep->UsesH46017()) {
				// for NATed endpoint, only check rx_addr
			    bReject = (ep->GetNATIP() != rx_addr);
			    if (bReject) {
					PTRACE(3, "RAS\tLightweight registration rejected, because IP doesn't match");
				}
			} else {
				PIPSocket::Address oaddr, raddr;
				WORD oport = 0, rport = 0;
				if (request.m_callSignalAddress.GetSize() >= 1 && !ep->GetForceDirectMode()) {
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
				bReject = (oaddr != raddr) || (oport != rport) || (IsLoopback(rx_addr) ? false : (raddr != rx_addr));
			    if (bReject) {
					PTRACE(3, "RAS\tLightweight registration rejected, because IP or ports don't match: old addr=" << AsString(oaddr, oport) << " receive addr=" << AsString(raddr, rport) << " rx_addr=" << rx_addr);
				}
			}
		}
		if (bReject) {
			if (ep && bSendReply) {
                PTRACE(1, "RAS\tWarning: Possible endpointId collision, security attack or IP change");
                if (Toolkit::AsBool(GkConfig()->GetString(RRQFeatureSection, "SupportDynamicIP", "0"))) {
                    PTRACE(1, "RAS\tDynamic IP?  Removing existing endpoint record and force re-registration. Disconnecting calls.");
                    while (callptr call = CallTbl->FindCallRec(ep)) {
                        call->Disconnect();
                        CallTbl->RemoveCall(call);
                    }
                    EndpointTbl->RemoveByEndptr(ep);
                }
			}
			// endpoint was NOT registered, force Full Registration
			return BuildRRJ(H225_RegistrationRejectReason::e_fullRegistrationRequired);
		} else {
			 if (ntype < 8) {
#ifdef HAS_H46023
				if (ntype > 1) {
				  PTRACE(4, "Std23\tEndpoint reports itself as being behind a NAT/FW!");
				  PTRACE(4, "Std23\tNAT/FW reported as being " << ep->GetEPNATTypeString((EndpointRec::EPNatTypes)ntype));
				  ep->SetNAT(true);
				  ep->SetNATAddress(rx_addr, rx_port);
				} else {
					if (ntype == 0) {
						PTRACE(4, "Std23\tEndpoint instructs H.460.23/.24 to be disabled (BAD NAT)");
						ep->SetH46024(false);
						ep->SetUsesH46023(false);
					} else {  // ntype == 1
						PTRACE(4, "Std23\tEndpoint reports itself as not behind a NAT/FW!");
						if (GkConfig()->GetBoolean(RoutedSec, "H46023ForceNat", false)) {
							ep->SetNAT(true);
							ep->SetNATAddress(rx_addr, rx_port);
							ntype = 6;  // symmetric firewall
						} else {
							ep->SetCallSignalAddress(originalCallSigAddress);
							ep->SetNAT(false);
						}
					}
				}
#endif
				ep->SetEPNATType(ntype);
			}

#ifdef HAS_H460P
			// If we have some presence information
			ep->SetUsesH460P(presenceSupport);
			if (presencePDU)
				  ep->ParsePresencePDU(preFeature);
#endif

			// forward lightweights, too
			if (bForwardRequest)
				RasSrv->ForwardRasMsg(m_msg->m_recvRAS);

			// Additive Registration lightweightRRQ
			if (request.HasOptionalField(H225_RegistrationRequest::e_additiveRegistration)
				&& request.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)
                && (request.m_terminalAlias != ep->GetAliases())) {
				// Authenticate the new registration
				RRQAuthData authData;
				authData.m_rejectReason = H225_RegistrationRejectReason::e_securityDenial;
				if (!RasSrv->ValidatePDU(*this, authData)) {
					return BuildRRJ(authData.m_rejectReason);
				}

				// Check for existing aliases
				const endptr lep = EndpointTbl->FindByAliases(request.m_terminalAlias);
				if (lep && (lep->GetCallSignalAddress() != ep->GetCallSignalAddress())) {
					return BuildRRJ(H225_RegistrationRejectReason::e_invalidTerminalAliases);
				}
			}

			// endpoint was already registered
			ep->Update(m_msg->m_recvRAS);
			if (bSendReply) {
				BuildRCF(ep);
				H225_RegistrationConfirm & rcf = m_msg->m_replyRAS;
				// for additive registrations we only include the added alias in the RCF
				if (request.HasOptionalField(H225_RegistrationRequest::e_additiveRegistration)) {
                    rcf.IncludeOptionalField(H225_RegistrationConfirm::e_terminalAlias);
                    rcf.m_terminalAlias = request.m_terminalAlias;
				}

#ifdef HAS_H46018
				// H.460.18
				if (Toolkit::Instance()->IsH46018Enabled()) {
					if (ep->IsTraversalClient()) {
						rcf.IncludeOptionalField(H225_RegistrationConfirm::e_featureSet);
						H460_FeatureStd H46018 = H460_FeatureStd(18);
						rcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
						H225_ArrayOf_FeatureDescriptor & desc = rcf.m_featureSet.m_supportedFeatures;
						desc.SetSize(1);
						desc[0] = H46018;
					}
				}
#endif
#ifdef HAS_H460
				// H.460.22
				if (supportH46022) {
					rcf.IncludeOptionalField(H225_RegistrationConfirm::e_featureSet);
					H460_FeatureStd H46022 = H460_FeatureStd(22);
					rcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
					H225_ArrayOf_FeatureDescriptor & desc = rcf.m_featureSet.m_supportedFeatures;
					PINDEX sz = desc.GetSize();
					desc.SetSize(sz+1);
					desc[sz] = H46022;
				}
#endif // HAS_H460
#ifdef HAS_H46023
				// H.460.23
				if (Toolkit::Instance()->IsH46023Enabled()) {
					if (ep->UsesH46023()) {
						rcf.IncludeOptionalField(H225_RegistrationConfirm::e_featureSet);
						H460_FeatureStd H46023 = H460_FeatureStd(23);
						rcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
						H225_ArrayOf_FeatureDescriptor & desc = rcf.m_featureSet.m_supportedFeatures;
						PINDEX sz = desc.GetSize();
						desc.SetSize(sz+1);
						desc[sz] = H46023;
					}
				}
#endif

#ifdef HAS_H460P
				// H.460P
				if (presenceSupport) {
					H460_FeatureOID presence = H460_FeatureOID(rPreFS);
#ifndef HAS_H460P_VER_3
					PASN_OctetString preData;
					if (ep->BuildPresencePDU(rcf.GetTag(),preData))
						presence.Add(OID3_PDU,H460_FeatureContent(preData));
#endif
					rcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
					H225_ArrayOf_FeatureDescriptor & desc = rcf.m_featureSet.m_supportedFeatures;
					PINDEX sz = desc.GetSize();
					desc.SetSize(sz+1);
					desc[sz] = presence;
				}
#endif

#ifdef HAS_H460

#ifdef HAS_H460PRE
				// H.460 PreEmption
				if (ep->SupportPreemption()) {
					rcf.IncludeOptionalField(H225_RegistrationConfirm::e_featureSet);
					rcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
					H225_ArrayOf_FeatureDescriptor & desc = rcf.m_featureSet.m_supportedFeatures;
					PINDEX sz = desc.GetSize();
					desc.SetSize(sz+1);
					desc[sz] = H460_FeatureOID(rPriFS);
				}
#endif // HAS_H460PRE

				// H.460.9
				if (EPSupportsQoSReporting
					&& Toolkit::AsBool(GkConfig()->GetString("GkQoSMonitor", "Enable", "0"))) {
					rcf.IncludeOptionalField(H225_RegistrationConfirm::e_featureSet);
					rcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_desiredFeatures);
					H225_ArrayOf_FeatureDescriptor & desc = rcf.m_featureSet.m_desiredFeatures;
					PINDEX sz = desc.GetSize();
					desc.SetSize(sz+1);
					desc[sz] = H460_FeatureStd(9);
				}
#endif

			}

            // set H.235.1 tokens for lightweight response
            // (Innovaphone accepts without, SmartNode can be configured, H323Plus currently needs it)
            SetupResponseTokens(m_msg->m_replyRAS, ep);

			return bSendReply;
		}
	} // end lightweight

	if (request.m_rasAddress.GetSize() == 0)
		return BuildRRJ(H225_RegistrationRejectReason::e_invalidRASAddress);

	bool nated = false;
	bool validaddress = false;
	if (request.m_callSignalAddress.GetSize() >= 1) {
		PIPSocket::Address ipaddr;
		for (int s = 0; s < request.m_callSignalAddress.GetSize(); ++s) {
			SignalAddr = request.m_callSignalAddress[s];
			if (GetIPFromTransportAddr(SignalAddr, ipaddr)) {
				validaddress = ((rx_addr == ipaddr) || IsLoopback(rx_addr));
				if (validaddress) {
				    break;
				}
			}
		}
		//valid address = PIPSocket::IsLocalHost(rx_addr.AsString());
		if (!bSendReply) { // don't check forwarded RRQ
			validaddress = true;
		} else if (!validaddress && !IsLoopback(ipaddr)) { // do not allow NATed from loopback
			nated = true;
			PString featureRequired = GkConfig()->GetString(RoutedSec, "NATStdMin", "");
			if (!featureRequired && ( 0
#ifdef HAS_H46018
					|| (featureRequired == "18" && !supportH46018)
#endif
#ifdef HAS_H46023
					 || (featureRequired == "23" && !supportH46023)
#endif
					 )) {
						return BuildRRJ(H225_RegistrationRejectReason::e_neededFeatureNotSupported, nated);
			}
			else
				validaddress = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "SupportNATedEndpoints", "0"));
		}
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
//	   if (ResolveAlternateGatekeeper(request.m_endpointIdentifier, rx_addr))
//		  return BuildRRJ(H225_RegistrationRejectReason::e_invalidRASAddress);

		endptr ep = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier);
		// endpoint exists, but has different IP or port - this could be a new registration from a NATed endpoint where the firewall close the pinhole
		if (ep && ep->GetCallSignalAddress() != SignalAddr
            && !GkConfig()->GetBoolean("RasSrv::RRQFeatures", "OverwriteEPOnSameAddress", false) ) {
            PTRACE(1, "RAS\tNew registration with existing endpointID, but different IP: oldIP=" << AsDotString(ep->GetCallSignalAddress()) << " newIP=" << AsDotString(SignalAddr));
			// no reason named invalidEndpointIdentifier? :(
			return BuildRRJ(H225_RegistrationRejectReason::e_securityDenial);
        }
        if (Toolkit::Instance()->IsMaintenanceMode()) {
            callptr call = callptr(NULL);
            if (ep)
                CallTbl->FindCallRec(ep);
            if (!ep || !call) {
                PTRACE(1, "Rejecting registration in maintenance mode, endpoint not in call");
                if (ep)
                    EndpointTbl->RemoveByEndptr(ep);
                return BuildRRJ(H225_RegistrationRejectReason::e_resourceUnavailable, true);
            }
        }
	} else {
        if (Toolkit::Instance()->IsMaintenanceMode()) {
            PTRACE(1, "Rejecting new registration in maintenance mode");
            return BuildRRJ(H225_RegistrationRejectReason::e_resourceUnavailable, true);
        }
	}

	RRQAuthData authData;
	authData.m_rejectReason = H225_RegistrationRejectReason::e_securityDenial;
	if (!RasSrv->IsPassThroughRegistrant() && !RasSrv->ValidatePDU(*this, authData)) {
		return BuildRRJ(authData.m_rejectReason);
	}

	bool bNewEP = true;
	if (request.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) && (request.m_terminalAlias.GetSize() >= 1)) {
		H225_ArrayOf_AliasAddress Alias, & Aliases = request.m_terminalAlias;
		if (GkConfig()->GetBoolean("RasSrv::RRQFeatures", "AuthenticatedAliasesOnly", false) &&
			authData.m_authAliases.GetSize() > 0) {
			PString recvAlias;
            for (int a = 0; a < Aliases.GetSize(); ++a) {
                bool found = false;
                recvAlias = AsString(Aliases[a],false);
                for (int j = 0; j < authData.m_authAliases.GetSize(); ++j) {
                    if (recvAlias == authData.m_authAliases[j]) {
                        found = true;
						break;
                    }
                }
                if (!found) {
                    PTRACE(4, "RAS\tRemoving UnAuthenticated Alias " << recvAlias);
					Aliases.RemoveAt(a--);
                }
            }
		}
		Alias.SetSize(1);
		for (int a = 0; a < Aliases.GetSize(); ++a) {
			Alias[0] = Aliases[a];
			bool skip = false;
			for (int j = 0; j < a; ++j) {
				skip = (Alias[0] == Aliases[j]);
				if (skip)
					break;
			}
			if (skip) { // remove duplicate alias
				Aliases.RemoveAt(a--);
				continue;
			}

			const endptr ep = EndpointTbl->FindByAliases(Alias);
			if (ep) {
				bNewEP = (ep->GetCallSignalAddress() != SignalAddr);
				if (bNewEP) {
					if ((RegPrior > ep->Priority()) || (preempt) ||
                        (Toolkit::AsBool(GkConfig()->GetString("RasSrv::RRQFeatures", "OverwriteEPOnSameAddress", "0")))) {
						// If the operators policy allows this case:
						// 1a) terminate all calls on active ep and
						// 1b) unregister the active ep - sends URQ and
						// 2) remove the ep from the EndpointTable, then
						// 3) allow the new ep to register - see below
						PTRACE(1, "RAS\tTerminating all calls on registration overwrite for EP " << ep->GetEndpointIdentifier().GetValue());
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
#ifdef HAS_H460PRE
						// notify that EP can pre-empt previous registration
						if ((preemptsupport) && (RegPrior == ep->Priority())) {
							rrj.IncludeOptionalField(H225_RegistrationReject::e_genericData);
							H460_FeatureOID pre = H460_FeatureOID(rPriFS);
							pre.Add(PString(OID6_PreNot),H460_FeatureContent(TRUE));
							H225_ArrayOf_GenericData & data = rrj.m_genericData;
                            PINDEX lastPos = data.GetSize();
                            data.SetSize(lastPos + 1);
							data[lastPos] = pre;
						}
#endif // HAS_H460PRE
						H225_ArrayOf_AliasAddress & duplicateAlias = rrj.m_rejectReason;
						duplicateAlias = Alias;
						return true;
					}
				}
			}
			PString s = AsString(Alias[0], FALSE);
			// reject the empty string
			//if (s.GetLength() < 1 || !(isalnum(s[0]) || s[0]=='#') )
			if (s.GetLength() < 1) {
				return BuildRRJ(H225_RegistrationRejectReason::e_invalidAlias);
			}
			if (!nated && !s)
				nated = GkConfig()->HasKey("NATedEndpoints", s);
		}
	} else {
		// reject gw without alias
		switch (request.m_terminalType.GetTag()) {
			case H225_EndpointType::e_gatekeeper:
			case H225_EndpointType::e_gateway:
			case H225_EndpointType::e_mcu:
				return BuildRRJ(H225_RegistrationRejectReason::e_invalidAlias);
		}
	}

	if (bNewEP && RasSrv->IsRedirected(H225_RasMessage::e_registrationRequest)) {
		PTRACE(1, "RAS\tWarning: Exceed registration limit!!");
		return BuildRRJ(H225_RegistrationRejectReason::e_resourceUnavailable, true);
	}

    bool enableGnuGkNATTraversal = GkConfig()->GetBoolean(RoutedSec, "EnableGnuGkNATTraversal", false);
    PTRACE(4, "NAT\tGnuGk's own NAT traversal is " << (enableGnuGkNATTraversal ? "ON" : "OFF"));
	if (!nated && enableGnuGkNATTraversal && request.HasOptionalField(H225_RegistrationRequest::e_nonStandardData)) {
		int iec = Toolkit::iecUnknown;
		if (request.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
			iec = Toolkit::Instance()->GetInternalExtensionCode(request.m_nonStandardData.m_nonStandardIdentifier);
		} else if (request.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_object) {
			PASN_ObjectId & oid = request.m_nonStandardData.m_nonStandardIdentifier;
			if (oid.GetDataLength() == 0)
				iec = Toolkit::iecNATTraversal;
		}
		if (iec == Toolkit::iecNATTraversal) {
			PString ipdata = request.m_nonStandardData.m_data.AsString();
			if (strncmp(ipdata, "IP=", 3) == 0) {
				PStringArray ips(ipdata.Mid(3).Tokenise(",;", false));
				PINDEX k;
				for (k = 0; k < ips.GetSize(); ++k)
					if (PIPSocket::Address(ips[k]) == rx_addr)
						break;
				nated = (k >= ips.GetSize());
				request.RemoveOptionalField(H225_RegistrationRequest::e_nonStandardData);
			}
		}
	}
	request.m_callSignalAddress.SetSize(1);
	request.m_callSignalAddress[0] = SignalAddr;

	if (RasSrv->IsPassThroughRegistrant() && !RasSrv->ValidateAdditivePDU(*this, authData)) {
 		return BuildRRJ(authData.m_rejectReason);
	}

	endptr ep = EndpointTbl->InsertRec(m_msg->m_recvRAS, nated ? rx_addr : PIPSocket::Address(GNUGK_INADDR_ANY));
	if (!ep) {
		PTRACE(3, "RAS\tRRQ rejected by unknown reason from " << rx_addr);
		return BuildRRJ(H225_RegistrationRejectReason::e_undefinedReason);
	}
	// remember which of our IPs the endpoint has sent the RRQ to (to keep all later signaling to this IP)
	ep->SetRasServerIP(m_msg->m_localAddr);
	PTRACE(7, "JW RTP set rasserverip for " << m_msg->m_peerAddr << " to " << m_msg->m_localAddr);

#ifdef HAS_H46017
	if (usesH46017) {
		if (ep->IsH46017Disabled()) {
			EndpointTbl->RemoveByEndptr(ep);
			return BuildRRJ(H225_RegistrationRejectReason::e_securityDenial);
		}
		ep->SetUsesH46017(usesH46017);
		ep->SetNATAddress(rx_addr, rx_port);
	}
#endif

#ifdef HAS_H46018
	if (supportH46018 && !ep->IsH46018Disabled()) {	// check endpoint specific switch, too
		PTRACE(3, "H46018\tEP on " << rx_addr << " supports H.460.18");
		ep->SetTraversalRole(TraversalClient);
		ep->SetNATAddress(rx_addr, rx_port);
	}
	if (supportH46018 && ep->IsH46018Disabled()) {
		// if the endpoint wanted H.460.18, we have overwritten its callSignalAddr above
		// we have to restore it here if we disable H.460.18 for this endpoint
		ep->SetCallSignalAddress(originalCallSigAddress);
	}
#endif // HAS_H46018
#ifdef HAS_H460P
	// If we have some presence information
	ep->SetUsesH460P(presenceSupport);
	if (presencePDU)
	   ep->ParsePresencePDU(preFeature);

#endif // HAS_H460P

	if (nated || (ep->IsTraversalClient() && !validaddress)) {
		ep->SetNATAddress(rx_addr, rx_port);
	} else {
        ep->SetNAT(h46018nat);
        if (h46018nat && supportH46024) {
            PTRACE(4, "RAS\tH46024 NAT detected set default PortRestricted: Wait for result of NAT Test");
           ep->SetEPNATType(EndpointRec::NatPortRestricted);
        }
		ep->SetH46024(supportH46024);
		ep->SetH46024A(supportH46024A);
		ep->SetH46024B(supportH46024B);
	}

	ep->SetPriority(RegPrior);
	ep->SetPreemption(preemptsupport);

	ep->SetH235Authenticators(authData.m_authenticator);
	authData.m_authenticator = NULL; // make sure we don't delete authenticator object when authData gets deleted

	if (bSendReply) {
		//
		// OK, now send RCF
		//
		BuildRCF(ep);
		H225_RegistrationConfirm & rcf = m_msg->m_replyRAS;


#ifdef HAS_AVAYA_SUPPORT
		// Avaya hack RRQ
		if (request.HasOptionalField(H225_RegistrationRequest::e_nonStandardData)
			&& request.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_object) {
			const PASN_ObjectId & id = request.m_nonStandardData.m_nonStandardIdentifier;
			if (id.AsString() == OID_AVAYA_H221nonStandardId) {
				bAvayaHack = true;

				if (rcf.HasOptionalField(H225_RegistrationConfirm::e_gatekeeperIdentifier))
					rcf.RemoveOptionalField(H225_RegistrationConfirm::e_gatekeeperIdentifier);

				PASN_OctetString & data = request.m_nonStandardData.m_data;
				if (data.GetSize() >= 20) {
					PTRACE(5, "RRQ\tAvaya: MAC "  + PString(PString::Printf, "%02x", ((unsigned char)data[13])) +
						PString(PString::Printf, ":%02x", ((unsigned char)data[14])) +
						PString(PString::Printf, ":%02x", ((unsigned char)data[15])) +
						PString(PString::Printf, ":%02x", ((unsigned char)data[16])) +
						PString(PString::Printf, ":%02x", ((unsigned char)data[17])) +
						PString(PString::Printf, ":%02x", ((unsigned char)data[18])));
				}

				H225_VendorIdentifier & vi = request.m_endpointVendor;
				PString out;
				if (vi.m_vendor.m_manufacturerCode == Toolkit::t35mLucent) out = "Lucent"; else
				if (vi.m_vendor.m_manufacturerCode == Toolkit::t35mAvaya) out = "Avaya"; else out = PString(vi.m_vendor.m_manufacturerCode);
				if (vi.HasOptionalField(H225_VendorIdentifier::e_productId)) {
					out += " " + vi.m_productId.AsString();
				}
				if (vi.HasOptionalField(H225_VendorIdentifier::e_versionId)) {
					out += " " + vi.m_versionId.AsString();
				}
				PTRACE(5, "RRQ\tAvaya: " + out);

				rcf.IncludeOptionalField(H225_RegistrationConfirm::e_nonStandardData);
				PASN_ObjectId & rcf_id = rcf.m_nonStandardData.m_nonStandardIdentifier;
				rcf_id.SetValue(OID_AVAYA_H221nonStandardId);
				if (request.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
					if (request.m_terminalAlias.GetSize()) {
						PString ext = AsString(request.m_terminalAlias[0], false);
						PTRACE(5, "RRQ\tAvaya: EXT " + ext);
						unsigned char CCMS_loginAccepted_Current[sizeof(CCMS_loginAccepted_1000)];
						memcpy(CCMS_loginAccepted_Current, CCMS_loginAccepted_1000, sizeof(CCMS_loginAccepted_1000));
						if (ext.GetLength() == 4) {
							memcpy(&CCMS_loginAccepted_Current[76], (const unsigned char *) ext, 4);
							memcpy(&CCMS_loginAccepted_Current[84], (const unsigned char *) ext, 4);
							rcf.m_nonStandardData.m_data = PASN_OctetString((const char *) CCMS_loginAccepted_Current, sizeof(CCMS_loginAccepted_1000));
						} else bAvayaHack = false;
					} else bAvayaHack = false;
				} else bAvayaHack = false;

				if (!bAvayaHack) {
					PTRACE(5, "RAS\tAvaya: Sending RRJ due to inconsistent extension data");
					return BuildRRJ(H225_RegistrationRejectReason::e_undefinedReason);
				}
			}
        }
#endif

		if (GkConfig()->GetBoolean(RoutedSec, "PregrantARQ", false)) {
			rcf.IncludeOptionalField(H225_RegistrationConfirm::e_preGrantedARQ);
			rcf.m_preGrantedARQ.m_makeCall = true;
			rcf.m_preGrantedARQ.m_answerCall = true;
			if (RasSrv->IsGKRouted() && !ep->GetForceDirectMode()) {
				// in routed-mode we require all calls to be placed through the gatekeeper
				rcf.m_preGrantedARQ.m_useGKCallSignalAddressToMakeCall = true;
				rcf.m_preGrantedARQ.m_useGKCallSignalAddressToAnswer = true;
			}
		}

		if (supportcallingNAT
            && enableGnuGkNATTraversal
#ifdef HAS_H46017
			&& !usesH46017
#endif
			&& !ep->IsTraversalClient()) {
			// tell the endpoint its translated address
			rcf.IncludeOptionalField(H225_RegistrationConfirm::e_nonStandardData);
		    rcf.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
			H225_H221NonStandard & t35 = rcf.m_nonStandardData.m_nonStandardIdentifier;
			t35.m_t35CountryCode = Toolkit::t35cPoland;
			t35.m_manufacturerCode = Toolkit::t35mGnuGk;
			t35.m_t35Extension = Toolkit::t35eNATTraversal;
			// if the client is NAT or you are forcing ALL registrations to use a keepAlive TCP socket
			if ((nated) || GkConfig()->GetBoolean(RoutedSec, "ForceNATKeepAlive", false))
				rcf.m_nonStandardData.m_data = "NAT=" + rx_addr.AsString();
			else  // Be careful as some public IP's may block TCP but not UDP resulting in an incorrect NAT test result.
				rcf.m_nonStandardData.m_data = "NoNAT";
		}

#ifdef HAS_H460
		H225_ArrayOf_FeatureDescriptor & gd = rcf.m_featureSet.m_supportedFeatures;

#ifdef HAS_H46017
		if (m_msg->m_h46017Socket)
			ep->SetNATSocket(m_msg->m_h46017Socket);
		if (ep->UsesH46017()) {
			rcf.m_callSignalAddress.SetSize(0);
			rcf.IncludeOptionalField(H225_RegistrationConfirm::e_maintainConnection);
			rcf.m_maintainConnection = true;
		}
#endif

#ifdef HAS_H46018
		// H.460.18
		if (Toolkit::Instance()->IsH46018Enabled()) {
			if (ep->IsTraversalClient()) {
				H460_FeatureStd H46018 = H460_FeatureStd(18);
				PINDEX lPos = gd.GetSize();
				gd.SetSize(lPos + 1);
				gd[lPos] = H46018;
			}
		}
#endif // HAS_H46018

#ifdef HAS_H460
		// H.460.22
		if (supportH46022) {
			if (supportH46022TLS) {
				ep->SetUseTLS(true);	// don't set to supportH46022TLS, value might be set by other means
				ep->SetTLSAddress(tlsAddr);
			}
			if (supportH46022IPSec)
				ep->SetUseIPSec(true);	// don't set to supportH46022IPSec, value might be set by other means
			H460_FeatureStd H46022 = H460_FeatureStd(22);
			PINDEX lPos = gd.GetSize();
			gd.SetSize(lPos + 1);
			gd[lPos] = H46022;
		}
#endif // HAS_H460

#ifdef HAS_H46023
		if (supportH46023 && Toolkit::Instance()->IsH46023Enabled()) {
			// if we support NAT notify the client they are behind a NAT or to test for NAT
			// send off a request to test the client NAT type with a STUN Server
			// if behind Nat see if STUN server is available for the interface
			// if not then disable Std23 for this endpoint
			H323TransportAddress stunaddr;
			bool ok23 = Toolkit::Instance()->GetH46023STUN(rx_addr, stunaddr);

			// Build the message
			if (ok23) {
				ep->SetUsesH46023(true);
				bool h46023nat = nated || h46018nat || GkConfig()->GetBoolean(RoutedSec, "H46018NoNAT", true);

				H460_FeatureStd natfs = H460_FeatureStd(23);
				natfs.Add(Std23_IsNAT, H460_FeatureContent(h46023nat));
				if (h46023nat) {
					natfs.Add(Std23_STUNAddr, H460_FeatureContent(stunaddr));
				} else {
					// If not NAT then provide the RAS address to the client to determine
					// whether there is an ALG (or some other device) making things appear as they are not
					natfs.Add(Std23_DetRASAddr, H460_FeatureContent(H323TransportAddress(request.m_rasAddress[0])));
				}

				PINDEX lPos = gd.GetSize();
				gd.SetSize(lPos + 1);
				gd[lPos] = natfs;
			 }
		}
#endif // HAS_H46023

#ifdef HAS_H460P
		if (presenceSupport) {
			H460_FeatureOID presence = H460_FeatureOID(rPreFS);
#ifndef HAS_H460P_VER_3
			PASN_OctetString preData;
			if (ep->BuildPresencePDU(rcf.GetTag(), preData))
				presence.Add(OID3_PDU, H460_FeatureContent(preData));
#endif
			PINDEX lPos = gd.GetSize();
			gd.SetSize(lPos+1);
			gd[lPos] = presence;
		}
#endif // HAS_H460P

#ifdef HAS_H460PRE
		// if the client supports Registration PreEmption then notify the client that we do too
		if ((preemptsupport) &&
			(request.HasOptionalField(H225_RegistrationRequest::e_keepAlive) && (!request.m_keepAlive))) {
			H460_FeatureOID pre = H460_FeatureOID(rPriFS);
			PINDEX lPos = gd.GetSize();
			gd.SetSize(lPos+1);
			gd[lPos] = pre;
		}
#endif  // HAS_H460PRE

		// H.460.9
		if (EPSupportsQoSReporting
			&& GkConfig()->GetBoolean("GkQoSMonitor", "Enable", false)) {
			rcf.IncludeOptionalField(H225_RegistrationConfirm::e_featureSet);
			rcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_desiredFeatures);
			H225_ArrayOf_FeatureDescriptor & desc = rcf.m_featureSet.m_desiredFeatures;
			PINDEX sz = desc.GetSize();
			desc.SetSize(sz+1);
			desc[sz] = H460_FeatureStd(9);
		}

		if (gd.GetSize() > 0)	{
			rcf.IncludeOptionalField(H225_RegistrationConfirm::e_featureSet);
			rcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
		}
#endif // HAS_H460

#ifdef HAS_LANGUAGE
		// Assigned Language
		if (request.HasOptionalField(H225_RegistrationRequest::e_language)) {
			if (ep->SetAssignedLanguage(request.m_language, rcf.m_language))
				rcf.IncludeOptionalField(H225_RegistrationConfirm::e_language);
		}
#endif

		// Gatekeeper assigned Aliases if the client supplied aliases
		if (request.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
			if (!ep->IsGateway() || GkConfig()->GetBoolean(RRQFeatureSection, "GatewayAssignAliases", true))
				ep->SetAssignedAliases(rcf.m_terminalAlias);
			rcf.IncludeOptionalField(H225_RegistrationConfirm::e_terminalAlias);
		}

#ifdef h323v6
		// Assigned GKs
		if (request.HasOptionalField(H225_RegistrationRequest::e_assignedGatekeeper)) {
			ep->SetAssignedGatekeeper(rcf.m_assignedGatekeeper);
			PString alias;
			if (ep->GetAliases().GetSize() > 0) {
                alias = AsString(ep->GetAliases()[0], false);
			}
            if (RasSrv->HasAssignedGK(alias, m_msg->m_peerAddr, rcf)) {
			    PTRACE(2, "RCF\t" << alias << " informed of assigned gatekeeper");
            }
		}
#endif

		// Alternate GKs
		if (request.HasOptionalField(H225_RegistrationRequest::e_supportsAltGK)) {
			RasSrv->SetAlternateGK(rcf, m_msg->m_peerAddr);
#if HAS_DATABASE
			// check if we have GnuGk-assigned home gatekeepers
            if (Toolkit::Instance()->GnuGkAssignedGKs().HasAssignedGk(ep, m_msg->m_peerAddr)) {
			    PTRACE(2, "RCF\tEndpoint is assigned to other gatekeeper - will try to re-home");
            }
#endif // HAS_DATABASE
		}

		// Call credit display
		if (ep->AddCallCreditServiceControl(rcf.m_serviceControl,
			authData.m_amountString, authData.m_billingMode, -1))
			  rcf.IncludeOptionalField(H225_RegistrationConfirm::e_serviceControl);

		// URL link
		if (ep->AddHTTPServiceControl(rcf.m_serviceControl) &&
		   !rcf.HasOptionalField(H225_RegistrationConfirm::e_serviceControl))
			      rcf.IncludeOptionalField(H225_RegistrationConfirm::e_serviceControl);

#ifdef H323_H350
		// H.350 link
		if (ep->AddH350ServiceControl(rcf.m_serviceControl) &&
		   !rcf.HasOptionalField(H225_RegistrationConfirm::e_serviceControl))
			      rcf.IncludeOptionalField(H225_RegistrationConfirm::e_serviceControl);
#endif
        // set H.235.1 tokens
		SetupResponseTokens(m_msg->m_replyRAS, ep);

#ifdef HAS_AVAYA_SUPPORT
		// Avaya hack RCF
		if (bAvayaHack) {
			if (!rcf.HasOptionalField(H225_RegistrationConfirm::e_maintainConnection))
				rcf.IncludeOptionalField(H225_RegistrationConfirm::e_maintainConnection);
			rcf.m_maintainConnection = true;

			if (!rcf.HasOptionalField(H225_RegistrationConfirm::e_willRespondToIRR))
				rcf.IncludeOptionalField(H225_RegistrationConfirm::e_willRespondToIRR);
			rcf.m_willRespondToIRR = false;

			if (!rcf.HasOptionalField(H225_RegistrationConfirm::e_alternateGatekeeper))
				rcf.IncludeOptionalField(H225_RegistrationConfirm::e_alternateGatekeeper);

			H225_AlternateGK altGK;
			GetRasAddress(altGK.m_rasAddress);
			altGK.m_needToRegister = true;
			rcf.m_alternateGatekeeper.SetSize(1);
			rcf.m_alternateGatekeeper[0] = altGK;

			if (rcf.HasOptionalField(H225_RegistrationConfirm::e_timeToLive))
				rcf.RemoveOptionalField(H225_RegistrationConfirm::e_timeToLive);

			if (rcf.HasOptionalField(H225_RegistrationConfirm::e_terminalAlias))
				rcf.RemoveOptionalField(H225_RegistrationConfirm::e_terminalAlias);

			if (rcf.HasOptionalField(H225_RegistrationConfirm::e_supportsAdditiveRegistration))
				rcf.RemoveOptionalField(H225_RegistrationConfirm::e_supportsAdditiveRegistration);

			PTRACE(5, "RCF\tAvaya: Confirmation fulfilled");
		}
#endif

	} else {
		PIPSocket::Address rasip, sigip;
		if (GetIPFromTransportAddr(request.m_rasAddress[0], rasip) && GetIPFromTransportAddr(SignalAddr, sigip) && rasip != sigip)
			// this is an nated endpoint
			ep->SetNATAddress(rasip);
	}
	// forward heavyweight
	if (bForwardRequest) {
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
	if (bNewEP || !GkConfig()->GetBoolean("GkStatus::Filtering", "NewRCFOnly", false)) {
        PString log = "RCF|" + ep->PrintOn(false) + ";";
		PrintStatus(log);
	}

	return bSendReply;
}

bool RegistrationRequestPDU::BuildRCF(const endptr & ep, bool additiveRegistration)
{
	H225_RegistrationConfirm & rcf = BuildConfirm();
	rcf.m_protocolIdentifier = request.m_protocolIdentifier;
	if (RasSrv->IsGKRouted() && !ep->GetForceDirectMode()) {
		rcf.m_callSignalAddress.SetSize(1);
		GetCallSignalAddress(rcf.m_callSignalAddress[0]);
	} else {
		rcf.m_callSignalAddress.SetSize(0);	// we don't have a call signal address in direct mode
	}
	if (!additiveRegistration) {
		rcf.IncludeOptionalField(H225_RegistrationConfirm::e_terminalAlias);
		rcf.m_terminalAlias = ep->GetAliases();
	}
	rcf.m_endpointIdentifier = ep->GetEndpointIdentifier();
	rcf.IncludeOptionalField(H225_RegistrationConfirm::e_gatekeeperIdentifier);
	rcf.m_gatekeeperIdentifier = Toolkit::GKName();
	if (ep->GetTimeToLive() > 0) {
		rcf.IncludeOptionalField(H225_RegistrationConfirm::e_timeToLive);
		rcf.m_timeToLive = ep->GetTimeToLive();
	}

	rcf.IncludeOptionalField(H225_RegistrationConfirm::e_supportsAdditiveRegistration);

	return true;
}

bool RegistrationRequestPDU::BuildRRJ(unsigned reason, bool alt)
{
	H225_RegistrationReject & rrj = BuildReject(reason);
	rrj.m_protocolIdentifier = request.m_protocolIdentifier;
	rrj.IncludeOptionalField(H225_RegistrationReject::e_gatekeeperIdentifier);
	rrj.m_gatekeeperIdentifier = Toolkit::GKName();
	if (alt)
		RasSrv->SetAltGKInfo(rrj, m_msg->m_peerAddr);

	if (request.HasOptionalField(H225_RegistrationRequest::e_nonStandardData)
		&& request.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
		const H225_H221NonStandard& nonStandard = request.m_nonStandardData.m_nonStandardIdentifier;
		if (Toolkit::Instance()->GetInternalExtensionCode(nonStandard) == Toolkit::iecFailoverRAS)
			CopyNonStandardData(request, rrj);
	}

	PString alias(request.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) ? AsString(request.m_terminalAlias) : PString(" "));
	PString log = "RRJ|" + m_msg->m_peerAddr.AsString()
					+ "|" + alias
					+ "|" + AsString(request.m_terminalType)
					+ "|" + rrj.m_rejectReason.GetTagName()
					+ ";";

	return PrintStatus(log);
}

template<> bool RasPDU<H225_UnregistrationRequest>::Process()
{
	// OnURQ
	PString log;

	bool bSendReply, bForwardRequest;
	bSendReply = bForwardRequest = !RasSrv->IsForwardedRas(request, m_msg->m_peerAddr);

	PString endpointId(request.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier) ? request.m_endpointIdentifier.GetValue() : PString(" "));
	endptr ep = request.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier) ?
		EndpointTbl->FindByEndpointId(request.m_endpointIdentifier) :
		request.m_callSignalAddress.GetSize() ? EndpointTbl->FindBySignalAdr(request.m_callSignalAddress[0], m_msg->m_peerAddr) : endptr(NULL);
	if (ep) {
		if (RasSrv->ReplyToRasAddress(m_msg->m_peerAddr)) {
			if (GetIPAndPortFromTransportAddr(ep->GetRasAddress(), m_msg->m_peerAddr, m_msg->m_peerPort)) {
				PTRACE(3, "Reply to saved rasAddress:" << AsString(m_msg->m_peerAddr, m_msg->m_peerPort));
			} else {
				PTRACE(1, "Unable to parse saved rasAddress " << ep->GetRasAddress());
			}
		}

		// TODO/BUG: H.323 clause 7.2.2 says that for every endpoint (not only those who use additive registrations)
		// an URQ with a partial list of aliases means to unregister only those aliases, not the whole endpoint
		if (ep->IsAdditiveRegistrant()
			&& request.HasOptionalField(H225_UnregistrationRequest::e_endpointAlias)
			&& !ep->RemoveAliases(request.m_endpointAlias)) {

				EndpointRec logRec(m_msg->m_recvRAS);
				RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctUnregister, endptr(&logRec));

				log = "UCF|" + m_msg->m_peerAddr.AsString()
				+ "|" + endpointId
				+ "|" + AsString(request.m_endpointAlias);
				PrintStatus(log);
				BuildConfirm();
				return bSendReply;
		}

		// Disconnect all calls of the endpoint
		SoftPBX::DisconnectEndpoint(ep);
		// Remove from the table
		EndpointTbl->RemoveByEndptr(ep);

		// Return UCF
		BuildConfirm();

        // set H.235.1 tokens
		SetupResponseTokens(m_msg->m_replyRAS, ep);

		log = "UCF|" + m_msg->m_peerAddr.AsString()
				+ "|" + endpointId
				+ ";";
	} else {
		// Return URJ
		H225_UnregistrationReject & urj = BuildReject(H225_UnregRejectReason::e_notCurrentlyRegistered);
		log = "URJ|" + m_msg->m_peerAddr.AsString()
				+ "|" + endpointId
				+ "|" + urj.m_rejectReason.GetTagName()
				+ ";";
	}

	if (bForwardRequest)
		RasSrv->ForwardRasMsg(m_msg->m_recvRAS);
	PrintStatus(log);

	return bSendReply;
}

PString AdmissionRequestPDU::GetCallingStationId(
	/// additional data
	ARQAuthData & authData
	) const
{
	if (!authData.m_callingStationId)
		return authData.m_callingStationId;

	const H225_AdmissionRequest & arq = request;
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
		return PString::Empty();  // No Call Linkage detected.

}

bool AdmissionRequestPDU::Process()
{
	// OnARQ
	bool bReject = false;
	bool answer = request.m_answerCall;
	PString in_rewrite_source, out_rewrite_source;

	PString msg;
	if (!Toolkit::Instance()->IsLicenseValid(msg)) {
		PTRACE(2, "Error: No license: " << msg);
		SNMP_TRAP(9, SNMPError, General, "No license: " + msg);
		return BuildReply(H225_AdmissionRejectReason::e_undefinedReason);
	}

	if (Toolkit::Instance()->IsMaintenanceMode()) {
        PTRACE(1, "Rejecting new call in maintenance mode");
        CallRec dummyCall(*this, 0, destinationString); // dummy call object so accounting variables can be filled
        (void)RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctReject, callptr(&dummyCall));	// ignore success/failure
		return BuildReply(H225_AdmissionRejectReason::e_resourceUnavailable);
	}

	// find the caller
	RequestingEP = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier);
	if (!RequestingEP) {
        CallRec dummyCall(*this, 0, destinationString); // dummy call object so accounting variables can be filled
        (void)RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctReject, callptr(&dummyCall));	// ignore success/failure
		return BuildReply(H225_AdmissionRejectReason::e_callerNotRegistered);
	}

    if (GkConfig()->GetBoolean("RasSrv::ARQFeatures", "CheckSenderIP", false)) {
        PIPSocket::Address storedAddr;
        WORD storedPort = 0;
		if (GetIPAndPortFromTransportAddr(RequestingEP->GetRasAddress(), storedAddr, storedPort)) {
		    if (storedAddr != m_msg->m_peerAddr) {
                PTRACE(1, "RAS\tSender address of ARQ didn't match: " << AsString(storedAddr) << " != " << AsString(m_msg->m_peerAddr));
                CallRec dummyCall(*this, 0, destinationString); // dummy call object so accounting variables can be filled
                (void)RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctReject, callptr(&dummyCall));	// ignore success/failure
                return BuildReply(H225_AdmissionRejectReason::e_callerNotRegistered);
		    }
		} else {
			PTRACE(1, "Unable to parse saved rasAddress " << RequestingEP->GetRasAddress());
		}
    }

	if (RasSrv->ReplyToRasAddress(m_msg->m_peerAddr)) {
		if (GetIPAndPortFromTransportAddr(RequestingEP->GetRasAddress(), m_msg->m_peerAddr, m_msg->m_peerPort)) {
			PTRACE(3, "Reply to saved rasAddress:" << AsString(m_msg->m_peerAddr, m_msg->m_peerPort));
		} else {
			PTRACE(1, "Unable to parse saved rasAddress " << RequestingEP->GetRasAddress());
		}
	}

	if (RasSrv->IsRedirected(H225_RasMessage::e_admissionRequest) && !answer) {
		PTRACE(1, "RAS\tWarning: Exceed call limit!!");
        CallRec dummyCall(*this, 0, destinationString); // dummy call object so accounting variables can be filled
        (void)RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctReject, callptr(&dummyCall));	// ignore success/failure

		return BuildReply(H225_AdmissionRejectReason::e_resourceUnavailable);
	}

	// send RIP message before doing any real work if configured to do so
	unsigned ripDelay = GkConfig()->GetInteger("RasSrv::ARQFeatures", "SendRIP", 0);
	if (ripDelay > 0) {
		RasSrv->SendRIP(request.m_requestSeqNum, ripDelay, m_msg->m_peerAddr, m_msg->m_peerPort, RequestingEP->GetH235Authenticators());
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
		if (!answer && hasDestInfo) {
			authData.m_dialedNumber = GetBestAliasAddressString(
				request.m_destinationInfo, false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber));
		}
	}
	if (authData.m_dialedNumber.IsEmpty()
        && request.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)
        && GkConfig()->GetBoolean("CallTable", "UseDestCallSignalIPAsDialedNumber", false)) {
        authData.m_dialedNumber = AsDotString(request.m_destCallSignalAddress);
	}

	if (hasDestInfo) { // apply rewriting rules

		in_rewrite_source = GetBestAliasAddressString(
			RequestingEP->GetAliases(), false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber));

     	if (in_rewrite_source.IsEmpty() && request.m_srcInfo.GetSize() > 0) {
        	in_rewrite_source = GetBestAliasAddressString(request.m_srcInfo, false,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber));
		}

	 	if (!in_rewrite_source.IsEmpty()) {
	 		if (Toolkit::Instance()->GWRewriteE164(in_rewrite_source, GW_REWRITE_IN, request.m_destinationInfo[0], pExistingCallRec)
				&& (!RasSrv->IsGKRouted() || RequestingEP->GetForceDirectMode())) {
				aliasesChanged = true;
			}
		}

		// Normal rewriting
		if (Toolkit::Instance()->RewriteE164(request.m_destinationInfo[0]) && (!RasSrv->IsGKRouted() || RequestingEP->GetForceDirectMode())) {
			aliasesChanged = true;
		}
	}

	destinationString = hasDestInfo ? AsString(request.m_destinationInfo) :
		request.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress) ?
		AsDotString(request.m_destCallSignalAddress) : PString("unknown");

	authData.m_callingStationId = GetCallingStationId(authData);
	authData.m_calledStationId = GetCalledStationId(authData);
	authData.m_callLinkage = GetCallLinkage(authData);

	if (!RasSrv->ValidatePDU(*this, authData)) {
		if (authData.m_rejectReason < 0) {
			authData.m_rejectReason = H225_AdmissionRejectReason::e_securityDenial;
		}
        CallRec dummyCall(*this, 0, destinationString, authData.m_proxyMode); // dummy call object so accounting variables can be filled
        (void)RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctReject, callptr(&dummyCall));	// ignore success/failure

		return BuildReply(authData.m_rejectReason);
	}

	if (authData.m_routeToAlias.GetSize() > 0) {
		request.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
		request.m_destinationInfo = authData.m_routeToAlias;
		authData.m_calledStationId = AsString(authData.m_routeToAlias, FALSE);
		PTRACE(2, "RAS\tARQ destination set to " << authData.m_calledStationId);
		hasDestInfo = true;
		destinationString = AsString(request.m_destinationInfo);
		if (!RasSrv->IsGKRouted() || RequestingEP->GetForceDirectMode()) {
			aliasesChanged = true;
		}
	}

	if (RasSrv->IsGKRouted() && answer && !pExistingCallRec) {
		if (GkConfig()->GetBoolean("RasSrv::ARQFeatures", "ArjReasonRouteCallToGatekeeper", true)) {
			bReject = true;
			if (request.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress)) {
				PIPSocket::Address ipaddress;
				if (GetIPFromTransportAddr(request.m_srcCallSignalAddress, ipaddress)) {
					bReject = !RasSrv->IsForwardedMessage(0, ipaddress);
				}
			}
			if (bReject) {
                CallRec dummyCall(*this, 0, destinationString, authData.m_proxyMode); // dummy call object so accounting variables can be filled
                (void)RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctReject, callptr(&dummyCall));	// ignore success/failure
				return BuildReply(H225_AdmissionRejectReason::e_routeCallToGatekeeper);
			}
		}
	}

	bool signalOffload = false;
#ifdef HAS_H460
    bool EPSupportsQoSReporting = false;
    bool EPSupportsH46022 = false;
    bool EPSupportsH46022TLS = false;
    bool EPSupportsH46022IPSec = false;
	bool vendorInfo = false;
	PString vendor, version;
#if defined(HAS_H46026) || defined(HAS_H46023)
    bool EPRequiresH46026 = false;
#endif
#ifdef HAS_H46023
	bool natsupport = false;
	CallRec::NatStrategy natoffloadsupport = CallRec::e_natUnknown;
#endif

	if (request.HasOptionalField(H225_AdmissionRequest::e_featureSet)) {
		H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);
		// H.460.9 QoS Reporting
		if (fs.HasFeature(9)) {
			EPSupportsQoSReporting = true;
		}
		// H.460.22
		if (fs.HasFeature(22)) {
			EPSupportsH46022 = true;
			EPSupportsH46022TLS = RequestingEP->UseTLS();
			EPSupportsH46022IPSec = RequestingEP->UseIPSec();
		}
#ifdef HAS_H46026
        if (fs.HasFeature(26) && Toolkit::Instance()->IsH46026Enabled())
            EPRequiresH46026 = true;
        RequestingEP->SetUsesH46026(EPRequiresH46026);
#endif
	}

	if (request.HasOptionalField(H225_AdmissionRequest::e_genericData)) {
		H225_ArrayOf_GenericData & data = request.m_genericData;
		for (PINDEX i = 0; i < data.GetSize(); i++) {
			H460_Feature & feat = (H460_Feature &)data[i];
			if (feat.GetFeatureID() == H460_FeatureID(OpalOID(OID9)))
				vendorInfo = true;
#ifdef HAS_H46023
			if (Toolkit::Instance()->IsH46023Enabled() && !EPRequiresH46026) {
				if (feat.GetFeatureID() == H460_FeatureID(24)) {
					natsupport = true;
					H460_FeatureStd & std24 = (H460_FeatureStd &)feat;
					if (std24.Contains(Std24_NATInstruct)) {
						unsigned natstat = std24.Value(Std24_NATInstruct);
						natoffloadsupport = (CallRec::NatStrategy)natstat;
					}
				}
			}
#endif
		}
	}
#endif

	if (request.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
		H225_TransportAddress tmp;
		GetCallSignalAddress(tmp);
		if (tmp == request.m_destCallSignalAddress)
			request.RemoveOptionalField(H225_AdmissionRequest::e_destCallSignalAddress);
	}

	// routing decision
	bool toParent = false;
	H225_TransportAddress CalledAddress;
	bool connectWithTLS = false;
	Routing::AdmissionRequest arq(request, this, authData.m_callingStationId, authData.m_clientAuthId);
	if (!answer) {
		if (!authData.m_destinationRoutes.empty()) {
			list<Route>::const_iterator i = authData.m_destinationRoutes.begin();
			while (i != authData.m_destinationRoutes.end())
				arq.AddRoute(*i++);
		} else
			arq.Process();

		if (arq.GetRoutes().empty()) {
            CallRec dummyCall(*this, 0, destinationString, authData.m_proxyMode); // dummy call object so accounting variables can be filled
            (void)RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctReject, callptr(&dummyCall));	// ignore success/failure
            SetupResponseTokens(m_msg->m_replyRAS, RequestingEP);
            return BuildReply(arq.GetRejectReason());
		}

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
				&& route.m_destEndpoint	&& !route.m_destEndpoint->HasAvailableCapacity(request.m_destinationInfo)) {
            CallRec dummyCall(*this, 0, destinationString, authData.m_proxyMode); // dummy call object so accounting variables can be filled
            (void)RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctReject, callptr(&dummyCall));	// ignore success/failure
            SetupResponseTokens(m_msg->m_replyRAS, RequestingEP);
			return BuildReply(H225_AdmissionRejectReason::e_resourceUnavailable);
        }

		CalledEP = route.m_destEndpoint;
		CalledAddress = route.m_destAddr;
		Language = route.m_language;
		connectWithTLS = route.m_useTLS;
		toParent = route.m_flags & Route::e_toParent;
		aliasesChanged = aliasesChanged || (arq.GetFlags() & Routing::AdmissionRequest::e_aliasesChanged);

		// record neighbor used for rewriting purposes
		if (route.m_flags & Route::e_toNeighbor)
			out_rewrite_source = route.m_routeId;

		authData.m_proxyMode = route.m_proxyMode;
	}

	// bandwidth check
	long BWRequest = request.m_bandWidth.GetValue();	// this is the bidirectional bandwidth
	// force a minimum bandwidth for endpoints that don't properly report usage (eg. Netmeeting)
	if ((CallTbl->GetMinimumBandwidthPerCall() > 0) && (BWRequest < CallTbl->GetMinimumBandwidthPerCall()))
		BWRequest = CallTbl->GetMinimumBandwidthPerCall();
	// enforce max bandwidth per call
	if ((CallTbl->GetMaximumBandwidthPerCall() > 0) && (BWRequest > CallTbl->GetMaximumBandwidthPerCall()))
		BWRequest = CallTbl->GetMaximumBandwidthPerCall();

	if (BWRequest > 0) {
		// check if it is the first arrived ARQ
		if (pExistingCallRec) {
			// 2nd ARQ: request more bandwidth if needed
			BWRequest = CallTbl->CheckEPBandwidth(pExistingCallRec->GetCalledParty(), BWRequest);
			long AdditionalBW = 0;
			long callBW = pExistingCallRec->GetBandwidth();
			if (BWRequest > callBW) {
				AdditionalBW = CallTbl->CheckTotalBandwidth(BWRequest - callBW);
				AdditionalBW = CallTbl->CheckEPBandwidth(pExistingCallRec->GetCallingParty(), AdditionalBW);
				BWRequest = callBW + AdditionalBW;
				callBW = BWRequest;
			}
			if (BWRequest <= 0) {
				bReject = true;
			} else {
				bReject = false;
				CallTbl->UpdateEPBandwidth(pExistingCallRec->GetCallingParty(), AdditionalBW);
				CallTbl->UpdateEPBandwidth(pExistingCallRec->GetCalledParty(), callBW);
				CallTbl->UpdateTotalBandwidth(AdditionalBW);
				pExistingCallRec->SetBandwidth(callBW);
			}
		} else {
			// 1st ARQ
			BWRequest = CallTbl->CheckEPBandwidth(RequestingEP, BWRequest);
			BWRequest = CallTbl->CheckEPBandwidth(CalledEP, BWRequest);
			BWRequest = CallTbl->CheckTotalBandwidth(BWRequest);
			if (BWRequest <= 0) {
				bReject = true;
				PTRACE(3, "GK\tARJ - no bandwidth");
			} else {
				CallTbl->UpdateEPBandwidth(RequestingEP, BWRequest);
				CallTbl->UpdateTotalBandwidth(BWRequest);
			}
		}
	}
	if (bReject) {
        CallRec dummyCall(*this, BWRequest, destinationString, authData.m_proxyMode); // dummy call object so accounting variables can be filled
        (void)RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctReject, callptr(&dummyCall));	// ignore success/failure
        // set H.235.1 tokens
		SetupResponseTokens(m_msg->m_replyRAS, RequestingEP);
		return BuildReply(H225_AdmissionRejectReason::e_requestDenied);
	}

	PTRACE(3, "GK\tACF will grant bandwidth of " << BWRequest);
	// new connection admitted
	H225_AdmissionConfirm & acf = BuildConfirm();
	acf.m_bandWidth = (int)BWRequest;

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
			if (Toolkit::Instance()->GWRewriteE164(out_rewrite_source, GW_REWRITE_OUT, request.m_destinationInfo[0], pExistingCallRec)
				&& (!RasSrv->IsGKRouted() || RequestingEP->GetForceDirectMode()))
				aliasesChanged = true;
	}

	if (hasDestInfo && CalledEP && RequestingEP != CalledEP && !arq.GetRoutes().empty() && !arq.GetRoutes().front().m_destOutNumber.IsEmpty()) {
        bool forceDirectMode = (CalledEP && CalledEP->GetForceDirectMode());
		for (PINDEX i = 0; i < request.m_destinationInfo.GetSize(); ++i)
			if (request.m_destinationInfo[i].GetTag() == H225_AliasAddress::e_dialedDigits) {
				H323SetAliasAddress(arq.GetRoutes().front().m_destOutNumber, request.m_destinationInfo[i], request.m_destinationInfo[i].GetTag());
				aliasesChanged = aliasesChanged || (RasSrv->IsGKRouted() && !forceDirectMode);
			} else if (request.m_destinationInfo[i].GetTag() == H225_AliasAddress::e_partyNumber) {
				H225_PartyNumber &partyNumber = request.m_destinationInfo[i];
				if (partyNumber.GetTag() == H225_PartyNumber::e_e164Number) {
					H225_PublicPartyNumber &number = partyNumber;
					number.m_publicNumberDigits = arq.GetRoutes().front().m_destOutNumber;
					aliasesChanged = aliasesChanged || (RasSrv->IsGKRouted() && !forceDirectMode);
				} else if (partyNumber.GetTag() == H225_PartyNumber::e_privateNumber) {
					H225_PrivatePartyNumber &number = partyNumber;
					number.m_privateNumberDigits = arq.GetRoutes().front().m_destOutNumber;
					aliasesChanged = aliasesChanged || (RasSrv->IsGKRouted() && !forceDirectMode);
				}
			}
	}

	CallRec *pCallRec = NULL;
	if (pExistingCallRec) {
		// duplicate or answer ARQ
		PTRACE(3, "GK\tACF: found existing call no " << pExistingCallRec->GetCallNumber());
		if (authData.m_callDurationLimit > 0)
			pExistingCallRec->SetDurationLimit(authData.m_callDurationLimit);
		if (!authData.m_callingStationId)
			pExistingCallRec->SetCallingStationId(authData.m_callingStationId);
		if (!authData.m_calledStationId)
			pExistingCallRec->SetCalledStationId(authData.m_calledStationId);
		if (authData.m_clientAuthId > 0)
			pExistingCallRec->SetClientAuthId(authData.m_clientAuthId);
		pExistingCallRec->SetBindHint(arq.GetSourceIP());
		if (arq.HasNewSetupInternalAliases()) {
            pExistingCallRec->SetNewSetupInternalAliases(arq.GetNewSetupInternalAliases());
        }
	} else {

		// the call is not in the table
		pCallRec = new CallRec(*this, BWRequest, destinationString, authData.m_proxyMode);

		pCallRec->SetBindHint(arq.GetSourceIP());
		if (arq.HasNewSetupInternalAliases()) {
            pCallRec->SetNewSetupInternalAliases(arq.GetNewSetupInternalAliases());
        }
		pCallRec->SetCallerID(arq.GetCallerID());
		pCallRec->SetCallerDisplayIE(arq.GetCallerDisplayIE());
		pCallRec->SetCalledDisplayIE(arq.GetCalledDisplayIE());
		if (CalledEP) {
			pCallRec->SetCalled(CalledEP);
		} else {
			if (answer) {
				pCallRec->SetCalled(RequestingEP);
			}
			pCallRec->SetDestSignalAddr(CalledAddress);
		}
		if (!answer) {
			pCallRec->SetCalling(RequestingEP);
		}
		if (toParent) {
			pCallRec->SetToParent(true);
		}
		if (connectWithTLS) {
			pCallRec->SetConnectWithTLS(true);
		}
#ifdef HAS_H46023
		if (natoffloadsupport == CallRec::e_natNoassist) { // If no assistance then No NAT type
			PTRACE(4, "RAS\tNAT Type reset to none");
			pCallRec->SetNATType(0);
		}
#endif
		pCallRec->SetNewRoutes(arq.GetRoutes());

		if (!authData.m_disabledcodecs.IsEmpty())
			pCallRec->SetDisabledCodecs(authData.m_disabledcodecs);

		if (authData.m_callDurationLimit > 0)
			pCallRec->SetDurationLimit(authData.m_callDurationLimit);
		if (!authData.m_callingStationId)
			pCallRec->SetCallingStationId(authData.m_callingStationId);
		if (!authData.m_calledStationId)
			pCallRec->SetCalledStationId(authData.m_calledStationId);
		if (!authData.m_dialedNumber)
			pCallRec->SetDialedNumber(authData.m_dialedNumber);

		if (authData.m_routeToAlias.GetSize() > 0)
			pCallRec->SetRouteToAlias(authData.m_routeToAlias);
		if (authData.m_clientAuthId > 0)
			pCallRec->SetClientAuthId(authData.m_clientAuthId);

		if (!RasSrv->IsGKRouted() || (pExistingCallRec && pExistingCallRec->GetCallingParty() && pExistingCallRec->GetCallingParty()->GetForceDirectMode()))
			pCallRec->SetConnected();
		else if (acf.HasOptionalField(H225_AdmissionConfirm::e_cryptoTokens))
			pCallRec->SetAccessTokens(acf.m_cryptoTokens);
		CallTbl->Insert(pCallRec);

#ifdef HAS_H46023
		if (Toolkit::Instance()->IsH46023Enabled() && !EPRequiresH46026) {
			// Std24 proxy offload. See if the media can go direct.
			if (natoffloadsupport == CallRec::e_natUnknown) {
				if (!pCallRec->NATOffLoad(answer, natoffloadsupport)) {
					if (natoffloadsupport == CallRec::e_natFailure) {
						PTRACE(2, "RAS\tWarning: NAT Media Failure detected " << (unsigned)request.m_callReferenceValue);
                        CallRec dummyCall(*this, BWRequest, destinationString, authData.m_proxyMode); // dummy call object so accounting variables can be filled
                        (void)RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctReject, callptr(&dummyCall));	// ignore success/failure
                        SetupResponseTokens(m_msg->m_replyRAS, RequestingEP);
						return BuildReply(H225_AdmissionRejectReason::e_noRouteToDestination, true);
					 }
				}
			}

			// If not required disable the proxy support function for this call
			if (pCallRec->GetProxyMode() != CallRec::ProxyDisabled &&
				(natoffloadsupport == CallRec::e_natLocalMaster ||
					natoffloadsupport == CallRec::e_natRemoteMaster ||
					natoffloadsupport == CallRec::e_natNoassist ||
				(!pCallRec->SingleGatekeeper() && (natoffloadsupport == CallRec::e_natRemoteProxy ||
												   natoffloadsupport == CallRec::e_natAnnexB)))) {
						PTRACE(4, "RAS\tNAT Proxy disabled due to offload support");
						pCallRec->SetProxyMode(CallRec::ProxyDisabled);
			}

			if (!pCallRec->SingleGatekeeper() &&
				pCallRec->GetProxyMode() == CallRec::ProxyDisabled &&
				(natoffloadsupport == CallRec::e_natRemoteMaster ||
				 natoffloadsupport == CallRec::e_natRemoteProxy ||
				 natoffloadsupport == CallRec::e_natAnnexB)) {
					// Where the remote will handle the NAT Traversal
					// the local gatekeeper may not receive any signaling so
					// set the call as connected.
					if (!RasSrv->IsGKRouted() || (pExistingCallRec && pExistingCallRec->GetCallingParty() && pExistingCallRec->GetCallingParty()->GetForceDirectMode()))
						pCallRec->SetConnected();
			}

			if ((!RasSrv->IsGKRouted() || (pExistingCallRec && pExistingCallRec->GetCallingParty() && pExistingCallRec->GetCallingParty()->GetForceDirectMode()))
                && natoffloadsupport == CallRec::e_natUnknown)
				pCallRec->SetConnected();

			pCallRec->SetNATStrategy(natoffloadsupport);
			PTRACE(4, "RAS\tNAT strategy for Call No: " << pCallRec->GetCallNumber() <<
						" set to " << pCallRec->GetNATOffloadString(natoffloadsupport));

			if (natoffloadsupport == CallRec::e_natNoassist) { // If no assistance then No NAT type
				PTRACE(4, "RAS\tNAT Type reset to none");
				pCallRec->SetNATType(0);
			}

			signalOffload = pCallRec->NATSignallingOffload(answer);
			if (signalOffload) {
				PTRACE(4, "RAS\tNAT H46023 Signal Offload set by policy");
				pCallRec->ResetTimeOut();
			}

			pCallRec->GetRemoteInfo(vendor, version);
		}
#endif
		// Put rewriting information into call record
		pCallRec->SetInboundRewriteId(in_rewrite_source);
		pCallRec->SetOutboundRewriteId(out_rewrite_source);

	}

	// decide routed or direct mode for the call
    bool callerForcedDirect = false;
    bool calledForcedDirect = false;
    if (pCallRec && pCallRec->GetCallingParty() && pCallRec->GetCallingParty()->GetForceDirectMode()) {
        callerForcedDirect = true;
    }
    if (pExistingCallRec && pExistingCallRec->GetCallingParty() && pExistingCallRec->GetCallingParty()->GetForceDirectMode()) {
        calledForcedDirect = true;
    }
    if (pCallRec && pCallRec->GetCalledParty() && pCallRec->GetCalledParty()->GetForceDirectMode()) {
        calledForcedDirect = true;
    }
    if (pExistingCallRec && pExistingCallRec->GetCalledParty() && pExistingCallRec->GetCalledParty()->GetForceDirectMode()) {
        calledForcedDirect = true;
    }

	if (RasSrv->IsGKRouted() && !signalOffload && !callerForcedDirect && !calledForcedDirect) {
        // regular routed mode
		acf.m_callModel.SetTag(H225_CallModel::e_gatekeeperRouted);
		GetCallSignalAddress(acf.m_destCallSignalAddress);
#ifdef HAS_TLS
		if (Toolkit::Instance()->IsTLSEnabled() && RequestingEP->UseTLS()) {
			// tell endpoint to use the TLS port
			WORD tlsSignalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT);
			SetH225Port(acf.m_destCallSignalAddress, tlsSignalPort);
		}
#endif
	} else if (RasSrv->IsGKRouted() && !signalOffload && callerForcedDirect && !calledForcedDirect) {
        // forced direct to routed EP
	    if (!answer) {
            acf.m_callModel.SetTag(H225_CallModel::e_direct);
	    } else {
            acf.m_callModel.SetTag(H225_CallModel::e_gatekeeperRouted);
	    }
        GetCallSignalAddress(acf.m_destCallSignalAddress); // set to GK IP
	} else if (RasSrv->IsGKRouted() && !signalOffload && !callerForcedDirect && calledForcedDirect) {
        // routed EP to forced direct EP
	    if (answer) {
            acf.m_callModel.SetTag(H225_CallModel::e_direct);
	    } else {
            acf.m_callModel.SetTag(H225_CallModel::e_gatekeeperRouted);
	    }
        GetCallSignalAddress(acf.m_destCallSignalAddress); // set to GK IP
	} else {
        // regular direct mode
		acf.m_callModel.SetTag(H225_CallModel::e_direct);
		if (answer && pExistingCallRec && pExistingCallRec->GetCallingParty()) {
			CalledAddress = pExistingCallRec->GetCallingParty()->GetCallSignalAddress();
		}
		acf.m_destCallSignalAddress = CalledAddress;
        if (pCallRec)
            pCallRec->ResetTimeOut(); // disable checking for signaling timeout
        if (pExistingCallRec)
            pExistingCallRec->ResetTimeOut(); // disable checking for signaling timeout
	}

	long irrFrq = GkConfig()->GetInteger("CallTable", "IRRFrequency", 120);
	if (irrFrq > 0) {
		acf.IncludeOptionalField ( H225_AdmissionConfirm::e_irrFrequency );
		acf.m_irrFrequency.SetValue(irrFrq);
	}

	if( !answer && aliasesChanged
		&& request.HasOptionalField(H225_AdmissionRequest::e_canMapAlias)
		&& request.m_canMapAlias
		&& request.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)
		&& request.m_destinationInfo.GetSize() > 0) {
		acf.IncludeOptionalField(H225_AdmissionConfirm::e_destinationInfo);
		acf.m_destinationInfo = request.m_destinationInfo;
	}

	if (RequestingEP->AddCallCreditServiceControl(acf.m_serviceControl,
			authData.m_amountString, authData.m_billingMode,
			authData.m_callDurationLimit)) {
			   	acf.IncludeOptionalField(H225_AdmissionConfirm::e_serviceControl);
	}

#ifdef HAS_LANGUAGE
	if (!answer && GkConfig()->GetBoolean("RasSrv::LRQFeatures", "EnableLanguageRouting", false)) {
		H323SetLanguages(Language, acf.m_language);
		acf.IncludeOptionalField(H225_AdmissionConfirm::e_language);
	}
#endif

#ifdef HAS_H460
	if (!answer) {
		PINDEX lastPos = 0;
		H225_ArrayOf_GenericData & data = acf.m_genericData;
#ifdef HAS_H46023
		// If we have a call record and the remote party needs NAT support
		// and the requesting EP can provide it then notify the EP to lend assistance.
		if (natsupport && RequestingEP->UsesH46023()) {
			 H460_FeatureStd fs = H460_FeatureStd(24);
			 fs.Add(Std24_NATInstruct, H460_FeatureContent((int)natoffloadsupport, 8));
			 lastPos++;
			 data.SetSize(lastPos);
			 data[lastPos-1] = fs;
		}
#endif
#ifdef HAS_H460VEN
		/// OID9 Vendor Information
		if (vendorInfo) {
			H460_FeatureOID fs = H460_FeatureOID(OID9);
			if (!vendor.IsEmpty()) {
				fs.Add(PString(VendorProdOID), H460_FeatureContent(vendor));
				fs.Add(PString(VendorVerOID), H460_FeatureContent(version));
			}
			lastPos++;
			data.SetSize(lastPos);
			data[lastPos-1] = fs;
		}
#endif
		if (lastPos > 0)
			acf.IncludeOptionalField(H225_AdmissionConfirm::e_genericData);
	}

	// H.460.9 QoS Reporting
	if (EPSupportsQoSReporting
		&& GkConfig()->GetBoolean("GkQoSMonitor", "Enable", false)) {
		H460_FeatureStd feat = H460_FeatureStd(9);
		if (GkConfig()->GetBoolean("GkQoSMonitor", "CallEndOnly", true)) {
            // PVX ignores this parameter and always sends data in IRR and DRQ
			H460_FeatureID finalonly = H460_FeatureID(0);
			feat.AddParameter(&finalonly);
		}
		acf.IncludeOptionalField(H225_AdmissionConfirm::e_featureSet);
		acf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_desiredFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = acf.m_featureSet.m_desiredFeatures;
		PINDEX len = desc.GetSize();
		desc.SetSize(len + 1);
		desc[len] = feat;
	}

	// H.460.22
	if (EPSupportsH46022) {
		H460_FeatureStd H46022 = H460_FeatureStd(22);
		if (RasSrv->IsGKRouted() && !signalOffload && !(CalledEP && CalledEP->GetForceDirectMode())) {
			// inform endpoint about gatekeeper's capabilities
#ifdef HAS_TLS
			if (Toolkit::Instance()->IsTLSEnabled() && EPSupportsH46022TLS) {
				H460_FeatureStd settings;
				settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
				H323TransportAddress signalAddr = acf.m_destCallSignalAddress;
				settings.Add(Std22_ConnectionAddress, H460_FeatureContent(signalAddr));
				H46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
			}
#endif
		} else {
			// inform endpoint about remote endpoint's capabilities
			if (EPSupportsH46022TLS && CalledEP && CalledEP->UseTLS()) {
				H460_FeatureStd settings;
				settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
				settings.Add(Std22_ConnectionAddress, H460_FeatureContent(CalledEP->GetTLSAddress()));
				H46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
			}
			if (EPSupportsH46022IPSec && CalledEP && CalledEP->UseIPSec()) {
				H460_FeatureStd settings;
				settings.Add(Std22_Priority, H460_FeatureContent(2, 8)); // Priority=2, type=number8
				H46022.Add(Std22_IPSec, H460_FeatureContent(settings.GetCurrentTable()));
			}
		}
		if (H46022.Contains(Std22_TLS) || H46022.Contains(Std22_IPSec)) {
			acf.IncludeOptionalField(H225_AdmissionConfirm::e_featureSet);
			acf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
			H225_ArrayOf_FeatureDescriptor & desc = acf.m_featureSet.m_supportedFeatures;
			PINDEX sz = desc.GetSize();
			desc.SetSize(sz+1);
			desc[sz] = H46022;
		}
	}

#ifdef HAS_H46026
	/// H.460.26 media tunneling
	if (EPRequiresH46026) {
		H460_FeatureStd feat = H460_FeatureStd(26);
		acf.IncludeOptionalField(H225_AdmissionConfirm::e_featureSet);
		acf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_neededFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = acf.m_featureSet.m_neededFeatures;
		PINDEX len = desc.GetSize();
		desc.SetSize(len + 1);
		desc[len] = feat;
	}
#endif	// HAS_H46026
#endif	// HAS_H460

    // set H.235.1 tokens
	SetupResponseTokens(m_msg->m_replyRAS, RequestingEP);

	return BuildReply(e_acf, false, pCallRec);
}

bool AdmissionRequestPDU::BuildReply(int reason, bool h460, CallRec * rec)
{
	PString source = RequestingEP ? AsDotString(RequestingEP->GetCallSignalAddress()) : PString(" ");
	PString srcInfo = AsString(request.m_srcInfo);
	const char *answerCall = request.m_answerCall ? "true" : "false";

	PString log;
	if (reason == e_routeRequest) {
		log = "RouteRequest|" + source
				+ "|" + RequestingEP->GetEndpointIdentifier().GetValue()
				+ "|" + PString(request.m_callReferenceValue)
				+ "|" + destinationString
				+ "|" + srcInfo;
		PString callid = AsString(request.m_callIdentifier);
		callid.Replace(" ", "-", true);
		log += PString("|") + callid;
		log += PString("|") + (rec ? rec->GetMediaRouting() : " ");
		log += PString(";");
	} else if (reason < 0) {
		log = "ACF|" + source
				+ "|" + RequestingEP->GetEndpointIdentifier().GetValue()
				+ "|" + PString(request.m_callReferenceValue)
				+ "|" + destinationString
				+ "|" + srcInfo
				+ "|" + answerCall;
		PString callid = AsString(request.m_callIdentifier);
		callid.Replace(" ", "-", true);
		log += PString("|") + callid;
		log += PString("|") + (rec ? rec->GetMediaRouting() : " ");
		log += PString(";");
	} else {
		H225_AdmissionReject & arj = BuildReject(reason);
		if (reason == H225_AdmissionRejectReason::e_resourceUnavailable)
			RasSrv->SetAltGKInfo(arj, m_msg->m_peerAddr);
#ifdef HAS_H46023
		if (h460) {
			arj.IncludeOptionalField(H225_AdmissionReject::e_genericData);
			H460_FeatureStd h46024 = H460_FeatureStd(24);
			arj.m_genericData.SetSize(1);
			arj.m_genericData[0] = h46024;
		}
#endif
		log = "ARJ|" + source
				+ "|" + destinationString
				+ "|" + srcInfo
				+ "|" + answerCall
				+ "|" + arj.m_rejectReason.GetTagName();
		PString callid = AsString(request.m_callIdentifier);
		callid.Replace(" ", "-", true);
		log += PString("|") + callid;
		log += PString(";");
	}
	return PrintStatus(log);
}

template<> bool RasPDU<H225_BandwidthRequest>::Process()
{
	// OnBRQ
	endptr RequestingEP = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier);
	if (RequestingEP && RasSrv->ReplyToRasAddress(m_msg->m_peerAddr)) {
		if (GetIPAndPortFromTransportAddr(RequestingEP->GetRasAddress(), m_msg->m_peerAddr, m_msg->m_peerPort)) {
			PTRACE(3, "Reply to saved rasAddress:" << AsString(m_msg->m_peerAddr, m_msg->m_peerPort));
		} else {
			PTRACE(1, "Unable to parse saved rasAddress " << RequestingEP->GetRasAddress());
		}
	}

	long bandwidth = request.m_bandWidth.GetValue();
	// enforce minimum bandwidth per call
	if ((CallTbl->GetMinimumBandwidthPerCall() > 0) && (bandwidth < CallTbl->GetMinimumBandwidthPerCall()))
		bandwidth = CallTbl->GetMinimumBandwidthPerCall();
	// enforce max bandwidth per call
	if ((CallTbl->GetMaximumBandwidthPerCall() > 0) && (bandwidth > CallTbl->GetMaximumBandwidthPerCall()))
		bandwidth = CallTbl->GetMaximumBandwidthPerCall();

	callptr pCall = request.HasOptionalField(H225_BandwidthRequest::e_callIdentifier) ?
		CallTbl->FindCallRec(request.m_callIdentifier) :
		CallTbl->FindCallRec(request.m_callReferenceValue);

	PString log;
	unsigned rsn = H225_BandRejectReason::e_securityDenial;
	bool bReject = !RasSrv->ValidatePDU(*this, rsn);
	if (!GkConfig()->GetBoolean("GrantAllBRQ", false)) {
        if (!bReject && !pCall) {
            bReject = true;
            rsn = H225_BandRejectReason::e_invalidConferenceID;
        } else
        if (!bReject) {
            long AdditionalBW = bandwidth - pCall->GetBandwidth();
            // only update settings when more BW is requested, if its less, agree and leave as is
            if (AdditionalBW > 0) {
                AdditionalBW = CallTbl->CheckEPBandwidth(pCall->GetCallingParty(), AdditionalBW);
                AdditionalBW = CallTbl->CheckEPBandwidth(pCall->GetCalledParty(), AdditionalBW);
                AdditionalBW = CallTbl->CheckTotalBandwidth(AdditionalBW);
                if (AdditionalBW > 0) {
                    CallTbl->UpdateEPBandwidth(pCall->GetCallingParty(), AdditionalBW);
                    CallTbl->UpdateEPBandwidth(pCall->GetCalledParty(), AdditionalBW);
                    CallTbl->UpdateTotalBandwidth(AdditionalBW);
                    bandwidth = pCall->GetBandwidth() + AdditionalBW;
                    pCall->SetBandwidth(bandwidth);
                } else {
                    bReject = true;
                    rsn = H225_BandRejectReason::e_insufficientResources;
                }
            } else {
                // the endpoint has requested to lower the bandwidth
                // for now we just agree, we could also reduce update the current total, per call and per endpoint usage
            }
        }
	}
	if (bReject) {
		H225_BandwidthReject & brj = BuildReject(rsn);
		if (rsn == H225_BandRejectReason::e_insufficientResources) {
			brj.m_allowedBandWidth = (int)CallTbl->GetAvailableBW();
			// ask the endpoint to try alternate gatekeepers
			RasSrv->SetAltGKInfo(brj, m_msg->m_peerAddr);
		}
		log = PString(PString::Printf, "BRJ|%s|%s|%lu|%s;",
			(const char *)m_msg->m_peerAddr.AsString(),
			(const unsigned char *) request.m_endpointIdentifier.GetValue(),
			bandwidth,
			(const unsigned char *) brj.m_rejectReason.GetTagName()
		      );
	} else {
		H225_BandwidthConfirm & bcf = BuildConfirm();
		bcf.m_bandWidth = (int)bandwidth;
		log = PString(PString::Printf, "BCF|%s|%s|%lu;",
			(const char *)m_msg->m_peerAddr.AsString(),
			(const unsigned char *) request.m_endpointIdentifier.GetValue(),
			bandwidth
		      );
	}

    // set H.235.1 tokens
	SetupResponseTokens(m_msg->m_replyRAS, RequestingEP);

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

	if (ep && RasSrv->ReplyToRasAddress(m_msg->m_peerAddr)) {
		if (GetIPAndPortFromTransportAddr(ep->GetRasAddress(), m_msg->m_peerAddr, m_msg->m_peerPort)) {
			PTRACE(3, "Reply to saved rasAddress:" << AsString(m_msg->m_peerAddr, m_msg->m_peerPort));
		} else {
			PTRACE(1, "Unable to parse saved rasAddress " << ep->GetRasAddress());
		}
	}

#ifdef H323_H4609
	if (request.HasOptionalField(H225_DisengageRequest::e_genericData)) {
		H225_ArrayOf_GenericData & data = request.m_genericData;
		for (PINDEX i = 0; i < data.GetSize(); i++) {
			H460_Feature & feat = (H460_Feature &)data[i];
			/// H.460.9 QoS Feature
			if (feat.GetFeatureID() == H460_FeatureID(9)) {
				H460_FeatureStd & qosfeat = (H460_FeatureStd &)feat;
				if (qosfeat.Contains(1)) {
					CallTbl->QoSReport(*this, ep, qosfeat.Value(1));
				}
			}
		}
	}
#endif

	PString log;
	if (bReject) {
		H225_DisengageReject & drj = BuildReject(rsn);
		log = PString(PString::Printf, "DRJ|%s|%s|%u|%s",
				(const char *)m_msg->m_peerAddr.AsString(),
				(const unsigned char *) request.m_endpointIdentifier.GetValue(),
				(unsigned) request.m_callReferenceValue,
				(const unsigned char *) drj.m_rejectReason.GetTagName()
		      	);
		PString callid = AsString(request.m_callIdentifier);
		callid.Replace(" ", "-", true);
		log += PString("|") + callid;
		log += PString(";");
	} else {
		BuildConfirm();
		// always signal DCF
		log = PString(PString::Printf, "DCF|%s|%s|%u|%s",
				(const char *)m_msg->m_peerAddr.AsString(),
				(const unsigned char *) request.m_endpointIdentifier.GetValue(),
				(unsigned) request.m_callReferenceValue,
				(const unsigned char *) request.m_disengageReason.GetTagName()
		      	);
		PString callid = AsString(request.m_callIdentifier);
		callid.Replace(" ", "-", true);
		log += PString("|") + callid;
		log += PString(";");
		if (!RasSrv->IsGKRouted() || RasSrv->RemoveCallOnDRQ() || (ep && ep->GetForceDirectMode()))
			CallTbl->RemoveCall(request, ep);
	}

    // set H.235.1 tokens
	SetupResponseTokens(m_msg->m_replyRAS, ep);

    if (ep && Toolkit::Instance()->IsMaintenanceMode()) {
        PTRACE(1, "DRQ in maintenance mode, send URQ");
        ep->Unregister();
	}

	return PrintStatus(log);
}

template<> bool RasPDU<H225_LocationRequest>::Process()
{
	// OnLRQ
	PString log;
	bool fromTraversalClient = false;
    bool loopDetection = GkConfig()->GetBoolean(LRQFeaturesSection, "LoopDetection", false);

	PString msg;
	if (!Toolkit::Instance()->IsLicenseValid(msg)) {
		PTRACE(2, "Error: No license: " << msg);
		SNMP_TRAP(9, SNMPError, General, "No license: " + msg);
		BuildReject(H225_LocationRejectReason::e_undefinedReason);
		return true;
	}

    if (Toolkit::Instance()->IsMaintenanceMode()) {
        PTRACE(1, "Rejecting LRQ in maintenance mode");
        H225_LocationReject & lrj = BuildReject(H225_LocationRejectReason::e_resourceUnavailable);
        RasSrv->SetAltGKInfo(lrj, m_msg->m_peerAddr);
        return true;
	}

	if (request.m_destinationInfo.GetSize() > 0) {
		// Do a check and make sure this is not a ping
		PString pingAlias = GkConfig()->GetString(LRQFeaturesSection, "PingAlias", "gatekeeper-monitoring-check");
		if (pingAlias == AsString(request.m_destinationInfo[0], false)) {
            BuildReject(H225_LocationRejectReason::e_undefinedReason);
            PTRACE(5, "LRQ PING caught from " << AsDotString(request.m_replyAddress));
            return true;
		}

		if (loopDetection) {
            H225_LocationConfirm cachedLCF;
            switch (CallLoopTable::Instance()->IsLoop(request, AsString(m_msg->m_peerAddr), cachedLCF)) {
                case CallLoopTable::NoLoop:
        		    CallLoopTable::Instance()->CollectLoopData(request, AsString(m_msg->m_peerAddr));
                    break;
                case CallLoopTable::CachedLCF: {
                    H225_LocationConfirm & lcf = BuildConfirm();
                    lcf = cachedLCF;
    				lcf.m_requestSeqNum = request.m_requestSeqNum; // use same sequence number as current request
                    PTRACE(2, "RAS\tSending cached LCF");
                    return true;
                }
                case CallLoopTable::Loop:
                    BuildReject(H225_LocationRejectReason::e_undefinedReason);
                    PTRACE(2, "RAS\tLRQ loop detected from " << AsString(m_msg->m_peerAddr));
                    return true;
		        case CallLoopTable::Resent:
                    PTRACE(2, "RAS\tLRQ resent from " << AsString(m_msg->m_peerAddr));
		            return false; // don't answer
            }
		}

		// do GWRewriteE164 for neighbor before processing
		PString neighbor_id = RasSrv->GetNeighbors()->GetNeighborIdBySigAdr(request.m_replyAddress);
		PString neighbor_gkid = RasSrv->GetNeighbors()->GetNeighborGkIdBySigAdr(request.m_replyAddress);
		// if we didn't find the neighbor by SigIP, check if is a traversal client
		if (neighbor_id.IsEmpty()) {
			fromTraversalClient = RasSrv->GetNeighbors()->IsTraversalClient(m_msg->m_peerAddr);
			if (fromTraversalClient)
				neighbor_id = RasSrv->GetNeighbors()->GetNeighborGkIdBySigAdr(m_msg->m_peerAddr);
		}

		// do the GW IN rewrites
		if (!neighbor_id.IsEmpty()) {
			Toolkit::Instance()->GWRewriteE164(neighbor_id, GW_REWRITE_IN, request.m_destinationInfo[0]);
		}
		if (!neighbor_gkid.IsEmpty() && (neighbor_gkid != neighbor_id)) {
			Toolkit::Instance()->GWRewriteE164(neighbor_gkid, GW_REWRITE_IN, request.m_destinationInfo[0]);
		}

		// Normal rewrite
		Toolkit::Instance()->RewriteE164(request.m_destinationInfo[0]);
	}

	unsigned reason = H225_LocationRejectReason::e_securityDenial;
	PIPSocket::Address ipaddr;
	WORD port;
	bool fromRegEndpoint = false;
	bool replyAddrMatch = GetIPAndPortFromTransportAddr(request.m_replyAddress, ipaddr, port) && (ipaddr == m_msg->m_peerAddr && port == m_msg->m_peerPort);
	endptr ep;
	if (request.HasOptionalField(H225_LocationRequest::e_endpointIdentifier)) {
		ep = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier);
		if (ep) {
			fromRegEndpoint = replyAddrMatch ? true : ep->IsNATed();
		}
	}

	// send RIP message before doing any real work if configured to do so
	unsigned ripDelay = GkConfig()->GetInteger("RasSrv::LRQFeatures", "SendRIP", 0);
	if (ripDelay > 0) {
		RasSrv->SendRIP(request.m_requestSeqNum, ripDelay, m_msg->m_peerAddr, m_msg->m_peerPort, ep ? ep->GetH235Authenticators() : NULL);
	}

    // neighbors do not need validation
	bool bReject = !(fromRegEndpoint || RasSrv->GetNeighbors()->CheckLRQ(this));

	// ff not neighbor and support non neighbor LRQ's then validate the PDU
	if (bReject && (Toolkit::AsBool(GkConfig()->GetString(LRQFeaturesSection, "AcceptNonNeighborLRQ", "0"))))
        bReject = !RasSrv->ValidatePDU(*this, reason);

	PString sourceInfoString(fromRegEndpoint ? request.m_endpointIdentifier.GetValue() : request.HasOptionalField(H225_LocationRequest::e_gatekeeperIdentifier) ? request.m_gatekeeperIdentifier.GetValue() : m_msg->m_peerAddr.AsString());

	// reply to the replyAddress if ReplyToRasAddress is configured
	if (RasSrv->ReplyToRasAddress(m_msg->m_peerAddr)) {
		if (GetIPAndPortFromTransportAddr(request.m_replyAddress, m_msg->m_peerAddr, m_msg->m_peerPort)) {
			PTRACE(3, "Reply to saved rasAddress:" << AsString(m_msg->m_peerAddr, m_msg->m_peerPort));
		} else {
			PTRACE(1, "Unable to parse saved rasAddress " << request.m_replyAddress);
		}
	}

	if (!bReject) {
		endptr WantedEndPoint;
		Route route;
		Routing::LocationRequest lrq(request, this);
		lrq.Process();
		if (lrq.GetFirstRoute(route)) {
			WantedEndPoint = route.m_destEndpoint;
			if ((lrq.GetRoutes().size() == 1 || !Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "ActivateFailover", "0")))
					&& WantedEndPoint && !WantedEndPoint->HasAvailableCapacity(request.m_destinationInfo)) {
				bReject = true;
				reason = H225_LocationRejectReason::e_resourceUnavailable;
			} else {
				H225_LocationConfirm & lcf = BuildConfirm();
				GetRasAddress(lcf.m_rasAddress);

#ifdef HAS_H460
				// check H.460.22 in LRQ
				bool senderSupportsH46022 = false;
				bool senderSupportsH46022TLS = false;
				bool senderSupportsH46022IPSec = false;
				if (request.HasOptionalField(H225_LocationRequest::e_featureSet)) {
					H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);
					senderSupportsH46022 = fs.HasFeature(22);
					if (senderSupportsH46022) {
						H460_FeatureStd * secfeat = (H460_FeatureStd *)fs.GetFeature(22);
						senderSupportsH46022TLS = secfeat->Contains(Std22_TLS);
						senderSupportsH46022IPSec = secfeat->Contains(Std22_IPSec);
						PTRACE(1, "RAS\tEP supports H.460.22: TLS=" << senderSupportsH46022TLS << " IPSec=" << senderSupportsH46022IPSec);
					}
				}
#endif

				if (RasSrv->IsGKRouted() && !(WantedEndPoint && WantedEndPoint->GetForceDirectMode())) {
					GetCallSignalAddress(lcf.m_callSignalAddress);
#if defined(HAS_TLS) && defined(HAS_H460)
					if (Toolkit::Instance()->IsTLSEnabled()) {
						// enable TLS by config file
						bool useTLS = RasSrv->GetNeighbors()->GetNeighborTLSBySigAdr(request.m_replyAddress);
						// include H.460.22 if UseTLS configured for this neighbor or if H.460.22 in LRQ
						if (useTLS || senderSupportsH46022) {
							// tell endpoint to use the TLS port
							WORD tlsSignalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT);
							// force TLS signaling port if UseTLS switch was set
							if (useTLS) {
								SetH225Port(lcf.m_callSignalAddress, tlsSignalPort);
							}
							H460_FeatureStd H46022 = H460_FeatureStd(22);
							H460_FeatureStd settings;
							settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
							H225_TransportAddress h225SignalAddr = lcf.m_callSignalAddress;
							SetH225Port(h225SignalAddr, tlsSignalPort);
							H323TransportAddress signalAddr = h225SignalAddr;
							settings.Add(Std22_ConnectionAddress, H460_FeatureContent(signalAddr));
							H46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
							lcf.IncludeOptionalField(H225_LocationConfirm::e_featureSet);
							lcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
							H225_ArrayOf_FeatureDescriptor & desc = lcf.m_featureSet.m_supportedFeatures;
							PINDEX sz = desc.GetSize();
							desc.SetSize(sz + 1);
							desc[sz] = H46022;
						}
					}
#endif

/* The access token should be standardized somehow and use a correct object
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
					// in direct mode
					lcf.m_callSignalAddress = route.m_destAddr;
#ifdef HAS_H460
					if (senderSupportsH46022) {
						H460_FeatureStd H46022 = H460_FeatureStd(22);
						// pass endpoint's H.460.22 capabilities
						if (WantedEndPoint && WantedEndPoint->UseTLS()) {
							H460_FeatureStd settings;
							settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
							settings.Add(Std22_ConnectionAddress, H460_FeatureContent(WantedEndPoint->GetTLSAddress()));
							H46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
						}
						if (WantedEndPoint && WantedEndPoint->UseIPSec()) {
							H460_FeatureStd settings;
							settings.Add(Std22_Priority, H460_FeatureContent(2, 8)); // Priority=2, type=number8
							H46022.Add(Std22_IPSec, H460_FeatureContent(settings.GetCurrentTable()));
						}
						if (H46022.Contains(Std22_TLS) || H46022.Contains(Std22_IPSec)) {
							lcf.IncludeOptionalField(H225_LocationConfirm::e_featureSet);
							lcf.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
							H225_ArrayOf_FeatureDescriptor & desc = lcf.m_featureSet.m_supportedFeatures;
							PINDEX sz = desc.GetSize();
							desc.SetSize(sz + 1);
							desc[sz] = H46022;
						}
					}
#endif
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

#ifdef HAS_LANGUAGE
				if (request.HasOptionalField(H225_LocationRequest::e_language) &&
					GkConfig()->GetBoolean("RasSrv::LRQFeatures", "EnableLanguageRouting", false)) {
						if (WantedEndPoint && WantedEndPoint->SetAssignedLanguage(lcf.m_language))
							lcf.IncludeOptionalField(H225_LocationConfirm::e_language);
				}
#endif

#ifdef HAS_H460
				H225_ArrayOf_GenericData & data = lcf.m_genericData;
				PINDEX lastPos = 0;
				if ((WantedEndPoint) && (request.HasOptionalField(H225_LocationRequest::e_genericData))) {
					H225_ArrayOf_GenericData & locdata = request.m_genericData;
					for (PINDEX i = 0; i < locdata.GetSize(); i++) {
						H460_Feature & feat = (H460_Feature &)locdata[i];
						/// Std24 NAT Traversal
#ifdef HAS_H46023
						if (Toolkit::Instance()->IsH46023Enabled()) {
							if (feat.GetFeatureID() == H460_FeatureID(24)) {
								H460_FeatureStd std24 = H460_FeatureStd(24);

								PIPSocket::Address remoteIP;
								GetIPFromTransportAddr(request.m_replyAddress,remoteIP);
								bool mustproxy = !Toolkit::Instance()->H46023SameNetwork(remoteIP,
									  WantedEndPoint->IsNATed() ? WantedEndPoint->GetNATIP() : WantedEndPoint->GetIP());

								std24.Add(Std24_RemoteNAT, H460_FeatureContent(WantedEndPoint->SupportH46024()));
								if (mustproxy) {
									std24.Add(Std24_MustProxy,H460_FeatureContent(mustproxy));
								} else {
									std24.Add(Std24_IsNAT, H460_FeatureContent(true));
									std24.Add(Std24_NATdet, H460_FeatureContent(WantedEndPoint->GetEPNATType(), 8));
									std24.Add(Std24_ProxyNAT, H460_FeatureContent(WantedEndPoint->HasNATProxy()));
									std24.Add(Std24_SourceAddr, H460_FeatureContent(H323TransportAddress(WantedEndPoint->GetNATIP(), 0)));
									std24.Add(Std24_AnnexA, H460_FeatureContent(WantedEndPoint->SupportH46024A()));
									std24.Add(Std24_AnnexB, H460_FeatureContent(WantedEndPoint->SupportH46024B()));
								}
								lastPos++;
								data.SetSize(lastPos);
								data[lastPos-1] = std24;
							}
						}
#endif
#ifdef HAS_H460VEN
						/// OID9 Vendor Interoperability
						if (feat.GetFeatureID() == H460_FeatureID(OpalOID(OID9))) {
							PString vendor, version;
							if (WantedEndPoint->GetEndpointInfo(vendor, version)) {
								H460_FeatureOID foid9 = H460_FeatureOID(OID9);
								foid9.Add(PString(VendorProdOID), H460_FeatureContent(vendor));
								foid9.Add(PString(VendorVerOID), H460_FeatureContent(version));
								lastPos++;
								data.SetSize(lastPos);
								data[lastPos-1] = foid9;
							}
						}
#endif // HAS_H460VEN
					}
				}

				if (lastPos > 0)
					lcf.IncludeOptionalField(H225_LocationConfirm::e_genericData);

				PString featureRequired = GkConfig()->GetString(RoutedSec, "NATStdMin", "");
				PBoolean assumePublicH46024 = GkConfig()->GetBoolean(RoutedSec, "H46023PublicIP", false);
				if (!featureRequired && featureRequired == "23" && WantedEndPoint && (!WantedEndPoint->SupportH46024() && !assumePublicH46024)) {
					bReject = true;
					reason = H225_LocationRejectReason::e_genericDataReason;
				} else
#endif	// HAS_H460
				{
				    if (loopDetection
                        && request.HasOptionalField(H225_LocationRequest::e_callIdentifier)
                        && request.m_destinationInfo.GetSize() > 0) {
    				    CallLoopTable::Instance()->CacheLCF(lcf, request.m_callIdentifier, request.m_destinationInfo[0]);
				    }
					log = "LCF|" + m_msg->m_peerAddr.AsString()
							+ "|" + (WantedEndPoint ? WantedEndPoint->GetEndpointIdentifier().GetValue() : AsDotString(route.m_destAddr))
							+ "|" + AsString(request.m_destinationInfo),
							+ "|" + sourceInfoString
							+ ";";
				}
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
				log = "RIP|" + m_msg->m_peerAddr.AsString()
						+ "|" + ripData
						+ "|" + AsString(request.m_destinationInfo)
						+ "|" + sourceInfoString
						+ ";";
			} else {
				bReject = true;
				reason = lrq.GetRejectReason();
			}
		}
	}

	if (bReject) {
		// Alias not found
		H225_LocationReject & lrj = BuildReject(reason);
		log = "LRJ|" + m_msg->m_peerAddr.AsString()
				+ "|" + AsString(request.m_destinationInfo),
				+ "|" + sourceInfoString,
				+ "|" + lrj.m_rejectReason.GetTagName()
				+ ";";
	}

	// for a registered endpoint, reply to the sent address
	if (!(fromRegEndpoint || replyAddrMatch || fromTraversalClient))
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
#ifdef H323_H4609
		if (call && request.HasOptionalField(H225_InfoRequestResponse::e_genericData)) {
			H225_ArrayOf_GenericData & data = request.m_genericData;
			for (PINDEX i = 0; i < data.GetSize(); i++) {
				H460_Feature & feat = (H460_Feature &)data[i];
				/// H.460.9 QoS Feature
				if (feat.GetFeatureID() == H460_FeatureID(9)) {
					H460_FeatureStd & qosfeat = (H460_FeatureStd &)feat;
					if (qosfeat.Contains(1)) {
						CallTbl->QoSReport(*this, call, ep , qosfeat.Value(1));
					}
				}
			}
		}
#endif
		if (request.HasOptionalField(H225_InfoRequestResponse::e_needResponse) && request.m_needResponse) {
			if (RasSrv->ReplyToRasAddress(m_msg->m_peerAddr)) {
				PIPSocket::Address rasIP;
				WORD rasPort;
				if (GetIPAndPortFromTransportAddr(request.m_rasAddress, rasIP, rasPort)) {
					PTRACE(3, "Reply to rasAddress from request:" << AsString(rasIP, rasPort));
					m_msg->m_peerAddr = rasIP;
					m_msg->m_peerPort = rasPort;
				} else {
					PTRACE(1, "Unable to parse rasAddress " << request.m_rasAddress);
				}
			}
			BuildConfirm();
            // set H.235.1 tokens
            SetupResponseTokens(m_msg->m_replyRAS, ep);

			PrintStatus(PString(PString::Printf, "IACK|%s;", (const char *)m_msg->m_peerAddr.AsString()));
			return true;
		}
	}
	// otherwise don't respond
	return false;
}

template<> bool RasPDU<H225_ResourcesAvailableIndicate>::Process()
{
	// OnRAI
	endptr ep = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier);
	if (ep && RasSrv->ReplyToRasAddress(m_msg->m_peerAddr)) {
		if (GetIPAndPortFromTransportAddr(ep->GetRasAddress(), m_msg->m_peerAddr, m_msg->m_peerPort)) {
			PTRACE(3, "Reply to saved rasAddress:" << AsString(m_msg->m_peerAddr, m_msg->m_peerPort));
		} else {
			PTRACE(1, "Unable to parse saved rasAddress " << ep->GetRasAddress());
		}
	}

    unsigned rsn = 0;
	bool bAccept = RasSrv->ValidatePDU(*this, rsn);

    if (bAccept) {
        // accept all RAIs
        H225_ResourcesAvailableConfirm & rac = BuildConfirm();
        rac.m_protocolIdentifier = request.m_protocolIdentifier;

        // set H.235.1 tokens
        SetupResponseTokens(m_msg->m_replyRAS, ep);

        PrintStatus(PString(PString::Printf, "RAC|%s;", (const char *)m_msg->m_peerAddr.AsString()));
    } else {
        PTRACE(5, "RAS\tInvalid RAI received");
    }
	return bAccept;
}

template<> bool RasPDU<H225_ServiceControlIndication>::Process()
{
	// OnSCI
	endptr ep = EndpointTbl->FindByEndpointId(request.m_endpointIdentifier);
	if (ep && RasSrv->ReplyToRasAddress(m_msg->m_peerAddr)) {
		if (GetIPAndPortFromTransportAddr(ep->GetRasAddress(), m_msg->m_peerAddr, m_msg->m_peerPort)) {
			PTRACE(3, "Reply to saved rasAddress:" << m_msg->m_peerAddr << ":" << m_msg->m_peerPort);
		} else {
			PTRACE(1, "Unable to parse saved rasAddress " << ep->GetRasAddress());
		}
	}
	H225_ServiceControlResponse & scr = BuildConfirm();
	scr.m_requestSeqNum = request.m_requestSeqNum; // redundant, just to avoid compiler warning when H.460.18 is disabled

#ifdef HAS_H46018
	bool incomingCall = false;

	// check if its from parent
	GkClient * gkClient = RasServer::Instance()->GetGkClient();
	bool fromParent = gkClient && gkClient->IsRegistered() && gkClient->UsesH46018() && gkClient->CheckFrom(m_msg->m_peerAddr);
	bool useTLS = false;
	H323TransportAddress tlsAddr;
	if (fromParent) {
		// check H.460.22 indicator from parent
		if (request.HasOptionalField(H225_ServiceControlIndication::e_genericData)) {
			H460_FeatureSet fs = H460_FeatureSet(request.m_genericData);
			if (fs.HasFeature(22)) {	// supports H.460.22
				H460_FeatureStd * secfeat = (H460_FeatureStd *)fs.GetFeature(22);
				useTLS = secfeat->Contains(Std22_TLS);
				if (useTLS) {
					H460_FeatureParameter & tlsparam = secfeat->Value(Std22_TLS);
					H460_FeatureStd settings;
					settings.SetCurrentTable(tlsparam);
					if (settings.Contains(Std22_ConnectionAddress)) {
						tlsAddr = settings.Value(Std22_ConnectionAddress);
					} else {
						PTRACE(1, "TLS\tError: H.460.22 TLS address missing");
					}
				}
			}
		}
	}

	// find the neighbor this comes from
	NeighborList::List & neighbors = *RasServer::Instance()->GetNeighbors();
#if (__cplusplus >= 201703L) // C++17
	NeighborList::List::iterator iter = find_if(neighbors.begin(), neighbors.end(), bind(mem_fn(&Neighbors::Neighbor::IsFrom), std::placeholders::_1, &m_msg->m_peerAddr));
#else
	NeighborList::List::iterator iter = find_if(neighbors.begin(), neighbors.end(), bind2nd(mem_fun(&Neighbors::Neighbor::IsFrom), &m_msg->m_peerAddr));
#endif
	Neighbors::Neighbor * from_neighbor = NULL;
	bool neighbor_authenticated = true;
	if (iter != neighbors.end())
		from_neighbor = (*iter);
	// check the password, if set
	if (from_neighbor)
		neighbor_authenticated = from_neighbor->Authenticate(this);

	// accept incomingIndication from neighbor without an entry in supportedFeatures
	if (request.HasOptionalField(H225_ServiceControlIndication::e_genericData)
		&& Toolkit::Instance()->IsH46018Enabled()) {
		if (fromParent || (from_neighbor && neighbor_authenticated)) {
			for (PINDEX i = 0; i < request.m_genericData.GetSize(); i++) {
				H460_FeatureStd & feat = (H460_FeatureStd &)request.m_genericData[i];
				if (feat.GetFeatureID() == H460_FeatureID(18) && feat.Contains(H460_FeatureID(1))) {
					// incoming call from parent or neighbor
					PASN_OctetString rawIncomingIndication = feat.Value(H460_FeatureID(1));
					H46018_IncomingCallIndication incomingIndication;
					PPER_Stream raw(rawIncomingIndication);
					if (incomingIndication.Decode(raw)) {
						incomingCall = true;
						H225_TransportAddress sigAddr = incomingIndication.m_callSignallingAddress;
						PTRACE(2, "Incoming H.460.18 call from neighbor/parent sigAdr=" << AsDotString(sigAddr)
							<< " callID=" << AsString(incomingIndication.m_callID) << " TLS=" << useTLS);
						CallSignalSocket * outgoingSocket = NULL;
#ifdef HAS_TLS
						if (Toolkit::Instance()->IsTLSEnabled() && useTLS) {
							outgoingSocket = new TLSCallSignalSocket();
							sigAddr = H323ToH225TransportAddress(tlsAddr);
						} else
#endif // HAS_TLS
						{
							outgoingSocket = new CallSignalSocket();
						}
						outgoingSocket->OnSCICall(incomingIndication.m_callID, sigAddr, useTLS);
					} else {
						PTRACE(1, "Error decoding IncomingIndication");
						SNMP_TRAP(9, SNMPError, Network, "Error decoding IncomingIndication");
					}
				}
			}
		}
	}

	// check if its a keepAlive from neighbor
	if (!incomingCall && request.HasOptionalField(H225_ServiceControlIndication::e_featureSet)) {
		H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);
		if (fs.HasFeature(18) && Toolkit::Instance()->IsH46018Enabled()) {
			if (request.HasOptionalField(H225_ServiceControlIndication::e_cryptoTokens)) {
				// check if this is from a traversal client, so we can update the IP
				if ((request.m_cryptoTokens.GetSize() > 0)
					&& (request.m_cryptoTokens[0].GetTag() == H225_CryptoH323Token::e_cryptoGKPwdHash)) {
					H225_CryptoH323Token_cryptoGKPwdHash & token = request.m_cryptoTokens[0];
					PString gkid = token.m_gatekeeperId;
#if (__cplusplus >= 201703L) // C++17
					NeighborList::List::iterator iter = find_if(neighbors.begin(), neighbors.end(), bind(mem_fn(&Neighbors::Neighbor::IsTraversalUser), std::placeholders::_1, &gkid));
#else
					NeighborList::List::iterator iter = find_if(neighbors.begin(), neighbors.end(), bind2nd(mem_fun(&Neighbors::Neighbor::IsTraversalUser), &gkid));
#endif
					if (iter != neighbors.end()) {
						from_neighbor = (*iter);
						neighbor_authenticated = from_neighbor->Authenticate(this);
						if (neighbor_authenticated) {
							from_neighbor->SetApparentIP(m_msg->m_peerAddr, m_msg->m_peerPort);
							from_neighbor->SetDisabled(false); // is reachable
                        }
					}
				}
			}
			// set interval
			if (from_neighbor && neighbor_authenticated) {
				from_neighbor->SetH46018Server(true);	// remember to use H.460.18 with this neighbor
				// keepAlive from a neighbor, send out a SCR with a keepAliveInterval
				H460_FeatureStd feat = H460_FeatureStd(18);
				scr.IncludeOptionalField(H225_ServiceControlResponse::e_featureSet);
				scr.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				scr.m_featureSet.m_supportedFeatures.SetSize(1);
				scr.m_featureSet.m_supportedFeatures[0] = feat;
				H46018_LRQKeepAliveData lrqKeepAlive;
				lrqKeepAlive.m_lrqKeepAliveInterval = (int)GkConfig()->GetInteger(RoutedSec, "H46018KeepAliveInterval", 19);
				PASN_OctetString rawKeepAlive;
				rawKeepAlive.EncodeSubType(lrqKeepAlive);
				feat.Add(2, H460_FeatureContent(rawKeepAlive));
				scr.IncludeOptionalField(H225_ServiceControlResponse::e_genericData);
				H225_ArrayOf_GenericData & gd = scr.m_genericData;
				gd.SetSize(1);
				gd[0] = feat;
				// signal success
				scr.IncludeOptionalField(H225_ServiceControlResponse::e_result);
				scr.m_result = H225_ServiceControlResponse_result::e_started;
			} else {
				// signal failure
				scr.IncludeOptionalField(H225_ServiceControlResponse::e_result);
				scr.m_result = H225_ServiceControlResponse_result::e_failed;
			}
		}
	}
#endif

#ifdef HAS_H460P
	if (request.HasOptionalField(H225_ServiceControlIndication::e_genericData)) {
		H460_FeatureSet fs = H460_FeatureSet(request.m_genericData);
		OpalOID oid3(OID3);
		if (fs.HasFeature(oid3) && Toolkit::Instance()->IsH460PEnabled()) {
			H460_FeatureOID * feat = (H460_FeatureOID *)fs.GetFeature(oid3);
			if (feat->Contains(OID3_PDU)) {
				PASN_OctetString & prePDU = feat->Value(OID3_PDU);
				GkPresence & handler  = Toolkit::Instance()->GetPresenceHandler();
				handler.ProcessPresenceElement(prePDU);
			}
		}
	}
#endif

    // TODO235: add tokens for neighbor

	PrintStatus(PString(PString::Printf, "SCR|%s;", (const char *)m_msg->m_peerAddr.AsString()));
	return true;
}

template<> bool RasPDU<H225_ServiceControlResponse>::Process()
{
	// OnSCR
#ifdef HAS_H46018
	// check if it belongs to a neighbor SCI and use the keepAliveInterval
    NeighborList::List & neighbors = *RasServer::Instance()->GetNeighbors();
#if (__cplusplus >= 201703L) // C++17
    NeighborList::List::iterator iter = find_if(neighbors.begin(), neighbors.end(), bind(mem_fn(&Neighbors::Neighbor::IsFrom), std::placeholders::_1, &m_msg->m_peerAddr));
#else
    NeighborList::List::iterator iter = find_if(neighbors.begin(), neighbors.end(), bind2nd(mem_fun(&Neighbors::Neighbor::IsFrom), &m_msg->m_peerAddr));
#endif
    if (iter != neighbors.end()) {
        if (request.HasOptionalField(H225_ServiceControlResponse::e_result)) {
            if (request.m_result.GetTag() == H225_ServiceControlResponse_result::e_started) {
                (*iter)->SetDisabled(false);

                if (request.HasOptionalField(H225_ServiceControlResponse::e_featureSet)) {
                    H460_FeatureSet fs = H460_FeatureSet(request.m_featureSet);
                    if (fs.HasFeature(18) && Toolkit::Instance()->IsH46018Enabled()) {
                        for (PINDEX i = 0; i < request.m_genericData.GetSize(); i++) {
                            H460_FeatureStd & feat = (H460_FeatureStd &)request.m_genericData[i];
                            if (feat.Contains(H460_FeatureID(2))) {
                                PASN_OctetString rawKeepAlive = feat.Value(H460_FeatureID(2));
                                H46018_LRQKeepAliveData lrqKeepAlive;
                                PPER_Stream raw(rawKeepAlive);
                                if (lrqKeepAlive.Decode(raw)) {
                                    (*iter)->SetH46018GkKeepAliveInterval(lrqKeepAlive.m_lrqKeepAliveInterval);
                                } else {
                                    PTRACE(1, "Error decoding LRQKeepAlive");
                                    SNMP_TRAP(9, SNMPError, Network, "Error decoding LRQKeepAlive");
                                }
                            }
                        }
                    }
                }
            } else if (request.m_result.GetTag() == H225_ServiceControlResponse_result::e_failed) {
                (*iter)->SetDisabled(true);
            }
        }
    }
#endif
	// do nothing
	return false;
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
