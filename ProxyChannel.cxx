//////////////////////////////////////////////////////////////////
//
// ProxyChannel.cxx
//
// Copyright (c) Citron Network Inc. 2001-2002
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 12/19/2001
//
//////////////////////////////////////////////////////////////////

#include "ANSI.h"
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "ProxyChannel.h"
#include <q931.h>
#include <h245.h>

const char *RoutedSec = "RoutedMode";

// to avoid ProxyThread.cxx to include the large h225.h,
// put the method here...
ProxySocket *ProxyListener::CreateSocket()
{
	return new CallSignalSocket;
}

CallSignalSocket::CallSignalSocket() : m_h245handler(0), h245socket(0)
{
	localAddr = peerAddr = INADDR_ANY;
}

CallSignalSocket::CallSignalSocket(WORD port, CallSignalSocket *socket)
      : ProxySocket(port, socket), h245socket(0)
{
	m_call = socket->m_call;
	m_crv = (socket->m_crv & 0x7fffu);
	socket->GetLocalAddress(localAddr);
	socket->GetPeerAddress(peerAddr, peerPort);
	m_h245handler = (socket->m_h245handler) ? new H245Handler(localAddr, false) : 0;
	m_call->SetSocket(socket, this);
}

CallSignalSocket::~CallSignalSocket()
{
	delete m_h245handler;
	if (h245socket)
		h245socket->CloseConnection();
	if (m_call)
		CallTable::Instance()->RemoveCall(m_call);
}

ProxySocket *CallSignalSocket::ConnectTo()
{
	if (remote->Connect(peerAddr)) {
		PTRACE(3, "CallSig(" << getpid() << ") Connect to " << peerAddr << " successful");
		SetConnected(true);
		remote->SetConnected(true);
		ForwardData();
	} else {
		PTRACE(3, "CallSig\t" << peerAddr << " DIDN'T ACCEPT THE CALL");
		CloseConnection();
		delete remote; // would close myself
		// remote = 0; // already detached
	}
	return remote;
}

void CallSignalSocket::BuildReleasePDU(Q931 & ReleasePDU) const
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
	H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_releaseComplete);
	H225_ReleaseComplete_UUIE & uuie = body;
	uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_callIdentifier);
	uuie.m_callIdentifier = m_call->GetCallIdentifier();
	PPER_Stream sb;
	signal.Encode(sb);
	sb.CompleteEncoding();

	ReleasePDU.BuildReleaseComplete(m_crv, m_crv & 0x8000u);
	ReleasePDU.SetIE(Q931::UserUserIE, sb);
}

bool CallSignalSocket::CloseConnection()
{
	if (m_call) {
		Q931 ReleasePDU;
		BuildReleasePDU(ReleasePDU);
		ReleasePDU.Encode(buffer);
		TransmitData();
		PTRACE(4, "GK\tSend Release Complete to " << Name());
//		PTRACE(5, "GK\tRelease Complete: " << ReleasePDU);
	}
	return ProxySocket::CloseConnection();
}

ProxySocket::Result CallSignalSocket::ReceiveData()
{
	if (!ReadTPKT())
		return NoData;

	Q931 q931pdu;
	q931pdu.Decode(buffer);

	PTRACE(3, "Q931\t" << Name() << " Message type : " << q931pdu.GetMessageTypeName());
	PTRACE(4, "Q931\t" << Name() << " Call reference : " << q931pdu.GetCallReference());
	PTRACE(4, "Q931\t" << Name() << " From destination " << q931pdu.IsFromDestination());
	PTRACE(6, ANSI::BYEL << "\nQ931: " << setprecision(2) << q931pdu << ANSI::OFF);

	if (q931pdu.HasIE(Q931::UserUserIE)) {
		H225_H323_UserInformation signal;
		PPER_Stream q = q931pdu.GetIE(Q931::UserUserIE);
		if (!signal.Decode(q)) {
			PTRACE(4, "Q931\t" << Name() << " ERROR DECODING UUIE!");
			return Error;
		}

		H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
		H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;

		PTRACE(5, "\nH225_H323_UU_PDU: " << setprecision(2) << pdu);

		switch (body.GetTag())
		{
		case H225_H323_UU_PDU_h323_message_body::e_setup:
			m_crv = (q931pdu.GetCallReference() | 0x8000u);
			OnSetup(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_callProceeding:
			OnCallProceeding(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_connect:
			OnConnect(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_alerting:
			OnAlerting(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_information:
			OnInformation(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_releaseComplete:
			OnReleaseComplete(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_facility:
			OnFacility(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_progress:
			OnProgress(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_empty:
			OnEmpty(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_status:
			OnStatus(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_statusInquiry:
			OnStatusInquiry(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_setupAcknowledge:
			OnSetupAcknowledge(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_notify:
			OnNotify(body);
			break;
		default:
			PTRACE(4, "Q931\t" << Name() << " UNKNOWN Q.931");
			break;
		}
		
		if (pdu.HasOptionalField(H225_H323_UU_PDU::e_nonStandardControl)) {
			for (PINDEX n = 0; n < pdu.m_nonStandardControl.GetSize(); ++n)
				OnNonStandardData(pdu.m_nonStandardControl[n].m_data);
			PTRACE(5, "Q931\t" << Name() << " Rewriting nonStandardControl\n" << setprecision(2) << pdu);
		}
		if (pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control) && m_h245handler)
			OnTunneledH245(pdu);

		PPER_Stream sb;
		signal.Encode(sb);
		sb.CompleteEncoding();
		q931pdu.SetIE(Q931::UserUserIE, sb);
	} 
/*
   Note: Openh323 1.7.9 or later required.
   The older version has an out of memory bug in Q931::GetCalledPartyNumber.
*/
	if (q931pdu.HasIE(Q931::CalledPartyNumberIE)) {
		unsigned plan, type;
		PString calledNumber;
		if (q931pdu.GetCalledPartyNumber(calledNumber, &plan, &type) &&
		    Toolkit::Instance()->RewritePString(calledNumber))
			q931pdu.SetCalledPartyNumber(calledNumber, plan, type);
	}
/*
	if (q931pdu.HasIE(Q931::CalledPartyNumberIE)) {
		PBYTEArray n_array = q931pdu.GetIE(Q931::CalledPartyNumberIE);
		if (n_array.GetSize() > 0) {
			const char* n_bytes = (const char*) (n_array.GetPointer());
			PString n_string(n_bytes+1, n_array.GetSize()-1);
			if (Toolkit::Instance()->RewritePString(n_string))
				q931pdu.SetCalledPartyNumber(n_string, Q931::ISDNPlan, Q931::NationalType);
		}
	}
*/
	PTRACE(5, ANSI::BGRE << "\nQ931: " << setprecision(2) << q931pdu << ANSI::OFF);

	q931pdu.Encode(buffer);

	switch (q931pdu.GetMessageType())
	{
		case Q931::SetupMsg:
			break;
		case Q931::StatusMsg:
			// don't forward status messages mm-30.04.2001
			return NoData;
		case Q931::ReleaseCompleteMsg:
			if (m_call) {
				CallTable::Instance()->RemoveCall(m_call);
				m_call = callptr(0);
			}
			return Closing;
		default:
			return Forwarding;
	}
	
	if (!m_call) {
		PTRACE(3, "GK\t" << Name() << " Setup destination not found!");
		CloseConnection();
		return Error;
	}
	if (peerAddr == INADDR_ANY) {
		PTRACE(3, "GK\t" << Name() << " INVALID ADDRESS");
		CloseConnection();
		return Error;
	}

	return Connecting;
}

void CallSignalSocket::OnSetup(H225_Setup_UUIE & Setup)
{
	if (!Setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
		PTRACE(1, "SignalHandler\tOnSetup() no callIdentifier!");
		return;
	}
	m_call = CallTable::Instance()->FindCallRec(Setup.m_callIdentifier);
	if (!m_call) {
		PTRACE(3, "SignalHandler\tOnSetup() didn't find the call: " << AsString(Setup.m_callIdentifier.m_guid));
		return;
	}
	const H225_TransportAddress *ad = m_call->GetCalledAddress();
	if (ad || ad->GetTag() == H225_TransportAddress::e_ipAddress) {
		const H225_TransportAddress_ipAddress & ip = *ad;
		peerAddr = PIPSocket::Address(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
		peerPort = ip.m_port;
		localAddr = Toolkit::Instance()->GetRouteTable()->GetLocalAddress(peerAddr);
		if (m_call->IsH245Routed())
			m_h245handler = new H245Handler(localAddr, true);

		remote = new CallSignalSocket(peerPort, this);
	}

	// re-route called endpoint signalling messages to gatekeeper	
	Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
	Setup.m_sourceCallSignalAddress = SocketToH225TransportAddr(localAddr, GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_ROUTE_SIGNAL_PORT));

	// in routed mode the caller may have put the GK address in destCallSignalAddress
	// since it is optional, we just remove it (we could alternativly insert the real destination SignalAdr)
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress))
		Setup.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);

	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
		for (PINDEX n = 0; n < Setup.m_destinationAddress.GetSize(); ++n)
			Toolkit::Instance()->RewriteE164(Setup.m_destinationAddress[n]);

	// to compliance to MediaRing VR, we have to setup our H323ID
	PString H323ID = GkConfig()->GetString("H323ID");
	if (!H323ID) {
		PINDEX s = 0;
		if (Setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress))
			s = Setup.m_sourceAddress.GetSize();
		else
			Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
		Setup.m_sourceAddress.SetSize(s+1);
		H225_AliasAddress & alias = Setup.m_sourceAddress[s];
		alias.SetTag(H225_AliasAddress::e_h323_ID);
		(PASN_BMPString &)alias = H323ID;
	}

	InternalSetH245Address(Setup);
	
//	PTRACE(4, "GK\tSetup_UUIE:\n" << setprecision(2) << Setup);
}
 
void CallSignalSocket::OnCallProceeding(H225_CallProceeding_UUIE & CallProceeding)
{
	InternalSetH245Address(CallProceeding);
}

void CallSignalSocket::OnConnect(H225_Connect_UUIE & Connect)
{
	if (m_call) // hmm... it should not be null
		m_call->SetConnected(true);
#ifndef NDEBUG
	if (!Connect.HasOptionalField(H225_Connect_UUIE::e_callIdentifier)) {
		PTRACE(1, "SignalHandler\tOnConnect() no callIdentifier!");
	} else if (m_call->GetCallIdentifier() != Connect.m_callIdentifier) {
		PTRACE(1, "SignalHandler\tCallIdentifier not match?");
	}
#endif
	InternalSetH245Address(Connect);
}

void CallSignalSocket::OnAlerting(H225_Alerting_UUIE & Alerting)
{
	InternalSetH245Address(Alerting);
}

void CallSignalSocket::OnInformation(H225_Information_UUIE &)
{
	// do nothing
}

void CallSignalSocket::OnReleaseComplete(H225_ReleaseComplete_UUIE & ReleaseComplete)
{
	// do nothing
}

void CallSignalSocket::OnFacility(H225_Facility_UUIE & Facility)
{
	InternalSetH245Address(Facility);
}

void CallSignalSocket::OnProgress(H225_Progress_UUIE & Progress)
{
	InternalSetH245Address(Progress);
}

void CallSignalSocket::OnEmpty(H225_H323_UU_PDU_h323_message_body &)
{
	// do nothing
}

void CallSignalSocket::OnStatus(H225_Status_UUIE &)
{
	// do nothing
}

void CallSignalSocket::OnStatusInquiry(H225_StatusInquiry_UUIE &)
{
	// do nothing
}

void CallSignalSocket::OnSetupAcknowledge(H225_SetupAcknowledge_UUIE &)
{
	// do nothing
}

void CallSignalSocket::OnNotify(H225_Notify_UUIE &)
{
	// do nothing
}

void CallSignalSocket::OnNonStandardData(PASN_OctetString & octs)
{
	BOOL changed = FALSE;
	BYTE buf[5000];
	BYTE *pBuf  = buf;               // write pointer
	BYTE *pOcts = octs.GetPointer(); // read pointer
	BYTE *mOcts = pOcts + octs.GetSize();
	PString *CalledPN;
	
	while (pOcts < mOcts) {
		BYTE type  = pOcts[0];
		BYTE len   = pOcts[1];
		switch (type) { 
		case 0x70: // called party
			CalledPN = new PString( (char*) (&(pOcts[3])), len-1); 
			if(Toolkit::Instance()->RewritePString(*CalledPN)) {
				// change
				const char* s = *CalledPN;
				pBuf[0] = type;
				pBuf[1] = strlen(s)+1;
				pBuf[2] = pOcts[2];  // type of number, numbering plan id
				memcpy(&(pBuf[3]), s, strlen(s));
				pBuf += strlen(s)+3; 
				changed = TRUE;
			}
			else { 
				// leave unchanged
				memcpy(pBuf, pOcts, (len+2)*sizeof(BYTE));
				pBuf += len+2;  // incr write pointer
			}
			delete CalledPN;
			break;
		case 0x6c: // calling party
		default: // copy through
			memcpy(pBuf, pOcts, (len+2)*sizeof(BYTE));
			pBuf += len+2;  // incr write pointer
		}
		
		// increment read pointer
		pOcts += len+2;
	}
	
	// set new value if necessary
	if (changed)
		octs.SetValue(buf, pBuf-buf);
}

void CallSignalSocket::OnTunneledH245(H225_H323_UU_PDU & uu_pdu)
{
	for(PINDEX i = 0; i < uu_pdu.m_h245Control.GetSize(); ++i) {
		PPER_Stream strm = uu_pdu.m_h245Control[i].GetValue();
		Result res;
		if (HandleH245Mesg(strm, res))
			uu_pdu.m_h245Control[i].SetValue(strm);
	}
}

bool CallSignalSocket::SetH245Address(H225_TransportAddress & h245addr)
{
	CallSignalSocket *ret = dynamic_cast<CallSignalSocket *>(remote);
	if (!ret) {
		PTRACE(2, "H245\t" << Name() << " no remote party?");
		return false;
	}
	if (h245socket) {
		if (h245socket->IsConnected()) {
			PTRACE(4, "H245\t" << Name() << " H245 session already established");
			return false;
		} else {
			h245socket->SetH245Address(h245addr, localAddr);
			return true;
		}
	}
	h245socket = new H245Socket(this);
	ret->h245socket = new H245Socket(h245socket, ret);
	h245socket->SetHandler(phandler);
	h245socket->SetH245Address(h245addr, localAddr);
	phandler->ConnectTo(h245socket);
	return true;
}

H245Handler::H245Handler(PIPSocket::Address local, bool FromCaller)
      : localAddr(local), bFromCaller(FromCaller)
{
}

H245Handler::~H245Handler()
{
}

bool H245Handler::HandleMesg(PPER_Stream & mesg, ProxySocket::Result & res)
{
	res = ProxySocket::Forwarding;
	H245_MultimediaSystemControlMessage h245msg;
	h245msg.Decode(mesg);
	bool changed = false;
	switch (h245msg.GetTag())
	{
		case H245_MultimediaSystemControlMessage::e_request:
			changed = HandleRequest(h245msg);
			break;
		case H245_MultimediaSystemControlMessage::e_response:
			changed = HandleResponse(h245msg);
			break;
		case H245_MultimediaSystemControlMessage::e_command:
			changed = HandleCommand(h245msg);
			if (((H245_CommandMessage &)h245msg).GetTag() == H245_CommandMessage::e_endSessionCommand)
				res = ProxySocket::Closing;
			break;
		case H245_MultimediaSystemControlMessage::e_indication:
			changed = HandleIndication(h245msg);
			break;
		default:
			PTRACE(2, "H245\tUnknown H245 message: " << h245msg.GetTag());
			break;
	}
	if (changed) {
		h245msg.Encode(mesg);
		mesg.CompleteEncoding();
	}

	PTRACE(5, "H245\nMessage: " << setprecision(2) << h245msg);
	return changed;
}

bool H245Handler::HandleRequest(H245_RequestMessage & Request)
{
	PTRACE(4, "H245\tRequest: " << Request.GetTagName());
	switch (Request.GetTag())
	{
		case H245_RequestMessage::e_openLogicalChannel:
//			HandleOpenLogicalChannel(Request);
			break;
		default: // Nothing to do for now....
			break;
	}
	return false;
}

bool H245Handler::HandleResponse(H245_ResponseMessage & Response)
{
	PTRACE(4, "H245\tResponse: " << Response.GetTagName());
	switch (Response.GetTag())
	{
		case H245_ResponseMessage::e_openLogicalChannelAck:
			break;
		case H245_ResponseMessage::e_openLogicalChannelReject:
			break;
		default : // Nothing to do for now....
			break;
	}
	return false;
}

bool H245Handler::HandleIndication(H245_IndicationMessage & Indication)
{
	PTRACE(4, "H245\tIndication: " << Indication.GetTagName());
	return false;
}

bool H245Handler::HandleCommand(H245_CommandMessage & Command)
{
	PTRACE(4, "H245\tCommand: " << Command.GetTagName());
	return false;
}

H245Socket::H245Socket(CallSignalSocket *sig)
      : sigSocket(sig), listener(new PTCPSocket)
{
//	listener->Listen(INADDR_ANY, 1);
	listener->Listen(1);
}

H245Socket::H245Socket(H245Socket *socket, CallSignalSocket *sig)
      : ProxySocket(0, socket), sigSocket(sig), listener(0)
{
	socket->remote = this;
}

H245Socket::~H245Socket()
{
	sigSocket->DetachH245Socket();
	delete listener;
}

void H245Socket::SetH245Address(H225_TransportAddress & h245addr, Address myip)
{
	H245Socket * s = (listener) ? this : dynamic_cast<H245Socket *>(remote);
	s->peerH245Addr = h245addr;
	PIPSocket::Address h245ip;
	WORD h245port;
	s->listener->GetLocalAddress(h245ip, h245port);
	h245addr = SocketToH225TransportAddr(myip, h245port);
	PTRACE(3, "H245\t" << Name() << " Set h245Address to " << AsDotString(h245addr));
}

ProxySocket *H245Socket::ConnectTo()
{
	if (Accept(*listener)) {
		listener->Close(); // don't accept other connection
		if (peerH245Addr.GetTag() != H225_TransportAddress::e_ipAddress) {
			PTRACE(3, "H245\tINVALID ADDRESS");
			return false;
		}
		H225_TransportAddress_ipAddress & ip = peerH245Addr;
		PIPSocket::Address peerAddr(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
		remote->SetPort(ip.m_port);
		if (remote->Connect(peerAddr)) {
			PTRACE(3, "H245(" << getpid() << ") Connect to " << peerAddr << " successful");
			phandler->Insert(this);
			SetConnected(true);
			remote->SetConnected(true);
			return remote;
		}
		PTRACE(3, "H245\t" << peerAddr << " DIDN'T ACCEPT THE CALL");
	} else {
		Errors err = GetErrorCode();
		PTRACE(2, "H245\tError: " << GetErrorText(err));
	}
	delete remote;
	// remote = 0; // already detached
	// insert myself into the handler so it will be deleted anyway
	phandler->Insert(this);
	return 0;
}

bool H245Socket::CloseConnection()
{
	if (listener)
		listener->Close();
	return ProxySocket::CloseConnection();
}

ProxySocket::Result H245Socket::ReceiveData()
{
	if (!ReadTPKT())
		return NoData;

	PPER_Stream strm(buffer);
	Result res;
	if (sigSocket->HandleH245Mesg(strm, res))
		buffer = strm;
	return res;
}


// class HandlerList
void HandlerList::LoadConfig()
{
	WORD port = GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_ROUTE_SIGNAL_PORT);
	if (!listenerThread || (GKPort != port)) {
		CloseListener();
		unsigned queueSize = GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH);
		listenerThread = new ProxyListener(this, GKHome, port, queueSize);
		GKPort = listenerThread->GetPort();
	}

	// the handler number can only be increased
	int s = GkConfig()->GetInteger(RoutedSec, "CallSignalHandlerNumber", 1);
	for (int i = handlers.size(); i < s; ++i)
		handlers.push_back(new ProxyHandleThread(i));
}

