/*
 * sigmsg.cxx
 *
 * Structures to hold and process signaling messages
 *
 * Copyright (c) 2005, Michal Zygmuntowicz
 * Copyright (c) 2005-2010, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include <ptlib.h>
#include <ptlib/sockets.h>
#include <q931.h>
#include <h225.h>
#include "sigmsg.h"


SignalingMsg::SignalingMsg(
	Q931 *q931pdu, /// this pointer is not cloned and deleted by this class destructor
	H225_H323_UserInformation *uuie, /// decoded User-User IE
	const PIPSocket::Address &localAddr, /// an address the message has been received on
	WORD localPort, /// a port number the message has been received on
	const PIPSocket::Address &peerAddr, /// an address the message has been received from
	WORD peerPort /// a port number the message has been received from
	) : m_q931(q931pdu), m_uuie(uuie), m_localAddr(localAddr), m_localPort(localPort),
	m_peerAddr(peerAddr), m_peerPort(peerPort), m_changed(false), m_uuieChanged(false)
{
	PAssertNULL(q931pdu);
}

SignalingMsg::~SignalingMsg()
{
	delete m_uuie;
	delete m_q931;
}

SignalingMsg* SignalingMsg::Clone()
{
	return new SignalingMsg(new Q931(*m_q931), 
		(H225_H323_UserInformation*)(m_uuie->Clone()),
		m_localAddr, m_localPort, m_peerAddr, m_peerPort
		);
}

unsigned SignalingMsg::GetTag() const
{ 
	return m_q931->GetMessageType();
}

PString SignalingMsg::GetTagName() const
{
	return m_q931->GetMessageTypeName();
}

unsigned SignalingMsg::GetCallReference() const
{ 
	return m_q931->GetCallReference();
}


void SignalingMsg::GetLocalAddr(
	PIPSocket::Address &addr,
	WORD &port
	) const
{
	addr = m_localAddr;
	port = m_localPort;
}

void SignalingMsg::GetLocalAddr(
	PIPSocket::Address &addr
	) const
{
	addr = m_localAddr;
}

void SignalingMsg::GetPeerAddr(
	PIPSocket::Address &addr,
	WORD &port
	) const
{
	addr = m_peerAddr;
	port = m_peerPort;
}

void SignalingMsg::GetPeerAddr(
	PIPSocket::Address &addr
	) const
{
	addr = m_peerAddr;
}

bool SignalingMsg::Encode(PBYTEArray &buffer)
{
	if (m_uuie != NULL && m_uuieChanged) {
		PPER_Stream strm;
		m_uuie->Encode(strm);
		strm.CompleteEncoding();
		m_q931->SetIE(Q931::UserUserIE, strm);
	}
	return m_q931->Encode(buffer);
}

bool SignalingMsg::Decode(const PBYTEArray & buffer)
{
	return m_q931->Decode(buffer);
}

SignalingMsg* SignalingMsg::Create(
	Q931 *q931pdu, /// this pointer is not cloned and deleted by this class destructor
	H225_H323_UserInformation *uuie, /// decoded User-User IE
	const PIPSocket::Address &localAddr, /// an address the message has been received on
	WORD localPort, /// a port number the message has been received on
	const PIPSocket::Address &peerAddr, /// an address the message has been received from
	WORD peerPort /// a port number the message has been received from
	)
{
	if (q931pdu == NULL)
		return NULL;
		
	if (uuie != NULL) {
		H225_H323_UU_PDU_h323_message_body &body = uuie->m_h323_uu_pdu.m_h323_message_body;
		switch (body.GetTag()) {
		case H225_H323_UU_PDU_h323_message_body::e_setup:
			return new SetupMsg(q931pdu, uuie, (H225_Setup_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
		case H225_H323_UU_PDU_h323_message_body::e_callProceeding:
			return new CallProceedingMsg(q931pdu, uuie, (H225_CallProceeding_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
		case H225_H323_UU_PDU_h323_message_body::e_connect:
			return new ConnectMsg(q931pdu, uuie, (H225_Connect_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
		case H225_H323_UU_PDU_h323_message_body::e_alerting:
			return new AlertingMsg(q931pdu, uuie, (H225_Alerting_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
		case H225_H323_UU_PDU_h323_message_body::e_information:
			return new InformationMsg(q931pdu, uuie, (H225_Information_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
		case H225_H323_UU_PDU_h323_message_body::e_releaseComplete:
			return new ReleaseCompleteMsg(q931pdu, uuie, (H225_ReleaseComplete_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
		case H225_H323_UU_PDU_h323_message_body::e_facility:
			return new FacilityMsg(q931pdu, uuie, (H225_Facility_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
		case H225_H323_UU_PDU_h323_message_body::e_progress:
			return new ProgressMsg(q931pdu, uuie, (H225_Progress_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
//		case H225_H323_UU_PDU_h323_message_body::e_status:
//			return new StatusMsg(q931pdu, uuie, (H225_Status_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
//		case H225_H323_UU_PDU_h323_message_body::e_statusInquiry:
//			return new StatusInquiryMsg(q931pdu, uuie, (H225_StatusInquiry_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
//		case H225_H323_UU_PDU_h323_message_body::e_notify:
//			return new NotifyMsg(q931pdu, uuie, (H225_Notify_UUIE&)body, localAddr, localPort, peerAddr, peerPort);
		}
	}
	
	return new SignalingMsg(q931pdu, uuie, localAddr, localPort, peerAddr, peerPort);
}
