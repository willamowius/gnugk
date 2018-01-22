/*
 * sigmsg.h
 *
 * Structures to hold and process signaling messages
 *
 * Copyright (c) 2005, Michal Zygmuntowicz
 * Copyright (c) 2005-2018, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#ifndef SIGMSG_H
#define SIGMSG_H "@(#) $Id$"

#include <ptlib/sockets.h>
#include "q931.h"

class H225_H323_UserInformation;
class H225_Setup_UUIE;
class H225_SetupAck_UUIE;
class H225_CallProceeding_UUIE;
class H225_Alerting_UUIE;
class H225_Connect_UUIE;
class H225_Progress_UUIE;
class H225_Facility_UUIE;
class H225_ReleaseComplete_UUIE;
class H225_Information_UUIE;
class H225_Notify_UUIE;
class H225_Status_UUIE;
class H225_StatusInquiry_UUIE;

/// Base class to hold generic information associated with a signaling message
class SignalingMsg {
public:
	virtual ~SignalingMsg();

	/// @return	a cloned object of this or a derived class
	virtual SignalingMsg* Clone();

	/// @return	signaling message type (#Q931::MsgTypes enum#)
	unsigned GetTag() const;

	/// @return	signaling message type as a string
	PString GetTagName() const;

	/// @return	CRV associated with the signaling message
	unsigned GetCallReference() const;

	/// @return	a reference to the Q.931 message stored
	Q931 & GetQ931() const { return *m_q931; }

	/// @return a pointer to the User-User IE, NULL if not present
	H225_H323_UserInformation* GetUUIE() { return m_uuie; }

	/// Get an address the message has been received on
	void GetLocalAddr(PIPSocket::Address & addr, WORD & port) const;
	void GetLocalAddr(PIPSocket::Address & addr) const;

	/// Get an address the message has been received from
	void GetPeerAddr(PIPSocket::Address & addr, WORD & port) const;
	void GetPeerAddr(PIPSocket::Address & addr) const;

	/// Set a flag to indicate that the Q.931 message has been modified
	void SetChanged() { m_changed = true; }

	/** Set a flag to indicate that the decoded H.225 UserInformation element
	    has been modified and the corresponding Q.931 IE should be recreated.
	*/
	void SetUUIEChanged() { m_changed = m_uuieChanged = true; }

	/// @return	true if the Q.931 message has been modified
	bool IsChanged() const { return m_changed; }

	/** Encode the Q.931 message back into a binary form.

	    @return
	    True if the message has been encoded successfully.
	*/
	bool Encode(
		PBYTEArray & buffer /// buffer to hold the encoded message
		);
	bool Decode(
		const PBYTEArray & buffer /// buffer holding the encoded message
		);

	/// factory constructor for signaling messages
	static SignalingMsg* Create(
		Q931 * q931pdu, /// this pointer is not cloned and deleted by this class destructor
		H225_H323_UserInformation * uuie, /// decoded User-User IE
		const PIPSocket::Address & localAddr, /// an address the message has been received on
		WORD localPort, /// a port number the message has been received on
		const PIPSocket::Address & peerAddr, /// an address the message has been received from
		WORD peerPort /// a port number the message has been received from
		);

protected:
	SignalingMsg(
		Q931 * q931pdu, /// this pointer is not cloned and deleted by this class destructor
		H225_H323_UserInformation * uuie, /// decoded User-User IE
		const PIPSocket::Address & localAddr, /// an address the message has been received on
		WORD localPort, /// a port number the message has been received on
		const PIPSocket::Address & peerAddr, /// an address the message has been received from
		WORD peerPort /// a port number the message has been received from
		);

private:
	SignalingMsg();
	SignalingMsg(const SignalingMsg &);
public:
	SignalingMsg& operator=(const SignalingMsg &);

protected:
	Q931 * m_q931; /// whole Q.931 message
	H225_H323_UserInformation * m_uuie; /// User-User IE element of the Q.931 msg
	PIPSocket::Address m_localAddr; /// local IP address the msg arrived to
	WORD m_localPort; /// local port number the msg arrived to
	PIPSocket::Address m_peerAddr; /// remote IP address the msg arrived from
	WORD m_peerPort; /// remote port number the msg arrived from
	bool m_changed; /// indicate changes to the Q.931 message
	bool m_uuieChanged; /// indicate changes to the H.225 User Information element
};

/// Specialized template for a particular H.225.0 signaling message
template<class UUIE>
class H225SignalingMsg : public SignalingMsg {
public:
	/// Build a new SignalingMsg
	H225SignalingMsg(
		Q931 * q931pdu, /// this pointer is not cloned and deleted by this class destructor
		H225_H323_UserInformation * uuie, /// decoded User-User IE
		UUIE & /*uuieBody*/, /// decoded UUIE body
		const PIPSocket::Address & localAddr, /// an address the message has been received on
		WORD localPort, /// a port number the message has been received on
		const PIPSocket::Address & peerAddr, /// an address the message has been received from
		WORD peerPort /// a port number the message has been received from
		) : SignalingMsg(q931pdu, uuie, localAddr, localPort, peerAddr, peerPort),
			m_uuieBody(uuie->m_h323_uu_pdu.m_h323_message_body) { }

	UUIE & GetUUIEBody() const { return m_uuieBody; }

	virtual SignalingMsg * Clone()
	{
		H225_H323_UserInformation *uuieClone = (H225_H323_UserInformation*)(m_uuie->Clone());
		return new H225SignalingMsg<UUIE>(new Q931(*m_q931), uuieClone,
			(UUIE&)(uuieClone->m_h323_uu_pdu.m_h323_message_body),
			m_localAddr, m_localPort, m_peerAddr, m_peerPort);
	}

private:
	H225SignalingMsg();
	H225SignalingMsg(const H225SignalingMsg &);
	H225SignalingMsg& operator=(const H225SignalingMsg &);

protected:
	UUIE & m_uuieBody; /// H.225.0 UUIE structure associated with the message
};

typedef H225SignalingMsg<H225_Setup_UUIE> SetupMsg;
typedef H225SignalingMsg<H225_Alerting_UUIE> AlertingMsg;
typedef H225SignalingMsg<H225_CallProceeding_UUIE> CallProceedingMsg;
typedef H225SignalingMsg<H225_Connect_UUIE> ConnectMsg;
typedef H225SignalingMsg<H225_Progress_UUIE> ProgressMsg;
typedef H225SignalingMsg<H225_ReleaseComplete_UUIE> ReleaseCompleteMsg;
typedef H225SignalingMsg<H225_Information_UUIE> InformationMsg;
typedef H225SignalingMsg<H225_Facility_UUIE> FacilityMsg;
//typedef H225SignalingMsg<H225_Notify_UUIE> NotifyMsg;
typedef H225SignalingMsg<H225_Status_UUIE> StatusMsg;
//typedef H225SignalingMsg<H225_StatusInquiry_UUIE> StatusInquiryMsg;

#endif // SIGMSG_H
