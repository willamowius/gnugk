// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2002 Nils Bokermann <Nils.Bokermann@mediaWays.net>
//
// PURPOSE OF THIS FILE: This Class will listen for incoming packets and let another
// new started thread analyze and answer the PDU
//
// - Automatic Version Information via RCS:
//   $Id$
//   $Source$
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//

#include "RasListener.h"
#include "Toolkit.h"
#include "ProxyThread.h"
#include "h323util.h"
#include "SoftPBX.h"
#include "GkClient.h"
#include "ANSI.h"
#include "gk_const.h"
#include "Neighbor.h"

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = RASLISTENER_H;
#endif /* lint */

GK_RASListener::GK_RASListener(PIPSocket::Address Home) :
	PThread(10000, NoAutoDeleteThread), m_routedSignaling(FALSE), m_routedH245(FALSE)
{
	GKHome=Home;
	m_gkauthenticator_mutex.Wait();
	m_gkauthenticator = new GkAuthenticatorList(GkConfig());
	m_gkauthenticator_mutex.Signal();

}

GK_RASListener::~GK_RASListener()
{
	m_gkauthenticator_mutex.Wait();
	delete m_gkauthenticator;
	m_gkauthenticator = NULL;
	m_gkauthenticator_mutex.Signal();

}

// void
// GK_RASListener::Main(void)
// {
// 	PAssertAlways("No, you must not call GK_RASListener without overloading Main()");
// }

void
GK_RASListener::SetRoutedMode(BOOL routedSignaling, BOOL routedH245)
{
	m_routedSignaling = routedSignaling;
	m_routedH245 = routedH245;
	Toolkit::Instance()->GetHandlerList().LoadConfig();
	GKCallSigPort = Toolkit::Instance()->GetHandlerList().GetCallSignalPort();
}

void
GK_RASListener::SetRoutedMode()
{
	PString gkrouted(GkConfig()->GetString(RoutedSec, "GKRouted", ""));
	PString h245routed(GkConfig()->GetString(RoutedSec, "H245Routed", ""));
	SetRoutedMode(
		(!gkrouted) ? Toolkit::AsBool(gkrouted) : m_routedSignaling,
		(!h245routed) ? Toolkit::AsBool(h245routed) : m_routedH245
       );
}

void
GK_RASListener::LoadConfig()
{
	PTRACE(1, "What Config?");
}

H225_ArrayOf_AlternateGK
GK_RASListener::GetAlternativeGK() {
	H225_ArrayOf_AlternateGK null;
	return null;
}

BOOL
GK_RASListener::AcceptUnregisteredCalls(PIPSocket::Address ip, bool & fromParent) const
{
       fromParent = (Toolkit::Instance()->GkClientIsRegistered() && Toolkit::Instance()->GetGkClient().CheckGKIP(ip));
       return Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AcceptUnregisteredCalls", "0"))
	       || ( Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AcceptNeighborsCalls", "1")) ?
		    (fromParent || Toolkit::Instance()->GetNeighbor().CheckIP(ip)) : FALSE);
}

const H225_TransportAddress GK_RASListener::GetRasAddress(PIPSocket::Address peerAddr) const
{
	GKHome_mutex.Wait();
	PIPSocket::Address localAddr((GKHome == INADDR_ANY) ? Toolkit::Instance()->GetRouteTable()->GetLocalAddress(peerAddr) : GKHome);
	GKHome_mutex.Signal();
	return SocketToH225TransportAddr(localAddr, GKRasPort);
}

const H225_TransportAddress GK_RASListener::GetCallSignalAddress(PIPSocket::Address peerAddr) const
{
	GKHome_mutex.Wait();
	PIPSocket::Address localAddr((GKHome == INADDR_ANY) ? Toolkit::Instance()->GetRouteTable()->GetLocalAddress(peerAddr) : GKHome);
	GKHome_mutex.Signal();
	PTRACE(5, "GetCallSignalAddress: " << localAddr << ":" << GKCallSigPort);
	return SocketToH225TransportAddr(localAddr, GKCallSigPort);
}

void
GK_RASListener::SendTo(PPER_Stream &buffer, const unsigned int &length, const PIPSocket::Address &rx_addr, const WORD &rx_port)
{
	PTRACE(5, "SendTo" << rx_addr << ":" << rx_port);
	alternate_mutex.Wait();
	if(!alternate.WriteTo(buffer.GetPointer(), length, rx_addr, rx_port))
		PTRACE(4, "RASListener: Write error: " << alternate.GetErrorText());
	else
		PTRACE(4, "RASListener: Sent Successful");
	alternate_mutex.Signal();
}

void
GK_RASListener::SendTo(const H225_RasMessage &msg, const PIPSocket::Address &rx_addr, const WORD &rx_port)
{
	PBYTEArray buffer(4096);
	PPER_Stream writestream(buffer);

	PTRACE(5, "SendTo");
	msg.Encode(writestream);
	writestream.CompleteEncoding();
	SendTo(writestream, writestream.GetSize(), rx_addr, rx_port);
}

void
GK_RASListener::ForwardRasMsg(H225_RasMessage &msg)
{
	PString param = GkConfig()->GetString("SendTo","");
	if (!param) {
		PTRACE(5, ANSI::BLU << "Forwarding: yes! " << ANSI::OFF);

		// include the "this is a forwared message" tag (could be a static variable to increase performance)
		H225_NonStandardParameter nonStandardParam;
		H225_NonStandardIdentifier &id = nonStandardParam.m_nonStandardIdentifier;
		id.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
		H225_H221NonStandard & h221 = id;
		h221.m_t35CountryCode   = Toolkit::t35cOpenOrg;
		h221.m_t35Extension     = Toolkit::t35eFailoverRAS;
		h221.m_manufacturerCode = Toolkit::t35mOpenOrg;
		nonStandardParam.m_data.SetSize(0);

		switch(msg.GetTag()) {
		case H225_RasMessage::e_registrationRequest: {
			H225_RegistrationRequest &o = msg;
			o.IncludeOptionalField(H225_RegistrationRequest::e_nonStandardData);
			o.m_nonStandardData = nonStandardParam;
			break;
		}
		case H225_RasMessage::e_unregistrationRequest: {
			H225_UnregistrationRequest &o = msg;
			o.IncludeOptionalField(H225_UnregistrationRequest::e_nonStandardData);
			o.m_nonStandardData = nonStandardParam;
			break;
		}
		default:
			PTRACE(2,"Warning: unsupported RAS message type for forwarding; field 'forwarded' not included in msg.");
		}

		// send to all
		const PStringArray &svrs = param.Tokenise(" ,;\t", FALSE);
		for(PINDEX i=0; i<svrs.GetSize(); i++) {
			const PString &svr = svrs[i];
			const PStringArray &tokens = svr.Tokenise(":", FALSE);
			if(tokens.GetSize() != 2) {
				PTRACE(1,"GK\tFormat error in Sendto");
				continue;
			}
			PTRACE(4, ANSI::BLU << "Forwarding RRQ to "
				   << ( (PIPSocket::Address)tokens[0] )
				   << ":" << ( (unsigned)(tokens[1].AsUnsigned()) ) << ANSI::OFF);
			PBYTEArray buffer(4096);
			PPER_Stream writestream(buffer);

			msg.Encode(writestream);
			writestream.CompleteEncoding();
			SendForward(writestream, writestream.GetSize(), (PIPSocket::Address)tokens[0],
					  (unsigned)(tokens[1].AsUnsigned()));
		}
	}

	return;
}


void
GK_RASListener::SendForward(PPER_Stream &buffer, const unsigned int &length, const PIPSocket::Address &rx_addr, const WORD &rx_port)
{
	alternate_mutex.Wait();
	if(!alternate.WriteTo(buffer.GetPointer(), length, rx_addr, rx_port))
		PTRACE(4, "RASListener: Forward error: " << alternate.GetErrorText());
	else
		PTRACE(4, "RASListener: Forwarded Successful");
	alternate_mutex.Signal();
}

BOOL
GK_RASListener::AcceptNBCalls()
{
	return Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "AcceptNeighborsCalls", "1"));
}

GkAuthenticatorList &
GK_RASListener::GetAuthenticator()
{
	PWaitAndSignal lock(m_gkauthenticator_mutex);
	if (NULL == m_gkauthenticator)
		m_gkauthenticator = new GkAuthenticatorList(GkConfig());
	return *m_gkauthenticator;
}

// Class H323RasListener (was part of RasSrv)
H323RasListener::H323RasListener(PIPSocket::Address address) : GK_RASListener(address)
{
	LoadConfig();
	PTRACE(1, "Starting RasListener");
	Resume();
	// GkClient()?
}

H323RasListener::~H323RasListener()
{
	// Release all Calls
	Close();
	UnregisterAllEndpoints();
}

void
H323RasListener::LoadConfig()
{
	GKRasPort = GkConfig()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT);
}

void
H323RasListener::Main()
{
	listener_mutex.Wait();
	GKHome_mutex.Wait();
	listener.Listen(GKHome, 0, GKRasPort, PSocket::CanReuseAddress);
	GKHome_mutex.Signal();
	listener_mutex.Signal();
	listener_mutex.Wait();
	while (listener.IsOpen()) {
		listener_mutex.Signal();
		const int buffersize = 4096;
		BYTE buffer[buffersize];
		WORD rx_port;
		PIPSocket::Address rx_addr;
		rx_port=0;
		listener_mutex.Wait();
		int result=listener.ReadFrom(buffer, buffersize,  rx_addr, rx_port);
		if(result!=0) {
			listener_mutex.Signal();
			PPER_Stream stream(buffer, listener.GetLastReadCount());
			// RasWorker will delete itself.
			new H323RasWorker(stream, rx_addr, rx_port, *this);
		} else {
			PTRACE(1, "RAS LISTENER: Read Error on : " << rx_addr << ":" << rx_port);
		}
		listener_mutex.Wait();// before new truth value for while clause is computed
	}
	listener_mutex.Signal();
}

void
H323RasListener::UnregisterAllEndpoints()
{
	SoftPBX::UnregisterAllEndpoints();
}

void
H323RasListener::Close()
{
	PTRACE(2, "GK\tClosing RasListener");

	// disconnect all calls
	CallTable::Instance()->ClearTable();

	if (Toolkit::Instance()->GkClientIsRegistered())
		Toolkit::Instance()->GetGkClient().SendURQ();

	if(!listener_mutex.WillBlock())
		listener_mutex.Wait();
	listener.Close();

	PTRACE(1, "GK\tRasSrv closed");
}
