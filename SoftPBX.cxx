//////////////////////////////////////////////////////////////////
//
// SoftPBX.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// initial author: Jan Willamowius
//
//////////////////////////////////////////////////////////////////


#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4800 ) // one performance warning off
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#endif

#include <ptlib.h>
#include <ptlib/sockets.h>
#include "gk_const.h"
#include "h323util.h"
#include "h225.h"
#include "h323pdu.h"
#include "RasTbl.h"
#include "Toolkit.h"
#include "SoftPBX.h"

static int RequestNum = 1;	// this is the only place we are _generating_ sequence numbers at the moment

namespace {  // anonymous namespace

bool SendRasPDU(H225_RasMessage &ras_msg, const H225_TransportAddress & dest)
{
	if (dest.GetTag() != H225_TransportAddress::e_ipAddress) {
		PTRACE(3, "No IP address to send!" );
		return false;
	}

	PBYTEArray wtbuf(4096);
	PPER_Stream wtstrm(wtbuf);
	ras_msg.Encode(wtstrm);
	wtstrm.CompleteEncoding();

	const H225_TransportAddress_ipAddress & RasIpAddress = dest;
	PIPSocket::Address ipaddress(RasIpAddress.m_ip[0], RasIpAddress.m_ip[1], RasIpAddress.m_ip[2], RasIpAddress.m_ip[3]);

	PTRACE(2, "GK\tSend to " << ipaddress << " [" << RasIpAddress.m_port << "] : " << ras_msg.GetTagName());
	PTRACE(3, "GK\t" << endl << setprecision(2) << ras_msg);
	PUDPSocket Socket;
	return Socket.WriteTo(wtstrm.GetPointer(), wtstrm.GetSize(), ipaddress, RasIpAddress.m_port);
}

bool SendDRQ(const endptr &ep, CallRec *Call)
{
	if (!ep) {
		PTRACE(2, "GK\tSoftPBX: Can't find endpoint registration");
		return false;
	}
	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_disengageRequest);
	H225_DisengageRequest & drq = ras_msg;
	drq.m_requestSeqNum.SetValue(RequestNum++);
	drq.m_endpointIdentifier = ep->GetEndpointIdentifier();
	drq.m_disengageReason.SetTag(H225_DisengageReason::e_forcedDrop);

	if (Call != NULL) {
		drq.m_callIdentifier = Call->m_callIdentifier;
		drq.m_conferenceID = Call->m_conferenceIdentifier;
	}
	return SendRasPDU(ras_msg, ep->GetRasAddress());
}

bool SendDRQ(const endptr &ep)
{
	// find callId and conferenceId
	CallRec * Call = (CallRec *)CallTable::Instance()->FindBySignalAdr(ep->GetCallSignalAddress());
	return SendDRQ(ep, Call);
}

} // end of anonymous namespace

void SoftPBX::PrintAllRegistrations(GkStatus::Client &client, BOOL verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintAllRegistrations");
	RegistrationTable::Instance()->PrintAllRegistrations(client, verbose);
}

void SoftPBX::PrintCurrentCalls(GkStatus::Client &client, BOOL verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintCurrentCalls");
	CallTable::Instance()->PrintCurrentCalls(client, verbose);
}

// send URQ to the specify endpoint
void SoftPBX::UnregisterEndpoint(const endptr &endpoints)
{
	if (!endpoints) {
		PTRACE(2, "GK\tSoftPBX Warning: unregister null pointer!");
		return;
	}
	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_unregistrationRequest);
	H225_UnregistrationRequest & urq = ras_msg;
	urq.m_requestSeqNum.SetValue(RequestNum++);
	urq.IncludeOptionalField(urq.e_gatekeeperIdentifier);
	urq.m_gatekeeperIdentifier.SetValue( Toolkit::GKName() );
	urq.IncludeOptionalField(urq.e_endpointIdentifier);
	urq.m_endpointIdentifier = endpoints->GetEndpointIdentifier();
	urq.m_callSignalAddress.SetSize(1);
	urq.m_callSignalAddress[0] = endpoints->GetCallSignalAddress();

	SendRasPDU(ras_msg, endpoints->GetRasAddress());
}

// send URQ to all endpoints
void SoftPBX::UnregisterAllEndpoints()
{
	RegistrationTable::Instance()->ClearTable();
}

void SoftPBX::UnregisterAlias(PString Alias)
{
	H225_AliasAddress EpAlias;	// alias of endpoint to be disconnected
	H323SetAliasAddress(Alias, EpAlias);
	PTRACE(3, "GK\tSoftPBX: Unregister " << EpAlias);

	const endptr ep = RegistrationTable::Instance()->FindByAlias(EpAlias);
	SoftPBX::UnregisterEndpoint(ep);

	// remove the endpoint (even if we don't get a UCF - the endoint might be dead)
	RegistrationTable::Instance()->RemoveByEndpointId(ep->GetEndpointIdentifier());

	PString msg("Endpoint " + Alias + " disconnected.\n");
	PTRACE(2, "GK\tSoftPBX: endpoint " << Alias << " disconnected.");
	GkStatus::Instance()->SignalStatus(msg);
}

// send a DRQ to this endpoint
void SoftPBX::DisconnectIp(PString Ip)
{
        PIPSocket::Address ipaddress;
        PINDEX p=Ip.Find(':');
        PIPSocket::GetHostAddress(Ip.Left(p), ipaddress);
	WORD port = (p!=P_MAX_INDEX) ? Ip.Mid(p+1).AsUnsigned() :
		GkConfig()->GetInteger("EndpointSignalPort", GK_DEF_ENDPOINT_SIGNAL_PORT);
	H225_TransportAddress callSignalAddress = SocketToH225TransportAddr(ipaddress, port);

	PTRACE(3, "GK\tSoftPBX: DisconnectIp " << ipaddress << ':' << port);

	SendDRQ( RegistrationTable::Instance()->FindBySignalAdr(callSignalAddress) );
}

// send a DRQ to this endpoint
void SoftPBX::DisconnectAlias(PString Alias)
{
	H225_AliasAddress EpAlias;	// alias of endpoint to be disconnected
	H323SetAliasAddress(Alias, EpAlias);
	PTRACE(3, "GK\tSoftPBX: DisconnectAlias " << EpAlias);

	SendDRQ( RegistrationTable::Instance()->FindByAlias(EpAlias) );
}

// send a DRQ to this endpoint
void SoftPBX::DisconnectEndpoint(PString Id)
{
	H225_EndpointIdentifier EpId;	// id of endpoint to be disconnected
	EpId = Id;
	PTRACE(3, "GK\tSoftPBX: DisconnectEndpoint " << EpId);

        SendDRQ( RegistrationTable::Instance()->FindByEndpointId(EpId) );
}

// send a DRQ to caller of this call number, causing it to close the H.225 channel
// this causes the gatekeeper to close the H.225 channel to the called party when
// it recognises the caller has gone away
void SoftPBX::DisconnectCall(PINDEX CallNumber)
{
	PTRACE(3, "GK\tSoftPBX: DisconnectCall " << CallNumber);

	CallRec * Call = (CallRec *)CallTable::Instance()->FindCallRec(CallNumber);
	if (Call == NULL)
	{
		PString msg(PString::Printf, "Can't find call number %d .\n", CallNumber);
		PTRACE(2, "GK\tSoftPBX: " << msg);
		GkStatus::Instance()->SignalStatus(msg);
		return;
	};

	EndpointCallRec * callep = Call->Calling;
	if (callep == NULL)
	{
		PTRACE(3, "GK\tSoftPBX: Call number " << CallNumber << " has no calling party");
		callep = Call->Called;
	};
	if (callep == NULL)
	{
		PTRACE(3, "GK\tSoftPBX: Call number " << CallNumber << " has no called party");
		return;
	};

	endptr ep = RegistrationTable::Instance()->FindBySignalAdr(callep->m_callSignalAddress);
	if (!ep) {
		PTRACE(2, "GK\tSoftPBX: Calling endpoint is already deregistered");
		callep = Call->Called;
		ep = RegistrationTable::Instance()->FindBySignalAdr(callep->m_callSignalAddress);
		if (!ep) {
			PTRACE(2, "GK\tSoftPBX: All endpoints of call number " << CallNumber << " are already deregistered");
			return;
		}
	}

        SendDRQ( ep, Call );

	PString msg(PString::Printf, "Call number %d disconnected.\n", CallNumber);
	PTRACE(2, "GK\tSoftPBX: " << msg);
	GkStatus::Instance()->SignalStatus(msg);
}

void SoftPBX::TransferCall(PString SourceAlias, PString DestinationAlias)
{
	PTRACE(1, "GK\tSoftPBX: TransferCall " << SourceAlias << " -> " << DestinationAlias);
	PTRACE(1, "GK\tSoftPBX: TransferCall not implemented, yet");
}

void SoftPBX::MakeCall(PString SourceAlias, PString DestinationAlias)
{
	PTRACE(1, "GK\tSoftPBX: MakeCall " << SourceAlias << " -> " << DestinationAlias);
	PTRACE(1, "GK\tSoftPBX: MakeCall not implemented, yet");
}

