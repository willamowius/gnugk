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


void SoftPBX::PrintAllRegistrations(GkStatus::Client &client, BOOL verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintAllRegistrations");
	RegistrationTable::Instance()->PrintAllRegistrations(client, verbose);
};

void SoftPBX::PrintCurrentCalls(GkStatus::Client &client, BOOL verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintCurrentCalls");
	CallTable::Instance()->PrintCurrentCalls(client, verbose);
}

// function object used by for_each
// unregisters a single endpoint
class UnregisterEP {
  public:
	UnregisterEP(H225_RasMessage *r) : ras_msg(r) {}
	void operator()(const endpointRec &er);

  private:
	H225_RasMessage *ras_msg;
};
 
void UnregisterEP::operator()(const endpointRec & er)
{
	PUDPSocket URQSocket;

	// these values are specific for each endpoint
	H225_UnregistrationRequest & urq = *ras_msg;
	urq.m_requestSeqNum.SetValue(RequestNum++);
	urq.m_callSignalAddress.SetSize(1);
	urq.IncludeOptionalField(urq.e_endpointIdentifier);

	const H225_TransportAddress_ipAddress & RasIpAddress = er.m_rasAddress;
	PIPSocket::Address ipaddress(RasIpAddress.m_ip[0], RasIpAddress.m_ip[1], RasIpAddress.m_ip[2], RasIpAddress.m_ip[3]);
	urq.m_callSignalAddress[0] = er.m_callSignalAddress;
	urq.m_endpointIdentifier = er.m_endpointIdentifier;

	// send URQ
	PBYTEArray wtbuf(4096);
	PPER_Stream wtstrm(wtbuf);
	ras_msg->Encode(wtstrm);
	wtstrm.CompleteEncoding();
	PTRACE(2, "GK\tSend to " << ipaddress << " [" << RasIpAddress.m_port << "] : " << ras_msg->GetTagName());
	PTRACE(3, "GK\t" << endl << setprecision(2) << (*ras_msg));
	URQSocket.WriteTo(wtstrm.GetPointer(), wtstrm.GetSize(), ipaddress, RasIpAddress.m_port);
}

// send URQ to all endpoints
void SoftPBX::UnregisterAllEndpoints()
{
	H225_RasMessage ras_msg;
	
	ras_msg.SetTag(H225_RasMessage::e_unregistrationRequest);
	H225_UnregistrationRequest & urq = ras_msg;
	urq.IncludeOptionalField(urq.e_gatekeeperIdentifier);
	urq.m_gatekeeperIdentifier.SetValue( Toolkit::GKName() );

	for_each(RegistrationTable::Instance()->EndpointList.begin(),
		 RegistrationTable::Instance()->EndpointList.end(),
		 UnregisterEP(&ras_msg));

	RegistrationTable::Instance()->EndpointList.clear(); 
	RegistrationTable::Instance()->GatewayPrefixes.clear();
	RegistrationTable::Instance()->GatewayFlags.clear();
}

void SoftPBX::UnregisterAlias(PString Alias)
{
	H225_RasMessage ras_msg;
	H225_AliasAddress EpAlias;	// alias of endpoint to be disconnected

	H323SetAliasAddress(Alias, EpAlias);
	PTRACE(3, "GK\tSoftPBX: Unregister " << EpAlias);

	ras_msg.SetTag(H225_RasMessage::e_unregistrationRequest);
	H225_UnregistrationRequest & urq = ras_msg;
	urq.IncludeOptionalField(urq.e_gatekeeperIdentifier);
	urq.m_gatekeeperIdentifier.SetValue( Toolkit::GKName() );

	endpointRec * ep = (endpointRec *)RegistrationTable::Instance()->FindByAlias(EpAlias);

	if (ep == NULL)
	{
		PTRACE(2, "GK\tSoftPBX: Can't find endpoint registration for " << EpAlias);
		return;
	};

#ifndef WIN32
	(UnregisterEP(&ras_msg))(*ep);
#else   // Create temporary object by hand, stupid bug of VC!!
	UnregisterEP u(&ras_msg); u(*ep);
#endif
	// remove the endpoint (even if we don't get a UCF - the endoint might be dead)
	RegistrationTable::Instance()->RemoveByEndpointId(ep->m_endpointIdentifier);

	PString msg("Endpoint " + Alias + " disconnected.\n");
	PTRACE(2, "GK\tSoftPBX: endpoint " << Alias << " disconnected.");
	GkStatus::Instance()->SignalStatus(msg);
}

// send a DRQ to this endpoint
void SoftPBX::DisconnectIp(PString Ip)
{
	PUDPSocket SendSocket;
	PIPSocket::Address ipaddress(Ip);
	PBYTEArray * wtbuf = new PBYTEArray(4096);
	PPER_Stream * wtstrm = new PPER_Stream(*wtbuf);

	H225_TransportAddress callSignalAddress;

	callSignalAddress = SocketToH225TransportAddr(ipaddress, GkConfig()->GetInteger("EndpointSignalPort", GK_DEF_ENDPOINT_SIGNAL_PORT));
	endpointRec * ep = (endpointRec *)RegistrationTable::Instance()->FindBySignalAdr(callSignalAddress);

	PTRACE(3, "GK\tSoftPBX: DisconnectIp " << ipaddress);

	if (ep == NULL)
	{
		PTRACE(2, "GK\tSoftPBX: Can't find endpoint registration");
		return;
	};
	H225_TransportAddress rasAddress = ep->m_rasAddress;
	H225_TransportAddress_ipAddress & ipRasAddress = rasAddress;
	PTRACE(3, "GK\tSoftPBX: RAS address " << rasAddress);

	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_disengageRequest);
	H225_DisengageRequest & drq = ras_msg;
	drq.m_requestSeqNum.SetValue(RequestNum++);
	drq.m_endpointIdentifier = ep->m_endpointIdentifier;
	// find callId and conferenceId
	CallRec * Call = (CallRec *)CallTable::Instance()->FindBySignalAdr(callSignalAddress);
	if (Call != NULL)
	{
		drq.m_callIdentifier = Call->m_callIdentifier;
		drq.m_conferenceID = Call->m_conferenceIdentifier;
	};
	drq.m_disengageReason.SetTag(H225_DisengageReason::e_forcedDrop);

	ras_msg.Encode(*wtstrm);
	wtstrm->CompleteEncoding();
	SendSocket.WriteTo(wtstrm->GetPointer(), wtstrm->GetSize(), ipaddress, ipRasAddress.m_port);
	delete wtbuf;
	delete wtstrm;
};

// send a DRQ to this endpoint
void SoftPBX::DisconnectAlias(PString Alias)
{
	PUDPSocket SendSocket;
	H225_AliasAddress EpAlias;	// alias of endpoint to be disconnected
	PBYTEArray * wtbuf = new PBYTEArray(4096);
	PPER_Stream * wtstrm = new PPER_Stream(*wtbuf);

	H323SetAliasAddress(Alias, EpAlias);
	PTRACE(3, "GK\tSoftPBX: DisconnectAlias " << EpAlias);

	endpointRec * ep = (endpointRec *)RegistrationTable::Instance()->FindByAlias(EpAlias);

	if (ep == NULL)
	{
		PTRACE(2, "GK\tSoftPBX: Can't find endpoint registration");
		return;
	};
	H225_TransportAddress rasAddress = ep->m_rasAddress;
	H225_TransportAddress_ipAddress & ipRasAddress = rasAddress;
	PIPSocket::Address ipaddress(ipRasAddress.m_ip[0], ipRasAddress.m_ip[1], ipRasAddress.m_ip[2], ipRasAddress.m_ip[3]);
	PTRACE(3, "GK\tSoftPBX: RAS address " << rasAddress);

	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_disengageRequest);
	H225_DisengageRequest & drq = ras_msg;
	drq.m_requestSeqNum.SetValue(RequestNum++);
	drq.m_endpointIdentifier = ep->m_endpointIdentifier;
	// find callId and conferenceId
	CallRec * Call = (CallRec *)CallTable::Instance()->FindBySignalAdr(ep->m_callSignalAddress);
	if (Call != NULL)
	{
		drq.m_callIdentifier = Call->m_callIdentifier;
		drq.m_conferenceID = Call->m_conferenceIdentifier;
	};
	drq.m_disengageReason.SetTag(H225_DisengageReason::e_forcedDrop);

	ras_msg.Encode(*wtstrm);
	wtstrm->CompleteEncoding();
	SendSocket.WriteTo(wtstrm->GetPointer(), wtstrm->GetSize(), ipaddress, ipRasAddress.m_port);
	delete wtbuf;
	delete wtstrm;
};

// send a DRQ to caller of this call number, causing it to close the H.225 channel
// this causes the gatekeeper to close the H.225 channel to the called party when
// it recognises the caller has gone away
void SoftPBX::DisconnectCall(PINDEX CallNumber)
{
	PUDPSocket SendSocket;
	PBYTEArray * wtbuf = new PBYTEArray(4096);
	PPER_Stream * wtstrm = new PPER_Stream(*wtbuf);

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

	endpointRec * ep = (endpointRec *)RegistrationTable::Instance()->FindBySignalAdr(callep->m_callSignalAddress);
	if (ep == NULL)
	{
		PTRACE(2, "GK\tSoftPBX: Calling endpoint is already deregistered");
		callep = Call->Called;
		ep = (endpointRec *)RegistrationTable::Instance()->FindBySignalAdr(callep->m_callSignalAddress);
	}
	if (ep == NULL)
	{
		PTRACE(2, "GK\tSoftPBX: All endpoints of call number " << CallNumber << " are already deregistered");
		return;
	};

	H225_TransportAddress rasAddress = ep->m_rasAddress;
	H225_TransportAddress_ipAddress & ipRasAddress = rasAddress;
	PIPSocket::Address ipaddress(ipRasAddress.m_ip[0], ipRasAddress.m_ip[1], ipRasAddress.m_ip[2], ipRasAddress.m_ip[3]);
	PTRACE(3, "GK\tSoftPBX: RAS address " << rasAddress);

	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_disengageRequest);
	H225_DisengageRequest & drq = ras_msg;
	drq.m_requestSeqNum.SetValue(RequestNum++);
	drq.m_endpointIdentifier = ep->m_endpointIdentifier;

	drq.m_callIdentifier = Call->m_callIdentifier;
	drq.m_conferenceID = Call->m_conferenceIdentifier;
	drq.m_disengageReason.SetTag(H225_DisengageReason::e_forcedDrop);

	ras_msg.Encode(*wtstrm);
	wtstrm->CompleteEncoding();
	SendSocket.WriteTo(wtstrm->GetPointer(), wtstrm->GetSize(), ipaddress, ipRasAddress.m_port);
	delete wtbuf;
	delete wtstrm;

	PString msg(PString::Printf, "Call number %d disconnected.\n", CallNumber);
	PTRACE(2, "GK\tSoftPBX: " << msg);
	GkStatus::Instance()->SignalStatus(msg);
};

// send a DRQ to this endpoint
void SoftPBX::DisconnectEndpoint(PString Id)
{
	PUDPSocket SendSocket;
	H225_EndpointIdentifier EpId;	// id of endpoint to be disconnected
	PBYTEArray * wtbuf = new PBYTEArray(4096);
	PPER_Stream * wtstrm = new PPER_Stream(*wtbuf);

	PTRACE(3, "GK\tSoftPBX: DisconnectEndpoint " << EpId);

	EpId = Id;
	endpointRec * ep = (endpointRec *)RegistrationTable::Instance()->FindByEndpointId(EpId);

	if (ep == NULL)
	{
		PTRACE(2, "GK\tSoftPBX: Can't find endpoint registration");
		return;
	};
	H225_TransportAddress rasAddress = ep->m_rasAddress;
	H225_TransportAddress_ipAddress & ipRasAddress = rasAddress;
	PIPSocket::Address ipaddress(ipRasAddress.m_ip[0], ipRasAddress.m_ip[1], ipRasAddress.m_ip[2], ipRasAddress.m_ip[3]);
	PTRACE(3, "GK\tSoftPBX: RAS address " << rasAddress);

	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_disengageRequest);
	H225_DisengageRequest & drq = ras_msg;
	drq.m_requestSeqNum.SetValue(RequestNum++);
	drq.m_endpointIdentifier = ep->m_endpointIdentifier;
	// find callId and conferenceId
	CallRec * Call = (CallRec *)CallTable::Instance()->FindBySignalAdr(ep->m_callSignalAddress);
	if (Call != NULL)
	{
		drq.m_callIdentifier = Call->m_callIdentifier;
		drq.m_conferenceID = Call->m_conferenceIdentifier;
	};
	drq.m_disengageReason.SetTag(H225_DisengageReason::e_forcedDrop);

	ras_msg.Encode(*wtstrm);
	wtstrm->CompleteEncoding();
	SendSocket.WriteTo(wtstrm->GetPointer(), wtstrm->GetSize(), ipaddress, ipRasAddress.m_port);
	delete wtbuf;
	delete wtstrm;
}

void SoftPBX::TransferCall(PString SourceAlias, PString DestinationAlias)
{
	PTRACE(1, "GK\tSoftPBX: TransferCall " << SourceAlias << " -> " << DestinationAlias);
	PTRACE(1, "GK\tSoftPBX: TransferCall not implemented, yet");
};

void SoftPBX::MakeCall(PString SourceAlias, PString DestinationAlias)
{
	PTRACE(1, "GK\tSoftPBX: MakeCall " << SourceAlias << " -> " << DestinationAlias);
	PTRACE(1, "GK\tSoftPBX: MakeCall not implemented, yet");
};

