//////////////////////////////////////////////////////////////////
//
// SoftPBX.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
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
#include "h323pdu.h"
#include "h323util.h"
#include "h225.h"
#include "RasTbl.h"
#include "Toolkit.h"
#include "SoftPBX.h"


int SoftPBX::TimeToLive = -1;
PTime SoftPBX::StartUp;


void SoftPBX::PrintEndpoint(const PString & Alias, GkStatus::Client &client, BOOL verbose)
{
	H225_ArrayOf_AliasAddress EpAlias;
	EpAlias.SetSize(1);
	H323SetAliasAddress(Alias, EpAlias[0]);
	const endptr ep = RegistrationTable::Instance()->FindEndpoint(EpAlias, TRUE);

	PString msg;
	if (ep)
		msg = "RCF|" + ep->PrintOn(verbose) + ";";
	else
		msg = "SoftPBX: alias " + Alias + " not found!";

	client.WriteString(msg + "\r\n");
}

void SoftPBX::PrintAllRegistrations(GkStatus::Client &client, BOOL verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintAllRegistrations");
	RegistrationTable::Instance()->PrintAllRegistrations(client, verbose);
}

void SoftPBX::PrintAllCached(GkStatus::Client &client, BOOL verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintAllCached");
	RegistrationTable::Instance()->PrintAllCached(client, verbose);
}

void SoftPBX::PrintRemoved(GkStatus::Client &client, BOOL verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintRemoved");
	RegistrationTable::Instance()->PrintRemoved(client, verbose);
}

void SoftPBX::PrintCurrentCalls(GkStatus::Client &client, BOOL verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintCurrentCalls");
	CallTable::Instance()->PrintCurrentCalls(client, verbose);
}

void SoftPBX::PrintStatistics(GkStatus::Client &client, BOOL)
{
	PTRACE(3, "GK\tSoftPBX: PrintStatistics");
	PString msg = RegistrationTable::Instance()->PrintStatistics()
		    + CallTable::Instance()->PrintStatistics()
		    + SoftPBX::Uptime() + "\r\n;\r\n";
	client.WriteString(msg);
}

// send URQ to all endpoints
void SoftPBX::UnregisterAllEndpoints()
{
	RegistrationTable::Instance()->ClearTable();
}

void SoftPBX::UnregisterAlias(PString Alias)
{
	H225_ArrayOf_AliasAddress EpAlias;
	EpAlias.SetSize(1);
	H323SetAliasAddress(Alias, EpAlias[0]);
	PTRACE(3, "GK\tSoftPBX: UnregisterAlias " << Alias);

	const endptr ep = RegistrationTable::Instance()->FindByAliases(EpAlias);
	if (!ep) {
		PString msg("SoftPBX: alias " + Alias + " not found!");
		PTRACE(1, "GK\t" + msg);
		GkStatus::Instance()->SignalStatus(msg + "\r\n");
		return;
	}
	ep->Unregister();

	// remove the endpoint (even if we don't get a UCF - the endoint might be dead)
	RegistrationTable::Instance()->RemoveByEndptr(ep);

	PString msg("SoftPBX: Endpoint " + Alias + " unregistered!");
	PTRACE(2, "GK\t" + msg);
	GkStatus::Instance()->SignalStatus(msg + "\r\n");
}

void SoftPBX::UnregisterIp(PString Ip)
{
	PIPSocket::Address ipaddress;
	PINDEX p=Ip.Find(':');
	PIPSocket::GetHostAddress(Ip.Left(p), ipaddress);
	WORD port = (p!=P_MAX_INDEX) ? Ip.Mid(p+1).AsUnsigned() :
		GkConfig()->GetInteger("EndpointSignalPort", GK_DEF_ENDPOINT_SIGNAL_PORT);
	H225_TransportAddress callSignalAddress = SocketToH225TransportAddr(ipaddress, port);

	PTRACE(3, "GK\tSoftPBX: UnregisterIp " << AsDotString(callSignalAddress));

	const endptr ep = RegistrationTable::Instance()->FindBySignalAdr(callSignalAddress);
	if (!ep) {
		PString msg("SoftPBX: ip " + AsDotString(callSignalAddress) + " not found!");
		PTRACE(1, "GK\t" + msg);
		GkStatus::Instance()->SignalStatus(msg + "\r\n");
		return;
	}
	ep->Unregister();

	// remove the endpoint (even if we don't get a UCF - the endoint might be dead)
	RegistrationTable::Instance()->RemoveByEndptr(ep);

	PString msg("SoftPBX: Endpoint " + AsDotString(callSignalAddress) + " unregistered!");
	PTRACE(2, "GK\t" + msg);
	GkStatus::Instance()->SignalStatus(msg + "\r\n");
}

// send a DRQ to caller of this call number, causing it to close the H.225 channel
// this causes the gatekeeper to close the H.225 channel to the called party when
// it recognises the caller has gone away
void SoftPBX::DisconnectCall(PINDEX CallNumber)
{
	PTRACE(3, "GK\tSoftPBX: DisconnectCall " << CallNumber);

	callptr Call = CallTable::Instance()->FindCallRec(CallNumber);
	if (!Call) {
		PString msg(PString::Printf, "Can't find call number %u", CallNumber);
		PTRACE(2, "GK\tSoftPBX: " << msg);
		GkStatus::Instance()->SignalStatus(msg + "\r\n");
		return;
	}

	Call->Disconnect(true);
	// remove the call directly so we don't have to handle DCF
	CallTable::Instance()->RemoveCall(Call);

	PString msg(PString::Printf, "Call number %d disconnected.", CallNumber);
	PTRACE(2, "GK\tSoftPBX: " << msg);
	GkStatus::Instance()->SignalStatus(msg + "\r\n");
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

	DisconnectEndpoint(RegistrationTable::Instance()->FindBySignalAdr(callSignalAddress));
}

// send a DRQ to this endpoint
void SoftPBX::DisconnectAlias(PString Alias)
{
	H225_ArrayOf_AliasAddress EpAlias;
	EpAlias.SetSize(1);
	H323SetAliasAddress(Alias, EpAlias[0]);
	PTRACE(3, "GK\tSoftPBX: DisconnectAlias " << Alias);

	DisconnectEndpoint(RegistrationTable::Instance()->FindByAliases(EpAlias));
}

// send a DRQ to this endpoint
void SoftPBX::DisconnectEndpoint(PString Id)
{
	H225_EndpointIdentifier EpId;	// id of endpoint to be disconnected
	EpId = Id;
	PTRACE(3, "GK\tSoftPBX: DisconnectEndpoint " << EpId);

        DisconnectEndpoint(RegistrationTable::Instance()->FindByEndpointId(EpId));
}

void SoftPBX::DisconnectEndpoint(const endptr &ep)
{
	if (!ep) {
		PString msg("SoftPBX: no endpoint to disconnect!");
		PTRACE(1, "GK\t" + msg);
		GkStatus::Instance()->SignalStatus(msg + "\r\n");
		return;
	}
	callptr Call;
	// remove all calls of ep
	while (Call = CallTable::Instance()->FindCallRec(ep)) {
		Call->Disconnect();
		CallTable::Instance()->RemoveCall(Call);
	}
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

PString SoftPBX::Uptime()
{
	long total = (PTime() - SoftPBX::StartUp).GetSeconds();
	int days = total / (24*60*60);
	int hour = (total % (24*60*60)) / (60*60);
	int min  = (total % (60*60)) / 60;
	int sec  = total % 60;

	return PString(PString::Printf,
			"Startup: %s   Running: %d days %02d:%02d:%02d",
			(const char *)SoftPBX::StartUp.AsString(),
			days, hour, min, sec);
}
