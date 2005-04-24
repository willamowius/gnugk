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

#if defined(_WIN32) && (_MSC_VER <= 1200)  
#pragma warning(disable:4786) // warning about too long debug symbol off
#pragma warning(disable:4284)
#endif

#include <ptlib.h>
#include <h323pdu.h>
#include "gk_const.h"
#include "Toolkit.h"
#include "GkStatus.h"
#include "RasSrv.h"
#include "ProxyChannel.h"
#include "SoftPBX.h"


int SoftPBX::TimeToLive = -1;
PTime SoftPBX::StartUp;


void SoftPBX::PrintEndpoint(const PString & EpStr, USocket *client, bool verbose)
{
	H225_ArrayOf_AliasAddress EpAlias;
	EpAlias.SetSize(1);
	H323SetAliasAddress(EpStr, EpAlias[0]);
	// Apply rewriting rules
	Toolkit::Instance()->RewriteE164(EpAlias[0]);
	endptr ep = RegistrationTable::Instance()->FindEndpoint(EpAlias, false, true);
	if (!ep) {
		H225_EndpointIdentifier id;
		id = EpStr;
		ep = RegistrationTable::Instance()->FindByEndpointId(id);
	}
	if (!ep) {
		H225_TransportAddress callSignalAddress;
		GetTransportAddress(EpStr, (WORD)GkConfig()->GetInteger("EndpointSignalPort", GK_DEF_ENDPOINT_SIGNAL_PORT), callSignalAddress);
		ep = RegistrationTable::Instance()->FindBySignalAdr(callSignalAddress);
	}

	PString msg;
	if (ep)
		msg = "RCF|" + ep->PrintOn(verbose) + ";\r\n";
	else
		msg = "SoftPBX: endpoint " + EpStr + " not found!\r\n";
	client->TransmitData(msg);
}

void SoftPBX::PrintAllRegistrations(USocket *client, bool verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintAllRegistrations");
	RegistrationTable::Instance()->PrintAllRegistrations(client, verbose);
}

void SoftPBX::PrintAllCached(USocket *client, bool verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintAllCached");
	RegistrationTable::Instance()->PrintAllCached(client, verbose);
}

void SoftPBX::PrintRemoved(USocket *client, bool verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintRemoved");
	RegistrationTable::Instance()->PrintRemoved(client, verbose);
}

void SoftPBX::PrintCurrentCalls(USocket *client, bool verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintCurrentCalls");
	CallTable::Instance()->PrintCurrentCalls(client, verbose);
}

void SoftPBX::PrintStatistics(USocket *client, bool)
{
	PTRACE(3, "GK\tSoftPBX: PrintStatistics");
	PString msg = RegistrationTable::Instance()->PrintStatistics()
		    + CallTable::Instance()->PrintStatistics()
		    + SoftPBX::Uptime() + "\r\n;\r\n";
	client->TransmitData(msg);
}

// send URQ to all endpoints
void SoftPBX::UnregisterAllEndpoints()
{
	CallTable::Instance()->ClearTable();
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
	DisconnectEndpoint(ep);
	ep->Unregister();

	// remove the endpoint (even if we don't get a UCF - the endoint might be dead)
	RegistrationTable::Instance()->RemoveByEndptr(ep);

	PString msg("SoftPBX: Endpoint " + Alias + " unregistered!");
	PTRACE(2, "GK\t" + msg);
	GkStatus::Instance()->SignalStatus(msg + "\r\n");
}

void SoftPBX::UnregisterIp(PString Ip)
{
	H225_TransportAddress callSignalAddress;
	GetTransportAddress(Ip, (WORD)GkConfig()->GetInteger("EndpointSignalPort", GK_DEF_ENDPOINT_SIGNAL_PORT), callSignalAddress);

	PTRACE(3, "GK\tSoftPBX: UnregisterIp " << AsDotString(callSignalAddress));

	const endptr ep = RegistrationTable::Instance()->FindBySignalAdr(callSignalAddress);
	if (!ep) {
		PString msg("SoftPBX: ip " + AsDotString(callSignalAddress) + " not found!");
		PTRACE(1, "GK\t" + msg);
		GkStatus::Instance()->SignalStatus(msg + "\r\n");
		return;
	}
	DisconnectEndpoint(ep);
	ep->Unregister();

	// remove the endpoint (even if we don't get a UCF - the endoint might be dead)
	RegistrationTable::Instance()->RemoveByEndptr(ep);

	PString msg("SoftPBX: Endpoint " + AsDotString(callSignalAddress) + " unregistered!");
	PTRACE(2, "GK\t" + msg);
	GkStatus::Instance()->SignalStatus(msg + "\r\n");
}

void SoftPBX::DisconnectAll()
{
	CallTable::Instance()->ClearTable();
}

// send a DRQ to caller of this call number, causing it to close the H.225 channel
// this causes the gatekeeper to close the H.225 channel to the called party when
// it recognises the caller has gone away
void SoftPBX::DisconnectCall(unsigned CallNumber)
{
	PTRACE(3, "GK\tSoftPBX: DisconnectCall " << CallNumber);

	callptr Call = CallTable::Instance()->FindCallRec(CallNumber);
	if (!Call) {
		PString msg(PString::Printf, "Can't find call number %u", CallNumber);
		PTRACE(2, "GK\tSoftPBX: " << msg);
		GkStatus::Instance()->SignalStatus(msg + "\r\n");
		return;
	}

	Call->Disconnect();
	// remove the call directly so we don't have to handle DCF
	CallTable::Instance()->RemoveCall(Call);

	PString msg(PString::Printf, "Call number %d disconnected.", CallNumber);
	PTRACE(2, "GK\tSoftPBX: " << msg);
	GkStatus::Instance()->SignalStatus(msg + "\r\n");
}

// send a DRQ to this endpoint
void SoftPBX::DisconnectIp(PString Ip)
{
	H225_TransportAddress callSignalAddress;
	GetTransportAddress(Ip, (WORD)GkConfig()->GetInteger("EndpointSignalPort", GK_DEF_ENDPOINT_SIGNAL_PORT), callSignalAddress);
	PTRACE(3, "GK\tSoftPBX: DisconnectIp " << AsDotString(callSignalAddress));

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

	endptr lDestForward;
	endptr lSrcForward;
	callptr lCall;
	PString lForwarder = SourceAlias + ":forward";
	PString lAltDestInfo = DestinationAlias;
	CallSignalSocket *lForwardedSocket = 0;

	PStringList lBufferAliasArrayString;
	H225_ArrayOf_AliasAddress lBufferAliasArray;

	//Search for the call in CallTable
	lBufferAliasArrayString.AppendString(SourceAlias);
	H323SetAliasAddresses(lBufferAliasArrayString, lBufferAliasArray);

	lSrcForward = RegistrationTable::Instance()->FindEndpoint(lBufferAliasArray, true, true);
	lBufferAliasArrayString.RemoveAll();
	lBufferAliasArray.RemoveAll();

	if (!lSrcForward) {
		PString msg("SoftPBX: no endpoint to transfer!");
		PTRACE(1, "GK\t" + msg);
		GkStatus::Instance()->SignalStatus(msg + "\r\n");
		return;
	}
	lCall = CallTable::Instance()->FindCallRec(lSrcForward);

	//Search for the Forwarded CallSignalSocket in lCall ( calling or caller socket ? )
	if (lCall) {
		endptr lCalling, lCalled;
		lCalling = lCall->GetCallingParty();
		lCalled = lCall->GetCalledParty();
		H225_ArrayOf_AliasAddress aliases = lSrcForward->GetAliases();
		if (lCalling && lCalling->CompareAlias(&aliases)) {
			lForwardedSocket = lCall->GetCallSignalSocketCalling();
		} else if (lCalled && lCalled->CompareAlias(&aliases)) {
			lForwardedSocket = lCall->GetCallSignalSocketCalled();
		}
		if (!lForwardedSocket) {
			PString msg("SoftPBX: can't transfer call in direct mode!");
			PTRACE(1, "GK\t" + msg);
			GkStatus::Instance()->SignalStatus(msg + "\r\n");
			return;
		}
	} else {
		PString msg("SoftPBX: no call to transfer!");
		PTRACE(1, "GK\t" + msg);
		GkStatus::Instance()->SignalStatus(msg + "\r\n");
		return;
	}

	//Search destination of call forwarding : lDestForward
	lBufferAliasArrayString.AppendString(DestinationAlias);
	H323SetAliasAddresses(lBufferAliasArrayString, lBufferAliasArray);

	lDestForward = RegistrationTable::Instance()->FindEndpoint(lBufferAliasArray, true, true);
	lBufferAliasArrayString.RemoveAll();
	lBufferAliasArray.RemoveAll();

	if (!lDestForward) {
		PString msg("SoftPBX: transferred destination not found!");
		PTRACE(1, "GK\t" + msg);
		GkStatus::Instance()->SignalStatus(msg + "\r\n");
		return;
	}

	Q931 q931;
	PBYTEArray lBuffer;
	lForwardedSocket->BuildFacilityPDU(q931, H225_FacilityReason::e_callForwarded, &DestinationAlias);
	q931.Encode(lBuffer);
	lForwardedSocket->TransmitData(lBuffer);

	PString msg = PString("SoftPBX: call ") + PString(lCall->GetCallNumber()) + " transferred from" + SourceAlias + " to " + DestinationAlias;
	PTRACE(1, "GK\t" + msg);
	GkStatus::Instance()->SignalStatus(msg + "\r\n");
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
