//////////////////////////////////////////////////////////////////
//
// SoftPBX.h
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// initial author: Jan Willamowius
//
//////////////////////////////////////////////////////////////////

#ifndef _SOFTPBX_H
#define _SOFTPBX_H

#include "GkStatus.h"
#include "h225.h"

class endptr;

namespace SoftPBX
{
	void PrintAllRegistrations(GkStatus::Client &client, BOOL verbose=FALSE);
	void PrintCurrentCalls(GkStatus::Client &client, BOOL verbose=FALSE);
	void UnregisterEndpoint(const endptr &Endpoints,
		H225_UnregRequestReason::Choices reason = H225_UnregRequestReason::e_maintenance);
	void UnregisterAllEndpoints();
	void UnregisterAlias(PString Alias);
	void DisconnectIp(PString Ip);
	void DisconnectAlias(PString Alias);
	void DisconnectEndpoint(PString Id);
	void DisconnectCall(PINDEX CallNumber);
	void TransferCall(PString SourceAlias, PString DestinationAlias);
	void MakeCall(PString SourceAlias, PString DestinationAlias);

}

#endif

