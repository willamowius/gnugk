//////////////////////////////////////////////////////////////////
//
// SoftPBX.h
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Jan Willamowius
//
//////////////////////////////////////////////////////////////////

#ifndef _SOFTPBX_H
#define _SOFTPBX_H

#include <ptlib.h>
#include "GkStatus.h"
#include "RasTbl.h"


namespace SoftPBX
{
	void PrintEndpoint(const PString & Alias, GkStatus::Client &client, BOOL verbose);
	void PrintAllRegistrations(GkStatus::Client &client, BOOL verbose=FALSE);
	void PrintAllCached(GkStatus::Client &client, BOOL verbose=FALSE);
	void PrintRemoved(GkStatus::Client &client, BOOL verbose=FALSE);
	void PrintCurrentCalls(GkStatus::Client &client, BOOL verbose=FALSE);
	void PrintStatistics(GkStatus::Client &client, BOOL verbose=FALSE);
	void UnregisterAllEndpoints();
	void UnregisterAlias(PString Alias);
	void UnregisterIp(PString Ip);
	void DisconnectCall(PINDEX CallNumber);
	void DisconnectIp(PString Ip);
	void DisconnectAlias(PString Alias);
	void DisconnectEndpoint(PString Id);
	void DisconnectEndpoint(const endptr &);
	void TransferCall(PString SourceAlias, PString DestinationAlias);
	void MakeCall(PString SourceAlias, PString DestinationAlias);

	PString Uptime();

	extern int TimeToLive;
	extern PTime StartUp;
}


#endif

