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

class SoftPBX : public Singleton<SoftPBX>
{
public:
	void PrintAllRegistrations(GkStatus::Client &client, BOOL verbose=FALSE);
	void PrintCurrentCalls(GkStatus::Client &client, BOOL verbose=FALSE);
	void DisconnectIp(PString Ip);
	void DisconnectAlias(PString Alias);
	void DisconnectCall(PINDEX CallNumber);
	void DisconnectEndpoint(PString Id);
	void UnregisterAllEndpoints();
	void UnregisterAlias(PString Alias);
	void TransferCall(PString SourceAlias, PString DestinationAlias);
	void MakeCall(PString SourceAlias, PString DestinationAlias);

};

#endif

