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

#ifndef SOFTPBX
#define SOFTPBX

#include "ptlib.h"
#include "ptlib/sockets.h"
#include <h225.h>
#include "GkStatus.h"

class SoftPBX
{
public:
	static SoftPBX * Instance(void);

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

protected:
	static SoftPBX * m_instance;
	static PMutex m_CreationLock;		// lock to protect singleton creation
};

#endif

