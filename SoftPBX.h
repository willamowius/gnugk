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

#ifndef SOFTPBX_H
#define SOFTPBX_H "@(#) $Id$"

// nothing to include :)

class PTime;
class PString;
class USocket;
class EndpointRec;
template<class> class SmartPtr;
typedef SmartPtr<EndpointRec> endptr;

namespace SoftPBX
{
	void PrintEndpoint(const PString & EpStr, USocket *client, bool verbose);
	void PrintAllRegistrations(USocket *client, bool verbose=false);
	void PrintAllCached(USocket *client, bool verbose=false);
	void PrintRemoved(USocket *client, bool verbose=false);
	void PrintCurrentCalls(USocket *client, bool verbose=false);
	void PrintStatistics(USocket *client, bool verbose=false);
	void UnregisterAllEndpoints();
	void UnregisterAlias(PString Alias);
	void UnregisterIp(PString Ip);
	void DisconnectAll();
	void DisconnectCall(unsigned CallNumber);
	void DisconnectIp(PString Ip);
	void DisconnectAlias(PString Alias);
	void DisconnectEndpoint(PString Id);
	void DisconnectEndpoint(const endptr &);
	void TransferCall(PString SourceAlias, PString DestinationAlias);
	void MakeCall(PString SourceAlias, PString DestinationAlias);
	void RouteToAlias(PString TargetAlias, PString SourceEpId, PString CallRef);
	void RouteReject(PString SourceEpId, PString CallRef);

	PString Uptime();

	extern int TimeToLive;
	extern PTime StartUp;
}

#endif // SOFTPBX_H
