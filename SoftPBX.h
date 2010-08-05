//////////////////////////////////////////////////////////////////
//
// SoftPBX.h
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitly grant the right to link this code
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
class CallRec;
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
	void ResetCallCounters(USocket *client);
	void UnregisterAllEndpoints();
	void UnregisterAlias(const PString & Alias);
	void UnregisterIp(const PString & Ip);
	void DisconnectAll();
	void DisconnectCall(unsigned CallNumber);
	void DisconnectCallId(const PString & CallId);
	void DisconnectIp(const PString & Ip);
	void DisconnectAlias(const PString & Alias);
	void DisconnectEndpoint(const PString & Id);
	void DisconnectEndpoint(const endptr &);
	void SendProceeding(const PString & CallId);
	void TransferCall(const PString & SourceAlias, const PString & DestinationAlias);
	void TransferCall(const PString & CallId, const PCaselessString & which, const PString & Destination, const PString & method);
	void MakeCall(const PString & SourceAlias, const PString & DestinationAlias);
	void RerouteCall(const PString & CallId, const PCaselessString & whichLeg, const PString & destination);
	void PrintPrefixCapacities(USocket *client, const PString & alias);
	void PrintCapacityControlRules(USocket *client);
	
	PString Uptime();

	extern int TimeToLive;
	extern PTime StartUp;
}

#endif // SOFTPBX_H
