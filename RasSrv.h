//////////////////////////////////////////////////////////////////
//
// RasSrv.h
//
// New Multi-threaded RAS Server for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2001-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 03/14/2003
//
//////////////////////////////////////////////////////////////////

#ifndef RASSRV_H
#define RASSRV_H "@(#) $Id$"

#include <vector>
#include <list>
#include "h323util.h"
#include "yasocket.h"
#include "singleton.h"
#include "RasTbl.h"
#include "RasPDU.h"
#include "gkauth.h"

class H225_RasMessage;
class H225_GatekeeperRequest;
class H225_GatekeeperConfirm;
class H225_NonStandardParameter;
class H225_TransportAddress;
class H225_ArrayOf_AlternateGK;
class H225_Setup_UUIE;
class Q931;

//struct GatekeeperMessage;
class RasListener;
//class RasMsg;
//class RasHandler;
class GkInterface;
//class GkAuthenticatorList;
class GkAcctLoggerList;
class GkClient;
class ProxyHandler;
class HandlerList;
struct GkAuthenticator::ARQAuthData;
struct GkAuthenticator::SetupAuthData;

class WaitingARQlist;

namespace Neighbors {
	class NeighborList;
}

using Neighbors::NeighborList;

namespace Routing {
	class VirtualQueue;
}

using Routing::VirtualQueue;

class RasServer : public Singleton<RasServer>, public SocketsReader {
public:
	typedef PIPSocket::Address Address;

	RasServer();
	~RasServer();

	// override from class SocketsReader
	virtual void Stop();

	// set routed according to the config file
	void SetRoutedMode();
	// set routed method
	void SetRoutedMode(bool, bool);

	bool IsGKRouted() const { return GKRoutedSignaling; }
	bool IsH245Routed() const { return GKRoutedH245; }
	bool AcceptUnregisteredCalls(const PIPSocket::Address &) const;

	// customized handler
	bool RegisterHandler(RasHandler *);
	bool UnregisterHandler(RasHandler *);

	void Check();
	void LoadConfig();
	void AddListener(RasListener *);
	void AddListener(TCPListenSocket *);
	bool CloseListener(TCPListenSocket *);

	WORD GetRequestSeqNum();

	GkInterface *SelectInterface(const Address &);
	const GkInterface *SelectInterface(const Address &) const;
	Address GetLocalAddress(const Address &) const;
	H225_TransportAddress GetRasAddress(const Address &) const;
	H225_TransportAddress GetCallSignalAddress(const Address &) const;

	bool SendRas(const H225_RasMessage &, const Address &, WORD, RasListener * = 0);
	bool SendRas(const H225_RasMessage &, const H225_TransportAddress &, RasListener * = 0);
	bool SendRas(const H225_RasMessage &, const Address &, WORD, const Address &);

	bool IsRedirected(unsigned = 0) const;
	bool IsForwardedMessage(const H225_NonStandardParameter *, const Address &) const;
	void ForwardRasMsg(H225_RasMessage &);

	bool RemoveCallOnDRQ() const { return bRemoveCallOnDRQ; }

	PString GetParent() const;
	GkClient *GetGkClient() { return gkClient; }
	NeighborList *GetNeighbors() { return neighbors; }
	VirtualQueue *GetVirtualQueue() { return vqueue; }
	const GkClient *GetGkClient() const { return gkClient; }
	const NeighborList *GetNeighbors() const { return neighbors; }
	const VirtualQueue *GetVirtualQueue() const { return vqueue; }

	// get signalling handler
	ProxyHandler *GetProxyHandler();

	void SelectH235Capability(const H225_GatekeeperRequest &, H225_GatekeeperConfirm &) const;

	template<class RAS> bool ValidatePDU(RasPDU<RAS>& ras, unsigned & reason)
	{
		return authList->Validate(ras, reason);
	}

	bool ValidatePDU(
		RasPDU<H225_AdmissionRequest>& ras, 
		GkAuthenticator::ARQAuthData& authData
		)
	{
		return authList->Validate(ras, authData);
	}

	bool ValidatePDU(
		Q931& q931pdu,
		H225_Setup_UUIE& setup,
		GkAuthenticator::SetupAuthData& authData
		)
	{
		return authList->Validate(q931pdu, setup, authData);
	}

	bool LogAcctEvent(
		int evt,
		callptr& call,
		time_t now = 0
		);
	
	template<class RAS> bool IsForwardedRas(const RAS & ras, const Address & addr) const
	{
		return IsForwardedMessage(ras.HasOptionalField(RAS::e_nonStandardData) ? &ras.m_nonStandardData : 0, addr);
	}

	template<class RAS> void SetAlternateGK(RAS & ras)
	{
		if (altGKs->GetSize() > 0) {
			ras.IncludeOptionalField(RAS::e_alternateGatekeeper);
			ras.m_alternateGatekeeper = *altGKs;
		}
	}

	template<class RAS> void SetAltGKInfo(RAS & ras)
	{
		if (altGKs->GetSize() > 0) {
			ras.IncludeOptionalField(RAS::e_altGKInfo);
			ras.m_altGKInfo.m_altGKisPermanent = (redirectGK == e_permanentRedirect);
			ras.m_altGKInfo.m_alternateGatekeeper = *altGKs;
		}
	}

	// override from class RegularJob
	virtual void Run();

private:
	// override from class RegularJob
	virtual void OnStop();

	void GetAlternateGK();
	void ClearAltGKsTable();
	void HouseKeeping();

	// override from class SocketsReader
	virtual void ReadSocket(IPSocket *);
	virtual void CleanUp();

	// new virtual function
	virtual GkInterface *CreateInterface(const Address &);

	typedef std::list<GkInterface *>::iterator ifiterator;
	typedef std::list<GkInterface *>::const_iterator const_ifiterator;

	WORD requestSeqNum;
	PMutex seqNumMutex;

	std::list<GkInterface *> interfaces;

	std::list<RasMsg *> requests;
	PMutex hmutex;
	std::list<RasHandler *> handlers;

	bool GKRoutedSignaling, GKRoutedH245;
	bool bRemoveCallOnDRQ;

	TCPServer *listeners;
	RasListener *broadcastListener;

	HandlerList *sigHandler;
	GkAuthenticatorList *authList;
	GkAcctLoggerList* acctList;
	GkClient *gkClient;
	NeighborList *neighbors;
	VirtualQueue *vqueue;

	// alternate GK support
	enum {
		e_noRedirect,
		e_temporaryRedirect,
		e_permanentRedirect
	};
	std::vector<Address> altGKsAddr, skipAddr;
	std::vector<WORD> altGKsPort;
	H225_ArrayOf_AlternateGK *altGKs;
	PINDEX altGKsSize;
	PINDEX epLimit, callLimit;
	int redirectGK;

	WaitingARQlist *wArqList;
};

#endif // RASSRV_H
