//////////////////////////////////////////////////////////////////
//
// RasSrv.h
//
// Multi-threaded RAS Server for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2001-2003
// Copyright (c) 2000-2014, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef RASSRV_H
#define RASSRV_H "@(#) $Id$"

#include <vector>
#include <list>
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
class SignalingMsg;
template <class> class H225SignalingMsg;
typedef H225SignalingMsg<H225_Setup_UUIE> SetupMsg;

class RasListener;
class GkInterface;
class GkAcctLoggerList;
class GkClient;
class ProxyHandler;
class HandlerList;

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
	virtual ~RasServer();

	// override from class SocketsReader
	virtual void Stop();

	// set routed according to the config file
	void SetRoutedMode();
	// set routed method
	void SetRoutedMode(bool, bool);

	// Set the ENUM Servers
	void SetENUMServers();

	// Set the RDS Servers
	void SetRDSServers();

	bool IsGKRouted() const { return GKRoutedSignaling; }
	bool IsH245Routed() const { return GKRoutedH245; }
	bool AcceptUnregisteredCalls(const PIPSocket::Address &) const;
	bool AcceptPregrantedCalls(const H225_Setup_UUIE & setupBody, const PIPSocket::Address &) const;
	bool IsCallFromTraversalClient(const PIPSocket::Address &) const;
	bool IsCallFromTraversalServer(const PIPSocket::Address &) const;

	// customized handler
	bool RegisterHandler(RasHandler *);
	bool UnregisterHandler(RasHandler *);

	void LoadConfig();
	void AddListener(RasListener *);
	void AddListener(TCPListenSocket *);
	bool CloseListener(TCPListenSocket *);

	WORD GetRequestSeqNum();

	GkInterface *SelectInterface(const Address &);
    GkInterface *SelectDefaultInterface(unsigned version);
	const GkInterface *SelectInterface(const Address &) const;
	RasListener * GetRasListener(const Address & addr) const;
	Address GetLocalAddress(const Address &) const;
	Address GetMasqAddress(const Address &) const;
	H225_TransportAddress GetRasAddress(const Address &) const;
	H225_TransportAddress GetCallSignalAddress(const Address &) const;

	bool SendRas(H225_RasMessage &, const Address &, WORD, RasListener * = NULL, GkH235Authenticators * auth = NULL);
	bool SendRas(H225_RasMessage &, const H225_TransportAddress &, RasListener * = NULL, GkH235Authenticators * auth = NULL);
	bool SendRas(H225_RasMessage &, const Address &, WORD, const Address &, GkH235Authenticators * auth);
	bool SendRIP(H225_RequestSeqNum seqNum, unsigned ripDelay, const Address & addr, WORD port, GkH235Authenticators * auth);

	bool IsRedirected(unsigned = 0) const;
	bool IsForwardedMessage(const H225_NonStandardParameter *, const Address &) const;
	void ForwardRasMsg(H225_RasMessage &);
	bool ReplyToRasAddress(const NetworkAddress & ip) const;

	bool RemoveCallOnDRQ() const { return bRemoveCallOnDRQ; }

	PString GetParent() const;
	bool IsPassThroughRegistrant();
	bool RemoveAdditiveRegistration(const H225_ArrayOf_AliasAddress &);

	GkClient *GetGkClient() { return gkClient; }
	NeighborList *GetNeighbors() { return neighbors; }
	VirtualQueue *GetVirtualQueue() { return vqueue; }
	const GkClient *GetGkClient() const { return gkClient; }
	const NeighborList *GetNeighbors() const { return neighbors; }
	const VirtualQueue *GetVirtualQueue() const { return vqueue; }

	// get signaling handler
	ProxyHandler *GetSigProxyHandler();
	ProxyHandler *GetRtpProxyHandler();

	void SelectH235Capability(const H225_GatekeeperRequest &, H225_GatekeeperConfirm &) const;

	template<class RAS> bool ValidatePDU(RasPDU<RAS>& ras, unsigned & reason)
	{
		return authList->Validate(ras, reason);
	}

	bool ValidateAdditivePDU(RasPDU<H225_RegistrationRequest>& ras, RRQAuthData & authData);

	bool ValidatePDU(RasPDU<H225_RegistrationRequest> & ras, RRQAuthData & authData)
	{
		return authList->Validate(ras, authData);
	}

	bool ValidatePDU(RasPDU<H225_AdmissionRequest> & ras, ARQAuthData & authData)
	{
		return authList->Validate(ras, authData);
	}

	bool ValidatePDU(SetupMsg & setup, SetupAuthData & authData)
	{
		return authList->Validate(setup, authData);
	}

	bool ValidatePDU(Q931 & msg, Q931AuthData & authData)
	{
		return authList->Validate(msg, authData);
	}

	GkAcctLoggerList * GetAcctList() { return acctList; }
	GkAuthenticatorList * GetAuthList() { return authList; }

	bool LogAcctEvent(int evt, const callptr & call, time_t now = 0);

	bool LogAcctEvent(int evt, const endptr & ep);

	PString GetAuthInfo(const PString & moduleName);

	PString GetAcctInfo(const PString & moduleName);

	template<class RAS> bool IsForwardedRas(const RAS & ras, const Address & addr) const
	{
		return IsForwardedMessage(ras.HasOptionalField(RAS::e_nonStandardData) ? &ras.m_nonStandardData : 0, addr);
	}

	template<class RAS> void SetAlternateGK(RAS & ras, const NetworkAddress & ip)
	{
		H225_ArrayOf_AlternateGK alternates = GetAltGKForIP(ip);
#if HAS_DATABASE
		Toolkit::Instance()->AlternateGKs().GetAlternateGK(ip.m_address, alternates);
#endif
		if (alternates.GetSize() > 0) {
			// add alternates by IP
			ras.IncludeOptionalField(RAS::e_alternateGatekeeper);
			ras.m_alternateGatekeeper = alternates;
		} else	if (altGKs.GetSize() > 0) {
			// use global configuration
			ras.IncludeOptionalField(RAS::e_alternateGatekeeper);
			ras.m_alternateGatekeeper = altGKs;
		}
	}

	template<class RAS> void SetAltGKInfo(RAS & ras, const NetworkAddress & ip)
	{
		H225_ArrayOf_AlternateGK alternates = GetAltGKForIP(ip);
#if HAS_DATABASE
		Toolkit::Instance()->AlternateGKs().GetAlternateGK(ip.m_address, alternates);
#endif
        if (Toolkit::Instance()->IsMaintenanceMode() && alternates.GetSize() == 0) {
            alternates = Toolkit::Instance()->GetMaintenanceAlternate();
        }
		if (alternates.GetSize() > 0) {
			// add alternates by IP
			ras.IncludeOptionalField(RAS::e_altGKInfo);
			ras.m_altGKInfo.m_altGKisPermanent = (redirectGK == e_permanentRedirect);
			ras.m_altGKInfo.m_alternateGatekeeper = alternates;
		} else	if (altGKs.GetSize() > 0) {
			// use global configuration
			ras.IncludeOptionalField(RAS::e_altGKInfo);
			ras.m_altGKInfo.m_altGKisPermanent = (redirectGK == e_permanentRedirect);
			ras.m_altGKInfo.m_alternateGatekeeper = altGKs;
		}
	}

#ifdef h323v6
	template<class RAS> bool HasAssignedGK(const PString & alias,const PIPSocket::Address & ip, RAS & ras)
	{
        H225_ArrayOf_AlternateGK assignedGK;
		assignedGK.SetSize(0);

		// Queries a DB for gatekeeper registrations with the first being
		// the assigned gatekeeper. The alternates are then in preference order
		// Note: If an assigned gatekeeper is found then the registration is not
		// handled by this gatekeeper but by the assigned gatekeeper.
		if (!Toolkit::Instance()->AssignedGKs().GetAssignedGK(alias, ip, assignedGK))
			return false;

		if (assignedGK.GetSize() == 0)
			return false;

        ras.IncludeOptionalField(RAS::e_assignedGatekeeper);
		ras.m_assignedGatekeeper = assignedGK[0];

		if (assignedGK.GetSize() > 1) {
			for (PINDEX i=1; i< assignedGK.GetSize(); i++) {
			   ras.m_alternateGatekeeper.SetSize(i);
			   ras.m_alternateGatekeeper[i-1] = assignedGK[i];
			}
			ras.IncludeOptionalField(RAS::e_alternateGatekeeper);
		}

		return true;
	}
#endif

	// override from class RegularJob
	virtual void Run();

#ifdef HAS_H46017
	virtual void ReadH46017Message(const PBYTEArray & ras, const PIPSocket::Address & fromIP, WORD fromPort, const PIPSocket::Address & localAddr, CallSignalSocket * s);
#endif

private:
	// override from class RegularJob
	virtual void OnStop();

	void GetAlternateGK();
	H225_ArrayOf_AlternateGK ParseAltGKConfig(const PString & altGkSetting) const;
	H225_ArrayOf_AlternateGK GetAltGKForIP(const NetworkAddress & ip) const;
	void ClearAltGKsTable();
	void HouseKeeping();

	// override from class SocketsReader
	virtual void ReadSocket(IPSocket *);
	virtual void CleanUp();

	// new virtual function
	virtual void CreateRasJob(GatekeeperMessage * msg, bool syncronous = false);
	virtual GkInterface *CreateInterface(const Address &);

	typedef std::list<GkInterface *>::iterator ifiterator;
	typedef std::list<GkInterface *>::const_iterator const_ifiterator;

	WORD requestSeqNum;
	PMutex seqNumMutex;

	std::list<GkInterface *> interfaces;

	PMutex requests_mutex;
	std::list<RasMsg *> requests;
	PMutex handlers_mutex;
	std::list<RasHandler *> handlers;	// handlers checking for expected RAS messages eg. from parent or neighbors

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
	H225_ArrayOf_AlternateGK altGKs;
	PINDEX altGKsSize;
	std::map<NetworkAddress, H225_ArrayOf_AlternateGK> m_altGkRules;	// alternate GK rules by IP
	PINDEX epLimit, callLimit;
	int redirectGK;

	std::map<NetworkAddress, bool> m_replyras; // on which network should we use the rasAddress included in GRQ/RRQ/IRQ
};

#endif // RASSRV_H
