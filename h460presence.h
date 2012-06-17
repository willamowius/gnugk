//////////////////////////////////////////////////////////////////
//
// Presence in H.323 gatekeeper
//
// Copyright (c) 2009-2010, Simon Horne
// Copyright (c) 2009-2010, Jan Willamowius
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the H323plus library.
//
//////////////////////////////////////////////////////////////////


#include "config.h"

#ifdef HAS_H460P

#ifndef HAS_H460_H
#define HAS_H460_H

#include <h460/h460p.h>

class PresWorker;
#ifdef HAS_DATABASE
class GkSQLConnection;
#endif
class GkPresence : public H323PresenceHandler
{
public:
	GkPresence();
	~GkPresence();

	bool IsEnabled() const;

	void LoadConfig(PConfig * cfg);

    bool RegisterEndpoint(const H225_EndpointIdentifier & ep, const H225_ArrayOf_AliasAddress & addr);
	void UnRegisterEndpoint(const H225_ArrayOf_AliasAddress & addr);

	bool BuildPresenceElement(unsigned msgtag, const H225_EndpointIdentifier & ep, PASN_OctetString & pdu);
	bool BuildPresenceElement(unsigned msgtag, const H225_TransportAddress & ip, PASN_OctetString & pdu);
	void ProcessPresenceElement(const PASN_OctetString & pdu);

	bool GetPendingIdentifiers(list<H225_EndpointIdentifier> & epid);
	bool GetPendingAddresses(list<H225_TransportAddress> & gkip);

	bool GetSubscriptionIdentifier(const H225_AliasAddress & local,
									const H225_AliasAddress & remote,
									H460P_PresenceIdentifier & id);

	bool GetSubscription(const H460P_PresenceIdentifier & id,
									H323PresenceID & local);

	bool GetLocalSubscriptions(const H225_AliasAddress & local,
							list<H460P_PresenceIdentifier> & id);

	void DatabaseIncrementalUpdate();

protected:

  // Processing Functions
	bool EnQueuePresence(const H225_AliasAddress & addr, const H460P_PresencePDU & msg);

	bool EnQueueFullNotification(const H225_AliasAddress & local, const H225_AliasAddress & remote);


  // Inherited Events Endpoints
	virtual void OnNotification(MsgType tag,
								const H460P_PresenceNotification & notify,
								const H225_AliasAddress & addr
								);
	virtual void OnSubscription(MsgType tag,
								const H460P_PresenceSubscription & subscription,
								const H225_AliasAddress & addr
								);
	virtual void OnInstructions(MsgType tag,
								const H460P_ArrayOf_PresenceInstruction & instruction,
								const H225_AliasAddress & addr
								);

  // Inherited Events Gatekeepers
	virtual void OnNotification(MsgType tag,
								const H460P_PresenceNotification & notify,
								const H225_TransportAddress & ip
								);

	virtual void OnSubscription(MsgType tag,
								const H460P_PresenceSubscription & subscription,
								const H225_TransportAddress & ip
								);

	virtual void OnIdentifiers(MsgType tag,
								const H460P_PresenceIdentifier & identifier,
								const H225_TransportAddress & ip
								);

  // Build callback - Endpoint
	virtual PBoolean BuildSubscription(const H225_EndpointIdentifier & ep,
								H323PresenceStore & subscription
								);

	virtual PBoolean BuildNotification(const H225_EndpointIdentifier & ep,
								H323PresenceStore & notify
								);

	virtual PBoolean BuildInstructions(const H225_EndpointIdentifier & ep,
								H323PresenceStore & instruction
								);

  // Build Callback - Gatekeepers
	virtual PBoolean BuildSubscription(bool request,
								const H225_TransportAddress & ip,
								H323PresenceGkStore & subscription
								);

	virtual PBoolean BuildNotification(
								const H225_TransportAddress & ip,
								H323PresenceGkStore & notify
								);

	virtual PBoolean BuildIdentifiers(bool alive,
								const H225_TransportAddress & ip,
								H323PresenceGkStore & identifiers
								);

  // Handling Functions
	bool HandleNewAlias(const H225_AliasAddress & addr);
	bool HandleStatusUpdates(const H460P_PresenceIdentifier & identifier, const H225_AliasAddress & local, unsigned type, const H225_AliasAddress & remote, const H323PresenceID * id = NULL);
	bool HandleForwardPresence(const H460P_PresenceIdentifier & identifier, const H460P_PresencePDU & msg);

	bool HandleNewInstruction(unsigned tag, const H225_AliasAddress & addr, const H460P_PresenceInstruction & instruction,
								H323PresenceInstructions & instructions);

	H460P_PresenceSubscription & HandleSubscription(bool isNew, const H460P_PresenceIdentifier & pid, const H323PresenceID & id);
	bool HandleSubscriptionLocal(const H460P_PresenceSubscription & subscription, bool & approved);
	bool RemoveSubscription(unsigned type, const H460P_PresenceIdentifier & pid);

  // Database Functions
	bool DatabaseLoad(PBoolean incremental);
	bool DatabaseAdd(const PString & identifier, const H323PresenceID & id);
	bool DatabaseDelete(const PString & identifier);
	bool DatabaseUpdate(unsigned tag, const PString & identifier);


private:
	H323PresenceStore		localStore;    // Subscription/Block list for Local Registered endpoints

	H323PresenceAlias		aliasList;	   // list of presence Aliases registered locally
	H323PresenceLocal		pendingStore;  // Local Message handling store

    H323PresenceExternal    remoteList;    // remote aliases and their transport address
	H323PresenceRemote		remoteStore;   // Messages to/from remote gatekeepers

	H323PresenceIds			remoteIds;
	H323PresenceIdMap		remoteIdmap;
	H323PresenceLRQRelay	remoteRelay;

	PMutex					m_AliasMutex;

	bool					m_enabled;
	bool					m_sqlactive;

	PresWorker*				m_worker;

#if HAS_DATABASE
	// connection to the SQL database
	GkSQLConnection*		m_sqlConn;

	PString					m_queryList;
    PString					m_queryAdd;
	PString 				m_queryDelete;
	PString					m_queryUpdate;

	// query timeout
	long					m_timeout;
	PInt64					m_lastTimeStamp;
	PBoolean				m_incrementalUpdate;
#endif

};

#endif   // HAS_H460_H

#endif   // HAS_H460P


