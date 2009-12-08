
//////////////////////////////////////////////////////////////////
//
// Presence in H.323 gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the H323plus library.
//
// initial author: Simon Horne <s.horne@packetizer.com>
// initial version: 08/12/2009
//
//////////////////////////////////////////////////////////////////


#include "config.h"

#ifdef HAS_H460P

#include <h460/h460p.h>

#ifdef HAS_DATABASE
class GkSQLConnection;
#endif
class GkPresence : public H323PresenceHandler
{
public:
	GkPresence();

	bool IsEnabled() const;

	void LoadConfig(PConfig * cfg);

    bool RegisterEndpoint(const H225_EndpointIdentifier & ep, const H225_ArrayOf_AliasAddress & addr);
	void UnRegisterEndpoint(const H225_ArrayOf_AliasAddress & addr);

	bool BuildPresenceElement(unsigned msgtag, const H225_EndpointIdentifier & ep, PASN_OctetString & pdu);
	void ProcessPresenceElement(const PASN_OctetString & pdu);

protected:

	PBoolean LoadEndpoint(const H225_AliasAddress & addr, H323PresenceEndpoint & ep);

	void EnQueuePresence(const H225_AliasAddress & addr, const H460P_PresencePDU & msg);

  // Inherited Events
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
    virtual void OnIdentifiers(MsgType tag,
								const H460P_ArrayOf_PresenceIdentifier & identifier,
								const H225_AliasAddress & addr
								);

  // Build callback
	virtual PBoolean BuildSubscription(const H225_EndpointIdentifier & ep,
								H323PresenceStore & subscription
								);

	virtual PBoolean BuildNotification(const H225_EndpointIdentifier & ep,
								H323PresenceStore & notify
								);

	virtual PBoolean BuildInstructions(const H225_EndpointIdentifier & ep,
								H323PresenceStore & instruction
								);

	void HandleNewInstruction(unsigned tag, 
								const H460P_PresenceInstruction & instruction, 
								H323PresenceInstructions & instructions
								);

private:
	H323PresenceStore		localStore;    // Subscription/Block list for Local Registered endpoints

	H323PresenceAlias		aliasList;	   // list of presence Aliases registered locally
	H323PresenceLocal		pendingStore;  // Local Message handling store

    H323PresenceExternal    remoteList;    // remote aliases and their transport address
	H323PresenceRemote		remoteStore;   // Messages to/from remote gatekeepers

	PMutex					m_AliasMutex;

	bool					m_enabled;
	bool					m_sqlactive;
#if HAS_DATABASE
	// connection to the SQL database
	GkSQLConnection*		m_sqlConn;

	PString					m_queryList;
	PString					m_queryPost;
	PString 				m_queryDelete;
	// query timeout
	long					m_timeout;
#endif

};

#endif
