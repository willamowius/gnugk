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


#include "h460presence.h"

#ifdef HAS_H460P

#include "RasSrv.h"
#include "gk_const.h"
#include "h323util.h"
#ifdef HAS_DATABASE
#include "gksql.h"
#endif

#include "h460/h4601.h"
#include <h323pdu.h>
#include <ptclib/delaychan.h>

#define DEFAULT_PRESWORKER_TIMER 2   // fire thread every 2 seconds;

///////////////////////////////////////////////////////

class PresWorker : public PThread
{
public:
	PCLASSINFO(PresWorker, PThread)

	/// create a new Worker thread and start it immediatelly
	PresWorker(
		GkPresence * _handler,
		int _waitTime
	);

	~PresWorker();

	// override from class PThread
	virtual void Main();

	// Close
	void Close();

protected:
	void ProcessMessages();

private:
	GkPresence * handler;
	long waitTime;
	bool shutDown;

	PAdaptiveDelay m_delay;

};

PresWorker::PresWorker(GkPresence * _handler , int _waitTime)
: PThread(5000, AutoDeleteThread), handler(_handler), waitTime(_waitTime), shutDown(false)
{
	PTRACE(4,"PRES\tPresence Thread instance fire every " << waitTime << " sec");
	Resume();
}

PresWorker::~PresWorker()
{
	Close();
}
	
void PresWorker::Main()
{
	while (!shutDown) {

		// Go do the coding
		ProcessMessages();

		// Wait
		m_delay.Delay(waitTime);
	}
}

void PresWorker::Close()
{
	if (!shutDown) {
	    PTRACE(4,"PRES\tPresence Thread Shutdown");
		shutDown = true;
	}
}

void BuildSCI(H225_RasMessage & sci_ras, PASN_OctetString & data)
{
	RasServer *RasSrv = RasServer::Instance();
	sci_ras.SetTag(H225_RasMessage::e_serviceControlIndication);
	H225_ServiceControlIndication & sci = sci_ras;
	sci.m_requestSeqNum = RasSrv->GetRequestSeqNum();

	H225_ServiceControlSession controlRefresh;
	controlRefresh.m_sessionId = 0;
	controlRefresh.m_reason = H225_ServiceControlSession_reason::e_refresh;
	sci.m_serviceControl.SetSize(1);
	sci.m_serviceControl[0] = controlRefresh;

	H460_FeatureOID feat = H460_FeatureOID(OpalOID(OID3));
	feat.Add(OID3_PDU, H460_FeatureContent(data));
	sci.IncludeOptionalField(H225_ServiceControlIndication::e_genericData);
	H225_ArrayOf_GenericData & gd = sci.m_genericData;
	gd.SetSize(1);
	gd[0] = feat;
}

void BuildLRQ(H225_RasMessage & lrq_ras, PASN_OctetString & data)
{
	RasServer *RasSrv = RasServer::Instance();
	lrq_ras.SetTag(H225_RasMessage::e_locationRequest);
	H225_LocationRequest & lrq = lrq_ras;
	lrq.m_requestSeqNum = RasSrv->GetRequestSeqNum();

	H460_FeatureOID feat = H460_FeatureOID(OpalOID(OID3));
	feat.Add(OID3_PDU, H460_FeatureContent(data));
	lrq.IncludeOptionalField(H225_LocationRequest::e_genericData);
	H225_ArrayOf_GenericData & gd = lrq.m_genericData;
	gd.SetSize(1);
	gd[0] = feat;
}

void PresWorker::ProcessMessages()
{
	// Get a list of endpoint identifiers with pending presence
	list<H225_EndpointIdentifier> epid;
	if (handler->GetPendingIdentifiers(epid)) {
		// Process the SCI message for each endpoint identifier
		list<H225_EndpointIdentifier>::iterator i = epid.begin();
		while (i != epid.end()) {
			endptr ep = RegistrationTable::Instance()->FindByEndpointId(*i);
			if (ep) {
				PASN_OctetString element;
				if (handler->BuildPresenceElement(H225_RasMessage::e_serviceControlIndication, *i, element)) {
					H225_RasMessage sci_ras;
					BuildSCI(sci_ras,element);
					RasServer::Instance()->SendRas(sci_ras, ep->GetRasAddress());
				}
			}
			i++;
		}
	}

	// Process the message for other gatekeepers
	list<H225_TransportAddress> gkip;
	if (handler->GetPendingAddresses(gkip)) {
		// Process the LRQ message for each TransportAddress
		list<H225_TransportAddress>::iterator i = gkip.begin();
		while (i != gkip.end()) {
			PASN_OctetString element;
			if (handler->BuildPresenceElement(H225_RasMessage::e_locationRequest,*i, element)) {
				H225_RasMessage lrq_ras;
				BuildLRQ(lrq_ras,element);
				RasServer::Instance()->SendRas(lrq_ras, *i);
			}
			i++;
		}
	}

}

//////////////////////////////////////////////////////
// Utilities

H460P_PresenceInstruction & BuildInstructionMsg(const H460P_PresenceInstruction & instruct, H460P_PresencePDU & msg)
{
	H460P_PresencePDU m;
	m.SetTag(H460P_PresencePDU::e_instruction);
	H460P_PresenceInstruction & inst = m;
	inst = instruct;
	msg = *(H460P_PresencePDU *)m.Clone();
	return msg;
}

H460P_PresenceInstruction & BuildInstructionMsg(unsigned type, const H225_AliasAddress & addr, H460P_PresencePDU & msg)
{
	H323PresenceInstruction instruct((H323PresenceInstruction::Instruction)type, AsString(addr,0));
	return BuildInstructionMsg(instruct,msg);
}

H460P_PresenceSubscription & BuildSubscriptionMsg(const H460P_PresenceSubscription & subscription, H460P_PresencePDU & msg)
{
	H460P_PresencePDU m;
	m.SetTag(H460P_PresencePDU::e_subscription);
	H460P_PresenceSubscription & sub = m;
	sub = subscription;
	msg = *(H460P_PresencePDU *)m.Clone();
	return msg;
}

H460P_PresenceSubscription & BuildSubscriptionMsg(const OpalGloballyUniqueID & id, const H225_AliasAddress remote,
												const H225_AliasAddress local, H460P_PresencePDU & msg)
{
	H323PresenceSubscription sub;
	sub.SetSubscription(id);
	sub.SetSubscriptionDetails(local,remote);
	return BuildSubscriptionMsg(sub,msg);
}

H460P_PresenceNotification & BuildNotificationMsg(const H460P_PresenceNotification & notification, H460P_PresencePDU & msg)
{
	H460P_PresencePDU m;
	m.SetTag(H460P_PresencePDU::e_notification);
	H460P_PresenceNotification & notify = m;
	notify = notification;
	msg = *(H460P_PresencePDU *)m.Clone();
	return msg;
}

H460P_PresenceIdentifier & BuildIdentifierMsg(const H460P_PresenceIdentifier & identifier, H460P_PresencePDU & msg)
{
	H460P_PresencePDU m;
	m.SetTag(H460P_PresencePDU::e_identifier);
	H460P_PresenceIdentifier & pid = (H460P_PresenceIdentifier &)m;
	pid = identifier;
	msg = *(H460P_PresencePDU *)m.Clone();
	return msg;
}

bool RemoveInstruction(const H225_AliasAddress & addr, H323PresenceInstructions & list)
{
	bool found = false;
	int sz = list.GetSize();
	for (PINDEX i=0; i<sz;  ++i) {
		if (addr == list[i]) {
			found = true;
			continue;
		}
		if (found) {
			list[i-1] = list[i];
		}
	}
	if (found)
		list.SetSize(sz-1);

	return found;
}

bool UpdateInstruction(const H460P_PresenceInstruction & addr, H323PresenceInstructions & inst)
{
	bool found = false;
	for (PINDEX i=0; i< inst.GetSize(); ++i) {
		if (AsString(addr,0) == inst[i].GetAlias()) {
			found = true;
			inst[i] = (const H323PresenceInstruction &)addr;
		}
	}
	if (!found) {
		int sz = inst.GetSize();
		inst.SetSize(sz+1);
		inst[sz] = (const H323PresenceInstruction &)addr;
	}
	return true;
}

bool AddPresenceMap(const H460P_PresenceIdentifier & pid, const H323PresenceID & id, H323PresenceIds & Ids, H323PresenceIdMap & Idmap)
{
	if (!id.m_isSubscriber)
		Ids.insert(pair<H460P_PresenceIdentifier, H323PresenceID>(pid, id));

	H323PresenceIdMap::iterator i = Idmap.find(id.m_subscriber);
	if (i != Idmap.end()) {
		H323PresencePending & pend = i->second;
		pend.insert(pair<H225_AliasAddress, H460P_PresenceIdentifier>(id.m_Alias, pid));
	} else {
		H323PresencePending pend;
		pend.insert(pair<H225_AliasAddress, H460P_PresenceIdentifier>(id.m_Alias, pid));
		Idmap.insert(pair<H225_AliasAddress, H323PresencePending>(id.m_subscriber, pend));
	}

	return true;
}

bool RemovePresenceMap(const H460P_PresenceIdentifier & pid, H323PresenceIds & Ids, H323PresenceIdMap & Idmap)
{
	H323PresenceIds::iterator id = Ids.find(pid);
	if (id != Ids.end()) {
		H323PresenceIdMap::iterator a = Idmap.find(id->second.m_subscriber);
		if (a != Idmap.end()) {
			Idmap.erase(a);
		}
		H323PresenceIdMap::iterator b = Idmap.find(id->second.m_Alias);
		if (b != Idmap.end()) {
			Idmap.erase(b);
		}
		Ids.erase(id);
		return true;
	}
	return false;
}


H460P_PresenceIdentifier & AsPresenceId(const PString & id)
{
	H460P_PresenceIdentifier pid;
	OpalGloballyUniqueID uid(id);
	pid.m_guid.SetValue(uid);
	return *(H460P_PresenceIdentifier *)pid.Clone();
}

PString AsPresenceString(const H460P_PresenceIdentifier & pid)
{
	OpalGloballyUniqueID uid(pid.m_guid);
	return uid.AsString();
}

bool IsLocalPresence(const H225_AliasAddress & alias, const H323PresenceStore & store)
{
	H323PresenceStore::const_iterator itx = store.find(alias);
	return (itx != store.end());
}

bool IsLocalAvailable(const H225_AliasAddress & alias, const H323PresenceAlias & aliasList)
{
	H323PresenceAlias::const_iterator itx = aliasList.find(alias);
	return (itx != aliasList.end());
}

PString PresMsgType(unsigned tag)
{
	switch (tag) {
		case H460P_PresencePDU::e_instruction:
			return PString("Instruction");
		case H460P_PresencePDU::e_notification:
			return PString("Notification");
		case H460P_PresencePDU::e_subscription:
			return PString("Subscription");
		case H460P_PresencePDU::e_identifier:
			return PString("Identifier");
		default:
			return "Unknown";
	};
}

//////////////////////////////////////////////////////

GkPresence::GkPresence()
 : m_enabled(false), m_sqlactive(false), m_worker(NULL)
#if HAS_DATABASE
	, m_sqlConn(NULL), m_timeout(-1)
#endif
{
}

GkPresence::~GkPresence()
{
	if (m_worker)
		m_worker->Close();
}

bool GkPresence::IsEnabled() const
{
	return m_enabled;
}

void GkPresence::LoadConfig(PConfig * cfg)
{
	m_enabled = cfg->GetBoolean("RoutedMode", "EnableH460P", 0);
	if (!m_enabled)
		return;

#if HAS_DATABASE
	delete m_sqlConn;
	PString authName = "GkPresence::SQL";

   if (cfg->GetSections().GetStringsIndex(authName) == P_MAX_INDEX)
		return;

	const PString driverName = cfg->GetString(authName, "Driver", "");
	if (driverName.IsEmpty()) {
		PTRACE(0, "H460PSQL\tModule creation failed: "
			"no SQL driver selected"
			);
		PTRACE(0, "H460PSQL\tFATAL: Shutting down");
		return;
	}
	
	m_sqlConn = GkSQLConnection::Create(driverName, "GkPresence");
	if (m_sqlConn == NULL) {
		PTRACE(0, "H460PSQL\tModule creation failed: "
			"Could not find " << driverName << " database driver"
			);
		PTRACE(0, "H460PSQL\tFATAL: Shutting down");
		return;
	}
		
	m_queryList = cfg->GetString(authName, "QueryList", "");
	if (m_queryList.IsEmpty()) {
		PTRACE(0, "H460PSQL\tModule creation failed: No QueryList configured"
			);
		PTRACE(0, "H460PSQL\tFATAL: Shutting down");
		return;
	} else
		PTRACE(4, "H460PSQL\tQuerylist: " << m_queryList);

	m_queryAdd = cfg->GetString(authName, "QueryAdd", "");
	if (m_queryAdd.IsEmpty()) {
		PTRACE(0, "H460PSQL\tModule creation failed: No QueryAdd configured"
			);
		PTRACE(0, "H460PSQL\tFATAL: Shutting down");
		return;
	} else
		PTRACE(4, "H460PSQL\tQueryAdd: " << m_queryAdd);

	m_queryDelete = cfg->GetString(authName, "QueryDelete", "");
	if (m_queryDelete.IsEmpty()) {
		PTRACE(0, "H460PSQL\tModule creation failed: No QueryDelete configured"
			);
		PTRACE(0, "H460PSQL\tFATAL: Shutting down");
		return;
	} else
		PTRACE(4, "H460PSQL\tQueryDelete: " << m_queryDelete);

	m_queryUpdate = cfg->GetString(authName, "QueryUpdate", "");
	if (m_queryUpdate.IsEmpty()) {
		PTRACE(0, "H460PSQL\tModule creation failed: No QueryUpdate configured"
			);
		PTRACE(0, "H460PSQL\tFATAL: Shutting down");
		return;
	} else
		PTRACE(4, "H460PSQL\tQueryUpdate: " << m_queryUpdate);

	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(0, "H460PSQL\tModule creation failed: Could not connect to the database"
			);
		return;
	}

	m_sqlactive = DatabaseLoad();
#endif

	if (!m_sqlactive) {
		PTRACE(1, "H460P\tNo backend database support. Please recompile GnuGk with database support.");
		return;
	}

	m_worker = new PresWorker(this, cfg->GetInteger("RoutedMode", "H460PActThread", DEFAULT_PRESWORKER_TIMER)*1000);
}

bool GkPresence::DatabaseLoad()
{
#ifdef HAS_DATABASE
	GkSQLResult::ResultRow resultRow;
	std::map<PString, PString> params;
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_queryList,params, m_timeout);
	if (result == NULL) {
		PTRACE(2, "H460PSQL\tSubList failed - timeout or fatal error");
		return false;
	}
	if (result->GetNumRows() > 0 && result->GetNumFields() < 7) {
		PTRACE(2, "H460PSQL\tBad-formed query - "
			"insufficient columns found in the result set expect 7"
			);
		return false;
	}
	if (result->GetNumRows() == 0) {
		PTRACE(2, "H460PSQL\tDatabase returns 0 entries, assume table is empty.");
		return true;
	}

	// Clear the cache.
	localStore.clear();
	remoteIds.clear();
	remoteIdmap.clear();

	PStringArray retval;
	while (result->FetchRow(retval)) {
		if (retval[0].IsEmpty()) {
			PTRACE(1, "H460PSQL\tQuery Invalid value found.");
			continue;
		}
		PTRACE(6, "H460PSQL\tQuery result: " << retval[0] << " " << retval[1]
								    << " " << retval[2] << " " << retval[3]
									<< " " << retval[4] << " " << retval[5]
									<< " " << retval[6] << " " << retval[7]
									);

									
		H460P_PresenceIdentifier & pid = AsPresenceId(retval[0]);

		H323PresenceID id;
			H323SetAliasAddress(retval[1], id.m_subscriber);
			H323SetAliasAddress(retval[2], id.m_Alias);
			id.m_isSubscriber = Toolkit::AsBool(retval[3]);
			id.m_Status = (H323PresenceInstruction::Instruction)retval[4].AsInteger();
			id.m_Active = Toolkit::AsBool(retval[5]);
			id.m_Updated = PTime(retval[6]);
		
		// Load the local Store with active or subscriber pending subscriptions
		if (id.m_Active || (id.m_isSubscriber && (id.m_Status == H323PresenceInstruction::e_pending))) {
			H323PresenceStore::iterator itx = localStore.find(id.m_subscriber);
			if (itx != localStore.end()) {
				if (id.m_subscriber != id.m_Alias) {
					H323PresenceInstruction instruct(id.m_Status, retval[2]);
					itx->second.m_Instruction.Add(instruct);
				}
			} else {
				H323PresenceEndpoint store;
				store.m_Notify.SetSize(1);
				if (id.m_subscriber != id.m_Alias) {
					H323PresenceInstruction instruct(id.m_Status, retval[2]);
					store.m_Instruction.Add(instruct);
				}
				localStore.insert(pair<H225_AliasAddress,H323PresenceEndpoint>(id.m_subscriber,store));
			}
		}

		if (id.m_subscriber == id.m_Alias)
			continue;

		// Load the identifier store
		AddPresenceMap(pid,id,remoteIds,remoteIdmap);
	}
	delete result;

	return true;
#else
	return false;
#endif
}

bool GkPresence::DatabaseAdd(const PString & identifier, const H323PresenceID & id)
{
#ifdef HAS_DATABASE
	if (!m_sqlConn)
		return false;

	GkSQLResult::ResultRow resultRow;
	std::map<PString, PString> params;
	params["i"] = identifier;
	params["u"] = AsString(id.m_subscriber,0);
	params["a"] = AsString(id.m_Alias,0);
	params["s"] = (id.m_isSubscriber ? "1" : "0");

	return (m_sqlConn->ExecuteQuery(m_queryAdd, params, m_timeout) != NULL);
#else
	return false;
#endif
}
	
bool GkPresence::DatabaseDelete(const PString & identifier)
{
#ifdef HAS_DATABASE
	if (!m_sqlConn)
		return false;

	GkSQLResult::ResultRow resultRow;
	std::map<PString, PString> params;
	params["i"] = identifier;

	return (m_sqlConn->ExecuteQuery(m_queryDelete, params, m_timeout) != NULL);
#else
	return false;
#endif
}

bool GkPresence::DatabaseUpdate(unsigned tag, const PString & identifier)
{
#ifdef HAS_DATABASE
	if (!m_sqlConn)
		return false;

	GkSQLResult::ResultRow resultRow;
	std::map<PString, PString> params;
	params["i"] = identifier;
	params["b"] = tag;
	
	return (m_sqlConn->ExecuteQuery(m_queryUpdate, params, m_timeout) != NULL);
#else
	return false;
#endif
}

bool GkPresence::HandleNewAlias(const H225_AliasAddress & addr)
{
	OpalGloballyUniqueID uid;

	H323PresenceID id;
		id.m_subscriber = addr;
		id.m_Alias = addr;
		id.m_Active = true;
		id.m_isSubscriber = true;

	DatabaseAdd(uid.AsString(),id);
    DatabaseUpdate(H323PresenceInstruction::e_subscribe,uid.AsString());

	// load the cache with empty store
	H323PresenceEndpoint store;
	localStore.insert(pair<H225_AliasAddress,H323PresenceEndpoint>(addr,store));
	return true;
}

H460P_PresenceSubscription & GkPresence::HandleSubscription(bool isNew, const H460P_PresenceIdentifier & pid, const H323PresenceID & id)
{
	if (isNew)
		HandleStatusUpdates(pid, id.m_subscriber, e_pending, id.m_Alias, &id);

	H460P_PresencePDU msg;
    H460P_PresenceSubscription & sub = BuildSubscriptionMsg(pid.m_guid,id.m_Alias,id.m_subscriber,msg);
	EnQueuePresence(id.m_subscriber,msg);
	return *(H460P_PresenceSubscription *)sub.Clone();
}

bool GkPresence::RegisterEndpoint(const H225_EndpointIdentifier & ep, const H225_ArrayOf_AliasAddress & addr)
{
	PWaitAndSignal m(m_AliasMutex);

	for (PINDEX j = 0; j < addr.GetSize(); j++) {
		// register the endpoint as being at this endpoint identifier
		H323PresenceAlias::iterator it = aliasList.find(addr[j]);
		if (it == aliasList.end())
			aliasList.insert(pair<H225_AliasAddress,H225_EndpointIdentifier>(addr[j],ep));
			
		// handle subscriptions/notifications from local store
		H323PresenceStore::iterator itx = localStore.find(addr[j]);
		if (itx == localStore.end()) {
			PTRACE(4, "H460PSQL\tNo Information for " << addr[j] << " assume new alias");
			HandleNewAlias(addr[j]);
			continue;
		}

		// Queue up any notifications of existing registrations
		for (PINDEX i=0; i< itx->second.m_Instruction.GetSize(); i++) {
		   // Queue up info from the datastore to supply to the endpoint
			H460P_PresencePDU msg;
			BuildInstructionMsg(itx->second.m_Instruction[i],msg);
			EnQueuePresence(addr[j],msg);

			// look in the local store to see if we can send presence info to people logged in.
			if ((itx->second.m_Instruction[i].GetTag() == e_subscribe) &&
										(IsLocalAvailable(itx->second.m_Instruction[i],aliasList)))
						EnQueueFullNotification(itx->second.m_Instruction[i],addr[j]);
		}

		// Check for pending subscriptions
		list<H460P_PresenceIdentifier> plist;
		if (GetLocalSubscriptions(addr[j],plist)) {
			list<H460P_PresenceIdentifier>::iterator i = plist.begin();
			while (i != plist.end()) {
				H323PresenceID local;
				if (GetSubscription(*i,local) && (local.m_subscriber == addr[j]) && !local.m_Active) {
					H460P_PresenceSubscription & sub = HandleSubscription(false,*i,local);
					int sz = itx->second.m_Authorize.GetSize();
					itx->second.m_Authorize.SetSize(sz+1);
					itx->second.m_Authorize[sz] = (H323PresenceSubscription &)sub;
				}
				i++;
			}
		}		
	}
	return true;
}

void GkPresence::UnRegisterEndpoint(const H225_ArrayOf_AliasAddress & addr)
{
	PWaitAndSignal m(m_AliasMutex);

	H460P_PresencePDU msg;
	msg.SetTag(H460P_PresencePDU::e_notification);
	H460P_PresenceNotification & n = msg;
	n.m_presentity.m_state = H460P_PresenceState::e_offline;

	for (PINDEX i=0; i < addr.GetSize(); i++) {
		// Send Notification
		OnNotification(H323PresenceHandler::e_Status, n, addr[i]);

		H323PresenceAlias::iterator it = aliasList.find(addr[i]);
		if (it != aliasList.end())
			aliasList.erase(it);
	}	
}

bool GkPresence::GetPendingIdentifiers(list<H225_EndpointIdentifier> & epid)
{
	PWaitAndSignal m(m_AliasMutex);

	H323PresenceLocal::const_iterator i = pendingStore.begin();
	while (i != pendingStore.end()) {
		epid.push_back(i->first);
		i++;
	}
	return (!epid.empty());
}

bool GkPresence::GetPendingAddresses(list<H225_TransportAddress> & gkip)
{
	PWaitAndSignal m(m_AliasMutex);

	H323PresenceRemote::const_iterator i = remoteStore.begin();
	while (i != remoteStore.end()) {
		gkip.push_back(i->first);
		i++;
	}
	return (!gkip.empty());
}

bool GkPresence::GetSubscriptionIdentifier(const H225_AliasAddress & local, const H225_AliasAddress & remote, H460P_PresenceIdentifier & id)
{
	 H323PresenceIdMap::const_iterator i = remoteIdmap.find(local);
	 if (i != remoteIdmap.end()) {
		 H323PresencePending::const_iterator j = i->second.find(local);
		 if (j != i->second.end()) {
			id = j->second;
			return true;
		 }
	 }
	 return false;
}

bool GkPresence::GetLocalSubscriptions(const H225_AliasAddress & local, list<H460P_PresenceIdentifier> & id)
{
	 H323PresenceIdMap::const_iterator i = remoteIdmap.find(local);
	 if (i != remoteIdmap.end()) {
		H323PresencePending::const_iterator j = i->second.begin();
		while (j != i->second.end()) {
			id.push_back(j->second);
			j++;
		}
	    return true;
	 }
	return false;
}

bool GkPresence::GetSubscription(const H460P_PresenceIdentifier & id, H323PresenceID & local)
{
	H323PresenceIds::const_iterator i = remoteIds.find(id);
	if (i != remoteIds.end()) {
		local = i->second;
		return true;
	}
	return false;
}

void GkPresence::ProcessPresenceElement(const PASN_OctetString & pdu)
{
	PWaitAndSignal m(m_AliasMutex);

	if (!ReceivedPDU(pdu)) {
		PTRACE(4,"H460P\tError processing PDU");
	}
}

void GkPresence::ProcessPresenceElement(const PASN_OctetString & pdu, const H225_TransportAddress & ip)
{
	PWaitAndSignal m(m_AliasMutex);

	if (!ReceivedPDU(pdu)) {
		PTRACE(4,"H460P\tError processing PDU");
	}
}


bool GkPresence::BuildPresenceElement(unsigned msgtag, const H225_EndpointIdentifier & ep, PASN_OctetString & pdu)
{
	PWaitAndSignal m(m_AliasMutex);

	return H323PresenceHandler::BuildPresenceElement(msgtag, ep, pdu);
}

bool GkPresence::BuildPresenceElement(unsigned msgtag, const H225_TransportAddress & ip, PASN_OctetString & pdu)
{
	PWaitAndSignal m(m_AliasMutex);

	return H323PresenceHandler::BuildPresenceElement(msgtag, ip, pdu);
}

bool GkPresence::EnQueueFullNotification(const H225_AliasAddress & local, const H225_AliasAddress & remote)
{
    H323PresenceStore::const_iterator itm = localStore.find(local);
	if (itm != localStore.end()) {
		H460P_PresencePDU msg;
		H460P_PresenceNotification & notification = BuildNotificationMsg(itm->second.m_Notify[0],msg);
		notification.IncludeOptionalField(H460P_PresenceNotification::e_aliasAddress);
		notification.m_aliasAddress = local;
		EnQueuePresence(remote,msg);
		return true;
	}
	return false;
}

bool GkPresence::EnQueuePresence(const H225_AliasAddress & addr, const H460P_PresencePDU & msg)
{
	// Check if the alias is registered locally
	H323PresenceAlias::iterator it = aliasList.find(addr);
	if (it != aliasList.end()) {
		H323PresenceLocal::iterator itx = pendingStore.find(it->second);
		if (itx != pendingStore.end()) {
			H323PresenceInd & xlist = itx->second;
			H323PresenceInd::iterator pi = xlist.find(addr);
			if (pi != xlist.end())
			    pi->second.push_back(msg);
			else {
				list<H460P_PresencePDU> m_Indication;
				m_Indication.push_back(msg);
				xlist.insert(pair<H225_AliasAddress,list<H460P_PresencePDU> >(addr,m_Indication));
			}
		} else {
			list<H460P_PresencePDU> m_Indication;
			m_Indication.push_back(msg);
			H323PresenceInd xlist;
			xlist.insert(pair<H225_AliasAddress,list<H460P_PresencePDU> >(addr,m_Indication));	
			pendingStore.insert(pair<H225_EndpointIdentifier,H323PresenceInd>(it->second,xlist));
		}
		return true;
	}
	
	// check if the alias is registered remotely
	H323PresenceExternal::iterator rt = remoteList.find(addr);
	if (rt != remoteList.end()) {
		H323PresenceRemote::iterator rtx = remoteStore.find(rt->second);
		if (rtx != remoteStore.end()) {
			H323PresenceInd & xlist = rtx->second;
			H323PresenceInd::iterator pi = xlist.find(addr);
			if (pi != xlist.end())
			    pi->second.push_back(msg);
			else {
				list<H460P_PresencePDU> m_Indication;
				m_Indication.push_back(msg);
				xlist.insert(pair<H225_AliasAddress,list<H460P_PresencePDU> >(addr,m_Indication));
			}
		} else {
			list<H460P_PresencePDU> m_Indication;
			m_Indication.push_back(msg);
			H323PresenceInd xlist;
			xlist.insert(pair<H225_AliasAddress,list<H460P_PresencePDU> >(addr,m_Indication));	
			remoteStore.insert(pair<H225_TransportAddress,H323PresenceInd>(rt->second,xlist));
		}
		return true;
	}

	// neither registered remote or locally
	PTRACE(2,"PRES\tPresence " << PresMsgType(msg.GetTag()) << " to " << addr << " dropped as no destination resolved.");
	return false;
}

PBoolean GkPresence::BuildSubscription(const H225_EndpointIdentifier & ep, H323PresenceStore & subscription)
{
	bool found = false;

	H323PresenceLocal::iterator it = pendingStore.find(ep);
	if (it != pendingStore.end())  {
		H323PresenceInd & aliasList = it->second;
		int aliasCount = aliasList.size();
		H323PresenceInd::iterator i = aliasList.begin();
		while (i != aliasList.end()) {
			int pduCount = i->second.size();
			list<H460P_PresencePDU>::iterator j = i->second.begin();
			while (j != i->second.end()) {
				if (j->GetTag() == H460P_PresencePDU::e_subscription) {
					const H460P_PresenceSubscription & n = *j;

					H323PresenceStore::iterator k = subscription.find(i->first);
					if (k == subscription.end())  {
						H323PresenceEndpoint pe;
						pe.m_Authorize.Add((const H323PresenceSubscription &)n);
						subscription.insert(pair<H225_AliasAddress,H323PresenceEndpoint>(i->first,pe));	
					} else
						k->second.m_Authorize.Add((const H323PresenceSubscription &)n);

					i->second.erase(j++);
					pduCount--;
					found = true;
				} else
				    j++;

				if (pduCount == 0) {
					aliasList.erase(i++);
					aliasCount--;
					break;
				}
			}
			if (aliasCount == 0) {
				pendingStore.erase(it);
				break;
			} else if (i == aliasList.end()) {
				break;
			} else if (pduCount > 0)
			    i++;
		}
	}
	return found;
}

PBoolean GkPresence::BuildNotification(const H225_EndpointIdentifier & ep, H323PresenceStore & notify)
{
	bool found = false;

	H323PresenceLocal::iterator it = pendingStore.find(ep);
	if (it != pendingStore.end())  {
		H323PresenceInd & aliasList = it->second;
		int aliasCount = aliasList.size();
		H323PresenceInd::iterator i = aliasList.begin();
		while (i != aliasList.end()) {
			int pduCount = i->second.size();
			list<H460P_PresencePDU>::iterator j = i->second.begin();
			while (j != i->second.end()) {
				if (j->GetTag() == H460P_PresencePDU::e_notification) {
					const H460P_PresenceNotification & n = *j;

					H323PresenceStore::iterator k = notify.find(i->first);
					if (k == notify.end())  {
						H323PresenceEndpoint pe;
						pe.m_Notify.Add((const H323PresenceNotification &)n);
						notify.insert(pair<H225_AliasAddress,H323PresenceEndpoint>(i->first,pe));	
					} else
						k->second.m_Notify.Add((const H323PresenceNotification &)n);

					i->second.erase(j++);
					pduCount--;
					found = true;
				} else
				    j++;

				if (pduCount == 0) {
					aliasList.erase(i++);
					aliasCount--;
					break;
				}
			}
			if (aliasCount == 0) {
				pendingStore.erase(it);
				break;
			} else if (i == aliasList.end()) {
				break;
			} else if (pduCount > 0)
			    i++;
		}
	}
	return found;
}

PBoolean GkPresence::BuildInstructions(const H225_EndpointIdentifier & ep, H323PresenceStore & instruction)
{
	bool found = false;

	H323PresenceLocal::iterator it = pendingStore.find(ep);
	if (it != pendingStore.end())  {
		H323PresenceInd & aliasList = it->second;
		int aliasCount = aliasList.size();
		H323PresenceInd::iterator i = aliasList.begin();
		while (i != aliasList.end()) {
			int pduCount = i->second.size();
			list<H460P_PresencePDU>::iterator j = i->second.begin();
			while (j != i->second.end()) {
				if (j->GetTag() == H460P_PresencePDU::e_instruction) {
					const H460P_PresenceInstruction & n = *j;

					H323PresenceStore::iterator k = instruction.find(i->first);
					if (k == instruction.end())  {
						H323PresenceEndpoint pe;
						pe.m_Instruction.Add((const H323PresenceInstruction &)n);
						instruction.insert(pair<H225_AliasAddress,H323PresenceEndpoint>(i->first,pe));	
					} else
						k->second.m_Instruction.Add((const H323PresenceInstruction &)n);

					i->second.erase(j++);
					pduCount--;
					found = true;
				} else
				    j++;

				if (pduCount == 0) {
					aliasList.erase(i++);
					aliasCount--;
					break;
				}
			}
			if (aliasCount == 0) {
				pendingStore.erase(it);
				break;
			} else if (i == aliasList.end()) {
				break;
			} else if (pduCount > 0)
			    i++;
		}
	}
	return found;
}

PBoolean GkPresence::BuildSubscription(bool request, const H225_TransportAddress & ip, H323PresenceGkStore & subscription)
{
	bool found = false;

	H323PresenceRemote::iterator it = remoteStore.find(ip);
	if (it != remoteStore.end())  {
		H323PresenceInd & IPList = it->second;
		int IPCount = IPList.size();
		H323PresenceInd::iterator i = IPList.begin();
		while (i != IPList.end()) {
			int pduCount = i->second.size();
			list<H460P_PresencePDU>::iterator j = i->second.begin();
			while (j != i->second.end()) {
				if (j->GetTag() == H460P_PresencePDU::e_subscription) {
					const H460P_PresenceSubscription & n = *j;
					if (n.HasOptionalField(H460P_PresenceSubscription::e_approved) != request) {
						H323PresenceGkStore::iterator k = subscription.find(i->first);
						if (k == subscription.end())  {
							H323PresenceEndpoint pe;
							pe.m_Authorize.Add((const H323PresenceSubscription &)n);
							subscription.insert(pair<H225_TransportAddress,H323PresenceEndpoint>(ip,pe));	
						} else
							k->second.m_Authorize.Add((const H323PresenceSubscription &)n);

						i->second.erase(j++);
						pduCount--;
						found = true;
					}
				} else
				    j++;

				if (pduCount == 0) {
					IPList.erase(i++);
					IPCount--;
					break;
				}
			}
			if (IPCount == 0) {
				remoteStore.erase(it);
				break;
			} else if (i == IPList.end()) {
				break;
			} else if (pduCount > 0)
			    i++;
		}
	}
	return found;
}

PBoolean GkPresence::BuildNotification(const H225_TransportAddress & ip, H323PresenceGkStore & notify)
{
	bool found = false;

	H323PresenceRemote::iterator it = remoteStore.find(ip);
	if (it != remoteStore.end())  {
		H323PresenceInd & IPList = it->second;
		int IPCount = IPList.size();
		H323PresenceInd::iterator i = IPList.begin();
		while (i != IPList.end()) {
			int pduCount = i->second.size();
			list<H460P_PresencePDU>::iterator j = i->second.begin();
			while (j != i->second.end()) {
				if (j->GetTag() == H460P_PresencePDU::e_notification) {
					const H460P_PresenceNotification & n = *j;
					H323PresenceGkStore::iterator k = notify.find(i->first);
					if (k == notify.end())  {
						H323PresenceEndpoint pe;
						pe.m_Notify.Add((const H323PresenceNotification &)n);
						notify.insert(pair<H225_TransportAddress,H323PresenceEndpoint>(ip,pe));	
					} else
						k->second.m_Notify.Add((const H323PresenceNotification &)n);

					i->second.erase(j++);
					pduCount--;
					found = true;
				} else
				    j++;

				if (pduCount == 0) {
					IPList.erase(i++);
					IPCount--;
					break;
				}
			}
			if (IPCount == 0) {
				remoteStore.erase(it);
				break;
			} else if (i == IPList.end()) {
				break;
			} else if (pduCount > 0)
			    i++;
		}
	}
	return found;
}

PBoolean GkPresence::BuildIdentifiers(bool alive, const H225_TransportAddress & ip, H323PresenceGkStore & identifiers)
{
	bool found = false;

	H323PresenceRemote::iterator it = remoteStore.find(ip);
	if (it != remoteStore.end())  {
		H323PresenceInd & IPList = it->second;
		int IPCount = IPList.size();
		H323PresenceInd::iterator i = IPList.begin();
		while (i != IPList.end()) {
			int pduCount = i->second.size();
			list<H460P_PresencePDU>::iterator j = i->second.begin();
			while (j != i->second.end()) {
				if (j->GetTag() == H460P_PresencePDU::e_identifier) {
					const H460P_PresenceIdentifier & n = *j;
					if (n.HasOptionalField(H460P_PresenceIdentifier::e_remove) != alive) {
						H323PresenceGkStore::iterator k = identifiers.find(i->first);
						if (k == identifiers.end())  {
							H323PresenceEndpoint pe;
							pe.m_Identifiers.Add(n.m_guid);
							identifiers.insert(pair<H225_TransportAddress,H323PresenceEndpoint>(ip,pe));	
						} else
							k->second.m_Identifiers.Add(n.m_guid);

						i->second.erase(j++);
						pduCount--;
						found = true;
					}
				} else
				    j++;

				if (pduCount == 0) {
					IPList.erase(i++);
					IPCount--;
					break;
				}
			}
			if (IPCount == 0) {
				remoteStore.erase(it);
				break;
			} else if (i == IPList.end()) {
				break;
			} else if (pduCount > 0)
			    i++;
		}
	}
	return found;
}

void UpdateLocalPresence(H460P_PresenceNotification & local, const H460P_PresenceNotification & received)
{
	H460P_Presentity & l = local.m_presentity;
	const H460P_Presentity & r = received.m_presentity;

	l.m_state = r.m_state;
	if (r.HasOptionalField(H460P_Presentity::e_supportedFeatures)) {
		l.IncludeOptionalField(H460P_Presentity::e_supportedFeatures);
		l.m_supportedFeatures = r.m_supportedFeatures;
	}
	if (r.HasOptionalField(H460P_Presentity::e_geolocation)) {
		l.IncludeOptionalField(H460P_Presentity::e_geolocation);
		l.m_geolocation = r.m_geolocation;
	}
	if (r.HasOptionalField(H460P_Presentity::e_display)) {
		l.IncludeOptionalField(H460P_Presentity::e_display);
		l.m_display = r.m_display;
	}
	if (r.HasOptionalField(H460P_Presentity::e_genericData)) {
		l.IncludeOptionalField(H460P_Presentity::e_genericData);
		bool found;
		for (PINDEX i=0; i < r.m_genericData.GetSize(); ++i) {
		   found = false;
			for (PINDEX j=0; i < l.m_genericData.GetSize(); ++j) {
				if (r.m_genericData[i].m_id == l.m_genericData[j].m_id) {
					l.m_genericData[j] = r.m_genericData[i];
					found = true;
					break;
				}
			}
			if (!found) {
				int sz = l.m_genericData.GetSize();
				l.m_genericData.SetSize(sz+1);
				l.m_genericData[sz] = r.m_genericData[i];
			}
		}
	}
}

bool GkPresence::HandleStatusUpdates(const H460P_PresenceIdentifier & pid, const H225_AliasAddress & local,
									 unsigned type, const H225_AliasAddress & remote,
									 const H323PresenceID * id)
{
		H460P_PresencePDU msg;
		H460P_PresenceInstruction & inst = BuildInstructionMsg(type,remote,msg);

		PString spid = AsPresenceString(pid);

		H323PresenceStore::iterator it = localStore.find(local);
		if (it != localStore.end()) {
			switch (type) {
			  case H460P_PresenceInstruction::e_subscribe:
				  DatabaseUpdate(type,spid);
				  UpdateInstruction(inst,it->second.m_Instruction);
				  break;

			  case H460P_PresenceInstruction::e_unsubscribe:
				  DatabaseDelete(spid);
				  RemovePresenceMap(pid, remoteIds, remoteIdmap);
				  RemoveInstruction(remote,it->second.m_Instruction);
				  break;

			  case H460P_PresenceInstruction::e_block:
				  if (id) {
					DatabaseAdd(spid,*id);
					DatabaseUpdate(type,AsPresenceString(pid));
					AddPresenceMap(pid, *id, remoteIds, remoteIdmap);
					UpdateInstruction(inst,it->second.m_Instruction);
				  }
				  break;

			  case H460P_PresenceInstruction::e_unblock:
				  DatabaseDelete(spid);
				  RemovePresenceMap(pid, remoteIds, remoteIdmap);
  				  RemoveInstruction(remote,it->second.m_Instruction);
				  break;

			  case H460P_PresenceInstruction::e_pending:
				  if (id) {
					  DatabaseAdd(spid,*id);
					  AddPresenceMap(pid, *id, remoteIds, remoteIdmap);
					  UpdateInstruction(inst,it->second.m_Instruction);
				  }
				  break;
			}
		}

		PTRACE(4,"PRES\tChanged Subscription for " << local << " : " << PresMsgType(type) <<  " " << remote);

		if (!IsLocalAvailable(local,aliasList))
			return true;
		else
			return EnQueuePresence(local,msg);
}

bool GkPresence::HandleForwardPresence(const H460P_PresenceIdentifier & identifier, const H460P_PresencePDU & msg)
{
	H323PresenceLRQRelay::const_iterator itx = remoteRelay.find(identifier);
	if (itx != remoteRelay.end()) {
		list<H460P_PresencePDU> m_Indication;
		m_Indication.push_back(msg);
		H323PresenceInd xlist;
		H225_AliasAddress a;
		H323SetAliasAddress(PString("Relay"),a);
		PTRACE(5,"PRES\tRelaying Identifier " << identifier << " to " << itx->second);
		xlist.insert(pair<H225_AliasAddress,list<H460P_PresencePDU> >(a,m_Indication));	
		remoteStore.insert(pair<H225_TransportAddress,H323PresenceInd>(itx->second,xlist));
		return true;
	}
	return false;
}

bool GkPresence::HandleSubscriptionLocal(const H460P_PresenceSubscription & subscription, bool & approved)
{
	// need to find the local alias
	approved = false;
	H323PresenceIds::const_iterator it = remoteIds.find(subscription.m_identifier);
	if (it != remoteIds.end()) {
		if (!subscription.HasOptionalField(H460P_PresenceSubscription::e_approved)) {
			PTRACE(4,"PRES\tLOGIC ERROR: Received a subscription reply but not subscriber and no approval indication");
			return false;
		}
		approved = subscription.m_approved;
		if (approved) {
			HandleStatusUpdates(subscription.m_identifier, it->second.m_subscriber, e_subscribe, it->second.m_Alias);
			if (IsLocalAvailable(it->second.m_subscriber,aliasList))
				EnQueueFullNotification(it->second.m_subscriber,it->second.m_Alias);
		} else
			RemoveSubscription(e_unsubscribe,subscription.m_identifier);

		return true;
	}

	H323PresenceStore::iterator itx = localStore.find(subscription.m_subscribe);
	if (itx != localStore.end()) {
		itx->second.m_Authorize.Add((H323PresenceSubscription &)subscription);
		H323PresenceID id;
			id.m_subscriber = subscription.m_subscribe;
			id.m_Alias = subscription.m_aliases[0];
			id.m_Active = false;
			id.m_isSubscriber = false;
		HandleSubscription(true,subscription.m_identifier,id);
		return true;
	}
	return false;
}

bool GkPresence::RemoveSubscription(unsigned type,const H460P_PresenceIdentifier & pid)
{
	H323PresenceIds::iterator it = remoteIds.find(pid);
	if (it != remoteIds.end()) {
		H323PresenceStore::iterator it1 = localStore.find(it->second.m_subscriber);
		if (it1 != localStore.end())
			HandleStatusUpdates(pid,it->second.m_subscriber, type, it->second.m_Alias);

		H323PresenceStore::iterator it2 = localStore.find(it->second.m_Alias);
		if (it2 != localStore.end())
			HandleStatusUpdates(pid,it->second.m_Alias,type,it->second.m_subscriber);

	   PTRACE(4,"PRES\tRemoved Subscription " << PresMsgType(type) << " : " << it->second.m_subscriber << " to " << it->second.m_Alias);
	   return true;
	}
	return false;
}

bool GkPresence::HandleNewInstruction(unsigned tag, const H225_AliasAddress & addr,
									  const H460P_PresenceInstruction & instruction, H323PresenceInstructions & instructions)
{

	const H225_AliasAddress & a = instruction;

	if (a == addr)
		return true;

	// Check to see if we already have this instruction
	for (PINDEX i=0; i< instructions.GetSize(); i++) {
		H225_AliasAddress & b = instructions[i];
		if (a == b) {
			if (instruction.GetTag() == instructions[i].GetTag())
				return true;

			if (instruction.GetTag() == H460P_PresenceInstruction::e_unsubscribe) {
				H460P_PresenceIdentifier pid;
				if (GetSubscriptionIdentifier(addr, a, pid))
					return RemoveSubscription(tag,pid);
			}
			if (instruction.GetTag() == H460P_PresenceInstruction::e_unblock) {
				H460P_PresenceIdentifier pid;
				if (GetSubscriptionIdentifier(addr, a, pid))
					return HandleStatusUpdates(pid, addr, e_unblock, a);
			}
			PTRACE(4,"PRES\tPresence Instruction : " << instruction << " from " << addr << " not handled!");
			return false;
		}
	}

	  if ((tag == H460P_PresenceInstruction::e_subscribe) ||
		   (tag == H460P_PresenceInstruction::e_block)) {
			OpalGloballyUniqueID uid;
			H460P_PresenceIdentifier pid;
			pid.m_guid = uid;

			H323PresenceID idx;
			idx.m_Updated = PTime();
			idx.m_Active = false;

			if ((tag == H460P_PresenceInstruction::e_subscribe)) {
				//Build Remote Subscription message
					idx.m_isSubscriber = false;
					idx.m_subscriber = a;
					idx.m_Alias = addr;
				HandleSubscription(true,pid,idx);

				//Build local side
				idx.m_isSubscriber = true;
				idx.m_subscriber = addr;
				idx.m_Alias = a;
				HandleStatusUpdates(pid, addr, e_pending, a, &idx);
			}

			if ((tag == H460P_PresenceInstruction::e_block)) {
				idx.m_isSubscriber = true;
				idx.m_subscriber = addr;
				idx.m_Alias = a;
				HandleStatusUpdates(pid, addr, e_block, a, &idx);
			}
			int sz = instructions.GetSize();
			instructions.SetSize(sz+1);
			instructions[sz] = (const H323PresenceInstruction &)instruction;
	  }
	  return true;
}

void GkPresence::OnNotification(MsgType tag, const H460P_PresenceNotification & notify, const H225_AliasAddress & addr)
{
	if (tag == e_Status) {
		// Update the local Store
		H323PresenceStore::iterator itx = localStore.find(addr);
		if (itx != localStore.end()) {
			H323PresenceEndpoint & ep = itx->second;
			ep.m_Notify.SetSize(1);
			UpdateLocalPresence(ep.m_Notify[0], notify);

			for (PINDEX i=0; i < ep.m_Instruction.GetSize(); i++) {
				if (ep.m_Instruction[i].GetTag() == H460P_PresenceInstruction::e_subscribe) {
					H225_AliasAddress & a = ep.m_Instruction[i];
					H460P_PresencePDU msg;
					H460P_PresenceNotification & notification = BuildNotificationMsg(notify,msg);
					notification.IncludeOptionalField(H460P_PresenceNotification::e_aliasAddress);
					notification.m_aliasAddress = addr;
					EnQueuePresence(a,msg);
				}
			}
		}
	}
}

void GkPresence::OnInstructions(MsgType tag, const H460P_ArrayOf_PresenceInstruction & instruction, const H225_AliasAddress & addr)
{
	// Load the local Store for this alias
	H323PresenceStore::iterator itx = localStore.find(addr);
	if (itx != localStore.end()) {
		H323PresenceEndpoint & ep = itx->second;
		for (PINDEX i=0; i<instruction.GetSize(); i++) {
			HandleNewInstruction(instruction[i].GetTag(), addr, instruction[i], ep.m_Instruction);
		}
	}
}

void GkPresence::OnSubscription(MsgType tag, const H460P_PresenceSubscription & subscription, const H225_AliasAddress & addr)
{
	bool approved = false;
	if (!HandleSubscriptionLocal(subscription,approved)) {
		H460P_PresencePDU msg;
		BuildSubscriptionMsg(subscription,msg);
		if (!HandleForwardPresence(subscription.m_identifier, msg)) {
			PTRACE(2,"PRES\tSubscription received " << subscription.m_identifier.m_guid << " from " << AsString(addr,0) << " not handled");
			return;
		}
	}

	// Handle the senders side
	for (PINDEX i=0; i<subscription.m_aliases.GetSize(); i++) {
		if (IsLocalPresence(subscription.m_aliases[i],localStore)) {
			if (approved) {
				HandleStatusUpdates(subscription.m_identifier, subscription.m_aliases[i], e_subscribe, subscription.m_subscribe);
				if (IsLocalAvailable(subscription.m_aliases[i],aliasList))
					EnQueueFullNotification(subscription.m_aliases[i], subscription.m_subscribe);
			} else
				HandleStatusUpdates(subscription.m_identifier, subscription.m_aliases[i], e_unsubscribe, subscription.m_subscribe);
		}
	}
}

// Gatekeepers
void GkPresence::OnNotification(MsgType tag, const H460P_PresenceNotification & notify, const H225_TransportAddress & ip)
{
	if (!notify.HasOptionalField(H460P_PresenceNotification::e_subscribers))
			return;

	for (PINDEX i=0; i<notify.m_subscribers.GetSize(); ++i) {
		// need to find the local alias
		H323PresenceIds::const_iterator it = remoteIds.find(notify.m_subscribers[i]);
		if (it != remoteIds.end()) {
			H225_AliasAddress addr = it->second.m_subscriber;
			PTRACE(5,"PRES\tReceived Notification " << notify.m_subscribers[i] << " for " << addr << " from " << ip);
			H460P_PresencePDU msg;
			H460P_PresenceNotification & notification = BuildNotificationMsg(notify,msg);
			notification.RemoveOptionalField(H460P_PresenceNotification::e_subscribers);
			EnQueuePresence(addr,msg);
		} else {
			// not one of ours see if we are passing on.
			H460P_PresencePDU msg;
			H460P_PresenceNotification & notification = BuildNotificationMsg(notify,msg);
			notification.m_subscribers.SetSize(1);
			notification.m_subscribers[0] = notify.m_subscribers[i];
            if (!HandleForwardPresence(notification.m_subscribers[0], msg)) {
		        PTRACE(4,"PRES\tUnknown Notification received " << notification.m_subscribers[0] << " from " << ip << " disgarding.");
		    }
		}
	}
}

void GkPresence::OnSubscription(MsgType tag,const H460P_PresenceSubscription & subscription,const H225_TransportAddress & ip)
{
	bool approved;
	if (!HandleSubscriptionLocal(subscription,approved)) {
		H460P_PresencePDU msg;
		BuildSubscriptionMsg(subscription,msg);
		if (!HandleForwardPresence(subscription.m_identifier, msg)) {
			PTRACE(4,"PRES\tUnknown Subscription received " << subscription.m_identifier << " from " << ip << " disgarding.");
			return;
		}
	}
}

void GkPresence::OnIdentifiers(MsgType tag, const H460P_PresenceIdentifier & identifier,const H225_TransportAddress & ip)
{
	// Check if the identifier is local
	H323PresenceIds::const_iterator it = remoteIds.find(identifier);
	if (it != remoteIds.end()) {
		H323PresenceID id = it->second;

		if (tag == e_Alive) {
			/// keepAlive
  			PTRACE(5,"PRES\tReceived KeepAlive " << identifier << " for " << id.m_subscriber << " from " << ip);
		}

		if (tag == e_Remove) {
			/// Remove Subscription
			HandleStatusUpdates(identifier, id.m_subscriber, e_unsubscribe, id.m_Alias);
		}

	} else {
		// not one of ours see if we are passing on.
		H460P_PresencePDU msg;
		BuildIdentifierMsg(identifier,msg);
		if (!HandleForwardPresence(identifier, msg)) {
			PTRACE(4,"PRES\tUnknown Identifier received " << identifier << " from " << ip << " disgarding.");
		}
	}
}
#endif


