
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


#include "h460presence.h"

#ifdef HAS_H460P

#ifdef HAS_DATABASE
#include "gksql.h"
#endif
#include "h323util.h"


GkPresence::GkPresence()
 : m_enabled(false), m_sqlactive(false), m_sqlConn(NULL)
{
}

bool GkPresence::IsEnabled() const
{
	return m_enabled;
}

void GkPresence::LoadConfig(PConfig * cfg)
{
	m_enabled = cfg->GetBoolean("RoutedMode", "EnableH460P", 0);

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

	m_queryPost = cfg->GetString(authName, "QueryPost", "");
	if (m_queryPost.IsEmpty()) {
		PTRACE(0, "H460PSQL\tModule creation failed: No QueryPost configured"
			);
		PTRACE(0, "H460PSQL\tFATAL: Shutting down");
		return;
	} else
		PTRACE(4, "H460PSQL\tQuerylist: " << m_queryPost);

	m_queryDelete = cfg->GetString(authName, "QueryDelete", "");
	if (m_queryDelete.IsEmpty()) {
		PTRACE(0, "H460PSQL\tModule creation failed: No QueryDelete configured"
			);
		PTRACE(0, "H460PSQL\tFATAL: Shutting down");
		return;
	} else
		PTRACE(4, "H460PSQL\tQueryDelete: " << m_queryDelete);
		
	if (!m_sqlConn->Initialize(cfg, authName)) {
		PTRACE(0, "H460PSQL\tModule creation failed: Could not connect to the database"
			);
		return;
	}

	m_sqlactive = true;
#endif

}

PBoolean GkPresence::LoadEndpoint(const H225_AliasAddress & addr, H323PresenceEndpoint & ep)
{
#ifdef HAS_DATABASE
	if (!m_sqlactive)
		return false;

	GkSQLResult::ResultRow resultRow;
	std::map<PString, PString> params;
	params["u"] = AsString(addr,false);
	GkSQLResult* result = m_sqlConn->ExecuteQuery(m_queryList, params, m_timeout);
	if (result == NULL) {
		PTRACE(2, "H460PSQL\tQuery failed - timeout or fatal error");
		return false;
	}

	if (!result->IsValid()) {
		PTRACE(2, "H460PSQL\tQuery failed (" << result->GetErrorCode()
			<< ") - " << result->GetErrorMessage()
			);
		delete result;
		return false;
	}
	
	bool success = false;

	if (result->GetNumRows() < 1)
		PTRACE(3, "H460PSQL\tQuery returned no rows");
	else if (result->GetNumFields() < 2)
		PTRACE(2, "H460PSQL\tBad-formed query - "
			"no columns found in the result set"
			);
	else {
		PStringArray retval;
		while (result->FetchRow(retval)) {
			if (retval[0].IsEmpty()) {
				PTRACE(1, "H460PSQL\tQuery Invalid value found.");
				continue;
			} 
		    if (!success) success = true;
			PTRACE(5, "H460PSQL\tQuery result: " << retval[0] << " " << retval[1]);
			H323PresenceInstruction::Instruction inst = (H323PresenceInstruction::Instruction)retval[0].AsInteger();
			H323PresenceInstruction instruct(inst, retval[1]);
			ep.m_Instruction.Add(instruct);
		}
	}
	delete result;
	return success;
#else
	return false;
#endif
}

bool GkPresence::RegisterEndpoint(const H225_EndpointIdentifier & ep, const H225_ArrayOf_AliasAddress & addr)
{
	PWaitAndSignal m(m_AliasMutex);

	for (PINDEX j = 0; j < addr.GetSize(); j++) {
		H323PresenceAlias::iterator it = aliasList.find(addr[j]);
		if (it == aliasList.end()) {
			for (PINDEX i=0; i < addr.GetSize(); i++)
				aliasList.insert(pair<H225_AliasAddress,H225_EndpointIdentifier>(addr[j],ep));
			
		}

		// Load the local Store from Database
		H323PresenceStore::iterator itx = localStore.find(addr[j]);
		if (itx == localStore.end()) {
			H323PresenceEndpoint store;
			if (LoadEndpoint(addr[j],store))  {
				// Queue up any notifications of existing registrations
				for (PINDEX i=0; i< store.m_Instruction.GetSize(); i++) {
				   // Queue up info from the datastore to supply to the endpoint
					H460P_PresencePDU msg;
					msg.SetTag(H460P_PresencePDU::e_instruction);
					H460P_PresenceInstruction & inst = msg;
					inst = store.m_Instruction[i];
					EnQueuePresence(addr[j],msg);

					if (store.m_Instruction[i].GetTag() == e_subscribe) {
						  // look in the local store
					    H323PresenceStore::iterator itm = localStore.find(store.m_Instruction[i]);
						if (itm != localStore.end()) {
							H323PresenceEndpoint & ep = itm->second;
							if (ep.m_Notify.GetSize() > 0) {
								H460P_PresencePDU msg;
								msg.SetTag(H460P_PresencePDU::e_notification);
								H460P_PresenceNotification & notification = msg;
								notification = ep.m_Notify[0];
								EnQueuePresence(addr[j],msg);
							}
						} else {
						  // We need to go find them...

						}

					}
				}
			}
			localStore.insert(pair<H225_AliasAddress,H323PresenceEndpoint>(addr[j],store));
		}
		
	}

	return true;
}

void GkPresence::UnRegisterEndpoint(const H225_ArrayOf_AliasAddress & addr)
{
	PWaitAndSignal m(m_AliasMutex);

	// Go signal all the subscriptions that alias is offline.



	// Remove the Endpoint Record
	for (PINDEX i=0; i < addr.GetSize(); i++) {
		H323PresenceAlias::iterator it = aliasList.find(addr[i]);
		if (it != aliasList.end()) 
			aliasList.erase(it);
	}

	for (PINDEX j=0; j < addr.GetSize(); j++) {
		H323PresenceStore::iterator itx = localStore.find(addr[j]);
		if (itx != localStore.end()) 
			localStore.erase(itx);
	}
		
}

void GkPresence::ProcessPresenceElement(const PASN_OctetString & pdu)
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

void GkPresence::EnQueuePresence(const H225_AliasAddress & addr, const H460P_PresencePDU & msg)
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
		return;
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
		return;
	}

	// neither registered remote or local then we need to find the endpoint.

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
			int pduCount = it->second.size()+1;
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
			} else if (i != aliasList.end()) 
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
			int pduCount = it->second.size()+1;
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
			} else if (i != aliasList.end()) 
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
			int pduCount = it->second.size()+1;
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
			} else if (i != aliasList.end()) 
				i++;
		}
	}
	return found; 
}

void GkPresence::OnNotification(MsgType tag, const H460P_PresenceNotification & notify, const H225_AliasAddress & addr)
{
	if (tag == e_Status) {
		// Update the local Store
		H323PresenceStore::iterator itx = localStore.find(addr);
		if (itx != localStore.end()) {
			H323PresenceEndpoint & ep = itx->second;
			ep.m_Notify.SetSize(1);
			ep.m_Notify[0] = ((const H323PresenceNotification &)notify);

			for (PINDEX i=0; i < ep.m_Instruction.GetSize(); i++) {
				if (ep.m_Instruction[i].GetTag() == H460P_PresenceInstruction::e_subscribe) {
					H460P_PresencePDU msg;
					msg.SetTag(H460P_PresencePDU::e_notification);
					H460P_PresenceNotification & notification = msg;
					notification = notify;
					EnQueuePresence(ep.m_Instruction[i],msg);
				}
			}
		}
	}
}

void GkPresence::OnSubscription(MsgType tag, const H460P_PresenceSubscription & subscription, const H225_AliasAddress & addr)
{

}

void GkPresence::HandleNewInstruction(unsigned tag, const H460P_PresenceInstruction & instruction, H323PresenceInstructions & instructions)
{
	int found = 0;
	const H225_AliasAddress & a = instruction;
	PString addr = AsString(a,1);

	// Check to see if we already have this instruction
	for (PINDEX i=0; i< instructions.GetSize(); i++) {
		H225_AliasAddress & b = instructions[i];
		PString addr2 = AsString(b,1);
		if (addr == addr2) {
			if (tag != instructions[i].GetTag()) {
				// We are undoing something...
				if (tag == instructions[i].GetTag()+1) {
					// We delete the previous...

					// remove it from the database
				}
			}
			found = i;
		}
	}
	if (found)
		return;

	  int sz = instructions.GetSize();
	  instructions.SetSize(sz+1);
	  instructions[sz] = (const H323PresenceInstruction &)instruction;
	  // enter it into the database

	  if (tag == H460P_PresenceInstruction::e_subscribe) {
		  // We need to get that authorized

	  }

}

void GkPresence::OnInstructions(MsgType tag, const H460P_ArrayOf_PresenceInstruction & instruction, const H225_AliasAddress & addr)
{
	// Load the local Store for this alias
	H323PresenceStore::iterator itx = localStore.find(addr);
	if (itx != localStore.end()) {
		H323PresenceEndpoint & ep = itx->second;
		for (PINDEX i=0; i<instruction.GetSize(); i++) {
			HandleNewInstruction(instruction[i].GetTag(), instruction[i], ep.m_Instruction);
		}
	}
}

void GkPresence::OnIdentifiers(MsgType tag, const H460P_ArrayOf_PresenceIdentifier & identifier, const H225_AliasAddress & addr) 
{

}

#endif


