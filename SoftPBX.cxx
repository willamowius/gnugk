//////////////////////////////////////////////////////////////////
//
// SoftPBX.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// initial author: Jan Willamowius
//
//////////////////////////////////////////////////////////////////

#include "SoftPBX.h"

#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4800 ) // one performance warning off
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#endif

#include <ptlib/sockets.h>
#include "h225.h"
#include "RasTbl.h"
#include "Toolkit.h"
#include "gk_const.h"

static int RequestNum = 1;	// this is the only place we are _generating_ sequence number at the moment

SoftPBX * SoftPBX::m_instance = NULL;
PMutex SoftPBX::m_CreationLock;

SoftPBX * SoftPBX::Instance(void)
{
	if (m_instance == NULL)
	{
		m_CreationLock.Wait();
		if (m_instance == NULL)
			m_instance = new SoftPBX;
		m_CreationLock.Signal();
	};
	return m_instance;
};

void SoftPBX::PrintAllRegistrations(GkStatus::Client &client, BOOL verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintAllRegistrations");
	RegistrationTable::Instance()->PrintAllRegistrations(client, verbose);
};

void SoftPBX::PrintCurrentCalls(GkStatus::Client &client, BOOL verbose)
{
	PTRACE(3, "GK\tSoftPBX: PrintCurrentCalls");
	CallTable::Instance()->PrintCurrentCalls(client, verbose);
};

// helper function to for_each_with
// unregisters a single endpoint
void UnregisterEP(const endpointRec &er, void* param) 
{
	H225_RasMessage *ras_msg = (H225_RasMessage *)param;
	PUDPSocket URQSocket;
	
	// these values are specific for each endpoint
	H225_UnregistrationRequest & urq = *ras_msg;
	urq.m_requestSeqNum.SetValue(RequestNum++);
	urq.m_callSignalAddress.SetSize(1);
	urq.IncludeOptionalField(urq.e_endpointIdentifier);
	
	const H225_TransportAddress_ipAddress & RasIpAddress = er.m_rasAddress;
	PIPSocket::Address ipaddress(RasIpAddress.m_ip[0], RasIpAddress.m_ip[1], RasIpAddress.m_ip[2], RasIpAddress.m_ip[3]);
	urq.m_callSignalAddress[0] = er.m_callSignalAddress;
	urq.m_endpointIdentifier = er.m_endpointIdentifier;
	
	// send URQ
	PBYTEArray wtbuf(4096);
	PPER_Stream wtstrm(wtbuf);
	ras_msg->Encode(wtstrm);
	wtstrm.CompleteEncoding();
	PTRACE(2, "GK\tSend to " << ipaddress << " [" << RasIpAddress.m_port << "] : " << ras_msg->GetTagName());
	PTRACE(3, "GK\t" << endl << setprecision(2) << (*ras_msg));
	URQSocket.WriteTo(wtstrm.GetPointer(), wtstrm.GetSize(), ipaddress, RasIpAddress.m_port);
}

// send URQ to all endpoints
void SoftPBX::UnregisterAllEndpoints()
{
	H225_RasMessage ras_msg;
	
	ras_msg.SetTag(H225_RasMessage::e_unregistrationRequest);
	H225_UnregistrationRequest & urq = ras_msg;
	urq.IncludeOptionalField(urq.e_gatekeeperIdentifier);
	urq.m_gatekeeperIdentifier.SetValue( Toolkit::GKName() );

#ifdef WIN32
	// Visual C++ doesn't grock the for_each_with2 template function
	// anybody have a better fix ?
	set<endpointRec>::const_iterator EpIter;
	for (EpIter=RegistrationTable::Instance()->EndpointList.begin();
		EpIter != RegistrationTable::Instance()->EndpointList.end();
		++EpIter)
	{
		UnregisterEP(*EpIter, &ras_msg);
	};
#else
	Toolkit::for_each_with(RegistrationTable::Instance()->EndpointList.begin(), 
						   RegistrationTable::Instance()->EndpointList.end(), 
						   UnregisterEP, (void*)(&ras_msg));
#endif

	RegistrationTable::Instance()->EndpointList.clear(); 
	RegistrationTable::Instance()->GatewayPrefixes.clear();
};

// send a DRQ to this endpoint
void SoftPBX::Disconnect(PString Ip)
{
	PUDPSocket SendSocket;
	PIPSocket::Address ipaddress(Ip);
	PBYTEArray * wtbuf = new PBYTEArray(4096);
	PPER_Stream * wtstrm = new PPER_Stream(*wtbuf);

	H225_TransportAddress callSignallAddress;
	callSignallAddress.SetTag(H225_TransportAddress::e_ipAddress);

	H225_TransportAddress_ipAddress & ipSignalAddress = callSignallAddress;
	ipSignalAddress.m_ip[0] = ipaddress.Byte1();
	ipSignalAddress.m_ip[1] = ipaddress.Byte2();
	ipSignalAddress.m_ip[2] = ipaddress.Byte3();
	ipSignalAddress.m_ip[3] = ipaddress.Byte4();
	ipSignalAddress.m_port = Toolkit::Config()->GetInteger("EndpointSignalPort", GK_DEF_ENDPOINT_SIGNAL_PORT);
	endpointRec * ep = (endpointRec *)RegistrationTable::Instance()->FindBySignalAdr(callSignallAddress);

	PTRACE(3, "GK\tSoftPBX: Disconnect " << ipaddress);

	if (ep == NULL)
	{
		PTRACE(3, "GK\tSoftPBX: Can't find endpoint registration");
		return;
	};
	H225_TransportAddress rasAddress = ep->m_rasAddress;
	H225_TransportAddress_ipAddress & ipRasAddress = rasAddress;
	PTRACE(3, "GK\tSoftPBX: RAS address " << rasAddress);

	H225_RasMessage ras_msg;
	ras_msg.SetTag(H225_RasMessage::e_disengageRequest);
	H225_DisengageRequest & drq = ras_msg;
	drq.m_requestSeqNum.SetValue(RequestNum++);
	drq.m_endpointIdentifier = ep->m_endpointIdentifier;
	// find callId and conferenceId
	CallRec * Call = (CallRec *)CallTable::Instance()->FindBySignalAdr(callSignallAddress);
	if (Call != NULL)
	{
		drq.m_callIdentifier = Call->m_callIdentifier;
		drq.m_conferenceID = Call->m_conferenceIdentifier;
	};
	drq.m_disengageReason.SetTag(H225_DisengageReason::e_forcedDrop);

	ras_msg.Encode(*wtstrm);
	wtstrm->CompleteEncoding();
	SendSocket.WriteTo(wtstrm->GetPointer(), wtstrm->GetSize(), ipaddress, ipRasAddress.m_port);
	delete wtbuf;
	delete wtstrm;
};

