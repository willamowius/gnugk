// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2002 Nils Bokermann <Nils.Bokermann@mediaWays.net>
//
// PURPOSE OF THIS FILE: This class will read the packets coming from
// the RasListener and react in an appropiate way
//
// - Automatic Version Information via RCS:
//   $Id$
//   $Source$
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//

#include "RasWorker.h"
#include "RasListener.h"
#include "h323util.h"
#include "ANSI.h"
#include "ProxyThread.h"
#include "SoftPBX.h"
#include "gkDestAnalysis.h"
#include "Neighbor.h"
#include "GkClient.h"

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = RASWORKER_H;
#endif /* lint */


GK_RASWorker::GK_RASWorker(PPER_Stream initial_pdu, PIPSocket::Address rx_addr, WORD rx_port, GK_RASListener &listener) :
	PThread(1000, NoAutoDeleteThread), raw_pdu(initial_pdu), addr(rx_addr), port(rx_port), master(listener),
	need_answer(FALSE)
{
	PTRACE(5, "RasWorker started");
}

GK_RASWorker::~GK_RASWorker() {
	PTRACE(5, "RasWorker stopped");
};

void
GK_RASWorker::Main()
{
	PTRACE(1, "You shall not use GK_RASWorker without overloading Main()");
	if(!pdu.Decode(raw_pdu)) {
		PTRACE(5, "RasWorker: Did not decode message");
		return;
	}
	OnUnknown(pdu);
	return;
}

void
GK_RASWorker::OnUnknown(H225_RasMessage & ras)
{
	PTRACE(5, "RasWorker got Unknown PDU: " << pdu);
}

void
GK_RASWorker::SendRas()
{
	PBYTEArray buffer(4096);
	PPER_Stream writestream(buffer);

	PTRACE(5, "SendRAS: " << answer_pdu);
	answer_pdu.Encode(writestream);
	writestream.CompleteEncoding();
	master.SendTo(writestream, writestream.GetSize(), addr, port);
}

void
GK_RASWorker::ForwardRasMsg(H225_RasMessage &msg)
{

	master.ForwardRasMsg(msg);
// Hmm??
}


void
GK_RASWorker::ProcessARQ(endptr &RequestingEP, endptr &CalledEP, H225_AdmissionRequest &arq, BOOL &bReject)
{
	if (answer_pdu.GetTag() != H225_RasMessage::e_admissionReject)
		answer_pdu.SetTag(H225_RasMessage::e_admissionReject);
	H225_AdmissionReject & arj = answer_pdu;

	// check if the endpoint requesting is registered with this gatekeeper
	if (!bReject && !RequestingEP) {
		bReject = TRUE;
		arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_callerNotRegistered/*was :e_invalidEndpointIdentifier*/);
	}


	if(!bReject && !CalledEP) {
		// if bReject is false but no called EP means, that the EP won't handle ARJ correctly. We have to send a
		// ACF here and handle the Overlap Sending in Q.931
		if (arj.m_rejectReason.GetTag()==H225_AdmissionRejectReason::e_incompleteAddress) {
			answer_pdu.SetTag(H225_RasMessage::e_admissionConfirm);
			PTRACE(3, "handling ARJ with cisco");
		} else {
			bReject = TRUE;
		}
	}

	//
	// Bandwidth
	// and GkManager admission
	//
	int BWRequest = 1280;

	if (!bReject) {
		//
		// Give bandwidth
		//

		// hack for Netmeeting 3.0x
		if (arq.m_bandWidth.GetValue() >= 100)
			BWRequest = arq.m_bandWidth.GetValue();
		PTRACE(3, "GK\tARQ will request bandwith of " << BWRequest);

		//
		// GkManager admission
		//
		if (!CallTable::Instance()->GetAdmission(BWRequest)) {
			bReject = TRUE;
			arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_resourceUnavailable);
		}
	}

 	//
 	// call from one GW to itself?
 	// generate ARJ-reason: 'routeCallToSCN'
 	//
 	if(!bReject &&
 	   Toolkit::AsBool(GkConfig()->GetString("RasSrv::ARQFeatures","ArjReasonRouteCallToSCN","0")) )
 	{
 		// are the endpoints the same (GWs of course)?
 		if( (CalledEP) && (RequestingEP) && (CalledEP == RequestingEP) &&
 			(!arq.m_answerCall) // only first ARQ may be rejected with with 'routeCallToSCN'
 			)
 		{
 			// we have to extract the SCN from the destination. only EP-1 will be rejected this way
 			if ( arq.m_destinationInfo.GetSize() >= 1 )	{
 				// PN will be the number that is set in the arj reason
 				H225_PartyNumber PN;
 				PN.SetTag(H225_PartyNumber::e_e164Number);
 				H225_PublicPartyNumber &PPN = PN;
 				// set defaults
 				PPN.m_publicTypeOfNumber.SetTag(H225_PublicTypeOfNumber::e_unknown);
 				PPN.m_publicNumberDigits = "";

 				// there can be diffent information in the destination info
 				switch(arq.m_destinationInfo[0].GetTag()) {
 				case H225_AliasAddress::e_dialedDigits:
 					// normal number, extract only the digits
 					PPN.m_publicNumberDigits = AsString(arq.m_destinationInfo[0], FALSE);
 					break;
 				case H225_AliasAddress::e_partyNumber:
 					// ready-to-use party number
 					PN = static_cast<H225_PartyNumber &>(arq.m_destinationInfo[0]); // Gives a warning, nilsb
 					break;
 				default:
 					PTRACE(1,"Unsupported AliasAdress for ARQ reason 'routeCallToSCN': "
 						   << arq.m_destinationInfo[0]);
 				}

 				// set the ARJ reason
 				bReject = TRUE;
 				arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_routeCallToSCN);
 				H225_ArrayOf_PartyNumber &APN = arj.m_rejectReason;
 				APN.SetSize(1);
 				APN[0] = PN;
 			}
 			else {
 				// missing destination info. is this possible at this point?
 			}
 		}
 	}

	//
	// Do the reject or the confirm
	//
	PString srcInfoString = (RequestingEP) ? AsDotString(RequestingEP->GetCallSignalAddress()) : PString(" ");
	PString destinationInfoString = (arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)) ?
		AsString(arq.m_destinationInfo) : PString("unknown");

	// get matching callRec
        // CallRecs should be looked for using callIdentifier instead of callReferenceValue
        // callIdentifier is globally unique, callReferenceValue is just unique per-endpoint.

	callptr pExistingCallRec = (arq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier)) ?
		CallTable::Instance()->FindCallRec(arq.m_callIdentifier) :
	// since callIdentifier is optional, we might have to look for the callReferenceValue as well
		CallTable::Instance()->FindCallRec(arq.m_callReferenceValue);

	if (!bReject && Toolkit::AsBool(GkConfig()->GetString("RasSrv::ARQFeatures", "ArjReasonRouteCallToGatekeeper", "1"))) {
		if (master.IsGKRouted() && arq.m_answerCall && !pExistingCallRec) {
			bool fromAlternateGK = false;
			const PString SkipForwards = GkConfig()->GetString("SkipForwards", "");
			if (!SkipForwards) {
				if (arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress) &&
				    arq.m_srcCallSignalAddress.GetTag() == H225_TransportAddress::e_ipAddress) {
					const H225_TransportAddress_ipAddress & srcipaddr = static_cast<H225_TransportAddress_ipAddress &>(arq.m_srcCallSignalAddress);
					PString srcip(PString::Printf,"%d.%d.%d.%d", srcipaddr.m_ip[0], srcipaddr.m_ip[1], srcipaddr.m_ip[2], srcipaddr.m_ip[3]);
					fromAlternateGK = (SkipForwards.Find(srcip) != P_MAX_INDEX);
				}
			}
			if (!fromAlternateGK) {
				bReject = TRUE;
				arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_routeCallToGatekeeper);
			}
		}
	}

	if (bReject)
	{
		arj.m_requestSeqNum = arq.m_requestSeqNum;
		PString msg(PString::Printf, "ARJ|%s|%s|%s|%s|%s;" GK_LINEBRK,
			    (const unsigned char *) srcInfoString,
			    (const unsigned char *) destinationInfoString,
			    (const unsigned char *) AsString(arq.m_srcInfo),
			    (arq.m_answerCall) ? "true" : "false",
			    (const unsigned char *) arj.m_rejectReason.GetTagName() );
		PTRACE(2, msg);
		GkStatus::Instance()->SignalStatus(msg);
	} else 	{
		// new connection admitted
		answer_pdu.SetTag(H225_RasMessage::e_admissionConfirm); // re-cast (see above)
		H225_AdmissionConfirm & acf = answer_pdu;

		acf.m_requestSeqNum = arq.m_requestSeqNum;
		acf.m_bandWidth = BWRequest;

		if (pExistingCallRec) {
			// set calledEP
			pExistingCallRec->SetCalled(CalledEP, arq.m_callReferenceValue);
			// if it is the first ARQ then add the rest of informations in callRec
			if (!arq.m_answerCall) {
				pExistingCallRec->SetBandwidth(BWRequest);
				// No Timerhandling for called Party.
// Routed mode is now in class RasSrv.
				if (!master.IsGKRouted()) {
					pExistingCallRec->SetConnected(true);
				}
			}
		} else {
			// the call is not in the table
			CallRec *pCallRec = new CallRec(arq.m_callIdentifier, arq.m_conferenceID,
							destinationInfoString, AsString(arq.m_srcInfo),
							BWRequest, master.IsGKRoutedH245());
			pCallRec->SetCalled(CalledEP, arq.m_callReferenceValue);

			if (!arq.m_answerCall) // the first ARQ
				pCallRec->SetCalling(RequestingEP, arq.m_callReferenceValue);
			if (!master.IsGKRouted())
				pCallRec->SetConnected(true);

			pCallRec->Lock();

			if(pCallRec->GetCallingProfile().GetCallTimeout()==0) {
				delete pCallRec;
				answer_pdu.SetTag(H225_RasMessage::e_admissionReject); // Build ARJ
				H225_AdmissionReject & arj=answer_pdu;
				arj.m_requestSeqNum = arq.m_requestSeqNum;
				arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_exceedsCallCapacity);
				return;
			}

			CallTable::Instance()->Insert(pCallRec);

			int timeout = (pCallRec->GetCallingProfile().GetCallTimeout()>=0 ?
				       pCallRec->GetCallingProfile().GetCallTimeout() :
				       GkConfig()->GetInteger("CallTable", "DefaultCallTimeout", 0));
			pCallRec->SetTimer(timeout);
			pCallRec->StartTimer();
			pCallRec->Unlock();
		}

		if ( master.IsGKRouted()) {
			PTRACE(5, "Setting destcallsignalAddress: " << master.GetCallSignalAddress(addr));
			acf.m_callModel.SetTag( H225_CallModel::e_gatekeeperRouted );
			acf.m_destCallSignalAddress = master.GetCallSignalAddress(addr);
		} else {
			// direct signalling

			// Set ACF fields
			acf.m_callModel.SetTag( H225_CallModel::e_direct );
			if( arq.HasOptionalField( H225_AdmissionRequest::e_destCallSignalAddress) )
				acf.m_destCallSignalAddress = arq.m_destCallSignalAddress;
			else
				acf.m_destCallSignalAddress = CalledEP->GetCallSignalAddress();
		}

		acf.IncludeOptionalField ( H225_AdmissionConfirm::e_irrFrequency );
		acf.m_irrFrequency.SetValue( 120 );

		PString destinationInfoString = "unknown destination alias";
		if (arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
			destinationInfoString = AsString(arq.m_destinationInfo);
		else if (arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
			H225_TransportAddress DestSignalAdr = arq.m_destCallSignalAddress;
			const endptr pEPRec = RegistrationTable::Instance()->FindBySignalAdr(DestSignalAdr);
			if (pEPRec)
				destinationInfoString = AsString(pEPRec->GetAliases());
		}

		// always signal ACF
		PString msg(PString::Printf, "ACF|%s|%s|%u|%s|%s;" GK_LINEBRK,
				(const unsigned char *) srcInfoString,
				(const unsigned char *) RequestingEP->GetEndpointIdentifier().GetValue(),
				(unsigned) arq.m_callReferenceValue,
				(const unsigned char *) destinationInfoString,
				(const unsigned char *) AsString(arq.m_srcInfo)
				);
		PTRACE(2, msg);
		GkStatus::Instance()->SignalStatus(msg);

	}
}

// Derived Class H323RasWorker

H323RasWorker::H323RasWorker(PPER_Stream initial_pdu, PIPSocket::Address rx_addr, WORD rx_port, GK_RASListener &listener) :
	GK_RASWorker(initial_pdu, rx_addr, rx_port, listener)
{
	PTRACE(5, "H323RasWorker started");
//	Resume();
}

H323RasWorker::~H323RasWorker() {
	PTRACE(5, "H323RasWorker exit");
};

void H323RasWorker::Terminate() {
	PTRACE(5, "Terminate()");
}

void
H323RasWorker::Main()
{
	PTRACE(5, "RasWorker Main");
	if(!pdu.Decode(raw_pdu)) {
		PTRACE(5, "RasWorker: Did not decode message");
		return;
	}
	PTRACE(5, "RasWorker got PDU: " << endl << pdu);
	switch(pdu.GetTag()) {
	case H225_RasMessage::e_gatekeeperRequest:
		OnGRQ(pdu);
		break;
	case H225_RasMessage::e_registrationRequest:
		OnRRQ(pdu);
		break;
	case H225_RasMessage::e_unregistrationRequest:
		OnURQ(pdu);
		break;
	case H225_RasMessage::e_admissionRequest:
		OnARQ(pdu);
		break;
	case H225_RasMessage::e_bandwidthRequest:
		OnBRQ(pdu);
		break;
	case H225_RasMessage::e_disengageRequest:
		OnDRQ(pdu);
		break;
	case H225_RasMessage::e_locationRequest:
		OnLRQ(pdu);
		break;
	case H225_RasMessage::e_locationConfirm:
		OnLCF(pdu);
		break;
	case H225_RasMessage::e_locationReject:
		OnLRJ(pdu);
		break;
	case H225_RasMessage::e_infoRequestResponse:
		OnIRR(pdu);
		break;
	case H225_RasMessage::e_resourcesAvailableIndicate:
		OnRAI(pdu);
		break;
	default:
		OnUnknown(pdu);
	}
	if(need_answer) {
		PTRACE(1,"Sending message");
		SendRas();
	} else {
		PTRACE(1, "nothing to send");
	}
	return;
}

void
H323RasWorker::OnGRQ(H225_GatekeeperRequest &grq)
{
	PTRACE(1, "GK\tGRQ Received");

	BOOL bShellForwardRequest = TRUE;

	// reply only if gkID matches
	if ( grq.HasOptionalField ( H225_GatekeeperRequest::e_gatekeeperIdentifier ) )
		if (grq.m_gatekeeperIdentifier.GetValue() != Toolkit::GKName()) {
			PTRACE(2, "GK\tGRQ is not meant for this gatekeeper");
			need_answer=FALSE;
			return;
		}

	// mechanism 1: forwarding detection per "flag"
	if(grq.HasOptionalField(H225_GatekeeperRequest::e_nonStandardData)) {
		switch(grq.m_nonStandardData.m_nonStandardIdentifier.GetTag()) {
		case H225_NonStandardIdentifier::e_h221NonStandard:
			const H225_H221NonStandard &nonStandard =
				static_cast<H225_H221NonStandard &> (grq.m_nonStandardData.m_nonStandardIdentifier);
			int iec = Toolkit::Instance()->GetInternalExtensionCode(nonStandard);
			if(iec == Toolkit::iecFailoverRAS) {
				bShellForwardRequest = FALSE;
			}
		}
	}

	// mechanism 2: forwarding detection per "from"
	const PString SkipForwards = GkConfig()->GetString("SkipForwards", "");
	if (!SkipForwards)
		if (SkipForwards.Find(addr.AsString()) != P_MAX_INDEX) {
			PTRACE(5, "GRQ\tWill skip forwarding GRQ to other GK.");
			bShellForwardRequest = FALSE;
		}

	PString msg;
	unsigned rsn = H225_GatekeeperRejectReason::e_securityDenial;
	if (!authList->Check(grq, rsn)) {
		answer_pdu.SetTag(H225_RasMessage::e_gatekeeperReject);
		H225_GatekeeperReject & grj = answer_pdu;
		grj.m_requestSeqNum = grq.m_requestSeqNum;
		grj.m_rejectReason.SetTag(rsn);
		grj.IncludeOptionalField(grj.e_gatekeeperIdentifier);
		grj.m_gatekeeperIdentifier.SetValue( Toolkit::GKName() );
		msg = PString(PString::Printf, "GRJ|%s;" GK_LINEBRK, inet_ntoa(addr));
	} else {
		answer_pdu.SetTag(H225_RasMessage::e_gatekeeperConfirm);
		H225_GatekeeperConfirm & obj_gcf = answer_pdu;

		obj_gcf.m_requestSeqNum = grq.m_requestSeqNum;
		obj_gcf.m_protocolIdentifier = grq.m_protocolIdentifier;
		obj_gcf.m_nonStandardData = grq.m_nonStandardData;
		obj_gcf.m_rasAddress = master.GetRasAddress(addr);
		obj_gcf.IncludeOptionalField(obj_gcf.e_gatekeeperIdentifier);
		obj_gcf.m_gatekeeperIdentifier.SetValue( Toolkit::GKName() );

		PString aliasListString(grq.HasOptionalField(H225_GatekeeperRequest::e_endpointAlias) ?
					AsString(grq.m_endpointAlias) : PString());

		if (bShellForwardRequest) {
			ForwardRasMsg(pdu);
		}

		msg = PString(PString::Printf, "GCF|%s|%s|%s;" GK_LINEBRK,
			inet_ntoa(addr),
			(const unsigned char *) aliasListString,
			(const unsigned char *) AsString(grq.m_endpointType) );
	}

	PTRACE(2, msg);
	GkStatus::Instance()->SignalStatus(msg);

	need_answer = TRUE;
	return;

}

void
H323RasWorker::OnRRQ(H225_RegistrationRequest &rrq)
{
	PTRACE(1, "GK\tRRQ Received");
	need_answer=TRUE;

	BOOL bReject = FALSE;		// RRJ with any other reason from #rejectReason#
	H225_RegistrationRejectReason rejectReason;

	PString alias;

	H225_TransportAddress SignalAdr;

	BOOL bShellForwardRequest = TRUE;

	// mechanism 1: forwarding detection per "flag"
	if(rrq.HasOptionalField(H225_RegistrationRequest::e_nonStandardData)) {
		switch(rrq.m_nonStandardData.m_nonStandardIdentifier.GetTag()) {
		case H225_NonStandardIdentifier::e_h221NonStandard:
			const H225_H221NonStandard &nonStandard =
				static_cast <H225_H221NonStandard &>(rrq.m_nonStandardData.m_nonStandardIdentifier);
			int iec = Toolkit::Instance()->GetInternalExtensionCode(nonStandard);
			if(iec == Toolkit::iecFailoverRAS) {
				need_answer = FALSE;
				bShellForwardRequest = FALSE;
			}
		}
	}

	// mechanism 2: forwarding detection per "from"
	const PString SkipForwards = GkConfig()->GetString("SkipForwards", "");
        if (!SkipForwards)
		if (SkipForwards.Find(addr.AsString()) != P_MAX_INDEX)
		{
			PTRACE(5, "RRQ\tWill skip forwarding RRQ to other GK.");
			need_answer = FALSE;
			bShellForwardRequest = FALSE;
		}

	// lightweight registration update
	if (rrq.HasOptionalField(H225_RegistrationRequest::e_keepAlive) &&
		rrq.m_keepAlive.GetValue())
	{
		endptr ep = RegistrationTable::Instance()->FindByEndpointId(rrq.m_endpointIdentifier);
		bReject = endptr(NULL)!=ep;
		// check if the RRQ was sent from the registered endpoint
		if (endptr(NULL)!=ep) {
#ifdef CHECK_FOR_ALIAS0
			PAssert(FALSE,"H323RasSrv::OnRRQ using only first");
#endif
			if (rrq.m_callSignalAddress.GetSize() >= 1)
				bReject = (ep->GetCallSignalAddress() != rrq.m_callSignalAddress[0]);
			else if (rrq.m_rasAddress.GetSize() >= 1)
				bReject = (ep->GetRasAddress() != rrq.m_rasAddress[0]);
			// No call signal and ras address provided.
			// TODO: check rx_addr?
			else
				bReject = FALSE;
		}

		if (bReject || endptr(NULL)==ep) {
			PTRACE_IF(1, ep, "WARNING:\tPossibly endpointId collide or security attack!!");
			// endpoint was NOT registered
			rejectReason.SetTag(H225_RegistrationRejectReason::e_fullRegistrationRequired);
		} else {
			// endpoint was already registered
			answer_pdu.SetTag(H225_RasMessage::e_registrationConfirm);
			H225_RegistrationConfirm & rcf = answer_pdu;
			rcf.m_requestSeqNum = rrq.m_requestSeqNum;
			rcf.m_protocolIdentifier =  rrq.m_protocolIdentifier;
			rcf.m_endpointIdentifier = rrq.m_endpointIdentifier;
			rcf.IncludeOptionalField(rcf.e_gatekeeperIdentifier);
			rcf.m_gatekeeperIdentifier.SetValue(Toolkit::GKName() );
			if (ep->GetTimeToLive() > 0) {
				rcf.IncludeOptionalField(rcf.e_timeToLive);
				rcf.m_timeToLive = ep->GetTimeToLive();
			}

			// Alternate GKs
			master.SetAlternateGK(rcf);

			// forward lightweights, too
			if (bShellForwardRequest) {
				H225_RasMessage ras = ep->GetCompleteRegistrationRequest();
				ForwardRasMsg(ras);
			}

			ep->Update(pdu);
			return ;
		}
	}

	bool nated = false, validaddress = false;
	if (rrq.m_callSignalAddress.GetSize() >= 1) {
		SignalAdr = rrq.m_callSignalAddress[0];
		if (SignalAdr.GetTag() == H225_TransportAddress::e_ipAddress) {
			H225_TransportAddress_ipAddress & ip = SignalAdr;
			PIPSocket::Address ipaddr(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
			validaddress = (addr == ipaddr);

			const PString SkipForwards = GkConfig()->GetString("SkipForwards", "");
			if (!SkipForwards)
				if (SkipForwards.Find(addr.AsString()) != P_MAX_INDEX)
					validaddress = true;

			if (!validaddress && Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "SupportNATedEndpoints", "0")))
				validaddress = nated = true;
		}
	}

	if (!bReject && !validaddress) {
		bReject = TRUE;
		rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidCallSignalAddress);
	}

	// Check if the endpoint has specified the EndpointIdentifier.
	// The GK will accept the EndpointIdentifier if
	// the EndpointIdentifier doesn't exist in the RegistrationTable,
	// or the request is sent from the original endpoint that has
	// this EndpointIdentifier. Otherwise the request will be rejected.
	if (!bReject && rrq.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier)) {
		endptr ep = RegistrationTable::Instance()->FindByEndpointId(rrq.m_endpointIdentifier);
		if (ep && ep->GetCallSignalAddress() != SignalAdr) {
			bReject = TRUE;
			// no reason named invalidEndpointIdentifier? :(
			rejectReason.SetTag(H225_RegistrationRejectReason::e_securityDenial);
		}
	}

	if (!bReject) {
		if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) &&
			(rrq.m_terminalAlias.GetSize() >= 1)) {
			const H225_ArrayOf_AliasAddress & NewAliases = rrq.m_terminalAlias;
			const endptr ep = RegistrationTable::Instance()->FindByAliases(NewAliases);
			if (ep && ep->GetCallSignalAddress() != SignalAdr) {
				bReject = TRUE;
				rejectReason.SetTag(H225_RegistrationRejectReason::e_duplicateAlias);
			}
			// reject the empty string
			for (PINDEX AliasIndex=0; AliasIndex < NewAliases.GetSize(); ++AliasIndex) {
				const PString & s = AsString(NewAliases[AliasIndex], FALSE);
//				if (s.GetLength() < 1 || !(isalnum(s[0]) || s[0]=='#') ) {
				if (s.GetLength() < 1) {
					bReject = TRUE;
					rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidAlias);
				}
			}
		} else {
			// reject gw without alias
			switch (rrq.m_terminalType.GetTag()) {
			case H225_EndpointType::e_gatekeeper:
			case H225_EndpointType::e_gateway:
			case H225_EndpointType::e_mcu:
				bReject = TRUE;
				rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidAlias);
				break;
			/* only while debugging
			default:
				bReject = TRUE;
				rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidAlias);
				break;
			*/
			}
		}
	}
	unsigned rsn = H225_RegistrationRejectReason::e_securityDenial;
	if (!bReject && !authList->Check(rrq, rsn)) {
		bReject = TRUE;
		rejectReason.SetTag(rsn);
	}

	if (!bReject) {
		// make a copy for modifying
		H225_RasMessage store_rrq = pdu;

		endptr ep = RegistrationTable::Instance()->InsertRec(store_rrq);
		if ( ep ) {
			if (nated)
				ep->SetNATAddress(addr);
			//
			// OK, now send RCF
			//
			answer_pdu.SetTag(H225_RasMessage::e_registrationConfirm);
			H225_RegistrationConfirm & rcf = answer_pdu;
			rcf.m_requestSeqNum = rrq.m_requestSeqNum;
			rcf.m_protocolIdentifier =  rrq.m_protocolIdentifier;
			rcf.m_nonStandardData = rrq.m_nonStandardData;
			// This should copy all Addresses.
			rcf.m_callSignalAddress = rrq.m_callSignalAddress;
// 			rcf.m_callSignalAddress.SetSize( rrq.m_callSignalAddress.GetSize() );
// 			for( PINDEX cnt = 0; cnt < rrq.m_callSignalAddress.GetSize(); cnt ++ )
// 				rcf.m_callSignalAddress[cnt] = rrq.m_callSignalAddress[cnt];

			rcf.IncludeOptionalField(H225_RegistrationConfirm::e_terminalAlias);
			rcf.m_terminalAlias = ep->GetAliases();
			rcf.m_endpointIdentifier = ep->GetEndpointIdentifier();
			rcf.IncludeOptionalField(rcf.e_gatekeeperIdentifier);
			rcf.m_gatekeeperIdentifier.SetValue( Toolkit::GKName() );
			if (ep->GetTimeToLive() > 0) {
				rcf.IncludeOptionalField(rcf.e_timeToLive);
				rcf.m_timeToLive = ep->GetTimeToLive();
			}

			// Alternate GKs
			master.SetAlternateGK(rcf);

			// forward heavyweight
			if(bShellForwardRequest) {
				ForwardRasMsg(store_rrq);
			}

			// Note that the terminalAlias is not optional here as we pass the auto generated alias if not were provided from
			// the endpoint itself
			PString msg(PString::Printf, "RCF|%s|%s|%s|%s;" GK_LINEBRK,
				    (const unsigned char *) AsDotString(ep->GetCallSignalAddress()),
				    (const unsigned char *) AsString(rcf.m_terminalAlias),
				    (const unsigned char *) AsString(rrq.m_terminalType),
				    (const unsigned char *) ep->GetEndpointIdentifier().GetValue()
				    );
			PTRACE(2, msg);
			GkStatus::Instance()->SignalStatus(msg);

			return ;
		} else { // Oops! Should not happen...
			bReject = TRUE;
			rejectReason.SetTag(H225_RegistrationRejectReason::e_undefinedReason);
			PTRACE(3, "Gk\tRRQAuth rejected by unknown reason " << alias);
		}
	}
	//
	// final rejection handling
	//
	answer_pdu.SetTag(H225_RasMessage::e_registrationReject);
	H225_RegistrationReject & rrj = answer_pdu;

	rrj.m_requestSeqNum = rrq.m_requestSeqNum;
	rrj.m_protocolIdentifier =  rrq.m_protocolIdentifier;
	rrj.m_nonStandardData = rrq.m_nonStandardData ;
	rrj.IncludeOptionalField(rrj.e_gatekeeperIdentifier);
	rrj.m_gatekeeperIdentifier.SetValue( Toolkit::GKName() );
	rrj.m_rejectReason = rejectReason;

	PString aliasListString;
	if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
		aliasListString = AsString(rrq.m_terminalAlias);
	else
		aliasListString = " ";

	PString msg(PString::Printf, "RRJ|%s|%s|%s|%s;" GK_LINEBRK,
		    inet_ntoa(addr),
		    (const unsigned char *) aliasListString,
		    (const unsigned char *) AsString(rrq.m_terminalType),
		    (const unsigned char *) rrj.m_rejectReason.GetTagName()
		    );
	PTRACE(2,msg);
	GkStatus::Instance()->SignalStatus(msg);
	need_answer=TRUE;
	return;
}

void
H323RasWorker::OnURQ(H225_UnregistrationRequest &urq)
{
	PTRACE(1, "GK\tURQ Received");

	need_answer=TRUE;
	PString msg;

	BOOL bShellForwardRequest = TRUE;

	// check first if it comes from my GK
// 	if (Toolkit::Instance()->GkClientIsRegistered() && Toolkit::Instance()->GetGkClient().OnURQ(urq, addr)) {
// 		// Return UCF
// 		answer_pdu.SetTag(H225_RasMessage::e_unregistrationConfirm);
// 		H225_UnregistrationConfirm & ucf = answer_pdu;
// 		ucf.m_requestSeqNum = urq.m_requestSeqNum;
// 		need_answer = TRUE;
// 		return;
// 	}
	// OK, it comes from my endpoints
	// mechanism 1: forwarding detection per "flag"
	if(urq.HasOptionalField(H225_UnregistrationRequest::e_nonStandardData)) {
		switch(urq.m_nonStandardData.m_nonStandardIdentifier.GetTag()) {
		case H225_NonStandardIdentifier::e_h221NonStandard:
			const H225_H221NonStandard &nonStandard =
				static_cast <H225_H221NonStandard &>(urq.m_nonStandardData.m_nonStandardIdentifier);
			int iec = Toolkit::Instance()->GetInternalExtensionCode(nonStandard);
			if(iec == Toolkit::iecFailoverRAS) {
				need_answer = FALSE;
				bShellForwardRequest = FALSE;
			}
		}
	}
	// mechanism 2: forwarding detection per "from"
	const PString SkipForwards = GkConfig()->GetString("SkipForwards", "");
	if (!SkipForwards)
		if (SkipForwards.Find(addr.AsString()) != P_MAX_INDEX) {
			PTRACE(5, "RRQ\tWill skip forwarding RRQ to other GK.");
			need_answer = FALSE;
			bShellForwardRequest = FALSE;
		}

	PString endpointIdentifierString(urq.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier) ? urq.m_endpointIdentifier.GetValue() : PString(" "));
#ifdef CHECK_FOR_ALIAS0
	PAssert(1,"H323RasSrv::OnURQ using only field 1");
#endif

	endptr ep = urq.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier) ?
		RegistrationTable::Instance()->FindByEndpointId(urq.m_endpointIdentifier) :
		RegistrationTable::Instance()->FindBySignalAdr(urq.m_callSignalAddress[0]);
	if (ep) {
		// Disconnect all calls of the endpoint
		SoftPBX::DisconnectEndpoint(ep);
		// Remove from the table
//		RegistrationTable::Instance()->RemoveByEndpointId(urq.m_endpointIdentifier);
		RegistrationTable::Instance()->RemoveByEndptr(ep);

		// Return UCF
		answer_pdu.SetTag(H225_RasMessage::e_unregistrationConfirm);
		H225_UnregistrationConfirm & ucf = answer_pdu;
		ucf.m_requestSeqNum = urq.m_requestSeqNum;
		ucf.m_nonStandardData = urq.m_nonStandardData;

		msg = PString(PString::Printf, "UCF|%s|%s;",
			      inet_ntoa(addr),
			     (const unsigned char *) endpointIdentifierString) ;
	} else {
		// Return URJ
		answer_pdu.SetTag(H225_RasMessage::e_unregistrationReject);
		H225_UnregistrationReject & urj = answer_pdu;
		urj.m_requestSeqNum = urq.m_requestSeqNum;
		urj.m_nonStandardData = urq.m_nonStandardData ;
		urj.m_rejectReason.SetTag(H225_UnregRejectReason::e_notCurrentlyRegistered);

		msg = PString(PString::Printf, "URJ|%s|%s|%s;",
			      inet_ntoa(addr),
			      (const unsigned char *) endpointIdentifierString,
			      (const unsigned char *) urj.m_rejectReason.GetTagName() );
	}

	PTRACE(2, msg);
	GkStatus::Instance()->SignalStatus(msg + GK_LINEBRK);

	if(bShellForwardRequest) {
		ForwardRasMsg(pdu);
	}

	return;
}

void
H323RasWorker::OnARQ(H225_AdmissionRequest &arq)
{
	PTRACE(2, "GK\tARQ Received: << " << arq) ;

	BOOL bReject = FALSE;

	// find the caller
	endptr RequestingEP = RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier);

	endptr CalledEP(NULL);

	if (RequestingEP) { // Is the ARQ from a registered endpoint?
		bool bHasDestInfo = (arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo) && arq.m_destinationInfo.GetSize() >= 1);
		if (bHasDestInfo) // apply rewriting rules
			Toolkit::Instance()->RewriteE164(arq.m_destinationInfo[0]);

		unsigned rsn = H225_AdmissionRejectReason::e_securityDenial;
		if (!authList->Check(arq, rsn)) {
			bReject = TRUE;
		} else if (arq.m_answerCall) {
			// don't search endpoint table for an answerCall ARQ
			CalledEP = RequestingEP;
		} else {
			// if a destination address is provided, we check if we know it
			if (arq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress) &&
				master.GetCallSignalAddress(addr) != arq.m_destCallSignalAddress) { // if destAddr is the GK, ignore it
				CalledEP = RegistrationTable::Instance()->FindBySignalAdr(arq.m_destCallSignalAddress);
				if (!CalledEP && Toolkit::AsBool(GkConfig()->GetString("RasSrv::ARQFeatures", "CallUnregisteredEndpoints", "1"))) {
					H225_RasMessage arq = arq;
					CalledEP = RegistrationTable::Instance()->InsertRec(arq);
				}
			}
			if (!CalledEP && RequestingEP && arq.m_destinationInfo.GetSize() >= 1) {
				// create new callRec, set callingEP and insert callRec in callTable
				CallRec *pCallRec = new CallRec(arq.m_callIdentifier, arq.m_conferenceID,
								AsString(arq.m_destinationInfo),
								AsString(arq.m_srcInfo), 0,
								master.IsGKRoutedH245()); //BWRequest will be set in ProcessARQ
				pCallRec->SetCalling(RequestingEP, arq.m_callReferenceValue);
				CallTable::Instance()->Insert(pCallRec);
				// get called ep
				CalledEP = RegistrationTable::Instance()->getMsgDestination(arq, RequestingEP, rsn, TRUE);
				if (!CalledEP && rsn == H225_AdmissionRejectReason::e_incompleteAddress) {
					PTRACE(5, "Incomplete Number");
					bReject = TRUE;
				}
				if (CalledEP!=endptr(NULL) && rsn == H225_AdmissionRejectReason::e_incompleteAddress) {
					PTRACE(1,"Setting CalledEP to NULL");
					pCallRec->SetCalled(endptr(NULL), arq.m_callReferenceValue);
					CalledEP=endptr(NULL);
				}

				if (!bReject && !CalledEP &&
				    ( rsn == H225_AdmissionRejectReason::e_securityDenial ||
					    rsn == H225_AdmissionRejectReason::e_resourceUnavailable ||
					    rsn == H225_AdmissionRejectReason::e_calledPartyNotRegistered)) {
					H225_ArrayOf_AliasAddress dest = arq.m_destinationInfo;
					H225_AdmissionRequest arq_fake=arq;
					// The arq is the non-rewritten H225_AdmissionRequest. We need to change the destination-address
					// so we copy it to arq_fake and then build a new AdmissionRequest.
					PString number = H323GetAliasAddressString(dest[0]);
					Q931::NumberingPlanCodes plan = Q931::ISDNPlan;
					Q931::TypeOfNumberCodes ton = Q931::UnknownType;
					H225_ScreeningIndicator::Enumerations si = H225_ScreeningIndicator::e_userProvidedNotScreened;
					CallProfile & profile=pCallRec->GetCallingProfile();
					PTRACE(5, "foo");
					profile.debugPrint();
					ton = static_cast<Q931::TypeOfNumberCodes> (
						profile.TreatCalledPartyNumberAs() == CallProfile::LeaveUntouched ?
						ton : profile.TreatCalledPartyNumberAs());
					Toolkit::Instance()->GetRewriteTool().PrefixAnalysis(number, plan, ton, si,
											     profile);
					H323SetAliasAddress(number, dest[0], H225_AliasAddress::e_dialedDigits);
					PTRACE(5, "rewriting destination " << dest[0]);
					arq_fake.m_destinationInfo=dest;
					if (Toolkit::Instance()->GkClientIsRegistered()) {
						Toolkit::Instance()->GetGkClient().SendARQ(arq_fake, RequestingEP);
						need_answer = FALSE;
						return;

					} else if (Toolkit::Instance()->GetNeighbor().InsertARQ(arq_fake, RequestingEP)) { // Neighbor!
						need_answer = FALSE;
						return ;
					}
				}
			}
		}

		if(bReject || CalledEP==endptr(NULL)) {
			answer_pdu.SetTag(H225_RasMessage::e_admissionReject);
			H225_AdmissionReject & arj = answer_pdu;
			arj.m_rejectReason.SetTag(rsn);
			arj.m_requestSeqNum=arq.m_requestSeqNum;
			PTRACE(5, "setting Reject Reason: " << arj.m_rejectReason.GetTagName());
		}
	}

	ProcessARQ(RequestingEP, CalledEP, arq, bReject);
	need_answer = TRUE;
	return;
}

void
H323RasWorker::OnDRQ(H225_DisengageRequest &drq)
{
	PTRACE(1, "GK\tDRQ Received " << drq);

	bool bReject = false;

//        if (Toolkit::Instance()->GkClientIsRegistered() && Toolkit::Instance()->GetGkClient().OnDRQ(drq, addr)) {
//                PTRACE(4,"GKC\tDRQ: from my GK");
//        } else
	if (RegistrationTable::Instance()->FindByEndpointId(drq.m_endpointIdentifier)) {
		callptr call = CallTable::Instance()->FindCallRec(drq.m_callIdentifier);
		if(callptr(NULL)!=call) {
			call->GetCalledProfile().SetReleaseCause(drq.m_disengageReason);
		}
		PTRACE(4, "GK\tDRQ: closed conference");
	} else {
		bReject = true;
	}

	PString msg;
	if (bReject) {
		PTRACE(4, "GK\tDRQ: reject");
		answer_pdu.SetTag(H225_RasMessage::e_disengageReject);
		H225_DisengageReject & drj = answer_pdu;
		drj.m_requestSeqNum = drq.m_requestSeqNum;
		drj.m_rejectReason.SetTag( drj.m_rejectReason.e_notRegistered );

		msg = PString(PString::Printf, "DRJ|%s|%s|%u|%s;" GK_LINEBRK,
			      inet_ntoa(addr),
			      (const unsigned char *) drq.m_endpointIdentifier.GetValue(),
			      (unsigned) drq.m_callReferenceValue,
			      (const unsigned char *) drj.m_rejectReason.GetTagName());
	} else {

	       answer_pdu.SetTag(H225_RasMessage::e_disengageConfirm);
	       H225_DisengageConfirm & dcf = answer_pdu;
	       dcf.m_requestSeqNum = drq.m_requestSeqNum;

	       // always signal DCF
	       msg = PString(PString::Printf, "DCF|%s|%s|%u|%s;" GK_LINEBRK,
			     inet_ntoa(addr),
			     (const unsigned char *) drq.m_endpointIdentifier.GetValue(),
			     (unsigned) drq.m_callReferenceValue,
			     (const unsigned char *) drq.m_disengageReason.GetTagName() );
	       CallTable::Instance()->RemoveCall(drq);
       }

	PTRACE(2, msg);
	GkStatus::Instance()->SignalStatus(msg);
	need_answer = TRUE;
	return;
}

void
H323RasWorker::OnBRQ(H225_BandwidthRequest &brq)
{
	PTRACE(1, "GK\tBRQ Received");

	answer_pdu.SetTag(H225_RasMessage::e_bandwidthConfirm);
	H225_BandwidthConfirm & bcf = answer_pdu;
	bcf.m_requestSeqNum = brq.m_requestSeqNum;
	/* for now we grant whatever bandwidth was requested */
	if (brq.m_bandWidth.GetValue() < 100)
	{
		/* hack for Netmeeting 3.0 */
		bcf.m_bandWidth.SetValue ( 1280 );
	} else {
		/* otherwise grant what was asked for */
		bcf.m_bandWidth = brq.m_bandWidth;
	}
	bcf.m_nonStandardData = brq.m_nonStandardData;

	PString msg(PString::Printf, "BCF|%s|%s|%u;" GK_LINEBRK,
		    inet_ntoa(addr),
		    (const unsigned char *) brq.m_endpointIdentifier.GetValue(),
		    bcf.m_bandWidth.GetValue() );
	PTRACE(2,msg);
	GkStatus::Instance()->SignalStatus(msg);

	need_answer = TRUE;
	return;
}

void
H323RasWorker::OnLRQ(H225_LocationRequest &lrq)
{
	PTRACE(1, "GK\tLRQ Received");

	PString msg;
	endptr WantedEndPoint;

	Toolkit::Instance()->RewriteE164(lrq.m_destinationInfo[0]);
	endptr cgEP;

	for(PINDEX i=0; i<lrq.m_destinationInfo.GetSize(); i++)
		Toolkit::Instance()->RewriteE164(lrq.m_destinationInfo[i]);
	unsigned rsn = H225_LocationRejectReason::e_securityDenial;
	bool fromRegEndpoint = (lrq.HasOptionalField(H225_LocationRequest::e_endpointIdentifier) &&
				RegistrationTable::Instance()->FindByEndpointId(lrq.m_endpointIdentifier));
	bool bReject = (!(fromRegEndpoint || Toolkit::Instance()->GetNeighbor().CheckIP(addr)) || !authList->Check(lrq, rsn));

	bReject = true; // Ignore LRQ for now

	PString sourceInfoString((lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)) ? AsString(lrq.m_sourceInfo) : PString(" "));
	if (!bReject) {
		PTRACE(5, "LRQ from known endpoint");
		if ((WantedEndPoint = RegistrationTable::Instance()->getMsgDestination(lrq, cgEP, rsn, FALSE))) {
			PTRACE(5, "GK: Destination found!");

			// Alias found
			answer_pdu.SetTag(H225_RasMessage::e_locationConfirm);
			H225_LocationConfirm & lcf = answer_pdu;
			lcf.m_requestSeqNum = lrq.m_requestSeqNum;
			lcf.IncludeOptionalField(H225_LocationConfirm::e_nonStandardData);
			lcf.m_nonStandardData = lrq.m_nonStandardData;

			WantedEndPoint->BuildLCF(answer_pdu);
			if (master.IsGKRouted() && master.AcceptNBCalls()) {
				lcf.m_callSignalAddress = master.GetCallSignalAddress(addr);
				lcf.m_rasAddress = master.GetRasAddress(addr);
			}

			msg = PString(PString::Printf, "LCF|%s|%s|%s|%s;\r\n",
				      inet_ntoa(addr),
				      (const unsigned char *) WantedEndPoint->GetEndpointIdentifier().GetValue(),
				      (const unsigned char *) AsString(lrq.m_destinationInfo),
				      (const unsigned char *) sourceInfoString);
		} else {
			if (Toolkit::Instance()->GetNeighbor().ForwardLRQ(addr, lrq) > 0)
				return ; // forward successful, nothing for us :)
			bReject = true;
			rsn = H225_LocationRejectReason::e_requestDenied;
		}
	}
	if (bReject) {
		// Alias not found
                answer_pdu.SetTag(H225_RasMessage::e_locationReject);
                H225_LocationReject & lrj = answer_pdu;
                lrj.m_requestSeqNum = lrq.m_requestSeqNum;
                lrj.m_rejectReason.SetTag(rsn); // can't find the location
                lrj.IncludeOptionalField(H225_LocationReject::e_nonStandardData);
                lrj.m_nonStandardData = lrq.m_nonStandardData;

                msg = PString(PString::Printf, "LRJ|%s|%s|%s|%s;\r\n",
			      inet_ntoa(addr),
			      (const unsigned char *) AsString(lrq.m_destinationInfo),
			      (const unsigned char *) sourceInfoString,
			      (const unsigned char *) lrj.m_rejectReason.GetTagName() );
	}
	if (lrq.m_replyAddress.GetTag() == H225_TransportAddress::e_ipAddress) {
		const H225_TransportAddress_ipAddress & ip = static_cast <H225_TransportAddress_ipAddress &> (lrq.m_replyAddress);
		PIPSocket::Address ipaddr(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);
		if (!bReject)
			Toolkit::Instance()->GetNeighbor().InsertSiblingIP(ipaddr);
		addr=ipaddr;
		port=ip.m_port;
		need_answer = TRUE;
	}

	PTRACE(2, msg);
	GkStatus::Instance()->SignalStatus(msg);

	return;
}

void
H323RasWorker::OnLCF(H225_RasMessage &lcf) // No conversion needed here!
{
	PTRACE(1, "GK\tLCF Received");
	need_answer = FALSE;
	if (Toolkit::Instance()->GetNeighbor().CheckIP(addr)) // may send from sibling
		Toolkit::Instance()->GetNeighbor().ProcessLCF(lcf);
	return;
}

void
H323RasWorker::OnLRJ(H225_RasMessage &lrj) // No conversion needed here!
{
	PTRACE(1, "GK\tLRJ Received");
	need_answer = FALSE;
	// we should ignore LRJ from sibling
	if (Toolkit::Instance()->GetNeighbor().CheckIP(addr))
		Toolkit::Instance()->GetNeighbor().ProcessLRJ(lrj);
	return;
}

void
H323RasWorker::OnIRR(H225_InfoRequestResponse &irr)
{
	PTRACE(1, "GK\tIRR Received");

	if (endptr ep = RegistrationTable::Instance()->FindByEndpointId(irr.m_endpointIdentifier)) {
		ep->Update(pdu);
		if (irr.HasOptionalField( H225_InfoRequestResponse::e_needResponse) && irr.m_needResponse.GetValue()) {
			answer_pdu.SetTag(H225_RasMessage::e_infoRequestAck);
			H225_InfoRequestAck & ira = answer_pdu;
			ira.m_requestSeqNum = irr.m_requestSeqNum;
			ira.m_nonStandardData = irr.m_nonStandardData;

			PString msg(PString::Printf, "IACK|%s;", inet_ntoa(addr));
			PTRACE(2, msg);
			GkStatus::Instance()->SignalStatus(msg + "\r\n");
			need_answer = TRUE;
		}
	}
	// otherwise don't respond
	return;

}

void
H323RasWorker::OnRAI(H225_ResourcesAvailableIndicate &rai)
{
	PTRACE(1, "GK\tRAI Received");

	/* accept all RAIs */
	answer_pdu.SetTag(H225_RasMessage::e_resourcesAvailableConfirm);
	H225_ResourcesAvailableConfirm & rac = answer_pdu;
	rac.m_requestSeqNum = rai.m_requestSeqNum;
	rac.m_protocolIdentifier =  rai.m_protocolIdentifier;
	rac.m_nonStandardData = rai.m_nonStandardData;

	need_answer=TRUE;
	return;

}

// Class NeighborWorker

NeighborWorker::NeighborWorker(PPER_Stream initial_pdu, PIPSocket::Address rx_addr, WORD rx_port, GK_RASListener & server)
	: GK_RASWorker(initial_pdu, rx_addr, rx_port, server), m_called(NULL)
{
	PTRACE(5, "Neighbor Worker started");
}

NeighborWorker::NeighborWorker(PPER_Stream initial_pdu, endptr called, PIPSocket::Address rx_addr, WORD rx_port, GK_RASListener & server)
	: GK_RASWorker(initial_pdu, rx_addr, rx_port, server), m_called(called)
{
	PTRACE(5, "Neighbor Worker started");
}

NeighborWorker::~NeighborWorker()
{

}

void
NeighborWorker::Main()
{
	if(!pdu.Decode(raw_pdu)) {
		PTRACE(5, "RasWorker: Did not decode message");
		return;
	}
	switch(pdu.GetTag()) {
	case H225_RasMessage::e_locationConfirm:
	case H225_RasMessage::e_admissionRequest:
		OnARQ(pdu);
		break;
	default:
		OnUnknown(pdu);
	}
	if(need_answer)
		SendRas();
	return;
}

void
NeighborWorker::OnARQ(H225_AdmissionRequest &arq)
{
	BOOL reject = FALSE;
	endptr RequestingEP = RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier);
	answer_pdu.SetTag(H225_RasMessage::e_admissionConfirm);
	if (endptr(NULL)==RequestingEP) {
		answer_pdu.SetTag(H225_RasMessage::e_admissionReject);
		H225_AdmissionReject & arj = answer_pdu;
		arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_calledPartyNotRegistered);
		reject=TRUE;
	}
	if (endptr(NULL)==m_called) {
		answer_pdu.SetTag(H225_RasMessage::e_admissionReject);
		H225_AdmissionReject & arj = answer_pdu;
		arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_calledPartyNotRegistered);
		reject=TRUE;
	}
	ProcessARQ(RequestingEP, m_called, arq, reject);
	need_answer=TRUE;
}
