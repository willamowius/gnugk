//////////////////////////////////////////////////////////////////
//
// RAS-Server for H.323 gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
//  990500  initial version (Xiang Ping Chen, Rajat Todi, Joe Metzger)
//  990600  ported to OpenH323 V. 1.08 (Jan Willamowius)
//  990620  bugfix for unregistration (Jan Willamowius)
//  990702  code cleanup, small fixes for compilation under Visual C++ 5 (Jan Willamowius)
//  990924  bugfix for registrations without terminalAlias (Jan Willamowius)
//  991016  clean shutdown (Jan Willamowius)
//  991027  added support for LRQ (Ashley Unitt)
//  991100  new call table (Jan Willamowius)
//  991100  status messages (Henrik Joerring)
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4800 ) // one performance warning off
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#define snprintf _snprintf
#endif

//towi. if you did not patch the openh323-lib
#define NO_ARJREASON_ROUTECALLTOSCN

#include <ptlib.h>
#include <ptlib/sockets.h>
#include <stdio.h>

#include "RasSrv.h"
#include "gk_const.h"
#include "h323util.h"
#include "gk.h"
#include "Toolkit.h"
#include "SoftPBX.h"
#include "ANSI.h"

#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define MAX(x,y) ((x) < (y) ? (y) : (x))




H323RasSrv::H323RasSrv(PIPSocket::Address _GKHome)
  : listener(Toolkit::Config()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT)),
	udpForwarding()
{
	GKHome = _GKHome;
	
	EndpointTable = RegistrationTable::Instance();
	GKManager = resourceManager::Instance();

	GKCallSignalAddress.SetTag(H225_TransportAddress::e_ipAddress);
	H225_TransportAddress_ipAddress & ipAddress = GKCallSignalAddress;
	GKRasAddress.SetTag(H225_TransportAddress::e_ipAddress);
	H225_TransportAddress_ipAddress & RasIpAddress = GKRasAddress;

	GKroutedSignaling = FALSE;
	TimeToLive = -1; 	// don't set the files
	sigListener = NULL;

	// own IP number
	ipAddress.m_ip[0] = GKHome.Byte1();
	ipAddress.m_ip[1] = GKHome.Byte2();
	ipAddress.m_ip[2] = GKHome.Byte3();
	ipAddress.m_ip[3] = GKHome.Byte4();
	ipAddress.m_port = Toolkit::Config()->GetInteger("RouteSignalPort", GK_DEF_ROUTE_SIGNAL_PORT);

	RasIpAddress.m_ip[0] = GKHome.Byte1();
	RasIpAddress.m_ip[1] = GKHome.Byte2();
	RasIpAddress.m_ip[2] = GKHome.Byte3();
	RasIpAddress.m_ip[3] = GKHome.Byte4();
	int rp = Toolkit::Config()->GetInteger("UnicastRasPort", GK_DEF_UNICAST_RAS_PORT);
	RasIpAddress.m_port = Toolkit::Config()->GetInteger("UnicastRasPort", rp);

	PTRACE(2, "GK\tRasIP Address: " << GKHome << "[" << rp << "]");

	udpForwarding.SetWriteTimeout(PTimeInterval(300));
 
	GkStatusThread = new GkStatus(GKHome);
}


H323RasSrv::~H323RasSrv()
{
}

void H323RasSrv::Close(void)
{
	PTRACE(2, "GK\tClosing RasSrv");
 
	listener.Close();
	if (GKroutedSignaling)
	{
		sigListener->Close();
		sigListener->WaitForTermination();
		delete sigListener;
		sigListener = NULL;
	};
	if (GkStatusThread != NULL)
	{
		GkStatusThread->Close();
		GkStatusThread->WaitForTermination();
		delete GkStatusThread;
		GkStatusThread = NULL;
	};
 
	PTRACE(1, "GK\tRasSrv closed");
}


void H323RasSrv::UnregisterAllEndpoints(void)
{
	SoftPBX::Instance()->UnregisterAllEndpoints();
};


/* Gatekeeper request */
BOOL H323RasSrv::OnGRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_grq, H225_RasMessage & obj_rpl)
{
	const H225_GatekeeperRequest & obj_gr = obj_grq;

	// reply only if gkID matches
	if ( obj_gr.HasOptionalField ( H225_GatekeeperRequest::e_gatekeeperIdentifier ) )
		if (obj_gr.m_gatekeeperIdentifier.GetValue() != GetGKName()) 
			return FALSE;

	// Always confirm a GRQ request.
	obj_rpl.SetTag(H225_RasMessage::e_gatekeeperConfirm); 
	H225_GatekeeperConfirm & obj_gcf = obj_rpl;

	obj_gcf.m_requestSeqNum = obj_gr.m_requestSeqNum;
	obj_gcf.m_protocolIdentifier = obj_gr.m_protocolIdentifier;
	obj_gcf.m_nonStandardData = obj_gr.m_nonStandardData;
	obj_gcf.m_rasAddress = GKRasAddress;
	obj_gcf.IncludeOptionalField(obj_gcf.e_gatekeeperIdentifier);
	obj_gcf.m_gatekeeperIdentifier.SetValue( GetGKName() );

	PString aliasListString;
	if (obj_gr.HasOptionalField(H225_GatekeeperRequest::e_endpointAlias)) {
		aliasListString = AsString(obj_gr.m_endpointAlias);
	}
	else aliasListString = " ";

	PString msg(PString::Printf, "GCF|%s|%s|%s;\r\n", 
		    inet_ntoa(rx_addr),
		    (const unsigned char *) aliasListString,
		    (const unsigned char *) AsString(obj_gr.m_endpointType) );

	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);
		
	return TRUE;
}

    
  

BOOL H323RasSrv::SigAuthCondition(const H225_TransportAddress &SignalAdr, const PString &Condition) const
{
	const static BOOL ON_ERROR = TRUE; // return value on parse error in condition

	const PStringArray rule = Condition.Tokenise(":", FALSE);
	if(rule.GetSize() < 1) {
		PTRACE(1, "Errornous RRQAuth rule: " << Condition);
		return ON_ERROR;
	}
	
	// 
	// condition = rule[0]:rule[1]... = rName:params...
	//
	
	const PString &rName = rule[0];
	//
	// condition 'sigaddr' example:
	//   sigaddr:.*ipAddress .* ip = .* c3 47 e2 a2 .*port = 1720.*
	//
	if(rName=="sigaddr") {
		return Toolkit::MatchRegex(AsString(SignalAdr), rule[1]);
	}
	//
	// condition 'sigip' example:
	//   sigip:195.71.129.69:1720
	//
	else if(rName=="sigip") { 
		// we build a regex like "sigaddr" from the params of "sigip"
		const PStringArray ip4 = rule[1].Tokenise(".",FALSE);
		if(rule.GetSize()<2 || ip4.GetSize()<4) {
			PTRACE(1, "Errornous RRQAuth condition: " << Condition);
			return ON_ERROR;
		}
		PString regexStr(PString::Printf, 
						 ".*ipAddress .* ip = .* %02x %02x %02x %02x .*port = %s.*",
						 ip4[0].AsInteger(),
						 ip4[1].AsInteger(),
						 ip4[2].AsInteger(),
						 ip4[3].AsInteger(),
						 (const char*)(rule[2]) /*port*/ );
		
		return Toolkit::MatchRegex(AsString(SignalAdr), regexStr);
	}
	else {
		PTRACE(4, "Unknown RRQAuth condition: " << Condition);
		return ON_ERROR;
	}

	// not reached...
	return FALSE;
}




BOOL 
H323RasSrv::SetAlternateGK(H225_RegistrationConfirm &rcf)
{
	PTRACE(5, ANSI::BLU << "Alternating? " << ANSI::OFF);
	BOOL result = FALSE;

	// TODO: speed up with pre-parsing of config line
	PString param = Toolkit::Config()->GetString("AlternateGKs","");
	if(param != "") {
		PTRACE(5, ANSI::BLU << "Alternating: yes! " << ANSI::OFF);
		result = TRUE;

        const PStringArray &altgks = param.Tokenise(" ,;\t", FALSE);
		rcf.IncludeOptionalField(H225_RegistrationConfirm::e_alternateGatekeeper);
		rcf.m_alternateGatekeeper.SetSize(altgks.GetSize());

		for(PINDEX idx=0; idx<altgks.GetSize(); idx++) {
			const PString &altgk = altgks[idx];
			const PStringArray &tokens = altgk.Tokenise(":", FALSE);

			if(tokens.GetSize() < 4) {
				PTRACE(1,"GK\tFormat error in AlternateGKs");
				continue; 
			}

			H225_AlternateGK &A = rcf.m_alternateGatekeeper[idx];
			
			const PStringArray &bytes = tokens[0].Tokenise(".", FALSE);
			if(bytes.GetSize() != 4) {
				PTRACE(1,"GK\tFormat error in AlternateGKs IP");
				continue; 
			}
			
			A.m_rasAddress.SetTag(H225_TransportAddress::e_ipAddress);
			H225_TransportAddress_ipAddress & ip = A.m_rasAddress;
			ip.m_ip.SetSize(4);
			ip.m_ip[0] = bytes[0].AsUnsigned();
			ip.m_ip[1] = bytes[1].AsUnsigned();
			ip.m_ip[2] = bytes[2].AsUnsigned();
			ip.m_ip[3] = bytes[3].AsUnsigned();
			ip.m_port  = tokens[1].AsUnsigned();
			
			A.m_needToRegister = Toolkit::AsBool(tokens[2]);
			
			A.m_priority = tokens[3].AsInteger();;
			
			if(tokens.GetSize() > 4) {
				A.IncludeOptionalField(H225_AlternateGK::e_gatekeeperIdentifier);
				A.m_gatekeeperIdentifier = tokens[4];
			}
		}
	}
	
	return result;
}


BOOL
H323RasSrv::ForwardRasMsg(H225_RasMessage msg) // not passed as const, ref or pointer!
{
	PTRACE(5, ANSI::BLU << "Forwarding? " << ANSI::OFF);
	BOOL result = FALSE;

	PString param = Toolkit::Config()->GetString("Sendto","");
	if(param != "") {
		PTRACE(5, ANSI::BLU << "Forwarding: yes! " << ANSI::OFF);
		result = TRUE;

		// include the "this is a forwared message" tag (could be a static variable to increase performance)
		H225_NonStandardParameter nonStandardParam;
		H225_NonStandardIdentifier &id = nonStandardParam.m_nonStandardIdentifier;
		id.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
		H225_H221NonStandard & h221 = id;
		h221.m_t35CountryCode   = Toolkit::t35cOpenOrg;
		h221.m_t35Extension     = Toolkit::t35eFailoverRAS;
		h221.m_manufacturerCode = Toolkit::t35mOpenOrg;
		nonStandardParam.m_data.SetSize(0);

		switch(msg.GetTag()) {
		case H225_RasMessage::e_registrationRequest: {
			H225_RegistrationRequest &o = msg;
			o.IncludeOptionalField(H225_UnregistrationRequest::e_nonStandardData);
			o.m_nonStandardData = nonStandardParam;
			break;
		}
		case H225_RasMessage::e_unregistrationRequest: {
			H225_UnregistrationRequest &o = msg;
			o.IncludeOptionalField(H225_UnregistrationRequest::e_nonStandardData);
			o.m_nonStandardData = nonStandardParam;
			break;
		}
		default:
			PTRACE(2,"Warning: unsupported RAS message type for forwarding; field 'forwarded' not included in msg.");
		}
		
		// send to all
		const PStringArray &svrs = param.Tokenise(" ,;\t", FALSE);
		for(PINDEX i=0; i<svrs.GetSize(); i++) {
			const PString &svr = svrs[i];
			const PStringArray &tokens = svr.Tokenise(":", FALSE);
			if(tokens.GetSize() != 2) {
				PTRACE(1,"GK\tFormat error in Sendto");
				continue; 
			}
			PTRACE(4, ANSI::BLU << "Forwarding RRQ to " 
				   << ( (PIPSocket::Address)tokens[0] ) 
				   << ":" << ( (unsigned)(tokens[1].AsUnsigned()) ) << ANSI::OFF);
				SendReply(msg,
					  (PIPSocket::Address)tokens[0], 
					  (unsigned)(tokens[1].AsUnsigned()), 
					  udpForwarding);
		}
	}
	
	return result;
}


/* Registration Request */
BOOL H323RasSrv::OnRRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_rrq, H225_RasMessage & obj_rpl)
{
	const H225_RegistrationRequest & obj_rr = obj_rrq;
	PINDEX cnt;
	BOOL bHasAlias = FALSE;
	BOOL bAliasIsKnown = TRUE;
	BOOL bAlreadyRegistered;	// by someone else
	BOOL bReject = FALSE;		// RRJ with any other reason from #rejectReason#
	H225_RegistrationRejectReason rejectReason;

	H225_ArrayOf_AliasAddress NewAliases;
	H225_TransportAddress SignalAdr;
	H225_EndpointIdentifier NewEndpointId;

	//towi-00/02/03: MWays specific; GK-Failover
	BOOL bShellSendReply = TRUE;
	BOOL bShellForwardRequest = TRUE;

	// mechanism 1: forwarding detection per "flag"
	if(obj_rr.HasOptionalField(H225_RegistrationRequest::e_nonStandardData)) {
		switch(obj_rr.m_nonStandardData.m_nonStandardIdentifier.GetTag()) {
		case H225_NonStandardIdentifier::e_h221NonStandard:
			const H225_H221NonStandard &nonStandard = 
				(const H225_H221NonStandard&)(obj_rr.m_nonStandardData.m_nonStandardIdentifier);
			int iec = Toolkit::Instance()->GetInternalExtensionCode(nonStandard);
			if(iec == Toolkit::iecFailoverRAS) {
				bShellSendReply = FALSE;
				bShellForwardRequest = FALSE;
			}
		}
	}

	// mechanism 2: forwarding detection per "from"
	{
		const PString addr = rx_addr;
		if(Toolkit::AsBool(Toolkit::Config()->GetString("skipfrom-"+addr, ""))) {
			bShellSendReply = FALSE;
			bShellForwardRequest = FALSE;
		}
	}
	if(!bShellForwardRequest)
		PTRACE(4, "RRQ\tSkip forwarding.");

	//:towi

	// lightweight registration update
	if (obj_rr.HasOptionalField(H225_RegistrationRequest::e_keepAlive) &&
		obj_rr.m_keepAlive.GetValue())
	{
		if (EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier) != NULL)
		{
			// endpoint was already registered
			obj_rpl.SetTag(H225_RasMessage::e_registrationConfirm); 
			H225_RegistrationConfirm & rcf = obj_rpl;
			rcf.m_requestSeqNum = obj_rr.m_requestSeqNum;
			rcf.m_protocolIdentifier =  obj_rr.m_protocolIdentifier;
			rcf.m_endpointIdentifier = obj_rr.m_endpointIdentifier;
			rcf.IncludeOptionalField(rcf.e_gatekeeperIdentifier);
			rcf.m_gatekeeperIdentifier.SetValue( GetGKName() );
			if (TimeToLive != -1)
			{
				rcf.IncludeOptionalField(rcf.e_timeToLive);
				rcf.m_timeToLive = TimeToLive;
			};

			//towi-00/02/04: Alternate GKs
			SetAlternateGK(rcf);
			//:towi

			//towi-00/02/04: forward lightweights, too
			if(bShellForwardRequest) 
				ForwardRasMsg(EndpointTable->FindByEndpointId
							  (obj_rr.m_endpointIdentifier)->GetCompleteRegistrationRequest());
			//:towi

			return bShellSendReply;
		}
		else {
			// endpoint was NOT registered
			bReject = TRUE;
			rejectReason.SetTag(H225_RegistrationRejectReason::e_fullRegistrationRequired);
		}
	};

	if (obj_rr.m_callSignalAddress.GetSize() >= 1)
		SignalAdr = obj_rr.m_callSignalAddress[0];
	else {
		bReject = TRUE;
		rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidCallSignalAddress);
	}

	bHasAlias = (obj_rr.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) && (obj_rr.m_terminalAlias.GetSize() >= 1));

	if (bHasAlias)
		NewAliases = obj_rr.m_terminalAlias;
	else {
		// reject gw without alias
		switch (obj_rr.m_terminalType.GetTag()) {
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
	
	if (!bReject)
		bAliasIsKnown = (EndpointTable->FindByAnyAliasInList(NewAliases) != NULL);

	if (!bReject &&
	   bHasAlias && 
	   bAliasIsKnown &&
	   (EndpointTable->FindByAnyAliasInList(NewAliases)->m_callSignalAddress != SignalAdr)
	   ) {
		bReject = TRUE;
		rejectReason.SetTag(H225_RegistrationRejectReason::e_duplicateAlias);
	}

	bAlreadyRegistered = (EndpointTable->FindBySignalAdr(SignalAdr) != NULL );
	//towi-00/02/03: use the sent regId if possible
	if(obj_rr.HasOptionalField(H225_RegistrationRequest::e_endpointIdentifier)) {
		NewEndpointId = obj_rr.m_endpointIdentifier;
		endpointRec *ep = (endpointRec*)( EndpointTable->FindBySignalAdr(SignalAdr) ); 
		if( ep != NULL) {
			ep->m_endpointIdentifier = NewEndpointId;
		}
		//if(EndpointTable->FindByEndpointId(NewEndpointId) != NULL)
			// already used by another EP => generate own OR reject
		//	NewEndpointId = EndpointTable->GenerateEndpointId();
		//}
		//else
		//	NewEndpointId = EndpointTable->GenerateEndpointId();
	}
	else if (bAlreadyRegistered)
		NewEndpointId = EndpointTable->FindBySignalAdr(SignalAdr)->m_endpointIdentifier;
	else
		NewEndpointId = EndpointTable->GenerateEndpointId();
	

	if (!bHasAlias)
		NewAliases = EndpointTable->GenerateAlias(NewEndpointId);

	// reject the empty string
	for (PINDEX AliasIndex=0; AliasIndex < NewAliases.GetSize(); ++AliasIndex)
	{
		const PString & s = AsString(NewAliases[AliasIndex], FALSE);
		if (s.GetLength() < 1 || !isalnum(s[0]) ) {
			bReject = TRUE;
			rejectReason.SetTag(H225_RegistrationRejectReason::e_invalidAlias);
		}
	}

	// Extended Registration Auth Rules
	{
		// #alias# is the config file entry of this endpoint
		const PString alias = AsString(NewAliases[0], FALSE);
		const PString cfgString = Toolkit::Config()->GetString("RasSrv::RRQAuth", alias, "");
		if (cfgString != "") {
			const PStringArray conditions = cfgString.Tokenise("&", FALSE);

			for (PINDEX iCnd=0; iCnd<conditions.GetSize(); iCnd++) {
				
				if (!SigAuthCondition(SignalAdr, conditions[iCnd])) {
					bReject = TRUE;
					rejectReason.SetTag(H225_RegistrationRejectReason::e_securityDenial);
					PTRACE(4, "Gk\tRRQAuth condition '" << conditions[iCnd] << "' rejected endpoint " << alias);
					break;
				}
				else
					PTRACE(4, "Gk\tRRQAuth condition applied successfully for endpoint " << alias);
			}
		}
	}

	//
	// final rejection handling
	//
	if (bReject) {
		obj_rpl.SetTag(H225_RasMessage::e_registrationReject); 
		H225_RegistrationReject & rrj = obj_rpl;
 
		rrj.m_requestSeqNum = obj_rr.m_requestSeqNum;
		rrj.m_protocolIdentifier =  obj_rr.m_protocolIdentifier;
		rrj.m_nonStandardData = obj_rr.m_nonStandardData ;
		rrj.IncludeOptionalField(rrj.e_gatekeeperIdentifier);
		rrj.m_gatekeeperIdentifier.SetValue( GetGKName() );
		rrj.m_rejectReason = rejectReason;
			
		PString aliasListString;
		if (obj_rr.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
			aliasListString = AsString(obj_rr.m_terminalAlias);
		else
			aliasListString = " ";
		
		PString msg(PString::Printf, "RRJ|%s|%s|%s|%s;\r\n", 
			    inet_ntoa(rx_addr),
			    (const unsigned char *) aliasListString,
			    (const unsigned char *) AsString(obj_rr.m_terminalType),
			    (const unsigned char *) rrj.m_rejectReason.GetTagName()
			    );
		PTRACE(2,msg);
		GkStatusThread->SignalStatus(msg);
		return bShellSendReply;
	}   
	
	// make a copy for modifying
	H225_RasMessage store_rrq = obj_rrq;

	if (!bAlreadyRegistered) { 
		H225_RegistrationRequest & store_rr = store_rrq;
		
		// we want to use the same 'endpoint id' in all GKs
		store_rr.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
		store_rr.m_endpointIdentifier = NewEndpointId;

		// new endpoint registration.    
		endpointRec er(obj_rr.m_rasAddress[0], SignalAdr, NewEndpointId, NewAliases, obj_rr.m_terminalType,
					   store_rrq);
		EndpointTable->Insert(er);

		PString NewAliasStr = ((PASN_BMPString&)NewAliases[0].GetObject()).GetValue();
		if (NewAliasStr != "") {
			PString prefixes = Toolkit::Config()->GetString("RasSvr::GWPrefixes", NewAliasStr, "");
			if (prefixes != "") {
				EndpointTable->AddPrefixes(NewAliasStr, prefixes);
				PTRACE(2, ANSI::DBG << "Gateway prefixes for '" << NewAliasStr << "' are '" << prefixes << "'" << ANSI::OFF);
			} 
			// else: do nothing; the RasTbl::GatewayPrefixes will return NULL for that GW-alias.
		}
	}
	else if ( bHasAlias ) {
		// this registration request only updates the alias
		EndpointTable->UpdateAliasBySignalAdr(SignalAdr, NewAliases);
	}
	
	obj_rpl.SetTag(H225_RasMessage::e_registrationConfirm); 
	H225_RegistrationConfirm & rcf = obj_rpl;
	rcf.m_requestSeqNum = obj_rr.m_requestSeqNum;
	rcf.m_protocolIdentifier =  obj_rr.m_protocolIdentifier;
	rcf.m_nonStandardData = obj_rr.m_nonStandardData;
	rcf.m_callSignalAddress.SetSize( obj_rr.m_callSignalAddress.GetSize() );
	for( cnt = 0; cnt < obj_rr.m_callSignalAddress.GetSize(); cnt ++ )
		rcf.m_callSignalAddress[cnt] = obj_rr.m_callSignalAddress[cnt];
	
	rcf.IncludeOptionalField( H225_RegistrationConfirm::e_terminalAlias);
	rcf.m_terminalAlias = NewAliases;
	rcf.m_endpointIdentifier = NewEndpointId;
	rcf.IncludeOptionalField(rcf.e_gatekeeperIdentifier);
	rcf.m_gatekeeperIdentifier.SetValue( GetGKName() );
	if (TimeToLive != -1)
	{
		rcf.IncludeOptionalField(rcf.e_timeToLive);
		rcf.m_timeToLive = TimeToLive;
	};


	//towi-00/02/04: Alternate GKs
	SetAlternateGK(rcf);
	//:towi

	//towi-00/02/04: forward heavyweiht
	if(bShellForwardRequest) {
		ForwardRasMsg(store_rrq);
	}
	//:towi

	// Note that the terminalAlias is not optional here as we pass the auto generated alias if not were provided from
	// the endpoint itself
	PString msg(PString::Printf, "RCF|%s|%s|%s|%s;\r\n", 
		    inet_ntoa(rx_addr),
		    (const unsigned char *) AsString(rcf.m_terminalAlias),
		    (const unsigned char *) AsString(obj_rr.m_terminalType),
		    (const unsigned char *) NewEndpointId.GetValue()
		    );
	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);

	return bShellSendReply;
}



BOOL H323RasSrv::CheckForIncompleteAddress(const PString &aliasStr) const
{
	// #aliasStr# must not include a ":" char!

	const PString IncAddrs = Toolkit::Config()->GetString
		("RasSvr::ARQ", "IncompleteAddresses", "");
	if (IncAddrs == "") 
		return FALSE; // not an incomplete address
		
	BOOL found = IncAddrs.Find(":" + aliasStr) >= 0;

	PTRACE(4,"Gk\tConsidered as incomplete address: " << aliasStr);

	return found;
}
	
	
/* Admission Request */
BOOL H323RasSrv::OnARQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_arq, H225_RasMessage & obj_rpl)
{    
	const H225_AdmissionRequest & obj_rr = obj_arq;
	PTRACE(1, "OnARQ");
	const endpointRec * RequestingEP = EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier);

	endpointRec * CalledEP = NULL;
	int BWRequest = 640; //towi:initialized

	// We use #obj_rpl# for storing information about a potential reject (e.g. the
	// rejectReason). If the request results in a confirm (bReject==FALSE) then
	// we have to ignore the previous set data in #obj_rpl# and re-cast it.
	BOOL bReject = FALSE;
	obj_rpl.SetTag(H225_RasMessage::e_admissionReject); 
	H225_AdmissionReject & arj = obj_rpl; 


	if (obj_rr.m_destinationInfo.GetSize() >= 1)
	{
	    // apply rewrite rules
	    Toolkit::Instance()->RewriteE164(obj_rr.m_destinationInfo[0]);

		CalledEP = (endpointRec *)EndpointTable->FindByAlias(obj_rr.m_destinationInfo[0]);

		// try gw prefix match
		if (CalledEP == NULL)
			CalledEP = (endpointRec *)EndpointTable->FindByPrefix(obj_rr.m_destinationInfo[0]);
	}

	// if a destination address is provided, we check if we know it
	if ( !obj_rr.HasOptionalField( H225_AdmissionRequest::e_destCallSignalAddress) )
	{
		// allow overlap sending for incomplete prefixes
		if (CalledEP == NULL && obj_rr.m_destinationInfo.GetSize() >= 1) {
			const PString alias = AsString(obj_rr.m_destinationInfo[0], FALSE);
			if (CheckForIncompleteAddress(alias)) {
				bReject = TRUE;
				arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_incompleteAddress);
			}
		}
	};  

	if(!bReject && CalledEP == NULL) //towi-000225: CalledEP was NULL later
	{
		bReject = TRUE;
		arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_calledPartyNotRegistered);
	}

	// check if the endpoint requesting is registered with this getekeeper
	if (!bReject && RequestingEP == NULL)
	{
		bReject = TRUE;
		arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_callerNotRegistered/*was :e_invalidEndpointIdentifier*/);
	}
	
	//
	// Bandwidth 
	// and GkManager admission
	//
	if (!bReject) {
		//
		// Give bandwidth
		// 
		if (obj_rr.m_bandWidth.GetValue() < 100) {
			/* hack for Netmeeting 3.0x */
			BWRequest = MIN(1280, GKManager->GetAvailableBW());
		}
		else {
			BWRequest = MIN(obj_rr.m_bandWidth.GetValue(), GKManager->GetAvailableBW());
		};
		PTRACE(3, "GK\tARQ will request bandwith of " << BWRequest);
		
		//
		// GkManager admission
		//
		if (!GKManager->GetAdmission(obj_rr.m_endpointIdentifier, obj_rr.m_conferenceID, BWRequest)) {
			bReject = TRUE;
			arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_resourceUnavailable);
		}
	}

#ifndef NO_ARJREASON_ROUTECALLTOSCN
	//towi:000222
	//
	// call from one GW to itself? 
	// generate ARJ-reason: 'routeCallToSCN'
	//
	if(!bReject && 
	   Toolkit::AsBool(Toolkit::Config()->GetString("RasSrv::ARQFeatures","ArjReasonRouteCallToSCN","TRUE")) ) 
	{
		// are the endpoints the same (GWs of course)?
		if( (CalledEP != NULL) && (RequestingEP != NULL) && (CalledEP == RequestingEP) && 
			(!obj_rr.m_answerCall) // only first ARQ may be rejected with with 'routeCallToSCN'
			) 
		{
			// we have to extract the SCN from the destination. only EP-1 will be rejected this way
			if ( obj_rr.m_destinationInfo.GetSize() >= 1 ) 
			{
				// PN will be the number that is set in the arj reason
				H225_PartyNumber PN;
				PN.SetTag(H225_PartyNumber::e_publicNumber);
				H225_PublicPartyNumber &PPN = PN;
				// set defaults
				PPN.m_publicTypeOfNumber.SetTag(H225_PublicTypeOfNumber::e_unknown);
				PPN.m_publicNumberDigits = "";
				
				// there can be diffent information in the destination info
				switch(obj_rr.m_destinationInfo[0].GetTag()) {
				case H225_AliasAddress::e_e164: 
					// normal number, extract only thge digits
					PPN.m_publicNumberDigits = AsString(obj_rr.m_destinationInfo[0], FALSE);
					break;
				case H225_AliasAddress::e_partyNumber: 
					// ready-to-use party number
					PN = obj_rr.m_destinationInfo[0];
					break;
				default:
					PTRACE(1,"Unsupported AliasAdress for ARQ reason 'routeCallToSCN': "
						   << obj_rr.m_destinationInfo[0]);
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
	//:towi
#endif
	
	//
	// Do the reject or the confirm
	//
	if (bReject)
	{
		// has to be set before!!!
		// obj_rpl.SetTag(H225_RasMessage::e_admissionReject); 
		// H225_AdmissionReject & arj = obj_rpl;
		// arj.m_rejectReason.SetTag(H225_AdmissionRejectReason::e_resourceUnavailable);
 
		arj.m_requestSeqNum = obj_rr.m_requestSeqNum;

		PString destinationInfoString;
		if (obj_rr.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
			destinationInfoString = AsString(obj_rr.m_destinationInfo);
		else
			destinationInfoString = " ";

		PString msg(PString::Printf, "ARJ|%s|%s|%s|%s|%s;\r\n", 
			    inet_ntoa(rx_addr),
			    (const unsigned char *) destinationInfoString,
			    (const unsigned char *) AsString(obj_rr.m_srcInfo),
			    (obj_rr.m_answerCall) ? "true" : "false",
			    (const unsigned char *) arj.m_rejectReason.GetTagName() );
		PTRACE(2,msg);
		GkStatusThread->SignalStatus(msg);
		return TRUE;
	}   
	else
	{
		BOOL sendStatusMsg = TRUE; // to indicate whether both endpoints have obtained admission
		
		// new connection admitted.
		obj_rpl.SetTag(H225_RasMessage::e_admissionConfirm); // re-cast (see above)
		H225_AdmissionConfirm & acf = obj_rpl;

		acf.m_requestSeqNum = obj_rr.m_requestSeqNum;
		acf.m_bandWidth = BWRequest;

		CallRec * pExistingCallRec = NULL;
		
		if ( GKroutedSignaling )
		{
			H225_TransportAddress destAddress;
			  // in routed mode we only use aliases
			  // we can't redirect absolut callSignalladdresses right now
			  // if that were desired, we'd have to add a list with the callRef and
			  // the callSignallAddress from the ARQ, to create the new proper
			  // connection on SETUP
			destAddress = CalledEP->m_callSignalAddress; //towi-000225: CalledEP was NULL ###
//  			H225_TransportAddress_ipAddress & address = destAddress;
//  			PIPSocket::Address * calledEndpoint =
//  				new PIPSocket::Address( address.m_ip[0], address.m_ip[1], address.m_ip[2], address.m_ip[3]);

//  			PString caller;
//  			PString called = calledEndpoint->AsString();
//  			if ( sigListener->getCallTable()->GetCrvIndex( obj_rr.m_callReferenceValue ) == P_MAX_INDEX )
//  			{
//  				sigListener->getCallTable()->NewCall( obj_rr.m_callReferenceValue, caller, called );
//  				// Now a new element is created and SignalConnection will use it to connect
//  				// to called endpoint.
//  			};

// BUG: check on 2nd ARQ if there is a CallRec already and only
// update CallRef !!!
			// add the new call to global table
			EndpointCallRec Calling(RequestingEP->m_callSignalAddress, RequestingEP->m_rasAddress, obj_rr.m_callReferenceValue);
			EndpointCallRec * pCalled = NULL;
			if (CalledEP != NULL)
				pCalled = new EndpointCallRec(CalledEP->m_callSignalAddress, CalledEP->m_rasAddress, 0);
			else
			{
				H225_TransportAddress EmptyRasAdr;
				EmptyRasAdr.SetTag(H225_TransportAddress::e_ipAddress);
				H225_CallReferenceValue EmptyCallRef;
				pCalled = new EndpointCallRec(destAddress, EmptyRasAdr, EmptyCallRef);
			};
			CallTable::Instance()->Insert(Calling, *pCalled, BWRequest, obj_rr.m_callIdentifier, obj_rr.m_conferenceID);

			acf.m_callModel.SetTag( H225_CallModel::e_gatekeeperRouted );
			acf.m_destCallSignalAddress = GKCallSignalAddress;
		}
		else
		{
			  // direct signalling

			  //Is there an entry in CallTable with this  callReferenceValue
			if (NULL != (pExistingCallRec = (CallRec *)CallTable::Instance()->FindCallRec(obj_rr.m_callReferenceValue))) {
				  // the call is already in the table hence this must be the 2. ARQ
				EndpointCallRec newEP(RequestingEP->m_callSignalAddress, RequestingEP->m_rasAddress, obj_rr.m_callReferenceValue);

				if (pExistingCallRec->Called)	// This test is not necessary - the second ARQ is from called
					pExistingCallRec->SetCalling(newEP);
				else
					pExistingCallRec->SetCalled(newEP);
				
				sendStatusMsg = TRUE;
			}
			else {
				  // the call is not in the table hence this must be the 1. ARQ

				EndpointCallRec Calling(RequestingEP->m_callSignalAddress, RequestingEP->m_rasAddress, obj_rr.m_callReferenceValue);

				sendStatusMsg = FALSE;
				
				  /*
					if (CalledEP != NULL)
					pCalled = new EndpointCallRec(CalledEP->m_callSignalAddress, CalledEP->m_rasAddress, 0);
					else
					{
					H225_TransportAddress EmptyRasAdr;
					EmptyRasAdr.SetTag(H225_TransportAddress::e_ipAddress);
					H225_CallReferenceValue EmptyCallRef;
					pCalled = new EndpointCallRec(destAddress, EmptyRasAdr, EmptyCallRef);
					}
				  */
				CallTable::Instance()->Insert(Calling, BWRequest, obj_rr.m_callIdentifier, obj_rr.m_conferenceID);
				sendStatusMsg = FALSE;
			}
			
			// Set ACF fields
			acf.m_callModel.SetTag( H225_CallModel::e_direct );
			if( obj_rr.HasOptionalField( H225_AdmissionRequest::e_destCallSignalAddress) )
				acf.m_destCallSignalAddress = obj_rr.m_destCallSignalAddress;
			else
				acf.m_destCallSignalAddress = CalledEP->m_callSignalAddress;
		}

		acf.IncludeOptionalField ( H225_AdmissionConfirm::e_irrFrequency );
		acf.m_irrFrequency.SetValue( 120 );

		if (sendStatusMsg)
		{	
			PString destinationInfoString;
			if (obj_rr.HasOptionalField(H225_AdmissionRequest::e_destinationInfo))
				destinationInfoString = AsString(obj_rr.m_destinationInfo);
			else
				destinationInfoString = AsString(RegistrationTable::Instance()->FindBySignalAdr(pExistingCallRec->Called->m_callSignalAddress)->m_terminalAliases);

			char callReferenceValueString[8];
			sprintf(callReferenceValueString, "%u", (unsigned) obj_rr.m_callReferenceValue);

			PString msg(PString::Printf, "ACF|%s|%s|%s|%s|%s;\r\n", 
				    inet_ntoa(rx_addr),
				    (const unsigned char *) RequestingEP->m_endpointIdentifier.GetValue(),
				    callReferenceValueString,
				    (const unsigned char *) destinationInfoString,
				    (const unsigned char *) AsString(obj_rr.m_srcInfo)
				    );
			PTRACE(2,msg);
			GkStatusThread->SignalStatus(msg);
		}
		
	}
	return TRUE;
}


/* Disengage Request */
BOOL H323RasSrv::OnDRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage & obj_drq, H225_RasMessage & obj_rpl)
{    
	const H225_DisengageRequest & obj_rr = obj_drq;

	char callReferenceValueString[8];
	sprintf(callReferenceValueString, "%u", (unsigned) obj_rr.m_callReferenceValue);
		
	PTRACE(4,"DRQ");
	PString msg;
	
	if ( GKManager->CloseConference(obj_rr.m_endpointIdentifier, obj_rr.m_conferenceID) )
	{
		PTRACE(4,"\tDRQ: closed conference");
		obj_rpl.SetTag(H225_RasMessage::e_disengageConfirm); 
		H225_DisengageConfirm & dcf = obj_rpl;
		dcf.m_requestSeqNum = obj_rr.m_requestSeqNum;    

		if ( GKroutedSignaling )
		{
//			sigListener->m_callTable.HungUp(obj_rr.m_callReferenceValue);
			CallTable::Instance()->RemoveEndpoint(obj_rr.m_callReferenceValue);
		}
		else {
			// I do not know if more is to be done - if not then the routing type check is obsolete
			CallTable::Instance()->RemoveEndpoint(obj_rr.m_callReferenceValue);
		}
		PTRACE(4,"\tDRQ: removed first endpoint");
		
		// we signal end of call on first DRQ
		PString msg2(PString::Printf, "DCF|%s|%s|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) obj_rr.m_endpointIdentifier.GetValue(),
			     callReferenceValueString,
			     (const unsigned char *) obj_rr.m_disengageReason.GetTagName() );
		msg = msg2;
	}
	// The first EP that sends DRQ closes the conference and removes the CallTable entry -
	// this should not exclude the second one
	// from receiving DCF. This way we will not catch stray DRQs but we send the right messages ourselves
	else if (EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier))
	{
		PTRACE(4,"\tDRQ: endpoint found"); //towi
		obj_rpl.SetTag(H225_RasMessage::e_disengageConfirm); 
		H225_DisengageConfirm & dcf = obj_rpl;
		dcf.m_requestSeqNum = obj_rr.m_requestSeqNum;
		  /* We only send DCF once - when the first DRQ is received.
			if( 0 > snprintf(MsgBuffer, MSGBUFFERSIZE, "DCF|%s|%s|%s;\r\n", inet_ntoa(rx_addr),
			(const unsigned char *) obj_rr.m_endpointIdentifier.GetValue(),
			callReferenceValueString)) {
			PTRACE(1,"DCF: truncated message buffer string");
			}
		  */

		// storm 15.02.2000
		CallTable::Instance()->RemoveEndpoint(obj_rr.m_callReferenceValue);
		PTRACE(4,"\tDRQ: removed second endpoint");
	}
	else
	{
		PTRACE(4,"\tDRQ: reject"); //towi
		obj_rpl.SetTag(H225_RasMessage::e_disengageReject); 
		H225_DisengageReject & drj = obj_rpl;
		drj.m_requestSeqNum = obj_rr.m_requestSeqNum;
		drj.m_rejectReason.SetTag( drj.m_rejectReason.e_notRegistered );

		PString msg2(PString::Printf, "DRJ|%s|%s|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) obj_rr.m_endpointIdentifier.GetValue(),
			     callReferenceValueString,
			     (const unsigned char *) drj.m_rejectReason.GetTagName() );
		msg = msg2;
	}

	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);
	return TRUE;
}


/* Unregistration Request */
BOOL H323RasSrv::OnURQ(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_urq, H225_RasMessage &obj_rpl)
{ 
	const H225_UnregistrationRequest & obj_rr = obj_urq;
	PString msg;

	//towi: MWays specific; GK-Failover
	BOOL bShellSendReply = TRUE;
	BOOL bShellForwardRequest = TRUE;

	// mechanism 1: forwarding detection per "flag"
	if(obj_rr.HasOptionalField(H225_UnregistrationRequest::e_nonStandardData)) {
		switch(obj_rr.m_nonStandardData.m_nonStandardIdentifier.GetTag()) {
		case H225_NonStandardIdentifier::e_h221NonStandard:
			const H225_H221NonStandard &nonStandard = 
				(const H225_H221NonStandard&)(obj_rr.m_nonStandardData.m_nonStandardIdentifier);
			int iec = Toolkit::Instance()->GetInternalExtensionCode(nonStandard);
			if(iec == Toolkit::iecFailoverRAS) {
				bShellSendReply = FALSE;
				bShellForwardRequest = FALSE;
			}
		}
	}
	// mechanism 2: forwarding detection per "from"
	{
		const PString addr = rx_addr;
		if(Toolkit::AsBool(Toolkit::Config()->GetString("skipfrom-"+addr, ""))) {
			bShellSendReply = FALSE;
			bShellForwardRequest = FALSE;
		}
	}
	//:towi

	const endpointRec* ep = EndpointTable->FindByEndpointId(obj_rr.m_endpointIdentifier);
	if (ep)
	{
		// remove prefixes if existing
		EndpointTable->RemovePrefixes(ep->m_terminalAliases[0]);

		// Remove from the table
		EndpointTable->RemoveByEndpointId(obj_rr.m_endpointIdentifier);	

		// Return UCF
		obj_rpl.SetTag(H225_RasMessage::e_unregistrationConfirm);
		H225_UnregistrationConfirm & ucf = obj_rpl;
		ucf.m_requestSeqNum = obj_rr.m_requestSeqNum;
		ucf.m_nonStandardData = obj_rr.m_nonStandardData;

		PString endpointIdentifierString;
		if (obj_rr.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier))
			endpointIdentifierString = obj_rr.m_endpointIdentifier.GetValue();
		else
			endpointIdentifierString = " ";

		PString msg2(PString::Printf, "UCF|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) endpointIdentifierString) ;
		msg = msg2;
	}
	else
	{
		// Return URJ	
		obj_rpl.SetTag(H225_RasMessage::e_unregistrationReject);
		H225_UnregistrationReject & urj = obj_rpl;
		urj.m_requestSeqNum = obj_rr.m_requestSeqNum;
		urj.m_nonStandardData = obj_rr.m_nonStandardData ;
		urj.m_rejectReason.SetTag(H225_UnregRejectReason::e_notCurrentlyRegistered);

		PString endpointIdentifierString;
		if (obj_rr.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier))
			endpointIdentifierString = obj_rr.m_endpointIdentifier.GetValue();
		else
			endpointIdentifierString = " ";

		PString msg2(PString::Printf, "URJ|%s|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) endpointIdentifierString,
			     (const unsigned char *) urj.m_rejectReason.GetTagName() );
		msg = msg2;
	}

	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);

	//towi: Forwarding Failover Mechanism; 
	if(bShellForwardRequest) 
		ForwardRasMsg(obj_urq);
	//:towi

	return bShellSendReply;
}


/* Information Request Response */
BOOL H323RasSrv::OnIRR(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &obj_rpl)
{ 
	const H225_InfoRequestResponse & obj_irr = obj_rr;

	if (obj_irr.HasOptionalField( H225_InfoRequestResponse::e_needResponse ))
	{
		obj_rpl.SetTag(H225_RasMessage::e_infoRequestAck);
		H225_InfoRequestAck & ira = obj_rpl;
		ira.m_requestSeqNum = obj_irr.m_requestSeqNum;
		ira.m_nonStandardData = obj_irr.m_nonStandardData;

		PString msg(PString::Printf, "IRR|%s;\r\n", inet_ntoa(rx_addr) );
		PTRACE(2,msg);
		GkStatusThread->SignalStatus(msg);
		return TRUE;
	}
	else
		// otherwise don't respond
		return FALSE;
}


/* Bandwidth Request */
BOOL H323RasSrv::OnBRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &obj_rpl)
{ 
	const H225_BandwidthRequest & obj_brq = obj_rr;

	obj_rpl.SetTag(H225_RasMessage::e_bandwidthConfirm);
	H225_BandwidthConfirm & bcf = obj_rpl;
	bcf.m_requestSeqNum = obj_brq.m_requestSeqNum;
	/* for now we grant whatever bandwidth was requested */
	if (obj_brq.m_bandWidth.GetValue() < 100)
	{
		/* hack for Netmeeting 3.0 */
		bcf.m_bandWidth.SetValue ( 1280 );
	}
	else
	{
		/* otherwise grant what was asked for */
		bcf.m_bandWidth = obj_brq.m_bandWidth;
	};
	bcf.m_nonStandardData = obj_brq.m_nonStandardData;

	PString msg(PString::Printf, "BCF|%s|%s|%u;\r\n", 
		    inet_ntoa(rx_addr),
		    (const unsigned char *) obj_brq.m_endpointIdentifier.GetValue(),
		    bcf.m_bandWidth.GetValue() );
	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);

	return TRUE;
}


/* Location Request */
BOOL H323RasSrv::OnLRQ(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &obj_rpl)
{ 
	const H225_LocationRequest & obj_lrq = obj_rr;
	const endpointRec * WantedEndPoint = EndpointTable->FindByAlias(obj_lrq.m_destinationInfo[0]);
	PString msg;

	// TODO: we should really send the reply to the reply address
	//       we should modify the rx_addr

	if ( WantedEndPoint != NULL )
	{
		// Alias found
		obj_rpl.SetTag(H225_RasMessage::e_locationConfirm);
		H225_LocationConfirm & lcf = obj_rpl;
		lcf.m_requestSeqNum = obj_lrq.m_requestSeqNum;
		lcf.m_callSignalAddress = WantedEndPoint->m_callSignalAddress;
		lcf.m_rasAddress = WantedEndPoint->m_rasAddress;
		lcf.m_nonStandardData = obj_lrq.m_nonStandardData;

		PString sourceInfoString;
		if (obj_lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)) {
			sourceInfoString = AsString(obj_lrq.m_sourceInfo);
		}
		else sourceInfoString = " ";

		PString msg2(PString::Printf, "LCF|%s|%s|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) WantedEndPoint->m_endpointIdentifier.GetValue(),
			     (const unsigned char *) AsString(obj_lrq.m_destinationInfo),
			     (const unsigned char *) sourceInfoString);
		msg = msg2;
	}
	else
	{
		// Alias not found
		obj_rpl.SetTag(H225_RasMessage::e_locationReject);
		H225_LocationReject & lrj = obj_rpl;
		lrj.m_requestSeqNum = obj_lrq.m_requestSeqNum;
		lrj.m_rejectReason.SetTag(H225_LocationRejectReason::e_requestDenied); // can't find the location
		lrj.m_nonStandardData = obj_lrq.m_nonStandardData;

		PString sourceInfoString;
		if (obj_lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo))
			sourceInfoString = AsString(obj_lrq.m_sourceInfo);
		else
			sourceInfoString = " ";

		PString msg2(PString::Printf, "LRJ|%s|%s|%s|%s;\r\n", 
			     inet_ntoa(rx_addr),
			     (const unsigned char *) AsString(obj_lrq.m_destinationInfo),
			     (const unsigned char *) sourceInfoString,
			     (const unsigned char *) lrj.m_rejectReason.GetTagName() );
		msg = msg2;
	};

	PTRACE(2,msg);
	GkStatusThread->SignalStatus(msg);

	return TRUE;
}


/* Resource Availability Indicate */
BOOL H323RasSrv::OnRAI(const PIPSocket::Address & rx_addr, const H225_RasMessage &obj_rr, H225_RasMessage &obj_rpl)
{ 
	const H225_ResourcesAvailableIndicate & obj_rai = obj_rr;

	/* accept all RAIs */
	obj_rpl.SetTag(H225_RasMessage::e_resourcesAvailableConfirm);
	H225_ResourcesAvailableConfirm & rac = obj_rpl;
	rac.m_requestSeqNum = obj_rai.m_requestSeqNum;
	rac.m_protocolIdentifier =  obj_rai.m_protocolIdentifier;
	rac.m_nonStandardData = obj_rai.m_nonStandardData;
    
	return TRUE;
}


void H323RasSrv::SendReply(const H225_RasMessage & obj_rpl, PIPSocket::Address rx_addr, WORD rx_port, PUDPSocket & BoundSocket)
{
	PBYTEArray wtbuf(4096);      //towi: 'new/delete' unneccessary
	PPER_Stream wtstrm(wtbuf);   //towi: 'new/delete' unneccessary

	obj_rpl.Encode(wtstrm);
	wtstrm.CompleteEncoding();
	PTRACE(2, "GK\tSend to "<< rx_addr << " [" << rx_port << "] : " << obj_rpl.GetTagName());
	PTRACE(3, "GK\t" << endl << setprecision(2) << obj_rpl);

	if(! BoundSocket.WriteTo(wtstrm.GetPointer(), wtstrm.GetSize(), rx_addr, rx_port) ) {
		PTRACE(4, "GK\tRAS thread: Write error: " << BoundSocket.GetErrorText());
	} else {
		PTRACE(5, "GK\tSent Successful");
	}

	// delete wtbuf;   /- towi: 'new/delete' unneccessary
	// delete wtstrm;  /- towi: 'new/delete' unneccessary
}

void H323RasSrv::HandleConnections(void)
{
	PString err_msg("ERROR: Request received by gatekeeper: ");   
    PTRACE(2, "GK\tEntering connection handling loop");

	if (GKroutedSignaling)
		sigListener = new SignalChannel(1000, GKHome, Toolkit::Config()->GetInteger("RouteSignalPort", GK_DEF_ROUTE_SIGNAL_PORT));
	listener.Listen(GKHome, 
					Toolkit::Config()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH), 
					listener.GetPort(), 
					PSocket::CanReuseAddress);
	if (!listener.IsOpen())
	{
		PTRACE(1,"GK\tBind to RAS port failed!");
	};

	while (listener.IsOpen())
	{ 
		int iResult;
		WORD rx_port;
		PIPSocket::Address rx_addr;
		H225_RasMessage obj_req;   
		H225_RasMessage obj_rpl;
		BOOL ShallSendReply = FALSE;
		PBYTEArray * rdbuf = new PBYTEArray(4096);
		PPER_Stream * rdstrm = new PPER_Stream(*rdbuf);

		iResult = listener.ReadFrom(rdstrm->GetPointer(), rdstrm->GetSize(), rx_addr, rx_port);
		if (!iResult)
		{
			PTRACE(1, "GK\tRAS thread: Read error: " << listener.GetErrorText());

			delete rdbuf;
			delete rdstrm;

			// TODO: "return" (terminate) on some errors (like the one at shutdown)
			continue;
		};
		PTRACE(2, "GK\tRead from : " << rx_addr << " [" << rx_port << "]");    
    
		if (!obj_req.Decode( *rdstrm ))
		{
			PTRACE(1, "GK\tCouldn't decode message!");

			delete rdbuf;
			delete rdstrm;
 
			continue;
		};
		
		PTRACE(3, "GK\t" << endl << setprecision(2) << obj_req);
 
		delete rdbuf;
		delete rdstrm;

		switch (obj_req.GetTag())
		{
		case H225_RasMessage::e_gatekeeperRequest:    
			PTRACE(1, "GK\tGRQ Received");
			ShallSendReply = OnGRQ( rx_addr, obj_req, obj_rpl );
			break;
			
		case H225_RasMessage::e_registrationRequest:    
			PTRACE(1, "GK\tRRQ Received");
			ShallSendReply = OnRRQ( rx_addr, obj_req, obj_rpl );
			break;
			
		case H225_RasMessage::e_unregistrationRequest :
			PTRACE(1, "GK\tURQ Received");
			ShallSendReply = OnURQ( rx_addr, obj_req, obj_rpl );
			break;
			
		case H225_RasMessage::e_admissionRequest :
			PTRACE(1, "GK\tARQ Received");
			ShallSendReply = OnARQ( rx_addr, obj_req, obj_rpl );
			break;
    
		case H225_RasMessage::e_bandwidthRequest :
			PTRACE(1, "GK\tBRQ Received");
			ShallSendReply = OnBRQ( rx_addr, obj_req, obj_rpl );
			break;
    
		case H225_RasMessage::e_disengageRequest :
			PTRACE(1, "GK\tDRQ Received");
			ShallSendReply = OnDRQ( rx_addr, obj_req, obj_rpl );
			break;
    
		case H225_RasMessage::e_locationRequest :
			PTRACE(1, "GK\tLRQ Received");
			ShallSendReply = OnLRQ( rx_addr, obj_req, obj_rpl );
			break;
    
		case H225_RasMessage::e_infoRequestResponse :
			PTRACE(1, "GK\tIRR Received");
			ShallSendReply = OnIRR( rx_addr, obj_req, obj_rpl );
			break;
    
		case H225_RasMessage::e_resourcesAvailableIndicate :
			PTRACE(1, "GK\tRAI Received");
			ShallSendReply = OnRAI( rx_addr, obj_req, obj_rpl );
			break;

		// we case safely ignore these messages and don't have to act upon them
		case H225_RasMessage::e_unregistrationConfirm :
		case H225_RasMessage::e_unregistrationReject :
		case H225_RasMessage::e_bandwidthConfirm :
		case H225_RasMessage::e_bandwidthReject :
			PTRACE(2, "GK\t" << obj_req.GetTagName() << " received and safely ignored");
			break;


		// handling these is optional (action only necessary once we send GRQs)
		case H225_RasMessage::e_locationConfirm :
		case H225_RasMessage::e_locationReject :
		case H225_RasMessage::e_nonStandardMessage :
			PTRACE(2, "GK\t" << err_msg << obj_req.GetTagName());
			break;
    
		// handling these messages is _mandatory_ ! (no action necessary)
		case H225_RasMessage::e_disengageConfirm :
		case H225_RasMessage::e_disengageReject :
			PTRACE(2, "GK\t" << err_msg << obj_req.GetTagName());
			break;
    
		// handling this message is _mandatory_ !!  (any action necessary ??)
		case H225_RasMessage::e_unknownMessageResponse :
			PTRACE(1, "GK\tUnknownMessageResponse received - no action");
			break;
			
		default:
			PTRACE(1, "GK\tUnknown RAS message received");
			break;      
		}

		if (ShallSendReply)
			SendReply( obj_rpl, rx_addr, rx_port, listener );
	};
};

