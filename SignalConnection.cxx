//////////////////////////////////////////////////////////////////
//
// SignalConnection.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Sergio Artero
// initial version: 12/9/1999
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#endif

#include "SignalConnection.h"
#include "ANSI.h"
#include "Toolkit.h"
#include "h323util.h"
#include "gk_const.h"


/* This constructor is invoked from Main() thread below.
 * This new thread handles receiving data from remote to gatekeeper.
 */
SignalConnection::SignalConnection ( PINDEX stackSize, PIPSocket::Address _GKHome, PTCPSocket * local, PTCPSocket * remote, const Q931 & caller_m_q931 )
	: PThread ( stackSize, NoAutoDeleteThread )
{
	PTRACE(6, ANSI::CYA << "SignalConnection::SignalConnection(1)" << ANSI::OFF);

	bH245Routing = FALSE;	// TODO: read config
	GKHome = _GKHome;
	m_connection = local;
	m_remote = remote;
	m_sigChannel = NULL;  // this also indicates remote-thread
	// to fix memory leaks
	// always NULL in this instance of SignalConnection
	remoteConnection = NULL;
	m_crv.SetValue(caller_m_q931.GetCallReference());
	statusEnquiry.BuildStatusEnquiry(m_crv.GetValue(), TRUE);
	//mm-27.04.2001
	connectionName = ANSI::RED + m_connection->GetName() + ANSI::OFF;
PTRACE(3, "GK\t" << connectionName << "\t Create SignalConnection crv=" << m_crv);
	Resume();
}


/* This constructor is invoked from SignalChannel thread.
 * This thread handles receiving data from caller to gatekeeper.
 */
SignalConnection::SignalConnection ( PINDEX stackSize, PIPSocket::Address _GKHome, PTCPSocket * caller, SignalChannel * sigChannel ):
			PThread ( stackSize, NoAutoDeleteThread)
{
	PTRACE(6, ANSI::CYA << "SignalConnection::SignalConnection(2)" << ANSI::OFF);

	GKHome = _GKHome;
	m_connection = caller;
	m_remote = NULL;
	m_sigChannel = sigChannel;  // this also indicates caller-thread
	// points to the instance of SignalConnection that handles receiving data from remote to gatekeeper.
	remoteConnection = NULL;
	//mm-27.04.2001
	connectionName = ANSI::GRE + m_connection->GetName() + ANSI::OFF;
	if (bH245Routing) {
		// start a H.245 thread for this connection
		m_h245_thread = NULL;
	}

	Resume();
}

SignalConnection::~SignalConnection()
{
	/* The following delete will delete the connection instance from caller to gatekeeper OR
	 * connection instance from remote to gatekeeper.
	 * This depends on which thread it is.
	 * REMEMBER IN remoteConnection THREAD INSTANCE m_connection = m_remote
	 */
	delete m_connection;     // delete connection to remote
	m_connection = NULL;
	if (bH245Routing) {
		delete m_h245_thread;
		m_h245_thread = NULL;
	}
}

void SignalConnection::CloseSignalConnection(void)
{ 
	PTRACE(5, "GK\t" << connectionName << "\tentering CloseSignalConnection");

	if (m_CloseMutex.WillBlock()) {
		PTRACE(5, "GK\t" << connectionName << "\tClosing by other thread, ignore!");
		return;
	}
	PWaitAndSignal lock(m_CloseMutex);
	// instance of SignalConnection that handles receiving data from caller to gatekeeper?
	if (remoteConnection) {
		/* close the other SignalConnection thread created by this thread
		 * This will invoke the else condition below in the other thread instance.
		 */
		remoteConnection->CloseSignalConnection();
		remoteConnection->WaitForTermination();
		/* Free the memory associated with remoteConnection
		 * This will invoke destructor above which will 'delete m_remote'
		 * REMEMBER IN remoteConnection THREAD INSTANCE m_connection = m_remote
		 */
		delete remoteConnection;
		remoteConnection = NULL;
	}

	if (m_connection->IsOpen())
		m_connection->Close();
	// else
	// 	already closed, fine!

	if (m_sigChannel) { // this indicates caller-thread
// TODO: 
	// resourceManager::Instance()->CloseConference(obj_rr.m_endpointIdentifier, obj_rr.m_conferenceID);

        	// maipulate call-table
		CallTable::Instance()->RemoveCall(pCallRec);
	}
	PTRACE(5, "GK\t" << connectionName << "\t" << " CloseSignalConnection done!");
}

void SignalConnection::SendReleaseComplete()
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
	H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_releaseComplete);
	H225_ReleaseComplete_UUIE & uuie = body;
	uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_callIdentifier);
	uuie.m_callIdentifier = m_callid;
	PPER_Stream sb;
	signal.Encode(sb);
	sb.CompleteEncoding();

	Q931 releasePDU;
	releasePDU.BuildReleaseComplete(m_crv, TRUE);
	releasePDU.SetIE(Q931::UserUserIE, sb);
	Send(m_connection, releasePDU);
	if (m_remote) {
		releasePDU.BuildReleaseComplete(m_crv, FALSE);
		releasePDU.SetIE(Q931::UserUserIE, sb);
		Send(m_remote, releasePDU);
	}
	PTRACE(4, "GK\tSend Release Complete to " << connectionName);

// In some situation, the Sleep causes the thread unterminated. Strange!	
//	Sleep(100); // wait for the pdu to be sent
	CloseSignalConnection();
}

void SignalConnection::Main(void)
{
	remoteConnection = NULL;
	//detect dead calls
	int allowedPendings = 0;
	BOOL usePings = GkConfig()->GetBoolean("SignalConnection::StatusEnquiry", "UsePing", FALSE);
	if (usePings) {
	  allowedPendings = GkConfig()->GetInteger("SignalConnection::StatusEnquiry", "AllowedPendings", 3);
	  PTRACE(6, "GK\t" << connectionName << "\tallowedPendings "<<allowedPendings);
	  //constructor: long millisecs, long seconds, long minutes, long hours, int days
	  //m_connection->SetReadTimeout(PTimeInterval(0l, 10l, 0l, 0l, 0));
	  m_connection->SetReadTimeout(PTimeInterval(0l, (long)(GkConfig()->GetInteger("SignalConnection::StatusEnquiry", "Timeout", 1)), 0l, 0l, 0));
	  PTRACE(6, "GK\t" << connectionName << "\treadTimeout "<< GkConfig()->GetInteger("SignalConnection::StatusEnquiry", "Timeout", 1));
	}
	pendingCount = 0;
	killMe = FALSE;

	while ( m_connection->IsOpen() )
	{
		// Read incoming messages
		if ( ! OnReceivedData() )
		{
			PTRACE(2, "GK\t" << connectionName << "\tREAD ERROR !!!\nCLOSING CONNECTION...");
			CloseSignalConnection();
			break;
		}

		if (usePings) {
			// build only once in caller-thread (Q931-instances initialise with callReference = 0)
			if (statusEnquiry.GetCallReference() == 0) {
				PTRACE(5, "GK\t" << connectionName << "\tstatusEnquiryMsg not set");
				if (m_q931.GetCallReference() == 0) {
					PTRACE(5, "GK\t" << connectionName << "\tcallReference not set, continuing...");
					if (pendingCount > 0) // prevent multiple timeouts before call-setup
						--pendingCount;
					continue; //while-loop
				}

				if (m_sigChannel) { //caller-thread
					statusEnquiry.BuildStatusEnquiry(m_q931.GetCallReference(), FALSE);
					PTRACE(5, "GK\t" << connectionName << "\tsetting statusEnquiryMsg: "
						<< statusEnquiry.GetCallReference());
				} else {
					PTRACE(2, "GK\t" << connectionName << "\tERROR: not in caller-thread!!");
					break;
				}
			};

			if (remoteConnection)
				if (remoteConnection->ShouldBeTerminated()) {
					CloseSignalConnection();
					break;
				};

			if (pendingCount > 0) {
				PTRACE(5, "GK\t" << connectionName << "\ttimeout no: " << pendingCount);
				if (pendingCount <= allowedPendings) {
					//allowed timeout -> send StatusEnquiry
					PTRACE(5, "GK\t" << connectionName << "\tsending StatusEnquiry");
					// send StatusEnquiry to this thread's endpoint
					if ( !Send(m_connection, statusEnquiry) ) {
						PTRACE(1, "GK\t" << connectionName << "\tSEND ERROR !\nCLOSING CONNECTION...");
						CloseSignalConnection();
			  		};

					continue; //while-loop
				} else if (pendingCount > allowedPendings) {

					// too many timeouts - no answer to StatusEnquiry - cancel call
					PTRACE(5, "GK\t" << connectionName << "\tclosing signal connection");
					if (m_sigChannel)
						CloseSignalConnection();  // kills both treads
			  		else
						// indicate remote thread to be killed (this will also terminate caller thread)
						killMe = TRUE;
			 		break;
				};
			};
		};

#ifdef GENERATE_CALL_PROCEEDING
		if (m_q931.GetMessageType() == Q931::CallProceedingMsg )        // swallow CALL PROCEEDING
			continue;
#endif // GENERATE_CALL_PROCEEDING

		if (m_q931.GetMessageType() == Q931::SetupMsg) // SETUP
		{
			// SETUP message received, open connection to remote endpoint

			m_crv.SetValue(m_q931.GetCallReference());
			PTRACE(4, "GK\t" << connectionName << "\tCALL REFERENCE VALUE : " << m_crv); 
/* comment out by cwhuang:
   it's dangerous to use CRV here, an irrelevant call may be found
			// CallRecs are looked for using callIdentifier; if non-existant
			// (it's optional), FindCallRec uses callReferenceValue instead
			if (!pCallRec)
				pCallRec = CallTable::Instance()->FindCallRec(m_crv);
*/
			if (!pCallRec) {
				PTRACE(3, "GK\t" << connectionName << "\tCALL NOT REGISTERED");
				SendReleaseComplete();
				break;
			};

			const H225_TransportAddress *pAddr = pCallRec->GetCalledAddress();
			if (!pAddr || pAddr->GetTag() != H225_TransportAddress::e_ipAddress) {
				PTRACE(3, "GK\t" << connectionName << "\tINVALID IP ADDRESS");
				SendReleaseComplete();
				break;
			}
			
			const H225_TransportAddress_ipAddress & ipaddress = *pAddr;
			m_remote = new PTCPSocket(ipaddress.m_port);
			PIPSocket::Address calledIP( ipaddress.m_ip[0], ipaddress.m_ip[1], ipaddress.m_ip[2], ipaddress.m_ip[3]);
			if ( !m_remote->Connect(calledIP) ) {
				PTRACE(3, "GK\t" << connectionName << "\t" << calledIP << " DIDN'T ACCEPT THE CALL");
				SendReleaseComplete();
				break;
			};

			PTRACE(4, "GK\t" << connectionName << "\t" << calledIP << " ACCEPTED THE CALL!");
			remoteConnection = new SignalConnection( 1000, GKHome, m_remote, m_connection, m_q931);
		};

		PTRACE(4, "GK\t" << connectionName << "\tQ931 Msg Type " << m_q931.GetMessageTypeName()); 

		if ( m_q931.GetMessageType() != Q931::StatusMsg) // don't forward status messages mm-30.04.2001
			if ( !Send(m_remote, m_q931) )
			{
				PTRACE(1, "GK\t" << connectionName << "\tSEND ERROR !\nCLOSING CONNECTION...");
				CloseSignalConnection();
				break;
			};

		if ( m_q931.GetMessageType() == Q931::ReleaseCompleteMsg ) // RELEASE COMPLETE
		{
			CloseSignalConnection();
			break;
		};


#ifdef GENERATE_CALL_PROCEEDING
		// send CALL PROCEEDING to Caller !
		if (m_q931.GetMessageType() == Q931::SetupMsg)
		{
			H225_H323_UserInformation signal;
			PTRACE(1, "GK\t" << connectionName << "\tSending CALL PROCEEDING to Caller ...");

			if ( !Send(m_remote, m_q931) )
			{
				PTRACE(1, "GK\tSEND ERROR !\nCLOSING CONNECTION...");
				CloseSignalConnection();
				break;
			};

			// re-use existing SETUP msg
			H225_CallReferenceValue m_crv = m_q931.GetCallReference();
			m_q931.BuildCallProceeding(m_crv);

			// Since the CallReferenceValue is unique per-endpoint, we can use it to
			// identify the call so we don't have to dig into the Q931 message to get
			// callIdentifier (which is just optional)
			// Do we need to set anything other than the CRV ?

			if ( !Send(m_connection, m_q931) )
			{
				PTRACE(1, "GK\tSEND ERROR !\nCLOSING CONNECTION...");
				CloseSignalConnection();
				break;
			};
		};
#endif // GENERATE_CALL_PROCEEDING
	};
}


void Modify_NonStandardControlData(PASN_OctetString &octs)
{
	BOOL changed = FALSE;
	BYTE buf[10000];
	BYTE *pBuf  = buf;               // write pointer
	BYTE *pOcts = octs.GetPointer(); // read pointer
	BYTE *mOcts = pOcts + octs.GetSize();
	PString *CalledPN;
	
	while (pOcts < mOcts) {
		BYTE type  = pOcts[0];
		BYTE len   = pOcts[1];
		switch (type) { 
		case 0x70: // called party
			CalledPN = new PString( (char*) (&(pOcts[3])), len-1); 
			if(Toolkit::Instance()->RewritePString(*CalledPN)) {
				// change
				const char* s = *CalledPN;
				pBuf[0] = type;
				pBuf[1] = strlen(s)+1;
				pBuf[2] = pOcts[2];  // type of number, numbering plan id
				memcpy(&(pBuf[3]), s, strlen(s));
				pBuf += strlen(s)+3; 
				changed = TRUE;
			}
			else { 
				// leave unchanged
				memcpy(pBuf, pOcts, (len+2)*sizeof(BYTE));
				pBuf += len+2;  // incr write pointer
			}
			delete CalledPN;
			break;
		case 0x6c: // calling party
		default: // copy through
			memcpy(pBuf, pOcts, (len+2)*sizeof(BYTE));
			pBuf += len+2;  // incr write pointer
		}
		
		// increment read pointer
		pOcts += len+2;
	}
	
	// set new value if necessary
	if (changed)
		octs.SetValue(buf, pBuf-buf);
}


// read incoming message and store it in m_q931
BOOL SignalConnection::OnReceivedData(void)
{
	PTRACE(4, "GK\t" << connectionName << "\tReceiving data");
	// Read tpkt
	BYTE tpkt[4];
	PTRACE(5, "GK\t" << connectionName << "\t-\tTPKT...");
	if ( !m_connection->ReadBlock( tpkt, sizeof(tpkt) ) )
	{

	  if (m_connection->GetErrorCode() == PTCPSocket::Timeout) {
		  PTRACE(5, "GK\t" << connectionName << "\tTIMEOUT");
		  ++pendingCount;
		  return TRUE;
	  } else {
		  PTRACE(4, "GK\t" << connectionName << "\tREAD ERROR");
		  return FALSE;
	  }
	};

	// indicate we received something on this channel, independent of message type
	if (pendingCount > 0)
	  --pendingCount;

	if (tpkt[0] != 3)  // Only support version 3
	{
	  PTRACE(4, "GK\t" << connectionName << "\tONLY TPKT VERSION 3 SUPPORTED");
		return FALSE;
	};

#ifndef NDEBUG
	printf("data(4+): %02x %02x %02x %02x.\n",tpkt[0],tpkt[1],tpkt[2],tpkt[3]);
#endif

	int packetLength = ((tpkt[2] << 8)|tpkt[3]) - 4;
	
  	if ( packetLength < 5 )		// Packet too short
	{
	  PTRACE(4, "GK\t" << connectionName << "\tPACKET TOO SHORT!");
    		return FALSE;
	};

	PBYTEArray byteArray(packetLength);
	PPER_Stream streamBuffer(byteArray);

	PTRACE(5, "GK\t" << connectionName << "\t-\tQ931...");
	if ( !m_connection->ReadBlock(byteArray.GetPointer(packetLength), packetLength ) ) {
		PTRACE(4, "GK\t" << connectionName << "\tPROBLEMS READING!");
		return FALSE;
	};
	
#ifndef NDEBUG
	const BYTE *bxx = streamBuffer.GetPointer();
	printf("data(+x): %02x %02x %02x %02x %02x %02x %02x %02x...\n",
		   bxx[0],bxx[1],bxx[2],bxx[3],bxx[4],bxx[5],bxx[6],bxx[7]);
#endif

	m_q931.Decode(byteArray);
	PTRACE(5, "GK\t" << connectionName << "\tReceived.");

	PTRACE(4, "GK\t" << connectionName << "\tCall reference : " << m_q931.GetCallReference());
	PTRACE(4, "GK\t" << connectionName << "\tFrom destination " << m_q931.IsFromDestination());
	PTRACE(4, "GK\t" << connectionName << "\tMessage type : " << (int)m_q931.GetMessageType());
	PTRACE(5, ANSI::BYEL << "\nQ931: " << m_q931 << ANSI::OFF << endl);

	if(m_q931.HasIE(Q931::UserUserIE)) {
		H225_H323_UserInformation signal;

		PPER_Stream q = m_q931.GetIE(Q931::UserUserIE);
		if ( ! signal.Decode(q) ) {
			PTRACE(4, "GK\t" << connectionName << "\tERROR DECODING Q931.UserInformation!");
			return false;
		}

		H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
		H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;

		PTRACE(5,"H225_H323_UU_PDU: " << pdu);
		if(pdu.HasOptionalField(H225_H323_UU_PDU::e_nonStandardControl)) {
			PTRACE(5, connectionName << "\tREWRITING");
			PASN_OctetString &octs = pdu.m_nonStandardControl[0].m_data;
			Modify_NonStandardControlData(octs);
			PTRACE(5, connectionName << "\tH225_H323_UU_PDU: " << pdu);
		}
		
		// give OnXXX methods a change to modify the message
		// before forwarding them
		PTRACE(4, "GK\t" << connectionName << "\tTag = " << body.GetTag());
		switch(body.GetTag()) {
		case H225_H323_UU_PDU_h323_message_body::e_setup:
			OnSetup(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_callProceeding:
			OnCallProceeding(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_connect:
			OnConnect(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_alerting:
			OnAlerting(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_information:
			OnInformation(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_releaseComplete:
			OnReleaseComplete(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_facility:
			OnFacility(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_progress:
			OnProgress(body);
			break;
		case H225_H323_UU_PDU_h323_message_body::e_empty:
			OnEmpty(body);
			break;
		default:
			PTRACE(4, "GK\tUNKNOWN");
			break;
		};
		
		// cerr << ANSI::RED << "H225_H323_UserInformation: " << signal << ANSI::OFF << endl;

		PPER_Stream sb;
		signal.Encode(sb);
		sb.CompleteEncoding();
		
		m_q931.SetIE(Q931::UserUserIE, sb);
	} 
	
	if (m_q931.HasIE(Q931::CalledPartyNumberIE)) {
		PBYTEArray n_array = m_q931.GetIE(Q931::CalledPartyNumberIE);
		const char* n_bytes = (const char*) (n_array.GetPointer());
		PString n_string(n_bytes+1, n_array.GetSize()-1);
		if (Toolkit::Instance()->RewritePString(n_string))
			m_q931.SetCalledPartyNumber(n_string, Q931::ISDNPlan, Q931::NationalType);
	}

	PTRACE(5, ANSI::BGRE << "\nQ931: " << m_q931 << ANSI::OFF << endl);

	return TRUE;
};
 

void SignalConnection::OnSetup( H225_Setup_UUIE & Setup )
{
	if (!Setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
		PTRACE(1, "SignalConnection\tOnSetup() no callIdentifier!");
		return;
	}
	m_callid = Setup.m_callIdentifier;
	// save callIdentifier + conferenceIdentifier
	pCallRec = CallTable::Instance()->FindCallRec(m_callid);
	if (!pCallRec) {
		PTRACE(3, "SignalConnection\tOnSetup() didn't find the call: " << AsString(m_callid.m_guid));
		return;
	};
	pCallRec->SetSigConnection(this);
/* comment out by cwhuang
   Is there any meaning to set callIdentifier & conferenceIdentifier again?
   Aren't them already set?
	pCallRec->m_callIdentifier = Setup.m_callIdentifier;
	pCallRec->m_conferenceIdentifier = Setup.m_conferenceID;
*/ 
	// re-route called endpoint signalling messages to gatekeeper	
	Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
	Setup.m_sourceCallSignalAddress = SocketToH225TransportAddr(GKHome, GkConfig()->GetInteger("RouteSignalPort", GK_DEF_ROUTE_SIGNAL_PORT));

	// in routed mode the caller may have put the GK address in destCallSignalAddress
	// since it is optional, we just remove it (we could alternativly insert the real destination SignalAdr)
	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
		Setup.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
	}

	// to compliance to MediaRing VR, we have to setup our H323ID
	PString H323ID = GkConfig()->GetString("H323ID");
	if (!H323ID) {
		PINDEX s = 0;
		if (Setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress))
			s = Setup.m_sourceAddress.GetSize();
		else
			Setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
		Setup.m_sourceAddress.SetSize(s+1);
		H225_AliasAddress & alias = Setup.m_sourceAddress[s];
		alias.SetTag(H225_AliasAddress::e_h323_ID);
		(PASN_BMPString &)alias = H323ID;
	}

	if (Setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
		Toolkit::Instance()->RewriteE164(Setup.m_destinationAddress[0]);

	if (bH245Routing) {
		// replace H.245 address with gatekeepers address
	}
	
	PTRACE(4, "GK\t" << setprecision(2) << Setup);
	PTRACE(4, "GK\tEND OF TRACED MESSAGE");
}
 
void SignalConnection::OnCallProceeding( H225_CallProceeding_UUIE & CallProceeding )
{
	if (bH245Routing) {
		// replace H.245 address with gatekeepers address
//		CallProceeding.IncludeOptionalField( H225_CallProceeding_UUIE::e_h245Address );
//		CallProceeding.m_h245Address = Addr;
	}
};
 
void SignalConnection::OnConnect( H225_Connect_UUIE & Connect )
{
	if (!Connect.HasOptionalField(H225_Connect_UUIE::e_callIdentifier)) {
		PTRACE(1, "SignalConnection\tOnConnect() no callIdentifier!");
		return;
	}
	m_callid = Connect.m_callIdentifier;
	pCallRec = CallTable::Instance()->FindCallRec(m_callid);
	if (!pCallRec) {
		PTRACE(3, "SignalConnection\tOnConnect() didn't find the call!");
		return;
	};

	pCallRec->SetConnected(true);

	if (bH245Routing) {
		// replace H.245 address with gatekeepers address
//		Connect.IncludeOptionalField( H225_Connect_UUIE::e_h245Address );
//		Connect.m_h245Address = Addr;
	}
}
 
void SignalConnection::OnAlerting( H225_Alerting_UUIE & Alerting )
{
	if (bH245Routing) {
		// replace H.245 address with gatekeepers address
//		Alerting.IncludeOptionalField( H225_Alerting_UUIE::e_h245Address );
//		Alerting.m_h245Address = Addr;
	}
};
 
void SignalConnection::OnInformation( H225_Information_UUIE & Information )
{
	// do nothing
};
 
void SignalConnection::OnReleaseComplete( H225_ReleaseComplete_UUIE & ReleaseComplete )
{
	if (pCallRec)
		pCallRec->SetSigConnection(0);
// would be removed on CloseSignalConnection
//	CallTable::Instance()->RemoveCall(pCallRec);
}
 
void SignalConnection::OnFacility( H225_Facility_UUIE & Facility )
{
	// do nothing
};
 
void SignalConnection::OnProgress( H225_Progress_UUIE & Progress )
{
	// do nothing
};
 
void SignalConnection::OnEmpty( H225_H323_UU_PDU_h323_message_body & Empty )
{
	// do nothing
};

BOOL SignalConnection::Send( PTCPSocket * socket, const Q931 & toSend ) 
{
	// write the q931 data to #sbuf#
	PBYTEArray sbuf;
	//	m_q931.Encode(sbuf); // mm-27.04.2001
	toSend.Encode(sbuf);
	const PINDEX bufLen = sbuf.GetSize();
//	const BYTE *buf = sbuf.GetPointer();

	PINDEX pktlen = bufLen + 4;
	BYTE *pktbuf = new BYTE[pktlen];

	pktbuf[0] = 3; // TPKT code
  	pktbuf[1] = 0; // Must be zero
  	pktbuf[2] = (BYTE)(pktlen >> 8);
  	pktbuf[3] = (BYTE)(pktlen);
	memcpy(pktbuf + 4, sbuf.GetPointer(), bufLen);

#ifndef NDEBUG	
	printf("data(4+%d): ", bufLen);
	printf("%02x %02x %02x %02x.", pktbuf[0],pktbuf[1],pktbuf[2],pktbuf[3]);
	BYTE *buf = pktbuf + 4;
	for(PINDEX i=0; i<bufLen; i++) {
		if(isalnum(buf[i]))
			printf("%s%c%s",ANSI::YEL, (char)(buf[i]), ANSI::OFF);
		else
			printf("%02x ", buf[i]);
	}
	printf("\n");
#endif	
/* comment out by cwhuang
   if we send the packet by two Write calls,
   it's possible be interrupted by another thread
   and disturb the packet.
	if (!socket->Write(header, 4)) {
		PTRACE(4, "GK\t" << connectionName << "\tPROBLEMS SENDING TPKT.");
		return FALSE;
	}
	if (!socket->Write(buf, bufLen)) {
		PTRACE(4, "GK\t" << connectionName << "\tPROBLEMS SENDING Q931 DATA.");
		return FALSE;
	}
*/	
	BOOL result = socket->Write(pktbuf, pktlen);
	delete [] pktbuf;

	PTRACE_IF(4, !result, "GK\t" << connectionName << "\tPROBLEMS SENDING TPKT.");
	PTRACE_IF(5, result, "GK\t" << connectionName << "\tSent.");
	return result;
}

