//////////////////////////////////////////////////////////////////
//
// SignalConnection.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// initial author: Sergio Artero
// initial version: 12/9/1999
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#endif

#include "SignalConnection.h"
#include "RasTbl.h"
#include "ANSI.h"
#include "Toolkit.h"


/* This constructor is invoked from Main() thread below.
 * This new thread handles receiving data from remote to gatekeeper.
 */
SignalConnection::SignalConnection ( PINDEX stackSize, PIPSocket::Address _GKHome, PTCPSocket * local, PTCPSocket * remote )
	: PThread ( stackSize, NoAutoDeleteThread )
{
	PTRACE(6, ANSI::CYA << "SignalConnection::SignalConnection(1)" << ANSI::OFF);

	GKHome = _GKHome;
	m_connection = local;
	m_remote = remote;
	m_sigChannel = NULL;
	// to fix memory leaks
	// always NULL in this instance of SignalConnection
	remoteConnection = NULL;
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
	m_sigChannel = sigChannel;
	// points to the instance of SignalConnection that handles receiving data from remote to gatekeeper.
	remoteConnection = NULL;  
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
}


void SignalConnection::CloseSignalConnection(void)
{ 
	// instance of SignalConnection that handles receiving data from caller to gatekeeper?
	if (remoteConnection) 
	{
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
		m_connection->Close();   // close connection to caller
	}
	else 
	/* Close instance of SignalConnection that handles receiving data from remote to gatekeeper
	 * OR
	 * CloseSignalConnection() was called before remoteConnection could be setup
	 */
	{
		m_connection->Close();
	}
}

void SignalConnection::Main(void)
{
	remoteConnection = NULL;

	while ( m_connection->IsOpen() )
	{
		// Read incoming messages
		if ( ! OnReceivedData() )
		{
			PTRACE(1, "GK\tREAD ERROR !!!\nCLOSING CONNECTION...");
			CloseSignalConnection();
			break;
		}

		if (m_q931.GetMessageType() == Q931::SetupMsg) // SETUP
		{
			// SETUP message received, open connection to remote endpoint

			m_crv.SetValue(m_q931.GetCallReference());
			PTRACE(4, "GK\tCALL REFERENCE VALUE : " << m_crv); 
			CallRec * Call = (CallRec *)CallTable::Instance()->FindCallRec(m_crv);
 
			if (Call == NULL)
			{
				PTRACE(4, "GK\tCALL NOT REGISTERED");
				break;
			};
			
			H225_TransportAddress_ipAddress & ipaddress = Call->Called->m_callSignalAddress;
			m_remote = new PTCPSocket(ipaddress.m_port);
			PIPSocket::Address calledIP( ipaddress.m_ip[0], ipaddress.m_ip[1], ipaddress.m_ip[2], ipaddress.m_ip[3]);
			if ( !m_remote->Connect(calledIP) )
			{
				PTRACE(4, "GK\t" << calledIP << " DIDN'T ACCEPT THE CALL");
				break;
			};
			PTRACE(4, "GK\t" << calledIP << " ACCEPTED THE CALL!");
			remoteConnection = new SignalConnection( 1000, GKHome, m_remote, m_connection);
		};

		PTRACE(4, "GK\tQ931 Msg Type " << m_q931.GetMessageTypeName()); 

		if ( !Send(m_remote) )
		{
			PTRACE(1, "GK\tSEND ERROR !\nCLOSING CONNECTION...");
			CloseSignalConnection();
			break;
		};
		if ( m_q931.GetMessageType() == Q931::ReleaseCompleteMsg ) 	// RELEASE COMPLETE
		{
			CloseSignalConnection();
			break;
		};

		// send CALL PROCEEDING to Caller !
		// storm 20.01.00
		if (m_q931.GetMessageType() == Q931::SetupMsg)
		{
			PTRACE(1, "GK\tSending CALL PROCEEDING to Caller ...");

			// Save the identifiers sent by caller
			GkQ931 proceeding;
			proceeding.BuildCallProceeding(m_q931.GetCallReference());
//			if (m_q931.HasOptionalField(H225_Setup_UUIE::e_callIdentifier))
//				proceeding.m_callIdentifier.callIdentifier = m_q931.m_callIdentifier.m_guid;

//			proceeding.m_h323_message_body.SetTag(H225_H323_UU_PDU_h323_message_body::e_callProceeding);
//			proceeding.m_h323_message_body.m_protocolIdentifier.SetValue(H225_ProtocolID);

//			m_remote->SetEndpointTypeInfo(proceeding.m_h323_message_body.m_destinationInfo);
//			if ( !Send(m_remote) )
//			{
//				PTRACE(1, "GK\tSEND ERROR !\nCLOSING CONNECTION...");
//				CloseSignalConnection();
//				break;
//			};

		};
	};
}

void H323SetAliasAddress(const PString & name, H225_AliasAddress & alias)
{
	alias.SetTag(H225_AliasAddress::e_e164);
	PASN_IA5String & ia5 = (PASN_IA5String &)alias;
	ia5 = name;
	if (name == (PString)ia5)
		return;
	
	// Could not encode it as a phone number, so do it as a full string.
	alias.SetTag(H225_AliasAddress::e_h323_ID);
	(PASN_BMPString &)alias = name;
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


BOOL SignalConnection::OnReceivedData(void)
{
	PTRACE(4, "GK\tReceiving data from " << m_connection->GetName() << "...");
	//BOOL isUser = FALSE;
	
	// Read tpkt
	BYTE tpkt[4];
	PTRACE(5, "GK\t-\tTPKT...");
  	if ( !m_connection->ReadBlock( tpkt, sizeof(tpkt) ) )
	{
		PTRACE(4, "GK\tREAD ERROR");
		return FALSE;
	};
 	if (tpkt[0] != 3)  // Only support version 3
	{
		PTRACE(4, "GK\tONLY TPKT VERSION 3 SUPPORTED");
		return FALSE;
	};

#ifndef NDEBUG
	printf("data(4+): %02x %02x %02x %02x.\n",tpkt[0],tpkt[1],tpkt[2],tpkt[3]);
#endif

	int packetLength = ((tpkt[2] << 8)|tpkt[3]) - 4;
	
  	if ( packetLength < 5 )		// Packet too short
	{
		PTRACE(4, "GK\tPACKET TOO SHORT!");
    		return FALSE;
	};

	PBYTEArray byteArray(packetLength);
	PPER_Stream streamBuffer(byteArray);

	PTRACE(5, "GK\t-\tQ931...");
	if ( !m_connection->Read(streamBuffer.GetPointer(), streamBuffer.GetSize() ) ) {
		PTRACE(4, "GK\tPROBLEMS READING!");
		return FALSE;
	};
	
#ifndef NDEBUG
	const BYTE *bxx = streamBuffer.GetPointer();
	printf("data(+x): %02x %02x %02x %02x %02x %02x %02x %02x...\n",
		   bxx[0],bxx[1],bxx[2],bxx[3],bxx[4],bxx[5],bxx[6],bxx[7]);
#endif

	m_q931.Decode(byteArray);
	PTRACE(5, "GK\tReceived.");

	PTRACE(4, "GK\tCall reference : " << m_q931.GetCallReference());
	PTRACE(4, "GK\tFrom destination " << m_q931.IsFromDestination());
	PTRACE(4, "GK\tMessage type : " << (int)m_q931.GetMessageType());
	PTRACE(5, ANSI::BYEL << "Q931: " << m_q931 << ANSI::OFF << endl);

	if(m_q931.HasField(GkQ931::UserUserField)) {
		H225_H323_UserInformation signal;

		PPER_Stream q = m_q931.GetField(GkQ931::UserUserField);
		if ( ! signal.Decode(q) ) {
			PTRACE(4, "GK\tERROR DECODING Q931.UserInformation!");
			return false;
		}

		H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
		H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;

		PTRACE(5,"H225_H323_UU_PDU: " << pdu);
		if(pdu.HasOptionalField(H225_H323_UU_PDU::e_nonStandardControl)) {
			PTRACE(5,"REWRITING");
			PASN_OctetString &octs = pdu.m_nonStandardControl[0].m_data;
			Modify_NonStandardControlData(octs);
			PTRACE(5, "H225_H323_UU_PDU: " << pdu);
		}
		
		// give OnXXX methods a change to modify the message
		// before forwarding them
		PTRACE(4, "GK\t" << body.GetTag());
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
		
		m_q931.SetField(GkQ931::UserUserField, sb);
	} 
	
	if (m_q931.HasField(GkQ931::CalledPartyNumberField)) {
		PBYTEArray n_array = m_q931.GetField(GkQ931::CalledPartyNumberField);
		const char* n_bytes = (const char*) (n_array.GetPointer());
		PString n_string(n_bytes+1, n_array.GetSize()-1);
		if(Toolkit::Instance()->RewritePString(n_string))
			m_q931.SetCalledPartyNumber(n_string, GkQ931::ISDNPlan, GkQ931::NationalType);
	}

	PTRACE(5, ANSI::BGRE << "Q931: " << m_q931 << ANSI::OFF << endl);

	return TRUE;
};
 


void SignalConnection::OnSetup( H225_H323_UU_PDU_h323_message_body & body )
{
	H225_Setup_UUIE & setup = body;

	// save callIdentifier + conferenceIdentifier
	CallRec * Call = (CallRec *)CallTable::Instance()->FindCallRec(m_crv);
	if (Call != NULL)
	{
		Call->m_callIdentifier = setup.m_callIdentifier;
		Call->m_conferenceIdentifier = setup.m_conferenceID;
	};
 
	// re-route called endpoint signalling messages to gatekeeper	
	if ( setup.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress) )
	{
		H225_TransportAddress_ipAddress & ipAddress = setup.m_sourceCallSignalAddress;
		ipAddress.m_ip[0] = GKHome.Byte1();
		ipAddress.m_ip[1] = GKHome.Byte2();
		ipAddress.m_ip[2] = GKHome.Byte3();
		ipAddress.m_ip[3] = GKHome.Byte4();
		ipAddress.m_port = Toolkit::Config()->GetInteger("RouteSignalPort", GK_DEF_ROUTE_SIGNAL_PORT);
	};

	PTRACE(4, "GK\t" << setprecision(2) << setup);
	PTRACE(4, "GK\tEND OF TRACED MESSAGE");
};
 
void SignalConnection::OnCallProceeding( H225_H323_UU_PDU_h323_message_body & body )
{
	// do nothing
};
 
void SignalConnection::OnConnect( H225_H323_UU_PDU_h323_message_body & body )
{
	// only in case of routed H245 control channel GK should add its Transport Address
	// in other case only forward message
};
 
void SignalConnection::OnAlerting( H225_H323_UU_PDU_h323_message_body & body )
{
	// do nothing
};
 
void SignalConnection::OnInformation( H225_H323_UU_PDU_h323_message_body & body )
{
	// do nothing
};
 
void SignalConnection::OnReleaseComplete( H225_H323_UU_PDU_h323_message_body & body )
{
	// do nothing
};
 
void SignalConnection::OnFacility( H225_H323_UU_PDU_h323_message_body & body )
{
	// do nothing
};
 
void SignalConnection::OnProgress( H225_H323_UU_PDU_h323_message_body & body )
{
	// do nothing
};
 
void SignalConnection::OnEmpty( H225_H323_UU_PDU_h323_message_body & body )
{
	// do nothing
};


BOOL SignalConnection::Send( PTCPSocket * socket ) 
{
	//towi-XXX	PTRACE(4, "GK\tSending data to " << socket->GetName() << "...");

	// write the q931 data to #sbuf#
	PBYTEArray sbuf;
	m_q931.Encode(sbuf);
	const PINDEX bufLen = sbuf.GetSize();
	const BYTE *buf = sbuf.GetPointer();

	// ...and the header to #header#
	BYTE header[4];
	header[0] = 3; // TPKT code
  	header[1] = 0; // Must be zero
  	header[2] = (BYTE)((bufLen+4) >> 8);
  	header[3] = (BYTE)(bufLen+4);

#ifndef NDEBUG	
	printf("data(4+%d): ", bufLen);
	printf("%02x %02x %02x %02x.", header[0],header[1],header[2],header[3]);
	for(PINDEX i=0; i<bufLen; i++) {
		if(isalnum(buf[i]))
			printf("%s%c%s",ANSI::YEL, (char)(buf[i]), ANSI::OFF);
		else
			printf("%02x ", buf[i]);
	}
	printf("\n");
#endif	

	if (!socket->Write(header, 4)) {
		PTRACE(4, "GK\tPROBLEMS SENDING TPKT.");
		return FALSE;
	}
	if (!socket->Write(buf, bufLen)) {
		PTRACE(4, "GK\tPROBLEMS SENDING Q931 DATA.");
		return FALSE;
	}
	
	PTRACE(5, "GK\tSent.");
	return TRUE;
	
};

