//////////////////////////////////////////////////////////////////
//
// GkStatus.h thread for external interface
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
// 	990924	initial version (Jan Willamowius)
//	991025	Added command thread (Ashley Unitt)
//
//////////////////////////////////////////////////////////////////


#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4800 ) // one performance warning off
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4101 ) // warning unused locals off
#endif

#include "GkStatus.h"
#include "gk_const.h"
#include "SoftPBX.h"
#include "Toolkit.h"
#include "ANSI.h"
#include "h323util.h"


const int GkStatus::NumberOfCommandStrings = 29;
const static PStringToOrdinal::Initialiser GkStatusClientCommands[GkStatus::NumberOfCommandStrings] =
{
	{"printallregistrations",    GkStatus::e_PrintAllRegistrations},
	{"r",                        GkStatus::e_PrintAllRegistrations},
	{"?",                        GkStatus::e_PrintAllRegistrations},
	{"printallregistrationsverbose", GkStatus::e_PrintAllRegistrationsVerbose},
	{"rv",                       GkStatus::e_PrintAllRegistrationsVerbose},
	{"??",                       GkStatus::e_PrintAllRegistrationsVerbose},
	{"printcurrentcalls",        GkStatus::e_PrintCurrentCalls},
	{"c",                        GkStatus::e_PrintCurrentCalls},
	{"!",                        GkStatus::e_PrintCurrentCalls},
	{"printcurrentcallsverbose", GkStatus::e_PrintCurrentCallsVerbose},
	{"!!",                       GkStatus::e_PrintCurrentCallsVerbose},
	{"cv",                       GkStatus::e_PrintCurrentCallsVerbose},
	{"disconnectip",             GkStatus::e_DisconnectIp},
	{"disconnectcall",           GkStatus::e_DisconnectCall},
	{"disconnectalias",          GkStatus::e_DisconnectAlias},
	{"disconnectendpoint",       GkStatus::e_DisconnectEndpoint},
	{"unregisterallendpoints",   GkStatus::e_UnregisterAllEndpoints},
	{"unregisteralias",          GkStatus::e_UnregisterAlias},
	{"transfercall",             GkStatus::e_TransferCall},
	{"makecall",                 GkStatus::e_MakeCall},
	{"yell",                     GkStatus::e_Yell},
	{"who",                      GkStatus::e_Who},
	{"help",                     GkStatus::e_Help},
	{"h",                        GkStatus::e_Help},
	{"version",                  GkStatus::e_Version},
	{"debug",                    GkStatus::e_Debug},
	{"exit",                     GkStatus::e_Exit},
	{"quit",                     GkStatus::e_Exit},
	{"q",                        GkStatus::e_Exit}

};

int GkStatus::Client::StaticInstanceNo = 0;

// initialise singelton instance
GkStatus * GkStatus::m_instance = NULL;
PMutex GkStatus::m_CreationLock;

GkStatus * GkStatus::Instance(PIPSocket::Address _gkhome ) {
	if (m_instance == NULL)
	{
		m_CreationLock.Wait();
		if (m_instance == NULL) {
		  if (_gkhome.AsString() == PString("0.0.0.0")) {
			PTRACE(1, "error in GkHome-IP-Address!");
			exit(1);
		  } else
			m_instance = new GkStatus(_gkhome);
		}
		m_CreationLock.Signal();
	};
	return m_instance;
};


GkStatus::GkStatus(PIPSocket::Address _GKHome)
: PThread(1000, NoAutoDeleteThread), 
  StatusListener(Toolkit::Config()->GetInteger("StatusPort", GK_DEF_STATUS_PORT)),
	m_IsDirty(FALSE)
{
	GKHome = _GKHome;
	Resume();	// start the thread
};

GkStatus::~GkStatus()
{
};

void GkStatus::Main()
{
	StatusListener.Listen
		(GKHome, 
		 Toolkit::Config()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH), 
		 Toolkit::Config()->GetInteger("StatusPort", GK_DEF_STATUS_PORT), 
		 PSocket::CanReuseAddress);

	StatusListener.SetReadTimeout(Toolkit::Config()->GetInteger("StatusReadTimeout", 3000));
	PTCPSocket * NewConnection = new PTCPSocket;
	while(StatusListener.IsOpen())
	{
		CleanupClients();

		if(!NewConnection->Accept (StatusListener)) 
			continue;
		
		if (NewConnection->IsOpen())
		{
			// add new connection to connection list
			Client * NewClient = new Client( this, NewConnection );
			ClientSetLock.Wait();
			Clients.insert(NewClient);
			ClientSetLock.Signal();
			// Socket will be deleted by the client thread when it closes...
			NewConnection = new PTCPSocket;
		}
	};
	delete NewConnection;

};

void GkStatus::Close(void)
{
	PTRACE(2, "GK\tClosing Status thread.");
	
	// close all connected clients
	ClientSetLock.Wait();
	for (ClientIter=Clients.begin(); ClientIter != Clients.end(); ++ClientIter)
	{
		(*ClientIter)->Close();
	};
	ClientSetLock.Signal();

	// Wait for client threads to die...
	BOOL Empty;
	PTimeInterval tenth(100); // 1/10 sec
	do
	{
		ClientSetLock.Wait();
		Empty = Clients.empty();
		ClientSetLock.Signal();
		Sleep(tenth);
	} while ( !Empty );

	// close my listening socket
	StatusListener.Close();

	PTRACE(2, "GK\tClosed Status thread.");
};


void WriteWhoAmI(const GkStatus::Client *pclient, void *p1)
{
	GkStatus::Client *writeTo = (GkStatus::Client *)p1;
	writeTo->WriteString("  " + pclient->WhoAmI() + "\r\n");
}


void ClientSignalStatus(const GkStatus::Client *pclient, void* p1, void* p2)
{
	PString *msg   = (PString*)p1;
	int     level = *((int*)p2);
	int ctl = pclient->TraceLevel;
	if((ctl<=10) && (ctl>=0)) {
		if (level >= ctl) 
			((GkStatus::Client*)pclient)->WriteString(*msg);
	}
}


void GkStatus::SignalStatus(const PString &Message, int level)
{
//	ClientSetLock.Wait();
#ifdef WIN32
	// Visual C++ doesn't grock the for_each_with2 template function
	// anybody have a better fix ?
	for (ClientIter=Clients.begin(); ClientIter != Clients.end(); ++ClientIter)
	{
		ClientSignalStatus(*ClientIter, (void*)&Message, &level);
	};
#else
	Toolkit::for_each_with2(Clients.begin(),Clients.end(), ClientSignalStatus, 
							(void*)(&Message), (void*)(&level));
#endif
//	ClientSetLock.Signal();
};


void GkStatus::RemoveClient( GkStatus::Client * Client )
{
	PTRACE(5,"RemoveClient");

	Clients.erase(Client);
	delete Client;
}


void GkStatus::CleanupClients()
{
	PTRACE(6,"CleanupClients");
	if(IsDirty()) {
		/* we will only delete one client per round */
		
		Client* deleteThis = NULL; // will be != NULL for deletition
		
		for (ClientIter=Clients.begin(); ClientIter != Clients.end(); ++ClientIter)
		{
			if((*ClientIter)->PleaseDelete) {
				deleteThis = *ClientIter;
				break;
			}
		};
		
		if(deleteThis != NULL) 
		{
			ClientSetLock.Wait();
			RemoveClient(deleteThis);
			ClientSetLock.Signal();
			// one more round: do not set SetDirty(FALSE);
		}
		else {
			// no more cleanum rounds
			SetDirty(FALSE);
		}
  }
}



PStringToOrdinal GkStatus::Client::Commands(NumberOfCommandStrings, GkStatusClientCommands, TRUE);

GkStatus::Client::Client( GkStatus * _StatusThread, PTCPSocket * _Socket )
	: PThread(1000, NoAutoDeleteThread),
	  TraceLevel(0),
	  PleaseDelete(FALSE),
	  Socket(_Socket),
	  StatusThread(_StatusThread)
{
	InstanceNo = ++StaticInstanceNo;
	Resume();	// start the thread
};


GkStatus::Client::~Client()
{
	Mutex.Wait();
	if(Socket->IsOpen())
		Close();
	delete Socket;
	Socket = NULL;
	Mutex.Signal();
};


PString GkStatus::Client::ReadCommand()
{
	PString Command;
	int	CharRead;
	
	for(;;)
	{
		CharRead = Socket->ReadChar();
		if ( CharRead < 0 )
			throw -1;
		if ( CharRead == '\n' )
			break;	
		if ( CharRead != '\r' )		// ignore carriage return
			Command += CharRead;
	}

	return Command;
}

void GkStatus::Client::Main()
{
#ifdef PTRACING
	PIPSocket::Address PeerAddress;
	Socket->GetPeerAddress(PeerAddress);
	PTRACE(2, "GK\tGkStatus new status client: addr " << PeerAddress.AsString());
#endif

	if(!StatusThread->AuthenticateClient(*Socket)) 
	{
		WriteString("Access forbidden!\r\n");
	}
	else 
	{
		BOOL exit_and_out = FALSE;
		while ( Socket->IsOpen() && !exit_and_out)
		{
			PString Line;

			try {
			  Line = ReadCommand();
			} catch (int i) {
			  break;
			}

			Line = Line.Trim(); // the 'Tokenise' seems not correct for leading spaces
			const PStringArray Args = Line.Tokenise(" ", FALSE);
			if(Args.GetSize() < 1) 
				continue;
			
			const PCaselessString &Command = Args[0];

			PTRACE(2, "GK\tGkStatus got command " << Command);
			if(Commands.Contains(Command.ToLower())) 
			{
				PINDEX key = Commands[Command];
				switch(key) {
				case GkStatus::e_DisconnectIp:
					// disconnect call on this IP number
					if (Args.GetSize() == 2)
						SoftPBX::Instance()->DisconnectIp(Args[1]);
					else
						WriteString("Syntax Error: DisconnectIp <ip address>\r\n");
					break;
				case GkStatus::e_DisconnectAlias:
					// disconnect call on this alias
					if (Args.GetSize() == 2)
						SoftPBX::Instance()->DisconnectAlias(Args[1]);
					else
						WriteString("Syntax Error: DisconnectAlias <h.323 alias>\r\n");
					break;
				case GkStatus::e_DisconnectCall:
					// disconnect call with this call number
					if (Args.GetSize() == 2)
						SoftPBX::Instance()->DisconnectCall(atoi(Args[1]));
 					else
						WriteString("Syntax Error: DisconnectCall <call number>\r\n");
 					break;
				case GkStatus::e_DisconnectEndpoint:
					// disconnect call on this alias
					if (Args.GetSize() == 2)
						SoftPBX::Instance()->DisconnectEndpoint(Args[1]);
					else
						WriteString("Syntax Error: DisconnectEndpoint ID\r\n");
					break;
				case GkStatus::e_PrintAllRegistrations:
					// print list of all registered endpoints
					SoftPBX::Instance()->PrintAllRegistrations(*this);
					break;
				case GkStatus::e_PrintAllRegistrationsVerbose:
					// print list of all registered endpoints verbose
					SoftPBX::Instance()->PrintAllRegistrations(*this, TRUE);
					break;
				case GkStatus::e_PrintCurrentCalls:
					// print list of currently ongoing calls
					SoftPBX::Instance()->PrintCurrentCalls(*this);
					break;
				case GkStatus::e_PrintCurrentCallsVerbose:
					// print list of currently ongoing calls
					SoftPBX::Instance()->PrintCurrentCalls(*this, TRUE);
					break;
				case GkStatus::e_Yell:
					StatusThread->SignalStatus(PString("  "+WhoAmI() + ": " + Line + "\r\n"));
					break;
				case GkStatus::e_Who:
#ifdef WIN32
					// Visual C++ doesn't grock the for_each_with2 template function
					// anybody have a better fix ?
					for (StatusThread->ClientIter=StatusThread->Clients.begin();
						StatusThread->ClientIter != StatusThread->Clients.end();
						++(StatusThread->ClientIter) )
					{
						WriteWhoAmI(*(StatusThread->ClientIter), this);
					};
#else
					Toolkit::for_each_with(StatusThread->Clients.begin(), StatusThread->Clients.end(), 
						WriteWhoAmI, this);
#endif
					WriteString(";\r\n");
					break;
				case GkStatus::e_Help:
					PrintHelp();
					break;
				case GkStatus::e_Debug:
					DoDebug(Args);
					break;
				case GkStatus::e_Version:
					WriteString("Version:\n\r");
					WriteString(Toolkit::GKVersion());
					WriteString("GkStatus: Version(1.0) Ext()\r\n");
					WriteString("Toolkit: Version(1.0) Ext("
								+Toolkit::Instance()->GetName()+")\r\n");
					WriteString(";\r\n");
					break;
				case GkStatus::e_Exit:
					Mutex.Wait();
					Close();
					Mutex.Signal();
				  	exit_and_out = TRUE;
					break;
				case GkStatus::e_UnregisterAllEndpoints:
					SoftPBX::Instance()->UnregisterAllEndpoints();
					WriteString("Done\n;\n");
					break;
				case GkStatus::e_UnregisterAlias:
					// unregister this alias
					if (Args.GetSize() == 2)
						SoftPBX::Instance()->UnregisterAlias(Args[1]);
					else
						WriteString("Syntax Error: UnregisterAlias Alias\r\n");
					break;
				case GkStatus::e_TransferCall:
					if (Args.GetSize() == 3)
						SoftPBX::Instance()->TransferCall(Args[1], Args[2]);
					else
						WriteString("Syntax Error: TransferCall Source Destination\r\n");
					break;
				case GkStatus::e_MakeCall:
					if (Args.GetSize() == 3)
						SoftPBX::Instance()->MakeCall(Args[1], Args[2]);
					else
						WriteString("Syntax Error: MakeCall Source Destination\r\n");
					break;
				default:
					PTRACE(3, "WRONG COMMANDS TABLE ENTRY. PLEASE LOOK AT THE CODE.");
					WriteString("Error: Internal Error.\r\n");
					break;
				}
			}
			else 
			{
				// commmand not recognized
				PTRACE(3, "Gk\tUnknown Command.");
				WriteString("Error: Unknown Command.\r\n");
			}
		}
	}
	
	PTRACE(2, "GK\tGkStatus client " << PeerAddress.AsString() << " has disconnected");
	PleaseDelete = TRUE;
	StatusThread->SetDirty(TRUE);

	// returning from main will delete this thread
};


void GkStatus::Client::DoDebug(const PStringArray &Args)
{
	if ( (NULL == Socket) || !Socket->IsOpen() ) {
		return;
	}

	if(Args.GetSize() <= 1) {
		WriteString("Debug options:\r\n");
		WriteString("  trc [+|-|n]       Show/modify trace level\r\n");
		WriteString("  cfg SEC PAR       Read and print a config PARameter in a SECtion\r\n");
		WriteString("  set SEC PAR VAL   Write a config VALue PARameter in a SECtion\r\n");
		WriteString("  reload            Reload config file\r\n");
	}
	else {
		if(Args[1] *= "trc") {
			if(Args.GetSize() >= 3) {
				if((Args[2] == "-") && (PTrace::GetLevel() > 0)) 
					PTrace::SetLevel(PTrace::GetLevel()-1);
				else if(Args[2] == "+") 
					PTrace::SetLevel(PTrace::GetLevel()+1);
				else PTrace::SetLevel(Args[2].AsInteger());
			}
			WriteString(PString(PString::Printf, "Trace Level is now %d\r\n", PTrace::GetLevel()));
		}
		else if((Args[1] *= "cfg") && (Args.GetSize()>=4)) 
			WriteString(Toolkit::Config()->GetString(Args[2],Args[3],"") + "\r\n");
		else if(Args[1] *= "reload")
			ReloadHandler();
		else if((Args[1] *= "set") && (Args.GetSize()>=5)) {
			Toolkit::Config()->SetString(Args[2],Args[3],Args[4]);
			WriteString(Toolkit::Config()->GetString(Args[2],Args[3],"") + "\r\n");
		}
	}
}


void GkStatus::Client::PrintHelp()
{
	if ( (NULL == Socket) || !Socket->IsOpen() ) {
		return;
	}

	WriteString("Commands:\r\n");
	for(PINDEX i=0; i<Commands.GetSize(); i++) {
		const PString &s = Commands.GetKeyAt(i);
		WriteString(s+"\r\n");
	}
	WriteString(";\r\n");
	return;
}



BOOL GkStatus::Client::WriteString(const PString &Message, int level) // level defaults to 0
{
	Mutex.Wait();

	if(level < TraceLevel)
		return TRUE;

	BOOL result;
	if ( (NULL != Socket) && Socket->IsOpen() )
		result = ( Socket->WriteString(Message) );
	else
		result = FALSE;

	Mutex.Signal();

	return result;
}

void GkStatus::Client::Close(void)
{
	if ( (NULL != Socket) && Socket->IsOpen() )
		Socket->Close();
};


BOOL GkStatus::AuthenticateClient(PIPSocket &Socket) const
{
	static PMutex AuthClientMutex;
	GkProtectBlock _using(AuthClientMutex);
	
	BOOL result = FALSE;

	const PString rule = Toolkit::Config()->GetString("GkStatus::Auth", "rule", "forbid");
	PIPSocket::Address PeerAddress;
	Socket.GetPeerAddress(PeerAddress);
	const PString peer = PeerAddress.AsString();
	PTRACE(4,"Auth client from " << peer);

	if(rule *= "forbid") { // "*=": case insensitive
		PTRACE(5,"Auth client rule=forbid");
		result =  FALSE;
	}
	else if(rule *= "allow") {
		PTRACE(5,"Auth client rule=allow");
		result =  TRUE;
	}
	else if(rule *= "explicit") {
		PTRACE(5,"Auth client rule=explicit");
		PString val = Toolkit::Config()->GetString("GkStatus::Auth", peer, "");
		if(val == "") { // use "default" entry
			PTRACE(5,"Auth client rule=explicit, ip-param not found, using default");
			result = Toolkit::AsBool
				(Toolkit::Config()->GetString("GkStatus::Auth", "default", "FALSE"));
		}
		else 
			result = Toolkit::AsBool(val);
	}
	else if(rule *= "regex") {
		PTRACE(5,"Auth client rule=regex");
		PString val = Toolkit::Config()->GetString("GkStatus::Auth", peer, "");
		if(val == "") 
			result = Toolkit::MatchRegex(peer, Toolkit::Config()->GetString("GkStatus::Auth", "regex", ""));
		else 
			result = Toolkit::AsBool(val);
	} 
	else {
		PTRACE(2, "Invalid [GkStatus::Auth].rule");
		result = FALSE;
	}
	
	return result;
}
