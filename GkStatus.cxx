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

// status trace
#define STRACE(xxx)  cerr << ANSI::BRED << xxx << ANSI::OFF<<endl
// client trace
#define CTRACE(xxx)  cerr << ANSI::BRED<<"["<<InstanceNo<<"]\t"<< xxx <<ANSI::OFF<<endl

/// this is a counter only useful while debugging!!!
unsigned long countNitroBugfix = 0;


const int GkStatus::NumberOfCommandStrings = 22;
const static PStringToOrdinal::Initialiser GkStatusClientCommands[GkStatus::NumberOfCommandStrings] =
{ // the leading spaces: PWLib Bug for PStringToOrdinal in Solaris for short strings?
	{"  PrintAllRegistrations",    GkStatus::e_PrintAllRegistrations},
	{"  r",                        GkStatus::e_PrintAllRegistrations},
	{"  ?",                        GkStatus::e_PrintAllRegistrations},
	{"  PrintAllRegistrationsVerbose", GkStatus::e_PrintAllRegistrationsVerbose},
	{"  rv",                       GkStatus::e_PrintAllRegistrationsVerbose},
	{"  ??",                       GkStatus::e_PrintAllRegistrationsVerbose},
	{"  PrintCurrentCalls",        GkStatus::e_PrintCurrentCalls},
	{"  c",                        GkStatus::e_PrintCurrentCalls},
	{"  !",                        GkStatus::e_PrintCurrentCalls},
	{"  PrintCurrentCallsVerbose", GkStatus::e_PrintCurrentCallsVerbose},
	{"  !!",                       GkStatus::e_PrintCurrentCallsVerbose},
	{"  cv",                       GkStatus::e_PrintCurrentCallsVerbose},
	{"  Disconnect",               GkStatus::e_Disconnect},
	{"  UnregisterAllEndpoints",   GkStatus::e_UnregisterAllEndpoints},
	{"  Yell",                     GkStatus::e_Yell},
	{"  Who",                      GkStatus::e_Who},
	{"  Help",                     GkStatus::e_Help},
	{"  h",                        GkStatus::e_Help},
	{"  Version",                  GkStatus::e_Version},
	{"  Debug",                    GkStatus::e_Debug},
	{"  Exit",                     GkStatus::e_Exit},
	{"  Quit",                     GkStatus::e_Exit}
};

int GkStatus::Client::StaticInstanceNo = 0;


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
	else
		countNitroBugfix++;
		
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
	STRACE("["<<Client->InstanceNo<<"]\tRemoveClient(c)");
	//ClientSetLock.Wait();

	/* towi-000217: doesn't erase call the destructor? 
	 * So we have to wait for pending writes!
	 */
	Clients.erase(Client);
	delete Client;
	//ClientSetLock.Signal();
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
	CTRACE("CONSTRUCT");
	Resume();	// start the thread
};


GkStatus::Client::~Client()
{
	Mutex.Wait(); //x
	CTRACE("DESTRUCT");
	if(Socket->IsOpen())
		Close();
	delete Socket;
	Socket = NULL;
	Mutex.Signal(); //x
};


PString GkStatus::Client::ReadCommand()
{
	CTRACE("ReadCommand()");
	PString Command;
	int	CharRead;
	
	for(;;)
	{
		CharRead = Socket->ReadChar();
		if ( CharRead < 0 )
			throw -1;
		if ( CharRead == '\n' )
			break;	
		if ( CharRead != '\r' )		// Ignore carriage return
			Command += CharRead;
	}

	return Command;
}

void GkStatus::Client::Main()
{
	CTRACE("Main()");

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
			
			const PString &Command = "  " + Args[0]; // PWLib Bug for Solaris; elongate short strings...
			
			PTRACE(2, "GK\tGkStatus got command " << Command);
			if(Commands.Contains(Command)) 
			{
				PINDEX key = Commands[Command];
				switch(key) {
				case GkStatus::e_Disconnect:
					// disconnect call on this IP number
					SoftPBX::Instance()->Disconnect(Args[1]);
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
					Mutex.Wait(); //x
					Close(); //x
					Mutex.Signal(); //x
				  	exit_and_out = TRUE;
					break;
				case GkStatus::e_UnregisterAllEndpoints:
					SoftPBX::Instance()->UnregisterAllEndpoints();
					WriteString("Done\n;\n");
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

	// returning from main will delete this thread   [towi: does it?]
};


void GkStatus::Client::DoDebug(const PStringArray &Args)
{
	if ( (NULL == Socket) || !Socket->IsOpen() ) {
		return;
	}

	if(Args.GetSize() <= 1) {
		WriteString("Debug options:\r\n");
		WriteString("  nitro             Show number of applied nitro bugfixes\r\n");
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
		else if(Args[1] *= "nitro") {
			WriteString(PString(PString::Printf, "applied nitros: %lu\r\n", countNitroBugfix));
		}
		else if(Args[1] *= "reload") {
			Toolkit::ReloadConfig();
			WriteString("reloaded.\r\n");
		}
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
	Mutex.Wait(); //x
	//x StatusThread->ClientSetLock.Wait();

	CTRACE("   WriteString()");
	if ( (TraceLevel < 0) || (TraceLevel>10) ) {
		countNitroBugfix++;
		return TRUE;
	} else if(level < TraceLevel)
		return TRUE;

	BOOL result;
	if ( (NULL != Socket) && Socket->IsOpen() )
		result = ( Socket->WriteString(Message) );
	else
		result = FALSE;

	//StatusThread->ClientSetLock.Signal();
	Mutex.Signal(); //x
	return result;
}

void GkStatus::Client::Close(void)
{
	CTRACE("Close()");
	if ( (NULL != Socket) && Socket->IsOpen() ) //towi: was "Socket != NULL"
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
