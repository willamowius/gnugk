// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// GkStatus.h thread for external interface
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
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

#include <ptlib.h>
#include <h225.h>
#include "gk.h"
#include "gk_const.h"
#include "GkStatus.h"
#include "GkDatabase.h"
#include "SoftPBX.h"
#include "Toolkit.h"
#include "ANSI.h"

using std::for_each;
using std::mem_fun;

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = GKSTATUS_H;
#endif /* lint */


static const int GkStatus::NumberOfCommandStrings = GkStatus::NO_enumCommands;
static const PStringToOrdinal::Initialiser GkStatusClientCommands[GkStatus::NumberOfCommandStrings] =
{
	{"printallregistrations",    GkStatus::e_PrintAllRegistrations},
	{"r",                        GkStatus::e_PrintAllRegistrations},
	{"?",                        GkStatus::e_PrintAllRegistrations},
	{"printallregistrationsverbose", GkStatus::e_PrintAllRegistrationsVerbose},
	{"rv",                       GkStatus::e_PrintAllRegistrationsVerbose},
	{"??",                       GkStatus::e_PrintAllRegistrationsVerbose},
	{"printallcached",           GkStatus::e_PrintAllCached},
	{"rc",                       GkStatus::e_PrintAllCached},
	{"printcurrentcalls",        GkStatus::e_PrintCurrentCalls},
	{"c",                        GkStatus::e_PrintCurrentCalls},
	{"!",                        GkStatus::e_PrintCurrentCalls},
	{"printcurrentcallsverbose", GkStatus::e_PrintCurrentCallsVerbose},
	{"!!",                       GkStatus::e_PrintCurrentCallsVerbose},
	{"cv",                       GkStatus::e_PrintCurrentCallsVerbose},
	{"find",                     GkStatus::e_Find},
	{"f",                        GkStatus::e_Find},
	{"findverbose",              GkStatus::e_FindVerbose},
	{"fv",                       GkStatus::e_FindVerbose},
	{"disconnectip",             GkStatus::e_DisconnectIp},
	{"disconnectcall",           GkStatus::e_DisconnectCall},
	{"disconnectalias",          GkStatus::e_DisconnectAlias},
	{"disconnectendpoint",       GkStatus::e_DisconnectEndpoint},
	{"unregisterallendpoints",   GkStatus::e_UnregisterAllEndpoints},
	{"unregisteralias",          GkStatus::e_UnregisterAlias},
	{"unregisterip",             GkStatus::e_UnregisterIp},
	{"transfercall",             GkStatus::e_TransferCall},
	{"makecall",                 GkStatus::e_MakeCall},
	{"yell",                     GkStatus::e_Yell},
	{"who",                      GkStatus::e_Who},
	{"help",                     GkStatus::e_Help},
	{"h",                        GkStatus::e_Help},
	{"version",                  GkStatus::e_Version},
	{"v",                        GkStatus::e_Version},
	{"debug",                    GkStatus::e_Debug},
	{"statistics",               GkStatus::e_Statistics},
	{"s",                        GkStatus::e_Statistics},
	{"reload",                   GkStatus::e_Reload},
	{"shutdown",                 GkStatus::e_Shutdown},
	{"exit",                     GkStatus::e_Exit},
	{"quit",                     GkStatus::e_Exit},
	{"q",                        GkStatus::e_Exit},
	{"flush",                    GkStatus::e_CDB_Flush}

};

int GkStatus::Client::StaticInstanceNo = 0;


GkStatus::GkStatus()
: PThread(1000, NoAutoDeleteThread),
  StatusListener(GkConfig()->GetInteger("StatusPort", GK_DEF_STATUS_PORT)),
	m_IsDirty(FALSE)
{
}

GkStatus::~GkStatus()
{
}

void GkStatus::Initialize(PIPSocket::Address _GKHome)
{
	GKHome = _GKHome;
	Resume();	// start the thread
}

void GkStatus::Main()
{
	unsigned qSize = GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH);
	WORD sPort = GkConfig()->GetInteger("StatusPort", GK_DEF_STATUS_PORT);
	if (GKHome == INADDR_ANY)
		StatusListener.Listen(qSize, sPort, PSocket::CanReuseAddress);
	else
		StatusListener.Listen(GKHome, qSize, sPort, PSocket::CanReuseAddress);

	StatusListener.SetReadTimeout(GkConfig()->GetInteger("StatusReadTimeout", 3000));
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

}

void GkStatus::Close(void)
{
	PTRACE(2, "GK\tClosing Status thread.");

	// close all connected clients
	ClientSetLock.Wait();
	for_each(Clients.begin(), Clients.end(), mem_fun(&Client::Close));
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
}

// function object used by for_each
class WriteWhoAmI {
  public:
	WriteWhoAmI(GkStatus::Client *c) : writeTo(c) {}
	void operator()(const GkStatus::Client *) const;

  private:
	GkStatus::Client *writeTo;
};

void WriteWhoAmI::operator()(const GkStatus::Client *pclient) const
{
	writeTo->WriteString("  " + pclient->WhoAmI() + GK_LINEBRK);
}

// function object used by for_each
class ClientSignalStatus {
  public:
	ClientSignalStatus(const PString &m, int l) : msg(m), level(l) {}
	void operator()(GkStatus::Client *) const;

  private:
	const PString &msg;
	int level;
};

void ClientSignalStatus::operator()(GkStatus::Client *pclient) const
{
	int ctl = pclient->TraceLevel;
	if((ctl<=10) && (ctl>=0) && (level >= ctl))
		pclient->WriteString(msg);
}


void GkStatus::SignalStatus(const PString &Message, int level)
{
//	ClientSetLock.Wait();
	for_each(Clients.begin(),Clients.end(), ClientSignalStatus(Message, level));
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


namespace {

PString PrintGkVersion()
{
	return PString("Version:" GK_LINEBRK) + Toolkit::GKVersion() +
		GK_LINEBRK "GkStatus: Version(1.0) Ext()" GK_LINEBRK
		"Toolkit: Version(1.0) Ext(" + Toolkit::Instance()->GetName() +
		")" GK_LINEBRK + SoftPBX::Uptime() + GK_LINEBRK ";" GK_LINEBRK;
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
}


GkStatus::Client::~Client()
{
	Mutex.Wait();
	if(Socket->IsOpen())
		Close();
	delete Socket;
	Socket = NULL;
	Mutex.Signal();
}


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
		WriteString("Access forbidden!" GK_LINEBRK);
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
						SoftPBX::DisconnectIp(Args[1]);
					else
						WriteString("Syntax Error: DisconnectIp <ip address>" GK_LINEBRK);
					break;
				case GkStatus::e_DisconnectAlias:
					// disconnect call on this alias
					if (Args.GetSize() == 2)
						SoftPBX::DisconnectAlias(Args[1]);
					else
						WriteString("Syntax Error: DisconnectAlias <h.323 alias>" GK_LINEBRK);
					break;
				case GkStatus::e_DisconnectCall:
					// disconnect call with this call number
					if (Args.GetSize() >= 2)
						for (PINDEX p=1; p < Args.GetSize(); ++p)
							SoftPBX::DisconnectCall(Args[p].AsInteger());
 					else
						WriteString("Syntax Error: DisconnectCall <call number> ..." GK_LINEBRK);
 					break;
				case GkStatus::e_DisconnectEndpoint:
					// disconnect call on this endpoint
					if (Args.GetSize() == 2)
						SoftPBX::DisconnectEndpoint(Args[1]);
					else
						WriteString("Syntax Error: DisconnectEndpoint ID" GK_LINEBRK);
					break;
				case GkStatus::e_PrintAllRegistrations:
					// print list of all registered endpoints
					SoftPBX::PrintAllRegistrations(*this);
					break;
				case GkStatus::e_PrintAllRegistrationsVerbose:
					// print list of all registered endpoints verbose
					SoftPBX::PrintAllRegistrations(*this, TRUE);
					break;
				case GkStatus::e_PrintAllCached:
					// print list of all cached outer-zone endpoints
					SoftPBX::PrintAllCached(*this, (Args.GetSize() > 1));
					break;
				case GkStatus::e_PrintCurrentCalls:
					// print list of currently ongoing calls
					SoftPBX::PrintCurrentCalls(*this);
					break;
				case GkStatus::e_PrintCurrentCallsVerbose:
					// print list of currently ongoing calls
					SoftPBX::PrintCurrentCalls(*this, TRUE);
					break;
				case GkStatus::e_Statistics:
					SoftPBX::PrintStatistics(*this, TRUE);
					break;
				case GkStatus::e_Find:
					if (Args.GetSize() == 2)
						SoftPBX::PrintEndpoint(Args[1], *this, FALSE);
					else
						WriteString("Syntax Error: Find alias" GK_LINEBRK);
					break;
				case GkStatus::e_FindVerbose:
					if (Args.GetSize() == 2)
						SoftPBX::PrintEndpoint(Args[1], *this, TRUE);
					else
						WriteString("Syntax Error: FindVerbose alias" GK_LINEBRK);
					break;
				case GkStatus::e_Yell:
					StatusThread->SignalStatus(PString("  "+WhoAmI() + ": " + Line + GK_LINEBRK));
					break;
				case GkStatus::e_Who:
					for_each(StatusThread->Clients.begin(), StatusThread->Clients.end(), WriteWhoAmI(this));
					WriteString(";" GK_LINEBRK);
					break;
				case GkStatus::e_Help:
					PrintHelp();
					break;
				case GkStatus::e_Debug:
					DoDebug(Args);
					break;
				case GkStatus::e_Version:
					WriteString(PrintGkVersion());
					break;
				case GkStatus::e_Exit:
					Mutex.Wait();
					Close();
					Mutex.Signal();
				  	exit_and_out = TRUE;
					break;
				case GkStatus::e_UnregisterAllEndpoints:
					SoftPBX::UnregisterAllEndpoints();
					WriteString("Done\n;\n");
					break;
				case GkStatus::e_UnregisterAlias:
					// unregister this alias
					if (Args.GetSize() == 2)
						SoftPBX::UnregisterAlias(Args[1]);
					else
						WriteString("Syntax Error: UnregisterAlias Alias" GK_LINEBRK);
					break;
				case GkStatus::e_UnregisterIp:
					// unregister this IP
					if (Args.GetSize() == 2)
						SoftPBX::UnregisterIp(Args[1]);
					else
						WriteString("Syntax Error: UnregisterIp <ip addr>" GK_LINEBRK);
					break;
				case GkStatus::e_TransferCall:
					if (Args.GetSize() == 3)
						SoftPBX::TransferCall(Args[1], Args[2]);
					else
						WriteString("Syntax Error: TransferCall Source Destination" GK_LINEBRK);
					break;
				case GkStatus::e_MakeCall:
					if (Args.GetSize() == 3)
						SoftPBX::MakeCall(Args[1], Args[2]);
					else
						WriteString("Syntax Error: MakeCall Source Destination" GK_LINEBRK);
					break;
				case GkStatus::e_Reload:
					ReloadHandler();
					break;
				case GkStatus::e_Shutdown:
					PTRACE(1, "Shutting down the GK");
					SoftPBX::UnregisterAllEndpoints();
					SoftPBX::PrintStatistics(*this, TRUE);
					ShutdownHandler();
					WriteString("BYE" GK_LINEBRK);
					exit(0);
					break;
				case GkStatus::e_CDB_Flush:
					PTRACE(3, "Flushing the common gk database cache");
					GkDatabase::Instance()->flush_cache();
					break
				default:
					PTRACE(3, "WRONG COMMANDS TABLE ENTRY. PLEASE LOOK AT THE CODE.");
					WriteString("Error: Internal Error." GK_LINEBRK);
					break;
				}
			}
			else
			{
				// commmand not recognized
				PTRACE(3, "Gk\tUnknown Command.");
				WriteString("Error: Unknown Command." GK_LINEBRK);
			}
		}
	}

	PTRACE(2, "GK\tGkStatus client " << PeerAddress.AsString() << " has disconnected");
	PleaseDelete = TRUE;
	StatusThread->SetDirty(TRUE);

	// returning from main will delete this thread
}


void GkStatus::Client::DoDebug(const PStringArray &Args)
{
	if ( (NULL == Socket) || !Socket->IsOpen() ) {
		return;
	}

	if(Args.GetSize() <= 1) {
		WriteString("Debug options:" GK_LINEBRK);
		WriteString("  trc [+|-|n]       Show/modify trace level" GK_LINEBRK);
		WriteString("  cfg SEC PAR       Read and print a config PARameter in a SECtion" GK_LINEBRK);
		WriteString("  set SEC PAR VAL   Write a config VALue PARameter in a SECtion" GK_LINEBRK);
		WriteString("  remove SEC PAR    Remove a config VALue PARameter in a SECtion" GK_LINEBRK);
		WriteString("  remove SEC        Remove a SECtion" GK_LINEBRK);
		WriteString("  printrm VERBOSE   Print all removed endpoint records" GK_LINEBRK);
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
			WriteString(PString(PString::Printf, "Trace Level is now %d" GK_LINEBRK, PTrace::GetLevel()));
		} else if (Args[1] *= "cfg") {
			if (Args.GetSize()>=4)
				WriteString(GkConfig()->GetString(Args[2],Args[3],"") + GK_LINEBRK ";" GK_LINEBRK);
			else if (Args.GetSize()>=3) {
				PStringList cfgs(GkConfig()->GetKeys(Args[2]));
				PString result = "Section [" + Args[2] + "]" GK_LINEBRK;
				for (PINDEX i=0; i < cfgs.GetSize(); ++i) {
					PString v(GkConfig()->GetString(Args[2], cfgs[i], ""));
					result += cfgs[i] + "=" + v + GK_LINEBRK;
				}
				WriteString(result + ";" GK_LINEBRK);
			}
		} else if((Args[1] *= "set") && (Args.GetSize()>=5)) {
			GkConfig()->SetString(Args[2],Args[3],Args[4]);
			WriteString(GkConfig()->GetString(Args[2],Args[3],"") + GK_LINEBRK);
		} else if (Args[1] *= "remove") {
			if (Args.GetSize()>=4) {
				GkConfig()->DeleteKey(Args[2],Args[3]);
				WriteString("Remove " + Args[3] + " in section " + Args[2] + GK_LINEBRK);
			} else if (Args.GetSize()>=3) {
				GkConfig()->DeleteSection(Args[2]);
				WriteString("Remove section " + Args[2] + GK_LINEBRK);
			}
		} else if((Args[1] *= "printrm")) {
			SoftPBX::PrintRemoved(*this, (Args.GetSize() >= 3));
		}
	}
}


void GkStatus::Client::PrintHelp()
{
	if ( (NULL == Socket) || !Socket->IsOpen() ) {
		return;
	}

	WriteString("Commands:" GK_LINEBRK);
	for(PINDEX i=0; i<Commands.GetSize(); i++) {
		const PString &s = Commands.GetKeyAt(i);
		WriteString(s+GK_LINEBRK);
	}
	WriteString(";" GK_LINEBRK);
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

int GkStatus::Client::Close(void)
{
	if ( (NULL != Socket) && Socket->IsOpen() )
		Socket->Close();
	return 0; // workaround for VC
}


BOOL GkStatus::AuthenticateClient(PIPSocket &Socket) const
{
	static PMutex AuthClientMutex;
	GkProtectBlock _using(AuthClientMutex);

	BOOL result = FALSE;

	const PString rule = GkConfig()->GetString("GkStatus::Auth", "rule", "forbid");
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
		PString val = GkConfig()->GetString("GkStatus::Auth", peer, "");
		if(val == "") { // use "default" entry
			PTRACE(5,"Auth client rule=explicit, ip-param not found, using default");
			result = Toolkit::AsBool
				(GkConfig()->GetString("GkStatus::Auth", "default", "FALSE"));
		}
		else
			result = Toolkit::AsBool(val);
	}
	else if(rule *= "regex") {
		PTRACE(5,"Auth client rule=regex");
		PString val = GkConfig()->GetString("GkStatus::Auth", peer, "");
		if(val == "")
			result = Toolkit::MatchRegex(peer, GkConfig()->GetString("GkStatus::Auth", "regex", ""));
		else
			result = Toolkit::AsBool(val);
	}
	else {
		PTRACE(2, "Invalid [GkStatus::Auth].rule");
		result = FALSE;
	}

	return result;
}
