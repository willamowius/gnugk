//////////////////////////////////////////////////////////////////
//
// gk.cxx for H.323 gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
// 	990500	initial version (Xiang Ping Chen, Rajat Todi, Joe Metzger)
//	990600	ported to OpenH323 V. 1.08 (Jan Willamowius)
//	990702	code cleanup (Jan Willamowius)
//	990924	clean shutdown (Jan Willamowius)
//	991016	clean shutdown (Jan Willamowius)
//
//////////////////////////////////////////////////////////////////


#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4800 ) // one performance warning off
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#endif

#ifndef WIN32
#include <signal.h>
#endif
#include <ptlib.h>
#include <q931.h>
#include "gk.h"
#include "RasSrv.h"
#include "RasTbl.h"
#include "MulticastGRQ.h"
#include "BroadcastListen.h"
#include "Toolkit.h"
#include "h323util.h"


/*
 * many things here should be members of Gatkeeper. 
 */

H323RasSrv * RasThread = NULL;
MulticastGRQ * MulticastGRQThread = NULL;
BroadcastListen * BroadcastThread = NULL;
PMutex ShutdownMutex;


void ShutdownHandler(void)
{
	// we may get one shutdown signal for every thread; make sure we
	// delete objects only once
	if (ShutdownMutex.WillBlock())
		return;
	PWaitAndSignal shutdown(ShutdownMutex);
	if (BroadcastThread != NULL)
	{
		PTRACE(3, "GK\tClosing BroadcastThread");
		BroadcastThread->Close();
		BroadcastThread->WaitForTermination();
		delete BroadcastThread;
		BroadcastThread = NULL;
	};
	if (MulticastGRQThread != NULL)
	{
		PTRACE(3, "GK\tClosing MulticastGRQThread");
		MulticastGRQThread->Close();
		MulticastGRQThread->WaitForTermination();
		delete MulticastGRQThread;
		MulticastGRQThread = NULL;
	};
	if (RasThread != NULL)
	{
		PTRACE(3, "GK\tClosing RasThread");
		RasThread->Close();
		// send all registered clients a URQ
		RasThread->UnregisterAllEndpoints();
		delete RasThread;
		RasThread = NULL;
	};

	// delete singleton objects
	PTRACE(3, "GK\tDeleting global reference tables");

	// The singletons would be deleted automatically
	// by destructor of listptr<SingletonBase *>
	// However, I have to delete Toolkit instance here,
	// or it will cause a core dump. I don't know why...
//        delete resourceManager::Instance();
//        delete RegistrationTable::Instance();
//        delete CallTable::Instance();
//        delete SoftPBX::Instance();
        delete Toolkit::Instance();

	return;
}


#ifdef WIN32

BOOL WINAPI WinCtrlHandlerProc(DWORD dwCtrlType)
{
	PTRACE(1, "GK\tGatekeeper shutdown");
	ShutdownHandler();
	exit(0);	// if we don't exit(), this handler gets called again and again - strange...
	return TRUE;
};

#else

PThread *mainThread = NULL;

void UnixShutdownHandler(int sig)
{
	PTRACE(1, "GK\tGatekeeper shutdown (signal " << sig << ")");
	// exit(2); // dump gprof info to gmon.out
	if (PThread::Current() == mainThread) {
		RasThread->Shutdown();
	} else {
		PTRACE(1, "This is not main thread, ignore!\n");
	}
};

void UnixReloadHandler(int sig) // For HUP Signal
{
	PTRACE(1, "GK\tGatekeeper Hangup (signal " << sig << ")");
	ReloadHandler();
};

#endif


// default params for overwriting
Gatekeeper::Gatekeeper(const char * manuf,
					   const char * name,
					   WORD majorVersion,
					   WORD minorVersion,
					   CodeStatus status,
					   WORD buildNumber)
	: PProcess(manuf, name, majorVersion, minorVersion, status, buildNumber)
{
}


const PString Gatekeeper::GetArgumentsParseString() const
{
	return PString
		("r-routed."
		 "b-bandwidth:"
		 "i-interface:"
#ifdef PTRACING
		 "t-trace."
		 "o-output:"
#endif
		 "l-timetolive:"
		 "c-configfile:"
		 "s-section:"
		 "h-help:"
		 );
}


BOOL Gatekeeper::InitHandlers(const PArgList &args)
{
#ifdef WIN32
	SetConsoleCtrlHandler(WinCtrlHandlerProc, TRUE);
#else
	signal(SIGTERM, UnixShutdownHandler);
	signal(SIGINT, UnixShutdownHandler);
	signal(SIGQUIT, UnixShutdownHandler);
	signal(SIGUSR1, UnixShutdownHandler);

	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGHUP); // ignore while in handler
	sa.sa_flags = 0;
	sa.sa_handler = UnixReloadHandler;

	sigaction(SIGHUP, &sa, NULL);
	mainThread = PThread::Current();
#endif

	return TRUE;
}


BOOL Gatekeeper::InitLogging(const PArgList &args)
{
#ifdef PTRACING
	// PTrace::SetOptions(PTrace::Timestamp | PTrace::Thread);
	// PTrace::SetOptions(PTrace::Timestamp);
	PTrace::SetOptions(PTrace::DateAndTime | PTrace::TraceLevel);
	PTrace::SetLevel(args.GetOptionCount('t'));
	if (args.HasOption('o'))
	{
		static PTextFile output;
		if (output.Open(args.GetOptionString('o'), PFile::WriteOnly))
			PTrace::SetStream(&output);
		else
		{
			cout << "Warning: could not open trace output file \""
				<< args.GetOptionString('o') << '"' << endl;
		}
	}
	PTRACE(1, "GK\tTrace logging started.");
#endif
	
	return TRUE;
}


BOOL Gatekeeper::InitToolkit(const PArgList &args)
{
	InstanceOf<Toolkit>(); // force using the right Toolkit constructor

	return TRUE;
}


BOOL Gatekeeper::InitConfig(const PArgList &args)
{
	// get the name of the config file
	PFilePath fp("gatekeeper.ini");
	PString   section("Gatekeeper::Main");

	if (args.HasOption('c')) 
		fp = PFilePath(args.GetOptionString('c'));

	if (args.HasOption('s')) 
		section = args.GetOptionString('s');

	InstanceOf<Toolkit>()->SetConfig(fp, section);

	if( (GkConfig()->GetInteger("Fourtytwo") ) != 42) { 
		cerr << "WARNING: No config file found!\n"
			 << "- Does the config file exist? The default (~/.pwlib_config/Gatekeeper.ini or gatekeeper.ini in current directory) or the one given with -c?\n"
			 << "- Did you specify they the right 'Main' section with -s?\n" 
			 << "- Is the line 'Fourtytwo=42' present in this 'Main' section?"<<endl;
	}
	
	return TRUE;
}


void Gatekeeper::PrintOpts(void)
{
	PStringArray opts = GetArgumentsParseString().Tokenise(".:", FALSE);

	cout << "Known options:" << endl;
	for(PINDEX i=0; i< opts.GetSize(); i++){
		cout << opts[i]<< endl;
	}
}


void Gatekeeper::Main()
{
	PArgList & args = GetArguments();
	args.Parse(GetArgumentsParseString());

	int GKcapacity = 100000; // default gatekeeper capacity (in 100s bit)
	int TimeToLive = -1;
	BOOL GKroutedSignaling = FALSE;	// default: use direct signaling
	PIPSocket::Address GKHome;

	if(! InitLogging(args)) return;

	if(! InitHandlers(args)) return;

	if(! InitToolkit(args)) return;

	if(! InitConfig(args)) return;

	if (args.HasOption('h')) {
		cout << "OpenH323 gatekeeper '" << Toolkit::GKName() << "' started on " << inet_ntoa(GKHome) << endl;
		cout << Toolkit::GKVersion() << endl;
		PrintOpts();
        	delete Toolkit::Instance();
		exit(0);
	}

	// read gatekeeper home address from commandline
	if (args.HasOption('i'))
		GKHome = PString(args.GetOptionString('i'));
	else {
		PString s = GkConfig()->GetString("Home", "x");
		if (s == "x")
			PIPSocket::GetHostAddress(GKHome);
		else
			GKHome = s;
	}
	
	cout << "OpenH323 gatekeeper with ID '" << Toolkit::GKName() << "' started on " << inet_ntoa(GKHome) << endl;
	cout << Toolkit::GKVersion() << endl;
	PTRACE(1, "GK\tGatekeeper with ID '" << Toolkit::GKName() << "' started on " << inet_ntoa(GKHome));
	PTRACE(1, "GK\t"<<Toolkit::GKVersion());

	// Copyright notice
	cout <<
		"This program is free software; you can redistribute it and/or\n"
		"modify it under the terms of the GNU General Public License\n"
		"as published by the Free Software Foundation; either version 2\n"
		"of the License, or (at your option) any later version.\n"
	    << endl;

	// read signaling method from commandline
	if (args.HasOption('r'))
		GKroutedSignaling = TRUE;
	if (GKroutedSignaling)
		PTRACE(2, "GK\tUsing routed signalling");
	else
		PTRACE(2, "GK\tUsing direct signalling");

	// read capacity from commandline
	if (args.HasOption('b'))
		GKcapacity = atoi(args.GetOptionString('b'));
	PTRACE(2, "GK\tAvailable Bandwidth: " << GKcapacity);
	resourceManager::Instance()->SetBandWidth(GKcapacity);

	// read timeToLive from command line
	if (args.HasOption('l'))
		TimeToLive = atoi(args.GetOptionString('l'));
	PTRACE(2, "GK\tTimeToLive for Registrations: " << TimeToLive);
  
	RasThread = new H323RasSrv(GKHome);
	RasThread->SetGKSignaling(GKroutedSignaling);
	RasThread->SetTimeToLive(TimeToLive);

	MulticastGRQThread = new MulticastGRQ(GKHome, RasThread);

#if (defined P_LINUX) || (defined P_FREEBSD) || (defined P_HPUX9) || (defined P_SOLARIS)
	// On some OS we don't get broadcasts on a socket that is
	// bound to a specific interface. For those we have to start
	// a thread that listens just for those broadcasts.
	// On Windows NT we get all messages on the RAS socket, even
	// if it's bound to a specific interface and thus don't have
	// to start this thread.
	BroadcastThread = new BroadcastListen(RasThread);
#endif

	// let's go
	RasThread->HandleConnections();

	// graceful shutdown
	ShutdownHandler();
}
