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
#include "gk.h"
#include "RasSrv.h"
#include "MulticastGRQ.h"
#include "BroadcastListen.h"
#include "Toolkit.h"
#include "SoftPBX.h"


/*towi:
 * many things here should be members of Gatkeeper. 
 */

H323RasSrv * RasThread = NULL;
MulticastGRQ * MulticastGRQThread = NULL;
BroadcastListen * BroadcastThread = NULL;
PMutex ShutdownMutex;


PConfig* LoadReloadConfig()
{
	return Toolkit::ReloadConfig();
	/* The following patch in pwlib is neccessary to reload the config file:
	 * ### file: ~/openh323/gk/pwlib_src_ptlib_unix_config.cxx.patch ########
	 * *** config.cxx.old      Tue Jan 11 08:57:55 2000
	 * --- config.cxx.new      Tue Jan 11 08:57:20 2000
	 * ***************
	 * *** 444,450 ****
	 *
	 *      // decrement the instance count, but don't remove it yet
	 *       PFilePath key = GetKeyAt(index);
	 * !     instance->RemoveInstance(key);
	 *     }
	 *
	 *     mutex.Signal();
	 * --- 444,451 ----
	 * 
	 *       // decrement the instance count, but don't remove it yet
	 *       PFilePath key = GetKeyAt(index);
	 * !     if(instance->RemoveInstance(key)) //towi
	 * !               RemoveAt(key);              // towi
	 *     }
	 * 
	 *     mutex.Signal();
	 * #######################################################################
	 * You may apply the patch by saving the above in a patch file (without #-lines)
	 * and use the following commands:
	 * $> cd ~/pwlib/src/ptlib/unix
	 * $> patch config.cxx ~/openh323/gk/pwlib_src_ptlib_unix_config.cxx.patch
	 */
}
/*:towi*/

void ShutdownHandler(void)
{
	// we may get one shutdown signal for every thread; make sure we
	// delete objects only once
	if (ShutdownMutex.WillBlock())
		return;
	ShutdownMutex.Wait();
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
	delete resourceManager::Instance();
	delete RegistrationTable::Instance();
	delete CallTable::Instance();
	ShutdownMutex.Signal();

	return;
}


void ReloadHandler(void)
{
	// only one thread must do this
	if (ShutdownMutex.WillBlock())
		return;
	
	/*
	** Enter critical Section
	*/
	ShutdownMutex.Wait();

	/*
	** Force reloading config
	*/
	LoadReloadConfig();
	PTRACE(3, "GK\t\tConfig reloaded.");

	/*
	** Unregister all endpoints
	*/
	SoftPBX::Instance()->UnregisterAllEndpoints();
	PTRACE(3, "GK\t\tEndpoints unregistered.");

	/*
	** Don't disengage current calls!
	*/
	PTRACE(3, "GK\t\tCarry on current calls.");

	/*
	** Leave critical Section
	*/
	// give other threads the chance to pass by this handler
	PProcess::Current().Sleep(1000); 

	ShutdownMutex.Signal();

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

void UnixShutdownHandler(int sig)
{
	PTRACE(1, "GK\tGatekeeper shutdown (signal " << sig << ")");
	// exit(2); // dump gprof info to gmon.out
	ShutdownHandler();
	exit(0);
};

void UnixReloadHandler(int sig) // For HUP Signal
{
	PTRACE(1, "GK\tGatekeeper Hangup (signal " << sig << ")");
#ifdef P_SOLARIS
	// on Solaris the handler has to be reset
	signal(SIGHUP, UnixReloadHandler);
#endif
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
		 "h-home:"
#ifdef PTRACING
		 "t-trace."
		 "o-output:"
#endif
		 "l-timetolive:"
		 "c-configfile:"
		 "s-section:"
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
	signal(SIGHUP, UnixReloadHandler);
#endif
	
	return TRUE;
}


BOOL Gatekeeper::InitLogging(const PArgList &args)
{
#ifdef PTRACING
	// PTrace::SetOptions(PTrace::Timestamp | PTrace::Thread);
	// PTrace::SetOptions(PTrace::Timestamp);
	PTrace::SetOptions(PTrace::DateAndTime | PTrace::TraceLevel); // towi
	PTrace::SetLevel(args.GetOptionCount('t'));
	if (args.HasOption('o'))
	{
		PTextFile * output = new PTextFile;
		if (output->Open(args.GetOptionString('o'), PFile::WriteOnly))
			PTrace::SetStream(output);
		else
		{
			cout << "Warning: could not open trace output file \""
				<< args.GetOptionString('o') << '"' << endl;
			delete output;
		}
	}
	PTRACE(1, "GK\tTrace logging started.");
#endif
	
	return TRUE;
}


BOOL Gatekeeper::InitToolkit(const PArgList &args)
{
	Toolkit::Instance(); // force using the right Toolkit constructor

	return TRUE;
}


/*towi: This is not complete now. We must not use LoadReloadConfig
 * like it is now. We have to think how to use signal handles
 * and (virtual or static) method functions.
 */
BOOL Gatekeeper::InitConfig(const PArgList &args)
{
	// get the name of the config file
	PFilePath fp("gatekeeper.ini");
	PString   section("Gatekeeper::Main");

	if (args.HasOption('c')) 
		fp = PFilePath(args.GetOptionString('c'));

	if (args.HasOption('s')) 
		section = args.GetOptionString('s');

	Toolkit::SetConfig(fp, section);
	// not neccessary: LoadReloadConfig();Toolkit::m_Instance
	
	if( (Toolkit::Config()->GetInteger("Fourtytwo") ) != 42) { 
		cerr << "CONFIG CHECK FAILED!\n"
			 << "- Does the config file exist? The default or the one given with -c?\n"
			 << "- Did you specify they the right 'Main' section with -s?\n" 
			 << "- Is the line 'Fourtytwo=42' present in this 'Main' section?"<<endl;
		exit(1);
	}
	
	return TRUE;
}


void Gatekeeper::Main()
{
	PArgList & args = GetArguments();
	args.Parse(GetArgumentsParseString());

	int GKcapacity = 100000; // default gatekeeper capacity (in 100s bit)
	int TimeToLive = -1;
	BOOL GKroutedSignaling = FALSE;	// default: use direct signaling
	PIPSocket::Address GKHome;

	if(! InitHandlers(args)) return;

	if(! InitToolkit(args)) return;

	if(! InitConfig(args)) return;

	if(! InitLogging(args)) return;

	// read gatekeeper home address from commandline
	if (args.HasOption('h'))
		GKHome = PString(args.GetOptionString('h'));
	else {
		PString s = Toolkit::Config()->GetString("Home", "x");
		if (s == "x")
			PIPSocket::GetHostAddress(GKHome);
		else
			GKHome = s;
	}
	
	cout << "OpenH323 gatekeeper '" << Toolkit::GKName() << "' started on " << inet_ntoa(GKHome) << endl;
	cout << Toolkit::GKVersion() << endl;
	PTRACE(1, "GK\tGatekeeper '" << Toolkit::GKName() << "' started on " << inet_ntoa(GKHome));
	PTRACE(1, "GK\t"<<Toolkit::GKVersion());

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
}
