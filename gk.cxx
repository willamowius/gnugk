//////////////////////////////////////////////////////////////////
//
// gk.cxx for OpenH323 Gatekeeper - GNU Gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
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
#define HAS_SETUSERNAME
#include <signal.h>
#endif
#include "gk.h"
#include "RasSrv.h"
#include "RasTbl.h"
#include "SoftPBX.h"
#include "Toolkit.h"
#include "h323util.h"
#include "stl_supp.h"


#if PTRACING
PTextFile *logfile = 0;
PString logfilename;

void ReopenLogFile()
{
	if (!logfilename) {
		PTRACE_IF(1, logfile, "GK\tLogging closed.");
		PTrace::SetStream(&cerr); // redirect to cerr
		delete logfile;

		PTime now;
		PString fileName = logfilename;
		fileName.Replace(".", "." + now.AsString( "yyyy-MM-dd" ) + "." );

		logfile = new PTextFile( fileName, PFile::WriteOnly, PFile::Create);
		
		if (!logfile->IsOpen()) {
			cerr << "Warning: could not open trace output file \""
			     << fileName << '"' << endl;
			delete logfile;
			logfile = 0;
			return;
		}
		logfile->SetPosition(logfile->GetLength());
		PTrace::SetStream(logfile); // redirect to logfile
	}
	PTRACE(1, "GK\tTrace logging restarted.");
}
#endif


/*
 * many things here should be members of Gatkeeper. 
 */

PReadWriteMutex ConfigReloadMutex;

namespace { // keep the global objects private


PMutex ShutdownMutex;
PMutex ReloadMutex;

#ifndef WIN32
PString pidfile("/var/run/gnugk.pid");
#endif

void ShutdownHandler()
{
	// delete singleton objects
	PTRACE(3, "GK\tDeleting global reference tables");

	Job::StopAll();
	delete CallTable::Instance();
	delete RegistrationTable::Instance();
	delete RasServer::Instance();
	delete Toolkit::Instance();
	PTRACE(3, "GK\tdelete ok");

#if PTRACING
	PTrace::SetStream(&cerr); // redirect to cerr
	delete logfile;
#endif
}

bool CheckSectionName(PConfig *cfg)
{
	bool result = true;
	PStringList sections = cfg->GetSections();
	for (PINDEX i = 0; i < sections.GetSize(); ++i) {
		PString sec = sections[i];
		if (sec.Find("RasSvr") == 0) {
			cerr << "The section " << sec << " should be ";
			sec.Replace("RasSvr", "RasSrv");
		       	cerr << sec << '\n';
			result = false;
		}
	}
	if (!result)
		cerr << endl;
	return result;
}

// due to some unknown reason (PWLib bug?),
// we have to delete Toolkit::Instance first,
// or we get core dump
void ExitGK()
{
	delete Toolkit::Instance();

#if PTRACING
	PTrace::SetStream(&cerr); // redirect to cerr
	delete logfile;
#endif
	exit(0);
}

} // end of anonymous namespace

void ReloadHandler()
{
	// only one thread must do this
	if (ReloadMutex.WillBlock())
		return;
	
	/*
	** Enter critical Section
	*/
	PWaitAndSignal reload(ReloadMutex);

	ConfigReloadMutex.StartWrite();

	/*
	** Force reloading config
	*/
	InstanceOf<Toolkit>()->ReloadConfig();

	SoftPBX::TimeToLive = GkConfig()->GetInteger("TimeToLive", SoftPBX::TimeToLive);

	/*
	** Update all gateway prefixes
	*/

	CallTable::Instance()->LoadConfig();
	RegistrationTable::Instance()->LoadConfig();

	// don't put this in LoadConfig()
	RasServer::Instance()->SetRoutedMode();

	RasServer::Instance()->LoadConfig();

	ConfigReloadMutex.EndWrite();

	/*
	** Don't disengage current calls!
	*/
	PTRACE(3, "GK\tCarry on current calls.");

	/*
	** Leave critical Section
	*/
	// give other threads the chance to pass by this handler
	PProcess::Sleep(500);
}

#ifdef WIN32

BOOL WINAPI WinCtrlHandlerProc(DWORD dwCtrlType)
{
	PTRACE(1, "GK\tGatekeeper shutdown");
	PWaitAndSignal shutdown(ShutdownMutex);
	RasServer::Instance()->Stop();
	return true;
}

bool Gatekeeper::SetUserAndGroup(const PString &username)
{
	return false;
}

#else
#  include <pwd.h>

bool Gatekeeper::SetUserAndGroup(const PString &username)
{
#if defined(P_PTHREADS) && !defined(P_THREAD_SAFE_CLIB)
	static const size_t MAX_PASSWORD_BUFSIZE = 1024;

	struct passwd userdata;
	struct passwd *userptr;
	char buffer[MAX_PASSWORD_BUFSIZE];

#if defined (P_LINUX) || defined (P_AIX) || defined(P_IRIX) || (__GNUC__>=3 && defined(P_SOLARIS)) || defined(P_RTEMS)
	::getpwnam_r(username,&userdata,buffer,sizeof(buffer),&userptr);
#else
	userptr = ::getpwnam_r(username, &userdata, buffer, sizeof(buffer));
#endif
#else
	struct passwd *userptr = ::getpwnam(username);
#endif

	return userptr && userptr->pw_name 
		&& (::setgid(userptr->pw_gid) == 0) && (::setuid(userptr->pw_uid) == 0);
}

void UnixShutdownHandler(int sig)
{
	if (ShutdownMutex.WillBlock() || !RasServer::Instance()->IsRunning())
		return;
	PWaitAndSignal shutdown(ShutdownMutex);
	PTRACE(1, "GK\tReceived signal " << sig);
	PFile::Remove(pidfile);
	RasServer::Instance()->Stop();
}

void UnixReloadHandler(int sig) // For HUP Signal
{
	PTRACE(1, "GK\tGatekeeper Hangup (signal " << sig << ")");
#if PTRACING
	ReopenLogFile();
#endif
	ReloadHandler();
}

void DumbHandler(int sig)
{
	PTRACE(1, "Warning: signal " << sig << " received and ignored!");
}

#endif // WIN32


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
		 "-h245routed."
		 "d-direct."
		 "i-interface:"
		 "l-timetolive:"
		 "b-bandwidth:"
#ifdef HAS_SETUSERNAME
		 "u-user:"
#endif
#if PTRACING
		 "t-trace."
		 "o-output:"
#endif
		 "c-config:"
		 "s-section:"
		 "-pid:"
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

	// ignore these signals
	signal(SIGPIPE, DumbHandler);
	signal(SIGABRT, DumbHandler);


	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGHUP); // ignore while in handler
	sa.sa_flags = 0;
	sa.sa_handler = UnixReloadHandler;

	sigaction(SIGHUP, &sa, NULL);

	if (args.HasOption("pid"))
		pidfile = args.GetOptionString("pid");
	PTextFile pid(pidfile, PFile::WriteOnly);
	pid.WriteLine(PString(PString::Unsigned, getpid()));
#endif
	return TRUE;
}


BOOL Gatekeeper::InitLogging(const PArgList &args)
{
#if PTRACING
	// PTrace::SetOptions(PTrace::Timestamp | PTrace::Thread);
	// PTrace::SetOptions(PTrace::Timestamp);
	//PTrace::SetOptions(PTrace::DateAndTime | PTrace::TraceLevel | PTrace::Thread);
	PTrace::SetOptions(PTrace::DateAndTime | PTrace::TraceLevel);
	PTrace::SetLevel(args.GetOptionCount('t'));
	if (args.HasOption('o')) {
		logfilename = args.GetOptionString('o');
		ReopenLogFile();
	}
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
	PString section("Gatekeeper::Main");

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
	
	return CheckSectionName(GkConfig());
}


void Gatekeeper::PrintOpts(void)
{
	cout << "Options:\n"
		"  -r  --routed       : Use gatekeeper routed call signaling\n"
		"  -rr --h245routed   : Use H.245 control channel routed\n"
		"  -d  --direct       : Use direct endpoint call signaling\n"
		"  -i  --interface IP : The IP that the gatekeeper listen to\n"
		"  -l  --timetolive n : Time to live for client registration\n"
		"  -b  --bandwidth n  : Specify the total bandwidth\n"
#ifdef HAS_SETUSERNAME
		"  -u  --user name    : Run as this user\n"
#endif
#if PTRACING
		"  -t  --trace        : Set trace verbosity\n"
		"  -o  --output file  : Write trace to this file\n"
#endif
		"  -c  --config file  : Specify which config file to use\n"
		"  -s  --section sec  : Specify which main section to use in the config file\n"
		"      --pid file     : Specify the pid file\n"
		"  -h  --help         : Show this message\n" << endl;
}


void Gatekeeper::Main()
{
	PArgList & args = GetArguments();
	args.Parse(GetArgumentsParseString());

#ifdef HAS_SETUSERNAME
	if (args.HasOption('u')) {
		const PString username = args.GetOptionString('u');

		if ( !SetUserAndGroup(username) ) {
			cout << "GNU Gatekeeper could not run as user "
			     << username
			     << endl;
			return;
		}
	}
#endif

	if(!InitLogging(args) || !InitToolkit(args))
		return;

	if (args.HasOption('h')) {
		PrintOpts();
		ExitGK();
	}

	if (!InitConfig(args) || !InitHandlers(args))
		ExitGK();

	PString welcome("OpenH323 Gatekeeper - The GNU Gatekeeper with ID '" + Toolkit::GKName() + "' started\n" + Toolkit::GKVersion());
	cout << welcome << '\n';
	PTRACE(1, welcome);

	if (args.HasOption('i'))
		Toolkit::Instance()->SetGKHome(args.GetOptionString('i').Lines());

	std::vector<PIPSocket::Address> GKHome;
	PString home(Toolkit::Instance()->GetGKHome(GKHome));
	if (GKHome.empty()) {
		cerr << "Fatal: Cannot find any interface to run GnuGK!\n";
		ExitGK();
	}
	cout << "Listen on " << home << "\n\n";

	// Copyright notice
	cout <<
		"This program is free software; you can redistribute it and/or\n"
		"modify it under the terms of the GNU General Public License\n"
		"as published by the Free Software Foundation; either version 2\n"
		"of the License, or (at your option) any later version.\n"
	     << endl;

	// read capacity from commandline
	int GKcapacity;
	if (args.HasOption('b'))
		GKcapacity = args.GetOptionString('b').AsInteger();
	else
		GKcapacity = GkConfig()->GetInteger("TotalBandwidth", -1);
	CallTable::Instance()->SetTotalBandWidth(GKcapacity);
	if (GKcapacity < 0)
		cout << "\nDisable Bandwidth Management" << endl;
	else
		cout << "\nAvailable Bandwidth " << GKcapacity << endl;

	// read timeToLive from command line
	if (args.HasOption('l'))
		SoftPBX::TimeToLive = args.GetOptionString('l').AsInteger();
	else
		SoftPBX::TimeToLive = GkConfig()->GetInteger("TimeToLive", -1);
	PTRACE(2, "GK\tTimeToLive for Registrations: " << SoftPBX::TimeToLive);
  
	RasServer *RasSrv = RasServer::Instance();

	// read signaling method from commandline
	if (args.HasOption('r'))
		RasSrv->SetRoutedMode(true, (args.GetOptionCount('r') > 1 || args.HasOption("h245routed")));
	else if (args.HasOption('d'))
		RasSrv->SetRoutedMode(false, false);
	else
		RasSrv->SetRoutedMode();

	// let's go
	RasSrv->Run();

	//HouseKeeping();

	// graceful shutdown
	cerr << "\nShutting down gatekeeper";
	ShutdownHandler();
	cerr << "done\n";
}

