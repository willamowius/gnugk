// -*- mode: c++; eval: (c-set-style "linux"); -*-
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
#include <signal.h>
#endif
#include <ptlib.h>
#include <q931.h>
#include "gk.h"
#include "RasSrv.h"
#include "SoftPBX.h"
#include "MulticastGRQ.h"
#include "BroadcastListen.h"
#include "Toolkit.h"
#include "h323util.h"
#include "ANSI.h"

/*
 * many things here should be members of Gatkeeper.
 */

namespace { // keep the global objects private

MulticastGRQ * MulticastGRQThread = NULL;
BroadcastListen * BroadcastThread = NULL;
PMutex ShutdownMutex;
PMutex ReloadMutex;

#ifndef WIN32
PString pidfile("/var/run/gnugk.pid");
#endif
#ifdef PTRACING
PTextFile *logfile = 0;
PString logfilename;
#endif

bool ExitFlag = false;

} // end of anonymous namespace

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
	}
	if (MulticastGRQThread != NULL)
	{
		PTRACE(3, "GK\tClosing MulticastGRQThread");
		MulticastGRQThread->Close();
		MulticastGRQThread->WaitForTermination();
		delete MulticastGRQThread;
		MulticastGRQThread = NULL;
	}
	if (RasThread != NULL)
	{
		PTRACE(3, "GK\tClosing RasThread");
		RasThread->Close();
		// send all registered clients a URQ
		RasThread->UnregisterAllEndpoints();
		RasThread->WaitForTermination();
		delete RasThread;
		RasThread = NULL;
	}

	// delete singleton objects
	PTRACE(3, "GK\tDeleting global reference tables");

	delete CallTable::Instance();
	delete RegistrationTable::Instance();
	delete GkStatus::Instance();
#if defined(HAVE_DIGIT_ANALYSIS)
	delete DigitCodeLibrary::Instance();
#endif /* HAVE_DIGIT_ANALYSIS */
	delete Toolkit::Instance();
	PTRACE(3, "GK\tdelete ok");

#ifdef PTRACING
	PTrace::SetStream(&cerr); // redirect to cerr
	delete logfile;
#endif
	return;
}

#ifdef PTRACING
void ReopenLogFile()
{
	if (!logfilename) {
		PTRACE_IF(1, logfile, "GK\tLogging closed.");
		PTrace::SetStream(&cerr); // redirect to cerr
		delete logfile;
		logfile = new PTextFile(logfilename, PFile::WriteOnly);//, PFile::Create);
		if (!logfile->IsOpen()) {
			cerr << "Warning: could not open trace output file \""
				<< logfilename << '"' << endl;
			delete logfile;
			logfile = 0;
			return;
		}
		PTrace::SetStream(logfile); // redirect to logfile
	}
	PTRACE(1, "GK\tTrace logging restarted.");
}
#endif

void ReloadHandler(void)
{
	// only one thread must do this
	if (ReloadMutex.WillBlock())
		return;

	/*
	** Enter critical Section
	*/
	PWaitAndSignal reload(ReloadMutex);

	/*
	** Force reloading config
	*/
	InstanceOf<Toolkit>()->ReloadConfig();
	PTRACE(3, "GK\tConfig reloaded.");
	GkStatus::Instance()->SignalStatus("Config reloaded." GK_LINEBRK);

	SoftPBX::TimeToLive = GkConfig()->GetInteger("TimeToLive", SoftPBX::TimeToLive);

	/*
	** Update all gateway prefixes
	*/

	CallTable::Instance()->LoadConfig();
	RegistrationTable::Instance()->LoadConfig();

	RasThread->LoadConfig();
	RasThread->SetRoutedMode();
	/*
	** Don't disengage current calls!
	*/
	PTRACE(3, "GK\tCarry on current calls.");

	/*
	** Leave critical Section
	*/
	// give other threads the chance to pass by this handler
	PProcess::Sleep(1000);
}

#ifdef WIN32

BOOL WINAPI WinCtrlHandlerProc(DWORD dwCtrlType)
{
	PTRACE(1, "GK\tGatekeeper shutdown");
	PWaitAndSignal shutdown(ShutdownMutex);
	return ExitFlag = true;
}

#else

void UnixShutdownHandler(int sig)
{
	PTRACE(1, "GK\tGatekeeper shutdown (signal " << sig << ")");
	if (ShutdownMutex.WillBlock())
		return;
	PWaitAndSignal shutdown(ShutdownMutex);
	ExitFlag = true;
	PFile::Remove(pidfile);
}

void UnixReloadHandler(int sig) // For HUP Signal
{
	PTRACE(1, "GK\tGatekeeper Hangup (signal " << sig << ")");
#ifdef PTRACING
	ReopenLogFile();
#endif
	ReloadHandler();
}

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
		 "-h245routed."
		 "d-direct."
		 "i-interface:"
		 "l-timetolive:"
		 "b-bandwidth:"
#ifdef PTRACING
		 "t-trace."
		 "o-output:"
#endif
		 "c-config:"
		 "s-section:"
		 "-pid:"
		 "h-help:"
#ifdef PTRACING
#  if defined(HAVE_DIGIT_ANALYSIS)
		 "X-number:"
#  endif /* HAVE_DIGIT_ANALYSIS */
		 "Y-codeddata:"
		 "Z-codingdata:"
#endif
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

	if (args.HasOption("pid"))
		pidfile = args.GetOptionString("pid");
	PTextFile pid(pidfile, PFile::WriteOnly);
	pid.WriteLine(PString(PString::Unsigned, getpid()));
#endif
	return TRUE;
}


BOOL Gatekeeper::InitLogging(const PArgList &args)
{
#ifdef PTRACING
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


#if defined(HAVE_DIGIT_ANALYSIS) && defined(PTRACING)
BOOL Gatekeeper::InitDigitCodeLibrary(const PArgList &args)
{
	InstanceOf<DigitCodeLibrary>(); // force using the right DigitCodeLibrary constructor

	return TRUE;
}
#endif /* HAVE_DIGIT_ANALYSIS && PTRACING */


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
		PTRACE(0, "WARNING: No config file found!" GK_LINEBRK
		       " - Does the config file exist? The default "
		       "(~/.pwlib_config/Gatekeeper.ini or gatekeeper.ini "
		       "in current directory) or the one given with -c?" GK_LINEBRK
		       " - Did you specify they the right 'Main' section with -s?" GK_LINEBRK
		       " - Is the line 'Fourtytwo=42' present in this 'Main' section?");
	}

	return TRUE;
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
#ifdef PTRACING
		"  -t  --trace        : Set trace verbosity\n"
		"  -o  --output file  : Write trace to this file\n"
#endif
		"  -c  --config file  : Specify which config file to use\n"
		"  -s  --section sec  : Specify which main section to use in the config file\n"
		"      --pid file     : Specify the pid file\n"
		"  -h  --help         : Show this message\n" << endl;
}


void Gatekeeper::HouseKeeping(void)
{
	for (unsigned count=1; !ExitFlag; count++) {

		Sleep(1000);

		if (!RasThread->Check()) // return true if the thread running
			break;

		if (!(count % 60)) // one minute
			RegistrationTable::Instance()->CheckEndpoints();

		CallTable::Instance()->CheckCalls();
	}
}

void Gatekeeper::Main()
{
	PArgList & args = GetArguments();
	args.Parse(GetArgumentsParseString());

	PIPSocket::Address GKHome = INADDR_ANY;

	if(! InitLogging(args)) return;
	if(! InitHandlers(args)) return;
	if(! InitToolkit(args)) return;
	if(! InitConfig(args)) return;
#if defined(HAVE_DIGIT_ANALYSIS) && defined(PTRACING)
	if(! InitDigitCodeLibrary(args)) return;
#endif /* HAVE_DIGIT_ANALYSIS && PTRACING*/

	// read gatekeeper home address from commandline
	if (args.HasOption('i'))
		GKHome = args.GetOptionString('i');
	else {
		PString home = GkConfig()->GetString("Home", "");
		if (!home)
			GKHome = home;
	}

	PString welcome("OpenH323 Gatekeeper - The GNU Gatekeeper with ID '" + Toolkit::GKName() + "' started on " + GKHome.AsString() + "\n" + Toolkit::GKVersion());
	cout << welcome << endl;
	PTRACE(1, welcome);

	if (GKHome == INADDR_ANY) {
               PString myip("Default IP = " + Toolkit::Instance()->GetRouteTable()->GetLocalAddress().AsString());
               cout << myip << "\n\n";
	}

	if (args.HasOption('h')) {
		PrintOpts();
		delete DigitCodeLibrary::Instance();
        	delete Toolkit::Instance();
		exit(0);
	}

	// Copyright notice
	cout <<
		"This program is free software; you can redistribute it and/or" GK_LINEBRK
		"modify it under the terms of the GNU General Public License" GK_LINEBRK
		"as published by the Free Software Foundation; either version 2" GK_LINEBRK
		"of the License, or (at your option) any later version." GK_LINEBRK
		;

#if defined(HAVE_DIGIT_ANALYSIS) && defined(PTRACING)
	const char optX = 'X';
	if (args.HasOption(optX)) {
		PString s = args.GetOptionString(optX);
		E164_IPTNString n(s);
		E164_AnalysedNumber m(n);
		cout << endl << "TESTING digit analysis:" << endl ;
		cout << "E164_IPTNString n: " << n << endl;
		cout << "E164_AnalysedNumber m CC: " << m.GetCC() << endl;
		cout << "E164_AnalysedNumber m NDC_IC: " << m.GetNDC_IC() << endl;
		cout << "E164_AnalysedNumber m GSN_SN: " << m.GetGSN_SN() << endl;
		cout << "E164_AnalysedNumber m kind: " << m.GetIPTN_kind() << endl;
		cout << "- as PString: " << (PString)m << endl;
		cout << "- as E164_IPTNString: " << (E164_IPTNString)m << endl;
		cout << endl;

		delete DigitCodeLibrary::Instance();
        	delete Toolkit::Instance();
		exit(0);
	}
#endif /* HAVE_DIGIT_ANALYSIS && PTRACING*/


#if defined(PTRACING)
	PString I("");
	const char optY = 'Y';
	if (args.HasOption(optY)) {
		cout << endl << "TESTING shared secret cryptograpy (deciphering):" << endl ;
		PTPW_Codec::Info(I);
		cout << I << endl;
		PString s = args.GetOptionString(optY);
		PTPW_Codec::codec_kind codec = PTPW_Codec::GetAlgo(s);
		PTPW_Codec decoder(codec, PTPW_Codec::CT_DECODE);
		cout << "Data read: " << ANSI::GRE << s << ANSI::OFF << endl;
		cout << "Data plain: " << ANSI::BRED << *(decoder.cipher(s)) << ANSI::OFF << endl;
		delete DigitCodeLibrary::Instance();
        	delete Toolkit::Instance();
		exit(0);
	}
	const char optZ = 'Z';
	if (args.HasOption(optZ)) {
		cout << endl << "TESTING shared secret cryptograpy (enciphering):" << endl ;
		cout << PTPW_Codec::Info(I) << endl;
		PString s = args.GetOptionString(optZ);
		PTPW_Codec::codec_kind codec = PTPW_Codec::GetAlgo(s);
		PTPW_Codec encoder(codec, PTPW_Codec::CT_ENCODE);
		cout << "Data plain: " << ANSI::GRE << s << ANSI::OFF << endl;
		cout << "Data cipher: " << ANSI::BRED << *(encoder.cipher(s)) << ANSI::OFF << endl;

		delete DigitCodeLibrary::Instance();
        	delete Toolkit::Instance();
		exit(0);
	}
#endif /* PTRACING*/

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

	RasThread = new H323RasSrv(GKHome);
	// read signaling method from commandline
	if (args.HasOption('r'))
		RasThread->SetRoutedMode(true, (args.GetOptionCount('r') > 1 || args.HasOption("h245routed")));
	else if (args.HasOption('d'))
		RasThread->SetRoutedMode(false, false);
	else
		RasThread->SetRoutedMode();

	MulticastGRQThread = new MulticastGRQ(GKHome, RasThread);

#if (defined P_LINUX) || (defined P_FREEBSD) || (defined P_HPUX9) || (defined P_SOLARIS)
	// On some OS we don't get broadcasts on a socket that is
	// bound to a specific interface. For those we have to start
	// a thread that listens just for those broadcasts.
	// On Windows NT we get all messages on the RAS socket, even
	// if it's bound to a specific interface and thus don't have
	// to start this thread.

	// only start the thread if we don't bind to all interfaces
	if (GKHome != INADDR_ANY)
		BroadcastThread = new BroadcastListen(RasThread);
#endif

	// let's go
	RasThread->Resume();

	HouseKeeping();

	// graceful shutdown
	ShutdownHandler();
}
