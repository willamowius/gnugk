//////////////////////////////////////////////////////////////////
//
// gk.h gatekeeper process
//
// Copyright (c) 2000-2015, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//

//////////////////////////////////////////////////////////////////


#ifndef GK_H
#define GK_H "@(#) $Id$"
#include "config.h"
#include "version.h"
#ifdef COMPILE_AS_SERVICE
#include <ptlib/svcproc.h>
#else
#include <ptlib/pprocess.h>
#endif

#ifdef _WIN32
#include <mswsock.h>
#endif

#ifdef COMPILE_AS_SERVICE
#define GNUGK_NAME	"GNU Gatekeeper"
#else
#define GNUGK_NAME	"Gatekeeper"
#endif

extern PSemaphore ShutdownMutex;
extern bool ShutdownFlag;	// you may only set this flag if you own the ShutdownMutex, once it is set, it can never be cleared!
extern const char * KnownConfigEntries[][2];

// you must change PTLib 2.10.x / 2.11.x configure.ac to set WINVER = 0x0600 to enable
#define WINDOWS_VISTA	0x0600
#if defined(_WIN32) && (_WIN32_WINNT >= WINDOWS_VISTA)
extern LPFN_WSASENDMSG g_pfWSASendMsg;
#endif

class GkTimer;

extern bool IsGatekeeperShutdown();
extern void ExitGK();


#ifdef COMPILE_AS_SERVICE
class Gatekeeper : public PServiceProcess
{
	PCLASSINFO(Gatekeeper, PServiceProcess)
#else
class Gatekeeper : public PProcess
{
	PCLASSINFO(Gatekeeper, PProcess)
#endif
 public:
	Gatekeeper
#ifdef COMPILE_AS_SERVICE
		(const char * _manuf = "GnuGk.org",
#else
		(const char * _manuf = "GNU",
#endif
		 const char * _name = GNUGK_NAME,
		 WORD _majorVersion = GNUGK_MAJOR_VERSION,
		 WORD _minorVersion = GNUGK_MINOR_VERSION,
		 CodeStatus _status = GNUGK_BUILD_TYPE,
		 WORD _buildNumber = GNUGK_BUILD_NUMBER);

	virtual void Main();

#ifdef COMPILE_AS_SERVICE
	virtual PBoolean OnStart();
	virtual void OnStop();
	virtual void Terminate();
	virtual PBoolean OnPause();
	virtual void OnContinue();
	virtual void OnControl();
#endif

	enum RotationIntervals {
		Hourly,
		Daily,
		Weekly,
		Monthly,
		RotationIntervalMax
	};

	static bool SetLogFilename(const PString & filename);


	static bool RotateLogFile();
	static bool ReopenLogFile();
	static void CloseLogFile();

	static void EnableLogFileRotation(bool enable = true);

	/** Rotate the log file, saving old file contents to a different
	    file and starting with a new one. This is a callback function
	    called when the rotation timer expires.
	*/
	static void RotateOnTimer(
		GkTimer * timer /// timer object that triggered rotation
		);

 protected:
	/** returns the template string for which the cmommand line is parsed */
	virtual const PString GetArgumentsParseString() const;

	/**@name Initialization
	 * A sequence of virtual initialization methods is called from #Main#
	 * before the fun starts.
	 * Every method may return #FALSE# to abort #Main# and end the program.
	 */

	//@{

	/** installs the signal handlers; First called init method. */
	virtual bool InitHandlers(const PArgList & args);

	virtual bool InitConfig(const PArgList & args);

	/** initiates logging and tracing; Called after #InitConfig# */
	virtual bool InitLogging(const PArgList & args);

	/** print the available command-line-options **/
	void PrintOpts();

	/** Set a new user and group (ownership) for the GK process.
		The group that will be set is the user's default group.
	*/
	virtual bool SetUserAndGroup(const PString & username);
	//@}

private:
	/// parse rotation interval from the config
	static void GetRotateInterval(
		PConfig & cfg, /// the config
		const PString & section /// name of the config section to check
		);

private:
	/// rotate file after the specified period of time (if >= 0)
	static int m_rotateInterval;
	/// a minute when the interval based rotation should occur
	static int m_rotateMinute;
	/// an hour when the interval based rotation should occur
	static int m_rotateHour;
	/// day of the month (or of the week) for the interval based rotation
	static int m_rotateDay;
	/// timer for rotation events
	static GkTimer* m_rotateTimer;
	/// gatekeeper log file
	static PTextFile* m_logFile;
	/// filename for the logfile
	static PFilePath m_logFilename;
	/// atomic log file operations (rotation, closing)
	static PMutex m_logFileMutex;
	/// human readable names for rotation intervals
	static const char* const m_intervalNames[];

#ifdef COMPILE_AS_SERVICE
	PString savedArguments;
#endif
	bool m_strictConfigCheck;
};
#endif // GK_H

