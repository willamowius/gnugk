// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// gk.h gatekeeper process
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
//	990710	working again with OpenH323 V. 1.08 (Jan Willamowius)
//
//////////////////////////////////////////////////////////////////


#ifndef GK_H
#define GK_H "@(#) $Id$"

#include <ptlib.h>

class Gatekeeper : public PProcess
{
	PCLASSINFO(Gatekeeper, PProcess)
 public:
	Gatekeeper
		(const char * manuf = MANUFACTURER,
		 const char * name = PROGRAMMNAME, 
		 WORD majorVersion = VERSION_MAJOR,
		 WORD minorVersion = VERSION_MINOR,
		 CodeStatus status = VERSION_STATUS,
		 WORD buildNumber = VERSION_BUILD);

	virtual void Main();

 protected:
	/** returns the template string for which the cmommand line is parsed */
	virtual const PString GetArgumentsParseString() const;

	/**@name Initialization
	 * A sequence of virtual initialization methods is called from #Main#
	 * before the fun starts.
	 * Each one takes the already parsed command line arguments (so you can
	 * depend the behavior on them). Later -- after #InitConfig# -- you can
	 * also use #Toolkit::Config()# to decide different things.
	 * Every method may return #FALSE# to abort #Main# and end the program.
	 */
	//@{

	/** installs the signal handlers; First called init method. */
	virtual BOOL InitHandlers(const PArgList &args);

	/** factory for the static toolkit; Called after #InitHandlers#.  */
	virtual BOOL InitToolkit(const PArgList &args);

#if defined(HAVE_DIGIT_ANALYSIS)
	/** factory for the static DigitCode library; Called after #InitConfig#.  */
	virtual BOOL InitDigitCodeLibrary(const PArgList &args);
#endif /* HAVE_DIGIT_ANALYSIS */

	/** factory for the static Config in Toolkit; Called after #InitToolkit# */
	virtual BOOL InitConfig(const PArgList &args);

	/** initiates logging and tracing; Called after #InitConfig# */
	virtual BOOL InitLogging(const PArgList &args);

	/** print the available command-line-options **/
	void PrintOpts(void);

	/** do some routines **/
	void HouseKeeping(void);

	//@}

};

// Handle a shutdown request, from either source, gracefully
extern void ShutdownHandler(void);

// Handle a reload request, from either source, gracefully
extern void ReloadHandler(void);

#endif /* GK_H */
