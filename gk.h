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

#ifndef _PTLIB_H
#include <ptlib.h>
#endif
#ifndef GNUGK_VERSION_H
#include "version.h"
#endif

class Gatekeeper : public PProcess {
	PCLASSINFO(Gatekeeper, PProcess)
 public:
	Gatekeeper
		(const char * manuf = "GNU", 
		 const char * name = "Gatekeeper", 
		 WORD majorVersion = GNUGK_MAJOR_VERSION,
		 WORD minorVersion = GNUGK_MINOR_VERSION,
		 CodeStatus status = GNUGK_BUILD_TYPE,
		 WORD buildNumber = GNUGK_BUILD_NUMBER);

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

	/** factory for the static Config in Toolkit; Called after #InitToolkit# */
	virtual BOOL InitConfig(const PArgList &args);

	/** initiates logging and tracing; Called after #InitConfig# */
	virtual BOOL InitLogging(const PArgList &args);

	/** print the available command-line-options **/
	void PrintOpts(void);

	//@}

};

#endif // GK_H
