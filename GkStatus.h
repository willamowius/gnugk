//////////////////////////////////////////////////////////////////
//
// GkStatus.h	thread listening for connections to receive
//		status updates from the gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	990913	initial version (Jan Willamowius)
//	991025	Added command thread (Ashley Unitt)
//	030511  redesign based on new architecture (cwhuang)
//
//////////////////////////////////////////////////////////////////

#ifndef GKSTATUS_H
#define GKSTATUS_H "@(#) $Id$"

#include "yasocket.h"
#include "singleton.h"

#ifdef P_SOLARIS
#define map stl_map
#endif

#include <map>

class TelnetSocket;
class StatusClient;

class GkStatus : public Singleton<GkStatus>, public SocketsReader {
public:
	GkStatus();

	// authenticate and add a client
	void AuthenticateClient(StatusClient *);

	// #level# is the 'status trace level'
	void SignalStatus(const PString & Message, int level = 0);

	// disconnect a given session
	bool DisconnectSession(int session, StatusClient *);

	void ShowUsers(StatusClient *) const;

	void PrintHelp(StatusClient *) const;

	enum {
		e_PrintAllRegistrations,
		e_PrintAllRegistrationsVerbose,/// extra line per reg starting with '#'. yeah #.
		e_PrintAllCached,
		e_PrintCurrentCalls,
		e_PrintCurrentCallsVerbose,    /// extra line per call starting with '#'. yeah #.
		e_Find,                        /// find an endpoint
		e_FindVerbose,
		e_DisconnectIp,                /// disconnect a call by endpoint IP number
		e_DisconnectAlias,             /// disconnect a call by endpoint alias
		e_DisconnectCall,              /// disconnect a call by call number
		e_DisconnectEndpoint,          /// disconnect a call by endpoint ID
		e_DisconnectSession,           /// disconnect a user from status port
		e_ClearCalls,                  /// disconnect all calls
		e_UnregisterAllEndpoints,      /// force unregisterung of all andpoints
		e_UnregisterIp,                /// force unregisterung of one andpoint by IP number
		e_UnregisterAlias,             /// force unregisterung of one andpoint by alias
		e_TransferCall,                /// transfer call from one endpoint to another
		e_MakeCall,                    /// establish a new call from endpoint A to endpoint B
		e_Yell,                        /// write a message to all status clients
		e_Who,                         /// list who is logged on at a status port
		e_GK,                          /// show my parent gatekeeper
		e_Help,                        /// List all commands
		e_Version,                     /// GkStatus Protocol Info
		e_Debug,                       /// Debugging commands
		e_Statistics,                  /// Show Statistics
		e_Exit,                        /// Close Connection
		e_Reload,                      /// Reload Config File
		e_Shutdown,                    /// Shutdown the program
		e_RouteToAlias,                /// Route a call upon ARQ to a specified alias eg. a free CTI agent
		e_RouteReject                  /// Reject to Route a call upon ARQ (send ARJ)
		/// Number of different strings
	};

	int ParseCommand(const PString &, PStringArray &);

private:
	// override from class RegularJob
	virtual void OnStart();
	virtual void OnStop();

	// override from class SocketsReader
	virtual void ReadSocket(IPSocket *);
	virtual void CleanUp();

	// map for fast (and easy) 'parsing' the commands from the user
	std::map<PString, int> m_commands;
};

class StatusListener : public TCPListenSocket {
#ifndef LARGE_FDSET
	PCLASSINFO ( StatusListener, TCPListenSocket )
#endif
public:
	StatusListener(const Address &, WORD);

	// override from class TCPListenSocket
	virtual ServerSocket *CreateAcceptor() const;
};

#endif // GKSTATUS_H
