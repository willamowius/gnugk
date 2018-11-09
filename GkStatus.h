//////////////////////////////////////////////////////////////////
//
// GkStatus.h	thread listening for connections to receive
//		status updates from the gatekeeper
//
// Copyright (c) 2000-2018, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef GKSTATUS_H
#define GKSTATUS_H "@(#) $Id$"

#include <map>
#include <list>
#include "yasocket.h"
#include "singleton.h"

/** The idea of status interface output trace levels
    allows to select the kind of output received by a status interface client.
	Level 0 - no broadcast messages (except reload notifications and yell)
	Level 1 - only CDRs and Route Requests
	Level 2 - everything
*/
#define MIN_STATUS_TRACE_LEVEL 0
#define MAX_STATUS_TRACE_LEVEL 2
#define STATUS_TRACE_LEVEL_CDR 1
#define STATUS_TRACE_LEVEL_RAS 2
#define STATUS_TRACE_LEVEL_ROUTEREQ 1

class TelnetSocket;
class StatusClient;

/** Singleton class that listens for the status interface connections
    and maintains a list of connected status interface clients.
*/
class GkStatus : public Singleton<GkStatus>, public SocketsReader
{
public:
	GkStatus();
	virtual ~GkStatus();

    virtual void LoadConfig();

	/** Authenticate new telnet connection. Ask for username/password
		if required. If the authentication is successful, the client
		is added to the list of active clients. If it fails, client
		instance is deleted.
	*/
	void AuthenticateClient(
		/// new status interface client to be authenticated
		StatusClient * newClient
		);

	/** Broadcast the message to all active client connected
		to the status interface. The message is sent to each client
		only if client trace level is greater or equal to the trace level
		of the message.
	*/
	void SignalStatus(
		/// message string to be broadcasted
		const PString & msg,
		/// trace level at which the message should be broadcasted
		/// if the current output trace level is less than this value,
		/// the client will not receive this message
		int level = MIN_STATUS_TRACE_LEVEL
		);

	/** Disconnect the specified status interface client.

		@return
		true if the status interface client with the given session ID
		has been found and disconnected.
	*/
	bool DisconnectSession(
		/// session ID (instance number) for the status client to be disconnected
		int instanceNo,
		/// status interface client that requested disconnect
		StatusClient* requestingClient
		);


	/** Notification form the status client that it has been deleted
	*/
	void StatusClientDeleted() { if (m_statusClients > 0) --m_statusClients; }

	/** Print a list of all connected status interface users
		to the requesting client.
	*/
	void ShowUsers(
		/// client that requested the list of all active clients
		StatusClient * requestingClient
		) const;

    /** Print the event backlog to the requesting client.
    */
    void PrintEventBacklog(StatusClient * requestingClient) const;

	/** Print help (list of status interface commands)
		to the requesting client.
	*/
	void PrintHelp(
		/// client that requested the help message
		StatusClient * requestingClient
		) const;

	enum StatusInterfaceCommands {
		e_PrintAllRegistrations,
		e_PrintAllRegistrationsVerbose,/// extra line per reg starting with '#'.
		e_PrintAllCached,
		e_PrintCurrentCalls,
		e_PrintCurrentCallsVerbose,    /// extra line per call starting with '#'.
		e_PrintCurrentCallsPorts,
		e_Find,                        /// find an endpoint
		e_FindVerbose,
		e_DisconnectIp,                /// disconnect a call by endpoint IP number
		e_DisconnectAlias,             /// disconnect a call by endpoint alias
		e_DisconnectCall,              /// disconnect a call by call number
		e_DisconnectCallId,            /// disconnect a call by call ID
		e_DisconnectEndpoint,          /// disconnect a call by endpoint ID
		e_DisconnectSession,           /// disconnect a user from status port
		e_ClearCalls,                  /// disconnect all calls
		e_UnregisterAllEndpoints,      /// force unregistering of all endpoints
		e_UnregisterIp,                /// force unregistering of one endpoint by IP number
		e_UnregisterEP,                /// force unregistering of one endpoint by endpoint ID
		e_UnregisterAlias,             /// force unregistering of one endpoint by alias
		e_TransferCall,                /// transfer call from one endpoint to another
		e_RerouteCall,                 /// transfer call with pause and reroute
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
		e_RouteToAlias,                /// Route a call to a specified alias
		e_RouteToGateway,              /// Route a call to a specified alias + destinationCallSignalAddr
		e_RouteToInternalGateway,      /// Route a call to a specified alias + destinationCallSignalAddr, but don't let caller know about new destination
		e_BindAndRouteToGateway,       /// Route a call to a specified alias + destinationCallSignalAddr + specify bind IP
		e_BindAndRouteToInternalGateway, /// Route a call to a specified alias + destinationCallSignalAddr + specify bind IP, but don't let caller know about new destination
		e_RouteReject,                 /// Reject to Route a call upon ARQ (send ARJ)
		e_Trace,                       /// change trace level for status interface output
		e_RotateLog,                   /// Force log file rotation
		e_SetLogFilename,              /// Change log file location
		e_AddIncludeFilter,            /// Add include filter
		e_RemoveIncludeFilter,         /// Remove include filter
		e_AddExcludeFilter,            /// Add exclude filter
		e_RemoveExcludeFilter,         /// Remove exclude filter
		e_Filter,                      /// Activate Status Port filtering
		e_PrintExcludeFilters,         /// Print list of all exclude filters
		e_PrintIncludeFilters,         /// Print list of all include filters
		e_PrintPrefixCapacities,       /// Print prefix capacity settings with their current counters
		e_PrintCapacityControlRules,   /// Print CapacityControl rules and their current capacities
		e_SendProceeding,              /// Send a CallProceeding message for this call-id
		e_GetAuthInfo,                 /// Get auth module information
		e_GetAcctInfo,                 /// Get acct module information
		e_ResetCallCounters,           /// Reset the call counters
		e_PrintEndpointQoS,            /// Print QoS values for all endpoints
		e_PrintAllConfigSwitches,      /// print all known config switches
		e_PrintEventBacklog,           /// print buffered events
		e_PrintNeighbors,              /// print list of neighbors
		e_PrintCallInfo,               /// print detailed information for a call
		e_MaintenanceMode,             /// switch in or out of maintenance mode
		e_numCommands
		/// Number of different strings
	};

	/** Parse the text message into the status interface command.

		@return
		The command code (see #StatusInterfaceCommands enum#)
		and 'args' filled with command tokens
		or -1 if no corresponding command has been found.
	*/
	int ParseCommand(
		/// message to be parsed
		const PString & msg,
		/// message split into tokens upon successful return
		PStringArray & args
		);

protected:
	// override from class RegularJob
	virtual void OnStart();

	// override from class SocketsReader
	virtual void ReadSocket(IPSocket *);
	virtual void CleanUp();

	/// map for fast (and easy) 'parsing' the commands from the user
	std::map<PString, int> m_commands;

	unsigned m_statusClients;
	unsigned m_maxStatusClients;

	// event backlog
	std::list<PString> m_eventBacklog;
	PMutex m_eventBacklogMutex;
	unsigned m_eventBacklogLimit;
	PRegularExpression m_eventBacklogRegex;
};

/** Listen for incoming connections to the status interface port
	and create StatusClients for each new connection.
*/
class StatusListener : public TCPListenSocket {
#ifndef LARGE_FDSET
	PCLASSINFO ( StatusListener, TCPListenSocket )
#endif
public:
	/// create the new listener socket
	StatusListener(
		/// address the socket is to be bound to
		const Address & addr,
		/// port number the socket is to be bound to
		WORD port
		);

	virtual ~StatusListener();

	/** Create a new StatusClient socket that will be used
		to accept a next incoming connection.
		Override from class TCPListenSocket.
	*/
	virtual ServerSocket *CreateAcceptor() const;

protected:
	Address m_addr;
};

#endif // GKSTATUS_H
