// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// GkStatus.h	thread listening for connections to receive
//				status updates from the gatekeeper
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	990913	initial version (Jan Willamowius)
//	991025	Added command thread (Ashley Unitt)
//
//////////////////////////////////////////////////////////////////


#ifndef GKSTATUS_H
#define GKSTATUS_H "@(#) $Id$"

#if (_MSC_VER >= 1200)  
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#endif

#include <ptlib.h>
#include <ptlib/sockets.h>
#include <set>
#include "singleton.h"

class GkStatus : public PThread, public Singleton<GkStatus>
{
	PCLASSINFO(GkStatus, PThread)
public:
	GkStatus();
	virtual ~GkStatus();

	void Initialize(PIPSocket::Address);

	void Close(void);

	/** controls wether there may be a client to delete or not */
	void SetDirty(BOOL isDirty) { m_IsDirty = isDirty; }
	BOOL IsDirty() const { return m_IsDirty; }

	/** called frequently to erase clients from the list */
	void CleanupClients();

	/** #level# is the 'status trace level'  */
	void SignalStatus(const PString &Message, int level=0);


	enum enumCommands {
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
		e_UnregisterAllEndpoints,      /// force unregisterung of all andpoints
		e_UnregisterAlias,             /// force unregisterung of one andpoint by alias
		e_UnregisterIp,                /// force unregisterung of one andpoint by IP number
		e_TransferCall,                /// transfer call from one endpoint to another
		e_MakeCall,                    /// establish a new call from endpoint A to endpoint B
		e_Yell,                        /// write a message to all status clients
		e_Who,                         /// list who is logged on at a status port
		e_Help,                        /// List all commands
		e_Version,                     /// GkStatus Protocol Info
		e_Debug,                       /// Debugging commands
		e_Statistics,                  /// Show Statistics
		e_Exit,                        /// Close Connection
		e_Reload,                      /// Reload Config File
		e_Shutdown,                    /// Shutdown the program
		/// Number of different strings
	};
	static const int NumberOfCommandStrings;

	/** Returns TRUE if a client from this #Socket# may conntect to the status channel.
	 * This implementation uses the config and for authorization. The config section
	 * [GkStatus::Auth] is used.
	 * The parameter "rule" may be one of the following:
	 * - "forbid" disallow any connection (default when no rule us given)
	 * - "allow" allow any connection
	 * - "explicit" reads the parameter #"<ip>=<value>"# with ip is the ip4-address
	 *    if the peering client. #<value># is resolved with #Toolkit::AsBool#. If the ip
	 *    is not listed the param "default" is used.
	 * - "regex" the #<ip># of the client is matched against the given regular expression.
	 */
	virtual BOOL AuthenticateClient(PIPSocket &Socket) const;


// Visual C++ doesn't grok this:
// protected:
	// Client class handles status commands
	class Client : public PThread
	{
		PCLASSINFO(Client, PThread)
	public:
		Client( GkStatus * _StatusThread, PTCPSocket * _Socket );
		virtual ~Client();

		/* 
		BOOL Write( const char * Message, size_t MsgLen ); 
		*/
		BOOL WriteString(const PString &Message, int level=0);
		int Close(void);
		
		PString WhoAmI() const {
			return Socket->GetName();
		}

	public:
		int          TraceLevel;
		int          InstanceNo;
		BOOL       PleaseDelete;
		static int   StaticInstanceNo;

		/** mutex to protect writing to the socket */
		PMutex       Mutex;

	protected:
		virtual void Main();
		PString ReadCommand();

		PTCPSocket * Socket;
		GkStatus   * StatusThread;
		
		/// map for fast (and easy) 'parsing' the commands from the user
		static PStringToOrdinal Commands;

		/// prints out the GkStatus commands to the client
		void PrintHelp();

		/// handles the 'Debug' command. #Args# is the whole tokenised command line.
		void DoDebug(const PStringArray &Args);

	};

	friend class Client;

	virtual void Main();
	void RemoveClient( GkStatus::Client * Client );

	PIPSocket::Address GKHome;
	PTCPSocket StatusListener;
	std::set<Client*> Clients;
	std::set<Client*>::const_iterator ClientIter;
	PMutex       ClientSetLock;
	BOOL         m_IsDirty;
};

#endif // GKSTATUS_H




