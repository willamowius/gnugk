//////////////////////////////////////////////////////////////////
//
// GkStatus.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////

#if defined(_WIN32) && (_MSC_VER <= 1200)
#pragma warning(disable:4786) // warning about too long debug symbol off
#pragma warning(disable:4284)
#endif

#include <ptlib.h>
#include <ptlib/sockets.h>
#include <ptclib/telnet.h>
#include <h225.h>
#include <vector>
#include "gk_const.h"
#include "stl_supp.h"
#include "SoftPBX.h"
#include "Toolkit.h"
#include "RasSrv.h"
#include "Routing.h"
#include "rwlock.h"
#include "gk.h"
#include "GkStatus.h"

void ReloadHandler(); // avoid to include...

static const char *authsec="GkStatus::Auth";
static const char *filteringsec="GkStatus::Filtering";

// a very lightweight implementation of telnet socket
class TelnetSocket : public ServerSocket {
#ifndef LARGE_FDSET
	PCLASSINFO(TelnetSocket, TCPSocket)
#endif
public:
	typedef PTelnetSocket::Options Options;
	typedef PTelnetSocket::Command Command;

	TelnetSocket();

	// override from class TCPSocket
#ifdef LARGE_FDSET
	virtual bool Accept(YaTCPSocket &);
#else
	virtual BOOL Accept(PSocket &);
#endif

	virtual int ReadChar();

	bool SendDo(BYTE);
	bool SendDont(BYTE);
	bool SendWill(BYTE);
	bool SendWont(BYTE);
	bool SendCommand(Command, BYTE);

	bool NeedEcho() const { return m_needEcho; }

private:
	enum State {
		StateNormal,
		StateCarriageReturn,
		StateIAC,
		StateDo,
		StateDont,
		StateWill,
		StateWont,
		StateSubNegotiations,
		StateEndNegotiations
	};

	// new virtual function
	virtual void OnDo(BYTE);
	virtual void OnDont(BYTE);
	virtual void OnWill(BYTE);
	virtual void OnWont(BYTE);

	bool m_needEcho;
	State m_state;
};

/** Class that manages a single status interface client connection.
 */
class StatusClient : public TelnetSocket, public USocket {
#ifndef LARGE_FDSET
	PCLASSINFO(StatusClient, TelnetSocket)
#endif
public:
	StatusClient(
		/// unique session ID (instance number) for this client
		int instanceNo
		);

	bool ReadCommand(
		/// command that has been read (if ReadCommand succeeded)
		PString& cmd,
		/// should the command be echoed (also NeedEcho() has to be true)
		bool echo = true,
		/// timeout (ms) for read operation
		int readTimeout = 0
		);
		
	/** Send the message (string) to the status interface client,
		if the output trace level is lesser or equal to the one set
		for this client.
		
		@return
		true if the message has been sent (or ignored because of trace level).
	*/
	bool WriteString(
		/// string to be sent through the socket
		const PString& msg, 
		/// output trace level assigned to the message
		int level = MIN_STATUS_TRACE_LEVEL
		);
		
	void FlushData();

	/** @return
		A string with connection information about this client.
	*/
	PString WhoAmI() const;
	
	/** Check the client with all configured status authentication rules.
		Ask for username/password, if required.
		
		@return
		true if the client has been granted access, false to reject the client.
	*/
	bool Authenticate();
	
	/** Executes the given command as a new Job (in a separate Worker thread).
	*/
	void OnCommand(
		/// command to be executed
		const PString& cmd
		);

	/** @return
		Unique instance number (session identifier) for this client.
	*/
	int GetInstanceNo() const { return m_instanceNo; }
	
	/** @return
		Output trace level for this status client. The trace level
		decides what kind of information is allowed to be broadcasted
		to this client.
	*/
	int GetTraceLevel() const { return m_traceLevel; }

	/// Set the new output trace level for this status interface client
	void SetTraceLevel(
		/// new output trace level to be set
		int newLevel
		)
	{
		m_traceLevel = newLevel;
	}
		
	/** @return
		true if one or more commands from this status interface client
		are executing by Worker threads.
	*/
	bool IsBusy()
	{ 
		PWaitAndSignal lock(m_cmutex);
		return m_numExecutingCommands > 0; 
	}

	const PString& GetUser() const { return m_user; }
	
private:
	// override from class ServerSocket
	virtual void Dispatch();

	/// Handle the 'Debug' command (its many variants).
	void DoDebug(
		/// tokenized debug command
		const PStringArray& args
		);

	/** Check a new client connection against the specified authentication
		rule.
		
		@return
		true if the client satisfied the rule (has been authenticated successfully
		with this rule).
	*/
	bool CheckAuthRule(
		/// authentication rule to be used
		const PString& rule
		);

	/** Authenticate this status interface client through all authentication
		rules and return the final result.
		
		@return
		true if the use has been authenticated.
	*/
	bool AuthenticateUser();

	/** @return
		The decrypted password associated with the specified login.
	*/	
	PString GetPassword(
		/// login the password is to be retrieved for
		const PString& login
		) const;

	/** Parse and execute the given command. The function is called
		in a separate Worker thread (as a Job).
	*/
	void ExecCommand(
		/// the command to be executed
		PString cmd
		);

    // Adds regular expression filter
    void AddFilter(
	// filter vector
	std::vector<PString>& regexFilters,
	// Regex to be matched against messages
	PString& regex
	);

    /** Remove regular expression filter located
	at the given index from the specified vector
    */
    void RemoveFilter(
	// filter vector
	std::vector<PString>& regexFilters,
	// Index of filter to be removed
	const PINDEX index
	);

    // Checks whether the given string is to be exclude
    bool IsExcludeMessage(
	// String to be check against the exclude regular expressions
	const PString &msg
	) const;

    // Print a list of all filters in the specified vector
    void PrintFilters(
	// filter vector
	std::vector<PString>& regexFilters
	);

    // Checks whether the given string is to be include
    bool IsIncludeMessage(
	// String to be check against the include regular expressions
	const PString &msg
	) const;
    
    // Match the given string against filters held by the specified vector
    bool MatchFilter(
	// filter vector
	const std::vector<PString>& regexFilters,
	// String to be matched
	const PString &msg
	) const;

	/// the most recent command
	PString m_lastCmd;
	/// command being currently entered (and not yet completed)
	PString m_currentCmd;
	/// GkStatus instance that created this client
	GkStatus* m_gkStatus;
	/// status interface user that is logged in
	PString	m_user;
	/// for atomic access to the m_numExecutingCommands counter
	PMutex m_cmutex;
	/// number of commands being currently executed by Worker threads
	int m_numExecutingCommands;
	/// unique identifier for this client
	int m_instanceNo;
	/// output trace level for this client
	int m_traceLevel;

    	// vectors of regular expressions to be matched against Status messages
    	std::vector<PString> m_excludeFilterRegex;
        std::vector<PString> m_includeFilterRegex;		
	
        // This flag indicates whether filtering is active or not
        bool m_isFilteringActive;
};


TelnetSocket::TelnetSocket() : m_needEcho(false), m_state(StateNormal)
{
}

#ifdef LARGE_FDSET
bool TelnetSocket::Accept(YaTCPSocket & socket)
#else
BOOL TelnetSocket::Accept(PSocket & socket)
#endif
{
	if (!TCPSocket::Accept(socket))
		return false;

	SendDo(PTelnetSocket::SuppressGoAhead);
	SendWill(PTelnetSocket::StatusOption);
	SendDont(PTelnetSocket::EchoOption);
#ifndef LARGE_FDSET
	Address raddr, laddr;
	WORD rport = 0, lport = 0;
	GetPeerAddress(raddr, rport);
	GetLocalAddress(laddr, lport);
	SetName(AsString(raddr, rport) + "=>" + AsString(laddr, lport));
	SetReadTimeout(0);
#else
	// name already be set
#endif
	return true;
}

int TelnetSocket::ReadChar()
{
	bool hasData = false;
	BYTE currentByte = 0;

	while (!hasData) {
		if (!TCPSocket::Read(&currentByte, 1)) {
			if (GetErrorCode(PSocket::LastReadError) != PSocket::Timeout) {
				PTRACE(3, "TELNET\t" << GetName() << " closed the connection ("
					<< GetErrorCode(PSocket::LastReadError) << '/' 
					<< GetErrorNumber(PSocket::LastReadError) << ": "
					<< GetErrorText(PSocket::LastReadError) << ')'
					);
				Close();
			}
			break;
		}
		switch (m_state)
		{
		case StateCarriageReturn:
			m_state = StateNormal;
			if (currentByte == '\0' || currentByte == '\n')
				break; // Ignore \0 \n after CR
			// else fall through for normal processing
		case StateNormal:
			if (currentByte == PTelnetSocket::IAC)
				m_state = StateIAC;
			else {
				if (currentByte == '\r')
					m_state = StateCarriageReturn;
				hasData = true;
			}
			break;
		case StateIAC:
			switch (currentByte)
			{
			case PTelnetSocket::IAC:
				hasData = true;
				m_state = StateNormal;
				break;
			case PTelnetSocket::DO:
				m_state = StateDo;
				break;
			case PTelnetSocket::DONT:
				m_state = StateDont;
				break;
			case PTelnetSocket::WILL:
				m_state = StateWill;
				break;
			case PTelnetSocket::WONT:
				m_state = StateWont;
				break;
			default:
				m_state = StateNormal;
				break;
			}
			break;
		case StateDo:
			OnDo(currentByte);
			m_state = StateNormal;
			break;
		case StateDont:
			OnDont(currentByte);
			m_state = StateNormal;
			break;
		case StateWill:
			OnWill(currentByte);
			m_state = StateNormal;
			break;
		case StateWont:
			OnWont(currentByte);
			m_state = StateNormal;
			break;
		default:
			PTRACE(1, "TELNET\t" << GetName() << " telnet socket entered unrecognized state " << m_state);
			m_state = StateNormal;
			break;
		}
	}

	return hasData ? currentByte : -1;
}

bool TelnetSocket::SendDo(BYTE code)
{
	return SendCommand(PTelnetSocket::DO, code);
}

bool TelnetSocket::SendDont(BYTE code)
{
	return SendCommand(PTelnetSocket::DONT, code);
}

bool TelnetSocket::SendWill(BYTE code)
{
	return SendCommand(PTelnetSocket::WILL, code);
}

bool TelnetSocket::SendWont(BYTE code)
{
	return SendCommand(PTelnetSocket::WONT, code);
}

bool TelnetSocket::SendCommand(Command cmd, BYTE opt)
{
	int length = 2;
	BYTE buffer[3];
	buffer[0] = PTelnetSocket::IAC;
	buffer[1] = (BYTE)cmd;

	switch (cmd)
	{
	case PTelnetSocket::DO:
	case PTelnetSocket::DONT:
	case PTelnetSocket::WILL:
	case PTelnetSocket::WONT:
		buffer[2] = opt;
		length = 3;
		break;

	default:
		// do not support now
		break;
	}
	return Write(buffer, length);
}

void TelnetSocket::OnDo(BYTE code)
{
	PTRACE(6, "TELNET\t" << GetName() << " got DO " << int(code));
}

void TelnetSocket::OnDont(BYTE code)
{
	PTRACE(6, "TELNET\t" << GetName() << " got DONT " << int(code));
}

void TelnetSocket::OnWill(BYTE code)
{
	PTRACE(6, "TELNET\t" << GetName() << " got WILL " << int(code));
}

void TelnetSocket::OnWont(BYTE code)
{
	PTRACE(6, "TELNET\t" << GetName() << " got WONT " << int(code));
	if (code == PTelnetSocket::EchoOption) // Windows client?
		m_needEcho = true;
}

namespace {

PString PrintGkVersion()
{
	return PString("Version:\r\n") + Toolkit::GKVersion() +
		"GkStatus: Version(2.0) Ext()\r\n"
		"Toolkit: Version(1.0) Ext(" + Toolkit::Instance()->GetName() + ")\r\n" 
		+ SoftPBX::Uptime() + "\r\n;\r\n";
}

}

// class GkStatus
GkStatus::GkStatus() : Singleton<GkStatus>("GkStatus"), SocketsReader(500)
{
#ifdef LARGE_FDSET
	PTRACE(1, "STATUS\tLarge fd_set(" << LARGE_FDSET << ") enabled");
#endif

	SetName("GkStatus");
	Execute();
}

void GkStatus::AuthenticateClient(
	StatusClient* newClient
	)
{
	if (newClient->Authenticate()) {
		newClient->SetTraceLevel(GkConfig()->GetInteger("StatusTraceLevel", MAX_STATUS_TRACE_LEVEL));
		PTRACE(1, "STATUS\tNew client authenticated succesfully: " << newClient->WhoAmI()
			<< ", login: " << newClient->GetUser()
			);
		// the welcome messages
		newClient->WriteString(PrintGkVersion());
		newClient->Flush();
		AddSocket(newClient);
	} else {
		PTRACE(3, "STATUS\tNew client rejected: " << newClient->WhoAmI()
			<< ", login: " << newClient->GetUser()
			);
		newClient->WriteString("\r\nAccess forbidden!\r\n");
		newClient->Flush();
		delete newClient;
		newClient = NULL;
	}
}

/** Functor class used to send the message to the specified client.
*/
class ClientSignalStatus 
{
public:
	ClientSignalStatus(
		/// message to be sent
		const PString& msg, 
		/// output trace level assigned to the message
		int level
		) : m_message(msg), m_traceLevel(level) {}
	
	/** Actual function call operator that sends the message.
	*/
	void operator()(
		/// socket to send the message through
		IPSocket* clientSocket
		) const
	{
		StatusClient* client = static_cast<StatusClient*>(clientSocket);
		if (m_traceLevel <= client->GetTraceLevel()) 
			client->WriteString(m_message);
	}

private:
	/// message to be sent
	const PString& m_message;
	/// output trace level assigned to the message
	int m_traceLevel;
};

void GkStatus::SignalStatus(
	/// message string to be broadcasted
	const PString& msg, 
	/// trace level at which the message should be broadcasted
	int level
	)
{
	ReadLock lock(m_listmutex);
	ForEachInContainer(m_sockets, ClientSignalStatus(msg, level));
}

bool GkStatus::DisconnectSession(
	/// session ID (instance number) for the status client to be disconnected
	int instanceNo,
	/// status interface client that requested disconnect
	StatusClient* requestingClient
	)
{
	ReadLock lock(m_listmutex);
	for (iterator i = m_sockets.begin(); i != m_sockets.end(); ++i) {
		StatusClient *client = static_cast<StatusClient *>(*i);
		if (client->GetInstanceNo() == instanceNo) {
			client->WriteString("Disconnected by session " + requestingClient->WhoAmI());
			PTRACE(1, "STATUS\tClient " << client->WhoAmI() << " (ID: " 
				<< instanceNo << ") disconnected by " << requestingClient->WhoAmI()
				);
			return client->Close();
		}
	}
	return false;
}

/** Functor class used to gather a list of active status interface clients.
*/
class WriteWhoAmI 
{
public:
	WriteWhoAmI(
		/// status interface client to send the information to
		StatusClient* requestingClient
		) : m_requestingClient(requestingClient) {}
	
	void operator()(
		/// status interface client to send the information to
		const IPSocket* clientSocket
		) const
	{
		const StatusClient* client = static_cast<const StatusClient *>(clientSocket);
		m_requestingClient->WriteString("  " + client->WhoAmI() + "\r\n");
	}

private:
	/// status interface client to send the information to
	StatusClient* m_requestingClient;
};


void GkStatus::ShowUsers(
	/// client that requested the list of all active clients
	StatusClient* requestingClient
	) const
{
	ReadLock lock(m_listmutex);
	ForEachInContainer(m_sockets, WriteWhoAmI(requestingClient));
}

void GkStatus::PrintHelp(
	/// client that requested the help message
	StatusClient* requestingClient
	) const
{
	requestingClient->WriteString("Commands:\r\n");
	std::map<PString, int>::const_iterator i = m_commands.begin();
	while (i != m_commands.end())
		requestingClient->WriteString(i->first + "\r\n"), ++i;
	requestingClient->WriteString(";\r\n");
}

int GkStatus::ParseCommand(
	/// message to be parsed
	const PString& msg,
	/// message split into tokens upon successful return
	PStringArray& args
	)
{
	// the 'Tokenise' doesn't seem to work correctly for leading spaces
	args = msg.Trim().Tokenise(" \t", FALSE);
	if (args.GetSize() == 0)
		return -1;
		
	// try explicit match
	const PString command = args[0].ToLower();
	if (m_commands.find(command) != m_commands.end())
		return m_commands[command];
	
	// try to find the closest match (expand command prefix)
	std::map<PString, int>::iterator iter = m_commands.begin();
	std::map<PString, int>::iterator expandedCmd = m_commands.end();
	
	while (iter != m_commands.end()) {
		if (command == iter->first.Left(command.GetLength())) {
			// if the key matches more than one command, do not expand
			if( expandedCmd != m_commands.end() )
				return -1;
			else
				expandedCmd = iter;
		}
		iter++;
	}
	if( expandedCmd != m_commands.end() ) {
		PTRACE(6, "STATUS\tExpanded prefix '" << command << "' into command '" 
			<< expandedCmd->first << "'"
			);
		return expandedCmd->second;
	}
	return -1;
}

void GkStatus::OnStart()
{
	m_commands["printallregistrations"] = e_PrintAllRegistrations;
	m_commands["r"] = e_PrintAllRegistrations;
	m_commands["?"] = e_PrintAllRegistrations;
	m_commands["printallregistrationsverbose"] = e_PrintAllRegistrationsVerbose;
	m_commands["rv"] = e_PrintAllRegistrationsVerbose;
	m_commands["??"] = e_PrintAllRegistrationsVerbose;
	m_commands["printallcached"] = e_PrintAllCached;
	m_commands["rc"] = e_PrintAllCached;
	m_commands["printcurrentcalls"] = e_PrintCurrentCalls;
	m_commands["c"] = e_PrintCurrentCalls;
	m_commands["!"] = e_PrintCurrentCalls;
	m_commands["printcurrentcallsverbose"] = e_PrintCurrentCallsVerbose;
	m_commands["cv"] = e_PrintCurrentCallsVerbose;
	m_commands["!!"] = e_PrintCurrentCallsVerbose;
	m_commands["find"] = e_Find;
	m_commands["f"] = e_Find;
	m_commands["findverbose"] = e_FindVerbose;
	m_commands["fv"] = e_FindVerbose;
	m_commands["disconnectip"] = e_DisconnectIp;
	m_commands["disconnectcall"] = e_DisconnectCall;
	m_commands["disconnectalias"] = e_DisconnectAlias;
	m_commands["disconnectendpoint"] = e_DisconnectEndpoint;
	m_commands["disconnectsession"] = e_DisconnectSession;
	m_commands["clearcalls"] = e_ClearCalls;
	m_commands["unregisterallendpoints"] = e_UnregisterAllEndpoints;
	m_commands["unregisterip"] = e_UnregisterIp;
	m_commands["unregisteralias"] = e_UnregisterAlias;
	m_commands["transfercall"] = e_TransferCall;
	m_commands["makecall"] = e_MakeCall;
	m_commands["yell"] = e_Yell;
	m_commands["who"] = e_Who;
	m_commands["gk"] = e_GK;
	m_commands["help"] = e_Help;
	m_commands["h"] = e_Help;
	m_commands["version"] = e_Version;
	m_commands["v"] = e_Version;
	m_commands["debug"] = e_Debug;
	m_commands["statistics"] = e_Statistics;
	m_commands["s"] = e_Statistics;
	m_commands["reload"] = e_Reload;
	m_commands["routetoalias"] = e_RouteToAlias;
	m_commands["rta"] = e_RouteToAlias;
	m_commands["routetogateway"] = e_RouteToGateway;
	m_commands["rtg"] = e_RouteToGateway;
	m_commands["routereject"] = e_RouteReject;
	m_commands["shutdown"] = e_Shutdown;
	m_commands["exit"] = e_Exit;
	m_commands["quit"] = e_Exit;
	m_commands["q"] = e_Exit;
	m_commands["trace"] = e_Trace;
#if PTRACING
	m_commands["rotatelog"] = e_RotateLog;
	m_commands["setlog"] = e_SetLogFilename;
#endif
	m_commands["addincludefilter"] = e_AddIncludeFilter;
	m_commands["removeincludefilter"] = e_RemoveIncludeFilter;
	m_commands["addexcludefilter"] = e_AddExcludeFilter;
	m_commands["removeexcludefilter"] = e_RemoveExcludeFilter;
	m_commands["filter"] = e_Filter;
	m_commands["printexcludefilters"] = e_PrintExcludeFilters;
	m_commands["printincludefilters"] = e_PrintIncludeFilters;
}

void GkStatus::ReadSocket(
	IPSocket* clientSocket
	)
{
	PString cmd;
	StatusClient* client = static_cast<StatusClient*>(clientSocket);
	if (client->ReadCommand(cmd) && !cmd)
		client->OnCommand(cmd);
}

void GkStatus::CleanUp()
{
	if (m_rmsize > 0) {
		PWaitAndSignal lock(m_rmutex);
		iterator iter = m_removed.begin();
		while (iter != m_removed.end()) {
			iterator i = iter++;
			StatusClient *client = static_cast<StatusClient *>(*i);
			if (!client->IsBusy()) {
				m_removed.erase(i);
				--m_rmsize;
				delete client;
				client = NULL;
				iter = m_removed.begin();	// reset iterator after changing list
			}
		}
	}
	RemoveClosed(false);
}


StatusClient::StatusClient(
	/// unique session ID (instance number) for this client
	int instanceNo
	) 
	: 
	USocket(this, "Status"), 
	m_gkStatus(GkStatus::Instance()),
	m_numExecutingCommands(0),
	m_instanceNo(instanceNo),
	m_traceLevel(MAX_STATUS_TRACE_LEVEL),
	m_isFilteringActive(false)
{
        PStringToString filters = GkConfig()->GetAllKeyValues(filteringsec);
        SetWriteTimeout(10);
	
	PString key;
	PString data;
	for (PINDEX i = 0; i < filters.GetSize(); i++) {
	    key = filters.GetKeyAt(i);
	    data = filters.GetDataAt(i);
	    PStringArray regexArray(data.Tokenise("\n", false));
	    for (PINDEX k = 0; k < regexArray.GetSize(); ++k) {
		if(filters.GetKeyAt(i) == "IncludeFilter")
		    AddFilter(m_includeFilterRegex, regexArray[k]);
		else if(filters.GetKeyAt(i) == "ExcludeFilter")
		    AddFilter(m_excludeFilterRegex, regexArray[k]);
	    }
	}
}

bool StatusClient::ReadCommand(
	/// command that has been read (if ReadCommand succeeded)
	PString& cmd,
	/// should the command be echoed (also NeedEcho() has to be true)
	bool echo,
	/// timeout (ms) for read operation, 0 means infinite
	int readTimeout
	)
{
	while (IsReadable(readTimeout)) {
		char byte;
		int read = ReadChar();
		switch (read)
		{
			case -1:
				break; // read IAC or socket closed
			case '\r':
			case '\n':
				cmd = m_currentCmd;
				m_lastCmd = cmd;
				m_currentCmd = PString();
				if (echo && NeedEcho())
					TransmitData("\r\n");
				return true;
			case '\b':
				if (m_currentCmd.GetLength()) {
					m_currentCmd = m_currentCmd.Left(m_currentCmd.GetLength() - 1);
					byte = char(read);
					if (echo && NeedEcho()) {
						Write(&byte, 1);
						Write(&" ", 1);
						Write(&byte, 1);
					}
				}
				break;
			default:
				byte = char(read);
				m_currentCmd += byte;
				cmd = m_currentCmd.Right(3);
				if (cmd == "\x1b\x5b\x41") { // Up Arrow
					if (echo && NeedEcho()) {
						for(PINDEX i = 0; i < m_currentCmd.GetLength() - 3; i ++)
							Write("\b", 1);
						WriteString(m_lastCmd);
					}
					m_currentCmd = m_lastCmd;
				} else if (cmd.Find('\x1b') == P_MAX_INDEX)
					if (echo && NeedEcho())
						Write(&byte, 1);
				break;
		}
	}
	return false;
}

bool StatusClient::WriteString(
	/// string to be sent through the socket
	const PString& msg, 
	/// output trace level assigned to the message
	int level
	)
{
	if (level > m_traceLevel)
		return true;
	if (CanFlush())
	    Flush();

	if (m_isFilteringActive && (IsExcludeMessage(msg) || !IsIncludeMessage(msg)))
	    return false;
	
	if (!WriteData(msg, msg.GetSize()))
	    while (CanFlush())
		Flush();

	return IsOpen();
}

/*
void StatusClient::FlushData()
{
	// flush data in another thread
	int i;
	MarkSocketBlocked lock(this);
	SetWriteTimeout(GkConfig()->GetInteger("StatusWriteTimeout", 5000));
	for (i = 0; i < 3; ++i) // try three times
		if (CanFlush() && Flush())
			break;
	if (i == 3) {
		PTRACE(1, "Status\tClose dead client " << m_instanceNo << ' ' << GetName());
		Close();
	}
	SetWriteTimeout(10);
}
*/

PString StatusClient::WhoAmI() const
{
	return PString(m_instanceNo) + '\t' + GetName() + '\t' + m_user;
}

bool StatusClient::Authenticate()
{
	PINDEX rule_start = 0;
	bool result, logical_or;
	const PString rules = GkConfig()->GetString(authsec, "rule", "forbid");
	while (true) {
		const PINDEX rule_end = rules.FindOneOf("&|", rule_start);
		if (rule_end == P_MAX_INDEX) {
			result = CheckAuthRule(rules(rule_start, P_MAX_INDEX).Trim());
			break;
		} else
			result = CheckAuthRule(rules(rule_start, rule_end - 1).Trim());
		logical_or = (rules[rule_end] == '|') ;
		if ((logical_or && result) || !(logical_or || result))
			break;
		rule_start = rule_end + 1;
	}

	PTRACE(4, "STATUS\tNew connection from " << GetName() 
		<< (result?" accepted":" rejected")
		);
	return result;
}

void StatusClient::OnCommand(
	/// command to be executed
	const PString& cmd
	)
{
	{
		PWaitAndSignal lock(m_cmutex);
		++m_numExecutingCommands;
	}
	// problem - if the ExecCommand does not get executed for some reason,
	// m_numExecutingCommands will not decrement
	CreateJob(this, &StatusClient::ExecCommand, cmd, "StatusCmd " + cmd);
}

void StatusClient::Dispatch()
{
	ReadLock lockConfig(ConfigReloadMutex);
	m_gkStatus->AuthenticateClient(this);
}

void StatusClient::DoDebug(
	/// tokenized debug command
	const PStringArray& args
	)
{
        bool tmp = m_isFilteringActive;
	m_isFilteringActive = false;

	if (args.GetSize() <= 1) {
		WriteString("Debug options:\r\n"
			"  trc [+|-|n]       Show/modify trace level for the log\r\n"
			"  cfg               Read and print config sections\r\n"
			"  cfg SEC PAR       Read and print a config PARameter in a SECtion\r\n"
			"  set SEC PAR VAL   Write a config VALue PARameter in a SECtion\r\n"
			"  remove SEC PAR    Remove a config VALue PARameter in a SECtion\r\n"
			"  remove SEC        Remove a SECtion\r\n"
			"  printrm VERBOSE   Print all removed endpoint records\r\n"
			);
	} else {
		if (args[1] *= "trc") {
			if(args.GetSize() >= 3) {
				if((args[2] == "-") && (PTrace::GetLevel() > 0)) 
					PTrace::SetLevel(PTrace::GetLevel()-1);
				else if(args[2] == "+") 
					PTrace::SetLevel(PTrace::GetLevel()+1);
				else PTrace::SetLevel(args[2].AsInteger());
			}
			WriteString(PString(PString::Printf, "Trace Level is now %d\r\n", PTrace::GetLevel()));
		} else if (args[1] *= "cfg") {
			if (args.GetSize()>=4)
				WriteString(GkConfig()->GetString(args[2],args[3],"") + "\r\n;\r\n");
			else if (args.GetSize()>=3) {
				const PStringList cfgs(GkConfig()->GetKeys(args[2]));
				PString result = "Section [" + args[2] + "]\r\n";
				for (PINDEX i=0; i < cfgs.GetSize(); ++i)
					result += cfgs[i] + "=" 
						+ GkConfig()->GetString(args[2], cfgs[i], "") + "\r\n";
				WriteString(result + ";\r\n");
			} else {
				const PStringList secs(GkConfig()->GetSections());
				PString result = "Config sections\r\n";
				for (PINDEX i = 0; i < secs.GetSize(); i++)
					result += "[" + secs[i] + "]\r\n";
				WriteString(result);
			}
		} else if ((args[1] *= "set") && (args.GetSize()>=5)) {
			Toolkit::Instance()->SetConfig(1, args[2], args[3], args[4]);
			WriteString(GkConfig()->GetString(args[2],args[3],"") + "\r\n");
		} else if (args[1] *= "remove") {
			if (args.GetSize()>=4) {
				Toolkit::Instance()->SetConfig(2, args[2], args[3]);
				WriteString("Remove " + args[3] + " in section " + args[2] + "\r\n");
			} else if (args.GetSize()>=3) {
				Toolkit::Instance()->SetConfig(3, args[2]);
				WriteString("Remove section " + args[2] + "\r\n");
			}
		} else if ((args[1] *= "printrm")) {
			SoftPBX::PrintRemoved(this, (args.GetSize() >= 3));
		} else {
			WriteString("Unknown debug command!\r\n");
		}
	}
	m_isFilteringActive = tmp;
}

bool StatusClient::CheckAuthRule(
	/// authentication rule to be used
	const PString& rule
	)
{
	PIPSocket::Address peerAddress;
	GetPeerAddress(peerAddress);
	const PString peer = peerAddress.AsString();

	bool result = false;
	if (rule *= "forbid") { // "*=": case insensitive
		result =  false;
	} else if (rule *= "allow") {
		result =  true;
	} else if (rule *= "explicit") {
		PString val;
		if (!peer)
		    val = GkConfig()->GetString(authsec, peer, "");
		if (val.IsEmpty()) { // use "default" entry
			result = Toolkit::AsBool(GkConfig()->GetString(authsec, "default", "0"));
			PTRACE(5, "STATUS\tClient IP " << peer << " not found for explicit rule, using default ("
				<< result << ')'
				);
		} else 
			result = Toolkit::AsBool(val);
	} else if (rule *= "regex") {
		PString val;
		if (!peer)
		    val = GkConfig()->GetString(authsec, peer, "");
		if (val.IsEmpty()) {
			result = Toolkit::MatchRegex(peer, GkConfig()->GetString(authsec, "regex", ""));
			PTRACE(5, "STATUS\tClient IP " << peer << " not found for regex rule, using default ("
				<< GkConfig()->GetString(authsec, "regex", "") << ')'
				);
		} else
			result = Toolkit::AsBool(val);
	} else if (rule *= "password") {
		result = AuthenticateUser();
	} else {
		PTRACE(1, "STATUS\tERROR: Unrecognized [GkStatus::Auth] rule (" << rule << ')');
	}
	
	PTRACE(4, "STATUS\tAuthentication rule '" << rule 
		<< (result?"' accepted":"' rejected") << " the client " << Name() 
		);
	return result;
}

bool StatusClient::AuthenticateUser()
{
	const time_t now = time(NULL);
	const int delay = GkConfig()->GetInteger(authsec, "DelayReject", 0);
	const int loginTimeout = GkConfig()->GetInteger(authsec, "LoginTimeout", 120);
	bool tmp = m_isFilteringActive;
	
	m_isFilteringActive = false;

	for (int retries = 0; retries < 3; ++retries) {
		PString login, password;
		WriteString("\r\n" + Toolkit::GKName() + " login: ");
		if (!ReadCommand(login, true, loginTimeout * 1000))
			break;
		login = login.Trim();

		SendWill(PTelnetSocket::EchoOption);
		WriteString("Password: ");
		if (!ReadCommand(password, false, loginTimeout * 1000))
			break;
		password = password.Trim();
		WriteString("\r\n", 1);

		SendWont(PTelnetSocket::EchoOption);
		
		const PString storedPassword = GetPassword(login);
		if (storedPassword.IsEmpty())
			PTRACE(5, "STATUS\tCould not find password in the config for user " << login);
		else if (!password && password == storedPassword) {
			m_user = login;
			m_isFilteringActive = tmp;
			return true;
		} else
			PTRACE(5, "STATUS\tPassword mismatch for user " << login);
			
		PProcess::Sleep(delay * 1000);

		if ((time(NULL) - now) > loginTimeout)
			break;
	}
	m_isFilteringActive = tmp;
	return false;
}

PString StatusClient::GetPassword(
	/// login the password is to be retrieved for
	const PString& login
	) const
{
	return !login
		? Toolkit::Instance()->ReadPassword(authsec, login, true) : PString();
}

void StatusClient::ExecCommand(
	/// the command to be executed
	PString cmd
	)
{
	ReadLock lockConfig(ConfigReloadMutex);
	
	PTRACE(5, "STATUS\tGot command " << cmd << " from client " << Name());
	
	PStringArray args;
	switch (m_gkStatus->ParseCommand(cmd, args))
	{
	case GkStatus::e_DisconnectIp:
		// disconnect call on this IP number
		if (args.GetSize() == 2)
			SoftPBX::DisconnectIp(args[1]);
		else {
			WriteString("Syntax Error: DisconnectIp IP_ADDRESS\r\n");
			PTRACE(2, "Syntax Error: DisconnectIp IP_ADDRESS");
		}
		break;
	case GkStatus::e_DisconnectAlias:
		// disconnect call on this alias
		if (args.GetSize() == 2)
			SoftPBX::DisconnectAlias(args[1]);
		else {
			WriteString("Syntax Error: DisconnectAlias ALIAS\r\n");
			PTRACE(2, "Syntax Error: DisconnectAlias ALIAS");
		}
		break;
	case GkStatus::e_DisconnectCall:
		// disconnect call with this call number
		if (args.GetSize() >= 2)
			for (PINDEX p=1; p < args.GetSize(); ++p)
				SoftPBX::DisconnectCall(args[p].AsInteger());
		else {
			WriteString("Syntax Error: DisconnectCall CALL_NUMBER [CALL_NUMBER...]\r\n");
			PTRACE(2, "Syntax Error: DisconnectCall CALL_NUMBER [CALL_NUMBER...]");
		}
		break;
	case GkStatus::e_DisconnectEndpoint:
		// disconnect call on this alias
		if (args.GetSize() == 2)
			SoftPBX::DisconnectEndpoint(args[1]);
		else {
			WriteString("Syntax Error: DisconnectEndpoint ENDPOINT_IDENTIFIER\r\n");
			PTRACE(2, "Syntax Error: DisconnectEndpoint ENDPOINT_IDENTIFIER");
		}
		break;
	case GkStatus::e_DisconnectSession:
		// disconnect a user from status port
		if (args.GetSize() == 2)
			if (m_gkStatus->DisconnectSession(args[1].AsInteger(), this))
				WriteString("Session " + args[1] + " disconnected\r\n");
			else
				WriteString("Session " + args[1] + " not found\r\n");
		else {
			WriteString("Syntax Error: DisconnectSession SESSION_ID\r\n");
			PTRACE(2, "Syntax Error: DisconnectSession SESSION_ID");
		}
		break;
	case GkStatus::e_ClearCalls:
		SoftPBX::DisconnectAll();
		break;
	case GkStatus::e_PrintAllRegistrations:
		// print list of all registered endpoints
		SoftPBX::PrintAllRegistrations(this);
		break;
	case GkStatus::e_PrintAllRegistrationsVerbose:
		// print list of all registered endpoints verbose
		SoftPBX::PrintAllRegistrations(this, TRUE);
		break;
	case GkStatus::e_PrintAllCached:
		// print list of all cached outer-zone endpoints
		SoftPBX::PrintAllCached(this, (args.GetSize() > 1));
		break;
	case GkStatus::e_PrintCurrentCalls:
		// print list of currently ongoing calls
		SoftPBX::PrintCurrentCalls(this);
		break;
	case GkStatus::e_PrintCurrentCallsVerbose:
		// print list of currently ongoing calls
		SoftPBX::PrintCurrentCalls(this, TRUE);
		break;
	case GkStatus::e_Statistics:
		SoftPBX::PrintStatistics(this, TRUE);
		break;
	case GkStatus::e_Find:
		if (args.GetSize() == 2)
			SoftPBX::PrintEndpoint(args[1], this, FALSE);
		else {
			WriteString("Syntax Error: Find ALIAS\r\n");
			PTRACE(2, "Syntax Error: Find ALIAS");
		}
		break;
	case GkStatus::e_FindVerbose:
		if (args.GetSize() == 2)
			SoftPBX::PrintEndpoint(args[1], this, TRUE);
		else {
			WriteString("Syntax Error: FindVerbose ALIAS\r\n");
			PTRACE(2, "Syntax Error: FindVerbose ALIAS");
		}
		break;
	case GkStatus::e_Yell:
		m_gkStatus->SignalStatus(PString("  "+ WhoAmI() + ": " + cmd + "\r\n"));
		break;
	case GkStatus::e_Who:
		m_gkStatus->ShowUsers(this);
		WriteString(";\r\n");
		break;
	case GkStatus::e_GK:
		WriteString(RasServer::Instance()->GetParent() + "\r\n;\r\n");
		break;
	case GkStatus::e_Help:
		m_gkStatus->PrintHelp(this);
		break;
	case GkStatus::e_Debug:
		DoDebug(args);
		break;
	case GkStatus::e_Version:
		WriteString(PrintGkVersion());
		break;
	case GkStatus::e_Exit:
		Close();
		break;
	case GkStatus::e_UnregisterAllEndpoints:
		SoftPBX::UnregisterAllEndpoints();
		WriteString("Done\n;\n");
		break;
	case GkStatus::e_UnregisterAlias:
		// unregister this alias
		if (args.GetSize() == 2)
			SoftPBX::UnregisterAlias(args[1]);
		else {
			WriteString("Syntax Error: UnregisterAlias ALIAS\r\n");
			PTRACE(2, "Syntax Error: UnregisterAlias ALIAS");
		}
		break;
	case GkStatus::e_UnregisterIp:
		// unregister this IP
		if (args.GetSize() == 2)
			SoftPBX::UnregisterIp(args[1]);
		else {
			WriteString("Syntax Error: UnregisterIp IP_ADDRESS\r\n");
			PTRACE(2, "Syntax Error: UnregisterIp IP_ADDRESS");
		}
		break;
	case GkStatus::e_TransferCall:
		if (args.GetSize() == 3)
			SoftPBX::TransferCall(args[1], args[2]);
		else {
			WriteString("Syntax Error: TransferCall SOURCE DESTINATION\r\n");
			PTRACE(2, "Syntax Error: TransferCall SOURCE DESTINATION");
		}
		break;
	case GkStatus::e_MakeCall:
		if (args.GetSize() == 3)
			SoftPBX::MakeCall(args[1], args[2]);
		else {
			WriteString("Syntax Error: MakeCall SOURCE DESTINATION\r\n");
			PTRACE(2, "Syntax Error: MakeCall SOURCE DESTINATION");
		}
		break;
	case GkStatus::e_Reload:
		{
			ConfigReloadMutex.EndRead();
			ReloadHandler();
			ConfigReloadMutex.StartRead();
		}
		PTRACE(1, "STATUS\tConfig reloaded.");
		m_gkStatus->SignalStatus("Config reloaded.\r\n");
		break;
	case GkStatus::e_Shutdown:
		if (!Toolkit::AsBool(GkConfig()->GetString(authsec, "Shutdown", "1"))) {
			WriteString("Shutdown not allowed!\r\n");
			PTRACE(2, "Shutdown not allowed!");
			break;
		}
		SoftPBX::PrintStatistics(this, true);
		RasServer::Instance()->Stop();
		break;
	case GkStatus::e_RouteToAlias:
		if (args.GetSize() == 4) {
			RasServer::Instance()->GetVirtualQueue()->RouteToAlias(args[1], "", args[2], args[3].AsUnsigned(), "");
		} else if (args.GetSize() == 5) {
			args[4].Replace("-", " ", true);
			args[4] = args[4].Trim();
			RasServer::Instance()->GetVirtualQueue()->RouteToAlias(args[1], "", args[2], args[3].AsUnsigned(), args[4]);
		} else {
			WriteString("Syntax Error: RouteToAlias TARGET_ALIAS CALLING_ENDPOINT_ID CRV [CALLID]\r\n");
			PTRACE(2, "Syntax Error: RouteToAlias TARGET_ALIAS CALLING_ENDPOINT_ID CRV [CALLID]");
		}
		break;
	case GkStatus::e_RouteToGateway:
		if (args.GetSize() == 5) {
			RasServer::Instance()->GetVirtualQueue()->RouteToAlias(args[1], args[2], args[3], args[4].AsUnsigned(), "");
		} else if (args.GetSize() == 6) {
			args[5].Replace("-", " ", true);
			args[5] = args[5].Trim();
			RasServer::Instance()->GetVirtualQueue()->RouteToAlias(args[1], args[2], args[3], args[4].AsUnsigned(), args[5]);
		} else {
			WriteString("Syntax Error: RouteToGateway TARGET_ALIAS TARGET_IP CALLING_ENDPOINT_ID CRV [CALLID]\r\n");
			PTRACE(2, "Syntax Error: RouteToGateway TARGET_ALIAS TARGET_IP CALLING_ENDPOINT_ID CRV [CALLID]");
		}
		break;
	case GkStatus::e_RouteReject:
		if (args.GetSize() == 3) {
			RasServer::Instance()->GetVirtualQueue()->RouteReject(args[1], args[2].AsUnsigned(), "");
		} else if (args.GetSize() == 4) {
			args[3].Replace("-", " ", true);
			args[3] = args[3].Trim();
			RasServer::Instance()->GetVirtualQueue()->RouteReject(args[1], args[2].AsUnsigned(), args[3]);
		} else {
			WriteString("Syntax Error: RouteReject CALLING_ENDPOINT_ID CRV [CALLID]\r\n");
			PTRACE(2, "Syntax Error: RouteReject CALLING_ENDPOINT_ID CRV [CALLID]");
		}
		break;
	case GkStatus::e_Trace:
		if (args.GetSize() == 2) {
			if (args[1] *= "min")
				m_traceLevel = MIN_STATUS_TRACE_LEVEL;
			else if (args[1] *= "max")
				m_traceLevel = MAX_STATUS_TRACE_LEVEL;
			else {
				unsigned level = args[1].AsUnsigned();
				if (level >= MIN_STATUS_TRACE_LEVEL 
					&& level <= MAX_STATUS_TRACE_LEVEL)
					m_traceLevel = level;
				else {
					WriteString("Syntax Error: trace 0|1|2|\"min\"|\"max\"\r\n");
					PTRACE(2, "Syntax Error: trace 0|1|2|\"min\"|\"max\"");
					break;
				}
			}
		}
		WriteString("Output trace level is " + PString(m_traceLevel) + "\r\n");
		break;

#if PTRACING
	case GkStatus::e_RotateLog:
	    if (Gatekeeper::RotateLogFile())
			WriteString("Log file rotation succeeded\r\n");
		else						
			WriteString("Log file rotation failed\r\n");
	    break;
				
	case GkStatus::e_SetLogFilename:
		if (args.GetSize() == 2) {
			if (Gatekeeper::SetLogFilename(args[1])) {
				WriteString("Logging to the file '" + args[1] + "'\r\n");
			} else {					
				WriteString("Failed to open the log file'" + args[1] + "'\r\n");
				PTRACE(2, "Failed to open the log file'" + args[1] + "'");
			}
		} else {
			WriteString("Syntax Error: setlog <logfilepath>\r\n");
			PTRACE(2, "Syntax Error: setlog <logfilepath>");
		}
		break;				
#endif

	case GkStatus::e_AddIncludeFilter:
	    if (args.GetSize() == 2) {
		AddFilter(m_includeFilterRegex, args[1]);
	    } else {
			WriteString("Syntax Error: addincludefilter REGEX\r\n");
			PTRACE(2, "Syntax Error: addincludefilter REGEX");
		}
	    break;
	case GkStatus::e_RemoveIncludeFilter:
	    if (args.GetSize() == 2) {
		RemoveFilter(m_includeFilterRegex, atoi(args[1]));
	    } else {
			WriteString("Syntax Error: removeincludefilter FILTER_INDEX\r\n");
			PTRACE(2, "Syntax Error: removeincludefilter FILTER_INDEX");
		}
	    break;
	case GkStatus::e_AddExcludeFilter:
	    if (args.GetSize() == 2) {
		AddFilter(m_excludeFilterRegex, args[1]);
	    } else {
			WriteString("Syntax Error: addexcludefilter REGEX\r\n");
			PTRACE(2, "Syntax Error: addexcludefilter REGEX");
		}
	    break;
	case GkStatus::e_RemoveExcludeFilter:
	    if (args.GetSize() == 2) {
		RemoveFilter(m_excludeFilterRegex, atoi(args[1]));
	    } else {
			WriteString("Syntax Error: removeincludefilter FILTER_INDEX\r\n");
			PTRACE(2, "Syntax Error: removeincludefilter FILTER_INDEX");
		}
	    break;
	case GkStatus::e_Filter:
	    if (args.GetSize() == 2) {
		if (!(args[1] *= "0") && !(args[1] *= "1")) {
		    WriteString("Syntax Error: filter 0|1\r\n");
			PTRACE(2, "Syntax Error: filter 0|1");
		    break;
		}
		m_isFilteringActive = Toolkit::AsBool(args[1]);
	    }
	    if (m_isFilteringActive) {
		PString msg("Filtering is active\r\n");
		WriteData(msg, msg.GetLength());
	    }
	    else {
		PString msg("Filtering is not active\r\n");
		WriteData(msg, msg.GetLength());
	    }
	    break;
	case GkStatus::e_PrintExcludeFilters:
	    PrintFilters(m_excludeFilterRegex);
	    break;
	case GkStatus::e_PrintIncludeFilters:
	    PrintFilters(m_includeFilterRegex);
	    break;
	default:
		// commmand not recognized
		WriteString("Error: Unknown command " + cmd + "\r\n");
		PTRACE(2, "STATUS\tUnknown command '" << cmd << "' from client " << Name());
		break;
	}
	PWaitAndSignal lock(m_cmutex);
	--m_numExecutingCommands;
}

void StatusClient::AddFilter(
    // vector of filters
    std::vector<PString>& regexFilters,
    // Regular expression
    PString& regex
    )
{
    regexFilters.push_back(regex);
}

void StatusClient::RemoveFilter(
    // vector of filters
    std::vector<PString>& regexFilters,
    // Index of filter to be removed
    const PINDEX index
    )
{
    if (index < 0 || index >= (PINDEX) regexFilters.size()) {
		PString msg("Index mismatch.\r\n");
		WriteData(msg, msg.GetLength());
		return;
    }

    std::vector<PString>::iterator it = regexFilters.begin();

    PINDEX i = 0;
    while(i != index) {
		++it;
		++i;
    }

    regexFilters.erase(it);
}

bool StatusClient::IsExcludeMessage(
    // String to be chacked against exclude regular expressions 
    const PString &msg
    ) const
{
    return MatchFilter(m_excludeFilterRegex, msg);
}

bool StatusClient::MatchFilter(
    // filter vector
    const std::vector<PString>& regexFilters,
    // String to be matched against filters
    const PString &msg
    ) const
{
    std::vector<PString>::const_iterator it = regexFilters.begin();
    std::vector<PString>::const_iterator itEnd = regexFilters.end();

    for(; it != itEnd; ++it) {
	if (Toolkit::MatchRegex(msg, *it))
	    return true;
    }

    return false;
}

bool StatusClient::IsIncludeMessage(
    // String to be chacked against include regular expressions 
    const PString &msg
    ) const
{
    return MatchFilter(m_includeFilterRegex, msg);
}

void StatusClient::PrintFilters(
    // filter vector
    std::vector<PString>& regexFilters
    )
{
    std::vector<PString>::const_iterator it = regexFilters.begin();
    std::vector<PString>::const_iterator itEnd = regexFilters.end();
    unsigned int index = 0;
    PString count;

    if (regexFilters.size() == 0) {
		PString msg("No Filters are defined\r\n");
		WriteData(msg, msg.GetLength());
		return;
    }

    PString msg("Filter List:\r\n");
    WriteData(msg, msg.GetLength());
    for(; it != itEnd; ++it, ++index) {
		count = index;
		PString item(count);
		item += ") " + *it + "\r\n";
		WriteData(item, item.GetLength());
    }
    
    msg = ";\r\n";
    WriteData(msg, msg.GetLength());
}

// class StatusListener
StatusListener::StatusListener(
	const Address& addr, 
	WORD port
	)
{
	const unsigned queueSize = GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH);
	if (!Listen(addr, queueSize, port, PSocket::CanReuseAddress)) {
		PTRACE(1, "STATUS\tCould not open listening socket at " << addr << ':' << port
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< GetErrorNumber(PSocket::LastGeneralError) << ": " 
			<< GetErrorText(PSocket::LastGeneralError)
			);
		Close();
	}
	SetName(AsString(addr, GetPort()));
}

ServerSocket *StatusListener::CreateAcceptor() const
{
	static int StaticInstanceNo = 0;
	return new StatusClient(++StaticInstanceNo);
}
