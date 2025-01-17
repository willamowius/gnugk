//////////////////////////////////////////////////////////////////
//
// GkStatus.cxx
//
// Copyright (c) 2000-2023, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "config.h"

#ifdef HAS_LIBSSH

#if _WIN32 || _WIN64
#pragma comment(lib, LIBSSH_LIB)
#endif
#include "libssh/libssh.h"
#include "libssh/server.h"
#endif

// disable warning about comparison with zero for Intel icpc
#ifdef __INTEL_COMPILER
#pragma warning(disable: 186)
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
#include "gkacct.h"
#include "capctrl.h"
#include "rwlock.h"
#include "gk.h"
#include "h323util.h"
#include "GkStatus.h"

void ReloadHandler(); // avoid to include...

#ifdef UNIT_TEST
void ExitGK() { }; // mockup function for unit testing
#endif

static const char *authsec = "GkStatus::Auth";
static const char *filteringsec = "GkStatus::Filtering";

// a very lightweight implementation of telnet socket
class TelnetSocket : public ServerSocket {
#ifndef LARGE_FDSET
	PCLASSINFO(TelnetSocket, ServerSocket)
#endif
public:
	typedef PTelnetSocket::Options Options;
	typedef PTelnetSocket::Command Command;

	TelnetSocket();

	// override from class TCPSocket
#ifdef LARGE_FDSET
	virtual bool Accept(YaTCPSocket &);
#else
	virtual PBoolean Accept(PSocket &);
#endif

	virtual int ReadChar();

	bool SendDo(BYTE);
	bool SendDont(BYTE);
	bool SendWill(BYTE);
	bool SendWont(BYTE);
	bool SendCommand(Command, BYTE);

	bool NeedEcho() const { return m_needEcho; }

protected:
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

	virtual ~StatusClient();

	virtual void OnDo(BYTE code);

	virtual bool ReadCommand(
		/// command that has been read (if ReadCommand succeeded)
		PString & cmd,
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
	virtual bool WriteString(
		/// string to be sent through the socket
		const PString & msg,
		/// output trace level assigned to the message
		int level = MIN_STATUS_TRACE_LEVEL
		);

	/** @return
		A string with connection information about this client.
	*/
	PString WhoAmI() const;

	/** Check the client with all configured status authentication rules.
		Ask for username/password, if required.

		@return
		true if the client has been granted access, false to reject the client.
	*/
	virtual bool Authenticate();

	/** Executes the given command as a new Job (in a separate Worker thread).
	*/
	void OnCommand(
		/// command to be executed
		PString cmd
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
	bool IsBusy() const
	{
		PWaitAndSignal lock(m_cmutex);
		return m_numExecutingCommands > 0;
	}

	bool IsDone() const { return m_done; }

	const PString & GetUser() const { return m_user; }

protected:
	// override from class ServerSocket
	virtual void Dispatch();

	/// Handle the 'Debug' command (its many variants).
	void DoDebug(
		/// tokenized debug command
		const PStringArray & args
		);

	/** Check a new client connection against the specified authentication
		rule.

		@return
		true if the client satisfied the rule (has been authenticated successfully
		with this rule).
	*/
	bool CheckAuthRule(
		/// authentication rule to be used
		const PString & rule
		);

	/** Authenticate this status interface client through all authentication
		rules and return the final result.

		@return
		true if the use has been authenticated.
	*/
	virtual bool AuthenticateUser();

	/** @return
		The PBKDF2 digest for the password using the salt.
	*/
    PString PBKDF2_Digest(const PString & salt, const PString & password) const;

	/** @return
		The decrypted password associated with the specified login.
	*/
	PString GetPassword(const PString & userName) const;

	/** Parse and execute the given command. The function is called
		in a separate Worker thread (as a Job).
	*/
	void ExecCommand(
		/// the command to be executed
		PString cmd
		);

	/** Print error message to status port and trace
	*/
	void CommandError(const PString & msg);

	// Adds regular expression filter
	void AddFilter(
	// filter vector
	std::vector<PString> & regexFilters,
	// Regex to be matched against messages
	const PString & regex
	);

	/** Remove regular expression filter located
	at the given index from the specified vector
	*/
    void RemoveFilter(
	// filter vector
	std::vector<PString> & regexFilters,
	// Index of filter to be removed
	unsigned int index
	);

    // Checks whether the given string is to be exclude
    bool IsExcludeMessage(
	// String to be check against the exclude regular expressions
	const PString & msg
	) const;

    // Print a list of all filters in the specified vector
    void PrintFilters(
	// filter vector
	const std::vector<PString> & regexFilters
	);

    // Checks whether the given string is to be include
    bool IsIncludeMessage(
	// String to be check against the include regular expressions
	const PString & msg
	) const;

    // Match the given string against filters held by the specified vector
    bool MatchFilter(
	// filter vector
	const std::vector<PString> & regexFilters,
	// String to be matched
	const PString & msg
	) const;

	/// the most recent command
	PString m_lastCmd;
	/// command being currently entered (and not yet completed)
	PString m_currentCmd;
	/// GkStatus instance that created this client
	GkStatus * m_gkStatus;
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
	/// should the client be terminated, eg. after finishing a one-shot execute
	bool m_done;
	/// last resort flag if this status client has already been deleted
	bool m_deleted;

	// vectors of regular expressions to be matched against Status messages
	std::vector<PString> m_excludeFilterRegex;
	std::vector<PString> m_includeFilterRegex;

	// this flag indicates whether filtering is active or not
	bool m_isFilteringActive;
	bool m_handlePasswordRule;	// password rule is handled differently in SSHStatusClient subclass
};

#ifdef HAS_LIBSSH

// SSH version of the status client
class SSHStatusClient : public StatusClient {
public:
	SSHStatusClient(int instanceNo);
	virtual ~SSHStatusClient();

#ifdef LARGE_FDSET
	virtual bool Accept(YaTCPSocket &);
#else
	virtual PBoolean Accept(PSocket &);
#endif

	/** Check the client with all configured status authentication rules.
		Ask for username/password, if required.

		@return
		true if the client has been granted access, false to reject the client.
	*/
	virtual bool Authenticate();

	/** Authenticate this status interface client through all authentication
		rules and return the final result.

		@return
		true if the use has been authenticated.
	*/
	virtual bool AuthenticateUser();

	virtual bool ReadCommand(
		/// command that has been read (if ReadCommand succeeded)
		PString& cmd,
		/// should the command be echoed (also NeedEcho() has to be true)
		bool echo = true,
		/// timeout (ms) for read operation
		int readTimeout = 0
		);

	virtual bool WriteData(const BYTE * msg, int len);

protected:
	ssh_bind m_sshbind;
	ssh_session m_session;
    ssh_message m_message;
    ssh_channel m_chan;
};

SSHStatusClient::SSHStatusClient(int instanceNo) : StatusClient(instanceNo)
{
	m_chan = 0;
	m_needEcho = true;
	m_handlePasswordRule = false;	// modify behavior of password rule check in super class
	m_sshbind = NULL;
	m_session = NULL;
	m_message = NULL;
}

SSHStatusClient::~SSHStatusClient()
{
	ssh_disconnect(m_session);
	ssh_free(m_session);
	if (m_sshbind) {
		ssh_bind_set_fd(m_sshbind, -1);		// make sure StatusListener is not closed
		ssh_bind_free(m_sshbind);
	}
	GkStatus::Instance()->StatusClientDeleted();
}

#ifdef LARGE_FDSET
bool SSHStatusClient::Accept(YaTCPSocket & socket)
#else
PBoolean SSHStatusClient::Accept(PSocket & socket)
#endif
{
	m_sshbind = ssh_bind_new();
	m_session = ssh_new();

	//ssh_bind_options_set(m_sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");	// only enable for debugging
	// disable compression, doesn't seem to work (bug in libssh)
	ssh_options_set(m_session, SSH_OPTIONS_COMPRESSION_C_S, "none");
	ssh_options_set(m_session, SSH_OPTIONS_COMPRESSION_S_C, "none");

	bool keyAvailable = false;
	PString dsakey = GkConfig()->GetString(authsec, "DSAKey", "/etc/ssh/ssh_host_dsa_key");
	if (PFile::Exists(dsakey) && PFile::Access(dsakey, PFile::ReadOnly)) {
		keyAvailable = true;
		ssh_bind_options_set(m_sshbind, SSH_BIND_OPTIONS_DSAKEY, (const char *)dsakey);
		PTRACE(3, "Setting DSA key to " << dsakey);
	}
	PString rsakey = GkConfig()->GetString(authsec, "RSAKey", "/etc/ssh/ssh_host_rsa_key");
	if (PFile::Exists(rsakey) && PFile::Access(rsakey, PFile::ReadOnly)) {
		keyAvailable = true;
		ssh_bind_options_set(m_sshbind, SSH_BIND_OPTIONS_RSAKEY, (const char *)rsakey);
		PTRACE(3, "Setting RSA key to " << rsakey);
	}
	if (!keyAvailable) {
		PTRACE(1, "No DSA or RSA key file found");
		SNMP_TRAP(7, SNMPError, Network, "No SSH keys");
		socket.Close();
		return false;
	}

	ssh_bind_set_fd(m_sshbind, socket.GetHandle());
	if (ssh_bind_accept(m_sshbind, m_session) == SSH_ERROR) {
		PTRACE(1, "ssh_bind_accept() failed: " << ssh_get_error(m_sshbind));
		SNMP_TRAP(7, SNMPError, Network, "SSH bind failed");
		return false;
    }

    if (ssh_handle_key_exchange(m_session)) {
		PTRACE(1, "ssh_handle_key_exchange failed: " << ssh_get_error(m_session));
		SNMP_TRAP(7, SNMPError, Network, "SSH key exchange failed");
		return false;
	}

	// set handle for SocketsReader
	os_handle = ssh_get_fd(m_session);

#ifdef LARGE_FDSET
	socklen_t addr_len = sizeof(peeraddr);
	(void)getpeername(os_handle, ((struct sockaddr *)&peeraddr), &addr_len);  // OK to fail on private IPs etc.
#endif

	Address raddr, laddr;
	WORD rport = 0, lport = 0;
	GetPeerAddress(raddr, rport);
	UnmapIPv4Address(raddr);
	GetLocalAddress(laddr, lport);
	UnmapIPv4Address(laddr);
	SetName(AsString(raddr, rport) + "=>" + AsString(laddr, lport));

	return true;
}

bool SSHStatusClient::Authenticate()
{
	// check the auth rules if the ssh client is denied by explicit or regex rule
	bool ipcheck = StatusClient::Authenticate();
	if (!ipcheck) {
		PTRACE(1, "ssh client denied by IP rules");
		return false;
	}
	const time_t now = time(NULL);
	const int loginTimeout = GkConfig()->GetInteger(authsec, "LoginTimeout", 120);
    bool auth = false;
    const int MAX_RETRIES = 3;
    int retries = 0;
    do {
        m_message = ssh_message_get(m_session);
        if (!m_message) {
			PTRACE(1, "ssh read error: " << ssh_get_error(m_session));
			SNMP_TRAP(7, SNMPError, Network, PString("SSH read error: ") + ssh_get_error(m_session));
            break;
		}
		switch(ssh_message_type(m_message)) {
            case SSH_REQUEST_AUTH:
                switch(ssh_message_subtype(m_message)) {
                    case SSH_AUTH_METHOD_PASSWORD:
						retries++;
                        if (AuthenticateUser()) {
							auth = true;
							ssh_message_auth_reply_success(m_message, 0);
							break;
						}
						// fall through intended: not authenticated, send default message
                    case SSH_AUTH_METHOD_NONE:
                    default:
                        ssh_message_auth_set_methods(m_message, SSH_AUTH_METHOD_PASSWORD);
                        ssh_message_reply_default(m_message);
                        break;
                }
                break;
            default:
                ssh_message_reply_default(m_message);
        }
        ssh_message_free(m_message);
    } while (!auth && (retries < MAX_RETRIES) && ((time(NULL) - now) < loginTimeout));

    if (!auth) {
        return false;
    }

	// open channel
    do {
        m_message = ssh_message_get(m_session);
        if (m_message) {
            switch(ssh_message_type(m_message)) {
                case SSH_REQUEST_CHANNEL_OPEN:
                    if (ssh_message_subtype(m_message) == SSH_CHANNEL_SESSION) {
                        m_chan = ssh_message_channel_request_open_reply_accept(m_message);
                        break;
                    }
	                // fall through intended
                default:
	                ssh_message_reply_default(m_message);
            }
            ssh_message_free(m_message);
        }
    } while(m_message && !m_chan);
    if (!m_chan) {
        PTRACE(1, "Error establishing SSH channel: " << ssh_get_error(m_session));
		SNMP_TRAP(7, SNMPError, Network, PString("SSH error: ") + ssh_get_error(m_session));
        return false;
    }

	// handle requests
	bool shell = false;
    do {
        m_message = ssh_message_get(m_session);
        if (m_message) {
            switch(ssh_message_type(m_message)) {
                case SSH_REQUEST_CHANNEL:
                    switch (ssh_message_subtype(m_message)) {
						case SSH_CHANNEL_REQUEST_UNKNOWN:
							// eg. Putty X11 forwarding, deny to avoid hang
			                ssh_message_reply_default(m_message);	// deny
			                break;
						case SSH_CHANNEL_REQUEST_PTY:
		                    ssh_message_channel_request_reply_success(m_message);
			                break;
						case SSH_CHANNEL_REQUEST_EXEC:
							{
								shell = true;
								const char * cmd = ssh_message_channel_request_command(m_message);
								OnCommand(cmd);
								Flush();
			                    ssh_message_channel_request_reply_success(m_message);
								m_done = true;
							}
			                break;
						case SSH_CHANNEL_REQUEST_SHELL:
							shell = true;
		                    ssh_message_channel_request_reply_success(m_message);
			                break;
						case SSH_CHANNEL_X11:
			                ssh_message_reply_default(m_message);	// deny X11 forwarding
			                break;
						default:
							PTRACE(3, "Unhandled SSH_REQUEST_CHANNEL message subtype " << ssh_message_subtype(m_message));
							break;
					}
					break;
				default:
					PTRACE(3, "Unhandled SSH message " << ssh_message_type(m_message) << " subtype " << ssh_message_subtype(m_message));
				// ignore the rest for now
            }
            ssh_message_free(m_message);
        }
	} while(m_message && !shell);
	if (!m_message)
		return false;

    return true;
}

bool SSHStatusClient::AuthenticateUser()
{
	const int delay = GkConfig()->GetInteger(authsec, "DelayReject", 0);

	PString login = ssh_message_auth_user(m_message);
	PString password = ssh_message_auth_password(m_message);

	// PTRACE(1, "User " << login << " wants to authenticate with password " << password);

#ifdef P_SSL
    PString rawPassword = GkConfig()->GetString(authsec, login, "");
    if (rawPassword.Left(7) == "PBKDF2:") {
        const PINDEX dashPos = rawPassword.Find("-");
        const PString salt = rawPassword.Mid(7, dashPos - 7);
        const PString digest = rawPassword.Mid(dashPos + 1);
        if (PBKDF2_Digest(salt, password) == digest) {
            m_user = login;
            return true;
        } else {
            PTRACE(3, "STATUS\tPassword digest mismatch for user " << login);
        }
    }
    else
#endif
    {
        const PString storedPassword = GetPassword(login);
        if (storedPassword.IsEmpty())
            PTRACE(5, "STATUS\tCould not find password in the config for user " << login);
        else if (!password && password == storedPassword) {
            m_user = login;
            return true;
        } else {
            PTRACE(5, "STATUS\tPassword mismatch for user " << login);
        }
    }

	PThread::Sleep(delay * 1000);

	return false;
}

bool SSHStatusClient::ReadCommand(PString& cmd, bool echo, int readTimeout)
{
    char buf[2048];
    int i = 0;
    do {
        i = ssh_channel_read(m_chan, buf, sizeof(buf), 0);
		for (int c = 0; c < i; c++) {
			char ch = buf[c];
			switch (ch)
			{
				case '\r':
				case '\n':
					cmd = m_currentCmd;
					m_lastCmd = cmd;
					m_currentCmd = PString();
					if (echo && NeedEcho())
						ssh_channel_write(m_chan, (void *)"\r\n", 2);
					return true;
				case '\b':
				case 0x7f:	// backspace with ssh
					if (m_currentCmd.GetLength()) {
						m_currentCmd = m_currentCmd.Left(m_currentCmd.GetLength() - 1);
						if (echo && NeedEcho()) {
							ssh_channel_write(m_chan, (void *)"\b \b", 3);
						}
					}
					break;
				case '\x03':	// Ctrl-C
				case '\x04':	// Ctrl-D
					cmd = "exit";
					m_lastCmd = cmd;
					m_currentCmd = PString::Empty();
					return true;
				default:
					char byte = char(ch);
					m_currentCmd += byte;
					cmd = m_currentCmd.Right(3);
					// Note: this only works if the telnet client doesn't buffer characters
					// Windows does, my Linux telnet doesn't
					if (cmd == "\x1b\x5b\x41" || cmd == "\x5b\x41") { // Up Arrow
						if (echo && NeedEcho()) {
							for(PINDEX i = 0; i < m_currentCmd.GetLength() - 3; i ++)
								Write("\b", 1);
							WriteString(m_lastCmd);
						}
						m_currentCmd = m_lastCmd;
					} else if (cmd.Find('\x1b') == P_MAX_INDEX)
						if (echo && NeedEcho())
							ssh_channel_write(m_chan, &buf[c], 1);
					break;
				}
			}
    } while (i > 0);

	return true;
}

bool SSHStatusClient::WriteData(const BYTE * msg, int len)
{
	if (!m_chan)
		return false;

	int written = ssh_channel_write(m_chan, msg, len);
	ssh_blocking_flush(m_session, 5000);	// wait 5 sec. max
	return (written == len);
}

#endif // HAS_LIBSSH

TelnetSocket::TelnetSocket() : m_needEcho(false), m_state(StateNormal)
{
}

#ifdef LARGE_FDSET
bool TelnetSocket::Accept(YaTCPSocket & socket)
#else
PBoolean TelnetSocket::Accept(PSocket & socket)
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
	UnmapIPv4Address(raddr);
	GetLocalAddress(laddr, lport);
	UnmapIPv4Address(laddr);
	SetName(AsString(raddr, rport) + "=>" + AsString(laddr, lport));
	SetReadTimeout(0);
#else
	// name already be set
#endif
    SetOption(SO_SNDBUF, GkConfig()->GetInteger("StatusSendBufferSize", 16384));
    SetOption(SO_RCVBUF, GkConfig()->GetInteger("StatusReceiveBufferSize", 16384));
	return true;
}

int TelnetSocket::ReadChar()
{
	bool hasData = false;
	BYTE currentByte = 0;

	while (!hasData) {
		if (!TCPSocket::Read(&currentByte, 1)) {
			const PSocket::Errors err = GetErrorCode(PSocket::LastReadError);
			if ((err != PSocket::Timeout) && (err != PSocket::NoError)) {
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
			// else fall through intended for normal processing
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
		SoftPBX::Uptime() + "\r\n;\r\n";
}

}

// class GkStatus
GkStatus::GkStatus() : Singleton<GkStatus>("GkStatus"), SocketsReader(500)
{
	SetName("GkStatus");
	m_statusClients = 0;
    LoadConfig();

	Execute();
}

GkStatus::~GkStatus()
{
	ReadLock lock(m_listmutex);
	for (iterator i = m_sockets.begin(); i != m_sockets.end(); ++i) {
		(*i)->Close();
	}
}

void GkStatus::LoadConfig()
{
	m_maxStatusClients = GkConfig()->GetInteger("MaxStatusClients", 20);
    m_eventBacklogLimit = GkConfig()->GetInteger("StatusEventBacklog", 0);
    PString eventBacklogRegex = GkConfig()->GetString("StatusEventBacklogRegex", ".");
	m_eventBacklogRegex = PRegularExpression(eventBacklogRegex, PRegularExpression::Extended);
	if (m_eventBacklogRegex.GetErrorCode() != PRegularExpression::NoError) {
		PTRACE(2, "Error '"<< m_eventBacklogRegex.GetErrorText() <<"' compiling StatusEventBacklogRegex: " << eventBacklogRegex);
		m_eventBacklogRegex = PRegularExpression(".", PRegularExpression::Extended);
	}
}

void GkStatus::AuthenticateClient(StatusClient * newClient)
{
	if ((m_statusClients++ < m_maxStatusClients) && (newClient->Authenticate())) {
		newClient->SetTraceLevel(GkConfig()->GetInteger("StatusTraceLevel", MAX_STATUS_TRACE_LEVEL));
		PTRACE(1, "STATUS\tNew client authenticated successfully: " << newClient->WhoAmI()
			<< ", login: " << newClient->GetUser());
		// the welcome messages
		newClient->WriteString(PrintGkVersion());
		newClient->Flush();
		AddSocket(newClient);
		if (newClient->IsDone()) {
			while (newClient->IsBusy()) {
				PThread::Sleep(100);	// give forked threads time to finish
			}
			newClient->Flush();
			newClient->Close();
		}
	} else {
		PTRACE(3, "STATUS\tNew client rejected: " << newClient->WhoAmI() << ", login: " << newClient->GetUser());
		newClient->WriteString("\r\nAccess forbidden!\r\n");
		// newClient->Flush();	// dont' flush when access is denied to avoid blocking
		delete newClient;
	}
}

/** Functor class used to send the message to the specified client.
*/
class ClientSignalStatus
{
public:
	ClientSignalStatus(
		/// message to be sent
		const PString & msg,
		/// output trace level assigned to the message
		int level
		) : m_message(msg), m_traceLevel(level) { }

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
	const PString & m_message;
	/// output trace level assigned to the message
	int m_traceLevel;
};

void GkStatus::SignalStatus(
	/// message string to be broadcasted
	const PString & msg,
	/// trace level at which the message should be broadcasted
	int level
	)
{
	ReadLock lock(m_listmutex);
    // signal event to all connected clients
	ForEachInContainer(m_sockets, ClientSignalStatus(msg, level));

	// save event in backlog
    PWaitAndSignal eventLock(m_eventBacklogMutex);
	if (m_eventBacklogLimit > 0) {
        PString event = msg.Trim();
        event.Replace("\r\n", "");
        if (event != ";") {
            PINDEX pos = 0;
            if (m_eventBacklogRegex.Execute(event, pos)) {
                event = Toolkit::Instance()->AsString(PTime(), "MySQL") + ": " + event;
                m_eventBacklog.push_back(event);
                if (m_eventBacklog.size() > m_eventBacklogLimit) {
                    m_eventBacklog.pop_front();
                }
            }
        }
	}
}

bool GkStatus::DisconnectSession(
	/// session ID (instance number) for the status client to be disconnected
	int instanceNo,
	/// status interface client that requested disconnect
	StatusClient * requestingClient
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
		StatusClient * requestingClient
		) : m_requestingClient(requestingClient) { }

	void operator()(
		/// status interface client to send the information to
		const IPSocket * clientSocket
		) const
	{
		const StatusClient* client = static_cast<const StatusClient *>(clientSocket);
		m_requestingClient->WriteString("  " + client->WhoAmI() + "\r\n");
	}

private:
	/// status interface client to send the information to
	StatusClient * m_requestingClient;
};


void GkStatus::ShowUsers(
	/// client that requested the list of all active clients
	StatusClient * requestingClient
	) const
{
	ReadLock lock(m_listmutex);
	ForEachInContainer(m_sockets, WriteWhoAmI(requestingClient));
}

void GkStatus::PrintEventBacklog(StatusClient * requestingClient) const
{
	PWaitAndSignal lock(m_eventBacklogMutex);
	if (m_eventBacklogLimit == 0) {
    	requestingClient->WriteString("Please enable the status port event backlog by setting [Gatekeeper::Main] StatusEventBacklog=100\r\n");
	}
	for (std::list<PString>::const_iterator i = m_eventBacklog.begin(); i != m_eventBacklog.end(); ++i) {
	    requestingClient->WriteString(*i + "\r\n");
	}
    requestingClient->WriteString(";\r\n");
}

void GkStatus::PrintHelp(
	/// client that requested the help message
	StatusClient * requestingClient
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
	const PString & msg,
	/// message split into tokens upon successful return
	PStringArray & args
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
		++iter;
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
	m_commands["par"] = e_PrintAllRegistrations;
	m_commands["r"] = e_PrintAllRegistrations;
	m_commands["?"] = e_PrintAllRegistrations;
	m_commands["printallregistrationsverbose"] = e_PrintAllRegistrationsVerbose;
	m_commands["parv"] = e_PrintAllRegistrationsVerbose;
	m_commands["rv"] = e_PrintAllRegistrationsVerbose;
	m_commands["??"] = e_PrintAllRegistrationsVerbose;
	m_commands["printallcached"] = e_PrintAllCached;
	m_commands["pac"] = e_PrintAllCached;
	m_commands["rc"] = e_PrintAllCached;
	m_commands["printcurrentcalls"] = e_PrintCurrentCalls;
	m_commands["pcc"] = e_PrintCurrentCalls;
	m_commands["c"] = e_PrintCurrentCalls;
	m_commands["!"] = e_PrintCurrentCalls;
	m_commands["printcurrentcallsverbose"] = e_PrintCurrentCallsVerbose;
	m_commands["pccv"] = e_PrintCurrentCallsVerbose;
	m_commands["cv"] = e_PrintCurrentCallsVerbose;
	m_commands["!!"] = e_PrintCurrentCallsVerbose;
	m_commands["printcurrentcallsports"] = e_PrintCurrentCallsPorts;
	m_commands["pccp"] = e_PrintCurrentCallsPorts;
	m_commands["find"] = e_Find;
	m_commands["f"] = e_Find;
	m_commands["findverbose"] = e_FindVerbose;
	m_commands["fv"] = e_FindVerbose;
	m_commands["disconnectip"] = e_DisconnectIp;
	m_commands["dip"] = e_DisconnectIp;
	m_commands["disconnectcall"] = e_DisconnectCall;
	m_commands["dc"] = e_DisconnectCall;
	m_commands["disconnectcallid"] = e_DisconnectCallId;
	m_commands["dcid"] = e_DisconnectCallId;
	m_commands["disconnectalias"] = e_DisconnectAlias;
	m_commands["dca"] = e_DisconnectAlias;
	m_commands["disconnectendpoint"] = e_DisconnectEndpoint;
	m_commands["de"] = e_DisconnectEndpoint;
	m_commands["disconnectsession"] = e_DisconnectSession;
	m_commands["ds"] = e_DisconnectSession;
	m_commands["clearcalls"] = e_ClearCalls;
	m_commands["cc"] = e_ClearCalls;
	m_commands["unregisterallendpoints"] = e_UnregisterAllEndpoints;
	m_commands["uae"] = e_UnregisterAllEndpoints;
	m_commands["unregisterip"] = e_UnregisterIp;
	m_commands["uip"] = e_UnregisterIp;
	m_commands["unregisteralias"] = e_UnregisterAlias;
	m_commands["ua"] = e_UnregisterAlias;
	m_commands["transfercall"] = e_TransferCall;
	m_commands["tc"] = e_TransferCall;
	m_commands["reroutecall"] = e_RerouteCall;
	m_commands["rrc"] = e_RerouteCall;
	m_commands["makecall"] = e_MakeCall;
	m_commands["mc"] = e_MakeCall;
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
	m_commands["bindandroutetogateway"] = e_BindAndRouteToGateway;
	m_commands["brtg"] = e_BindAndRouteToGateway;
	m_commands["routetointernalgateway"] = e_RouteToInternalGateway;
	m_commands["rtig"] = e_RouteToInternalGateway;
	m_commands["routereject"] = e_RouteReject;
	m_commands["rr"] = e_RouteReject;
	m_commands["shutdown"] = e_Shutdown;
	m_commands["exit"] = e_Exit;
	m_commands["quit"] = e_Exit;
	m_commands["q"] = e_Exit;
	m_commands["trace"] = e_Trace;
	m_commands["rotatelog"] = e_RotateLog;
	m_commands["rl"] = e_RotateLog;
	m_commands["setlog"] = e_SetLogFilename;
	m_commands["addincludefilter"] = e_AddIncludeFilter;
	m_commands["removeincludefilter"] = e_RemoveIncludeFilter;
	m_commands["addexcludefilter"] = e_AddExcludeFilter;
	m_commands["removeexcludefilter"] = e_RemoveExcludeFilter;
	m_commands["filter"] = e_Filter;
	m_commands["printexcludefilters"] = e_PrintExcludeFilters;
	m_commands["printincludefilters"] = e_PrintIncludeFilters;
	m_commands["printprefixcapacities"] = e_PrintPrefixCapacities;
	m_commands["printpc"] = e_PrintPrefixCapacities;
	m_commands["printcc"] = e_PrintCapacityControlRules;
	m_commands["sendproceeding"] = e_SendProceeding;
	m_commands["getauthinfo"] = e_GetAuthInfo;
	m_commands["gai"] = e_GetAuthInfo;
	m_commands["getacctinfo"] = e_GetAcctInfo;
	m_commands["gci"] = e_GetAcctInfo;
	m_commands["resetcallcounters"] = e_ResetCallCounters;
	m_commands["printendpointqos"] = e_PrintEndpointQoS;
	m_commands["peq"] = e_PrintEndpointQoS;
	m_commands["printallconfigswitches"] = e_PrintAllConfigSwitches;
	m_commands["printeventbacklog"] = e_PrintEventBacklog;
	m_commands["printneighbors"] = e_PrintNeighbors;
	m_commands["pn"] = e_PrintNeighbors;
	m_commands["printcallinfo"] = e_PrintCallInfo;
	m_commands["pci"] = e_PrintCallInfo;
	m_commands["maintenancemode"] = e_MaintenanceMode;
	m_commands["maintenance"] = e_MaintenanceMode;
	m_commands["getlicensestatus"] = e_GetLicenseStatus;
	m_commands["getserverid"] = e_GetServerID;
}

void GkStatus::ReadSocket(IPSocket * clientSocket)
{
	PString cmd;
	StatusClient * client = static_cast<StatusClient*>(clientSocket);
	if (client->ReadCommand(cmd) && !cmd.IsEmpty()) {
		client->OnCommand(cmd);
	}
}

void GkStatus::CleanUp()
{
	if (m_rmsize > 0) {
		PWaitAndSignal lock(m_rmutex);
		iterator iter = m_removed.begin();
		while (iter != m_removed.end()) {
			StatusClient * client = static_cast<StatusClient *>(*iter);
			if (client && !client->IsBusy()) {
				iter = m_removed.erase(iter);
				--m_rmsize;
				delete client;
				client = NULL;
			}
			else ++iter;
		}
	}
	RemoveClosed(false);	// TODO: this runs every second, do we really need this here ? other SocketsReader don't do this
}


StatusClient::StatusClient(
	/// unique session ID (instance number) for this client
	int instanceNo) :
	USocket(this, "Status"),
	m_gkStatus(GkStatus::Instance()),
	m_numExecutingCommands(0),
	m_instanceNo(instanceNo),
	m_traceLevel(MAX_STATUS_TRACE_LEVEL),
	m_done(false), m_deleted(false),
	m_isFilteringActive(false),
	m_handlePasswordRule(true)
{
	PStringToString filters = GkConfig()->GetAllKeyValues(filteringsec);
	SetWriteTimeout(10);

	for (PINDEX i = 0; i < filters.GetSize(); i++) {
	    PString key = filters.GetKeyAt(i);
	    PString data = filters.GetDataAt(i);
	    PStringArray regexArray(data.Tokenise("\n", false));
	    for (PINDEX k = 0; k < regexArray.GetSize(); ++k) {
            if (filters.GetKeyAt(i) == "IncludeFilter")
                AddFilter(m_includeFilterRegex, regexArray[k]);
            else if (filters.GetKeyAt(i) == "ExcludeFilter")
                AddFilter(m_excludeFilterRegex, regexArray[k]);
	    }
	}
	m_isFilteringActive = Toolkit::AsBool(GkConfig()->GetString(filteringsec, "Enable", "0"));
}

StatusClient::~StatusClient()
{
	GkStatus::Instance()->StatusClientDeleted();
    m_deleted = true;
}

void StatusClient::OnDo(BYTE code)
{
	if (code == 6)  // Ctrl-C from Linux telnet client
        Close();
}

bool StatusClient::ReadCommand(
	/// command that has been read (if ReadCommand succeeded)
	PString & cmd,
	/// should the command be echoed (also NeedEcho() has to be true)
	bool echo,
	/// timeout (ms) for read operation, 0 means infinite
	int timeout
	)
{
	while (IsReadable(timeout)) {
		char byte;
		int ch = ReadChar();
		int lastErr = GetErrorNumber(PSocket::LastReadError);
		switch (ch)
		{
			case -1:
				// read IAC or socket closed
				if (lastErr == 0) { // yes, lastErr==0 means closed, IAC usually has err=110
					Close();
				}
				break;
			case '\r':
			case '\n':
				cmd = m_currentCmd;
				m_lastCmd = cmd;
				m_currentCmd = PString::Empty();
				if (echo && NeedEcho())
					TransmitData("\r\n");
				return true;
			case '\b':
				if (m_currentCmd.GetLength()) {
					m_currentCmd = m_currentCmd.Left(m_currentCmd.GetLength() - 1);
					byte = char(ch);
					if (echo && NeedEcho()) {
						Write(&byte, 1);
						Write(&" ", 1);
						Write(&byte, 1);
					}
				}
				break;
			case '\x03':	// Ctrl-C from Windows telnet client
			case '\x04':	// Ctrl-D
				cmd = "exit";
				m_lastCmd = cmd;
				m_currentCmd = PString::Empty();
				return true;
			default:
				byte = char(ch);
				m_currentCmd += byte;
				cmd = m_currentCmd.Right(3);
				// Note: this only works if the telnet client doesn't buffer characters
				// Windows doesn't, my Linux telnet does
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
	const PString & msg,
	/// output trace level assigned to the message
	int level)
{
	if (level > m_traceLevel)
		return true;
	if (CanFlush())
	    Flush();

	if (m_isFilteringActive && (IsExcludeMessage(msg) || !IsIncludeMessage(msg)))
	    return false;

	if (!WriteData(msg, msg.GetLength()))
	    while (CanFlush())
			Flush();

	return IsOpen();
}

PString StatusClient::WhoAmI() const
{
	return PString(m_instanceNo) + '\t' + GetName() + '\t' + m_user;
}

bool StatusClient::Authenticate()
{
	PINDEX rule_start = 0;
	bool result = false;
	const PString rules = GkConfig()->GetString(authsec, "rule", "forbid");
	while (true) {
		const PINDEX rule_end = rules.FindOneOf("&|", rule_start);
		if (rule_end == P_MAX_INDEX) {
			result = CheckAuthRule(rules(rule_start, P_MAX_INDEX).Trim());
			break;
		} else
			result = CheckAuthRule(rules(rule_start, rule_end - 1).Trim());
		bool logical_or = (rules[rule_end] == '|');
		if ((logical_or && result) || !(logical_or || result))
			break;
		rule_start = rule_end + 1;
	}

	PTRACE(4, "STATUS\tNew connection from " << GetName() << (result ? " accepted" : " rejected"));
	return result;
}

void StatusClient::OnCommand(
	/// command to be executed
	PString cmd
	)
{
	{
		PWaitAndSignal lock(m_cmutex);
		++m_numExecutingCommands;
	}
	// problem - if the ExecCommand does not get executed for some reason,
	// m_numExecutingCommands will not decrement

	// make sure this PString doesn't share memory with other PStrings
	// when we send it into another thread
	cmd.MakeUnique();
	CreateJob(this, &StatusClient::ExecCommand, cmd, "StatusCmd " + cmd);
}

void StatusClient::Dispatch()
{
	ReadLock lockConfig(ConfigReloadMutex);
	m_gkStatus->AuthenticateClient(this);
}

void StatusClient::DoDebug(
	/// tokenized debug command
	const PStringArray & args)
{
	bool tmp = m_isFilteringActive;
	m_isFilteringActive = false;	// deactivate filtering during this command

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
			if (args.GetSize() >= 4)
				WriteString(GkConfig()->GetString(args[2],args[3],"") + "\r\n;\r\n");
			else if (args.GetSize() >= 3) {
				if (args[2] *= "all") {
					// print all content of all config sections (= full config file)
					const PStringList secs(GkConfig()->GetSections());
					PString result;
					for (PINDEX i = 0; i < secs.GetSize(); i++) {
						if (secs[i].Left(1) == ";")
							continue;
						result += "Section [" + secs[i] + "]\r\n";
						const PStringList cfgs(GkConfig()->GetKeys(secs[i]));
						for (PINDEX j = 0; j < cfgs.GetSize(); ++j) {
							result += cfgs[j] + "=" + GkConfig()->GetString(secs[i], cfgs[j], "") + "\r\n";
						}
					}
					WriteString(result + ";\r\n");
				} else {
					PString result = "Section [" + args[2] + "]\r\n";
					const PStringList cfgs(GkConfig()->GetKeys(args[2]));
					for (PINDEX i = 0; i < cfgs.GetSize(); ++i) {
						result += cfgs[i] + "=" + GkConfig()->GetString(args[2], cfgs[i], "") + "\r\n";
					}
					WriteString(result + ";\r\n");
				}
			} else {
				const PStringList secs(GkConfig()->GetSections());
				PString result = "Config sections\r\n";
				for (PINDEX i = 0; i < secs.GetSize(); i++) {
					if (secs[i].Left(1) == ";")
						continue;	// skip comment lines
					result += "[" + secs[i] + "]\r\n";
				}
				WriteString(result + ";\r\n");
			}
		} else if ((args[1] *= "set") && (args.GetSize() >= 5)) {
			// re-assemble config value
			PString value = args[4];
			for (PINDEX i = 5; i < args.GetSize(); ++i)
				value += " " + args[i];
			Toolkit::Instance()->SetConfig(1, args[2], args[3], value);
			WriteString(GkConfig()->GetString(args[2],args[3], "") + "\r\n");
		} else if (args[1] *= "remove") {
			if (args.GetSize() >= 4) {
				Toolkit::Instance()->SetConfig(2, args[2], args[3]);
				WriteString("Remove " + args[3] + " in section " + args[2] + "\r\n");
			} else if (args.GetSize() >= 3) {
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
	const PString & rule
	)
{
	PIPSocket::Address peerAddress;
	GetPeerAddress(peerAddress);
	UnmapIPv4Address(peerAddress);
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
				<< GkConfig()->GetString(authsec, "regex", "") << ')');
		} else {
			result = Toolkit::AsBool(val);
		}
	} else if ((rule *= "password") && m_handlePasswordRule) {
		result = AuthenticateUser();
	} else if ((rule *= "password") && !m_handlePasswordRule) {
		result = true;	// used when called from SSHStatusClient
	} else {
		PTRACE(1, "STATUS\tERROR: Unrecognized [GkStatus::Auth] rule (" << rule << ')');
		SNMP_TRAP(7, SNMPError, Configuration, "Invalid [GkStatus::Auth] rule: " + rule);
	}

	PTRACE(4, "STATUS\tAuthentication rule '" << rule
		<< (result ? "' accepted" : "' rejected") << " the client " << Name());
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
		PString userName, password;
		WriteString("\r\n" + Toolkit::GKName() + " login: ");
		if (!ReadCommand(userName, true, loginTimeout * 1000))
			break;
		userName = userName.Trim();

		SendWill(PTelnetSocket::EchoOption);
		WriteString("Password: ");
		if (!ReadCommand(password, false, loginTimeout * 1000))
			break;
		password = password.Trim();
		WriteString("\r\n", 1);

		SendWont(PTelnetSocket::EchoOption);

#ifdef P_SSL
        PString rawPassword = GkConfig()->GetString(authsec, userName, "");
        if (rawPassword.Left(7) == "PBKDF2:") {
            const PINDEX dashPos = rawPassword.Find("-");
            const PString salt = rawPassword.Mid(7, dashPos - 7);
            const PString digest = rawPassword.Mid(dashPos + 1);
            if (PBKDF2_Digest(salt, password) == digest) {
                m_user = userName;
                m_isFilteringActive = tmp;
                return true;
            } else {
                PTRACE(3, "STATUS\tPassword digest mismatch for user " << userName);
            }
        }
        else
#endif
        {
            const PString storedPassword = GetPassword(userName);
            if (storedPassword.IsEmpty()) {
                PTRACE(5, "STATUS\tCould not find password in the config for user " << userName);
            } else if (!password.IsEmpty() && password == storedPassword) {
                m_user = userName;
                m_isFilteringActive = tmp;
                return true;
            } else {
                PTRACE(3, "STATUS\tPassword mismatch for user " << userName);
            }
        }

		PThread::Sleep(delay * 1000);

		if ((time(NULL) - now) > loginTimeout)
			break;
	}
	m_isFilteringActive = tmp;
	return false;
}

PString StatusClient::PBKDF2_Digest(const PString & salt, const PString & password) const
{
// need OpenSSL >= 1.0.x
#if defined(P_SSL) && OPENSSL_VERSION_NUMBER >= 0x1000000fL
    // the definitions here must match those in addpasswd.cxx
    const int iterations = 65536;
    const int outputBytes = 32;
    const unsigned saltSize = 8;

    unsigned char digest[outputBytes];
    char digestStr[2 * outputBytes + 1];
    memset(digestStr, 0, sizeof(digestStr));

    PKCS5_PBKDF2_HMAC((const char*)password, password.GetLength(), (const unsigned char*)salt, 2*saltSize, iterations, EVP_sha512(), outputBytes, digest);
    for (unsigned i = 0; i < sizeof(digest); i++)
        snprintf(digestStr + (i * 2), 2+1, "%02x", 255 & digest[i]);

    return digestStr;
#else
	PTRACE(1, "Error: PBKDF2 support not compiled in");
	return PString::Empty();
#endif
}

// read obfuscated password
PString StatusClient::GetPassword(const PString & userName) const
{
	return userName.IsEmpty() ? "" : Toolkit::Instance()->ReadPassword(authsec, userName, true);
}

void StatusClient::CommandError(const PString & msg)
{
	WriteString(msg + "\r\n");
	PTRACE(2, "STATUS\t" + msg + " from client " << Name());
}

// ignore warning when comparing to define
#if (!_WIN32) && (GCC_VERSION >= 40400)
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif

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
		else
			CommandError("Syntax Error: DisconnectIp IP_ADDRESS");
		break;
	case GkStatus::e_DisconnectAlias:
		// disconnect call on this alias
		if (args.GetSize() == 2)
			SoftPBX::DisconnectAlias(args[1]);
		else
			CommandError("Syntax Error: DisconnectAlias ALIAS");
		break;
	case GkStatus::e_DisconnectCall:
		// disconnect call with this call number
		if (args.GetSize() >= 2)
			for (PINDEX p = 1; p < args.GetSize(); ++p)
				SoftPBX::DisconnectCall(args[p].AsInteger());
		else
			CommandError("Syntax Error: DisconnectCall CALL_NUMBER [CALL_NUMBER...]");
		break;
	case GkStatus::e_DisconnectCallId:
		// disconnect call with this call ID
		if (args.GetSize() == 2)
			SoftPBX::DisconnectCallId(args[1]);
		else
			CommandError("Syntax Error: DisconnectCallId CALL_ID");
		break;
	case GkStatus::e_DisconnectEndpoint:
		// disconnect call on this alias
		if (args.GetSize() == 2)
			SoftPBX::DisconnectEndpoint(args[1]);
		else
			CommandError("Syntax Error: DisconnectEndpoint ENDPOINT_IDENTIFIER");
		break;
	case GkStatus::e_DisconnectSession:
		// disconnect a user from status port
		if (args.GetSize() == 2)
			if (m_gkStatus->DisconnectSession(args[1].AsInteger(), this))
				WriteString("Session " + args[1] + " disconnected\r\n");
			else
				WriteString("Session " + args[1] + " not found\r\n");
		else
			CommandError("Syntax Error: DisconnectSession SESSION_ID");
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
		// print list of all cached out-of-zone endpoints
		SoftPBX::PrintAllCached(this, (args.GetSize() > 1));
		break;
	case GkStatus::e_PrintCurrentCalls:
		// print list of currently ongoing calls
		SoftPBX::PrintCurrentCalls(this, FALSE);
		break;
	case GkStatus::e_PrintCurrentCallsVerbose:
		// print list of currently ongoing calls
		SoftPBX::PrintCurrentCalls(this, TRUE);
		break;
	case GkStatus::e_PrintCurrentCallsPorts:
		// print list of currently ongoing calls with their dynamic ports
		SoftPBX::PrintCurrentCallsPorts(this);
		break;
	case GkStatus::e_Statistics:
		SoftPBX::PrintStatistics(this, TRUE);
		break;
	case GkStatus::e_ResetCallCounters:
		SoftPBX::ResetCallCounters(this);
		break;
	case GkStatus::e_Find:
		if (args.GetSize() == 2)
			SoftPBX::PrintEndpoint(args[1], this, FALSE);
		else
			CommandError("Syntax Error: Find ALIAS");
		break;
	case GkStatus::e_FindVerbose:
		if (args.GetSize() == 2)
			SoftPBX::PrintEndpoint(args[1], this, TRUE);
		else
			CommandError("Syntax Error: FindVerbose ALIAS");
		break;
	case GkStatus::e_Yell:
		m_gkStatus->SignalStatus(PString("  " + WhoAmI() + ": " + cmd + "\r\n"));
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
		WriteString("Done\r\n;\r\n");
		break;
	case GkStatus::e_UnregisterAlias:
		// unregister this alias
		if (args.GetSize() == 2)
			SoftPBX::UnregisterAlias(args[1]);
		else
			CommandError("Syntax Error: UnregisterAlias ALIAS");
		break;
	case GkStatus::e_UnregisterIp:
		// unregister this IP
		if (args.GetSize() == 2)
			SoftPBX::UnregisterIp(args[1]);
		else
			CommandError("Syntax Error: UnregisterIp IP_ADDRESS");
		break;
	case GkStatus::e_UnregisterEP:
		// unregister this endpoint ID
		if (args.GetSize() == 2)
			SoftPBX::UnregisterEndpoint(args[1]);
		else
			CommandError("Syntax Error: UnregisterEP ENDPOINT-ID");
		break;
	case GkStatus::e_TransferCall:
		if (args.GetSize() == 3)
			SoftPBX::TransferCall(args[1], args[2]);
		else if (args.GetSize() == 4)
			SoftPBX::TransferCall(args[1], args[2], args[3], "FacilityForward");
		else if (args.GetSize() == 5)
			SoftPBX::TransferCall(args[1], args[2], args[3], args[4]);
		else
			CommandError("Syntax Error: TransferCall SOURCE DESTINATION or TransferCall CALLID CALLER|CALLED DESTINATION [TRANSFER-METHOD]");
		break;
	case GkStatus::e_RerouteCall:
		if (args.GetSize() == 4)
			SoftPBX::RerouteCall(args[1], args[2], args[3]);
		else
			CommandError("Syntax Error: RerouteCall CALLID CALLER|CALLED DESTINATION");
		break;
	case GkStatus::e_MakeCall:
		if (args.GetSize() == 3)
			SoftPBX::MakeCall(args[1], args[2]);
		else if (args.GetSize() == 4)
			SoftPBX::MakeCall(args[1], args[2], args[3]);
		else
			CommandError("Syntax Error: MakeCall SOURCE DESTINATION [TRANSFER-METHOD]");
		break;
	case GkStatus::e_Reload:
		{
			if (args.GetSize() >= 2) {
				ConfigReloadMutex.StartWrite();
				Toolkit::Instance()->PrepareReloadConfig();
				if (args[1] == "acctconfig") {
					GkAcctLoggerList *acctList = RasServer::Instance()->GetAcctList();
					if (acctList)
						acctList->OnReload();
					PTRACE(1, "STATUS\tAcct Config reloaded.");
					m_gkStatus->SignalStatus("Acct Config reloaded.\r\n");
				} else if (args[1] == "authconfig") {
					GkAuthenticatorList *authList = RasServer::Instance()->GetAuthList();
					if (authList)
						authList->OnReload();
					PTRACE(1, "STATUS\tAuth Config reloaded.");
					m_gkStatus->SignalStatus("Auth Config reloaded.\r\n");
				} else if (args[1] == "capconfig") {
					CapacityControl::Instance()->LoadConfig();
					PTRACE(1, "STATUS\tCapacityControl Config reloaded.");
					m_gkStatus->SignalStatus("CapacityControl Config reloaded.\r\n");
				} else if (args[1] == "epconfig") {
					CallTable::Instance()->LoadConfig();
					RegistrationTable::Instance()->LoadConfig();
					CallTable::Instance()->UpdatePrefixCapacityCounters();
					PTRACE(1, "STATUS\tEP Config reloaded.");
					m_gkStatus->SignalStatus("EP Config reloaded.\r\n");
				} else {
					CommandError("Syntax Error: Reload <AcctConfig|AuthConfig|CapConfig|EpConfig>");
				}
				ConfigReloadMutex.EndWrite();
			} else {
				ConfigReloadMutex.EndRead();	// ReloadHandler() re-acquires a write lock
				ReloadHandler();
				ConfigReloadMutex.StartRead();
				PTRACE(1, "STATUS\tFull Config reloaded.");
				// return immediately if this status client has already been deleted
				if (m_deleted)
                    return;
				m_gkStatus->SignalStatus("Full Config reloaded.\r\n");
			}
		}
		break;
	case GkStatus::e_Shutdown:
		if (!Toolkit::AsBool(GkConfig()->GetString(authsec, "Shutdown", "1"))) {
			CommandError("Shutdown not allowed!");
			break;
		}
		SoftPBX::PrintStatistics(this, true);
		RasServer::Instance()->Stop();
		break;
	case GkStatus::e_SendProceeding:
		if (args.GetSize() == 2) {
			SoftPBX::SendProceeding(args[1]);
		} else
			CommandError("Syntax Error: SendProceeding CALLID");
		break;
	case GkStatus::e_RouteToAlias:
		if (args.GetSize() < 4 || args.GetSize() > 8) {
			CommandError("Syntax Error: RouteToAlias TARGET_ALIAS CALLING_ENDPOINT_ID CRV [CALLID [CALLER-ID [CALLER-DISPLAY-IE [CALLED-DISPLAY-IE]]]]");
        } else {
            PString alias = args[1];
			if (alias == "-")
				alias = "";	// "-" is empty agent
            PString epid = args[2];
            unsigned crv = args[3].AsUnsigned();
            PString callID = "";
            if (args.GetSize() > 4) {
                args[4].Replace("-", " ", true);
                callID = args[4].Trim();
            }
            PString callerID = "";
            if (args.GetSize() > 5) {
                callerID = args[5];
                if (callerID == "-")
                    callerID = ""; // "-" is empty callerID
            }
            PString callerDisplayIE = "";
            if (args.GetSize() > 6) {
                callerDisplayIE = args[6];
                if (callerDisplayIE == "-")
                    callerDisplayIE = ""; // "-" is empty displayIE
                callerDisplayIE.Replace("+", " ", true); // restore spaces in displayIE
            }
            PString calledDisplayIE = "";
            if (args.GetSize() > 7) {
                calledDisplayIE = args[7];
                if (calledDisplayIE == "-")
                    calledDisplayIE = ""; // "-" is empty displayIE
                calledDisplayIE.Replace("+", " ", true); // restore spaces in displayIE
            }
			RasServer::Instance()->GetVirtualQueue()->RouteToAlias(alias, "", epid, crv, callID, "", callerID, false, false, callerDisplayIE, calledDisplayIE);
        }
		break;
	case GkStatus::e_RouteToGateway:
		if (args.GetSize() < 5 || args.GetSize() > 9) {
			CommandError("Syntax Error: RouteToGateway TARGET_ALIAS TARGET_IP CALLING_ENDPOINT_ID CRV [CALLID [CALLER-ID [CALLER-DISPLAY-IE [CALLED-DISPLAY-IE]]]]");
        } else {
            PString alias = args[1];
			if (alias == "-")
				alias = "";	// "-" is empty agent
            PString ip = args[2];
            PString epid = args[3];
            unsigned crv = args[4].AsUnsigned();
            PString callID = "";
            if (args.GetSize() > 5) {
                args[5].Replace("-", " ", true);
                callID = args[5].Trim();
            }
            PString callerID = "";
            if (args.GetSize() > 6) {
                callerID = args[6];
                if (callerID == "-")
                    callerID = ""; // "-" is empty callerID
            }
            PString callerDisplayIE = "";
            if (args.GetSize() > 7) {
                callerDisplayIE = args[7];
                if (callerDisplayIE == "-")
                    callerDisplayIE = ""; // "-" is empty displayIE
                callerDisplayIE.Replace("+", " ", true); // restore spaces in displayIE
            }
            PString calledDisplayIE = "";
            if (args.GetSize() > 8) {
                calledDisplayIE = args[8];
                if (calledDisplayIE == "-")
                    calledDisplayIE = ""; // "-" is empty displayIE
                calledDisplayIE.Replace("+", " ", true); // restore spaces in displayIE
            }
			RasServer::Instance()->GetVirtualQueue()->RouteToAlias(alias, ip, epid, crv, callID, "", callerID, false, false, callerDisplayIE, calledDisplayIE);
        }
		break;
	case GkStatus::e_RouteToInternalGateway:
		if (args.GetSize() < 5 || args.GetSize() > 9) {
			CommandError("Syntax Error: RouteToInternalGateway TARGET_ALIAS TARGET_IP CALLING_ENDPOINT_ID CRV [CALLID [CALLER-ID [CALLER-DISPLAY-IE [CALLED-DISPLAY-IE]]]]");
        } else {
            PString alias = args[1];
			if (alias == "-")
				alias = "";	// "-" is empty agent
            PString ip = args[2];
            PString epid = args[3];
            unsigned crv = args[4].AsUnsigned();
            PString callID = "";
            if (args.GetSize() > 5) {
                args[5].Replace("-", " ", true);
                callID = args[5].Trim();
            }
            PString callerID = "";
            if (args.GetSize() > 6) {
                callerID = args[6];
                if (callerID == "-")
                    callerID = ""; // "-" is empty callerID
            }
            PString callerDisplayIE = "";
            if (args.GetSize() > 7) {
                callerDisplayIE = args[7];
                if (callerDisplayIE == "-")
                    callerDisplayIE = ""; // "-" is empty displayIE
                callerDisplayIE.Replace("+", " ", true); // restore spaces in displayIE
            }
            PString calledDisplayIE = "";
            if (args.GetSize() > 8) {
                calledDisplayIE = args[8];
                if (calledDisplayIE == "-")
                    calledDisplayIE = ""; // "-" is empty displayIE
                calledDisplayIE.Replace("+", " ", true); // restore spaces in displayIE
            }
			RasServer::Instance()->GetVirtualQueue()->RouteToAlias(alias, ip, epid, crv, callID, "", callerID, false, true, callerDisplayIE, calledDisplayIE);
        }
		break;
	case GkStatus::e_BindAndRouteToGateway:
		if (args.GetSize() < 6 || args.GetSize() > 10) {
			CommandError("Syntax Error: BindAndRouteToGateway BIND_IP TARGET_ALIAS TARGET_IP CALLING_ENDPOINT_ID CRV [CALLID [CALLER-ID [CALLER-DISPLAY-IE [CALLED-DISPLAY-IE]]]]");
        } else {
            PString bindIP = args[1];
            PString alias = args[2];
			if (alias == "-")
				alias = "";	// "-" is empty agent
            PString ip = args[3];
            PString epid = args[4];
            unsigned crv = args[5].AsUnsigned();
            PString callID = "";
            if (args.GetSize() > 6) {
                args[6].Replace("-", " ", true);
                callID = args[6].Trim();
            }
            PString callerID = "";
            if (args.GetSize() > 7) {
                callerID = args[7];
                if (callerID == "-")
                    callerID = ""; // "-" is empty callerID
            }
            PString callerDisplayIE = "";
            if (args.GetSize() > 8) {
                callerDisplayIE = args[8];
                if (callerDisplayIE == "-")
                    callerDisplayIE = ""; // "-" is empty displayIE
                callerDisplayIE.Replace("+", " ", true); // restore spaces in displayIE
            }
            PString calledDisplayIE = "";
            if (args.GetSize() > 9) {
                calledDisplayIE = args[9];
                if (calledDisplayIE == "-")
                    calledDisplayIE = ""; // "-" is empty displayIE
                calledDisplayIE.Replace("+", " ", true); // restore spaces in displayIE
            }
			RasServer::Instance()->GetVirtualQueue()->RouteToAlias(alias, ip, epid, crv, callID, bindIP, callerID, false, false, callerDisplayIE, calledDisplayIE);
        }
		break;
	case GkStatus::e_BindAndRouteToInternalGateway:
		if (args.GetSize() < 6 || args.GetSize() > 10) {
			CommandError("Syntax Error: BindAndRouteToInternalGateway BIND_IP TARGET_ALIAS TARGET_IP CALLING_ENDPOINT_ID CRV [CALLID [CALLER-ID [CALLER-DISPLAY-IE [CALLED-DISPLAY-IE]]]]");
        } else {
            PString bindIP = args[1];
            PString alias = args[2];
			if (alias == "-")
				alias = "";	// "-" is empty agent
            PString ip = args[3];
            PString epid = args[4];
            unsigned crv = args[5].AsUnsigned();
            PString callID = "";
            if (args.GetSize() > 6) {
                args[6].Replace("-", " ", true);
                callID = args[6].Trim();
            }
            PString callerID = "";
            if (args.GetSize() > 7) {
                callerID = args[7];
                if (callerID == "-")
                    callerID = ""; // "-" is empty callerID
            }
            PString callerDisplayIE = "";
            if (args.GetSize() > 8) {
                callerDisplayIE = args[8];
                if (callerDisplayIE == "-")
                    callerDisplayIE = ""; // "-" is empty displayIE
                callerDisplayIE.Replace("+", " ", true); // restore spaces in displayIE
            }
            PString calledDisplayIE = "";
            if (args.GetSize() > 9) {
                calledDisplayIE = args[9];
                if (calledDisplayIE == "-")
                    calledDisplayIE = ""; // "-" is empty displayIE
                calledDisplayIE.Replace("+", " ", true); // restore spaces in displayIE
            }
			RasServer::Instance()->GetVirtualQueue()->RouteToAlias(alias, ip, epid, crv, callID, bindIP, callerID, false, true, callerDisplayIE, calledDisplayIE);
        }
		break;
	case GkStatus::e_RouteReject:
		if (args.GetSize() == 3) {
			RasServer::Instance()->GetVirtualQueue()->RouteReject(args[1], args[2].AsUnsigned(), "");
		} else if (args.GetSize() == 4) {
			args[3].Replace("-", " ", true);
			args[3] = args[3].Trim();
			RasServer::Instance()->GetVirtualQueue()->RouteReject(args[1], args[2].AsUnsigned(), args[3]);
		} else if (args.GetSize() == 5) {
			args[3].Replace("-", " ", true);
			args[3] = args[3].Trim();
			RasServer::Instance()->GetVirtualQueue()->RouteReject(args[1], args[2].AsUnsigned(), args[3], args[4].AsUnsigned());
		} else
			CommandError("Syntax Error: RouteReject CALLING_ENDPOINT_ID CRV [CALLID [REASON]]");
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
					CommandError("Syntax Error: trace 0|1|2|\"min\"|\"max\"");
					break;
				}
			}
		}
		WriteString("Output trace level is " + PString(m_traceLevel) + "\r\n");
		break;

#ifndef UNIT_TEST
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
			} else
				CommandError("Failed to open the log file'" + args[1] + "'");
		} else
			CommandError("Syntax Error: setlog <logfilepath>");
		break;
#endif

	case GkStatus::e_AddIncludeFilter:
	    if (args.GetSize() == 2) {
			AddFilter(m_includeFilterRegex, args[1]);
			PString msg("IncludeFilter added\r\n");
			WriteData(msg, msg.GetLength());
	    } else
			CommandError("Syntax Error: addincludefilter REGEX");
	    break;
	case GkStatus::e_RemoveIncludeFilter:
	    if (args.GetSize() == 2) {
			RemoveFilter(m_includeFilterRegex, atoi(args[1]));
			PString msg("IncludeFilter removed\r\n");
			WriteData(msg, msg.GetLength());
	    } else
			CommandError("Syntax Error: removeincludefilter FILTER_INDEX");
	    break;
	case GkStatus::e_AddExcludeFilter:
	    if (args.GetSize() == 2) {
			AddFilter(m_excludeFilterRegex, args[1]);
			PString msg("ExcludeFilter added\r\n");
			WriteData(msg, msg.GetLength());
	    } else
			CommandError("Syntax Error: addexcludefilter REGEX");
	    break;
	case GkStatus::e_RemoveExcludeFilter:
	    if (args.GetSize() == 2) {
			RemoveFilter(m_excludeFilterRegex, atoi(args[1]));
			PString msg("ExcludeFilter removed\r\n");
			WriteData(msg, msg.GetLength());
	    } else
			CommandError("Syntax Error: removeincludefilter FILTER_INDEX");
	    break;
	case GkStatus::e_Filter:
	    if (args.GetSize() == 2) {
			if (!(args[1] *= "0") && !(args[1] *= "1")) {
				CommandError("Syntax Error: filter 0|1");
				break;
			}
			m_isFilteringActive = Toolkit::AsBool(args[1]);
	    }
	    if (m_isFilteringActive) {
			PString msg("Filtering is active\r\n");
			WriteData(msg, msg.GetLength());
	    } else {
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
	case GkStatus::e_PrintPrefixCapacities:
		if (args.GetSize() == 1)
			SoftPBX::PrintPrefixCapacities(this, "");
		else if (args.GetSize() == 2)
			SoftPBX::PrintPrefixCapacities(this, args[1]);
		else
			CommandError("Syntax Error: PrintPrefixCapacities [ALIAS]");
		break;
	case GkStatus::e_PrintCapacityControlRules:
		SoftPBX::PrintCapacityControlRules(this);
		break;
	case GkStatus::e_GetAuthInfo:
		if (args.GetSize() == 2)
			WriteString(RasServer::Instance()->GetAuthInfo(args[1]));
		else
			CommandError("Syntax Error: GetAuthInfo|gai AUTH_MODULE_NAME");
		break;
	case GkStatus::e_GetAcctInfo:
		if (args.GetSize() == 2)
			WriteString(RasServer::Instance()->GetAcctInfo(args[1]));
		else
			CommandError("Syntax Error: GetAcctInfo|gci ACCT_MODULE_NAME");
		break;
	case GkStatus::e_PrintEndpointQoS:
		// print QoS values for all endpoints
		SoftPBX::PrintEndpointQoS(this);
		break;
	case GkStatus::e_PrintAllConfigSwitches:
		{
			const char * sect = NULL;
			unsigned j = 0;
			while ((sect = KnownConfigEntries[j][0])) {
				WriteString(PString(sect) + "," + PString(KnownConfigEntries[j][1]) + "\r\n");
				j++;
			}
			WriteString(";\r\n");
		}
		break;
	case GkStatus::e_PrintEventBacklog:
	    GkStatus::Instance()->PrintEventBacklog(this);
		break;
	case GkStatus::e_PrintNeighbors:
	    SoftPBX::PrintNeighbors(this);
		break;
	case GkStatus::e_PrintCallInfo:
		if (args.GetSize() == 2)
            SoftPBX::PrintCallInfo(this, args[1]);
		else
			CommandError("Syntax Error: PrintCallInfo|pci CALL-ID");
		break;
	case GkStatus::e_MaintenanceMode:
		if (args.GetSize() == 1) {          // ON
            SoftPBX::MaintenanceMode(true);
		} else if (args.GetSize() == 2) {   // OFF
            if (PCaselessString(args[1]) == "OFF") {
                SoftPBX::MaintenanceMode(false);
            } else {                        // ON with alternate IP
                SoftPBX::MaintenanceMode(true, args[1]);
            }
		} else {
			CommandError("Syntax Error: MaintenanceMode [Alternate-IP | OFF]");
        }
		break;
	case GkStatus::e_GetLicenseStatus:
		{
		PString license;
		if (Toolkit::Instance()->IsLicenseValid(license)) {
			license = "OK: " + Toolkit::Instance()->GetLicenseType();
		} else {
			license = "Invalid license: " + license + "\r\n";
		}
		WriteString(license + "\r\n");
		WriteString(";\r\n");
		}
		break;
	case GkStatus::e_GetServerID:
		WriteString(Toolkit::Instance()->GetServerID() + "\r\n");
		WriteString(";\r\n");
		break;
	default:
		// command not recognized
		CommandError("Error: Unknown command '" + cmd + "'");
		break;
	}
	PWaitAndSignal lock(m_cmutex);
	--m_numExecutingCommands;
}

void StatusClient::AddFilter(
    // vector of filters
    std::vector<PString> & regexFilters,
    // Regular expression
    const PString & regex
    )
{
    regexFilters.push_back(regex);
}

void StatusClient::RemoveFilter(
    // vector of filters
    std::vector<PString> & regexFilters,
    // Index of filter to be removed
    unsigned int index
    )
{
    if (index >= regexFilters.size()) {
		PString msg("Index mismatch.\r\n");
		WriteData(msg, msg.GetLength());
		return;
    }

    regexFilters.erase(regexFilters.begin() + index);
}

bool StatusClient::IsExcludeMessage(
    // String to be checked against exclude regular expressions
    const PString & msg
    ) const
{
    return MatchFilter(m_excludeFilterRegex, msg);
}

bool StatusClient::MatchFilter(
    // filter vector
    const std::vector<PString>& regexFilters,
    // String to be matched against filters
    const PString & msg
    ) const
{
    std::vector<PString>::const_iterator it = regexFilters.begin();

    for(; it != regexFilters.end(); ++it) {
		if (Toolkit::MatchRegex(msg, *it))
			return true;
    }

    return false;
}

bool StatusClient::IsIncludeMessage(
    // String to be checked against include regular expressions
    const PString & msg
    ) const
{
    return MatchFilter(m_includeFilterRegex, msg);
}

void StatusClient::PrintFilters(
    // filter vector
    const std::vector<PString> & regexFilters
    )
{
	PString msg;

    if (regexFilters.empty()) {
		msg = "No Filters are defined\r\n";
		WriteData(msg, msg.GetLength());
		return;
    }

    msg = "Filter List:\r\n";
    WriteData(msg, msg.GetLength());
    for(unsigned int index = 0; index < regexFilters.size(); index++) {
		msg = PString(index) + ") " + regexFilters[index] + "\r\n";
		WriteData(msg, msg.GetLength());
    }

    msg = ";\r\n";
    WriteData(msg, msg.GetLength());
}

// class StatusListener
StatusListener::StatusListener(const Address & addr, WORD lport)
{
	const unsigned queueSize = GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH);
	if (!Listen(addr, queueSize, lport, PSocket::CanReuseAddress)) {
		PTRACE(1, "STATUS\tCould not open listening socket at " << AsString(addr, lport)
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< GetErrorNumber(PSocket::LastGeneralError) << ": "
			<< GetErrorText(PSocket::LastGeneralError)
			);
		Close();
	}
	SetName(AsString(addr, GetPort()));
	m_addr = addr;
	if (Toolkit::Instance()->IsPortNotificationActive())
		Toolkit::Instance()->PortNotification(StatusPort, PortOpen, "tcp", m_addr, lport);
}

StatusListener::~StatusListener()
{
	if (Toolkit::Instance()->IsPortNotificationActive())
		Toolkit::Instance()->PortNotification(StatusPort, PortClose, "tcp", m_addr, GetPort());
}

ServerSocket * StatusListener::CreateAcceptor() const
{
	static int StaticInstanceNo = 0;
#ifdef HAS_LIBSSH
	if (Toolkit::AsBool(GkConfig()->GetString("SSHStatusPort", 0))) {
		PTRACE(4, "STATUS\tUsing SSH for status port");
		return new SSHStatusClient(++StaticInstanceNo);
	} else {
#endif
		return new StatusClient(++StaticInstanceNo);
#ifdef HAS_LIBSSH
	}
#endif
}
