//////////////////////////////////////////////////////////////////
//
// GkStatus.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	990924	initial version (Jan Willamowius)
//	991025	added command thread (Ashley Unitt)
//	030511  redesign based on new architecture (cwhuang)
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4355 ) // warning about using 'this' in initializer
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include "GkStatus.h"
#include "gk_const.h"
#include "stl_supp.h"
#include "SoftPBX.h"
#include "Toolkit.h"
#include "RasSrv.h"
#include "Routing.h"
#include "rwlock.h"
#include <ptclib/telnet.h>


void ReloadHandler(); // avoid to include...

static const char *authsec="GkStatus::Auth";

// a very lightweight implementation of telnet socket
class TelnetSocket : public ServerSocket {
public:
	typedef PTelnetSocket::Options Options;
	typedef PTelnetSocket::Command Command;

	TelnetSocket();

	// override from class TCPSocket
#ifdef LARGE_FDSET
	virtual bool Accept(YaTCPSocket &);
#else
	PCLASSINFO ( TelnetSocket, TCPSocket )
	virtual BOOL Accept(PSocket &);
#endif

	virtual int ReadChar();

	bool SendDo(BYTE);
	bool SendDont(BYTE);
	bool SendWill(BYTE);
	bool SendWont(BYTE);
	bool SendCommand(Command, BYTE);

	bool NeedEcho() const { return needEcho; }

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

	bool needEcho;
	State state;
};

TelnetSocket::TelnetSocket() : needEcho(false)
{
	state = StateNormal;
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
	Address addr;
	WORD pt;
	GetPeerAddress(addr, pt);
	SetName(AsString(addr, pt));
	SetReadTimeout(0);
#else
	// name already be set
#endif
	return true;
}

int TelnetSocket::ReadChar()
{
	bool hasData = false;
	BYTE currentByte;

	while (!hasData) {
	       	if (!TCPSocket::Read(&currentByte, 1)) {
			if (GetErrorCode(PSocket::LastReadError) != PSocket::Timeout) {
				PTRACE(2, "Telnet\t" << GetName() << " has disconnected");
				Close();
			}
			break;
		}
		switch (state)
		{
			case StateCarriageReturn:
				state = StateNormal;
				if (currentByte == '\0' || currentByte == '\n')
					break; // Ignore \0 \n after CR
				// else fall through for normal processing
			case StateNormal:
				if (currentByte != PTelnetSocket::IAC) {
					if (currentByte == '\r')
						state = StateCarriageReturn;
					hasData = true;
				} else
					state = StateIAC;
				break;
			case StateIAC:
				switch (currentByte)
				{
					case PTelnetSocket::IAC :
						hasData = true;
						state = StateNormal;
						break;
					case PTelnetSocket::DO:
						state = StateDo;
						break;
					case PTelnetSocket::DONT:
						state = StateDont;
						break;
					case PTelnetSocket::WILL:
						state = StateWill;
						break;
					case PTelnetSocket::WONT:
						state = StateWont;
						break;
					default:
						state = StateNormal;
						break;
				}
				break;
			case StateDo:
				OnDo(currentByte);
				state = StateNormal;
				break;
			case StateDont:
				OnDont(currentByte);
				state = StateNormal;
				break;
			case StateWill:
				OnWill(currentByte);
				state = StateNormal;
				break;
			case StateWont:
				OnWont(currentByte);
				state = StateNormal;
				break;
			default:
				PTRACE(5, "Telnet\t" << GetName() << " unsupported state");
				state = StateNormal;
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
	PTRACE(5, "Telnet\t" << GetName() << " get DO " << int(code));
}

void TelnetSocket::OnDont(BYTE code)
{
	PTRACE(5, "Telnet\t" << GetName() << " get DONT " << int(code));
}

void TelnetSocket::OnWill(BYTE code)
{
	PTRACE(5, "Telnet\t" << GetName() << " get WILL " << int(code));
}

void TelnetSocket::OnWont(BYTE code)
{
	PTRACE(5, "Telnet\t" << GetName() << " get WONT " << int(code));
	if (code == PTelnetSocket::EchoOption) // Windows client?
		needEcho = true;
}


class StatusClient : public TelnetSocket, public USocket {
#ifndef LARGE_FDSET
	PCLASSINFO ( StatusClient, TelnetSocket )
#endif
public:
	StatusClient(int);

	bool ReadCommand(PString &, bool = true, int = 0);
	bool WriteString(const PString &, int = 0);
	void FlushData();

	PString WhoAmI() const;
	bool Authenticate();
	void OnCommand(const PString &);

	int GetInstanceNo() const { return m_instanceNo; }
	int GetTraceLevel() const { return m_traceLevel; }
	bool IsBusy() const { return m_executedCmd > 0; }

private:
	// override from class ServerSocket
	virtual void Dispatch();

	// handles the 'Debug' command. #Args# is the whole tokenised command line.
	void DoDebug(const PStringArray & Args);

	bool CheckRule(const PString &);
	bool AuthenticateUser();
	PString GetPassword(const PString & UserName) const;
	void ExecCommand(PString);

	PString m_lastCmd;
	PString m_currentCmd;
	GkStatus *m_gkStatus;
	PString	m_user;
	PMutex m_cmutex;
	int m_executedCmd;
	int m_instanceNo;
	int m_traceLevel;
};


namespace {

PString PrintGkVersion()
{
	return PString("Version:\r\n") + Toolkit::GKVersion() +
#ifdef LARGE_FDSET
		PString(PString::Printf, "Large fd_set(%d) enabled\r\n", LARGE_FDSET) +
#endif
		"\r\nGkStatus: Version(2.0) Ext()\r\n"
		"Toolkit: Version(1.0) Ext(" + Toolkit::Instance()->GetName() +
		")\r\n" + SoftPBX::Uptime() + "\r\nBuilt:" + PString( __DATE__) + 
		PString( " " ) + PString( __TIME__ ) + "\r\n\r\n;";
}

}

// class GkStatus
GkStatus::GkStatus() : Singleton<GkStatus>("GkStatus"), SocketsReader(500)
{
#ifdef LARGE_FDSET
	PTRACE(1, "GK\tLarge fd_set(" << LARGE_FDSET << ") enabled");
#endif

	SetName("GkStatus");
	Execute();
}

void GkStatus::AuthenticateClient(StatusClient *client)
{
	if (client->Authenticate()) {
		AddSocket(client);
		PTRACE(2, "Status\tnew client " << client->WhoAmI());
		// the welcome messages
		client->WriteString(PrintGkVersion());
	} else {
		client->WriteString("\r\nAccess forbidden!\r\n");
		delete client;
	}
}

// function object used by for_each
class ClientSignalStatus {
  public:
	ClientSignalStatus(const PString & m, int l) : msg(m), level(l) {} 
	void operator()(IPSocket *) const;

  private:
	const PString & msg;
	int level;
};

void ClientSignalStatus::operator()(IPSocket *socket) const
{
	StatusClient *client = static_cast<StatusClient *>(socket);
	int ctl = client->GetTraceLevel();
	if ((ctl <= 10) && (ctl >= 0) && (level >= ctl)) 
		client->WriteString(msg);
}

void GkStatus::SignalStatus(const PString &Message, int level)
{
	ReadLock lock(m_listmutex);
	ForEachInContainer(m_sockets, ClientSignalStatus(Message, level));
}

bool GkStatus::DisconnectSession(int InstanceNo, StatusClient *kicker)
{
	PTRACE(1, "Disconnect Session " << InstanceNo);
	ReadLock lock(m_listmutex);
	for (iterator i = m_sockets.begin(); i != m_sockets.end(); ++i) {
		StatusClient *client = static_cast<StatusClient *>(*i);
		if (client->GetInstanceNo() == InstanceNo) {
			client->WriteString("Disconnected by session " + kicker->WhoAmI());
			return client->Close();
		}
	}
	return false;
}

// function object used by for_each
class WriteWhoAmI {
  public:
	WriteWhoAmI(StatusClient *c) : writeTo(c) {}
	void operator()(const IPSocket *) const;

  private:
	StatusClient *writeTo;
};

void WriteWhoAmI::operator()(const IPSocket *socket) const
{
	const StatusClient *client = static_cast<const StatusClient *>(socket);
	writeTo->WriteString("  " + client->WhoAmI() + "\r\n");
}

void GkStatus::ShowUsers(StatusClient *c) const
{
	ReadLock lock(m_listmutex);
	ForEachInContainer(m_sockets, WriteWhoAmI(c));
}

void GkStatus::PrintHelp(StatusClient *client) const
{
	client->WriteString("Commands:\r\n");
	std::map<PString, int>::const_iterator i = m_commands.begin();
	while (i != m_commands.end())
		client->WriteString(i->first + "\r\n"), ++i;
	client->WriteString(";\r\n");
}

int GkStatus::ParseCommand(const PString & cmd, PStringArray & args)
{
	// the 'Tokenise' seems not correct for leading spaces
	args = cmd.Trim().Tokenise(" \t", false);
	if (args.GetSize() > 0) {
		PString key = args[0].ToLower();
		PTRACE(2, "Status\tgot command " << key);
		if (m_commands.find(key) != m_commands.end())
			return m_commands[key];
		std::map<PString, int>::iterator it = m_commands.begin();
		int expandedCmd = -1;
#if PTRACING
		PString expandedCmdStr;
#endif
		while (it != m_commands.end()) {
			const PString& cmd = it->first;
			if (key == cmd.Left(key.GetLength())) {
				// if the key matches more than one command, do not expand
				if( expandedCmd != -1 )
					return -1;
				else {
					expandedCmd = it->second;
#if PTRACING
					expandedCmdStr = cmd;
#endif
				}
			}
			it ++;
		}
		if( expandedCmd != -1 ) {
			PTRACE(4, "Status\tExpanded "<<key<<" into command "<<expandedCmdStr);
			return expandedCmd;
		}
	}
	return -1;
}

void GkStatus::OnStart()
{
	m_commands["printallregistrations"] =	     e_PrintAllRegistrations;
	m_commands["r"] =			     e_PrintAllRegistrations;
	m_commands["?"] =			     e_PrintAllRegistrations;
	m_commands["printallregistrationsverbose"] = e_PrintAllRegistrationsVerbose;
	m_commands["rv"] =			     e_PrintAllRegistrationsVerbose;
	m_commands["??"] =			     e_PrintAllRegistrationsVerbose;
	m_commands["printallcached"] =		     e_PrintAllCached;
	m_commands["rc"] =			     e_PrintAllCached;
	m_commands["printcurrentcalls"] =	     e_PrintCurrentCalls;
	m_commands["c"] =			     e_PrintCurrentCalls;
	m_commands["!"] =			     e_PrintCurrentCalls;
	m_commands["printcurrentcallsverbose"] =     e_PrintCurrentCallsVerbose;
	m_commands["cv"] =			     e_PrintCurrentCallsVerbose;
	m_commands["!!"] =			     e_PrintCurrentCallsVerbose;
	m_commands["find"] =			     e_Find;
	m_commands["f"] =			     e_Find;
	m_commands["findverbose"] =		     e_FindVerbose;
	m_commands["fv"] =			     e_FindVerbose;
	m_commands["disconnectip"] =		     e_DisconnectIp;
	m_commands["disconnectcall"] =		     e_DisconnectCall;
	m_commands["disconnectalias"] =		     e_DisconnectAlias;
	m_commands["disconnectendpoint"] =	     e_DisconnectEndpoint;
	m_commands["disconnectsession"] =	     e_DisconnectSession;
	m_commands["clearcalls"] =		     e_ClearCalls;
	m_commands["unregisterallendpoints"] =	     e_UnregisterAllEndpoints;
	m_commands["unregisterip"] =		     e_UnregisterIp;
	m_commands["unregisteralias"] =		     e_UnregisterAlias;
	m_commands["transfercall"] =		     e_TransferCall;
	m_commands["makecall"] =		     e_MakeCall;
	m_commands["yell"] =			     e_Yell;
	m_commands["who"] =			     e_Who;
	m_commands["gk"] =			     e_GK;
	m_commands["help"] =			     e_Help;
	m_commands["h"] =			     e_Help;
	m_commands["version"] =			     e_Version;
	m_commands["v"] =			     e_Version;
	m_commands["debug"] =			     e_Debug;
	m_commands["statistics"] =		     e_Statistics;
	m_commands["s"] =			     e_Statistics;
	m_commands["reload"] =			     e_Reload;
	m_commands["routetoalias"] =		     e_RouteToAlias;
	m_commands["rta"] =			     e_RouteToAlias;
	m_commands["routereject"] =		     e_RouteReject;
	m_commands["shutdown"] =		     e_Shutdown;
	m_commands["exit"] =			     e_Exit;
	m_commands["quit"] =			     e_Exit;
	m_commands["q"] =			     e_Exit;
}

void GkStatus::OnStop()
{
	PTRACE(1, "GK\tGkStatus stopped");
}

void GkStatus::ReadSocket(IPSocket *socket)
{
	PString cmd;
	StatusClient *client = static_cast<StatusClient *>(socket);
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
				delete client;
				m_removed.erase(i);
				--m_rmsize;
			}
		}
	}
	RemoveClosed(false);
}


// class StatusClient
StatusClient::StatusClient(int i) : USocket(this, "Status"), m_instanceNo(i)
{
	m_gkStatus = GkStatus::Instance();
	m_executedCmd = m_traceLevel = 0;
	SetWriteTimeout(10);
}

bool StatusClient::ReadCommand(PString & cmd, bool echo, int timeout)
{
	while (IsReadable(timeout)) {
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

bool StatusClient::WriteString(const PString & msg, int level)
{
	if (level < m_traceLevel)
		return true;
	if (CanFlush())
		Flush();
	return WriteData(msg, msg.GetLength());
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
	PTRACE(4, "Status\tAuth client from " << GetName());

	PINDEX p = 0;
	bool result, logical_or;
	const PString rules = GkConfig()->GetString(authsec, "rule", "forbid");
	while (true) {
		PINDEX q = rules.FindOneOf("&|", p);
		result = CheckRule(rules(p, q - 1).Trim());
		if (q == P_MAX_INDEX)
			break;
		logical_or = (rules[q] == '|') ;
		if ((logical_or && result) || !(logical_or || result))
			break;
		p = q + 1;
	}

	return result;
}

void StatusClient::OnCommand(const PString & cmd)
{
	CreateJob(this, &StatusClient::ExecCommand, cmd, "Command " + cmd);
	PWaitAndSignal lock(m_cmutex);
	++m_executedCmd;
}

void StatusClient::Dispatch()
{
	m_gkStatus->AuthenticateClient(this);
}

void StatusClient::DoDebug(const PStringArray & Args)
{
	if (Args.GetSize() <= 1) {
		WriteString("Debug options:\r\n"
			    "  trc [+|-|n]       Show/modify trace level\r\n"
				"  cfg               Read and print config sections\r\n"
			    "  cfg SEC PAR       Read and print a config PARameter in a SECtion\r\n"
			    "  set SEC PAR VAL   Write a config VALue PARameter in a SECtion\r\n"
			    "  remove SEC PAR    Remove a config VALue PARameter in a SECtion\r\n"
			    "  remove SEC        Remove a SECtion\r\n"
			    "  printrm VERBOSE   Print all removed endpoint records\r\n");
	} else {
		if (Args[1] *= "trc") {
			if(Args.GetSize() >= 3) {
				if((Args[2] == "-") && (PTrace::GetLevel() > 0)) 
					PTrace::SetLevel(PTrace::GetLevel()-1);
				else if(Args[2] == "+") 
					PTrace::SetLevel(PTrace::GetLevel()+1);
				else PTrace::SetLevel(Args[2].AsInteger());
			}
			WriteString(PString(PString::Printf, "Trace Level is now %d\r\n", PTrace::GetLevel()));
		} else if (Args[1] *= "cfg") {
			if (Args.GetSize()>=4)
				WriteString(GkConfig()->GetString(Args[2],Args[3],"") + "\r\n;\r\n");
			else if (Args.GetSize()>=3) {
				PStringList cfgs(GkConfig()->GetKeys(Args[2]));
				PString result = "Section [" + Args[2] + "]\r\n";
				for (PINDEX i=0; i < cfgs.GetSize(); ++i) {
					PString v(GkConfig()->GetString(Args[2], cfgs[i], ""));
					result += cfgs[i] + "=" + v + "\r\n";
				}
				WriteString(result + ";\r\n");
			} else {
				const PStringList secs(GkConfig()->GetSections());
				PString result = "Config sections\r\n";
				for (PINDEX i = 0; i < secs.GetSize(); i++)
					result += "[" + secs[i] + "]\r\n";
				WriteString(result);
			}
		} else if ((Args[1] *= "set") && (Args.GetSize()>=5)) {
			Toolkit::Instance()->SetConfig(1, Args[2], Args[3], Args[4]);
			WriteString(GkConfig()->GetString(Args[2],Args[3],"") + "\r\n");
		} else if (Args[1] *= "remove") {
			if (Args.GetSize()>=4) {
				Toolkit::Instance()->SetConfig(2, Args[2], Args[3]);
				WriteString("Remove " + Args[3] + " in section " + Args[2] + "\r\n");
			} else if (Args.GetSize()>=3) {
				Toolkit::Instance()->SetConfig(3, Args[2]);
				WriteString("Remove section " + Args[2] + "\r\n");
			}
		} else if ((Args[1] *= "printrm")) {
			SoftPBX::PrintRemoved(this, (Args.GetSize() >= 3));
		} else {
			WriteString("Unknown debug command!\r\n");
		}
	}
}

bool StatusClient::CheckRule(const PString & rule)
{
	PIPSocket::Address PeerAddress;
	GetPeerAddress(PeerAddress);
	const PString peer = PeerAddress.AsString();

	PTRACE(5, "Auth client rule=" << rule);
	bool result = false;
	if (rule *= "forbid") { // "*=": case insensitive
		result =  false;
	} else if (rule *= "allow") {
		result =  true;
	} else if (rule *= "explicit") {
		PString val = GkConfig()->GetString(authsec, peer, "");
		if (val.IsEmpty()) { // use "default" entry
			PTRACE(5,"Auth client rule=explicit, ip-param not found, using default");
			result = Toolkit::AsBool(GkConfig()->GetString(authsec, "default", "FALSE"));
		} else 
			result = Toolkit::AsBool(val);
	} else if (rule *= "regex") {
		PString val = GkConfig()->GetString(authsec, peer, "");
		if (val.IsEmpty()) {
			PTRACE(5,"Auth client rule=regex, ip-param not found, using regex");
			result = Toolkit::MatchRegex(peer, GkConfig()->GetString(authsec, "regex", ""));
		} else
			result = Toolkit::AsBool(val);
	} else if (rule *= "password") {
		result = AuthenticateUser();
	} else {
		PTRACE(1, "Warning: Invalid [GkStatus::Auth].rule");
	}
	return result;
}

bool StatusClient::AuthenticateUser()
{
	PTime now;
	int Delay = GkConfig()->GetInteger(authsec, "DelayReject", 0);
	int LoginTimeout = GkConfig()->GetInteger(authsec, "LoginTimeout", 120) * 1000;

	for (int retries = 0; retries < 3; ++retries) {
		PString UserName, Password;
		WriteString("\r\n" + Toolkit::GKName() + " login: ");
		if (!ReadCommand(UserName, true, LoginTimeout))
			break;
		UserName = UserName.Trim();

		SendWill(PTelnetSocket::EchoOption);
		WriteString("Password: ");
		if (!ReadCommand(Password, false, LoginTimeout))
			break;
		Password = Password.Trim();
		WriteString("\r\n", 1);

		SendWont(PTelnetSocket::EchoOption);
		if (!Password && Password == GetPassword(UserName)) {
			m_user = UserName;
			PTRACE(1, "Status\tAuth: user " << UserName << " logged in");
			return true;
		}
		PProcess::Sleep(Delay * 1000);

		if ((PTime() - now) > LoginTimeout)
			break;
	}
	return false;
}

PString StatusClient::GetPassword(const PString & UserName) const
{
	int filled = GkConfig()->GetInteger(authsec, "KeyFilled", 0);
	return Toolkit::CypherDecode(UserName, GkConfig()->GetString(authsec, UserName, ""), filled);
}

void StatusClient::ExecCommand(PString cmd)
{
	PStringArray Args;
	switch (m_gkStatus->ParseCommand(cmd, Args))
	{
		case GkStatus::e_DisconnectIp:
			// disconnect call on this IP number
			if (Args.GetSize() == 2)
				SoftPBX::DisconnectIp(Args[1]);
			else
				WriteString("Syntax Error: DisconnectIp <ip address>\r\n");
			break;
		case GkStatus::e_DisconnectAlias:
			// disconnect call on this alias
			if (Args.GetSize() == 2)
				SoftPBX::DisconnectAlias(Args[1]);
			else
				WriteString("Syntax Error: DisconnectAlias <h.323 alias>\r\n");
			break;
		case GkStatus::e_DisconnectCall:
			// disconnect call with this call number
			if (Args.GetSize() >= 2)
				for (PINDEX p=1; p < Args.GetSize(); ++p)
					SoftPBX::DisconnectCall(Args[p].AsInteger());
			else
				WriteString("Syntax Error: DisconnectCall <call number> ...\r\n");
			break;
		case GkStatus::e_DisconnectEndpoint:
			// disconnect call on this alias
			if (Args.GetSize() == 2)
				SoftPBX::DisconnectEndpoint(Args[1]);
			else
				WriteString("Syntax Error: DisconnectEndpoint ID\r\n");
			break;
		case GkStatus::e_DisconnectSession:
			// disconnect a user from status port
			if (Args.GetSize() == 2)
				if (m_gkStatus->DisconnectSession(Args[1].AsInteger(), this))
					WriteString("Session " + Args[1] + " disconnected\r\n");
				else
					WriteString("Session " + Args[1] + " not found\r\n");
			else
				WriteString("Syntax Error: DisconnectSession SessionID\r\n");
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
			SoftPBX::PrintAllCached(this, (Args.GetSize() > 1));
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
			if (Args.GetSize() == 2)
				SoftPBX::PrintEndpoint(Args[1], this, FALSE);
			else
				WriteString("Syntax Error: Find alias\r\n");
			break;
		case GkStatus::e_FindVerbose:
			if (Args.GetSize() == 2)
				SoftPBX::PrintEndpoint(Args[1], this, TRUE);
			else
				WriteString("Syntax Error: FindVerbose alias\r\n");
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
			DoDebug(Args);
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
			if (Args.GetSize() == 2)
				SoftPBX::UnregisterAlias(Args[1]);
			else
				WriteString("Syntax Error: UnregisterAlias Alias\r\n");
			break;
		case GkStatus::e_UnregisterIp:
			// unregister this IP
			if (Args.GetSize() == 2)
				SoftPBX::UnregisterIp(Args[1]);
			else
				WriteString("Syntax Error: UnregisterIp <ip addr>\r\n");
			break;
		case GkStatus::e_TransferCall:
			if (Args.GetSize() == 3)
				SoftPBX::TransferCall(Args[1], Args[2]);
			else
				WriteString("Syntax Error: TransferCall Source Destination\r\n");
			break;
		case GkStatus::e_MakeCall:
			if (Args.GetSize() == 3)
				SoftPBX::MakeCall(Args[1], Args[2]);
			else
				WriteString("Syntax Error: MakeCall Source Destination\r\n");
			break;
		case GkStatus::e_Reload:
			ReloadHandler();
			PTRACE(3, "GK\tConfig reloaded.");
			m_gkStatus->SignalStatus("Config reloaded.\r\n");
			break;
		case GkStatus::e_Shutdown:
			if (!Toolkit::AsBool(GkConfig()->GetString(authsec, "Shutdown", "1"))) {
				WriteString("Not allowed!\r\n");
				break;
			}
			SoftPBX::PrintStatistics(this, true);
			RasServer::Instance()->Stop();
			break;
		case GkStatus::e_RouteToAlias:
			if (Args.GetSize() == 4) {
				RasServer::Instance()->GetVirtualQueue()->RouteToAlias(Args[1], Args[2], Args[3].AsUnsigned());
			} else
				WriteString("Syntax Error: RouteToAlias <target agent> <calling endpoint ID> <callRef>\r\n");
			break;
		case GkStatus::e_RouteReject:
			if (Args.GetSize() == 3) {
				RasServer::Instance()->GetVirtualQueue()->RouteReject(Args[1], Args[2].AsUnsigned());
			} else
				WriteString("Syntax Error: RouteReject <calling endpoint ID> <callRef>\r\n");
			break;
		default:
			// commmand not recognized
			WriteString("Error: Unknown Command " + cmd + "\r\n");
			PTRACE(3, "Status\tUnknown Command " << cmd);
			break;
	}
	PWaitAndSignal lock(m_cmutex);
	--m_executedCmd;
}


// class StatusListener
StatusListener::StatusListener(const Address & addr, WORD pt)
{
	unsigned queueSize = GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH);
	Listen(addr, queueSize, pt);
	SetName(AsString(addr, GetPort()));
}

ServerSocket *StatusListener::CreateAcceptor() const
{
	static int StaticInstanceNo = 0;
	return new StatusClient(++StaticInstanceNo);
}
