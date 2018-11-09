//////////////////////////////////////////////////////////////////
//
// yasocket.h
//
// Copyright (c) Citron Network Inc. 2002-2003
// Copyright (c) 2004-2018, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef YASOCKET_H
#define YASOCKET_H "@(#) $Id$"

#include "config.h"
#include <list>
#include <vector>
#include <ptlib/sockets.h>
#include "job.h"

#ifdef LARGE_FDSET

// yet another socket class to replace PSocket (Unix only)

class YaSocket : public NamedObject {
public:
	typedef PIPSocket::Address Address;

	YaSocket();
	virtual ~YaSocket();

	int GetHandle() const { return os_handle; }
	bool IsOpen() const { return os_handle > 0; }
	bool Close();

	void SetReadTimeout(const PTimeInterval & time) { readTimeout = time; }
	virtual bool Read(void * buf, int sz, bool wantZeroReads = false);
	virtual int GetLastReadCount() const { return lastReadCount; }

	void SetWriteTimeout(const PTimeInterval & time) { writeTimeout = time; }
	virtual bool Write(const void * buf, int sz);
	virtual int GetLastWriteCount() const { return lastWriteCount; }

	void SetPort(WORD pt) { port = pt; }
	WORD GetPort() const { return port; }
	virtual PBoolean GetLocalAddress(Address &) const;
	virtual PBoolean GetLocalAddress(Address &, WORD &) const;
	bool SetOption(int, int, int = SOL_SOCKET);
	bool SetOption(int, const void *, int, int = SOL_SOCKET);
	bool GetOption(int, int &, int = SOL_SOCKET);
	bool GetOption(int, void *, PINDEX, int);

	PSocket::Errors GetErrorCode(PSocket::ErrorGroup group) const { return lastErrorCode[group]; }
	int GetErrorNumber(PSocket::ErrorGroup group) const { return lastErrorNumber[group]; }
	PString GetErrorText(PSocket::ErrorGroup) const;
	bool ConvertOSError(int libReturnValue, PSocket::ErrorGroup = PSocket::LastGeneralError);

	virtual bool CanRead(long timeout) const;
	virtual bool CanWrite(long timeout) const;

protected:
	virtual int os_recv(void *, int) = 0;
	virtual int os_send(const void *, int) = 0;
	bool SetNonBlockingMode();
	bool Bind(const Address &, WORD);

private:
	YaSocket(const YaSocket &);
	YaSocket & operator=(const YaSocket &);

protected:
	int os_handle;
	int lastReadCount, lastWriteCount;
	WORD port;

	PTimeInterval readTimeout, writeTimeout;

	PSocket::Errors lastErrorCode[PSocket::NumErrorGroups];
	int lastErrorNumber[PSocket::NumErrorGroups];
};

class YaTCPSocket : public YaSocket {
public:
	YaTCPSocket(WORD pt = 0);
	virtual ~YaTCPSocket() { }

	void GetPeerAddress(Address &) const;
	void GetPeerAddress(Address &, WORD &) const;

	bool SetLinger();
	bool Listen(unsigned, WORD, PSocket::Reusability reuse = PSocket::AddressIsExclusive);
	bool Listen(const Address &, unsigned, WORD, PSocket::Reusability reuse = PSocket::AddressIsExclusive);

#ifdef hasIPV6
	bool DualStackListen(WORD port);
#endif

	// new virtual function
	virtual bool Accept(YaTCPSocket &);
	virtual bool Connect(const Address &, WORD, const Address &);
	virtual bool Connect(const Address &);

protected:
	// override from class YaSocket
	virtual int os_recv(void *, int);
	virtual int os_send(const void *, int);

private:
	YaTCPSocket(const YaTCPSocket &);
	YaTCPSocket & operator=(const YaTCPSocket &);

protected:
#ifdef hasIPV6
	sockaddr_in6 peeraddr;
#else
	sockaddr_in peeraddr;
#endif
};

class YaUDPSocket : public YaSocket, public PObject {
public:
	YaUDPSocket(WORD port = 0, int iAddressFamily = AF_INET);

	bool Listen(unsigned, WORD, PSocket::Reusability reuse = PSocket::AddressIsExclusive);
	bool Listen(const Address &, unsigned, WORD, PSocket::Reusability reuse = PSocket::AddressIsExclusive);
#ifdef hasIPV6
	bool DualStackListen(const Address & localAddr, WORD port);
#endif
	void GetLastReceiveAddress(Address &, WORD &) const;
	void SetSendAddress(const Address &, WORD);
	/// Get the address to use for connectionless Write().
	void GetSendAddress(
		Address & address, /// IP address to send packets.
		WORD & port /// Port to send packets.
		);

	virtual bool ReadFrom(void *, PINDEX, Address &, WORD);
	virtual bool WriteTo(const void *, PINDEX, const Address &, WORD);

protected:
	// override from class YaSocket
	virtual int os_recv(void *, int);
	virtual int os_send(const void *, int);

private:
	YaUDPSocket(const YaUDPSocket &);
	YaUDPSocket & operator=(const YaUDPSocket &);

private:
#ifdef hasIPV6
	sockaddr_in6 recvaddr, sendaddr;
#else
	sockaddr_in recvaddr, sendaddr;
#endif
};

class YaSelectList {
public:
	typedef std::vector<YaSocket *>::iterator iterator;
	typedef std::vector<YaSocket *>::const_iterator const_iterator;

	/// build a select list for more than one socket
	YaSelectList(
		/// estimated number of sockets to be put in this select list
		size_t reserve = 512
	) : maxfd(0) { fds.reserve(reserve); }

	/// build a select list for more than one socket
	YaSelectList(
		/// name for this select list
		const PString & name,
		/// estimated number of sockets to be put in this select list
		size_t reserve = 512
	) : maxfd(0), m_name(name) { fds.reserve(reserve); }

	/// build a select list for single socket only
	YaSelectList(
		YaSocket * singleSocket /// socket to be put on the list
		) : fds(1, singleSocket), maxfd(singleSocket->GetHandle()) { }

	/// build a select list for single socket only
	YaSelectList(
		/// name for this select list
		const PString & name,
		YaSocket* singleSocket /// socket to be put on the list
		) : fds(1, singleSocket), maxfd(singleSocket->GetHandle()), m_name(name) { }

	void Append(
		YaSocket * s /// the socket to be appended
		)
	{
		if (s && s->IsOpen()) {
			fds.push_back(s);
			if (s->GetHandle() > maxfd)
				maxfd = s->GetHandle();
		}
	}

	bool IsEmpty() const { return fds.empty(); }
	int GetSize() const { return fds.size(); }
	YaSocket * operator[](int i) const { return fds[i]; }

	enum SelectType {
		Read,
		Write
	};

	bool Select(SelectType, const PTimeInterval &);

	struct large_fd_set {
		large_fd_set() { memset(this, 0, sizeof(large_fd_set)); }
		void add(int fd) { if (fd >= 0 && fd < LARGE_FDSET) FD_SET(fd, &__fdset__); }
		bool has(int fd) { return (fd >= 0 && fd < LARGE_FDSET) ? FD_ISSET(fd, &__fdset__) : false; }
		operator fd_set *() { return &__fdset__; }

		union {
			fd_set __fdset__;
			char __mem__[LARGE_FDSET / 8];
		};
	};

	PString GetName() const { return m_name; }

private:
	std::vector<YaSocket *> fds;
	int maxfd;
	PString m_name;
};

typedef YaSelectList SocketSelectList;
typedef YaSocket IPSocket;
typedef YaTCPSocket TCPSocket;
typedef YaUDPSocket UDPSocket;

#else // not LARGE_FDSET

class SocketSelectList : public PSocket::SelectList {
public:
	enum SelectType {
		Read,
		Write
	};
	SocketSelectList(size_t) { }
	SocketSelectList(PIPSocket * s = NULL) { if (s && s->IsOpen()) Append(s); }
	SocketSelectList(const PString & name, size_t) : m_name(name) { }
	SocketSelectList(const PString & name, PIPSocket * s = NULL) : m_name(name) { if (s && s->IsOpen()) Append(s); }
	bool Select(SelectType, const PTimeInterval &);
	PSocket *operator[](int i) const;

	PString GetName() const { return m_name; }

private:
	PString m_name;
};

typedef PIPSocket IPSocket;

class TCPSocket : public PTCPSocket, public NamedObject {
public:
	PCLASSINFO(TCPSocket, PTCPSocket)
	TCPSocket(WORD pt = 0) : PTCPSocket(pt) { }
	virtual ~TCPSocket() { }

	// override from class PIPSocket
	PString GetName() const { return (const char *)NamedObject::GetName(); }

#ifdef hasIPV6
	bool DualStackListen(WORD port);
#endif

private:
	TCPSocket(const TCPSocket &);
	TCPSocket & operator=(const TCPSocket &);
};

class UDPSocket : public PUDPSocket, public NamedObject {
public:
	PCLASSINFO(UDPSocket, PUDPSocket)

	UDPSocket(WORD port = 0, int iAddressFamily = AF_INET);
	virtual ~UDPSocket() { }

	// override from class PIPSocket
	PString GetName() const { return (const char *)NamedObject::GetName(); }

#ifdef hasIPV6
	bool DualStackListen(const PIPSocket::Address & localAddr, WORD port);
#endif

private:
	UDPSocket(const UDPSocket &);
	UDPSocket & operator=(const UDPSocket &);
};

#endif // LARGE_FDSET


// abstract interface of utilities of a socket
class USocket {
public:
	USocket(IPSocket *, const char *);
	virtual ~USocket() = 0; // abstract class

	const char* Type() const { return type; }
#ifdef LARGE_FDSET
	const PString & Name() const { return self->GetName(); }
#else
	PString Name() const { return self->GetName(); }
#endif

	// new virtual function
	virtual bool TransmitData(const PString &);
	virtual bool TransmitData(const PBYTEArray &);
	virtual bool TransmitData(const BYTE *, int);

	bool IsSocketOpen() const { return self->IsOpen(); }
	bool CloseSocket() { return IsSocketOpen() ? self->Close() : false; }

	virtual bool Flush();
	bool CanFlush() const { return (qsize > 0) && IsSocketOpen(); }

	bool IsBlocked() const { return blocked; }
	void MarkBlocked(bool b) { blocked = b; }

	class MarkSocketBlocked {
	public:
		MarkSocketBlocked(USocket * _s) : s(_s) { s->MarkBlocked(true); }
		~MarkSocketBlocked() { s->MarkBlocked(false); }

	private:
		USocket * s;
	};

#ifdef LARGE_FDSET
	bool IsReadable(long timeout = 0) { return self->CanRead(timeout); }
	bool IsWriteable(long timeout = 0) { return self->CanWrite(timeout); }
#else
	bool IsReadable(int milisec = 0)
	{
		return self->IsOpen() && SocketSelectList(self).Select(SocketSelectList::Read, milisec);
	}

	bool IsWriteable(int milisec = 0)
	{
		return self->IsOpen() && SocketSelectList(self).Select(SocketSelectList::Write, milisec);
	}
#endif

	IPSocket * Self() const { return self; }

protected:
	virtual bool WriteData(const BYTE *, int);
	bool InternalWriteData(const BYTE *, int);

	int GetQueueSize() const { return qsize; }
	void QueuePacket(const BYTE * buf, int len)
	{
		queueMutex.Wait();
		queue.push_back(new PBYTEArray(buf, len));
		++qsize;
		queueMutex.Signal();
	}
	PBYTEArray * PopQueuedPacket()
	{
		PBYTEArray * packet = NULL;
		queueMutex.Wait();
		if (!queue.empty()) {
			packet = queue.front();
			queue.pop_front();
			--qsize;
		}
		queueMutex.Signal();
		return packet;
	}
	void ClearQueue();

	virtual bool ErrorHandler(PSocket::ErrorGroup);

	IPSocket * self;

private:
	USocket();
	USocket(const USocket &);
	USocket & operator=(const USocket &);

private:
	std::list<PBYTEArray *> queue;
	int qsize;
	bool blocked;
	PTimedMutex writeMutex, queueMutex;
	const char * type;
};

class SocketsReader : public RegularJob {
public:
	SocketsReader(int selectTimeout = 1000);
	virtual ~SocketsReader();

	// override from class RegularJob
	virtual void Stop();

	// override from class Task
	virtual void Exec();

protected:
	// the derived classes should provide new interface to add sockets
	void AddSocket(IPSocket *);

	// new virtual function

	// build a list of sockets for selecting
	// return true if the list is not empty
	// default behavior: put all sockets into the list
	virtual bool BuildSelectList(SocketSelectList &);

	// read data from the specified socket
	virtual void ReadSocket(IPSocket *) = 0;

	// clean up routine
	// default behavior: delete sockets in m_removed
	virtual void CleanUp();

	bool SelectSockets(SocketSelectList &);

	typedef std::list<IPSocket *>::iterator iterator;
	typedef std::list<IPSocket *>::const_iterator const_iterator;

	// remove closed sockets
	void RemoveClosed(bool);

private:
	SocketsReader(const SocketsReader &);
	SocketsReader & operator=(const SocketsReader &);

protected:
	PTimeInterval m_timeout;
	std::list<IPSocket *> m_sockets, m_removed;
	// keep the size of list since list::size() is not thread-safe
	volatile int m_socksize;
	volatile int m_rmsize;
	mutable PReadWriteMutex m_listmutex;
	mutable PMutex m_rmutex;
};

class ServerSocket : public TCPSocket {
#ifndef LARGE_FDSET
	PCLASSINFO ( ServerSocket, TCPSocket )
#endif
public:
	ServerSocket(WORD pt = 0) : TCPSocket(pt) { }
	virtual ~ServerSocket() { }

	// new virtual function

	// dispatch this socket to an appropriate handler
	virtual void Dispatch() = 0;

private:
	ServerSocket(const ServerSocket &);
	ServerSocket & operator=(const ServerSocket &);
};

class TCPListenSocket : public TCPSocket {
#ifndef LARGE_FDSET
	PCLASSINFO ( TCPListenSocket, TCPSocket )
#endif
public:
	TCPListenSocket(int seconds = 0);
	virtual ~TCPListenSocket();

	bool IsTimeout(const PTime *) const;

	// new virtual function

	// create an appropriate socket to accept the request
	virtual ServerSocket *CreateAcceptor() const = 0;

private:
	TCPListenSocket(const TCPListenSocket &);
	TCPListenSocket & operator=(const TCPListenSocket &);

private:
	PTime start;
};

class TCPServer : public SocketsReader {
public:
	TCPServer();

	// read config settings
	void LoadConfig();

	// add a TCP listener
	void AddListener(TCPListenSocket * socket) { AddSocket(socket); }

	// since listeners may be closed and deleted unexpectedly,
	// the method provides a thread-safe way to close a listener
	bool CloseListener(TCPListenSocket *socket);

private:
	TCPServer(const TCPServer &);
	TCPServer & operator=(const TCPServer &);

	// override from class SocketsReader
	virtual void ReadSocket(IPSocket *);
	virtual void CleanUp();

private:
	// rate limiting
	unsigned int cps_limit;	// max cps per one sec
	unsigned int check_interval; // number of sec. to check if cps_limit applies
	std::list<time_t> one_sec;
	std::list<time_t> many_sec;
};

#endif // YASOCKET_H
