//////////////////////////////////////////////////////////////////
//
// yasocket.h
//
// Copyright (c) Citron Network Inc. 2002-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chin-Wei Huang <cwhuang@linux.org.tw>
// initial version: 03/14/2003
//
//////////////////////////////////////////////////////////////////

#ifndef YASOCKET_H
#define YASOCKET_H "@(#) $Id$"

#include <list>
#include <vector>
#include "job.h"

//#define LARGE_FDSET 32768
#ifdef LARGE_FDSET

// yet another socket class to replace PSocket

class YaSocket : public NamedObject {
public:
	typedef PIPSocket::Address Address;

	YaSocket();
	virtual ~YaSocket();

	int GetHandle() const { return os_handle; }
	bool IsOpen() const { return os_handle > 0; }
	bool Close();

	void SetReadTimeout(const PTimeInterval & time) { readTimeout = time; }
	bool Read(void *, int);
	bool ReadBlock(void *, int);
	int GetLastReadCount() const { return lastReadCount; }

	void SetWriteTimeout(const PTimeInterval & time) { writeTimeout = time; }
	bool Write(const void *, int);
	int GetLastWriteCount() const { return lastWriteCount; }

	void SetPort(WORD pt) { port = pt; }
	WORD GetPort() const { return port; }
	void GetLocalAddress(Address &) const;
	void GetLocalAddress(Address &, WORD &) const;
	bool SetOption(int, int, int = SOL_SOCKET);
	bool SetOption(int, const void *, int, int = SOL_SOCKET);

	PSocket::Errors GetErrorCode(PSocket::ErrorGroup group) const { return lastErrorCode[group]; }
	int GetErrorNumber(PSocket::ErrorGroup group) const { return lastErrorNumber[group]; }
	PString GetErrorText(PSocket::ErrorGroup) const;
	bool ConvertOSError(int libReturnValue, PSocket::ErrorGroup = PSocket::LastGeneralError);

protected:
	virtual int os_recv(void *, int) = 0;
	virtual int os_send(const void *, int) = 0;
	bool SetNonBlockingMode();
	bool Bind(const Address &, WORD);

	int os_handle;
	int lastReadCount, lastWriteCount;
	WORD port;

	PTimeInterval readTimeout, writeTimeout;

	PSocket::Errors lastErrorCode[PSocket::NumErrorGroups];
	int lastErrorNumber[PSocket::NumErrorGroups];
};

class YaTCPSocket : public YaSocket {
public:
	YaTCPSocket(WORD = 0);

	void GetPeerAddress(Address &) const;
	void GetPeerAddress(Address &, WORD &) const;

	bool SetLinger();
	bool Listen(unsigned, WORD);
	bool Listen(const Address &, unsigned, WORD);

	// new virtual function
	virtual bool Accept(YaTCPSocket &);
	virtual bool Connect(const Address &, WORD, const Address &);
	virtual bool Connect(const Address &);

protected:
	sockaddr_in peeraddr;

private:
	// override from class YaSocket
	virtual int os_recv(void *, int);
	virtual int os_send(const void *, int);
};

class YaUDPSocket : public YaSocket {
public:
	YaUDPSocket();

	bool Listen(unsigned, WORD);
	bool Listen(const Address &, unsigned, WORD, int);
	void GetLastReceiveAddress(Address &, WORD &) const;
	void SetSendAddress(const Address &, WORD);

	virtual bool ReadFrom(void *, PINDEX, Address &, WORD);
	virtual bool WriteTo(const void *, PINDEX, const Address &, WORD);

private:
	// override from class YaSocket
	virtual int os_recv(void *, int);
	virtual int os_send(const void *, int);

	sockaddr_in recvaddr, sendaddr;
};

class YaSelectList {
public:
	typedef std::vector<YaSocket *>::iterator iterator;
	typedef std::vector<YaSocket *>::const_iterator const_iterator;

	YaSelectList(YaSocket * = 0);

	void Append(YaSocket *);

	bool IsEmpty() const { return fds.empty(); }
	int GetSize() const { return fds.size(); }
	YaSocket *operator[](int i) const { return fds[i]; }

	enum SelectType {
		Read,
		Write
	};

	bool Select(SelectType, const PTimeInterval &);

	struct large_fd_set {
		large_fd_set() { memset(this, 0, sizeof(large_fd_set)); }
		void add(int fd) { if (fd > 0) FD_SET(fd, &__fdset__); }
		bool has(int fd) { return (fd > 0) ? FD_ISSET(fd, &__fdset__) : false; }
		operator fd_set *() { return &__fdset__; }

		union {
			fd_set __fdset__;
			char __mem__[LARGE_FDSET / 8];
		};
	};

private:
	std::vector<YaSocket *> fds;
	int maxfd;
};

typedef YaSelectList SocketSelectList;
typedef YaSocket IPSocket;
typedef YaTCPSocket TCPSocket;
typedef YaUDPSocket UDPSocket;

#else

class SocketSelectList : public PSocket::SelectList {
public:
	enum SelectType {
		Read,
		Write
	};
	SocketSelectList(PIPSocket *s = 0);
	bool Select(SelectType, const PTimeInterval &);
	PSocket *operator[](int i) const;
};

typedef PIPSocket IPSocket;

class TCPSocket : public PTCPSocket, public NamedObject {
public:
	PCLASSINFO( TCPSocket, PTCPSocket )
	TCPSocket(WORD pt = 0) : PTCPSocket(pt) {}
	// override from class PIPSocket
        PString GetName() const { return (const char *)NamedObject::GetName(); }
};

class UDPSocket : public PUDPSocket, public NamedObject {
public:
	PCLASSINFO( UDPSocket, PUDPSocket )
	// override from class PIPSocket
        PString GetName() const { return (const char *)NamedObject::GetName(); }
};

#endif // LARGE_FDSET


// abstract interface of utilities of a socket
class USocket {
public:
	USocket(IPSocket *, const char *);
	virtual ~USocket() = 0; // abstract class

	const char *Type() const { return type; }
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

	bool Flush();
	bool CanFlush() const { return (qsize > 0) && IsSocketOpen(); }

	bool IsBlocked() const { return blocked; }
	void MarkBlocked(bool b) { blocked = b; }

	class MarkSocketBlocked {
	public:
		MarkSocketBlocked(USocket *_s) : s(_s) { s->MarkBlocked(true); }
		~MarkSocketBlocked() { s->MarkBlocked(false); }

	private:
		USocket *s;
	};

	bool IsReadable(int = 0);
	bool IsWriteable(int = 0);

protected:
	bool WriteData(const BYTE *, int);
	bool ErrorHandler(PSocket::ErrorGroup);

	IPSocket *self;

private:
	bool InternalWriteData(const BYTE *, int);

	std::list<PBYTEArray *> queue;
	int qsize;

	bool blocked;
	PMutex writeMutex, queueMutex;
	const char *type;
};

class SocketsReader : public RegularJob {
public:
	SocketsReader(int = 1000);
	~SocketsReader();

	// override from class RegularJob
	virtual void Stop();

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
	// for historical reason, assume the list has been locked
	void RemoveSocket(iterator);
	void RemoveSocket(IPSocket *);

	PTimeInterval m_timeout;
	std::list<IPSocket *> m_sockets, m_removed;
	// keep the size of list since list::size() is not thread-safe
	int m_socksize, m_rmsize;
	mutable PReadWriteMutex m_listmutex;
	mutable PMutex m_rmutex;

private:
	// override from class Task
	virtual void Exec();
};

class ServerSocket : public TCPSocket {
#ifndef LARGE_FDSET
	PCLASSINFO ( ServerSocket, TCPSocket )
#endif
public:
	ServerSocket(WORD pt = 0) : TCPSocket(pt) {}

	// new virtual function

	// dispatch this socket to an appropriate handler
	virtual void Dispatch() = 0;
};

class TCPListenSocket : public TCPSocket {
#ifndef LARGE_FDSET
	PCLASSINFO ( TCPListenSocket, TCPSocket )
#endif
public:
	TCPListenSocket::TCPListenSocket(int seconds = 0);
	~TCPListenSocket();

	bool IsTimeout(const PTime *) const;

	// new virtual function

	// create an appropriate socket to accept the request
	virtual ServerSocket *CreateAcceptor() const = 0;

private:
	PTime start;
};

class TCPServer : public SocketsReader {
public:
	TCPServer();

	// add a TCP listener
	void AddListener(TCPListenSocket *socket) { AddSocket(socket); }

	// since listeners may be closed and deleted unexpectedly,
	// the method provides a thread-safe way to close a listener
	bool CloseListener(TCPListenSocket *socket);

private:
	// override from class SocketsReader
	virtual void ReadSocket(IPSocket *);
	virtual void CleanUp();
};

#endif // YASOCKET_H
