// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// ProxyThread.h
//
// Copyright (c) Citron Network Inc. 2001-2002
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chin-Wei Huang <cwhuang@linux.org.tw>
// initial version: 12/7/2001
//
//////////////////////////////////////////////////////////////////

#ifndef __proxythread_h__
#define __proxythread_h__

#include "rwlock.h"
#include <list>
#include <vector>
#include <ptlib.h>
#include <ptlib/sockets.h>


class ProxySocket;
class ProxyListener;
class ProxyConnectThread;
class ProxyHandleThread;
class HandlerList;

extern const char *RoutedSec;

// abstract interface of a proxy socket
class ProxySocket {
public:
	enum Result {
		NoData,
		Connecting,
		Forwarding,
		Closing,
		Error
	};

	ProxySocket(PIPSocket *, const char *);
	virtual ~ProxySocket() =0; // abstract class
	PString Name() const { return name; }

	virtual Result ReceiveData();
	virtual bool ForwardData() { return WriteData(self); }
	virtual bool TransmitData() { return WriteData(self); }
	virtual bool EndSession();

	bool IsSocketOpen() const { return self->IsOpen(); }
	bool CloseSocket() { return IsSocketOpen() ? self->Close() : false; }

	bool Flush();
	bool CanFlush() const;
	bool IsBlocked() const { return blocked; }
	void MarkBlocked(bool b) { blocked = b; }
	bool IsConnected() const { return connected; }
	void SetConnected(bool c) { connected = c; }
	bool IsDeletable() const { return deletable; }
	void SetDeletable() { deletable = true; }
	ProxyHandleThread *GetHandler() const { return handler; }
	void SetHandler(ProxyHandleThread *h) { handler = h; }

	void AddToSelectList(PSocket::SelectList &);

protected:
	bool WriteData(PIPSocket *);
	void InternalCleanup();
	bool SetMinBufSize(WORD);
	bool ErrorHandler(PSocket *, PChannel::ErrorGroup);
	void SetName(PIPSocket::Address ip, WORD pt);

	PIPSocket *self;
	PIPSocket *wsocket;
	WORD maxbufsize, buflen;
	BYTE *wbuffer, *bufptr;
	PString name;
	const char *type;

private:
	ProxyHandleThread *handler;
	bool blocked;
	bool connected;
	bool deletable;
};

class TCPProxySocket : public PTCPSocket, public ProxySocket {
public:
	PCLASSINFO( TCPProxySocket, PTCPSocket )

	TCPProxySocket(const char * , TCPProxySocket * = 0, WORD = 0);
	virtual ~TCPProxySocket();

	// override from class ProxySocket
	virtual bool ForwardData();
	virtual bool TransmitData();

	// override from class PTCPSocket
	virtual BOOL Accept(PSocket &);
	virtual BOOL Connect(WORD, const Address &);
//	BOOL WriteAsync( const void * buf, PINDEX len );
//	void OnWriteComplete( const void * buf, PINDEX len );

	// new virtual function
	virtual TCPProxySocket *ConnectTo() = 0;
////    PROTECTED
	TCPProxySocket *remote;

protected:
	bool ReadTPKT();

	PBYTEArray buffer;

private:
	bool InternalWrite();
	void SetName();
};

class MyPThread : public PThread {
public:
	PCLASSINFO ( MyPThread, PThread )

	MyPThread();
	virtual ~MyPThread() {}

	virtual void Close();
	virtual void Exec() = 0;

	bool Wait();
	void Go();
	void Main();

	bool Destroy();

protected:
	PSyncPoint sync;
	bool isOpen;
};

class ProxyListener : public MyPThread {
public:
	PCLASSINFO ( ProxyListener, MyPThread )

	ProxyListener(HandlerList *, PIPSocket::Address, WORD, unsigned);
	virtual ~ProxyListener();
	virtual bool Open(unsigned);

	// override from class MyPThread
	virtual void Close();
	virtual void Exec();

	WORD GetPort() const { return m_port; }

protected:
	PTCPSocket *m_listener;
	PIPSocket::Address m_interface;
	WORD m_port;

private:
	TCPProxySocket *CreateSocket();

	HandlerList *m_handler;
};

class ProxyHandleThread : public MyPThread {
public:
	PCLASSINFO ( ProxyHandleThread, MyPThread )

	typedef std::list<ProxySocket *>::iterator iterator;
        typedef std::list<ProxySocket *>::const_iterator const_iterator;
	typedef std::list<ProxyConnectThread *>::iterator citerator;
        typedef std::list<ProxyConnectThread *>::const_iterator const_citerator;

	ProxyHandleThread() : lcHandler(0) {}
	ProxyHandleThread(PINDEX);
	virtual ~ProxyHandleThread();

	void Insert(ProxySocket *);
	void InsertLC(ProxySocket *socket) { lcHandler->Insert(socket); }
	void Remove(iterator);
	void Remove(ProxySocket *socket);
	void SetID(const PString & i) { id = i; }
	void ConnectTo(ProxySocket *);
	bool CloseUnusedThreads();

	// override from class MyPThread
	virtual void Exec();

private:
	void FlushSockets();
	void RemoveSockets();
	void BuildSelectList(PSocket::SelectList &);
	ProxyConnectThread *FindConnectThread();

	std::list<ProxySocket *> sockList;
	std::list<ProxySocket *> removedList;
	mutable PReadWriteMutex mutex;
	PMutex removedMutex;
	std::list<ProxyConnectThread *> connList;
	mutable PReadWriteMutex connMutex;
	ProxyHandleThread *lcHandler;
	PString id;

	static void delete_socket(ProxySocket *s) { PTRACE(5, "deleteSocket: " << s->Name()); delete s; }
};

class HandlerList {
public:
	HandlerList(PIPSocket::Address = INADDR_ANY);
	~HandlerList();

	void LoadConfig();
	void Insert(ProxySocket *);
	void Check();

	WORD GetCallSignalPort() const { return listenerThread->GetPort(); }

private:
	void CloseListener();
	static void close_threads(ProxyHandleThread *t) { t->CloseUnusedThreads(); }

	std::vector<ProxyHandleThread *> handlers;
	ProxyListener *listenerThread;
	PINDEX currentHandler;
	PMutex mutex;
	PIPSocket::Address GKHome;
	WORD GKPort;

	static void delete_thread(MyPThread *t) { delete t; }
};


inline bool ProxySocket::CanFlush() const
{
	return (wsocket && wsocket->IsOpen());
}

inline void ProxySocket::AddToSelectList(PSocket::SelectList & slist)
{
	slist.Append(self);
}

inline void ProxySocket::InternalCleanup()
{
	wsocket = 0;
	buflen = 0;
	blocked = false;
}

inline void ProxySocket::SetName(PIPSocket::Address ip, WORD pt)
{
	name = ip.AsString() + PString(PString::Printf, ":%u", pt);
}

inline bool MyPThread::Wait()
{
	ReadUnlock unlock(ConfigReloadMutex);
	sync.Wait();
	return isOpen;
}

inline void MyPThread::Go()
{
	if (sync.WillBlock())
		sync.Signal();
}

inline void ProxyHandleThread::Remove(ProxySocket *socket)
{
	PWaitAndSignal lock(removedMutex);
	PTRACE(5, "Removing: " << socket << " : " << socket->Name());
	removedList.push_back(socket);
	sockList.remove(socket);
}

#ifdef WIN32
inline DWORD getpid()
{
       return GetCurrentThreadId();
}
#endif

#endif // __proxythread_h__
