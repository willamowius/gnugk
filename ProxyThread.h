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

#ifndef PROXYTHREAD_H
#define PROXYTHREAD_H "@(#) $Id$"

#include "rwlock.h"
#include "gklock.h"
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

	friend class ProxyDeleter;
	ProxySocket(PIPSocket *, const char *);
	virtual ~ProxySocket() =0; // abstract class
	PString Name() const { PWaitAndSignal lock(m_lock); return name; }

	virtual Result ReceiveData();
	virtual bool ForwardData() { PWaitAndSignal lock(m_lock); return WriteData(self); }
	virtual bool TransmitData() { PWaitAndSignal lock(m_lock); return WriteData(self); }
	virtual bool EndSession();

	bool IsSocketOpen() const { PWaitAndSignal lock(m_lock); return InternalIsSocketOpen(); }
	bool CloseSocket() { PWaitAndSignal lock(m_lock); return InternalCloseSocket(); }

	bool Flush();
	bool CanFlush() const;
	bool IsBlocked() const { PWaitAndSignal lock(m_lock); return blocked; }
	void MarkBlocked(bool b) { PWaitAndSignal lock(m_lock); blocked = b; }
	bool IsConnected() const { PWaitAndSignal lock(m_lock); return connected; }
	virtual void SetConnected(bool c) { PWaitAndSignal lock(m_lock); connected = c; }
	bool IsDeletable() const { PWaitAndSignal lock(m_lock); return deletable; }
	void SetDeletable() { PWaitAndSignal lock(m_lock); deletable = true; }
	ProxyHandleThread *GetHandler() const { PWaitAndSignal lock(m_lock); return handler; }
	void SetHandler(ProxyHandleThread *h) { PWaitAndSignal lock(m_lock); handler = h; }

	void AddToSelectList(PSocket::SelectList &);

	// Locking Functions
// 	virtual void Lock();
// 	virtual void Unlock();

	// These two function are used to lock the existance of
	// the Object as long as a pointer to it is active. The
	// user has to Lock/Unlock the Object.
	virtual void LockUse(const PString &name);
	virtual void UnlockUse(const PString &name);
	virtual const BOOL IsInUse();

protected:
	bool WriteData(PIPSocket *);
	void InternalCleanup();
	bool SetMinBufSize(WORD);
	bool ErrorHandler(PSocket *, PChannel::ErrorGroup);
	void SetName(PIPSocket::Address ip, WORD pt);

	bool InternalIsSocketOpen() const { return self->IsOpen();}
	bool InternalCloseSocket() { return InternalIsSocketOpen() ? self->Close() : false; }

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
	mutable PMutex m_lock; // lock over all member objects.
	mutable ProxyCondMutex m_usedCondition;
};

class TCPProxySocket : public PTCPSocket, public ProxySocket {
public:
	PCLASSINFO( TCPProxySocket, PTCPSocket )

	TCPProxySocket(const char * , TCPProxySocket * = NULL, WORD = 0);
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

	// Locking Functions
// 	virtual void Lock();
// 	virtual void Unlock();

	// These two function are used to lock the existance of
	// the Object as long as a pointer to it is active. The
	// user has to Lock/Unlock the Object.
	virtual void LockUse(const PString &name);
	virtual void UnlockUse(const PString &name);
	virtual const BOOL IsInUse();

////    PROTECTED
	TCPProxySocket *remote;

	bool ReadTPKT();

	PBYTEArray buffer;

private:
	bool InternalWrite();
	void SetName();
	mutable PMutex m_lock; // lock over all member objects.
	mutable ProxyCondMutex m_usedCondition;
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

// Quick hack to avoid lock when deleting multiple ProxySockets from the handler thread.
// The old version might produce a even a deadlock.
// In longer terms we have to think about the handlerlist-locks.
//
// This class will take a proxysocket via constructor and delete it, when scheduler gives
// time.

class ProxyDeleter : public PThread {
public:
	PCLASSINFO (ProxyDeleter, PThread)

	ProxyDeleter(ProxySocket *s);
	~ProxyDeleter() { PTRACE(1,"Destructor of ProxyDeleter");}
	virtual void Main();
protected:
	ProxySocket *delete_socket;
	PTimer max_wait;

	PDECLARE_NOTIFIER(PTimer, ProxyDeleter, OnTimeout);

//	void OnTimeout(PTimer &timer, int extra);
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
	mutable PMutex removedMutex;
	std::list<ProxyConnectThread *> connList;
	mutable PReadWriteMutex connMutex;
	ProxyHandleThread *lcHandler;
	PString id;

	static void delete_socket(ProxySocket *s);
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
	PWaitAndSignal lock(m_lock);
	return (wsocket && wsocket->IsOpen());
}

inline void ProxySocket::AddToSelectList(PSocket::SelectList & slist)
{
	PWaitAndSignal lock(m_lock);
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
	removedList.push_back(socket);
	sockList.remove(socket);
}

#ifdef WIN32
inline DWORD getpid()
{
       return GetCurrentThreadId();
}
#endif

#endif // PROXYTHREAD_H
