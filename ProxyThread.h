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

#include <list>
#include <vector>
#include <ptlib.h>
#include <ptlib/sockets.h>


class ProxySocket;
class ProxyListener;
class ProxyConnectThread;
class ProxyHandleThread;
class HandlerList;


class ProxySocket : public PTCPSocket {
public:
	PCLASSINFO( ProxySocket, PTCPSocket )

	enum Result {
		NoData,
		Connecting,
		Forwarding,
		Closing,
		Error
	};

	ProxySocket(WORD = 0, ProxySocket * = 0);
	virtual ~ProxySocket();
	PString Name() const { return name; }

	virtual ProxySocket *ConnectTo() = 0;
	virtual Result ReceiveData() = 0;
	virtual bool CloseConnection();

	bool ForwardData();
	bool TransmitData();

	bool Flush();
	bool CanFlush() const;
	bool IsBlocked() const { return blocked; }
	void MarkBlocked(bool b) { blocked = b; }
	void SetHandler(ProxyHandleThread *);
	
	// override from class PTCPSocket
	virtual BOOL Accept(PSocket &);
	virtual BOOL Connect(const Address &);

	bool IsConnected() const { return connected; }
	void SetConnected(bool c) { connected = c; }

//	BOOL WriteAsync( const void * buf, PINDEX len );
//	void OnWriteComplete( const void * buf, PINDEX len );

protected:
	bool ReadTPKT();
	bool SetMinBufSize(WORD);
	bool ErrorHandler(ProxySocket *, ErrorGroup);

	ProxySocket *remote;
	PBYTEArray buffer;
	ProxyHandleThread *phandler;

private:
	void SetName();
	bool InternalWrite();

	ProxySocket *wsocket;
	WORD maxbufsize, buflen;
	BYTE *wbuffer, *bufptr;
	bool blocked;
	bool connected;
	PString name;
};

// abstract class
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

	void Destroy();

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
	virtual void Close();
	void Exec();

	WORD GetPort() const { return m_port; }
				
protected:
	PTCPSocket *m_listener;
	PIPSocket::Address m_interface; 
	WORD m_port;

private:
	ProxySocket *CreateSocket();

	HandlerList *m_handler;
};

class ProxyHandleThread : public MyPThread {
public:
	PCLASSINFO ( ProxyHandleThread, MyPThread )

	typedef std::list<ProxySocket *>::iterator iterator;
        typedef std::list<ProxySocket *>::const_iterator const_iterator;
	typedef std::list<ProxyConnectThread *>::iterator citerator;
        typedef std::list<ProxyConnectThread *>::const_iterator const_citerator;

	ProxyHandleThread(PINDEX);
	~ProxyHandleThread();
	void Insert(ProxySocket *);
	void Exec();

	void CloseUnusedThreads();
	void ConnectTo(ProxySocket *);

private:
	ProxyConnectThread *FindConnectThread();
	void FlushSockets();
	void BuildSelectList(PSocket::SelectList &);
	static void delete_socket(ProxySocket *s) { delete s; }
	
	std::list<ProxySocket *> sockList;
	mutable PReadWriteMutex mutex, connMutex;
	std::list<ProxyConnectThread *> connList;

	PIPSocket::Address toAddr;
	WORD toPort;

	PINDEX id;
};

class HandlerList {     
public:         
	HandlerList(PIPSocket::Address = INADDR_ANY);
	~HandlerList();

	void LoadConfig();
	void Insert(ProxySocket *);
	void Check();

	WORD GetCallSignalPort() const { return GKPort; }

private:
	void CloseListener();

	std::vector<ProxyHandleThread *> handlers;
	ProxyListener *listenerThread;

	PINDEX currentHandler;
	PMutex mutex;
	PIPSocket::Address GKHome;
	WORD GKPort;
};


inline bool ProxySocket::CanFlush() const
{
	return (wsocket && wsocket->IsOpen());
}

inline BOOL ProxySocket::Accept(PSocket & socket)
{
	BOOL result = PTCPSocket::Accept(socket);
	// since GetName() may not work if socket closed,
	// we save it for reference
	SetName();
	return result;
}

inline BOOL ProxySocket::Connect(const Address & addr)
{
	BOOL result = PTCPSocket::Connect(addr);
	// since GetName() may not work if socket closed,
	// we save it for reference
	SetName();
	return result;
}

inline void ProxySocket::SetHandler(ProxyHandleThread *h)
{
	phandler = h;
}

inline bool MyPThread::Wait()
{
	sync.Wait();
	return isOpen;
}

inline void MyPThread::Go()
{
	if (sync.WillBlock())
		sync.Signal();
}

#endif // __proxythread_h__

