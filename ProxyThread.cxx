//////////////////////////////////////////////////////////////////
//
// ProxyThread.cxx
//
// Copyright (c) Citron Network Inc. 2001-2002
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 12/7/2001
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4355 ) // warning about using 'this' in initializer
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include <algorithm>
#include <functional>
#include "ANSI.h"
#include "gk_const.h"
#include "stl_supp.h"
#include "ProxyThread.h"


class ProxyConnectThread : public MyPThread {
public:
	PCLASSINFO ( ProxyConnectThread, MyPThread )

	ProxyConnectThread(ProxyHandleThread *);
	bool IsAvailable() const { return available; }
	bool Connect(ProxySocket *);

	// override from class MyPThread
	virtual void Exec();

private:
	ProxyHandleThread *handler;
	bool available;

	ProxySocket *calling;
};

struct TPKTV3 {
	TPKTV3() {}
	TPKTV3(WORD);

	BYTE header, padding;
	WORD length;
};

inline TPKTV3::TPKTV3(WORD len)
	: header(3), padding(0)
{
	length = PIPSocket::Host2Net(WORD(len + sizeof(TPKTV3)));
}


// class ProxySocket
ProxySocket::ProxySocket(PIPSocket *s, const char *t) : self(s), type(t)
{
	maxbufsize = 1024;
	wbuffer = new BYTE[maxbufsize];
	deletable = connected = false;
	InternalCleanup();
}

ProxySocket::~ProxySocket()
{
	delete [] wbuffer;
	PTRACE(4, type << "\tDelete socket " << name);
}

ProxySocket::Result ProxySocket::ReceiveData()
{
	if (!self->Read(wbuffer, maxbufsize)) {
		ErrorHandler(self, PChannel::LastReadError);
		return NoData;
	}
	PTRACE(6, type << "\tReading from " << Name());
	buflen = self->GetLastReadCount();
	return Forwarding;
}

bool ProxySocket::WriteData(PIPSocket *socket)
{
	if (buflen == 0)
		return false;
	bufptr = wbuffer;
	wsocket = socket;
	MarkBlocked(true);
	return Flush();
}

bool ProxySocket::EndSession()
{
	MarkBlocked(false);
	SetConnected(false);
	return CloseSocket();
}

bool ProxySocket::Flush()
{
	if (!wsocket || buflen == 0) {
		InternalCleanup();
		PTRACE(6, Name() << " Error: nothing to flush");
		return false;
	}
//PTRACE(5, wsocket->Name() << " Write " << buflen << " bytes");
	if (wsocket->Write(bufptr, buflen)) {
//PTRACE(5, wsocket->Name() << " Write ok");
		InternalCleanup();
		return true;
	}
	buflen -= wsocket->GetLastWriteCount();
	bufptr += wsocket->GetLastWriteCount();

	return ErrorHandler(wsocket, PChannel::LastWriteError);
}

bool ProxySocket::ErrorHandler(PSocket *socket, PChannel::ErrorGroup group)
{
	PChannel::Errors e = socket->GetErrorCode(group);

	PString msg(PString(type) + "\t" + dynamic_cast<ProxySocket *>(socket)->Name());
	switch (e)
	{
//		case PChannel::NoError:
//			// I don't know why there is error with code NoError
//			PTRACE(4, msg << " Error(" << group << "): No error?");
//			break;
		case PChannel::Timeout:
			PTRACE(4, msg << " Error(" << group << "): Timeout");
			break;
		default:
			PTRACE(3, msg << " Error(" << group << "): " << PChannel::GetErrorText(e) << " (" << e << ')');
			InternalCleanup();
			if (socket->IsOpen())
				socket->Close();
			break;
	}
	return false;
}

bool ProxySocket::SetMinBufSize(WORD len)
{
	if (maxbufsize < len) {
		delete [] wbuffer;
		wbuffer = new BYTE[maxbufsize = len];
	}
	return (wbuffer != 0);
}

// class TCPProxySocket
TCPProxySocket::TCPProxySocket(const char *t, TCPProxySocket *s, WORD p)
      : PTCPSocket(p), ProxySocket(this, t), remote(s)
{
	SetReadTimeout(PTimeInterval(100));
	SetWriteTimeout(PTimeInterval(100));
}

TCPProxySocket::~TCPProxySocket()
{
	if (remote) {
		if (remote->wsocket == this)
			remote->InternalCleanup();
		remote->remote = 0; // detach myself from remote
		remote->SetDeletable();
	}
}

void TCPProxySocket::SetName()
{
	// since GetName() may not work if socket closed,
	// we save it for reference
	Address ip;
	WORD pt;
	GetPeerAddress(ip, pt);
	ProxySocket::SetName(ip, pt);
}

bool TCPProxySocket::ForwardData()
{
	if (buffer.GetSize() == 0)
		return false;
	if (!wsocket && remote) {
		wsocket = remote;
		return InternalWrite();
	}
	PTRACE(5, Name() << " Can't forward");
	return false;
}

bool TCPProxySocket::TransmitData()
{
	if (buffer.GetSize() == 0)
		return false;
	if (!wsocket) {
		wsocket = this;
		return InternalWrite();
	}
	PTRACE(2, Name() << " Error: socket is busy");
	return false;
}

BOOL TCPProxySocket::Accept(PSocket & socket)
{
	BOOL result = PTCPSocket::Accept(socket);
	// since GetName() may not work if socket closed,
	// we save it for reference
	SetName();
	return result;
}

BOOL TCPProxySocket::Connect(const Address & addr)
{
	BOOL result = PTCPSocket::Connect(addr);
	// since GetName() may not work if socket closed,
	// we save it for reference
	SetName();
	return result;
}

bool TCPProxySocket::ReadTPKT()
{
	PTRACE(5, "Proxy\tReading from " << Name());
	if (buflen == 0) {
		TPKTV3 tpkt;
		if (!ReadBlock(&tpkt, sizeof(TPKTV3)))
			return ErrorHandler(this, LastReadError);
		//if (tpkt.header != 3 || tpkt.padding != 0)
		// some bad endpoints don't set padding to 0, e.g., Cisco AS5300
		if (tpkt.header != 3)
			return false; // Only support version 3
		buflen = Net2Host(tpkt.length) - sizeof(TPKTV3);
		if (buflen < 1) {
			PTRACE(3, "Proxy\t" << Name() << " PACKET TOO SHORT!");
			buflen = 0;
			return false;
		}
		buffer.SetSize(buflen);
		bufptr = buffer.GetPointer();
	}

	if (!Read(bufptr, buflen))
		return ErrorHandler(this, LastReadError);

	buflen -= GetLastReadCount();
	if (buflen > 0) {
		bufptr += GetLastReadCount();
		PTRACE(3, "Proxy\t" << Name() << " read timeout?");
		return false;
	}
	return true;
}

bool TCPProxySocket::InternalWrite()
{
	WORD len = buffer.GetSize();
	buflen = len + sizeof(TPKTV3);
	SetMinBufSize(buflen);
	new (wbuffer) TPKTV3(len); // placement operator
	memcpy(wbuffer + sizeof(TPKTV3), buffer, len);
	bufptr = wbuffer;
	MarkBlocked(true);
	return Flush();
}


// class MyPThread
MyPThread::MyPThread() : PThread(5000, NoAutoDeleteThread), isOpen(true)
{
}

void MyPThread::Close()
{
	isOpen = false;
	sync.Signal();
}

void MyPThread::Main()
{
	PTRACE(2, GetClass() << ' ' << getpid() << " started");
	while (isOpen)
		Exec();

	PTRACE(2, GetClass() << ' ' << getpid() << " closed");
}

bool MyPThread::Destroy()
{
	Close();
	WaitForTermination();
	delete this;
	return true; // useless, workaround for VC
}


// class ProxyConnectThread
ProxyConnectThread::ProxyConnectThread(ProxyHandleThread *h)
	: handler(h), available(true)
{
	Resume();
}

bool ProxyConnectThread::Connect(ProxySocket *socket)
{
	if (!available)
		return false;
	available = false;

	socket->MarkBlocked(true);
	calling = socket;
	Go();
	return true;
}

void ProxyConnectThread::Exec()
{
	if (!Wait())
		return;

	TCPProxySocket *socket = dynamic_cast<TCPProxySocket *>(calling);
	TCPProxySocket *remote = socket->ConnectTo();
	if (remote) {
		handler->Insert(remote);
		socket->MarkBlocked(false);
	}
	// else
	// 	Note: socket may be invalid

	available = true;
}

// class ProxyListener
ProxyListener::ProxyListener(HandlerList *h, PIPSocket::Address i, WORD p, unsigned qs)
      : m_listener(0), m_interface(i), m_port(p), m_handler(h)
{
	Open(qs);
}

ProxyListener::~ProxyListener()
{
	delete m_listener;
}

bool ProxyListener::Open(unsigned queueSize)
{
	m_listener = new PTCPSocket(m_port);
	isOpen = (m_interface == INADDR_ANY) ?
		  m_listener->Listen(queueSize) :
		  m_listener->Listen(m_interface, queueSize);
	m_port = m_listener->GetPort(); // get the listen port
	if (isOpen) {
		PTRACE(2, "ProxyL\tListen to " << m_interface << ':' << m_port);
		Resume();
#ifdef PTRACING
	} else {
		PTRACE(1, "ProxyL\tCan't listen port " << m_port);
#endif
	}
	return isOpen;
}

void ProxyListener::Close()
{
	PTRACE(3, "ProxyL\tClosing ProxyListener");
	m_listener->Close();
	isOpen = false;
}

void ProxyListener::Exec()
{
	if (!m_listener->IsOpen()) {
		isOpen = false;
		return;
	}

	TCPProxySocket *socket = CreateSocket();
	if (socket->Accept(*m_listener)) { // incoming connection
		PTRACE(3, "ProxyL\tConnected from " << socket->Name());
		m_handler->Insert(socket);
	} else {
		PChannel::Errors err = socket->GetErrorCode();
		delete socket;  // delete unused socket
		PTRACE_IF(3, err != PChannel::Interrupted,
			  "ProxyL\tError: " << PChannel::GetErrorText(err));
	}
}

// class ProxyHandleThread
ProxyHandleThread::ProxyHandleThread(PINDEX i)
{
	SetID(PString(PString::Printf, "ProxyH(%u)", i));
	Resume();

	FindConnectThread(); // pre-fork a connect thread
	lcHandler = new ProxyHandleThread;
	lcHandler->SetID(PString(PString::Printf, "ProxyLC(%u)", i));
	lcHandler->SetPriority(HighPriority);
	lcHandler->Resume();
}

ProxyHandleThread::~ProxyHandleThread()
{
	if (lcHandler)
		lcHandler->Destroy();
	std::for_each(connList.begin(), connList.end(), mem_fun(&MyPThread::Destroy));
	std::for_each(sockList.begin(), sockList.end(), delete_socket);
}

void ProxyHandleThread::Insert(ProxySocket *socket)
{
	socket->SetHandler(this);
	mutex.StartWrite();
	sockList.push_back(socket);
	mutex.EndWrite();
	Go();
}

void ProxyHandleThread::FlushSockets()
{
	PSocket::SelectList wlist;
	mutex.StartRead();
	iterator i = sockList.begin(), j = sockList.end();
	while (i != j) {
		if ((*i)->CanFlush())
			(*i)->AddToSelectList(wlist);
		++i;
	}
	mutex.EndRead();
	if (wlist.IsEmpty())
		return;

	// unfortunately, there is no method to select only sockets to write
	PSocket::SelectList rlist = wlist;
	PSocket::Select(rlist, wlist, PTimeInterval(10));
	
	PTRACE(5, "Proxy\t" << wlist.GetSize() << " sockets to flush...");
	for (PINDEX k = 0; k < wlist.GetSize(); ++k) {
		ProxySocket *socket = dynamic_cast<ProxySocket *>(&wlist[k]);
		if (socket->Flush()) {
			PTRACE(4, "Proxy\t" << socket->Name() << " flush ok");
		}
	}
}

void ProxyHandleThread::BuildSelectList(PSocket::SelectList & result)
{
	mutex.StartWrite();
	iterator i = sockList.begin(), j = sockList.end();
	while (i != j) {
		iterator k=i++;
		ProxySocket *socket = *k;
		if (!socket->IsBlocked()) {
			if (socket->IsDeletable())
				Remove(k);
			else if (socket->IsSocketOpen())
				socket->AddToSelectList(result);
#ifdef PTRACING
		} else {
			PTRACE(5, socket->Name() << " is busy!");
#endif
		}
	}
	mutex.EndWrite();
}

void ProxyHandleThread::Exec()
{
	PSocket::SelectList sList;
	while (true) {
		FlushSockets();
		BuildSelectList(sList);
		if (!sList.IsEmpty())
			break;
		PTRACE(5, id << " waiting...");
		if (!Wait())
			return;
	}

#ifdef PTRACING
	PINDEX ss = sList.GetSize();
#endif
	PSocket::Select(sList, PTimeInterval(100));
        if (sList.IsEmpty())
		return;

#ifdef PTRACING
	PString msg(PString::Printf, " %u sockets selected from %u, total %u", sList.GetSize(), ss, sockList.size());
	PTRACE(4, id + msg);
#endif
	for (PINDEX i = 0; i < sList.GetSize(); ++i) {
		ProxySocket *socket = dynamic_cast<ProxySocket *>(&sList[i]);
		switch (socket->ReceiveData())
		{
			case ProxySocket::Connecting:
				ConnectTo(socket);
				break;
			case ProxySocket::Forwarding:
				if (!socket->ForwardData()) {
					PTRACE(3, "Proxy\t" << socket->Name() << " forward blocked");
				}
				break;
			case ProxySocket::Closing:
				socket->ForwardData();
				// then close the socket
			case ProxySocket::Error:
				socket->CloseSocket();
				break;
			default:
				break;
		}
	}
}

ProxyConnectThread *ProxyHandleThread::FindConnectThread()
{
	connMutex.StartRead();
	for (citerator i = connList.begin(); i != connList.end(); ++i)
		if ((*i)->IsAvailable()) {
			connMutex.EndRead();
			return (*i);
		}

	connMutex.EndRead();
	ProxyConnectThread *ct = new ProxyConnectThread(this);
	connMutex.StartWrite();
	connList.push_back(ct);
	connMutex.EndWrite();
	PTRACE(2, "Proxy\tCreate a new ConnectThread, total " << connList.size());
	return ct;
}

void ProxyHandleThread::ConnectTo(ProxySocket *socket)
{
	FindConnectThread()->Connect(socket);
}

bool ProxyHandleThread::CloseUnusedThreads()
{
	static unsigned idx = 0;
	if (connList.size() <= 1 || (++idx % 60))
		return true;

	connMutex.StartRead();
	citerator i = connList.end();
	while (--i != connList.begin()) {
		if ((*i)->IsAvailable()) {
			connMutex.EndRead();
			connMutex.StartWrite();
			connList.erase(i);
			connMutex.EndWrite();

			(*i)->Destroy();
			PTRACE(3, id << " Close one unused ConnectThread");
			return true;
		}
	}
	connMutex.EndRead();
	return true; // useless, workaround for VC
}


HandlerList::HandlerList(PIPSocket::Address home) : GKHome(home), GKPort(0)
{
	currentHandler = 0;
	listenerThread = 0;
	LoadConfig();
}

HandlerList::~HandlerList()
{
	CloseListener();
	std::for_each(handlers.begin(), handlers.end(), std::mem_fun(&MyPThread::Destroy));
}

void HandlerList::Insert(ProxySocket *socket)
{
	// only lister thread will call this method, no mutex required
	handlers[currentHandler]->Insert(socket);
	if (++currentHandler >= handlers.size())
		currentHandler = 0;
}

void HandlerList::Check()
{
	std::for_each(handlers.begin(), handlers.end(), std::mem_fun(&ProxyHandleThread::CloseUnusedThreads));
}

void HandlerList::CloseListener()
{
	if (listenerThread) {
		listenerThread->Destroy();
		listenerThread = 0;
	}
}

