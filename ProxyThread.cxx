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

#include <algorithm>
#include <functional>
#include "ANSI.h"
#include "gk_const.h"
#include "stl_supp.h"
#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 )
#endif
#include "ProxyThread.h"


class ProxyConnectThread : public MyPThread {
public:
	PCLASSINFO ( ProxyConnectThread, MyPThread )

	ProxyConnectThread(ProxyHandleThread *);
	bool IsAvailable() const { return available; }
	bool Connect(ProxySocket *);
	void Exec();

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


ProxySocket::ProxySocket(PIPSocket *socket) : self(socket)
{
	maxbufsize = 1024;
	wbuffer = new BYTE[maxbufsize];
	connected = false;
	InternalCleanup();
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

	switch (e)
	{
//		case PChannel::NoError:
			// I don't know why there is error with code NoError
		case PChannel::Timeout:
			break;
		default:
			InternalCleanup();
			if (socket->IsOpen())
				socket->Close();
			break;
	}

	PTRACE(4, "ProxyS\t" << dynamic_cast<ProxySocket *>(socket)->Name() << " Error(" << group << "): " << PChannel::GetErrorText(e) << " (" << e << ')');

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

TCPProxySocket::TCPProxySocket(WORD p, TCPProxySocket *s)
      : PTCPSocket(p), ProxySocket(this), remote(s)
{
	SetReadTimeout(PTimeInterval(1000));
	SetWriteTimeout(PTimeInterval(100));
}

TCPProxySocket::~TCPProxySocket()
{
	if (remote) {
		if (remote->wsocket == this)
			remote->InternalCleanup();
		if (remote->IsOpen())
			remote->Close();
		remote->remote = 0; // detach myself from remote
	}
}

void TCPProxySocket::SetName()
{
	// since GetName() may not work if socket closed,
	// we save it for reference
	PIPSocket::Address ip;
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
	PTRACE(5, "ProxyH\tReading from " << Name());
	if (buflen == 0) {
		TPKTV3 tpkt;
		if (!ReadBlock(&tpkt, sizeof(TPKTV3)))
			return ErrorHandler(this, LastReadError);
		if (tpkt.header != 3 || tpkt.padding != 0)
			return false; // Only support version 3
		buflen = Net2Host(tpkt.length) - sizeof(TPKTV3);
		if (buflen < 1) {
			PTRACE(3, "ProxyS\t" << Name() << " PACKET TOO SHORT!");
			buflen = 0;
			return false;
		}
		buffer.SetSize(buflen);
		bufptr = buffer.GetPointer();
	}

	if (Read(bufptr, buflen)) {
		buflen -= GetLastReadCount();
		if (buflen > 0) {
			bufptr += GetLastReadCount();
			PTRACE(3, "ProxyS\t" << Name() << " read timeout?");
			return false;
		}
		return true;
	}
	return ErrorHandler(this, LastReadError);
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
#ifndef WIN32
	PTRACE(2, GetClass() << ' ' << getpid() << " started");
#endif
	while (isOpen)
		Exec();

#ifndef WIN32
	PTRACE(2, GetClass() << ' ' << getpid() << " closed");
#endif
}

void MyPThread::Destroy()
{
	Close();
	WaitForTermination();
	delete this;
}


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
	if (remote)
		handler->Insert(remote);

	available = true;
	socket->MarkBlocked(false);
}

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
		if (err == PTCPSocket::Interrupted)
			return;
		PTRACE(1, "ProxyL\tError: " << PChannel::GetErrorText(err));
	}
}

ProxyHandleThread::ProxyHandleThread(PINDEX i)
{
	id = PString(PString::Printf, "ProxyH(%u)", i);
	FindConnectThread(); // pre-fork a connect thread
	Resume();
}

ProxyHandleThread::~ProxyHandleThread()
{
	std::for_each(connList.begin(), connList.end(), delete_thread);
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

void ProxyHandleThread::ConnectTo(ProxySocket *socket)
{
	FindConnectThread()->Connect(socket);
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
	PTRACE(2, "ProxyH\tCreate a new ConnectThread, total " << connList.size());
	return ct;
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
	
	PTRACE(5, "ProxyH\t" << wlist.GetSize() << " sockets to flush...");
	for (PINDEX k = 0; k < wlist.GetSize(); ++k) {
		ProxySocket *socket = dynamic_cast<ProxySocket *>(&wlist[k]);
		if (socket->Flush()) {
			PTRACE(4, "ProxyH\t" << socket->Name() << " flush ok");
		}
	}
}

void ProxyHandleThread::BuildSelectList(PSocket::SelectList & result)
{
	// remove closed sockets
	mutex.StartWrite();
	iterator i = sockList.begin(), j = sockList.end();
	while (i != j) {
		iterator k=i++;
		ProxySocket *socket = *k;
		if (socket->IsSocketOpen() && !socket->IsBlocked()) {
			socket->AddToSelectList(result);
		} else if (!socket->IsBlocked()) {
			PTRACE(4, "ProxyH\tDelete socket " << socket->Name());
			Remove(k);
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
	PTRACE(3, id + msg);
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
					PTRACE(2, "ProxyH\t" << socket->Name() << " forward blocked");
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
//PTRACE(5, id << " handle " << socket->Name() << " ok...");
	}
}

void ProxyHandleThread::CloseUnusedThreads()
{
	static unsigned idx = 0;
	if (connList.size() <= 1 || (++idx % 60))
		return;

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
			return;
		}
	}
	connMutex.EndRead();
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
	std::for_each(handlers.begin(), handlers.end(), delete_thread);
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
	std::for_each(handlers.begin(), handlers.end(), close_threads);
}

void HandlerList::CloseListener()
{
	if (listenerThread) {
		listenerThread->Destroy();
		listenerThread = 0;
	}
}

