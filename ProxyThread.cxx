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


ProxySocket::ProxySocket(WORD p, ProxySocket *s) : PTCPSocket(p), remote(s)
{
	wsocket = 0;
	buflen = 0;
	blocked = false;
	maxbufsize = 1024;
	wbuffer = new BYTE[maxbufsize];
	connected = false;

	SetReadTimeout(PTimeInterval(1000));
	SetWriteTimeout(PTimeInterval(100));
}

ProxySocket::~ProxySocket()
{
	delete [] wbuffer;
	if (remote) {
		if (remote->wsocket == this) {
			remote->wsocket = 0;
			remote->blocked = false;
		}
		if (remote->IsOpen())
			remote->Close();
		remote->remote = 0; // detach myself from remote
	}
}

bool ProxySocket::CloseConnection()
{
	connected = false;
	return Close();
}

bool ProxySocket::Flush()
{
	if (!wsocket) {
		PTRACE(6, Name() << " Error: no socket to flush");
		return false;
	}
//PTRACE(5, wsocket->Name() << " Write " << buflen << " bytes");
	if (wsocket->Write(bufptr, buflen)) {
//PTRACE(5, wsocket->Name() << " Write ok");
		buflen = 0;
		wsocket = 0;
		blocked = false;
		return true;
	}
	buflen -= wsocket->GetLastWriteCount();
	bufptr += wsocket->GetLastWriteCount();

	return ErrorHandler(wsocket, LastWriteError);
}

bool ProxySocket::ErrorHandler(ProxySocket *socket, ErrorGroup group)
{
	Errors e = socket->GetErrorCode(group);

	PTRACE(4, "ProxyS\t" << socket->Name() << " Error(" << group << "): " << GetErrorText(e) << " (" << e << ')');

	switch (e)
	{
//		case NoError:
			// I don't know why there is error with code NoError
		case Timeout:
			break;
		default:
			socket->Close();
			wsocket = 0;
			blocked = false;
			break;
	}
	return false;
}

bool ProxySocket::ForwardData()
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

bool ProxySocket::TransmitData()
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

bool ProxySocket::ReadTPKT()
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

bool ProxySocket::SetMinBufSize(WORD len)
{
	if (maxbufsize < len) {
		delete [] wbuffer;
		wbuffer = new BYTE[maxbufsize = len];
	}
	return (wbuffer != 0);
}

void ProxySocket::SetName()
{
	// since GetName() may not work if socket closed,
	// we save it for reference
	Address ip;
	WORD pt;
	GetPeerAddress(ip, pt);
	name = ip.AsString() + PString(PString::Printf, ":%u", pt);
}

bool ProxySocket::InternalWrite()
{
	WORD len = buffer.GetSize();
	buflen = len + sizeof(TPKTV3);
	SetMinBufSize(buflen);
	new (wbuffer) TPKTV3(len); // placement operator
	memcpy(wbuffer + sizeof(TPKTV3), buffer, len);
	bufptr = wbuffer;
	blocked = true;
	return Flush();
}


MyPThread::MyPThread()
      : PThread(1000, NoAutoDeleteThread), isOpen(true)
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
	PTRACE(2, "Proxy\t" << GetClass() << " started, pid " << getpid());
#endif
	while (isOpen)
		Exec();

	PTRACE(2, GetClass() << " closed!");
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

	ProxySocket *remote = calling->ConnectTo();
	if (remote) {
//		calling->ForwardData();
		handler->Insert(remote);
//	} else {
//		PTRACE(3, "ProxyCT\tREMOTE PARTY DIDN'T ACCEPT THE CALL");
//		calling->CloseConnection(); // already closed
	}
	available = true;
	calling->MarkBlocked(false);
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

	ProxySocket *socket = CreateSocket();
	if (socket->Accept(*m_listener)) { // incoming connection
		PTRACE(2, "ProxyL\tConnected from " << socket->Name());
		m_handler->Insert(socket);
	} else {
		PChannel::Errors err = socket->GetErrorCode();
		delete socket;  // delete unused socket
		if (err == PTCPSocket::Interrupted)
			return;
		PTRACE(1, "ProxyL\tError: " << PChannel::GetErrorText(err));
	}
}

ProxyHandleThread::ProxyHandleThread(PINDEX i) : id(i)
{
	FindConnectThread(); // pre-fork a connect thread
	Resume();
}

ProxyHandleThread::~ProxyHandleThread()
{
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
			wlist.Append(*i);
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
		if (socket->IsOpen() && !socket->IsBlocked()) {
			result.Append(socket);
		} else if (!socket->IsBlocked()) {
			PTRACE(4, "ProxyH\tDelete socket " << socket->Name());
			delete socket;
			sockList.erase(k);
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
		PTRACE(5, "ProxyH(" << id << ") waiting...");
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
	PString msg(PString::Printf, "ProxyH(%u)\t%u sockets selected from %u, total %u", id, sList.GetSize(), ss, sockList.size());
	PTRACE(3, msg);
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
				socket->Close();
				break;
			default:
				break;
		}
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
			PTRACE(3, "ProxyH\tClose one unused ConnectThread");
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


/*
class ProxyWriteThread : public MyPThread {
public:
	PCLASSINFO ( ProxyWriteThread, MyPThread )

	typedef std::list<ProxySocket *>::iterator iterator;
        typedef std::list<ProxySocket *>::const_iterator const_iterator;

	ProxyWriteThread(ProxyHandleThread *);
//	~ProxyWriteThread();
	void Insert(ProxySocket *);
	void Exec();

private:
	void Remove(iterator);

	std::list<ProxySocket *> sockList;
	mutable PReadWriteMutex mutex;
	ProxyHandleThread *handler;
};

ProxyWriteThread::ProxyWriteThread(ProxyHandleThread *h) : handler(h)
{
	Resume();
}

void ProxyWriteThread::Insert(ProxySocket *socket)
{
	PTRACE(4, "ProxyW\tAdd " << socket->Name() << " to flush");
	mutex.StartWrite();
	sockList.push_back(socket);
	mutex.EndWrite();
	Go();
}

void ProxyWriteThread::Remove(iterator i)
{
	mutex.StartWrite();
	if (i != sockList.end())
		sockList.erase(i);
	mutex.EndWrite();
}

void ProxyWriteThread::Exec()
{
	if (sockList.empty() && !Wait())
		return;

	mutex.StartRead();
	iterator i = sockList.begin(), j;
	mutex.EndRead();
	do {
		mutex.StartRead();
		iterator s = i++;
		mutex.EndRead();
		if (!((*s)->CanFlush())) {
			PTRACE(4, "ProxyW\t" << (*s)->Name() << " can't flush");
			(*s)->MarkBlocked(false);
			Remove(s);
		} else if ((*s)->Flush()) {
			PTRACE(3, "ProxyW\t" << (*s)->Name() << " flush ok");
			Remove(s);
			handler->Go();
		}
		mutex.StartRead();
		j = sockList.end();
		mutex.EndRead();
	} while (i != j);
}
*/
