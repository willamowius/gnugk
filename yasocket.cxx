//////////////////////////////////////////////////////////////////
//
// yasocket.cxx
//
// Copyright (c) Citron Network Inc. 2002-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 03/14/2003
//
//////////////////////////////////////////////////////////////////

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include <ptlib.h>
#include "h323util.h"
#include "stl_supp.h"
#include "rwlock.h"
#include "yasocket.h"

#ifdef LARGE_FDSET

bool YaSelectList::Select(SelectType t, const PTimeInterval & timeout)
{
	large_fd_set fdset;
	// add handles to the fdset
	const_iterator i = fds.begin();
	const_iterator endIter = fds.end();
	while (i != endIter)
		fdset.add((*i++)->GetHandle());

	fd_set *readfds, *writefds;
	if (t == Read)
		readfds = fdset, writefds = 0;
	else
		writefds = fdset, readfds = 0;

	const unsigned long msec = timeout.GetInterval();
	struct timeval tval;
	tval.tv_sec  = msec / 1000;
	tval.tv_usec = (msec - tval.tv_sec * 1000) * 1000;
	bool r = ::select(maxfd + 1, readfds, writefds, 0, &tval) > 0;
	if (r) {
#if 1
		std::vector<YaSocket*>::iterator last = std::remove_if(
			fds.begin(), fds.end(),
			std::not1(std::compose1(
				std::bind1st(mem_fun(&large_fd_set::has), &fdset), 
				mem_fun(&YaSocket::GetHandle)
				)));
		fds.erase(last, fds.end());
#else
		/* This unrolled implementation of the above code may give
		   another 10-15% of performance gain. As it is not much under normal
		   conditions, I leave it for thouse who want to squeeze a few more
		   calls from their proxies;-)
		   
		   I did some performance tests (Duron 1.1GHz) with simulation of
		   various fds selected sockets coverage (10%, 33%, 50%, 75%, 90%):
		   
		   LARGE_FDSET=1024  - 12% performance gain
		   LARGE_FDSET=4096  - 15% performance gain
		   LARGE_FDSET=16384 - 13% performance gain
		   
		   For LARGE_FDSET=4096 it took less than 1ms to manipulate the fdset
		   and this grows in a linear fashion (LARGE_FDSET=16384 takes a few
		   milliseconds to perform the same task).
		*/
		std::vector<YaSocket*>::reverse_iterator j = fds.rbegin();
		std::vector<YaSocket*>::iterator k = fds.end();
		const std::vector<YaSocket*>::reverse_iterator rendIter = fds.rend();
		bool hasfd = false;
		
		// start from the end of the list, skip consecutive sockets 
		// that were not selected (find the first one selected)
		while (j != rendIter) {
			k--;
			if (fdset.has((*j)->GetHandle())) {
				hasfd = true;
				break;
			} else
				j++;
		}
		// reorder remaining sockets, so non-selected sockets 
		// are moved to the end of the vector
		if (hasfd) {
			while (++j != rendIter) {
				if (!fdset.has((*j)->GetHandle()))
					*j = *k--;
			}
			// at this point the vector [begin(),k] should contain
			// all selected sockets, so erase the remaining vector elements
			fds.erase(++k, fds.end());
		} else
			fds.clear();
#endif
	}
	return r;
}


// class YaSocket
YaSocket::YaSocket() : os_handle(-1)
{
	lastReadCount = lastWriteCount = 0;
}

YaSocket::~YaSocket()
{
	Close();
}

bool YaSocket::Close()
{
	if (!IsOpen())
		return false;

	// send a shutdown to the other end
	int handle = os_handle;
	os_handle = -1;
	::shutdown(handle, SHUT_RDWR);
#ifdef WIN32
	::closesocket(handle);
#else
	::close(handle);
#endif
	return true;
}

bool YaSocket::Read(void *buf, int sz)
{
	int r = os_recv(buf, sz);
	lastReadCount = ConvertOSError(r, PSocket::LastReadError) ? r : 0;
	return lastReadCount > 0;
}

bool YaSocket::ReadBlock(void *buf, int len)
{
	// lazy implementation, but it is enough for us...
	return Read(buf, len) && (lastReadCount == len);
}

bool YaSocket::CanRead(
	long timeout
	) const
{
	const int h = os_handle;
	if (h < 0)
		return false;

	YaSelectList::large_fd_set fdset;
	fdset.add(h);

	struct timeval tval;
	tval.tv_sec  = timeout / 1000;
	tval.tv_usec = (timeout - tval.tv_sec * 1000) * 1000;
	return ::select(h + 1, (fd_set*)fdset, NULL, NULL, &tval) > 0;
}

bool YaSocket::CanWrite(
	long timeout
	) const
{
	const int h = os_handle;
	if (h < 0)
		return false;
		
	YaSelectList::large_fd_set fdset;
	fdset.add(h);

	struct timeval tval;
	tval.tv_sec  = timeout / 1000;
	tval.tv_usec = (timeout - tval.tv_sec * 1000) * 1000;
	return ::select(h + 1, NULL, (fd_set*)fdset, NULL, &tval) > 0;
}

bool YaSocket::Write(const void *buf, int sz)
{
	lastWriteCount = 0;
	if (!CanWrite(writeTimeout.GetInterval())) {
		errno = EAGAIN;
		return ConvertOSError(-1, PSocket::LastWriteError);
	}
	int r = os_send(buf, sz);
	if (ConvertOSError(r, PSocket::LastWriteError))
		lastWriteCount = r;
	return lastWriteCount == sz;
}

void YaSocket::GetLocalAddress(Address & addr) const
{
	WORD pt;
	GetLocalAddress(addr, pt);
}

void YaSocket::GetLocalAddress(Address & addr, WORD & pt) const
{
	sockaddr_in inaddr;
	socklen_t insize = sizeof(inaddr);
	if (::getsockname(os_handle, (struct sockaddr*)&inaddr, &insize) == 0) {
		addr = inaddr.sin_addr;
		pt = ntohs(inaddr.sin_port);
	}
}

bool YaSocket::SetOption(int option, int value, int level)
{
	return ConvertOSError(::setsockopt(os_handle, level, option, (char *)&value, sizeof(int)));
}

bool YaSocket::SetOption(int option, const void *value, int size, int level)
{
	return ConvertOSError(::setsockopt(os_handle, level, option, (char *)value, size));
}

PString YaSocket::GetErrorText(PSocket::ErrorGroup group) const
{
	return PSocket::GetErrorText(GetErrorCode(group));
}

bool YaSocket::ConvertOSError(int libReturnValue, PSocket::ErrorGroup group)
{
	if ((libReturnValue < 0) && (errno == EAGAIN)) {
		lastErrorCode[group] = PSocket::Timeout;
		lastErrorNumber[group] = errno;
		return false;
	}
	return PSocket::ConvertOSError(libReturnValue, lastErrorCode[group], lastErrorNumber[group]);
}

bool YaSocket::SetNonBlockingMode()
{
	if (!IsOpen())
		return false;
	int cmd = 1;
	if (::ioctl(os_handle, FIONBIO, &cmd) == 0 && ::fcntl(os_handle, F_SETFD, 1) == 0)
		return true;
	Close();
	return false;

}

bool YaSocket::Bind(const Address & addr, WORD pt)
{
	if (IsOpen()) {
		sockaddr_in inaddr;
		memset(&inaddr, 0, sizeof(inaddr));
		inaddr.sin_family = AF_INET;
		inaddr.sin_addr.s_addr = addr;
		inaddr.sin_port = htons(pt);
		if (SetOption(SO_REUSEADDR, 1) && ConvertOSError(::bind(os_handle, (struct sockaddr *)&inaddr, sizeof(inaddr)))) {
			socklen_t insize = sizeof(inaddr);
			if (::getsockname(os_handle, (struct sockaddr *)&inaddr, &insize) == 0) {
				port = ntohs(inaddr.sin_port);
				return true;
			}
		}
	}
	return false;
}


// class YaTCPSocket
YaTCPSocket::YaTCPSocket(WORD pt)
{
	peeraddr.sin_family = AF_INET;
	SetPort(pt);
}

void YaTCPSocket::GetPeerAddress(Address & addr) const
{
	addr = peeraddr.sin_addr;
}

void YaTCPSocket::GetPeerAddress(Address & addr, WORD & pt) const
{
	addr = peeraddr.sin_addr;
	pt = ntohs(peeraddr.sin_port);
}

bool YaTCPSocket::SetLinger()
{
	SetOption(TCP_NODELAY, 1, IPPROTO_TCP);
	const linger ling = { 1, 3 };
	return SetOption(SO_LINGER, &ling, sizeof(ling));
}

bool YaTCPSocket::Listen(unsigned qs, WORD pt)
{
	return Listen(INADDR_ANY, qs, pt);
}

bool YaTCPSocket::Listen(const Address & addr, unsigned qs, WORD pt)
{
	os_handle = ::socket(PF_INET, SOCK_STREAM, 0);
	if (!ConvertOSError(os_handle))
		return false;

//	SetNonBlockingMode();
	if (Bind(addr, pt) && ConvertOSError(::listen(os_handle, qs)))
		return true;
	Close();
	return false;
}

bool YaTCPSocket::Accept(YaTCPSocket & socket)
{
	while (true) {
		int fd = socket.GetHandle();
		if (fd < 0) { // socket closed
			errno = ENOTSOCK;
			break;
		}

		YaSelectList::large_fd_set fdset;
		fdset.add(fd);
		struct timeval tval = { 1, 0 };
		int r = ::select(fd + 1, fdset, 0, 0, &tval);
		if (r < 0)
			break;
		else if (r == 0)
			continue;

		socklen_t addrsize = sizeof(peeraddr);
		os_handle = ::accept(fd, (struct sockaddr *)&peeraddr, &addrsize);
		if (os_handle < 0)
			break;

		SetLinger();
		SetNonBlockingMode();
		SetWriteTimeout(PTimeInterval(10));
		SetName(AsString(peeraddr.sin_addr, ntohs(peeraddr.sin_port)));
		port = socket.GetPort();
		return true;
	}
	return ConvertOSError(-1);
}

bool YaTCPSocket::Connect(const Address & iface, WORD localPort, const Address & addr)
{
	if (os_handle < 0) {
		os_handle = ::socket(PF_INET, SOCK_STREAM, 0);
		if (!ConvertOSError(os_handle))
			return false;
	}

	int optval;
	socklen_t optlen = sizeof(optval);

	WORD peerPort = port;
	// bind local interface and port
	if (iface != INADDR_ANY || localPort != 0)
		if (!Bind(iface, localPort))
			return false;

	// connect in non-blocking mode
	SetNonBlockingMode();
	SetWriteTimeout(PTimeInterval(10));
	peeraddr.sin_addr = addr;
	peeraddr.sin_port = htons(port = peerPort);
	SetName(AsString(addr, port));

	int r = ::connect(os_handle, (struct sockaddr *)&peeraddr, sizeof(peeraddr));
#ifdef WIN32
	if ((r != 0) && (WSAGetLastError() != WSAEWOULDBLOCK))
#else
	if (r == 0 || errno != EINPROGRESS)
#endif
		return ConvertOSError(r);

	YaSelectList::large_fd_set fdset;
	fdset.add(os_handle);
	YaSelectList::large_fd_set exset = fdset;
	struct timeval tval = { 6, 0 }; // TODO: read from config...
	if (::select(os_handle + 1, 0, fdset, exset, &tval) > 0) {
		optval = -1;
		::getsockopt(os_handle, SOL_SOCKET, SO_ERROR, &optval, &optlen);
		if (optval == 0) // connected
			return SetLinger();
		errno = optval;
	}
	return ConvertOSError(-1);
}

bool YaTCPSocket::Connect(const Address & addr)
{
	return YaTCPSocket::Connect(INADDR_ANY, 0, addr);
}

int YaTCPSocket::os_recv(void *buf, int sz)
{
#if HAS_MSG_NOSIGNAL
	return ::recv(os_handle, buf, sz, MSG_NOSIGNAL);
#else
	return ::recv(os_handle, buf, sz, 0);
#endif
}

int YaTCPSocket::os_send(const void *buf, int sz)
{
#if HAS_MSG_NOSIGNAL
	return ::send(os_handle, buf, sz, MSG_NOSIGNAL);
#else
	return ::send(os_handle, buf, sz, 0);
#endif
}


// class YaUDPSocket
YaUDPSocket::YaUDPSocket()
{
	sendaddr.sin_family = AF_INET;
	sendaddr.sin_port = 0;
}

bool YaUDPSocket::Listen(unsigned, WORD pt)
{
	return Listen(INADDR_ANY, 0, pt, 0);
}

bool YaUDPSocket::Listen(const Address & addr, unsigned, WORD pt, int)
{
	os_handle = ::socket(PF_INET, SOCK_DGRAM, 0);
	if (!ConvertOSError(os_handle))
		return false;

	SetNonBlockingMode();
	return Bind(addr, pt);
}

void YaUDPSocket::GetLastReceiveAddress(Address & addr, WORD & pt) const
{
	addr = recvaddr.sin_addr;
	pt = ntohs(recvaddr.sin_port);
}

void YaUDPSocket::SetSendAddress(const Address & addr, WORD pt)
{
	sendaddr.sin_addr = addr;
	sendaddr.sin_port = htons(pt);
}

void YaUDPSocket::GetSendAddress(
	Address& address, /// IP address to send packets.
	WORD& port /// Port to send packets.
	)
{
	address = sendaddr.sin_addr;
	port = ntohs(sendaddr.sin_port);
}

bool YaUDPSocket::ReadFrom(void *buf, PINDEX len, Address & addr, WORD pt)
{
	bool result = Read(buf, len);
	if (result)
		GetLastReceiveAddress(addr, pt);
	return result;
}

bool YaUDPSocket::WriteTo(const void *buf, PINDEX len, const Address & addr, WORD pt)
{
	SetSendAddress(addr, pt);
	return Write(buf, len);
}

int YaUDPSocket::os_recv(void *buf, int sz)
{
	socklen_t addrlen = sizeof(recvaddr);
	return ::recvfrom(os_handle, buf, sz, 0, (struct sockaddr *)&recvaddr, &addrlen);
}

int YaUDPSocket::os_send(const void *buf, int sz)
{
	return ::sendto(os_handle, buf, sz, 0, (struct sockaddr *)&sendaddr, sizeof(sendaddr));
}

#else // LARGE_FDSET

bool SocketSelectList::Select(SelectType t, const PTimeInterval & timeout)
{
	if (IsEmpty())
		return false;
	SocketSelectList dumb, *rlist, *wlist;
	if (t == Read)
		rlist = this, wlist = &dumb;
	else
		wlist = this, rlist = &dumb;
	const PSocket::Errors r = PSocket::Select(*rlist, *wlist, timeout);
	PTRACE_IF(3, r != PSocket::NoError, "ProxyH\tSelect error: " << r);
	return !IsEmpty();
}

PSocket *SocketSelectList::operator[](int i) const
{
	typedef PSocket::SelectList PSocketSelectList; // stupid VC...
	return &PSocketSelectList::operator[](i);
}

#endif // LARGE_FDSET


// class USocket
USocket::USocket(IPSocket *s, const char *t) 
	: self(s), qsize(0), blocked(false), type(t)
{
}

USocket::~USocket()
{
	//PWaitAndSignal lock(writeMutex);
	{
		PWaitAndSignal lock(queueMutex);
		DeleteObjectsInContainer(queue);
		queue.clear();
		qsize = 0;
	}
	PTRACE(3, type << "\tDelete socket " << Name());
}

bool USocket::TransmitData(const PBYTEArray & buf)
{
	return WriteData(buf, buf.GetSize());
}

bool USocket::TransmitData(const PString & str)
{
	return WriteData(str, str.GetLength());
}

bool USocket::TransmitData(const BYTE *buf, int len)
{
	return WriteData(buf, len);
}

bool USocket::Flush()
{
	bool result = true;
	PWaitAndSignal lock(writeMutex);
	while (result && qsize > 0) {
		PBYTEArray* const pdata = PopQueuedPacket();
		if (pdata) {
			result = InternalWriteData(*pdata, pdata->GetSize());
			PTRACE_IF(4, result, type << '\t' << pdata->GetSize() << " bytes flushed to " << Name());
			delete pdata;
		} else
			break;
	}
	return result;
}

bool USocket::WriteData(const BYTE *buf, int len)
{
	if (IsSocketOpen()) {
		if (qsize == 0 && !writeMutex.WillBlock()) {
			PWaitAndSignal lock(writeMutex);
			return InternalWriteData(buf, len);
		}
		if (qsize > 100) { // to be justitied
			PTRACE(2, type << '\t' << Name() << " is dead and closed");
			CloseSocket();
		} else {
			PTRACE(3, type << '\t' << Name() << " is busy, " << len << " bytes queued");
			QueuePacket(buf, len);
		}
	}
	return false;
}

bool USocket::ErrorHandler(PSocket::ErrorGroup group)
{
	PSocket::Errors e = self->GetErrorCode(group);

	PString msg(PString(type) + "\t" + Name());
	switch (e)
	{
		case PSocket::Timeout:
			PTRACE(4, msg << " Error(" << group << "): Timeout");
			break;
		case PSocket::NoError:
			if (group == PSocket::LastReadError) {
				PTRACE(5, msg << " closed by remote");
				CloseSocket();
				break;
			}
		default:
			PTRACE(3, msg << " Error(" << group << "): " 
				<< PSocket::GetErrorText(e) << " (" << e << ':'
				<< self->GetErrorNumber(group) << ')'
				);
			CloseSocket();
			break;
	}
	return false;
}

bool USocket::InternalWriteData(const BYTE *buf, int len)
{
	if (self->Write(buf, len)) {
		PTRACE(6, Name() << ' ' << len << " bytes sent");
		return true;
	}

	int wcount = self->GetLastWriteCount();
	buf += wcount, len -= wcount;

	if (wcount == 0)
		ErrorHandler(PSocket::LastWriteError);
	if (IsSocketOpen()) {
		PTRACE(4, type << '\t' << Name() << " blocked, " << wcount << " bytes written, " << len << " bytes queued");
		// push_front used intentionally, as InternalWriteData can be called
		// either when flushing the queue (so any remaining unflushed data
		// should be put back at the queue front) or when the queue is epmty
		PWaitAndSignal lock(queueMutex);
		queue.push_front(new PBYTEArray(buf, len));
		++qsize;
	}
	return false;
}

void USocket::ClearQueue()
{
	queueMutex.Wait();
	DeleteObjectsInContainer(queue);
	queue.clear();
	qsize = 0;
	queueMutex.Signal();
}


// class SocketsReader
SocketsReader::SocketsReader(int t) : m_timeout(t), m_socksize(0), m_rmsize(0)
{
	SetName("SocketsReader");
}

SocketsReader::~SocketsReader()
{
	RemoveClosed(false);
	SocketsReader::CleanUp();
	//DeleteObjectsInContainer(m_removed);
	//DeleteObjectsInContainer(m_sockets);
}

void SocketsReader::Stop()
{
	PWaitAndSignal lock(m_deletionPreventer);
	ReadLock llock(m_listmutex);
	ForEachInContainer(m_sockets, mem_fun(&IPSocket::Close));
	RegularJob::Stop();
}

void SocketsReader::AddSocket(IPSocket *socket)
{
	m_listmutex.StartWrite();
	m_sockets.push_back(socket);
	++m_socksize;
	m_listmutex.EndWrite();
	Signal();
	PTRACE(5, GetName() << " total sockets " << m_socksize);
}

bool SocketsReader::BuildSelectList(SocketSelectList & slist)
{
	ReadLock lock(m_listmutex);
	ForEachInContainer(m_sockets, bind1st(mem_fun(&SocketSelectList::Append), &slist));
	return !slist.IsEmpty();
}

void SocketsReader::CleanUp()
{
	PWaitAndSignal lock(m_rmutex);
	DeleteObjectsInContainer(m_removed);
	m_removed.clear();
	m_rmsize = 0;
}

bool SocketsReader::SelectSockets(SocketSelectList & slist)
{
#if PTRACING
	int ss = slist.GetSize();
#endif
	ReadUnlock cfglock(ConfigReloadMutex);
	if (!slist.Select(SocketSelectList::Read, m_timeout))
		return false;

#if PTRACING
	PString msg(PString::Printf, " %u sockets selected from %u, total %u/%u", slist.GetSize(), ss, m_socksize, m_rmsize);
	PTRACE(5, GetName() << msg);
#endif
	return true;
}

void SocketsReader::RemoveClosed(bool bDeleteImmediately)
{
	WriteLock lock(m_listmutex);
	iterator iter = partition(m_sockets.begin(), m_sockets.end(), mem_fun(&IPSocket::IsOpen));
	if (ptrdiff_t rmsize = distance(iter, m_sockets.end())) {
		if (bDeleteImmediately)
			DeleteObjects(iter, m_sockets.end());
		else {
			PWaitAndSignal lock(m_rmutex);
			copy(iter, m_sockets.end(), back_inserter(m_removed));
			m_rmsize += rmsize;
		}
		m_sockets.erase(iter, m_sockets.end());
		m_socksize -= rmsize;
	}
}
/*
void SocketsReader::RemoveSocket(iterator i)
{
	m_sockets.erase(i);
	--m_socksize;
	PWaitAndSignal lock(m_rmutex);
	m_removed.push_back(*i);
	++m_rmsize;
}

void SocketsReader::RemoveSocket(IPSocket *s)
{
	m_sockets.remove(s);
	--m_socksize;
	PWaitAndSignal lock(m_rmutex);
	m_removed.push_back(s);
	++m_rmsize;
}
*/
void SocketsReader::Exec()
{
	ReadLock cfglock(ConfigReloadMutex);
	SocketSelectList slist;

	if (BuildSelectList(slist)) {
		if (SelectSockets(slist)) {
			int ss = slist.GetSize();
			for (int i = 0; i < ss; ++i)
#ifdef LARGE_FDSET
				ReadSocket(slist[i]);
#else
				ReadSocket(dynamic_cast<IPSocket *>(slist[i]));
#endif
		}
		CleanUp();
	} else {
		CleanUp();
		ReadUnlock unlock(ConfigReloadMutex);
		PTRACE(3, GetName() << " waiting...");
		Wait();
	}
}


// class TCPListenSocket
TCPListenSocket::TCPListenSocket(int timeout)
{
	if (timeout > 0)
		SetReadTimeout(timeout * 1000);
}

TCPListenSocket::~TCPListenSocket()
{
	PTRACE(3, "TCP\t" << "Delete listener " << GetName());
}

bool TCPListenSocket::IsTimeout(const PTime *now) const
{
	if ( readTimeout < PMaxTimeInterval )
	{
		return IsOpen() ? ((readTimeout > 0) ? ((*now - start) > readTimeout) : false) : true;
	}
	else
	{
		return ! IsOpen();
	}
}


// class TCPServer
TCPServer::TCPServer()
{
	SetName("TCPServer");
	Execute();
}

bool TCPServer::CloseListener(TCPListenSocket *socket)
{
	ReadLock lock(m_listmutex);
	iterator iter = find(m_sockets.begin(), m_sockets.end(), socket);
	return (iter != m_sockets.end()) ? (*iter)->Close() : false;
}

void TCPServer::ReadSocket(IPSocket *socket)
{
	PTRACE(4, "TCP\t" << "Accept request on " << socket->GetName());
	TCPListenSocket *listener = dynamic_cast<TCPListenSocket *>(socket);
	ServerSocket *acceptor = listener->CreateAcceptor();
	if (acceptor->Accept(*listener))
		CreateJob(acceptor, &ServerSocket::Dispatch, "Acceptor");
	else
		delete acceptor;
}

void TCPServer::CleanUp()
{
	PTime now;
	WriteLock lock(m_listmutex);
	iterator iter = m_sockets.begin(), eiter = m_sockets.end();
	while (iter != eiter) {
		iterator i = iter++;
		TCPListenSocket *listener = dynamic_cast<TCPListenSocket *>(*i);
		if (listener && listener->IsTimeout(&now)) {
			m_sockets.erase(i);
			--m_socksize;
			delete listener;
		}
	}
}
