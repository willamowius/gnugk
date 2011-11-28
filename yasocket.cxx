//////////////////////////////////////////////////////////////////
//
// yasocket.cxx
//
// Copyright (c) Citron Network Inc. 2002-2003
// Copyright (c) 2004-2011, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include "h323util.h"
#include "stl_supp.h"
#include "rwlock.h"
#include "yasocket.h"
#include "Toolkit.h"
#include "gk.h"

using std::mem_fun;
using std::bind1st;
using std::partition;
using std::distance;
using std::copy;
using std::back_inserter;
using std::find;

namespace {
/// time to recheck state of closed sockets owned by a proxy handler
const long SOCKETSREADER_IDLE_TIMEOUT = 1000;
const long SOCKET_CHUNK_PAUSE = 250;	// send in 10K chunks
const int MAX_SOCKET_CHUNK = 10240;	// send in 10K chunks
}

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
	tval.tv_sec = msec / 1000;
	tval.tv_usec = (msec - tval.tv_sec * 1000) * 1000;
	int r = ::select(maxfd + 1, readfds, writefds, 0, &tval);
	if (r > 0) {
#if 1
		std::vector<YaSocket*>::iterator last = remove_if(
			fds.begin(), fds.end(),
			not1(compose1(
				bind1st(mem_fun(&large_fd_set::has), &fdset),
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
				++j;
		}
		// reorder remaining sockets, so non-selected sockets
		// are moved to the end of the vector
		if (hasfd) {
			while (++j != rendIter) {
				if (!fdset.has((*j)->GetHandle())) {
					*j = *k--;
				}
			}
			// at this point the vector [begin(),k] should contain
			// all selected sockets, so erase the remaining vector elements
			fds.erase(++k, fds.end());
		} else {
			fds.clear();
		}
#endif
	} else if (r < 0) {
		PTRACE(3, GetName() << "\tSelect " << (t == Read ? "read" : "write") << " error - errno: " << errno);
	}
	return r > 0;
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
#ifdef _WIN32
	::closesocket(handle);
#else
	::close(handle);
#endif
	return true;
}

bool YaSocket::Read(void * buf, int sz)
{
	int r = os_recv(buf, sz);
	lastReadCount = ConvertOSError(r, PSocket::LastReadError) ? r : 0;
	return lastReadCount > 0;
}

bool YaSocket::ReadBlock(void * buf, int len)
{
	// lazy implementation, but it is enough for us...
	return Read(buf, len) && lastReadCount == len;
}

bool YaSocket::CanRead(long timeout) const
{
	const int h = os_handle;
	if (h < 0)
		return false;

	YaSelectList::large_fd_set fdset;
	fdset.add(h);

	struct timeval tval;
	tval.tv_sec = timeout / 1000;
	tval.tv_usec = (timeout - tval.tv_sec * 1000) * 1000;
	return ::select(h + 1, (fd_set*)fdset, NULL, NULL, &tval) > 0;
}

bool YaSocket::CanWrite(long timeout) const
{
	const int h = os_handle;
	if (h < 0)
		return false;
		
	YaSelectList::large_fd_set fdset;
	fdset.add(h);

	struct timeval tval;
	tval.tv_sec = timeout / 1000;
	tval.tv_usec = (timeout - tval.tv_sec * 1000) * 1000;
	return ::select(h + 1, NULL, (fd_set*)fdset, NULL, &tval) > 0;
}

bool YaSocket::Write(const void * buf, int sz)
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

PBoolean YaSocket::GetLocalAddress(Address & addr) const
{
	WORD pt;
	return GetLocalAddress(addr, pt);
}

PBoolean YaSocket::GetLocalAddress(Address & addr, WORD & pt) const
{
#ifdef hasIPV6
	sockaddr_in6 inaddr;
#else
	sockaddr_in inaddr;
#endif
	socklen_t insize = sizeof(inaddr);
	if (::getsockname(os_handle, (struct sockaddr*)&inaddr, &insize) == 0) {
#ifdef hasIPV6
		if (((struct sockaddr*)&inaddr)->sa_family == AF_INET6) {
			addr = ((struct sockaddr_in6*)&inaddr)->sin6_addr;
			pt = ntohs(((struct sockaddr_in6*)&inaddr)->sin6_port);
		} else
#endif
		{
			addr = ((struct sockaddr_in*)&inaddr)->sin_addr;
			pt = ntohs(((struct sockaddr_in*)&inaddr)->sin_port);
		}
	}
	return true;
}

bool YaSocket::SetOption(int option, int value, int level)
{
	return ConvertOSError(::setsockopt(os_handle, level, option, (char *)&value, sizeof(int)));
}

bool YaSocket::SetOption(int option, const void *value, int size, int level)
{
	return ConvertOSError(::setsockopt(os_handle, level, option, (char *)value, size));
}

bool YaSocket::GetOption(int option, int & value, int level)
{
	socklen_t valSize = sizeof(value);
	return ConvertOSError(::getsockopt(os_handle, level, option, (char *)&value, &valSize));
}

bool YaSocket::GetOption(int option, void * valuePtr, PINDEX valueSize, int level)
{
	return ConvertOSError(::getsockopt(os_handle, level, option,
		(char *)valuePtr, (socklen_t *)&valueSize)
		);
}

PString YaSocket::GetErrorText(PSocket::ErrorGroup group) const
{
	return PSocket::GetErrorText(GetErrorCode(group));
}

bool YaSocket::ConvertOSError(int libReturnValue, PSocket::ErrorGroup group)
{
	if (libReturnValue < 0 && errno == EAGAIN) {
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
	// is call to F_SETFD with F_CLOEXEC really neccessary?
	int cmd = 1;
	if (ConvertOSError(::ioctl(os_handle, FIONBIO, &cmd))
			&& ConvertOSError(::fcntl(os_handle, F_SETFD, 1)))
		return true;
	Close();
	return false;

}

bool YaSocket::Bind(const Address & addr, WORD pt)
{
	if (IsOpen()) {
#ifdef hasIPV6
		if (addr.GetVersion() == 6) {
			struct sockaddr_in6 inaddr;
			SetSockaddr(inaddr, addr, pt);
			if (ConvertOSError(::bind(os_handle, (struct sockaddr*)&inaddr, sizeof(inaddr)))) {
				socklen_t insize = sizeof(inaddr);
				if (::getsockname(os_handle, (struct sockaddr*)&inaddr, &insize) == 0) {
					port = ntohs(inaddr.sin6_port);
					return true;
				}
			}
		} else
#endif
		{
			struct sockaddr_in inaddr;
			SetSockaddr(inaddr, addr, pt);
			if (ConvertOSError(::bind(os_handle, (struct sockaddr*)&inaddr, sizeof(inaddr)))) {
				socklen_t insize = sizeof(inaddr);
				if (::getsockname(os_handle, (struct sockaddr*)&inaddr, &insize) == 0) {
					port = ntohs(inaddr.sin_port);
					return true;
				}
			}
		}
	}
	return false;
}


// class YaTCPSocket
YaTCPSocket::YaTCPSocket(WORD pt)
{
	((struct sockaddr*)&peeraddr)->sa_family = AF_INET;		// overwritten in Connect()
	SetPort(pt);
}

void YaTCPSocket::GetPeerAddress(Address & addr) const
{
#ifdef hasIPV6
	if (((struct sockaddr*)&peeraddr)->sa_family == AF_INET6)
		addr = ((struct sockaddr_in6*)&peeraddr)->sin6_addr;
	else
#endif
		addr = ((struct sockaddr_in*)&peeraddr)->sin_addr;
}

void YaTCPSocket::GetPeerAddress(Address & addr, WORD & pt) const
{
#ifdef hasIPV6
	if (((struct sockaddr*)&peeraddr)->sa_family == AF_INET6) {
		addr = ((struct sockaddr_in6*)&peeraddr)->sin6_addr;
		pt = ntohs(((struct sockaddr_in6*)&peeraddr)->sin6_port);
	} else
#endif
	{
		addr = ((struct sockaddr_in*)&peeraddr)->sin_addr;
		pt = ntohs(((struct sockaddr_in*)&peeraddr)->sin_port);
	}
}

bool YaTCPSocket::SetLinger()
{
	SetOption(TCP_NODELAY, 1, IPPROTO_TCP);
	const linger ling = { 1, 3 };
	return SetOption(SO_LINGER, &ling, sizeof(ling));
}

bool YaTCPSocket::Listen(unsigned qs, WORD pt, PSocket::Reusability reuse)
{
	return Listen(GNUGK_INADDR_ANY, qs, pt, reuse);
}

bool YaTCPSocket::Listen(const Address & addr, unsigned qs, WORD pt, PSocket::Reusability reuse)
{
#ifdef hasIPV6
	if (addr.GetVersion() == 6) {
		os_handle = ::socket(PF_INET6, SOCK_STREAM, 0);
		if (addr.IsAny() && !SetOption(IPV6_V6ONLY, 0, IPPROTO_IPV6)) {
			PTRACE(1, "Removing of IPV6_V6ONLY failed");
		}
	}
	else
#endif
	{
		os_handle = ::socket(PF_INET, SOCK_STREAM, 0);
	}
	if (!ConvertOSError(os_handle))
		return false;

	if (!SetOption(SO_REUSEADDR, reuse == PSocket::CanReuseAddress ? 1 : 0))
		return false;
	
//	SetNonBlockingMode();
	if (Bind(addr, pt) && ConvertOSError(::listen(os_handle, qs)))
		return true;
	Close();
	return false;
}

#ifdef hasIPV6
bool YaTCPSocket::DualStackListen(WORD port)
{
	return Listen(GNUGK_INADDR_ANY, 1, port, PSocket::CanReuseAddress);
}
#endif


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
#ifdef hasIPV6
		if (((struct sockaddr *)&peeraddr)->sa_family == AF_INET6)
			SetName(AsString(((struct sockaddr_in6*)&peeraddr)->sin6_addr, ntohs(((struct sockaddr_in6*)&peeraddr)->sin6_port)));
		else
#endif
			SetName(AsString(((struct sockaddr_in*)&peeraddr)->sin_addr, ntohs(((struct sockaddr_in*)&peeraddr)->sin_port)));
		port = socket.GetPort();
		return true;
	}
	return ConvertOSError(-1);
}

bool YaTCPSocket::Connect(const Address & iface, WORD localPort, const Address & addr)
{
	if (os_handle < 0) {
#ifdef hasIPV6
		if (iface.GetVersion() == 6)
			os_handle = ::socket(PF_INET6, SOCK_STREAM, 0);
		else
#endif
			os_handle = ::socket(PF_INET, SOCK_STREAM, 0);
		if (!ConvertOSError(os_handle))
			return false;
	}

	SetOption(SO_REUSEADDR, 0);

	int optval;
	socklen_t optlen = sizeof(optval);

	WORD peerPort = port;
	// bind local interface and port
	if (!iface.IsAny() || localPort != 0)
		if (!Bind(iface, localPort))
			return false;

	// connect in non-blocking mode
	SetNonBlockingMode();
	SetWriteTimeout(PTimeInterval(10));
	port = peerPort;
	SetSockaddr(peeraddr, addr, peerPort);
	SetName(AsString(addr, port));

#ifdef P_FREEBSD
	// FreeBSD is extra picky about the size argument, not sure if thats the correct size for Linux
	int r = ::connect(os_handle, (struct sockaddr*)&peeraddr, sizeof(struct sockaddr));
#else
	int r = ::connect(os_handle, (struct sockaddr*)&peeraddr, sizeof(peeraddr));
#endif

#ifdef _WIN32
	if ((r != 0) && (WSAGetLastError() != WSAEWOULDBLOCK))
#else
	if (r == 0 || errno != EINPROGRESS)
#endif
		return ConvertOSError(r);

	YaSelectList::large_fd_set fdset;
	fdset.add(os_handle);
	YaSelectList::large_fd_set exset = fdset;
	struct timeval tval = { 6, 0 };
	if ((r = ::select(os_handle + 1, 0, fdset, exset, &tval)) > 0) {
		optval = -1;
		::getsockopt(os_handle, SOL_SOCKET, SO_ERROR, &optval, &optlen);
		if (optval == 0) // connected
			return SetLinger();
		errno = optval;
	} else {
		if (r == 0) {
#ifdef _WIN32
			errno = WSAETIMEDOUT;
#else
			errno = ETIMEDOUT;
#endif
		}
	}
	return ConvertOSError(-1);
}

bool YaTCPSocket::Connect(const Address & addr)
{
	return YaTCPSocket::Connect(GNUGK_INADDR_ANY, 0, addr);
}

int YaTCPSocket::os_recv(void * buf, int sz)
{
#if HAS_MSG_NOSIGNAL
	return ::recv(os_handle, buf, sz, MSG_NOSIGNAL);
#else
	return ::recv(os_handle, buf, sz, 0);
#endif
}

int YaTCPSocket::os_send(const void * buf, int sz)
{
#if HAS_MSG_NOSIGNAL
	return ::send(os_handle, buf, sz, MSG_NOSIGNAL);
#else
	return ::send(os_handle, buf, sz, 0);
#endif
}


// class YaUDPSocket
YaUDPSocket::YaUDPSocket(WORD port, int iAddressFamily)
{
	((struct sockaddr*)&sendaddr)->sa_family = iAddressFamily;
	((struct sockaddr_in*)&sendaddr)->sin_port = htons(port);
}

bool YaUDPSocket::Listen(unsigned, WORD pt, PSocket::Reusability reuse)
{
	return Listen(GNUGK_INADDR_ANY, 0, pt, reuse);
}

bool YaUDPSocket::Listen(const Address & addr, unsigned, WORD pt, PSocket::Reusability reuse)
{
#ifdef hasIPV6
	if (addr.GetVersion() == 6) {
		os_handle = ::socket(PF_INET6, SOCK_DGRAM, 0);
		if (addr.IsAny() && !SetOption(IPV6_V6ONLY, 0, IPPROTO_IPV6)) {
			PTRACE(1, "Removing of IPV6_V6ONLY failed");
		}
	} else
#endif
		os_handle = ::socket(PF_INET, SOCK_DGRAM, 0);
	if (!ConvertOSError(os_handle))
		return false;

	if (!SetNonBlockingMode())
		return false;
	if (!SetOption(SO_REUSEADDR, reuse == PSocket::CanReuseAddress ? 1 : 0))
		return false;
	return Bind(addr, pt);
}

#ifdef hasIPV6
bool YaUDPSocket::DualStackListen(const Address & addr, WORD pt)
{
	return Listen(addr, 0, pt, PSocket::CanReuseAddress);
}
#endif

void YaUDPSocket::GetLastReceiveAddress(Address & addr, WORD & pt) const
{
#ifdef hasIPV6
	if (((struct sockaddr*)&recvaddr)->sa_family == AF_INET6) {
		addr = ((struct sockaddr_in6*)&recvaddr)->sin6_addr;
		pt = ntohs(((struct sockaddr_in6*)&recvaddr)->sin6_port);
	} else
#endif
	{
		addr = ((struct sockaddr_in*)&recvaddr)->sin_addr;
		pt = ntohs(((struct sockaddr_in*)&recvaddr)->sin_port);
	}
}

void YaUDPSocket::SetSendAddress(const Address & addr, WORD pt)
{
	SetSockaddr(sendaddr, addr, pt);
}

void YaUDPSocket::GetSendAddress(
	Address & address, /// IP address to send packets.
	WORD & port /// Port to send packets.
	)
{
#ifdef hasIPV6
	if (((struct sockaddr*)&sendaddr)->sa_family == AF_INET6) {
		address = ((struct sockaddr_in6*)&sendaddr)->sin6_addr;
		port = ntohs(((struct sockaddr_in6*)&sendaddr)->sin6_port);
	} else
#endif
	{
		address = ((struct sockaddr_in*)&sendaddr)->sin_addr;
		port = ntohs(((struct sockaddr_in*)&sendaddr)->sin_port);
	}
}

bool YaUDPSocket::ReadFrom(void * buf, PINDEX len, Address & addr, WORD pt)
{
	bool result = Read(buf, len);
	if (result)
		GetLastReceiveAddress(addr, pt);
	return result;
}

bool YaUDPSocket::WriteTo(const void * buf, PINDEX len, const Address & addr, WORD pt)
{
	SetSendAddress(addr, pt);
	return Write(buf, len);
}

int YaUDPSocket::os_recv(void * buf, int sz)
{
	socklen_t addrlen = sizeof(recvaddr);
	return ::recvfrom(os_handle, buf, sz, 0, (struct sockaddr *)&recvaddr, &addrlen);
}

int YaUDPSocket::os_send(const void * buf, int sz)
{
	return ::sendto(os_handle, buf, sz, 0, (struct sockaddr *)&sendaddr, sizeof(sendaddr));
}

#else // LARGE_FDSET

#ifdef hasIPV6
bool TCPSocket::DualStackListen(WORD newPort)
{
	if (!Toolkit::Instance()->IsIPv6Enabled())
		return Listen(GNUGK_INADDR_ANY, 1, newPort, PSocket::CanReuseAddress);

	// make sure we have a port
	if (newPort != 0)
		port = newPort;

	// Always close and re-open as the bindAddr address family might change.
	os_close();

	// attempt to create a socket
	if (!OpenSocket(PF_INET6)) {
		PTRACE(4, "Socket\tOpenSocket failed");
		return false;
	}

	// allow IPv4 connects
	if (!SetOption(IPV6_V6ONLY, 0, IPPROTO_IPV6)) {
		PTRACE(4, "Socket\tSetOption(IPV6_V6ONLY) failed");
	}

	// attempt to listen
	if (!SetOption(SO_REUSEADDR, 1)) {
		PTRACE(4, "Socket\tSetOption(SO_REUSEADDR) failed");
		os_close();
		return false;
	}

	sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_addr = in6addr_any;
	sa.sin6_port = htons(newPort);
	if (!ConvertOSError(::bind(os_handle, (sockaddr*)&sa, sizeof(sa)))) {
		os_close();
		return false;
	}

	if (!ConvertOSError(::listen(os_handle, 1))) {
		PTRACE(4, "Socket\tlisten failed: " << GetErrorText());
		os_close();
		return false;
	}

	if (port != 0)
		return true;

	socklen_t size = sizeof(sa);
	if (!ConvertOSError(::getsockname(os_handle, (sockaddr*)&sa, &size))) {
		PTRACE(4, "Socket\tgetsockname failed: " << GetErrorText());
		os_close();
		return false;
	}

	port = ntohs(sa.sin6_port);
	return true;
}
#endif

UDPSocket::UDPSocket(WORD port, int iAddressFamily)
#ifdef hasIPV6
	// can use always, because old PTLib versions (eg. 2.4.5) didn't have 2nd argument
	: PUDPSocket(port, iAddressFamily)
#endif
{
}

#ifdef hasIPV6
bool UDPSocket::DualStackListen(const PIPSocket::Address & localAddr, WORD newPort)
{
	if (!Toolkit::Instance()->IsIPv6Enabled() || !localAddr.IsAny())
		return Listen(localAddr, 0, newPort);

	// make sure we have a port
	if (newPort != 0)
		port = newPort;

	// Always close and re-open as the bindAddr address family might change.
	os_close();

	// attempt to create a socket
	if (!OpenSocket(PF_INET6)) {
		PTRACE(4, "Socket\tOpenSocket failed");
		return false;
	}

	// allow IPv4 connects
	if (!SetOption(IPV6_V6ONLY, 0, IPPROTO_IPV6)) {
		PTRACE(4, "Socket\tSetOption(IPV6_V6ONLY) failed");
	}

	sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_addr = in6addr_any;
	sa.sin6_port = htons(newPort);
	if (!ConvertOSError(::bind(os_handle, (sockaddr*)&sa, sizeof(sa)))) {
		os_close();
		return false;
	}

	if (port != 0)
		return true;

	socklen_t size = sizeof(sa);
	if (!ConvertOSError(::getsockname(os_handle, (sockaddr*)&sa, &size))) {
		PTRACE(4, "Socket\tgetsockname failed: " << GetErrorText());
		os_close();
		return false;
	}

	port = ntohs(sa.sin6_port);
	return true;
}

#endif

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
	if (r != PSocket::NoError) {
		PTRACE(3, GetName() << "\tSelect " << (t == Read ? "read" : "write") << " error: " << r);
		return false;
	} else
		return !IsEmpty();
}

PSocket *SocketSelectList::operator[](int i) const
{
	typedef PSocket::SelectList PSocketSelectList; // stupid VC...
	return &PSocketSelectList::operator[](i);
}

#endif // LARGE_FDSET


// class USocket
USocket::USocket(IPSocket * s, const char * t)
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
	PIPSocket::Address addr(0);
	WORD port = 0;
	self->GetLocalAddress(addr, port);
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

bool USocket::TransmitData(const BYTE * buf, int len)
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
			unsigned bytesSent = self->GetLastWriteCount();
			PTRACE_IF(4, bytesSent > 0, type << '\t' << bytesSent << " bytes flushed to " << Name());
			delete pdata;
		} else
			break;
	}
	return result;
}

bool USocket::WriteData(const BYTE * buf, int len)
{
	if (!IsSocketOpen())
		return false;
		
	int remaining = len;
	if (qsize == 0 && !writeMutex.WillBlock()) {
		PWaitAndSignal lock(writeMutex);
		while (remaining > 0) {
			int sendnow = remaining > MAX_SOCKET_CHUNK
				? MAX_SOCKET_CHUNK : remaining;
			if (!InternalWriteData(buf, sendnow)) {
				unsigned bytesSent = self->GetLastWriteCount();
				remaining -= bytesSent;
				buf += bytesSent;
				break;
			} else {
				remaining -= sendnow;
				buf += sendnow;
				if (remaining > 0)
					PThread::Sleep(SOCKET_CHUNK_PAUSE);
			}
		}
		if (remaining == 0)
			return true;
	}
	if (qsize > 100) { // to be justitied
		PTRACE(2, type << '\t' << Name() << " is dead and closed");
		CloseSocket();
	} else if (remaining > 0 && IsSocketOpen()) {
		PTRACE(3, type << '\t' << Name() << " is busy, " << len << " bytes queued");
		QueuePacket(buf, remaining);
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
			}
			break;
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

bool USocket::InternalWriteData(const BYTE * buf, int len)
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
		std::list<PBYTEArray*>::iterator i = queue.begin();
		while (len > 0) {
			int chunk = len > MAX_SOCKET_CHUNK ? MAX_SOCKET_CHUNK : len;
			i = queue.insert(i, new PBYTEArray(buf, chunk));
			++i;
			++qsize;
			len -= chunk;
			buf += chunk;
		}
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
	SetName("SockRdr");
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
	
	m_listmutex.StartWrite();
	ForEachInContainer(m_sockets, mem_fun(&IPSocket::Close));
	m_listmutex.EndWrite();
	
	RegularJob::Stop();
}

void SocketsReader::AddSocket(IPSocket * socket)
{
	if (socket == NULL)
		return;
	m_listmutex.StartWrite();
	iterator iter = find(m_sockets.begin(), m_sockets.end(), socket);
	if (iter == m_sockets.end()) {
		m_sockets.push_back(socket);
		++m_socksize;
	} else
		PTRACE(1, GetName() << "\tTrying to add an already existing socket to the handler");
	m_listmutex.EndWrite();
	Signal();
	PTRACE(5, GetName() << "\tTotal sockets: " << m_socksize);
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
	int ss = slist.GetSize();
	ConfigReloadMutex.EndRead();
	if (!slist.Select(SocketSelectList::Read, m_timeout)) {
		ConfigReloadMutex.StartRead();
		return false;
	}
	ConfigReloadMutex.StartRead();
	if (PTrace::CanTrace(6)) {
		PString msg(PString::Printf, "\t%u sockets selected from %u, total %u/%u", slist.GetSize(), ss, m_socksize, m_rmsize);
		PTRACE(6, GetName() << msg);
	}
	return true;
}

void SocketsReader::RemoveClosed(bool bDeleteImmediately)
{
	WriteLock listlock(m_listmutex);
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

void SocketsReader::Exec()
{
	ReadLock cfglock(ConfigReloadMutex);
	SocketSelectList slist(GetName());

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
		ConfigReloadMutex.EndRead();
		PTRACE(6, GetName() << " waiting...");
		Wait(SOCKETSREADER_IDLE_TIMEOUT);
		ConfigReloadMutex.StartRead();
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
	PTRACE(3, "TCP\tDelete listener " << GetName());
}

bool TCPListenSocket::IsTimeout(const PTime * now) const
{
	if (readTimeout < PMaxTimeInterval)
		return IsOpen() ? ((readTimeout > 0) ? ((*now - start) > readTimeout) : false) : true;
	else
		return !IsOpen();
}


// class TCPServer
TCPServer::TCPServer()
{
	SetName("TCPSrv");
	LoadConfig();
	Execute();
}

void TCPServer::LoadConfig()
{
	cps_limit = GkConfig()->GetInteger("RoutedMode", "CpsLimit", 0);
	if (cps_limit == 0)
		PTRACE(4, "TCPSrv\tCpsLimit disabled");
	else
		PTRACE(4, "TCPSrv\tCpsLimit set to " << cps_limit);
	if (cps_limit > 0) {
		check_interval = GkConfig()->GetInteger("RoutedMode", "CpsCheckInterval", 5);
		PTRACE(4, "TCPSrv\tCpsCheckInterval set to " << check_interval);
	}
}

bool TCPServer::CloseListener(TCPListenSocket * socket)
{
	WriteLock lock(m_listmutex);
	iterator iter = find(m_sockets.begin(), m_sockets.end(), socket);
	if (iter != m_sockets.end()) {
		PTRACE(6, GetName() << "\tListener " << (*iter)->GetName() << " closed");
		(*iter)->Close();
		return true;
	} else
		return false;
}

void TCPServer::ReadSocket(IPSocket * socket)
{
	if (ShutdownMutex.WillBlock()) {
		PTRACE(4, GetName() << "\tShutdown: Rejecting call on " << socket->GetName());
		int rej = ::accept(socket->GetHandle(), NULL, NULL);
		::shutdown(rej, 2 /* SHUT_RDWR */ );
#if defined(_WIN32)
		::closesocket(rej);
#else
		::close(rej);
#endif
		return;
	}

	PTRACE(4, GetName() << "\tAccept request on " << socket->GetName());
	// rate limiting
	if (cps_limit > 0) {
		time_t now = time(NULL);
		// clear old values
		one_sec.remove_if(bind2nd(not_equal_to<time_t>(), now));
		many_sec.remove_if(bind2nd(less<time_t>(), now - check_interval));
		PTRACE(4, GetName() << "\tcurrent cps=" << one_sec.size() << " calls in interval=" << many_sec.size());
		if ((many_sec.size() > (cps_limit * check_interval)) && (one_sec.size() > cps_limit)) {
			// reject call
			PTRACE(1, GetName() << "\tRate limit reached (max " << cps_limit << " cps) - rejecting call on " << socket->GetName());
			int rej = ::accept(socket->GetHandle(), NULL, NULL);
			::shutdown(rej, 2 /* SHUT_RDWR */ );
#if defined(_WIN32)
			::closesocket(rej);
#else
			::close(rej);
#endif
			return;
		}
		// add accepted calls to stats list
		one_sec.push_back(now);
		many_sec.push_back(now);
	}

	TCPListenSocket *listener = dynamic_cast<TCPListenSocket *>(socket);
	ServerSocket *acceptor = listener->CreateAcceptor();
	if (acceptor->Accept(*listener)) {
		PTRACE(6, GetName() << "\tAccepted new connection on " << socket->GetName() << " from " << acceptor->GetName());
		CreateJob(acceptor, &ServerSocket::Dispatch, "Acceptor");
	} else {
		PTRACE(4, GetName() << "\tAccept failed on " << socket->GetName());
		delete acceptor;
	}
}

void TCPServer::CleanUp()
{
	PTime now;
	WriteLock lock(m_listmutex);
	iterator iter = m_sockets.begin();
	while (iter != m_sockets.end()) {
		TCPListenSocket *listener = dynamic_cast<TCPListenSocket *>(*iter);
		if (listener && listener->IsTimeout(&now)) {
			iter = m_sockets.erase(iter);
			--m_socksize;
			delete listener;
		}
		else ++iter;
	}
}
