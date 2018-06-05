//////////////////////////////////////////////////////////////////
//
// ProxyChannel.cxx
//
// Copyright (c) Citron Network Inc. 2001-2002
// Copyright (c) 2002-2018, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#define __APPLE_USE_RFC_3542	// MacOSX supposedly needs this to be able to set the UDP source IP

#include "config.h"
#include <ptlib.h>
#include <ptclib/random.h>
#include <q931.h>
#include <h245.h>
#include <h323pdu.h>
#include "snmp.h"
#include "gk.h"
#include "gk_const.h"
#include "h323util.h"
#include "Toolkit.h"
#include "stl_supp.h"
#include "gkacct.h"
#include "RasSrv.h"
#include "GkClient.h"
#include "Neighbor.h"
#include "sigmsg.h"
#include "ProxyChannel.h"
#include "GkStatus.h"
#include <queue>

#ifdef H323_H450
 #ifdef h323pluslib
   #include "h450/h4501.h"
   #include "h450/h4502.h"
 #else
   #include "h4501.h"
   #include "h4502.h"
 #endif
#include "SoftPBX.h"
#endif

#ifdef HAS_H460
	#include <h460/h4601.h>
	#ifdef HAS_H46018
		#include <h460/h46018.h>
		#include <h460/h46019.h>
	#endif
#endif

#ifdef HAS_H235_MEDIA
	#include "h235/h2351.h"
	#include "h235/h2356.h"
	#include "h235/h235crypto.h"
#endif

#ifdef _WIN32
#include <mswsock.h>
#endif

#ifdef P_OPENBSD
#include <sys/uio.h>
#endif

using namespace std;
using Routing::Route;

const char* RoutedSec = "RoutedMode";
const char* TLSSec = "TLS";
const char* ProxySection = "Proxy";
char H225_ProtocolID[ProtocolID_BufferSize];
char H245_ProtocolID[ProtocolID_BufferSize];

const char *H225_Protocol_Version[MAX_H323_VERSION+1] = {
    "0.0.8.2250.0.0",   // dummy, never used
    "0.0.8.2250.0.1",
    "0.0.8.2250.0.2",
    "0.0.8.2250.0.3",
    "0.0.8.2250.0.4",
    "0.0.8.2250.0.5",
    "0.0.8.2250.0.6",
    "0.0.8.2250.0.7"
};

const char *H245_Protocol_Version[MAX_H323_VERSION+1] = {
    "0.0.8.245.0.0",    // dummy, never used
    "0.0.8.245.0.2",
    "0.0.8.245.0.3",
    "0.0.8.245.0.5",
    "0.0.8.245.0.7",
    "0.0.8.245.0.9",
    "0.0.8.245.0.13",
    "0.0.8.245.0.15"
};


#define UNDEFINED_PAYLOAD_TYPE		255
#define H46019_AUTO_DETECTION_WAIT	4000 // wait n millisec before doing H.460.19 port auto-detection

#define G722_1_OID  "0.0.7.7221.1.0"
#define G722_1C_OID "0.0.7.7221.1.1.0"
#define G722_2_OID  "0.0.7.7221.2.0"


namespace {
// default timeout (ms) for initial Setup message,
// if not specified in the config file
const long DEFAULT_SETUP_TIMEOUT = 8000;
// time to wait before deleting a closed socket
const long DEFAULT_SOCKET_CLEANUP_TIMEOUT = 5000;
// if socket bind fails, try next DEFAULT_NUM_SEQ_PORTS subsequent port numbers
const int DEFAULT_NUM_SEQ_PORTS = 500;

// maximum number of handlder threads GnuGk will start (call signaling or RTP)
const unsigned MAX_HANDLER_NUMBER = 200;

enum RTPSessionTypes { Unknown = 0, Audio, Video, Presentation, Data };

// RTCP functions used in UDPProxySocket and H46019Session
void ParseRTCP(const callptr & call, WORD sessionID, PIPSocket::Address fromIP, BYTE * wbuffer, WORD buflen);
void BuildReceiverReport(const callptr & call, WORD sessionID, const RTP_ControlFrame & frame, PINDEX offset, bool dst);

H245_H2250LogicalChannelParameters *GetLogicalChannelParameters(H245_OpenLogicalChannel & olc, bool & isReverseLC);


#ifdef HAS_H46018
bool odd(unsigned n) { return (n % 2) != 0; }
#endif

template <class UUIE>
inline unsigned GetH225Version(const UUIE & uuie)
{
	if (uuie.m_protocolIdentifier.GetSize() < 6)
		return 0;
	else
		return uuie.m_protocolIdentifier[5];
}

H245_UnicastAddress *GetH245UnicastAddress(H245_TransportAddress & tsap)
{
	if (tsap.GetTag() == H245_TransportAddress::e_unicastAddress) {
		H245_UnicastAddress & uniaddr = tsap;
		return &uniaddr;
	}
	return NULL;
}

inline H245_UnicastAddress & operator<<(H245_UnicastAddress & addr, const PIPSocket::Address & ip)
{
	if (ip.GetVersion() == 6) {
		addr.SetTag(H245_UnicastAddress::e_iP6Address);
		H245_UnicastAddress_iP6Address & addrv6 = addr;
		for (int i = 0; i < 16; ++i)
			addrv6.m_network[i] = ip[i];
		} else {
			addr.SetTag(H245_UnicastAddress::e_iPAddress);
			H245_UnicastAddress_iPAddress & addrv4 = addr;
			for (int i = 0; i < 4; ++i)
			addrv4.m_network[i] = ip[i];
	}
	return addr;
}

inline H245_UnicastAddress & operator<<(H245_UnicastAddress & addr, WORD port)
{
	if (addr.GetTag() == H245_UnicastAddress::e_iPAddress) {
		H245_UnicastAddress_iPAddress & addrv4 = addr;
		addrv4.m_tsapIdentifier = port;
	} else if (addr.GetTag() == H245_UnicastAddress::e_iP6Address) {
		H245_UnicastAddress_iP6Address & addrv6 = addr;
		addrv6.m_tsapIdentifier = port;
	}
	return addr;
}

inline const H245_UnicastAddress & operator>>(const H245_UnicastAddress & addr, PIPSocket::Address & ip)
{
	if (addr.GetTag() == H245_UnicastAddress::e_iPAddress) {
		const H245_UnicastAddress_iPAddress & addrv4 = addr;
		ip = PIPSocket::Address(addrv4.m_network.GetSize(), addrv4.m_network);
	} else if (addr.GetTag() == H245_UnicastAddress::e_iP6Address) {
		const H245_UnicastAddress_iP6Address & addrv6 = addr;
	ip = PIPSocket::Address(addrv6.m_network.GetSize(), addrv6.m_network);
	}
	return addr;
}

inline const H245_UnicastAddress & operator>>(const H245_UnicastAddress & addr, WORD & port)
{
	if (addr.GetTag() == H245_UnicastAddress::e_iPAddress) {
		const H245_UnicastAddress_iPAddress & addrv4 = addr;
		port = (WORD)addrv4.m_tsapIdentifier;
	} else if (addr.GetTag() == H245_UnicastAddress::e_iP6Address) {
		const H245_UnicastAddress_iP6Address & addrv6 = addr;
		port = (WORD)addrv6.m_tsapIdentifier;
	}
	return addr;
}

PString GetH245CodecName(const H245_AudioCapability & cap)
{
	switch (cap.GetTag()) {
	case H245_AudioCapability::e_g711Alaw64k:
		return "G711A";
	case H245_AudioCapability::e_g711Alaw56k:
		return "G711A56";
	case H245_AudioCapability::e_g711Ulaw64k:
		return "G711U";
	case H245_AudioCapability::e_g711Ulaw56k:
		return "G711U56";
	case H245_AudioCapability::e_g722_64k:
		return "G72264";
	case H245_AudioCapability::e_g722_56k:
		return "G72256";
	case H245_AudioCapability::e_g722_48k:
		return "G72248";
	case H245_AudioCapability::e_g7231:
		return "G7231";
	case H245_AudioCapability::e_g728:
		return "G728";
	case H245_AudioCapability::e_g729:
		return "G729";
	case H245_AudioCapability::e_g729AnnexA:
		return "G729A";
	case H245_AudioCapability::e_g729wAnnexB:
		return "G729B";
	case H245_AudioCapability::e_g729AnnexAwAnnexB:
		return "G729AB";
	case H245_AudioCapability::e_g7231AnnexCCapability:
		return "G7231C";
	case H245_AudioCapability::e_gsmFullRate:
		return "GSMFR";
	case H245_AudioCapability::e_gsmHalfRate:
		return "GSMHR";
	case H245_AudioCapability::e_gsmEnhancedFullRate:
		return "GSMEFR";
	case H245_AudioCapability::e_genericAudioCapability: {
            const H245_GenericCapability & genericcap = cap;
            if (genericcap.m_capabilityIdentifier.GetTag() == H245_CapabilityIdentifier::e_standard) {
                const PASN_ObjectId & id = genericcap.m_capabilityIdentifier;
                if (id == G722_1_OID)
                    return "G722.1";
                if (id == G722_1C_OID)
                    return "G722.1C";
                if (id == G722_2_OID)
                    return "G722.2";
            }
            return "GenericAudio";
		}
	}
	return "Unknown";
}

PString GetH245CodecName(const H245_VideoCapability & cap)
{
	switch (cap.GetTag()) {
	case H245_VideoCapability::e_h261VideoCapability:
		return "H.261";
	case H245_VideoCapability::e_h263VideoCapability:
		return "H.263";
	case H245_VideoCapability::e_genericVideoCapability:
		return "H.264";
	case H245_VideoCapability::e_extendedVideoCapability:
		return "H.239";
	}
	return "Unknown";
}

unsigned GetH245CodecBitrate(const H245_AudioCapability & cap)
{
	switch (cap.GetTag()) {
	case H245_AudioCapability::e_g711Alaw64k:
		return 640;
	case H245_AudioCapability::e_g711Alaw56k:
		return 560;
	case H245_AudioCapability::e_g711Ulaw64k:
		return 640;
	case H245_AudioCapability::e_g711Ulaw56k:
		return 560;
	case H245_AudioCapability::e_g722_64k:
		return 640;
	case H245_AudioCapability::e_g722_56k:
		return 560;
	case H245_AudioCapability::e_g722_48k:
		return 480;
	case H245_AudioCapability::e_g7231:
		return 63;
	case H245_AudioCapability::e_g728:
		return 160;
	case H245_AudioCapability::e_g729:
		return 80;
	case H245_AudioCapability::e_g729AnnexA:
		return 80;
	case H245_AudioCapability::e_g729wAnnexB:
		return 80;
	case H245_AudioCapability::e_g729AnnexAwAnnexB:
		return 80;
	case H245_AudioCapability::e_g7231AnnexCCapability:
		return 63;
	case H245_AudioCapability::e_gsmFullRate:
		return 130;
	case H245_AudioCapability::e_gsmHalfRate:
		return 56;
	case H245_AudioCapability::e_gsmEnhancedFullRate:
		return 122;
	case H245_AudioCapability::e_genericAudioCapability: {
            const H245_GenericCapability & genericcap = cap;
            if (genericcap.m_capabilityIdentifier.GetTag() == H245_CapabilityIdentifier::e_standard) {
                const PASN_ObjectId & id = genericcap.m_capabilityIdentifier;
                if (id == G722_1_OID)
                    return genericcap.m_maxBitRate / 100; // G.722.1 Annex A changes units to bit/s, not 100 bit/s !!!
            }
            return genericcap.m_maxBitRate;
		}
	}
	return 0;
}

unsigned GetH245CodecBitrate(const H245_VideoCapability & cap)
{
	switch (cap.GetTag()) {
	case H245_VideoCapability::e_h261VideoCapability: {
            const H245_H261VideoCapability & h261cap = cap;
            return h261cap.m_maxBitRate;
		}
	case H245_VideoCapability::e_h263VideoCapability: {
            const H245_H263VideoCapability & h263cap = cap;
            return h263cap.m_maxBitRate;
		}
	case H245_VideoCapability::e_genericVideoCapability: {
            const H245_GenericCapability & genericcap = cap;
            return genericcap.m_maxBitRate;
		}
	}
	return 0;
}

#ifdef HAS_H235_MEDIA
BYTE GetStaticAudioPayloadType(unsigned tag)
{
	switch (tag) {
		case H245_AudioCapability::e_g711Alaw64k:
		case H245_AudioCapability::e_g711Alaw56k:
			return 8;
		case H245_AudioCapability::e_g711Ulaw64k:
		case H245_AudioCapability::e_g711Ulaw56k:
			return 0;
		case H245_AudioCapability::e_g722_64k:
		case H245_AudioCapability::e_g722_56k:
		case H245_AudioCapability::e_g722_48k:
			return 9;
		case H245_AudioCapability::e_g7231:
		case H245_AudioCapability::e_g7231AnnexCCapability:
			return 4;
		case H245_AudioCapability::e_g728:
			return 15;
		case H245_AudioCapability::e_g729:
		case H245_AudioCapability::e_g729AnnexA:
		case H245_AudioCapability::e_g729wAnnexB:
		case H245_AudioCapability::e_g729AnnexAwAnnexB:
			return 18;
		case H245_AudioCapability::e_gsmFullRate:
		case H245_AudioCapability::e_gsmHalfRate:
		case H245_AudioCapability::e_gsmEnhancedFullRate:
			return 3;
	};
	return UNDEFINED_PAYLOAD_TYPE;
};

BYTE GetStaticVideoPayloadType(unsigned tag)
{
	switch (tag) {
		case H245_VideoCapability::e_h261VideoCapability:
			return 31;
		case H245_VideoCapability::e_h263VideoCapability:
			return 34;
	};
	return UNDEFINED_PAYLOAD_TYPE;
};

BYTE GetStaticPayloadType(const H245_DataType & type)
{
	if (type.GetTag() == H245_DataType::e_audioData) {
		const H245_AudioCapability & audioCap = type;
		return GetStaticAudioPayloadType(audioCap.GetTag());
	}
	if (type.GetTag() == H245_DataType::e_videoData) {
		const H245_VideoCapability & videoCap = type;
		return GetStaticVideoPayloadType(videoCap.GetTag());
	}
	if (type.GetTag() == H245_DataType::e_h235Media) {
		const H245_H235Media & h235data = type;
		if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_audioData) {
			const H245_AudioCapability & audioCap = h235data.m_mediaType;
			return GetStaticAudioPayloadType(audioCap.GetTag());
		}
		if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_videoData) {
			const H245_VideoCapability & videoCap = h235data.m_mediaType;
			return GetStaticVideoPayloadType(videoCap.GetTag());
		}
	}
	return UNDEFINED_PAYLOAD_TYPE;
}

// pick a random payload type, but not the old one or the plaintext PT
BYTE RandomPT(BYTE oldPT, BYTE plainPT)
{
	BYTE newPT = oldPT;
	while ((newPT == oldPT) || (newPT == plainPT)) {
		newPT = PRandom::Number() % 254 + 1;	// generate random in range [1-254]
	}
	return newPT;
}

bool IsOldH263(const H245_DataType & type)
{
	if (type.GetTag() == H245_DataType::e_videoData) {
		const H245_VideoCapability & videoCap = type;
		if (videoCap.GetTag() == H245_VideoCapability::e_h263VideoCapability) {
			const H245_H263VideoCapability & h263cap = videoCap;
			return !h263cap.HasOptionalField(H245_H263VideoCapability::e_h263Options);
		}
	}
	if (type.GetTag() == H245_DataType::e_h235Media) {
		const H245_H235Media & h235data = type;
		if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_videoData) {
			const H245_VideoCapability & videoCap = h235data.m_mediaType;
			if (videoCap.GetTag() == H245_VideoCapability::e_h263VideoCapability) {
				const H245_H263VideoCapability & h263cap = videoCap;
				return !h263cap.HasOptionalField(H245_H263VideoCapability::e_h263Options);
			}
		}
	}
	return false;
}
#endif // HAS_H235_MEDIA

} // end of anonymous namespace


// send a UPD datagram and set the source IP (used only for RTP, RAS is using sockets bound to specific IPs)
// the method is highly OS specific

#ifdef _WIN32
ssize_t UDPSendWithSourceIP(int fd, void * data, size_t len, const IPAndPortAddress & toAddress)
{
#ifdef hasIPV6
	struct sockaddr_in6 dest;
#else
	struct sockaddr_in dest;
#endif
	// set dest address
	PIPSocket::Address toIP;
	WORD toPort = 0;
	if (!IsSet(toAddress) || !	toAddress.GetIpAndPort(toIP, toPort)) {
        PTRACE(5, "RTP\tSend error, toAddress not set");
        return -1;
	}
	SetSockaddr(dest, toIP, toPort);

#if (_WIN32_WINNT >= WINDOWS_VISTA)
	if (g_pfWSASendMsg && !g_disableSettingUDPSourceIP) {
		// set source address
		PIPSocket::Address src = RasServer::Instance()->GetLocalAddress(toIP);

		WSABUF wsabuf;
		WSAMSG msg;

		wsabuf.buf = (CHAR *)data;
		wsabuf.len = len;

		memset(&msg, 0, sizeof(msg));
		msg.name = (struct sockaddr*)&dest;
		msg.namelen = sizeof(dest);
		msg.lpBuffers = &wsabuf;
		msg.dwBufferCount = 1;

		WSACMSGHDR * cm = NULL;
		char cmsg[WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
		unsigned cmsg_data_size = sizeof(struct in_pktinfo);
		memset(cmsg, 0, sizeof(cmsg));

		msg.Control.buf = cmsg;
		msg.Control.len = sizeof(cmsg);

		if (!Toolkit::Instance()->IsIPv6Enabled() || (((struct sockaddr*)&dest)->sa_family == AF_INET)) {
            // set IPv4 source
			cm = WSA_CMSG_FIRSTHDR(&msg);
			cm->cmsg_len = WSA_CMSG_LEN(cmsg_data_size);
			cm->cmsg_level = IPPROTO_IP;
			cm->cmsg_type = IP_PKTINFO;
			{
				struct in_pktinfo ipi = { 0 };
				ipi.ipi_addr.s_addr = src;
				memcpy(WSA_CMSG_DATA(cm), &ipi, sizeof(ipi));
			}
		}
#ifdef hasIPV6
		if (Toolkit::Instance()->IsIPv6Enabled()) {
			// set IPv6 source with IPV6_PKTINFO
			WSACMSGHDR * cm = NULL;
			char cmsg6[WSA_CMSG_SPACE(sizeof(struct in6_pktinfo))];
			unsigned cmsg6_data_size = sizeof(struct in6_pktinfo);
			memset(cmsg6, 0, sizeof(cmsg6));

			msg.Control.buf = cmsg6;
			msg.Control.len = sizeof(cmsg6);

			cm = WSA_CMSG_FIRSTHDR(&msg);
			cm->cmsg_len = WSA_CMSG_LEN(cmsg6_data_size);
			cm->cmsg_level = IPPROTO_IPV6;
			cm->cmsg_type = IPV6_PKTINFO;
			{
				struct in6_pktinfo ipi = { 0 };
				struct sockaddr_in6 s6;
				SetSockaddr(s6, src, 0);
				ipi.ipi6_addr = s6.sin6_addr;
				memcpy(WSA_CMSG_DATA(cm), &ipi, sizeof(ipi));
			}
		}
#endif

		DWORD bytesSent = 0;
		int rc = g_pfWSASendMsg(fd, &msg, 0, &bytesSent, NULL, NULL);
		if (rc == 0) {
			return bytesSent;
		} else {
			int err = WSAGetLastError();
			PTRACE(7, "RTP\tSend error " << err);
			return -1;
		}
	} else
#endif
	{
        // on XP we fall back to sendto()
        // we can't set the source addr and XP seems to have trouble with IPv6, but IPv4 works OK
		return ::sendto(fd, (const char *)data, len, 0, (struct sockaddr *)&dest, sizeof(dest));
	}
}

#else // Unix

ssize_t UDPSendWithSourceIP(int fd, void * data, size_t len, const IPAndPortAddress & toAddress)
{
#ifdef hasIPV6
	struct sockaddr_in6 dest;
#else
	struct sockaddr_in dest;
#endif
	// set dest address
	PIPSocket::Address toIP;
	WORD toPort = 0;
	if (!IsSet(toAddress) || !toAddress.GetIpAndPort(toIP, toPort)) {
        PTRACE(5, "RTP\tSend error, toAddress not set");
        return -1;
	}
	SetSockaddr(dest, toIP, toPort);

    if (g_disableSettingUDPSourceIP) {
        size_t addr_len = sizeof(sockaddr_in);
#ifdef hasIPV6
        if (toIP.GetVersion() == 6)
            addr_len = sizeof(sockaddr_in6);
#endif  // hasIPV6
        ssize_t bytesSent = sendto(fd, (char *)data, len, 0, (struct sockaddr*)&dest, addr_len);
        if (bytesSent < 0) {
            PTRACE(5, "RTP\tSend error " << strerror(errno));
        }
        return bytesSent;
    }

	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct iovec iov = { };
	char cbuf[256];
	memset(&cbuf, 0, sizeof(cbuf));	// zero the buffer to shut up Valgrind

	// Set up iov and msgh structures
	memset(&msgh, 0, sizeof(struct msghdr));
	iov.iov_base = data;
	iov.iov_len = len;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_name = (struct sockaddr*)&dest;
	// must pass short len when sending to IPv4 address on Solaris 11, OpenBSD and NetBSD
	// sizeof(dest) is OK on Linux and FreeBSD
	size_t addr_len = sizeof(sockaddr_in);
#ifdef hasIPV6
	if (toIP.GetVersion() == 6)
		addr_len = sizeof(sockaddr_in6);
#endif  // hasIPV6
	msgh.msg_namelen = addr_len;

	// set source address
	PIPSocket::Address src = RasServer::Instance()->GetLocalAddress(toIP);

#ifdef hasIPV6
	if (Toolkit::Instance()->IsIPv6Enabled() && (src.GetVersion() == 6)) {
		struct in6_pktinfo *pkt;

		msgh.msg_control = cbuf;
		msgh.msg_controllen = CMSG_SPACE(sizeof(*pkt));

		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

		pkt = (struct in6_pktinfo *) CMSG_DATA(cmsg);
		memset(pkt, 0, sizeof(*pkt));
		pkt->ipi6_addr = src;
		msgh.msg_controllen = cmsg->cmsg_len;
	} else
#endif  // hasIPV6
	{
#if defined(IP_PKTINFO)	&& !defined(P_NETBSD) // Linux and Solaris 11 (NetBSD 7 only has incomplete IP_PKTINFO support)
		struct in_pktinfo *pkt;
		msgh.msg_control = cbuf;
		msgh.msg_controllen = CMSG_SPACE(sizeof(*pkt));

		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

		pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
		memset(pkt, 0, sizeof(*pkt));
		pkt->ipi_spec_dst = src;
#else
#ifdef IP_SENDSRCADDR	// FreeBSD
		// FreeBSD doesn't allow IP_SENDSRCADDR on sockets bound to anything else than INADDR_ANY
		bool skipSENDSRCADDR = false;
		struct sockaddr name;
		socklen_t name_len = sizeof(name);
		if (getsockname(fd, &name, &name_len) >= 0) {
			if (name.sa_family == AF_INET6) {
				if (!IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)&name)->sin6_addr)) {
					skipSENDSRCADDR = true;
				}
			} else {
				if (((struct sockaddr_in *)&name)->sin_addr.s_addr != INADDR_ANY) {
					skipSENDSRCADDR = true;
				}
			}
		}
		if (skipSENDSRCADDR) {
			PTRACE(7, "JW RTP: Skipping IP_SENDSRCADDR on this socket");
		} else {
			struct in_addr *in;

			msgh.msg_control = cbuf;
			msgh.msg_controllen = CMSG_SPACE(sizeof(*in));

			cmsg = CMSG_FIRSTHDR(&msgh);
			cmsg->cmsg_level = IPPROTO_IP;
			cmsg->cmsg_type = IP_SENDSRCADDR;
			cmsg->cmsg_len = CMSG_LEN(sizeof(*in));

			in = (struct in_addr *) CMSG_DATA(cmsg);
			*in = src;
		}
#endif  // IP_SENDSRCADDR
#endif  // IP_PKTINFO else
	}

	ssize_t bytesSent = sendmsg(fd, &msgh, 0);
	if (bytesSent < 0) {
		PTRACE(5, "RTP\tSend error " << strerror(errno));
	}

	return bytesSent;
}
#endif

ssize_t UDPSendWithSourceIP(int fd, void * data, size_t len, const PIPSocket::Address & ip, WORD port)
{
	const IPAndPortAddress to(ip, port);
	return UDPSendWithSourceIP(fd, data, len, to);
}


#ifdef HAS_H46018

void RemoveH46019Descriptor(H225_ArrayOf_FeatureDescriptor & supportedFeatures, bool & senderSupportsH46019Multiplexing, bool & isH46019Client)
{
	for (PINDEX i = 0; i < supportedFeatures.GetSize(); i++) {
		H225_GenericIdentifier & id = supportedFeatures[i].m_id;
		if (id.GetTag() == H225_GenericIdentifier::e_standard) {
			PASN_Integer & asnInt = id;
			if (asnInt.GetValue() == 19) {
				senderSupportsH46019Multiplexing = false;
				isH46019Client = true;
				for (PINDEX p = 0; p < supportedFeatures[i].m_parameters.GetSize(); p++) {
					if (supportedFeatures[i].m_parameters[p].m_id.GetTag() == H225_GenericIdentifier::e_standard) {
						PASN_Integer & pInt = supportedFeatures[i].m_parameters[p].m_id;
						if (pInt == 1) {
							senderSupportsH46019Multiplexing = true;
						}
						if (pInt == 2) {
							isH46019Client = false;
						}
					}
				}
				// delete, move others 1 up
				for (PINDEX j=i+1; j < supportedFeatures.GetSize(); j++) {
					supportedFeatures[j-1] = supportedFeatures[j];
				}
				supportedFeatures.SetSize(supportedFeatures.GetSize() - 1);
				return;
			}
		}
	}
}
#endif

#ifdef HAS_H46023
// Fix for H323plus 1.25 and prior with H.460.24 Multiplexing parameter being sent in the wrong field
// in the Alerting and Connect message
bool FixH46024Multiplexing(const H225_ArrayOf_GenericData & data, H225_FeatureSet & features)
{
	for (PINDEX i=0; i < data.GetSize(); i++) {
		H225_GenericIdentifier & id = data[i].m_id;
		if (id.GetTag() == H225_GenericIdentifier::e_standard) {
			PASN_Integer & asnInt = id;
			if (asnInt.GetValue() == 19) {
				features.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				H225_ArrayOf_FeatureDescriptor & supportedFeatures = features.m_supportedFeatures;
				int sz = supportedFeatures.GetSize();
				supportedFeatures.SetSize(sz+1);
				supportedFeatures[sz] = (const H225_FeatureDescriptor &)data[i];
				PTRACE(4,"H46023\tCorrecting message in generic field");
				return true;
			}
		}
	}
	return false;
}

bool HasH46024Descriptor(H225_ArrayOf_FeatureDescriptor & supportedFeatures)
{
	bool found = false;
	bool senderSupportsH46019Multiplexing = false;
	for (PINDEX i=0; i < supportedFeatures.GetSize(); i++) {
		H225_GenericIdentifier & id = supportedFeatures[i].m_id;
		if (id.GetTag() == H225_GenericIdentifier::e_standard) {
			PASN_Integer & asnInt = id;
			if (asnInt.GetValue() == 24)
				found = true;
		}
	}
	if (!found)
		return false;

	// if we are not interzone Multiplexing or don't support it remove the .19 Feature if it is there
	for (PINDEX i=0; i < supportedFeatures.GetSize(); i++) {
		H225_GenericIdentifier & id = supportedFeatures[i].m_id;
		if (id.GetTag() == H225_GenericIdentifier::e_standard) {
			PASN_Integer & asnInt = id;
			if (asnInt.GetValue() == 19) {
				for (PINDEX p=0; p < supportedFeatures[i].m_parameters.GetSize(); p++) {
					if (supportedFeatures[i].m_parameters[p].m_id.GetTag()  == H225_GenericIdentifier::e_standard) {
						PASN_Integer & pInt = supportedFeatures[i].m_parameters[p].m_id;
						if (pInt == 1)
							senderSupportsH46019Multiplexing = true;
					}
				}
				if (!senderSupportsH46019Multiplexing ||
					!Toolkit::AsBool(GkConfig()->GetString(ProxySection, "RTPMultiplexing", "0"))) {
						for (PINDEX j=i+1; j < supportedFeatures.GetSize(); j++) {
							supportedFeatures[j-1] = supportedFeatures[j];
						}
						supportedFeatures.SetSize(supportedFeatures.GetSize() - 1);
				}
			}
		}
	}
	return found;
}

bool IsH46024ProxyStrategy(CallRec::NatStrategy strat)
{
	if (strat == CallRec::e_natUnknown
		|| strat == CallRec::e_natLocalProxy
		|| strat == CallRec::e_natFullProxy)
			return true;

	return false;
}
#endif

#ifdef HAS_H46024A
bool GetH245GenericStringOctetString(unsigned id, const H245_ArrayOf_GenericParameter & params, PString & str)
{
	for (PINDEX i=0; i < params.GetSize(); i++) {
		const H245_GenericParameter & param = params[i];
		const H245_ParameterIdentifier & idm = param.m_parameterIdentifier;
		if (idm.GetTag() == H245_ParameterIdentifier::e_standard) {
			const PASN_Integer & idx = idm;
			if (idx == id) {
				const H245_ParameterValue & genvalue = params[i].m_parameterValue;
				if (genvalue.GetTag() == H245_ParameterValue::e_octetString) {
					const PASN_OctetString & valg = genvalue;
					PASN_IA5String data;
					valg.DecodeSubType(data);
					str = data;
					return true;
				}
			}
		}
	}
	PTRACE(4,"H46024A\tError finding String parameter " << id);
	return false;
}

bool GetH245GenericUnsigned(unsigned id, const H245_ArrayOf_GenericParameter & params, unsigned & num)
{
	for (PINDEX i=0; i < params.GetSize(); i++) {
		const H245_GenericParameter & param = params[i];
		const H245_ParameterIdentifier & idm = param.m_parameterIdentifier;
		if (idm.GetTag() == H245_ParameterIdentifier::e_standard) {
			const PASN_Integer & idx = idm;
			if (idx == id) {
				const H245_ParameterValue & genvalue = params[i].m_parameterValue;
				if (genvalue.GetTag() == H245_ParameterValue::e_unsigned32Min) {
					const PASN_Integer & valg = genvalue;
					num = valg;
					return true;
				}
			}
		}
	}
	PTRACE(4,"H46024A\tError finding unsigned parameter " << id);
	return false;
}

bool GetH245TransportGenericOctetString(unsigned id, const H245_ArrayOf_GenericParameter & params, H323TransportAddress & str)
{
	for (PINDEX i=0; i < params.GetSize(); i++) {
		const H245_GenericParameter & param = params[i];
		const H245_ParameterIdentifier & idm = param.m_parameterIdentifier;
		if (idm.GetTag() == H245_ParameterIdentifier::e_standard) {
			const PASN_Integer & idx = idm;
			if (idx == id) {
				const H245_ParameterValue & genvalue = params[i].m_parameterValue;
				if (genvalue.GetTag() == H245_ParameterValue::e_octetString) {
					const PASN_OctetString & valg = genvalue;
					H245_TransportAddress addr;
					valg.DecodeSubType(addr);
					str = H323TransportAddress(addr);
					return true;
				}
			}
		}
	}
	return false;
}

H245_GenericParameter & BuildH245GenericOctetString(H245_GenericParameter & param, unsigned id, const PASN_Object & data)
{
	H245_ParameterIdentifier & idm = param.m_parameterIdentifier;
		idm.SetTag(H245_ParameterIdentifier::e_standard);
		PASN_Integer & idx = idm;
		idx = id;
		H245_ParameterValue & genvalue = param.m_parameterValue;
		genvalue.SetTag(H245_ParameterValue::e_octetString);
		PASN_OctetString & valg = genvalue;
		valg.EncodeSubType(data);
	return param;
}

H245_GenericParameter & BuildH245GenericOctetString(H245_GenericParameter & param, unsigned id, const H323TransportAddress & transport)
{
	H245_TransportAddress data;
	transport.SetPDU(data);
	return BuildH245GenericOctetString(param, id, data);
}

H245_GenericParameter & BuildH245GenericUnsigned(H245_GenericParameter & param, unsigned id, unsigned val)
{
	H245_ParameterIdentifier & idm = param.m_parameterIdentifier;
		idm.SetTag(H245_ParameterIdentifier::e_standard);
		PASN_Integer & idx = idm;
		idx = id;
		H245_ParameterValue & genvalue = param.m_parameterValue;
		genvalue.SetTag(H245_ParameterValue::e_unsigned32Min);
		PASN_Integer & xval = genvalue;
		xval = val;
	return param;
}
#endif

struct PortRange {
	PortRange() : port(0), minport(0), maxport(0) { }

	WORD GetPort();
	int GetNumPorts() const;
	void LoadConfig(const char *, const char *, const char * = "");

private:
	PortRange(const PortRange &);
	PortRange & operator=(const PortRange &);

private:
	WORD port, minport, maxport;
	PMutex mutex;
};

WORD PortRange::GetPort()
{
	if (port == 0)
		return 0;
	PWaitAndSignal lock(mutex);
	WORD result = port++;
	if (port > maxport)
		port = minport;
	if (port < minport) // special case to check for 16-bit wrap around
		port = minport;
	if (port == 0)
		port = 1;
	return result;
}

int PortRange::GetNumPorts() const
{
	return maxport - minport + 1;
}

void PortRange::LoadConfig(const char *sec, const char *setting, const char *def)
{
	PStringArray cfgs = GkConfig()->GetString(sec, setting, def).Tokenise(",.:-/'", FALSE);
	if (cfgs.GetSize() >= 2) {
		minport = (WORD)cfgs[0].AsUnsigned(), maxport = (WORD)cfgs[1].AsUnsigned();
		if (port < minport || port > maxport)
			port = minport;
	} else
		port = 0;
	PTRACE_IF(2, port, setting << ": " << minport << '-' << maxport);
}

static PortRange Q931PortRange;
static PortRange H245PortRange;
static PortRange T120PortRange;
static PortRange RTPPortRange;

class H245Socket : public TCPProxySocket {
public:
#ifndef LARGE_FDSET
	PCLASSINFO ( H245Socket, TCPProxySocket )
#endif

	H245Socket(CallSignalSocket *);
	H245Socket(H245Socket *, CallSignalSocket *);
	virtual ~H245Socket();

	void ConnectTo();
	void ConnectToRerouteDestination();
	void ConnectToDirectly();

	// override from class ProxySocket
    virtual Result ReceiveData();
	virtual bool EndSession();

	void SendEndSessionCommand();
#ifdef HAS_H46018
	void SendH46018Indication();
#endif
	void SendTCS(H245_TerminalCapabilitySet * tcs, unsigned seq);
	void SendH245KeepAlive();
	bool Send(const H245_MultimediaSystemControlMessage & h245msg);
	bool Send(const PASN_OctetString & h245msg);
	H225_TransportAddress GetH245Address(const Address &);
	bool SetH245Address(H225_TransportAddress & h245addr, const Address &);
	bool Reverting(const H225_TransportAddress &);
	void OnSignalingChannelClosed();
	void SetSigSocket(CallSignalSocket *socket) { sigSocket = socket; }
	PString GetCallIdentifierAsString() const;

protected:
	// override from class TCPProxySocket
#ifdef LARGE_FDSET
	virtual bool Accept(YaTCPSocket &);
#else
	virtual PBoolean Accept(PSocket &);
#endif
	// new virtual function
	virtual bool ConnectRemote();

private:
	H245Socket();
	H245Socket(const H245Socket &);
	H245Socket & operator=(const H245Socket &);

	// override from class ServerSocket
	virtual void Dispatch() { /* useless */ }

protected:
	WORD m_port;
	CallSignalSocket *sigSocket;
	H225_TransportAddress *peerH245Addr;
	TCPSocket *listener;
	/// to avoid race condition inside calls between this socket and its signaling socket
	PMutex m_signalingSocketMutex;
};

class NATH245Socket : public H245Socket {
public:
#ifndef LARGE_FDSET
	PCLASSINFO ( NATH245Socket, H245Socket )
#endif
	NATH245Socket(CallSignalSocket *sig) : H245Socket(sig) {}

private:
	NATH245Socket();
	NATH245Socket(const NATH245Socket &);
	NATH245Socket & operator=(const NATH245Socket &);

	// override from class H245Socket
	virtual bool ConnectRemote();
};


class T120LogicalChannel;

class T120ProxySocket : public TCPProxySocket {
public:
#ifndef LARGE_FDSET
	PCLASSINFO ( T120ProxySocket, TCPProxySocket )
#endif

	T120ProxySocket(T120LogicalChannel *);
	T120ProxySocket(T120ProxySocket * = NULL, WORD = 0);

	// override from class ProxySocket
	virtual bool ForwardData();

private:
	T120ProxySocket(const T120ProxySocket &);
	T120ProxySocket & operator=(const T120ProxySocket &);

	// override from class ServerSocket
	virtual void Dispatch();

private:
	T120LogicalChannel * t120lc;
};

class LogicalChannel {
public:
	LogicalChannel(WORD flcn = 0) : channelNumber(flcn), port(0), used(false) { }
	virtual ~LogicalChannel() { }

	bool Compare(WORD lcn) const { return channelNumber == lcn; }
	WORD GetPort() const { return port; }
	WORD GetChannelNumber() const { return channelNumber; }
	void SetChannelNumber(WORD cn) { channelNumber = cn; }

	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *, callptr &, bool fromTraversalClient, bool useRTPMultiplexing) = 0;
	virtual void StartReading(ProxyHandler *) = 0;
	virtual void SetRTPMute(bool toMute) = 0;

	virtual int GetRTPOSSocket() const { return INVALID_OSSOCKET; }
	virtual int GetRTCPOSSocket() const { return INVALID_OSSOCKET; }

protected:
	WORD channelNumber;
	WORD port;
	bool used;
};

class RTPLogicalChannel : public LogicalChannel {
public:
	RTPLogicalChannel(const H225_CallIdentifier & id, WORD flcn, bool nated, WORD sessionID, RTPSessionTypes sessionType);
	RTPLogicalChannel(RTPLogicalChannel *flc, WORD flcn, bool nated, RTPSessionTypes sessionType);
	virtual ~RTPLogicalChannel();

	void SetRTPSessionID(WORD id);
	void SetMediaChannelSource(const H245_UnicastAddress &);
	void ZeroMediaChannelSource();
	void SetMediaControlChannelSource(const H245_UnicastAddress &);
	void ZeroMediaControlChannelSource();
	void HandleMediaChannel(H245_UnicastAddress *, H245_UnicastAddress *, const PIPSocket::Address &, bool, callptr &,
		bool fromTraversalClient, bool useRTPMultiplexing, bool isUnidirectional);
	bool OnLogicalChannelParameters(H245_H2250LogicalChannelParameters &, const PIPSocket::Address &, bool, callptr &, bool, bool useRTPMultiplexing, bool isUnidirectional);

	// override from class LogicalChannel
	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *, callptr &, bool fromTraversalClient, bool useRTPMultiplexing);
	virtual void StartReading(ProxyHandler *);
	virtual void SetRTPMute(bool toMute);

	bool IsAttached() const { return (peer != NULL); }
	void OnHandlerSwapped(bool);

	bool IsOpen() const;
	void SetUniDirectional(bool uni);
	RTPSessionTypes GetType() const { return m_sessionType; }

#ifdef HAS_H46018
	void SetUsesH46019fc(bool);
	void SetUsesH46019();
	int GetRTPOSSocket() const { return rtp ? rtp->GetOSSocket() : INVALID_OSSOCKET; }
	int GetRTCPOSSocket() const { return rtcp ? rtcp->GetOSSocket() : INVALID_OSSOCKET; }

	void AddLCKeepAlivePT(unsigned pt);
	void SetLCMultiplexDestination(bool isRTCP, const IPAndPortAddress & toAddress, H46019Side side);
	void SetLCMultiplexID(bool isRTCP, DWORD multiplexID, H46019Side side);
	void SetLCMultiplexSocket(bool isRTCP, int multiplexSocket, H46019Side side);
#endif

#ifdef HAS_H235_MEDIA
	bool CreateH235Session(H235Authenticators & auth, const H245_EncryptionSync & encryptionSync, bool encrypting);
	bool CreateH235SessionAndKey(H235Authenticators & auth, H245_EncryptionSync & sync, bool encrypting);
	bool UpdateMediaKey(const H245_EncryptionSync & encryptionSync);
	bool GenerateNewMediaKey(BYTE newPayloadType, H245_EncryptionSync & encryptionSync);
	bool ProcessH235Media(BYTE * buffer, WORD & len, bool encrypt, unsigned char * ivsequence, bool & rtpPadding, BYTE & payloadType);
	void SetPlainPayloadType(BYTE pt) { m_plainPayloadType = pt; }
	BYTE GetPlainPayloadType() const { return m_plainPayloadType; }
	void SetCipherPayloadType(BYTE pt) { m_cipherPayloadType = pt; }
	BYTE GetCipherPayloadType() const { return m_cipherPayloadType; }
#endif

    void GetRTPPorts(PIPSocket::Address & fSrcIP, PIPSocket::Address & fDestIP, PIPSocket::Address & rSrcIP, PIPSocket::Address & rDestIP,
                        WORD & fSrcPort, WORD & dDestPort, WORD & rSrcPort, WORD & rDestPort) const;
    bool IsRTPInactive() const;

private:
	void SetNAT(bool);
	static WORD GetPortNumber();	// get a new port number to use

	bool reversed;
	RTPLogicalChannel *peer;
	UDPProxySocket *rtp, *rtcp;
	PIPSocket::Address SrcIP;
	WORD SrcPort; // RTP port from OLC (deduced from RTCP if not present)

#ifdef HAS_H235_MEDIA
	PMutex m_cryptoEngineMutex;
	H235CryptoEngine * m_H235CryptoEngine;
	H235Authenticators * m_auth;
	bool m_encrypting;
	BYTE m_plainPayloadType;			// remember in OLC to use in OLCA
	BYTE m_cipherPayloadType;			// remember in OLC to use in OLCA
#endif
	H225_CallIdentifier m_callID;
	PINDEX m_callNo;
    bool m_ignoreSignaledIPs;   // ignore all RTP/RTCP IPs in signalling, do full auto-detect
    bool m_ignoreSignaledPrivateH239IPs;   // also ignore private IPs signaled in H.239 streams
    list<NetworkAddress> m_keepSignaledIPs;   // don't do auto-detect on this network
    bool m_isUnidirectional;
    RTPSessionTypes m_sessionType;
};

class T120LogicalChannel : public LogicalChannel {
public:
	T120LogicalChannel(WORD);
	virtual ~T120LogicalChannel();

	// override from class LogicalChannel
	virtual bool SetDestination(H245_OpenLogicalChannelAck &, H245Handler *, callptr &, bool /*fromTraversalClient*/, bool);
	virtual void StartReading(ProxyHandler *);
	virtual void SetRTPMute(bool /*toMute*/) { }   /// We do not Mute T.120 Channels

	void Create(T120ProxySocket *);
	bool OnSeparateStack(H245_NetworkAccessParameters &, H245Handler *);

private:
	class T120Listener : public TCPListenSocket {
	public:
		T120Listener(T120LogicalChannel *lc);

	private:
		// override from class TCPListenSocket
		virtual ServerSocket *CreateAcceptor() const;

		T120LogicalChannel *t120lc;
	};

	T120Listener * listener;
	ProxyHandler * handler;
	PIPSocket::Address peerAddr;
	WORD peerPort;
	std::list<T120ProxySocket *> sockets;
	PMutex m_smutex;
};

class NATHandler {
public:
	NATHandler(const PIPSocket::Address & remote) : remoteAddr(remote) { }

	void TranslateH245Address(H225_TransportAddress &);
	bool HandleOpenLogicalChannel(H245_OpenLogicalChannel &);
	bool HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck &);

private:
	bool SetAddress(H245_UnicastAddress *);
	bool ChangeAddress(H245_UnicastAddress * addr);
	PIPSocket::Address remoteAddr;
};

class H245Handler {
// This class handles H.245 messages which can either be transmitted on their
// own TCP connection or can be tunneled in the Q.931 connection
public:
	H245Handler(const PIPSocket::Address & local, const PIPSocket::Address & remote,
		             const PIPSocket::Address & masq);
	virtual ~H245Handler();

	virtual void OnH245Address(H225_TransportAddress &);
	virtual bool HandleMesg(H245_MultimediaSystemControlMessage &, bool & suppress, callptr & call, H245Socket * h245sock);
	virtual bool HandleFastStartSetup(H245_OpenLogicalChannel &, callptr &);
	virtual bool HandleFastStartResponse(H245_OpenLogicalChannel &, callptr &);
	typedef bool (H245Handler::*pMem)(H245_OpenLogicalChannel &, callptr &);

	PIPSocket::Address GetLocalAddr() const { return localAddr; }
    PIPSocket::Address GetMasqAddr() const { return masqAddr; }
    PIPSocket::Address GetRemoteAddr() const { return remoteAddr; }
	bool IsSessionEnded() const { return isH245ended; }

protected:
	virtual bool HandleRequest(H245_RequestMessage &, callptr &);
	virtual bool HandleResponse(H245_ResponseMessage &, callptr &);
	virtual bool HandleCommand(H245_CommandMessage &, bool & suppress, callptr &, H245Socket * h245sock);
	virtual bool HandleIndication(H245_IndicationMessage &, bool & suppress);

	NATHandler *hnat;

	PIPSocket::Address localAddr, remoteAddr, masqAddr;
	bool isH245ended;
    PTime m_lastVideoFastUpdatePicture; // last time we sent a VideoFastUpdatePicture when we are filtering them
};

class H245ProxyHandler : public H245Handler {
public:
	typedef std::map<WORD, LogicalChannel *>::iterator iterator;
	typedef std::map<WORD, LogicalChannel *>::const_iterator const_iterator;
	typedef std::map<WORD, RTPLogicalChannel *>::iterator siterator;
	typedef std::map<WORD, RTPLogicalChannel *>::const_iterator const_siterator;

	H245ProxyHandler(const H225_CallIdentifier &, const PIPSocket::Address &, const PIPSocket::Address &, const PIPSocket::Address &, H245ProxyHandler * = NULL);
	virtual ~H245ProxyHandler();

	// override from class H245Handler
	virtual bool HandleFastStartSetup(H245_OpenLogicalChannel &,callptr &);
	virtual bool HandleFastStartResponse(H245_OpenLogicalChannel &,callptr &);

	void SetHandler(ProxyHandler *);
	H245ProxyHandler * GetPeer() const { return peer; }
	void UpdateLogicalChannelSessionID(WORD flcn, WORD id);
	LogicalChannel * FindLogicalChannel(WORD flcn);
	RTPLogicalChannel * FindRTPLogicalChannelBySessionID(WORD id) const;
	RTPLogicalChannel * FindRTPLogicalChannelBySessionType(RTPSessionTypes sessionType) const;
	bool UsesH46019() const { return m_useH46019; }
	void SetTraversalRole(H46019TraversalType type) { m_traversalType = type; m_useH46019 = (type != None); }
	H46019TraversalType GetTraversalRole() const { return m_traversalType; }
	bool IsTraversalServer() const { return m_traversalType == TraversalServer; }
	bool IsTraversalClient() const { return m_traversalType == TraversalClient; }
	void SetUsesH46019fc(bool use) { m_useH46019fc = use; }
	bool UsesH46019fc() const { return m_useH46019fc; }
	void SetH46019fcState(int use) { m_H46019fcState = use; }
	int GetH46019fcState() const { return m_H46019fcState; }
	void SetH46019Direction(int dir) { m_H46019dir = dir; }
	int GetH46019Direction() const { return m_H46019dir; }
	void SetRequestRTPMultiplexing(bool epCanTransmitMultipled);
	void SetUsesH46026(bool val) { m_usesH46026 = val; }
	bool UsesH46026() const { return m_usesH46026; }
	void SetRoles(bool isCaller, bool isH245Master) { m_isCaller = isCaller; m_isH245Master = isH245Master; }
	bool IsCaller() const { return m_isCaller; }
	bool IsH245Master() const { return m_isH245Master; }
    bool IsRTPInactive(short session) const;


protected:
	// override from class H245Handler
	virtual bool HandleRequest(H245_RequestMessage &, callptr &);
	virtual bool HandleResponse(H245_ResponseMessage &, callptr &);
	virtual bool HandleCommand(H245_CommandMessage &, bool & suppress, callptr &, H245Socket * h245sock);
	virtual bool HandleIndication(H245_IndicationMessage &, bool & suppress);

	bool OnLogicalChannelParameters(H245_H2250LogicalChannelParameters *, WORD flcn, bool isUnidirectional, RTPSessionTypes sessionType);
	bool HandleOpenLogicalChannel(H245_OpenLogicalChannel &, callptr &);
	bool HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck &, callptr &);
	bool HandleOpenLogicalChannelReject(H245_OpenLogicalChannelReject &, callptr & call);
	bool HandleCloseLogicalChannel(H245_CloseLogicalChannel &, callptr &);
	void HandleMuteRTPChannel();
#ifdef HAS_H235_MEDIA
	bool HandleEncryptionUpdateRequest(H245_MiscellaneousCommand & cmd, bool & suppress, callptr & call, H245Socket * h245sock);
	bool HandleEncryptionUpdateCommand(H245_MiscellaneousCommand & cmd, bool & suppress, callptr & call, H245Socket * h245sock);
	bool HandleEncryptionUpdateAck(H245_MiscellaneousCommand & cmd, bool & suppress, callptr & call, H245Socket * h245sock);
#endif

	bool ParseTraversalParameters(
		/* in */
		const H245_GenericInformation & genericInfo,
		/* out */
		unsigned & payloadtype,
		H225_TransportAddress & keepAliveRTPAddr,
		unsigned & keepAliveInterval,
		H225_TransportAddress & multiplexedRTPAddr,
		H225_TransportAddress & multiplexedRTCPAddr,
		DWORD & multiplexID) const;

	RTPLogicalChannel *CreateRTPLogicalChannel(WORD sessionId, WORD flcn, RTPSessionTypes sessionType);
	RTPLogicalChannel *CreateFastStartLogicalChannel(WORD sessionId, RTPSessionTypes sessionType);
	T120LogicalChannel *CreateT120LogicalChannel(WORD sessionId);
	bool RemoveLogicalChannel(WORD flcn);
	//void DumpChannels(const PString & msg, bool dumpPeer = true) const;

	std::map<WORD, LogicalChannel *> logicalChannels;
	std::map<WORD, RTPLogicalChannel *> sessionIDs;
	std::map<WORD, RTPLogicalChannel *> fastStartLCs;
	ProxyHandler *handler;
	H245ProxyHandler *peer;
	H225_CallIdentifier callid;
	bool isMute;
	bool m_useH46019;
	H46019TraversalType m_traversalType;
	bool m_useH46019fc;
	int m_H46019fcState;
	int m_H46019dir;
	bool m_isRTPMultiplexingEnabled;
	bool m_requestRTPMultiplexing;
	bool m_remoteRequestsRTPMultiplexing;
	WORD m_multiplexedRTPPort;
	WORD m_multiplexedRTCPPort;
	bool m_usesH46026;
	bool m_isCaller;
	bool m_isH245Master;
    bool m_ignoreSignaledIPs;   // ignore all RTP/RTCP IPs in signalling, do full auto-detect
    bool m_ignoreSignaledPrivateH239IPs;   // also ignore private IPs signaled in H.239 streams
    list<NetworkAddress> m_keepSignaledIPs;   // don't do auto-detect on this network
};


// class ProxySocket
ProxySocket::ProxySocket(
	IPSocket *s,
	const char *t,
	WORD buffSize
	) : USocket(s, t), wbuffer(new BYTE[buffSize]), wbufsize(buffSize), buflen(0),
	connected(false), deletable(false), handler(NULL)
{
}

ProxySocket::~ProxySocket()
{
	delete [] wbuffer;
}

ProxySocket::Result ProxySocket::ReceiveData()
{
	if (!self->Read(wbuffer, wbufsize)) {
		ErrorHandler(PSocket::LastReadError);
		return NoData;
	}
	PTRACE(6, Type() << "\tReading from " << Name());
	buflen = (WORD)self->GetLastReadCount();
	return Forwarding;
}

bool ProxySocket::ForwardData()
{
	return WriteData(wbuffer, buflen);
}

bool ProxySocket::EndSession()
{
	MarkBlocked(false);
//	SetConnected(false);
	return CloseSocket();
}

inline TCPProxySocket::TPKTV3::TPKTV3(WORD len)
	: header(3), padding(0)
{
	length = PIPSocket::Host2Net(WORD(len + sizeof(TPKTV3)));
}

// class TCPProxySocket
TCPProxySocket::TCPProxySocket(const char * t, TCPProxySocket * s, WORD p)
      : ServerSocket(p), ProxySocket(this, t), remote(s), bufptr(NULL), tpkt(0), tpktlen(0),
        m_h46018KeepAlive(true), m_keepAliveInterval(19), m_keepAliveTimer(GkTimerManager::INVALID_HANDLE)
{
    PCaselessString str;
    // H.225: default to empty TPKT like standard says
    str = GkConfig()->GetString(RoutedSec, "H460KeepAliveMethodH225", "EmptyFacility");
    m_h460KeepAliveMethodH225 = TPKTH225;
    if (str == "TPKT") {
        m_h460KeepAliveMethodH225 = TPKTH225;
    } else if (str == "EmptyFacility") {
        m_h460KeepAliveMethodH225 = EmptyFacility;
    } else if (str == "Information") {
        m_h460KeepAliveMethodH225 = Information;
    } else if (str == "Notify") {
        m_h460KeepAliveMethodH225 = Notify;
    } else if (str == "Status") {
        m_h460KeepAliveMethodH225 = Status;
    } else if (str == "StatusInquiry") {
        m_h460KeepAliveMethodH225 = StatusInquiry;
    } else if (str == "None") {
        m_h460KeepAliveMethodH225 = NoneH225;
    } else {
        PTRACE(1, "Error: Unknown H.460 Keepalive method for H.225: " << str);
    }
    str = GkConfig()->GetString(RoutedSec, "GnuGkTcpKeepAliveMethodH225", "EmptyFacility");
    m_nonStdKeepAliveMethodH225 = TPKTH225;
    if (str == "TPKT") {
        m_nonStdKeepAliveMethodH225 = TPKTH225;
    } else if (str == "EmptyFacility") {
        m_nonStdKeepAliveMethodH225 = EmptyFacility;
    } else if (str == "Information") {
        m_nonStdKeepAliveMethodH225 = Information;
    } else if (str == "Notify") {
        m_nonStdKeepAliveMethodH225 = Notify;
    } else if (str == "Status") {
        m_nonStdKeepAliveMethodH225 = Status;
    } else if (str == "StatusInquiry") {
        m_nonStdKeepAliveMethodH225 = StatusInquiry;
    } else if (str == "None") {
        m_nonStdKeepAliveMethodH225 = NoneH225;
    } else {
        PTRACE(1, "Error: Unknown GnuGk Keepalive method for H.225: " << str);
    }

    // H.245: default to UserInput for all due to Polycom issue
    str = GkConfig()->GetString(RoutedSec, "H460KeepAliveMethodH245", "UserInput");
    m_h460KeepAliveMethodH245 = UserInput;
    if (str == "TPKT") {
        m_h460KeepAliveMethodH245 = TPKTH245;
    } else if (str == "UserInput") {
        m_h460KeepAliveMethodH245 = UserInput;
    } else if (str == "None") {
        m_h460KeepAliveMethodH245 = NoneH245;
    } else {
        PTRACE(1, "Error: Unknown H.460 Keepalive method for H.245: " << str);
    }
    str = GkConfig()->GetString(RoutedSec, "GnuGkTcpKeepAliveMethodH245", "UserInput");
    m_nonStdKeepAliveMethodH245 = UserInput;
    if (str == "TPKT") {
        m_nonStdKeepAliveMethodH245 = TPKTH245;
    } else if (str == "UserInput") {
        m_nonStdKeepAliveMethodH245 = UserInput;
    } else if (str == "None") {
        m_nonStdKeepAliveMethodH245 = NoneH245;
    } else {
        PTRACE(1, "Error: Unknown GnuGk Keepalive method for H.245: " << str);
    }
}

TCPProxySocket::~TCPProxySocket()
{
    UnregisterKeepAlive();
    DetachRemote();
}

void TCPProxySocket::DetachRemote()
{
	PWaitAndSignal lock(m_remoteLock);
	if (remote) {
		remote->remote = NULL; // detach myself from remote
		CallSignalSocket * css = dynamic_cast<CallSignalSocket *>(remote);
		if (!css || !css->MaintainConnection())
			remote->SetDeletable();
		remote = NULL;
	}
}

bool TCPProxySocket::ForwardData()
{
	PWaitAndSignal lock(m_remoteLock);
	return (remote) ? remote->InternalWrite(buffer) : false;
}

bool TCPProxySocket::TransmitData(const PBYTEArray & buf)
{
	return InternalWrite(buf);
}

#ifndef LARGE_FDSET
PBoolean TCPProxySocket::Accept(PSocket & socket)
{
//	SetReadTimeout(PMaxTimeInterval);
	PBoolean result = PTCPSocket::Accept(socket);
	if (result) {
		PTimeInterval timeout(100);
		SetReadTimeout(timeout);
		SetWriteTimeout(timeout);
		// since GetName() may not work if socket closed,
		// we save it for reference
		Address raddr;
		WORD rport = 0;
		GetPeerAddress(raddr, rport);
		UnmapIPv4Address(raddr);
		SetName(AsString(raddr, rport));
	} else {
		int errorNumber = GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, Type() << "\tCould not accept TCP socket"
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << GetErrorText(PSocket::LastGeneralError));
		SNMP_TRAP(10, SNMPError, Network, "Could not accept TCP socket - error "
			+ PString(PString::Unsigned, GetErrorCode(PSocket::LastGeneralError)) + PString("/")
			+ PString(PString::Unsigned, errorNumber) + PString(": ")
			+ GetErrorText(PSocket::LastGeneralError));
	}
	return result;
}

PBoolean TCPProxySocket::Connect(const Address & iface, WORD localPort, const Address & addr)
{
	SetName(AsString(addr, GetPort()));
	SetReadTimeout(PTimeInterval(6000));
	PBoolean result = PTCPSocket::Connect(iface, localPort, addr);
	if (result) {
		PTimeInterval timeout(100);
		SetReadTimeout(timeout);
		SetWriteTimeout(timeout);
	}
	return result;
}

PBoolean TCPProxySocket::Connect(const Address & addr)
{
	return Connect(GNUGK_INADDR_ANY, 0, addr);
}

#endif

bool TCPProxySocket::ReadTPKT()
{
	PTRACE(5, Type() << "\tReading from " << GetName());
	if (tpktlen < sizeof(tpkt)) {
		if (!Read(reinterpret_cast<BYTE*>(&tpkt) + tpktlen, sizeof(tpkt) - tpktlen))
			return ErrorHandler(PSocket::LastReadError);
		tpktlen += GetLastReadCount();
		if (tpktlen < sizeof(tpkt)) {
			PTRACE(3, Type() << "\t" << GetName() << " fragmented TPKT header, will wait for more data");
			return false;
		}

		// TPKT Continuation - ignore
		if (tpkt.header == 0 && tpkt.padding == 3 && tpkt.length == 1024) {
			PTRACE(3, Type() << "\tignoring empty Tandberg TPKT from " << GetName() << " (keep-alive)");
			buflen = 0;
			tpktlen = 0;
			return false;
		}
		// some endpoints don't set padding to 0, e.g. Cisco AS5300 (setting it to 0 is only required in H.323v3 or later)
		if (tpkt.header != 3) {
			PTRACE(2, Type() << "\t" << GetName() << " NOT A TPKT PACKET!"
				<< " header=" << (int)tpkt.header << " padding=" << (int)tpkt.padding << " length=" << (int)tpkt.length);
			tpktlen = 0;
			errno = EINVAL;
			ConvertOSError(-1, PSocket::LastReadError);
			return ErrorHandler(PSocket::LastReadError);
		}
		buflen = PIPSocket::Net2Host(tpkt.length) - sizeof(TPKTV3);
		if (buflen < 1) {
			PTRACE(3, Type() << "\tignoring empty TPKT from " << GetName() << " (keep-alive)");
			buflen = 0;
			tpktlen = 0;
			return false;
		}
		if (!SetMinBufSize(buflen)) {
			PTRACE(1, Type() << "\t" << GetName() << " could not set new buffer size: " << buflen);
			errno = ENOMEM;
			ConvertOSError(-1, PSocket::LastReadError);
			return ErrorHandler(PSocket::LastReadError);
		}
		buffer = PBYTEArray(bufptr = wbuffer, buflen, false);
	}

#if defined(LARGE_FDSET) && !defined(HAS_TLS)
	// some endpoints may send TPKT header and payload in separate
	// packets, so we have to check again if data available
	// TLS adds another layer of buffering, so this optimization will fail -> disable
	if (this->GetHandle() < (int)FD_SETSIZE) {
		if (!YaSelectList(GetName(), this).Select(YaSelectList::Read, 0)) {
			return false;
		}
	}
#endif
	if (!Read(bufptr, buflen))
		return ErrorHandler(PSocket::LastReadError);

	buflen -= GetLastReadCount();
	if (buflen == 0) {
		tpktlen = 0;
		return true;
	}

	bufptr += GetLastReadCount();
	PTRACE(3, Type() << "\t" << GetName() << " TPKT fragmented, will wait for more data");
	return false;
}

bool TCPProxySocket::InternalWrite(const PBYTEArray & buf)
{
	WORD len = (WORD)buf.GetSize(), tlen = len + sizeof(TPKTV3);
	PBYTEArray tbuf(tlen);
	BYTE *bptr = tbuf.GetPointer();
	new (bptr) TPKTV3(len); // placement operator
	memcpy(bptr + sizeof(TPKTV3), buf, len);
	return WriteData(bptr, tlen);
}

void TCPProxySocket::SendKeepAlive(GkTimer * timer)
{
    if (!IsOpen()) {
        // don't unregister KeepAlive here, we are called from within CheckTimers()
        // wait until it gets deleted in the d'tor
        return;
    }
    H245Socket * h245sock = dynamic_cast<H245Socket*>(this);
    if (h245sock != NULL) {
        H245KeepAliveMethod method;
        if (m_h46018KeepAlive) {
            method = m_h460KeepAliveMethodH245;
        } else {
            method = m_nonStdKeepAliveMethodH245;
        }
        switch(method) {
            case TPKTH245:
                SendEmptyTPKTKeepAlive();
                break;
            case UserInput:
                h245sock->SendH245KeepAlive();
                break;
            case NoneH245:
                // do nothing
                break;
        }
    } else {
        CallSignalSocket * sig_sock = dynamic_cast<CallSignalSocket*>(this);
        H225KeepAliveMethod method;
        if (m_h46018KeepAlive) {
            method = m_h460KeepAliveMethodH225;
        } else {
            method = m_nonStdKeepAliveMethodH225;
        }
        switch(method) {
            case TPKTH225:
                SendEmptyTPKTKeepAlive();
                break;
            case EmptyFacility:
                if (sig_sock != NULL) {
                    sig_sock->SendFacilityKeepAlive();
                }
                break;
            case Information:
                if (sig_sock != NULL) {
                    sig_sock->SendInformationKeepAlive();
                }
                break;
            case Notify:
                if (sig_sock != NULL) {
                    sig_sock->SendNotifyKeepAlive();
                }
                break;
            case Status:
                if (sig_sock != NULL) {
                    sig_sock->SendStatusKeepAlive();
                }
                break;
            case StatusInquiry:
                if (sig_sock != NULL) {
                    sig_sock->SendStatusInquiryKeepAlive();
                }
                break;
            case NoneH225:
                // do nothing
                break;
        }
	}
}

void TCPProxySocket::SendEmptyTPKTKeepAlive()
{
    PTRACE(6, "Send EmptyTPKT KeepAlive to " << GetName());
    PBYTEArray tbuf(sizeof(TPKTV3));
    BYTE *bptr = tbuf.GetPointer();
    new (bptr) TPKTV3(0); // placement operator
    WriteData(bptr, sizeof(TPKTV3));
}

void TCPProxySocket::RegisterKeepAlive(int h46018_interval)
{
	if (h46018_interval > 0) {
		m_h46018KeepAlive = true;
		m_keepAliveInterval = h46018_interval;
	} else {
		m_h46018KeepAlive = false;
        m_keepAliveInterval = GkConfig()->GetInteger(RoutedSec, "GnuGkTcpKeepAliveInterval", 19);
	}
	UnregisterKeepAlive();  // make sure old registrations get deleted
	// enable for H.460.18 or via config
	if (h46018_interval || GkConfig()->GetBoolean(RoutedSec, "EnableGnuGkTcpKeepAlive", false)) {
        PTime now;
        m_keepAliveTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
            this, &TCPProxySocket::SendKeepAlive, now + PTimeInterval(0, m_keepAliveInterval), m_keepAliveInterval);
    } else {
        m_keepAliveTimer = GkTimerManager::INVALID_HANDLE;
    }
}

void TCPProxySocket::UnregisterKeepAlive()
{
    if (m_keepAliveTimer != GkTimerManager::INVALID_HANDLE) {
        Toolkit::Instance()->GetTimerManager()->UnregisterTimer(m_keepAliveTimer);
        m_keepAliveTimer = GkTimerManager::INVALID_HANDLE;
    }
}

bool TCPProxySocket::SetMinBufSize(WORD len)
{
	if (wbufsize < len) {
		delete [] wbuffer;
		wbuffer = new BYTE[wbufsize = len];
	}
	return (wbuffer != NULL);
}

void TCPProxySocket::RemoveRemoteSocket()
{
    //m_remoteLock.Wait(); // don't lock here, causes dead lock in reroute
	remote = NULL;
}


// class CallSignalSocket
CallSignalSocket::CallSignalSocket()
	: TCPProxySocket("Q931s"), m_callerSocket(true)
{
	InternalInit();
	localAddr = peerAddr = masqAddr = GNUGK_INADDR_ANY;
	peerPort = 0;
	m_h245Tunneling = true;
	SetHandler(RasServer::Instance()->GetSigProxyHandler());
}

CallSignalSocket::CallSignalSocket(CallSignalSocket *socket, WORD _port)
	: TCPProxySocket("Q931d", socket, _port), m_callerSocket(false)
{
	InternalInit();
	m_h245Tunneling = true;
	SetRemote(socket);
}

void CallSignalSocket::InternalInit()
{
	m_crv = 0;
	m_h245handler = NULL;
	m_h245socket = NULL;
	m_h245TunnelingTranslation = Toolkit::Instance()->Config()->GetBoolean(RoutedSec, "H245TunnelingTranslation", false);
	m_isnatsocket = false;
	m_maintainConnection = false;
	m_result = NoData;
	m_setupPdu = NULL;
#ifdef HAS_H46017
	m_h46017Enabled = GkConfig()->GetBoolean(RoutedSec, "EnableH46017", false);
	rc_remote = NULL;
#endif
#ifdef HAS_H46018
	m_callFromTraversalServer = false;
	m_callToTraversalServer = false;
	m_senderSupportsH46019Multiplexing = false;
#endif
#ifdef HAS_H235_MEDIA
	m_setupClearTokens = NULL;
#endif
	m_isH245Master = false;
#ifdef HAS_H46026
	if (Toolkit::Instance()->IsH46026Enabled() && GkConfig()->GetBoolean(RoutedSec, "UseH46026PriorityQueue", true)) {
		m_h46026PriorityQueue = new H46026ChannelManager();
	} else {
		m_h46026PriorityQueue = NULL;
	}
#endif
	// m_callerSocket is always initialized in init list
	m_h225Version = 0;
	m_tcsRecSeq = 0;
	m_tcsAckRecSeq = 0;

	RegisterKeepAlive();   // if enabled, start a keep-alive with default interval
}

#ifdef HAS_H46017
void CallSignalSocket::CleanupCall()
{
#ifdef HAS_H46018
	if (m_call && Toolkit::AsBool(GkConfig()->GetString(ProxySection, "RTPMultiplexing", "0")))
		MultiplexedRTPHandler::Instance()->RemoveChannels(m_call->GetCallNumber());
#endif
#ifdef HAS_H46026
	if (m_call && Toolkit::Instance()->IsH46026Enabled())
		H46026RTPHandler::Instance()->RemoveChannels(m_call->GetCallNumber());
	if (m_h46026PriorityQueue)
		m_h46026PriorityQueue->BufferRelease(0);	// clear buffers for all calls on this socket
#endif
	// clear the call
	m_call = callptr(NULL);
	m_crv = 0;

	// clear H.245 socket and handler
	if (m_h245socket)
		m_h245socket->OnSignalingChannelClosed();	// close socket and set deletable
	m_h245socket = NULL;
	m_h245handlerLock.Wait();
	if (m_h245handler)
		delete m_h245handler;
	m_h245handler = NULL;
	m_h245handlerLock.Signal();

	if (remote)
		rc_remote = remote;	// save remote pointer to forward ReleaseComplete
	DetachRemote();

	if (m_setupPdu)
		delete m_setupPdu;
	m_setupPdu = NULL;
	// std::queue douesn't have a clear() operation, swap in an empty queue instead
	std::queue<PASN_OctetString> empty;
	std::swap(m_h245Queue, empty);
#ifdef HAS_H46018
	m_callFromTraversalServer = false;
	m_callToTraversalServer = false;
	m_senderSupportsH46019Multiplexing = false;
#endif
#ifdef HAS_H235_MEDIA
	if (m_setupClearTokens)
		delete m_setupClearTokens;
	m_setupClearTokens = NULL;
#endif
	m_isH245Master = false;
	m_h225Version = 0;
}
#endif

bool CallSignalSocket::ForwardData()
{
	PWaitAndSignal lock(m_remoteLock);
	if (remote) {
		return remote->InternalWrite(buffer);
	}
#ifdef HAS_H46017
	// with H.460.17 the remote pointer may have been deleted when ending the call
	// use rc_remote to forward the last ReleaseComplete in the call
	if (rc_remote) {
		bool result = rc_remote->InternalWrite(buffer);
		rc_remote = NULL;
		return result;
	}
#endif
	return false;
}

void CallSignalSocket::SetRemote(CallSignalSocket * socket)
{
	remote = socket;
	m_call = socket->m_call;
	m_call->SetSocket(socket, this);
#ifdef HAS_H46026
	// now that we have a call associated with this socket, set the H.460.26 pipe bandwidth
	if (m_h46026PriorityQueue && m_call && m_call->GetCalledParty()) {
		m_h46026PriorityQueue->SetPipeBandwidth(m_call->GetCalledParty()->GetH46026BW());
	}
#endif
	m_crv = (socket->m_crv & 0x7fffu);
	if (!m_h245TunnelingTranslation)
		m_h245Tunneling = socket->m_h245Tunneling;
	socket->GetPeerAddress(peerAddr, peerPort);
	UnmapIPv4Address(peerAddr);
	localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
	UnmapIPv4Address(localAddr);
	masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
	UnmapIPv4Address(masqAddr);

	SetHandler(socket->GetHandler());
	// don't rename the existing remote socket of a H.460.17 call
	if (!(m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46017())) {
		SetName(AsString(socket->peerAddr, GetPort()));
	}

	Address calling = GNUGK_INADDR_ANY, called = GNUGK_INADDR_ANY;
	int nat_type = m_call->GetNATType(calling, called);
	if (nat_type & CallRec::calledParty) {
		socket->peerAddr = called;
	}

	if (m_call->GetProxyMode() != CallRec::ProxyEnabled
		&& nat_type == CallRec::both && calling == called) {
		if (!Toolkit::AsBool(GkConfig()->GetString(ProxySection, "ProxyForSameNAT", "1"))) {
			PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy DISABLED. (Same NAT)");
			m_call->SetProxyMode(CallRec::ProxyDisabled);
			return;
		}
	}

	if (GkConfig()->GetBoolean(ProxySection, "ProxyAlways", false)) {
			PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled. (ProxyAlways)");
		m_call->SetProxyMode(CallRec::ProxyEnabled);
		m_call->SetH245Routed(true);
	}

	// enable proxy if required, no matter whether H.245 routed
	if (m_call->GetProxyMode() == CallRec::ProxyDetect) {
		if ((nat_type != CallRec::none && GkConfig()->GetBoolean(ProxySection, "ProxyForNAT", false)) ) {
			// must proxy
			PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled. (ProxyForNAT)");
			m_call->SetProxyMode(CallRec::ProxyEnabled);
		} else {
			// check if we have a [ModeSelection] rule matching for this call
			int mode = Toolkit::Instance()->SelectRoutingMode(peerAddr, socket->peerAddr);

			// check if we have a [ModeVendorSelection] rule matching the calling party
			PString vendor, version;
			if ((mode != CallRec::Proxied) && m_call->GetCallingVendor(vendor, version)) {
				int vendormode = Toolkit::Instance()->SelectRoutingVendorMode(vendor + " " + version);
				if (vendormode > mode)
                    mode = vendormode;
			}

			switch (mode) {
				case CallRec::SignalRouted:
					m_call->SetProxyMode(CallRec::ProxyDisabled);
					m_call->SetH245Routed(false);
					break;
				case CallRec::H245Routed:
					m_call->SetProxyMode(CallRec::ProxyDisabled);
					m_call->SetH245Routed(true);
					break;
				case CallRec::Proxied:
                    PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled. (mode selection or vendor mode)");
					m_call->SetProxyMode(CallRec::ProxyEnabled);
					m_call->SetH245Routed(true);
					break;
				default:
					m_call->SetProxyMode(CallRec::ProxyDisabled);
					break;
			}
		}
	}
	PTRACE(1, "Call " << m_call->GetCallNumber() << ": h245Routed=" << m_call->IsH245Routed() << " proxy=" << ((m_call->GetProxyMode() == CallRec::ProxyEnabled) ? 1 : 0));

	if (m_call->GetProxyMode() == CallRec::ProxyEnabled) {
		H245ProxyHandler *proxyhandler = new H245ProxyHandler(m_call->GetCallIdentifier(), socket->localAddr, calling, socket->masqAddr);
#ifdef HAS_H46026
		if (m_call->GetCallingParty())
			proxyhandler->SetUsesH46026(m_call->GetCallingParty()->UsesH46026());
#endif
#ifdef HAS_H46018
		if (m_call->GetCallingParty() && m_call->GetCallingParty()->GetTraversalRole() != None) {
			proxyhandler->SetTraversalRole(m_call->GetCallingParty()->GetTraversalRole());
		}
		if (RasServer::Instance()->IsCallFromTraversalClient(peerAddr)) {
			// if we get a Setup from a traversal zone, it must me from a traversal client and we won't have an EPRec for it
			proxyhandler->SetTraversalRole(TraversalClient);
		}
		GkClient * gkClient = RasServer::Instance()->GetGkClient();
		if (gkClient && gkClient->CheckFrom(peerAddr) && gkClient->UsesH46018()) {
			// for a Setup from a parent we won't have an EPRec and if H.460.18 is used it must be the server
			proxyhandler->SetTraversalRole(TraversalServer);
		}
		proxyhandler->SetH46019Direction(m_call->GetH46019Direction());
		proxyhandler->SetRequestRTPMultiplexing(socket->m_senderSupportsH46019Multiplexing);
#endif
		socket->m_h245handler = proxyhandler;
		m_h245handler = new H245ProxyHandler(m_call->GetCallIdentifier(), localAddr, called, masqAddr, proxyhandler);
#ifdef HAS_H46026
		if (m_call->GetCalledParty())
			((H245ProxyHandler*)m_h245handler)->SetUsesH46026(m_call->GetCalledParty()->UsesH46026());
#endif
#ifdef HAS_H46018
		if (m_call->GetCalledParty() && m_call->GetCalledParty()->GetTraversalRole() != None) {
			((H245ProxyHandler*)m_h245handler)->SetTraversalRole(m_call->GetCalledParty()->GetTraversalRole());
		}
		((H245ProxyHandler*)m_h245handler)->SetH46019Direction(m_call->GetH46019Direction());
		((H245ProxyHandler*)m_h245handler)->SetRequestRTPMultiplexing(m_senderSupportsH46019Multiplexing);
#endif
		proxyhandler->SetHandler(GetHandler());
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled");
	} else {
		if (m_call->IsH245Routed()) {
			socket->m_h245handler = new H245Handler(socket->localAddr, calling, socket->masqAddr);
			m_h245handler = new H245Handler(localAddr, called, masqAddr);
		}
	}
}

CallSignalSocket::~CallSignalSocket()
{
#ifdef HAS_H46018
	if (m_call && Toolkit::AsBool(GkConfig()->GetString(ProxySection, "RTPMultiplexing", "0")))
		MultiplexedRTPHandler::Instance()->RemoveChannels(m_call->GetCallNumber());
#endif
#ifdef HAS_H46026
	if (m_call && Toolkit::Instance()->IsH46026Enabled())
		H46026RTPHandler::Instance()->RemoveChannels(m_call->GetCallNumber());
	if (m_h46026PriorityQueue)
		delete m_h46026PriorityQueue;
#endif
	if (m_h245socket) {
		if (CallSignalSocket *ret = static_cast<CallSignalSocket *>(remote)) {
			if (m_h245handler && !m_h245handler->IsSessionEnded() && ret->m_h245socket) {
				ret->m_h245socket->SendEndSessionCommand();
			}
			if (ret->m_h245handler && !ret->m_h245handler->IsSessionEnded()) {
				m_h245socket->SendEndSessionCommand();
			}
		}
		m_h245socket->OnSignalingChannelClosed();
	}

	if (m_call) {
		if (m_call->GetCallSignalSocketCalling() == this) {
			m_call->SetCallSignalSocketCalling(NULL);
			PTRACE(1, "Q931\tWARNING: Calling socket " << GetName()
				<< " not removed from CallRec before deletion"
				);
		} else if (m_call->GetCallSignalSocketCalled() == this) {
			m_call->SetCallSignalSocketCalled(NULL);
			PTRACE(1, "Q931\tWARNING: Called socket " << GetName()
				<< " not removed from CallRec before deletion"
				);
		}
	}

	m_h245handlerLock.Wait();
	delete m_h245handler;
	m_h245handler = NULL;
	m_h245handlerLock.Signal();
	delete m_setupPdu;
	m_setupPdu = NULL;
	// std::queue douesn't have a clear() operation, swap in an empty queue instead
	std::queue<PASN_OctetString> empty;
	std::swap(m_h245Queue, empty);
#ifdef HAS_H235_MEDIA
	delete m_setupClearTokens;
	m_setupClearTokens = NULL;
#endif
}

#ifdef LARGE_FDSET
bool CallSignalSocket::Connect(const Address & addr)
#else
PBoolean CallSignalSocket::Connect(const Address & addr)
#endif
{
	Address local = RasServer::Instance()->GetLocalAddress(addr);
	UnmapIPv4Address(local);
	int numPorts = min(Q931PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = Q931PortRange.GetPort();
		if (TCPProxySocket::Connect(local, pt, addr)) {
			return true;
		}
		int errorNumber = GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, Type() << "\tCould not open/connect Q.931 socket at " << AsString(local, pt)
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << GetErrorText(PSocket::LastGeneralError)
			<< " remote addr: " << AsString(addr));
		Close();
	}
	return false;
}

void PrintQ931(int tlevel, const char *msg1, const char *msg2, const Q931 *q931, const H225_H323_UserInformation *uuie)
{
	PStringStream pstrm;
	pstrm << "Q931\t" << msg1 << msg2 << " {\n  q931pdu = " << setprecision(2) << *q931;
	if (uuie)
		pstrm << "\n  h225pdu = " << setprecision(2) << *uuie;
	pstrm << "\n}";
	PTRACE(tlevel, pstrm);
}

void CallSignalSocket::RemoveCall()
{
	if (m_call) {
		m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
		CallTable::Instance()->RemoveCall(m_call);
	}
}

void RemoveHopToHopTokens(Q931 * msg, H225_H323_UserInformation * uuie)
{
    H225_ArrayOf_ClearToken * tokens = NULL;
    H225_ArrayOf_CryptoH323Token * cryptoTokens = NULL;
    bool changed = false;

    GkH235Authenticators::GetQ931Tokens(msg->GetMessageType(), uuie, &tokens, &cryptoTokens);

    if (!cryptoTokens) {
        return;
    }

    PINDEX i = 0;
    while (i < cryptoTokens->GetSize()) {
        const H225_CryptoH323Token & token = (*cryptoTokens)[i];
        if (token.GetTag() == H225_CryptoH323Token::e_nestedcryptoToken) {
            const H235_CryptoToken & nestedCryptoToken = token;
            if (nestedCryptoToken.GetTag() == H235_CryptoToken::e_cryptoHashedToken) {
                const H235_CryptoToken_cryptoHashedToken & cryptoHashedToken = nestedCryptoToken;
                if (cryptoHashedToken.m_tokenOID == OID_H235_A_V1 || cryptoHashedToken.m_tokenOID == OID_H235_A_V2) {
                    // remove H.235.1 token
                    // TODO235: check for dhkey inside nestedctyptoToken ??? H.235.1 clause 7 + 8 says it might be here instead of the H.235.6 clearTokens ?
                    for (PINDEX j = i+1; j < cryptoTokens->GetSize(); j++)
                        (*cryptoTokens)[j-1] = (*cryptoTokens)[j];
                    cryptoTokens->SetSize(cryptoTokens->GetSize() - 1);
                    i--;    // re-check new i (re-incremented below)
                    changed = true;
                }
            }
        }
        i++;
    }
    if (changed) {
        SetUUIE(*msg, *uuie);
    }
}

ProxySocket::Result CallSignalSocket::ReceiveData()
{
	if (!ReadTPKT()) {
#ifdef HAS_H46017
		if (m_isnatsocket && !IsOpen()) {
			RegistrationTable::Instance()->OnNATSocketClosed(this);
			CleanupCall();
		}
#endif
		return IsOpen() ? NoData : Error;
	}

	H225_H323_UserInformation * uuie = NULL;
	Q931 * q931pdu = new Q931();

	if (!q931pdu->Decode(buffer)) {
		PTRACE(1, Type() << "\t" << GetName() << " ERROR DECODING Q.931!");
		SNMP_TRAP(9, SNMPError, General, "Error decoding Q931 message from " + GetName());
		delete q931pdu;
		q931pdu = NULL;
		PCaselessString action = GkConfig()->GetString(RoutedSec, "Q931DecodingError", "Disconnect");
		if (action == "Drop") {
			m_result = NoData;
		} else if (action == "Forward") {
			m_result = Forwarding;
		} else {
			m_result = Error;
		}
		return m_result;
	}

	PIPSocket::Address _localAddr, _peerAddr;
	WORD _localPort = 0, _peerPort = 0;
	GetLocalAddress(_localAddr, _localPort);
	UnmapIPv4Address(_localAddr);
	GetPeerAddress(_peerAddr, _peerPort);
	UnmapIPv4Address(_peerAddr);

	PTRACE(3, Type() << "\tReceived: " << q931pdu->GetMessageTypeName()
		<< " CRV=" << q931pdu->GetCallReference() << " from " << GetName());

	if (q931pdu->HasIE(Q931::UserUserIE)) {
		uuie = new H225_H323_UserInformation();
		if (!GetUUIE(*q931pdu, *uuie)) {
			PTRACE(1, Type() << "\tCould not decode User-User IE for message "
				<< q931pdu->GetMessageTypeName() << " CRV="
				<< q931pdu->GetCallReference() << " from " << GetName());
			SNMP_TRAP(9, SNMPWarning, General, "Error decoding User-User IE message from " + GetName());
			if (q931pdu->GetMessageType() == Q931::NotifyMsg) {
				PTRACE(1, "Unknown User-User IE in Notify, continuing");
				uuie = NULL;
				m_result = Forwarding;
			} else {
				delete uuie;
				uuie = NULL;
				delete q931pdu;
				q931pdu = NULL;
				return m_result = Error;
			}
		}
	}

	m_result = Forwarding;

#ifdef HAS_H46017
	// only show full decode of H.460.26 RTP when level 7 trace is active
	if (m_h46017Enabled && m_maintainConnection && (q931pdu->GetMessageType() == Q931::InformationMsg) && !PTrace::CanTrace(7)) {
		// don't print Info message
	} else
#endif
	{
		PrintQ931(4, "Received:", "", q931pdu, uuie);
	}

	SignalingMsg *msg = SignalingMsg::Create(q931pdu, uuie,
		_localAddr, _localPort, _peerAddr, _peerPort);

#ifdef HAS_H46017
	// check for incoming H.460.17 RAS message before authentication
	// RAS authentication is inside the tunneled RAS message
	if (msg->GetTag() == Q931::FacilityMsg
		&& uuie
		&& uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_genericData)
		&& m_h46017Enabled) {
		bool h46017found = false;
		for (PINDEX i = 0; i < uuie->m_h323_uu_pdu.m_genericData.GetSize(); ++i) {
			H460_Feature & feat = (H460_Feature &)uuie->m_h323_uu_pdu.m_genericData[i];
			if (feat.GetFeatureID() == H460_FeatureID(17)) {
				H460_FeatureStd & std17 = (H460_FeatureStd &)feat;
				h46017found = true;
				if (!uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling)) {
                    // assume H.245 tunneling, because its required for H.460.17 and Innovaphone sometimes forgets the flag
                    m_h245Tunneling = true;
				}
				// multiple RAS messages can be transmitted
				if (std17.GetParameterCount() > 1) {
					PTRACE(4, "H46017\tWarning: " << std17.GetParameterCount() << " bundled messages");
				}
				for (PINDEX j = 0; j < std17.GetParameterCount(); ++j) {
					H460_FeatureParameter p = std17.GetFeatureParameter(j);
					if (p.ID() == 1 && p.hasContent()) {
						PASN_OctetString & data = p;
						// mark this socket as NAT socket
						m_isnatsocket = true;
						m_maintainConnection = true; // GnuGk NAT will close the TCP connection after the call, for H.460.17 we don't want that
						SetConnected(true); // avoid the socket be deleted
						// hand RAS message to RasSserver for processing
						RasServer::Instance()->ReadH46017Message(data.GetValue(), _peerAddr, _peerPort, _localAddr, this);
					}
				}
			}
		}
		if (h46017found) {
			delete msg;
			return NoData;	// don't forward
		}
	}
#endif

    // need source EP to find H.235.1 authenticator
    callptr tmpCall = m_call;
    endptr fromEP;
    GkH235Authenticators * auth = NULL;
    H225_ArrayOf_AliasAddress aliases;
    if (!tmpCall && (q931pdu->GetMessageType() == Q931::SetupMsg) && uuie
        && (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() == H225_H323_UU_PDU_h323_message_body::e_setup)) {
        H225_Setup_UUIE & setup = uuie->m_h323_uu_pdu.m_h323_message_body;
        if (setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
            tmpCall = CallTable::Instance()->FindCallRec(setup.m_callIdentifier);
        } else {
            tmpCall = CallTable::Instance()->FindCallRec(q931pdu->GetCallReference());
        }
    }
    if (tmpCall) {
        if (q931pdu->IsFromDestination()) {
            fromEP = tmpCall->GetCalledParty();
        } else {
            fromEP = tmpCall->GetCallingParty();
        }
    }
    if (fromEP) {
        auth = fromEP->GetH235Authenticators();
        aliases = fromEP->GetAliases();
    }
    bool overTLS = false;
#ifdef HAS_TLS
    overTLS = (dynamic_cast<TLSCallSignalSocket *>(this) != NULL);
#endif

    // validate all Q.931 messages, except Setup which is checked further down
    // checking all, would break authenticators that don't support new Q.931 checks
    if (q931pdu->GetMessageType() != Q931::SetupMsg) {
        Q931AuthData authData(aliases, _peerAddr, _peerPort, overTLS, auth);
        if (!RasServer::Instance()->ValidatePDU(*q931pdu, authData)) {
            if (tmpCall) {
                tmpCall->SetDisconnectCause(Q931::NormalUnspecified); // Q.931 code for reason=SecurityDenied
            } else {
                // TODO: set disconnect cause differently for pregranted or unregistered calls ?
            }
            delete msg;
            return m_result = Error;
        }
    }

    RemoveHopToHopTokens(q931pdu, uuie);

    m_result = Forwarding;

#ifdef H323_H450
	// Enable H.450.2 Call Transfer Emulator
	if (m_call
		&& uuie
		&& Toolkit::AsBool(Toolkit::Instance()->Config()->GetString(RoutedSec, "EnableH450.2", "0"))
		&& uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h4501SupplementaryService)) {
			// Process H4501SupplementaryService APDU
			if (OnH450PDU(uuie->m_h323_uu_pdu.m_h4501SupplementaryService))  {
				delete msg;
				return NoData;   // don't forward
			}
    }
#endif

	if (m_h245Tunneling && uuie != NULL) {
#if H225_PROTOCOL_VERSION >= 4
		if (!uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_provisionalRespToH245Tunneling))
#endif
		m_h245Tunneling = (uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling)
			&& uuie->m_h323_uu_pdu.m_h245Tunneling.GetValue());
		if (!m_h245Tunneling && !m_h245TunnelingTranslation && GetRemote())
			GetRemote()->m_h245Tunneling = false;
	}

	bool disableH245Tunneling = Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "DisableH245Tunneling", "0"));
	if (disableH245Tunneling) {
		m_h245Tunneling = false;
		if (GetRemote())
			GetRemote()->m_h245Tunneling = false;
	}

	if (m_h245TunnelingTranslation) {
		// un-tunnel H.245 messages
		if (m_h245Tunneling && GetRemote() && !GetRemote()->m_h245Tunneling) {
			if (uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control)
				&& uuie->m_h323_uu_pdu.m_h245Control.GetSize() > 0) {
				// process tunneled H.245 messages before un-tunneling them
				bool suppress = false;
				OnTunneledH245(msg->GetUUIE()->m_h323_uu_pdu.m_h245Control, suppress);
				if (!suppress) {
					bool remoteHasH245Connection = (GetRemote()->m_h245socket && GetRemote()->m_h245socket->IsConnected());
					for (PINDEX i = 0; i < uuie->m_h323_uu_pdu.m_h245Control.GetSize(); ++i) {
						if (remoteHasH245Connection) {
							GetRemote()->m_h245socket->Send(uuie->m_h323_uu_pdu.m_h245Control[i]);
						} else {
							PTRACE(4, "H245\tQueueing H.245 messages until connected");
							m_h245Queue.push(uuie->m_h323_uu_pdu.m_h245Control[i]);
						}
					}
				}
			}
			if (msg->GetTag() == Q931::ConnectMsg) {
				// inject H.245 address into Connect for H.245 tunneling translation
				ConnectMsg * connect = dynamic_cast<ConnectMsg*>(msg);
				if (connect != NULL) {
					H225_Connect_UUIE & connectBody = connect->GetUUIEBody();
					connectBody.IncludeOptionalField(H225_Connect_UUIE::e_h245Address);
					// set a placeholder, will be overwritten when the H.245 listener is started
					connectBody.m_h245Address = SocketToH225TransportAddr(masqAddr, 1);
				}
			}
			uuie->m_h323_uu_pdu.RemoveOptionalField(H225_H323_UU_PDU::e_h245Control);
			uuie->m_h323_uu_pdu.m_h245Tunneling.SetValue(false);
			msg->SetUUIEChanged();
		}
		if (msg->GetTag() == Q931::SetupMsg) {
			// when Setup comes in, we don't know, yet, if tunneling translation is needed
			// so we always save the H.245 but leave it in the Setup in case the remote side tunnels
			if (uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control)
				&& uuie->m_h323_uu_pdu.m_h245Control.GetSize() > 0) {
				// process tunneled H.245 messages before saving
				bool suppress = false;
				OnTunneledH245(msg->GetUUIE()->m_h323_uu_pdu.m_h245Control, suppress);
				if (!suppress) {
					for (PINDEX i = 0; i < uuie->m_h323_uu_pdu.m_h245Control.GetSize(); ++i) {
						PTRACE(4, "H245\tQueueing H.245 messages from Setup");
						m_h245Queue.push(uuie->m_h323_uu_pdu.m_h245Control[i]);
					}
				}
			}
		}
		if (!m_h245Tunneling && ((GetRemote() && GetRemote()->m_h245Tunneling) || (msg->GetTag() == Q931::SetupMsg))) {
			// if we haven't received a Q.931 message from the remote, yet, we assume it will be tunneling, so Setup messages will set it to TRUE here
			uuie->m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
			uuie->m_h323_uu_pdu.m_h245Tunneling.SetValue(true);
			msg->SetUUIEChanged();
		}
	}
	if (disableH245Tunneling && uuie && uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling)) {
		// if the h245Tunnelling field isn't present, that means no tunneling anyway
		uuie->m_h323_uu_pdu.m_h245Tunneling.SetValue(false);
		msg->SetUUIEChanged();
	}

	switch (msg->GetTag()) {
	case Q931::SetupMsg:
		m_rawSetup = buffer;
		m_rawSetup.MakeUnique();
		OnSetup(msg);
		break;
	case Q931::CallProceedingMsg:
		OnCallProceeding(msg);
		break;
	case Q931::ConnectMsg:
		m_rawConnect = buffer;
		m_rawConnect.MakeUnique();
		OnConnect(msg);
		break;
	case Q931::AlertingMsg:
		OnAlerting(msg);
		break;
	case Q931::ReleaseCompleteMsg:
		OnReleaseComplete(msg);
		break;
	case Q931::FacilityMsg:
		OnFacility(msg);
		break;
	case Q931::ProgressMsg:
		OnProgress(msg);
		break;
	case Q931::InformationMsg:
		OnInformation(msg);
		break;
	case Q931::StatusMsg:
		OnStatus(msg);
		break;
	}

	if (!m_callerSocket && m_call
		&& ((msg->GetTag() == Q931::AlertingMsg) || (msg->GetTag() == Q931::ConnectMsg))) {
		m_call->SetCallInProgress();
	}

	if (m_result == Error || m_result == NoData) {
		delete msg;
		return m_result;
	}

	if (msg->GetUUIE() != NULL && msg->GetUUIE()->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control)) {
		bool suppress = false;
		if (m_h245handler && OnTunneledH245(msg->GetUUIE()->m_h323_uu_pdu.m_h245Control, suppress))
			msg->SetUUIEChanged();

        if (suppress) {
			m_result = NoData;	// don't forward anything
		    PTRACE(2, "Not forwarding " << msg->GetTagName());
		    delete msg;
		    return m_result;
        }

		if (!m_callerSocket && m_call)
			m_call->SetH245ResponseReceived();
	}

	if (m_call && (m_call->GetRerouteState() == RerouteInitiated) && (msg->GetTag() == Q931::ReleaseCompleteMsg)) {
		// don't end reroute on RC to/from dropped party
		if ( (m_callerSocket && m_call->GetRerouteDirection() == Caller)
            || (!m_callerSocket && m_call->GetRerouteDirection() == Called)) {
            PTRACE(1, "Q931\tReroute failed, terminating call");
            m_call->SetRerouteState(NoReroute);
		}
	}

	if (m_call && (m_call->GetRerouteState() == RerouteInitiated) && (msg->GetTag() != Q931::SetupMsg) && (msg->GetTag() != Q931::ConnectMsg)) {
		m_result = NoData;	// don't forward anything until reroute is through
		PTRACE(2, "Call in reroute: won't forward " << msg->GetTagName());
		delete msg;
		return m_result;
	}

	if (m_call && m_call->GetRerouteState() == RerouteInitiated && (msg->GetTag() == Q931::ConnectMsg)) {
		m_result = NoData;	// process messages, but don't forward anything until reroute is through
		PTRACE(2, "Call in reroute: won't forward " << msg->GetTagName() << " switching to Rerouting state");
		m_call->SetRerouteState(Rerouting);

		// forward saved TCS
		if (m_h245Tunneling) {
			// WARNING: this code for h245tunneled mode is hardly tested
			// when tunneling, forward the TCS here (we probably got it in the connect)
			// when call is not tunneled, the TCS comes later and goes through automatically

			// build TCS
			H245_MultimediaSystemControlMessage h245msg;
			h245msg.SetTag(H245_MultimediaSystemControlMessage::e_request);
			H245_RequestMessage & h245req = h245msg;
			h245req.SetTag(H245_RequestMessage::e_terminalCapabilitySet);
			H245_TerminalCapabilitySet & tcs = h245req;
			tcs = GetRemote()->GetSavedTCS();	// TODO: is this the right side, or should we use remote->GetSavedTCS() ?
			tcs.m_protocolIdentifier.SetValue(H245_ProtocolID);

			// send TCS to forwarded party
			if ((m_call->GetRerouteDirection() == Called) && m_call->GetCallSignalSocketCalled()) {
                unsigned seq = m_call->GetCallSignalSocketCalled()->GetNextTCSSeq();
                tcs.m_sequenceNumber = seq;
				m_call->GetCallSignalSocketCalled()->SendTunneledH245(h245msg);
			} else if (m_call->GetCallSignalSocketCalling()) {
                unsigned seq = m_call->GetCallSignalSocketCalling()->GetNextTCSSeq();
                tcs.m_sequenceNumber = seq;
				m_call->GetCallSignalSocketCalling()->SendTunneledH245(h245msg);
			}
		}

/*      don't send the Notify: it doesn't seem to help any endpoint and Polycom RealPresence starts a flood of Status messages
        // send Notify with new DisplayIE and BearerCapabilityIE
        if ((msg->GetQ931().HasIE(Q931::DisplayIE) || msg->GetQ931().HasIE(Q931::BearerCapabilityIE)) && GetRemote()) {
            Q931 q931;
			H225_H323_UserInformation uuie;
            BuildNotifyPDU(q931, true);
            GetUUIE(q931, uuie);
            if (msg->GetQ931().HasIE(Q931::DisplayIE)) {
                q931.SetIE(Q931::DisplayIE, msg->GetQ931().GetIE(Q931::DisplayIE));
                // only set if receiver is H.225 v7 or higher ?
                H225_Notify_UUIE & notify = uuie.m_h323_uu_pdu.m_h323_message_body;
                notify.IncludeOptionalField(H225_Notify_UUIE::e_displayName);
                notify.m_displayName.SetSize(1);
                notify.m_displayName[0].m_name = q931.GetDisplayName();
            }
			if (msg->GetQ931().HasIE(Q931::BearerCapabilityIE))
                q931.SetIE(Q931::BearerCapabilityIE, msg->GetQ931().GetIE(Q931::BearerCapabilityIE));
            uuie.m_h323_uu_pdu.m_h245Tunneling = GetRemote()->IsH245Tunneling();
            SetUUIE(q931, uuie);
            PBYTEArray lBuffer;
            q931.Encode(lBuffer);
            PrintQ931(3, "Send to ", GetRemote()->GetName(), &q931, &uuie);
            GetRemote()->TransmitData(lBuffer);
            // TODO:
            // Also send a Facility with H.450.8 Connected Party Name ?
            // H.450.8 says the ConnectedPartyName shall be sent in the Connect message
        }
*/
		delete msg;
		return m_result;
	}

	if (msg->GetQ931().HasIE(Q931::DisplayIE)) {
		PString newDisplayIE;
        PString screenDisplayIE = GkConfig()->GetString(RoutedSec, "ScreenDisplayIE", "");
        PString appendToDisplayIE = GkConfig()->GetString(RoutedSec, "AppendToDisplayIE", "");
		if (m_crv & 0x8000u) {	// rewrite DisplayIE from caller
            if (m_call) {
                if (!m_call->GetCallerID().IsEmpty() || !m_call->GetCallerDisplayIE().IsEmpty()) {
                    newDisplayIE = m_call->GetCallerID();
                    if (!m_call->GetCallerDisplayIE().IsEmpty()) {
                        newDisplayIE = m_call->GetCallerDisplayIE();
                    }
                } else if (screenDisplayIE != PCaselessString("Called")) {
                    newDisplayIE = screenDisplayIE + appendToDisplayIE;
                }
                if (screenDisplayIE == PCaselessString("Calling") || screenDisplayIE == PCaselessString("CallingCalled")) {
                    if (m_call) {
                        newDisplayIE = m_call->GetCallingStationId() + appendToDisplayIE;
                    }
                }
			}
		} else {
            if (m_call) {
                if (!m_call->GetCalledDisplayIE().IsEmpty()) {
                    newDisplayIE = m_call->GetCalledDisplayIE();
                } else if (screenDisplayIE != PCaselessString("Calling")) {
                    newDisplayIE = screenDisplayIE + appendToDisplayIE;
                }
                if (screenDisplayIE == PCaselessString("Called") || screenDisplayIE == PCaselessString("CallingCalled")) {
                    if (m_call) {
                        newDisplayIE = m_call->GetCalledStationId() + appendToDisplayIE;
                    }
                }
            }
		}
        if (screenDisplayIE == PCaselessString("Delete")) {
			msg->GetQ931().RemoveIE(Q931::DisplayIE);
			msg->SetChanged();
		} else if (!newDisplayIE.IsEmpty()) {
            PTRACE(4, "Q931\tSetting DisplayIE to " << newDisplayIE);
			msg->GetQ931().SetDisplayName(newDisplayIE);
			msg->SetChanged();
		}
	}

	// just copy unknown IEs in Notify
	if ((q931pdu->GetMessageType() == Q931::NotifyMsg)
		&& (q931pdu->HasIE(Q931::UserUserIE))
		&& (uuie == NULL)) {
		PTRACE(1, "Copy unknown User-User IE in Notify");
		msg->GetQ931().SetIE(Q931::UserUserIE, q931pdu->GetIE(Q931::UserUserIE));
	}

// if we put the signaling messages into the prio queue, it locks up on Connect
//#ifdef HAS_H46026
//	CallSignalSocket * remote_css = dynamic_cast<CallSignalSocket *>(remote);
//	if (remote_css && remote_css->m_h46026PriorityQueue) {
//		// put message into priority queue
//		remote_css->m_h46026PriorityQueue->SignalMsgOut(*q931pdu);
//		delete msg;
//
//		remote_css->PollPriorityQueue();
//
//		m_result = NoData;
//		return m_result;
//	}
//#endif

	if (msg->IsChanged() && !msg->Encode(buffer)) {
		m_result = Error;
    } else if (remote && (m_result != DelayedConnecting)) {
        // add H.235.1 tokens
        if (m_call) {
            endptr toEP;
            if (msg->GetQ931().IsFromDestination()) {
                toEP = m_call->GetCallingParty();
            } else {
                toEP = m_call->GetCalledParty();
            }
            if (toEP) {
                auth = toEP->GetH235Authenticators();
                if (auth) {
                    uuie = msg->GetUUIE();  // needed ?
                    if (uuie) {
                        if (SetupResponseTokens(msg, auth, toEP)) {
                            msg->SetChanged();
                            msg->SetUUIEChanged();
                            if (msg->Encode(buffer)) {
                                auth->Finalise(msg->GetTag(), buffer);
                            }
                        }
                    }
                }
            }
        }
        PrintQ931(4, "Send to ", remote->GetName(), &msg->GetQ931(), msg->GetUUIE());
    }

	delete msg;
	return m_result;
}


bool CallSignalSocket::SetupResponseTokens(SignalingMsg * msg, GkH235Authenticators * auth, const endptr & ep)
{
    if (msg == NULL || auth == NULL) {
        return false;   // message not changed
    }

    if (GkConfig()->GetBoolean("H235", "UseEndpointIdentifier", true) && ep) {
        auth->SetProcedure1RemoteId(ep->GetEndpointIdentifier().GetValue());
    }

    H225_H323_UserInformation * uuie = msg->GetUUIE();
    if (uuie == NULL) {
        PTRACE(1, "Error: Can't add tokens without a UUIE");
        return false;   // message not changed
    }
    H225_ArrayOf_ClearToken tokens; // not used
    H225_ArrayOf_CryptoH323Token cryptoTokens;
    auth->PrepareTokens(msg->GetTag(), tokens, cryptoTokens);

    if (cryptoTokens.GetSize() > 0) {
        switch (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag()) {
            case H225_H323_UU_PDU_h323_message_body::e_alerting: {
                    H225_Alerting_UUIE & alerting = uuie->m_h323_uu_pdu.m_h323_message_body;
                    alerting.IncludeOptionalField(H225_Alerting_UUIE::e_cryptoTokens);
                    alerting.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_callProceeding: {
                    H225_CallProceeding_UUIE & proceeding = uuie->m_h323_uu_pdu.m_h323_message_body;
                    proceeding.IncludeOptionalField(H225_CallProceeding_UUIE::e_cryptoTokens);
                    proceeding.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_connect: {
                    H225_Connect_UUIE & connect = uuie->m_h323_uu_pdu.m_h323_message_body;
                    connect.IncludeOptionalField(H225_Connect_UUIE::e_cryptoTokens);
                    connect.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_progress: {
                    H225_Progress_UUIE & progress = uuie->m_h323_uu_pdu.m_h323_message_body;
                    progress.IncludeOptionalField(H225_Progress_UUIE::e_cryptoTokens);
                    progress.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_setup: {
                    H225_Setup_UUIE & setup = uuie->m_h323_uu_pdu.m_h323_message_body;
                    setup.IncludeOptionalField(H225_Setup_UUIE::e_cryptoTokens);
                    setup.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_setupAcknowledge: {
                    H225_SetupAcknowledge_UUIE & setupAck = uuie->m_h323_uu_pdu.m_h323_message_body;
                    setupAck.IncludeOptionalField(H225_SetupAcknowledge_UUIE::e_cryptoTokens);
                    setupAck.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_releaseComplete: {
                    H225_ReleaseComplete_UUIE & rc = uuie->m_h323_uu_pdu.m_h323_message_body;
                    rc.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_cryptoTokens);
                    rc.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_information: {
                    H225_Information_UUIE & info = uuie->m_h323_uu_pdu.m_h323_message_body;
                    info.IncludeOptionalField(H225_Information_UUIE::e_cryptoTokens);
                    info.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_notify: {
                    H225_Notify_UUIE & notify = uuie->m_h323_uu_pdu.m_h323_message_body;
                    notify.IncludeOptionalField(H225_Notify_UUIE::e_cryptoTokens);
                    notify.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_status: {
                    H225_Status_UUIE & status = uuie->m_h323_uu_pdu.m_h323_message_body;
                    status.IncludeOptionalField(H225_Status_UUIE::e_cryptoTokens);
                    status.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_statusInquiry: {
                    H225_StatusInquiry_UUIE & statusInquiry = uuie->m_h323_uu_pdu.m_h323_message_body;
                    statusInquiry.IncludeOptionalField(H225_StatusInquiry_UUIE::e_cryptoTokens);
                    statusInquiry.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_facility: {
                    H225_Facility_UUIE & facility = uuie->m_h323_uu_pdu.m_h323_message_body;
                    facility.IncludeOptionalField(H225_Facility_UUIE::e_cryptoTokens);
                    facility.m_cryptoTokens = cryptoTokens;
                }
                break;
            case H225_H323_UU_PDU_h323_message_body::e_empty: {
                    // can't add token without a body
                    return false;   // message not changed
                }
                break;
            default:
                return false;   // message not changed
                break;
        }
    }
    return true;   // message changed
}

void CallSignalSocket::BuildReleasePDU(Q931 & ReleasePDU, const H225_CallTerminationCause *cause) const
{
	ReleasePDU.BuildReleaseComplete(m_crv, m_crv & 0x8000u);
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_releaseComplete);
	H225_ReleaseComplete_UUIE & uuie = body;
	uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (m_call) {
		uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_callIdentifier);
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	} else {
		uuie.RemoveOptionalField(H225_ReleaseComplete_UUIE::e_callIdentifier);
	}
	if (cause) {
		if (cause->GetTag() == H225_CallTerminationCause::e_releaseCompleteReason) {
			uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_reason);
			uuie.m_reason = *cause;
			// remember disconnect cause for billing purposes
			if (m_call && m_call->GetDisconnectCause() == 0)
				m_call->SetDisconnectCause(
					Toolkit::Instance()->MapH225ReasonToQ931Cause(uuie.m_reason.GetTag()));
			if (m_call)
				ReleasePDU.SetCause(Q931::CauseValues(m_call->GetDisconnectCause()));
		} else { // H225_CallTerminationCause::e_releaseCompleteCauseIE
			PPER_Stream strm;
			cause->Encode(strm);
			strm.CompleteEncoding();
			ReleasePDU.SetIE(Q931::CauseIE, strm);
			// remember the cause for billing purposes
			if (m_call && m_call->GetDisconnectCause() == 0)
				m_call->SetDisconnectCause(ReleasePDU.GetCause());
		}
	} else { // either CauseIE or H225_ReleaseComplete_UUIE is mandatory
		if (m_call && m_call->GetDisconnectCause())
			// extract the stored disconnect cause, if not specified directly
			ReleasePDU.SetCause( (Q931::CauseValues)(m_call->GetDisconnectCause()) );
		else {
			uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_reason);
			uuie.m_reason = H225_ReleaseCompleteReason(H225_ReleaseCompleteReason::e_undefinedReason);
		}
	}

	SetUUIE(ReleasePDU, signal);

	PrintQ931(4, "Send to ", GetName(), &ReleasePDU, &signal);
}

void CallSignalSocket::SendReleaseComplete(const H225_CallTerminationCause *cause)  // + endptr
{
	if (IsOpen()) {
		Q931 ReleasePDU;
		BuildReleasePDU(ReleasePDU, cause);
		// TODO235: if (ep->getAuthenticators() && ep->GetAuthenticators()->HasProcedure1Password() SetupResponseTokens(ReleasePDU, ep->getAuthenticators(), ep);
		PBYTEArray buf;
		ReleasePDU.Encode(buf);
		// TODO235: if (ep->getAuthenticators() && ep->getAuthenticators()->HasProcedure1Password() auth->finalize()
		TransmitData(buf);
	}
}

void CallSignalSocket::SendReleaseComplete(H225_ReleaseCompleteReason::Choices reason)
{
	H225_CallTerminationCause cause;
	cause.SetTag(H225_CallTerminationCause::e_releaseCompleteReason);
	H225_ReleaseCompleteReason & releaseReason = cause;
	releaseReason.SetTag(reason);
	SendReleaseComplete(&cause);
}

// calling party must delete returned pointer
PASN_OctetString * CallSignalSocket::GetNextQueuedH245Message()
{
	if (m_h245Queue.empty())
		return NULL;
	PASN_OctetString * result = new PASN_OctetString(m_h245Queue.front());
	m_h245Queue.pop();
	return result;
}

void CallSignalSocket::SendPostDialDigits()
{
	// handle post dial digits
	// TODO: add check if master/slave and TCS have already been exchanged
	if (m_call && m_call->HasPostDialDigits()) {
		bool sendOK = false;
		PTRACE(3, "H245\tSending PostDialDigts " << m_call->GetPostDialDigits());
		for (PINDEX i = 0; i < m_call->GetPostDialDigits().GetLength(); i++) {
			H245_MultimediaSystemControlMessage ui;
			ui.SetTag(H245_MultimediaSystemControlMessage::e_indication);
			H245_IndicationMessage & indication = ui;
			indication.SetTag(H245_IndicationMessage::e_userInput);
			H245_UserInputIndication & userInput = indication;
			userInput.SetTag(H245_UserInputIndication::e_alphanumeric);
			PASN_GeneralString & str = userInput;
			str = m_call->GetPostDialDigits()[i];

			// always send to called side
			if (m_callerSocket) {
				if (GetRemote()) {
					if (GetRemote()->IsH245Tunneling()) {
						sendOK = GetRemote()->SendTunneledH245(ui);
					} else {
						if (GetRemote()->GetH245Socket()) {
							sendOK = GetRemote()->GetH245Socket()->Send(ui);
						}
					}
				}
			} else {
				if (IsH245Tunneling()) {
					sendOK = SendTunneledH245(ui);
				} else {
					if (GetH245Socket()) {
						sendOK = GetH245Socket()->Send(ui);
					}
				}
			}

			if (!sendOK) {
				PTRACE(2, "H245\tError: Sending post dial digit failed");
			}
		}
		if (sendOK)
			m_call->SetPostDialDigits("");	// post dial digits sent, make sure we don't send them again
	}
}

bool CallSignalSocket::HandleH245Mesg(PPER_Stream & strm, bool & suppress, H245Socket * h245sock)
{
	bool changed = false;
	H245_MultimediaSystemControlMessage h245msg;
	if (!h245msg.Decode(strm)) {
		PTRACE(3, "H245\tERROR DECODING H.245 from " << GetName());
		return false;
	}

	PTRACE(4, "H245\tReceived from " << GetName() << " (CallID: " << GetCallIdentifierAsString() << "): " << setprecision(2) << h245msg);

	// remove t38FaxUdpOptions from t38FaxProfile eg. for Avaya Communication Manager
	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_request
		&& ((H245_RequestMessage &) h245msg).GetTag() == H245_RequestMessage::e_requestMode
		&& Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveFaxUDPOptionsFromRM", "0"))) {
		H245_RequestMode & rm = (H245_RequestMessage &) h245msg;
		for (PINDEX i = 0; i < rm.m_requestedModes.GetSize(); i++) {
			for (PINDEX j = 0; j < rm.m_requestedModes[i].GetSize(); j++) {
				if (rm.m_requestedModes[i][j].m_type.GetTag() == H245_ModeElementType::e_dataMode) {
					H245_DataMode & dm = (H245_DataMode &) rm.m_requestedModes[i][j].m_type;
					if (dm.m_application.GetTag() == H245_DataMode_application::e_t38fax) {
						H245_DataMode_application_t38fax & t38fax = (H245_DataMode_application_t38fax &) dm.m_application;
						if (t38fax.m_t38FaxProtocol.GetTag() == H245_DataProtocolCapability::e_udp
							&& t38fax.m_t38FaxProfile.HasOptionalField(H245_T38FaxProfile::e_t38FaxUdpOptions)) {
								PTRACE(2, "H245\tRemoving t38FaxUdpOptions received in RM from " << GetName());
								t38fax.m_t38FaxProfile.RemoveOptionalField(H245_T38FaxProfile::e_t38FaxUdpOptions);
						}
					}
				}
			}
		}
	}

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_request
		&& ((H245_RequestMessage&)h245msg).GetTag() == H245_RequestMessage::e_openLogicalChannel) {

		SendPostDialDigits();	// 2nd check, for non-tunneled connections

		H245_OpenLogicalChannel & olc = (H245_RequestMessage&)h245msg;
#ifdef HAS_H235_MEDIA
		if (Toolkit::Instance()->IsH235HalfCallMediaEnabled()) {
			changed = HandleH235OLC(olc);
		}
#endif
		// store media IPs
        if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)) {
            H245_OpenLogicalChannel_reverseLogicalChannelParameters & revParams = olc.m_reverseLogicalChannelParameters;
            bool isAudio = (revParams.m_dataType.GetTag() == H245_DataType::e_audioData);
            bool isVideo = (revParams.m_dataType.GetTag() == H245_DataType::e_videoData);
            bool isH239 = false;
            if (isVideo) {
                H245_VideoCapability * videoCap = &((H245_VideoCapability&)olc.m_reverseLogicalChannelParameters.m_dataType);
                if (videoCap->GetTag() != H245_VideoCapability::e_extendedVideoCapability) {
                    isH239 = true;
                    isVideo = false;
                }
            }
            if (revParams.m_dataType.GetTag() == H245_DataType::e_h235Media) {
                const H245_H235Media & h235data = revParams.m_dataType;
                if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_audioData) {
                    isAudio = true;
                }
                if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_videoData) {
                    isVideo = true;
                    H245_VideoCapability * videoCap = &((H245_VideoCapability&)h235data.m_mediaType);
                    if (videoCap->GetTag() != H245_VideoCapability::e_extendedVideoCapability) {
                        isH239 = true;
                        isVideo = false;
                    }
                }
            }
            if (revParams.HasOptionalField(H245_OpenLogicalChannel_reverseLogicalChannelParameters::e_multiplexParameters)
                && revParams.m_multiplexParameters.GetTag() == H245_OpenLogicalChannel_reverseLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters) {

                H245_H2250LogicalChannelParameters & channel = revParams.m_multiplexParameters;
                if (channel.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)) {
                    H245_UnicastAddress *addr = GetH245UnicastAddress(channel.m_mediaChannel);
                    if (addr != NULL && m_call) {
                        PIPSocket::Address ip;
                        *addr >> ip;
                        WORD port = GetH245Port(*addr);
                        if (isAudio && m_callerSocket) {
                            m_call->SetCallerAudioIP(ip, port);
                        }
                        if (isVideo && m_callerSocket) {
                            m_call->SetCallerVideoIP(ip, port);
                        }
                        if (isH239 && m_callerSocket) {
                            m_call->SetCallerH239IP(ip, port, channel.m_sessionID);
                        }
                        if (isAudio && !m_callerSocket) {
                            m_call->SetCalledAudioIP(ip, port);
                        }
                        if (isVideo && !m_callerSocket) {
                            m_call->SetCalledVideoIP(ip, port);
                        }
                        if (isH239 && !m_callerSocket) {
                            m_call->SetCalledH239IP(ip, port, channel.m_sessionID);
                        }
                    }
                }
            }
        }

		H245_AudioCapability * audioCap = NULL;
		bool h235Audio = false;
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
				&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData) {
			audioCap = &((H245_AudioCapability&)olc.m_reverseLogicalChannelParameters.m_dataType);
		} else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData) {
			audioCap = &((H245_AudioCapability&)olc.m_forwardLogicalChannelParameters.m_dataType);
		} else if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
				&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_h235Media) {
			H245_H235Media & h235data = olc.m_reverseLogicalChannelParameters.m_dataType;
			if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_audioData) {
				audioCap = &((H245_AudioCapability&)h235data.m_mediaType);
				h235Audio = true;
			}
		} else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_h235Media) {
			H245_H235Media & h235data = olc.m_forwardLogicalChannelParameters.m_dataType;
			if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_audioData) {
				audioCap = &((H245_AudioCapability&)h235data.m_mediaType);
				h235Audio = true;
			}
		}
		if (audioCap != NULL && m_call) {
            if (m_callerSocket) {
                m_call->SetCallerAudioCodec(GetH245CodecName(*audioCap) + (h235Audio ? " (H.235)" : ""));
                m_call->SetCallerAudioBitrate(GetH245CodecBitrate(*audioCap));
            } else {
                m_call->SetCalledAudioCodec(GetH245CodecName(*audioCap) + (h235Audio ? " (H.235)" : ""));
                m_call->SetCalledAudioBitrate(GetH245CodecBitrate(*audioCap));
            }
        }

		H245_VideoCapability * videoCap = NULL;
		bool h235Video = false;
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
				&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_videoData) {
			videoCap = &((H245_VideoCapability&)olc.m_reverseLogicalChannelParameters.m_dataType);
		} else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_videoData) {
			videoCap = &((H245_VideoCapability&)olc.m_forwardLogicalChannelParameters.m_dataType);
		} else if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
				&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_h235Media) {
			H245_H235Media & h235data = olc.m_reverseLogicalChannelParameters.m_dataType;
			if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_videoData) {
				videoCap = &((H245_VideoCapability&)h235data.m_mediaType);
				h235Video = true;
			}
		} else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_h235Media) {
			H245_H235Media & h235data = olc.m_forwardLogicalChannelParameters.m_dataType;
			if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_videoData) {
				videoCap = &((H245_VideoCapability&)h235data.m_mediaType);
				h235Video = true;
			}
		}
		if (videoCap != NULL && m_call) {
            if (videoCap->GetTag() != H245_VideoCapability::e_extendedVideoCapability) {
                if (m_callerSocket) {
                    m_call->SetCallerVideoCodec(GetH245CodecName(*videoCap) + (h235Video ? " (H.235)" : ""));
                    m_call->SetCallerVideoBitrate(GetH245CodecBitrate(*videoCap));
                } else {
                    m_call->SetCalledVideoCodec(GetH245CodecName(*videoCap) + (h235Video ? " (H.235)" : ""));
                    m_call->SetCalledVideoBitrate(GetH245CodecBitrate(*videoCap));
                }
            } else {
                // H.239
                H245_ExtendedVideoCapability & extendedVideoCap = *videoCap;
                if (extendedVideoCap.m_videoCapability.GetSize() > 0) {
                    videoCap = &(extendedVideoCap.m_videoCapability[0]);
                    if (m_callerSocket) {
                        m_call->SetCallerH239Codec(GetH245CodecName(*videoCap) + (h235Video ? " (H.235)" : ""));
                        m_call->SetCallerH239Bitrate(GetH245CodecBitrate(*videoCap));
                    } else {
                        m_call->SetCalledH239Codec(GetH245CodecName(*videoCap) + (h235Video ? " (H.235)" : ""));
                        m_call->SetCalledH239Bitrate(GetH245CodecBitrate(*videoCap));
                    }
                }
            }
        }
	}

    if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_indication) {
#ifdef HAS_H46023
		H245_IndicationMessage & imsg  = h245msg;
		if (imsg.GetTag() == H245_IndicationMessage::e_genericIndication) {
			H245_GenericMessage & gmsg = imsg;
			H245_CapabilityIdentifier & id = gmsg.m_messageIdentifier;
			if (id.GetTag() == H245_CapabilityIdentifier::e_standard) {
#if defined (HAS_H46024A) || defined (HAS_H46024B)
				PASN_ObjectId & val = id;
#ifdef HAS_H46024A
				if (val.AsString() == H46024A_OID) {
					// TODO Signal to shutdown proxy support - SH
					suppress = false;  // Allow to travel to the other party
					return false;
				}
#endif
#ifdef HAS_H46024B
				if (val.AsString() == H46024B_OID) {
					// TODO shutdown the proxy channel if media going direct - SH
					suppress = true;
					return false;
				}
#endif
#endif
			}
		}
#endif
    }

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_request) {
#ifdef HAS_H46024B
		H245_RequestMessage & reqmsg  = h245msg;
		if (reqmsg.GetTag() == H245_RequestMessage::e_genericRequest) {
		    H245_GenericMessage & gmsg = reqmsg;
		    H245_CapabilityIdentifier & id = gmsg.m_messageIdentifier;
			if (id.GetTag() == H245_CapabilityIdentifier::e_standard) {
				PASN_ObjectId & val = id;
				if (val.AsString() == H46024B_OID &&
					gmsg.HasOptionalField(H245_GenericMessage::e_messageContent)) {
						if (!m_call->HandleH46024BRequest(gmsg.m_messageContent)) {
							PTRACE(2, "H245\tH46024B: Error Handling Request!");
						}
					suppress = true;
					return false;
				}
			}
		}
#endif
    }

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_response) {
		H245_ResponseMessage & rmsg  = h245msg;
#ifdef HAS_H46024B
		if (rmsg.GetTag() == H245_ResponseMessage::e_genericResponse) {
 			H245_GenericMessage & gmsg = rmsg;
			H245_CapabilityIdentifier & id = gmsg.m_messageIdentifier;
			if (id.GetTag() == H245_CapabilityIdentifier::e_standard) {
				PASN_ObjectId & val = id;
				if (val.AsString() == H46024B_OID) {
					m_call->H46024BRespond();
					suppress = true;
					return false;
				}
			}
		}
#endif

		if (rmsg.GetTag() == H245_ResponseMessage::e_masterSlaveDeterminationAck) {
			H245_MasterSlaveDeterminationAck msAck = rmsg;
			// the master tells the other endpoint to be slave
			m_isH245Master = (msAck.m_decision.GetTag() == H245_MasterSlaveDeterminationAck_decision::e_slave);
			H245ProxyHandler * h245ProxyHandler = dynamic_cast<H245ProxyHandler *>(m_h245handler);
			if (h245ProxyHandler)
				h245ProxyHandler->SetRoles(m_callerSocket, m_isH245Master);
		}

		if (rmsg.GetTag() == H245_ResponseMessage::e_openLogicalChannelAck) {
			H245_OpenLogicalChannelAck & olcack = rmsg;
            if (olcack.HasOptionalField(H245_OpenLogicalChannelAck::e_forwardMultiplexAckParameters)
                    && olcack.m_forwardMultiplexAckParameters.GetTag() == H245_OpenLogicalChannelAck_forwardMultiplexAckParameters::e_h2250LogicalChannelAckParameters) {
                H245_H2250LogicalChannelAckParameters & channel = olcack.m_forwardMultiplexAckParameters;
                bool isAudio = (channel.m_sessionID == 1);
                bool isVideo = (channel.m_sessionID == 2);
                bool isH239 = (channel.m_sessionID != 1 && channel.m_sessionID != 2);   // TODO: clould also be H.224
                if (channel.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaChannel)) {
                    H245_UnicastAddress *addr = GetH245UnicastAddress(channel.m_mediaChannel);
                    if (addr != NULL && m_call) {
                        PIPSocket::Address ip;
                        *addr >> ip;
                        WORD port = GetH245Port(*addr);
                        if (isAudio && m_callerSocket) {
                            m_call->SetCallerAudioIP(ip, port);
                        }
                        if (isVideo && m_callerSocket) {
                            m_call->SetCallerVideoIP(ip, port);
                        }
                        if (isH239 && m_callerSocket) {
                            m_call->SetCallerH239IP(ip, port, channel.m_sessionID);
                        }
                        if (isAudio && !m_callerSocket) {
                            m_call->SetCalledAudioIP(ip, port);
                        }
                        if (isVideo && !m_callerSocket) {
                            m_call->SetCalledVideoIP(ip, port);
                        }
                        if (isH239 && !m_callerSocket) {
                            m_call->SetCalledH239IP(ip, port, channel.m_sessionID);
                        }
                    }
                }
            }
		}
	}

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_request
		&& ((H245_RequestMessage&)h245msg).GetTag() == H245_RequestMessage::e_closeLogicalChannel) {
        H245_CloseLogicalChannel & clc = (H245_RequestMessage&)h245msg;

		if (m_call && m_call->GetRerouteState() == RerouteInitiated) {
            // Ack CLCs during closedown of initial call
			PTRACE(2, "H245\tReroute: Ack CLC from " << GetName() << " during Reroute");
            H245_MultimediaSystemControlMessage h245msg_clcAck;
            h245msg_clcAck.SetTag(H245_MultimediaSystemControlMessage::e_response);
            H245_ResponseMessage & h245resp_clcAck = h245msg_clcAck;
            h245resp_clcAck.SetTag(H245_ResponseMessage::e_closeLogicalChannelAck);
            H245_CloseLogicalChannelAck & clcAck = h245resp_clcAck;
            clcAck.m_forwardLogicalChannelNumber = clc.m_forwardLogicalChannelNumber;

			if (GetH245Socket()) {
                GetH245Socket()->Send(h245msg_clcAck);
			} else {
                SendTunneledH245(h245msg_clcAck);
			}
		}

    }

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_response
		&& ((H245_ResponseMessage&)h245msg).GetTag() == H245_ResponseMessage::e_terminalCapabilitySetAck) {
		H245_TerminalCapabilitySetAck & ack = (H245_ResponseMessage&)h245msg;

        // update seqNum
        if (GetRemote()) {
            if (ack.m_sequenceNumber != GetRemote()->m_tcsAckRecSeq) {
                ack.m_sequenceNumber = GetRemote()->m_tcsAckRecSeq;
                changed = true;
            }
        }
		if (m_call && m_call->GetRerouteState() == RerouteInitiated) {
            // filter out 2 Ack for TCS0
			PTRACE(2, "H245\tReroute: Filtering out TCSAck received from " << GetName());
			suppress = true;
		}

		if (m_call && m_call->GetRerouteState() == Rerouting) {
            // after we update the call, the forwarded socket is always the calling socket in the new call
			CallSignalSocket * forwarded = m_call->GetCallSignalSocketCalling();
			if (forwarded) {
				if (forwarded->CompareH245Socket(h245sock)) {
                    // nothing
				} else {
                    // filter out Ack for 1st TCS to new party
					PTRACE(2, "H245\tReroute: Filtering out TCSAck received from " << GetName());
					suppress = true;
					// update reroute state, don't filter any more
					m_call->SetRerouteState(NoReroute);
				}
			}
		}
	}

	if (h245msg.GetTag() == H245_MultimediaSystemControlMessage::e_request
		&& ((H245_RequestMessage&)h245msg).GetTag() == H245_RequestMessage::e_terminalCapabilitySet) {

		H245_TerminalCapabilitySet & tcs = (H245_RequestMessage &)h245msg;
        // update seqNum (needed after we did a TCS0 rerouting)
        m_tcsAckRecSeq = tcs.m_sequenceNumber;  // we'll expect the next TCSAck with this sequenceNum
        if (GetRemote()) {
            unsigned seq = GetRemote()->GetNextTCSSeq();
            if (tcs.m_sequenceNumber != seq) {
                tcs.m_sequenceNumber = seq;
                changed = true;
            }
        }
#ifdef HAS_H235_MEDIA
		if (Toolkit::Instance()->IsH235HalfCallMediaEnabled()) {
			changed = HandleH235TCS(tcs);
		}
#endif
        H245_ArrayOf_CapabilityTableEntry & CapabilityTables = tcs.m_capabilityTable;

		// codec filtering
		if (m_call && m_call->GetCallingParty()) {
            // add filtered codecs for the calling party
            m_call->AddDisabledCodecs(m_call->GetCallingParty()->GetDisabledCodecs());
		}
		if (m_call && m_call->GetCalledParty()) {
            // add filtered codecs for the calling party
            m_call->AddDisabledCodecs(m_call->GetCalledParty()->GetDisabledCodecs());
		}
        if (m_call && !(m_call->GetDisabledCodecs().IsEmpty())) {
            std::set<unsigned> removedCaps;

            // filter capability classes
            for (PINDEX i = 0; i < CapabilityTables.GetSize(); i++) {
                unsigned int cten = CapabilityTables[i].m_capabilityTableEntryNumber.GetValue();
                H245_Capability & H245Capability = CapabilityTables[i].m_capability;

                if (m_call && m_call->GetDisabledCodecs().Find(H245Capability.GetTagName() + ";", 0) != P_MAX_INDEX) {
                    PTRACE(4, "H245\tDelete capability " << H245Capability.GetTagName() << " (" << cten << ")");
                    changed = true;
                    removedCaps.insert(cten);
                    CapabilityTables.RemoveAt(i);
                    i--;
                }
            }

            // filter the audio capabilities
            for (PINDEX i = 0; i < CapabilityTables.GetSize(); i++) {
                // PTRACE(4, "CapabilityTable: " << setprecision(2) << CapabilityTables[i]);
                unsigned int cten = CapabilityTables[i].m_capabilityTableEntryNumber.GetValue();
                H245_Capability & H245Capability = CapabilityTables[i].m_capability;

                if (H245Capability.GetTag() == H245_Capability::e_receiveAudioCapability || H245Capability.GetTag() == H245_Capability::e_receiveAndTransmitAudioCapability) {
                    H245_AudioCapability & H245AudioCapability = H245Capability;
                    if (m_call && m_call->GetDisabledCodecs().Find(H245AudioCapability.GetTagName() + ";", 0) != P_MAX_INDEX) {
                        PTRACE(4, "H245\tDelete audio capability " << H245AudioCapability.GetTagName() << " (" << cten << ")");
                        changed = true;
                        removedCaps.insert(cten);
                        CapabilityTables.RemoveAt(i);
                        i--;
                    }
                }
            }

            // filter the video capabilities
            for (PINDEX i = 0; i < CapabilityTables.GetSize(); i++) {
                // PTRACE(4, "CapabilityTable: " << setprecision(2) << CapabilityTables[i]);
                unsigned int cten = CapabilityTables[i].m_capabilityTableEntryNumber.GetValue();
                H245_Capability & H245Capability = CapabilityTables[i].m_capability;

                if (H245Capability.GetTag() == H245_Capability::e_receiveVideoCapability || H245Capability.GetTag() == H245_Capability::e_receiveAndTransmitVideoCapability) {
                    H245_VideoCapability & H245VideoCapability = H245Capability;
                    if (m_call && m_call->GetDisabledCodecs().Find(H245VideoCapability.GetTagName() + ";", 0) != P_MAX_INDEX) {
                        PTRACE(4, "H245\tDelete video capability " << H245VideoCapability.GetTagName() << " (" << cten << ")");
                        changed = true;
                        removedCaps.insert(cten);
                        CapabilityTables.RemoveAt(i);
                        i--;
                    }
                }
            }

            // filter the user input capabilities
            for (PINDEX i = 0; i < CapabilityTables.GetSize(); i++) {
                unsigned int cten = CapabilityTables[i].m_capabilityTableEntryNumber.GetValue();
                H245_Capability & H245Capability = CapabilityTables[i].m_capability;

                if (H245Capability.GetTag() == H245_Capability::e_receiveUserInputCapability || H245Capability.GetTag() == H245_Capability::e_receiveAndTransmitUserInputCapability) {
                    H245_UserInputCapability & h245UserInput = H245Capability;
                    if (m_call && m_call->GetDisabledCodecs().Find(h245UserInput.GetTagName() + ";", 0) != P_MAX_INDEX) {
                        PTRACE(4, "H245\tDelete UserInput capability " << h245UserInput.GetTagName() << " (" << cten << ")");
                        changed = true;
                        removedCaps.insert(cten);
                        CapabilityTables.RemoveAt(i);
                        i--;
                    }
                }
            }

            // remove SecurityCapabilities associated with deleted capabilities
            for (PINDEX i = 0; i < CapabilityTables.GetSize(); i++) {
                unsigned int cten = CapabilityTables[i].m_capabilityTableEntryNumber.GetValue();
                H245_Capability & H245Capability = CapabilityTables[i].m_capability;

                if (H245Capability.GetTag() == H245_Capability::e_h235SecurityCapability) {
                    H245_H235SecurityCapability & h245Security = H245Capability;
                    if (removedCaps.count(h245Security.m_mediaCapability) > 0) {
                        PTRACE(4, "H245\tDelete Security capability for media cap " << h245Security.m_mediaCapability << " (" << cten << ")");
                        changed = true;
                        removedCaps.insert(cten);
                        CapabilityTables.RemoveAt(i);
                        i--;
                    }
                }
            }

            // delete the removed capabilities from AlternativeCapabilitySets
            H245_ArrayOf_CapabilityDescriptor & CapabilityDescriptor = tcs.m_capabilityDescriptors;
            for (PINDEX n = 0; n < CapabilityDescriptor.GetSize(); n++){
                H245_ArrayOf_AlternativeCapabilitySet & AlternativeCapabilitySet = CapabilityDescriptor[n].m_simultaneousCapabilities;
                for (PINDEX j = 0; j < AlternativeCapabilitySet.GetSize(); j++) {
                    for (PINDEX m = 0; m < AlternativeCapabilitySet[j].GetSize(); m++) {
                        if (removedCaps.count(AlternativeCapabilitySet[j][m].GetValue()) > 0) {
                            PTRACE(4, "H245\tRemove from AlternativeCapabilitySets: " << AlternativeCapabilitySet[j][m].GetValue());
                            AlternativeCapabilitySet[j].RemoveAt(m);
                            m--;
                        }
                    }
                    // remove set if now empty
                    if (AlternativeCapabilitySet[j].GetSize() == 0) {
                        PTRACE(4, "H245\tRemoving now empty AlternativeCapabilitySet " << j);
                        AlternativeCapabilitySet.RemoveAt(j);
                        j--;
                    }
                }
            }
		}

		if (changed && !suppress) {
			PTRACE(4, "H245\tNew Capability Table: " << setprecision(2) << tcs);
		}

		// save 1st TCS
		if (m_savedTCS.GetSize() == 0) {
            m_savedTCS = tcs;
        }
	}

	if ((!m_h245handler || !m_h245handler->HandleMesg(h245msg, suppress, m_call, h245sock)) && !changed)
		return false;

	strm.BeginEncoding();
	h245msg.Encode(strm);
	strm.CompleteEncoding();
	if (!suppress) {
        PTRACE(5, "H245\tTo send (CallID: " << GetCallIdentifierAsString() << "): " << setprecision(2) << h245msg);
    }

	return true;
}

#ifdef HAS_H235_MEDIA

bool SupportsH235Media(const H225_ArrayOf_ClearToken & clearTokens)
{
	bool h235v3compatible = false;
	bool supportedDHkey = false;

	for (PINDEX i = 0; i < clearTokens.GetSize(); ++i) {
		if (clearTokens[i].m_tokenOID == "0.0.8.235.0.3.24")
			h235v3compatible = true;
		if (clearTokens[i].m_tokenOID == "0.0.8.235.0.3.43")
			supportedDHkey = true;
#ifdef H323_H235_AES256
		if (clearTokens[i].m_tokenOID == "0.0.8.235.0.3.45")
			supportedDHkey = true;
		if (clearTokens[i].m_tokenOID == "0.0.8.235.0.3.47")
			supportedDHkey = true;
#endif
	}
	return (h235v3compatible && supportedDHkey);
}

// convert key bit count to bytes
unsigned AlgorithmKeySize(const PString & oid)
{
	if (oid == ID_AES128) {
		return 128 / 8;
#ifdef H323_H235_AES256
	} else if (oid == ID_AES192) {
		return 192 / 8;
	} else if (oid == ID_AES256) {
		return 256 / 8;
#endif
	}
	return 0;
}

bool RemoveH235Capability(unsigned entryNo,
                          H245_ArrayOf_CapabilityTableEntry & capTable,
                          H245_ArrayOf_CapabilityDescriptor & capDesc)
{
    PTRACE(5, "Removing H.235 capability no: " << entryNo);

    for (PINDEX i = 0; i < capTable.GetSize(); ++i) {
		if (capTable[i].m_capabilityTableEntryNumber.GetValue() == entryNo) {
			capTable.RemoveAt(i);
			i--;    // RemoveAt() moves content down 1 position
			break;
		}
	}
    for (PINDEX n = 0; n < capDesc.GetSize(); n++){
        for (PINDEX j = 0; j < capDesc[n].m_simultaneousCapabilities.GetSize(); j++) {
	        for (PINDEX m = 0; m < capDesc[n].m_simultaneousCapabilities[j].GetSize(); m++) {
		        if (capDesc[n].m_simultaneousCapabilities[j][m].GetValue() == entryNo) {
			        capDesc[n].m_simultaneousCapabilities[j].RemoveAt(m);
			        m--;    // RemoveAt() moves content down 1 position
		        }
	        }
        }
    }
   return true;
}

bool AddH235Capability(unsigned entryNo, const PStringList & capList,
						H245_ArrayOf_CapabilityTableEntry & capTable,
						H245_ArrayOf_CapabilityDescriptor & capDesc)
{
    if (capList.GetSize() == 0)
        return false;

    PTRACE(5, "Add H.235 Support for: " << entryNo);
    unsigned secCapNo = 100 + entryNo;	// TODO: calculate the largest actually used CapNo instead of using 100 ?

    int sz = capTable.GetSize();
    if (sz >= PASN_Object::GetMaximumArraySize()) {
        PTRACE(2, "H235\tError: Maximum ASN.1 array size reached (" << PASN_Object::GetMaximumArraySize() << ")");
        return false;
    }
    capTable.SetSize(sz + 1);
    H245_CapabilityTableEntry & entry = capTable[sz];
	entry.m_capabilityTableEntryNumber.SetValue(secCapNo);
	entry.IncludeOptionalField(H245_CapabilityTableEntry::e_capability);
	H245_Capability & cap = entry.m_capability;
	cap.SetTag(H245_Capability::e_h235SecurityCapability);
	H245_H235SecurityCapability & sec = cap;
	sec.m_mediaCapability.SetValue(entryNo);
	sec.m_encryptionAuthenticationAndIntegrity.IncludeOptionalField(H245_EncryptionAuthenticationAndIntegrity::e_encryptionCapability);
	H245_EncryptionCapability & enc = sec.m_encryptionAuthenticationAndIntegrity.m_encryptionCapability;
	enc.SetSize(capList.GetSize());
	for (PINDEX i = 0; i < capList.GetSize(); ++i) {
		H245_MediaEncryptionAlgorithm & alg = enc[i];
		alg.SetTag(H245_MediaEncryptionAlgorithm::e_algorithm);
		PASN_ObjectId & id = alg;
		id.SetValue(capList[i]);
	}

    for (PINDEX n = 0; n < capDesc.GetSize(); n++){
        for (PINDEX j = 0; j < capDesc[n].m_simultaneousCapabilities.GetSize(); j++) {
            H245_AlternativeCapabilitySet & alternate = capDesc[n].m_simultaneousCapabilities[j];
            int ns = alternate.GetSize();
	        for (PINDEX m = 0; m < ns; m++) {
		        if (alternate[m].GetValue() == entryNo) {
                   alternate.SetSize(ns + 1);
                   alternate[ns] = secCapNo;
                   break;
		        }
	        }
        }
    }
   return true;
}

bool CallSignalSocket::HandleH235TCS(H245_TerminalCapabilitySet & tcs)
{
	if (!m_call)
		return false;

    if (m_call && m_call->GetEncryptDirection() == CallRec::none)
        return false;

    bool toRemove = ((!m_callerSocket && m_call && (m_call->GetEncryptDirection() == CallRec::callingParty))
	                 || (m_callerSocket && m_call && (m_call->GetEncryptDirection() == CallRec::calledParty)));
    bool foundEntriesToRemove = false;

    PStringList capList;
    if (m_call && !m_call->GetAuthenticators().GetAlgorithms(capList)) {
        PTRACE(1, "H235\tEncryption support but no common algorithm! DISABLING!!");
        m_call->SetMediaEncryption(CallRec::none);
        m_call->GetAuthenticators().SetSize(0);
        return false;
    }

    H245_ArrayOf_CapabilityDescriptor & capDesc = tcs.m_capabilityDescriptors;
    H245_ArrayOf_CapabilityTableEntry & capTable = tcs.m_capabilityTable;

    H245_ArrayOf_CapabilityTableEntry * tmpCapStatPtr = (H245_ArrayOf_CapabilityTableEntry *)capTable.Clone();
    H245_ArrayOf_CapabilityTableEntry capStat = *tmpCapStatPtr;
    delete tmpCapStatPtr;
    tmpCapStatPtr = NULL;
    for (PINDEX i = 0; i < capStat.GetSize(); ++i) {
        if (capStat[i].HasOptionalField(H245_CapabilityTableEntry::e_capability)) {
            H245_CapabilityTableEntryNumber & entryNumber = capStat[i].m_capabilityTableEntryNumber;
            H245_Capability & cap = capStat[i].m_capability;
            if (toRemove) {
				if (cap.GetTag() == H245_Capability::e_h235SecurityCapability) {
					RemoveH235Capability(entryNumber.GetValue(), capTable, capDesc);
					foundEntriesToRemove = true;
                }
            } else {
                // we currently support Audio, Video and Data
                if ((cap.GetTag() >= H245_Capability::e_receiveVideoCapability)
                    && (cap.GetTag() <= H245_Capability::e_receiveAndTransmitDataApplicationCapability)) {
                        AddH235Capability(entryNumber.GetValue(), capList, capTable, capDesc);
                }
            }
        }
    }
    if (toRemove && !foundEntriesToRemove) {
        PTRACE(1, "H235\tNo H.235 entries in TCS, not adding encryption");
        m_call->SetMediaEncryption(CallRec::none);  // turn off encryption for this call
        return false;
    }
    return true;
}

// encryptionSync is handled in HandleOpenLogicalChannel
bool CallSignalSocket::HandleH235OLC(H245_OpenLogicalChannel & olc)
{
    if (!m_call)
        return false;

    if (m_call && m_call->GetEncryptDirection() == CallRec::none)
        return false;

    bool toRemove = ((!m_callerSocket && m_call && (m_call->GetEncryptDirection() == CallRec::callingParty))
                 || (m_callerSocket && m_call && (m_call->GetEncryptDirection() == CallRec::calledParty)));

    bool isReverse = false;
    H245_DataType * tmpCapPtr = NULL;
    H245_DataType rawCap;
    if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)) {
		tmpCapPtr = (H245_DataType*)olc.m_reverseLogicalChannelParameters.m_dataType.Clone();
        isReverse = true;
    } else {
		tmpCapPtr = (H245_DataType*)olc.m_forwardLogicalChannelParameters.m_dataType.Clone();
	}
	rawCap = *tmpCapPtr;
	delete tmpCapPtr;
	tmpCapPtr = NULL;

    if ((toRemove && (rawCap.GetTag() != H245_DataType::e_h235Media))
		|| (!toRemove && (rawCap.GetTag() == H245_DataType::e_h235Media))) {
			PTRACE(1, "H235\tOLC Logic Error! ABORTIING REWRITE!");
			return false;
    }

    H245_DataType newCap;
    if (toRemove) {
        H245_H235Media_mediaType & cType = ((H245_H235Media &)rawCap).m_mediaType;
		if (cType.GetTag() == H245_H235Media_mediaType::e_audioData) {
			newCap.SetTag(H245_DataType::e_audioData);
			(H245_AudioCapability &)newCap = (H245_AudioCapability &)cType;
		} else if (cType.GetTag() == H245_H235Media_mediaType::e_videoData) {
			newCap.SetTag(H245_DataType::e_videoData);
			(H245_VideoCapability &)newCap = (H245_VideoCapability &)cType;
		} else if (cType.GetTag() == H245_H235Media_mediaType::e_data) {
			newCap.SetTag(H245_DataType::e_data);
			(H245_DataApplicationCapability &)newCap = (H245_DataApplicationCapability &)cType;
		}
    } else {
        PStringList m_capList;
        if (m_call && !m_call->GetAuthenticators().GetAlgorithms(m_capList)) {
            PTRACE(1, "H235\tOLC No Algorithms! ABORTIING REWRITE!");
            return false;
        }

        newCap.SetTag(H245_DataType::e_h235Media);
        H245_H235Media & h235Media = newCap;

        H245_EncryptionAuthenticationAndIntegrity & encAuth = h235Media.m_encryptionAuthenticationAndIntegrity;
		encAuth.IncludeOptionalField(H245_EncryptionAuthenticationAndIntegrity::e_encryptionCapability);
		H245_EncryptionCapability & enc = encAuth.m_encryptionCapability;
		enc.SetSize(1);
		H245_MediaEncryptionAlgorithm & alg = enc[0];
		alg.SetTag(H245_MediaEncryptionAlgorithm::e_algorithm);
		PASN_ObjectId & id = alg;
		id.SetValue(m_capList[0]);

        H245_H235Media_mediaType & cType = h235Media.m_mediaType;
		if (rawCap.GetTag() == H245_DataType::e_audioData) {
			cType.SetTag(H245_H235Media_mediaType::e_audioData);
			(H245_AudioCapability &)cType = (H245_AudioCapability &)rawCap;
		} else if (rawCap.GetTag() == H245_DataType::e_videoData) {
			cType.SetTag(H245_H235Media_mediaType::e_videoData);
			(H245_VideoCapability &)cType = (H245_VideoCapability &)rawCap;
		} else if (rawCap.GetTag() == H245_DataType::e_data) {
			cType.SetTag(H245_H235Media_mediaType::e_data);
			(H245_DataApplicationCapability &)cType = (H245_DataApplicationCapability &)rawCap;
		}
		// don't touch the dynamicRTPPayloadType here, all cases are handled in HandleOpenLogicalChannel()
	}

	if (isReverse) {
		olc.m_reverseLogicalChannelParameters.m_dataType = newCap;
	} else
		olc.m_forwardLogicalChannelParameters.m_dataType = newCap;

	return true;
}

void CallSignalSocket::SendEncryptionUpdateCommand(WORD flcn, BYTE oldPT, BYTE plainPT)
{
	H245ProxyHandler * h245handler = dynamic_cast<H245ProxyHandler *>(m_h245handler);
	if (h245handler) {
		RTPLogicalChannel * rtplc = dynamic_cast<RTPLogicalChannel *>(h245handler->FindLogicalChannel(flcn));
		if (!rtplc && h245handler->GetPeer()) {
			rtplc = dynamic_cast<RTPLogicalChannel *>(h245handler->GetPeer()->FindLogicalChannel(flcn));
		}
		if (rtplc) {
			BYTE newPayloadType = RandomPT(oldPT, plainPT);
			H245_MultimediaSystemControlMessage h245msg;
			h245msg.SetTag(H245_MultimediaSystemControlMessage::e_command);
			H245_CommandMessage & h245cmd = h245msg;
			h245cmd.SetTag(H245_CommandMessage::e_miscellaneousCommand);
			H245_MiscellaneousCommand & misc = h245cmd;
			misc.m_type.SetTag(H245_MiscellaneousCommand_type::e_encryptionUpdateCommand);
			H245_MiscellaneousCommand_type_encryptionUpdateCommand & update = misc.m_type;
			misc.m_logicalChannelNumber = flcn;
			misc.IncludeOptionalField(H245_MiscellaneousCommand::e_direction);
			misc.m_direction.SetTag(H245_EncryptionUpdateDirection::e_masterToSlave);
			rtplc->GenerateNewMediaKey(newPayloadType, update.m_encryptionSync);
			if (m_h245Tunneling)
				SendTunneledH245(h245msg);
			else {
				PTRACE(4, "H245\tTo send (CallID: " << GetCallIdentifierAsString() << "): " << h245msg);
				if (m_h245socket)
					m_h245socket->Send(h245msg);
			}
		} else {
			PTRACE(1, "H235\tError: Couldn't find flcn " << flcn << " to send EncryptionUpdateCommand");
		}
	}
}

void CallSignalSocket::SendEncryptionUpdateRequest(WORD flcn, BYTE oldPT, BYTE plainPT)
{
	BYTE newPayloadType = RandomPT(oldPT, plainPT);
	H245_MultimediaSystemControlMessage h245msg;
	h245msg.SetTag(H245_MultimediaSystemControlMessage::e_command);
	H245_CommandMessage & h245cmd = h245msg;
	h245cmd.SetTag(H245_CommandMessage::e_miscellaneousCommand);
	H245_MiscellaneousCommand & misc = h245cmd;
	misc.m_type.SetTag(H245_MiscellaneousCommand_type::e_encryptionUpdateRequest);
	H245_EncryptionUpdateRequest & update = misc.m_type;
	update.IncludeOptionalField(H245_EncryptionUpdateRequest::e_synchFlag);
	update.m_synchFlag = newPayloadType;
	update.IncludeOptionalField(H245_EncryptionUpdateRequest::e_keyProtectionMethod);
	update.m_keyProtectionMethod.m_secureChannel = true;
	update.m_keyProtectionMethod.m_sharedSecret = false;
	update.m_keyProtectionMethod.m_certProtectedKey = false;
	misc.m_logicalChannelNumber = flcn;
	misc.IncludeOptionalField(H245_MiscellaneousCommand::e_direction);
	misc.m_direction.SetTag(H245_EncryptionUpdateDirection::e_slaveToMaster);
	if (m_h245Tunneling) {
		SendTunneledH245(h245msg);
	} else {
		PTRACE(4, "H245\tTo send (CallID: " << GetCallIdentifierAsString() << "): " << h245msg);
		if (m_h245socket)
			m_h245socket->Send(h245msg);
	}
}
#endif

bool CallSignalSocket::EndSession()
{
    if (m_call && m_call->GetRerouteState() != NoReroute
        && ((m_call->GetRerouteDirection() == Caller && m_callerSocket) || (m_call->GetRerouteDirection() == Called || !m_callerSocket))) {
        PTRACE(0, "JW EndSession: call in reroute: dir=" << m_call->GetRerouteDirection() << " callersocket=" << m_callerSocket);
        PTRACE(1, "Q931\tDon't send ReleaseComplete on EndSession to remaining party in reroute");
        // don't hang up when dropped party sends H.245 EndSession
        return true;
    }

    PTRACE(0, "JW EndSession -> SendReleaseComplete()");
	SendReleaseComplete();
	return TCPProxySocket::EndSession();
}

void CallSignalSocket::RemoveH245Handler()
{
	m_h245handlerLock.Wait();
	H245Handler * h = m_h245handler;
	m_h245handler = NULL;
	delete h;
	m_h245handlerLock.Signal();
}

void CallSignalSocket::OnError()
{
    PTRACE(0, "JW CallSignalSocket::OnError()");
	if (m_call) {
		m_call->SetDisconnectCause(Q931::ProtocolErrorUnspecified);
		RemoveCall();
	}
	EndSession();
	m_remoteLock.Wait();
	if (remote)
		remote->EndSession();
#ifdef HAS_H46017
	rc_remote = NULL;
#endif
	m_remoteLock.Signal();
}

void CallSignalSocket::ForwardCall(FacilityMsg * msg)
{
	ReadLock configLock(ConfigReloadMutex);
	MarkSocketBlocked lock(this);

	H225_TransportAddress oldDestSignalAddr = m_call->GetDestSignalAddr();
	H225_Facility_UUIE & facilityBody = msg->GetUUIEBody();

	Routing::FacilityRequest request(facilityBody, msg);
	H225_ArrayOf_AliasAddress *aliases = request.GetAliases();
	if (aliases)
		Toolkit::Instance()->RewriteE164(*aliases);

	request.Process();
	Route route;
	if (!request.GetFirstRoute(route)) {
		ForwardData();
		delete msg;
		msg = NULL;
		return;
	}

	endptr forwarded = route.m_destEndpoint;

	PString forwarder;
	if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_featureSet)
			&& facilityBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)) {
		// get the forwarder
		H225_ArrayOf_FeatureDescriptor & fd = facilityBody.m_featureSet.m_neededFeatures;
		if (fd.GetSize() > 0 && fd[0].HasOptionalField(H225_FeatureDescriptor::e_parameters))
			if (fd[0].m_parameters.GetSize() > 0) {
				H225_EnumeratedParameter & parm = fd[0].m_parameters[0];
				if (parm.HasOptionalField(H225_EnumeratedParameter::e_content))
					if (parm.m_content.GetTag() == H225_Content::e_alias)
						forwarder = AsString((const H225_AliasAddress &)parm.m_content, false) + ":forward";
			}
	}
	PString altDestInfo(aliases ? AsString(*aliases) : AsDotString(route.m_destAddr));
	CallSignalSocket *fsocket = (facilityBody.m_reason.GetTag() == H225_FacilityReason::e_callForwarded) ? this : NULL;
	m_call->SetForward(fsocket, route.m_destAddr, forwarded, forwarder, altDestInfo);
	if (route.m_flags & Route::e_toParent)
		m_call->SetToParent(true);
	m_call->SetBindHint(request.GetSourceIP());
	m_call->SetCallerID(request.GetCallerID());
	m_call->SetCallerDisplayIE(request.GetCallerDisplayIE());
	m_call->SetCalledDisplayIE(request.GetCalledDisplayIE());
	if (route.m_useTLS)
		m_call->SetConnectWithTLS(true);

	PTRACE(3, Type() << "\tCall " << m_call->GetCallNumber() << " is forwarded to "
		<< altDestInfo << (!forwarder ? (" by " + forwarder) : PString::Empty()));

	// disconnect from forwarder
	SendReleaseComplete(H225_ReleaseCompleteReason::e_facilityCallDeflection);
	if (!m_maintainConnection)
		Close();

	CallSignalSocket *remoteSocket = static_cast<CallSignalSocket *>(remote);
	if (!remoteSocket) {
		PTRACE(1, Type() << "\tWarning: " << GetName() << " has no remote party?");
		SNMP_TRAP(10, SNMPWarning, Network, "No remote party for " + GetName());
		delete msg;
		msg = NULL;
		return;
	}
	MarkSocketBlocked rlock(remoteSocket);
	if (!remoteSocket->m_setupPdu) {
		PTRACE(1, Type() << "\tError: " << GetName() << " has no Setup message stored!");
		SNMP_TRAP(10, SNMPError, Network, "No Setup message stored for " + GetName());
		delete msg;
		msg = NULL;
		return;
	}

	Q931 fakeSetup(*remoteSocket->m_setupPdu);
	H225_H323_UserInformation suuie;
	if (!GetUUIE(fakeSetup, suuie)
			|| suuie.m_h323_uu_pdu.m_h323_message_body.GetTag() !=  H225_H323_UU_PDU_h323_message_body::e_setup) {
		PTRACE(1, Type() << "\tError: " << GetName() << " has no Setup UUIE found!");
		SNMP_TRAP(10, SNMPError, Network, "No Setup UUIE from " + GetName());
		delete msg;
		msg = NULL;
		return;
	}

	H225_Setup_UUIE & setupUUIE = suuie.m_h323_uu_pdu.m_h323_message_body;
	if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_cryptoTokens)) {
		setupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_cryptoTokens);
		setupUUIE.m_cryptoTokens = facilityBody.m_cryptoTokens;
	}

#ifdef HAS_H235_MEDIA
	if (remoteSocket->m_setupClearTokens) {
		setupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_tokens);
		setupUUIE.m_tokens = *remoteSocket->m_setupClearTokens;
	}
#endif

	// delete destCallSignalAddr from saved Setup
	setupUUIE.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);

	if (aliases) {
		// set called-party to first E.164
		for (PINDEX n = 0; n < aliases->GetSize(); ++n)
			if (aliases[n].GetTag() == H225_AliasAddress::e_dialedDigits) {
				fakeSetup.SetCalledPartyNumber(AsString(aliases[n], FALSE));
				break;
			}
		setupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
		setupUUIE.m_destinationAddress = *aliases;
		// TODO: set dest IP to GK IP ?
	} else {
		// for calls that were dialed by IP, set the old destIP
		setupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		setupUUIE.m_destCallSignalAddress = oldDestSignalAddr;
	}

	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "ShowForwarderNumber", "0"))) {
		if (endptr fwd = m_call->GetForwarder()) {
			const H225_ArrayOf_AliasAddress & a = fwd->GetAliases();
			for (PINDEX n = 0; n < a.GetSize(); ++n)
				if (a[n].GetTag() == H225_AliasAddress::e_dialedDigits) {
					PString callingNumber(AsString(a[n], false));
					fakeSetup.SetCallingPartyNumber(callingNumber);
					setupUUIE.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
					setupUUIE.m_sourceAddress.SetSize(1);
					H323SetAliasAddress(callingNumber, setupUUIE.m_sourceAddress[0]);
					break;
				}
		}
	}

	// detach from the call
	m_call->SetSocket(NULL, NULL);
	remote = remoteSocket->remote = NULL;
	remoteSocket->LockH245Handler();
	delete remoteSocket->m_h245handler;
	remoteSocket->m_h245handler = NULL;
	remoteSocket->UnlockH245Handler();

	if (remoteSocket->CreateRemote(setupUUIE)) {
		SetUUIE(fakeSetup, suuie);
		fakeSetup.Encode(remoteSocket->buffer);
		PrintQ931(5, "Forward Setup to ", remoteSocket->remote->GetName(), &fakeSetup, &suuie);
		if (remoteSocket->m_result == Forwarding || remoteSocket->ForwardCallConnectTo()) {
			CallSignalSocket *result = static_cast<CallSignalSocket *>(remoteSocket->remote);
			if (m_h245socket) {
				m_h245socket->SetSigSocket(result);
				result->m_h245socket = m_h245socket;
				m_h245socket = NULL;
			}
			if (remoteSocket->m_result == Forwarding)
				remoteSocket->ForwardData();
			else
				GetHandler()->Insert(result);
		}
	} else {
		remoteSocket->EndSession();
		remoteSocket->SetConnected(false);
		if (m_call)
			m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
		CallTable::Instance()->RemoveCall(m_call);
	}

	// let the socket be deletable
	if (m_maintainConnection) {
#ifdef HAS_H46017
		CleanupCall();
#endif
	} else {
		SetDeletable();
	}
	delete msg;
	msg = NULL;
}

void CallSignalSocket::RerouteCall(FacilityMsg * msg)
{
	H225_Facility_UUIE & facilityBody = msg->GetUUIEBody();

    PString callID = AsString(m_call->GetCallIdentifier(), true);
    PString which = m_callerSocket ? "CALLED" : "CALLER";
    PString destination;
    if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress) &&
        facilityBody.m_alternativeAliasAddress.GetSize() > 0)
        destination = H323GetAliasAddressString(facilityBody.m_alternativeAliasAddress[0]);

    if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_alternativeAddress)) {
        if (!destination.IsEmpty())
            destination += '@';
        destination += H323TransportAddress(facilityBody.m_alternativeAddress);
    }

    PTRACE(0, "JW RerouteCall " << callID << " side=" << which << " dest=" << destination);
    SoftPBX::RerouteCall(callID, which, destination);
}

PString CallSignalSocket::GetCallingStationId(
	/// Q.931/H.225 Setup message with additional data
	const SetupMsg & setup,
	/// additional data
	SetupAuthData & authData
	) const
{
	if (!authData.m_callingStationId)
		return authData.m_callingStationId;

	const bool hasCall = authData.m_call.operator->() != NULL;
	PString id;

	setup.GetQ931().GetCallingPartyNumber(id);

	if (id.IsEmpty() && hasCall)
		id = authData.m_call->GetCallingStationId();

	if (!id)
		return id;

	H225_Setup_UUIE & setupBody = setup.GetUUIEBody();

	if (id.IsEmpty() && setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress))
		id = GetBestAliasAddressString(setupBody.m_sourceAddress, false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

	if (hasCall) {
		if (id.IsEmpty())
			id = GetBestAliasAddressString(
				authData.m_call->GetSourceAddress(), false,
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);

		if (id.IsEmpty()) {
			const endptr callingEP = authData.m_call->GetCallingParty();
			if (callingEP)
				id = GetBestAliasAddressString(callingEP->GetAliases(), false,
					AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
						| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
					);
		}
	}

	return id;
}

PString CallSignalSocket::GetCalledStationId(
	/// Q.931/H.225 Setup message with additional data
	const SetupMsg & setup,
	/// additional data
	SetupAuthData & authData
	) const
{
	if (!authData.m_calledStationId)
		return authData.m_calledStationId;

	const bool hasCall = authData.m_call.operator->() != NULL;
	PString id;

	setup.GetQ931().GetCalledPartyNumber(id);

	if (id.IsEmpty() && hasCall)
		id = authData.m_call->GetCalledStationId();

	if (!id)
		return id;

	H225_Setup_UUIE &setupBody = setup.GetUUIEBody();

	if (id.IsEmpty() && setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
		id = GetBestAliasAddressString(setupBody.m_destinationAddress, false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

	if (id.IsEmpty() && hasCall)
		id = GetBestAliasAddressString(
			authData.m_call->GetDestinationAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

	if (id.IsEmpty()) {
		PIPSocket::Address daddr;
		WORD dport = 0;
		if (hasCall && authData.m_call->GetDestSignalAddr(daddr, dport))
			id = AsString(daddr, dport);
		// this does not work well in routed mode, when destCallSignalAddress
		// is usually the gatekeeper address
		else if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)
				&& GetIPAndPortFromTransportAddr(setupBody.m_destCallSignalAddress, daddr, dport)
				&& daddr.IsValid())
			id = AsString(daddr, dport);
	}

	return id;
}

PString CallSignalSocket::GetDialedNumber(const SetupMsg & setup) const
{
	PString dialedNumber;

	setup.GetQ931().GetCalledPartyNumber(dialedNumber);

	if (!dialedNumber.IsEmpty())
		return dialedNumber;

	H225_Setup_UUIE & setupBody = setup.GetUUIEBody();

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
		dialedNumber = GetBestAliasAddressString(
			setupBody.m_destinationAddress, false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);

	if (dialedNumber.IsEmpty() && m_call)
		dialedNumber = m_call->GetDialedNumber();

	if (dialedNumber.IsEmpty() && m_call)
		dialedNumber = GetBestAliasAddressString(
			m_call->GetDestinationAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
			);
	if (dialedNumber.IsEmpty()
        && setupBody.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)
        && GkConfig()->GetBoolean("CallTable", "UseDestCallSignalIPAsDialedNumber", false)) {
        dialedNumber = AsDotString(setupBody.m_destCallSignalAddress);
	}

	return dialedNumber;
}

#ifdef HAS_H46023
bool CallSignalSocket::IsH46024Call(const H225_Setup_UUIE & setupBody)
{
	if (Toolkit::Instance()->IsH46023Enabled()
		&& setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
		const H225_ArrayOf_FeatureDescriptor & data = setupBody.m_supportedFeatures;
		for (PINDEX i = 0; i < data.GetSize(); i++) {
			H460_Feature & feat = (H460_Feature &)data[i];
			if (feat.GetFeatureID() == H460_FeatureID(24))
				return true;
        }
    }
    return false;
}
#endif

void CallSignalSocket::OnSetup(SignalingMsg * msg)
{
	SetupMsg* setup = dynamic_cast<SetupMsg*>(msg);
	if (setup == NULL) {
		PTRACE(2, Type() << "\tError: Setup message from " << GetName() << " without associated UUIE");
		SNMP_TRAP(9, SNMPError, Network, "Setup from " + GetName() + " has no UUIE");
		m_result = Error;
		return;
	}
	m_callerSocket = true;	// update for persistent H.460.17 sockets where this property can change

	Q931 & q931 = msg->GetQ931();
	H225_Setup_UUIE & setupBody = setup->GetUUIEBody();

	m_h225Version = GetH225Version(setupBody);
	m_callerSocket = true;
#ifdef HAS_H46017
	rc_remote = NULL;
#endif

	if (Toolkit::Instance()->IsMaintenanceMode()) {
        PTRACE(1, "Rejecting new call in maintenance mode");
		m_result = Error;
		return;
	}

	// prevent from multiple calls over the same signaling channel
	if (remote
#ifdef HAS_H46018
		&& !(m_call && m_call->IsH46018ReverseSetup())
#endif
		) {
		const WORD newcrv = (WORD)setup->GetCallReference();
		if (m_crv && newcrv == (m_crv & 0x7fffu))
			PTRACE(2, Type() << "\tWarning: duplicate Setup received from " << Name());
		else {
			PTRACE(2, Type() << "\tWarning: multiple calls over single "
				"signaling channel not supported - new connection needed "
				"(from " << Name() << ')'
				);

			/// we should perform accounting here for this new call
			// TODO: refector to use SendReleaseComplete() ?
			H225_H323_UserInformation userInfo;
			H225_H323_UU_PDU_h323_message_body & msgBody = userInfo.m_h323_uu_pdu.m_h323_message_body;
			msgBody.SetTag(H225_H323_UU_PDU_h323_message_body::e_releaseComplete);

			H225_ReleaseComplete_UUIE & uuie = msgBody;
			uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
			uuie.IncludeOptionalField(H225_ReleaseComplete_UUIE::e_reason);
			uuie.m_reason.SetTag(H225_ReleaseCompleteReason::e_newConnectionNeeded);
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_callIdentifier))
				uuie.m_callIdentifier = setupBody.m_callIdentifier;

			Q931 releasePDU;
			releasePDU.BuildReleaseComplete(newcrv, TRUE);
			SetUUIE(releasePDU, userInfo);
			PrintQ931(5, "Send to ", remote->GetName(), &releasePDU, &userInfo);

			PBYTEArray buf;
			if (releasePDU.Encode(buf))
				TransmitData(buf);
			else {
				PTRACE(1, Type() << "\tFailed to encode ReleaseComplete message " << releasePDU);
				SNMP_TRAP(7, SNMPError, Network, "Encoding failed");
			}
		}
		m_result = NoData;
		return;
	}

	RasServer *rassrv = RasServer::Instance();
	Toolkit *toolkit = Toolkit::Instance();
	time_t setupTime = time(0); // record the timestamp here since processing may take much time

	Address _peerAddr, _localAddr;
	WORD _peerPort = 0, _localPort = 0;
	msg->GetPeerAddr(_peerAddr, _peerPort);
	msg->GetLocalAddr(_localAddr, _localPort);

	// incompatible with 'explicit' routing
	if (GkConfig()->GetBoolean(RoutedSec, "RedirectCallsToGkIP", false)) {
        bool redirect = false;
        WORD signalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_CALL_SIGNAL_PORT);
        H225_TransportAddress mainIP = SocketToH225TransportAddr(Toolkit::Instance()->GetRouteTable()->GetLocalAddress(_peerAddr), signalPort);
        // check if our main or external IP is being called
        if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
            redirect = true;
            if (setupBody.m_destCallSignalAddress == mainIP) {
                redirect = false;
            }
            // also allow direct calls to all other Home IPs
            PIPSocket::Address destIP;
            GetIPFromTransportAddr(setupBody.m_destCallSignalAddress, destIP);
            std::vector<PIPSocket::Address> homeIPs;
            Toolkit::Instance()->GetGKHome(homeIPs);
            for (unsigned i = 0; i < homeIPs.size(); ++i) {
                if (destIP == homeIPs[i]) {
                    redirect = false;
                }
            }
        } else {
            PTRACE(1, "Setup doesn't have destCallSignalAddress, can't decide redirect");
        }
        if (redirect) {
            // build and send Facility Redirect
            Q931 FacilityPDU;
            FacilityPDU.BuildFacility(setup->GetCallReference(), true);
            H225_H323_UserInformation uuie;
            GetUUIE(FacilityPDU, uuie);
            uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
            uuie.m_h323_uu_pdu.m_h245Tunneling.SetValue(m_h245Tunneling);
            H225_H323_UU_PDU_h323_message_body & body = uuie.m_h323_uu_pdu.m_h323_message_body;
            body.SetTag(H225_H323_UU_PDU_h323_message_body::e_facility);
            H225_Facility_UUIE & facility_uuie = body;
            facility_uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
            facility_uuie.m_reason.SetTag(H225_FacilityReason::e_callForwarded);
            if (setupBody.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
                facility_uuie.IncludeOptionalField(H225_Facility_UUIE::e_callIdentifier);
                facility_uuie.m_callIdentifier = setupBody.m_callIdentifier;
            }
            facility_uuie.IncludeOptionalField(H225_Facility_UUIE::e_conferenceID);
            facility_uuie.m_conferenceID = setupBody.m_conferenceID;

            facility_uuie.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAddress);
            WORD signalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "CallSignalPort", GK_DEF_CALL_SIGNAL_PORT);
            H225_TransportAddress newIP = SocketToH225TransportAddr(Toolkit::Instance()->GetRouteTable()->GetLocalAddress(_peerAddr), signalPort);
            facility_uuie.m_alternativeAddress = newIP;
            if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) && setupBody.m_destinationAddress.GetSize() > 0) {
                facility_uuie.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress);
                facility_uuie.m_alternativeAliasAddress.SetSize(setupBody.m_destinationAddress.GetSize());
                // remove @ip or ip## from aliases before looping them back
                for (PINDEX i = 0; i < setupBody.m_destinationAddress.GetSize(); ++i) {
                    PString alias = AsString(setupBody.m_destinationAddress[i], false);
                    PINDEX at = alias.Find('@');
                    if (at != P_MAX_INDEX) {
                        alias = alias.Left(at) + "@" + AsDotString(newIP, false);
                    }
                    PINDEX hashhash = alias.Find("##");
                    if (hashhash != P_MAX_INDEX) {
                        alias = AsDotString(newIP, false) + "##" + alias.Mid(hashhash + 1);
                    }
                    H323SetAliasAddress(alias, facility_uuie.m_alternativeAliasAddress[i]);
                }
            }
            SetUUIE(FacilityPDU, uuie);

            PTRACE(1, "Redirecting call to " << AsString(facility_uuie.m_alternativeAddress));
            PrintQ931(5, "Send to ", GetName(), &FacilityPDU, &uuie);

            // send Facility
            PBYTEArray buf;
            FacilityPDU.Encode(buf);
            TransmitData(buf);

            // don't process the Setup further
            m_result = NoData;
            return;
 		}
	}

	if (GkConfig()->GetBoolean(RoutedSec, "GenerateCallProceeding", false)
		&& !GkConfig()->GetBoolean(RoutedSec, "UseProvisionalRespToH245Tunneling", false)
		&& !m_h245TunnelingTranslation) {
		// disable H.245 tunneling when the gatekeeper generates the CP
		H225_H323_UserInformation * uuie = msg->GetUUIE();
		if ((uuie != NULL) && uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling)) {
			msg->GetUUIE()->m_h323_uu_pdu.m_h245Tunneling.SetValue(false);
		}
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_parallelH245Control)) {
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_parallelH245Control);
		}
		m_h245Tunneling = false;
	}

	// save callers vendor info
	PString callingVendor, callingVersion;
	if (setupBody.m_sourceInfo.HasOptionalField(H225_EndpointType::e_vendor)) {
		if (setupBody.m_sourceInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_productId)) {
			callingVendor = setupBody.m_sourceInfo.m_vendor.m_productId.AsString();
		}
		if (setupBody.m_sourceInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_versionId)) {
			callingVersion = setupBody.m_sourceInfo.m_vendor.m_versionId.AsString();
		}
		if (m_call) {
			m_call->SetCallingVendor(callingVendor, callingVersion);
		}
	}

	if (GkConfig()->GetBoolean(RoutedSec, "TranslateSorensonSourceInfo", false)) {
		// Viable VPAD (Viable firmware, SBN Tech device), remove the CallingPartyNumber information
		// (its under the sorenson switch, even though not sorenson, can be moved later to own switch - SH)
		if (setupBody.m_sourceInfo.HasOptionalField(H225_EndpointType::e_vendor)
			&& setupBody.m_sourceInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_productId)
            && setupBody.m_sourceInfo.m_vendor.m_productId.AsString().Left(11) == "viable vpad") {
                if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
                    unsigned plan = Q931::ISDNPlan, type = Q931::InternationalType;
                    unsigned presentation = (unsigned)-1, screening = (unsigned)-1;
                    PString callingNumber = GetBestAliasAddressString(setupBody.m_sourceAddress, false,
                        AliasAddressTagMask(H225_AliasAddress::e_dialedDigits) | AliasAddressTagMask(H225_AliasAddress::e_partyNumber));
                    q931.SetCallingPartyNumber(callingNumber, plan, type, presentation, screening);
                }
		}

		if (q931.HasIE(Q931::CalledPartyNumberIE)) {
			PString dialedNumber;
			q931.GetCalledPartyNumber(dialedNumber);
			if (!IsValidE164(dialedNumber)) {
				PTRACE(4, "WARNING: Removed Called Party Number IE as it's not a valid E.164!");
				q931.RemoveIE(Q931::CalledPartyNumberIE);
			}
		}

		// Sorenson nTouch fix to provide a CalledPartyNumber as well if destinationAddress dialedDigits are provided
		if (!q931.HasIE(Q931::CalledPartyNumberIE)) {
			PString calledNumber;
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
				calledNumber = GetBestAliasAddressString(setupBody.m_destinationAddress, false,
					AliasAddressTagMask(H225_AliasAddress::e_dialedDigits) | AliasAddressTagMask(H225_AliasAddress::e_partyNumber));
				PTRACE(1, "Setting the Q.931 CalledPartyNumber to: " << calledNumber);
				if (IsValidE164(calledNumber)) {
					unsigned plan = Q931::ISDNPlan, type = Q931::InternationalType;
					q931.SetCalledPartyNumber(calledNumber, plan, type);
				}
			}
		}

		if (setupBody.m_sourceInfo.HasOptionalField(H225_EndpointType::e_terminal)
			&&  setupBody.m_sourceInfo.m_terminal.HasOptionalField(H225_TerminalInfo::e_nonStandardData)
            &&  setupBody.m_sourceInfo.HasOptionalField(H225_EndpointType::e_vendor)
            &&  setupBody.m_sourceInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_productId)
            &&  setupBody.m_sourceInfo.m_vendor.m_productId.AsString().Left(7) != "VidSoft") {	// VidSoft includes invalid numbers
			if (setupBody.m_sourceInfo.m_terminal.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
				H225_H221NonStandard h221nst = setupBody.m_sourceInfo.m_terminal.m_nonStandardData.m_nonStandardIdentifier;
				if (h221nst.m_manufacturerCode == 21334) {
					PString sinfo = setupBody.m_sourceInfo.m_terminal.m_nonStandardData.m_data.AsString();
					sinfo.Replace("SInfo:", "SInfo|");
					if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
						setupBody.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
						setupBody.m_sourceAddress.SetSize(0);
					}
					PStringArray tokens = sinfo.Tokenise("|", FALSE);
					for (PINDEX i = 0; i < tokens.GetSize(); ++i) {
						int sourceAdrSize = setupBody.m_sourceAddress.GetSize();
						if (tokens[i].Left(4) == "0007") {
							PString e164 = tokens[i].Mid(4);
							if (IsValidE164(e164)) {
								setupBody.m_sourceAddress.SetSize(sourceAdrSize + 1);
								H323SetAliasAddress(e164, setupBody.m_sourceAddress[sourceAdrSize], H225_AliasAddress::e_dialedDigits);
								sourceAdrSize++;
								setupBody.m_sourceAddress.SetSize(sourceAdrSize + 1);
								H323SetAliasAddress(e164, setupBody.m_sourceAddress[sourceAdrSize], H225_AliasAddress::e_h323_ID);
								// fill calling number IE
								if (!q931.HasIE(Q931::CallingPartyNumberIE)) {
									unsigned plan = Q931::ISDNPlan, type = Q931::InternationalType;
									unsigned presentation = (unsigned)-1, screening = (unsigned)-1;
									q931.SetCallingPartyNumber(e164, plan, type, presentation, screening);
								}
							} else {
								PTRACE(1, "Invalid character in Sorenson source info: " << e164);
							}
						} else if ((tokens[i].Left(4) == "0008") || (tokens[i].Left(4) == "2012")) {
						    // Sorensen uses 0008, P3PC uses 2012
							PString ip = tokens[i].Mid(4);
							// check format of IP to avoid runtime error
							if (ip.FindRegEx(PRegularExpression("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$", PRegularExpression::Extended)) != P_MAX_INDEX) {
                                m_call->SetSInfoIP(ip);
                                setupBody.m_sourceAddress.SetSize(sourceAdrSize + 1);
								H323SetAliasAddress(ip, setupBody.m_sourceAddress[sourceAdrSize], H225_AliasAddress::e_transportID);
							} else {
								PTRACE(1, "Invalid IP in Sorenson source info: " << ip);
							}
						}
					}
				}
			}
		}
	}

	// RemoveSorensonSourceInfo
	if (setupBody.m_sourceInfo.HasOptionalField(H225_EndpointType::e_terminal)
		&&  setupBody.m_sourceInfo.m_terminal.HasOptionalField(H225_TerminalInfo::e_nonStandardData)
		&&  setupBody.m_sourceInfo.HasOptionalField(H225_EndpointType::e_vendor)) {
		if (setupBody.m_sourceInfo.m_terminal.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
			H225_H221NonStandard h221nst = setupBody.m_sourceInfo.m_terminal.m_nonStandardData.m_nonStandardIdentifier;
			if (h221nst.m_manufacturerCode == 21334
				&& Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveSorensonSourceInfo", "0"))) {
				setupBody.m_sourceInfo.m_terminal.RemoveOptionalField(H225_TerminalInfo::e_nonStandardData);
			}
		}
	}

	if (Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "RemoveH245AddressFromSetup", "0"))) {
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_h245Address)) {
			PTRACE(3, "Removing H.245 address from Setup");
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_h245Address);
		}
	}

	m_crv = (WORD)(setup->GetCallReference() | 0x8000u);
	if (toolkit->Config()->GetBoolean(RoutedSec, "ForwardOnFacility", false) && m_setupPdu == NULL)
		m_setupPdu = new Q931(q931);

	if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)
			|| setupBody.m_destinationAddress.GetSize() < 1) {
		unsigned plan, type;
		PString destination;
		if (q931.GetCalledPartyNumber(destination, &plan, &type)) {
			// Setup_UUIE doesn't contain any destination information, but Q.931 has CalledPartyNumber
			// We create the destinationAddress according to it
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setupBody.m_destinationAddress.SetSize(1);
			H323SetAliasAddress(destination, setupBody.m_destinationAddress[0]);
		}
	}

	PString callid;
	if (!m_call) {
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
			m_call = CallTable::Instance()->FindCallRec(setupBody.m_callIdentifier);
			callid = AsString(setupBody.m_callIdentifier);
		} else { // try CallReferenceValue
			PTRACE(3, Type() << "\tSetup_UUIE from " << Name() << " doesn't contain CallIdentifier!");
			H225_CallReferenceValue crv;
			crv.SetValue(msg->GetCallReference());
			m_call = CallTable::Instance()->FindCallRec(crv);
			H225_CallIdentifier callIdentifier; // empty callIdentifier
			callid = AsString(callIdentifier);
		}
	} else
		callid = AsString(m_call->GetCallIdentifier());

#ifdef HAS_H46026
	// now that we have a call associated with this socket, set the H.460.26 pipe bandwidth
	if (m_h46026PriorityQueue && m_call && m_call->GetCallingParty()) {
		m_h46026PriorityQueue->SetPipeBandwidth(m_call->GetCallingParty()->GetH46026BW());
	}
#endif

	// perform inbound ANI/CLI rewrite
	toolkit->RewriteCLI(*setup);
	toolkit->RewriteSourceAddress(*setup);

	// store dialed number
	const PString dialedNumber = GetDialedNumber(*setup);

    // do rewrite initated by RouteToInternalGateway
    if (m_call && m_call->HasNewSetupInternalAliases()) {
        PTRACE(2, Type() << "\tSet new internal aliases: " << *(m_call->GetNewSetupInternalAliases()));
        setupBody.m_destinationAddress = *(m_call->GetNewSetupInternalAliases());
        if (setupBody.m_destinationAddress.GetSize() > 0) {
            q931.SetCalledPartyNumber(AsString(setupBody.m_destinationAddress[0], false));
        }
    }

	// endpoint alias to find an inbound rewrite rule
	PString in_rewrite_id;

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		// Do inbound per GWRewrite if we can before global rewrite
		PString rewrite_type;

		// Try lookup on neighbor list for rewrite source first
		in_rewrite_id = rassrv->GetNeighbors()->GetNeighborIdBySigAdr(_peerAddr);
		if (!in_rewrite_id)
			rewrite_type = "neighbor or explicit IP";

		// Try call record rewrite identifier next
		if (in_rewrite_id.IsEmpty() && m_call) {
			in_rewrite_id = m_call->GetInboundRewriteId();
			if (!in_rewrite_id)
				rewrite_type = "call record";
		}

		// Try the Setup's source field if this exists
		if (in_rewrite_id.IsEmpty() && setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)
				&& setupBody.m_sourceAddress.GetSize() > 0) {
			in_rewrite_id = GetBestAliasAddressString(
				setupBody.m_sourceAddress, false,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
				AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
					| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
				);
			if (!in_rewrite_id)
				rewrite_type = "setup H323 ID or E164";
		}

		if (in_rewrite_id.IsEmpty() && q931.GetCallingPartyNumber(in_rewrite_id)) {
			if (!in_rewrite_id)
				rewrite_type = "setup CLI";
		}

		if (!in_rewrite_id) {
			PTRACE(4, Type() << "\tGWRewrite source for " << Name() << ": " << rewrite_type);
			toolkit->GWRewriteE164(in_rewrite_id, GW_REWRITE_IN, setupBody.m_destinationAddress, m_call);
		}

		// Normal rewrite
		toolkit->RewriteE164(setupBody.m_destinationAddress);
	}

	// rewrite existing CalledPartyNumberIE
	if (q931.HasIE(Q931::CalledPartyNumberIE)) {
		unsigned plan, type;
		PString calledNumber;

		if (q931.GetCalledPartyNumber(calledNumber, &plan, &type)) {
			bool rewritten = false;
			// Do per GW inbound rewrite before global rewrite
			if (!in_rewrite_id)
				rewritten = toolkit->GWRewritePString(in_rewrite_id, GW_REWRITE_IN, calledNumber, m_call);

			// Normal rewrite
		    rewritten = toolkit->RewritePString(calledNumber) || rewritten;

			if (rewritten)
				q931.SetCalledPartyNumber(calledNumber, plan, type);
		}
	}

	if (m_call && m_call->GetCallingParty() && m_call->GetCallingParty()->AddCallingPartyToSourceAddress()) {
		PString callingParty;
		q931.GetCallingPartyNumber(callingParty);
		bool found = false;
		for (PINDEX i = 0; i < setupBody.m_sourceAddress.GetSize(); i++) {
			if (AsString(setupBody.m_sourceAddress[i], false) == callingParty) {
				found = true;
			}
		}
		if (!found) {
			PTRACE(4, Type() << "\tAdding callingParty to sourceAddress");
			H225_AliasAddress callingAlias;
			H323SetAliasAddress(callingParty, callingAlias);
			setupBody.m_sourceAddress.SetSize(setupBody.m_sourceAddress.GetSize() + 1);
			// move old sourceAddresses up one spot
			for (PINDEX i = setupBody.m_sourceAddress.GetSize(); i > 1; i--) {
				setupBody.m_sourceAddress[i-1] = setupBody.m_sourceAddress[i-2];
			}
			// add calling party as first entry
			setupBody.m_sourceAddress[0] = callingAlias;
		}
	}

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
		// rewrite destination IP here (can't do it in Explicit policy, because local IPs are removed before they get there)
		Routing::ExplicitPolicy::MapDestination(setupBody);
		// remove the destination signaling address of the gatekeeper
		PIPSocket::Address _destAddr;
		WORD _destPort = 0;
		if (GetIPAndPortFromTransportAddr(setupBody.m_destCallSignalAddress, _destAddr, _destPort)
				&& _destAddr == _localAddr && _destPort == _localPort) {
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		}
		GkClient * gkClient = RasServer::Instance()->GetGkClient();
		if (m_call && gkClient && gkClient->CheckFrom(_peerAddr)) {
			m_call->SetFromParent(true);
		}
#ifdef HAS_H46018
		// ignore destCallSignalAddress from traversal server:
		// client doesn't know external IP and the server only knows the external IP, so client can't tell if it is his IP or somebody else
		if (rassrv->IsCallFromTraversalServer(_peerAddr)
			|| (gkClient && gkClient->CheckFrom(_peerAddr) && gkClient->UsesH46018()) ) {
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		}
#endif
		//  also remove destCallSigAddr if its the ExternalIP
		PString extip = Toolkit::Instance()->GetExternalIP();
		if (!extip.IsEmpty()) {
			PIPSocket::Address ext((DWORD)0);
			H323TransportAddress ex = H323TransportAddress(extip);
			ex.GetIpAddress(ext);
			if (GetIPAndPortFromTransportAddr(setupBody.m_destCallSignalAddress, _destAddr, _destPort)
					&& _destAddr == ext) {
				PTRACE(1, "Removing External IP from destCallSignalAddr in Setup");
				setupBody.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
			}
		}
	}

	// send a CallProceeding (to avoid caller timeouts)
	if (Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "GenerateCallProceeding", "0"))) {
		PTRACE(4, "Q931\tGatekeeper generated CallProceeding");
		Q931 proceedingQ931;
		PBYTEArray lBuffer;
		BuildProceedingPDU(proceedingQ931, setupBody.m_callIdentifier, m_crv | 0x8000u);
		proceedingQ931.Encode(lBuffer);
		TransmitData(lBuffer);
	}

	GkClient *gkClient = rassrv->GetGkClient();
#ifdef HAS_H46018
    // enable TCP keep-alives for calls from traversal servers or neighbors
    if (rassrv->IsCallFromTraversalServer(_peerAddr)
        || (gkClient && gkClient->CheckFrom(_peerAddr) && gkClient->UsesH46018()) ) {
        bool h46017 = m_call && m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46017();
        if (!h46017) {
            PTRACE(5, "H46018\tEnable keep-alive for incoming H.460.18 call from traversal server/neighbor");
            RegisterKeepAlive(GkConfig()->GetInteger(RoutedSec, "H46018KeepAliveInterval", 19));
        }
    }
#endif

	bool rejectCall = false;
	bool overTLS = false;
#ifdef HAS_TLS
	overTLS = (dynamic_cast<TLSCallSignalSocket *>(this) != NULL);
#endif
	SetupAuthData authData(m_call, m_call ? true : false, overTLS);

#ifdef HAS_H46023
	CallRec::NatStrategy natoffloadsupport = CallRec::e_natUnknown;
#endif
	if (m_call
#ifdef HAS_H46018
		&& !m_call->IsH46018ReverseSetup()
#endif
		) {
		// existing CallRec
		bool secondSetup = false;	// second Setup with same call-id detected (avoid new acct start and overwriting acct data)
		m_call->SetSetupTime(setupTime);
		m_call->SetSrcSignalAddr(SocketToH225TransportAddr(_peerAddr, _peerPort));

		if (m_call->IsSocketAttached()
#ifdef HAS_H46018
			&& !m_call->IsH46018ReverseSetup()
#endif
			) {
			PTRACE(2, Type() << "\tWarning: socket (" << Name() << ") already attached for callid " << callid);
			m_call->SetDisconnectCause(Q931::CallRejected);
			rejectCall = true;
			// suppress 2nd AcctStart for same callid
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
				secondSetup = (AsString(m_call->GetCallIdentifier()) == AsString(setupBody.m_callIdentifier));
			}
		} else if (m_call->IsToParent() && !m_call->IsForwarded()) {
			if (gkClient->CheckFrom(_peerAddr)) {
				// looped call
				PTRACE(2, Type() << "\tWarning: a registered call from my GK(" << GetName() << ')');
				m_call->SetDisconnectCause(Q931::CallRejected);
				rejectCall = true;
			} else {
				gkClient->HandleSetup(*setup, true);
			}
		}

		const H225_ArrayOf_CryptoH323Token & tokens = m_call->GetAccessTokens();
		if (!rejectCall && tokens.GetSize() > 0) {
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_cryptoTokens);
			setupBody.m_cryptoTokens = tokens;
		}

		authData.m_dialedNumber = dialedNumber;
		authData.SetRouteToAlias(m_call->GetRouteToAlias());
		authData.m_callingStationId = GetCallingStationId(*setup, authData);
		authData.m_calledStationId = GetCalledStationId(*setup, authData);

		// authenticate the call
		if (!rejectCall && !rassrv->ValidatePDU(*setup, authData)) {
			PTRACE(3, Type() << "\tDropping call #" << m_call->GetCallNumber()
				<< " due to Setup authentication failure"
				);
			if (authData.m_rejectCause >= 0)
				m_call->SetDisconnectCause(authData.m_rejectCause);
			else if (authData.m_rejectReason >= 0)
				m_call->SetDisconnectCause(Toolkit::Instance()->MapH225ReasonToQ931Cause(authData.m_rejectReason));
			else
				m_call->SetDisconnectCause(Q931::CallRejected);
			rejectCall = true;
		}

		if (!rejectCall && authData.m_routeToAlias.GetSize() > 0) {
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setupBody.m_destinationAddress = authData.m_routeToAlias;

			const PString alias = AsString(setupBody.m_destinationAddress[0], FALSE);
			if (q931.HasIE(Q931::CalledPartyNumberIE)) {
				if (IsValidE164(alias)) {
					unsigned plan, type;
					PString calledNumber;
					if (q931.GetCalledPartyNumber(calledNumber, &plan, &type))
						q931.SetCalledPartyNumber(alias, plan, type);
				} else
					q931.RemoveIE(Q931::CalledPartyNumberIE);
			}
			authData.m_calledStationId = alias;
			PTRACE(3, Type() << "\tSetup CRV=" << msg->GetCallReference()
				<< " destination set to " << alias
				);
		}
		if (!rejectCall && authData.m_callDurationLimit > 0)
			m_call->SetDurationLimit(authData.m_callDurationLimit);
		if (!authData.m_callingStationId)
			m_call->SetCallingStationId(authData.m_callingStationId);
		if (!authData.m_calledStationId && !secondSetup)
			m_call->SetCalledStationId(authData.m_calledStationId);
		if (!authData.m_dialedNumber)
			m_call->SetDialedNumber(authData.m_dialedNumber);
		if (authData.m_clientAuthId > 0)
			m_call->SetClientAuthId(authData.m_clientAuthId);

		if (!secondSetup && (m_call->GetFailedRoutes().empty() || !m_call->SingleFailoverCDR())) {
			// log AcctStart accounting event
			if (!rassrv->LogAcctEvent(GkAcctLogger::AcctStart, m_call)) {
				PTRACE(2, Type() << "\tDropping call #" << m_call->GetCallNumber()
					<< " due to accounting failure"
					);
				m_call->SetDisconnectCause(Q931::TemporaryFailure);
				rejectCall = true;
			}
		} else
			PTRACE(5, Type() << "\tSupressing accounting start event for call #"
				<< m_call->GetCallNumber());

        PString statusCallID = callid;
        statusCallID.Replace(" ", "-", true);
        GkStatus::Instance()->SignalStatus("Setup|" + Name() + "|" + statusCallID + ";\r\n", STATUS_TRACE_LEVEL_RAS);
	} else {
		// no existing CallRec
		authData.m_dialedNumber = dialedNumber;
		authData.m_callingStationId = GetCallingStationId(*setup, authData);
		authData.m_calledStationId = GetCalledStationId(*setup, authData);

		if (!rassrv->ValidatePDU(*setup, authData)) {
			PTRACE(3, Type() << "\tDropping call CRV=" << msg->GetCallReference()
				<< " from " << Name() << " due to Setup authentication failure");
			if (authData.m_rejectCause == -1 && authData.m_rejectReason == -1)
				authData.m_rejectCause = Q931::CallRejected;
			rejectCall = true;
		}

		if (!rejectCall && authData.m_routeToAlias.GetSize() > 0) {
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setupBody.m_destinationAddress = authData.m_routeToAlias;

			const PString alias = AsString(setupBody.m_destinationAddress[0], FALSE);
			if (q931.HasIE(Q931::CalledPartyNumberIE)) {
				if (IsValidE164(alias)) {
					unsigned plan, type;
					PString calledNumber;
					if (q931.GetCalledPartyNumber(calledNumber, &plan, &type))
						q931.SetCalledPartyNumber(alias, plan, type);
				} else
					q931.RemoveIE(Q931::CalledPartyNumberIE);
			}
			authData.m_calledStationId = alias;
			PTRACE(3, Type() << "\tSetup CRV=" << msg->GetCallReference()
				<< " destination set to " << alias
				);
		}

		endptr called;
		bool destFound = false;
		H225_TransportAddress calledAddr;
		Routing::SetupRequest request(setupBody, setup, authData.m_callingStationId, authData.m_clientAuthId);

		// delete routes with no capacity
		for (list<Route>::iterator i = authData.m_destinationRoutes.begin(); i != authData.m_destinationRoutes.end(); /* nothing */ ) {
			H225_ArrayOf_AliasAddress destinationAliases;
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
				destinationAliases = setupBody.m_destinationAddress;
			}
			if ((*i).m_destEndpoint && !((*i).m_destEndpoint->HasAvailableCapacity(destinationAliases))) {
				authData.m_destinationRoutes.erase(i++);	// delete route
			} else {
				++i;	// check next
			}
		}

		if (!rejectCall && !authData.m_destinationRoutes.empty()) {
			list<Route>::const_iterator i = authData.m_destinationRoutes.begin();
			while (i != authData.m_destinationRoutes.end()) {
				request.AddRoute(*i++);
			}
			calledAddr = authData.m_destinationRoutes.front().m_destAddr;
			called = authData.m_destinationRoutes.front().m_destEndpoint;
			destFound = true;
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
			setupBody.m_destCallSignalAddress = calledAddr;
			PTRACE(3, Type() << "\tSetup CRV=" << msg->GetCallReference()
				<< " destination address set to " << AsDotString(setupBody.m_destCallSignalAddress));
		}

		bool useParent = gkClient && gkClient->IsRegistered() && gkClient->CheckFrom(_peerAddr);

#ifdef HAS_H46023
		if (Toolkit::Instance()->IsH46023Enabled()
			&& setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)
			&& authData.m_proxyMode != CallRec::ProxyDisabled) {
			H225_ArrayOf_FeatureDescriptor & data = setupBody.m_supportedFeatures;
			for (PINDEX i =0; i < data.GetSize(); i++) {
				H460_Feature & feat = (H460_Feature &)data[i];
				/// Std 24
				if (feat.GetFeatureID() == H460_FeatureID(24)) {
					H460_FeatureStd & std24 = (H460_FeatureStd &)feat;
					if (std24.Contains(Std24_NATInstruct)) {
						unsigned natstat = std24.Value(Std24_NATInstruct);
						natoffloadsupport = (CallRec::NatStrategy)natstat;
					}
				}
			}
		}
#endif

		if (!rejectCall && useParent) {
			gkClient->HandleSetup(*setup, false);
			if (!gkClient->SendARQ(request, true)) {
				PTRACE(2, Type() << "\tGot ARJ from parent for " << GetName());
				authData.m_rejectCause = Q931::CallRejected;
				rejectCall = true;
			} else
				request.SetFlag(Routing::RoutingRequest::e_fromParent);
		}

		if (!rejectCall && !destFound
				&& setupBody.HasOptionalField(H225_Setup_UUIE::e_cryptoTokens)
				&& setupBody.m_cryptoTokens.GetSize() > 0) {
			PINDEX s = setupBody.m_cryptoTokens.GetSize() - 1;
			// TODO: really check only the last token ?
			destFound = Neighbors::DecodeAccessToken(setupBody.m_cryptoTokens[s], _peerAddr, calledAddr);
			if (destFound) {
				called = RegistrationTable::Instance()->FindBySignalAdr(calledAddr);
				PTRACE(3, Type() << "\tGot destination " << AsDotString(calledAddr));
				if (s > 0)
					setupBody.m_cryptoTokens.SetSize(s);
				else
					setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);

				Route route("nbtoken", calledAddr);
				route.m_destEndpoint = called;
				request.AddRoute(route);

				if (!useParent) {
					Address toIP;
					GetIPFromTransportAddr(calledAddr, toIP);
					useParent = gkClient->IsRegistered() && gkClient->CheckFrom(toIP);
					if (useParent && !gkClient->SendARQ(request)) {
						PTRACE(2, Type() << "\tGot ARJ from parent for " << GetName());
						authData.m_rejectCause = Q931::CallRejected;
						rejectCall = true;
					}
				}
			}
		}

        PString statusCallID = callid;
        statusCallID.Replace(" ", "-", true);
        GkStatus::Instance()->SignalStatus("SetupUnreg|" + Name() + "|" + statusCallID + ";\r\n", STATUS_TRACE_LEVEL_RAS);

		bool proceedingSent = false;
		if (!rejectCall && !destFound) {
			// for compatible to old version
			if (!(useParent || rassrv->AcceptUnregisteredCalls(_peerAddr) || rassrv->AcceptPregrantedCalls(setupBody, _peerAddr))) {
				PTRACE(3, Type() << "\tReject unregistered call " << callid << " from " << Name());
				authData.m_rejectCause = Q931::CallRejected;
				rejectCall = true;
			} else {
				PreliminaryCall * tmpCall = new PreliminaryCall(this, setupBody.m_callIdentifier, m_crv);
				PreliminaryCallTable::Instance()->Insert(tmpCall);
				request.Process();
				proceedingSent = tmpCall->IsProceedingSent();
				PreliminaryCallTable::Instance()->Remove(setupBody.m_callIdentifier);
				delete tmpCall;
				// check if destination has changed in the routing process
				// eg. via canMapAlias in LRQ
				if (request.GetFlags() & Routing::SetupRequest::e_aliasesChanged) {
					if (request.GetFlags() & Routing::SetupRequest::e_Reject) {
						PTRACE(3, Type() << "\tRejecting unregistered call " << callid << " from " << Name());
						authData.m_rejectReason = request.GetRejectReason();
						rejectCall = true;
					} else {
						if (request.GetAliases() && request.GetAliases()->GetSize() > 0) {
							setupBody.m_destinationAddress = request.GetRequest().m_destinationAddress;
							const PString newCalledParty = AsString(setupBody.m_destinationAddress[0], FALSE);
							if (q931.HasIE(Q931::CalledPartyNumberIE)) {
								if (IsValidE164(newCalledParty)) {
									unsigned plan, type;
									PString calledNumber;
									if (q931.GetCalledPartyNumber(calledNumber, &plan, &type))
										q931.SetCalledPartyNumber(newCalledParty, plan, type);
									else
										q931.RemoveIE(Q931::CalledPartyNumberIE);
								}
								authData.m_calledStationId = newCalledParty;
							}
						}
					}
				}
				if (!rejectCall) {
					Route route;
					if (request.GetFirstRoute(route)) {
						destFound = true;
						calledAddr = route.m_destAddr;
						called = route.m_destEndpoint;
						if (authData.m_proxyMode == CallRec::ProxyDetect)
							authData.m_proxyMode = route.m_proxyMode;
						if (!useParent)
							useParent = route.m_flags & Route::e_toParent;
					} else {
						PTRACE(3, Type() << "\tNo destination for unregistered call "
							<< callid << " from " << Name());
						authData.m_rejectReason = request.GetRejectReason();
						rejectCall = true;
					}
				}
			}
		}

		PString destinationString(setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)
			? AsString(setupBody.m_destinationAddress) : AsDotString(calledAddr));

		// if I'm behind NAT and the call is from parent, always use H.245 routed,
		// also make sure all calls from endpoints with H.460.17/.18 are H.245 routed
		bool h245Routed = rassrv->IsH245Routed() || (useParent && (gkClient->IsNATed() || gkClient->UsesH46018()));
		bool callFromTraversalClient = false;
		bool callFromTraversalServer = false;
#ifdef HAS_H46017
		if ((m_call && m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46017())
			|| (m_call && m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46017()) ) {
			h245Routed = true;
		}
#endif

#ifdef HAS_H46018
		callFromTraversalClient = rassrv->IsCallFromTraversalClient(_peerAddr);
		callFromTraversalServer = rassrv->IsCallFromTraversalServer(_peerAddr);

		if ((m_call && m_call->GetCallingParty() && m_call->GetCallingParty()->GetTraversalRole() != None)
			|| (m_call && m_call->GetCalledParty() && m_call->GetCalledParty()->GetTraversalRole() != None)
			|| (m_call && m_call->IsH46018ReverseSetup()) || callFromTraversalClient || callFromTraversalServer) {
			h245Routed = true;
		}
#endif

		CallRec* call = new CallRec(q931, setupBody, h245Routed,
			destinationString, authData.m_proxyMode);
		call->SetProceedingSent(proceedingSent);
		call->SetSrcSignalAddr(SocketToH225TransportAddr(_peerAddr, _peerPort));
#ifdef HAS_H46023
		call->SetNATStrategy(natoffloadsupport);
#endif
		call->SetBindHint(request.GetSourceIP());
		call->SetCallerID(request.GetCallerID());
		call->SetCallerDisplayIE(request.GetCallerDisplayIE());
		call->SetCalledDisplayIE(request.GetCalledDisplayIE());
		call->SetCallingVendor(callingVendor, callingVersion);

#ifdef HAS_H46018
		// special case for reverse H.460.18 Setup
		if (m_call && m_call->IsH46018ReverseSetup()) {		// looking at the _old_ call
			call->SetH46018ReverseSetup(true);
			call->SetFromParent(m_call->IsFromParent());
			m_call->SetCallSignalSocketCalling(NULL);
			m_call->SetCallSignalSocketCalled(NULL);
			m_h245handlerLock.Wait();
			delete m_h245handler;
			m_h245handler = NULL;
			m_h245handlerLock.Signal();
			delete m_h245socket;
			m_h245socket = NULL;
			m_remoteLock.Wait();
			if (remote) {
				remote->RemoveRemoteSocket();
				GetHandler()->Remove(remote);	// will delete socket in CleanUp()
				remote = NULL;
			}
			m_remoteLock.Signal();
		}
#endif

		// make sure we have an EPRec for traversal calls from neighbor
        if (!call->GetCallingParty()) {
			if (callFromTraversalClient || callFromTraversalServer) {
				endptr callingEP = RegistrationTable::Instance()->InsertRec(setupBody, SocketToH225TransportAddr(_peerAddr, _peerPort));
				if (callFromTraversalClient)
					callingEP->SetTraversalRole(TraversalClient);
				if (callFromTraversalServer)
					callingEP->SetTraversalRole(TraversalServer);
				call->SetCalling(callingEP);
			}
#ifdef HAS_H46023
			else if (IsH46024Call(setupBody)) {
				callFromTraversalClient = true;
				endptr callingEP = RegistrationTable::Instance()->InsertRec(setupBody, SocketToH225TransportAddr(_peerAddr, _peerPort));
				call->SetCalling(callingEP);
			}
#endif
		}

		if (!callFromTraversalClient && !callFromTraversalServer) {
			// if the peer address is a public address, but the advertised source address is a private address
			// then there is a good chance the remote endpoint is behind a NAT.
			PIPSocket::Address srcAddr;
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress) && setupBody.m_sourceCallSignalAddress.IsValid()) {
				H323TransportAddress sourceAddress(setupBody.m_sourceCallSignalAddress);
				sourceAddress.GetIpAddress(srcAddr);

				if (_peerAddr != srcAddr) {  // do we have a NAT?
					if (Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "SupportNATedEndpoints", "0"))) {
						PTRACE(4, Type() << "\tSource address " <<  srcAddr
							<< " peer address " << _peerAddr << " caller is behind NAT");
						call->SetSrcNATed(srcAddr);
					} else {
						// if unregistered caller is NATed & no policy then reject.
						PTRACE(4, Type() << "\tUnregistered party is NATed. Not supported by policy.");
						authData.m_rejectReason = Q931::NoRouteToDestination;
						rejectCall = true;
					}
					// If the called Party is not NATed then the called EP must support NAT'd callers
					// later versions of OpenH323 and GnomeMeeting do also allow this condition.
				} else {
					PTRACE(4, Type() << "\tUnregistered party is not NATed");
				}
			} else {
				   // If the party cannot be determined if behind NAT and we have support then just treat as being NAT
					 if (Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "SupportNATedEndpoints", "0")) &&
						Toolkit::AsBool(toolkit->Config()->GetString(RoutedSec, "TreatUnregisteredNAT", "0"))) {
						PTRACE(4, Type() << "\tUnregistered party " << _peerAddr << " cannot detect if NATed. Treated as if NATed");
						srcAddr = "192.168.1.1";  // just an arbitrary internal address
						call->SetSrcNATed(srcAddr);
					} else {
						PTRACE(4, Type() << "\tWARNING: Unregistered party " << _peerAddr << " cannot detect if NATed");
					}
			}
		}

		if (called)
			call->SetCalled(called);
		else
			call->SetDestSignalAddr(calledAddr);

		if (useParent)
			call->SetToParent(true);

		// the first CallRec for a reverse H.460.18 Setup is not inserted into the CallTable and needs to be manually deleted here
		CallRec * savedPtr = NULL;
		if (m_call)
			savedPtr = m_call.operator->();
		m_call = callptr(call);
		if (savedPtr) {
			authData.m_call = callptr(call);
			savedPtr->ClearCallIdentifier(); // make sure multiplexed channels for this callID won't be deleted when tmp CallRec or socket get deleted
		}

		m_call->SetSetupTime(setupTime);
		CallTable::Instance()->Insert(call);

		if (!rejectCall && authData.m_callDurationLimit > 0)
			m_call->SetDurationLimit(authData.m_callDurationLimit);
		if (!authData.m_callingStationId)
			m_call->SetCallingStationId(authData.m_callingStationId);
		if (!authData.m_calledStationId)
			m_call->SetCalledStationId(authData.m_calledStationId);
		if (!authData.m_dialedNumber)
			m_call->SetDialedNumber(authData.m_dialedNumber);
		if (!rejectCall && destFound)
			m_call->SetNewRoutes(request.GetRoutes());
		if (authData.m_clientAuthId > 0)
			m_call->SetClientAuthId(authData.m_clientAuthId);

		if (!rassrv->LogAcctEvent(GkAcctLogger::AcctStart, m_call)) {
			PTRACE(2, Type() << "\tDropping call #" << call->GetCallNumber() << " due to accounting failure");
			authData.m_rejectCause = Q931::TemporaryFailure;
			rejectCall = true;
		}

		if (rejectCall) {
			if (authData.m_rejectCause >= 0)
				m_call->SetDisconnectCause(authData.m_rejectCause);
			else if (authData.m_rejectReason >= 0)
				m_call->SetDisconnectCause(Toolkit::Instance()->MapH225ReasonToQ931Cause(authData.m_rejectReason));
			else
				m_call->SetDisconnectCause(Q931::CallRejected);
		}
	}	// else: no CallRec

	// remove H.235 tokens from incoming Setup
	if (Toolkit::Instance()->RemoveH235TokensFrom(_peerAddr)) {
			PTRACE(3, "Removing H.235 tokens");
			setupBody.m_tokens.SetSize(0);
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_tokens);
			setupBody.m_cryptoTokens.SetSize(0);
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);
	}

#ifdef HAS_H235_MEDIA
	if (Toolkit::Instance()->IsH235HalfCallMediaEnabled()) {
		H235Authenticators & auth = m_call->GetAuthenticators();
		PString nonStdDHParamFile = GkConfig()->GetString(RoutedSec, "H235HalfCallDHParamFile", "");
		if (!nonStdDHParamFile.IsEmpty()) {
            auth.SetDHParameterFile(nonStdDHParamFile);
        }
		auth.SetEncryptionPolicy(1);	// request encryption
		auth.SetMaxCipherLength(128);
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_tokens) && SupportsH235Media(setupBody.m_tokens)) {
			// make sure clear and crypto token fields are pesent, at least with 0 size
			if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_tokens)) {
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_tokens);
				setupBody.m_tokens.SetSize(0);
			}
			if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_cryptoTokens)) {
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_cryptoTokens);
				setupBody.m_cryptoTokens.SetSize(0);
			}

#ifdef hasAutoCreateAuthenticators	// PTLib 2.11.x
			// Authenticators are created on demand by identifiers in token/cryptoTokens where supported
			// TODO: check if we need to set cipher and token length for PTLib >= 2.11.x
			auth.CreateAuthenticators(setupBody.m_tokens, setupBody.m_cryptoTokens);
#else
			// Create all authenticators for both media encryption and caller authentication
#ifdef HAS_SETTOKENLENGTH
			unsigned maxCipher = 128;	// AES128
			unsigned maxTokenLen = toolkit->Config()->GetInteger(RoutedSec, "H235HalfCallMaxTokenLength", 1024);
			if (maxTokenLen > 1024)
				maxCipher = 256;	// AES256
			H235Authenticators::SetMaxCipherLength(maxCipher);
			H235Authenticators::SetMaxTokenLength(maxTokenLen);
#endif
			auth.CreateAuthenticators(H235Authenticator::MediaEncryption);
			auth.CreateAuthenticators(H235Authenticator::EPAuthentication);
#endif
			// make sure authenticator gets received tokens, ignore the result
			H235Authenticator::ValidationResult result = auth.ValidateSignalPDU(
				H225_H323_UU_PDU_h323_message_body::e_setup,
				setupBody.m_tokens, setupBody.m_cryptoTokens, m_rawSetup);
			if (result != H235Authenticator::e_OK &&
				result != H235Authenticator::e_Absent &&
				result != H235Authenticator::e_Disabled) {
					PTRACE(5, "H235\tCaller Admission failed");
					m_call->SetDisconnectCause(Q931::CallRejected);
					rejectCall = true;
			}

			// Remove hop-by-hop cryptoTokens...
			setupBody.m_cryptoTokens.RemoveAll();
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);
			m_call->SetMediaEncryption(CallRec::calledParty);
		} else if (!rejectCall && !auth.SupportsEncryption()) {
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_tokens)) {
				// remove possible other clear tokens in order no to get a mix with ours
				setupBody.m_tokens.RemoveAll();
			} else {
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_tokens);
				setupBody.m_tokens.RemoveAll();
				setupBody.m_tokens.SetSize(0);
			}
			if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_cryptoTokens)) {
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_cryptoTokens);
				setupBody.m_cryptoTokens.SetSize(0);
			}
#ifdef hasAutoCreateAuthenticators
			// Authenticators are created on demand by identifiers in token/cryptoTokens where supported
			// TODO: check if we need to set cipher and token length for PTLib >= 2.11.x
			auth.CreateAuthenticators(setupBody.m_tokens, setupBody.m_cryptoTokens);
#else			// Create all authenticators for both media encryption and caller authentication
#ifdef HAS_SETTOKENLENGTH
			unsigned maxCipher = 128;	// AES128
			unsigned maxTokenLen = toolkit->Config()->GetInteger(RoutedSec, "H235HalfCallMaxTokenLength", 1024);
			if (maxTokenLen > 1024)
				maxCipher = 256;	// AES256
			H235Authenticators::SetMaxCipherLength(maxCipher);
			H235Authenticators::SetMaxTokenLength(maxTokenLen);
#endif
			auth.CreateAuthenticators(H235Authenticator::MediaEncryption);
			auth.CreateAuthenticators(H235Authenticator::EPAuthentication);
#endif
			auth.PrepareSignalPDU(H225_H323_UU_PDU_h323_message_body::e_setup,
									setupBody.m_tokens, setupBody.m_cryptoTokens);
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_tokens);
			if (setupBody.m_cryptoTokens.GetSize() == 0)
				setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);
		}
	}
	if (toolkit->Config()->GetBoolean(RoutedSec, "ForwardOnFacility", false)
		&& setupBody.HasOptionalField(H225_Setup_UUIE::e_tokens)) {
		m_setupClearTokens = new H225_ArrayOf_ClearToken(setupBody.m_tokens);	// save a copy of the tokens in case the call gets forwarded
	}
#endif


	if (rejectCall) {
		m_result = Error;
		return;
	}

	if (!rejectCall && strlen(authData.m_disabledcodecs) > 0)
		m_call->SetDisabledCodecs(authData.m_disabledcodecs);

	// remove endpointIdentifier from the forwarded Setup
	setupBody.RemoveOptionalField(H225_Setup_UUIE::e_endpointIdentifier);

	// include destCallSignalAddress (Polycom m100 1.0.0 crashes if its not present)
	if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
		setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		setupBody.m_destCallSignalAddress = m_call->GetDestSignalAddr();
	}

	// perform outbound rewrite
	PIPSocket::Address calleeAddr;
	WORD calleePort = 0;
	m_call->GetDestSignalAddr(calleeAddr, calleePort);
	toolkit->RewriteCLI(*setup, authData, calleeAddr);

	PString out_rewrite_id;
	// Do outbound per GW rewrite
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		if (!m_call->GetNewRoutes().empty() && !m_call->GetNewRoutes().front().m_destOutNumber.IsEmpty()) {
			PTRACE(4, Type() << "\tGWRewrite source for " << Name() << ": auth module");
			for (PINDEX i = 0; i < setupBody.m_destinationAddress.GetSize(); ++i)
				if (setupBody.m_destinationAddress[i].GetTag() == H225_AliasAddress::e_dialedDigits) {
					PTRACE(2, Type() << "\tAuth out rewrite: " << ::AsString(setupBody.m_destinationAddress[i]) << " to " << m_call->GetNewRoutes().front().m_destOutNumber);
					H323SetAliasAddress(m_call->GetNewRoutes().front().m_destOutNumber, setupBody.m_destinationAddress[i], setupBody.m_destinationAddress[i].GetTag());
				} else if (setupBody.m_destinationAddress[i].GetTag() == H225_AliasAddress::e_partyNumber) {
					H225_PartyNumber &partyNumber = setupBody.m_destinationAddress[i];
					if (partyNumber.GetTag() == H225_PartyNumber::e_e164Number) {
						H225_PublicPartyNumber &number = partyNumber;
						number.m_publicNumberDigits = m_call->GetNewRoutes().front().m_destOutNumber;
						PTRACE(2, Type() << "\tAuth out rewrite: " << ::AsString(setupBody.m_destinationAddress[i]) << " to " << m_call->GetNewRoutes().front().m_destOutNumber);
					} else if (partyNumber.GetTag() == H225_PartyNumber::e_privateNumber) {
						H225_PrivatePartyNumber &number = partyNumber;
						number.m_privateNumberDigits = m_call->GetNewRoutes().front().m_destOutNumber;
						PTRACE(2, Type() << "\tAuth out rewrite: " << ::AsString(setupBody.m_destinationAddress[i]) << " to " << m_call->GetNewRoutes().front().m_destOutNumber);
					}
				}
		} else {
			PIPSocket::Address neighbor_addr;
			WORD port;
			PString rewrite_type;

			// Try neighbor list first
			if (m_call->GetDestSignalAddr(neighbor_addr, port)) {
				out_rewrite_id = rassrv->GetNeighbors()->GetNeighborIdBySigAdr(neighbor_addr);
				if (!out_rewrite_id)
					rewrite_type = "neighbor or explicit IP";
			}

			// Try call record rewrite id
			if (out_rewrite_id.IsEmpty()) {
				out_rewrite_id = m_call->GetOutboundRewriteId();
				if (!out_rewrite_id)
					rewrite_type = "call record";
			}

			// Try configured endpoint
			if (out_rewrite_id.IsEmpty()) {
				endptr rewriteEndPointOut = m_call->GetCalledParty();
				if (rewriteEndPointOut && rewriteEndPointOut->GetAliases().GetSize() > 0) {
			 		out_rewrite_id = GetBestAliasAddressString(
						rewriteEndPointOut->GetAliases(), false,
						AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
						AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
							| AliasAddressTagMask(H225_AliasAddress::e_partyNumber)
						);
					if (!out_rewrite_id)
						rewrite_type = "setup H323 ID or E164";
				}
			}

			if (!out_rewrite_id) {
				PTRACE(4, Type() << "\tGWRewrite source for " << Name() << ": " << rewrite_type);
			    toolkit->GWRewriteE164(out_rewrite_id, GW_REWRITE_OUT, setupBody.m_destinationAddress, m_call);
			}
		}
	}

	if (q931.HasIE(Q931::CalledPartyNumberIE)) {
		unsigned plan, type;
		PString calledNumber;

		// Do per GW outbound rewrite after global rewrite
		if (q931.GetCalledPartyNumber(calledNumber, &plan, &type)) {
			if (!m_call->GetNewRoutes().empty() && !m_call->GetNewRoutes().front().m_destOutNumber.IsEmpty()) {
				PTRACE(4, Type() << "\tGWRewrite source for " << Name() << ": auth module");
				PTRACE(2, Type() << "\tAuth out rewrite Called-Party-Number IE: " << calledNumber << " to " << m_call->GetNewRoutes().front().m_destOutNumber);
				calledNumber = m_call->GetNewRoutes().front().m_destOutNumber;
				q931.SetCalledPartyNumber(calledNumber, plan, type);
			} else if (toolkit->GWRewritePString(out_rewrite_id, GW_REWRITE_OUT, calledNumber, m_call))
				q931.SetCalledPartyNumber(calledNumber, plan, type);
		}
	}

	// update CalledPartyNumberIE to H.225 destination
	if (toolkit->Config()->GetBoolean(RoutedSec, "UpdateCalledPartyToH225Destination", false)) {
        unsigned plan = Q931::ISDNPlan, type = Q931::InternationalType; // defaults
		PString calledNumber;
        if (q931.HasIE(Q931::CalledPartyNumberIE)) {
            q931.GetCalledPartyNumber(calledNumber, &plan, &type); // get current numbering plan and type
            q931.RemoveIE(Q931::CalledPartyNumberIE);
        }
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
            for (PINDEX i = 0; i < setupBody.m_destinationAddress.GetSize(); i++) {
                if (setupBody.m_destinationAddress[i].GetTag() == H225_AliasAddress::e_dialedDigits) {
                    calledNumber = AsString(setupBody.m_destinationAddress[i], false);
                    q931.SetCalledPartyNumber(calledNumber, plan, type);
                    break;
                }
            }
        }
	}

	// set forced CallingPartyNumberIE
	if (!m_call->GetCallerID().IsEmpty()) {
		unsigned plan = Q931::ISDNPlan, type = Q931::InternationalType;
		// unsigned presentation = (unsigned)-1;	// presentation and screening not included, if presentation=-1
		unsigned presentation = H225_PresentationIndicator::e_presentationAllowed;
		unsigned screening = H225_ScreeningIndicator::e_networkProvided;
		q931.SetCallingPartyNumber(m_call->GetCallerID(), plan, type, presentation, screening);
	}

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		const PString screenSourceAddress = GkConfig()->GetString(RoutedSec, "ScreenSourceAddress", "");
		if (!screenSourceAddress) {
			setupBody.m_sourceAddress.SetSize(1);
			H323SetAliasAddress(screenSourceAddress, setupBody.m_sourceAddress[0]);
		}
	}
	// remove H.235 tokens from outgoing Setup
	if (Toolkit::Instance()->RemoveH235TokensFrom(calleeAddr)) {
		PTRACE(3, "Removing H.235 tokens (outgoing)");
		setupBody.m_tokens.SetSize(0);
		setupBody.RemoveOptionalField(H225_Setup_UUIE::e_tokens);
		setupBody.m_cryptoTokens.SetSize(0);
		setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);
	}

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_multipleCalls)
			&& setupBody.m_multipleCalls)
		setupBody.m_multipleCalls = FALSE;

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_maintainConnection)) {
		setupBody.m_maintainConnection = (GetRemote() && GetRemote()->MaintainConnection());
	}

	PString cli = toolkit->Config()->GetString(RoutedSec, "ScreenCallingPartyNumberIE", "");
	if (!cli.IsEmpty()) {
		unsigned plan = Q931::ISDNPlan, type = Q931::InternationalType;
		unsigned presentation = (unsigned)-1, screening = (unsigned)-1;
        PString oldCLI;
		if (q931.HasIE(Q931::CallingPartyNumberIE)) {
			q931.GetCallingPartyNumber(oldCLI, &plan, &type, &presentation, &screening, (unsigned)-1, (unsigned)-1);
		}
		if (cli == "RegisteredAlias") {
            endptr ep = m_call ? m_call->GetCallingParty() : endptr(NULL);
            if (ep) {
                cli = m_call->GetCallingStationId();
            } else {
                cli = oldCLI; // leave as is for unregistered endpoints
            }
            PString append = toolkit->Config()->GetString(RoutedSec, "AppendToCallingPartyNumberIE", "");
            if (!append.IsEmpty()) {
                append = Toolkit::Instance()->ReplaceGlobalParams(append);
                cli += append;
            }
            PString prepend = toolkit->Config()->GetString(RoutedSec, "PrependToCallingPartyNumberIE", "");
            if (!prepend.IsEmpty()) {
                prepend = Toolkit::Instance()->ReplaceGlobalParams(prepend);
                cli = prepend + cli;
            }
		}
        q931.SetCallingPartyNumber(cli, plan, type, presentation, screening);
	}
	SetCallTypePlan(&q931);

	// store (rewritten) CallingPartyNumberIE, eg. for PrintCallInfo
    if (q931.HasIE(Q931::CallingPartyNumberIE)) {
        unsigned planIgnored = Q931::ISDNPlan, typeIgnored = Q931::InternationalType;
        unsigned presentationIgnored = (unsigned)-1, screeningIgnored = (unsigned)-1;
        PString callingPartyNumberIE;
        q931.GetCallingPartyNumber(callingPartyNumberIE, &planIgnored, &typeIgnored, &presentationIgnored, &screeningIgnored, (unsigned)-1, (unsigned)-1);
        m_call->SetCallingPartyNumberIE(callingPartyNumberIE);
    }

	// store (rewritten) CalledPartyNumberIE, eg. for PrintCallInfo
    if (q931.HasIE(Q931::CalledPartyNumberIE)) {
        unsigned planIgnored = Q931::ISDNPlan, typeIgnored = Q931::InternationalType;
        PString calledPartyNumberIE;
        q931.GetCalledPartyNumber(calledPartyNumberIE, &planIgnored, &typeIgnored);
        m_call->SetCalledPartyNumberIE(calledPartyNumberIE);
    }

	// add destination alias (for Swyx trunk)
	if (m_call->GetCalledParty()) {
		PString addAlias = m_call->GetCalledParty()->GetAdditionalDestinationAlias();
		if (!addAlias.IsEmpty()) {
			if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
				setupBody.m_destinationAddress.SetSize(0);
			}
			bool found = false; // see if already there
			for (PINDEX i = 0; i < setupBody.m_destinationAddress.GetSize(); i++) {
				if (AsString(setupBody.m_destinationAddress[i], false) == addAlias) {
					found = true;
					break;
				}
			}
			if (!found) {
				setupBody.m_destinationAddress.SetSize(setupBody.m_destinationAddress.GetSize()+1);
				H323SetAliasAddress(addAlias,
					setupBody.m_destinationAddress[setupBody.m_destinationAddress.GetSize() - 1]);
			}
		}
	}
	bool proxyIPv4ToIPv6 = toolkit->Config()->GetBoolean(RoutedSec, "AutoProxyIPv4ToIPv6Calls", true);
	unsigned callingIPVersion = GetVersion(m_call->GetSrcSignalAddr());
	// for traversal or neighbor calls we might not have the SrcSignalAddr
	if (callingIPVersion == 0)
		callingIPVersion = _peerAddr.GetVersion();
	unsigned calledIPVersion = GetVersion(m_call->GetDestSignalAddr());
	if (proxyIPv4ToIPv6 && (callingIPVersion != calledIPVersion)) {
		m_call->SetH245Routed(true);
		m_call->SetProxyMode(CallRec::ProxyEnabled);
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled (IPv4-to-IPv6)");
	}

#ifdef HAS_H46017
	// proxy if calling or called use H.460.17
	if ((m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46017())
		|| (m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46017()) ) {
		m_call->SetProxyMode(CallRec::ProxyEnabled);
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled (H.460.17)");
	}
#endif
#ifdef HAS_H46018
	// proxy if calling or called use H.460.18
	if ((m_call->H46019Required() && ((m_call->GetCallingParty() && m_call->GetCallingParty()->GetTraversalRole() != None)
		|| (m_call->GetCalledParty() && m_call->GetCalledParty()->GetTraversalRole() != None)))
		|| (gkClient && gkClient->CheckFrom(m_call->GetDestSignalAddr()) && gkClient->UsesH46018())
		|| m_call->IsH46018ReverseSetup() ) {
		m_call->SetProxyMode(CallRec::ProxyEnabled);
		PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled (H.460.18/.19)");
        // enable keep alive for called party when Facility comes in
	}

	// use delayed connecting if called party is a traversal client
	if (!(m_call->GetCalledParty() && m_call->GetCalledParty()->IsTraversalClient() && !m_call->GetCalledParty()->UsesH46017()) )
#endif
	{
#ifdef HAS_H46018
#ifdef HAS_H46023
		bool OZH46024 = (m_call->GetCalledParty() && m_call->GetCalledParty()->IsRemote() &&
					setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures) &&
					HasH46024Descriptor(setupBody.m_supportedFeatures));
#else
		bool OZH46024 = false;
#endif
		// no traversal client (or traversal client using H.460.17) -> send regular Setup
		// remove H.460.19 indicator
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures) && !OZH46024) {
			bool isH46019Client = false;
			RemoveH46019Descriptor(setupBody.m_supportedFeatures, m_senderSupportsH46019Multiplexing, isH46019Client);
			if (m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46017() && isH46019Client) {
				m_call->GetCallingParty()->SetTraversalRole(TraversalClient);
			}
		}
		if ( (m_call->GetCalledParty() && m_call->GetCalledParty()->IsTraversalServer())
			|| (gkClient && gkClient->CheckFrom(m_call->GetDestSignalAddr()) && gkClient->UsesH46018()) ) {
			H460_FeatureStd feat = H460_FeatureStd(19);
			if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)) {
				H460_FeatureID feat_id(1);	// supportTransmitMultiplexedMedia
				feat.AddParameter(&feat_id);
			}
			if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_supportedFeatures);
				setupBody.m_supportedFeatures.SetSize(0);
			}
			AddH460Feature(setupBody.m_supportedFeatures, feat);
		}
#endif	// HAS_H46018

#if defined(HAS_H46026)
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_neededFeatures)) {
		RemoveH460Descriptor(26, setupBody.m_neededFeatures);
		if (setupBody.m_neededFeatures.GetSize() == 0)
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_neededFeatures);
	}
#endif

#if defined(HAS_H46017)
     if (m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46017()) {
#if defined(HAS_H46018)
		if (Toolkit::Instance()->IsH46018Enabled()) {
			// offer H.460.19 to H.460.17 endpoints
			H460_FeatureStd feat = H460_FeatureStd(19);
			H460_FeatureID feat_id(2);	// mediaTraversalServer
			feat.AddParameter(&feat_id);

			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
				bool isH46019Client = false;
				// RemoveH46019Descriptor() runs possibly 2nd time here, make sure not to screw up flags discovered by 1st run
				RemoveH46019Descriptor(setupBody.m_supportedFeatures, m_senderSupportsH46019Multiplexing, isH46019Client);
				if (m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46017() && isH46019Client) {
					m_call->GetCallingParty()->SetTraversalRole(TraversalClient);
				}
			}

			if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)) {
				feat_id = H460_FeatureID(1);	// supportTransmitMultiplexedMedia
				feat.AddParameter(&feat_id);
			}
			if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_supportedFeatures);
				setupBody.m_supportedFeatures.SetSize(0);
			}
			AddH460Feature(setupBody.m_supportedFeatures, feat);
        }
#endif   // HAS_H46018
#ifdef HAS_H46026
        // Offer both H.460.19 and H.460.26 and let the endpoint decide
		if (Toolkit::Instance()->IsH46026Enabled()) {
			H460_FeatureStd feat = H460_FeatureStd(26);

            // We offer H.460.26 as supported endpoint ARQ will decide if needed
			if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_neededFeatures))
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_neededFeatures);

			AddH460Feature(setupBody.m_neededFeatures, feat);
        }
#endif  // HAS_H46026
     }
#endif

		CreateRemote(setupBody);
	}
#ifdef HAS_H46018
	else {
		// call to H.460.18 traversal client
		// can't connect the 2 sockets now, remember the calling socket until the called has pinholed throuth the NAT
		// this may set the wrong localAddr, because we don't know the peerAddr, yet, updated later in OnFacility()
		localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
		UnmapIPv4Address(localAddr);
		masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
		UnmapIPv4Address(masqAddr);
		m_call->SetCallSignalSocketCalling(this);
		SetConnected(true);	// avoid deletion

		// only rewrite sourceCallSignalAddress if we are proxying,
		// otherwise leave the receiving endpoint the option to deal with NATed caller itself
		if (m_call->GetProxyMode() == CallRec::ProxyEnabled
			|| GkConfig()->GetBoolean(RoutedSec, "AlwaysRewriteSourceCallSignalAddress", true)) {
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
			setupBody.m_sourceCallSignalAddress = SocketToH225TransportAddr(masqAddr, GetPort());
		}

		// For compatibility with endpoints which do not support large Setup messages or send incorrect tokens
		if (Toolkit::Instance()->RemoveAllH235Tokens()) {
			PTRACE(3, "Removing H.235 tokens");
			setupBody.m_tokens.SetSize(0);
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_tokens);
			setupBody.m_cryptoTokens.SetSize(0);
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);
		}

		if (Toolkit::Instance()->IsH46018Enabled())
		{
			H460_FeatureStd feat = H460_FeatureStd(19);
			H460_FeatureID feat_id(2);	// mediaTraversalServer
			feat.AddParameter(&feat_id);

#ifdef HAS_H46023
			if (Toolkit::Instance()->IsH46023Enabled())
				m_call->SetReceiveNATStategy(natoffloadsupport, authData.m_proxyMode);
#endif
			if (setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
				bool isH46019Client = false;
				RemoveH46019Descriptor(setupBody.m_supportedFeatures, m_senderSupportsH46019Multiplexing, isH46019Client);
				if (m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46017() && isH46019Client) {
					m_call->GetCallingParty()->SetTraversalRole(TraversalClient);
				}
			}

			if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)
#ifdef HAS_H46023
				&& (m_senderSupportsH46019Multiplexing || (!HasH46024Descriptor(setupBody.m_supportedFeatures) && IsH46024ProxyStrategy(natoffloadsupport)))
#endif
			) {
				H460_FeatureID feat_id(1);	// supportTransmitMultiplexedMedia
				feat.AddParameter(&feat_id);
			}
			if (!setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
				// add H.460.19 indicator to Setups
				setupBody.IncludeOptionalField(H225_Setup_UUIE::e_supportedFeatures);
				setupBody.m_supportedFeatures.SetSize(0);
			}
			AddH460Feature(setupBody.m_supportedFeatures, feat);
		}
#ifdef HAS_H46023
		if (Toolkit::Instance()->IsH46023Enabled()
			&& m_call->GetCalledParty()->UsesH46023()
			&& !HasH46024Descriptor(setupBody.m_supportedFeatures)) {
				// if remote does not support H.460.24 add Strategy to add local NAT Support.
				H460_FeatureStd std24 = H460_FeatureStd(24);
				std24.Add(Std24_NATInstruct,H460_FeatureContent((int)natoffloadsupport,8));
				AddH460Feature(setupBody.m_supportedFeatures, std24);
		}
#endif
	}
#endif
	msg->SetUUIEChanged();

#ifdef HAS_H46018
	// if destination route/endpoint is a traversal client
	if (m_call->GetCalledParty() && m_call->GetCalledParty()->IsTraversalClient() && !m_call->GetCalledParty()->UsesH46017()) {
		// send SCI
		RasServer *RasSrv = RasServer::Instance();
		H225_RasMessage sci_ras;
		sci_ras.SetTag(H225_RasMessage::e_serviceControlIndication);
		H225_ServiceControlIndication & sci = sci_ras;
		sci.m_requestSeqNum = RasSrv->GetRequestSeqNum();
		// Tandberg GK adds open here, the standard doesn't mention this
		H225_ServiceControlSession controlOpen;
		controlOpen.m_sessionId = 0;
		controlOpen.m_reason = H225_ServiceControlSession_reason::e_open;
		sci.m_serviceControl.SetSize(1);
		sci.m_serviceControl[0] = controlOpen;

		H46018_IncomingCallIndication incoming;
		incoming.m_callID = setupBody.m_callIdentifier;

		// send GK's signal addr on the best interface for this endpoint
		if (!m_call->GetDestSignalAddr(peerAddr, peerPort)) {
			PTRACE(3, Type() << "\tINVALID DESTINATION ADDRESS for call from " << Name());
			m_call->SetDisconnectCause(Q931::IncompatibleDestination);
			m_result = Error;
			return;
		}
		incoming.m_callSignallingAddress = RasServer::Instance()->GetCallSignalAddress(peerAddr);

		H460_FeatureStd feat = H460_FeatureStd(18);
		PASN_OctetString rawIndication;
		rawIndication.EncodeSubType(incoming);
		feat.Add(1, H460_FeatureContent(rawIndication));
		sci.IncludeOptionalField(H225_ServiceControlIndication::e_genericData);
		H225_ArrayOf_GenericData & gd = sci.m_genericData;
		gd.SetSize(1);
		gd[0] = feat;

#if defined(HAS_TLS) && defined(HAS_H460)
		// Although not covered in H.460.22 for H.460.18. The SCI needs to include H.460.22
		// to notify the endpoint to establish the TCP connection to the TLS port. - SH
		if (Toolkit::Instance()->IsTLSEnabled() && m_call->GetCalledParty()->UseTLS()) {
			H460_FeatureStd h46022 = H460_FeatureStd(22);
			H460_FeatureStd settings;
			settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
			WORD tlsSignalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT);
			H225_TransportAddress h225Addr = RasServer::Instance()->GetCallSignalAddress(m_call->GetCalledParty()->GetIP());
			SetH225Port(h225Addr, tlsSignalPort);
			H323TransportAddress signalAddr = h225Addr;
			settings.Add(Std22_ConnectionAddress, H460_FeatureContent(signalAddr));
			h46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
			gd.SetSize(2);
			gd[1] = h46022;
		}
#endif

		RasSrv->SendRas(sci_ras, m_call->GetCalledParty()->GetRasAddress(), NULL, m_call->GetCalledParty()->GetH235Authenticators());

		// store Setup
		m_call->StoreSetup(msg);
		m_result = DelayedConnecting;	// don't forward now, wait for endpoint to send Facility
	}
#endif
}

// used for regular calls
bool CallSignalSocket::CreateRemote(H225_Setup_UUIE & setupBody)
{
	if (!m_call->GetDestSignalAddr(peerAddr, peerPort)) {
		PTRACE(3, Type() << "\tINVALID DESTINATION ADDRESS for call from " << Name());
		m_call->SetDisconnectCause(Q931::IncompatibleDestination);
		m_result = Error;
		return false;
	}

	Address calling = GNUGK_INADDR_ANY;
	int nat_type = m_call->GetNATType(calling, peerAddr);

	WORD notused;
	if (!m_call->GetBindHint().IsEmpty() && GetTransportAddress(m_call->GetBindHint(), 0, localAddr, notused)) {
		masqAddr = localAddr;
		PTRACE(5, "Using BindHint=" << localAddr);
	} else {
		localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
		UnmapIPv4Address(localAddr);
		masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
		UnmapIPv4Address(masqAddr);
	}
	// only rewrite sourceCallSignalAddress if we are proxying,
	// otherwise leave the receiving endpoint the option to deal with NATed caller itself
	if (m_call->GetProxyMode() == CallRec::ProxyEnabled
		|| GkConfig()->GetBoolean(RoutedSec, "AlwaysRewriteSourceCallSignalAddress", true)) {
		setupBody.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
		setupBody.m_sourceCallSignalAddress = SocketToH225TransportAddr(masqAddr, GetPort());
	} else {
		// check if we are calling from behind a NAT that no "well meaning" ALG
		// has fiddled with the source address breaking remote NAT detection.
		if (nat_type == CallRec::callingParty
			&& setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress)
			&& setupBody.m_sourceCallSignalAddress.IsValid()) {
			PIPSocket::Address sourceAddr;
			GetIPFromTransportAddr(setupBody.m_sourceCallSignalAddress, sourceAddr);
			if (m_call->GetCallingParty() && (sourceAddr == m_call->GetCallingParty()->GetNATIP())) {
				PTRACE(3, Type() << "\tSignal ALG DETECTED correcting source Address");
				setupBody.m_sourceCallSignalAddress = m_call->GetCallingParty()->GetCallSignalAddress();
			}
		}
	}

	// For compatibility with endpoints which do not support large Setup messages or send incorrect tokens
	if (Toolkit::Instance()->RemoveAllH235Tokens()) {
			PTRACE(3, "Removing H.235 tokens");
			setupBody.m_tokens.SetSize(0);
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_tokens);
			setupBody.m_cryptoTokens.SetSize(0);
			setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);
	}

	// For compatibility to call pre-H323v4 devices that do not support H.460
	// This strips the Feature Advertisements from the PDU.
	if (GkConfig()->GetBoolean(RoutedSec, "RemoveH460Call", false)
#ifdef HAS_H46023
		&& (!m_call->GetCalledParty() || (m_call->GetCalledParty()->GetEPNATType() == (int)EndpointRec::NatUnknown))
#endif
		) {
		   setupBody.RemoveOptionalField(H225_Setup_UUIE::e_desiredFeatures);
		   setupBody.RemoveOptionalField(H225_Setup_UUIE::e_supportedFeatures);
		   setupBody.RemoveOptionalField(H225_Setup_UUIE::e_neededFeatures);

#ifdef HAS_H46023
	} else {
		if (Toolkit::Instance()->IsH46023Enabled() && m_call->GetCalledParty() && !m_call->GetCalledParty()->IsRemote()) {
			// Add NAT offload support to older non supporting Endpoints (>H323v4)
			// This will allow NAT endpoints who support the NAT offload feature
			// to avoid proxying twice (remote and local)
			bool m_calledh46023 = m_call->GetCalledParty()->UsesH46023();

				bool natfound = false;
				PINDEX id = 0;
				H225_ArrayOf_FeatureDescriptor & fsn = setupBody.m_supportedFeatures;
				if (setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
					for (PINDEX i=0; i < fsn.GetSize(); i++) {
						if (fsn[i].m_id == H460_FeatureID(24))  {
							natfound = true;
							id = i;
							break;
						}
					}
				}

				if (m_calledh46023 && !natfound) {
					PTRACE(5, Type() << "Added NAT Support to Outbound Call.");
		            setupBody.IncludeOptionalField(H225_Setup_UUIE::e_supportedFeatures);
					H460_FeatureStd std24 = H460_FeatureStd(24);
					CallRec::NatStrategy strat = m_call->GetNATStrategy();

					if (strat == CallRec::e_natRemoteMaster)     strat = CallRec::e_natLocalMaster;
					else if (strat == CallRec::e_natLocalMaster) strat = CallRec::e_natRemoteMaster;
					else if (strat == CallRec::e_natRemoteProxy) strat = CallRec::e_natLocalProxy;
					else if (strat == CallRec::e_natLocalProxy)  strat = CallRec::e_natRemoteProxy;

					std24.Add(Std24_NATInstruct,H460_FeatureContent((int)strat,8));
					PINDEX lastpos = fsn.GetSize();
					fsn.SetSize(lastpos+1);
					fsn[lastpos] = std24;
				} else if (!m_calledh46023 && natfound) {  // Remove H460.23 from Supported Features.
					for (PINDEX j=id; j < fsn.GetSize()-1; ++j) {
						fsn[j] = fsn[j+1];
					}
					fsn.SetSize(fsn.GetSize()-1);
					if (fsn.GetSize() == 0)
						setupBody.RemoveOptionalField(H225_Setup_UUIE::e_supportedFeatures);
				}
		}
#endif
	}

	PTRACE(3, Type() << "\tCall " << m_call->GetCallNumber() << " is NAT type " << nat_type);
	endptr calledep = m_call->GetCalledParty();
	if (calledep) {
		// m_call->GetCalledParty() should not be null in the case
		if (CallSignalSocket *socket = calledep->GetAndRemoveSocket()) {
			PTRACE(3, Type() << "\tUsing NAT socket " << socket->GetName());

			// it's dangerous if the remote socket has
			// different handler than this
			// so we move this socket to other handler
			GetHandler()->MoveTo(socket->GetHandler(), this);

			// re-add the NAT socket for H.460.17 endpoints
			if (calledep->UsesH46017())
				calledep->SetNATSocket(socket);

			remote = socket;
			socket->SetRemote(this);
			SetConnected(true);
			socket->SetConnected(true);
			m_result = Forwarding;
		}
	}
	if (!remote) {
#ifdef HAS_TLS
		GkClient * gkClient = RasServer::Instance()->GetGkClient();
		if (Toolkit::Instance()->IsTLSEnabled()
			&& (m_call->ConnectWithTLS()
				|| (gkClient && gkClient->CheckFrom(m_call->GetDestSignalAddr()) && gkClient->UseTLS())) ) {
			remote = new TLSCallSignalSocket(this, peerPort);
		} else
#endif // HAS_TLS
		{
			remote = new CallSignalSocket(this, peerPort);
		}
#ifdef HAS_H46018
		if (m_call->GetCalledParty() && m_call->GetCalledParty()->IsTraversalServer()) {
			((CallSignalSocket*)remote)->m_callToTraversalServer = true;
		}
#endif
		m_result = Connecting;
	}

	HandleH245Address(setupBody);
	HandleFastStart(setupBody, true);

#if H225_PROTOCOL_VERSION >= 4
	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_parallelH245Control) && m_h245handler) {
		bool suppress = false;	// ignore for now
		OnTunneledH245(setupBody.m_parallelH245Control, suppress);
	}
#endif
	return true;
}

#ifdef HAS_H46018
// used for calls to traversal clients
bool CallSignalSocket::CreateRemote(const H225_TransportAddress & addr)
{
	if (!GetIPAndPortFromTransportAddr(addr, peerAddr, peerPort)) {
		PTRACE(3, Type() << "\tINVALID DESTINATION ADDRESS for call from " << Name());
		m_result = Error;
		return false;
	}

	localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
	UnmapIPv4Address(localAddr);
    masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
    UnmapIPv4Address(masqAddr);

#ifdef HAS_TLS
	if (Toolkit::Instance()->IsTLSEnabled() && m_call->ConnectWithTLS()) {
		remote = new TLSCallSignalSocket(this, peerPort);
	} else
#endif // HAS_TLS
	{
		remote = new CallSignalSocket(this, peerPort);
	}

	if (!InternalConnectTo()) {
		PTRACE(1, "CreateRemote: InternalConnectTo() failed");
		SNMP_TRAP(10, SNMPWarning, Network, PString() + "Connection failed");
		return false;
	}

	return true;
}

bool CallSignalSocket::IsTraversalClient() const
{
	return ((!m_callerSocket && m_call && m_call->GetCalledParty() && m_call->GetCalledParty()->IsTraversalClient())
		   || (m_callerSocket && m_call && m_call->GetCallingParty() && m_call->GetCallingParty()->IsTraversalClient()));
};

bool CallSignalSocket::IsTraversalServer() const
{
	return ((!m_callerSocket && m_call && m_call->GetCalledParty() && m_call->GetCalledParty()->IsTraversalServer())
		   || (m_callerSocket && m_call && m_call->GetCallingParty() && m_call->GetCallingParty()->IsTraversalServer()));
};
#endif

void CallSignalSocket::OnCallProceeding(SignalingMsg * msg)
{
	CallProceedingMsg * callProceeding = dynamic_cast<CallProceedingMsg*>(msg);
	if (callProceeding == NULL) {
		PTRACE(2, Type() << "\tError: CallProceeding message from " << Name() << " without associated UUIE");
		SNMP_TRAP(9, SNMPError, Network, "CallProceeding from " + GetName() + " has no UUIE");
		m_result = Error;
		return;
	}
	m_callerSocket = false;	// update for persistent H.460.17 sockets where this property can change

	if (callProceeding->GetUUIEBody().GetTag() != H225_H323_UU_PDU_h323_message_body::e_callProceeding)
        return;

	H225_CallProceeding_UUIE & cpBody = callProceeding->GetUUIEBody();

	m_h225Version = GetH225Version(cpBody);

	if (HandleFastStart(cpBody, false))
		msg->SetUUIEChanged();

	if (HandleH245Address(cpBody))
		msg->SetUUIEChanged();

	if (cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_multipleCalls)
			&& cpBody.m_multipleCalls) {
		cpBody.m_multipleCalls = FALSE;
		msg->SetUUIEChanged();
	}
	if (cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_maintainConnection)) {
		cpBody.m_maintainConnection = (GetRemote() && GetRemote()->MaintainConnection());
		msg->SetUUIEChanged();
	}

#ifdef HAS_H46018
#ifdef HAS_H46023
	if (callProceeding->GetUUIE()->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_genericData)) {
		if (FixH46024Multiplexing(callProceeding->GetUUIE()->m_h323_uu_pdu.e_genericData, cpBody.m_featureSet)) {
			cpBody.IncludeOptionalField(H225_CallProceeding_UUIE::e_featureSet);
			callProceeding->GetUUIE()->m_h323_uu_pdu.RemoveOptionalField(H225_H323_UU_PDU::e_genericData);
		}
	}
	bool OZH46024 = (m_call && m_call->GetCalledParty() && m_call->GetCalledParty()->IsRemote() &&
		cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_featureSet) &&
		HasH46024Descriptor(cpBody.m_featureSet.m_supportedFeatures));
#else
		bool OZH46024 = false;
#endif
	if (Toolkit::Instance()->IsH46018Enabled() && !OZH46024) {
		GkClient * gkClient = RasServer::Instance()->GetGkClient();
		// remove H.460.19 descriptor from sender
		if (cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_featureSet)) {
			bool isH46019Client = false;
			bool senderSupportsH46019Multiplexing = false;
			RemoveH46019Descriptor(cpBody.m_featureSet.m_supportedFeatures, senderSupportsH46019Multiplexing, isH46019Client);
			// ignore if the .19 descriptor isn't from an endpoint that uses H.460.17 or .18
			PIPSocket::Address _peerAddr;
			WORD _peerPort = 0;
			GetPeerAddress(_peerAddr, _peerPort);
			UnmapIPv4Address(_peerAddr);
			if ( (m_call && m_call->GetCalledParty()
				&& (m_call->GetCalledParty()->UsesH46017() || m_call->GetCalledParty()->GetTraversalRole() != None)
				&& !m_call->GetCalledParty()->UsesH46026() )
				|| RasServer::Instance()->IsCallFromTraversalClient(_peerAddr) || RasServer::Instance()->IsCallFromTraversalServer(_peerAddr)
				|| (gkClient && gkClient->CheckFrom(m_call->GetDestSignalAddr()) && gkClient->UsesH46018()) ) {
				// set traversal role for called party (needed for H.460.17, doesn't hurt H.460.18)
				H245ProxyHandler * proxyhandler = dynamic_cast<H245ProxyHandler *>(m_h245handler);
				if (isH46019Client && proxyhandler) {
					proxyhandler->SetTraversalRole(TraversalClient);
					if (m_call && m_call->GetCalledParty()) {
						m_call->GetCalledParty()->SetTraversalRole(TraversalClient);
					}
				}
				if (senderSupportsH46019Multiplexing && proxyhandler)
					proxyhandler->SetRequestRTPMultiplexing(true);
			}
			if (cpBody.m_featureSet.m_supportedFeatures.GetSize() == 0)
				cpBody.m_featureSet.RemoveOptionalField(H225_FeatureSet::e_supportedFeatures);
			if (!cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)
				&& !cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)
				&& !cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_desiredFeatures)) {
				cpBody.RemoveOptionalField(H225_CallProceeding_UUIE::e_featureSet);
			}
		}
		if (m_call && ((m_call->GetCallingParty() && (m_call->GetCallingParty()->GetTraversalRole() != None))
				|| (m_call->IsFromParent() && gkClient && gkClient->UsesH46018()) ) ) {
			H460_FeatureStd feat = H460_FeatureStd(19);
			if (m_call->GetCallingParty() && m_call->GetCallingParty()->IsTraversalClient()) {
				H460_FeatureID feat_id(2);	// mediaTraversalServer
				feat.AddParameter(&feat_id);
			}
			if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)) {
				H460_FeatureID feat_id(1);	// supportTransmitMultiplexedMedia
				feat.AddParameter(&feat_id);
			}
			// add H.460.19 indicator to CallProceeding
			if (!cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_featureSet))
				cpBody.IncludeOptionalField(H225_CallProceeding_UUIE::e_featureSet);
			if (!cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)) {
				cpBody.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				cpBody.m_featureSet.m_supportedFeatures.SetSize(0);
			}
			AddH460Feature(cpBody.m_featureSet.m_supportedFeatures, feat);
		}
		msg->SetUUIEChanged();
	}
#endif
#ifdef HAS_H46026
	// remove H.460.26 descriptor from sender
	if (cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_featureSet)) {
		// spec say it should be in neededFeatures
		if (cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)) {
			RemoveH460Descriptor(26, cpBody.m_featureSet.m_neededFeatures);
		}
		// but CP is sent before ACF decides if it is really used, so H323Plus sends it in supportedFeatures
		if (cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)) {
			RemoveH460Descriptor(26, cpBody.m_featureSet.m_supportedFeatures);
		}
	}

	if (m_call && m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46026())
	{
		H460_FeatureStd feat = H460_FeatureStd(26);
		// add H.460.26 indicator to CallProceeding
		if (!cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_featureSet))
			cpBody.IncludeOptionalField(H225_CallProceeding_UUIE::e_featureSet);
		if (!cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)) {
			cpBody.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_neededFeatures);
			cpBody.m_featureSet.m_neededFeatures.SetSize(0);
		}
		AddH460Feature(cpBody.m_featureSet.m_neededFeatures, feat);
		msg->SetUUIEChanged();
	}
#endif
	// remove featureSet if needed/supported/desired are empty
	if (cpBody.HasOptionalField(H225_CallProceeding_UUIE::e_featureSet)) {
		if (cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)
			&& cpBody.m_featureSet.m_neededFeatures.GetSize() == 0) {
			cpBody.m_featureSet.RemoveOptionalField(H225_FeatureSet::e_neededFeatures);
		}
		if (cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)
			&& cpBody.m_featureSet.m_supportedFeatures.GetSize() == 0) {
			cpBody.m_featureSet.RemoveOptionalField(H225_FeatureSet::e_supportedFeatures);
		}
		if (cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_desiredFeatures)
			&& cpBody.m_featureSet.m_desiredFeatures.GetSize() == 0) {
			cpBody.m_featureSet.RemoveOptionalField(H225_FeatureSet::e_desiredFeatures);
		}
		if (!cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)
			&& !cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)
			&& !cpBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_desiredFeatures)) {
			cpBody.RemoveOptionalField(H225_CallProceeding_UUIE::e_featureSet);
		}
	}

	if (m_call) {
		if (m_call->IsProceedingSent()) {
			// translate 2nd CallProceeding to Facility or Progress
			PTRACE(2, Type() << "\tTranslate CallProceeding to Facility/Progress");
			Q931 q931;
			H225_H323_UserInformation uuie;
			if (msg->GetUUIE()->m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_callProceeding)
                return;
			H225_CallProceeding_UUIE & cp_uuie = msg->GetUUIE()->m_h323_uu_pdu.m_h323_message_body;
			if ((cp_uuie.HasOptionalField(H225_CallProceeding_UUIE::e_fastStart)
				|| cp_uuie.HasOptionalField(H225_CallProceeding_UUIE::e_fastConnectRefused))
				&& (m_h225Version >= 2)) {
				BuildProgressPDU(q931, msg->GetQ931().IsFromDestination());
				GetUUIE(q931, uuie);
				H225_Progress_UUIE & progress_uuie = uuie.m_h323_uu_pdu.m_h323_message_body;
				progress_uuie.m_protocolIdentifier = cp_uuie.m_protocolIdentifier;
				if (msg->GetQ931().HasIE(Q931::DisplayIE))
					q931.SetIE(Q931::DisplayIE, msg->GetQ931().GetIE(Q931::DisplayIE));
				// copy over H.245 elements
				if (cp_uuie.HasOptionalField(H225_CallProceeding_UUIE::e_fastStart)) {
					progress_uuie.IncludeOptionalField(H225_Progress_UUIE::e_fastStart);
					progress_uuie.m_fastStart = cp_uuie.m_fastStart;
				}
				if (cp_uuie.HasOptionalField(H225_CallProceeding_UUIE::e_fastConnectRefused)) {
					progress_uuie.IncludeOptionalField(H225_Progress_UUIE::e_fastConnectRefused);
				}
			} else {
				BuildFacilityPDU(q931, H225_FacilityReason::e_transportedInformation);
				GetUUIE(q931, uuie);
				H225_Facility_UUIE & facility_uuie = uuie.m_h323_uu_pdu.m_h323_message_body;
				facility_uuie.m_protocolIdentifier = cp_uuie.m_protocolIdentifier;
				if (msg->GetQ931().HasIE(Q931::DisplayIE))
					q931.SetIE(Q931::DisplayIE, msg->GetQ931().GetIE(Q931::DisplayIE));
				if (m_h225Version > 0 && m_h225Version < 4)
					uuie.m_h323_uu_pdu.m_h323_message_body.SetTag(H225_H323_UU_PDU_h323_message_body::e_empty);
			}
			uuie.m_h323_uu_pdu.m_h245Tunneling = (GetRemote() && GetRemote()->IsH245Tunneling());
			msg->GetQ931() = q931;
			*msg->GetUUIE() = uuie;
			msg->SetUUIEChanged();
		}
		else
			m_call->SetProceedingSent(true);
	}
}

void CallSignalSocket::OnConnect(SignalingMsg *msg)
{
	ConnectMsg *connect = dynamic_cast<ConnectMsg*>(msg);
	if (connect == NULL) {
		PTRACE(2, Type() << "\tError: Connect message from " << Name() << " without associated UUIE");
		SNMP_TRAP(9, SNMPError, Network, "Connect from " + GetName() + " has no UUIE");
		m_result = Error;
		return;
	}
	m_callerSocket = false;	// update for persistent H.460.17 sockets where this property can change

	H225_Connect_UUIE & connectBody = connect->GetUUIEBody();

	m_h225Version = GetH225Version(connectBody);

	// store called party vendor info
	if (connectBody.m_destinationInfo.HasOptionalField(H225_EndpointType::e_vendor)) {
		PString vendor, version;
		if (connectBody.m_destinationInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_productId)) {
			vendor = connectBody.m_destinationInfo.m_vendor.m_productId.AsString();
		}
		if (connectBody.m_destinationInfo.m_vendor.HasOptionalField(H225_VendorIdentifier::e_versionId)) {
			version = connectBody.m_destinationInfo.m_vendor.m_versionId.AsString();
		}
		if (m_call) {
			m_call->SetCalledVendor(vendor, version);
			int mode = Toolkit::Instance()->SelectRoutingVendorMode(vendor + " " + version);
			switch (mode) {
				case CallRec::SignalRouted:
					// Don't worry about signal routed because we are already doing it.
					break;
				case CallRec::H245Routed:
					m_call->SetH245Routed(true);
					break;
				case CallRec::Proxied:
					m_call->SetProxyMode(CallRec::ProxyEnabled);
					m_call->SetH245Routed(true);
					PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled (Vendor Info)");
					break;
				default:
					// leave as default
					break;
			}
		}
	}

	if (m_call) {
		m_call->SetConnected();
		RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctConnect, m_call);
	}

	if (HandleFastStart(connectBody, false))
		msg->SetUUIEChanged();

	if (HandleH245Address(connectBody))
		msg->SetUUIEChanged();

	if (connectBody.HasOptionalField(H225_Connect_UUIE::e_multipleCalls)
			&& connectBody.m_multipleCalls) {
		connectBody.m_multipleCalls = FALSE;
		msg->SetUUIEChanged();
	}
	if (connectBody.HasOptionalField(H225_Connect_UUIE::e_maintainConnection)) {
		connectBody.m_maintainConnection = (GetRemote() && GetRemote()->MaintainConnection());
		msg->SetUUIEChanged();
	}

	// For compatibility with endpoints which do not support large Setup messages or send incorrect tokens
	PIPSocket::Address msgSource;
	msg->GetPeerAddr(msgSource);
	if (Toolkit::Instance()->RemoveH235TokensFrom(msgSource)) {
		PTRACE(3, "Removing H.235 tokens");
		connectBody.m_tokens.SetSize(0);
		connectBody.RemoveOptionalField(H225_Connect_UUIE::e_tokens);
		connectBody.m_cryptoTokens.SetSize(0);
		connectBody.RemoveOptionalField(H225_Connect_UUIE::e_cryptoTokens);
	}

#ifdef HAS_H235_MEDIA
	if (Toolkit::Instance()->IsH235HalfCallMediaEnabled()) {
		H235Authenticators & auth = m_call->GetAuthenticators();
		if (m_call && (m_call->GetEncryptDirection() == CallRec::calledParty)
		  && connectBody.HasOptionalField(H225_Connect_UUIE::e_tokens) && SupportsH235Media(connectBody.m_tokens)) {
			// there were tokens in the Setup and now in the Connect, then our help isn't needed
			PTRACE(4, "H235\tMedia Encrypted End to End : No Assistance");
			m_call->GetAuthenticators().SetSize(0);
			m_call->SetMediaEncryption(CallRec::none);
		} else if ((m_call && m_call->GetEncryptDirection() == CallRec::calledParty)
		  && !connectBody.HasOptionalField(H225_Connect_UUIE::e_tokens)) {
			// there were tokens in Setup, but none in Connect

			auth.PrepareSignalPDU(H225_H323_UU_PDU_h323_message_body::e_connect,
								  connectBody.m_tokens, connectBody.m_cryptoTokens);

//			// validate the tokens we just generated (pretend they are received tokens)
//			PBYTEArray nonce;
//			auth.ValidateSignalPDU(H225_H323_UU_PDU_h323_message_body::e_connect,
//						   connectBody.m_tokens, connectBody.m_cryptoTokens, nonce);

			connectBody.RemoveOptionalField(H225_Connect_UUIE::e_cryptoTokens);
			connectBody.IncludeOptionalField(H225_Connect_UUIE::e_tokens);
			msg->SetUUIEChanged();
			PTRACE(3, "H235\tMedia Encrypted Support added for Called Party");
			m_call->SetProxyMode(CallRec::ProxyEnabled);
			PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled (H.235 HalfCallMedia)");

		} else if (m_call && (m_call->GetEncryptDirection() == CallRec::none)
			&& !connectBody.HasOptionalField(H225_Connect_UUIE::e_tokens)) {
			// no tokens in Setup and none in Connect
			m_call->GetAuthenticators().SetSize(0);
			m_call->SetMediaEncryption(CallRec::none);
			PTRACE(3, "H235\tNo Media Encryption Support Detected: Disabling!");
			if (Toolkit::Instance()->Config()->GetBoolean(RoutedSec, "RequireH235HalfCallMedia", false)) {
				PTRACE(1, "H235\tDiconnection call because of missing H.235 support");
				m_call->SetDisconnectCause(Q931::NormalUnspecified); //Q.931 code for reason=SecurityDenied
				m_result = Error;
				return;
			}

		} else if (m_call && (m_call->GetEncryptDirection() == CallRec::none)
		  && connectBody.HasOptionalField(H225_Connect_UUIE::e_tokens) && SupportsH235Media(connectBody.m_tokens)) {
			// there were no tokens in Setup (but we added some), but there are in Connect

			// make sure crypto token fields are pesent, at least with 0 size
			if (!connectBody.HasOptionalField(H225_Connect_UUIE::e_cryptoTokens)) {
				connectBody.IncludeOptionalField(H225_Connect_UUIE::e_cryptoTokens);
				connectBody.m_cryptoTokens.SetSize(0);
			}

			PBYTEArray nonce;
			auth.ValidateSignalPDU(H225_H323_UU_PDU_h323_message_body::e_connect,
						   connectBody.m_tokens, connectBody.m_cryptoTokens, nonce);

			connectBody.RemoveOptionalField(H225_Connect_UUIE::e_cryptoTokens);
			connectBody.RemoveOptionalField(H225_Connect_UUIE::e_tokens);

			m_call->SetMediaEncryption(CallRec::callingParty);
			msg->SetUUIEChanged();
			PTRACE(3, "H235\tMedia Encrypted Support added for Calling Party");
			m_call->SetProxyMode(CallRec::ProxyEnabled);
			PTRACE(3, "GK\tCall " << m_call->GetCallNumber() << " proxy enabled (H.235 HalfCallMedia)");

		} else {
			PTRACE(1, "H235\tLogic error, this shouldn't happen...");
		}
    }
#endif

#ifdef HAS_H46018
#ifdef HAS_H46023
	if (connect->GetUUIE()->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_genericData)) {
		if (FixH46024Multiplexing(connect->GetUUIE()->m_h323_uu_pdu.e_genericData, connectBody.m_featureSet)) {
			connectBody.IncludeOptionalField(H225_Connect_UUIE::e_featureSet);
			connect->GetUUIE()->m_h323_uu_pdu.RemoveOptionalField(H225_H323_UU_PDU::e_genericData);
		}
	}
	bool OZH46024 = (m_call && m_call->GetCalledParty() && m_call->GetCalledParty()->IsRemote() &&
		connectBody.HasOptionalField(H225_Connect_UUIE::e_featureSet) &&
		HasH46024Descriptor(connectBody.m_featureSet.m_supportedFeatures));
#else
	bool OZH46024 = false;
#endif
	if (m_call && m_call->H46019Required() && Toolkit::Instance()->IsH46018Enabled() && !OZH46024) {
		GkClient * gkClient = RasServer::Instance()->GetGkClient();
		// remove H.460.19 descriptor from sender
		if (connectBody.HasOptionalField(H225_Connect_UUIE::e_featureSet)) {
			bool isH46019Client = false;
			bool senderSupportsH46019Multiplexing = false;
			RemoveH46019Descriptor(connectBody.m_featureSet.m_supportedFeatures, senderSupportsH46019Multiplexing, isH46019Client);
            // enable TCP keep-alives for calls from traversal servers or neighbors
            if (!isH46019Client) {
                bool h46017 = m_call && m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46017();
                if (!h46017) {
                    PTRACE(5, "H46018\tEnable keep-alive for outgoing H.460.18 call to traversal server/neighbor");
                    RegisterKeepAlive(GkConfig()->GetInteger(RoutedSec, "H46018KeepAliveInterval", 19));
                }
            }
			// ignore if the .19 descriptor isn't from an endpoint that uses H.460.17 or .18
			PIPSocket::Address _peerAddr;
			WORD _peerPort = 0;
			GetPeerAddress(_peerAddr, _peerPort);
			UnmapIPv4Address(_peerAddr);
			if ( (m_call && m_call->GetCalledParty()
					&& (m_call->GetCalledParty()->UsesH46017() || m_call->GetCalledParty()->GetTraversalRole() != None)
					&& !m_call->GetCalledParty()->UsesH46026() )
				|| RasServer::Instance()->IsCallFromTraversalClient(_peerAddr) || RasServer::Instance()->IsCallFromTraversalServer(_peerAddr)
				|| (gkClient && gkClient->CheckFrom(m_call->GetDestSignalAddr()) && gkClient->UsesH46018()) ) {
				// set traversal role for called party (needed for H.460.17, doesn't hurt H.460.18)
				H245ProxyHandler * proxyhandler = dynamic_cast<H245ProxyHandler*>(m_h245handler);
				if (isH46019Client && proxyhandler) {
					proxyhandler->SetTraversalRole(TraversalClient);
					if (m_call->GetCalledParty()) {
						m_call->GetCalledParty()->SetTraversalRole(TraversalClient);
					}
				}
				if (senderSupportsH46019Multiplexing && proxyhandler)
					proxyhandler->SetRequestRTPMultiplexing(true);
			}
			if (connectBody.m_featureSet.m_supportedFeatures.GetSize() == 0)
				connectBody.m_featureSet.RemoveOptionalField(H225_FeatureSet::e_supportedFeatures);
			if (!connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)
				&& !connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)
				&& !connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_desiredFeatures)) {
				connectBody.RemoveOptionalField(H225_Connect_UUIE::e_featureSet);
			}
		}
		if (m_call && ((m_call->GetCallingParty() && (m_call->GetCallingParty()->GetTraversalRole() != None))
				|| (m_call->IsFromParent() && gkClient && gkClient->UsesH46018()) ) ) {
			// add H.460.19 indicator
			H460_FeatureStd feat = H460_FeatureStd(19);
			if (m_call->GetCallingParty() && m_call->GetCallingParty()->IsTraversalClient()) {
				H460_FeatureID feat_id(2);	// mediaTraversalServer
				feat.AddParameter(&feat_id);
			}
			if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)) {
				H460_FeatureID feat_id(1);	// supportTransmitMultiplexedMedia
				feat.AddParameter(&feat_id);
			}
			if (!connectBody.HasOptionalField(H225_Connect_UUIE::e_featureSet))
				connectBody.IncludeOptionalField(H225_Connect_UUIE::e_featureSet);
			if (!connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)) {
				connectBody.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				connectBody.m_featureSet.m_supportedFeatures.SetSize(0);
			}
			AddH460Feature(connectBody.m_featureSet.m_supportedFeatures, feat);
		}
		msg->SetUUIEChanged();
	}
#endif
#ifdef HAS_H46026
	// remove H.460.26 descriptor from sender
	if (connectBody.HasOptionalField(H225_Connect_UUIE::e_featureSet)
		&& connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)) {
		unsigned unused = 0;
		if (FindH460Descriptor(26, connectBody.m_featureSet.m_neededFeatures, unused)) {
			// must reset .19 for called party, CP might have set it before UsesH46026() was set in 2nd ARQ
			H245ProxyHandler * proxyhandler = dynamic_cast<H245ProxyHandler*>(m_h245handler);
			if (proxyhandler) {
				proxyhandler->SetTraversalRole(None);
				proxyhandler->SetRequestRTPMultiplexing(false);
				proxyhandler->SetUsesH46026(true);
			}
			if (m_call->GetCalledParty()) {
				m_call->GetCalledParty()->SetTraversalRole(None);
				m_call->GetCalledParty()->SetUsesH46026(true);
			}

			RemoveH460Descriptor(26, connectBody.m_featureSet.m_neededFeatures);
		}
	}

	if (m_call && m_call->GetCallingParty()
		&& m_call->GetCallingParty()->UsesH46026())
	{
		// add H.460.26 descriptor for receiver
		H460_FeatureStd feat = H460_FeatureStd(26);
		if (!connectBody.HasOptionalField(H225_Connect_UUIE::e_featureSet))
			connectBody.IncludeOptionalField(H225_Connect_UUIE::e_featureSet);
		if (!connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)) {
			connectBody.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_neededFeatures);
			connectBody.m_featureSet.m_neededFeatures.SetSize(0);
		}
		AddH460Feature(connectBody.m_featureSet.m_neededFeatures, feat);
	    msg->SetUUIEChanged();
	}
#endif

	// remove featureSet if needed/supported/desired are empty
	if (connectBody.HasOptionalField(H225_Connect_UUIE::e_featureSet)) {
		if (connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)
			&& connectBody.m_featureSet.m_neededFeatures.GetSize() == 0) {
			connectBody.m_featureSet.RemoveOptionalField(H225_FeatureSet::e_neededFeatures);
		}
		if (connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)
			&& connectBody.m_featureSet.m_supportedFeatures.GetSize() == 0) {
			connectBody.m_featureSet.RemoveOptionalField(H225_FeatureSet::e_supportedFeatures);
		}
		if (connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_desiredFeatures)
			&& connectBody.m_featureSet.m_desiredFeatures.GetSize() == 0) {
			connectBody.m_featureSet.RemoveOptionalField(H225_FeatureSet::e_desiredFeatures);
		}
		if (!connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)
			&& !connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)
			&& !connectBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_desiredFeatures)) {
			connectBody.RemoveOptionalField(H225_Connect_UUIE::e_featureSet);
		}
	}

	SendPostDialDigits();	// 1st check, for tunneled H.245 connections
}

void CallSignalSocket::OnAlerting(SignalingMsg* msg)
{
	if (!m_call)
		return;

	m_call->SetAlertingTime(time(NULL));

	AlertingMsg * alerting = dynamic_cast<AlertingMsg*>(msg);
	if (alerting == NULL) {
		PTRACE(2, Type() << "\tError: Alerting message from " << Name() << " without associated UUIE");
		SNMP_TRAP(9, SNMPError, Network, "Alerting from " + GetName() + " has no UUIE");
		m_result = Error;
		return;
	}
	m_callerSocket = false;	// update for persistent H.460.17 sockets where this property can change

	H225_Alerting_UUIE & alertingBody = alerting->GetUUIEBody();

	m_h225Version = GetH225Version(alertingBody);

	RasServer::Instance()->LogAcctEvent(GkAcctLogger::AcctAlert, m_call);	// ignore success/failure

	if (HandleFastStart(alertingBody, false))
		msg->SetUUIEChanged();

	if (HandleH245Address(alertingBody))
		msg->SetUUIEChanged();

	if (alertingBody.HasOptionalField(H225_Alerting_UUIE::e_multipleCalls)
			&& alertingBody.m_multipleCalls) {
		alertingBody.m_multipleCalls = FALSE;
		msg->SetUUIEChanged();
	}
	if (alertingBody.HasOptionalField(H225_Alerting_UUIE::e_maintainConnection)) {
		alertingBody.m_maintainConnection = (GetRemote() && GetRemote()->MaintainConnection());
		msg->SetUUIEChanged();
	}

#ifdef HAS_H46018
#ifdef HAS_H46023
	if (alerting->GetUUIE()->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_genericData)) {
		if (FixH46024Multiplexing(alerting->GetUUIE()->m_h323_uu_pdu.e_genericData, alertingBody.m_featureSet)) {
			alertingBody.IncludeOptionalField(H225_Alerting_UUIE::e_featureSet);
			alerting->GetUUIE()->m_h323_uu_pdu.RemoveOptionalField(H225_H323_UU_PDU::e_genericData);
		}
	}
	bool OZH46024 = (m_call && m_call->GetCalledParty() && m_call->GetCalledParty()->IsRemote() &&
					alertingBody.HasOptionalField(H225_Alerting_UUIE::e_featureSet) &&
					HasH46024Descriptor(alertingBody.m_featureSet.m_supportedFeatures));
#else
	bool OZH46024 = false;
#endif
	if (m_call && m_call->H46019Required() && Toolkit::Instance()->IsH46018Enabled() && !OZH46024) {
		GkClient * gkClient = RasServer::Instance()->GetGkClient();
		// remove H.460.19 descriptor from sender
		if (alertingBody.HasOptionalField(H225_Alerting_UUIE::e_featureSet)) {
			bool isH46019Client = false;
			bool senderSupportsH46019Multiplexing = false;
			RemoveH46019Descriptor(alertingBody.m_featureSet.m_supportedFeatures, senderSupportsH46019Multiplexing, isH46019Client);
			// ignore if the .19 descriptor isn't from an endpoint that uses H.460.17 or .18
			PIPSocket::Address _peerAddr;
			WORD _peerPort = 0;
			GetPeerAddress(_peerAddr, _peerPort);
			UnmapIPv4Address(_peerAddr);
			if ( (m_call && m_call->GetCalledParty()
					&& (m_call->GetCalledParty()->UsesH46017() || m_call->GetCalledParty()->GetTraversalRole() != None)
					&& !m_call->GetCalledParty()->UsesH46026() )
				|| RasServer::Instance()->IsCallFromTraversalClient(_peerAddr) || RasServer::Instance()->IsCallFromTraversalServer(_peerAddr)
				|| (gkClient && gkClient->CheckFrom(m_call->GetDestSignalAddr()) && gkClient->UsesH46018()) ) {
				// set traversal role for called party (needed for H.460.17, doesn't hurt H.460.18)
				H245ProxyHandler * proxyhandler = dynamic_cast<H245ProxyHandler *>(m_h245handler);
				if (isH46019Client && proxyhandler) {
					proxyhandler->SetTraversalRole(TraversalClient);
					if (m_call->GetCalledParty()) {
						m_call->GetCalledParty()->SetTraversalRole(TraversalClient);
					}
				}
				if (senderSupportsH46019Multiplexing && proxyhandler) {
					proxyhandler->SetRequestRTPMultiplexing(true);
				}
			}
			if (alertingBody.m_featureSet.m_supportedFeatures.GetSize() == 0)
				alertingBody.m_featureSet.RemoveOptionalField(H225_FeatureSet::e_supportedFeatures);
			if (!alertingBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)
				&& !alertingBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)
				&& !alertingBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_desiredFeatures)) {
				alertingBody.RemoveOptionalField(H225_Alerting_UUIE::e_featureSet);
			}
		}
		if (m_call && ((m_call->GetCallingParty() && (m_call->GetCallingParty()->GetTraversalRole() != None))
				|| (m_call->IsFromParent() && gkClient && gkClient->UsesH46018()) ) ) {
			// add H.460.19 indicator
			H460_FeatureStd feat = H460_FeatureStd(19);
			if (m_call->GetCallingParty() && m_call->GetCallingParty()->IsTraversalClient()) {
				H460_FeatureID feat_id(2);	// mediaTraversalServer
				feat.AddParameter(&feat_id);
			}
			if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)) {
				H460_FeatureID feat_id(1);	// supportTransmitMultiplexedMedia
				feat.AddParameter(&feat_id);
			}
			if (!alertingBody.HasOptionalField(H225_Alerting_UUIE::e_featureSet))
				alertingBody.IncludeOptionalField(H225_Alerting_UUIE::e_featureSet);
			if (!alertingBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)) {
				alertingBody.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				alertingBody.m_featureSet.m_supportedFeatures.SetSize(0);
			}
			AddH460Feature(alertingBody.m_featureSet.m_supportedFeatures, feat);
		}
		msg->SetUUIEChanged();
	}
#endif
#ifdef HAS_H46026
	// remove H.460.26 descriptor from sender
	if (alertingBody.HasOptionalField(H225_Alerting_UUIE::e_featureSet)
		&& alertingBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)) {
		RemoveH460Descriptor(26, alertingBody.m_featureSet.m_neededFeatures);
	}

	if (m_call && m_call->GetCallingParty()
		&& m_call->GetCallingParty()->UsesH46026())
	{
		// add H.460.26 descriptor for receiver
		H460_FeatureStd feat = H460_FeatureStd(26);
		if (!alertingBody.HasOptionalField(H225_Alerting_UUIE::e_featureSet))
			alertingBody.IncludeOptionalField(H225_Alerting_UUIE::e_featureSet);
		if (!alertingBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_neededFeatures)) {
			alertingBody.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_neededFeatures);
			alertingBody.m_featureSet.m_neededFeatures.SetSize(0);
		}
		AddH460Feature(alertingBody.m_featureSet.m_neededFeatures, feat);
	    msg->SetUUIEChanged();
	}
#endif
}


#ifdef HAS_H46026
PBoolean ReadRTPFrame(const Q931 & q931, H46026_UDPFrame & data)
{
    H225_H323_UserInformation uuie;
    if (!GetUUIE(q931, uuie)) {
        PTRACE(2,"H46026\tError decoding Media PDU");
        return false;
    }

    // sanity checks
    if ((!uuie.m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_genericData)) ||
        (uuie.m_h323_uu_pdu.m_genericData.GetSize() == 0) ||
        (!uuie.m_h323_uu_pdu.m_genericData[0].HasOptionalField(H225_GenericData::e_parameters)) ||
        (uuie.m_h323_uu_pdu.m_genericData[0].m_parameters.GetSize() == 0) ||
        (!uuie.m_h323_uu_pdu.m_genericData[0].m_parameters[0].HasOptionalField(H225_EnumeratedParameter::e_content))
        ) {
            //PTRACE(2,"H46026\tERROR Non-Media Frame structure"); // or simply a Information message with a different purpose
            return false;
    }
    H225_GenericIdentifier & id = uuie.m_h323_uu_pdu.m_genericData[0].m_id;
    if (id.GetTag() != H225_GenericIdentifier::e_standard) {
        PTRACE(2,"H46026\tERROR Bad Media Frame ID");
        return false;
    }
    PASN_Integer & asnInt = id;
    if (asnInt.GetValue() != 26) {
        PTRACE(2,"H46026\tERROR Wrong Media Frame ID " << asnInt.GetValue());
        return false;
    }
    H225_GenericIdentifier & pid = uuie.m_h323_uu_pdu.m_genericData[0].m_parameters[0].m_id;
    if (id.GetTag() != H225_GenericIdentifier::e_standard) {
        PTRACE(2,"H46026\tERROR BAD Media Parameter ID");
        return false;
    }
    PASN_Integer & pInt = pid;
    if (pInt.GetValue() != 1) {
        PTRACE(2,"H46026\tERROR Wrong Media Parameter ID " << pInt.GetValue());
        return false;
    }

    // Get the RTP Payload
    PASN_OctetString & val = uuie.m_h323_uu_pdu.m_genericData[0].m_parameters[0].m_content;
    if (!val.DecodeSubType(data)) {
        PTRACE(2,"H46026\tERROR Decoding Media Frame");
        return false;
    }

    return true;
}
#endif


void CallSignalSocket::OnInformation(SignalingMsg * msg)
{
	Q931 & q931 = msg->GetQ931();

#ifdef HAS_H46026
	// handle H.460.26 RTP frames and forward as regular or mux RTP if only 1 party uses H.460.26
	bool callerUsesH46026 = (m_call && m_call->GetCallingParty() && m_call->GetCallingParty()->UsesH46026());
	bool calledUsesH46026 = (m_call && m_call->GetCalledParty() && m_call->GetCalledParty()->UsesH46026());

	if (callerUsesH46026 || calledUsesH46026) {
		H46026_UDPFrame data;
		if (ReadRTPFrame(q931, data)) {
			PTRACE(4, "H46026\tUnpacking H.460.26 RTP packet");
			// handle media encryption

#ifdef HAS_H235_MEDIA
			if (data.m_dataFrame && m_call->IsMediaEncryption()) {
				H46026Session session = H46026RTPHandler::Instance()->FindSession(m_call->GetCallNumber(), data.m_sessionId.GetValue());
				if (session.IsValid()) {
					for (PINDEX i = 0; i < data.m_frame.GetSize(); i++) {
						PASN_OctetString & bytes = data.m_frame[i];
						WORD wlen = bytes.GetSize();
						bool succesful = false;
						unsigned char ivSequence[6];
						BYTE payloadType = UNDEFINED_PAYLOAD_TYPE;
						bool rtpPadding = false;
						if (wlen >= 1)
							rtpPadding = bytes[0] & 0x20;
						if (wlen >= 2)
							payloadType = bytes[1] & 0x7f;
						if (wlen >= 8)
							memcpy(ivSequence, bytes.GetPointer() + 2, 6);

						bool encrypting = (m_callerSocket && m_call->GetEncryptDirection() == CallRec::callingParty)
							|| (!m_callerSocket && m_call->GetEncryptDirection() == CallRec::calledParty);
						if (encrypting) {
							if (session.m_encryptingLC) {
								bytes.SetSize(DEFAULT_PACKET_BUFFER_SIZE);	// data may grow when encrypting
								succesful = session.m_encryptingLC->ProcessH235Media(bytes.GetPointer(), wlen, true, ivSequence, rtpPadding, payloadType);
							}
						} else {
							if (session.m_decryptingLC) {
								succesful = session.m_decryptingLC->ProcessH235Media(bytes.GetPointer(), wlen, false, ivSequence, rtpPadding, payloadType);
							}
						}
						if (!succesful) {
							PTRACE(1, "H235\t" << (encrypting ? "En" : "De") << "crypting H.460.26 packet failed");
							continue;
						}

						// update RTP padding bit
						if (rtpPadding)
							bytes[0] |= 0x20;
						else
							bytes[0] &= 0xdf;
						// update payload type, preserve marker bit
						bytes[1] = (bytes[1] & 0x80) | (payloadType & 0x7f);

						bytes.SetSize(wlen);
					}
				}
				msg->SetChanged();
			}
#endif

			// handle RTCP stats
			if (GkConfig()->GetBoolean(ProxySection, "EnableRTCPStats", false)) {
				PIPSocket::Address _peerAddr;
				WORD _peerPort = 0;
				GetPeerAddress(_peerAddr, _peerPort);
				UnmapIPv4Address(_peerAddr);

				for (PINDEX i = 0; i < data.m_frame.GetSize(); i++) {
					PASN_OctetString & bytes = data.m_frame[i];
					if (!data.m_dataFrame) {
						ParseRTCP(m_call, data.m_sessionId, _peerAddr, bytes.GetPointer(), bytes.GetSize());
					}
				}
			}

			if ((callerUsesH46026 && !calledUsesH46026) || (!callerUsesH46026 && calledUsesH46026)) {
				// convert to RTP or RTP mux
#ifdef HAS_H46018
				// check if its a multiplexed RTP destination
				if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)
					&& MultiplexedRTPHandler::Instance()->HandlePacket(m_call->GetCallNumber(), data)) {
					m_result = NoData;	// forwarded as RTP
					return;
				}
#endif
				// plain RTP
				H46026RTPHandler::Instance()->HandlePacket(m_call->GetCallNumber(), data);

				m_result = NoData;	// forwarded as RTP
				return;
			}
		}
	}
#endif

	if (remote != NULL)
		return;

	m_result = m_call ? Forwarding : NoData;

    // If NAT support disabled then ignore the message.
	if (!Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "SupportNATedEndpoints", "0")))
		return;

	// If calling NAT support disabled then ignore the message.
	// Use this to block errant gateways that don't support NAT mechanism properly.
	if (!Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "SupportCallingNATedEndpoints", "1")))
		return;

	// look for GnuGk NAT messages, ignore everything else
	if (!q931.HasIE(Q931::FacilityIE))
		return;

	PWaitAndSignal m(infomutex);

	PBYTEArray buf = q931.GetIE(Q931::FacilityIE);
	if (buf.GetSize() > 0) {
		H225_EndpointIdentifier id;
		PString epid((const char *)buf.GetPointer(), buf.GetSize());
		id = epid;
		PTRACE(3, Type() << "\t" << GetName() << " NAT Information message from EPID = " << epid);
		endptr ep = RegistrationTable::Instance()->FindByEndpointId(id);
		if ((ep) && (!ep->IsNATed()))	// Fix for poor or bad implementations which send Facility message
			return;						// without checking the RCF message first

		if (q931.HasIE(Q931::CallStateIE)) {
			buf = q931.GetIE(Q931::CallStateIE);
			if (buf.GetSize() > 0 && buf[0] == Q931::CallState_DisconnectRequest) {
				if (ep) {
					CallSignalSocket *natsocket = ep->GetAndRemoveSocket();
					if (natsocket != NULL && natsocket != this) {
						natsocket->SetDeletable();
						natsocket->Close();
					}
					SetDeletable();
					PTRACE(3, Type() << "\tRequest to close NAT socket " << GetName());
				}
				Close();
			} else if (ep) {
				m_isnatsocket = true;
				ep->SetNATSocket(this);
				SetConnected(true); // avoid the socket be deleted
			}
			m_result = NoData;
		}
	}
}

#if H323_H450
bool CallSignalSocket::OnH450PDU(H225_ArrayOf_PASN_OctetString & supplementary)
{
  bool result = false;

  for (PINDEX i = 0; i < supplementary.GetSize(); i++) {
    H4501_SupplementaryService supplementaryService;

    // Decode the supplementary service PDU from the PPER Stream
    if (supplementary[i].DecodeSubType(supplementaryService)) {
      PTRACE(4, "H450\tReceived supplementary service PDU:\n  "
             << setprecision(2) << supplementaryService);
    }
    else {
      PTRACE(1, "H450\tInvalid supplementary service PDU decode:\n  "
             << setprecision(2) << supplementaryService);
      continue;
    }

    H4501_InterpretationApdu & interpretation = supplementaryService.m_interpretationApdu;

    if (supplementaryService.m_serviceApdu.GetTag() == H4501_ServiceApdus::e_rosApdus) {
      H4501_ArrayOf_ROS& operations = (H4501_ArrayOf_ROS&) supplementaryService.m_serviceApdu;

      for (PINDEX j = 0; j < operations.GetSize(); j ++) {
        X880_ROS& operation = operations[j];
        switch (operation.GetTag()) {
          case X880_ROS::e_invoke:
            result = OnH450Invoke((X880_Invoke &)operation, interpretation);
            break;

          case X880_ROS::e_returnResult:
          case X880_ROS::e_returnError:
          case X880_ROS::e_reject:
          default :
            break;
        }
      }
    }
  }
  return result;
}

bool CallSignalSocket::OnH450Invoke(X880_Invoke & invoke, H4501_InterpretationApdu & interpretation)
{
	bool result = false;

	// Get the invokeId
	// int invokeId = invoke.m_invokeId.GetValue();

	// Get the linkedId if present
	// int linkedId = -1;
	// if (invoke.HasOptionalField(X880_Invoke::e_linkedId)) {
	//		linkedId = invoke.m_linkedId.GetValue();
	// }

	// Get the argument if present
	PASN_OctetString * argument = NULL;
	if (invoke.HasOptionalField(X880_Invoke::e_argument)) {
		argument = &invoke.m_argument;
	}

	// Get the opcode
	if (invoke.m_opcode.GetTag() == X880_Code::e_local) {
		int opcode = ((PASN_Integer&) invoke.m_opcode).GetValue();

		switch (opcode) {
			case H4502_CallTransferOperation::e_callTransferInitiate:
				result = OnH450CallTransfer(argument);
				break;
			default:
				break;
		}
	}

	return result;
}

static PString ParseEndpointAddress(H4501_EndpointAddress& endpointAddress)
{
	H4501_ArrayOf_AliasAddress& destinationAddress = endpointAddress.m_destinationAddress;

	PString alias;
	PString remoteParty;
	H323TransportAddress transportAddress;

	for (PINDEX i = 0; i < destinationAddress.GetSize(); i++) {
		H225_AliasAddress& aliasAddress = destinationAddress[i];

		if (aliasAddress.GetTag() == H225_AliasAddress::e_transportID) {
			transportAddress = (H225_TransportAddress &)aliasAddress;
			transportAddress.Replace("ip$", "");
			transportAddress.Replace("*", "");
		} else {
			alias = ::H323GetAliasAddressString(aliasAddress);
			alias.Replace("E164:", "");
			alias.Replace("Private:", "");
			alias.Replace("Data:", "");
			alias.Replace("Telex:", "");
			alias.Replace("NSP:", "");
		}
	}
	if (alias.IsEmpty()) {
		remoteParty = transportAddress;
	}
	else if (transportAddress.IsEmpty()) {
		remoteParty = alias;
	}
	else {
		remoteParty = alias + '@' + transportAddress;
	}

	return remoteParty;
}

bool CallSignalSocket::OnH450CallTransfer(PASN_OctetString * argument)
{
	if (!argument)
		return false;

	H4502_CTInitiateArg ctInitiateArg;
	PPER_Stream argStream(*argument);
	if (ctInitiateArg.Decode(argStream)) {
		PString remoteParty = ParseEndpointAddress(ctInitiateArg.m_reroutingNumber);
		if (remoteParty.IsEmpty()) {
			PTRACE(1, "H.450.2 Emulator: Empty destination");
			return false;
		}
		// ignored for now
		//H225_CallIdentifier callid;
		//callid.m_guid = H225_GloballyUniqueID(ctInitiateArg.m_callIdentity.GetValue());
		if (!m_call) {
			PTRACE(1, "H.450.2 Emulator: No call to transfer");
			return false;
		}
		if (!(m_call->GetCallSignalSocketCalling() && m_call->GetCallSignalSocketCalled())) {
			PTRACE(1, "H.450.2 Emulator: Must have 2 connected parties on call for transfer");
			return false;
		}
		PCaselessString method = Toolkit::Instance()->Config()->GetString(RoutedSec, "H4502EmulatorTransferMethod", "callForwarded");
		PTRACE(2, "H.450.2 Emulator Transfer call to " << remoteParty << " using method " << method);
		if (method == "Reroute") {
			// fork another thread for the reroute, so this socket doesn't block
			remoteParty.MakeUnique();
			if (this == m_call->GetCallSignalSocketCalling()) {
				CreateJob(this, &CallSignalSocket::RerouteCalled, remoteParty, "Reroute to " + remoteParty);
			} else {
				CreateJob(m_call->GetCallSignalSocketCalling(), &CallSignalSocket::RerouteCaller, remoteParty, "Reroute to " + remoteParty);
			}
		} else {
			PString callid = AsString(m_call->GetCallIdentifier());
			callid.Replace(" ", "-", true);
			PCaselessString which = (this == m_call->GetCallSignalSocketCalling()) ? "called" : "calling";
			SoftPBX::TransferCall(callid, which, remoteParty, method);
		}
		return true;
	}
	return false;
}

#endif	// H323_H450

// helper method to start a thread with only one parameter (which would be 2nd)
void CallSignalSocket::RerouteCaller(PString destination)
{
	RerouteCall(Caller, destination);
}

void CallSignalSocket::RerouteCalled(PString destination)
{
	RerouteCall(Called, destination);
}

// to be called on the remaining socket !!!
bool CallSignalSocket::RerouteCall(CallLeg which, const PString & destination)
{
	CallSignalSocket * droppedSocket = NULL;
	CallSignalSocket * remainingSocket = NULL;

	// check if we have access to signaling channel of endpoint to be transferred
	if (which == Called) {
		droppedSocket = m_call->GetCallSignalSocketCalling();
		remainingSocket = m_call->GetCallSignalSocketCalled();
	} else {
		droppedSocket = m_call->GetCallSignalSocketCalled();
		remainingSocket = m_call->GetCallSignalSocketCalling();
	}
	if (this != remainingSocket) {
		PTRACE(1, "Error: RerouteCall() called on wrong socket" << this);
		SNMP_TRAP(7, SNMPError, Network, "RerouteCall() called on wrong socket");
		return false;
	}

	// build Setup
	Q931 q931;
	H225_H323_UserInformation uuie;
	PBYTEArray perBuffer;
	bool tunneling = (which == Called) ? m_call->GetCallSignalSocketCalled()->m_h245Tunneling : m_call->GetCallSignalSocketCalling()->m_h245Tunneling;
	if (which == Caller) {
		// use saved Setup and just change the destination
		q931.Decode(m_rawSetup);
		GetUUIE(q931, uuie);
		if (uuie.m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_setup) {
            PTRACE(1, "Error: Saved Setup is no Setup");
            return false;
		}
		H225_Setup_UUIE & setup = uuie.m_h323_uu_pdu.m_h323_message_body;
		uuie.m_h323_uu_pdu.m_h245Tunneling = tunneling;
		// remove old destination
		setup.RemoveOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		setup.RemoveOptionalField(H225_Setup_UUIE::e_destinationAddress);
        // remove H.235.6 tokens: caller probably connected without encryption to first destination and resetting keys won't work with most endpoints
        // TODO: make sure we don't remove other tokens
        setup.m_tokens.SetSize(0);
		// check if destination contains IP to set destCallSigAddr
		PString alias;
		PString destip;
		PINDEX at = destination.Find("@");
		if (at != P_MAX_INDEX) {
			alias = destination.Left(at);
			destip = destination.Mid(at+1);
			if (!IsIPAddress(destip)) {
				// use as URL_ID
				destip = "";
				alias = destination;
			}
		} else {
			if (IsIPAddress(destination)) {
				destip = destination;
			} else {
				alias = destination;
			}
		}
		if (!destip.IsEmpty()) {
			setup.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
			PStringArray adr_parts = SplitIPAndPort(destip, GK_DEF_ENDPOINT_SIGNAL_PORT);
			PIPSocket::Address ip(adr_parts[0]);
			WORD port = (WORD)(adr_parts[1].AsInteger());
			setup.m_destCallSignalAddress = SocketToH225TransportAddr(ip, port);
		}
		if (!alias.IsEmpty()) {
			setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
			setup.m_destinationAddress.SetSize(1);
			H323SetAliasAddress(alias, setup.m_destinationAddress[0]);
			if (setup.m_destinationAddress[0].GetTag() == H225_AliasAddress::e_dialedDigits) {
				q931.SetCalledPartyNumber(alias);
			}
		}
	} else {    // which == Called
		BuildSetupPDU(q931, m_call->GetCallIdentifier(), m_call->GetCallRef(), destination, tunneling);
		GetUUIE(q931, uuie);
		H225_Setup_UUIE & setup_uuie = uuie.m_h323_uu_pdu.m_h323_message_body;
		setup_uuie.IncludeOptionalField(H225_Setup_UUIE::e_sourceAddress);
		setup_uuie.m_sourceAddress.SetSize(1);
        H323SetAliasAddress(m_call->GetCalledStationId(), setup_uuie.m_sourceAddress[0]);
        // TODO: set displayIE, bearer capability + vendor from saved Connect
    	Q931 connectQ931;
	    H225_H323_UserInformation connectUuie;
		connectQ931.Decode(m_rawConnect);
		GetUUIE(connectQ931, connectUuie);
		if (connectUuie.m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_connect) {
            PTRACE(1, "Error: Saved Connect is no Connect");
            return false;
		}
		H225_Connect_UUIE & connect_uuie = connectUuie.m_h323_uu_pdu.m_h323_message_body;
		if (!connectQ931.GetDisplayName().IsEmpty())
            q931.SetDisplayName(connectQ931.GetDisplayName());
        Q931::InformationTransferCapability capability;
        unsigned transferRate;
        unsigned codingStandard;
        unsigned userInfoLayer1;
        connectQ931.GetBearerCapabilities(capability, transferRate, &codingStandard, &userInfoLayer1);
        q931.SetBearerCapabilities(capability, transferRate, codingStandard, userInfoLayer1);
        if (connect_uuie.m_destinationInfo.HasOptionalField(H225_EndpointType::e_vendor)) {
            setup_uuie.m_sourceInfo.IncludeOptionalField(H225_EndpointType::e_vendor);
            setup_uuie.m_sourceInfo.m_vendor = connect_uuie.m_destinationInfo.m_vendor;
        }
	}
	SetUUIE(q931, uuie);
	q931.Encode(perBuffer);
	m_rawSetup = perBuffer;
	m_rawSetup.MakeUnique();

	PrintQ931(3, "Setup for Reroute of ", GetName(), &q931, &uuie);

	PIPSocket::Address dummyAddr;
	SignalingMsg * msg = SignalingMsg::Create(&q931, &uuie, dummyAddr, 0, dummyAddr, 0);
	SetupMsg * setup = dynamic_cast<SetupMsg*>(msg);
	if (setup == NULL) {
		PTRACE(1, "Can't cast Setup");	// should never happen
		return false;
	}
	H225_Setup_UUIE & setupBody = setup->GetUUIEBody();

	// invoke authentication
	bool overTLS = false;
#ifdef HAS_TLS
	overTLS = (dynamic_cast<TLSCallSignalSocket *>(this) != NULL);
#endif
	SetupAuthData authData(m_call, m_call ? true : false, overTLS);
	authData.m_callingStationId = GetCallingStationId(*setup, authData);
	authData.m_calledStationId = GetCalledStationId(*setup, authData);
	if (!RasServer::Instance()->ValidatePDU(*setup, authData)) {
		PTRACE(1, "Q931\tAutentication of reroute destination failed");
		SNMP_TRAP(8, SNMPError, Authentication, "Reroute authentication failed");
		return false;
	}
	// invoke routing policies for destination
	Routing::SetupRequest request(setupBody, setup, authData.m_callingStationId, authData.m_clientAuthId);
	request.Process();
	Route route;
	if (!request.GetFirstRoute(route)) {
		PTRACE(1, "Q931\tCan't find reroute destination");
		return false;
	}
	PTRACE(1, "Q931\tRerouting route: " << route.AsString());

	m_call->SetRerouteState(RerouteInitiated);
	m_call->SetRerouteDirection(which);
	if (route.m_useTLS)
		m_call->SetConnectWithTLS(true);

    // build TCS0 for tunneled H.245 connection
    H245_MultimediaSystemControlMessage h245msg_tcs0;
    h245msg_tcs0.SetTag(H245_MultimediaSystemControlMessage::e_request);
    H245_RequestMessage & h245req_tcs0 = h245msg_tcs0;
    h245req_tcs0.SetTag(H245_RequestMessage::e_terminalCapabilitySet);
    H245_TerminalCapabilitySet & tcs0 = h245req_tcs0;
    tcs0.m_protocolIdentifier.SetValue(H245_ProtocolID);

    // build CLC (used for tunneled and non-tunneled)
    H245_MultimediaSystemControlMessage h245msg_clc;
	h245msg_clc.SetTag(H245_MultimediaSystemControlMessage::e_request);
	H245_RequestMessage & h245req_clc = h245msg_clc;
	h245req_clc.SetTag(H245_RequestMessage::e_closeLogicalChannel);
    H245_CloseLogicalChannel & clc = h245req_clc;
    clc.m_source.SetTag(H245_CloseLogicalChannel_source::e_user);

    vector<WORD> flcnList = m_call->GetChannelFlcnList();
    m_call->ClearChannelFlcnList();

	// send TCS0 to dropping party
    PTRACE(1, "Q931\tSending TCS0 to dropped tunneling=" << droppedSocket->IsH245Tunneling());
	if (!droppedSocket->IsH245Tunneling()) {
		droppedSocket->m_h245socket->SendTCS(NULL, droppedSocket->GetNextTCSSeq());
	} else {
		// send tunneled TCS0
        tcs0.m_sequenceNumber = droppedSocket->GetNextTCSSeq();
        droppedSocket->SendTunneledH245(h245msg_tcs0);
	}

	// send TCS0 to forwarded (remaining) party
    PTRACE(1, "Q931\tSending TCS0 to forwarded tunneling=" << remainingSocket->IsH245Tunneling());
	if (!remainingSocket->IsH245Tunneling()) {
		m_h245socket->SendTCS(NULL, GetNextTCSSeq());
		for (unsigned i = 0; i < flcnList.size(); i++) {
            PTRACE(2, "Q931\tSending CLC " << flcnList[i] << " to forwarded");
            clc.m_forwardLogicalChannelNumber = flcnList[i];
            m_h245socket->Send(h245msg_clc);
		}
	} else {
		// send tunneled TCS0 + CLCs
        tcs0.m_sequenceNumber = GetNextTCSSeq();
        SendTunneledH245(h245msg_tcs0);
		for (unsigned i = 0; i < flcnList.size(); i++) {
            PTRACE(2, "Q931\tSending CLC " << flcnList[i] << " to forwarded");
            clc.m_forwardLogicalChannelNumber = flcnList[i];
            SendTunneledH245(h245msg_clc);
        }
    }

	PThread::Sleep(500);	// wait for all CLCs to be sent

	// drop party from call
	if (which == Called) {
		m_call->RerouteDropCalling();
	} else {
		m_call->RerouteDropCalled();
	}

	droppedSocket->RemoveRemoteSocket();
	droppedSocket->RemoveH245Handler();
	if (droppedSocket->m_h245socket) {
		droppedSocket->m_h245socket->RemoveRemoteSocket();
	}
	if (droppedSocket->GetHandler()->Detach(this))
		PTRACE(1, "Q931\tSocket " << droppedSocket->GetName() << " detached from its handler");
	else {
		PTRACE(1, "Q931\tFailed to detach socket " << droppedSocket->GetName() << " from its handler");
	}
	remote = NULL;
	if (m_h245socket)
		m_h245socket->RemoveRemoteSocket();
	GetHandler()->Remove(droppedSocket);

	CallRec * newCall = new CallRec(m_call.operator ->());
	CallTable::Instance()->RemoveFailedLeg(m_call);
	// set calling and called party
	if (which == Called) {
	    newCall->SetCalling(m_call->GetCalledParty());
	} else {
	    newCall->SetCalling(m_call->GetCallingParty());
	}
	newCall->SetCalled(route.m_destEndpoint);

	m_remoteLock.Wait();
	CallSignalSocket * callingSocket = static_cast<CallSignalSocket*>(remote);
	if (callingSocket != NULL) {
		callingSocket->RemoveRemoteSocket();
		if (callingSocket->m_h245socket) {
			callingSocket->m_h245socket->SetSigSocket(NULL);
			callingSocket->m_h245socket = NULL;
		}
		callingSocket->RemoveH245Handler();
		if (callingSocket->GetHandler()->Detach(callingSocket))
			PTRACE(6, "Q931\tSocket " << callingSocket->GetName() << " detached from its handler");
		else {
			PTRACE(1, "Q931\tFailed to detach socket " << callingSocket->GetName() << " from its handler");
		}

		callingSocket->m_call = callptr(newCall);
		callingSocket->buffer = callingSocket->m_rawSetup;
		callingSocket->buffer.MakeUnique();
	}
	m_remoteLock.Signal();

	droppedSocket->SendReleaseComplete(H225_ReleaseCompleteReason::e_undefinedReason);      // callDeflection ?

	if (route.m_destEndpoint)
		m_call->SetCalled(route.m_destEndpoint);
	else
		m_call->SetDestSignalAddr(route.m_destAddr);

	if (route.m_flags & Route::e_toParent)
		m_call->SetToParent(true);

	if (!route.m_destNumber.IsEmpty()) {
		H225_ArrayOf_AliasAddress destAlias;
		destAlias.SetSize(1);
		H323SetAliasAddress(route.m_destNumber, destAlias[0]);
		m_call->SetRouteToAlias(destAlias);
	}
    CallTable::Instance()->Insert(newCall);

	// send Setup
	buffer = m_rawSetup;
	buffer.MakeUnique();
	//delete msg;	// TODO: crash or leak
	PTRACE(5, GetName() << "\tRerouting call to " << route.AsString());
	CreateJob(this, &CallSignalSocket::DispatchNextRoute, "Reroute");

	return true;
}

#ifdef HAS_H46017
bool CallSignalSocket::SendH46017Message(H225_RasMessage ras, GkH235Authenticators * authenticators)
{
	PTRACE(3, "RAS\tEncapsulating H.460.17 RAS reply\n" << ras);
	if (IsOpen()) {
		Q931 FacilityPDU;
		H225_H323_UserInformation uuie;
		BuildFacilityPDU(FacilityPDU, 0, NULL, true);
		GetUUIE(FacilityPDU, uuie);
		H225_H323_UU_PDU_h323_message_body & body = uuie.m_h323_uu_pdu.m_h323_message_body;
		body.SetTag(H225_H323_UU_PDU_h323_message_body::e_empty);
		uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
		uuie.m_h323_uu_pdu.m_h245Tunneling.SetValue(m_h245Tunneling);
		uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_genericData);
		uuie.m_h323_uu_pdu.m_genericData.SetSize(1);
		H460_FeatureStd feat = H460_FeatureStd(17);
		PBYTEArray rasbuf(1024); // buffer with initial size 1024
        PPER_Stream rasstrm(rasbuf);
		ras.Encode (rasstrm);
		rasstrm.CompleteEncoding();

		// make sure buffer gets shrunk to size of encoded message, because we'll write it instead of the PPER_Stream
        rasbuf.SetSize(rasstrm.GetSize());
        if (authenticators != NULL)
            authenticators->Finalise(ras, rasbuf);

		PASN_OctetString encRAS;
		encRAS.SetValue(rasbuf);
		feat.Add(1, H460_FeatureContent(encRAS));
		uuie.m_h323_uu_pdu.m_genericData[0] = feat;
		SetUUIE(FacilityPDU, uuie);

		PrintQ931(3, "Send to ", GetName(), &FacilityPDU, &uuie);

#ifdef HAS_H46026
		if (m_h46026PriorityQueue) {
			// put message into priority queue
			m_h46026PriorityQueue->SignalMsgOut(FacilityPDU);
			PollPriorityQueue();
			return true;
		}
#endif

		PBYTEArray buf;
		FacilityPDU.Encode(buf);
		return TransmitData(buf);
	} else {
		PTRACE(1, "Error: Can't send H.460.17 reply to " << GetName() << " - socket closed");
		SNMP_TRAP(10, SNMPWarning, Network, "Can't send H.460.17 reply to " + GetName() + " - socket closed");
		return false;
	}
}
#endif

#ifdef HAS_H46026
bool CallSignalSocket::SendH46026RTP(unsigned sessionID, bool isRTP, const void * data, unsigned len)
{
	if ((data == NULL) || (len == 0))
		return false;

	if (m_call && m_h46026PriorityQueue) {
		// put RTP into priority queue
		m_h46026PriorityQueue->RTPFrameOut(m_call->GetCallRef(),
			(sessionID == 1) ? H46026ChannelManager::e_Audio : H46026ChannelManager::e_Video, // guess the content
			sessionID, isRTP, (const BYTE *)data, len);
		PollPriorityQueue();
		return true;
	}

	if (IsOpen()) {
		H46026_UDPFrame frame;
		frame.m_sessionId = sessionID;
		frame.m_dataFrame = isRTP;
		frame.m_frame.SetSize(1);	// for now we don't combine multiple frames
		frame.m_frame[0].SetTag(isRTP ? H46026_FrameData::e_rtp : H46026_FrameData::e_rtcp);
		PASN_OctetString & raw = frame.m_frame[0];
		raw = PBYTEArray((const BYTE *)data, len);

		PBoolean fromDest = m_crv & 0x8000u;
		Q931 InformationPDU;
		H225_H323_UserInformation uuie;
		InformationPDU.BuildInformation(m_crv, fromDest);
		InformationPDU.SetCallState(Q931::CallState_CallInitiated);
		GetUUIE(InformationPDU, uuie);
		H225_H323_UU_PDU & info = uuie.m_h323_uu_pdu;
		info.IncludeOptionalField(H225_H323_UU_PDU::e_genericData);
		uuie.m_h323_uu_pdu.m_genericData.SetSize(1);
		H225_GenericData & gen = uuie.m_h323_uu_pdu.m_genericData[0];
		H225_GenericIdentifier & id = gen.m_id;
		id.SetTag(H225_GenericIdentifier::e_standard);
		PASN_Integer & asnInt = id;
		asnInt.SetValue(26);
		gen.IncludeOptionalField(H225_GenericData::e_parameters);
		gen.m_parameters.SetSize(1);
		H225_EnumeratedParameter & param = gen.m_parameters[0];
		H225_GenericIdentifier & pid = param.m_id;
		pid.SetTag(H225_GenericIdentifier::e_standard);
		PASN_Integer & pInt = pid;
		pInt.SetValue(1);
		param.IncludeOptionalField(H225_EnumeratedParameter::e_content);
		param.m_content.SetTag(H225_Content::e_raw);
		PASN_OctetString & val = uuie.m_h323_uu_pdu.m_genericData[0].m_parameters[0].m_content;
		val.EncodeSubType(frame);

		uuie.m_h323_uu_pdu.m_h323_message_body.SetTag(H225_H323_UU_PDU_h323_message_body::e_empty);
		uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
		uuie.m_h323_uu_pdu.m_h245Tunneling.SetValue(m_h245Tunneling);
		SetUUIE(InformationPDU, uuie);

		if (PTrace::CanTrace(7)) {
			PrintQ931(7, "Send to ", GetName(), &InformationPDU, &uuie);
		} else {
			PTRACE(3, "Send to " << GetName() << " Info with H.460.26 RTP");
		}

		PBYTEArray buf;
		InformationPDU.Encode(buf);
		return TransmitData(buf);
	} else {
		PTRACE(1, "Error: Can't send H.460.26 to " << GetName() << " - socket closed");
		return false;
	}
}

void CallSignalSocket::PollPriorityQueue()
{
	// check if we have something to send
	// TODO: might have to start a thread that polls all queues
	PBYTEArray data(10000);
	PINDEX len;
	if (m_h46026PriorityQueue->SocketOut(data, len)) {
		PTRACE(4, "H46026\tSending from priority queue, len=" << len);
		data.SetSize(len);
		TransmitData(data);
	}
}
#endif

#ifdef HAS_H46018
bool CallSignalSocket::OnSCICall(const H225_CallIdentifier & callID, H225_TransportAddress sigAdr, bool useTLS)
{
	CallRec * call = new CallRec(callID, sigAdr);
	m_call = callptr(call);
	if (useTLS)
		m_call->SetConnectWithTLS(true);
	if (CreateRemote(sigAdr)) {
		GetHandler()->Insert(this, remote);
		m_callFromTraversalServer = true;
		if (remote)
			((CallSignalSocket*)remote)->m_callFromTraversalServer = true;
		Q931 FacilityPDU;
		H225_H323_UserInformation uuie;
		BuildFacilityPDU(FacilityPDU, H225_FacilityReason::e_undefinedReason, &callID);
		GetUUIE(FacilityPDU, uuie);
		// we don't know, yet if the called endpoint supports tunneling,
		// so we can only offer it if tunneling translation is on
		if (m_h245TunnelingTranslation) {
			uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
			uuie.m_h323_uu_pdu.m_h245Tunneling.SetValue(true);
			SetUUIE(FacilityPDU, uuie);
		}
		PBYTEArray buf;
		FacilityPDU.Encode(buf);
		PrintQ931(5, "Send to ", remote ? remote->GetName() : "unknown", &FacilityPDU, &uuie);
 		if (!(remote && remote->TransmitData(buf))) {
			PTRACE(2, "H46018\tTransmitting Facility to Neighbor GK " << AsString(sigAdr) << " failed");
			SNMP_TRAP(11, SNMPError, Network, "Neighbor communication failed");
			return false;
		}
	} else {
		PTRACE(2, "H46018\tConnecting to Neighbor GK " << AsString(sigAdr) << " failed");
		SNMP_TRAP(11, SNMPError, Network, "Neighbor communication failed with " + AsString(sigAdr));
		return false;
	}
	return true;
}

void CallSignalSocket::SetSessionMultiplexDestination(WORD session, bool isRTCP, const IPAndPortAddress & toAddress, H46019Side side)
{
	H245ProxyHandler * handler = dynamic_cast<H245ProxyHandler*>(m_h245handler);
	if (handler) {
		RTPLogicalChannel * rtplc = handler->FindRTPLogicalChannelBySessionID(session);
		if (rtplc) {
			rtplc->SetLCMultiplexDestination(isRTCP, toAddress, side);
		} else {
			PTRACE(1, "Error: No RTP channel found in SetSessionMultiplexDestination() session=" << session << " to=" << AsString(toAddress));
		}
	} else {
        PTRACE(1, "Error: No H.245 handler channel found in SetSessionMultiplexDestination() session=" << session << " to=" << AsString(toAddress));
	}
}
#endif

void CallSignalSocket::OnReleaseComplete(SignalingMsg * msg)
{
	ReleaseCompleteMsg * rc = dynamic_cast<ReleaseCompleteMsg*>(msg);
	if (rc == NULL) {
		PTRACE(2, Type() << "\tWarning: ReleaseComplete message from " << Name() << " without associated UUIE");
	}

	unsigned cause = 0;
	if (m_call) {
		// regular ReleaseComplete processing
		m_call->SetDisconnectTime(time(NULL));
		m_call->SetReleaseSource(m_callerSocket ? CallRec::ReleasedByCaller : CallRec::ReleasedByCallee);
		// fix Q.931 direction flag for rerouted calls
        // TODO: only if call has been rerouted ?
        // TODO: doesn't cover RP as caller in makeCall being hung up by remote
#if (H323PLUS_VER >= 1268)
        if (m_callerSocket != !msg->GetQ931().IsFromDestination()) {
            msg->GetQ931().SetFromDestination(!m_callerSocket);
            msg->SetChanged();
        }
#endif
		// cause code rewriting
		if (msg->GetQ931().HasIE(Q931::CauseIE)) {
			cause = msg->GetQ931().GetCause();
			if (Toolkit::Instance()->IsCauseCodeTranslationActive()) {
				// translate cause codes
				unsigned new_cause = cause;
				// global translation first
				new_cause = Toolkit::Instance()->TranslateReceivedCause(new_cause);
				new_cause = Toolkit::Instance()->TranslateSentCause(new_cause);
				endptr calling = m_call->GetCallingParty();
				if (!calling)
					calling = RegistrationTable::Instance()->FindBySignalAdr(m_call->GetSrcSignalAddr());
				if (!calling)
					calling = RegistrationTable::Instance()->FindByAliases(m_call->GetSourceAddress());
				if (!calling) {
					// if all fails, search on default port
					PIPSocket::Address addr;
					WORD port;
					if (m_call->GetSrcSignalAddr(addr, port))
						calling = RegistrationTable::Instance()->FindBySignalAdr(SocketToH225TransportAddr(addr, GK_DEF_ENDPOINT_SIGNAL_PORT));
				}
				endptr called = m_call->GetCalledParty();
				if (!called)
					called = RegistrationTable::Instance()->FindBySignalAdr(m_call->GetDestSignalAddr());
				if (!called)
					called = RegistrationTable::Instance()->FindByAliases(m_call->GetDestinationAddress());
				if (!called) {
					// if all fails, search on default port
					PIPSocket::Address addr;
					WORD port;
					if (m_call->GetDestSignalAddr(addr, port))
						called = RegistrationTable::Instance()->FindBySignalAdr(SocketToH225TransportAddr(addr, GK_DEF_ENDPOINT_SIGNAL_PORT));
				}
				if (msg->GetQ931().IsFromDestination()) {
					if (called)
						new_cause = called->TranslateReceivedCause(new_cause);
					if (calling)
						new_cause = calling->TranslateSentCause(new_cause);
				} else {
					if (calling)
						new_cause = calling->TranslateReceivedCause(new_cause);
					if (called)
						new_cause = called->TranslateSentCause(new_cause);
				}
				if (new_cause != cause) {
					PTRACE(4, "Q931\tTranslated cause code " << cause << " to " << new_cause);
					msg->GetQ931().SetCause(Q931::CauseValues(new_cause));
					msg->SetChanged();
					m_call->SetDisconnectCauseTranslated(new_cause);
				}
			}

			m_call->SetDisconnectCause(cause);
		} else if (rc != NULL) {
			H225_ReleaseComplete_UUIE & rcBody = rc->GetUUIEBody();
			if (rcBody.HasOptionalField(H225_ReleaseComplete_UUIE::e_reason)) {
				cause = Toolkit::Instance()->MapH225ReasonToQ931Cause(rcBody.m_reason.GetTag());
				m_call->SetDisconnectCause(cause);
			}
		}
	} else {
		PTRACE(1, "Error: ReleaseComplete is not associated with a call - dropping");
		SNMP_TRAP(10, SNMPWarning, Network, "ReleaseComplete form " + GetName() + " not associated with any call");
		m_result = NoData;
		return;
	}

#ifdef HAS_H46017
	// save remote pointer for final RC for H.460.17
	if (remote)
		rc_remote = remote;
#endif

	if (m_callerSocket) {
		m_remoteLock.Wait();
		if (remote != NULL) {
			remote->RemoveRemoteSocket();
            remote = NULL;  // FIX for crash in call cleanup (race condition)
		}
		m_remoteLock.Signal();
	}

	if (m_call && remote != NULL && !m_callerSocket
		&& ((m_call->GetReleaseSource() == CallRec::ReleasedByCallee) || (m_call->GetReleaseSource() == CallRec::ReleasedByGatekeeper))
		&& m_call->MoveToNextRoute()) {
		if (!m_call->DisableRetryChecks() &&
			(m_call->IsCallInProgress() || m_call->IsFastStartResponseReceived()
				|| m_call->IsH245ResponseReceived() || m_h245socket != NULL)) {
			PTRACE(5, "Q931\tFailover disabled for call " << m_call->GetCallNumber());
		} else if (m_call->GetFailedRoutes().back().IsFailoverActive(cause)) {
			TryNextRoute();
			return;
		} else
			PTRACE(5, "Q931\tFailover inactive for call " << m_call->GetCallNumber() << ", Q931 cause " << cause);
	}

	if (m_call)
		CallTable::Instance()->RemoveCall(m_call);
	m_result = Closing;
}

void CallSignalSocket::TryNextRoute()
{
	CallRec * newCall = new CallRec(m_call.operator ->());
	CallTable::Instance()->RemoveFailedLeg(m_call);

	m_remoteLock.Wait();
	CallSignalSocket * callingSocket = static_cast<CallSignalSocket*>(remote);
	if (callingSocket != NULL) {
		callingSocket->RemoveRemoteSocket();
		if (callingSocket->m_h245socket) {
			callingSocket->m_h245socket->SetSigSocket(NULL);
			callingSocket->m_h245socket = NULL;
		}
		callingSocket->RemoveH245Handler();
		if (callingSocket->GetHandler()->Detach(callingSocket))
			PTRACE(6, "Q931\tSocket " << callingSocket->GetName() << " detached from its handler");
		else {
			PTRACE(1, "Q931\tFailed to detach socket " << callingSocket->GetName() << " from its handler");
			SNMP_TRAP(10, SNMPError, Network, "Socket detach failed");
		}

		callingSocket->m_call = callptr(newCall);
		callingSocket->buffer = callingSocket->m_rawSetup;
		callingSocket->buffer.MakeUnique();
	}
	m_remoteLock.Signal();

	if (newCall->GetNewRoutes().empty()) {
		PTRACE(1, "Q931\tERROR: TryNextRoute() without a route");
		SNMP_TRAP(7, SNMPError, Network, "Failover failed");
		if (callingSocket)
			callingSocket->m_call = callptr(NULL);
		delete newCall;
		return;
	}
	const Route & newRoute = newCall->GetNewRoutes().front();
	PTRACE(1, "Q931\tNew route: " << newRoute.AsString());
	if (newRoute.m_destEndpoint)
		newCall->SetCalled(newRoute.m_destEndpoint);
	else
		newCall->SetDestSignalAddr(newRoute.m_destAddr);

	if (newRoute.m_flags & Route::e_toParent)
		newCall->SetToParent(true);
	if (newRoute.m_useTLS)
		newCall->SetConnectWithTLS(true);

	if (!newRoute.m_destNumber.IsEmpty()) {
		H225_ArrayOf_AliasAddress destAlias;
		destAlias.SetSize(1);
		H323SetAliasAddress(newRoute.m_destNumber, destAlias[0]);
		newCall->SetRouteToAlias(destAlias);
	}

	CallTable::Instance()->Insert(newCall);

	remote = NULL;
	TCPProxySocket::EndSession();
	GetHandler()->Remove(this);

	if (callingSocket) {
		PTRACE(5, GetName() << "\tDispatching new call leg to " << newRoute.AsString());
		CreateJob(callingSocket, &CallSignalSocket::DispatchNextRoute, "Failover");
		m_result = NoData;
	} else {
		PTRACE(3, GetName() << "\tDispatching new call leg to " << newRoute.AsString() << " failed");
		SNMP_TRAP(7, SNMPError, Network, "Failover failed");
		CallTable::Instance()->RemoveCall(callptr(newCall));
		delete newCall;
		m_result = Closing;
	}
}

void CallSignalSocket::OnFacility(SignalingMsg * msg)
{
	FacilityMsg *facility = dynamic_cast<FacilityMsg*>(msg);
	if (facility == NULL)
		return;

	H225_Facility_UUIE & facilityBody = facility->GetUUIEBody();

	if (m_h225Version == 0)
		m_h225Version = GetH225Version(facilityBody);

	if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_multipleCalls)
			&& facilityBody.m_multipleCalls) {
		facilityBody.m_multipleCalls = FALSE;
		msg->SetUUIEChanged();
	}
	if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_maintainConnection)) {
		facilityBody.m_maintainConnection = (GetRemote() && GetRemote()->MaintainConnection());
		msg->SetUUIEChanged();
	}

	// clear featureSet before forwarding
	if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_featureSet)) {
		if (facilityBody.m_featureSet.HasOptionalField(H225_FeatureSet::e_supportedFeatures)) {
			facilityBody.m_featureSet.m_supportedFeatures.SetSize(0);
		}
		facilityBody.RemoveOptionalField(H225_Facility_UUIE::e_featureSet);
	}

	if (GkConfig()->GetBoolean(RoutedSec, "FilterEmptyFacility", false)) {
		H225_H323_UserInformation * uuie = facility->GetUUIE();
		if ( (uuie && (uuie->m_h323_uu_pdu.m_h323_message_body.GetTag() == H225_H323_UU_PDU_h323_message_body::e_empty))
			|| (facilityBody.m_reason.GetTag() == H225_FacilityReason::e_transportedInformation) ) {
			// filter out Facility messages with reason transportedInformation, but without h245Control or h4501SuplementaryService
			// needed for Avaya interop
			if (   !uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control)
				&& !uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h4501SupplementaryService) ) {
				PTRACE(3, "Q931\tFiltering empty Facility from " << GetName());
				m_result = NoData;
				return;
			}
		}
	}

	switch (facilityBody.m_reason.GetTag()) {
	case H225_FacilityReason::e_startH245:
		{
			if (facilityBody.HasOptionalField(H225_Facility_UUIE::e_h245Address)
					&& facilityBody.m_protocolIdentifier.GetValue().IsEmpty()) {
				if (m_h245socket && m_h245socket->Reverting(facilityBody.m_h245Address))
					m_result = NoData;
			}
			if (m_h245TunnelingTranslation && !m_h245Tunneling && GetRemote() && GetRemote()->m_h245Tunneling) {
				// don't forward to tunneling side
				m_result = NoData;
			}
#ifdef HAS_H46018
			// don't forward startH245 to traversal server
			CallSignalSocket * ret = dynamic_cast<CallSignalSocket *>(remote);
			if (ret && ret->IsTraversalServer()) {
				m_result = NoData;
			}
#endif
		}
		break;
	case H225_FacilityReason::e_routeCallToGatekeeper:
	case H225_FacilityReason::e_callForwarded:
	case H225_FacilityReason::e_routeCallToMC:
	    // TODO: only if calls is connected
		if (GkConfig()->GetBoolean(RoutedSec, "RerouteOnFacility", false)
            && facilityBody.m_reason.GetTag() != H225_FacilityReason::e_routeCallToGatekeeper) {
            // make sure the call is still active
            if (m_call && CallTable::Instance()->FindCallRec(m_call->GetCallNumber())) {
                CreateJob(this, &CallSignalSocket::RerouteCall, dynamic_cast<FacilityMsg*>(facility->Clone()), "RerouteCall");
                m_result = NoData;
                return;
            }
		} else {
            if (!GkConfig()->GetBoolean(RoutedSec, "ForwardOnFacility", false))
                break;

            // to avoid complicated handling of H.245 channel on forwarding,
            // we only do forward if forwarder is the called party (and thus doesn't have a saved Setup) and
            // H.245 channel is not established yet
            if (m_setupPdu || (m_h245socket && m_h245socket->IsConnected()))
                break;
            // make sure the call is still active
            if (m_call && CallTable::Instance()->FindCallRec(m_call->GetCallNumber())) {
                MarkBlocked(true);
                CreateJob(this, &CallSignalSocket::ForwardCall, dynamic_cast<FacilityMsg*>(facility->Clone()), "ForwardCall");
                m_result = NoData;
                return;
            }
		}
		break;

	case H225_FacilityReason::e_transportedInformation:
		if (GkConfig()->GetBoolean(RoutedSec, "TranslateFacility", false)) {
			CallSignalSocket * sigSocket = dynamic_cast<CallSignalSocket*>(remote);
			if (sigSocket != NULL && sigSocket->m_h225Version > 0
					&& sigSocket->m_h225Version < 4) {
				H225_H323_UserInformation * uuie = facility->GetUUIE();
				if (uuie) {
					uuie->m_h323_uu_pdu.m_h323_message_body.SetTag(
						H225_H323_UU_PDU_h323_message_body::e_empty);
					msg->SetUUIEChanged();
					return;
				}
			}
		}
		break;

#ifdef HAS_H46018
	case H225_FacilityReason::e_undefinedReason:
		if (Toolkit::Instance()->IsH46018Enabled()
			&& facilityBody.HasOptionalField(H225_Facility_UUIE::e_callIdentifier)) {
			H225_CallIdentifier callIdentifier = facilityBody.m_callIdentifier;
			m_call = CallTable::Instance()->FindCallRec(callIdentifier);
			if (m_call) {
				m_call->SetCallSignalSocketCalled(this);
				PBYTEArray rawSetup = m_call->RetrieveSetup();
				CallSignalSocket * callingSocket = m_call->GetCallSignalSocketCalling();
				if (callingSocket && (rawSetup.GetSize() > 0)) {
					m_callerSocket = false;
					remote = callingSocket;
					remote->GetPeerAddress(peerAddr, peerPort);
					UnmapIPv4Address(peerAddr);
					localAddr = RasServer::Instance()->GetLocalAddress(peerAddr);
					UnmapIPv4Address(localAddr);
					masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
					UnmapIPv4Address(masqAddr);
					callingSocket->remote = this;
					// update localAddr and masqAddr in remote, now that we know their peerAddr
					Address remote_peerAddr;
					WORD remote_peerPort;
					GetPeerAddress(remote_peerAddr, remote_peerPort);
					callingSocket->localAddr = RasServer::Instance()->GetLocalAddress(remote_peerAddr);
					UnmapIPv4Address(callingSocket->localAddr);
					callingSocket->masqAddr = RasServer::Instance()->GetMasqAddress(remote_peerAddr);
					UnmapIPv4Address(callingSocket->masqAddr);

					callingSocket->SetConnected(true);
					SetConnected(true);
					GetHandler()->MoveTo(callingSocket->GetHandler(), this);

					// always proxy H.245 for H.460.18/19
					Address calling = GNUGK_INADDR_ANY, called = GNUGK_INADDR_ANY;
					m_call->GetNATType(calling, called);
					// H.245 proxy hander for calling (doesn't have to use H.460.18/.19)
					H245ProxyHandler *proxyhandler = new H245ProxyHandler(m_call->GetCallIdentifier(), callingSocket->localAddr, calling, callingSocket->masqAddr);
#ifdef HAS_H46026
					if (m_call->GetCallingParty())
						proxyhandler->SetUsesH46026(m_call->GetCallingParty()->UsesH46026());
#endif
					if (m_call->GetCalledParty() && !m_call->GetCalledParty()->IsTraversalClient()) {
						PTRACE (1, "Traversal call to non-H.460.18 endpoint, maybe neighbor - setting now");
						m_call->GetCalledParty()->SetTraversalRole(TraversalClient);
					}
					callingSocket->m_h245handler = proxyhandler;
					if (m_call->GetCallingParty()) {
						proxyhandler->SetTraversalRole(m_call->GetCallingParty()->GetTraversalRole());
					}
					proxyhandler->SetRequestRTPMultiplexing(callingSocket->m_senderSupportsH46019Multiplexing);
					m_h245handler = new H245ProxyHandler(m_call->GetCallIdentifier(), localAddr, called, masqAddr, proxyhandler);
					proxyhandler->SetHandler(GetHandler());
#ifdef HAS_H46026
					if (m_call->GetCalledParty())
						((H245ProxyHandler*)m_h245handler)->SetUsesH46026(m_call->GetCalledParty()->UsesH46026());
#endif
					((H245ProxyHandler*)m_h245handler)->SetTraversalRole(TraversalClient);
					((H245ProxyHandler*)m_h245handler)->SetH46019Direction(m_call->GetH46019Direction());

					H225_H323_UserInformation *uuie = NULL;
					Q931 *q931pdu = new Q931();
					if (!q931pdu->Decode(rawSetup)) {
						PTRACE(1, Type() << "\t" << GetName() << " ERROR DECODING saved Setup!");
						SNMP_TRAP(9, SNMPError, Network, "Error decoding saved Setup from " + GetName());
						delete q931pdu;
						q931pdu = NULL;
						return;
					}
					if (q931pdu->HasIE(Q931::UserUserIE)) {
						uuie = new H225_H323_UserInformation();
						GetUUIE(*q931pdu, *uuie);
					}
					PIPSocket::Address _localAddr, _peerAddr;
					WORD _localPort = 0, _peerPort = 0;
					SetupMsg * setup = (SetupMsg *)SetupMsg::Create(q931pdu, uuie, _localAddr, _localPort, _peerAddr, _peerPort);
					setup->Decode(rawSetup);
					H225_Setup_UUIE & setupBody = setup->GetUUIEBody();

					// update destCallSignalAddress and sourceCallSignalAddress (previously unknown for traversal client)
					if (setupBody.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) {
						setupBody.m_destCallSignalAddress = m_call->GetDestSignalAddr();
					}
					if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress)) {
						setupBody.m_sourceCallSignalAddress = SocketToH225TransportAddr(callingSocket->masqAddr, callingSocket->GetPort());
					}
					// remove H.235 tokens from outgoing Setup
					PIPSocket::Address calleeAddr;
					WORD calleePort = 0;
					m_call->GetDestSignalAddr(calleeAddr, calleePort);
					if (Toolkit::Instance()->RemoveH235TokensFrom(calleeAddr)) {
						PTRACE(3, "Removing H.235 tokens (outgoing)");
						setupBody.m_tokens.SetSize(0);
						setupBody.RemoveOptionalField(H225_Setup_UUIE::e_tokens);
						setupBody.m_cryptoTokens.SetSize(0);
						setupBody.RemoveOptionalField(H225_Setup_UUIE::e_cryptoTokens);
					}
					// update tunneling flag, in case this Facility has changed the tunneling state
					if (uuie && (m_h245TunnelingTranslation || !m_h245Tunneling)) {
						if (!uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling)) {
							uuie->m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
						}
						uuie->m_h323_uu_pdu.m_h245Tunneling.SetValue(m_h245Tunneling);
					}
                    // screen displayIE
                    if (q931pdu->HasIE(Q931::DisplayIE)) {
                        PString newDisplayIE;
                        PString screenDisplayIE = GkConfig()->GetString(RoutedSec, "ScreenDisplayIE", "");
                        PString appendToDisplayIE = GkConfig()->GetString(RoutedSec, "AppendToDisplayIE", "");
                        if (!m_call->GetCallerID().IsEmpty() || !m_call->GetCallerDisplayIE().IsEmpty()) {
                            newDisplayIE = m_call->GetCallerID();
                            if (!m_call->GetCallerDisplayIE().IsEmpty()) {
                                newDisplayIE = m_call->GetCallerDisplayIE();
                            }
                        } else if (screenDisplayIE != PCaselessString("Called")) {
                            newDisplayIE = screenDisplayIE + appendToDisplayIE;
                        }
                        if (screenDisplayIE == PCaselessString("Calling") || screenDisplayIE == PCaselessString("CallingCalled")) {
                            if (m_call) {
                                newDisplayIE = m_call->GetCallingStationId() + appendToDisplayIE;
                            }
                        }
                        if (!newDisplayIE.IsEmpty()) {
                            PTRACE(4, "Q931\tSetting DisplayIE to " << newDisplayIE);
                            q931pdu->SetDisplayName(newDisplayIE);
                        }
                    }

					setup->SetUUIEChanged();

					if (HandleH245Address(setupBody))
						setup->SetUUIEChanged();

					if (HandleFastStart(setupBody, true))
						setup->SetUUIEChanged();

#if H225_PROTOCOL_VERSION >= 4
				if (setupBody.HasOptionalField(H225_Setup_UUIE::e_parallelH245Control) && m_h245handler) {
					bool suppress = false;	// ignore for now
					if (OnTunneledH245(setupBody.m_parallelH245Control, suppress))
						setup->SetUUIEChanged();
				}
#endif
					// re-encode with changes made here
					if (setup->IsChanged() && uuie)
						SetUUIE(*q931pdu, *uuie);

					PrintQ931(4, "Send to ", this->GetName(), &setup->GetQ931(), setup->GetUUIE());

					if (q931pdu->Encode(rawSetup))
						this->TransmitData(rawSetup);

					// deleting setup also disposes q931pdu and uuie
					delete setup;
					setup = NULL;
				}
				m_result = DelayedConnecting;	// don't forward, this was just to open the connection
			} else {
				PTRACE(1, "No matching call found for callid " << AsString(facilityBody.m_callIdentifier) << " will forward");
			}
		}
		break;
#endif
	}

	if (HandleFastStart(facilityBody, false))
		msg->SetUUIEChanged();

	if (m_result != NoData)
		if (HandleH245Address(facilityBody))
			msg->SetUUIEChanged();

}

void CallSignalSocket::OnProgress(SignalingMsg * msg)
{
	ProgressMsg * progress = dynamic_cast<ProgressMsg*>(msg);
	if (progress == NULL) {
		PTRACE(2, Type() << "\tError: Progress message from " << Name() << " without associated UUIE");
		SNMP_TRAP(9, SNMPError, Network, "Progress from " + GetName() + " has no UUIE");
		m_result = Error;
		return;
	}

	H225_Progress_UUIE & progressBody = progress->GetUUIEBody();

	if (m_h225Version == 0)
		m_h225Version = GetH225Version(progressBody);

	if (HandleFastStart(progressBody, false))
		msg->SetUUIEChanged();

	if (HandleH245Address(progressBody))
		msg->SetUUIEChanged();

	if (progressBody.HasOptionalField(H225_Progress_UUIE::e_multipleCalls)
			&& progressBody.m_multipleCalls) {
		progressBody.m_multipleCalls = FALSE;
		msg->SetUUIEChanged();
	}
	if (progressBody.HasOptionalField(H225_Progress_UUIE::e_maintainConnection)) {
		progressBody.m_maintainConnection = (GetRemote() && GetRemote()->MaintainConnection());
		msg->SetUUIEChanged();
	}
}

void CallSignalSocket::OnStatus(SignalingMsg * msg)
{
	if (!GetRemote()) {
		// ignore the Status message if we don't have a remote side,
		// thus avoiding sending a ReleaseComplete to the sender of the Status
		m_result = NoData;
	}
}

bool CallSignalSocket::OnTunneledH245(H225_ArrayOf_PASN_OctetString & h245Control, bool & suppress)
{
	bool changed = false;
	for (PINDEX i = 0; i < h245Control.GetSize(); ++i) {
		PPER_Stream strm = h245Control[i].GetValue();
		if (HandleH245Mesg(strm, suppress)) {
			h245Control[i].SetValue(strm);
			changed = true;
		}
	}
	return changed;
}

bool CallSignalSocket::OnFastStart(H225_ArrayOf_PASN_OctetString & fastStart, bool fromCaller)
{
	bool changed = false;
	for (PINDEX i = 0; i < fastStart.GetSize(); ++i) {
		PPER_Stream strm = fastStart[i].GetValue();
		H245_OpenLogicalChannel olc;
		if (!olc.Decode(strm)) {
			PTRACE(1, "Q931\t" << GetName() << " ERROR DECODING FAST START ELEMENT " << i);
			SNMP_TRAP(9, SNMPWarning, Network, "Error decofing fastStart element");
			return false;
		}
		PTRACE(6, "Q931\nfastStart[" << i << "] received: " << setprecision(2) << olc);

		// remove disabled audio codecs
		if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData && olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() != H245_DataType::e_nullData) {
			H245_AudioCapability & ac = olc.m_forwardLogicalChannelParameters.m_dataType;
			if (m_call->GetDisabledCodecs().Find(ac.GetTagName() + ";", 0) != P_MAX_INDEX) {
				PTRACE(4, "Delete Audio Forward Logical Channel " << ac.GetTagName());
				fastStart.RemoveAt(i);
				i--;
				continue;
			}
		}
		if (olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData && olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() != H245_DataType::e_nullData) {
			H245_AudioCapability & ac = olc.m_reverseLogicalChannelParameters.m_dataType;
			if (m_call->GetDisabledCodecs().Find(ac.GetTagName() + ";", 0) != P_MAX_INDEX) {
				PTRACE(4, "Delete Audio Reverse Logical Channel "  << ac.GetTagName());
				fastStart.RemoveAt(i);
				i--;
				continue;
			}
		}

		// remove disabled video codecs
		if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_videoData && olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() != H245_DataType::e_nullData) {
			H245_VideoCapability & vc = olc.m_forwardLogicalChannelParameters.m_dataType;
			if (m_call->GetDisabledCodecs().Find(vc.GetTagName() + ";", 0) != P_MAX_INDEX) {
				PTRACE(4, "Delete Video Forward Logical Channel " << vc.GetTagName());
				fastStart.RemoveAt(i);
				i--;
				continue;
			}
		}
		if (olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_videoData && olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() != H245_DataType::e_nullData) {
			H245_VideoCapability & vc = olc.m_reverseLogicalChannelParameters.m_dataType;
			if (m_call->GetDisabledCodecs().Find(vc.GetTagName() + ";", 0) != P_MAX_INDEX) {
				PTRACE(4, "Delete Video Reverse Logical Channel "  << vc.GetTagName());
				fastStart.RemoveAt(i);
				i--;
				continue;
			}
		}

		bool altered = false;
		if (fromCaller) {
			altered = m_h245handler->HandleFastStartSetup(olc, m_call);
		} else {
#ifdef HAS_H46018
			if (m_call->H46019Required() && PIsDescendant(m_h245handler, H245ProxyHandler) && ((H245ProxyHandler*)m_h245handler)->UsesH46019()) {
				altered = ((H245ProxyHandler*)m_h245handler)->HandleFastStartResponse(olc, m_call);
			} else
#endif
			{
				altered = m_h245handler->HandleFastStartResponse(olc, m_call);
			}
		}
		if (altered) {
			PPER_Stream wtstrm;
			olc.Encode(wtstrm);
			wtstrm.CompleteEncoding();
			fastStart[i].SetValue(wtstrm);
			changed = true;
			PTRACE(6, "Q931\nfastStart[" << i << "] to send " << setprecision(2) << olc);
		}

		// save media IPs
        if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)) {
            H245_OpenLogicalChannel_reverseLogicalChannelParameters & revParams = olc.m_reverseLogicalChannelParameters;
            bool isAudio = (revParams.m_dataType.GetTag() == H245_DataType::e_audioData);
            bool isVideo = (revParams.m_dataType.GetTag() == H245_DataType::e_videoData);
            if (revParams.HasOptionalField(H245_OpenLogicalChannel_reverseLogicalChannelParameters::e_multiplexParameters)
                && revParams.m_multiplexParameters.GetTag() == H245_OpenLogicalChannel_reverseLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters) {

                H245_H2250LogicalChannelParameters & channel = olc.m_reverseLogicalChannelParameters.m_multiplexParameters;
                if (channel.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)) {
                    H245_UnicastAddress *addr = GetH245UnicastAddress(channel.m_mediaChannel);
                    if (addr != NULL && m_call) {
                        PIPSocket::Address ip;
                        *addr >> ip;
                        WORD port = GetH245Port(*addr);
                        if (isAudio && fromCaller) {
                            m_call->SetCallerAudioIP(ip, port);
                        }
                        if (isVideo && fromCaller) {
                            m_call->SetCallerVideoIP(ip, port);
                        }
                        if (isAudio && !fromCaller) {
                            m_call->SetCalledAudioIP(ip, port);
                        }
                        if (isVideo && !fromCaller) {
                            m_call->SetCalledVideoIP(ip, port);
                        }
                    }
                }
            }
        }

		H245_AudioCapability * audioCap = NULL;
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
				&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData) {
			audioCap = &((H245_AudioCapability&)olc.m_reverseLogicalChannelParameters.m_dataType);
		} else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData) {
			audioCap = &((H245_AudioCapability&)olc.m_forwardLogicalChannelParameters.m_dataType);
		}
		if (audioCap != NULL && m_call) {
            if (m_callerSocket) {
                m_call->SetCallerAudioCodec(GetH245CodecName(*audioCap));
                m_call->SetCallerAudioBitrate(GetH245CodecBitrate(*audioCap));
            } else {
                m_call->SetCalledAudioCodec(GetH245CodecName(*audioCap));
                m_call->SetCalledAudioBitrate(GetH245CodecBitrate(*audioCap));
            }
        }

		H245_VideoCapability * videoCap = NULL;
		bool h235Video = false;
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
				&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_videoData) {
			videoCap = &((H245_VideoCapability&)olc.m_reverseLogicalChannelParameters.m_dataType);
		} else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_videoData) {
			videoCap = &((H245_VideoCapability&)olc.m_forwardLogicalChannelParameters.m_dataType);
		} else if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)
				&& olc.m_reverseLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_h235Media) {
			H245_H235Media & h235data = olc.m_reverseLogicalChannelParameters.m_dataType;
			if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_videoData) {
				videoCap = &((H245_VideoCapability&)h235data.m_mediaType);
				h235Video = true;
			}
		} else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_h235Media) {
			H245_H235Media & h235data = olc.m_forwardLogicalChannelParameters.m_dataType;
			if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_videoData) {
				videoCap = &((H245_VideoCapability&)h235data.m_mediaType);
				h235Video = true;
			}
		}
		if (videoCap != NULL && videoCap->GetTag() != H245_VideoCapability::e_extendedVideoCapability && m_call) {
            if (m_callerSocket) {
                m_call->SetCallerVideoCodec(GetH245CodecName(*videoCap) + (h235Video ? " (H.235)" : ""));
                m_call->SetCallerVideoBitrate(GetH245CodecBitrate(*videoCap));
            } else {
                m_call->SetCalledVideoCodec(GetH245CodecName(*videoCap) + (h235Video ? " (H.235)" : ""));
                m_call->SetCalledVideoBitrate(GetH245CodecBitrate(*videoCap));
            }
        }
	}
	if (changed) {
		PTRACE(4, "New FastStart: " << setprecision(2) << fastStart);
	}
	return changed;
}

void CallSignalSocket::BuildFacilityPDU(Q931 & FacilityPDU, int reason, const PObject *parm, bool h46017)
{
	PBoolean fromDest = m_crv & 0x8000u;
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_facility);
	H225_Facility_UUIE & uuie = body;
	// Don't set protocolID intentionally so the remote
	// can determine whether this is a message generate by GnuGk
	// uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (m_call) {
		uuie.IncludeOptionalField(H225_Facility_UUIE::e_conferenceID);
		uuie.m_conferenceID = m_call->GetConferenceIdentifier();
		uuie.IncludeOptionalField(H225_Facility_UUIE::e_callIdentifier);
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	}
	uuie.m_reason.SetTag(reason);
	switch (reason)
	{
		case H225_FacilityReason::e_transportedInformation:
			break;
		case H225_FacilityReason::e_startH245:
			uuie.IncludeOptionalField(H225_Facility_UUIE::e_h245Address);
			if (CallSignalSocket *ret = dynamic_cast<CallSignalSocket *>(remote)) {
				if (m_h245socket) {
					uuie.m_h245Address = m_h245socket->GetH245Address(ret->masqAddr);
				}
			} else {
				PTRACE(2, "Warning: " << GetName() << " has no remote party?");
			}
#ifdef HAS_H46018
			// add H.460.19 indicator if this is sent out to an endpoint that uses it
			if (m_call && m_call->GetCalledParty() && m_call->H46019Required()
				&& (m_call->GetCalledParty()->GetTraversalRole() != None) )
			{
				m_crv = m_call->GetCallRef();	// make sure m_crv is set
				uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
				uuie.RemoveOptionalField(H225_Facility_UUIE::e_conferenceID);
				H460_FeatureStd feat = H460_FeatureStd(19);
				H460_FeatureID * feat_id = NULL;
				if (m_call->GetCalledParty() && m_call->GetCalledParty()->IsTraversalClient()) {
					feat_id = new H460_FeatureID(2);	// mediaTraversalServer
					feat.AddParameter(feat_id);
					delete feat_id;
				}
				if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)) {
					feat_id = new H460_FeatureID(1);	// supportTransmitMultiplexedMedia
					feat.AddParameter(feat_id);
					delete feat_id;
				}
				uuie.IncludeOptionalField(H225_Facility_UUIE::e_featureSet);
				uuie.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				AddH460Feature(uuie.m_featureSet.m_supportedFeatures, feat);
			}
#endif
			break;

#ifdef HAS_H46018
		case H225_FacilityReason::e_undefinedReason:
			if (parm) {
				fromDest = PTrue;
				uuie.IncludeOptionalField(H225_Facility_UUIE::e_callIdentifier);
				uuie.m_callIdentifier = *dynamic_cast<const H225_CallIdentifier *>(parm);
				// if configured minimum H.225 version is > 6 use that otherwise use at least 6
                if (ProtocolVersion(H225_ProtocolID) > 6) {
                    uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
                } else {
                    uuie.m_protocolIdentifier.SetValue(H225_ProtocolIDv6);
                }
				uuie.RemoveOptionalField(H225_Facility_UUIE::e_conferenceID);
			}
			break;
#endif

		case H225_FacilityReason::e_callForwarded:
		case H225_FacilityReason::e_routeCallToMC:
			uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
			if (const H225_TransportAddress *addr = dynamic_cast<const H225_TransportAddress *>(parm)) {
				uuie.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAddress);
				uuie.m_alternativeAddress = *addr;
			} else if (const PString *dest = dynamic_cast<const PString *>(parm)) {
				PString destination = *dest;
				PString alias = "";
				PString ip = "";
				WORD destport = GK_DEF_ENDPOINT_SIGNAL_PORT;
				PINDEX at = destination.Find('@');
				if (at != P_MAX_INDEX) {
					alias = destination.Left(at);
					destination = destination.Right(destination.GetLength() - (at + 1));
				}
				if (IsIPAddress(destination)) {
					PStringArray adr_parts = SplitIPAndPort(destination, GK_DEF_ENDPOINT_SIGNAL_PORT);
					ip = adr_parts[0];
					destport = (WORD)adr_parts[1].AsUnsigned();
				}

				if (!ip.IsEmpty()) {
					H225_TransportAddress destaddr;
					if (GetTransportAddress(ip, destport, destaddr)) {
						uuie.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAddress);
						uuie.m_alternativeAddress = destaddr;
					} else {
						PTRACE(2, "Warning: Invalid transport address (" << AsString(PIPSocket::Address(ip), destport) << ")");
					}
				} else {
					alias = destination;
				}
				if (!alias.IsEmpty()) {
					uuie.IncludeOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress);
					uuie.m_alternativeAliasAddress.SetSize(1);
					H323SetAliasAddress(alias, uuie.m_alternativeAliasAddress[0]);
				}
				if (reason == H225_FacilityReason::e_routeCallToMC) {
					uuie.IncludeOptionalField(H225_Facility_UUIE::e_conferenceID);
				}
			}
			break;
	}

    if (h46017) {
        FacilityPDU.BuildFacility(0, fromDest); // CRV must be 0
    } else {
        FacilityPDU.BuildFacility(m_crv, fromDest);
    }
	if (reason == H225_FacilityReason::e_undefinedReason) {
		FacilityPDU.RemoveIE(Q931::FacilityIE);
	}
	SetUUIE(FacilityPDU, signal);
}

void CallSignalSocket::BuildProgressPDU(Q931 & ProgressPDU, PBoolean fromDestination)
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_progress);
	H225_Progress_UUIE & uuie = body;
	uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (m_call) {
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	}

	ProgressPDU.BuildProgress(m_crv, fromDestination, Q931::ProgressInbandInformationAvailable);
	SetUUIE(ProgressPDU, signal);
}

void CallSignalSocket::BuildNotifyPDU(Q931 & NotifyPDU, PBoolean fromDestination)
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_notify);
	H225_Notify_UUIE & uuie = body;
	uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (m_call) {
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	}
	NotifyPDU.BuildNotify(m_crv, fromDestination);
	// H.225.0 clause 7.4.2 says that a Notify must include a NotificationIndicationIE (0x27)
	PBYTEArray NotificationIndicatonIE;
	NotificationIndicatonIE.SetSize(1);
	NotificationIndicatonIE[0] = 0x82;  // bearer service changed
    NotifyPDU.SetIE((Q931::InformationElementCodes)0x27, NotificationIndicatonIE);
	SetUUIE(NotifyPDU, signal);
}

void CallSignalSocket::BuildStatusPDU(Q931 & StatusPDU, PBoolean fromDestination)
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_status);
	H225_Status_UUIE & uuie = body;
	uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (m_call) {
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	}
	StatusPDU.BuildNotify(m_crv, fromDestination);
	SetUUIE(StatusPDU, signal);
}

void CallSignalSocket::BuildStatusInquiryPDU(Q931 & StatusInquiryPDU, PBoolean fromDestination)
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_statusInquiry);
	H225_StatusInquiry_UUIE & uuie = body;
	uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (m_call) {
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	}
	StatusInquiryPDU.BuildNotify(m_crv, fromDestination);
	SetUUIE(StatusInquiryPDU, signal);
}

void CallSignalSocket::BuildInformationPDU(Q931 & InformationPDU, PBoolean fromDestination)
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_information);
	H225_Information_UUIE & uuie = body;
	uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (m_call) {
		uuie.m_callIdentifier = m_call->GetCallIdentifier();
	}
	InformationPDU.BuildInformation(m_crv, fromDestination);
	SetUUIE(InformationPDU, signal);
}

void CallSignalSocket::BuildProceedingPDU(Q931 & ProceedingPDU, const H225_CallIdentifier & callId, unsigned crv)
{
	H225_H323_UserInformation signal;
	H225_H323_UU_PDU_h323_message_body & body = signal.m_h323_uu_pdu.m_h323_message_body;
	body.SetTag(H225_H323_UU_PDU_h323_message_body::e_callProceeding);
	H225_CallProceeding_UUIE & uuie = body;
	uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
	uuie.m_callIdentifier = callId;
	uuie.m_destinationInfo.IncludeOptionalField(H225_EndpointType::e_gatekeeper);
	if (GkConfig()->GetBoolean(RoutedSec, "UseProvisionalRespToH245Tunneling", false)) {
		signal.m_h323_uu_pdu.RemoveOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
		signal.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_provisionalRespToH245Tunneling);
	} else {
		signal.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
		if (m_h245TunnelingTranslation)
			signal.m_h323_uu_pdu.m_h245Tunneling.SetValue(m_h245Tunneling);
		else
			signal.m_h323_uu_pdu.m_h245Tunneling.SetValue(false);
	}
	ProceedingPDU.BuildCallProceeding(crv);
	SetUUIE(ProceedingPDU, signal);

	PrintQ931(5, "Send to ", GetName(), &ProceedingPDU, &signal);
}

void CallSignalSocket::BuildSetupPDU(Q931 & SetupPDU, const H225_CallIdentifier & callid, unsigned crv, const PString & destination, bool h245tunneling)
{
	SetupPDU.BuildSetup(crv);
	H225_H323_UserInformation signal;
	signal.m_h323_uu_pdu.m_h245Tunneling = h245tunneling;
	signal.m_h323_uu_pdu.m_h323_message_body.SetTag(H225_H323_UU_PDU_h323_message_body::e_setup);
	H225_Setup_UUIE & setup = signal.m_h323_uu_pdu.m_h323_message_body;
	setup.m_protocolIdentifier.SetValue(H225_ProtocolID);
	setup.m_conferenceID = callid.m_guid; // generate new: OpalGloballyUniqueID();
	setup.m_callIdentifier.m_guid = setup.m_conferenceID;
	masqAddr = RasServer::Instance()->GetMasqAddress(peerAddr);
	setup.IncludeOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress);
	setup.m_sourceCallSignalAddress = SocketToH225TransportAddr(masqAddr, GetPort());
	// check if destination contain IP to set destCallSigAdr
	PString alias;
	PString destip;
	PINDEX at = destination.Find("@");
	if (at != P_MAX_INDEX) {
		alias = destination.Left(at);
		destip = destination.Mid(at+1);
		if (!IsIPAddress(destip)) {
			// use as URL_ID
			destip = "";
			alias = destination;
		}
	} else {
		if (IsIPAddress(destination)) {
			destip = destination;
		} else {
			alias = destination;
		}
	}
	if (!destip.IsEmpty()) {
		setup.IncludeOptionalField(H225_Setup_UUIE::e_destCallSignalAddress);
		PStringArray adr_parts = SplitIPAndPort(destip, GK_DEF_ENDPOINT_SIGNAL_PORT);
		PIPSocket::Address ip(adr_parts[0]);
		WORD port = (WORD)(adr_parts[1].AsInteger());
		setup.m_destCallSignalAddress = SocketToH225TransportAddr(ip, port);
	}
	if (!alias.IsEmpty()) {
		setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
		setup.m_destinationAddress.SetSize(1);
		H323SetAliasAddress(alias, setup.m_destinationAddress[0]);
		if (setup.m_destinationAddress[0].GetTag() == H225_AliasAddress::e_dialedDigits) {
			SetupPDU.SetCalledPartyNumber(alias);
		}
	}
	// set bearer capability to unrestricted information transfer + huge transfer rate
	PBYTEArray caps;
	caps.SetSize(4);
	caps[0] = 0x88;
	caps[1] = 0x18;
	caps[2] = 0x86;
	caps[3] = 0xa5;
	SetupPDU.SetIE(Q931::BearerCapabilityIE, caps);
	SetUUIE(SetupPDU, signal);
}

// handle a new message on a new connection
void CallSignalSocket::Dispatch()
{
	ReadLock lock(ConfigReloadMutex);

	const PTime channelStart;
	const int setupTimeout = PMAX(GkConfig()->GetInteger(RoutedSec, "SetupTimeout", DEFAULT_SETUP_TIMEOUT), (long)1000);
	int timeout = setupTimeout;

	if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
		Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
			GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "0")) ? 1 : 0,
			SOL_SOCKET
			);

	while (timeout > 0) {
		ConfigReloadMutex.EndRead();
		if (!IsReadable(timeout)) {
			PTRACE(3, "Q931\tTimed out waiting for initial Setup message from " << GetName());
			ConfigReloadMutex.StartRead();
			break;
		}
		ConfigReloadMutex.StartRead();

		switch (ReceiveData()) {
		case NoData:
			if (m_isnatsocket) {
				GetHandler()->Insert(this);
				return;
			}
			// update timeout to reflect remaing time
			timeout = setupTimeout - (PTime() - channelStart).GetInterval();
			break;

		case Connecting:
			if (InternalConnectTo()) {
				if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
					remote->Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
						GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "0")) ? 1 : 0,
						SOL_SOCKET);


				ConfigReloadMutex.EndRead();
				const bool isReadable = remote->IsReadable(2 * setupTimeout);
				ConfigReloadMutex.StartRead();
				if (!isReadable) {
					PTRACE(3, "Q931\tTimed out waiting for a response to Setup or SCI message from " << remote->GetName());
					if (m_call)
						m_call->SetDisconnectCause(Q931::TimerExpiry);
					OnError();
				}
				GetHandler()->Insert(this, remote);
				return;
			} else if (m_call && m_call->MoveToNextRoute() && (m_h245socket == NULL || m_call->DisableRetryChecks())) {
				PTRACE(3, "Q931\t" << AsString(peerAddr, peerPort) << " DIDN'T ACCEPT THE CALL");
				if (m_call) {
					m_call->SetCallSignalSocketCalled(NULL);
					m_call->SetDisconnectCause(Q931::NoRouteToDestination);
					m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
					m_call->SetDisconnectTime(time(NULL));
				}

				RemoveH245Handler();

				if (m_call->GetNewRoutes().empty()) {
					PTRACE(1, "Q931\tERROR: Call retry without a route");
					SNMP_TRAP(10, SNMPWarning, Network, "Call retry without route");
					return;
				}
				CallRec * newCall = new CallRec(m_call.operator ->());
				CallTable::Instance()->RemoveFailedLeg(m_call);
				Route newRoute = m_call->GetNewRoutes().front();
				PTRACE(1, "Q931\tNew route: " << newRoute.AsString());
				m_call = callptr(newCall);

				if (newRoute.m_destEndpoint)
					m_call->SetCalled(newRoute.m_destEndpoint);
				else
					m_call->SetDestSignalAddr(newRoute.m_destAddr);

				if (newRoute.m_flags & Route::e_toParent)
					m_call->SetToParent(true);
				if (newRoute.m_useTLS)
					m_call->SetConnectWithTLS(true);

				if (!newRoute.m_destNumber.IsEmpty()) {
					H225_ArrayOf_AliasAddress destAlias;
					destAlias.SetSize(1);
					H323SetAliasAddress(newRoute.m_destNumber, destAlias[0]);
					newCall->SetRouteToAlias(destAlias);
				}

				CallTable::Instance()->Insert(newCall);

				m_remoteLock.Wait();
				if (remote != NULL) {
					remote->RemoveRemoteSocket();
					delete remote;
					remote = NULL;
				}
				m_remoteLock.Signal();

				buffer = m_rawSetup;
				buffer.MakeUnique();

				ReadUnlock unlock(ConfigReloadMutex);
				DispatchNextRoute();
				return;
			} else {
				PTRACE(3, "Q931\t" << AsString(peerAddr, peerPort) << " DIDN'T ACCEPT THE CALL");
				SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
				if (m_call) {
					m_call->SetCallSignalSocketCalled(NULL);
					m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
				}
				CallTable::Instance()->RemoveCall(m_call);
				m_remoteLock.Wait();
				delete remote;
				remote = NULL;
				m_remoteLock.Signal();
				TCPProxySocket::EndSession();
				timeout = 0;
				break;
			}

#ifdef HAS_H46018
		case DelayedConnecting:
			GetHandler()->Insert(this);
			return;
#endif

		case Forwarding:
			if (remote && remote->IsConnected()) { // remote is NAT socket
				if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
					remote->Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
						GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "0")) ? 1 : 0,
						SOL_SOCKET
						);
				ForwardData();
// in case of NAT socket, IsReadable cause race condition if the remote socket
// is selected by its proxy handler, thanks to Daniel Liu
//
//					if (!remote->IsReadable(2*setupTimeout)) {
//						PTRACE(3, "Q931\tTimed out waiting for a response to Setup message from " << remote->GetName());
//						if (m_call) {
//							m_call->SetDisconnectCause(Q931::TimerExpiry);
//							CallTable::Instance()->RemoveCall(m_call);
//						}
//					}
				return;
			}
            // fallthrough intended

		default:
		    PTRACE(0, "JW CallSignalSocket::Dispatch() -> OnError()");
			OnError();
			timeout = 0;
			break;
		} /* switch */
	} /* while */

	if (m_call)
		m_call->SetSocket(NULL, NULL);

#ifdef HAS_H46017
	if (m_h46017Enabled) {
		// if this is a H.460.17 socket, make sure its removed from the EPRec
		RegistrationTable::Instance()->OnNATSocketClosed(this);
		CleanupCall();
	}
#endif
	delete this;
}

ProxySocket::Result CallSignalSocket::RetrySetup()
{
	H225_H323_UserInformation *uuie = NULL;
	Q931 *q931pdu = new Q931();

	buffer = m_rawSetup;
	buffer.MakeUnique();

	if (!q931pdu->Decode(buffer)) {
		PTRACE(1, Type() << "\t" << GetName() << " ERROR DECODING Q.931!");
		delete q931pdu;
		q931pdu = NULL;
		return m_result = Error;
	}

	PIPSocket::Address _localAddr, _peerAddr;
	WORD _localPort = 0, _peerPort = 0;
	GetLocalAddress(_localAddr, _localPort);
	UnmapIPv4Address(_localAddr);
	GetPeerAddress(_peerAddr, _peerPort);
	UnmapIPv4Address(_peerAddr);

	PTRACE(3, Type() << "\tRetrying " << q931pdu->GetMessageTypeName()
		<< " CRV=" << q931pdu->GetCallReference() << " from " << GetName());

	if (q931pdu->HasIE(Q931::UserUserIE)) {
		uuie = new H225_H323_UserInformation();
		if (!GetUUIE(*q931pdu, *uuie)) {
			PTRACE(1, Type() << "\tCould not decode User-User IE for message "
				<< q931pdu->GetMessageTypeName() << " CRV=" << q931pdu->GetCallReference() << " from " << GetName());
			delete uuie;
			uuie = NULL;
			delete q931pdu;
			q931pdu = NULL;
			return m_result = Error;
		}
	}

	m_result = Forwarding;

	SignalingMsg *msg = SignalingMsg::Create(q931pdu, uuie,
		_localAddr, _localPort, _peerAddr, _peerPort);

	if (m_h245Tunneling && uuie != NULL)
#if H225_PROTOCOL_VERSION >= 4
		if (!uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_provisionalRespToH245Tunneling))
#endif
		m_h245Tunneling = (uuie->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Tunneling)
			&& uuie->m_h323_uu_pdu.m_h245Tunneling.GetValue());

	switch (msg->GetTag()) {
	case Q931::SetupMsg:
		OnSetup(msg);
		break;
	default:
		PTRACE(1, Type() << "\t" << GetName() << " decoded message is not a Setup");
		delete msg;
		return m_result = Error;
	}

	if (m_result == Error || m_result == NoData) {
		delete msg;
		return m_result;
	}

	if (msg->GetUUIE() != NULL && msg->GetUUIE()->m_h323_uu_pdu.HasOptionalField(H225_H323_UU_PDU::e_h245Control)
			&& m_h245handler) {
		bool suppress = false;	// ignore for now
		if (OnTunneledH245(msg->GetUUIE()->m_h323_uu_pdu.m_h245Control, suppress))
			msg->SetUUIEChanged();
	}

	if (msg->GetQ931().HasIE(Q931::DisplayIE)) {
        PString newDisplayIE;
        PString screenDisplayIE = GkConfig()->GetString(RoutedSec, "ScreenDisplayIE", "");
        PString appendToDisplayIE = GkConfig()->GetString(RoutedSec, "AppendToDisplayIE", "");
        if (!m_call->GetCallerID().IsEmpty() || !m_call->GetCallerDisplayIE().IsEmpty()) {
            newDisplayIE = m_call->GetCallerID();
            if (!m_call->GetCallerDisplayIE().IsEmpty()) {
                newDisplayIE = m_call->GetCallerDisplayIE();
            }
        } else if (screenDisplayIE != PCaselessString("Called")) {
            newDisplayIE = screenDisplayIE + appendToDisplayIE;
        }
        if (screenDisplayIE == PCaselessString("Calling") || screenDisplayIE == PCaselessString("CallingCalled")) {
            if (m_call) {
                newDisplayIE = m_call->GetCallingStationId() + appendToDisplayIE;
            }
        }
		if (!newDisplayIE.IsEmpty()) {
            PTRACE(4, "Q931\tSetting DisplayIE to " << newDisplayIE);
			msg->GetQ931().SetDisplayName(newDisplayIE);
			msg->SetChanged();
		}
	}

	if (msg->IsChanged() && !msg->Encode(buffer))
		m_result = Error;
	else if (remote)
		PrintQ931(4, "Send to ", remote->GetName(), &msg->GetQ931(), msg->GetUUIE());

	delete msg;
	return m_result;
}

void CallSignalSocket::DispatchNextRoute()
{
	ReadLock lock(ConfigReloadMutex);
	const int setupTimeout = PMAX(GkConfig()->GetInteger(RoutedSec, "SetupTimeout", DEFAULT_SETUP_TIMEOUT), (long)1000);

	const PTime channelStart;

	switch (RetrySetup()) {
	case Connecting:
		if (InternalConnectTo()) {
			if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
				remote->Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
					GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "0")) ? 1 : 0,
					SOL_SOCKET);

			ConfigReloadMutex.EndRead();
			const bool isReadable = remote->IsReadable(2 * setupTimeout);
			ConfigReloadMutex.StartRead();
			if (!isReadable) {
				PTRACE(3, "Q931\tTimed out waiting for a response to Setup message from " << remote->GetName());
				if (m_call)
					m_call->SetDisconnectCause(Q931::TimerExpiry);
				OnError();
			}
			GetHandler()->Insert(this, remote);
			return;
		} else if (m_call && m_call->MoveToNextRoute()) {
			PTRACE(3, "Q931\t" << AsString(peerAddr, peerPort) << " DIDN'T ACCEPT THE CALL");

			m_call->SetCallSignalSocketCalled(NULL);
			m_call->SetDisconnectCause(Q931::NoRouteToDestination);
			m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);

			if (m_call->GetNewRoutes().empty()) {
				PTRACE(1, "Q931\tERROR: Call retry without a route");
				SNMP_TRAP(10, SNMPWarning, Network, "Call retry without route");
				return;
			}
			const Route &newRoute = m_call->GetNewRoutes().front();
			PTRACE(1, "Q931\tNew route: " << newRoute.AsString());

			CallRec *newCall = new CallRec(m_call.operator ->());
			CallTable::Instance()->RemoveFailedLeg(m_call);
			m_call = callptr(newCall);

			if (newRoute.m_destEndpoint)
				m_call->SetCalled(newRoute.m_destEndpoint);
			else
				m_call->SetDestSignalAddr(newRoute.m_destAddr);

			if (newRoute.m_flags & Route::e_toParent)
				m_call->SetToParent(true);
			if (newRoute.m_useTLS)
				m_call->SetConnectWithTLS(true);

			if (!newRoute.m_destNumber.IsEmpty()) {
				H225_ArrayOf_AliasAddress destAlias;
				destAlias.SetSize(1);
				H323SetAliasAddress(newRoute.m_destNumber, destAlias[0]);
				newCall->SetRouteToAlias(destAlias);
			}

			CallTable::Instance()->Insert(newCall);

			m_remoteLock.Wait();
			if (remote != NULL) {
				remote->RemoveRemoteSocket();
				delete remote;
				remote = NULL;
			}
			m_remoteLock.Signal();

			buffer = m_rawSetup;
			buffer.MakeUnique();

			ReadUnlock unlock(ConfigReloadMutex);
			DispatchNextRoute();
			return;
		} else {
			PTRACE(3, "Q931\t" << AsString(peerAddr, peerPort) << " DIDN'T ACCEPT THE CALL");
			SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
			if (m_call) {
				m_call->SetCallSignalSocketCalled(NULL);
				m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
			}
			CallTable::Instance()->RemoveCall(m_call);
			m_remoteLock.Wait();
			delete remote;
			remote = NULL;
			m_remoteLock.Signal();
			TCPProxySocket::EndSession();
			break;
		}

	case Forwarding:
		if (remote && remote->IsConnected()) { // remote is NAT socket
			if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
				remote->Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
					GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "0")) ? 1 : 0,
					SOL_SOCKET);
			ForwardData();
// in case of NAT socket, IsReadable cause race condition if the remote socket
// is selected by its proxy handler, thanks to Daniel Liu
//
//					if (!remote->IsReadable(2*setupTimeout)) {
//						PTRACE(3, "Q931\tTimed out waiting for a response to Setup message from " << remote->GetName());
//						if (m_call) {
//							m_call->SetDisconnectCause(Q931::TimerExpiry);
//							CallTable::Instance()->RemoveCall(m_call);
//						}
//					}
			return;
		}
		// fallthrough intended

	default:
	    PTRACE(0, "JW DispatchNextRoute OnError()");
		OnError();
		break;
	} /* switch */

	if (m_call)
		m_call->SetSocket(NULL, NULL);
	delete this; // oh!
}

bool CallSignalSocket::SendTunneledH245(const PPER_Stream & strm)
{
    PTRACE(0, "JW SendTunneledH245 PER");
	Q931 q931;
	H225_H323_UserInformation uuie;
	PBYTEArray lBuffer;
	BuildFacilityPDU(q931, 0);
	q931.RemoveIE(Q931::FacilityIE);
	GetUUIE(q931, uuie);
	H225_Facility_UUIE & facility_uuie = uuie.m_h323_uu_pdu.m_h323_message_body;
	if (m_h225Version < 4) {
		// prior to H.225.0 version 4 we send an empty body
		facility_uuie.SetTag(H225_H323_UU_PDU_h323_message_body::e_empty);
	} else {
		// starting with version 4 we send reason transportedInformation plus callID
        if (ProtocolVersion(H225_ProtocolID) > 4) {
            facility_uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
        } else {
            facility_uuie.m_protocolIdentifier.SetValue(H225_ProtocolIDv4);	// we are at least version 4
        }
		facility_uuie.m_reason.SetTag(H225_FacilityReason::e_transportedInformation);
		if (m_call) {
			facility_uuie.IncludeOptionalField(H225_Facility_UUIE::e_callIdentifier);
			facility_uuie.m_callIdentifier = m_call->GetCallIdentifier();
		}
		facility_uuie.RemoveOptionalField(H225_Facility_UUIE::e_conferenceID);
		facility_uuie.RemoveOptionalField(H225_Facility_UUIE::e_multipleCalls);
		facility_uuie.RemoveOptionalField(H225_Facility_UUIE::e_maintainConnection);
	}
	uuie.m_h323_uu_pdu.m_h245Tunneling = TRUE;
	uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Control);
	uuie.m_h323_uu_pdu.m_h245Control.SetSize(1);
	uuie.m_h323_uu_pdu.m_h245Control[0].SetValue(strm);
	SetUUIE(q931, uuie);
	q931.Encode(lBuffer);

	PrintQ931(3, "Send to ", GetName(), &q931, &uuie);
	return TransmitData(lBuffer);
}

bool CallSignalSocket::SendTunneledH245(const H245_MultimediaSystemControlMessage & h245msg)
{
    PTRACE(0, "JW SendTunneledH245 H245");
	Q931 q931;
	H225_H323_UserInformation uuie;
	PBYTEArray lBuffer;
	BuildFacilityPDU(q931, 0);
	GetUUIE(q931, uuie);
	H225_Facility_UUIE & facility_uuie = uuie.m_h323_uu_pdu.m_h323_message_body;
	if (m_h225Version < 4) {
		// prior to H.225.0 version 4 we send an empty body
		facility_uuie.SetTag(H225_H323_UU_PDU_h323_message_body::e_empty);
	} else {
		// starting with version 4 we send reason transportedInformation plus callID
        if (ProtocolVersion(H225_ProtocolID) > 4) {
            facility_uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
        } else {
            facility_uuie.m_protocolIdentifier.SetValue(H225_ProtocolIDv4);	// we are at least version 4
        }
		facility_uuie.m_protocolIdentifier.SetValue(H225_ProtocolIDv4);	// we are at least version 4
		facility_uuie.m_reason.SetTag(H225_FacilityReason::e_transportedInformation);
		if (m_call) {
			facility_uuie.IncludeOptionalField(H225_Facility_UUIE::e_callIdentifier);
			facility_uuie.m_callIdentifier = m_call->GetCallIdentifier();
		}
		facility_uuie.RemoveOptionalField(H225_Facility_UUIE::e_conferenceID);
		facility_uuie.RemoveOptionalField(H225_Facility_UUIE::e_multipleCalls);
		facility_uuie.RemoveOptionalField(H225_Facility_UUIE::e_maintainConnection);
	}
	uuie.m_h323_uu_pdu.m_h245Tunneling = TRUE;
	uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Control);
	uuie.m_h323_uu_pdu.m_h245Control.SetSize(1);
	uuie.m_h323_uu_pdu.m_h245Control[0].EncodeSubType(h245msg);
	SetUUIE(q931, uuie);
	q931.Encode(lBuffer);

	PrintQ931(3, "Send to ", GetName(), &q931, &uuie);
	return TransmitData(lBuffer);
}

void CallSignalSocket::SendFacilityKeepAlive()
{
    Q931 FacilityPDU;
    H225_H323_UserInformation uuie;
    BuildFacilityPDU(FacilityPDU, H225_FacilityReason::e_transportedInformation);
    GetUUIE(FacilityPDU, uuie);
    H225_Facility_UUIE & facility_uuie = uuie.m_h323_uu_pdu.m_h323_message_body;
	facility_uuie.RemoveOptionalField(H225_Facility_UUIE::e_conferenceID);
    if (m_h225Version < 4) {
        // prior to H.225.0 version 4 we send an empty body
        facility_uuie.SetTag(H225_H323_UU_PDU_h323_message_body::e_empty);
    } else {
        // starting with version 4 we send reason transportedInformation plus callID
        if (ProtocolVersion(H225_ProtocolID) > 4) {
            facility_uuie.m_protocolIdentifier.SetValue(H225_ProtocolID);
        } else {
            facility_uuie.m_protocolIdentifier.SetValue(H225_ProtocolIDv4);	// we are at least version 4
        }
        facility_uuie.m_protocolIdentifier.SetValue(H225_ProtocolIDv4);	// we are at least version 4
        facility_uuie.m_reason.SetTag(H225_FacilityReason::e_transportedInformation);
    }
    uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
    uuie.m_h323_uu_pdu.m_h245Tunneling.SetValue(m_h245Tunneling);
    SetUUIE(FacilityPDU, uuie);

    PrintQ931(5, "Send to ", GetName(), &FacilityPDU, &uuie);

    PBYTEArray buf;
    FacilityPDU.Encode(buf);
    TransmitData(buf);
}

void CallSignalSocket::SendInformationKeepAlive()
{
    PBoolean fromDest = m_crv & 0x8000u;
    Q931 q931;
    H225_H323_UserInformation uuie;
    BuildInformationPDU(q931, fromDest);
    q931.SetCallState(Q931::CallState_Active);
    GetUUIE(q931, uuie);
    uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
    uuie.m_h323_uu_pdu.m_h245Tunneling.SetValue(m_h245Tunneling);
    SetUUIE(q931, uuie);

    PrintQ931(5, "Send to ", GetName(), &q931, &uuie);

    PBYTEArray buf;
    q931.Encode(buf);
    TransmitData(buf);
}

void CallSignalSocket::SendNotifyKeepAlive()
{
    PBoolean fromDest = m_crv & 0x8000u;
    Q931 q931;
    H225_H323_UserInformation uuie;
    BuildNotifyPDU(q931, fromDest);
    GetUUIE(q931, uuie);
    uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
    uuie.m_h323_uu_pdu.m_h245Tunneling.SetValue(m_h245Tunneling);
    SetUUIE(q931, uuie);

    PrintQ931(5, "Send to ", GetName(), &q931, &uuie);

    PBYTEArray buf;
    q931.Encode(buf);
    TransmitData(buf);
}

void CallSignalSocket::SendStatusKeepAlive()
{
    PBoolean fromDest = m_crv & 0x8000u;
    Q931 q931;
    H225_H323_UserInformation uuie;
    BuildStatusPDU(q931, fromDest);
    GetUUIE(q931, uuie);
    uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
    uuie.m_h323_uu_pdu.m_h245Tunneling.SetValue(m_h245Tunneling);
    SetUUIE(q931, uuie);

    PrintQ931(5, "Send to ", GetName(), &q931, &uuie);

    PBYTEArray buf;
    q931.Encode(buf);
    TransmitData(buf);
}

void CallSignalSocket::SendStatusInquiryKeepAlive()
{
    PBoolean fromDest = m_crv & 0x8000u;
    Q931 q931;
    H225_H323_UserInformation uuie;
    BuildStatusInquiryPDU(q931, fromDest);
    GetUUIE(q931, uuie);
    uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h245Tunneling);
    uuie.m_h323_uu_pdu.m_h245Tunneling.SetValue(m_h245Tunneling);
    SetUUIE(q931, uuie);

    PrintQ931(5, "Send to ", GetName(), &q931, &uuie);

    PBYTEArray buf;
    q931.Encode(buf);
    TransmitData(buf);
}

bool CallSignalSocket::SetH245Address(H225_TransportAddress & h245addr)
{
	if (GetRemote() && GetRemote()->m_h245Tunneling
		&& Toolkit::AsBool(GkConfig()->GetString(RoutedSec, "RemoveH245AddressOnTunneling", "0"))
		&& !m_h245TunnelingTranslation) {
		return false;
	}
	if (!m_h245handler) { // not H.245 routed
		return true;
	}

	CallSignalSocket *ret = static_cast<CallSignalSocket *>(remote);
	if (!ret) {
		PTRACE(2, "Warning: " << GetName() << " has no remote party?");
		return false;
	}
	m_h245handler->OnH245Address(h245addr);
	if (m_h245socket) {
		if (m_h245socket->IsConnected()) {
			PTRACE(4, "H245\t" << GetName() << " H245 channel already established");
			return false;
		} else {
			if (m_h245socket->SetH245Address(h245addr, masqAddr)) {
				std::swap(m_h245socket, ret->m_h245socket);
			}
			if (m_h245TunnelingTranslation && !m_h245Tunneling && GetRemote() && GetRemote()->m_h245Tunneling) {
				return false;	// remove H245Address from message if it goes to tunneling side
			}
			return true;
		}
	}
	bool userevert = m_isnatsocket;
#ifdef HAS_H46018
	if (m_call->H46019Required() && IsTraversalClient()) {
		userevert = true;
	}
#endif
	m_h245socket = userevert ? new NATH245Socket(this) : new H245Socket(this);	// TODO: handle TLS
	if (!(m_call->GetRerouteState() == RerouteInitiated)) {
		ret->m_h245socket = new H245Socket(m_h245socket, ret);	// TODO: handle TLS
	}

	m_h245socket->SetH245Address(h245addr, masqAddr);
	if (m_h245TunnelingTranslation && !m_h245Tunneling && GetRemote() && GetRemote()->m_h245Tunneling) {
		CreateJob(m_h245socket, &H245Socket::ConnectToDirectly, "H245ActiveConnector");	// connnect directly
		return false;	// remove H.245Address from message if it goes to tunneling side
	}
	if (m_call->GetRerouteState() == RerouteInitiated) {
		// if in reroute, don't listen, actively connect to the other side, half of the H.245 connection is already up
		m_h245socket->SetRemoteSocket(ret->m_h245socket);
		if (ret->m_h245socket) {
            ret->m_h245socket->SetRemoteSocket(m_h245socket);
        } else {
            PTRACE(1, "Reroute: Error mixed tunneled / non-tunneled call");
        }
		CreateJob(m_h245socket, &H245Socket::ConnectToRerouteDestination, "H245RerouteConnector");
	} else {
		CreateJob(m_h245socket, &H245Socket::ConnectTo, "H245Connector");	// start a listener
	}
	return true;
}

bool CallSignalSocket::InternalConnectTo()
{
	int numPorts = min(Q931PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = Q931PortRange.GetPort();
		if (remote->Connect(localAddr, pt, peerAddr)) {
			PTRACE(3, "Q931\tConnect to " << remote->GetName() << " from "
				<< AsString(localAddr, pt) << " successful");
			SetConnected(true);
			remote->SetConnected(true);
			// RE - TOS H.225 outbound - setup, releaseComplete etc.
			int dscp = GkConfig()->GetInteger(RoutedSec, "H225DiffServ", 0);
            if (dscp > 0) {
                int h225TypeOfService = (dscp << 2);
#if defined(hasIPV6) && defined(IPV6_TCLASS)
                if (localAddr.GetVersion() == 6) {
                    // for IPv6 set TCLASS
                    if (!ConvertOSError(::setsockopt(remote->GetHandle(), IPPROTO_IPV6, IPV6_TCLASS, (char *)&h225TypeOfService, sizeof(int)))) {
                        PTRACE(1, remote->Type() << "\tCould not set TCLASS field in IPv6 header: "
                            << GetErrorCode(PSocket::LastGeneralError) << '/'
                            << GetErrorNumber(PSocket::LastGeneralError) << ": "
                            << GetErrorText(PSocket::LastGeneralError));
                    }
                } else
#endif
                {
                    // setting IPTOS_PREC_CRITIC_ECP required root permission on Linux until 2008 (the 2.6.24.4), now it doesn't anymore
                    // setting IP_TOS will silently fail on Windows XP, Vista and Win7, supposed to work again on Win8
                    if (!ConvertOSError(::setsockopt(remote->GetHandle(), IPPROTO_IP, IP_TOS, (char *)&h225TypeOfService, sizeof(int)))) {
                        PTRACE(1, remote->Type() << "\tCould not set TOS field in IP header: "
                            << GetErrorCode(PSocket::LastGeneralError) << '/'
                            << GetErrorNumber(PSocket::LastGeneralError) << ": "
                            << GetErrorText(PSocket::LastGeneralError));
                    }
                }
            }

			ForwardData();
			return true;
		}
		int errorNumber = remote->GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, remote->Type() << "\tCould not open/connect Q.931 socket at "
			<< AsString(localAddr, pt)
			<< " - error " << remote->GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << remote->GetErrorText(PSocket::LastGeneralError)
			<< " remote addr: " << AsString(peerAddr));
		remote->Close();
	}

	return false;
}

bool CallSignalSocket::ForwardCallConnectTo()
{
	int numPorts = min(Q931PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = Q931PortRange.GetPort();
		if (remote->Connect(localAddr, pt, peerAddr)) {
			PTRACE(3, "Q931\tConnect to " << remote->GetName() << " from "
				<< AsString(localAddr, pt) << " successful"
				);
			SetConnected(true);
			remote->SetConnected(true);
			ForwardData();
			return true;
		}
		int errorNumber = remote->GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, remote->Type() << "\tCould not open/connect Q.931 socket at "
			<< AsString(localAddr, pt)
			<< " - error " << remote->GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << remote->GetErrorText(PSocket::LastGeneralError)
			<< " remote addr: " << AsString(peerAddr));
		remote->Close();
	}

	PTRACE(3, "Q931\t" << AsString(peerAddr, peerPort) << " DIDN'T ACCEPT THE CALL");
	SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
	if (m_call) {
		m_call->SetCallSignalSocketCalled(NULL);
		m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
	}
	CallTable::Instance()->RemoveCall(m_call);
	m_remoteLock.Wait();
	delete remote;
	remote = NULL;
	m_remoteLock.Signal();
	return false;
}

void CallSignalSocket::SetCallTypePlan(Q931 *q931)
{
	if (!q931 || !m_call)
		return;

	unsigned plan, type;
	int dtype;
	int dplan;
	PIPSocket::Address calleeAddr;
	WORD calleePort = 0;
	PString Number;
	Toolkit* toolkit = Toolkit::Instance();
	m_call->GetDestSignalAddr(calleeAddr, calleePort);
	H225_TransportAddress callerAddr = SocketToH225TransportAddr(calleeAddr, calleePort);
	endptr called = RegistrationTable::Instance()->FindBySignalAdr(callerAddr);

	if (q931->HasIE(Q931::CalledPartyNumberIE)) {
		if (q931->GetCalledPartyNumber(Number, &plan, &type)) {
			dtype = -1;
			dplan = -1;
			if (called) {
				int proxy = called->GetProxyType();
				if (proxy > 0) {
					m_call->SetProxyMode(proxy);
					PTRACE(4, Type() << "Proxy mode set " << proxy);
				}
				dtype = called->GetCallTypeOfNumber(true);
				if (dtype != -1)
					type = dtype;
				dplan = called->GetCallPlanOfNumber(true);
				if (dplan != -1)
					plan = dplan;
			}
			if (dtype == -1) {
				dtype = toolkit->Config()->GetInteger(RoutedSec, "CalledTypeOfNumber", -1);
				if (dtype != -1)
					type = dtype;
			}
			if (dplan == -1) {
				dplan = toolkit->Config()->GetInteger(RoutedSec, "CalledPlanOfNumber", -1);
				if (dplan != -1)
					plan = dplan;
			}
			q931->SetCalledPartyNumber(Number, plan, type);
			PTRACE(4, Type() << "\tSet Called Numbering Plan=" << plan << " TypeOfNumber=" << type);
		}
	}

	if (q931->HasIE(Q931::CallingPartyNumberIE)) {
		unsigned presentation = (unsigned)-1, screening = (unsigned)-1;
		if (q931->GetCallingPartyNumber(Number, &plan, &type, &presentation, &screening, (unsigned)-1, (unsigned)-1)) {
			dtype = -1;
			dplan = -1;
			if (called) {
				dtype = called->GetCallTypeOfNumber(false);
				if (dtype != -1)
					type = dtype;
				dplan = called->GetCallPlanOfNumber(false);
				if (dplan != -1)
					plan = dplan;
			}
			if (dtype == -1) {
				dtype = toolkit->Config()->GetInteger(RoutedSec, "CallingTypeOfNumber", -1);
				if (dtype != -1)
					type = dtype;
			}
			if (dplan == -1) {
				dplan = toolkit->Config()->GetInteger(RoutedSec, "CallingPlanOfNumber", -1);
				if (dplan != -1)
					plan = dplan;
			}
			q931->SetCallingPartyNumber(Number, plan, type, presentation, screening);
			PTRACE(4, Type() << "\tSet Calling Numbering Plan " << plan << " Type Of Number " << type);
		}
	}
}

bool CallSignalSocket::IsRTPInactive(short session) const
{
    H245ProxyHandler * proxyhandler = dynamic_cast<H245ProxyHandler *>(m_h245handler);
    if (proxyhandler) {
        return proxyhandler->IsRTPInactive(session);
    } else {
        return false;
    }
}


// class H245Handler
H245Handler::H245Handler(const PIPSocket::Address & local, const PIPSocket::Address & remote, const PIPSocket::Address & masq)
      : localAddr(local), remoteAddr(remote), masqAddr(masq), isH245ended(false), m_lastVideoFastUpdatePicture(0)
{
	hnat = (remoteAddr != GNUGK_INADDR_ANY) ? new NATHandler(remoteAddr) : NULL;
}

H245Handler::~H245Handler()
{
	delete hnat;
}

void H245Handler::OnH245Address(H225_TransportAddress & addr)
{
	if (hnat)
		hnat->TranslateH245Address(addr);
}

bool H245Handler::HandleMesg(H245_MultimediaSystemControlMessage & h245msg, bool & suppress, callptr & call, H245Socket * h245sock)
{
	bool changed = false;

	switch (h245msg.GetTag())
	{
		case H245_MultimediaSystemControlMessage::e_request:
			changed = HandleRequest(h245msg, call);
			break;
		case H245_MultimediaSystemControlMessage::e_response:
			changed = HandleResponse(h245msg, call);
			break;
		case H245_MultimediaSystemControlMessage::e_command:
			changed = HandleCommand(h245msg, suppress, call, h245sock);
			break;
		case H245_MultimediaSystemControlMessage::e_indication:
			changed = HandleIndication(h245msg, suppress);
			break;
		default:
			PTRACE(2, "H245\tUnknown H245 message: " << h245msg.GetTag());
			break;
	}
	return changed;
}

bool H245Handler::HandleFastStartSetup(H245_OpenLogicalChannel & olc, callptr & call)
{
	return hnat ? hnat->HandleOpenLogicalChannel(olc) : false;
}

bool H245Handler::HandleFastStartResponse(H245_OpenLogicalChannel & olc, callptr & call)
{
	return hnat ? hnat->HandleOpenLogicalChannel(olc) : false;
}

bool H245Handler::HandleRequest(H245_RequestMessage & Request, callptr & call)
{
	PTRACE(4, "H245\tRequest: " << Request.GetTagName());
	if (Request.GetTag() == H245_RequestMessage::e_openLogicalChannel) {
        if (hnat) {
            return hnat->HandleOpenLogicalChannel(Request);
        } else {
            // remember all channels FLCN so we can close them on Reroute
            H245_OpenLogicalChannel & olc = Request;
            WORD flcn = (WORD)olc.m_forwardLogicalChannelNumber;
            call->AddChannelFlcn(flcn);
            return false;
        }
	} else {
		return false;
	}
}

bool H245Handler::HandleResponse(H245_ResponseMessage & Response, callptr & call)
{
	PTRACE(4, "H245\tResponse: " << Response.GetTagName());
	if (hnat && Response.GetTag() == H245_ResponseMessage::e_openLogicalChannelAck)
		return hnat->HandleOpenLogicalChannelAck(Response);
	else
		return false;
}

bool H245Handler::HandleIndication(H245_IndicationMessage & Indication, bool & suppress)
{
	PTRACE(4, "H245\tIndication: " << Indication.GetTagName());
	return false;
}

bool H245Handler::HandleCommand(H245_CommandMessage & Command, bool & suppress, callptr & call, H245Socket * h245sock)
{
	PTRACE(4, "H245\tCommand: " << Command.GetTagName());
	if (Command.GetTag() == H245_CommandMessage::e_endSessionCommand)
		isH245ended = true;

	unsigned filterFastUpdatePeriod = GkConfig()->GetInteger(RoutedSec, "FilterVideoFastUpdatePicture", 0);
	if (filterFastUpdatePeriod > 0 && Command.GetTag() == H245_CommandMessage::e_miscellaneousCommand) {
		H245_MiscellaneousCommand miscCommand = Command;
        if (miscCommand.m_type.GetTag() == H245_MiscellaneousCommand_type::e_videoFastUpdatePicture) {
            PTime now;
            if (now - m_lastVideoFastUpdatePicture > PTimeInterval(0, filterFastUpdatePeriod)) {
                m_lastVideoFastUpdatePicture = now;
                PTRACE(3, "H245\tAllow VideoFastUpdatePicture");
            } else {
                suppress = true;
                PTRACE(3, "H245\tFiltering out VideoFastUpdatePicture");
            }
		}
	}

	return false;
}

// class H245Socket
H245Socket::H245Socket(CallSignalSocket *sig)
      : TCPProxySocket("H245d"), sigSocket(sig), listener(new TCPSocket)
{
	m_port = 0;
	peerH245Addr = NULL;
	const int numPorts = min(H245PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = H245PortRange.GetPort();
#ifdef hasIPV6
		if (listener->DualStackListen(pt)) {
#else
		if (listener->Listen(GNUGK_INADDR_ANY, 1, pt, PSocket::CanReuseAddress)) {
#endif
			PIPSocket::Address notused;
			listener->GetLocalAddress(notused, m_port);
			if (Toolkit::Instance()->IsPortNotificationActive())
				Toolkit::Instance()->PortNotification(H245Port, PortOpen, "tcp", GNUGK_INADDR_ANY, m_port, sig->GetCallNumber());

			// RE - TOS - H.245 inbound TCS etc.
			int dscp = GkConfig()->GetInteger(RoutedSec, "H245DiffServ", 0);	// default: 0
            if (dscp > 0) {
                int h245TypeOfService = (dscp << 2);
                // set IPv4 and IPv6
#if defined(hasIPV6) && defined(IPV6_TCLASS)
                // for IPv6 set TCLASS
                if (!ConvertOSError(::setsockopt(listener->GetHandle(), IPPROTO_IPV6, IPV6_TCLASS, (char *)&h245TypeOfService, sizeof(int)))) {
                    PTRACE(1, Type() << "\tCould not set TCLASS field in IPv6 header: "
                        << GetErrorCode(PSocket::LastGeneralError) << '/'
                        << GetErrorNumber(PSocket::LastGeneralError) << ": "
                        << GetErrorText(PSocket::LastGeneralError));
                }
#endif
                // setting IPTOS_PREC_CRITIC_ECP required root permission on Linux until 2008 (the 2.6.24.4), now it doesn't anymore
                // setting IP_TOS will silently fail on Windows XP, Vista and Win7, supposed to work again on Win8
                if (!ConvertOSError(::setsockopt(listener->GetHandle(), IPPROTO_IP, IP_TOS, (char *)&h245TypeOfService, sizeof(int)))) {
                    PTRACE(1, Type() << "\tCould not set TOS field in IP header: "
                        << GetErrorCode(PSocket::LastGeneralError) << '/'
                        << GetErrorNumber(PSocket::LastGeneralError) << ": "
                        << GetErrorText(PSocket::LastGeneralError));
                }
            }

			break;
		}
		int errorNumber = listener->GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, Type() << "\tCould not open H.245 listener at " << AsString(GNUGK_INADDR_ANY, pt)
			<< " - error " << listener->GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << listener->GetErrorText(PSocket::LastGeneralError)
			);
		listener->Close();
	}
	SetHandler(sig->GetHandler());
	if (!GkConfig()->GetBoolean(RoutedSec, "DisableGnuGkH245TcpKeepAlive", false)) {
        if (sig->UsesH460KeepAlive()) {
            PTRACE(5, "H46018\tEnable keep-alive for H.245 in H.460.18 call");
            RegisterKeepAlive(GkConfig()->GetInteger(RoutedSec, "H46018KeepAliveInterval", 19));
        } else {
            RegisterKeepAlive();
        }
	}
}

H245Socket::H245Socket(H245Socket *socket, CallSignalSocket *sig)
      : TCPProxySocket("H245s", socket), sigSocket(sig), listener(NULL)
{
	m_port = 0;
	peerH245Addr = NULL;
	socket->remote = this;
    if (!GkConfig()->GetBoolean(RoutedSec, "DisableGnuGkH245TcpKeepAlive", false)) {
        if (sig->UsesH460KeepAlive()) {
            PTRACE(5, "H46018\tEnable keep-alive for H.245 in H.460.18 call");
            RegisterKeepAlive(GkConfig()->GetInteger(RoutedSec, "H46018KeepAliveInterval", 19));
        } else {
            RegisterKeepAlive();
        }
    }
}

H245Socket::~H245Socket()
{
	if (Toolkit::Instance()->IsPortNotificationActive() && (m_port != 0)) {
		PINDEX callNo = 0;
		if (sigSocket) {
			callNo = sigSocket->GetCallNumber();
		}
		Toolkit::Instance()->PortNotification(H245Port, PortClose, "tcp", GNUGK_INADDR_ANY, m_port, callNo);
	}
	delete listener;
	listener = NULL;
	delete peerH245Addr;
	peerH245Addr = NULL;
	PWaitAndSignal lock(m_signalingSocketMutex);
	if (sigSocket)
		sigSocket->OnH245ChannelClosed();
}

PString H245Socket::GetCallIdentifierAsString() const
{
    if (sigSocket) {
        return sigSocket->GetCallIdentifierAsString();
    }
    return "unknown";
}

void H245Socket::OnSignalingChannelClosed()
{
    PTRACE(0, "JW H245 OnSignalingChannelClosed");
	PWaitAndSignal lock(m_signalingSocketMutex);
	sigSocket = NULL;
	EndSession();
	SetDeletable();
}

void H245Socket::ConnectTo()
{
	if (remote->Accept(*listener)) {
		if (sigSocket && sigSocket->IsH245Tunneling() && sigSocket->IsH245TunnelingTranslation()) {
			// H.245 connect for tunneling leg - must be mixed mode
			H245Socket * remoteH245Socket = dynamic_cast<H245Socket *>(remote);
			if (remoteH245Socket) {
				ConfigReloadMutex.StartRead();
				remote->SetConnected(true);
				SetConnected(true);	// avoid deletion of this unconnected socket
				GetHandler()->Insert(this, remote);
				ConfigReloadMutex.EndRead();
				// send all queued H.245 messages now
				PTRACE(3, "H245\tSending " << sigSocket->GetH245MessageQueueSize() << " queued H.245 messages now");
				while (PASN_OctetString * h245msg = sigSocket->GetNextQueuedH245Message()) {
					if (!remoteH245Socket->Send(*h245msg)) {
						PTRACE(1, "H245\tSending queued messages failed");
					}
					delete h245msg;
				}
			}
            //RegisterKeepAlive();   // if enabled, start a keep-alive with default interval
			return;
		}
		if (ConnectRemote()) {
			ConfigReloadMutex.StartRead();
			SetConnected(true);
			remote->SetConnected(true);
			GetHandler()->Insert(this, remote);
			ConfigReloadMutex.EndRead();
            //RegisterKeepAlive();   // if enabled, start a keep-alive with default interval
#ifdef HAS_H46018
			if (sigSocket && (sigSocket->IsCallFromTraversalServer() || sigSocket->IsCallToTraversalServer())) {
				SendH46018Indication();
                RegisterKeepAlive(GkConfig()->GetInteger(RoutedSec, "H46018KeepAliveInterval", 19));
			}
#endif
			return;
		}
	} else {
		PTRACE(1, "Error: H.245 Accept() failed");
		SNMP_TRAP(10, SNMPError, Network, "H.245 accept failed");
	}

	ReadLock lockConfig(ConfigReloadMutex);

	m_signalingSocketMutex.Wait();
	// establish H.245 channel failed, disconnect the call
	PTRACE(1, "Error: Establishing the H.245 channel failed, disconnecting");
	SNMP_TRAP(10, SNMPError, Network, "H.245 failed");
	CallSignalSocket *socket = sigSocket; // use a copy to avoid race conditions with OnSignalingChannelClosed
	if (socket) {
		socket->SetConnected(false);
		socket->RemoveCall();
		if (!socket->IsBlocked())
		    socket->SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
		socket->CloseSocket();
	}
	m_signalingSocketMutex.Signal();

	if (H245Socket *ret = static_cast<H245Socket *>(remote)) {
		ret->m_signalingSocketMutex.Wait();
		socket = ret->sigSocket;
		if (socket) {
			if (socket->IsConnected() && !socket->IsBlocked())
				socket->SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
			socket->SetConnected(false);
			socket->CloseSocket();
		}
		ret->m_signalingSocketMutex.Signal();
	}
	GetHandler()->Insert(this, remote);
}

// called when in Reroute, don't listen, but connect directly and re-send TCS
void H245Socket::ConnectToRerouteDestination()
{
	if (ConnectRemote()) {
		ConfigReloadMutex.StartRead();
		SetConnected(true);
		if (!remote) {
            PTRACE(1, "Reroute: Error: mixed tunneled / non-tunneled call");
            ConfigReloadMutex.EndRead();
            return;
		}
		remote->SetConnected(true);
		GetHandler()->Insert(this, remote);
		ConfigReloadMutex.EndRead();

		// re-send TCS
		H245Socket * remote_h245socket = dynamic_cast<H245Socket*>(remote);
		if (remote_h245socket && remote_h245socket->sigSocket) {
			H245_TerminalCapabilitySet tcs = remote_h245socket->sigSocket->GetSavedTCS();
			SendTCS(&tcs, sigSocket->GetNextTCSSeq());
		} else {
			PTRACE(1, "Reroute: Can't retrieve TCS to re-send");
		}
		return;
	}

	ReadLock lockConfig(ConfigReloadMutex);

	m_signalingSocketMutex.Wait();
	// establish H.245 channel failed, disconnect the call
	PTRACE(1, "Error: Establishing the H.245 channel failed, disconnecting");
	SNMP_TRAP(10, SNMPError, Network, "H.245 failed");
	CallSignalSocket *socket = sigSocket; // use a copy to avoid race conditions with OnSignalingChannelClosed
	if (socket) {
		socket->SetConnected(false);
		socket->RemoveCall();
		if (!socket->IsBlocked())
		    socket->SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
		socket->CloseSocket();
	}
	m_signalingSocketMutex.Signal();

	if (H245Socket *ret = static_cast<H245Socket *>(remote)) {
		ret->m_signalingSocketMutex.Wait();
		socket = ret->sigSocket;
		if (socket) {
			if (socket->IsConnected() && !socket->IsBlocked())
				socket->SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
			socket->SetConnected(false);
			socket->CloseSocket();
		}
		ret->m_signalingSocketMutex.Signal();
	}
	GetHandler()->Insert(this, remote);
}

// called for H.245 tunneling translation
void H245Socket::ConnectToDirectly()
{
	if (ConnectRemote()) {
		ConfigReloadMutex.StartRead();
		SetConnected(true);
		if (remote) {
            remote->SetConnected(true);
            GetHandler()->Insert(this, remote);
        } else {
            PTRACE(1, "H245\tError: no remote socket");
        }
		ConfigReloadMutex.EndRead();
	}
}

ProxySocket::Result H245Socket::ReceiveData()
{
	if (!ReadTPKT())
		return NoData;

	PPER_Stream strm(buffer);

	bool suppress = false;
	if (sigSocket && sigSocket->HandleH245Mesg(strm, suppress, this))
		buffer = strm;

	if (suppress) {
		return NoData;	// eg. H.460.18 genericIndication
	} else {
		if (sigSocket && sigSocket->GetRemote()
			&& sigSocket->GetRemote()->IsH245Tunneling()
			&& sigSocket->GetRemote()->IsH245TunnelingTranslation()) {
			if (!sigSocket->GetRemote()->SendTunneledH245(strm)) {
				PTRACE(1, "Error: H.245 tunnel send failed to " << sigSocket->GetRemote()->GetName());
			}
			return NoData;	// already forwarded through tunnel
		}
		return Forwarding;
	}
}

bool H245Socket::EndSession()
{
	if (listener)
		listener->Close();
	return TCPProxySocket::EndSession();
}

void H245Socket::SendEndSessionCommand()
{
	if (!IsConnected())
		return;
	// generate EndSessionCommand
	H245_MultimediaSystemControlMessage h245msg;
	h245msg.SetTag(H245_MultimediaSystemControlMessage::e_command);
	H245_CommandMessage & h245cmd = h245msg;
	h245cmd.SetTag(H245_CommandMessage::e_endSessionCommand);
	H245_EndSessionCommand & endcmd = h245cmd;
	endcmd.SetTag(H245_EndSessionCommand::e_disconnect);
	PPER_Stream wtstrm;
	h245msg.Encode(wtstrm);
	wtstrm.CompleteEncoding();
	if (TransmitData(wtstrm)) {
		PTRACE(4, "H245\tSend endSessionCommand to " << GetName());
	} else {
		PTRACE(1, "H245\tSending of endSessionCommand to " << GetName() << " failed");
	}
}

#ifdef HAS_H46018
void H245Socket::SendH46018Indication()
{
	if (!IsConnected())
		return;
	H245_MultimediaSystemControlMessage h245msg;
	h245msg.SetTag(H245_MultimediaSystemControlMessage::e_indication);
	H245_IndicationMessage & h245ind = h245msg;
	h245ind.SetTag(H245_IndicationMessage::e_genericIndication);
	H245_GenericMessage & genericInd = h245ind;
	H245_CapabilityIdentifier id;
	id.SetTag(H245_CapabilityIdentifier::e_standard);
	PASN_ObjectId & val = id;
	val = H46018_OID;
	genericInd.m_messageIdentifier = id;
	genericInd.IncludeOptionalField(H245_GenericMessage::e_subMessageIdentifier);
	genericInd.m_subMessageIdentifier = 1;
	genericInd.IncludeOptionalField(H245_GenericMessage::e_messageContent);
	genericInd.m_messageContent.SetSize(1);
	genericInd.m_messageContent[0].m_parameterIdentifier.SetTag(H245_ParameterIdentifier::e_standard);
	PASN_Integer & n = genericInd.m_messageContent[0].m_parameterIdentifier;
	n = 1;
	if (sigSocket) {
		genericInd.m_messageContent[0].m_parameterValue.SetTag(H245_ParameterValue::e_octetString);
		PASN_OctetString & cid = genericInd.m_messageContent[0].m_parameterValue;
		cid.EncodeSubType(sigSocket->GetCallIdentifier().m_guid);
	}

	// add Answer parameter if we send the indication to the caller
	if (sigSocket && sigSocket->IsCaller()) {
		genericInd.m_messageContent.SetSize(2);
		genericInd.m_messageContent[1].m_parameterIdentifier.SetTag(H245_ParameterIdentifier::e_standard);
		PASN_Integer & m = genericInd.m_messageContent[1].m_parameterIdentifier;
		m = 2;
		genericInd.m_messageContent[1].m_parameterValue.SetTag(H245_ParameterValue::e_logical);
		PASN_Null & answer = genericInd.m_messageContent[1].m_parameterValue;
		answer = true;
	}
	PPER_Stream wtstrm;
	h245msg.Encode(wtstrm);
	wtstrm.CompleteEncoding();
	if (TransmitData(wtstrm)) {
		PTRACE(4, "H245\tSend H.460.18 Indication to " << GetName());
	} else {
		PTRACE(1, "H245\tSending of H.460.18 Indication to " << GetName() << " failed");
		SNMP_TRAP(10, SNMPError, Network, "Sending H.460.18 Indication failed");
	}
}
#endif

void H245Socket::SendTCS(H245_TerminalCapabilitySet * tcs, unsigned seq)
{
	if (!IsConnected()) {
		return;
	}
	H245_MultimediaSystemControlMessage h245msg;
	h245msg.SetTag(H245_MultimediaSystemControlMessage::e_request);
	H245_RequestMessage & h245req = h245msg;
	h245req.SetTag(H245_RequestMessage::e_terminalCapabilitySet);
	H245_TerminalCapabilitySet & newTCS = h245req;
	// saved capabilities, otherwise empty
	if (tcs) {
		newTCS = *tcs;
	} else {
		newTCS.m_protocolIdentifier.SetValue(H245_ProtocolID);
	}
	newTCS.m_sequenceNumber = seq;
	PPER_Stream wtstrm;
	h245msg.Encode(wtstrm);
	wtstrm.CompleteEncoding();
	if (TransmitData(wtstrm)) {
		PTRACE(4, "H245\tSend TerminalCapabilitySet to " << GetName());
	} else {
		PTRACE(1, "H245\tSending of TerminalCapabilitySet to " << GetName() << " failed");
		SNMP_TRAP(10, SNMPError, Network, "Sending TCS to " + GetName() + " failed");
	}
}

void H245Socket::SendH245KeepAlive()
{
    if (!IsConnected()) {
        return;
    }
    PTRACE(6, "Send UserInput KeepAlive to " << GetName());

    H245_MultimediaSystemControlMessage h245msg;
    h245msg.SetTag(H245_MultimediaSystemControlMessage::e_indication);
    H245_IndicationMessage & h245ind = h245msg;
    h245ind.SetTag(H245_IndicationMessage::e_userInput);
    H245_UserInputIndication & inputInd = h245ind;
    inputInd.SetTag(H245_UserInputIndication::e_nonStandard);
    H245_NonStandardParameter & nonStd = inputInd;
    nonStd.m_nonStandardIdentifier.SetTag(H245_NonStandardIdentifier::e_h221NonStandard);
    H245_NonStandardIdentifier & nonStdID = nonStd.m_nonStandardIdentifier;
    nonStdID.SetTag(H245_NonStandardIdentifier::e_h221NonStandard);
    H245_NonStandardIdentifier_h221NonStandard & nonStdIDH221 = nonStdID;
    nonStdIDH221.m_t35CountryCode = Toolkit::t35cPoland;
    nonStdIDH221.m_manufacturerCode = Toolkit::t35mGnuGk;
    nonStdIDH221.m_t35Extension = Toolkit::t35eH245KeepAlive;
    nonStd.m_data.SetSize(1);
    nonStd.m_data[0] = 42;
    Send(h245msg);
}

bool H245Socket::Send(const H245_MultimediaSystemControlMessage & h245msg)
{
	if (!IsConnected()) {
		return false;
	}
	PPER_Stream wtstrm;
	h245msg.Encode(wtstrm);
	wtstrm.CompleteEncoding();
	if (TransmitData(wtstrm)) {
		PTRACE(4, "H245\tSend H.245 message to " << GetName());
	} else {
		PTRACE(1, "H245\tSending of H.245 message " << h245msg.GetTagName() << " to " << GetName() << " failed");
		SNMP_TRAP(10, SNMPError, Network, "Sending H.245 message to " + GetName() + " failed");
		return false;
	}
	return true;
}

bool H245Socket::Send(const PASN_OctetString & octets)
{
	PPER_Stream strm(octets);
	H245_MultimediaSystemControlMessage h245msg;
	if (!h245msg.Decode(strm)) {
		PTRACE(3, "H245\tERROR DECODING H.245");
		SNMP_TRAP(7, SNMPError, General, "Decoding H.245 failed");
		return false;
	}
	return Send(h245msg);
}

#ifdef LARGE_FDSET
bool H245Socket::Accept(YaTCPSocket & socket)
#else
PBoolean H245Socket::Accept(PSocket & socket)
#endif
{
	bool result = TCPProxySocket::Accept(socket);
	if (result) {
		Address addr;
		WORD p;
		GetLocalAddress(addr, p);
		UnmapIPv4Address(addr);
		PTRACE(3, "H245\tConnected from " << GetName() << " on " << AsString(addr, p) << " (CallID: " << GetCallIdentifierAsString() << ")");
	} else if (peerH245Addr) {
		result = H245Socket::ConnectRemote();
	}
	return result;
}

bool H245Socket::ConnectRemote()
{
	if (listener)
		listener->Close(); // don't accept other connection
	PIPSocket::Address peerAddr, localAddr(0);
	WORD peerPort;

	// peerH245Addr may be accessed from multiple threads
	m_signalingSocketMutex.Wait();
	if (!peerH245Addr || !GetIPAndPortFromTransportAddr(*peerH245Addr, peerAddr, peerPort) || !peerPort) {
		m_signalingSocketMutex.Signal();
		PTRACE(3, "H245\tInvalid address");
		return false;
	}
	SetPort(peerPort);
	if (sigSocket != NULL) {
		sigSocket->GetLocalAddress(localAddr);
		UnmapIPv4Address(localAddr);
	}
	m_signalingSocketMutex.Signal();

	int numPorts = min(H245PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = H245PortRange.GetPort();
		if (Connect(localAddr, pt, peerAddr)) {
			SetConnected(true);
			PTRACE(3, "H245\tConnect to " << GetName() << " from " << AsString(localAddr, pt) << " successful" << " (CallID: " << GetCallIdentifierAsString() << ")");

			// RE - TOS - H.245 outbound - TCS messages etc.
            int dscp = GkConfig()->GetInteger(RoutedSec, "H245DiffServ", 0);
            if (dscp > 0) {
                int h245TypeOfService = (dscp << 2);
#if defined(hasIPV6) && defined(IPV6_TCLASS)
                if (localAddr.GetVersion() == 6) {
                    // for IPv6 set TCLASS
                    if (!ConvertOSError(::setsockopt(os_handle, IPPROTO_IPV6, IPV6_TCLASS, (char *)&h245TypeOfService, sizeof(int)))) {
                        PTRACE(1, remote->Type() << "\tCould not set TCLASS field in IPv6 header: "
                            << GetErrorCode(PSocket::LastGeneralError) << '/'
                            << GetErrorNumber(PSocket::LastGeneralError) << ": "
                            << GetErrorText(PSocket::LastGeneralError));
                    }
                } else
#endif
                {
                    // setting IPTOS_PREC_CRITIC_ECP required root permission on Linux until 2008 (the 2.6.24.4), now it doesn't anymore
                    // setting IP_TOS will silently fail on Windows XP, Vista and Win7, supposed to work again on Win8
                    if (!ConvertOSError(::setsockopt(os_handle, IPPROTO_IP, IP_TOS, (char *)&h245TypeOfService, sizeof(int)))) {
                        PTRACE(1, remote->Type() << "\tCould not set TOS field in IP header: "
                            << GetErrorCode(PSocket::LastGeneralError) << '/'
                            << GetErrorNumber(PSocket::LastGeneralError) << ": "
                            << GetErrorText(PSocket::LastGeneralError));
                    }
                }
            }

			if (sigSocket && sigSocket->GetRemote() && sigSocket->GetRemote()->IsH245TunnelingTranslation()) {
				// send all queued H.245 messages now
				PTRACE(3, "H245\tSending " << sigSocket->GetRemote()->GetH245MessageQueueSize() << " queued H.245 messages now");
				while (PASN_OctetString * h245msg = sigSocket->GetRemote()->GetNextQueuedH245Message()) {
					if (!Send(*h245msg)) {
						PTRACE(1, "H245\tSending queued messages failed");
					}
					delete h245msg;
				}
			}
			return true;
		}
		int errorNumber = GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, Type() << "\tCould not open/connect H.245 socket at " << AsString(localAddr, pt)
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << GetErrorText(PSocket::LastGeneralError)
			<< " remote addr: " << AsString(peerAddr));
		Close();
		PTRACE(3, "H245\t" << AsString(peerAddr, peerPort) << " DIDN'T ACCEPT THE CALL" << " (CallID: " << GetCallIdentifierAsString() << ")");
		SNMP_TRAP(10, SNMPError, Network, "H.245 connection to " + AsString(peerAddr, peerPort) + " failed");
	}
	return false;
}

H225_TransportAddress H245Socket::GetH245Address(const Address & myip)
{
	return SocketToH225TransportAddr(myip, listener ? listener->GetPort() : 0);
}

bool H245Socket::SetH245Address(H225_TransportAddress & h245addr, const Address & myip)
{
	bool swapped = false;
	H245Socket * socket = NULL;

	// peerH245Address may be accessed from multiple threads
	m_signalingSocketMutex.Wait();
	if (listener) {
		socket = this;
	} else {
		socket = static_cast<H245Socket *>(remote);
		swapped = true;
		std::swap(this->sigSocket, socket->sigSocket);
	}
	if (socket->peerH245Addr)
		*socket->peerH245Addr = h245addr;
	else
		socket->peerH245Addr = new H225_TransportAddress(h245addr);
	m_signalingSocketMutex.Signal();

	h245addr = SocketToH225TransportAddr(myip, socket->listener->GetPort());
	PTRACE(3, "H245\tSet h245Address to " << AsDotString(h245addr) << " (CallID: " << GetCallIdentifierAsString() << ")");
	return swapped;
}

bool H245Socket::Reverting(const H225_TransportAddress & h245addr)
{
	PTRACE(3, "H245\tH.245 Reverting detected");
	PWaitAndSignal lock(m_signalingSocketMutex); // peerH245Address may be accessed from multiple threads
	TCPSocket *socket = static_cast<H245Socket *>(remote)->listener;
	if (socket && socket->IsOpen()) {
		peerH245Addr = new H225_TransportAddress(h245addr);
		socket->Close();
		return true;
	}
	return false;
}

// class NATH245Socket
bool NATH245Socket::ConnectRemote()
{
    if (!GkConfig()->GetBoolean(RoutedSec, "DisableGnuGkH245TcpKeepAlive", false)) {
        if (sigSocket && sigSocket->UsesH460KeepAlive()) {
            PTRACE(5, "H46018\tEnable keep-alive for H.245 in H.460.18 call");
            RegisterKeepAlive(GkConfig()->GetInteger(RoutedSec, "H46018KeepAliveInterval", 19));
        } else {
            RegisterKeepAlive();
        }
    }

#ifdef HAS_H46018
	// when connecting to a traversal server, we can't send startH245, but must connect directly
	if (sigSocket && sigSocket->IsTraversalServer()) {
		return H245Socket::ConnectRemote();
	}
#endif

	m_signalingSocketMutex.Wait();
	if (!sigSocket || !listener) {
		m_signalingSocketMutex.Signal();
		return false;
	}

	Q931 q931;
	sigSocket->BuildFacilityPDU(q931, H225_FacilityReason::e_startH245);
	H225_H323_UserInformation uuie;
	GetUUIE(q931, uuie);
	PrintQ931(5, "Send to ", sigSocket->GetName(), &q931, &uuie);
	q931.Encode(buffer);
	sigSocket->TransmitData(buffer);
	m_signalingSocketMutex.Signal();

	bool result = Accept(*listener);
	PTRACE_IF(3, result, "H245\tChannel established for NAT EP");
	listener->Close();
	return result;
}

namespace { // anonymous namespace

inline bool compare_lc(pair<const WORD, RTPLogicalChannel *> p, LogicalChannel *lc)
{
	return p.second == lc;
}

bool IsSeparateLANStack(const H245_DataType & data)
{
	if (data.GetTag() == H245_DataType::e_data) {
		const H245_DataApplicationCapability & cap = data;
		if (cap.m_application.GetTag() == H245_DataApplicationCapability_application::e_t120) {
			const H245_DataProtocolCapability & proto_cap = cap.m_application;
			return (proto_cap.GetTag() == H245_DataProtocolCapability::e_separateLANStack);
		}
	}
	return false;
}

bool IsT120Channel(const H245_OpenLogicalChannel & olc)
{
	return  IsSeparateLANStack(olc.m_forwardLogicalChannelParameters.m_dataType) &&
		olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters) &&
		IsSeparateLANStack(olc.m_reverseLogicalChannelParameters.m_dataType);
}

H245_H2250LogicalChannelParameters *GetLogicalChannelParameters(H245_OpenLogicalChannel & olc, bool & isReverseLC)
{
	if (olc.HasOptionalField(H245_OpenLogicalChannel::e_reverseLogicalChannelParameters)) {
		if (!olc.m_reverseLogicalChannelParameters.HasOptionalField(H245_OpenLogicalChannel_reverseLogicalChannelParameters::e_multiplexParameters))
			return NULL;
		H245_OpenLogicalChannel_reverseLogicalChannelParameters_multiplexParameters & params = olc.m_reverseLogicalChannelParameters.m_multiplexParameters;
		isReverseLC = true;
		return (params.GetTag() == H245_OpenLogicalChannel_reverseLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters) ?  &((H245_H2250LogicalChannelParameters &)params) : NULL;
	} else {
		H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters & params = olc.m_forwardLogicalChannelParameters.m_multiplexParameters;
		isReverseLC = false;
		return (params.GetTag() == H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters) ?  &((H245_H2250LogicalChannelParameters &)params) : NULL;
	}
}

bool GetChannelsFromOLCA(H245_OpenLogicalChannelAck & olca, H245_UnicastAddress * & mediaControlChannel, H245_UnicastAddress * & mediaChannel)
{
	mediaChannel = NULL;
	mediaControlChannel = NULL;

	if (!olca.HasOptionalField(H245_OpenLogicalChannelAck::e_forwardMultiplexAckParameters))
		return false;
	H245_OpenLogicalChannelAck_forwardMultiplexAckParameters & ackparams = olca.m_forwardMultiplexAckParameters;
	if (ackparams.GetTag() != H245_OpenLogicalChannelAck_forwardMultiplexAckParameters::e_h2250LogicalChannelAckParameters)
		return false;
	H245_H2250LogicalChannelAckParameters & h225Params = ackparams;

	if (h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaControlChannel))
		mediaControlChannel = GetH245UnicastAddress(h225Params.m_mediaControlChannel);
	if (h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaChannel))
		mediaChannel = GetH245UnicastAddress(h225Params.m_mediaChannel);

	return mediaControlChannel != NULL;
}

} // end of anonymous namespace


#ifdef HAS_H46018

// class MultiplexRTPListener
MultiplexRTPListener::MultiplexRTPListener(WORD pt, WORD buffSize)
{
	wbuffer = new BYTE[buffSize];
	wbufsize = buffSize;

	PIPSocket::Address localAddr(GNUGK_INADDR_ANY);
	std::vector<PIPSocket::Address> home;
	Toolkit::Instance()->GetGKHome(home);
	if (home.size() == 1)
		localAddr = home[0];

	if (!Listen(localAddr, 0, pt)) {
		PTRACE(1, "RTPM\tCan't open multiplex RTP listener on " << AsString(localAddr, pt));
		return;
	}
	SetName(AsString(localAddr, pt) + "(Multiplex)");
	if (Toolkit::Instance()->IsPortNotificationActive())
		Toolkit::Instance()->PortNotification(RTPPort, PortOpen, "udp", GNUGK_INADDR_ANY, pt);

	// Set the IP Type Of Service field for prioritisation of media UDP / RTP packets
	int dscp = GkConfig()->GetInteger(ProxySection, "RTPDiffServ", 4);	// default: IPTOS_LOWDELAY
	if (dscp > 0) {
		int rtpIpTypeofService = (dscp << 2);
#if defined(hasIPV6) && defined(IPV6_TCLASS)
		if (localAddr.GetVersion() == 6) {
			// for IPv6 set TCLASS
			if (!ConvertOSError(::setsockopt(os_handle, IPPROTO_IPV6, IPV6_TCLASS, (char *)&rtpIpTypeofService, sizeof(int)))) {
				PTRACE(1, "RTPM\tCould not set TCLASS field in IPv6 header: "
					<< GetErrorCode(PSocket::LastGeneralError) << '/'
					<< GetErrorNumber(PSocket::LastGeneralError) << ": "
					<< GetErrorText(PSocket::LastGeneralError));
			}

		} else
#endif
		{
			// setting IPTOS_PREC_CRITIC_ECP required root permission on Linux until 2008 (the 2.6.24.4), now it doesn't anymore
			// setting IP_TOS will silently fail on Windows XP, Vista and Win7, supposed to work again on Win8
			if (!ConvertOSError(::setsockopt(os_handle, IPPROTO_IP, IP_TOS, (char *)&rtpIpTypeofService, sizeof(int)))) {
				PTRACE(1, "RTPM\tCould not set TOS field in IP header: "
					<< GetErrorCode(PSocket::LastGeneralError) << '/'
					<< GetErrorNumber(PSocket::LastGeneralError) << ": "
					<< GetErrorText(PSocket::LastGeneralError));
			}
		}
	}

	SetReadTimeout(PTimeInterval(50));
	SetWriteTimeout(PTimeInterval(50));
}

MultiplexRTPListener::~MultiplexRTPListener()
{
	if (Toolkit::Instance()->IsPortNotificationActive())
		Toolkit::Instance()->PortNotification(RTPPort, PortClose, "udp", GNUGK_INADDR_ANY, GetPort());
	delete [] wbuffer;
}

void MultiplexRTPListener::ReceiveData()
{
	if (!Read(wbuffer, wbufsize)) {
		return;
	}
	Address fromIP;
	WORD fromPort;
	GetLastReceiveAddress(fromIP, fromPort);
	UnmapIPv4Address(fromIP);
	Address localAddr;
	WORD localPort = 0;
	GetLocalAddress(localAddr, localPort);
	UnmapIPv4Address(localAddr);
	WORD buflen = (WORD)GetLastReadCount();
	DWORD multiplexID = INVALID_MULTIPLEX_ID;
	if (buflen >= 4)
		multiplexID = ((int)wbuffer[0] * 16777216) + ((int)wbuffer[1] * 65536) + ((int)wbuffer[2] * 256) + (int)wbuffer[3];

	if (multiplexID == INVALID_MULTIPLEX_ID) {
		PTRACE(1, "RTPM\tInvalid multiplexID reveived - ignoring packet on port " << localPort << " from " << AsString(fromIP, fromPort));
		return;
	}

	MultiplexedRTPHandler::Instance()->HandlePacket(multiplexID, IPAndPortAddress(fromIP, fromPort), wbuffer+4, buflen-4, odd(localPort));
}

H46019Session::H46019Session(PINDEX callno, WORD session, void * openedBy)
{
    m_deleted = false;
    m_deleteTime = 0;
    m_lastPacketFromA = time(NULL);
    m_lastPacketFromB = time(NULL);
	m_callno = callno;
	m_session = session;
	m_flcn = 0;	// only used for master assigned sessions
	m_openedBy = openedBy;
	m_otherSide = NULL;
	m_multiplexID_fromA = INVALID_MULTIPLEX_ID;
	m_multiplexID_toA = INVALID_MULTIPLEX_ID;
	m_multiplexID_fromB = INVALID_MULTIPLEX_ID;
	m_multiplexID_toB = INVALID_MULTIPLEX_ID;
	m_osSocketToA = INVALID_OSSOCKET;
	m_osSocketToA_RTCP = INVALID_OSSOCKET;
	m_osSocketToB = INVALID_OSSOCKET;
	m_osSocketToB_RTCP = INVALID_OSSOCKET;
	m_EnableRTCPStats = GkConfig()->GetBoolean(ProxySection, "EnableRTCPStats", false);
#ifdef HAS_H235_MEDIA
	m_encryptingLC = NULL;
	m_decryptingLC = NULL;
	m_encryptMultiplexID = INVALID_MULTIPLEX_ID;
	m_decryptMultiplexID = INVALID_MULTIPLEX_ID;
#endif
}

H46019Session::~H46019Session()
{
    // don't free any pointers
}

H46019Session::H46019Session(const H46019Session & other)
{
    m_deleted = other.m_deleted;
    m_deleteTime = other.m_deleteTime;
    m_lastPacketFromA = other.m_lastPacketFromA;
    m_lastPacketFromB = other.m_lastPacketFromB;
	m_callno = other.m_callno;
	m_session = other.m_session;
	m_flcn = other.m_flcn;
	m_openedBy = other.m_openedBy;
	m_otherSide = other.m_otherSide;
    m_addrA = other.m_addrA;
	m_addrA_RTCP = other.m_addrA_RTCP;
	m_addrB = other.m_addrB;
	m_addrB_RTCP = other.m_addrB_RTCP;
	m_multiplexID_fromA = other.m_multiplexID_fromA;
	m_multiplexID_toA = other.m_multiplexID_toA;
	m_multiplexID_fromB = other.m_multiplexID_fromB;
	m_multiplexID_toB = other.m_multiplexID_toB;
	m_osSocketToA = other.m_osSocketToA;
	m_osSocketToA_RTCP = other.m_osSocketToA_RTCP;
	m_osSocketToB = other.m_osSocketToB;
	m_osSocketToB_RTCP = other.m_osSocketToB_RTCP;
	m_EnableRTCPStats = other.m_EnableRTCPStats;
#ifdef HAS_H235_MEDIA
	m_encryptingLC = other.m_encryptingLC;
	m_decryptingLC = other.m_decryptingLC;
	m_encryptMultiplexID = other.m_encryptMultiplexID;
	m_decryptMultiplexID = other.m_decryptMultiplexID;
#endif
}

H46019Session & H46019Session::operator=(const H46019Session & other)
{
    if (this == &other)
        return *this;

    m_deleted = other.m_deleted;
    m_deleteTime = other.m_deleteTime;
    m_callno = other.m_callno;
    m_session = other.m_session;
    m_flcn = other.m_flcn;
    m_openedBy = other.m_openedBy;
    m_otherSide = other.m_otherSide;
    m_addrA = other.m_addrA;
    m_addrA_RTCP = other.m_addrA_RTCP;
    m_addrB = other.m_addrB;
    m_addrB_RTCP = other.m_addrB_RTCP;
    m_multiplexID_fromA = other.m_multiplexID_fromA;
    m_multiplexID_toA = other.m_multiplexID_toA;
    m_multiplexID_fromB = other.m_multiplexID_fromB;
    m_multiplexID_toB = other.m_multiplexID_toB;
    m_osSocketToA = other.m_osSocketToA;
    m_osSocketToA_RTCP = other.m_osSocketToA_RTCP;
    m_osSocketToB = other.m_osSocketToB;
    m_osSocketToB_RTCP = other.m_osSocketToB_RTCP;
    m_EnableRTCPStats = other.m_EnableRTCPStats;
#ifdef HAS_H235_MEDIA
    m_encryptingLC = other.m_encryptingLC;
    m_decryptingLC = other.m_decryptingLC;
    m_encryptMultiplexID = other.m_encryptMultiplexID;
    m_decryptMultiplexID = other.m_decryptMultiplexID;
#endif

    return *this;
}

// return a copy with side A and B swapped
H46019Session H46019Session::SwapSides() const
{
	H46019Session result = *this;
	swap(result.m_openedBy, result.m_otherSide);
	swap(result.m_addrA, result.m_addrB);
	swap(result.m_addrA_RTCP, result.m_addrB_RTCP);
	swap(result.m_multiplexID_fromA, result.m_multiplexID_fromB);
	swap(result.m_multiplexID_toA, result.m_multiplexID_toB);
	swap(result.m_osSocketToA, result.m_osSocketToB);
	swap(result.m_osSocketToA_RTCP, result.m_osSocketToB_RTCP);

	return result;
}

void H46019Session::Dump() const
{
    if (m_deleted)
        return;

	PTRACE(7, "JW H46019Session: session=" << m_session << " openedBy=" << m_openedBy << " flcn=" << m_flcn
			<< " IDfromA=" << m_multiplexID_fromA << " IDtoA=" << m_multiplexID_toA
			<< " IDfromB=" << m_multiplexID_fromB << " IDtoB=" << m_multiplexID_toB
			<< " addrA=" << AsString(m_addrA) << " addrA_RTCP=" << AsString(m_addrA_RTCP)
			<< " addrB=" << AsString(m_addrB) << " addrB_RTCP=" << AsString(m_addrB_RTCP)
			<< " callNo=" << m_callno);
#ifdef HAS_H235_MEDIA
	if (Toolkit::Instance()->IsH235HalfCallMediaEnabled()) {
		PTRACE(7, "JW session=" << m_session << " encryptLC=" << m_encryptingLC << " decryptLC=" << m_decryptingLC);
	}
#endif
}

void H46019Session::HandlePacket(DWORD receivedMultiplexID, const IPAndPortAddress & fromAddress, void * data, unsigned len, bool isRTCP)
{
    if (m_deleted)
        return;

	PTRACE(7, "JW RTP DB: multiplexID=" << receivedMultiplexID
					 << " isRTCP=" << isRTCP << " ka=" << IsKeepAlive(len, isRTCP)
					 << " from=" << AsString(fromAddress));
	Dump();

	// re-check status after waiting for I/O
    if (m_deleted)
        return;
    callptr call = CallTable::Instance()->FindCallRec(m_callno);
    if (!call) {
        PTRACE(5, "RTPM\tCan't find call " << m_callno);
        return;
    }
    // re-check deleted status after waiting for call table lock
    if (m_deleted)
        return;
    bool isFromA = (receivedMultiplexID == m_multiplexID_fromA);
    bool isFromB = (receivedMultiplexID == m_multiplexID_fromB);
    if (isFromA)
        m_lastPacketFromA = time(NULL);
    if (isFromB)
        m_lastPacketFromB = time(NULL);
    if (IsKeepAlive(len, isRTCP)) {
		if (isFromA) {
			if (isRTCP && (m_addrA_RTCP != fromAddress)) {
				m_addrA_RTCP = fromAddress;
                call->SetSessionMultiplexDestination(m_session, m_openedBy, isRTCP, fromAddress, SideA);
			} else if (m_addrA != fromAddress) {
				m_addrA = fromAddress;
                call->SetSessionMultiplexDestination(m_session, m_openedBy, isRTCP, fromAddress, SideA);
			}
		} else if (isFromB) {
			if (isRTCP && (m_addrB_RTCP != fromAddress)) {
				m_addrB_RTCP = fromAddress;
                call->SetSessionMultiplexDestination(m_session, m_openedBy, isRTCP, fromAddress, SideB);
			} else if (m_addrB != fromAddress) {
				m_addrB = fromAddress;
                call->SetSessionMultiplexDestination(m_session, m_openedBy, isRTCP, fromAddress, SideB);
			}
		}
		MultiplexedRTPHandler::Instance()->DumpChannels(" keepAlive handled ");

#ifdef HAS_H46024B
		if (call->GetNATStrategy() == CallRec::e_natAnnexB)
			call->H46024BInitiate(m_session, m_addrA, m_addrB, m_multiplexID_toA, m_multiplexID_toB);
#endif	// HAS_H46024B

		if (!isRTCP)
			return;	// don't forward RTP keepalives
	}

	// port detection by first media packet for channels from client to server that won't have a keepAlive
	if (isFromA) {
		if (isRTCP && (m_addrA_RTCP != fromAddress)) {
			m_addrA_RTCP = fromAddress;
            call->SetSessionMultiplexDestination(m_session, m_openedBy, isRTCP, fromAddress, SideA);
        }
		if (!isRTCP && (m_addrA != fromAddress)) {
			m_addrA = fromAddress;
            call->SetSessionMultiplexDestination(m_session, m_openedBy, isRTCP, fromAddress, SideA);
        }
	}
	if (isFromB) {
		if (isRTCP && (m_addrB_RTCP != fromAddress)) {
			m_addrB_RTCP = fromAddress;
            call->SetSessionMultiplexDestination(m_session, m_openedBy, isRTCP, fromAddress, SideB);
        }
		if (!isRTCP && (m_addrB != fromAddress)) {
			m_addrB = fromAddress;
            call->SetSessionMultiplexDestination(m_session, m_openedBy, isRTCP, fromAddress, SideB);
        }
	}

#ifdef HAS_H235_MEDIA
	if (!isRTCP && call->IsMediaEncryption() && IsSet(m_addrA) && IsSet(m_addrB)) {
		WORD wlen = len;
		bool succesful = false;
		unsigned char ivSequence[6];
		BYTE payloadType = UNDEFINED_PAYLOAD_TYPE;
		bool rtpPadding = false;
		if (len >= 1)
			rtpPadding = (((BYTE*)data)[0] & 0x20);
		if (len >= 2)
			payloadType = ((BYTE*)data)[1] & 0x7f;
		if (len >= 8)
			memcpy(ivSequence, (BYTE*)data + 2, 6);

		if (receivedMultiplexID == m_encryptMultiplexID) {
			if (m_encryptingLC) {
				succesful = m_encryptingLC->ProcessH235Media((BYTE*)data, wlen, true, ivSequence, rtpPadding, payloadType);
			}
		} else {
			if (m_decryptingLC) {
				succesful = m_decryptingLC->ProcessH235Media((BYTE*)data, wlen, false, ivSequence, rtpPadding, payloadType);
			}
		}

		if (!succesful)
			return;

		// update RTP padding bit
		if (rtpPadding)
			((BYTE*)data)[0] |= 0x20;
		else
			((BYTE*)data)[0] &= 0xdf;
		// update payload type, preserve marker bit
		((BYTE*)data)[1] = (((BYTE*)data)[1] & 0x80) | (payloadType & 0x7f);

		len = wlen;
	}
#endif

#ifdef HAS_H46026
	// send RTP for H.460.26 endpoints via TCP
    if (call->GetCallingParty() && call->GetCallingParty()->UsesH46026()) {
        if (call->GetCallingParty()->GetSocket()) {
            call->GetCallingParty()->GetSocket()->SendH46026RTP(m_session, !isRTCP, data, len);
        }
        return;
    } else if (call->GetCalledParty() && call->GetCalledParty()->UsesH46026()) {
        if (call->GetCalledParty()->GetSocket()) {
            call->GetCalledParty()->GetSocket()->SendH46026RTP(m_session, !isRTCP, data, len);
        }
        return;
    }
#endif

	if (receivedMultiplexID == m_multiplexID_fromA) {
		if (sideBReady(isRTCP)) {
			Send(m_multiplexID_toB, (isRTCP ? m_addrB_RTCP : m_addrB), (isRTCP ? m_osSocketToB_RTCP : m_osSocketToB), data, len, true);
		} else {
			PTRACE(5, "RTPM\tReceiver not ready");
		}
	} else if (receivedMultiplexID == m_multiplexID_fromB) {
		if (sideAReady(isRTCP)) {
			Send(m_multiplexID_toA, (isRTCP ? m_addrA_RTCP : m_addrA), (isRTCP ? m_osSocketToA_RTCP : m_osSocketToA), data, len, true);
		} else {
			PTRACE(5, "RTPM\tReceiver not ready");
		}
	}
	if (isRTCP && m_EnableRTCPStats) {
        ParseRTCP(call, m_session, fromAddress.GetIP(), (BYTE*)data, len);
    }
}

void H46019Session::Send(DWORD sendMultiplexID, const IPAndPortAddress & toAddress, int osSocket, void * data, unsigned len, bool bufferHasRoomForID)
{
	size_t lenToSend = len;
	size_t sent = 0;

	if (osSocket == INVALID_OSSOCKET) {
		PTRACE(1, "RTPM\tError: OSSocket to " << toAddress << " not set");
		SNMP_TRAP(10, SNMPError, Network, "Invalid multiplexing socket for " + AsString(toAddress));
		return;
	}
	if (sendMultiplexID != INVALID_MULTIPLEX_ID) {
		lenToSend += 4;
		BYTE * multiplexMsg = NULL;
		// prepend multiplexID
		if (bufferHasRoomForID) {
			// this data came multiplexed, and we can write the ID in place of the old ID (_in front of_ the buffer)
			multiplexMsg = (BYTE*)data - 4;
		} else {
			// this data came non multiplexed, we must allocate a buffer and copy the data
			multiplexMsg = (BYTE*)malloc(len+4);
			memcpy(multiplexMsg+4, data, len);
		}
		PUInt32b networkID = sendMultiplexID;   // convert multiplex ID to network format
		*((PUInt32b*)multiplexMsg) = networkID;	// set multiplexID

		sent = UDPSendWithSourceIP(osSocket, multiplexMsg, lenToSend, toAddress);
		if (!bufferHasRoomForID)
			free(multiplexMsg);
	} else {
		sent = UDPSendWithSourceIP(osSocket, data, lenToSend, toAddress);
	}
	if (sent != lenToSend) {
		PTRACE(1, "RTPM\tError sending RTP to " << toAddress << ": should send=" << lenToSend << " did send=" << sent << " errno=" << errno);
	}
}

MultiplexedRTPReader::MultiplexedRTPReader()
{
	m_multiplexRTPListener = NULL;
	m_multiplexRTCPListener = NULL;
	SetName("MultiplexedRTPReader");
	Execute();
}

MultiplexedRTPReader::~MultiplexedRTPReader()
{
	if (m_multiplexRTPListener) {
		m_multiplexRTPListener->Close();
	}
	if (m_multiplexRTCPListener) {
		m_multiplexRTCPListener->Close();
	}
}

void MultiplexedRTPReader::OnStart()
{
	if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)) {
		// create mutiplex RTP listeners
		 m_multiplexRTPListener = new MultiplexRTPListener((WORD)GkConfig()->GetInteger(ProxySection, "RTPMultiplexPort", GK_DEF_MULTIPLEX_RTP_PORT));
		 if (m_multiplexRTPListener->IsOpen()) {
			PTRACE(1, "RTPM\tMultiplex RTP listener listening on port " << m_multiplexRTPListener->GetPort());
			AddSocket(m_multiplexRTPListener);
		} else {
			PTRACE(1, "RTPM\tCannot start multiplex RTP listener on port " << m_multiplexRTPListener->GetPort());
			delete m_multiplexRTPListener;
			m_multiplexRTPListener = NULL;
		}
		 m_multiplexRTCPListener = new MultiplexRTPListener((WORD)GkConfig()->GetInteger(ProxySection, "RTCPMultiplexPort", GK_DEF_MULTIPLEX_RTCP_PORT));
		 if (m_multiplexRTCPListener->IsOpen()) {
			PTRACE(1, "RTPM\tMultiplex RTCP listener listening on port " << m_multiplexRTCPListener->GetPort());
			AddSocket(m_multiplexRTCPListener);
		} else {
			PTRACE(1, "RTPM\tCannot start multiplex RTCP listener on port " << m_multiplexRTCPListener->GetPort());
			delete m_multiplexRTCPListener;
			m_multiplexRTCPListener = NULL;
		}
	}
}

void MultiplexedRTPReader::ReadSocket(IPSocket * socket)
{
	MultiplexRTPListener *psocket = dynamic_cast<MultiplexRTPListener *>(socket);
	if (psocket == NULL) {
		PTRACE(1, "RTPM\tError: Invalid socket");
		SNMP_TRAP(10, SNMPError, Network, "Invalid read on multiplex socket");
		return;
	}
	psocket->ReceiveData();
}

MultiplexedRTPHandler::MultiplexedRTPHandler() : Singleton<MultiplexedRTPHandler>("MultiplexedRTPHandler")
{
	m_idCounter = 0;
    m_deleteDelay = WAIT_DELETE_AFTER_DISCONNECT; // wait 30 sec. before really deleting a deleted session
    m_inactivityCheck = GkConfig()->GetBoolean(ProxySection, "RTPInactivityCheck", false);
    m_inactivityTimeout = GkConfig()->GetInteger(ProxySection, "RTPInactivityTimeout", 300);    // 300 sec = 5 min
    PCaselessString sessionType = GkConfig()->GetString(ProxySection, "RTPInactivityCheckSession", "Audio");
    if (sessionType == "Audio") {
        m_inactivityCheckSession = 1;
    } else if (sessionType == "Video") {
        m_inactivityCheckSession = 2;
    } else {
        PTRACE(1, "RTPM\tError: You can only check audio or video sessions for inactivity");
        m_inactivityCheckSession = 1; // default to audio
    }
	if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)) {
		m_reader = new MultiplexedRTPReader();
		PTime now;
        m_cleanupTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(this, &MultiplexedRTPHandler::SessionCleanup, now, 30);
	} else {
		m_reader = NULL;
		m_cleanupTimer = GkTimerManager::INVALID_HANDLE;
	}
}

MultiplexedRTPHandler::~MultiplexedRTPHandler()
{
    if (m_cleanupTimer != GkTimerManager::INVALID_HANDLE)
		Toolkit::Instance()->GetTimerManager()->UnregisterTimer(m_cleanupTimer);
    // TODO: delete remaining sessions in list ?
}

void MultiplexedRTPHandler::AddChannel(const H46019Session & chan)
{
	WriteLock lock(m_listLock);
	if (chan.IsValid()) {
		bool found = false;
		// update if we have a channel for this session
		for (list<H46019Session>::iterator iter = m_h46019channels.begin();
				iter != m_h46019channels.end() ; ++iter) {
			if (   (iter->m_callno == chan.m_callno)
				&& (iter->m_session == chan.m_session)) {
				if (iter->m_openedBy == chan.m_openedBy) {
					*iter = chan;
				} else {
					*iter = chan.SwapSides();
				}
				found = true;
			}
		}
		// else add
		if (!found)
			m_h46019channels.push_back(chan);
	} else {
		PTRACE(1, "H46019\tError: Adding invalid H460.19 channel");
	}
	DumpChannels(" AddChannel() done ");
}

void MultiplexedRTPHandler::UpdateChannelSession(PINDEX callno, WORD flcn, void * openedBy, WORD session)
{
	WriteLock lock(m_listLock);
	for (list<H46019Session>::iterator iter = m_h46019channels.begin();
			iter != m_h46019channels.end() ; ++iter) {
        if (!iter->m_deleted) {
            if (   (iter->m_callno == callno)
                && (iter->m_session == session) ) {
                return;	// session already in list - all is well
            }
            if (   (iter->m_callno == callno)
                && (iter->m_flcn == flcn)
                && (iter->m_openedBy == openedBy) ) {
                    iter->m_session = session;
                    iter->m_flcn = 0;	// reset
                DumpChannels(" UpdateChannelSession() done ");
                return;
            }
		}
	}
	PTRACE(1, "H46019\tError: Updating master assigned RTP session failed: flcn=" << flcn << " openedBy=" << openedBy);
}

void MultiplexedRTPHandler::UpdateChannel(const H46019Session & chan)
{
	WriteLock lock(m_listLock);
	for (list<H46019Session>::iterator iter = m_h46019channels.begin();
			iter != m_h46019channels.end() ; ++iter) {
        if (!iter->m_deleted) {
            if (   (iter->m_callno == chan.m_callno)
                && (iter->m_session == chan.m_session)) {
                if (iter->m_openedBy == chan.m_openedBy) {
                    *iter = chan;
                } else {
                    *iter = chan.SwapSides();
                }
                DumpChannels(" UpdateChannel() done ");
                return;
            }
        }
	}
}

H46019Session MultiplexedRTPHandler::GetChannelSwapped(PINDEX callno, WORD session, void * openedBy) const
{
	ReadLock lock(m_listLock);
	for (list<H46019Session>::const_iterator iter = m_h46019channels.begin();
			iter != m_h46019channels.end() ; ++iter) {
        if (!iter->m_deleted) {
            if (iter->m_callno == callno && iter->m_session == session) {
                if (iter->m_openedBy == openedBy) {
                    return *iter;
                } else {
                    return iter->SwapSides();
                }
            }
        }
	}
	return H46019Session(0, 0, NULL);	// not found
}

H46019Session MultiplexedRTPHandler::GetChannel(PINDEX callno, WORD session) const
{
	ReadLock lock(m_listLock);
	for (list<H46019Session>::const_iterator iter = m_h46019channels.begin();
			iter != m_h46019channels.end() ; ++iter) {
		if (!iter->m_deleted && iter->m_callno == callno && iter->m_session == session) {
			return *iter;
		}
	}
	return H46019Session(0, 0, NULL);	// not found
}

void MultiplexedRTPHandler::RemoveChannels(PINDEX callno)
{
	WriteLock lock(m_listLock);
	for (list<H46019Session>::iterator iter = m_h46019channels.begin();
			iter != m_h46019channels.end() ; /* nothing */ ) {
		if (!iter->m_deleted && iter->m_callno == callno) {
            iter->m_deleted = true; // mark as logically deleted
            iter->m_deleteTime = time(NULL);
			//m_h46019channels.erase(iter++);
		} else {
			++iter;
		}
	}
	DumpChannels(" RemoveChannels() done ");
}

#ifdef HAS_H235_MEDIA
void MultiplexedRTPHandler::RemoveChannel(PINDEX callno, RTPLogicalChannel * rtplc)
{
	WriteLock lock(m_listLock);
	for (list<H46019Session>::iterator iter = m_h46019channels.begin();
			iter != m_h46019channels.end() ; /* nothing */ ) {
		if (!iter->m_deleted && iter->m_callno == callno) {
			if (iter->m_encryptingLC == rtplc)
				iter->m_encryptingLC = NULL;
			if (iter->m_decryptingLC == rtplc)
				iter->m_decryptingLC = NULL;
		}
		++iter;
	}
	DumpChannels(" RemoveChannel() done ");
}
#endif

void MultiplexedRTPHandler::DumpChannels(const PString & msg) const
{
	if (PTrace::CanTrace(7)) {
		PTRACE(7, "JW ===" << msg << "=== Dump19Channels Begin (" << m_h46019channels.size() << " channels) ===");
		for (list<H46019Session>::const_iterator iter = m_h46019channels.begin();
				iter != m_h46019channels.end() ; ++iter) {
			iter->Dump();
		}
		PTRACE(7, "JW =================== Dump19Channels End ====================");
	}
}

bool MultiplexedRTPHandler::HandlePacket(DWORD receivedMultiplexID, const IPAndPortAddress & fromAddress, void * data, unsigned len, bool isRTCP)
{
	ReadLock lock(m_listLock);
	// find the matching channel for the multiplex ID and let it handle the packet
	for (list<H46019Session>::iterator iter = m_h46019channels.begin();
			iter != m_h46019channels.end() ; ++iter) {
		if ((iter->m_multiplexID_fromA == receivedMultiplexID)
			|| (iter->m_multiplexID_fromB == receivedMultiplexID)) {
			if (!iter->m_deleted) {
                ReadUnlock unlock(m_listLock); // release read lock to avoid possible dead lock
                //PTRACE(0, "JW " << PThread::Current()->GetThreadId() << " HandlePacket ended READ lock");
                iter->HandlePacket(receivedMultiplexID, fromAddress, data, len, isRTCP);
            }
            return true;
		}
	}
	if (!isRTCP) {
        // no warning for RTCP, probably a Polycom RTCP packet with missing multiplex ID
        PTRACE(7, "RTP\tWarning: Didn't find a channel for receivedMultiplexID " << receivedMultiplexID << " from " << AsString(fromAddress));
    }
	return false;
}

#ifdef HAS_H46026
bool MultiplexedRTPHandler::HandlePacket(PINDEX callno, const H46026_UDPFrame & data)
{
	ReadLock lock(m_listLock);
	// find the matching channel by callID and sessionID
	for (list<H46019Session>::iterator iter = m_h46019channels.begin();
			iter != m_h46019channels.end() ; ++iter) {
		if (!iter->m_deleted && (iter->m_callno == callno) && (iter->m_session == data.m_sessionId)) {
			// found session, now send all RTP packets
			for (PINDEX i = 0; i < data.m_frame.GetSize(); i++) {
				PASN_OctetString & bytes = data.m_frame[i];
				PTRACE(7, "JW found .19 session, send packet, size=" << bytes.GetSize() << " rtp=" << data.m_dataFrame);
				if (iter->m_multiplexID_toA != INVALID_MULTIPLEX_ID) {
					if (!data.m_dataFrame) {
						if (IsSet(iter->m_addrA_RTCP) && (iter->m_osSocketToA_RTCP != INVALID_OSSOCKET)) {
							PTRACE(7, "JW send mux packet to " << iter->m_addrA_RTCP << " osSocket=" << iter->m_osSocketToA_RTCP);
							iter->Send(iter->m_multiplexID_toA, iter->m_addrA_RTCP, iter->m_osSocketToA_RTCP, bytes.GetPointer(), bytes.GetSize(), false);
						}
					} else {
						if (IsSet(iter->m_addrA) && (iter->m_osSocketToA != INVALID_OSSOCKET)) {
							PTRACE(7, "JW send mux packet to " << iter->m_addrA << " osSocket=" << iter->m_osSocketToA);
							iter->Send(iter->m_multiplexID_toA, iter->m_addrA, iter->m_osSocketToA, bytes.GetPointer(), bytes.GetSize(), false);
						}
					}
				} else if (iter->m_multiplexID_toB != INVALID_MULTIPLEX_ID) {
					if (!data.m_dataFrame) {
						if (IsSet(iter->m_addrB_RTCP) && (iter->m_osSocketToB_RTCP != INVALID_OSSOCKET)) {
							PTRACE(7, "JW send mux packet to " << iter->m_addrB_RTCP << " osSocket=" << iter->m_osSocketToB_RTCP);
							iter->Send(iter->m_multiplexID_toB, iter->m_addrB_RTCP, iter->m_osSocketToB_RTCP, bytes.GetPointer(), bytes.GetSize(), false);
						}
					} else {
						if (IsSet(iter->m_addrB) && (iter->m_osSocketToB != INVALID_OSSOCKET)) {
							PTRACE(7, "JW send mux packet to " << iter->m_addrB << " osSocket=" << iter->m_osSocketToB);
							iter->Send(iter->m_multiplexID_toB, iter->m_addrB, iter->m_osSocketToB, bytes.GetPointer(), bytes.GetSize(), false);
						}
					}
				}
			}
			return true;
		}
	}
	return false;
}
#endif // HAS_H46026

DWORD MultiplexedRTPHandler::GetMultiplexID(PINDEX callno, WORD session, void * to)
{
	ReadLock lock(m_listLock);
	for (list<H46019Session>::const_iterator iter = m_h46019channels.begin();
			iter != m_h46019channels.end() ; ++iter) {
		if (!iter->m_deleted && iter->m_callno == callno && iter->m_session == session) {
			if (iter->m_openedBy == to && iter->m_multiplexID_fromA != INVALID_MULTIPLEX_ID) {
				return iter->m_multiplexID_fromA;
			}
			if (iter->m_openedBy != to && iter->m_multiplexID_fromB != INVALID_MULTIPLEX_ID) {
				return iter->m_multiplexID_fromB;
			}
		}
	}
	return INVALID_MULTIPLEX_ID;	// not found
}

DWORD MultiplexedRTPHandler::GetNewMultiplexID()
{
	static const DWORD MAX_MULTIPLEX_ID = 2147483647;
	if (m_idCounter >= MAX_MULTIPLEX_ID) {
		m_idCounter = 0;
	}
	return m_idCounter = m_idCounter + 1;
}

bool MultiplexedRTPHandler::GetDetectedMediaIP(PINDEX callno, WORD sessionID, bool forCaller, /* out */ PIPSocket::Address & addr, WORD & port) const
{
    if (sessionID == 0)
        return false;

    H46019Session h46019chan = GetChannel(callno, sessionID);
    if (h46019chan.IsValid()) {
        H245ProxyHandler * h245handler = (H245ProxyHandler *)h46019chan.m_openedBy;
        if (h245handler) {
            if ((forCaller && h245handler->IsCaller()) || (!forCaller && !h245handler->IsCaller())) {
                return IsSet(h46019chan.m_addrA) && h46019chan.m_addrA.GetIpAndPort(addr, port);
            } else {
                return IsSet(h46019chan.m_addrB) && h46019chan.m_addrB.GetIpAndPort(addr, port);
            }
        }
    }
    // TODO: check if we have a detected IP from H.460.19 non-multiplexed or non-std port detection (IgnoreSignaledPorts=1)
    return false;
}

// delete sessions marked as deleted (runs every 30 sec)
void MultiplexedRTPHandler::SessionCleanup(GkTimer* /* timer */)
{
	WriteLock lock(m_listLock);
	time_t now = time(NULL);
	for (list<H46019Session>::iterator iter = m_h46019channels.begin();
			iter != m_h46019channels.end() ; /* nothing */ ) {
		if (iter->m_deleted && (now - iter->m_deleteTime > m_deleteDelay)) {
			m_h46019channels.erase(iter++);
		} else {
            // inactivity check
            if (m_inactivityCheck && iter->m_session == m_inactivityCheckSession) {
                bool terminate = false;
                if (iter->m_multiplexID_fromA != INVALID_MULTIPLEX_ID && (now - iter->m_lastPacketFromA > m_inactivityTimeout) ) {
                    PTRACE(1, "RTPM\tTerminating call because of RTP inactivity from " << iter->m_addrA << " CallNo " << iter->m_callno);
                    terminate = true;
                }
                if (iter->m_multiplexID_fromB != INVALID_MULTIPLEX_ID && (now - iter->m_lastPacketFromB > m_inactivityTimeout) ) {
                    PTRACE(1, "RTPM\tTerminating call because of RTP inactivity from " << iter->m_addrB << " CallNo " << iter->m_callno);
                    terminate = true;
                }
                if (terminate) {
                    callptr call = CallTable::Instance()->FindCallRec(iter->m_callno);
                    if (call) {
                        call->Disconnect(true);
                    } else {
                        PTRACE(1, "RTPM\tError: Can't find call to terminate");
                    }
                }
            }

			++iter;
		}
	}
	DumpChannels(" SessionCleanup() done ");
}

#endif


#ifdef HAS_H46026
H46026Session::H46026Session()
	: m_isValid(false), m_session(-1), m_osRTPSocket(-1), m_osRTCPSocket(-1)
{
#ifdef HAS_H235_MEDIA
	m_encryptingLC = NULL;
	m_decryptingLC = NULL;
#endif
}

H46026Session::H46026Session(PINDEX callno, WORD session,
							int osRTPSocket, int osRTCPSocket,
							const IPAndPortAddress & toRTP, const IPAndPortAddress & toRTCP)
	: m_isValid(true), m_callno(callno), m_session(session),
	  m_osRTPSocket(osRTPSocket), m_osRTCPSocket(osRTCPSocket), m_toAddressRTP(toRTP), m_toAddressRTCP(toRTCP)
{
#ifdef HAS_H235_MEDIA
	m_encryptingLC = NULL;
	m_decryptingLC = NULL;
#endif
}

void H46026Session::Send(void * data, unsigned len, bool isRTCP)
{
	size_t lenToSend = len;
	size_t sent = 0;
	int osSocket = INVALID_OSSOCKET;
	IPAndPortAddress toAddress;

	if (isRTCP) {
		osSocket = m_osRTCPSocket;
		toAddress = m_toAddressRTCP;
	} else {
		osSocket = m_osRTPSocket;
		toAddress = m_toAddressRTP;
	}

	sent = UDPSendWithSourceIP(osSocket, data, lenToSend, toAddress);
	if (sent != lenToSend) {
		PTRACE(1, "H46026\tError sending RTP to " << toAddress << ": should send=" << lenToSend << " did send=" << sent << " errno=" << errno);
	}
}

void H46026Session::Dump() const
{
	PTRACE(7, "JW H46026Session: session=" << m_session
//			<< " callID=" << AsString(m_callid)
			<< " osRTPSocket=" << m_osRTPSocket << " toRTP=" << m_toAddressRTP
			<< " osRTCPSocket=" << m_osRTCPSocket << " toRTCP=" << m_toAddressRTCP);
#ifdef HAS_H235_MEDIA
	if (Toolkit::Instance()->IsH235HalfCallMediaEnabled()) {
		PTRACE(7, "JW                encryptLC=" << m_encryptingLC << " decryptLC=" << m_decryptingLC);
	}
#endif
}


H46026RTPHandler::H46026RTPHandler() : Singleton<H46026RTPHandler>("H46026RTPHandler")
{
}

H46026RTPHandler::~H46026RTPHandler()
{
}

void H46026RTPHandler::AddChannel(const H46026Session & chan)
{
	WriteLock lock(m_listLock);
	m_h46026channels.push_back(chan);
	DumpChannels(" AddChannel() done ");
}

void H46026RTPHandler::ReplaceChannel(const H46026Session & chan)
{
	WriteLock lock(m_listLock);
	// find the matching channel by callno and sessionID
	for (list<H46026Session>::iterator iter = m_h46026channels.begin();
			iter != m_h46026channels.end() ; ++iter) {
		if ((iter->m_callno == chan.m_callno) && (iter->m_session == chan.m_session)) {
			*iter = chan;
			break;
		}
	}
	DumpChannels(" ReplaceChannel() done ");
}

void H46026RTPHandler::UpdateChannelRTP(PINDEX callno, WORD session, IPAndPortAddress toRTP)
{
	WriteLock lock(m_listLock);
	// find the matching channel by callno and sessionID
	for (list<H46026Session>::iterator iter = m_h46026channels.begin();
			iter != m_h46026channels.end() ; ++iter) {
		if ((iter->m_callno == callno) && (iter->m_session == session)) {
			iter->m_toAddressRTP = toRTP;
			break;
		}
	}
	DumpChannels(" UpdateChannelRTP() done ");
}

void H46026RTPHandler::UpdateChannelRTCP(PINDEX callno, WORD session, IPAndPortAddress toRTCP)
{
	WriteLock lock(m_listLock);
	// find the matching channel by callno and sessionID
	for (list<H46026Session>::iterator iter = m_h46026channels.begin();
			iter != m_h46026channels.end() ; ++iter) {
		if ((iter->m_callno == callno) && (iter->m_session == session)) {
			iter->m_toAddressRTCP = toRTCP;
			break;
		}
	}
	DumpChannels(" UpdateChannelRTCP() done ");
}

#ifdef HAS_H235_MEDIA
void H46026RTPHandler::UpdateChannelEncryptingLC(PINDEX callno, WORD session, RTPLogicalChannel * lc)
{
	WriteLock lock(m_listLock);
	// find the matching channel by callno and sessionID
	for (list<H46026Session>::iterator iter = m_h46026channels.begin();
			iter != m_h46026channels.end() ; ++iter) {
		if ((iter->m_callno == callno) && (iter->m_session == session)) {
			iter->m_encryptingLC = lc;
			break;
		}
	}
}

void H46026RTPHandler::UpdateChannelDecryptingLC(PINDEX callno, WORD session, RTPLogicalChannel * lc)
{
	WriteLock lock(m_listLock);
	// find the matching channel by callno and sessionID
	for (list<H46026Session>::iterator iter = m_h46026channels.begin();
			iter != m_h46026channels.end() ; ++iter) {
		if ((iter->m_callno == callno) && (iter->m_session == session)) {
			iter->m_decryptingLC = lc;
			break;
		}
	}
}
#endif

H46026Session H46026RTPHandler::FindSession(PINDEX callno, WORD session) const
{
	WriteLock lock(m_listLock);
	// find the matching channel by callno and sessionID
	for (list<H46026Session>::const_iterator iter = m_h46026channels.begin();
			iter != m_h46026channels.end() ; ++iter) {
		if ((iter->m_callno == callno) && (iter->m_session == session)) {
			return *iter;
		}
	}
	return H46026Session();	// return invalid session
}

void H46026RTPHandler::RemoveChannels(PINDEX callno)
{
	WriteLock lock(m_listLock);
	for (list<H46026Session>::iterator iter = m_h46026channels.begin();
			iter != m_h46026channels.end() ; /* nothing */ ) {
		if (iter->m_callno == callno) {
			m_h46026channels.erase(iter++);
		} else {
			++iter;
		}
	}
	DumpChannels(" RemoveChannels() done ");
}

void H46026RTPHandler::DumpChannels(const PString & msg) const
{
	if (PTrace::CanTrace(7) && !m_h46026channels.empty()) {
		PTRACE(7, "JW ===" << msg << "=== Dump26Channels Begin (" << m_h46026channels.size() << " channels) ===");
		for (list<H46026Session>::const_iterator iter = m_h46026channels.begin();
				iter != m_h46026channels.end() ; ++iter) {
			iter->Dump();
		}
		PTRACE(7, "JW =================== Dump26Channels End ====================");
	}
}

bool H46026RTPHandler::HandlePacket(PINDEX callno, H46026_UDPFrame & data)
{
	ReadLock lock(m_listLock);
	// find the matching channel by callno and sessionID
	for (list<H46026Session>::iterator iter = m_h46026channels.begin();
			iter != m_h46026channels.end() ; ++iter) {
		if ((iter->m_callno == callno) && (iter->m_session == data.m_sessionId)) {
			// found session, now send all RTP packets
			for (PINDEX i = 0; i < data.m_frame.GetSize(); i++) {
				PASN_OctetString & bytes = data.m_frame[i];
				iter->Send(bytes.GetPointer(), bytes.GetSize(), !data.m_dataFrame);
			}
			return true;
		}
	}
	PTRACE(3, "H46026\tWarning: Didn't find a H.460.26 channel for session " << data.m_sessionId << " of call no. " << callno);
	return false;
}

#endif	// HAS_H46026


// class UDPProxySocket
UDPProxySocket::UDPProxySocket(const char *t, PINDEX no)
	: ProxySocket(this, t), m_callNo(no),
		m_call(NULL), fSrcIP(0), fDestIP(0), rSrcIP(0), rDestIP(0),
		fSrcPort(0), fDestPort(0), rSrcPort(0), rDestPort(0), m_sessionID(0),
		m_encryptingLC(NULL), m_decryptingLC(NULL)
#ifdef HAS_H46018
	, m_h46019fc(false), m_useH46019(false), m_h46019uni(false),
	m_keepAlivePT_1(UNDEFINED_PAYLOAD_TYPE), m_keepAlivePT_2(UNDEFINED_PAYLOAD_TYPE),
	m_multiplexID_A(INVALID_MULTIPLEX_ID), m_multiplexSocket_A(INVALID_OSSOCKET),
	m_multiplexID_B(INVALID_MULTIPLEX_ID), m_multiplexSocket_B(INVALID_OSSOCKET)
#endif
#ifdef HAS_H235_MEDIA
	, m_haveShownPTWarning(false)
#endif
    , m_portDetectionDone(false), m_forwardAndReverseSeen(false)
{
	// set flags for RTP/RTCP to avoid string compares later on
	m_isRTPType = PString(t) == "RTP";
	m_isRTCPType = PString(t) == "RTCP";
	SetReadTimeout(PTimeInterval(50));
	SetWriteTimeout(PTimeInterval(50));
	fnat = rnat = mute = false;
	m_dontQueueRTP = GkConfig()->GetBoolean(ProxySection, "DisableRTPQueueing", true);
	m_EnableRTCPStats = GkConfig()->GetBoolean(ProxySection, "EnableRTCPStats", false);
	m_legacyPortDetection = GkConfig()->GetBoolean(ProxySection, "LegacyPortDetection", false);
    m_ignoreSignaledIPs = false;
    m_ignoreSignaledPrivateH239IPs = false;
    callptr call = CallTable::Instance()->FindCallRec(m_callNo);
#ifdef HAS_H46018
	m_checkH46019KeepAlivePT = GkConfig()->GetBoolean(ProxySection, "CheckH46019KeepAlivePT", true);
    if (call) {
        m_ignoreSignaledIPs = call->IgnoreSignaledIPs();
        if (m_ignoreSignaledIPs) {
            m_ignoreSignaledPrivateH239IPs = GkConfig()->GetBoolean(ProxySection, "IgnoreSignaledPrivateH239IPs", false);
            PStringArray keepSignaledIPs = GkConfig()->GetString(ProxySection, "AllowSignaledIPs", "").Tokenise(",", FALSE);
            for (PINDEX i = 0; i < keepSignaledIPs.GetSize(); ++i) {
                PString ip = keepSignaledIPs[i];
                if (ip.Find('/') == P_MAX_INDEX) {
                    // add netmask to pure IPs
                    if (IsIPv4Address(ip)) {
                        ip += "/32";
                    } else {
                        ip += "/128";
                    }
                }
                m_keepSignaledIPs.push_back(NetworkAddress(ip));
            }
        }
    }
#endif

    PCaselessString restrictRTP = GkConfig()->GetString(ProxySection, "RestrictRTPSources", "");
    m_restrictRTPSources = (restrictRTP != "");
    if (m_restrictRTPSources && call) {
        Address ip;
        WORD port;
        // source IP/net
        call->GetSrcSignalAddr(ip, port);
        if (restrictRTP == "NET") {
            if (IsIPv4Address(ip)) {
                m_restrictRTPNetwork_A = NetworkAddress(AsString(ip) + "/24");
            } else {
                m_restrictRTPNetwork_A = NetworkAddress(AsString(ip) + "/64");
            }
        } else {
            if (IsIPv4Address(ip)) {
                m_restrictRTPNetwork_A = NetworkAddress(AsString(ip) + "/32");
            } else {
                m_restrictRTPNetwork_A = NetworkAddress(AsString(ip) + "/128");
            }
        }
        // destination IP/net
        call->GetDestSignalAddr(ip, port);
        if (restrictRTP == "Net") {
            if (IsIPv4Address(ip)) {
                m_restrictRTPNetwork_B = NetworkAddress(AsString(ip) + "/24");
            } else {
                m_restrictRTPNetwork_B = NetworkAddress(AsString(ip) + "/64");
            }
        } else {
            if (IsIPv4Address(ip)) {
                m_restrictRTPNetwork_B = NetworkAddress(AsString(ip) + "/32");
            } else {
                m_restrictRTPNetwork_B = NetworkAddress(AsString(ip) + "/128");
            }
        }
    }
    m_lastPacketFromForwardSrc = time(NULL);
    m_lastPacketFromReverseSrc = time(NULL);
    m_inactivityTimeout = GkConfig()->GetInteger(ProxySection, "RTPInactivityTimeout", 300);    // 300 sec = 5 min
}

UDPProxySocket::~UDPProxySocket()
{
	if (Toolkit::Instance()->IsPortNotificationActive())
		Toolkit::Instance()->PortNotification(RTPPort, PortClose, "udp", GNUGK_INADDR_ANY, GetPort(), m_callNo);
}

bool UDPProxySocket::Bind(const Address & localAddr, WORD pt)
{
#ifdef hasIPV6
	if (!DualStackListen(localAddr, pt))
#else
	if (!Listen(localAddr, 0, pt))
#endif
		return false;

	// Set the IP Type Of Service field for prioritisation of media UDP / RTP packets
	int dscp = GkConfig()->GetInteger(ProxySection, "RTPDiffServ", 4);	// default: IPTOS_LOWDELAY
	if (dscp > 0) {
		int rtpIpTypeofService = (dscp << 2);
#if defined(hasIPV6) && defined(IPV6_TCLASS)
		if (localAddr.GetVersion() == 6) {
			// for IPv6 set TCLASS
			if (!ConvertOSError(::setsockopt(os_handle, IPPROTO_IPV6, IPV6_TCLASS, (char *)&rtpIpTypeofService, sizeof(int)))) {
				PTRACE(1, Type() << "\tCould not set TCLASS field in IPv6 header: "
					<< GetErrorCode(PSocket::LastGeneralError) << '/'
					<< GetErrorNumber(PSocket::LastGeneralError) << ": "
					<< GetErrorText(PSocket::LastGeneralError));
			}

		} else
#endif
		{
			// setting IPTOS_PREC_CRITIC_ECP required root permission on Linux until 2008 (the 2.6.24.4), now it doesn't anymore
			// setting IP_TOS will silently fail on Windows XP, Vista and Win7, supposed to work again on Win8
			if (!ConvertOSError(::setsockopt(os_handle, IPPROTO_IP, IP_TOS, (char *)&rtpIpTypeofService, sizeof(int)))) {
				PTRACE(1, Type() << "\tCould not set TOS field in IP header: "
					<< GetErrorCode(PSocket::LastGeneralError) << '/'
					<< GetErrorNumber(PSocket::LastGeneralError) << ": "
					<< GetErrorText(PSocket::LastGeneralError));
			}
		}
	}

	if (Toolkit::Instance()->IsPortNotificationActive())
		Toolkit::Instance()->PortNotification(RTPPort, PortOpen, "udp", GNUGK_INADDR_ANY, pt, m_callNo);
	return true;
}

void UDPProxySocket::SetNAT(bool rev)
{
    PTRACE(7, "JW RTP UDPProxySocket::SetNAT() fSrc=0, rSrc=0");
    if (!m_ignoreSignaledIPs) { // skip old NAT logic if we do port detection
        fSrcIP = 0;
        fSrcPort = 0;
        rSrcIP = 0;
        rSrcPort = 0;
    }

	// if the handler of lc is NATed,
	// the destination of reverse direction should be changed
	(rev ? fnat : rnat) = true;
	PTRACE(5, Type() << "\tfnat=" << fnat << " rnat=" << rnat);
}

void UDPProxySocket::UpdateSocketName()
{
	PString src = "(to be detected)";
	PString dst = "(to be detected)";
	Address laddr;
	WORD lport = 0;
	GetLocalAddress(laddr, lport);
	UnmapIPv4Address(laddr);
	if ((DWORD)fSrcIP)
		src = AsString(fSrcIP, fSrcPort);
	if ((DWORD)fDestIP)
		dst = AsString(fDestIP, fDestPort);
	SetName(src + "<=>" + AsString(laddr, lport) + "<=>" + dst);
}

void UDPProxySocket::SetForwardDestination(const Address & srcIP, WORD srcPort, H245_UnicastAddress * dstAddr, callptr & call)
{
	Address localaddr;
	WORD localport = 0;
	GetLocalAddress(localaddr, localport);
	UnmapIPv4Address(localaddr);
	PTRACE(7, "JW RTP SetFwdDest on " << localport
		<< " fSrc=" << AsString(fSrcIP, fSrcPort) << " fDest=" << AsString(fDestIP, fDestPort)
		<< " rSrc=" << AsString(rSrcIP, rSrcPort) << " rDest=" << AsString(rDestIP, rDestPort));

#ifdef HAS_H46018
    if (m_ignoreSignaledIPs && m_portDetectionDone && m_forwardAndReverseSeen) {
        PTRACE(7, "JW RTP skip overwriting due to completed port detection");
        return;
    }
#endif

	if ((DWORD)srcIP != 0 || m_ignoreSignaledIPs) {
		fSrcIP = srcIP, fSrcPort = srcPort;
	}
	if (dstAddr) {
		*dstAddr >> fDestIP >> fDestPort;
	} else {
		fDestIP = 0;
		fDestPort = 0;
	}

	UpdateSocketName();
	PTRACE(5, Type() << "\tForward " << AsString(srcIP, srcPort)  << " to " << AsString(fDestIP, fDestPort));

	SetConnected(true);

	SetMediaIP(true, fDestIP);  // SRC
	SetMediaIP(false, srcIP);   // DST

#ifdef HAS_H46018
    m_portDetectionDone = false;  // must re-do H.460.19 port detection, in case it has already been done by a previous channel on same port
#endif

	PTRACE(7, "JW RTP SetFwdDest2 on " << localport
		<< " fSrc=" << AsString(fSrcIP, fSrcPort) << " fDest=" << AsString(fDestIP, fDestPort)
		<< " rSrc=" << AsString(rSrcIP, rSrcPort) << " rDest=" << AsString(rDestIP, rDestPort));

#if defined(HAS_H46018) && defined(HAS_H46024B)
	// If required begin Annex B probing
	if (call && call->GetNATStrategy() == CallRec::e_natAnnexB) {
		call->H46024BSessionFlag(m_sessionID);
	}
#endif

	if (call)
		m_call = &call;
}

void UDPProxySocket::SetReverseDestination(const Address & srcIP, WORD srcPort, H245_UnicastAddress * dstAddr, callptr & call)
{
	Address localaddr;
	WORD localport = 0;
	GetLocalAddress(localaddr, localport);
	UnmapIPv4Address(localaddr);
	PTRACE(7, "JW RTP SetRevDest on " << localport
		<< " fSrc=" << AsString(fSrcIP, fSrcPort) << " fDest=" << AsString(fDestIP, fDestPort)
		<< " rSrc=" << AsString(rSrcIP, rSrcPort) << " rDest=" << AsString(rDestIP, rDestPort));

#ifdef HAS_H46018
    if (m_ignoreSignaledIPs && m_portDetectionDone && m_forwardAndReverseSeen) {
        PTRACE(7, "JW RTP skip overwriting due to completed port detection");
        return;
    }
#endif

	if ((DWORD)srcIP != 0 || m_ignoreSignaledIPs) {
		rSrcIP = srcIP, rSrcPort = srcPort;
	}
	if (dstAddr) {
		*dstAddr >> rDestIP >> rDestPort;
	} else {
		rDestIP = 0;
		rDestPort = 0;
	}

	UpdateSocketName();
	PTRACE(5, Type() << "\tReverse " << AsString(srcIP, srcPort) << " to " << AsString(rDestIP, rDestPort));

	SetConnected(true);

	SetMediaIP(true, srcIP);   // SRC
	SetMediaIP(false, rDestIP); // DST

#ifdef HAS_H46018
    m_portDetectionDone = false;  // must re-do H.460.19 port detection, in case it has already been done by a previous channel on same port
#endif

	PTRACE(7, "JW RTP SetRevDest2 on " << localport
		<< " fSrc=" << AsString(fSrcIP, fSrcPort) << " fDest=" << AsString(fDestIP, fDestPort)
		<< " rSrc=" << AsString(rSrcIP, rSrcPort) << " rDest=" << AsString(rDestIP, rDestPort));

    if (call)
        m_call = &call;
}

void UDPProxySocket::GetPorts(PIPSocket::Address & _fSrcIP, PIPSocket::Address & _fDestIP, PIPSocket::Address & _rSrcIP, PIPSocket::Address & _rDestIP,
                                WORD & _fSrcPort, WORD & _fDestPort, WORD & _rSrcPort, WORD & _rDestPort) const
{
    _fSrcIP = fSrcIP;
    _fDestIP = fDestIP;
    _rSrcIP = rSrcIP;
    _rDestIP = rDestIP;

    _fSrcPort = fSrcPort;
    _fDestPort = fDestPort;
    _rSrcPort = rSrcPort;
    _rDestPort = rDestPort;
}

void UDPProxySocket::ZeroAllIPs()
{
    if (!IsInNetworks(fSrcIP, m_keepSignaledIPs)) {
        fSrcIP = 0; fSrcPort = 0;
    }
    if (!IsInNetworks(fDestIP, m_keepSignaledIPs)) {
        fDestIP = 0; fDestPort = 0;
    }
    if (!IsInNetworks(rSrcIP, m_keepSignaledIPs)) {
        rSrcIP = 0; rSrcPort = 0;
    }
    if (!IsInNetworks(rDestIP, m_keepSignaledIPs)) {
        rDestIP = 0; rDestPort = 0;
    }
#ifdef HAS_H46018
    m_portDetectionDone = false;
#endif
}

#ifdef HAS_H46018
void UDPProxySocket::AddKeepAlivePT(BYTE pt)
{
	PWaitAndSignal lock(m_multiplexMutex);
	if ((m_keepAlivePT_1 == UNDEFINED_PAYLOAD_TYPE) || (m_keepAlivePT_1 == pt))
		m_keepAlivePT_1 = pt;
	else
		m_keepAlivePT_2 = pt;
}

void UDPProxySocket::SetMultiplexDestination(const IPAndPortAddress & toAddress, H46019Side side)
{
	PWaitAndSignal lock(m_multiplexMutex);
	if (side == SideA)
		m_multiplexDestination_A = toAddress;
	else
		m_multiplexDestination_B = toAddress;
	PTRACE(7, "JW after SetMultiplexDestination "
		<< " fSrc=" << AsString(fSrcIP, fSrcPort) << " fDest=" << AsString(fDestIP, fDestPort)
		<< " rSrc=" << AsString(rSrcIP, rSrcPort) << " rDest=" << AsString(rDestIP, rDestPort));
	PTRACE(7, "JW AFTER2 " << " type=" << Type() << " this=" << this << " H.460.19=" << UsesH46019()
		<< " multiplex: Dest A=" << AsString(m_multiplexDestination_A) << " ID A=" << m_multiplexID_A << " Socket A=" << m_multiplexSocket_A
		<< " Dest B=" << AsString(m_multiplexDestination_B) << " ID B=" << m_multiplexID_B << " Socket B=" << m_multiplexSocket_B);
}

void UDPProxySocket::SetMultiplexID(DWORD multiplexID, H46019Side side)
{
	PWaitAndSignal lock(m_multiplexMutex);
	if (side == SideA)
		m_multiplexID_A = multiplexID;
	else
		m_multiplexID_B = multiplexID;
}

void UDPProxySocket::SetMultiplexSocket(int multiplexSocket, H46019Side side)
{
	PWaitAndSignal lock(m_multiplexMutex);
	if (side == SideA)
		m_multiplexSocket_A = multiplexSocket;
	else
		m_multiplexSocket_B = multiplexSocket;
}
#endif

void UDPProxySocket::SetMediaIP(bool isSRC, const Address & ip)
{
    PWaitAndSignal lock(m_callMutex);
	if (m_call && *m_call) {
		if (m_isRTCPType) {
			if (isSRC)
				(*m_call)->SetSRC_media_control_IP(ip.AsString());
			else
				(*m_call)->SetDST_media_control_IP(ip.AsString());
		}
		if (m_isRTPType) {
			if (isSRC)
				(*m_call)->SetSRC_media_IP(ip.AsString());
			else
				(*m_call)->SetDST_media_IP(ip.AsString());
		}
	}
}

bool UDPProxySocket::IsRTPInactive() const
{
    time_t now = time(NULL);
    if ( (fSrcIP != 0 && fSrcPort != 0) && (now - m_lastPacketFromForwardSrc > m_inactivityTimeout) ) {
        PTRACE(1, "RTP\tTerminating call because of RTP inactivity from " << AsString(fSrcIP, fSrcPort) << " Call No. " << m_callNo);
        return true;
    }
    if ( (rSrcIP != 0 && rSrcPort != 0) && (now - m_lastPacketFromReverseSrc > m_inactivityTimeout) ) {
        PTRACE(1, "RTP\tTerminating call because of RTP inactivity from " << AsString(rSrcIP, rSrcPort) << " Call No. " << m_callNo);
        return true;
    }
    return false;
}

// this method handles either RTP, RTCP or T.38 data
ProxySocket::Result UDPProxySocket::ReceiveData()
{
#ifdef LARGE_FDSET
	if (!Read(wbuffer, wbufsize, true)) {
#else
	if (!Read(wbuffer, wbufsize)) {
#endif // LARGE_FDSET
		ErrorHandler(PSocket::LastReadError);
		return NoData;
	}
	PWaitAndSignal lockCall(m_callMutex);
	Address fromIP;
	WORD fromPort;
	GetLastReceiveAddress(fromIP, fromPort);
	buflen = (WORD)GetLastReadCount();

	if (!OnReceiveData(wbuffer, buflen, fromIP, fromPort))
		return NoData;

	UnmapIPv4Address(fromIP);
	IPAndPortAddress fromAddr(fromIP, fromPort);	// for easier comparison
	unsigned int version = 0;	// RTP version
	if (buflen >= 1)
		version = (((int)wbuffer[0] & 0xc0) >> 6);
	bool isRTCP = m_isRTCPType && (version == 2);
#if defined(HAS_H46018) || defined(HAS_H46024B) || defined(HAS_H235_MEDIA)
	bool isRTP = m_isRTPType && (version == 2);
#endif
#ifdef HAS_H235_MEDIA
	unsigned char ivSequence[6];
	bool rtpPadding = false;
	if (buflen >= 1)
		rtpPadding = (wbuffer[0] & 0x20);
	if (buflen >= 8)
		memcpy(ivSequence, wbuffer + 2, 6);
#endif

#if defined(HAS_H46018) || defined(HAS_H235_MEDIA)
	BYTE payloadType = UNDEFINED_PAYLOAD_TYPE;
	if ((buflen >= 2) && isRTP)
		payloadType = wbuffer[1] & 0x7f;
#endif

#ifdef HAS_H46018   // this code section also needed when working without H.460.18, but with ignores signaled IPs
	PWaitAndSignal lock(m_multiplexMutex);
	bool isRTPKeepAlive = isRTP && (buflen == 12);
	// Polycom RealPresence Group 300 hack for ignored IPs (needs LARGE_FDSET to work)
	if (buflen == 0 && m_ignoreSignaledIPs) {
        PTRACE(7, "JW RTP IN from " << AsString(fromIP, fromPort) << " 0-Byte UDP keep-alive");
        isRTPKeepAlive = true;
        m_checkH46019KeepAlivePT = false; // no PT to check
    }

	Address localaddr;
	WORD localport = 0;
	GetLocalAddress(localaddr, localport);
	UnmapIPv4Address(localaddr);
	unsigned int seq = 0;
	unsigned int timestamp = 0;
	if (buflen >= 4)
		seq = ((int)wbuffer[2] * 256) + (int)wbuffer[3];
	if (buflen >= 8)
		timestamp = ((int)wbuffer[4] * 16777216) + ((int)wbuffer[5] * 65536) + ((int)wbuffer[6] * 256) + (int)wbuffer[7];
	PTRACE(7, "JW RTP IN on " << localport << " from " << AsString(fromIP, fromPort) << " pType=" << (int)payloadType
		<< " seq=" << seq << " timestamp=" << timestamp << " len=" << buflen
		<< " fSrc=" << AsString(fSrcIP, fSrcPort) << " fDest=" << AsString(fDestIP, fDestPort)
		<< " rSrc=" << AsString(rSrcIP, rSrcPort) << " rDest=" << AsString(rDestIP, rDestPort));
	PTRACE(7, "JW RTP DB on " << localport << " type=" << Type() << " this=" << this << " H.460.19=" << UsesH46019()
		<< " fc=" << m_h46019fc << " m_h46019uni=" << m_h46019uni << " done=" << m_portDetectionDone << " fwd&rev=" << m_forwardAndReverseSeen
		<< " multiplex: Dest A=" << AsString(m_multiplexDestination_A) << " ID A=" << m_multiplexID_A << " Socket A=" << m_multiplexSocket_A
		<< " Dest B=" << AsString(m_multiplexDestination_B) << " ID B=" << m_multiplexID_B << " Socket B=" << m_multiplexSocket_B);

    // avoid RTP bleed attacks / DoS
    if (m_restrictRTPSources) {
        if (IsInNetwork(fromIP, m_restrictRTPNetwork_A) || IsInNetwork(fromIP, m_restrictRTPNetwork_B)) {
            //PTRACE(7, "JW RTP IN on " << localport << " meets IP restrictions - accepting");
        } else {
            PTRACE(5, "JW RTP IN on " << localport << " violates IP restrictions: not in " << AsString(m_restrictRTPNetwork_A) << " or " << AsString(m_restrictRTPNetwork_B) << " - ignoring");
            return NoData;
        }
    }

    if (m_ignoreSignaledIPs && !m_portDetectionDone) {
        //// learn from data we already have (eg. from H.239 signaling)
        // set known destination as assumed source
        if (fSrcIP == 0 && rSrcIP == 0 && fDestIP !=0) {
            rSrcIP = fDestIP, rSrcPort = fDestPort;
            PTRACE(7, "JW RTP IN on " << localport << " learned rSrc " << AsString(rSrcIP, rSrcPort) << " from fDest");
        }
        if (fSrcIP == 0 && rSrcIP == 0 && rDestIP !=0) {
            fSrcIP = rDestIP, fSrcPort = rDestPort;
            PTRACE(7, "JW RTP IN on " << localport << " learned fSrc " << AsString(fSrcIP, fSrcPort) << " from rDest");
        }

        //// learn from this RTP packet
        // no source set, this must be one of them
        if (fSrcIP == 0 && rSrcIP == 0) {
            fSrcIP = fromIP, fSrcPort = fromPort;
            PTRACE(7, "JW RTP IN on " << localport << " learned fSrc " << AsString(fSrcIP, fSrcPort));
        }
        // no forward source set and this is not from reverse source, so it must be from forward source
        if ((rSrcIP != fromIP || rSrcPort != fromPort) && fSrcIP == 0) {
            fSrcIP = fromIP, fSrcPort = fromPort;
            PTRACE(7, "JW RTP IN on " << localport << " learned fSrc " << AsString(fSrcIP, fSrcPort));
        }
        // no reverse source set and this is not from forward source, so it must be from reverse source
        if ((fSrcIP != fromIP || fSrcPort != fromPort) && rSrcIP == 0) {
            rSrcIP = fromIP, rSrcPort = fromPort;
            PTRACE(7, "JW RTP IN on " << localport << " learned rSrc " << AsString(rSrcIP, rSrcPort));
        }
        // this is from forward source and we we don't have reverse destination
        if (fSrcIP == fromIP && fSrcPort == fromPort && rDestIP == 0) {
            rDestIP = fromIP, rDestPort = fromPort;
            PTRACE(7, "JW RTP IN on " << localport << " learned rDest " << AsString(rDestIP, rDestPort) << " from fSrc " << AsString(fSrcIP, fSrcPort));
        }
        // this is from reverse source and we we don't have forward destination
        if (rSrcIP == fromIP && rSrcPort == fromPort && fDestIP == 0) {
            fDestIP = fromIP, fDestPort = fromPort;
            PTRACE(7, "JW RTP IN on " << localport << " learned fDest " << AsString(fDestIP, fDestPort) << " from rSrc " << AsString(rSrcIP, rSrcPort));
        }
        if (fSrcIP != 0 && rSrcIP != 0 && fDestIP !=0 && rDestIP != 0) {
            PTRACE(7, "JW RTP IN on " << localport << " port detection done");
            m_portDetectionDone = true; // stop using RTP packets for port detection, avoid RTP Bleed
        }
    }
	// check payloadType in keepAlive
	if (isRTPKeepAlive && !m_portDetectionDone && m_checkH46019KeepAlivePT) {
		if (m_keepAlivePT_1 != UNDEFINED_PAYLOAD_TYPE && m_keepAlivePT_2 != UNDEFINED_PAYLOAD_TYPE) {
			// we get keep-alives from 2 sides, this keepAlive must match at least one
			if (payloadType != m_keepAlivePT_1 && payloadType != m_keepAlivePT_2) {
				PTRACE(1, "H46019\tError: Invalid keepAlive with PT=" << (int)payloadType);
				isRTPKeepAlive = false;
			}
		} else if (m_keepAlivePT_1 != UNDEFINED_PAYLOAD_TYPE) {
			if (payloadType != m_keepAlivePT_1) {
				PTRACE(1, "H46019\tError: Invalid keepAlive with PT=" << (int)payloadType);
				isRTPKeepAlive = false;
			}
		} else if (m_keepAlivePT_2 != UNDEFINED_PAYLOAD_TYPE) {
			if (payloadType != m_keepAlivePT_2) {
				PTRACE(1, "H46019\tError: Invalid keepAlive with PT=" << (int)payloadType);
				isRTPKeepAlive = false;
			}
		}
	}

	// detecting ports for H.460.19
	if (!m_portDetectionDone) {
		if (!UsesH46019() && !m_ignoreSignaledIPs) {
			m_portDetectionDone = true;	// skip H.460.19 port detection if H.460.19 isn't used
		}
		if ((isRTCP || isRTPKeepAlive) && UsesH46019()) {
			PWaitAndSignal mutexWait (m_h46019DetectionLock);
			// combine IP+port for easier comparison
			IPAndPortAddress fSrcAddr(fSrcIP, fSrcPort);
			IPAndPortAddress fDestAddr(fDestIP, fDestPort);
			IPAndPortAddress rSrcAddr(rSrcIP, rSrcPort);
			IPAndPortAddress rDestAddr(rDestIP, rDestPort);
			PTRACE(5, "H46018\t" << (isRTCP ? "RTCP" : "RTP") << " keepAlive from " << AsString(fromIP, fromPort));
			if ((fDestIP == 0) && (fromAddr != rDestAddr) && ((rSrcIP == 0) || (rSrcAddr == fromAddr))) {
				// fwd dest was unset and packet didn't come from other side
				PTRACE(5, "H46018\tSetting forward destination to " << AsString(fromIP, fromPort) << " based on " << Type() << " keepAlive");
				fDestIP = fromIP; fDestPort = fromPort;
				rSrcIP = fromIP; rSrcPort = fromPort;
				SetMediaIP(true, fDestIP); // SRC
				UpdateSocketName();
			}
			else if ((rDestIP == 0) && (fromAddr != fDestAddr) && ((fSrcIP == 0) || (fSrcAddr == fromAddr))) {
				// reverse dest was unset and packet didn't come from other side
				PTRACE(5, "H46018\tSetting reverse destination to " << AsString(fromIP, fromPort) << " based on " << Type() << " keepAlive");
				rDestIP = fromIP; rDestPort = fromPort;
				fSrcIP = fromIP; fSrcPort = fromPort;
				SetMediaIP(false, rDestIP); // DST
				UpdateSocketName();
			}

			// use keep-alive for multiplexing channel, too
			// (it might have multiplexed RTP coming in to be forwarded as regular RTP)
			// set based on addr
			if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false)) {
				if (IsSet(m_multiplexDestination_A) && (m_multiplexDestination_A != fromAddr)) {
					H46019Session h46019chan = MultiplexedRTPHandler::Instance()->GetChannel(m_callNo, m_sessionID);
					if (h46019chan.IsValid()) {
						if (isRTCP)
							h46019chan.m_addrB_RTCP = fromAddr;
						else
							h46019chan.m_addrB = fromAddr;
						MultiplexedRTPHandler::Instance()->UpdateChannel(h46019chan);
					}
				}
				if (IsSet(m_multiplexDestination_B) && (m_multiplexDestination_B != fromAddr)) {
					H46019Session h46019chan = MultiplexedRTPHandler::Instance()->GetChannel(m_callNo, m_sessionID);
					if (h46019chan.IsValid()) {
						if (isRTCP)
							h46019chan.m_addrA_RTCP = fromAddr;
						else
							h46019chan.m_addrA = fromAddr;
						MultiplexedRTPHandler::Instance()->UpdateChannel(h46019chan);
					}
				}
				if (!IsSet(m_multiplexDestination_A) && !IsSet(m_multiplexDestination_B)) {
					// set if only one side sends multiplexex to GnuGk
					H46019Session h46019chan = MultiplexedRTPHandler::Instance()->GetChannel(m_callNo, m_sessionID);
					if ((h46019chan.m_multiplexID_fromA != INVALID_MULTIPLEX_ID) && (h46019chan.m_multiplexID_fromB == INVALID_MULTIPLEX_ID)) {
						if (h46019chan.IsValid()) {
							if (isRTCP)
								h46019chan.m_addrB_RTCP = fromAddr;
							else
								h46019chan.m_addrB = fromAddr;
							MultiplexedRTPHandler::Instance()->UpdateChannel(h46019chan);
						}
					}
					if ((h46019chan.m_multiplexID_fromA == INVALID_MULTIPLEX_ID) && (h46019chan.m_multiplexID_fromB != INVALID_MULTIPLEX_ID)) {
						if (h46019chan.IsValid()) {
							if (isRTCP)
								h46019chan.m_addrA_RTCP = fromAddr;
							else
								h46019chan.m_addrA = fromAddr;
							MultiplexedRTPHandler::Instance()->UpdateChannel(h46019chan);
						}
					}
				}
			}
#ifdef HAS_H46026
			// update new H.460.19 address in H.460.26 session
			if (Toolkit::Instance()->IsH46026Enabled()) {
                if (isRTCP) {
                    H46026RTPHandler::Instance()->UpdateChannelRTCP(m_callNo, m_sessionID, fromAddr);
                } else {
                    H46026RTPHandler::Instance()->UpdateChannelRTP(m_callNo, m_sessionID, fromAddr);
                }
            }
#endif

			if ((fDestIP != 0) && (rDestIP != 0)) {
				m_portDetectionDone = true;
				// note: we don't do port switching at this time, once the ports are set they stay (this also avoid RTPBleed)
#ifdef HAS_H46024B
				// If required begin Annex B probing
				if (isRTPKeepAlive && m_call && (*m_call) && (*m_call)->GetNATStrategy() == CallRec::e_natAnnexB) {
					(*m_call)->H46024BInitiate(m_sessionID, IPAndPortAddress(fDestIP, fDestPort), IPAndPortAddress(rDestIP, rDestPort));
				}
#endif	// HAS_H46024B
			}
			PTRACE(7, "JW RTP IN2 on " << localport << " from " << AsString(fromIP, fromPort)
				<< " fSrc=" << AsString(fSrcIP, fSrcPort) << " fDest=" << AsString(fDestIP, fDestPort)
				<< " rSrc=" << AsString(rSrcIP, rSrcPort) << " rDest=" << AsString(rDestIP, rDestPort)
			);
		}
	}
    // inactivity checking
    if (fromIP == fSrcIP && fromPort == fSrcPort) {
        m_lastPacketFromForwardSrc = time(NULL);
    }
    if (fromIP == rSrcIP && fromPort == rSrcPort) {
        m_lastPacketFromReverseSrc = time(NULL);
    }
	if (isRTPKeepAlive) {
		return NoData;	// don't forward RTP keepAlive (RTCP uses first data packet which must be forwarded)
	}

	// set of fixes for H.460.19 port detection
	if (UsesH46019() && !m_portDetectionDone) {
		// fix for H.239 from H.460.19 client
		if (m_h46019uni && !isRTCP
			&& fSrcIP == 0 && fDestIP != 0 && rDestIP == 0
			&& fromAddr != IPAndPortAddress(fDestIP, fDestPort)) {	// never create a loop
			PTRACE(5, "H46018\tSetting forward source on unidirectional channel to " << AsString(fromIP, fromPort));
			fSrcIP = fromIP, fSrcPort = fromPort;
			m_portDetectionDone = true;
		}
		if (m_h46019uni && !isRTCP
			&& fSrcIP != 0 && fDestIP != 0 && rSrcIP != 0 && rDestIP == 0
			&& fromAddr == IPAndPortAddress(fSrcIP, fSrcPort)
			&& fromAddr != IPAndPortAddress(rSrcIP, rSrcPort)) {	// never create a loop
			PTRACE(5, "H46018\tSetting reverse destination on unidirectional channel to " << AsString(fromIP, fromPort));
			rDestIP = fromIP, rDestPort = fromPort;
			m_portDetectionDone = true;
		}
		// fix for H.224 connection: m100 1.0.6 doesn't send keepAlive, but we can see where it apparently comes from
		PTimeInterval channelUpTime = PTime() - m_channelStartTime;
		if (!m_h46019uni && (channelUpTime.GetMilliSeconds() > H46019_AUTO_DETECTION_WAIT)) {
			IPAndPortAddress rSrcAddr(rSrcIP, rSrcPort);
			if (fSrcIP == 0 && rDestIP == 0 && fDestIP != 0
				&& rSrcIP != 0 && fromAddr != rSrcAddr
				&& fromAddr != IPAndPortAddress(fDestIP, fDestPort)) {	// never create a loop
				PTRACE(5, "H46018\tAuto-detecting forward source on H.460.19 channel to " << AsString(fromIP, fromPort));
				fSrcIP = fromIP, fSrcPort = fromPort;
			}
			IPAndPortAddress fSrcAddr(fSrcIP, fSrcPort);
			if (fSrcIP != 0 && rDestIP != 0 && fDestIP == 0
				&& rSrcIP == 0 && fromAddr != fSrcAddr
				&& fromAddr != IPAndPortAddress(rDestIP, rDestPort)) {	// never create a loop
				PTRACE(5, "H46018\tAuto-detecting reverse source on H.460.19 channel to " << AsString(fromIP, fromPort));
				rSrcIP = fromIP, rSrcPort = fromPort;
			}
		}
		// set RTCP destination in channels with only 1 H.460.19 client
		// (we only saved it as source IP form the OLC and didn't set the dest IP)
		if (m_isRTCPType && fSrcIP != 0 && fDestIP == 0 && rSrcIP == 0 && rDestIP == 0) {
			PTRACE(5, "H46018\tSet RTCP reverse dest from forward source to " << AsString(fSrcIP, fSrcPort));
			rDestIP = fSrcIP, rDestPort = fSrcPort;
		}
		if (m_isRTCPType && fSrcIP == 0 && fDestIP == 0 && rSrcIP != 0 && rDestIP == 0) {
			PTRACE(5, "H46018\tSet RTCP forward dest from reverse source to " << AsString(rSrcIP, rSrcPort));
			fDestIP = rSrcIP, fDestPort = rSrcPort;
		}
	}

#ifdef HAS_H235_MEDIA
    if (isRTP && (!m_call || (m_call && !(*m_call)))) {
		if (m_encryptingLC || m_decryptingLC) {
            PTRACE(7, "JW RTP dropping crypto RTP packet (call object already gone)");
            return NoData;
        }
    }
	// H.235.6 sect 9.3.3 says RTCP encryption is for further study, so we don't encrypt/decrypt RTCP
	if (m_call && (*m_call) && (*m_call)->IsMediaEncryption() && isRTP) {
		bool ready = false;
		bool encrypting = false;
		if (m_encryptingLC && m_decryptingLC) {
			if (m_encryptingLC->GetPlainPayloadType() == m_decryptingLC->GetCipherPayloadType()) {
				// HACK: this only works if caller and called are on different IPs and send media from the same IP as call signaling
				if (!m_haveShownPTWarning) { // show warning only once (not for every RTP packet)
					PTRACE(1, "WARNING: Can't use PT to decide encryption direction -> fall back on IPs");
					m_haveShownPTWarning = true;
				}
				PIPSocket::Address callerSignalIP;
				WORD notused;
				(*m_call)->GetSrcSignalAddr(callerSignalIP, notused);
				bool fromCaller = (callerSignalIP == fromIP);
				bool simulateCaller = ((*m_call)->GetEncryptDirection() == CallRec::callingParty);
				encrypting = ((fromCaller && simulateCaller) || (!fromCaller && !simulateCaller));
			} else {
				encrypting = (payloadType == m_encryptingLC->GetPlainPayloadType());
			}
			ready = true;
		}
		// one-sided channel
		if (!ready && m_encryptingLC && (payloadType == m_encryptingLC->GetPlainPayloadType())) {
			encrypting = true;
			ready = true;
		}
		if (!ready && m_decryptingLC && (payloadType == m_decryptingLC->GetCipherPayloadType())) {
			encrypting = false;
			ready = true;
		}

		bool succesful = false;
		if (ready) {
			if (encrypting) {
				succesful = m_encryptingLC->ProcessH235Media(wbuffer, buflen, encrypting, ivSequence, rtpPadding, payloadType);
			} else {
				succesful = m_decryptingLC->ProcessH235Media(wbuffer, buflen, encrypting, ivSequence, rtpPadding, payloadType);
			}
		} else {
			PTRACE(3, "H235\tCrypto channel not ready");
		}

		if (!succesful)
			return NoData;

		// update RTP padding bit
		if (rtpPadding)
			wbuffer[0] |= 0x20;
		else
			wbuffer[0] &= 0xdf;
		// update payload type, preserve marker bit
		wbuffer[1] = (wbuffer[1] & 0x80) | (payloadType & 0x7f);
	}
#endif

#ifdef HAS_H46026
	// send packets to H.460.26 endpoints via TCP
	if (m_call && (*m_call) && (*m_call)->GetCallingParty() && (*m_call)->GetCallingParty()->UsesH46026()) {
		if (m_call && (*m_call) && (*m_call)->GetCallingParty()->GetSocket()) {
			(*m_call)->GetCallingParty()->GetSocket()->SendH46026RTP(m_sessionID, isRTP, wbuffer, buflen);
		}
		return NoData;	// already forwarded via TCP
	} else if (m_call && (*m_call) && (*m_call)->GetCalledParty() && (*m_call)->GetCalledParty()->UsesH46026()) {
		if (m_call && (*m_call) && (*m_call)->GetCalledParty()->GetSocket()) {
			(*m_call)->GetCalledParty()->GetSocket()->SendH46026RTP(m_sessionID, isRTP, wbuffer, buflen);
		}
		return NoData;	// already forwarded via TCP
	}
#endif

	// send packets for a multiplexing destination out through multiplexing socket
	if (IsSet(m_multiplexDestination_A) && (m_multiplexDestination_A != fromAddr)) {
		if (isRTCP && m_EnableRTCPStats && m_call && (*m_call))
			ParseRTCP(*m_call, m_sessionID, fromIP, wbuffer, buflen);
		H46019Session::Send(m_multiplexID_A, m_multiplexDestination_A, m_multiplexSocket_A, wbuffer, buflen);
		return NoData;	// already forwarded through multiplex socket
	}
	if (IsSet(m_multiplexDestination_B) && (m_multiplexDestination_B != fromAddr)) {
		if (isRTCP && m_EnableRTCPStats && m_call && (*m_call))
			ParseRTCP(*m_call, m_sessionID, fromIP, wbuffer, buflen);
		H46019Session::Send(m_multiplexID_B, m_multiplexDestination_B, m_multiplexSocket_B, wbuffer, buflen);
		return NoData;	// already forwarded through multiplex socket
	}

#endif	// HAS_H46018
	// fSrcIP = forward-Source-IP, fDest-IP = forward destination IP, rDestIP = reverse destination IP
	/* autodetect channel source IP:PORT that was not specified by OLCs */
	if (rSrcIP == 0 && fromIP == fDestIP) {
        PTRACE(7, "JW RTP setting rSrcIP = " << AsString(rSrcIP, rSrcPort));
        rSrcIP = fromIP, rSrcPort = fromPort;
	}
	if (fSrcIP == 0 && fromIP == rDestIP) {
		fSrcIP = fromIP, fSrcPort = fromPort;
		Address laddr;
		WORD lport = 0;
		GetLocalAddress(laddr, lport);
		UnmapIPv4Address(laddr);
		SetName(AsString(fSrcIP, fSrcPort) + "=>" + AsString(laddr, lport));
	}

	// Workaround: some bad endpoints don't send packets from the specified port
	if ((fromIP == fSrcIP && fromPort == fSrcPort)
		|| (fromIP == rDestIP && fromIP != rSrcIP)) {   // TODO: BUG ? (fromIP == rDestIP && fromPort != rDestPort) ?
        if (fDestPort) {
            PTRACE(6, Type() << "\tforward " << fromIP << ':' << fromPort << " to " << AsString(fDestIP, fDestPort));
#ifdef HAS_H46024B
            if (isRTP && m_call && (*m_call) && (*m_call)->GetNATStrategy() == CallRec::e_natAnnexB) {
#ifdef HAS_H46018
                m_portDetectionDone = true;  // we missed the probe packets but detection is done
#endif
			    (*m_call)->H46024BInitiate(m_sessionID, IPAndPortAddress(fDestIP, fDestPort), IPAndPortAddress(fromIP, fromPort));
            }
#endif
#ifndef P_LINUX
            // needed on Windows and FreeBSD, breaks IPv4 on Linux
			if (Toolkit::Instance()->IsIPv6Enabled())
				MapIPv4Address(fDestIP);
#endif
			SetSendAddress(fDestIP, fDestPort);
		} else {
			PTRACE(6, Type() << "\tForward from " << AsString(fromIP, fromPort)
				<< " blocked, remote socket (" << AsString(fDestIP, fDestPort)
				<< ") not yet known or ready");
			if (m_dontQueueRTP)
				return NoData;
		}
        if (rnat && (!m_portDetectionDone || m_legacyPortDetection)) {
            // RTP bleed
            PTRACE(7, "JW RTP setting rDestIP = " << AsString(rDestIP, rDestPort));
            rDestIP = fromIP, rDestPort = fromPort;
        }
	} else {
		if (rDestPort) {
			PTRACE(6, Type() << "\tForward " << AsString(fromIP, fromPort)
				<< " to " << AsString(rDestIP, rDestPort));
#ifndef P_LINUX
            // needed on Windows and FreeBSD, breaks IPv4 on Linux
			if (Toolkit::Instance()->IsIPv6Enabled())
				MapIPv4Address(rDestIP);
#endif
			SetSendAddress(rDestIP, rDestPort);
		} else {
			PTRACE(6, Type() << "\tForward from " << AsString(fromIP, fromPort)
				<< " blocked, remote socket (" << AsString(rDestIP, rDestPort)
				<< ") not yet known or ready");
			if (m_dontQueueRTP)
				return NoData;
        }
        if (fnat && (!m_portDetectionDone || m_legacyPortDetection)) {
            // RTP bleed
            PTRACE(7, "JW RTP setting fDestIP = " << AsString(fDestIP, fDestPort));
            fDestIP = fromIP, fDestPort = fromPort;
        }
	}

	if (isRTCP && m_EnableRTCPStats && m_call && (*m_call))
		ParseRTCP(*m_call, m_sessionID, fromIP, wbuffer, buflen);

	PIPSocket::Address toIP;
	WORD toPort = 0;
	GetSendAddress(toIP, toPort);
	UDPSendWithSourceIP(os_handle, wbuffer, buflen, toIP, toPort);
	return NoData;	// we just forwarded the data here
}

namespace {

void ParseRTCP(const callptr & call, WORD sessionID, PIPSocket::Address fromIP, BYTE * wbuffer, WORD buflen)
{
	if (buflen < 4) {
		PTRACE(1, "RTCP\tInvalid RTCP frame");
		return;
	}

	bool fromDST = (call->GetSRC_media_control_IP() == fromIP.AsString());   // TODO: is this still correct in presence of NAT traversal protocols ???

	RTP_ControlFrame frame(2048);
	frame.Attach(wbuffer, buflen);
	do {
		BYTE * payload = frame.GetPayloadPtr();
		unsigned size = frame.GetPayloadSize();
		if ((payload == NULL) || (size == 0)
			|| (frame.GetVersion() != 2)
			|| ((payload + size) > (frame.GetPointer() + frame.GetSize()))) {
			// TODO: test for a maximum size ? what is the max size ? check size against buflen ?
			PTRACE(1, "RTCP\tInvalid RTCP frame");
			return;
		}
		switch (frame.GetPayloadType()) {
		case RTP_ControlFrame::e_SenderReport :
			PTRACE(7, "RTCP\tSenderReport packet");
			if (size >= (sizeof(RTP_ControlFrame::SenderReport) + frame.GetCount() * sizeof(RTP_ControlFrame::ReceiverReport))) {
				const RTP_ControlFrame::SenderReport & sr = *(const RTP_ControlFrame::SenderReport *)(payload);
				if (fromDST) {
					if (sessionID == RTP_Session::DefaultAudioSessionID) {
						call->SetRTCP_DST_packet_count(sr.psent);
						PTRACE(7, "RTCP\tSetRTCP_DST_packet_count: " << sr.psent);
					}
					if (sessionID == RTP_Session::DefaultVideoSessionID) {
						call->SetRTCP_DST_video_packet_count(sr.psent);
						PTRACE(7, "RTCP\tSetRTCP_DST_video_packet_count: " << sr.psent);
					}
				} else {
					if (sessionID == RTP_Session::DefaultAudioSessionID) {
						call->SetRTCP_SRC_packet_count(sr.psent);
						PTRACE(7, "RTCP\tSetRTCP_SRC_packet_count: " << sr.psent);
					}
					if (sessionID == RTP_Session::DefaultVideoSessionID) {
						call->SetRTCP_SRC_video_packet_count(sr.psent);
						PTRACE(7, "RTCP\tSetRTCP_SRC_video_packet_count: " << sr.psent);
					}
				}
				BuildReceiverReport(call, sessionID, frame, sizeof(RTP_ControlFrame::SenderReport), fromDST);
			} else {
				PTRACE(5, "RTCP\tSenderReport packet truncated");
			}
			break;
		case RTP_ControlFrame::e_ReceiverReport:
			PTRACE(7, "RTCP\tReceiverReport packet");
			if (size >= (frame.GetCount()*sizeof(RTP_ControlFrame::ReceiverReport))) {
				BuildReceiverReport(call, sessionID, frame, sizeof(DWORD), fromDST);
			} else {
				PTRACE(5, "RTCP\tReceiverReport packet truncated");
			}
			break;
		case RTP_ControlFrame::e_SourceDescription :
			PTRACE(7, "RTCP\tSourceDescription packet");
			if ((!call->GetRTCP_SRC_sdes_flag() && fromDST) || (!call->GetRTCP_DST_sdes_flag() && !fromDST))
				if (size >= (frame.GetCount()*sizeof(RTP_ControlFrame::SourceDescription))) {
					const RTP_ControlFrame::SourceDescription * sdes = (const RTP_ControlFrame::SourceDescription *)payload;
					for (PINDEX srcIdx = 0; srcIdx < (PINDEX)frame.GetCount(); srcIdx++) {
						const RTP_ControlFrame::SourceDescription::Item * item = sdes->item;
						while ((item != NULL)
								&& (((BYTE*)item + sizeof(RTP_ControlFrame::SourceDescription::Item)) <= (payload + size))
								&& (item->type != RTP_ControlFrame::e_END)) {
							if (item->length != 0) {
								switch (item->type) {
								case RTP_ControlFrame::e_CNAME:
									call->SetRTCP_sdes(fromDST, "cname="+((PString)(item->data)).Left(item->length));
									break;
								case RTP_ControlFrame::e_NAME:
									call->SetRTCP_sdes(fromDST, "name="+((PString)(item->data)).Left(item->length));
									break;
								case RTP_ControlFrame::e_EMAIL:
									call->SetRTCP_sdes(fromDST, "email="+((PString)(item->data)).Left(item->length));
									break;
								case RTP_ControlFrame::e_PHONE:
									call->SetRTCP_sdes(fromDST, "phone="+((PString)(item->data)).Left(item->length));
									break;
								case RTP_ControlFrame::e_LOC:
									call->SetRTCP_sdes(fromDST, "loc="+((PString)(item->data)).Left(item->length));
									break;
								case RTP_ControlFrame::e_TOOL:
									call->SetRTCP_sdes(fromDST, "tool="+((PString)(item->data)).Left(item->length));
									break;
								case RTP_ControlFrame::e_NOTE:
									call->SetRTCP_sdes(fromDST, "note="+((PString)(item->data)).Left(item->length));
									break;
								default:
									PTRACE(7, "RTCP\tSourceDescription unknown item type " << item->type);
									break;
								}
							}
							item = item->GetNextItem();
						}
						/* RTP_ControlFrame::e_END doesn't have a length field, so do NOT call item->GetNextItem()
						   otherwise it reads over the buffer */
						if ((item == NULL)
							|| (item->type == RTP_ControlFrame::e_END)
							|| ((sdes = (const RTP_ControlFrame::SourceDescription *)item->GetNextItem()) == NULL)){
							break;
					}
				}
			}
			break;
		case RTP_ControlFrame::e_Goodbye:
			PTRACE(7, "RTCP\tGoodbye packet");
			break;
		case RTP_ControlFrame::e_ApplDefined:
			PTRACE(7, "RTCP\tApplDefined packet");
			break;
		default:
			PTRACE(5, "RTCP\tUnknown control payload type: " << frame.GetPayloadType());
			break;
		}
	} while (frame.ReadNextCompound());
}

void BuildReceiverReport(const callptr & call, WORD sessionID, const RTP_ControlFrame & frame, PINDEX offset, bool dst)
{
	const RTP_ControlFrame::ReceiverReport * rr = (const RTP_ControlFrame::ReceiverReport *)(frame.GetPayloadPtr()+offset);
	for (PINDEX repIdx = 0; repIdx < (PINDEX)frame.GetCount(); repIdx++) {
		if (dst) {
			if (sessionID == RTP_Session::DefaultAudioSessionID) {
				call->SetRTCP_DST_packet_lost(rr->GetLostPackets());
				call->SetRTCP_DST_jitter(rr->jitter / 8);
				PTRACE(7, "RTCP\tSetRTCP_DST_packet_lost: " << rr->GetLostPackets());
				PTRACE(7, "RTCP\tSetRTCP_DST_jitter: " << (rr->jitter / 8));
			}
			if (sessionID == RTP_Session::DefaultVideoSessionID) {
				call->SetRTCP_DST_video_packet_lost(rr->GetLostPackets());
				call->SetRTCP_DST_video_jitter(rr->jitter / 90);
				PTRACE(7, "RTCP\tSetRTCP_DST_video_packet_lost: " << rr->GetLostPackets());
				PTRACE(7, "RTCP\tSetRTCP_DST_video_jitter: " << (rr->jitter / 90));
			}
		} else {
			if (sessionID == RTP_Session::DefaultAudioSessionID) {
				call->SetRTCP_SRC_packet_lost(rr->GetLostPackets());
				call->SetRTCP_SRC_jitter(rr->jitter / 8);
				PTRACE(7, "RTCP\tSetRTCP_SRC_packet_lost: " << rr->GetLostPackets());
				PTRACE(7, "RTCP\tSetRTCP_SRC_jitter: " << (rr->jitter / 8));
			}
			if (sessionID == RTP_Session::DefaultVideoSessionID) {
				call->SetRTCP_SRC_video_packet_lost(rr->GetLostPackets());
				call->SetRTCP_SRC_video_jitter(rr->jitter / 90);
				PTRACE(7, "RTCP\tSetRTCP_SRC_video_packet_lost: " << rr->GetLostPackets());
				PTRACE(7, "RTCP\tSetRTCP_SRC_video_jitter: " << (rr->jitter / 90));
			}
		}
		rr++;
	}
}

}	// end namespace

bool UDPProxySocket::WriteData(const BYTE *buffer, int len)
{
	if (!IsSocketOpen())
		return false;

	if (isMute())
		return true;

	// TODO: since we have to send data in 2 directions (fDestIP + rDestIP),
	// we should have 2 queues to avoid loopback
	const int queueSize = GetQueueSize();
	if (queueSize > 0) {
		if (queueSize < 50 && !m_dontQueueRTP) {
			QueuePacket(buffer, len);
			PTRACE(3, Type() << '\t' << Name() << " socket is busy, " << len << " bytes queued");
			return false;
		} else {
			ClearQueue();
			PTRACE(3, Type() << '\t' << Name() << " socket queue overflow, dropping queued packets");
		}
	}

	// check if the remote address to send data to has been already determined
	PIPSocket::Address addr;
	WORD wport = 0;
	GetSendAddress(addr, wport);
	if (wport == 0) {
		QueuePacket(buffer, len);
		PTRACE(3, Type() << '\t' << Name() << " socket has no destination address yet, " << len << " bytes queued");
		return false;
	}

	return InternalWriteData(buffer, len);
}

bool UDPProxySocket::Flush()
{
	// check if the remote address to send data to has been already determined
	PIPSocket::Address addr;
	WORD fport = 0;
	GetSendAddress(addr, fport);
	if (fport == 0) {
		PTRACE(3, Type() << '\t' << Name() << " socket has no destination address yet, flush ignored");
		return false;
	}

	// TODO: since we have to send data in 2 directions (fDestIP + rDestIP),
	// we should have 2 queues to avoid loopback
	bool result = true;
	while (result && GetQueueSize() > 0) {
		PBYTEArray* const pdata = PopQueuedPacket();
		if (pdata) {
			result = InternalWriteData(*pdata, pdata->GetSize());
			PTRACE_IF(4, result, Type() << '\t' << pdata->GetSize() << " bytes flushed to " << Name());
			delete pdata;
		} else
			break;
	}
	return result;
}

bool UDPProxySocket::ErrorHandler(PSocket::ErrorGroup group)
{
	const PString msg = PString(Type()) + "\t" + Name();
	const PSocket::Errors e = GetErrorCode(group);

	switch (e)
	{
		case PSocket::NoError:
			// I don't know why there is error with code NoError
			// PTRACE(4, msg << " Error(" << group << "): No error?");
			break;
		case PSocket::Timeout:
			PTRACE(4, msg << " Error(" << group << "): Timeout");
			SNMP_TRAP(10, SNMPWarning, Network, "UDP timeout: " + msg);
			break;
		case PSocket::NotOpen:
			CloseSocket();
			// fallthrough intended
		default:
			PTRACE(3, msg << " Error(" << group << "): "
				<< PSocket::GetErrorText(e) << " (" << e << ':'
				<< GetErrorNumber(group) << ')');
			SNMP_TRAP(10, SNMPWarning, Network, "UDP error: " + PSocket::GetErrorText(e));
			break;
	}
	return false;
}


// class T120ProxySocket
T120ProxySocket::T120ProxySocket(T120LogicalChannel *lc)
      : TCPProxySocket("T120s"), t120lc(lc)
{
}

T120ProxySocket::T120ProxySocket(T120ProxySocket *socket, WORD pt)
      : TCPProxySocket("T120d", socket, pt), t120lc(NULL)
{
	socket->remote = this;
}

bool T120ProxySocket::ForwardData()
{
	PWaitAndSignal lock(m_remoteLock);
	return remote ? remote->ProxySocket::TransmitData(wbuffer, buflen) : false;
}

void T120ProxySocket::Dispatch()
{
	ReadLock lock(ConfigReloadMutex);
	PTRACE(4, "T120\tConnected from " << GetName());
	t120lc->Create(this);
}


// class RTPLogicalChannel
RTPLogicalChannel::RTPLogicalChannel(const H225_CallIdentifier & id, WORD flcn, bool nated, WORD sessionID, RTPSessionTypes sessionType)
    : LogicalChannel(flcn), reversed(false), peer(NULL), m_sessionType(sessionType)
{
    m_ignoreSignaledIPs = false;
    m_ignoreSignaledPrivateH239IPs = false;
    m_callNo = 0;
    callptr call = CallTable::Instance()->FindCallRec(id);
    if (call) {
        m_callNo = call->GetCallNumber();
    }
#ifdef HAS_H46018
    if (call) {
        m_ignoreSignaledIPs = call->IgnoreSignaledIPs();
        if (m_ignoreSignaledIPs) {
            if (call && call->GetCallingParty() && call->GetCallingParty()->GetTraversalRole() != None) {
                // disable, when caller has NAT traversal enabled (call isn't from an party that needs NAT help)
                m_ignoreSignaledIPs = false;
                call->SetIgnoreSignaledIPs(false);
            } else {
                m_ignoreSignaledPrivateH239IPs = GkConfig()->GetBoolean(ProxySection, "IgnoreSignaledPrivateH239IPs", false);
                PStringArray keepSignaledIPs = GkConfig()->GetString(ProxySection, "AllowSignaledIPs", "").Tokenise(",", FALSE);
                for (PINDEX i = 0; i < keepSignaledIPs.GetSize(); ++i) {
                    PString ip = keepSignaledIPs[i];
                    if (ip.Find('/') == P_MAX_INDEX) {
                        // add netmask to pure IPs
                        if (IsIPv4Address(ip)) {
                            ip += "/32";
                        } else {
                            ip += "/128";
                        }
                    }
                    m_keepSignaledIPs.push_back(NetworkAddress(ip));
                }
            }
        }
    }
#endif
    m_isUnidirectional = false;
	SrcIP = 0;
	SrcPort = 0;
	rtp = NULL;
	rtcp = NULL;
	m_callID = id;
#ifdef HAS_H235_MEDIA
	m_H235CryptoEngine = NULL;
	m_auth = NULL;
	m_encrypting = false;
	m_plainPayloadType = UNDEFINED_PAYLOAD_TYPE;
	m_cipherPayloadType = UNDEFINED_PAYLOAD_TYPE;
#endif

#ifdef HAS_H46023
	// If we have a GKClient check whether to create NAT ports or not.
	GkClient * gkClient = RasServer::Instance()->GetGkClient();
	if (gkClient && !gkClient->H46023_CreateSocketPair(id, m_callNo, sessionID, rtp, rtcp, nated))
#endif
	{
		rtp = new UDPProxySocket("RTP", m_callNo);
		rtcp = new UDPProxySocket("RTCP", m_callNo);
	}
    SetNAT(nated);

	// if Home specifies only one local address, we want to bind
	// only to this specified local address
	PIPSocket::Address laddr(GNUGK_INADDR_ANY);
	std::vector<PIPSocket::Address> home;
	Toolkit::Instance()->GetGKHome(home);
	if (home.size() == 1)
		laddr = home[0];

	int numPorts = min(RTPPortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS*2);
	for (int i = 0; i < numPorts; i += 2) {
		port = GetPortNumber();
		// try to bind rtp to an even port and rtcp to the next one port
		if (rtp && !rtp->Bind(laddr, port)) {
			PTRACE(1, "RTP\tRTP socket " << AsString(laddr, port) << " not available - error "
				<< rtp->GetErrorCode(PSocket::LastGeneralError) << '/'
				<< rtp->GetErrorNumber(PSocket::LastGeneralError) << ": "
				<< rtp->GetErrorText(PSocket::LastGeneralError));
			SNMP_TRAP(10, SNMPError, Network, "Can't bind to RTP port " + AsString(laddr, port));
			rtp->Close();
			continue;
		}
		if (rtcp && !rtcp->Bind(laddr, port+1)) {
			PTRACE(1, "RTP\tRTCP socket " << AsString(laddr, port + 1) << " not available - error "
				<< rtcp->GetErrorCode(PSocket::LastGeneralError) << '/'
				<< rtcp->GetErrorNumber(PSocket::LastGeneralError) << ": "
				<< rtcp->GetErrorText(PSocket::LastGeneralError));
			SNMP_TRAP(10, SNMPError, Network, "Can't bind to RTCP port " + AsString(laddr, port));
			rtcp->Close();
			if (rtp)
                rtp->Close();
			continue;
		}
		return;
	}

	PTRACE(2, "RTP\tLogical channel " << flcn << " could not be established - out of RTP sockets");
}

RTPLogicalChannel::RTPLogicalChannel(RTPLogicalChannel * flc, WORD flcn, bool nated, RTPSessionTypes sessionType)
{
    m_ignoreSignaledIPs = false;
    m_ignoreSignaledPrivateH239IPs = false;
#ifdef HAS_H46018
    callptr call = CallTable::Instance()->FindCallRec(flc->m_callNo);
    if (call) {
        m_ignoreSignaledIPs = call->IgnoreSignaledIPs();
        if (m_ignoreSignaledIPs) {
            if (call && call->GetCallingParty() && call->GetCallingParty()->GetTraversalRole() != None) {
                // disable, when caller has NAT traversal enabled (call isn't from an party that needs NAT help)
                m_ignoreSignaledIPs = false;
                call->SetIgnoreSignaledIPs(false);
            } else {
                m_ignoreSignaledPrivateH239IPs = GkConfig()->GetBoolean(ProxySection, "IgnoreSignaledPrivateH239IPs", false);
                PStringArray keepSignaledIPs = GkConfig()->GetString(ProxySection, "AllowSignaledIPs", "").Tokenise(",", FALSE);
                for (PINDEX i = 0; i < keepSignaledIPs.GetSize(); ++i) {
                    PString ip = keepSignaledIPs[i];
                    if (ip.Find('/') == P_MAX_INDEX) {
                        // add netmask to pure IPs
                        if (IsIPv4Address(ip)) {
                            ip += "/32";
                        } else {
                            ip += "/128";
                        }
                    }
                    m_keepSignaledIPs.push_back(NetworkAddress(ip));
                }
            }
        }
    }
#endif
    m_isUnidirectional = false;
#ifdef HAS_H235_MEDIA
	m_H235CryptoEngine = NULL;
	m_auth = NULL;
	m_encrypting = false;
	m_plainPayloadType = UNDEFINED_PAYLOAD_TYPE;
	m_cipherPayloadType = UNDEFINED_PAYLOAD_TYPE;
#endif
	m_callID = flc->m_callID;
	m_callNo = flc->m_callNo;
	port = flc->port;
	used = flc->used;
	rtp = flc->rtp;
	rtcp = flc->rtcp;
	SrcIP = flc->SrcIP;     // gets overwritten with IP from OLC for this direction shortly
	SrcPort = flc->SrcPort;
	reversed = !flc->reversed;
	peer = flc, flc->peer = this;
	SetChannelNumber(flcn);
	SetNAT(nated);
	m_sessionType = sessionType;
}

RTPLogicalChannel::~RTPLogicalChannel()
{
#ifdef HAS_H235_MEDIA
#ifdef HAS_H46018
	// remove crypto engines from the multiplex channel
	if (GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false))
		MultiplexedRTPHandler::Instance()->RemoveChannel(m_callNo, this);
#endif
	m_cryptoEngineMutex.Wait();
	if (m_H235CryptoEngine) {
		if (rtp) {
			rtp->RemoveEncryptingRTPChannel(this);
			rtp->RemoveDecryptingRTPChannel(this);
		}
		delete m_H235CryptoEngine;
		m_H235CryptoEngine = NULL;
	}
	m_cryptoEngineMutex.Signal();
#endif

	if (rtp)
		rtp->RemoveCallPtr();
	if (rtcp)
		rtcp->RemoveCallPtr();

	if (peer) {
		peer->peer = NULL;
	} else {
        // skip object cleanup on system shutdown, may have already been deleted by ProxyHandler d'tor (race condition)
        if (!IsGatekeeperShutdown()) {
            if (used) {
                // the sockets will be deleted by ProxyHandler,
                // so we don't need to delete it here
                if (rtp) {
                    rtp->Close();
                    rtp->SetDeletable();
                    rtp = NULL;
                }
                if (rtcp) {
                    rtcp->Close();
                    rtcp->SetDeletable();
                    rtcp = NULL;
                }
            } else {
                delete rtp;
                rtp = NULL;
                delete rtcp;
                rtcp = NULL;
            }
        }
	}
	PTRACE(4, "RTP\tDelete logical channel " << channelNumber);
}

bool RTPLogicalChannel::IsOpen() const
{
	return rtp->IsOpen() && rtcp->IsOpen();
}

void RTPLogicalChannel::SetUniDirectional(bool uni)
{
    m_isUnidirectional = uni;
#ifdef HAS_H46018
    if (m_isUnidirectional) {   // don't overwrite a previous TRUE setting
        if (rtp)
            rtp->SetH46019UniDirectional(true);
        if (rtcp)
            rtcp->SetH46019UniDirectional(true);
    }
#endif
}

#ifdef HAS_H46018
void RTPLogicalChannel::SetUsesH46019fc(bool fc)
{
	if (rtp)
		rtp->SetUsesH46019fc(fc);
	if (rtcp)
		rtcp->SetUsesH46019fc(fc);
}

void RTPLogicalChannel::SetUsesH46019()
{
	if (rtp)
		rtp->SetUsesH46019();
	if (rtcp)
		rtcp->SetUsesH46019();
}

void RTPLogicalChannel::SetLCMultiplexDestination(bool isRTCP, const IPAndPortAddress & toAddress, H46019Side side)
{
	if (isRTCP) {
        if (rtcp) {
            rtcp->SetMultiplexDestination(toAddress, side);
        } else {
            PTRACE(2, "Error: No RTCP channel set in SetLCMultiplexDestination()");
        }
	}
	if (!isRTCP) {
        if (rtp) {
            rtp->SetMultiplexDestination(toAddress, side);
        } else {
            PTRACE(2, "Error: No RTP channel set in SetLCMultiplexDestination()");
        }
	}
}

void RTPLogicalChannel::AddLCKeepAlivePT(unsigned pt)
{
	if (rtp) {
		rtp->AddKeepAlivePT((BYTE)pt);
	}
}

void RTPLogicalChannel::SetLCMultiplexID(bool isRTCP, DWORD multiplexID, H46019Side side)
{
	if (isRTCP && rtcp) {
		rtcp->SetMultiplexID(multiplexID, side);
	}
	if (!isRTCP && rtp) {
		rtp->SetMultiplexID(multiplexID, side);
	}
}

void RTPLogicalChannel::SetLCMultiplexSocket(bool isRTCP, int multiplexSocket, H46019Side side)
{
	if (isRTCP && rtcp) {
		rtcp->SetMultiplexSocket(multiplexSocket, side);
	}
	if (!isRTCP && rtp) {
		rtp->SetMultiplexSocket(multiplexSocket, side);
	}
}
#endif

#ifdef HAS_H235_MEDIA
bool RTPLogicalChannel::CreateH235Session(H235Authenticators & auth, const H245_EncryptionSync & encryptionSync, bool encrypting)
{
	PWaitAndSignal lock(m_cryptoEngineMutex);
	m_auth = &auth;
	m_encrypting = encrypting;

	PString algorithmOID;
	PBYTEArray sessionKey;
	for (PINDEX i = 0; i < auth.GetSize(); i++) {
        if (auth[i].GetApplication() == H235Authenticator::MediaEncryption)  {
            auth[i].GetMediaSessionInfo(algorithmOID, sessionKey);
        }
    }
	if (algorithmOID.IsEmpty() || sessionKey.GetSize() == 0) {
		PTRACE(1, "H235\tError: GetMediaSessionInfo() failed");
		SNMP_TRAP(10, SNMPError, Authentication, "H.235.6 failure");
		return false;
	}

	// using the n least significant bits of the shared secret to encode the media keys
	// H.235.6 clause 7.6.1
	PBYTEArray shortSessionKey;
	shortSessionKey.SetSize(AlgorithmKeySize(algorithmOID));
	memcpy(shortSessionKey.GetPointer(), sessionKey.GetPointer() + sessionKey.GetSize() - shortSessionKey.GetSize(), shortSessionKey.GetSize());

	// use session key to decrypt the media key
	H235CryptoEngine H235Session(algorithmOID, shortSessionKey);

	m_cipherPayloadType = encryptionSync.m_synchFlag;
	PBYTEArray mediaKey;
	H235_H235Key h235key;
    encryptionSync.m_h235Key.DecodeSubType(h235key);
    if (h235key.GetTag() == H235_H235Key::e_secureSharedSecret) {
		const H235_V3KeySyncMaterial & v3data = h235key;
	    PTRACE(5, "H235\tH235_V3KeySyncMaterial=" << v3data);
	    if (v3data.HasOptionalField(H235_V3KeySyncMaterial::e_algorithmOID)
			&& (v3data.m_algorithmOID != algorithmOID)) {
		    PTRACE(1, "H235\tError: Different algo for session and media key not supported " << v3data);
			SNMP_TRAP(10, SNMPError, Authentication, "H.235.6 failure: different algo for session and media key");
		    return false;
	    }
	    if (v3data.m_paramS.HasOptionalField(H235_Params::e_iv)
			|| v3data.m_paramS.HasOptionalField(H235_Params::e_iv16)) {
		    PTRACE(1, "H235\tError: non-empty IV not supported, yet " << v3data);
			SNMP_TRAP(10, SNMPError, Authentication, "H.235.6 failure: non-empty IV");
		    return false;
		}
		if (v3data.HasOptionalField(H235_V3KeySyncMaterial::e_encryptedSessionKey)) {
			// this is the _media_key_ to be decrypted with the session key
			bool rtpPadding = false;
			mediaKey = H235Session.Decrypt(v3data.m_encryptedSessionKey, NULL, rtpPadding);
		} else {
		    PTRACE(1, "H235\tError: unsupported media key type: " << v3data);
			SNMP_TRAP(10, SNMPError, Authentication, "H.235.6 failure: unsupported media key type");
		}
	} else if (h235key.GetTag() == H235_H235Key::e_secureChannel) {
		// this is the _media_key_ in unencrypted form
		const H235_KeyMaterial & mediaKeyBits = h235key;
		PTRACE(3, "H235\tPlain key size=" << mediaKeyBits.GetSize() << " data=" << mediaKeyBits);
		mediaKey = PBYTEArray(mediaKeyBits.GetDataPointer(), mediaKeyBits.GetSize());
	} else {
		PTRACE(1, "H235\tUnsupported key type " << h235key.GetTagName());
		SNMP_TRAP(10, SNMPError, Authentication, "H.235.6 failure: unsupported key type");
		return false;
	}

	PTRACE(3, "H235\tMedia key decoded:" << endl << hex << mediaKey);
	if (mediaKey.GetSize() == 0) {
		PTRACE(1, "H235\tMedia key decode failed");
		SNMP_TRAP(10, SNMPError, Authentication, "H.235.6 failure: unable to decode media key");
		return false;
	}

	// delete old crypto engine (if we are called from UpdateMediaKey()
	if (m_H235CryptoEngine)
		delete m_H235CryptoEngine;
	// new session with media key after shared key was used to decrypt media key
	m_H235CryptoEngine = new H235CryptoEngine(algorithmOID, mediaKey);
	PTRACE(3, "H235\tNew crypto engine created: plainPT=" << (int)m_plainPayloadType << " cipherPT=" << (int)m_cipherPayloadType << " rtplc=" << this << " encrypt=" << m_encrypting);

	if (encrypting) {
		rtp->SetEncryptingRTPChannel(this);
	} else {
		rtp->SetDecryptingRTPChannel(this);
	}
	return true;
}

bool RTPLogicalChannel::CreateH235SessionAndKey(H235Authenticators & auth, H245_EncryptionSync & encryptionSync, bool encrypting)
{
	PWaitAndSignal lock(m_cryptoEngineMutex);
	m_auth = &auth;
	m_encrypting = encrypting;

	PString algorithmOID;
	PBYTEArray sessionKey;
	for (PINDEX i = 0; i < auth.GetSize(); i++) {
        if (auth[i].GetApplication() == H235Authenticator::MediaEncryption)  {
            auth[i].GetMediaSessionInfo(algorithmOID, sessionKey);
        }
    }
	if (algorithmOID.IsEmpty() || sessionKey.GetSize() == 0) {
		PTRACE(1, "H235\tError: GetMediaSessionInfo() failed");
		SNMP_TRAP(10, SNMPError, Authentication, "H.235.6 failure");
		return false;
	}

	// using the 128 least significant bits of the shared secret to encode the media keys
	// H.235.6 clause 7.6.1
	PBYTEArray shortSessionKey;
	shortSessionKey.SetSize(AlgorithmKeySize(algorithmOID));
	memcpy(shortSessionKey.GetPointer(), sessionKey.GetPointer() + sessionKey.GetSize() - shortSessionKey.GetSize(), shortSessionKey.GetSize());

	// use session key to decrypt the media key
	H235CryptoEngine H235Session(algorithmOID, shortSessionKey);

	// generate media key
	PBYTEArray mediaKey = H235Session.GenerateRandomKey(algorithmOID);
	PTRACE(3, "H235\tMedia key generated:" << endl << hex << mediaKey);

	encryptionSync.m_synchFlag = m_cipherPayloadType;
	H235_H235Key h235key;
	h235key.SetTag(H235_H235Key::e_secureSharedSecret);
	H235_V3KeySyncMaterial & v3data = h235key;
	v3data.IncludeOptionalField(H235_V3KeySyncMaterial::e_algorithmOID);
	v3data.m_algorithmOID = algorithmOID;
	v3data.IncludeOptionalField(H235_V3KeySyncMaterial::e_encryptedSessionKey);
	// encrypt media key with session key (shared secret)
	bool rtpPadding = false;
	v3data.m_encryptedSessionKey = H235Session.Encrypt(mediaKey, NULL, rtpPadding);
	encryptionSync.m_h235Key.EncodeSubType(h235key);

	// delete old crypto engine (if we are called from UpdateMediaKey()
	if (m_H235CryptoEngine)
		delete m_H235CryptoEngine;
	// new session with media key after shared key was used to encrypt media key for transmission
	m_H235CryptoEngine = new H235CryptoEngine(algorithmOID, mediaKey);
	PTRACE(3, "H235\tNew crypto engine created: plainPT=" << (int)m_plainPayloadType << " cipherPT=" << (int)m_cipherPayloadType << " rtplc=" << this << " encrypt=" << m_encrypting);

	if (encrypting) {
		rtp->SetEncryptingRTPChannel(this);
	} else {
		rtp->SetDecryptingRTPChannel(this);
	}
	return true;
}

bool RTPLogicalChannel::UpdateMediaKey(const H245_EncryptionSync & encryptionSync)
{
	if (!m_auth || !m_H235CryptoEngine) {
		PTRACE(1, "H235\tError: H.235 media key update before session initialization");
		SNMP_TRAP(10, SNMPError, Authentication, "H.235.6 key update failure");
		return false;
	}
	return CreateH235Session(*m_auth, encryptionSync, m_encrypting);
}

bool RTPLogicalChannel::GenerateNewMediaKey(BYTE newPayloadType, H245_EncryptionSync & encryptionSync)
{
	if (!m_auth || !m_H235CryptoEngine) {
		PTRACE(1, "H235\tError: H.235 media key update before session initialization");
		SNMP_TRAP(10, SNMPError, Authentication, "H.235.6 key update before session initialization");
		return false;
	}
	SetCipherPayloadType(newPayloadType);
	return CreateH235SessionAndKey(*m_auth, encryptionSync, m_encrypting);
}

bool RTPLogicalChannel::ProcessH235Media(BYTE * buffer, WORD & len, bool encrypt, unsigned char * ivsequence, bool & rtpPadding, BYTE & payloadType)
{
	PWaitAndSignal lock(m_cryptoEngineMutex);
	if (!m_H235CryptoEngine)
		return false;

	unsigned rtpHeaderLen = 12;	// TODO: skip more if header has CSRC or extensions
	PBYTEArray data(buffer+rtpHeaderLen, len-rtpHeaderLen);	// skip RTP header
	PBYTEArray processed;

	if (encrypt) {
		if (payloadType == m_plainPayloadType) {
			processed = m_H235CryptoEngine->Encrypt(data, ivsequence, rtpPadding);
		} else {
			PTRACE(1, "H235\tUnexpected plaintext payload type " << (int)payloadType << " expecting " << (int)m_plainPayloadType);
			SNMP_TRAP(10, SNMPWarning, Authentication, "H.235.6 payload type mismatch");
		}
		payloadType = m_cipherPayloadType;
	} else {
		if (payloadType == m_cipherPayloadType) {
			processed = m_H235CryptoEngine->Decrypt(data, ivsequence, rtpPadding);
		} else {
			PTRACE(1, "H235\tUnexpected chipher payload type " << (int)payloadType << " expecting " << (int)m_cipherPayloadType);
			SNMP_TRAP(10, SNMPWarning, Authentication, "H.235.6 payload type mismatch");
		}
		payloadType = m_plainPayloadType;
	}

	// check max buffer size
	len = processed.GetSize() + rtpHeaderLen;
	if (len > DEFAULT_PACKET_BUFFER_SIZE) {
		PTRACE(1, "H235\tRTP packet too large, truncating");
		len = DEFAULT_PACKET_BUFFER_SIZE;
		processed.SetSize(DEFAULT_PACKET_BUFFER_SIZE - rtpHeaderLen);
	}
	memcpy(buffer + rtpHeaderLen, processed.GetPointer(), processed.GetSize());
#if (H323PLUS_VER > 1252)
	if (Toolkit::Instance()->IsH235HalfCallMediaKeyUpdatesEnabled()) {
		// major endpoints seem to ignore the key updates, thus the switch
		if (m_H235CryptoEngine->IsMaxBlocksPerKeyReached()) {
			m_H235CryptoEngine->ResetBlockCount(); // reset count now, so we don't request update multiple times
			PTRACE(1, "H.235.6 media key update needed flcn=" << channelNumber);
			// find call by CallID, send key update command or request
			callptr call = CallTable::Instance()->FindCallRec(m_callID);
			if (call) {
				CallSignalSocket * dest = call->GetCallSignalSocketCalling();
				if (call->GetEncryptDirection() == CallRec::callingParty) {
					dest = call->GetCallSignalSocketCalled();
				}
				if (dest->IsH245Master()) {
					dest->SendEncryptionUpdateRequest(channelNumber, m_cipherPayloadType, m_plainPayloadType);
				} else {
					dest->SendEncryptionUpdateCommand(channelNumber, m_cipherPayloadType, m_plainPayloadType);
				}
			} else {
				PTRACE(1, "H235\tError: Can't find call to request media key update");
			}
		}
	}
#endif
	return (processed.GetSize() > 0);
}
#endif // HAS_H235_MEDIA

void RTPLogicalChannel::GetRTPPorts(PIPSocket::Address & fSrcIP, PIPSocket::Address & fDestIP, PIPSocket::Address & rSrcIP, PIPSocket::Address & rDestIP,
                                    WORD & fSrcPort, WORD & dDestPort, WORD & rSrcPort, WORD & rDestPort) const
{
    fSrcPort = dDestPort = rSrcPort = rDestPort = 0;
    if (rtp) {
        rtp->GetPorts(fSrcIP, fDestIP, rSrcIP, rDestIP, fSrcPort, dDestPort, rSrcPort, rDestPort);
    }
}

bool RTPLogicalChannel::IsRTPInactive() const
{
    return (rtp && rtp->IsRTPInactive());
}

void RTPLogicalChannel::SetRTPSessionID(WORD id)
{
	if (rtp)
		rtp->SetRTPSessionID(id);
	if (rtcp)
		rtcp->SetRTPSessionID(id);
}

void RTPLogicalChannel::SetMediaControlChannelSource(const H245_UnicastAddress & addr)
{
	addr >> SrcIP >> SrcPort;
	--SrcPort; // get the RTP port
}

void RTPLogicalChannel::ZeroMediaControlChannelSource()
{
	SrcIP = 0;
	SrcPort = 0;
}

void RTPLogicalChannel::SetMediaChannelSource(const H245_UnicastAddress & addr)
{
	addr >> SrcIP >> SrcPort;
}

void RTPLogicalChannel::ZeroMediaChannelSource()
{
	SrcIP = 0;
	SrcPort = 0;
}

// called on OLCAck
void RTPLogicalChannel::HandleMediaChannel(H245_UnicastAddress * mediaControlChannel, H245_UnicastAddress * mediaChannel, const PIPSocket::Address & local, bool rev, callptr & call, bool fromTraversalClient, bool useRTPMultiplexing, bool isUnidirectional)
{
    PTRACE(7, "JW RTP HandleMediaChannel: fromTraversalClient=" << fromTraversalClient << " isUnidirectional=" << isUnidirectional << " m_ignoreSignaledIPs=" << m_ignoreSignaledIPs);
	H245_UnicastAddress tmp, tmpmedia, tmpmediacontrol, *dest = mediaControlChannel;
	PIPSocket::Address tmpSrcIP = SrcIP;
	WORD tmpSrcPort = SrcPort + 1;
    bool zeroIP = m_ignoreSignaledIPs && !fromTraversalClient && !isUnidirectional;

	if (mediaControlChannel == NULL) {
		if (mediaChannel == NULL) {
			return;
		} else {
			// set mediaControlChannel if we have a mediaChannel
			tmpmediacontrol = *mediaChannel;
			if (useRTPMultiplexing) {
				// set mediaControlChannel to multiplexed port, LifeSize seems to use that instead of multiplexed port in TraversalParameters
				SetH245Port(tmpmediacontrol, (WORD)GkConfig()->GetInteger(ProxySection, "RTCPMultiplexPort", GK_DEF_MULTIPLEX_RTCP_PORT));
			} else {
				SetH245Port(tmpmediacontrol, GetH245Port(tmpmediacontrol) + 1);
			}
			mediaControlChannel = &tmpmediacontrol;
			dest = mediaControlChannel;
		}
	}

	if (rev) { // from a reverseLogicalChannelParameters
		tmp << tmpSrcIP << tmpSrcPort;
		dest = &tmp;
		*mediaControlChannel >> tmpSrcIP >> tmpSrcPort;
		if (!mediaChannel) {
			tmpmedia = *mediaControlChannel;
			if (useRTPMultiplexing) {
				// set mediaChannel to multiplexed port, LifeSize seems to use that instead of multiplexed port in TraversalParameters
				SetH245Port(tmpmedia, (WORD)GkConfig()->GetInteger(ProxySection, "RTPMultiplexPort", GK_DEF_MULTIPLEX_RTP_PORT));
			} else {
				if (GetH245Port(tmpmedia) > 0)
					SetH245Port(tmpmedia, GetH245Port(tmpmedia) - 1);
			}
			mediaChannel = &tmpmedia;
		}
	}
	UDPProxySocket::pMem SetDest = (reversed) ? &UDPProxySocket::SetReverseDestination : &UDPProxySocket::SetForwardDestination;
	(rtcp->*SetDest)(tmpSrcIP, tmpSrcPort, dest, call);
#ifdef HAS_H46018
	if (fromTraversalClient) {
		PTRACE(5, "H46018\tSetting control channel destination to 0");
		(rtcp->*SetDest)(tmpSrcIP, tmpSrcPort, NULL, call);
	}
#endif

    PIPSocket::Address ip = H245UnicastToSocketAddr(*dest);
    if (isUnidirectional) {
        if (m_ignoreSignaledIPs && !fromTraversalClient && isUnidirectional && IsPrivate(ip) && m_ignoreSignaledPrivateH239IPs) {
            zeroIP = true;
        }
        if (IsInNetworks(ip, m_keepSignaledIPs)) {
            zeroIP = false;
        }
        if (zeroIP) {
            PTRACE(7, "JW RTP IN zero RTCP src + dest (IgnoreSignaledIPs)");
            (rtcp->*SetDest)(0, 0, NULL, call);
        } else if (m_ignoreSignaledIPs && !fromTraversalClient && isUnidirectional && IsPrivate(tmpSrcIP) && m_ignoreSignaledPrivateH239IPs && !IsInNetworks(tmpSrcIP, m_keepSignaledIPs)) {
            // only zero out source IP
            PTRACE(7, "JW RTP IN zero RTCP src (IgnoreSignaledIPs && IgnoreSignaledPrivateH239IPs)");
            (rtcp->*SetDest)(0, 0, dest, call);
        }
    }

	if (useRTPMultiplexing) {
		*mediaControlChannel << local << (WORD)GkConfig()->GetInteger(ProxySection, "RTCPMultiplexPort", GK_DEF_MULTIPLEX_RTCP_PORT);
	} else {
		*mediaControlChannel << local << (port + 1);
	}

	if (mediaChannel) {
		if (rev) {
			if (GetH245Port(tmp) > 0)
				SetH245Port(tmp, GetH245Port(tmp) - 1);
		} else {
			dest = mediaChannel;
		}
		if (tmpSrcPort > 0)
			tmpSrcPort -= 1;
		if (useRTPMultiplexing)
			tmpSrcPort = (WORD)GkConfig()->GetInteger(ProxySection, "RTPMultiplexPort", GK_DEF_MULTIPLEX_RTP_PORT);
		(rtp->*SetDest)(tmpSrcIP, tmpSrcPort, dest, call);
#ifdef HAS_H46018
		if (fromTraversalClient) {
			PTRACE(5, "H46018\tSetting media channel destination to 0");
			(rtp->*SetDest)(tmpSrcIP, tmpSrcPort, NULL, call);
		}
#endif

        PIPSocket::Address ip = H245UnicastToSocketAddr(*dest);
        if (isUnidirectional) {
            // TODO: check if we should default zeroIP to false, before we do these checks
            if (m_ignoreSignaledIPs && !fromTraversalClient && isUnidirectional && IsPrivate(ip) && m_ignoreSignaledPrivateH239IPs) {
                zeroIP = true;
            }
            if (IsInNetworks(ip, m_keepSignaledIPs)) {
                zeroIP = false;
            }
            if (zeroIP) {
                PTRACE(7, "JW RTP IN zero RTP src + dest (IgnoreSignaledIPs)");
                (rtp->*SetDest)(0, 0, NULL, call);
            } else if (m_ignoreSignaledIPs && !fromTraversalClient && isUnidirectional && IsPrivate(tmpSrcIP) && m_ignoreSignaledPrivateH239IPs && !IsInNetworks(tmpSrcIP, m_keepSignaledIPs)) {
                // only zero out source IP
                PTRACE(7, "JW RTP IN zero RTP src (IgnoreSignaledIPs && IgnoreSignaledPrivateH239IPs)");
                (rtp->*SetDest)(0, 0, dest, call);
            }
        }

		if (useRTPMultiplexing) {
			*mediaChannel << local << (WORD)GkConfig()->GetInteger(ProxySection, "RTPMultiplexPort", GK_DEF_MULTIPLEX_RTP_PORT);
		} else {
			*mediaChannel << local << port;
		}
	}

#ifdef HAS_H46018
	if (m_ignoreSignaledIPs) {
        bool zeroNow = false;
        bool forwardAndReverseSeen = false;
        PIPSocket::Address fSrcIP, fDestIP, rSrcIP, rDestIP;
        WORD fSrcPort, fDestPort, rSrcPort, rDestPort;
        GetRTPPorts(fSrcIP, fDestIP, rSrcIP, rDestIP, fSrcPort, fDestPort, rSrcPort, rDestPort);
        PTRACE(7, "JW RTP IPs: fSrcIP=" << AsString(fSrcIP) << " fDestIP=" << AsString(fDestIP) << " rSrcIP=" << AsString(rSrcIP) << " rDestIP=" << AsString(rDestIP));
        PTRACE(7, "JW RTP ports: fSrcPort=" << fSrcPort << " fDestPort=" << fDestPort << " rSrcPort=" << rSrcPort << " rDestPort=" << rDestPort);
        if (call && call->GetCalledParty() && call->GetCalledParty()->GetTraversalRole() != None && ( (fDestPort > 0 && rSrcPort > 0) || (fSrcPort > 0 && rDestPort > 0) ) ) {
            // TODO: should this really happen for unidirectional channels ?
            if ((fSrcPort > 0 && fSrcPort == rDestPort) || (rSrcPort > 0 && rSrcPort == fDestPort)) { /* TODO: IP check ? */
                PTRACE(7, "JW RTP zero to traversal");
                zeroNow = true;
            } else {
                PTRACE(5, "RTP\tNon-symmetric port usage, disable auto-detect");
                call->SetIgnoreSignaledIPs(false);
            }
            forwardAndReverseSeen = true;
        } else {
            if (fSrcPort > 0 && fDestPort > 0 && rSrcPort > 0 && rDestPort > 0 && !isUnidirectional) {
                if (IsInNetworks(fSrcIP, m_keepSignaledIPs) || IsInNetworks(fDestIP, m_keepSignaledIPs) || IsInNetworks(rSrcIP, m_keepSignaledIPs) || IsInNetworks(rDestIP, m_keepSignaledIPs)) {
                    // assume symmetric port usage if one side is set to allowed IPs
                    PTRACE(7, "JW RTP zero with any AllowedIP");
                    zeroNow = true;
                } else if ((fSrcPort == rDestPort) && (rSrcPort == fDestPort)) { /* TODO: && fSrcIP == rDestIP && fDestIP == rSrcIP */
                    PTRACE(7, "JW RTP zero normal");
                    // the regular case
                    zeroNow = true;
                } else {
                	PTRACE(5, "RTP\tNon-symetric port usage, disable auto-detect");
                    call->SetIgnoreSignaledIPs(false);
                }
                forwardAndReverseSeen = true;
            }
        }
        if (zeroNow) {
            PTRACE(7, "JW RTP IN zero RTP src + dest (IgnoreSignaledIPs)");
            rtp->ZeroAllIPs();
            rtcp->ZeroAllIPs();
        }
        if (forwardAndReverseSeen) {
            rtp->ForwardAndReverseSeen();
            rtcp->ForwardAndReverseSeen();
        }
   }
#endif

}

void RTPLogicalChannel::SetRTPMute(bool toMute)
{
	if (rtp)
		rtp->SetMute(toMute);
}

bool RTPLogicalChannel::OnLogicalChannelParameters(H245_H2250LogicalChannelParameters & h225Params, const PIPSocket::Address & local, bool rev, callptr & call, bool fromTraversalClient, bool useRTPMultiplexing, bool isUnidirectional)
{
	m_isUnidirectional = isUnidirectional;  // remember for handling OLCAck
	if (!h225Params.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel))
		return false;
	H245_UnicastAddress *mediaControlChannel = GetH245UnicastAddress(h225Params.m_mediaControlChannel);
	H245_UnicastAddress *mediaChannel = h225Params.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel) ? GetH245UnicastAddress(h225Params.m_mediaChannel) : NULL;
	HandleMediaChannel(mediaControlChannel, mediaChannel, local, rev, call, fromTraversalClient, useRTPMultiplexing, isUnidirectional);
	return true;
}

bool RTPLogicalChannel::SetDestination(H245_OpenLogicalChannelAck & olca, H245Handler * handler, callptr & call, bool fromTraversalClient, bool useRTPMultiplexing)
{
	H245_UnicastAddress * mediaControlChannel = NULL;
	H245_UnicastAddress * mediaChannel = NULL;
	GetChannelsFromOLCA(olca, mediaControlChannel, mediaChannel);
	if (mediaControlChannel == NULL && mediaChannel == NULL) {
		return false;
	}
	HandleMediaChannel(mediaControlChannel, mediaChannel, handler->GetMasqAddr(), false, call, fromTraversalClient, useRTPMultiplexing, m_isUnidirectional);
	return true;
}

void RTPLogicalChannel::StartReading(ProxyHandler * /*handler*/)
{
	if (!used) {
		RasServer::Instance()->GetRtpProxyHandler()->Insert(rtp, rtcp);
		used = true;
		if (peer)
			peer->used = true;
	}
}

void RTPLogicalChannel::OnHandlerSwapped(bool nated)
{
	rtp->OnHandlerSwapped();
	rtcp->OnHandlerSwapped();
	SetNAT(nated);
}

void RTPLogicalChannel::SetNAT(bool nated)
{
    PTRACE(7, "JW RTP RTPLogicalChannel::SetNAT() nated=" << nated);
	if (nated) {
		if (rtp)
			rtp->SetNAT(reversed);
		if (rtcp)
			rtcp->SetNAT(reversed);
	}
}

WORD RTPLogicalChannel::GetPortNumber()
{
	WORD port = RTPPortRange.GetPort();
	if (port & 1) // make sure it is even
		port = RTPPortRange.GetPort();
	RTPPortRange.GetPort(); // skip odd port
	return port;
}


// class T120LogicalChannel
T120LogicalChannel::T120LogicalChannel(WORD flcn) : LogicalChannel(flcn)
{
	handler = NULL;
	listener = new T120Listener(this);
	port = listener->GetPort();
	peerPort = 0;
	if (listener->IsOpen())
		PTRACE(4, "T120\tOpen logical channel " << flcn << " port " << port);
	else {
		PTRACE(4, "T120\tFailed to open logical channel " << flcn << " port " << port);
		SNMP_TRAP(10, SNMPError, Network, "T.120 failed");
	}
}

T120LogicalChannel::~T120LogicalChannel()
{
	if (Toolkit::Instance()->IsPortNotificationActive() && listener)
		Toolkit::Instance()->PortNotification(T120Port, PortClose, "udp", GNUGK_INADDR_ANY, listener->GetPort());

	if (used) {
		RasServer::Instance()->CloseListener(listener);
		ForEachInContainer(sockets, mem_vfun(&T120ProxySocket::SetDeletable));
	} else {
		delete listener;
		listener = NULL;
	}
	PTRACE(4, "T120\tDelete logical channel " << channelNumber);
}

bool T120LogicalChannel::SetDestination(H245_OpenLogicalChannelAck & olca, H245Handler * _handler, callptr & /*call*/, bool /*fromTraversalClient*/, bool /*useRTPMultiplexing*/)
{
	return (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_separateStack)) ?
		OnSeparateStack(olca.m_separateStack, _handler) : false;
}

void T120LogicalChannel::StartReading(ProxyHandler * h)
{
	if (!used) {
		used = true;
		handler = h;
		RasServer::Instance()->AddListener(listener);
	}
}

T120LogicalChannel::T120Listener::T120Listener(T120LogicalChannel *lc) : t120lc(lc)
{
	int numPorts = min(T120PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = T120PortRange.GetPort();
		SetName("T120:" + PString(pt));
		if (Listen(5, pt, PSocket::CanReuseAddress)) {
			if (Toolkit::Instance()->IsPortNotificationActive())
				Toolkit::Instance()->PortNotification(T120Port, PortOpen, "udp", GNUGK_INADDR_ANY, pt);
			break;
		}
		int errorNumber = GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, GetName() << "Could not open listening T.120 socket at " << AsString(GNUGK_INADDR_ANY, pt)
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << GetErrorText(PSocket::LastGeneralError)
			);
		Close();
	}
}

ServerSocket *T120LogicalChannel::T120Listener::CreateAcceptor() const
{
	return new T120ProxySocket(t120lc);
}

void T120LogicalChannel::Create(T120ProxySocket *socket)
{
	T120ProxySocket * remote = new T120ProxySocket(socket, peerPort);
	int numPorts = min(T120PortRange.GetNumPorts(), DEFAULT_NUM_SEQ_PORTS);
	for (int i = 0; i < numPorts; ++i) {
		WORD pt = T120PortRange.GetPort();
		if (remote->Connect(GNUGK_INADDR_ANY, pt, peerAddr)) {
			PTRACE(3, "T120\tConnect to " << remote->GetName()
				<< " from " << AsString(GNUGK_INADDR_ANY, pt) << " successful");
			socket->SetConnected(true);
			remote->SetConnected(true);
			handler->Insert(socket, remote);
			PWaitAndSignal lock(m_smutex);
			sockets.push_back(socket);
			sockets.push_back(remote);
			return;
		}
		int errorNumber = remote->GetErrorNumber(PSocket::LastGeneralError);
		PTRACE(1, remote->Type() << "\tCould not open/connect T.120 socket at " << AsString(GNUGK_INADDR_ANY, pt)
			<< " - error " << remote->GetErrorCode(PSocket::LastGeneralError) << '/'
			<< errorNumber << ": " << remote->GetErrorText(PSocket::LastGeneralError));
		remote->Close();
		PTRACE(3, "T120\t" << AsString(peerAddr, peerPort) << " DIDN'T ACCEPT THE CALL");
	}
	delete remote;
	remote = NULL;
	delete socket;
	socket = NULL;
}

bool T120LogicalChannel::OnSeparateStack(H245_NetworkAccessParameters & sepStack, H245Handler * _handler)
{
	bool changed = false;
	if (sepStack.m_networkAddress.GetTag() == H245_NetworkAccessParameters_networkAddress::e_localAreaAddress) {
		H245_UnicastAddress *addr = GetH245UnicastAddress(sepStack.m_networkAddress);
		if (addr) {
			*addr >> peerAddr >> peerPort;
			*addr << _handler->GetMasqAddr() << port;
			changed = true;
		}
	}
	return changed;
}


// class H245ProxyHandler
H245ProxyHandler::H245ProxyHandler(const H225_CallIdentifier & id, const PIPSocket::Address & local, const PIPSocket::Address & remote, const PIPSocket::Address & masq, H245ProxyHandler * pr)
      : H245Handler(local, remote, masq), handler(NULL), peer(pr), callid(id), isMute(false), m_useH46019(false), m_traversalType(None),
		m_useH46019fc(false), m_H46019fcState(0), m_H46019dir(0), m_usesH46026(false)
{
	if (peer)
		peer->peer = this;

    m_ignoreSignaledIPs = false;
    m_ignoreSignaledPrivateH239IPs = false;
#ifdef HAS_H46018
    callptr call = CallTable::Instance()->FindCallRec(callid);
    if (call) {
        m_ignoreSignaledIPs = call->IgnoreSignaledIPs();
        if (m_ignoreSignaledIPs) {
            if (call && call->GetCallingParty() && call->GetCallingParty()->GetTraversalRole() != None) {
                // disable, when caller has NAT traversal enabled (call isn't from an party that needs NAT help)
                m_ignoreSignaledIPs = false;
                call->SetIgnoreSignaledIPs(false);
            } else {
                m_ignoreSignaledPrivateH239IPs = GkConfig()->GetBoolean(ProxySection, "IgnoreSignaledPrivateH239IPs", false);
            }
        }
    }
	m_isRTPMultiplexingEnabled = Toolkit::Instance()->IsH46018Enabled()
								&& GkConfig()->GetBoolean(ProxySection, "RTPMultiplexing", false);
#else
	m_isRTPMultiplexingEnabled = false;
#endif
	m_requestRTPMultiplexing = false;	// only enable in SetRequestRTPMultiplexing() if endpoint supports it
	m_remoteRequestsRTPMultiplexing = false;	// set when receiving the multiplexID
	m_multiplexedRTPPort = (WORD)GkConfig()->GetInteger(ProxySection, "RTPMultiplexPort", GK_DEF_MULTIPLEX_RTP_PORT);
	m_multiplexedRTCPPort = (WORD)GkConfig()->GetInteger(ProxySection, "RTCPMultiplexPort", GK_DEF_MULTIPLEX_RTCP_PORT);
#ifdef HAS_H235_MEDIA
	m_isCaller = false;
#endif
	m_isH245Master = false;
}

H245ProxyHandler::~H245ProxyHandler()
{
	// TODO: H.460.19 fastStart handling doesn't seem right and creates a leak
	if (peer) {
		if (peer->UsesH46019fc())
			return;
		peer->peer = NULL;
	}
	if (UsesH46019fc())
		return;

	DeleteObjectsInMap(logicalChannels);
	DeleteObjectsInMap(fastStartLCs);
}

bool H245ProxyHandler::HandleRequest(H245_RequestMessage & Request, callptr & call)
{
	PTRACE(4, "H245\tRequest: " << Request.GetTagName());
	if (peer)
		switch (Request.GetTag())
		{
			case H245_RequestMessage::e_openLogicalChannel:
				return HandleOpenLogicalChannel(Request, call);
			case H245_RequestMessage::e_closeLogicalChannel:
				return HandleCloseLogicalChannel(Request, call);
			default:
				break;
		}
	return false;
}

bool H245ProxyHandler::HandleResponse(H245_ResponseMessage & Response, callptr & call)
{
	PTRACE(4, "H245\tResponse: " << Response.GetTagName());
	if (peer)
		switch (Response.GetTag())
		{
			case H245_ResponseMessage::e_openLogicalChannelAck:
				return HandleOpenLogicalChannelAck(Response, call);
			case H245_ResponseMessage::e_openLogicalChannelReject:
				return HandleOpenLogicalChannelReject(Response, call);
			default:
				break;
		}
	return false;
}

bool H245ProxyHandler::HandleCommand(H245_CommandMessage & Command, bool & suppress, callptr & call, H245Socket * h245sock)
{
	PTRACE(4, "H245\tCommand: " << Command.GetTagName());

	unsigned filterFastUpdatePeriod = GkConfig()->GetInteger(RoutedSec, "FilterVideoFastUpdatePicture", 0);
	if (filterFastUpdatePeriod > 0 && Command.GetTag() == H245_CommandMessage::e_miscellaneousCommand) {
		H245_MiscellaneousCommand miscCommand = Command;
        if (miscCommand.m_type.GetTag() == H245_MiscellaneousCommand_type::e_videoFastUpdatePicture) {
            PTime now;
            if (now - m_lastVideoFastUpdatePicture > PTimeInterval(0, filterFastUpdatePeriod)) {
                m_lastVideoFastUpdatePicture = now;
                PTRACE(3, "H245\tAllow VideoFastUpdatePicture");
            } else {
                suppress = true;
                PTRACE(3, "H245\tFiltering out VideoFastUpdatePicture");
            }
		}
	}

#ifdef HAS_H235_MEDIA
	if (peer) {
		switch (Command.GetTag())
		{
			case H245_CommandMessage::e_miscellaneousCommand:
			{
				H245_MiscellaneousCommand miscCommand = Command;
				switch (miscCommand.m_type.GetTag())
				{
					case H245_MiscellaneousCommand_type::e_encryptionUpdateRequest:
						return HandleEncryptionUpdateRequest(Command, suppress, call, h245sock);
					case H245_MiscellaneousCommand_type::e_encryptionUpdateCommand:
						return HandleEncryptionUpdateCommand(Command, suppress, call, h245sock);
					case H245_MiscellaneousCommand_type::e_encryptionUpdateAck:
						return HandleEncryptionUpdateAck(Command, suppress, call, h245sock);
					default:
						break;
				}
			}
			default:
				break;
		}
	}
#endif
	return false;
}

// called on OLC
bool H245ProxyHandler::OnLogicalChannelParameters(H245_H2250LogicalChannelParameters * h225Params, WORD flcn, bool isUnidirectional, RTPSessionTypes sessionType)
{
	RTPLogicalChannel * lc = flcn ?
		CreateRTPLogicalChannel((WORD)h225Params->m_sessionID, flcn, sessionType) :
		CreateFastStartLogicalChannel((WORD)h225Params->m_sessionID, sessionType);
	if (!lc)
		return false;

    lc->SetUniDirectional(isUnidirectional);  // remember for handling OLCAck

#ifdef HAS_H46018
	if (IsTraversalServer() || IsTraversalClient()) {
		lc->SetUsesH46019();
	}
#endif
	lc->SetRTPSessionID((WORD)h225Params->m_sessionID);

	H245_UnicastAddress * addr = NULL;
	bool changed = false;
    bool zeroIP = m_ignoreSignaledIPs && !isUnidirectional;

	if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel)
		&& (addr = GetH245UnicastAddress(h225Params->m_mediaControlChannel)) ) {

		lc->SetMediaControlChannelSource(*addr);
		*addr << GetMasqAddr() << (lc->GetPort() + 1);
#ifdef HAS_H46018
		if (IsTraversalClient()) {
			PTRACE(5, "H46018\tSetting control channel to 0");
			lc->ZeroMediaControlChannelSource();
		}
#endif
        PIPSocket::Address ip = H245UnicastToSocketAddr(*addr);
        if (isUnidirectional) {
            if (m_ignoreSignaledIPs && isUnidirectional && IsPrivate(ip) && m_ignoreSignaledPrivateH239IPs) {
                zeroIP = true;
            }
            if (IsInNetworks(ip, m_keepSignaledIPs)) {
                zeroIP = false;
            }
            if (zeroIP) {
                lc->ZeroMediaControlChannelSource();
            }
        }
		changed = true;
	}
	if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)
		&& (addr = GetH245UnicastAddress(h225Params->m_mediaChannel))) {

		if (GetH245Port(*addr) != 0) {
			lc->SetMediaChannelSource(*addr);
			*addr << GetMasqAddr() << lc->GetPort();
#ifdef HAS_H46018
			if (IsTraversalClient()) {
				PTRACE(5, "H46018\tSetting media channel to 0");
				lc->ZeroMediaChannelSource();
			}
#endif
        PIPSocket::Address ip = H245UnicastToSocketAddr(*addr);
        if (m_ignoreSignaledIPs && isUnidirectional && IsPrivate(ip) && m_ignoreSignaledPrivateH239IPs) {
            zeroIP = true;
        }
        if (IsInNetworks(ip, m_keepSignaledIPs)) {
            zeroIP = false;
        }
        if (zeroIP) {
				lc->ZeroMediaChannelSource();
            }
		} else {
			*addr << GetMasqAddr() << (WORD)0;
		}
		changed = true;
	}

	return changed;
}

#ifdef HAS_H46018
bool H245ProxyHandler::ParseTraversalParameters(
	/* in */
	const H245_GenericInformation & genericInfo,
	/* out */
	unsigned & payloadtype,
	H225_TransportAddress & keepAliveRTPAddr,
	unsigned & keepAliveInterval,
	H225_TransportAddress & multiplexedRTPAddr,
	H225_TransportAddress & multiplexedRTCPAddr,
	DWORD & multiplexID) const
{
	// get the keepalive information (if present)
	H46019_TraversalParameters params;
	PASN_OctetString & raw = genericInfo.m_messageContent[0].m_parameterValue;
	if (raw.DecodeSubType(params)) {
		PTRACE(5, "H46018\tReceived TraversalParameters = " << params);
		payloadtype = UNDEFINED_PAYLOAD_TYPE;
		multiplexID = INVALID_MULTIPLEX_ID;
		keepAliveInterval = 0;
		if (params.HasOptionalField(H46019_TraversalParameters::e_keepAlivePayloadType)) {
			payloadtype = params.m_keepAlivePayloadType;
			PTRACE(5, "H46018\tReceived KeepAlive PayloadType=" << payloadtype);
		}
		if (params.HasOptionalField(H46019_TraversalParameters::e_keepAliveChannel)) {
			keepAliveRTPAddr = H245ToH225TransportAddress(params.m_keepAliveChannel);
			PTRACE(5, "H46018\tReceived KeepAlive Channel=" << keepAliveRTPAddr);
		}
		if (params.HasOptionalField(H46019_TraversalParameters::e_keepAliveInterval)) {
			keepAliveInterval = params.m_keepAliveInterval;
			PTRACE(5, "H46018\tReceived KeepAlive Interval=" << keepAliveInterval);
		}
		if (params.HasOptionalField(H46019_TraversalParameters::e_multiplexedMediaChannel)) {
			multiplexedRTPAddr = H245ToH225TransportAddress(params.m_multiplexedMediaChannel);
			PTRACE(5, "H46018\tReceived multiplexed RTP Channel=" << multiplexedRTPAddr);
		}
		if (params.HasOptionalField(H46019_TraversalParameters::e_multiplexedMediaControlChannel)) {
			multiplexedRTCPAddr = H245ToH225TransportAddress(params.m_multiplexedMediaControlChannel);
			PTRACE(5, "H46018\tReceived multiplexed RTCP Channel=" << multiplexedRTCPAddr);
		}
		if (params.HasOptionalField(H46019_TraversalParameters::e_multiplexID)) {
			multiplexID = params.m_multiplexID;
			PTRACE(5, "H46018\tReceived multiplexID=" << multiplexID);
		}
		return true;
	} else {
		return false;
	}
}
#endif

void GetSessionType(const H245_OpenLogicalChannel & olc, RTPSessionTypes & sessionType, bool & isUnidirectional)
{
    sessionType = Unknown;
    isUnidirectional = false;
	if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_audioData) {
        sessionType = Audio;
    } else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_videoData) {
        sessionType = Video;
        const H245_VideoCapability & vid = olc.m_forwardLogicalChannelParameters.m_dataType;
        if (vid.GetTag() == H245_VideoCapability::e_extendedVideoCapability) {
            sessionType = Presentation;
            isUnidirectional = true;
        }
    } else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_data) {
        sessionType = Data;
    } else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_h235Media) {
        const H245_H235Media & h235data = olc.m_forwardLogicalChannelParameters.m_dataType;
        if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_audioData) {
            sessionType = Audio;
        } else if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_videoData) {
            sessionType = Video;
            const H245_VideoCapability & vid = h235data.m_mediaType;
            if (vid.GetTag() == H245_VideoCapability::e_extendedVideoCapability) {
                sessionType = Presentation;
                isUnidirectional = true;
            }
        } else if (h235data.m_mediaType.GetTag() == H245_H235Media_mediaType::e_data) {
            sessionType = Data;
        }
    } else if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_multiplePayloadStream) {
        const H245_MultiplePayloadStream & stream = olc.m_forwardLogicalChannelParameters.m_dataType;
        for (PINDEX e = 0; e < stream.m_elements.GetSize(); e++) {
            H245_MultiplePayloadStreamElement & element = stream.m_elements[e];
            if (element.m_dataType.GetTag() == H245_DataType::e_videoData) {
                const H245_VideoCapability & vid = element.m_dataType;
                if (vid.GetTag() == H245_VideoCapability::e_extendedVideoCapability) {
                    sessionType = Presentation;
                    isUnidirectional = true;
                }
            }
            // no else: leave other data types as Unknown
        }
    } else {
        PTRACE(1, "Warning: Unhandled dataType in GetSessionType() - " << olc.m_forwardLogicalChannelParameters.m_dataType.GetTagName());
    }
}


bool H245ProxyHandler::HandleOpenLogicalChannel(H245_OpenLogicalChannel & olc, callptr & call)
{
	bool changed = false;
	if (hnat && !UsesH46019())
		changed = hnat->HandleOpenLogicalChannel(olc);

	if (UsesH46019fc()) {
		switch (GetH46019fcState()) {
			case 1:							// Initiating
				SetH46019fcState(2);
				break;
			case 2:							// Waiting for reply (switching)
				SetUsesH46019fc(false);
				break;
			default:
				break;
		}
	}

	WORD flcn = (WORD)olc.m_forwardLogicalChannelNumber;
    call->AddChannelFlcn(flcn); // remember all channels FLCN so we can close them on Reroute
	if (IsT120Channel(olc)) {
		T120LogicalChannel * lc = CreateT120LogicalChannel(flcn);
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_separateStack)
			&& lc && lc->OnSeparateStack(olc.m_separateStack, this)) {
			lc->StartReading(handler);
			return changed;
		}
		return false;
	} else {
		bool isReverseLC = false;
		H245_H2250LogicalChannelParameters * h225Params = GetLogicalChannelParameters(olc, isReverseLC);
#ifdef HAS_H46026
		if (UsesH46026() && peer && !peer->UsesH46026()) {
			PTRACE(4, "H46026\tAdding mediaControlChannel");
			if (h225Params) {
				h225Params->IncludeOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel);
				h225Params->m_mediaControlChannel = IPToH245TransportAddr(GetRemoteAddr(), 0);
				if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_transportCapability)) {
					// just remove media channel capabilities
					h225Params->m_transportCapability.RemoveOptionalField(H245_TransportCapability::e_mediaChannelCapabilities);
					// remove transportCapability if it doesn't contain Q0S or nonStandard items
					if (!h225Params->m_transportCapability.HasOptionalField(H245_TransportCapability::e_qOSCapabilities)
						&& !h225Params->m_transportCapability.HasOptionalField(H245_TransportCapability::e_nonStandard)) {
						h225Params->RemoveOptionalField(H245_H2250LogicalChannelParameters::e_transportCapability);
					}
				}
			}
			changed = true;
		}
#endif

#ifdef HAS_H46018
		WORD sessionID = h225Params ? (WORD)h225Params->m_sessionID : INVALID_RTP_SESSION;
		H46019Session h46019chan(0, INVALID_RTP_SESSION, NULL);
		if (m_requestRTPMultiplexing || m_remoteRequestsRTPMultiplexing
			|| (peer && peer->m_requestRTPMultiplexing)
			|| (peer && peer->m_remoteRequestsRTPMultiplexing) ) {
			h46019chan = MultiplexedRTPHandler::Instance()->GetChannelSwapped(call->GetCallNumber(), sessionID, this);
			if (!h46019chan.IsValid()) {
				h46019chan = H46019Session(call->GetCallNumber(), sessionID, this); // no existing found, create a new one
			}
			if (sessionID == INVALID_RTP_SESSION) {
				// master assigned RTP session ID - remember FLCN to help set it later
				h46019chan.m_flcn = flcn;
			}
		}
		if (!IsTraversalClient() && !UsesH46026()
			&& h225Params && h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel)) {
			h46019chan.m_addrA_RTCP = h225Params->m_mediaControlChannel;
		}
		// parse incoming traversal parameters for H.460.19
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_genericInformation)) {
			// remove traversal parameters from sender before forwarding
			for (PINDEX i = 0; i < olc.m_genericInformation.GetSize(); i++) {
				PASN_ObjectId & gid = olc.m_genericInformation[i].m_messageIdentifier;
				if (olc.m_genericInformation[i].m_messageContent.GetSize() > 0) {
					H245_ParameterIdentifier & ident = olc.m_genericInformation[i].m_messageContent[0].m_parameterIdentifier;
					PASN_Integer & n = ident;
					if (gid == H46019_OID && n == 1) {
						unsigned payloadtype = UNDEFINED_PAYLOAD_TYPE;
						H225_TransportAddress keepAliveRTPAddr;
						H245_UnicastAddress keepAliveRTCPAddr;
						unsigned keepAliveInterval = 0;
						H225_TransportAddress multiplexedRTPAddr;
						H225_TransportAddress multiplexedRTCPAddr;
						DWORD multiplexID = INVALID_MULTIPLEX_ID;
						if (ParseTraversalParameters(olc.m_genericInformation[i], payloadtype, keepAliveRTPAddr, keepAliveInterval,
								multiplexedRTPAddr, multiplexedRTCPAddr, multiplexID)) {
							H245_UnicastAddress * control = NULL;
							if (h225Params && h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel)
								&& (control = GetH245UnicastAddress(h225Params->m_mediaControlChannel)) ) {
								keepAliveRTCPAddr = *control;
							} else {
								PTRACE(1, "H46018\tError: H.460.19 server didn't provide mediaControlChannel");
								SNMP_TRAP(10, SNMPError, Network, "H.460.19 server didn't provide mediaControlChannel");
							}
							if (keepAliveInterval > 0) {
								call->AddRTPKeepAlive(flcn, keepAliveRTPAddr, keepAliveInterval, multiplexID);
								call->AddRTCPKeepAlive(flcn, keepAliveRTCPAddr, keepAliveInterval, multiplexID);
							}
							m_remoteRequestsRTPMultiplexing = m_isRTPMultiplexingEnabled && (multiplexID != INVALID_MULTIPLEX_ID);
							if (m_requestRTPMultiplexing || m_remoteRequestsRTPMultiplexing) {
								if (!h46019chan.IsValid()) {
									// eg. server requests multiplexing to it, but doesn't support sending multiplexed
									h46019chan = H46019Session(call->GetCallNumber(), sessionID, this); // no existing found, create a new one
								}
								h46019chan.m_multiplexID_toA = multiplexID;
								if (IsTraversalServer()) {
									if (IsSet(multiplexedRTPAddr))
										h46019chan.m_addrA = multiplexedRTPAddr;
									else
										h46019chan.m_addrA = keepAliveRTPAddr;
									h46019chan.m_addrA_RTCP = multiplexedRTCPAddr;
								}
							}
							if (payloadtype != UNDEFINED_PAYLOAD_TYPE) {
								LogicalChannel * lc = FindLogicalChannel(flcn);
								if (lc) {
									((RTPLogicalChannel*)lc)->AddLCKeepAlivePT(payloadtype);
								} else {
									PTRACE(1, "H46019\tError: No logical channel to set keepAlive PT=" << payloadtype);
								}
							}
						}
						// move remaining elements down
						for (PINDEX j = i+1; j < olc.m_genericInformation.GetSize(); j++) {
							olc.m_genericInformation[j-1] = olc.m_genericInformation[j];
						}
						olc.m_genericInformation.SetSize(olc.m_genericInformation.GetSize()-1);
					}
				}
			}
			if (olc.m_genericInformation.GetSize() == 0)
				olc.RemoveOptionalField(H245_OpenLogicalChannel::e_genericInformation);
		}
#endif

        bool isUnidirectional = false;
        RTPSessionTypes sessionType = Unknown;
        GetSessionType(olc, sessionType, isUnidirectional);

		// create LC objects, rewrite for forwarding after H.460.19 parameters have been parsed
		if (UsesH46019fc()) {
			changed |= (h225Params) ? OnLogicalChannelParameters(h225Params, 0, isUnidirectional, sessionType) : false;
		} else {
			changed |= (h225Params) ? OnLogicalChannelParameters(h225Params, flcn, isUnidirectional, sessionType) : false;
		}

		if (isUnidirectional) {
			LogicalChannel * lc = FindLogicalChannel(flcn);
			if (lc) {
				((RTPLogicalChannel*)lc)->SetUniDirectional(true);
			}
		}

#ifdef HAS_H46018
		// We don't put the generic identifier on the reverse OLC
		if (UsesH46019fc() && isReverseLC)
			return true;	// TODO: this looks buggy, will skip RTP multiplex assignments + H235 media etc.

		// add if peer is traversal client, don't add if we are traversal client
		PTRACE(5, "H46018\tPeer traversal role=" << (int)(peer ? peer->GetTraversalRole() : None));
		if (peer && (peer->IsTraversalClient() || (peer->IsTraversalServer() && peer->m_requestRTPMultiplexing))) {
			// We need to move any generic Information messages up 1 so H.460.19 will ALWAYS be in position 0.
			if (olc.HasOptionalField(H245_OpenLogicalChannel::e_genericInformation)) {
				olc.m_genericInformation.SetSize(olc.m_genericInformation.GetSize()+1);
				for (PINDEX j = 0; j < olc.m_genericInformation.GetSize()-1; j++) {
					olc.m_genericInformation[j+1] = olc.m_genericInformation[j];
				}
			} else {
				olc.IncludeOptionalField(H245_OpenLogicalChannel::e_genericInformation);
				olc.m_genericInformation.SetSize(1);
			}
			H245_CapabilityIdentifier & id = olc.m_genericInformation[0].m_messageIdentifier;
			id.SetTag(H245_CapabilityIdentifier::e_standard);
			PASN_ObjectId & gid = id;
			gid.SetValue(H46019_OID);
			olc.m_genericInformation[0].IncludeOptionalField(H245_GenericMessage::e_messageContent);
			olc.m_genericInformation[0].m_messageContent.SetSize(1);
			H245_GenericParameter genericParameter;
			H245_ParameterIdentifier & ident = genericParameter.m_parameterIdentifier;
			ident.SetTag(H245_ParameterIdentifier::e_standard);
			PASN_Integer & n = ident;
			n = 1;
			H46019_TraversalParameters params;
			if (peer->IsTraversalClient()) {
				params.IncludeOptionalField(H46019_TraversalParameters::e_keepAliveChannel);
				LogicalChannel * lc;
				if (UsesH46019fc()) {
					lc = fastStartLCs[sessionID];
				} else {
					lc = FindLogicalChannel(flcn);
				}
				if (lc) {
					params.m_keepAliveChannel = IPToH245TransportAddr(GetMasqAddr(), lc->GetPort()); // use RTP port for keepAlives
					((RTPLogicalChannel*)lc)->SetUsesH46019fc(UsesH46019fc());
					((RTPLogicalChannel*)lc)->SetRTPSessionID((WORD)h225Params->m_sessionID);
				} else {
					PTRACE(1, "Can't find RTP port for logical channel " << flcn);
				}
				params.IncludeOptionalField(H46019_TraversalParameters::e_keepAliveInterval);
				params.m_keepAliveInterval = 19;
			}
			if (peer->m_requestRTPMultiplexing) {
				params.IncludeOptionalField(H46019_TraversalParameters::e_multiplexID);
				params.m_multiplexID = MultiplexedRTPHandler::Instance()->GetMultiplexID(call->GetCallNumber(), sessionID, peer);
				if (params.m_multiplexID == INVALID_MULTIPLEX_ID) {
					params.m_multiplexID = MultiplexedRTPHandler::Instance()->GetNewMultiplexID();
				}

				params.IncludeOptionalField(H46019_TraversalParameters::e_multiplexedMediaControlChannel);
				params.m_multiplexedMediaControlChannel = IPToH245TransportAddr(GetMasqAddr(), m_multiplexedRTCPPort);
				params.IncludeOptionalField(H46019_TraversalParameters::e_multiplexedMediaChannel);
				params.m_multiplexedMediaChannel = IPToH245TransportAddr(GetMasqAddr(), m_multiplexedRTPPort);
				// set keepAliveChannel to multiplex media channel
				params.m_keepAliveChannel = IPToH245TransportAddr(GetMasqAddr(), m_multiplexedRTPPort);
				// set mediaControlChannel to multiplexed port, LifeSize seems to use that instead of multiplexedMediaControlPort
				if (h225Params) {
					if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel)) {
						h225Params->m_mediaControlChannel = IPToH245TransportAddr(GetMasqAddr(), m_multiplexedRTCPPort);
					}
				}
				h46019chan.m_multiplexID_fromB = params.m_multiplexID;
			}

			PTRACE(5, "Adding TraversalParams to OLC=" << params);
			H245_ParameterValue & octetValue = genericParameter.m_parameterValue;
			octetValue.SetTag(H245_ParameterValue::e_octetString);
			PASN_OctetString & raw = octetValue;
			raw.EncodeSubType(params);
			olc.m_genericInformation[0].m_messageContent[0] = genericParameter;
			changed = true;
		}

		// set sockets, depending if we will received as multiplexed or not
		// always fill structure, will be needed for keepAlive sockets etc.
		LogicalChannel * lc = FindLogicalChannel(flcn);
		// side A
		if (m_requestRTPMultiplexing) {
			h46019chan.m_osSocketToA = MultiplexedRTPHandler::Instance()->GetRTPOSSocket();
			h46019chan.m_osSocketToA_RTCP = MultiplexedRTPHandler::Instance()->GetRTCPOSSocket();
		}
		if (!m_requestRTPMultiplexing && lc) {
			h46019chan.m_osSocketToA = lc->GetRTPOSSocket();
			h46019chan.m_osSocketToA_RTCP = lc->GetRTCPOSSocket();
		}
		// side B
        if (peer) {
            if (peer->m_requestRTPMultiplexing) {
                h46019chan.m_osSocketToB = MultiplexedRTPHandler::Instance()->GetRTPOSSocket();
                h46019chan.m_osSocketToB_RTCP = MultiplexedRTPHandler::Instance()->GetRTCPOSSocket();
            }
            if (!peer->m_requestRTPMultiplexing && lc) {
                h46019chan.m_osSocketToB = lc->GetRTPOSSocket();
                h46019chan.m_osSocketToB_RTCP = lc->GetRTCPOSSocket();
            }

            // add multiplex channel only if at least one side does multiplexing
            if (m_requestRTPMultiplexing || m_remoteRequestsRTPMultiplexing
                || peer->m_requestRTPMultiplexing || peer->m_remoteRequestsRTPMultiplexing) {
                MultiplexedRTPHandler::Instance()->AddChannel(h46019chan);
    #ifdef HAS_H46024B
                if (call && call->GetNATStrategy() == CallRec::e_natAnnexB)
                    call->H46024BSessionFlag(sessionID);
    #endif
            }
		}

#ifdef HAS_H46024A
        if (call && !call->IsH46024APassThrough()) {
            if (olc.HasOptionalField(H245_OpenLogicalChannel::e_genericInformation)) {
                PINDEX i = 0;
                for (i = 0; i < olc.m_genericInformation.GetSize(); i++) {
                    PASN_ObjectId & gid = olc.m_genericInformation[i].m_messageIdentifier;
                    if (gid == H46024A_OID && olc.m_genericInformation[i].HasOptionalField(H245_GenericInformation::e_messageContent)) {
                        const H245_ArrayOf_GenericParameter & msg = olc.m_genericInformation[i].m_messageContent;
                        PTRACE(4,"H46024A\tAlt Port Info:\n" << msg);
                        PString m_CUI = PString();  H323TransportAddress m_altAddr1, m_altAddr2; unsigned m_altMuxID=0;
                        bool error = false;
                        if (!GetH245GenericStringOctetString(0, msg, m_CUI))  error = true;
                        if (!GetH245TransportGenericOctetString(1, msg, m_altAddr1))  error = true;
                        if (!GetH245TransportGenericOctetString(2, msg, m_altAddr2))  error = true;
                        GetH245GenericUnsigned(3, msg, m_altMuxID);
                        if (!error) {
                            GkClient * gkClient = RasServer::Instance()->GetGkClient();
                            if (gkClient)
                                gkClient->H46023_SetAlternates(call->GetCallIdentifier(), sessionID, m_CUI, m_altMuxID, m_altAddr1, m_altAddr2);
                        }
                        for (PINDEX j = i+1; j < olc.m_genericInformation.GetSize(); j++) {
                            olc.m_genericInformation[j-1] = olc.m_genericInformation[j];
                        }
                        olc.m_genericInformation.SetSize(olc.m_genericInformation.GetSize()-1);
                        if (olc.m_genericInformation.GetSize() == 0)
                            olc.RemoveOptionalField(H245_OpenLogicalChannel::e_genericInformation);
                        changed = true;
                        break;
                    }
                }
            } else {
                H245_ArrayOf_GenericParameter info;
                GkClient * gkClient = RasServer::Instance()->GetGkClient();
                if (gkClient) {
                    PString m_CUI = PString();
                    H323TransportAddress m_altAddr1, m_altAddr2;
                    unsigned m_altMuxID = 0;
                    gkClient->H46023_LoadAlternates(call->GetCallIdentifier(), sessionID, m_CUI, m_altMuxID, m_altAddr1, m_altAddr2);
                        H245_GenericInformation alt;
                        H245_CapabilityIdentifier & altid = alt.m_messageIdentifier;
                        altid.SetTag(H245_CapabilityIdentifier::e_standard);
                        PASN_ObjectId & oid = altid;
                        oid.SetValue(H46024A_OID);
                        alt.IncludeOptionalField(H245_GenericMessage::e_messageContent);
                        H245_ArrayOf_GenericParameter & msg = alt.m_messageContent;
                        msg.SetSize(3);
                        BuildH245GenericOctetString(msg[0], 0, (PASN_IA5String)m_CUI);
                        BuildH245GenericOctetString(msg[1], 1, m_altAddr1);
                        BuildH245GenericOctetString(msg[2], 2, m_altAddr2);
                        if (m_altMuxID) {
                            msg.SetSize(4);
                            BuildH245GenericUnsigned(msg[3], 3, m_altMuxID);
                        }
                    olc.IncludeOptionalField(H245_OpenLogicalChannel::e_genericInformation);
                    int sz = olc.m_genericInformation.GetSize();
                    olc.m_genericInformation.SetSize(sz+1);
                    olc.m_genericInformation[sz] = alt;
                    changed = true;
                }
            }
        }
#endif

		// make sure the keepalive payloadType doesn't conflict with encryption payloadType (VCS bug)
		if (olc.HasOptionalField(H245_OpenLogicalChannel::e_encryptionSync)
			&& olc.m_encryptionSync.m_synchFlag == GNUGK_KEEPALIVE_RTP_PAYLOADTYPE) {
			call->SetRTPKeepAlivePayloadType(flcn, GNUGK_KEEPALIVE_RTP_PAYLOADTYPE + 1);
		}
		// start KeepAlives if we are client (will be ignored if we are server and no KeepAlive has been added above)
		call->StartRTPKeepAlive(flcn, h46019chan.m_osSocketToA);
		call->StartRTCPKeepAlive(flcn, h46019chan.m_osSocketToA_RTCP);
#endif // HAS_H46018

#ifdef HAS_H235_MEDIA
		RTPLogicalChannel * rtplc = (RTPLogicalChannel *)FindLogicalChannel(flcn);
		if (call->IsMediaEncryption() && rtplc && h225Params) {
			if ((m_isCaller && call->GetEncryptDirection() == CallRec::callingParty)
				|| (!m_isCaller && call->GetEncryptDirection() == CallRec::calledParty)) {
				// we add encryption, OLC has already been rewritten
				if (!h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_dynamicRTPPayloadType)) {
					h225Params->IncludeOptionalField(H245_H2250LogicalChannelParameters::e_dynamicRTPPayloadType);
					if (isReverseLC) {
						rtplc->SetPlainPayloadType(GetStaticPayloadType(olc.m_reverseLogicalChannelParameters.m_dataType));
					} else {
						rtplc->SetPlainPayloadType(GetStaticPayloadType(olc.m_forwardLogicalChannelParameters.m_dataType));
					}
					h225Params->m_dynamicRTPPayloadType = call->GetNewDynamicPayloadType();
					rtplc->SetCipherPayloadType(h225Params->m_dynamicRTPPayloadType);
				} else {
					rtplc->SetPlainPayloadType(h225Params->m_dynamicRTPPayloadType);
					rtplc->SetCipherPayloadType(h225Params->m_dynamicRTPPayloadType);
				}
#ifdef HAS_H46018
				h46019chan.m_decryptMultiplexID = h46019chan.m_multiplexID_fromB;
#endif
			} else {
				// we remove encryption, OLC has already been rewritten
				if (!h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_dynamicRTPPayloadType)) {
					PTRACE(1, "H235\tError: dynamic PT missing");
					SNMP_TRAP(7, SNMPError, Authentication, "Dynamic H.235 PT missing");
				} else {
					BYTE mediaPayloadType = UNDEFINED_PAYLOAD_TYPE;
					if (isReverseLC)
						mediaPayloadType = GetStaticPayloadType(olc.m_reverseLogicalChannelParameters.m_dataType);
					else
						mediaPayloadType = GetStaticPayloadType(olc.m_forwardLogicalChannelParameters.m_dataType);
					if (mediaPayloadType != UNDEFINED_PAYLOAD_TYPE) {
						// plain media type has a static payload type, check if packatization supplies a better one
						if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaPacketization)
							&& (h225Params->m_mediaPacketization.GetTag() == H245_H2250LogicalChannelParameters_mediaPacketization::e_rtpPayloadType)) {
							H245_RTPPayloadType & desc = h225Params->m_mediaPacketization;
							if (desc.HasOptionalField(H245_RTPPayloadType::e_payloadType)) {
								mediaPayloadType = desc.m_payloadType;
							}
						}
						// look at h263Options do make distinction between old H.263 and H.263+
						if ( 	(isReverseLC && IsOldH263(olc.m_reverseLogicalChannelParameters.m_dataType))
							|| (!isReverseLC && IsOldH263(olc.m_forwardLogicalChannelParameters.m_dataType)) ) {
							mediaPayloadType = 34;	// use static payload type for H.263
						}

						rtplc->SetCipherPayloadType(h225Params->m_dynamicRTPPayloadType);
						rtplc->SetPlainPayloadType(mediaPayloadType);
						if (mediaPayloadType < MIN_DYNAMIC_PAYLOAD_TYPE) {
							h225Params->RemoveOptionalField(H245_H2250LogicalChannelParameters::e_dynamicRTPPayloadType);
						} else {
							h225Params->m_dynamicRTPPayloadType = mediaPayloadType;
						}
					} else {
						rtplc->SetCipherPayloadType(h225Params->m_dynamicRTPPayloadType);
						rtplc->SetPlainPayloadType(h225Params->m_dynamicRTPPayloadType);
					}
				}
#ifdef HAS_H46018
				h46019chan.m_encryptMultiplexID = h46019chan.m_multiplexID_fromB;
#endif
			}

			// is this the encryption or decryption direction ?
			bool encrypting = (m_isCaller && call->GetEncryptDirection() == CallRec::callingParty)
							|| (!m_isCaller && call->GetEncryptDirection() == CallRec::calledParty);
			// use the key sent by the other side
			if (olc.HasOptionalField(H245_OpenLogicalChannel::e_encryptionSync)) {
				rtplc->CreateH235Session(call->GetAuthenticators(), olc.m_encryptionSync, encrypting);
				olc.RemoveOptionalField(H245_OpenLogicalChannel::e_encryptionSync);
			} else if (m_isH245Master) {
				// the message comes from the master and doesn't have encryptionSync
				olc.IncludeOptionalField(H245_OpenLogicalChannel::e_encryptionSync);
				rtplc->CreateH235SessionAndKey(call->GetAuthenticators(), olc.m_encryptionSync, encrypting);
			}
#ifdef HAS_H46018
			if (m_requestRTPMultiplexing || m_remoteRequestsRTPMultiplexing
				|| peer->m_requestRTPMultiplexing || peer->m_remoteRequestsRTPMultiplexing) {
				// get the H46019Session object in standard (un-swapped) format
				H46019Session h46019chan = MultiplexedRTPHandler::Instance()->GetChannel(call->GetCallNumber(), sessionID);
				if (encrypting) {
					h46019chan.m_encryptingLC = rtplc;
				} else {
					h46019chan.m_decryptingLC = rtplc;
				}
				MultiplexedRTPHandler::Instance()->UpdateChannel(h46019chan);
			}
#endif
		}
#endif // HAS_H235_MEDIA

#ifdef HAS_H46026
		if (!UsesH46026() && peer && peer->UsesH46026()) {
			PTRACE(4, "H46026\tRemoving mediaControlChannel");
			if (h225Params) {
				h225Params->RemoveOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel);
				h225Params->RemoveOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel);	// just in case
				h225Params->IncludeOptionalField(H245_H2250LogicalChannelParameters::e_transportCapability);
				h225Params->m_transportCapability.IncludeOptionalField(H245_TransportCapability::e_mediaChannelCapabilities);
				h225Params->m_transportCapability.m_mediaChannelCapabilities.SetSize(1);
				h225Params->m_transportCapability.m_mediaChannelCapabilities[0].IncludeOptionalField(H245_MediaChannelCapability::e_mediaTransport);
				h225Params->m_transportCapability.m_mediaChannelCapabilities[0].m_mediaTransport.SetTag(H245_MediaTransportType::e_ip_TCP);
			}
			changed = true;
		}
#endif

		return changed;
	}
}

bool H245ProxyHandler::HandleOpenLogicalChannelReject(H245_OpenLogicalChannelReject & olcr, callptr & call)
{
	WORD flcn = (WORD)olcr.m_forwardLogicalChannelNumber;
	peer->RemoveLogicalChannel(flcn);
	return false; // nothing changed
}

bool H245ProxyHandler::HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck & olca, callptr & call)
{
	bool changed = false;
#ifdef HAS_H46026
	if (UsesH46026() && peer && !peer->UsesH46026()) {
		PTRACE(4, "H46026\tAdding mediaChannel + mediaControlChannel");
		if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_forwardMultiplexAckParameters)
			&& olca.m_forwardMultiplexAckParameters.GetTag() == H245_OpenLogicalChannelAck_forwardMultiplexAckParameters::e_h2250LogicalChannelAckParameters) {
			H245_H2250LogicalChannelAckParameters & h225Params  = olca.m_forwardMultiplexAckParameters;
			h225Params.IncludeOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaChannel);
			// ports will be set by proxy rewrite below
			h225Params.m_mediaChannel = IPToH245TransportAddr(GetRemoteAddr(), 0);
			h225Params.IncludeOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaControlChannel);
			h225Params.m_mediaControlChannel = IPToH245TransportAddr(GetRemoteAddr(), 0);
		}
	}
#endif

	if (hnat)
		hnat->HandleOpenLogicalChannelAck(olca);
	WORD flcn = (WORD)olca.m_forwardLogicalChannelNumber;
	LogicalChannel * lc = NULL;
	if (peer)
		lc = peer->FindLogicalChannel(flcn);
	if (!lc) {
		PTRACE(2, "Proxy\tWarning: logical channel " << flcn << " not found for opening");
		return false;
	}

#if defined(HAS_H46018) || defined(HAS_H46026)
	WORD sessionID = INVALID_RTP_SESSION;
	if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_forwardMultiplexAckParameters)
		&& olca.m_forwardMultiplexAckParameters.GetTag() == H245_OpenLogicalChannelAck_forwardMultiplexAckParameters::e_h2250LogicalChannelAckParameters)
		sessionID = ((H245_H2250LogicalChannelAckParameters&)olca.m_forwardMultiplexAckParameters).m_sessionID;
#endif
#if defined(HAS_H46018) || defined(HAS_H235_MEDIA)
	RTPLogicalChannel * rtplc = dynamic_cast<RTPLogicalChannel *>(lc);
#endif
#ifdef HAS_H46018
	if (IsTraversalServer() || IsTraversalClient()) {
		if (rtplc)
			rtplc->SetUsesH46019();
	}
	H46019Session h46019chan(0, INVALID_RTP_SESSION, NULL);
	DWORD assignedMultiplexID = INVALID_MULTIPLEX_ID; // only used when HAS_H235_MEDIA
 	if (m_requestRTPMultiplexing || m_remoteRequestsRTPMultiplexing || peer->m_requestRTPMultiplexing || peer->m_remoteRequestsRTPMultiplexing) {
		// update session ID if assigned by master
		if (sessionID > 3) {
			MultiplexedRTPHandler::Instance()->UpdateChannelSession(call->GetCallNumber(), flcn, peer, sessionID);
			peer->UpdateLogicalChannelSessionID(flcn, sessionID);
			((RTPLogicalChannel*)lc)->SetRTPSessionID(sessionID);
		}
		h46019chan = MultiplexedRTPHandler::Instance()->GetChannelSwapped(call->GetCallNumber(), sessionID, peer);
		if (!h46019chan.IsValid()) {
			MultiplexedRTPHandler::Instance()->DumpChannels(" ERROR: channel not found! ");
		} else {
			h46019chan.Dump();
		}
	}
	// parse traversal parameters from sender
	if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_genericInformation)) {
		for (PINDEX i = 0; i < olca.m_genericInformation.GetSize(); i++) {
			if (olca.m_genericInformation[i].m_messageContent.GetSize() > 0) {
				PASN_ObjectId & gid = olca.m_genericInformation[i].m_messageIdentifier;
				if (olca.m_genericInformation[i].m_messageContent.GetSize() > 0) {
					H245_ParameterIdentifier & ident = olca.m_genericInformation[i].m_messageContent[0].m_parameterIdentifier;
					PASN_Integer & n = ident;
					if (gid == H46019_OID && n == 1) {
						unsigned payloadtype = UNDEFINED_PAYLOAD_TYPE;
						H225_TransportAddress keepAliveRTPAddr;
						H245_UnicastAddress keepAliveRTCPAddr;
						unsigned keepAliveInterval = 0;
						H225_TransportAddress multiplexedRTPAddr;
						H225_TransportAddress multiplexedRTCPAddr;
						DWORD multiplexID = INVALID_MULTIPLEX_ID;
						if (ParseTraversalParameters(olca.m_genericInformation[i], payloadtype, keepAliveRTPAddr, keepAliveInterval,
								multiplexedRTPAddr, multiplexedRTCPAddr, multiplexID)) {
							m_remoteRequestsRTPMultiplexing = m_isRTPMultiplexingEnabled && (multiplexID != INVALID_MULTIPLEX_ID);
							if (m_requestRTPMultiplexing || m_remoteRequestsRTPMultiplexing) {
								if (!h46019chan.IsValid()) {
									// eg. server requests multiplexing to it, but doesn't support sending multiplexed
									h46019chan = H46019Session(call->GetCallNumber(), sessionID, peer); // no existing session, create a new one
									MultiplexedRTPHandler::Instance()->AddChannel(h46019chan);
									h46019chan = MultiplexedRTPHandler::Instance()->GetChannelSwapped(call->GetCallNumber(), sessionID, peer);
								}
								h46019chan.m_multiplexID_toB = multiplexID;
								if (IsTraversalServer()) {  // only save multiplex addresses if from server
									if (IsSet(multiplexedRTPAddr))
										h46019chan.m_addrB = multiplexedRTPAddr;
									else
										h46019chan.m_addrB = keepAliveRTPAddr;
									h46019chan.m_addrB_RTCP = multiplexedRTCPAddr;
								}
							}
							if ((payloadtype != UNDEFINED_PAYLOAD_TYPE) && rtplc)
								rtplc->AddLCKeepAlivePT(payloadtype);
						}
					}
				}
			}
		}
		// remove traversal parameters before forwarding OLCA
		if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_genericInformation)) {
			for (PINDEX i = 0; i < olca.m_genericInformation.GetSize(); i++) {
				PASN_ObjectId & gid = olca.m_genericInformation[i].m_messageIdentifier;
				if (gid == H46019_OID) {
					// remove traversal parameters, move remaining elements down
					for (PINDEX j = i+1; j < olca.m_genericInformation.GetSize(); j++) {
						olca.m_genericInformation[j-1] = olca.m_genericInformation[j];
					}
					olca.m_genericInformation.SetSize(olca.m_genericInformation.GetSize()-1);
				}
			}
			if (olca.m_genericInformation.GetSize() == 0)
				olca.RemoveOptionalField(H245_OpenLogicalChannelAck::e_genericInformation);
		}
		changed = true;
	}

	// add traversal parameters, if needed
	PTRACE(5, "H46018\tPeer traversal role=" << (int)(peer ? peer->GetTraversalRole() : None));
	if (peer && (peer->IsTraversalServer() || (peer->IsTraversalClient() && peer->m_requestRTPMultiplexing))) {
		// we need to move any generic Information messages up 1 so H.460.19 will ALWAYS be in position 0.
		if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_genericInformation)) {
			olca.m_genericInformation.SetSize(olca.m_genericInformation.GetSize()+1);
			for (PINDEX j = 0; j < olca.m_genericInformation.GetSize()-1; j++) {
				olca.m_genericInformation[j+1] = olca.m_genericInformation[j];
			}
		} else {
			olca.IncludeOptionalField(H245_OpenLogicalChannelAck::e_genericInformation);
			olca.m_genericInformation.SetSize(1);
		}
		H245_CapabilityIdentifier & id = olca.m_genericInformation[0].m_messageIdentifier;
		id.SetTag(H245_CapabilityIdentifier::e_standard);
		PASN_ObjectId & gid = id;
		gid.SetValue(H46019_OID);
		olca.m_genericInformation[0].IncludeOptionalField(H245_GenericMessage::e_messageContent);
		olca.m_genericInformation[0].m_messageContent.SetSize(1);
		H245_GenericParameter genericParameter;
		H245_ParameterIdentifier & ident = genericParameter.m_parameterIdentifier;
		ident.SetTag(H245_ParameterIdentifier::e_standard);
		PASN_Integer & n = ident;
		n = 1;
		H46019_TraversalParameters params;
		if (peer && peer->IsTraversalServer()) {
			params.IncludeOptionalField(H46019_TraversalParameters::e_keepAlivePayloadType);
			params.m_keepAlivePayloadType = GNUGK_KEEPALIVE_RTP_PAYLOADTYPE;
		}
		if (peer->m_requestRTPMultiplexing) {
			// tell originator of this channel, that GnuGk wants RTP multiplexing
			params.IncludeOptionalField(H46019_TraversalParameters::e_multiplexID);
			params.m_multiplexID = MultiplexedRTPHandler::Instance()->GetMultiplexID(call->GetCallNumber(), sessionID, peer);
			if (params.m_multiplexID == INVALID_MULTIPLEX_ID) {
				params.m_multiplexID = MultiplexedRTPHandler::Instance()->GetNewMultiplexID();
			}

			params.IncludeOptionalField(H46019_TraversalParameters::e_multiplexedMediaControlChannel);
			params.m_multiplexedMediaControlChannel = IPToH245TransportAddr(GetMasqAddr(), m_multiplexedRTCPPort);
			params.IncludeOptionalField(H46019_TraversalParameters::e_multiplexedMediaChannel);
			params.m_multiplexedMediaChannel = IPToH245TransportAddr(GetMasqAddr(), m_multiplexedRTPPort);

			h46019chan.m_multiplexID_fromA = params.m_multiplexID;
			assignedMultiplexID = params.m_multiplexID;
		}

		H245_ParameterValue & octetValue = genericParameter.m_parameterValue;
		octetValue.SetTag(H245_ParameterValue::e_octetString);
		PASN_OctetString & raw = octetValue;
		raw.EncodeSubType(params);
		olca.m_genericInformation[0].m_messageContent[0] = genericParameter;
		PTRACE(5, "Adding TraversalParams to OLCA=" << params);
		changed = true;
	}
	if (m_requestRTPMultiplexing || m_remoteRequestsRTPMultiplexing
		|| peer->m_requestRTPMultiplexing || peer->m_remoteRequestsRTPMultiplexing) {
		// save parameters for mixed multiplex/non-multiplexed call
		if (!IsTraversalClient() && !UsesH46026()) {
			if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_forwardMultiplexAckParameters)) {
				H245_OpenLogicalChannelAck_forwardMultiplexAckParameters & ackparams = olca.m_forwardMultiplexAckParameters;
				if (ackparams.GetTag() == H245_OpenLogicalChannelAck_forwardMultiplexAckParameters::e_h2250LogicalChannelAckParameters) {
					H245_H2250LogicalChannelAckParameters & h225Params = ackparams;
					if (h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaControlChannel))
						h46019chan.m_addrB_RTCP = H245ToH225TransportAddress(h225Params.m_mediaControlChannel);
					if (h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaChannel))
						h46019chan.m_addrB = H245ToH225TransportAddress(h225Params.m_mediaChannel);
				}
			}
		}
		MultiplexedRTPHandler::Instance()->UpdateChannel(h46019chan);

		// now get the same H46019Session object, but in standard (un-swapped) format to update the RTP LC
		h46019chan = MultiplexedRTPHandler::Instance()->GetChannel(call->GetCallNumber(), sessionID);
		RTPLogicalChannel * rtplc = dynamic_cast<RTPLogicalChannel *>(lc);
		if (rtplc) {
			if ((h46019chan.m_multiplexID_toA != INVALID_MULTIPLEX_ID)
				|| (h46019chan.m_multiplexID_fromA != INVALID_MULTIPLEX_ID)) {
				if (IsSet(h46019chan.m_addrA)) {
					rtplc->SetLCMultiplexDestination(false, h46019chan.m_addrA, SideA);
					rtplc->SetLCMultiplexDestination(true, h46019chan.m_addrA_RTCP, SideA);
				}
				rtplc->SetLCMultiplexID(false, h46019chan.m_multiplexID_toA, SideA);
				rtplc->SetLCMultiplexID(true, h46019chan.m_multiplexID_toA, SideA);
				rtplc->SetLCMultiplexSocket(false, h46019chan.m_osSocketToA, SideA);
				rtplc->SetLCMultiplexSocket(true, h46019chan.m_osSocketToA_RTCP, SideA);
			}
			if ((h46019chan.m_multiplexID_toB != INVALID_MULTIPLEX_ID)
				|| (h46019chan.m_multiplexID_fromB != INVALID_MULTIPLEX_ID)) {
				if (IsSet(h46019chan.m_addrB)) {
					rtplc->SetLCMultiplexDestination(false, h46019chan.m_addrB, SideB);
					rtplc->SetLCMultiplexDestination(true, h46019chan.m_addrB_RTCP, SideB);
				}
				rtplc->SetLCMultiplexID(false, h46019chan.m_multiplexID_toB, SideB);
				rtplc->SetLCMultiplexID(true, h46019chan.m_multiplexID_toB, SideB);
				rtplc->SetLCMultiplexSocket(false, h46019chan.m_osSocketToB, SideB);
				rtplc->SetLCMultiplexSocket(true, h46019chan.m_osSocketToB_RTCP, SideB);
			}
		} else {
            PTRACE(1, "Error: RTPLogicalChannel cast failed");
		}
	}
#endif

#ifdef HAS_H235_MEDIA
	if (call->IsMediaEncryption() && rtplc) {
		// is this the encryption or decryption direction ?
		bool encrypting = (m_isCaller && call->GetEncryptDirection() == CallRec::calledParty)
						|| (!m_isCaller && call->GetEncryptDirection() == CallRec::callingParty);
		// use the key sent by the other side
		if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_encryptionSync)) {
			rtplc->CreateH235Session(call->GetAuthenticators(), olca.m_encryptionSync, encrypting);
			olca.RemoveOptionalField(H245_OpenLogicalChannelAck::e_encryptionSync);
		} else if (m_isH245Master) {
			// the message comes from the master and its in the direction we are simulating
			olca.IncludeOptionalField(H245_OpenLogicalChannelAck::e_encryptionSync);
			rtplc->CreateH235SessionAndKey(call->GetAuthenticators(), olca.m_encryptionSync, encrypting);
		}
#ifdef HAS_H46018
		if (m_requestRTPMultiplexing || m_remoteRequestsRTPMultiplexing
			|| peer->m_requestRTPMultiplexing || peer->m_remoteRequestsRTPMultiplexing) {
			// get the H46019Session object in standard (un-swapped) format
			H46019Session h46019chan = MultiplexedRTPHandler::Instance()->GetChannel(call->GetCallNumber(), sessionID);
			if (encrypting) {
				h46019chan.m_encryptingLC = rtplc;
				h46019chan.m_encryptMultiplexID = assignedMultiplexID;
			} else {
				h46019chan.m_decryptingLC = rtplc;
				h46019chan.m_decryptMultiplexID = assignedMultiplexID;
			}
			MultiplexedRTPHandler::Instance()->UpdateChannel(h46019chan);
		}
#endif // HAS_H46018
	}
#endif // HAS_H235_MEDIA

#ifdef HAS_H46026
	if (UsesH46026() || (peer && peer->UsesH46026())) {
		// we'll save a channel object if any side uses .26
		IPAndPortAddress toRTP, toRTCP;
		if (!UsesH46026() && peer && peer->UsesH46026()) {
			PTRACE(4, "H46026\tRemoving mediaChannel + mediaControlChannel");
			if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_forwardMultiplexAckParameters)
				&& olca.m_forwardMultiplexAckParameters.GetTag() == H245_OpenLogicalChannelAck_forwardMultiplexAckParameters::e_h2250LogicalChannelAckParameters) {
				H245_H2250LogicalChannelAckParameters & h225Params  = olca.m_forwardMultiplexAckParameters;
				if (h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaChannel)) {
					toRTP = h225Params.m_mediaChannel;
				}
				h225Params.RemoveOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaChannel);
				if (h225Params.HasOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaControlChannel)) {
					toRTCP = h225Params.m_mediaControlChannel;
				}
				h225Params.RemoveOptionalField(H245_H2250LogicalChannelAckParameters::e_mediaControlChannel);
			}
			changed = true;
		}
		H46026Session chan = H46026RTPHandler::Instance()->FindSession(call->GetCallNumber(), sessionID);
		if (chan.IsValid()) {
			// channel found for other LC in same session, only update if we have more data
			if (!UsesH46026() && peer && peer->UsesH46026()) {
				H46026Session chan26(call->GetCallNumber(), sessionID, lc->GetRTPOSSocket(), lc->GetRTCPOSSocket(), toRTP, toRTCP);
				H46026RTPHandler::Instance()->ReplaceChannel(chan26);
			}
		} else {
			chan = H46026Session(call->GetCallNumber(), sessionID, lc->GetRTPOSSocket(), lc->GetRTCPOSSocket(), toRTP, toRTCP);
			H46026RTPHandler::Instance()->AddChannel(chan);
		}

#ifdef HAS_H235_MEDIA
		RTPLogicalChannel * rtplc = dynamic_cast<RTPLogicalChannel *>(lc);
		if (call->IsMediaEncryption() && rtplc) {
			// is this the encryption or decryption direction ?
			bool encrypting = (m_isCaller && call->GetEncryptDirection() == CallRec::calledParty)
							|| (!m_isCaller && call->GetEncryptDirection() == CallRec::callingParty);
			if (encrypting) {
				H46026RTPHandler::Instance()->UpdateChannelEncryptingLC(call->GetCallNumber(), sessionID, rtplc);
			} else {
				H46026RTPHandler::Instance()->UpdateChannelDecryptingLC(call->GetCallNumber(), sessionID, rtplc);
			}
		}
#endif
	}
#endif

	bool result = lc->SetDestination(olca, this, call, IsTraversalClient(), (peer && peer->m_requestRTPMultiplexing));
	if (result)
		lc->StartReading(handler);

	return result | changed;
}

#ifdef HAS_H235_MEDIA
bool H245ProxyHandler::HandleEncryptionUpdateRequest(H245_MiscellaneousCommand & cmd, bool & suppress, callptr & call, H245Socket * h245sock)
{
	if (call && call->IsMediaEncryption() && !m_isH245Master) {
		// we add encryption and this doesn't come from the master
		// send new media key
		H245_EncryptionUpdateRequest & request = cmd.m_type;
		WORD flcn = (WORD)cmd.m_logicalChannelNumber;
		BYTE newPayloadType = UNDEFINED_PAYLOAD_TYPE;
		if (request.HasOptionalField(H245_EncryptionUpdateRequest::e_synchFlag))
			newPayloadType = request.m_synchFlag;
		else {
			newPayloadType = RandomPT(0, 0);	// TODO: what are the current PTs so we can avoid them ?
		}
		RTPLogicalChannel * rtplc = dynamic_cast<RTPLogicalChannel *>(FindLogicalChannel(flcn));
		if (!rtplc && peer) {
			rtplc = dynamic_cast<RTPLogicalChannel *>(peer->FindLogicalChannel(flcn));
		}
		if (rtplc) {
			H245_MultimediaSystemControlMessage h245msg;
			h245msg.SetTag(H245_MultimediaSystemControlMessage::e_command);
			H245_CommandMessage & h245cmd = h245msg;
			h245cmd.SetTag(H245_CommandMessage::e_miscellaneousCommand);
			H245_MiscellaneousCommand & misc = h245cmd;
			misc.m_type.SetTag(H245_MiscellaneousCommand_type::e_encryptionUpdateCommand);
			H245_MiscellaneousCommand_type_encryptionUpdateCommand & update = misc.m_type;
			misc.m_logicalChannelNumber = cmd.m_logicalChannelNumber;
			misc.m_direction.SetTag(H245_EncryptionUpdateDirection::e_slaveToMaster); // this update was requested by the slave
			rtplc->GenerateNewMediaKey(newPayloadType, update.m_encryptionSync);
			if (h245sock) {
				PTRACE(4, "H245\tTo send (CallID: " << h245sock->GetCallIdentifierAsString() << "): " << h245msg);
				h245sock->Send(h245msg);
			} else {
				// send tunneled (to slave)
				CallSignalSocket * css = call->GetCallSignalSocketCalling();
				if (css->IsH245Master())
					css = call->GetCallSignalSocketCalled();
				css->SendTunneledH245(h245msg);
			}
		} else {
			PTRACE(1, "H235\tError: Couldn't find flcn " << flcn << " for EncryptionUpdateRequest");
		}
		suppress = true;
	}
	return false;
}

bool H245ProxyHandler::HandleEncryptionUpdateCommand(H245_MiscellaneousCommand & cmd, bool & suppress, callptr & call, H245Socket * h245sock)
{
	if (call && call->IsMediaEncryption() && m_isH245Master) {
		// we add encryption and this comes from the master
		// use this media key
		H245_MiscellaneousCommand_type_encryptionUpdateCommand & update = cmd.m_type;
		WORD flcn = (WORD)cmd.m_logicalChannelNumber;
		RTPLogicalChannel * rtplc = dynamic_cast<RTPLogicalChannel *>(FindLogicalChannel(flcn));
		if (!rtplc && peer) {
			rtplc = dynamic_cast<RTPLogicalChannel *>(peer->FindLogicalChannel(flcn));
		}
		if (rtplc) {
			rtplc->UpdateMediaKey(update.m_encryptionSync);

			// TODO: send ACK only if channel is owed by master
			H245_MultimediaSystemControlMessage h245msg;
			h245msg.SetTag(H245_MultimediaSystemControlMessage::e_command);
			H245_CommandMessage & h245cmd = h245msg;
			h245cmd.SetTag(H245_CommandMessage::e_miscellaneousCommand);
			H245_MiscellaneousCommand & misc = h245cmd;
			misc.m_type.SetTag(H245_MiscellaneousCommand_type::e_encryptionUpdateAck);
			H245_MiscellaneousCommand_type_encryptionUpdateAck & ack = misc.m_type;
			misc.m_logicalChannelNumber = cmd.m_logicalChannelNumber;
			misc.IncludeOptionalField(H245_MiscellaneousCommand::e_direction);
			misc.m_direction.SetTag(H245_EncryptionUpdateDirection::e_slaveToMaster);
			ack.m_synchFlag = update.m_encryptionSync.m_synchFlag;
			if (h245sock) {
				PTRACE(4, "H245\tTo send (CallID: " << h245sock->GetCallIdentifierAsString() << "): " << h245msg);
				h245sock->Send(h245msg);
			} else {
				// send tunneled to master side (only the master issues UpdateCommand, slave would have sent UpdateRequest)
				// (could also look at encryption direction in call object)
				CallSignalSocket * css = call->GetCallSignalSocketCalling();
				if (!css->IsH245Master())
					css = call->GetCallSignalSocketCalled();
				css->SendTunneledH245(h245msg);
			}
		} else {
			PTRACE(1, "H235\tError: Couldn't find flcn " << flcn << " for EncryptionUpdateCommand");
		}
		suppress = true;
	}
	return false;
}

bool H245ProxyHandler::HandleEncryptionUpdateAck(H245_MiscellaneousCommand & cmd, bool & suppress, callptr & call, H245Socket * h245sock)
{
	if (call->IsMediaEncryption() && !m_isH245Master) {
		// now we can officially use the key we sent to the slave (currently we use it right away and discard all media with old PT)
		suppress = true;
	}
	return false;
}
#endif

bool H245ProxyHandler::HandleIndication(H245_IndicationMessage & Indication, bool & suppress)
{
#ifdef HAS_H46018
	// filter out genericIndications for H.460.18
	if (Indication.GetTag() == H245_IndicationMessage::e_genericIndication) {
		H245_GenericMessage generic = Indication;
		PASN_ObjectId & gid = generic.m_messageIdentifier;
		if (gid == H46018_OID) {
			suppress = true;
			return false;
		}
	}
#endif

	/// userInput handling
	if (Indication.GetTag() != H245_IndicationMessage::e_userInput)
		return false;

	const H245_UserInputIndication & ind = Indication;
	PString value;
	switch (ind.GetTag()) {
		case H245_UserInputIndication::e_alphanumeric :
			value = (const PASN_GeneralString &)ind;
			break;

		case H245_UserInputIndication::e_signal :
		{
			const H245_UserInputIndication_signal & sig = ind;
			if (sig.m_signalType.GetDataLength() > 0)
				value = PString(sig.m_signalType[0]);
			break;
		}
	}
	PTRACE(3, "Received Input: " << value);

	if ((value == "*") &&
		GkConfig()->GetBoolean(ProxySection, "EnableRTPMute", false)) {
		HandleMuteRTPChannel();
	}
	return false;
}

void H245ProxyHandler::HandleMuteRTPChannel()
{
  	isMute = !isMute;

	iterator eIter = logicalChannels.end();
	for (iterator Iter = logicalChannels.begin(); Iter != eIter; ++Iter) {
		LogicalChannel * lc = Iter->second;
		lc->SetRTPMute(isMute);
		PTRACE(3, (isMute ? "Mute": "Release") << " RTP Channel " << lc->GetChannelNumber() );
	}
}

bool H245ProxyHandler::HandleCloseLogicalChannel(H245_CloseLogicalChannel & clc, callptr & call)
{
	bool found = this->RemoveLogicalChannel((WORD)clc.m_forwardLogicalChannelNumber);
	if (!found && GkConfig()->GetBoolean(ProxySection, "SearchBothSidesOnCLC", false)) {
		// due to bad implementation of some endpoints, we check the
		// forwardLogicalChannelNumber on both sides
		// JW: maybe this isn't needed any more after the bug in interpreting the source parameter is fixed now 2018-01-24
		if (peer)
			peer->RemoveLogicalChannel((WORD)clc.m_forwardLogicalChannelNumber);
	}
#ifdef HAS_H46018
	call->RemoveRTPKeepAlives(clc.m_forwardLogicalChannelNumber);
#endif
	return false; // nothing changed
}

bool H245ProxyHandler::HandleFastStartSetup(H245_OpenLogicalChannel & olc, callptr & call)
{
	if (!peer)
		return false;

	bool changed = false;
	if (hnat && (GetTraversalRole() == None)) {
		changed |= hnat->HandleOpenLogicalChannel(olc);
	}

	if (GkConfig()->GetBoolean(ProxySection, "RemoveMCInFastStartTransmitOffer", false)) {
		// for unicast transmit channels, mediaChannel should not be sent on offer
		// it is responsibility of callee to provide mediaChannel in an answer
		H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters &params = olc.m_forwardLogicalChannelParameters.m_multiplexParameters;
		if (params.GetTag() == H245_OpenLogicalChannel_forwardLogicalChannelParameters_multiplexParameters::e_h2250LogicalChannelParameters) {
			H245_H2250LogicalChannelParameters &h225Params = (H245_H2250LogicalChannelParameters &)params;
			if (h225Params.HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel)) {
				h225Params.RemoveOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel);
				changed = true;
			}
		}
	}

	if (IsTraversalClient()) {
		SetUsesH46019fc(true);
		SetH46019fcState(1);
	}

	if (UsesH46019() && call->GetCalledParty() && call->GetCalledParty()->IsTraversalClient())
		return (HandleOpenLogicalChannel(olc, call) || changed);
	else {
		bool nouse;
		H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse);
        bool isUnidirectional = false;
        RTPSessionTypes sessionType = Unknown;
        GetSessionType(olc, sessionType, isUnidirectional);
		return ((h225Params) ? OnLogicalChannelParameters(h225Params, 0, isUnidirectional, sessionType) : false) || changed;
	}
}

bool H245ProxyHandler::HandleFastStartResponse(H245_OpenLogicalChannel & olc, callptr & call)
{
	if (!peer)
		return false;

	if (UsesH46019()) {
		SetUsesH46019fc(true);
		SetH46019fcState(3);
    }

	bool changed = false;
	bool isReverseLC = false;
	RTPSessionTypes sessionType = Unknown;
	bool nouse;
	GetSessionType(olc, sessionType, nouse);
	if (hnat && (peer->GetTraversalRole() == None))
		changed = hnat->HandleOpenLogicalChannel(olc);

	if (peer->IsTraversalClient() && call->GetCallingParty() && call->GetCallingParty()->IsTraversalClient())
		changed |= HandleOpenLogicalChannel(olc, call);

	WORD flcn = (WORD)olc.m_forwardLogicalChannelNumber;
	H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, isReverseLC);
	if (!h225Params)
		return changed;
	WORD id = (WORD)h225Params->m_sessionID;
	RTPLogicalChannel * lc = NULL;
	siterator iter;
	if (UsesH46019()) {
	   iter = fastStartLCs.find(id);
	   lc = (iter != fastStartLCs.end()) ? iter->second : NULL;
	} else {
	   iter = peer->fastStartLCs.find(id);
	   lc = (iter != peer->fastStartLCs.end()) ? iter->second : NULL;
	}
	if (isReverseLC) {
		if (lc) {
			if (!FindLogicalChannel(flcn)) {
				logicalChannels[flcn] = sessionIDs[id] = lc;
				lc->SetChannelNumber(flcn);
				lc->OnHandlerSwapped(hnat != NULL);
				if (!UsesH46019())
					peer->fastStartLCs.erase(iter);
			}
		} else if ((lc = peer->FindRTPLogicalChannelBySessionID(id))) {
			LogicalChannel *akalc = FindLogicalChannel(flcn);
			if (akalc) {
				lc = static_cast<RTPLogicalChannel *>(akalc);
			} else {
				logicalChannels[flcn] = sessionIDs[id] = lc = new RTPLogicalChannel(lc, flcn, hnat != NULL, sessionType);
				if (!lc->IsOpen()) {
					PTRACE(1, "Proxy\tError: Can't create RTP logical channel " << flcn);
					SNMP_TRAP(10, SNMPWarning, Network, "Can't create RTP logical channel " + PString(PString::Unsigned, flcn));
				}
			}
		}
	} else {
		if (lc) {
			if (!peer->FindLogicalChannel(flcn)) {
				peer->logicalChannels[flcn] = peer->sessionIDs[id] = lc;
				lc->SetChannelNumber(flcn);
				if (!UsesH46019())
					peer->fastStartLCs.erase(iter);
			}
		} else if ((lc = FindRTPLogicalChannelBySessionID(id))) {
			LogicalChannel *akalc = peer->FindLogicalChannel(flcn);
			if (akalc) {
				lc = static_cast<RTPLogicalChannel *>(akalc);
			} else {
				peer->logicalChannels[flcn] = peer->sessionIDs[id] = lc = new RTPLogicalChannel(lc, flcn, hnat != NULL, sessionType);
			}
		}
	}
	bool useMultiplexing = m_isRTPMultiplexingEnabled && peer && peer->m_requestRTPMultiplexing;
    bool isUnidirectional = false;
	// check if we are doing unidirectional H.239
	if (olc.m_forwardLogicalChannelParameters.m_dataType.GetTag() == H245_DataType::e_videoData) {
		H245_VideoCapability & vid = olc.m_forwardLogicalChannelParameters.m_dataType;
		isUnidirectional = (vid.GetTag() == H245_VideoCapability::e_extendedVideoCapability);
    }
	if (lc && (changed = lc->OnLogicalChannelParameters(*h225Params, GetMasqAddr(), isReverseLC, call, IsTraversalClient(), useMultiplexing, isUnidirectional)))
		lc->StartReading(handler);
	return changed;
}

void H245ProxyHandler::SetHandler(ProxyHandler * h)
{
	handler = h;
	if (peer)
		peer->handler = h;
}

void H245ProxyHandler::UpdateLogicalChannelSessionID(WORD flcn, WORD id)
{
	iterator flcnIter = logicalChannels.find(flcn);
	siterator sessionIter = sessionIDs.find(0);	// update channel with temporary session ID 0
	if ((flcnIter != logicalChannels.end())
		&& (sessionIter != sessionIDs.end())) {
		sessionIDs.erase(sessionIter);		// remove 0 sessionID
		sessionIDs[id] = dynamic_cast<RTPLogicalChannel *>(flcnIter->second);	// add new session ID
	} else {
		PTRACE(1, "Error: No logical channel found to update");
	}
}

LogicalChannel * H245ProxyHandler::FindLogicalChannel(WORD flcn)
{
	iterator iter = logicalChannels.find(flcn);
	return (iter != logicalChannels.end()) ? iter->second : NULL;
}

RTPLogicalChannel * H245ProxyHandler::FindRTPLogicalChannelBySessionID(WORD id) const
{
	const_siterator iter = sessionIDs.find(id);
	return (iter != sessionIDs.end()) ? iter->second : NULL;
}

RTPLogicalChannel * H245ProxyHandler::FindRTPLogicalChannelBySessionType(RTPSessionTypes sessionType) const
{
	for (const_siterator iter = sessionIDs.begin(); iter != sessionIDs.end() ; ++iter) {
        if (iter->second->GetType() == sessionType) {
            RTPLogicalChannel * lc = iter->second;
            return lc;
        }
	}
    return NULL;
}

bool H245ProxyHandler::IsRTPInactive(short session) const
{
    bool inactive = false;
    RTPLogicalChannel * lc = FindRTPLogicalChannelBySessionID(session);
    if (lc) {
        inactive = lc->IsRTPInactive();
    }
    return inactive;
}

//void H245ProxyHandler::DumpChannels(const PString & msg, bool dumpPeer) const
//{
//	if (PTrace::CanTrace(7)) {
//		PTRACE(7, "JW === " << msg << " === DumpChannels Begin === for handler=" << this);
//        for (const_iterator iter = logicalChannels.begin(); iter != logicalChannels.end() ; ++iter) {
//            PTRACE(7, "JW LogicalChannel: flcn=" << iter->first << " port=" << iter->second->GetPort() << " this=" << iter->second);
//        }
//        for (const_siterator iter = sessionIDs.begin(); iter != sessionIDs.end() ; ++iter) {
//            PTRACE(7, "JW RTPChannel: session=" << iter->first << " port=" << iter->second->GetPort() << " type=" << iter->second->GetType() << " this=" << iter->second);
//        }
//		PTRACE(7, "JW =================== DumpChannels End ====================");
//	}
//	if (peer && dumpPeer) {
//        peer->DumpChannels(msg + " (peer)", false);
//	}
//}

RTPLogicalChannel * H245ProxyHandler::CreateRTPLogicalChannel(WORD id, WORD flcn, RTPSessionTypes sessionType)
{
	if (FindLogicalChannel(flcn)) {
		PTRACE(3, "Proxy\tRTP logical channel " << flcn << " already exist?");
		return NULL;
	}
	RTPLogicalChannel * lc = peer->FindRTPLogicalChannelBySessionID(id);

    if (!lc && ((id == 0) || (id > 2)) && m_ignoreSignaledPrivateH239IPs) {
        // look for channel with same media type
        lc = peer->FindRTPLogicalChannelBySessionType(sessionType);
    }

	if (lc && !lc->IsAttached()) {
		lc = new RTPLogicalChannel(lc, flcn, hnat != NULL, sessionType);
	} else if (!fastStartLCs.empty()) {
		// if H.245 OpenLogicalChannel is received, the fast connect procedure
		// should be disable. So we reuse the fast start logical channel here
		siterator iter = fastStartLCs.begin();
		if (!(iter->second)) {
			PTRACE(1, "Proxy\tError: Can't create RTP logical channel " << flcn << ": Invalid fastStart LC");
			SNMP_TRAP(10, SNMPWarning, Network, "Can't create RTP logical channel " + PString(PString::Unsigned, flcn));
			return NULL;
		}
		(lc = iter->second)->SetChannelNumber(flcn);
		fastStartLCs.erase(iter);
	} else if (!peer->fastStartLCs.empty()){
		siterator iter = peer->fastStartLCs.begin();
		if (!(iter->second)) {
			PTRACE(1, "Proxy\tError: Can't create RTP logical channel " << flcn << ": Invalid fastStart peer LC");
			SNMP_TRAP(10, SNMPWarning, Network, "Can't create RTP logical channel " + PString(PString::Unsigned, flcn));
			return NULL;
		}
		(lc = iter->second)->SetChannelNumber(flcn);
		lc->OnHandlerSwapped(hnat != NULL);
		peer->fastStartLCs.erase(iter);
	} else {
		lc = new RTPLogicalChannel(callid, flcn, hnat != NULL, id, sessionType);
		if (!lc->IsOpen()) {
			PTRACE(1, "Proxy\tError: Can't create RTP logical channel " << flcn);
			SNMP_TRAP(10, SNMPWarning, Network, "Can't create RTP logical channel " + PString(PString::Unsigned, flcn));
			delete lc;
			return NULL;
		}
	}

	logicalChannels[flcn] = sessionIDs[id] = lc;
	PTRACE(4, "RTP\tOpen logical channel " << flcn << " id " << id << " port " << lc->GetPort());
	return lc;
}

RTPLogicalChannel * H245ProxyHandler::CreateFastStartLogicalChannel(WORD id, RTPSessionTypes sessionType)
{
	siterator iter = fastStartLCs.find(id);
	RTPLogicalChannel * lc = (iter != fastStartLCs.end()) ? iter->second : NULL;
	if (!lc) {
		// the LogicalChannelNumber of a fastStart logical channel is irrelevant
		// it may be set later
		lc = new RTPLogicalChannel(callid, 0, hnat != NULL, id, sessionType);
		if (!lc->IsOpen()) {
			PTRACE(1, "Proxy\tError: Can't create fast start logical channel id " << id);
			SNMP_TRAP(10, SNMPWarning, Network, "Can't create fastStart logical channel " + PString(PString::Unsigned, id));
			delete lc;
			return NULL;
		}
		fastStartLCs[id] = lc;
		PTRACE(4, "RTP\tOpen fast start logical channel id " << id << " port " << lc->GetPort());
	}
	return lc;
}

T120LogicalChannel * H245ProxyHandler::CreateT120LogicalChannel(WORD flcn)
{
	if (FindLogicalChannel(flcn)) {
		PTRACE(3, "Proxy\tT120 logical channel " << flcn << " already exist?");
		return NULL;
	}
	T120LogicalChannel * lc = new T120LogicalChannel(flcn);
	logicalChannels[flcn] = lc;
	return lc;
}

bool H245ProxyHandler::RemoveLogicalChannel(WORD flcn)
{
	iterator iter = logicalChannels.find(flcn);
	if (iter == logicalChannels.end()) {
		PTRACE(3, "Proxy\tError: Logical channel " << flcn << " not found for removing");
		return false;
	}
	LogicalChannel * lc = iter->second;
	siterator i = find_if(sessionIDs.begin(), sessionIDs.end(), bind2nd(std::ptr_fun(compare_lc), lc));
	if (i != sessionIDs.end())
		sessionIDs.erase(i);
	logicalChannels.erase(iter);
	delete lc;
	return true;
}

void H245ProxyHandler::SetRequestRTPMultiplexing(bool epCanTransmitMultiplexed)
{
	m_requestRTPMultiplexing = epCanTransmitMultiplexed && m_isRTPMultiplexingEnabled && (m_traversalType != None);
}


// class NATHandler
void NATHandler::TranslateH245Address(H225_TransportAddress & h245addr)
{
	if (remoteAddr.GetVersion() == 6) {
		h245addr.SetTag(H225_TransportAddress::e_ip6Address);
		H225_TransportAddress_ip6Address & addr = h245addr;
		for (int i = 0; i < 16; ++i)
			addr.m_ip[i] = remoteAddr[i];
	} else {
		h245addr.SetTag(H225_TransportAddress::e_ipAddress);
		H225_TransportAddress_ipAddress & addr = h245addr;
		for (int i = 0; i < 4; ++i)
			addr.m_ip[i] = remoteAddr[i];
	}
}

bool NATHandler::HandleOpenLogicalChannel(H245_OpenLogicalChannel & olc)
{
	bool changed = false;
	if (IsT120Channel(olc) && olc.HasOptionalField(H245_OpenLogicalChannel::e_separateStack)) {
		if (olc.m_separateStack.m_networkAddress.GetTag() == H245_NetworkAccessParameters_networkAddress::e_localAreaAddress)
			changed = SetAddress(GetH245UnicastAddress(olc.m_separateStack.m_networkAddress));
	} else {
		bool nouse;
		if (H245_H2250LogicalChannelParameters *h225Params = GetLogicalChannelParameters(olc, nouse)) {
			if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaControlChannel))
				changed = SetAddress(GetH245UnicastAddress(h225Params->m_mediaControlChannel));
			if (h225Params->HasOptionalField(H245_H2250LogicalChannelParameters::e_mediaChannel))
				changed |= SetAddress(GetH245UnicastAddress(h225Params->m_mediaChannel));
		}
	}
	return changed;
}

bool NATHandler::HandleOpenLogicalChannelAck(H245_OpenLogicalChannelAck & olca)
{
	if (olca.HasOptionalField(H245_OpenLogicalChannelAck::e_separateStack)) {
		H245_NetworkAccessParameters & sepStack = olca.m_separateStack;
		if (sepStack.m_networkAddress.GetTag() == H245_NetworkAccessParameters_networkAddress::e_localAreaAddress)
			return SetAddress(GetH245UnicastAddress(sepStack.m_networkAddress));
	} else {
		H245_UnicastAddress *mediaControlChannel, *mediaChannel;
		GetChannelsFromOLCA(olca, mediaControlChannel, mediaChannel);
		bool changed = SetAddress(mediaChannel);
		changed = SetAddress(mediaControlChannel) || changed;
		return changed;
	}
	return false;
}

bool NATHandler::SetAddress(H245_UnicastAddress * addr)
{
	if (!ChangeAddress(addr)) {
	    if (!addr) {
			return false;
		} else {
			WORD port = GetH245Port(*addr);	// preserve port
			*addr << remoteAddr;			// set addr to remoteAddr
			SetH245Port(*addr, port);		// restore port
			return true;
	    }
	} else
		return true;
}

bool NATHandler::ChangeAddress(H245_UnicastAddress * addr)
{
	if (!addr)
		return false;

	PIPSocket::Address olcAddr;
	*addr >> olcAddr;

	// Is NATed Endpoint
	if (IsPrivate(olcAddr))
		return false;

	// if the OLC address differs from the remote NAT address
	if (remoteAddr != olcAddr)
		remoteAddr = olcAddr;

	return true;
}


// class CallSignalListener
CallSignalListener::CallSignalListener(const Address & addr, WORD pt)
{
	unsigned queueSize = GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH);
	if (!Listen(addr, queueSize, pt, PSocket::CanReuseAddress)) {
		PTRACE(1, "Q931\tCould not open Q.931 listening socket at " << AsString(addr, pt)
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< GetErrorNumber(PSocket::LastGeneralError) << ": "
			<< GetErrorText(PSocket::LastGeneralError));
		Close();
	}

	//RE - TOS - H.225 listener - callProceeding, alerting, connect etc.
	int dscp = GkConfig()->GetInteger(RoutedSec, "H225DiffServ", 0);	// default: 0
    if (dscp > 0) {
        int h225TypeOfService = (dscp << 2);
#if defined(hasIPV6) && defined(IPV6_TCLASS)
        if (addr.GetVersion() == 6) {
            // for IPv6 set TCLASS
            if (!ConvertOSError(::setsockopt(os_handle, IPPROTO_IPV6, IPV6_TCLASS, (char *)&h225TypeOfService, sizeof(int)))) {
                PTRACE(1, "Q931\tCould not set TCLASS field in IPv6 header: "
                    << GetErrorCode(PSocket::LastGeneralError) << '/'
                    << GetErrorNumber(PSocket::LastGeneralError) << ": "
                    << GetErrorText(PSocket::LastGeneralError));
            }
        } else
#endif
        {
            // setting IPTOS_PREC_CRITIC_ECP required root permission on Linux until 2008 (the 2.6.24.4), now it doesn't anymore
            // setting IP_TOS will silently fail on Windows XP, Vista and Win7, supposed to work again on Win8
            if (!ConvertOSError(::setsockopt(os_handle, IPPROTO_IP, IP_TOS, (char *)&h225TypeOfService, sizeof(int)))) {
                PTRACE(1, "Q931\tCould not set TOS field in IP header: "
                    << GetErrorCode(PSocket::LastGeneralError) << '/'
                    << GetErrorNumber(PSocket::LastGeneralError) << ": "
                    << GetErrorText(PSocket::LastGeneralError));
            }
        }
    }

	SetName(AsString(addr, GetPort()));
	if (Toolkit::Instance()->IsPortNotificationActive())
		Toolkit::Instance()->PortNotification(Q931Port, PortOpen, "tcp", addr, pt);
	m_addr = addr;
}

CallSignalListener::~CallSignalListener()
{
	if (Toolkit::Instance()->IsPortNotificationActive())
		Toolkit::Instance()->PortNotification(Q931Port, PortClose, "tcp", m_addr, port);
}

ServerSocket *CallSignalListener::CreateAcceptor() const
{
	return new CallSignalSocket();
}


#ifdef HAS_TLS
// class TLSCallSignalListener
TLSCallSignalListener::TLSCallSignalListener(const Address & addr, WORD pt) : CallSignalListener(addr, pt)
{
}

TLSCallSignalListener::~TLSCallSignalListener()
{
}

ServerSocket *TLSCallSignalListener::CreateAcceptor() const
{
	return new TLSCallSignalSocket();
}

TLSCallSignalSocket::TLSCallSignalSocket()
{
	m_ssl = NULL;
	m_lastReadCount = 0;
	m_lastWriteCount = 0;
}

TLSCallSignalSocket::TLSCallSignalSocket(CallSignalSocket * s, WORD port) : CallSignalSocket(s, port)
{
	// for outgoing call
	m_ssl = NULL;
	m_lastReadCount = 0;
	m_lastWriteCount = 0;
}

TLSCallSignalSocket::~TLSCallSignalSocket()
{
	if (m_ssl) {
		SSL_shutdown(m_ssl);
		SSL_free(m_ssl);
		m_ssl = NULL;
	}
}

bool TLSCallSignalSocket::Connect(const Address & addr)
{
	if (CallSignalSocket::Connect(addr)) {
		if (!(m_ssl = SSL_new(Toolkit::Instance()->GetTLSContext()))) {
			PTRACE(1, "TLS\tError creating SSL object");
			return false;
		}
		SSL_set_fd(m_ssl, GetHandle());
		int ret = 0;
		do {
			ret = SSL_connect(m_ssl);
			if (ret <= 0) {
				char msg[256];
				int err = SSL_get_error(m_ssl, ret);
				switch (err) {
					case SSL_ERROR_NONE:
						break;
					case SSL_ERROR_SSL:
						ERR_error_string(ERR_get_error(), msg);
						PTRACE(1, "TLS\tTLS protocol error in SSL_connect(): " << err << " / " << msg);
						SSL_shutdown(m_ssl);
						return false;
						break;
					case SSL_ERROR_SYSCALL:
						PTRACE(1, "TLS\tSyscall error in SSL_connect() errno=" << errno);
						switch (errno) {
							case 0:
								ret = 1;	// done
								break;
							case EAGAIN:
								break;
							default:
								ERR_error_string(ERR_get_error(), msg);
								PTRACE(1, "TLS\tTerminating connection: " << msg);
								SSL_shutdown(m_ssl);
								return false;
						};
						break;
					case SSL_ERROR_WANT_READ:
						// just retry
						break;
					case SSL_ERROR_WANT_WRITE:
						// just retry
						break;
					default:
						ERR_error_string(ERR_get_error(), msg);
						PTRACE(1, "TLS\tUnknown error in SSL_connect(): " << err << " / " << msg);
						SSL_shutdown(m_ssl);
						return false;
				}
			}
		} while (ret <= 0);
		// check if the certificate matches the IP
		Address raddr;
		WORD rport = 0;
		GetPeerAddress(raddr, rport);
		UnmapIPv4Address(raddr);
		if (!Toolkit::Instance()->MatchHostCert(m_ssl, raddr)) {
			SSL_shutdown(m_ssl);
			return false;
		}

		return true;
	} else {
		return false;
	}
}

PBoolean TLSCallSignalSocket::Connect(const Address & iface, WORD localPort, const Address & addr)
{
	SetName(AsString(addr, GetPort()));
	SetReadTimeout(PTimeInterval(6000));
	PBoolean result = TCPProxySocket::Connect(iface, localPort, addr);
	if (result) {
		PTimeInterval timeout(100);
		SetReadTimeout(timeout);
		SetWriteTimeout(timeout);

		if (!(m_ssl = SSL_new(Toolkit::Instance()->GetTLSContext()))) {
			PTRACE(1, "TLS\tError creating SSL object");
			return false;
		}
		SSL_set_fd(m_ssl, GetHandle());
		int ret = 0;
		do {
			ret = SSL_connect(m_ssl);
			if (ret <= 0) {
				char msg[256];
				int err = SSL_get_error(m_ssl, ret);
				switch (err) {
					case SSL_ERROR_NONE:
						break;
					case SSL_ERROR_SSL:
						ERR_error_string(ERR_get_error(), msg);
						PTRACE(1, "TLS\tTLS protocol error in SSL_connect(): " << err << " / " << msg);
						SSL_shutdown(m_ssl);
						return false;
						break;
					case SSL_ERROR_SYSCALL:
						PTRACE(1, "TLS\tSyscall error in SSL_connect() errno=" << errno);
						switch (errno) {
							case 0:
								ret = 1;	// done
								break;
							case EAGAIN:
								break;
							default:
								ERR_error_string(ERR_get_error(), msg);
								PTRACE(1, "TLS\tTerminating connection: " << msg);
								SSL_shutdown(m_ssl);
								return false;
						};
						break;
					case SSL_ERROR_WANT_READ:
						// just retry
						break;
					case SSL_ERROR_WANT_WRITE:
						// just retry
						break;
					default:
						ERR_error_string(ERR_get_error(), msg);
						PTRACE(1, "TLS\tUnknown error in SSL_connect(): " << err << " / " << msg);
						SSL_shutdown(m_ssl);
						return false;
				}
			}
		} while (ret <= 0);
		// check if the certificate matches the IP
		Address raddr;
		WORD rport = 0;
		GetPeerAddress(raddr, rport);
		UnmapIPv4Address(raddr);
		if (!Toolkit::Instance()->MatchHostCert(m_ssl, raddr)) {
			SSL_shutdown(m_ssl);
			return false;
		}

		return true;
	}
	return result;
}

bool TLSCallSignalSocket::Read(void * buf, int sz, bool /* wantZeroReads */)
{
	if (!m_ssl) {
		PTRACE(1, "TLS\tError: Not initialized");
		return false;
	}
	m_lastReadCount = 0;
	int ret = 0;
	do {
		ret = SSL_read(m_ssl, buf, sz);
		if (ret > 0) {
			m_lastReadCount += ret;
		}
		if (ret <= 0) {
			char msg[256];
			int err = SSL_get_error(m_ssl, ret);
			switch (err) {
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_SSL:
					ERR_error_string(ERR_get_error(), msg);
					PTRACE(1, "TLS\tTLS protocol error in SSL_connect(): " << err << " / " << msg);
					SSL_shutdown(m_ssl);
					return false;
					break;
				case SSL_ERROR_SYSCALL:
					PTRACE(1, "TLS\tSyscall error in SSL_read() errno=" << errno);
					switch (errno) {
						case 0:
							return false;	// done
							break;
						case EAGAIN:
							break;
						default:
							ERR_error_string(ERR_get_error(), msg);
							PTRACE(1, "TLS\tTerminating connection: " << msg);
							SSL_shutdown(m_ssl);
							return false;
					};
					break;
				case SSL_ERROR_WANT_READ:
					// just retry
					break;
				case SSL_ERROR_WANT_WRITE:
					// just retry
					break;
				default:
					ERR_error_string(ERR_get_error(), msg);
					PTRACE(1, "TLS\tUnknown error in SSL_read(): " << err << " / " << msg);
					SSL_shutdown(m_ssl);
					return false;
			}
		}
	} while (ret <= 0);
	return ret > 0;
}

bool TLSCallSignalSocket::Write(const void * buf, int sz)
{
	if (!m_ssl) {
		PTRACE(1, "TLS\tError: Not initialized");
		return false;
	}
	m_lastWriteCount = 0;
	int ret = 0;
	do {
		ret = SSL_write(m_ssl, buf, sz);
		if (ret > 0) {
			m_lastWriteCount += ret;
		}
		if (ret <= 0) {
			char msg[256];
			int err = SSL_get_error(m_ssl, ret);
			switch (err) {
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_SSL:
					ERR_error_string(ERR_get_error(), msg);
					PTRACE(1, "TLS\tTLS protocol error in SSL_connect(): " << err << " / " << msg);
					SSL_shutdown(m_ssl);
					return false;
					break;
				case SSL_ERROR_SYSCALL:
					PTRACE(1, "TLS\tSyscall error in SSL_write() errno=" << errno);
					switch (errno) {
						case 0:
							return false;	// done
							break;
						case EAGAIN:
							// just try again
							break;
						default:
							ERR_error_string(ERR_get_error(), msg);
							PTRACE(1, "TLS\tTerminating connection: " << msg);
							SSL_shutdown(m_ssl);
							return false;
					};
					break;
				case SSL_ERROR_WANT_READ:
					// just retry
					break;
				case SSL_ERROR_WANT_WRITE:
					// just retry
					break;
				default:
					ERR_error_string(ERR_get_error(), msg);
					PTRACE(1, "TLS\tUnknown error in SSL_write(): " << err << " / " << msg);
					SSL_shutdown(m_ssl);
					return false;
			}
		}
	} while (ret <= 0);
	return ret > 0;
}

void TLSCallSignalSocket::Dispatch()
{
	if (!(m_ssl = SSL_new(Toolkit::Instance()->GetTLSContext()))) {
		PTRACE(1, "TLS\tError creating SSL object");
		delete this;
		return;
	}
	SSL_set_fd(m_ssl, GetHandle());
	int ret = 0;
	do {
		ret = SSL_accept(m_ssl);
		if (ret <= 0) {
			char msg[256];
			int err = SSL_get_error(m_ssl, ret);
			switch (err) {
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_SSL:
					ERR_error_string(ERR_get_error(), msg);
					PTRACE(1, "TLS\tTLS protocol error in SSL_connect(): " << err << " / " << msg);
					SSL_shutdown(m_ssl);
					delete this;
					return;
					break;
				case SSL_ERROR_SYSCALL:
					PTRACE(1, "TLS\tSyscall error in SSL_accept() errno=" << errno);
					switch (errno) {
						case 0:
							ret = 1;	// done
							break;
						case EAGAIN:
							// just retry
							break;
						default:
							ERR_error_string(ERR_get_error(), msg);
							PTRACE(1, "TLS\tTerminating connection: " << msg);
							SSL_shutdown(m_ssl);
							delete this;
							return;
					};
					break;
				case SSL_ERROR_WANT_READ:
					// just retry
					break;
				case SSL_ERROR_WANT_WRITE:
					// just retry
					break;
				default:
					ERR_error_string(ERR_get_error(), msg);
					PTRACE(1, "TLS\tUnknown error in SSL_accept(): " << err << " / " << msg);
					SSL_shutdown(m_ssl);
					delete this;
					return;
			}
		}
	} while (ret <= 0);
	// check if the certificate matches the IP
	Address raddr;
	WORD rport = 0;
	GetPeerAddress(raddr, rport);
	UnmapIPv4Address(raddr);
	if (!Toolkit::Instance()->MatchHostCert(m_ssl, raddr)) {
		SSL_shutdown(m_ssl);
		delete this;
		return;
	}

	CallSignalSocket::Dispatch();
}

#endif // HAS_TLS


// class ProxyHandler
ProxyHandler::ProxyHandler(const PString & name)
	: SocketsReader(100), m_socketCleanupTimeout(DEFAULT_SOCKET_CLEANUP_TIMEOUT)
{
	SetName(name);
#ifdef HAS_H46017
	m_h46017Enabled = Toolkit::Instance()->Config()->GetBoolean(RoutedSec, "EnableH46017", false);
#endif
	m_proxyHandlerHighPrio = Toolkit::Instance()->Config()->GetBoolean(RoutedSec, "ProxyHandlerHighPrio", true);
	Execute();
}

ProxyHandler::~ProxyHandler()
{
	DeleteObjectsInContainer(m_removedTime);
}

void ProxyHandler::LoadConfig()
{
	m_socketCleanupTimeout = GkConfig()->GetInteger(RoutedSec, "SocketCleanupTimeout", DEFAULT_SOCKET_CLEANUP_TIMEOUT);
#ifdef HAS_H46017
	m_h46017Enabled = Toolkit::Instance()->Config()->GetBoolean(RoutedSec, "EnableH46017", false);
#endif
	m_proxyHandlerHighPrio = Toolkit::Instance()->Config()->GetBoolean(RoutedSec, "ProxyHandlerHighPrio", true);
}

void ProxyHandler::Insert(TCPProxySocket * socket)
{
	if (socket == NULL)
		return;

	ProxyHandler * h = socket->GetHandler();
	if (h == NULL) {
		socket->SetHandler(this);
		AddSocket(socket);
	} else
	h->MoveTo(this, socket);
}

void ProxyHandler::Insert(TCPProxySocket *first, TCPProxySocket *second)
{
	if (first == NULL || second == NULL)
		return;

	ProxyHandler *h = first->GetHandler();
	if (h != NULL && h != this)
		h->DetachSocket(first);
	first->SetHandler(this);
	h = second->GetHandler();
	if (h != NULL && h != this)
		h->DetachSocket(second);
	second->SetHandler(this);
	AddPairSockets(first, second);
}

void ProxyHandler::Insert(UDPProxySocket * rtp, UDPProxySocket * rtcp)
{
	AddPairSockets(rtp, rtcp);
}

void ProxyHandler::MoveTo(ProxyHandler * dest, TCPProxySocket * socket)
{
	m_listmutex.StartWrite();
	iterator iter = find(m_sockets.begin(), m_sockets.end(), socket);
	if (iter != m_sockets.end()) {
		m_sockets.erase(iter);
		--m_socksize;
	}
	m_listmutex.EndWrite();
	socket->SetHandler(dest);
	dest->AddSocket(socket);
}

void ProxyHandler::OnStart()
{
	if (m_proxyHandlerHighPrio) {
		PThread::Current()->SetPriority(PThread::HighPriority);
		// TODO: check with GetPriority() if it worked and set m_proxyHandlerHighPrio=false if it didn't so we only get 1 error message in the trace ?
	}
}

bool ProxyHandler::BuildSelectList(SocketSelectList & slist)
{
	FlushSockets();
	WriteLock lock(m_listmutex);
	iterator i = m_sockets.begin(), j = m_sockets.end();
	while (i != j) {
		iterator k=i++;
		ProxySocket *socket = dynamic_cast<ProxySocket *>(*k);
		if (socket && !socket->IsBlocked()) {
			if (socket->IsSocketOpen()) {
#ifdef _WIN32
				if (slist.GetSize() >= FD_SETSIZE) {
					PTRACE(0, "Proxy\tToo many sockets in this proxy handler "
						"(FD_SETSIZE=" << ((int)FD_SETSIZE) << ")");
					SNMP_TRAP(10, SNMPError, Network, "Too many sockets in proxy handler");
				}
#else
#ifdef LARGE_FDSET
				const int large_fdset = (int)LARGE_FDSET;
				if (socket->Self()->GetHandle() >= large_fdset) {
					PTRACE(0, "Proxy\tToo many opened file handles, skipping handle #"
						<< socket->Self()->GetHandle() << " (limit=" << large_fdset	<< ")");
					SNMP_TRAP(10, SNMPError, Network, "Too many sockets in proxy handler");
				}
#else
				if (socket->Self()->GetHandle() >= (int)FD_SETSIZE) {
					PTRACE(0, "Proxy\tToo many opened file handles, skipping handle #"
						<< socket->Self()->GetHandle() << " (limit=" << ((int)FD_SETSIZE) << ")");
					SNMP_TRAP(10, SNMPError, Network, "Too many sockets in proxy handler");
				}
#endif
#endif
				else
					slist.Append(*k);
			} else if (socket && !socket->IsConnected()) {
				Remove(k);
				continue;
			}
			if (socket && socket->IsDeletable()) {
				Remove(k);
			}
		}
	}
	return slist.GetSize() > 0;
}

// handle a new message on an existing connection
void ProxyHandler::ReadSocket(IPSocket * socket)
{
	ProxySocket * psocket = dynamic_cast<ProxySocket *>(socket);
	if (psocket == NULL) {
		PTRACE(1, "Error\tInvalid socket");
		SNMP_TRAP(10, SNMPWarning, Network, "Invalid socket");
		return;
	}
	switch (psocket->ReceiveData())
	{
		case ProxySocket::Connecting:
#ifdef HAS_H46018
			{
				CallSignalSocket * css = dynamic_cast<CallSignalSocket *>(socket);
				if (css) {
					css->PerformConnecting();
				} else {
					PTRACE(1, "Error: No CallSignalSocket ??? socket=" << socket);
					SNMP_TRAP(10, SNMPWarning, Network, "Invalid socket");
				}
			}
#else
			PTRACE(1, "Error\tcheck the code " << psocket->Type());
			SNMP_TRAP(7, SNMPError, Network, "Logic error in ReadSocket");
#endif
			break;
		case ProxySocket::DelayedConnecting:
			// do nothing - H.460.18 Facility
			break;
		case ProxySocket::Forwarding:
			if (!psocket->ForwardData()) {
				PTRACE(3, "Proxy\t" << psocket->Name() << " forward blocked");
			}
			break;
		case ProxySocket::Closing:
			{
				psocket->ForwardData();
				CallSignalSocket * css = dynamic_cast<CallSignalSocket *>(socket);
				if (css) {
					if (css->MaintainConnection()) {
						// just detach H.460.17 from the call, don't close them
						// shut down the H.245 channel for H.460.17 connection, usually done on socket delete
						H245Socket * h245socket = css->GetH245Socket();
						if (h245socket) {
							h245socket->OnSignalingChannelClosed();
							css->SetH245Socket(NULL);
						}
#ifdef HAS_H46017
						css->CleanupCall();
#endif
					}
#ifdef HAS_H46017
					css->LockRemote();
					if (css->GetRemote() && css->GetRemote()->MaintainConnection()) {
						// if the other side uses H.460.17 clean up that end of the connection
						css->GetRemote()->CleanupCall();
					}
					css->UnlockRemote();
#endif
					if (css->MaintainConnection()) {
						css->DetachRemote();
					}
				}
				if (!css || !css->MaintainConnection()) {
					// only close the Q.931 socket if it's not also used for H.460.17
					socket->Close();
				}
			}
			break;
		case ProxySocket::Error:
		    PTRACE(0, "JW ProxySocket OnError");
			psocket->OnError();
			socket->Close();
			break;
		case ProxySocket::NoData:
			break;
		default:
			break;
	}
}

#ifdef HAS_H46018
void CallSignalSocket::PerformConnecting()
{
	const int setupTimeout = PMAX(GkConfig()->GetInteger(RoutedSec, "SetupTimeout", DEFAULT_SETUP_TIMEOUT), (long)1000);

	if (InternalConnectTo()) {
		if (GkConfig()->HasKey(RoutedSec, "TcpKeepAlive"))
			remote->Self()->SetOption(SO_KEEPALIVE, Toolkit::AsBool(
				GkConfig()->GetString(RoutedSec, "TcpKeepAlive", "1")) ? 1 : 0,
				SOL_SOCKET);

		ConfigReloadMutex.EndRead();
		const bool isReadable = remote->IsReadable(2*setupTimeout);
		ConfigReloadMutex.StartRead();
		if (!isReadable) {
			PTRACE(3, "Q931\tTimed out waiting for a response to Setup or SCI message from " << remote->GetName());
			if (m_call)
				m_call->SetDisconnectCause(Q931::TimerExpiry);
			OnError();
		}
		GetHandler()->Insert(this, remote);
		return;
	} else if (m_call && m_call->MoveToNextRoute() && (m_h245socket == NULL || m_call->DisableRetryChecks())) {
		PTRACE(3, "Q931\t" << AsString(peerAddr, peerPort) << " DIDN'T ACCEPT THE CALL");
		if (m_call) {
			m_call->SetCallSignalSocketCalled(NULL);
			m_call->SetDisconnectCause(Q931::NoRouteToDestination);
			m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
			m_call->SetDisconnectTime(time(NULL));
		}

		RemoveH245Handler();

		CallRec *newCall = new CallRec(m_call.operator ->());
		CallTable::Instance()->RemoveFailedLeg(m_call);
		m_call = callptr(newCall);

		if (newCall->GetNewRoutes().empty()) {
			PTRACE(1, "Q931\tERROR: PerformConnecting() without a route");
			SNMP_TRAP(10, SNMPWarning, Network, "Connecting without a route");
			return;
		}

		const Route & newRoute = m_call->GetNewRoutes().front();
		PTRACE(1, "Q931\tNew route: " << newRoute.AsString());

		if (newRoute.m_destEndpoint)
			m_call->SetCalled(newRoute.m_destEndpoint);
		else
			m_call->SetDestSignalAddr(newRoute.m_destAddr);

		if (newRoute.m_flags & Route::e_toParent)
			m_call->SetToParent(true);
		if (newRoute.m_useTLS)
			m_call->SetConnectWithTLS(true);

		if (!newRoute.m_destNumber.IsEmpty()) {
			H225_ArrayOf_AliasAddress destAlias;
			destAlias.SetSize(1);
			H323SetAliasAddress(newRoute.m_destNumber, destAlias[0]);
			newCall->SetRouteToAlias(destAlias);
		}

		CallTable::Instance()->Insert(newCall);

		m_remoteLock.Wait();
		if (remote != NULL) {
			remote->RemoveRemoteSocket();
			delete remote;
			remote = NULL;
		}
		m_remoteLock.Signal();

		buffer = m_rawSetup;
		buffer.MakeUnique();

		ReadUnlock unlock(ConfigReloadMutex);
		DispatchNextRoute();
		return;
	} else {
		PTRACE(3, "Q931\t" << AsString(peerAddr, peerPort) << " DIDN'T ACCEPT THE CALL");
		SendReleaseComplete(H225_ReleaseCompleteReason::e_unreachableDestination);
		if (m_call) {
			m_call->SetCallSignalSocketCalled(NULL);
			m_call->SetReleaseSource(CallRec::ReleasedByGatekeeper);
		}
		CallTable::Instance()->RemoveCall(m_call);
		m_remoteLock.Wait();
		delete remote;
		remote = NULL;
		m_remoteLock.Signal();
		TCPProxySocket::EndSession();
		return;
	}
}
#endif

void ProxyHandler::CleanUp()
{
	if (m_rmsize > 0) {
		PTime now;
		PWaitAndSignal lock(m_rmutex);
		while (!m_removed.empty() && (now - **m_removedTime.begin()) >= m_socketCleanupTimeout) {
			IPSocket * s = *m_removed.begin();
			PTime * t = *m_removedTime.begin();
			m_removed.erase(m_removed.begin());
			m_removedTime.erase(m_removedTime.begin());
#ifdef HAS_H46017
			if (m_h46017Enabled) {
				CallSignalSocket * css = dynamic_cast<CallSignalSocket *>(s);
				if (css) {
					// if this is a H.460.17 socket, make sure its removed from the EPRec
					RegistrationTable::Instance()->OnNATSocketClosed(css);
					css->CleanupCall();
				}
			}
#endif
			delete s;
			delete t;
			--m_rmsize;
		}
	}
}

void ProxyHandler::AddPairSockets(IPSocket *first, IPSocket *second)
{
	m_listmutex.StartWrite();
	iterator iter = find(m_sockets.begin(), m_sockets.end(), first);
	if (iter == m_sockets.end()) {
		m_sockets.push_back(first);
		++m_socksize;
	} else {
		PTRACE(1, GetName() << "\tTrying to add an already existing socket to the handler");
	}
	iter = find(m_sockets.begin(), m_sockets.end(), second);
	if (iter == m_sockets.end()) {
		m_sockets.push_back(second);
		++m_socksize;
	} else {
		PTRACE(1, GetName() << "\tTrying to add an already existing socket to the handler");
	}
	m_listmutex.EndWrite();
	Signal();
	PTRACE(5, GetName() << " total sockets " << m_socksize);
}

void ProxyHandler::FlushSockets()
{
	SocketSelectList wlist(GetName());
	m_listmutex.StartRead();
	iterator i = m_sockets.begin(), j = m_sockets.end();
	while (i != j) {
		ProxySocket * s = dynamic_cast<ProxySocket *>(*i);
		if (s == NULL) {
			PTRACE(1, "Proxy\tCast of proxy socket failed");
			SNMP_TRAP(7, SNMPError, Network, "Socket error");
			++i;    // skip to next socket, make sure we don't get endless loop
			continue;
		}
		if (s->CanFlush()) {
#ifdef _WIN32
			if (wlist.GetSize() >= FD_SETSIZE) {
				PTRACE(0, "Proxy\tToo many sockets in this proxy handler "
					"(limit=" << ((int)FD_SETSIZE) << ")");
				SNMP_TRAP(10, SNMPError, Network, "Out of sockets");
			}
#else
#ifdef LARGE_FDSET
			const int large_fdset = (int)LARGE_FDSET;
			if ((*i)->GetHandle() >= large_fdset) {
				PTRACE(0, "Proxy\tToo many opened file handles, skipping handle #"
					<< (*i)->GetHandle() << " (limit=" << large_fdset << ")");
				SNMP_TRAP(10, SNMPError, Network, "Out of sockets");
			}
#else
			if ((*i)->GetHandle() >= (int)FD_SETSIZE) {
				PTRACE(0, "Proxy\tToo many opened file handles, skipping handle #"
					<< (*i)->GetHandle() << " (limit=" << ((int)FD_SETSIZE) << ")");
				SNMP_TRAP(10, SNMPError, Network, "Out of sockets");
			}
#endif
#endif
			else
				wlist.Append(*i);
		}
		++i;
	}
	m_listmutex.EndRead();
	if (wlist.IsEmpty())
		return;

	if (!wlist.Select(SocketSelectList::Write, PTimeInterval(10)))
	       return;

	PTRACE(5, "Proxy\t" << wlist.GetSize() << " sockets to flush...");
	for (int k = 0; k < wlist.GetSize(); ++k) {
		ProxySocket *socket = dynamic_cast<ProxySocket *>(wlist[k]);
		if (socket && socket->Flush()) {
			PTRACE(4, "Proxy\t" << socket->Name() << " flush ok");
		}
	}
}

void ProxyHandler::Remove(iterator i)
{
	// assume the list is locked for writing
	IPSocket *socket = *i;
	m_sockets.erase(i);
	--m_socksize;

	PWaitAndSignal lock(m_rmutex);
	// avoid double insert
	if (find(m_removed.begin(), m_removed.end(), socket) == m_removed.end()) {
		m_removed.push_back(socket);
		m_removedTime.push_back(new PTime);
		++m_rmsize;
	}
}

void ProxyHandler::Remove(TCPProxySocket *socket)
{
	m_listmutex.StartWrite();
	iterator i = find(m_sockets.begin(), m_sockets.end(), socket);
	if (i != m_sockets.end()) {
		m_sockets.erase(i);
		--m_socksize;
	}
	m_listmutex.EndWrite();

	PWaitAndSignal lock(m_rmutex);
	// avoid double insert
	if (find(m_removed.begin(), m_removed.end(), socket) == m_removed.end()) {
		m_removed.push_back(socket);
		m_removedTime.push_back(new PTime);
		++m_rmsize;
	}
}

bool ProxyHandler::Detach(TCPProxySocket *socket)
{
	bool detached = false;

	m_listmutex.StartWrite();
	iterator i = find(m_sockets.begin(), m_sockets.end(), socket);
	if (i != m_sockets.end()) {
		m_sockets.erase(i);
		--m_socksize;
		detached = true;
	}
	m_listmutex.EndWrite();

	return detached;
}

void ProxyHandler::DetachSocket(IPSocket *socket)
{
	m_listmutex.StartWrite();
	iterator iter = find(m_sockets.begin(), m_sockets.end(), socket);
	if (iter != m_sockets.end()) {
		ProxySocket * psock = dynamic_cast<ProxySocket*>(socket);
		if (psock)
			psock->SetHandler(NULL);
		m_sockets.erase(iter);
		--m_socksize;
	} else
		PTRACE(1, GetName() << "\tTrying to detach a socket that does not belong to any handler");
	m_listmutex.EndWrite();
	Signal();
	PTRACE(5, GetName() << "\tTotal sockets: " << m_socksize);
}

// class HandlerList
HandlerList::HandlerList() : m_numSigHandlers(0), m_numRtpHandlers(0),
	m_currentSigHandler(0), m_currentRtpHandler(0)
{
	LoadConfig();
}

HandlerList::~HandlerList()
{
	PWaitAndSignal lock(m_handlerMutex);
	ForEachInContainer(m_sigHandlers, mem_vfun(&ProxyHandler::Stop));
	ForEachInContainer(m_rtpHandlers, mem_vfun(&ProxyHandler::Stop));
}

ProxyHandler * HandlerList::GetSigHandler()
{
	PWaitAndSignal lock(m_handlerMutex);
	// round-robin
	ProxyHandler* const result = m_sigHandlers[m_currentSigHandler];
	if (++m_currentSigHandler >= m_numSigHandlers)
		m_currentSigHandler = 0;
	return result;
}

ProxyHandler * HandlerList::GetRtpHandler()
{
	PWaitAndSignal lock(m_handlerMutex);
	// round-robin
	ProxyHandler* const result = m_rtpHandlers[m_currentRtpHandler];
	if (++m_currentRtpHandler >= m_numRtpHandlers)
		m_currentRtpHandler = 0;
	return result;
}

void HandlerList::LoadConfig()
{
	PWaitAndSignal lock(m_handlerMutex);

	Q931PortRange.LoadConfig(RoutedSec, "Q931PortRange");
	H245PortRange.LoadConfig(RoutedSec, "H245PortRange");
	T120PortRange.LoadConfig(ProxySection, "T120PortRange");
	RTPPortRange.LoadConfig(ProxySection, "RTPPortRange", "1024-65535");

	m_numSigHandlers = GkConfig()->GetInteger(RoutedSec, "CallSignalHandlerNumber", 5); // update gk.cxx when changing default
	if (m_numSigHandlers < 1)
		m_numSigHandlers = 1;
	if (m_numSigHandlers > MAX_HANDLER_NUMBER)
		m_numSigHandlers = MAX_HANDLER_NUMBER;
	unsigned hs = m_sigHandlers.size();
	if (hs <= m_numSigHandlers) {
		for (unsigned i = hs; i < m_numSigHandlers; ++i)
			m_sigHandlers.push_back(new ProxyHandler(psprintf(PString("ProxyH(%d)"), i)));
	} else {
		m_currentSigHandler = 0;
	}

	m_numRtpHandlers = GkConfig()->GetInteger(RoutedSec, "RtpHandlerNumber", 1);    // update gk.cxx when changing default
	if (m_numRtpHandlers < 1)
		m_numRtpHandlers = 1;
	if (m_numRtpHandlers > MAX_HANDLER_NUMBER)
		m_numRtpHandlers = MAX_HANDLER_NUMBER;
	hs = m_rtpHandlers.size();
	if (hs <= m_numRtpHandlers) {
		for (unsigned i = hs; i < m_numRtpHandlers; ++i)
			m_rtpHandlers.push_back(new ProxyHandler(psprintf(PString("ProxyRTP(%d)"), i)));
	} else {
		m_currentRtpHandler = 0;
	}

	std::vector<ProxyHandler *>::const_iterator i = m_sigHandlers.begin();
	while (i != m_sigHandlers.end())
		(*i++)->LoadConfig();

	i = m_rtpHandlers.begin();
	while (i != m_rtpHandlers.end())
		(*i++)->LoadConfig();
}
