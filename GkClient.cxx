//////////////////////////////////////////////////////////////////
//
// GkClient.cxx
//
// Copyright (c) Citron Network Inc. 2001-2003
// Copyright (c) 2002-2018, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "config.h"
#include <ptlib.h>
#include <h323pdu.h>
#include <h235auth.h>
#include "stl_supp.h"
#include "RasPDU.h"
#include "RasSrv.h"
#include "ProxyChannel.h"
#include "h323util.h"
#include "sigmsg.h"
#include "cisco.h"
#include "GkClient.h"

#ifdef HAS_H460
#include <h460/h4601.h>
#endif

#ifdef HAS_H46023
#include <h460/h46024b.h>
#include <ptclib/pstun.h>
#include <ptclib/random.h>
#include <ptclib/cypher.h>
#endif

#if P_DNS
#include <ptclib/pdns.h>
#endif

using std::vector;
using std::multimap;
using std::make_pair;
using std::for_each;
using std::mem_fun;
using std::bind1st;
using Routing::Route;

namespace {
const char* const EndpointSection = "Endpoint";
const char* const RewriteE164Section = "Endpoint::RewriteE164";
}

bool IsOIDForAlgo(const PString & oid, const PCaselessString & algo)
{
    if (algo == "MD5" && oid == OID_H235_MD5) {
        return true;
    };
    if ( algo == "CAT" && oid == OID_H235_CAT) {
        return true;
    };
    if (algo == "H.235.1"
        && (oid == OID_H235_A_V1 || oid == OID_H235_A_V2 || oid == OID_H235_T_V1 || oid == OID_H235_T_V2 || oid == OID_H235_U_V1 || oid == OID_H235_U_V2)) {
        return true;
    };

    return false;
}


class AlternateGKs {
public:
	AlternateGKs(const PIPSocket::Address &, WORD);
	void Set(const H225_AlternateGK &);
	void Set(const H225_ArrayOf_AlternateGK &);
	void Set(const PString &);
	bool Get(PIPSocket::Address &, WORD &);

private:
    /* No copy constructor allowed */
	AlternateGKs(const AlternateGKs &);
	/* No operator= allowed */
	AlternateGKs & operator=(const AlternateGKs &);

	typedef multimap<int, H225_TransportAddress> GKList;
	GKList AltGKs;
	GKList::iterator index;
	PIPSocket::Address pgkaddr;
	WORD pgkport;
};

AlternateGKs::AlternateGKs(const PIPSocket::Address & gkaddr, WORD gkport)
	: pgkaddr(gkaddr), pgkport(gkport)
{
}

void AlternateGKs::Set(const H225_AlternateGK & agk)
{
	AltGKs.clear();
	AltGKs.insert(make_pair(int(agk.m_priority), agk.m_rasAddress));
	index = AltGKs.begin();
}

void AlternateGKs::Set(const H225_ArrayOf_AlternateGK & agk)
{
	AltGKs.clear();
	for (PINDEX i = 0; i < agk.GetSize(); ++i) {
		const H225_AlternateGK & gk = agk[i];
		AltGKs.insert(make_pair(int(gk.m_priority), gk.m_rasAddress));
	}
	index = AltGKs.begin();
}

void AlternateGKs::Set(const PString & addr)
{
	PIPSocket::Address gkaddr;
	WORD gkport;
	if (GetTransportAddress(addr, GK_DEF_UNICAST_RAS_PORT, gkaddr, gkport)) {
		H323TransportAddress taddr(gkaddr, gkport);
		H225_TransportAddress haddr;
		taddr.SetPDU(haddr);
		AltGKs.insert(make_pair(AltGKs.size()+1, haddr));
	}
}

bool AlternateGKs::Get(PIPSocket::Address & gkaddr, WORD & gkport)
{
	if (!AltGKs.empty()) {
		if (index == AltGKs.end()) {
			index = AltGKs.begin();
			// switch back to original GK
			gkaddr = pgkaddr;
			gkport = (WORD)pgkport;
			return false;
		}

		const H225_TransportAddress & rasAddress = (index++)->second;
		if (GetIPAndPortFromTransportAddr(rasAddress, gkaddr, gkport))
			return true;
		PTRACE(3, "GKC\tInvalid AlternateGK Address!");
		return Get(gkaddr, gkport); // try next
	}
	return false;
}


class NATClient : public RegularJob {
public:
	NATClient(const H225_TransportAddress &, const H225_EndpointIdentifier &);

	// override from class RegularJob
	virtual void Stop();

private:
	// override from class Task
	virtual void Exec();

	bool DetectIncomingCall();
	void SendInfo(int);

	PIPSocket::Address gkip;
	WORD gkport;
	PString endpointId;
	CallSignalSocket * socket;
};

NATClient::NATClient(const H225_TransportAddress & addr, const H225_EndpointIdentifier & id)
{
    gkport = 0; // make sure port gets initialized, even if addr is invalid
	GetIPAndPortFromTransportAddr(addr, gkip, gkport);
	endpointId = id.GetValue();
	socket = NULL;
	SetName("NATClient");
	Execute();
}

void NATClient::Stop()
{
	PWaitAndSignal lock(m_deletionPreventer);
	RegularJob::Stop();
	if (socket) {
		SendInfo(Q931::CallState_DisconnectRequest);
		socket->Close();
	}
}

void NATClient::Exec()
{
	ReadLock lockConfig(ConfigReloadMutex);

#ifdef HAS_TLS
	if (GkConfig()->GetBoolean(EndpointSection, "UseTLS", false)) {
		socket = new TLSCallSignalSocket();
	} else
#endif
	{
		socket = new CallSignalSocket();
	}
	socket->SetPort(gkport);
	if (socket->Connect(gkip)) {
		PTRACE(2, "GKC\t" << socket->GetName() << " connected, waiting for incoming call");
		if (DetectIncomingCall()) {
			PTRACE(3, "GKC\tIncoming call detected");
			CreateJob(socket, &CallSignalSocket::Dispatch, "NAT call");
			socket = NULL;
			return;
		}
	}
	PWaitAndSignal lockDeletion(m_deletionPreventer);
	delete socket;
	socket = NULL;
	// If we lose the TCP connection then retry after 60 sec
	int retryInterval = GkConfig()->GetInteger(EndpointSection, "NATRetryInterval", 60);
	PTRACE(4, "GKC\tNAT Socket connection lost " << gkip << " retry connection in " << retryInterval << " secs.");

	ReadUnlock unlockConfig(ConfigReloadMutex);
	Wait(retryInterval * 1000);
}

bool NATClient::DetectIncomingCall()
{
	while (socket->IsOpen()) {
        // keep alive interval must be less than 30 sec (from testing 20 sec seems fine)
		long retry = GkConfig()->GetInteger(EndpointSection, "NATKeepaliveInterval", 20);
		SendInfo(Q931::CallState_IncomingCallProceeding);

		ReadUnlock unlockConfig(ConfigReloadMutex);
		while (socket->IsOpen() && --retry > 0)
			if (socket->IsReadable(1000)) // one second
				return socket->IsOpen();
	}
	return false;
}

void NATClient::SendInfo(int state)
{
	Q931 information;
	information.BuildInformation(0, false);
	PBYTEArray buf, epid(endpointId, endpointId.GetLength(), false);
	information.SetIE(Q931::FacilityIE, epid);
	information.SetCallState(Q931::CallStates(state));
	information.Encode(buf);
	if (socket) {
		PrintQ931(5, "Send to ", socket->GetName(), &information, NULL);
		socket->TransmitData(buf);
	}
}

//////////////////////////////////////////////////////////////////////

#ifdef HAS_H46023

// stuff cut from pstun.cxx

#pragma pack(1)

struct STUNattribute
{
  enum Types {
    MAPPED_ADDRESS = 0x0001,
    RESPONSE_ADDRESS = 0x0002,
    CHANGE_REQUEST = 0x0003,
    SOURCE_ADDRESS = 0x0004,
    CHANGED_ADDRESS = 0x0005,
    USERNAME = 0x0006,
    PASSWORD = 0x0007,
    MESSAGE_INTEGRITY = 0x0008,
    ERROR_CODE = 0x0009,
    UNKNOWN_ATTRIBUTES = 0x000a,
    REFLECTED_FROM = 0x000b,
    MaxValidCode
  };

  PUInt16b type;
  PUInt16b length;

  STUNattribute * GetNext() const { return (STUNattribute *)(((const BYTE *)this)+length+4); }
};

class STUNaddressAttribute : public STUNattribute
{
public:
  BYTE     pad;
  BYTE     family;
  PUInt16b port;
  BYTE     ip[4];

  PIPSocket::Address GetIP() const { return PIPSocket::Address(4, ip); }

protected:
  enum { SizeofAddressAttribute = sizeof(BYTE)+sizeof(BYTE)+sizeof(WORD)+sizeof(PIPSocket::Address) };
  void InitAddrAttr(Types newType)
  {
    type = (WORD)newType;
    length = SizeofAddressAttribute;
    pad = 0;
    family = 1;
  }
  bool IsValidAddrAttr(Types checkType) const
  {
    return type == checkType && length == SizeofAddressAttribute;
  }
};

class STUNmappedAddress : public STUNaddressAttribute
{
public:
  void Initialise() { InitAddrAttr(MAPPED_ADDRESS); }
  bool IsValid() const { return IsValidAddrAttr(MAPPED_ADDRESS); }
};

class STUNchangedAddress : public STUNaddressAttribute
{
public:
  void Initialise() { InitAddrAttr(CHANGED_ADDRESS); }
  bool IsValid() const { return IsValidAddrAttr(CHANGED_ADDRESS); }
};

class STUNchangeRequest : public STUNattribute
{
public:
  BYTE flags[4];

  STUNchangeRequest(bool changeIP, bool changePort)
  {
    Initialise();
    SetChangeIP(changeIP);
    SetChangePort(changePort);
  }

  void Initialise()
  {
    type = CHANGE_REQUEST;
    length = sizeof(flags);
    memset(flags, 0, sizeof(flags));
  }
  bool IsValid() const { return type == CHANGE_REQUEST && length == sizeof(flags); }

  bool GetChangeIP() const { return (flags[3]&4) != 0; }
  void SetChangeIP(bool on) { if (on) flags[3] |= 4; else flags[3] &= ~4; }

  bool GetChangePort() const { return (flags[3]&2) != 0; }
  void SetChangePort(bool on) { if (on) flags[3] |= 2; else flags[3] &= ~2; }
};

class STUNmessageIntegrity : public STUNattribute
{
public:
  BYTE hmac[20];

  void Initialise()
  {
    type = MESSAGE_INTEGRITY;
    length = sizeof(hmac);
    memset(hmac, 0, sizeof(hmac));
  }
  bool IsValid() const { return type == MESSAGE_INTEGRITY && length == sizeof(hmac); }
};

struct STUNmessageHeader
{
  PUInt16b       msgType;
  PUInt16b       msgLength;
  BYTE           transactionId[16];
};


#pragma pack()

class STUNmessage : public PBYTEArray
{
public:
  enum MsgType {
    BindingRequest  = 0x0001,
    BindingResponse = 0x0101,
    BindingError    = 0x0111,

    SharedSecretRequest  = 0x0002,
    SharedSecretResponse = 0x0102,
    SharedSecretError    = 0x0112,
  };

  STUNmessage() { }

  STUNmessage(MsgType newType, const BYTE * id = NULL)
    : PBYTEArray(sizeof(STUNmessageHeader))
  {
    SetType(newType, id);
  }

  void SetType(MsgType newType, const BYTE * id = NULL)
  {
    SetMinSize(sizeof(STUNmessageHeader));
    STUNmessageHeader * hdr = (STUNmessageHeader *)theArray;
    hdr->msgType = (WORD)newType;
    for (PINDEX i = 0; i < ((PINDEX)sizeof(hdr->transactionId)); i++)
      hdr->transactionId[i] = id != NULL ? id[i] : (BYTE)PRandom::Number();
  }

  const STUNmessageHeader * operator->() const { return (STUNmessageHeader *)theArray; }

// ignore overflow warning when comparing length
#if (!_WIN32) && (GCC_VERSION >= 40400)
#pragma GCC diagnostic ignored "-Wstrict-overflow"
#endif

  STUNattribute * GetFirstAttribute()
  {
    if (theArray == NULL)
      return NULL;
    int length = ((STUNmessageHeader *)theArray)->msgLength;
    if (length < (int) sizeof(STUNmessageHeader))
      return NULL;

    STUNattribute * attr = (STUNattribute *)(theArray+sizeof(STUNmessageHeader));
    STUNattribute * ptr = attr;

    if (attr->length > GetSize() || attr->type >= STUNattribute::MaxValidCode)
      return NULL;

    while (ptr && (BYTE*) ptr < (BYTE*)(theArray+GetSize()) && length >= (int) ptr->length+4) {
        length -= ptr->length + 4;
        ptr = ptr->GetNext();
    }

    if (length != 0)
      return NULL;

    return attr;
  }

  bool Validate()
  {
    int length = ((STUNmessageHeader *)theArray)->msgLength;
    STUNattribute * attrib = GetFirstAttribute();
    while (attrib && length > 0) {
      length -= attrib->length + 4;
      attrib = attrib->GetNext();
    }

    return length == 0;  // Exactly correct length
  }

  void AddAttribute(const STUNattribute & attribute)
  {
    STUNmessageHeader * hdr = (STUNmessageHeader *)theArray;
    int oldLength = hdr->msgLength;
    int attrSize = attribute.length + 4;
    int newLength = oldLength + attrSize;
    hdr->msgLength = (WORD)newLength;
    // hdr pointer may be invalidated by next statement
    SetMinSize(newLength+sizeof(STUNmessageHeader));
    memcpy(theArray+sizeof(STUNmessageHeader)+oldLength, &attribute, attrSize);
  }

  void SetAttribute(const STUNattribute & attribute)
  {
    int length = ((STUNmessageHeader *)theArray)->msgLength;
    STUNattribute * attrib = GetFirstAttribute();
    while (length > 0) {
      if (attrib->type == attribute.type) {
        if (attrib->length == attribute.length)
          *attrib = attribute;
        else {
          // More here
        }
        return;
      }

      length -= attrib->length + 4;
      attrib = attrib->GetNext();
    }

    AddAttribute(attribute);
  }

  STUNattribute * FindAttribute(STUNattribute::Types type)
  {
    int length = ((STUNmessageHeader *)theArray)->msgLength;
    STUNattribute * attrib = GetFirstAttribute();
    while (length > 0) {
      if (attrib->type == type)
        return attrib;

      length -= attrib->length + 4;
      attrib = attrib->GetNext();
    }
    return NULL;
  }


  bool Read(UDPSocket & socket)
  {
    if (!socket.Read(GetPointer(1000), 1000))
      return false;
    SetSize(socket.GetLastReadCount());
    return true;
  }

  bool Write(UDPSocket & socket) const
  {
    return socket.Write(theArray, ((STUNmessageHeader *)theArray)->msgLength+sizeof(STUNmessageHeader)) != FALSE;
  }

  bool Poll(UDPSocket & socket, const STUNmessage & request, PINDEX pollRetries)
  {
    for (PINDEX retry = 0; retry < pollRetries; retry++) {
      if (!request.Write(socket))
        break;

      if (Read(socket) && Validate() &&
            memcmp(request->transactionId, (*this)->transactionId, sizeof(request->transactionId)) == 0)
        return true;
    }

    return false;
  }
};

//

class STUNsocket : public UDPProxySocket
{
public:
    STUNsocket(const char * t, PINDEX callNo);
#ifdef LARGE_FDSET
	// the YaSocket based UDPSocket has a const GetLocalAddress()
	virtual PBoolean GetLocalAddress(PIPSocket::Address &) const;
	virtual PBoolean GetLocalAddress(PIPSocket::Address &, WORD &) const;
#else
	// the PTLib based UDPSocket has a non-const GetLocalAddress()
	virtual PBoolean GetLocalAddress(PIPSocket::Address &);
	virtual PBoolean GetLocalAddress(PIPSocket::Address &, WORD &);
#endif

	PIPSocket::Address externalIP;
};

STUNsocket::STUNsocket(const char * t, PINDEX callNo)
  : UDPProxySocket(t, callNo), externalIP(0)
{
}


#ifdef LARGE_FDSET
PBoolean STUNsocket::GetLocalAddress(PIPSocket::Address & addr) const
#else
PBoolean STUNsocket::GetLocalAddress(PIPSocket::Address & addr)
#endif
{
  if (!externalIP.IsValid())
    return UDPSocket::GetLocalAddress(addr);

  addr = externalIP;
  return true;
}


#ifdef LARGE_FDSET
PBoolean STUNsocket::GetLocalAddress(PIPSocket::Address & addr, WORD & port) const
#else
PBoolean STUNsocket::GetLocalAddress(PIPSocket::Address & addr, WORD & port)
#endif
{
  if (!externalIP.IsValid())
     return UDPSocket::GetLocalAddress(addr, port);

  addr = externalIP;
  port = GetPort();
  return true;
}

//////

struct STUNportRange
{
	STUNportRange() :  minport(0), maxport(0) {}
	void LoadConfig(const char *, const char *, const char * = "");

	WORD minport, maxport;
};

void STUNportRange::LoadConfig(const char *sec, const char *setting, const char *def)
{
	PStringArray cfgs = GkConfig()->GetString(sec, setting, def).Tokenise(",.:-/'", FALSE);
	if (cfgs.GetSize() >= 2) {
		minport = (WORD)cfgs[0].AsUnsigned();
		maxport = (WORD)cfgs[1].AsUnsigned();
	}

	PTRACE(3, "STUN\tPort range set " << ": " << minport << '-' << maxport);
}

//////

class STUNClient	:  public  Job,
						public PSTUNClient
{
 public:
	STUNClient(GkClient * _client, const H323TransportAddress &);
	virtual ~STUNClient();

#if PTLIB_VER >= 2130
	struct PortInfo {
	PortInfo(WORD port = 0)
	: basePort(port), maxPort(port), currentPort(port) {}
		PMutex mutex;
		WORD	basePort;
		WORD	maxPort;
		WORD	currentPort;
	};
#endif

	virtual void Stop();

	virtual void Run();

	virtual bool CreateSocketPair(
			PINDEX callNo,
			UDPProxySocket * & rtp,
			UDPProxySocket * & rtcp,
			const PIPSocket::Address & binding = PIPSocket::GetDefaultIpAny()
	);

protected:
#if PTLIB_VER >= 2130
	PortInfo pairedPortInfo;
#endif
	bool OpenSocketA(UDPSocket & socket, PortInfo & portInfo, const PIPSocket::Address & binding);

private:
	// override from class Task
	virtual void Exec();
	// Callback
	void OnDetectedNAT(int m_nattype);

	GkClient *			m_client;
	NatTypes			m_nattype;
	bool				m_shutdown;
	PMutex				m_portCreateMutex;
	int					m_socketsForPairing;
	int					m_pollRetries;
};

STUNClient::STUNClient(GkClient * _client, const H323TransportAddress & addr)
:  m_client(_client), m_nattype(UnknownNat), m_shutdown(false),
   m_socketsForPairing(4), m_pollRetries(3)
{
	PIPSocket::Address ip;
	WORD port = 0;
	addr.GetIpAndPort(ip, port);
#ifdef hasNewSTUN
	m_serverAddress = PIPSocketAddressAndPort(ip, port);
#else
	SetServer(ip, port);
#endif

	STUNportRange ports;
	ports.LoadConfig("Proxy", "RTPPortRange", "1024-65535");
	SetPortRanges(ports.minport, ports.maxport, ports.minport, ports.maxport);

	SetName("STUNClient");
	Execute();
}

STUNClient::~STUNClient()
{
    Stop();
}

void STUNClient::Stop()
{
	Job::Stop();

	// disconnect from STUN Server
	m_shutdown = true;
}

void STUNClient::Run()
{
    Exec();
}

void STUNClient::Exec()
{
	ReadLock lockConfig(ConfigReloadMutex);

	// Wait 500 ms until the RCF has been processed before running tests
	// to prevent blocking.
	PThread::Sleep(500);

	// Get a valid NAT type....
	m_nattype = GetNatType(TRUE);

	OnDetectedNAT(m_nattype);
	ReadUnlock unlockConfig(ConfigReloadMutex);	// make sure the STUN client doesn't permanently hog the mutex

	// Keep this job (thread) open so that creating STUN ports does not hold up
	// the processing of other calls
	while (!m_shutdown) {
		PThread::Sleep(100);
	}
}

void STUNClient::OnDetectedNAT(int nattype)
{
	PTRACE(3, "STUN\tDetected NAT as type " << nattype << " " << GetNatTypeString((NatTypes)nattype));

	// Call back to signal the GKClient to do a lightweight reregister
	// to notify the gatekeeper
    m_client->H46023_TypeDetected(nattype);
}

#ifdef hasNewSTUN
bool STUNClient::OpenSocketA(UDPSocket & socket, PortInfo & portInfo, const PIPSocket::Address & binding)
{
	if (!m_serverAddress.IsValid()) {
		PTRACE(1, "STUN\tServer port not set.");
		return false;
	}

	if (portInfo.basePort == 0) {
		if (!socket.Listen(binding, 1)) {
			PTRACE(3, "STUN\tCannot bind port to " << m_interface);
			return false;
		}
	} else {
		WORD startPort = portInfo.currentPort;
		PTRACE(3, "STUN\tUsing ports " << portInfo.basePort << " through " << portInfo.maxPort << " starting at " << startPort);
		for (;;) {
			bool status = socket.Listen(binding, 1, portInfo.currentPort);
			PWaitAndSignal mutex(portInfo.mutex);
			portInfo.currentPort++;
			if (portInfo.currentPort > portInfo.maxPort)
				portInfo.currentPort = portInfo.basePort;
			if (status)
				break;
			if (portInfo.currentPort == startPort) {
				PTRACE(3, "STUN\tListen failed on " << AsString(m_interface, portInfo.currentPort));
				SNMP_TRAP(7, SNMPError, Network, "STUN failure");
				return false;
			}
		}
	}

	socket.SetSendAddress(m_serverAddress.GetAddress(), m_serverAddress.GetPort());

	return true;
}
#else
bool STUNClient::OpenSocketA(UDPSocket & socket, PortInfo & portInfo, const PIPSocket::Address & binding)
{
	if (serverPort == 0) {
		PTRACE(1, "STUN\tServer port not set.");
		return false;
	}

	if (!PIPSocket::GetHostAddress(serverHost, cachedServerAddress) || !cachedServerAddress.IsValid()) {
		PTRACE(2, "STUN\tCould not find host \"" << serverHost << "\".");
		return false;
	}

	PWaitAndSignal mutex(portInfo.mutex);

	WORD startPort = portInfo.currentPort;

	do {
		portInfo.currentPort++;
		if (portInfo.currentPort > portInfo.maxPort)
			portInfo.currentPort = portInfo.basePort;

		if (socket.Listen(binding, 1, portInfo.currentPort)) {
			socket.SetSendAddress(cachedServerAddress, serverPort);
			socket.SetReadTimeout(replyTimeout);
			return true;
		}
	} while (portInfo.currentPort != startPort);

	PTRACE(1, "STUN\tFailed to bind to local UDP port in range "
		<< portInfo.currentPort << '-' << portInfo.maxPort);
	SNMP_TRAP(7, SNMPError, Network, "STUN failure");
	return false;
}
#endif

bool STUNClient::CreateSocketPair(PINDEX callNo, UDPProxySocket * & rtp, UDPProxySocket * & rtcp, const PIPSocket::Address & binding)
{
	// We only create port pairs, a pair at a time.
	PWaitAndSignal m(m_portCreateMutex);

	rtp = NULL;
	rtcp = NULL;

	if (GetNatType(FALSE) != ConeNat) {
		PTRACE(1, "STUN\tCannot create socket pair using NAT type " << GetNatTypeName());
		return FALSE;
	}

	PINDEX i;

	PList<STUNsocket> stunSocket;
	PList<STUNmessage> request;
	PList<STUNmessage> response;

	for (i = 0; i < m_socketsForPairing; i++)
	{
		PString t = (i%2 == 0 ? "rtp" : "rtcp");
		PINDEX idx = stunSocket.Append(new STUNsocket(t, callNo));
		if (!OpenSocketA(stunSocket[idx], pairedPortInfo, binding)) {
			PTRACE(1, "STUN\tUnable to open socket to server " << GetServer());
			return false;
		}

		idx = request.Append(new STUNmessage(STUNmessage::BindingRequest));
		request[idx].AddAttribute(STUNchangeRequest(false, false));

		response.Append(new STUNmessage);
	}

	for (i = 0; i < m_socketsForPairing; i++)
	{
		if (!response[i].Poll(stunSocket[i], request[i], m_pollRetries))
		{
			PTRACE(1, "STUN\tServer unexpectedly went offline." << GetServer());
			return false;
		}
	}

	for (i = 0; i < m_socketsForPairing; i++)
	{
		STUNmappedAddress * mappedAddress = (STUNmappedAddress *)response[i].FindAttribute(STUNattribute::MAPPED_ADDRESS);
		if (mappedAddress == NULL)
		{
			PTRACE(2, "STUN\tExpected mapped address attribute from server " << GetServer());
			return false;
		}
		if (GetNatType(FALSE) != SymmetricNat)
			stunSocket[i].SetPort(mappedAddress->port);
		stunSocket[i].externalIP = mappedAddress->GetIP();
	}

	for (i = 0; i < m_socketsForPairing; i++)
	{
		for (PINDEX j = 0; j < m_socketsForPairing; j++)
		{
			if ((stunSocket[i].GetPort()&1) == 0 && (stunSocket[i].GetPort()+1) == stunSocket[j].GetPort()) {
				stunSocket[i].SetSendAddress(0, 0);
				stunSocket[i].SetReadTimeout(PMaxTimeInterval);
				stunSocket[j].SetSendAddress(0, 0);
				stunSocket[j].SetReadTimeout(PMaxTimeInterval);
				rtp = &stunSocket[i];
				rtcp = &stunSocket[j];
				stunSocket.DisallowDeleteObjects();
				stunSocket.Remove(rtp);
				stunSocket.Remove(rtcp);
				stunSocket.AllowDeleteObjects();
				return true;
			}
		}
	}

	PTRACE(2, "STUN\tCould not get a pair of adjacent port numbers from NAT");
	return false;
}

/////////////////////////////////////////////////////////////////////


class GkClient;

class H46024Socket : public UDPProxySocket
{
public:
    H46024Socket(GkClient * client, bool rtp, const H225_CallIdentifier & id, PINDEX callNo, CallRec::NatStrategy strategy, WORD sessionID);

	enum  probe_state {
		e_notRequired,			///< Polling has not started
		e_initialising,			///< We are initialising (local set but remote not)
		e_idle,					///< Idle (waiting for first packet from remote)
		e_probing,				///< Probing for direct route
		e_verify_receiver,		///< verified receive connectivity
		e_verify_sender,		///< verified send connectivity
		e_wait,					///< we are waiting for direct media (to set address)
		e_direct				///< we are going direct to detected address
	};

	struct probe_packet {
		PUInt16b	Length; 		// Length
		PUInt32b	SSRC;			// Time Stamp
		BYTE		name[4];		// Name is limited to 32 (4 Bytes)
		BYTE		cui[20];		// SHA-1 is always 160 (20 Bytes)
	};

	virtual bool OnReceiveData(void *, PINDEX, Address &, WORD &);
	PBoolean SendRTCPFrame(RTP_ControlFrame & report, const PIPSocket::Address & ip, WORD port, unsigned id);

	virtual PBoolean WriteTo(const void * buf, PINDEX len, const Address & addr, WORD port);
	virtual PBoolean WriteTo(const void * buf, PINDEX len, const Address & addr, WORD port, unsigned id);
#ifdef HAS_H46019CM
	PBoolean WriteSocket(const void * buf, PINDEX len, const Address & addr, WORD port, unsigned altMux = 0);
#endif

	void SetAlternateAddresses(const H323TransportAddress & address, const PString & cui, unsigned muxID);
	void GetAlternateAddresses(H323TransportAddress & address, PString & cui, unsigned & muxID);

	// Annex A
	PBoolean ReceivedProbePacket(const RTP_ControlFrame & frame, bool & probe, bool & success);
	void BuildProbe(RTP_ControlFrame & report, bool reply);
	void StartProbe();
	void ProbeReceived(bool probe, const PIPSocket::Address & addr, WORD & port);
	void SetProbeState(probe_state newstate);
	int GetProbeState() const;
	void SignalH46024Adirect();

	// Annex B
	void H46024Bdirect(const H323TransportAddress & address, unsigned muxID);
	void SendRTPPing(const PIPSocket::Address & ip, const WORD & port, unsigned id);

private:
	CallRec::NatStrategy m_natStrategy;
	WORD m_sessionID;
	H225_CallIdentifier m_callIdentifier;
	bool m_rtp;
	PMutex probeMutex;
	probe_state m_state;

	// Addresses
	PString m_CUIlocal;									///< Local CUI
	PString m_CUIremote;							    ///< Remote CUI
	PIPSocket::Address m_locAddr;						///< local Address (address used when starting socket)
	PIPSocket::Address m_remAddr;  WORD m_remPort;		///< Remote Address (address used when starting socket)
	PIPSocket::Address m_detAddr;  WORD m_detPort;		///< detected remote Address (as detected from actual packets)
	PIPSocket::Address m_pendAddr;  WORD m_pendPort;	///< detected pending RTCP Probe Address (as detected from actual packets)
	PIPSocket::Address m_altAddr;  WORD m_altPort;		///< supplied remote Address (as supplied in Generic Information)
	unsigned m_altMuxID;

	// Probes
	PDECLARE_NOTIFIER(PTimer, H46024Socket, Probe);		///< Thread to probe for direct connection
	PTimer m_Probe;										///< Probe Timer
	PINDEX m_probes;									///< Probe count
	DWORD SSRC;											///< Random number

	// Annex B Probes
	WORD m_keepseqno;                                   ///< Probe sequence number
	PTime m_keepStartTime;                              ///< Probe start time for TimeStamp.

};

H46024Socket::H46024Socket(GkClient * client, bool rtp, const H225_CallIdentifier & id, PINDEX callNo, CallRec::NatStrategy strategy, WORD sessionID)
	:UDPProxySocket((rtp ? "rtp" : "rtcp"), callNo),
	m_natStrategy(strategy), m_sessionID(sessionID), m_callIdentifier(id),
	m_rtp(rtp), m_state(e_notRequired),	m_remPort(0), m_detPort(0), m_pendPort(0), m_altPort(0),
	m_altMuxID(0), m_probes(0), SSRC(0), m_keepseqno(100)
{
}

PBoolean H46024Socket::ReceivedProbePacket(const RTP_ControlFrame & frame, bool & probe, bool & success)
{
	success = false;

	//Inspect the probe packet
	if (frame.GetPayloadType() != RTP_ControlFrame::e_ApplDefined)
		return false;

	int cstate = GetProbeState();
	if (cstate == e_notRequired) {
		PTRACE(6, "H46024A\ts:" << m_sessionID << " received RTCP probe packet. LOGIC ERROR!");
		return false;
	}

	if (cstate > e_probing) {
		PTRACE(6, "H46024A\ts:" << m_sessionID << " received RTCP probe packet. IGNORING! Already authenticated.");
		return false;
	}

	probe = (frame.GetCount() > 0);
	PTRACE(4, "H46024A\ts:" << m_sessionID << " RTCP Probe " << (probe ? "Reply" : "Request") << " received.");

#ifdef P_SSL
	BYTE * data = frame.GetPayloadPtr();
	PBYTEArray bytes(20);
	memcpy(bytes.GetPointer(),data+12, 20);
	PMessageDigest::Result bin_digest;
	PMessageDigestSHA1::Encode(OpalGloballyUniqueID(m_callIdentifier.m_guid).AsString() + m_CUIlocal, bin_digest);
	PBYTEArray val(bin_digest.GetPointer(),bin_digest.GetSize());

	if (bytes == val) {
		if (probe)  // We have a reply
			SetProbeState(e_verify_sender);
		else
			SetProbeState(e_verify_receiver);

		m_Probe.Stop();
		PTRACE(4, "H46024A\ts" << m_sessionID << " RTCP Probe " << (probe ? "Reply" : "Request") << " verified.");
		if (!m_CUIremote.IsEmpty())
			success = true;
		else {
			PTRACE(4, "H46024A\ts" << m_sessionID << " Remote not ready.");
		}
	} else {
		PTRACE(4, "H46024A\ts" << m_sessionID << " RTCP Probe " << (probe ? "Reply" : "Request") << " verify FAILURE");
	}
	return true;
#else
    return false;
#endif
}

bool H46024Socket::OnReceiveData(void * data, PINDEX datalen, Address & ipAddress, WORD & ipPort)
{
	if (m_natStrategy != CallRec::e_natAnnexA &&
		m_natStrategy != CallRec::e_natAnnexB)
		return true;

	int state = GetProbeState();
	if (state == e_notRequired || state == e_direct)
		return true;

	// We intercept any prob packets here.
	if (m_natStrategy == CallRec::e_natAnnexB && ipAddress == m_altAddr && port == m_altPort) {
		PTRACE(4, "H46024B\ts:" << m_sessionID << " " << Type() <<
			" Switching to " << ipAddress << ":" << port << " from " << m_remAddr << ":" << m_remPort);
		m_detAddr = ipAddress;  m_detPort = ipPort;
		SetProbeState(e_direct);
		return false;
	}

	/// Check the probe state
	switch (state) {
		case e_initialising:						// RTCP only
		case e_idle:								// RTCP only
		case e_probing:								// RTCP only
		case e_verify_receiver:						// RTCP only
		{
			bool probe = false; bool success = false;
			RTP_ControlFrame frame(datalen);
			memcpy(frame.GetPointer(),data,datalen);
			if (ReceivedProbePacket(frame,probe,success)) {
				if (success)
					ProbeReceived(probe,ipAddress,ipPort);
				else {
					m_pendAddr = ipAddress; m_pendPort = ipPort;
				}
				return false;  // don't forward on probe packets.
			}
		}
		break;
		case e_wait:
			if ((ipAddress == m_altAddr) && (ipPort == m_altPort)) {
				PTRACE(4, "H46024A\ts:" << m_sessionID << " " << Type() << " Already sending direct!");
				m_detAddr = ipAddress;  m_detPort = ipPort;
				SetProbeState(e_direct);
				return false;  // don't forward on probe packets.
			} else if ((ipAddress == m_pendAddr) && (ipPort == m_pendPort)) {
				PTRACE(4, "H46024A\ts:" << m_sessionID << " " << Type() <<
									" Switching to Direct " << ipAddress << ":" << ipPort);
				m_detAddr = ipAddress;  m_detPort = ipPort;
				SetProbeState(e_direct);
				return false; // don't forward on probe packets.
			} else if ((ipAddress != m_remAddr) || (ipPort != m_remPort)) {
				PTRACE(4, "H46024A\ts:" << m_sessionID << " " << Type() <<
									" Switching to " << ipAddress << ":" << ipPort << " from " << m_remAddr << ":" << m_remPort);
				m_detAddr = ipAddress;  m_detPort = ipPort;
				SetProbeState(e_direct);
				return false;  // don't forward on probe packets.
			}
			break;
		default:
		break;
	}
	return true;

}

PBoolean H46024Socket::WriteTo(const void * buf, PINDEX len, const Address & addr, WORD port)
{
	return WriteTo(buf, len, addr, port, 0);
}

PBoolean H46024Socket::WriteTo(const void * buf, PINDEX len, const Address & addr, WORD port, unsigned id)
{
#if defined(H323_H46024A) || defined(H323_H46024B)
	if (GetProbeState() == e_direct)
#ifdef HAS_H46019CM
		return WriteSocket(buf,len, m_detAddr, m_detPort, m_altMuxID);
#else
		return UDPProxySocket::WriteTo(buf,len, m_detAddr, m_detPort);
#endif  // H46019CM
	else
#endif  // H46024A/B
#ifdef HAS_H46019CM
		return WriteSocket(buf,len, addr, port, id);
#else
		return UDPProxySocket::WriteTo(buf,len, addr, port);
#endif // HAS_H46019CM
}

#ifdef HAS_H46019CM
PBoolean H46024Socket::WriteSocket(const void * buf, PINDEX len, const Address & addr, WORD port, unsigned altMux)
{
	unsigned mux = m_sendMultiplexID;
	if (altMux)
		mux = altMux;

	if (!PNatMethod_H46019::IsMultiplexed() && !mux)      // No Multiplex Rec'v or Send
		return UDPProxySocket::WriteTo(buf,len, addr, port);
	else {
#ifdef H323_H46024A
		if (m_remAddr.IsAny()) {
			m_remAddr = addr;
			m_remPort = port;
		}
#endif
		PUDPSocket * muxSocket = PNatMethod_H46019::GetMultiplexSocket(rtpSocket);
		if (muxSocket && !mux)                            // Rec'v Multiplex
			return muxSocket->WriteTo(buf,len, addr, port);

		RTP_MultiDataFrame frame(mux,(const BYTE *)buf,len);
		if (!muxSocket)												// Send Multiplex
			return UDPProxySocket::WriteTo(frame.GetPointer(), frame.GetSize(), addr, port);
		else														//  Send & Rec'v Multiplexed
			return muxSocket->WriteTo(frame.GetPointer(), frame.GetSize(), addr, port);

	}
}
#endif

void H46024Socket::SetAlternateAddresses(const H323TransportAddress & address, const PString & cui, unsigned muxID)
{
	address.GetIpAndPort(m_altAddr, m_altPort);

	PTRACE(6, "H46024A\ts: " << m_sessionID << (m_rtp ? " RTP " : " RTCP ")
			<< "Remote Alt: " << m_altAddr << ":" << m_altPort << " CUI: " << cui);

	if (!m_rtp) {
		m_CUIremote = cui;
		if (GetProbeState() < e_idle) {
			SetProbeState(e_idle);
			StartProbe();
		// We Already have a direct connection but we are waiting on the CUI for the reply
		} else if (GetProbeState() == e_verify_receiver)
			ProbeReceived(false,m_pendAddr,m_pendPort);
	}
}

#define H46024A_MAX_PROBE_COUNT  15
#define H46024A_PROBE_INTERVAL  200
void H46024Socket::StartProbe()
{
	PTRACE(4, "H46024A\ts: " << m_sessionID << " Starting direct connection probe.");

	SetProbeState(e_probing);
	m_probes = 0;
	m_Probe.SetNotifier(PCREATE_NOTIFIER(Probe));
	m_Probe.RunContinuous(H46024A_PROBE_INTERVAL);
}

void H46024Socket::BuildProbe(RTP_ControlFrame & report, bool probing)
{
#ifdef P_SSL
	report.SetPayloadType(RTP_ControlFrame::e_ApplDefined);
	report.SetCount((probing ? 0 : 1));  // SubType Probe

	report.SetPayloadSize(sizeof(probe_packet));

	probe_packet data;
		data.SSRC = SSRC;
		data.Length = sizeof(probe_packet);
		PString id = "24.1";
		PBYTEArray bytes(id,id.GetLength(), false);
		memcpy(&data.name[0], bytes, 4);

		PString m_callId = OpalGloballyUniqueID(m_callIdentifier.m_guid).AsString();
		PMessageDigest::Result bin_digest;
		PMessageDigestSHA1::Encode(m_callId + m_CUIremote, bin_digest);
		memcpy(&data.cui[0], bin_digest.GetPointer(), bin_digest.GetSize());

		memcpy(report.GetPayloadPtr(),&data,sizeof(probe_packet));
#endif
}

#if PTLIB_VER < 2120
void H46024Socket::Probe(PTimer &, INT)
#else
void H46024Socket::Probe(PTimer &, P_INT_PTR)
#endif
{
	m_probes++;

	if (m_probes > H46024A_MAX_PROBE_COUNT) {
		m_Probe.Stop();
		return;
	}

	if (GetProbeState() != e_probing)
		return;

	RTP_ControlFrame report;
	report.SetSize(4+sizeof(probe_packet));
	BuildProbe(report, true);
    if (SendRTCPFrame(report, m_altAddr, m_altPort, m_altMuxID)) {
		PTRACE(6, "H46024A\ts" << m_sessionID <<" RTCP Probe sent: " << m_altAddr << ":" << m_altPort);
	}
}

PBoolean H46024Socket::SendRTCPFrame(RTP_ControlFrame & report, const PIPSocket::Address & ip, WORD port, unsigned id)
{
	if (!WriteTo(report.GetPointer(),report.GetSize(),
				ip, port,id)) {
		switch (GetErrorNumber(PChannel::LastWriteError)) {
			case ECONNRESET :
			case ECONNREFUSED :
				PTRACE(2, "H46024\t" << ip << ":" << port << " not ready.");
				break;

			default:
				PTRACE(1, "H46024\t" << ip << ":" << port
					<< ", Write error on port ("
					<< GetErrorNumber(PChannel::LastWriteError) << "): "
					<< GetErrorText(PChannel::LastWriteError));
		}
		return false;
	}
	return true;
}

void H46024Socket::ProbeReceived(bool probe, const PIPSocket::Address & addr, WORD & port)
{
	if (probe) {
		SignalH46024Adirect();  //< Signal direct
	} else {
		RTP_ControlFrame reply;
		reply.SetSize(4+sizeof(probe_packet));
		BuildProbe(reply, false);
		if (SendRTCPFrame(reply,addr,port,m_altMuxID)) {
			PTRACE(4, "H46024\tRTCP Reply packet sent: " << addr << ":" << port);
		}
	}
}

void H46024Socket::SignalH46024Adirect()
{
#ifdef HAS_H46024A
	callptr call = CallTable::Instance()->FindCallRec(m_callIdentifier);
	if (call)
		call->H46024AMessage();
#endif
}

void H46024Socket::GetAlternateAddresses(H323TransportAddress & address, PString & cui, unsigned & muxID)
{
	PIPSocket::Address	tempAddr;
	WORD				tempPort;
	if (GetLocalAddress(tempAddr, tempPort))
		address = H323TransportAddress(tempAddr, tempPort);

	if (!m_rtp)
		cui = m_CUIlocal;
	else
		cui = PString();

	if (GetProbeState() < e_idle)
		SetProbeState(e_initialising);

	PTRACE(6, "H46024A\ts:" << m_sessionID << (m_rtp ? " RTP " : " RTCP ") << " Alt:" << address << " CUI " << cui);

}

void H46024Socket::SetProbeState(probe_state newstate)
{
	PWaitAndSignal m(probeMutex);

	PTRACE(4, "H46024\tChanging state for " << m_sessionID << " from " << m_state << " to " << newstate);

	m_state = newstate;
}

int H46024Socket::GetProbeState() const
{
	PWaitAndSignal m(probeMutex);

	return m_state;
}

void H46024Socket::H46024Bdirect(const H323TransportAddress & address, unsigned muxID)
{
	if (GetProbeState() == e_direct)  // We might already be doing annex A
		return;

	address.GetIpAndPort(m_altAddr, m_altPort);
	m_altMuxID = muxID;

	PTRACE(6,"H46024b\ts: " << m_sessionID << " RTP Remote Alt: " << m_altAddr << ":" << m_altPort
							<< " " << m_altMuxID);

	// Sending an empty RTP frame to the alternate address
	// will add a mapping to the router to receive RTP from
	// the remote
	for (PINDEX i=0; i<3; i++) {
		SendRTPPing(m_altAddr, m_altPort, m_altMuxID);
		PThread::Sleep(10);
	}
}

void H46024Socket::SendRTPPing(const PIPSocket::Address & ip, const WORD & port, unsigned id)
{
	RTP_DataFrame rtp;

	rtp.SetSequenceNumber(m_keepseqno);

	rtp.SetPayloadType((RTP_DataFrame::PayloadTypes)GNUGK_KEEPALIVE_RTP_PAYLOADTYPE);
	rtp.SetPayloadSize(0);

	// determining correct timestamp
	PTimeInterval timePassed = PTime() - m_keepStartTime;
	rtp.SetTimestamp((DWORD)timePassed.GetMilliSeconds() * 8);

	rtp.SetMarker(TRUE);

	if (!WriteTo(rtp.GetPointer(),
				rtp.GetHeaderSize()+rtp.GetPayloadSize(),
				ip, port,id)) {
		switch (GetErrorNumber(PChannel::LastWriteError)) {
		case ECONNRESET :
		case ECONNREFUSED :
			PTRACE(2, "H46024b\t" << ip << ":" << port << " not ready.");
			break;

		default:
			PTRACE(1, "H46024b\t" << ip << ":" << port
				<< ", Write error on port ("
				<< GetErrorNumber(PChannel::LastWriteError) << "): "
				<< GetErrorText(PChannel::LastWriteError));
		}
	} else {
		PTRACE(6, "H46024b\tRTP KeepAlive sent: " << ip << ":" << port << " " << id << " seq: " << m_keepseqno);
		m_keepseqno++;
	}
}

CallH46024Sockets::CallH46024Sockets(unsigned strategy)
: m_natStrategy(strategy), m_sessionID(0), m_rtpSocket(NULL), m_rtcpSocket(NULL)
{
}

CallH46024Sockets::CallH46024Sockets(WORD sessionID, UDPProxySocket * rtp, UDPProxySocket * rtcp)
: m_natStrategy(0), m_sessionID(sessionID), m_rtpSocket(rtp), m_rtcpSocket(rtcp)
{
}

CallH46024Sockets::~CallH46024Sockets()
{
}

void CallH46024Sockets::SetAlternate(PString cui, unsigned muxID, H323TransportAddress m_rtp, H323TransportAddress m_rtcp)
{
	if (m_rtpSocket)
		((H46024Socket*)m_rtpSocket)->SetAlternateAddresses(m_rtp,cui,muxID);

	if (m_rtcpSocket)
		((H46024Socket*)m_rtcpSocket)->SetAlternateAddresses(m_rtcp,cui,muxID);
}

void CallH46024Sockets::SetAlternate(const H46024B_AlternateAddress & alternate)
{
	int muxID = 0;
	if (alternate.HasOptionalField(H46024B_AlternateAddress::e_multiplexID))
		muxID = alternate.m_multiplexID;

	if (m_rtpSocket && alternate.HasOptionalField(H46024B_AlternateAddress::e_rtpAddress))
		((H46024Socket*)m_rtpSocket)->H46024Bdirect(H323TransportAddress(alternate.m_rtpAddress), muxID);

	if (m_rtcpSocket && alternate.HasOptionalField(H46024B_AlternateAddress::e_rtcpAddress))
		((H46024Socket*)m_rtcpSocket)->H46024Bdirect(H323TransportAddress(alternate.m_rtcpAddress), muxID);
}

void CallH46024Sockets::LoadAlternate(PString & cui, unsigned & muxID, H323TransportAddress & m_rtp, H323TransportAddress & m_rtcp)
{
	if (m_rtpSocket)
		((H46024Socket*)m_rtpSocket)->GetAlternateAddresses(m_rtp,cui,muxID);

	if (m_rtcpSocket)
		((H46024Socket*)m_rtcpSocket)->GetAlternateAddresses(m_rtp,cui,muxID);
}
#endif

/////////////////////////////////////////////////////////////////////

class GRQRequester : public RasRequester {
public:
	GRQRequester(const PString & gkid, H225_EndpointType & type);
	virtual ~GRQRequester();

	// override from class RasRequester
	virtual bool SendRequest(const Address &, WORD, int = 2);

	H225_RasMessage & GetMessage();

private:
	// override from class RasHandler
	virtual bool IsExpected(const RasMsg *) const;

	H225_RasMessage grq_ras;
};

GRQRequester::GRQRequester(const PString & gkid, H225_EndpointType & type) : RasRequester(grq_ras)
{
	grq_ras.SetTag(H225_RasMessage::e_gatekeeperRequest);
	H225_GatekeeperRequest & grq = grq_ras;
	grq.m_requestSeqNum = GetSeqNum();
	grq.m_protocolIdentifier.SetValue(H225_ProtocolID);
	if (!Toolkit::AsBool(GkConfig()->GetInteger(EndpointSection, "HideGk", 0)))
		grq.m_endpointType.IncludeOptionalField(H225_EndpointType::e_gatekeeper);
	if (type.HasOptionalField(H225_EndpointType::e_terminal))
		grq.m_endpointType.IncludeOptionalField(H225_EndpointType::e_terminal);
	if (type.HasOptionalField(H225_EndpointType::e_gateway))
		grq.m_endpointType.IncludeOptionalField(H225_EndpointType::e_gateway);
	grq.IncludeOptionalField(H225_GatekeeperRequest::e_supportsAltGK);
	grq.IncludeOptionalField(H225_GatekeeperRequest::e_supportsAssignedGK);
	if (!gkid) {
		grq.IncludeOptionalField(H225_GatekeeperRequest::e_gatekeeperIdentifier);
		grq.m_gatekeeperIdentifier = gkid;
	}

	// negotiate password algorithm if a password is set for the parent
    PString password = Toolkit::Instance()->ReadPassword(EndpointSection, "Password");
    if (!password.IsEmpty()) {
        PString auth = GkConfig()->GetString(EndpointSection, "Authenticators", "");
        PStringArray authlist(auth.Tokenise(" ,;\t"));
        if (authlist.GetSize() == 0 || authlist.GetStringsIndex("NONE") == P_MAX_INDEX) {
            grq.IncludeOptionalField(H225_GatekeeperRequest::e_authenticationCapability);
            grq.IncludeOptionalField(H225_GatekeeperRequest::e_algorithmOIDs);
        }
#ifdef H323_H235
        if (authlist.GetSize() == 0 || authlist.GetStringsIndex("H.235.1") != P_MAX_INDEX) {
            H235AuthProcedure1 h2351auth;
            h2351auth.SetPassword("dummy"); // activate it
            h2351auth.SetCapability(grq.m_authenticationCapability, grq.m_algorithmOIDs);
        }
#endif
        if (authlist.GetSize() == 0 || authlist.GetStringsIndex("MD5") != P_MAX_INDEX) {
            H235AuthSimpleMD5 md5auth;
            md5auth.SetPassword("dummy"); // activate it
            md5auth.SetCapability(grq.m_authenticationCapability, grq.m_algorithmOIDs);
        }
        if (authlist.GetSize() == 0 || authlist.GetStringsIndex("CAT") != P_MAX_INDEX) {
            H235AuthCAT catauth;
            catauth.SetPassword("dummy"); // activate it
            catauth.SetCapability(grq.m_authenticationCapability, grq.m_algorithmOIDs);
        }
        // TODO: we could also offer H235AuthDesECB, but then we have to implement the encryption part
    }
	m_rasSrv->RegisterHandler(this);
}

H225_RasMessage & GRQRequester::GetMessage()
{
	return grq_ras;
}

GRQRequester::~GRQRequester()
{
	m_rasSrv->UnregisterHandler(this);
}

bool GRQRequester::SendRequest(const Address & addr, WORD pt, int r)
{
	m_txAddr = addr, m_txPort = pt, m_retry = r;
	H225_GatekeeperRequest & grq = grq_ras;
	vector<Address> GKHome;
	Toolkit::Instance()->GetGKHome(GKHome);
	for (std::vector<Address>::iterator i = GKHome.begin(); i != GKHome.end(); ++i) {
		if ((IsLoopback(addr) || IsLoopback(*i)) && addr != *i)
			continue;
		if (addr.GetVersion() != i->GetVersion())
			continue;
		GkInterface * inter = m_rasSrv->SelectInterface(*i);
		if (inter == NULL)
			return false;
		RasListener *socket = inter->GetRasListener();
		grq.m_rasAddress = socket->GetRasAddress(addr == INADDR_BROADCAST ? *i : addr);
		if (addr == INADDR_BROADCAST)
			socket->SetOption(SO_BROADCAST, 1);
		socket->SendRas(grq_ras, addr, pt, NULL);
		if (addr == INADDR_BROADCAST)
			socket->SetOption(SO_BROADCAST, 0);
	}
	m_sentTime = PTime();
	return true;
}

bool GRQRequester::IsExpected(const RasMsg *ras) const
{
	if (ras->GetSeqNum() == GetSeqNum()) {
		if (ras->GetTag() == H225_RasMessage::e_gatekeeperRequest) {
			return m_txAddr == INADDR_BROADCAST; // catch broadcasted GRQ to avoid loop
		} else if (ras->GetTag() == H225_RasMessage::e_gatekeeperConfirm || ras->GetTag() == H225_RasMessage::e_gatekeeperReject) {
			return (m_txAddr == INADDR_BROADCAST) ? true : ras->IsFrom(m_txAddr, m_txPort);
		}
	}
	return false;
}


// handler to process requests to GkClient
class GkClientHandler : public RasHandler {
public:
	typedef bool (GkClient::*Handler)(RasMsg *);

	GkClientHandler(GkClient *c, Handler h, unsigned t) : client(c), handlePDU(h), tag(t) {}

private:
	// override from class RasHandler
	virtual bool IsExpected(const RasMsg *ras) const;
	virtual void Process(RasMsg *);

	void OnRequest(RasMsg *ras);

	GkClient *client;
	Handler handlePDU;
	unsigned tag;
};

bool GkClientHandler::IsExpected(const RasMsg * ras) const
{
	return (ras->GetTag() == tag) && client->CheckFrom(ras);
}

void GkClientHandler::Process(RasMsg *ras)
{
	CreateJob(this, &GkClientHandler::OnRequest, ras, ras->GetTagName());
}

void GkClientHandler::OnRequest(RasMsg * ras)
{
	ReadLock lockConfig(ConfigReloadMutex);
	if ((client->*handlePDU)(ras))
		ras->Reply(NULL);   // TODO235
	delete ras;
}

namespace {
const long DEFAULT_TTL = 60;
const long DEFAULT_RRQ_RETRY = 3;
}

// class GkClient
GkClient::GkClient()
	: m_rasSrv(RasServer::Instance()), m_registered(false),
	m_discoveryComplete(false), m_useAdditiveRegistration(false),
	m_ttl(GkConfig()->GetInteger(EndpointSection, "TimeToLive", DEFAULT_TTL)),
	m_timer(0),
	m_retry(GkConfig()->GetInteger(EndpointSection, "RRQRetryInterval", DEFAULT_RRQ_RETRY)),
	m_rewriteInfo(NULL), m_natClient(NULL),
	m_parentVendor(ParentVendor_GnuGk), m_endpointType(EndpointType_Gateway),
	m_discoverParent(true), m_enableGnuGkNATTraversal(false), m_enableH46018(false), m_registeredH46018(false), m_useTLS(false)
#ifdef HAS_H46023
	, m_nattype(0), m_natnotify(false), m_enableH46023(false), m_registeredH46023(false), m_stunClient(NULL), m_algDetected(false)
#endif
{
	m_resend = m_retry;
	m_gkfailtime = m_retry * 128;

	m_gkport = 0;

	m_useAltGKPermanent = false;
	m_gkList = new AlternateGKs(m_gkaddr, m_gkport);

	m_handlers[0] = new GkClientHandler(this, &GkClient::OnURQ, H225_RasMessage::e_unregistrationRequest);
	m_handlers[1] = new GkClientHandler(this, &GkClient::OnBRQ, H225_RasMessage::e_bandwidthRequest);
	m_handlers[2] = new GkClientHandler(this, &GkClient::OnDRQ, H225_RasMessage::e_disengageRequest);
	m_handlers[3] = new GkClientHandler(this, &GkClient::OnIRQ, H225_RasMessage::e_infoRequest);

	m_password = PString::Empty();
	PString auth = GkConfig()->GetString(EndpointSection, "Authenticators", "");
    PStringArray authlist(auth.Tokenise(" ,;\t"));
    m_h235Authenticators = new H235Authenticators();
    PFactory<H235Authenticator>::KeyList_T keyList = PFactory<H235Authenticator>::GetKeyList();
    PFactory<H235Authenticator>::KeyList_T::const_iterator r;
    for (r = keyList.begin(); r != keyList.end(); ++r) {
		H235Authenticator * Auth = PFactory<H235Authenticator>::CreateInstance(*r);
		if (Auth
            && (authlist.GetSize() == 0 || authlist.GetStringsIndex(Auth->GetName()) != P_MAX_INDEX) ) {
    		m_h235Authenticators->Append(Auth);
		} else {
            delete Auth;
        }
	}
}

GkClient::~GkClient()
{
    delete m_h235Authenticators;
#ifdef HAS_H46023
	m_natstrategy.clear();
#endif
	DeleteObjectsInArray(m_handlers, m_handlers + 4);
	delete m_gkList;
	delete m_rewriteInfo;
	PTRACE(1, "GKC\tDelete GkClient");
}

void GkClient::OnReload()
{
	PConfig *cfg = GkConfig();

	if (IsRegistered()) {
		if (Toolkit::AsBool(cfg->GetString(EndpointSection, "UnregisterOnReload", "0"))) {
			SendURQ();
		} else {
			Unregister();
		}
	}

	m_password = Toolkit::Instance()->ReadPassword(EndpointSection, "Password");
	m_retry = m_resend = cfg->GetInteger(EndpointSection, "RRQRetryInterval", DEFAULT_RRQ_RETRY);
	m_gkfailtime = m_retry * 128;
	m_authAlgo = "";

	PCaselessString s = GkConfig()->GetString(EndpointSection, "Vendor", "GnuGk");
	if (s.Find(',') != P_MAX_INDEX)
		s = "Generic";	// only set vendor ID, no extensions
	if (s == "Generic" ||  s == "Unknown")
		m_parentVendor = ParentVendor_Generic;
	else if (s == "Cisco")
		m_parentVendor = ParentVendor_Cisco;
	else
		m_parentVendor = ParentVendor_GnuGk;

	s = GkConfig()->GetString(EndpointSection, "Type", "Gateway");
	if (s[0] == 't' || s[0] == 'T') {
		m_endpointType = EndpointType_Terminal;
		m_prefixes.RemoveAll();
	} else {
		m_endpointType = EndpointType_Gateway;
		m_prefixes = cfg->GetString(EndpointSection, "Prefix", "").Tokenise(",;", FALSE);
	}

	m_discoverParent = Toolkit::AsBool(cfg->GetString(EndpointSection, "Discovery", "1"));

	m_h323Id = cfg->GetString(EndpointSection, "H323ID", (const char *)Toolkit::GKName()).Tokenise(" ,;\t", FALSE);
	m_e164 = cfg->GetString(EndpointSection, "E164", "").Tokenise(" ,;\t", FALSE);
    m_enableGnuGkNATTraversal = GkConfig()->GetBoolean(EndpointSection, "EnableGnuGkNATTraversal", false);

#ifdef HAS_H46018
	m_enableH46018 = GkConfig()->GetBoolean(EndpointSection, "EnableH46018", false);
	if (m_enableH46018 && !Toolkit::Instance()->IsH46018Enabled()) {
		PTRACE(1, "H46018\tWarning: H.460.18 enabled for parent/child, but global H.460.18 switch is OFF");
	}
#endif

#ifdef HAS_H46023
	m_enableH46023 = GkConfig()->GetBoolean(EndpointSection, "EnableH46023", false);
	if (m_enableH46023 && !Toolkit::Instance()->IsH46023Enabled()) {
		PTRACE(1, "H46023\tWarning: H.460.23 enabled for parent/child, but global H.460.23 switch is OFF");
	}
#endif

#ifdef HAS_TLS
	m_useTLS = GkConfig()->GetBoolean(EndpointSection, "UseTLS", false);
#endif

	PIPSocket::Address gkaddr = m_gkaddr;
	WORD gkport = m_gkport;
	PCaselessString gk(cfg->GetString(EndpointSection, "Gatekeeper", "no"));
	if ((gk != "no") && !m_rasSrv->IsGKRouted()) {
		PTRACE(1, "EP\tError: Child gatekeeper may not run in direct mode!");
		cerr << "Error: Child gatekeeper may not run in direct mode!" << endl;
	}


	PStringList gkHost;
#if P_DNS
	if (gk != "no" && !IsIPAddress(gk)) {
		PString number = "h323:user@" + gk;
		PStringList str;
		if (PDNS::LookupSRV(number, "_h323rs._udp.", str)) {
			PTRACE(5, "EP\t" << str.GetSize() << " h323rs SRV Records found");
			  for (PINDEX i = 0; i < str.GetSize(); i++) {
				PCaselessString newhost = str[i].Right(str[i].GetLength()-5);
				PTRACE(4, "EP\th323rs SRV record " << newhost);
				if (i == 0)
					gk = newhost;
				else
					m_gkList->Set(newhost);
			  }
		}
	}
#endif

	if (!IsRegistered())
		m_ttl = GkConfig()->GetInteger(EndpointSection, "TimeToLive", DEFAULT_TTL);


	if (gk == "no") {
		m_timer = 0;
		m_rrjReason = PString::Empty();
		return;
	} else if (gk == "auto") {
		m_gkaddr = INADDR_BROADCAST;
		m_gkport = GK_DEF_UNICAST_RAS_PORT;
		m_discoveryComplete = false;
	} else if (GetTransportAddress(gk, GK_DEF_UNICAST_RAS_PORT, m_gkaddr, m_gkport)) {
		m_discoveryComplete = (m_gkaddr == gkaddr) && (m_gkport == gkport);
	} else {
		// unresolvable?
		PTRACE(1, "GKC\tWarning: Can't resolve parent GK " << gk);
		return;
	}

	m_timer = 100;

	delete m_rewriteInfo;
	m_rewriteInfo = new Toolkit::RewriteData(cfg, RewriteE164Section);
}

void GkClient::CheckRegistration()
{
	if (m_timer > 0 && (PTime() - m_registeredTime) > m_timer)
		Register();
}

bool GkClient::CheckFrom(const RasMsg *ras) const
{
	return ras->IsFrom(m_gkaddr, m_gkport);
}

bool GkClient::CheckFrom(const PIPSocket::Address & ip) const
{
	return m_gkaddr == ip;
}

bool GkClient::CheckFrom(const H225_TransportAddress & addr) const
{
	PIPSocket::Address ip;
	return GetIPFromTransportAddr(addr, ip) && m_gkaddr == ip;
}

PString GkClient::GetParent() const
{
	return IsRegistered() ?
		AsString(m_gkaddr, m_gkport) + '\t' + m_endpointId.GetValue() :
		"not registered\t" + m_rrjReason;
}

bool GkClient::OnSendingGRQ(H225_GatekeeperRequest & grq)
{
	if (m_h323Id.GetSize() > 0) {
		int sz = m_h323Id.GetSize();
		grq.IncludeOptionalField(H225_GatekeeperRequest::e_endpointAlias);
		grq.m_endpointAlias.SetSize(sz);
		for (PINDEX i = 0; i < sz; ++i)
			H323SetAliasAddress(m_h323Id[i], grq.m_endpointAlias[i]);
	}

#ifdef HAS_H46018
	if (m_enableH46018) {
		grq.IncludeOptionalField(H225_GatekeeperRequest::e_featureSet);
		H460_FeatureStd feat = H460_FeatureStd(18);
		grq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = grq.m_featureSet.m_supportedFeatures;
		int sz = desc.GetSize();
		desc.SetSize(sz + 1);
		desc[sz] = feat;
	}
#endif

#if defined(HAS_TLS) && defined(HAS_H460)
	// H.460.22
	if (Toolkit::Instance()->IsTLSEnabled() && m_useTLS) {
		// include H.460.22 in supported features
		H460_FeatureStd h46022 = H460_FeatureStd(22);
		H460_FeatureStd settings;
		settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
		WORD tlsSignalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT);
		H225_ArrayOf_TransportAddress signalAddrArray;
		SetRasAddress(signalAddrArray);
		SetH225Port(signalAddrArray[0], tlsSignalPort);
		H323TransportAddress signalAddr = signalAddrArray[0];
		settings.Add(Std22_ConnectionAddress, H460_FeatureContent(signalAddr));
		h46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
		grq.IncludeOptionalField(H225_GatekeeperRequest::e_featureSet);
		grq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = grq.m_featureSet.m_supportedFeatures;
		PINDEX lPos = desc.GetSize();
		desc.SetSize(lPos + 1);
		desc[lPos] = h46022;
	}
#endif

#ifdef HAS_H46023
	if (m_enableH46023) {
		grq.IncludeOptionalField(H225_GatekeeperRequest::e_featureSet);
		H460_FeatureStd feat = H460_FeatureStd(23);
		grq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = grq.m_featureSet.m_supportedFeatures;
		int sz = desc.GetSize();
		desc.SetSize(sz + 1);
		desc[sz] = feat;
	}
#endif
	return true;
}

bool GkClient::OnSendingRRQ(H225_RegistrationRequest & rrq)
{
	if ((m_parentVendor == ParentVendor_GnuGk) && m_enableGnuGkNATTraversal && !m_enableH46018) {
		PIPSocket::Address sigip;
		if (rrq.m_callSignalAddress.GetSize() > 0
				&& GetIPFromTransportAddr(rrq.m_callSignalAddress[0], sigip)) {
			rrq.IncludeOptionalField(H225_RegistrationRequest::e_nonStandardData);
			rrq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
			H225_H221NonStandard & t35 = rrq.m_nonStandardData.m_nonStandardIdentifier;
			t35.m_t35CountryCode = Toolkit::t35cPoland;
			t35.m_manufacturerCode = Toolkit::t35mGnuGk;
			t35.m_t35Extension = Toolkit::t35eNATTraversal;
			rrq.m_nonStandardData.m_data = "IP=" + sigip.AsString();
		}
	}

#ifdef HAS_H46018
    if (m_enableH46018) {
        rrq.IncludeOptionalField(H225_RegistrationRequest::e_featureSet);
        H460_FeatureStd feat = H460_FeatureStd(18);
        rrq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
        H225_ArrayOf_FeatureDescriptor & desc = rrq.m_featureSet.m_supportedFeatures;
        int sz = desc.GetSize();
        desc.SetSize(sz + 1);
        desc[sz] = feat;
    }
#endif

#if defined(HAS_TLS) && defined(HAS_H460)
	// H.460.22
	if (Toolkit::Instance()->IsTLSEnabled() && m_useTLS) {
		// include H.460.22 in supported features
		H460_FeatureStd h46022 = H460_FeatureStd(22);
		H460_FeatureStd settings;
		settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
		WORD tlsSignalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT);
		H225_ArrayOf_TransportAddress signalAddrArray;
		SetRasAddress(signalAddrArray);
		SetH225Port(signalAddrArray[0], tlsSignalPort);
		H323TransportAddress signalAddr = signalAddrArray[0];
		settings.Add(Std22_ConnectionAddress, H460_FeatureContent(signalAddr));
		h46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_featureSet);
		rrq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = rrq.m_featureSet.m_supportedFeatures;
		PINDEX lPos = desc.GetSize();
		desc.SetSize(lPos + 1);
		desc[lPos] = h46022;
	}
#endif

#ifdef HAS_H46023
		if (m_enableH46023 && (!m_registered || m_registeredH46023)) {
			bool contents = false;
			H460_FeatureStd feat = H460_FeatureStd(23);

			if (!m_registered) {
				feat.Add(Std23_RemoteNAT, H460_FeatureContent(true));
				feat.Add(Std23_AnnexA   , H460_FeatureContent(true));
				feat.Add(Std23_AnnexB   , H460_FeatureContent(true));
				contents = true;
			} else if (m_algDetected) {
				feat.Add(Std23_RemoteNAT, H460_FeatureContent(false));
				feat.Add(Std23_NATdet	, H460_FeatureContent(PSTUNClient::OpenNat, 8));
				m_algDetected = false;
				contents = true;
			} else {
				int natType = 0;
				if (H46023_TypeNotify(natType)) {
					feat.Add(Std23_NATdet, H460_FeatureContent(natType, 8));
					m_natnotify = false;
					contents = true;
				}
			}
			if (contents) {
				rrq.IncludeOptionalField(H225_RegistrationRequest::e_featureSet);
				rrq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				H225_ArrayOf_FeatureDescriptor & desc = rrq.m_featureSet.m_supportedFeatures;
				int sz = desc.GetSize();
				desc.SetSize(sz + 1);
				desc[sz] = feat;
			}
		}
#endif

	return true;
}

bool GkClient::OnSendingARQ(H225_AdmissionRequest & arq, Routing::AdmissionRequest & /* req */)
{
	if (m_parentVendor == ParentVendor_Cisco) {
		Cisco_ARQnonStandardInfo nonStandardData;

		arq.IncludeOptionalField(H225_AdmissionRequest::e_nonStandardData);
		arq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
		H225_H221NonStandard & h221 = arq.m_nonStandardData.m_nonStandardIdentifier;
		h221.m_manufacturerCode = Toolkit::t35mCisco;
		h221.m_t35CountryCode = Toolkit::t35cUSA;
		h221.m_t35Extension = 0;

		PPER_Stream buff;
		nonStandardData.Encode(buff);
		buff.CompleteEncoding();
		arq.m_nonStandardData.m_data = buff;
	}
	return true;
}

bool GkClient::OnSendingLRQ(H225_LocationRequest & lrq, Routing::LocationRequest & /*req*/)
{
	if (m_parentVendor == ParentVendor_Cisco) {
		Cisco_LRQnonStandardInfo nonStandardData;

		nonStandardData.m_ttl = 6;

		if (lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)) {
			nonStandardData.IncludeOptionalField(Cisco_LRQnonStandardInfo::e_gatewaySrcInfo);
			nonStandardData.m_gatewaySrcInfo.SetSize(lrq.m_sourceInfo.GetSize());
			for (PINDEX i = 0; i < lrq.m_sourceInfo.GetSize(); i++)
				nonStandardData.m_gatewaySrcInfo[i] = lrq.m_sourceInfo[i];
		} else {
			if (m_h323Id.GetSize() > 0) {
				nonStandardData.IncludeOptionalField(Cisco_LRQnonStandardInfo::e_gatewaySrcInfo);
				nonStandardData.m_gatewaySrcInfo.SetSize(m_h323Id.GetSize());
				for (PINDEX i = 0; i < m_h323Id.GetSize(); i++)
					H323SetAliasAddress(m_h323Id[i], nonStandardData.m_gatewaySrcInfo[i], H225_AliasAddress::e_h323_ID);
			}
			if (m_e164.GetSize() > 0) {
				nonStandardData.IncludeOptionalField(Cisco_LRQnonStandardInfo::e_gatewaySrcInfo);
				PINDEX sz = nonStandardData.m_gatewaySrcInfo.GetSize();
				nonStandardData.m_gatewaySrcInfo.SetSize(sz + m_e164.GetSize());
				for (PINDEX i = 0; i < m_e164.GetSize(); i++)
					H323SetAliasAddress(m_e164[i], nonStandardData.m_gatewaySrcInfo[sz + i]);
			}
		}

		lrq.IncludeOptionalField(H225_LocationRequest::e_nonStandardData);
		lrq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
		H225_H221NonStandard & h221 = lrq.m_nonStandardData.m_nonStandardIdentifier;
		h221.m_manufacturerCode = Toolkit::t35mCisco;
		h221.m_t35CountryCode = Toolkit::t35cUSA;
		h221.m_t35Extension = 0;

		PPER_Stream buff;
		nonStandardData.Encode(buff);
		buff.CompleteEncoding();
		lrq.m_nonStandardData.m_data = buff;
	}
	return true;
}

bool GkClient::OnSendingARQ(H225_AdmissionRequest & arq, Routing::SetupRequest & req, bool /*answer*/)
{
	if (m_parentVendor == ParentVendor_Cisco) {
		const Q931 &setup = req.GetWrapper()->GetQ931();
		Cisco_ARQnonStandardInfo nonStandardData;

		if (setup.HasIE(Q931::CallingPartyNumberIE)) {
			PBYTEArray data = setup.GetIE(Q931::CallingPartyNumberIE);
			if (data.GetSize() >= 2 && (data[0] & 0x80) == 0x80) {
				nonStandardData.IncludeOptionalField(Cisco_ARQnonStandardInfo::e_callingOctet3a);
				nonStandardData.m_callingOctet3a = data[1];
			}
		}

		arq.IncludeOptionalField(H225_AdmissionRequest::e_nonStandardData);
		arq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
		H225_H221NonStandard & h221 = arq.m_nonStandardData.m_nonStandardIdentifier;
		h221.m_manufacturerCode = Toolkit::t35mCisco;
		h221.m_t35CountryCode = Toolkit::t35cUSA;
		h221.m_t35Extension = 0;

		PPER_Stream buff;
		nonStandardData.Encode(buff);
		buff.CompleteEncoding();
		arq.m_nonStandardData.m_data = buff;
	}
	return true;
}

bool GkClient::OnSendingARQ(H225_AdmissionRequest & arq, Routing::FacilityRequest & /*req*/)
{
	if (m_parentVendor == ParentVendor_Cisco) {
		Cisco_ARQnonStandardInfo nonStandardData;

		arq.IncludeOptionalField(H225_AdmissionRequest::e_nonStandardData);
		arq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
		H225_H221NonStandard & h221 = arq.m_nonStandardData.m_nonStandardIdentifier;
		h221.m_manufacturerCode = Toolkit::t35mCisco;
		h221.m_t35CountryCode = Toolkit::t35cUSA;
		h221.m_t35Extension = 0;

		PPER_Stream buff;
		nonStandardData.Encode(buff);
		buff.CompleteEncoding();
		arq.m_nonStandardData.m_data = buff;
	}
	return true;
}

bool GkClient::OnSendingDRQ(H225_DisengageRequest & /*drq*/, const callptr & /*call*/)
{
	return true;
}

bool GkClient::OnSendingURQ(H225_UnregistrationRequest & /*urq*/)
{
	return true;
}

bool GkClient::SendARQ(Routing::AdmissionRequest & arq_obj)
{
	const H225_AdmissionRequest & oarq = arq_obj.GetRequest();
	H225_RasMessage arq_ras;
	Requester<H225_AdmissionRequest> request(arq_ras, m_loaddr);
	H225_AdmissionRequest & arq = BuildARQ(arq_ras);

	if (Toolkit::AsBool(GkConfig()->GetString(EndpointSection, "ForwardDestIp", "1"))) {
		if (oarq.HasOptionalField(H225_AdmissionRequest::e_destCallSignalAddress)) {
			arq.IncludeOptionalField(H225_AdmissionRequest::e_destCallSignalAddress);
			arq.m_destCallSignalAddress = oarq.m_destCallSignalAddress;
		}
	}

	if (oarq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
		arq.m_destinationInfo = oarq.m_destinationInfo;
	}
	if (oarq.HasOptionalField(H225_AdmissionRequest::e_destExtraCallInfo)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_destExtraCallInfo);
		arq.m_destExtraCallInfo = oarq.m_destExtraCallInfo;
	}
	arq.m_srcInfo = oarq.m_srcInfo;
	RewriteE164(arq.m_srcInfo, true);
	arq.m_bandWidth = oarq.m_bandWidth;
	arq.m_callReferenceValue = oarq.m_callReferenceValue;
	arq.m_conferenceID = oarq.m_conferenceID;
	if (oarq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_callIdentifier);
		arq.m_callIdentifier = oarq.m_callIdentifier;
	}

#if defined(HAS_TLS) && defined(HAS_H460)
	// H.460.22
	if (Toolkit::Instance()->IsTLSEnabled() && m_useTLS) {
		// include H.460.22 in supported features
		H460_FeatureStd h46022 = H460_FeatureStd(22);
		H460_FeatureStd settings;
		settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
		WORD tlsSignalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT);
		H225_ArrayOf_TransportAddress signalAddrArray;
		SetRasAddress(signalAddrArray);
		SetH225Port(signalAddrArray[0], tlsSignalPort);
		H323TransportAddress signalAddr = signalAddrArray[0];
		settings.Add(Std22_ConnectionAddress, H460_FeatureContent(signalAddr));
		h46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
		arq.IncludeOptionalField(H225_AdmissionRequest::e_featureSet);
		arq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = arq.m_featureSet.m_supportedFeatures;
		PINDEX lPos = desc.GetSize();
		desc.SetSize(lPos + 1);
		desc[lPos] = h46022;
	}
#endif

#ifdef HAS_H46023
	if (m_registeredH46023) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_featureSet);
			H460_FeatureStd feat = H460_FeatureStd(24);
			arq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
			H225_ArrayOf_FeatureDescriptor & desc = arq.m_featureSet.m_supportedFeatures;
			desc.SetSize(1);
			desc[0] = feat;
	}
#endif

	return OnSendingARQ(arq, arq_obj) && WaitForACF(arq, request, &arq_obj);
}

bool GkClient::SendLRQ(Routing::LocationRequest & lrq_obj)
{
	const H225_LocationRequest & olrq = lrq_obj.GetRequest();
	H225_RasMessage lrq_ras;
	Requester<H225_LocationRequest> request(lrq_ras, m_loaddr);
	H225_LocationRequest & lrq = lrq_ras;
	lrq.m_destinationInfo = olrq.m_destinationInfo;
	lrq.m_replyAddress = m_rasSrv->GetRasAddress(m_loaddr);
	lrq.IncludeOptionalField(H225_LocationRequest::e_endpointIdentifier);
	lrq.m_endpointIdentifier = m_endpointId;
	if (olrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_sourceInfo);
		lrq.m_sourceInfo = olrq.m_sourceInfo;
		RewriteE164(lrq.m_sourceInfo, true);
	}
	if (olrq.HasOptionalField(H225_LocationRequest::e_canMapAlias)) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_canMapAlias);
		lrq.m_canMapAlias = olrq.m_canMapAlias;
	}
	if (olrq.HasOptionalField(H225_LocationRequest::e_hopCount)) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_hopCount);
		lrq.m_hopCount = olrq.m_hopCount;
		// decrement hopCount, but don't let it go below zero
		if (lrq.m_hopCount > 0)
			lrq.m_hopCount = lrq.m_hopCount - 1;
	}

#if defined(HAS_TLS) && defined(HAS_H460)
	// H.460.22
	if (Toolkit::Instance()->IsTLSEnabled() && m_useTLS) {
		// include H.460.22 in supported features
		H460_FeatureStd h46022 = H460_FeatureStd(22);
		H460_FeatureStd settings;
		settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
		WORD tlsSignalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT);
		H225_ArrayOf_TransportAddress signalAddrArray;
		SetRasAddress(signalAddrArray);
		SetH225Port(signalAddrArray[0], tlsSignalPort);
		H323TransportAddress signalAddr = signalAddrArray[0];
		settings.Add(Std22_ConnectionAddress, H460_FeatureContent(signalAddr));
        h46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
		lrq.IncludeOptionalField(H225_LocationRequest::e_featureSet);
		lrq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = lrq.m_featureSet.m_supportedFeatures;
		PINDEX lPos = desc.GetSize();
		desc.SetSize(lPos + 1);
		desc[lPos] = h46022;
	}
#endif

	SetNBPassword(lrq);

	if (!OnSendingLRQ(lrq, lrq_obj))
		return false;

	request.SendRequest(m_gkaddr, m_gkport);
	if (request.WaitForResponse(5000)) {
		RasMsg *ras = request.GetReply();
		unsigned tag = ras->GetTag();
		if (tag == H225_RasMessage::e_locationConfirm) {
			H225_LocationConfirm & lcf = (*ras)->m_recvRAS;
			// TODO22: handle H.460.22 in LCF here (parent policy)
			lrq_obj.AddRoute(Route("parent", lcf.m_callSignalAddress));
			RasMsg *oras = lrq_obj.GetWrapper();
			(*oras)->m_replyRAS.SetTag(H225_RasMessage::e_locationConfirm);
			H225_LocationConfirm & nlcf = (*oras)->m_replyRAS;
			if (lcf.HasOptionalField(H225_LocationConfirm::e_cryptoTokens)) {
				nlcf.IncludeOptionalField(H225_LocationConfirm::e_cryptoTokens);
				nlcf.m_cryptoTokens = lcf.m_cryptoTokens;
			}
			return true;
		}
	}
	return false;
}

bool GkClient::SendARQ(Routing::SetupRequest & setup_obj, bool answer)
{
	H225_RasMessage arq_ras;
	Requester<H225_AdmissionRequest> request(arq_ras, m_loaddr);
	H225_AdmissionRequest & arq = BuildARQ(arq_ras);

	H225_Setup_UUIE & setup = setup_obj.GetRequest();
	arq.m_callReferenceValue = setup_obj.GetWrapper()->GetCallReference();
	arq.m_conferenceID = setup.m_conferenceID;
	if (setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_callIdentifier);
		arq.m_callIdentifier = setup.m_callIdentifier;
	}
	if (setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		arq.m_srcInfo = setup.m_sourceAddress;
		if (!answer)
			RewriteE164(arq.m_srcInfo, true);
	} else {
		// no sourceAddress privided in Q.931 Setup?
		// since srcInfo is mandatory, set my aliases as the srcInfo
		if (m_h323Id.GetSize() > 0) {
			arq.m_srcInfo.SetSize(1);
			H323SetAliasAddress(m_h323Id[0], arq.m_srcInfo[0], H225_AliasAddress::e_h323_ID);
		}
		if (m_e164.GetSize() > 0) {
			PINDEX sz = arq.m_srcInfo.GetSize();
			arq.m_srcInfo.SetSize(sz + 1);
			H323SetAliasAddress(m_e164[0], arq.m_srcInfo[sz]);
		}
	}
	if (answer) {
        if (setup.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress)) {
            arq.m_srcCallSignalAddress = setup.m_sourceCallSignalAddress;
        } else {
            // remove field, because we don't know
            arq.RemoveOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress);
        }
	} else {
		arq.m_srcCallSignalAddress = m_rasSrv->GetCallSignalAddress(m_loaddr); // our signal addr when we call to parent
	}
	if (setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
		arq.m_destinationInfo = setup.m_destinationAddress;
		if (answer) {
			RewriteE164(arq.m_destinationInfo, true);
        }
	}
	arq.m_answerCall = answer;
	// workaround for bandwidth
	if (CallTable::Instance()->GetMinimumBandwidthPerCall() > 0) {
		arq.m_bandWidth = (unsigned)CallTable::Instance()->GetMinimumBandwidthPerCall();
	} else {
		arq.m_bandWidth = GK_DEF_BANDWIDTH;
	}

#if defined(HAS_TLS) && defined(HAS_H460)
	// H.460.22
	if (Toolkit::Instance()->IsTLSEnabled() && m_useTLS) {
		// include H.460.22 in supported features
		H460_FeatureStd h46022 = H460_FeatureStd(22);
		H460_FeatureStd settings;
		settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
		WORD tlsSignalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT);
		H225_ArrayOf_TransportAddress signalAddrArray;
		SetRasAddress(signalAddrArray);
		SetH225Port(signalAddrArray[0], tlsSignalPort);
		H323TransportAddress signalAddr = signalAddrArray[0];
		settings.Add(Std22_ConnectionAddress, H460_FeatureContent(signalAddr));
        h46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
		arq.IncludeOptionalField(H225_AdmissionRequest::e_featureSet);
		arq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = arq.m_featureSet.m_supportedFeatures;
		PINDEX lPos = desc.GetSize();
		desc.SetSize(lPos + 1);
		desc[lPos] = h46022;
	}
#endif

#ifdef HAS_H46023
	if (answer && m_registeredH46023) {
		CallRec::NatStrategy natoffload = H46023_GetNATStategy(setup.m_callIdentifier);
		arq.IncludeOptionalField(H225_AdmissionRequest::e_featureSet);
			H460_FeatureStd feat = H460_FeatureStd(24);
			feat.Add(Std24_NATInstruct, H460_FeatureContent((unsigned)natoffload, 8));
			arq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
			H225_ArrayOf_FeatureDescriptor & desc = arq.m_featureSet.m_supportedFeatures;
			int sz = desc.GetSize();
			desc.SetSize(sz + 1);
			desc[sz] = feat;
	}
#endif

	return OnSendingARQ(arq, setup_obj, answer)
		&& WaitForACF(arq, request, answer ? 0 : &setup_obj);
}

bool GkClient::SendARQ(Routing::FacilityRequest & facility_obj)
{
	H225_RasMessage arq_ras;
	Requester<H225_AdmissionRequest> request(arq_ras, m_loaddr);
	H225_AdmissionRequest & arq = BuildARQ(arq_ras);

	H225_Facility_UUIE & facility = facility_obj.GetRequest();
	arq.m_callReferenceValue = facility_obj.GetWrapper()->GetCallReference();
	if (facility.HasOptionalField(H225_Facility_UUIE::e_conferenceID))
		arq.m_conferenceID = facility.m_conferenceID;
	if (facility.HasOptionalField(H225_Facility_UUIE::e_callIdentifier)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_callIdentifier);
		arq.m_callIdentifier = facility.m_callIdentifier;
	}
	if (m_h323Id.GetSize() > 0) {
		arq.m_srcInfo.SetSize(1);
		H323SetAliasAddress(m_h323Id[0], arq.m_srcInfo[0], H225_AliasAddress::e_h323_ID);
	}
	if (m_e164.GetSize() > 0) {
		PINDEX sz = arq.m_srcInfo.GetSize();
		arq.m_srcInfo.SetSize(sz + 1);
		H323SetAliasAddress(m_e164[0], arq.m_srcInfo[sz]);
	}
	if (facility.HasOptionalField(H225_Facility_UUIE::e_alternativeAliasAddress)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
		arq.m_destinationInfo = facility.m_alternativeAliasAddress;
	}
	arq.m_answerCall = false;
	// workaround for bandwidth
	if (CallTable::Instance()->GetMinimumBandwidthPerCall() > 0) {
		arq.m_bandWidth = (unsigned)CallTable::Instance()->GetMinimumBandwidthPerCall();
	} else {
		arq.m_bandWidth = GK_DEF_BANDWIDTH;
	}

#if defined(HAS_TLS) && defined(HAS_H460)
	// H.460.22
	if (Toolkit::Instance()->IsTLSEnabled() && m_useTLS) {
		// include H.460.22 in supported features
		H460_FeatureStd h46022 = H460_FeatureStd(22);
		H460_FeatureStd settings;
		settings.Add(Std22_Priority, H460_FeatureContent(1, 8)); // Priority=1, type=number8
		WORD tlsSignalPort = (WORD)GkConfig()->GetInteger(RoutedSec, "TLSCallSignalPort", GK_DEF_TLS_CALL_SIGNAL_PORT);
		H225_ArrayOf_TransportAddress signalAddrArray;
		SetRasAddress(signalAddrArray);
		SetH225Port(signalAddrArray[0], tlsSignalPort);
		H323TransportAddress signalAddr = signalAddrArray[0];
		settings.Add(Std22_ConnectionAddress, H460_FeatureContent(signalAddr));
        h46022.Add(Std22_TLS, H460_FeatureContent(settings.GetCurrentTable()));
		arq.IncludeOptionalField(H225_AdmissionRequest::e_featureSet);
		arq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = arq.m_featureSet.m_supportedFeatures;
		PINDEX lPos = desc.GetSize();
		desc.SetSize(lPos + 1);
		desc[lPos] = h46022;
	}
#endif

	return OnSendingARQ(arq, facility_obj) && WaitForACF(arq, request, &facility_obj);
}

void GkClient::SendDRQ(const callptr & call)
{
	H225_RasMessage drq_ras;
	Requester<H225_DisengageRequest> request(drq_ras, m_loaddr);
	H225_DisengageRequest & drq = drq_ras;
	call->BuildDRQ(drq, H225_DisengageReason::e_normalDrop);
	drq.IncludeOptionalField(H225_DisengageRequest::e_gatekeeperIdentifier);
	drq.m_gatekeeperIdentifier = m_gatekeeperId;
	drq.m_endpointIdentifier = m_endpointId;
	drq.m_answeredCall = false;
	// TODO: the toParent and fromParent flags don't seem to be set correctly in the CallRec on the child
	//PTRACE(0, "JW SendDRQ m_toParent=" << call->IsToParent() << " m_fromParent=" << call->IsFromParent());
	if (call->IsToParent())
        drq.m_answeredCall = false;
	if (call->IsFromParent())
        drq.m_answeredCall = true;
	SetPassword(drq);

	if (OnSendingDRQ(drq, call)) {
		request.SendRequest(m_gkaddr, m_gkport);
		(void)request.WaitForResponse(3000);
	}
	// ignore response
}

void GkClient::SendURQ()
{
	// the order is important: build URQ, close NAT socket, then send URQ
	H225_RasMessage urq_ras;
	urq_ras.SetTag(H225_RasMessage::e_unregistrationRequest);
	H225_UnregistrationRequest & urq = urq_ras;
	urq.m_requestSeqNum = m_rasSrv->GetRequestSeqNum();
	urq.IncludeOptionalField(H225_UnregistrationRequest::e_gatekeeperIdentifier);
	urq.m_gatekeeperIdentifier = m_gatekeeperId;
	urq.IncludeOptionalField(H225_UnregistrationRequest::e_endpointIdentifier);
	urq.m_endpointIdentifier = m_endpointId;
	SetCallSignalAddress(urq.m_callSignalAddress);
	SetPassword(urq);

	Unregister();

	if (OnSendingURQ(urq))
		m_rasSrv->SendRas(urq_ras, m_gkaddr, m_gkport, m_loaddr, NULL); // TODO235
}

bool GkClient::RewriteE164(H225_AliasAddress & alias, bool fromInternal)
{
	if ((alias.GetTag() != H225_AliasAddress::e_dialedDigits) &&
		(alias.GetTag() != H225_AliasAddress::e_h323_ID))
		return false;

	PString e164 = AsString(alias, FALSE);

	bool changed = RewriteString(e164, fromInternal);
	if (changed)
		H323SetAliasAddress(e164, alias);

	return changed;
}

bool GkClient::RewriteE164(H225_ArrayOf_AliasAddress & aliases, bool fromInternal)
{
	bool changed = false;
	for (PINDEX i = 0; i < aliases.GetSize(); ++i)
		if (RewriteE164(aliases[i], fromInternal))
			changed = true;
	return changed;
}

bool GkClient::RewriteE164(SetupMsg & setup, bool fromInternal)
{
	Q931 & q931 = setup.GetQ931();
	H225_Setup_UUIE & setupBody = setup.GetUUIEBody();
	unsigned plan, type;
	PString number;

	bool result = false;
	if (fromInternal) {
		bool r1 = q931.GetCallingPartyNumber(number, &plan, &type);
		if (r1 && (result = RewriteString(number, true))) {
			q931.SetCallingPartyNumber(number, plan, type);
			setup.SetChanged();
		}
		if ((!r1 || result) && setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress))
			if (RewriteE164(setupBody.m_sourceAddress, true)) {
				result = true;
				setup.SetUUIEChanged();
			}
	} else {
		bool r1 = q931.GetCalledPartyNumber(number, &plan, &type);
		if (r1 && (result = RewriteString(number, false))) {
			q931.SetCalledPartyNumber(number, plan, type);
			setup.SetChanged();
		}
		if ((!r1 || result) && setupBody.HasOptionalField(H225_Setup_UUIE::e_destinationAddress))
			if (RewriteE164(setupBody.m_destinationAddress, false)) {
				result = true;
				setup.SetUUIEChanged();
			}
	}
	return result;
}

bool GkClient::Discovery()
{
	m_loaddr = m_gkaddr;
	m_gatekeeperId = PString::Empty();

	if (!m_discoverParent)
		return true;

	H225_EndpointType eptype;
	if (m_endpointType == EndpointType_Terminal) {
		eptype.IncludeOptionalField(H225_EndpointType::e_terminal);
	} else {
		eptype.IncludeOptionalField(H225_EndpointType::e_gateway);
	}
	GRQRequester request(GkConfig()->GetString(EndpointSection, "GatekeeperIdentifier", ""), eptype);
	OnSendingGRQ(request.GetMessage());

	// the spec: timeout value 5 sec, retry count 2
	request.SendRequest(m_gkaddr, m_gkport);
	while (request.WaitForResponse(5000)) {
		RasMsg *ras = request.GetReply();
		if (ras->GetTag() == H225_RasMessage::e_gatekeeperConfirm) {
			H225_GatekeeperConfirm & gcf = (*ras)->m_recvRAS;
			m_loaddr = (*ras)->m_localAddr;
			if (gcf.HasOptionalField(H225_GatekeeperConfirm::e_gatekeeperIdentifier))
				m_gatekeeperId = gcf.m_gatekeeperIdentifier;
			GetIPAndPortFromTransportAddr(gcf.m_rasAddress, m_gkaddr, m_gkport);
			if (gcf.HasOptionalField(H225_GatekeeperConfirm::e_algorithmOID))
				m_authAlgo = gcf.m_algorithmOID;
			PTRACE(2, "GKC\tDiscover GK " << AsString(m_gkaddr, m_gkport) << " at " << m_loaddr);
			if (gcf.HasOptionalField(H225_RegistrationConfirm::e_assignedGatekeeper))
                m_gkList->Set(gcf.m_assignedGatekeeper);
			else
				return true;
		} else if (ras->GetTag() == H225_RasMessage::e_gatekeeperReject) {
			H225_GatekeeperReject & grj = (*ras)->m_recvRAS;
			if (grj.HasOptionalField(H225_GatekeeperReject::e_altGKInfo)) {
				m_gkList->Set(grj.m_altGKInfo.m_alternateGatekeeper);
				m_useAltGKPermanent = grj.m_altGKInfo.m_altGKisPermanent;
				break;
			}
		}
	}
	return false;
}

void GkClient::Register()
{
	PWaitAndSignal lock(m_rrqMutex);
	m_rrjReason = "no response";
	if (!IsRegistered() && !m_discoveryComplete)
		while (!(m_discoveryComplete = Discovery()))
			if (!GetAltGK())
				return;

	H225_RasMessage rrq_ras;
	Requester<H225_RegistrationRequest> request(rrq_ras, m_loaddr);
	BuildRRQ(rrq_ras);
	OnSendingRRQ(rrq_ras);
	request.SendRequest(m_gkaddr, m_gkport);
	m_registeredTime = PTime();
	if (request.WaitForResponse(m_retry * 1000)) {
		RasMsg *ras = request.GetReply();
		switch (ras->GetTag())
		{
			case H225_RasMessage::e_registrationConfirm:
				OnRCF(ras);
				return;
			case H225_RasMessage::e_registrationReject:
				OnRRJ(ras);
				break;
		}
	}
	GetAltGK();
}

void GkClient::Unregister()
{
	if (m_natClient) {
		m_natClient->Stop();
		m_natClient = NULL;
	}
	for_each(m_handlers, m_handlers + 4, bind1st(mem_fun(&RasServer::UnregisterHandler), m_rasSrv));
	m_registered = false;
}

bool GkClient::GetAltGK()
{
	Unregister(); // always re-register
	bool result = false;
	if (Toolkit::AsBool(GkConfig()->GetString(EndpointSection, "UseAlternateGK", "1")))
		result = m_gkList->Get(m_gkaddr, m_gkport);
	PString altgk(AsString(m_gkaddr, m_gkport));
	if (m_useAltGKPermanent)
		Toolkit::Instance()->SetConfig(1, EndpointSection, "Gatekeeper", altgk);
	if (result) {
		m_timer = 100, m_resend = m_retry, m_discoveryComplete = false;
		PTRACE(1, "GKC\tUse Alternate GK " << altgk << (m_useAltGKPermanent ? " permanently" : " temporarily"));
	} else {
		// if no alternate gatekeeper found
		// increase our resent time to avoid flooding the parent
		m_timer = (m_resend *= 2) * 1000;
		if (m_resend >= m_gkfailtime) {
			Toolkit::Instance()->GetRouteTable()->InitTable();
			m_resend = m_gkfailtime;
		}
	}
	return result;
}

void GkClient::BuildRRQ(H225_RegistrationRequest & rrq)
{
	rrq.m_protocolIdentifier.SetValue(H225_ProtocolID);
	rrq.m_discoveryComplete = m_discoveryComplete;
	SetRasAddress(rrq.m_rasAddress);
	SetCallSignalAddress(rrq.m_callSignalAddress);
	rrq.IncludeOptionalField(H225_RegistrationRequest::e_supportsAltGK);
	IsRegistered() ? BuildLightWeightRRQ(rrq) : BuildFullRRQ(rrq);
	SetPassword(rrq);
}

void GkClient::BuildFullRRQ(H225_RegistrationRequest & rrq)
{
	if (!Toolkit::AsBool(GkConfig()->GetInteger(EndpointSection, "HideGk", 0)))
		rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_gatekeeper);

	PINDEX as;
	if (m_endpointType == EndpointType_Terminal) {
		rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_terminal);
	} else {
		rrq.m_terminalType.IncludeOptionalField(H225_EndpointType::e_gateway);
		as = m_prefixes.GetSize();
		if (as > 0) {
			rrq.m_terminalType.m_gateway.IncludeOptionalField(H225_GatewayInfo::e_protocol);
			rrq.m_terminalType.m_gateway.m_protocol.SetSize(1);
			H225_SupportedProtocols & protocol = rrq.m_terminalType.m_gateway.m_protocol[0];
			protocol.SetTag(H225_SupportedProtocols::e_voice);
			H225_VoiceCaps & voicecap = (H225_VoiceCaps &)protocol;
			voicecap.m_supportedPrefixes.SetSize(as);
			for (PINDEX p = 0; p < as; ++p)
				H323SetAliasAddress(m_prefixes[p].Trim(), voicecap.m_supportedPrefixes[p].m_prefix);
		}
	}

	rrq.IncludeOptionalField(H225_RegistrationRequest::e_terminalAlias);
	as = m_h323Id.GetSize();
	rrq.m_terminalAlias.SetSize(as);
	for (PINDEX p = 0; p < as; ++p)
		H323SetAliasAddress(m_h323Id[p], rrq.m_terminalAlias[p], H225_AliasAddress::e_h323_ID);

	PINDEX s = m_e164.GetSize() + as;
	rrq.m_terminalAlias.SetSize(s);
	for (PINDEX p = as; p < s; ++p)
		H323SetAliasAddress(m_e164[p-as], rrq.m_terminalAlias[p]);
    // TODO: with additive registrations enabled, the first RRQ should contain all aliases of endpoints registered so far

	int ttl = GkConfig()->GetInteger(EndpointSection, "TimeToLive", DEFAULT_TTL);
	if (ttl > 0) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_timeToLive);
		rrq.m_timeToLive = ttl;
	}

	H225_VendorIdentifier & vendor = rrq.m_endpointVendor;
	vendor.m_vendor.m_t35CountryCode = Toolkit::t35cPoland;
	vendor.m_vendor.m_manufacturerCode = Toolkit::t35mGnuGk;
	vendor.m_vendor.m_t35Extension = 0;
	PString vendorId = GkConfig()->GetString(EndpointSection, "Vendor", "");
	if (vendorId.Find(',') != P_MAX_INDEX) {
		PStringArray ids = vendorId.Tokenise(",", FALSE);
		if (ids.GetSize() == 3) {
			vendor.m_vendor.m_t35CountryCode = ids[0].AsUnsigned();
			vendor.m_vendor.m_manufacturerCode = ids[1].AsUnsigned();
			vendor.m_vendor.m_t35Extension = ids[2].AsUnsigned();
		}
	}
	vendor.IncludeOptionalField(H225_VendorIdentifier::e_productId);
	vendor.m_productId = PString(PString::Printf, "GNU Gatekeeper on %s %s %s, %s %s", (const unsigned char*)(PProcess::GetOSName()), (const unsigned char*)(PProcess::GetOSHardware()), (const unsigned char*)(PProcess::GetOSVersion()) ,__DATE__, __TIME__);
	vendor.IncludeOptionalField(H225_VendorIdentifier::e_versionId);
	vendor.m_versionId = "Version " + PProcess::Current().GetVersion();
	PString productId = GkConfig()->GetString(EndpointSection, "ProductId", "");
	if (!productId.IsEmpty())
		vendor.m_productId = productId;
	PString productVersion = GkConfig()->GetString(EndpointSection, "ProductVersion", "");
	if (!productVersion.IsEmpty())
		vendor.m_versionId = productVersion;

	// set user provided endpointIdentifier, if any
	PString endpointId(GkConfig()->GetString(EndpointSection, "EndpointIdentifier", ""));
	if (!endpointId) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
		rrq.m_endpointIdentifier = endpointId;
	}
	// set gatekeeperIdentifier found in discovery procedure
	if (!m_gatekeeperId.GetValue()) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_gatekeeperIdentifier);
		rrq.m_gatekeeperIdentifier = m_gatekeeperId;
	}
	rrq.m_keepAlive = FALSE;
}

void GkClient::BuildLightWeightRRQ(H225_RegistrationRequest & rrq)
{
	rrq.IncludeOptionalField(H225_RegistrationRequest::e_endpointIdentifier);
	rrq.m_endpointIdentifier = m_endpointId;
	rrq.IncludeOptionalField(H225_RegistrationRequest::e_gatekeeperIdentifier);
	rrq.m_gatekeeperIdentifier = m_gatekeeperId;
	if (m_ttl > 0) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_timeToLive);
		rrq.m_timeToLive = (int)m_ttl;
	}
	rrq.m_keepAlive = TRUE;
	H225_VendorIdentifier & vendor = rrq.m_endpointVendor;
	vendor.m_vendor.m_t35CountryCode = Toolkit::t35cPoland;
	vendor.m_vendor.m_manufacturerCode = Toolkit::t35mGnuGk;
	vendor.m_vendor.m_t35Extension = 0;
	PString vendorId = GkConfig()->GetString(EndpointSection, "Vendor", "");
	if (vendorId.Find(',') != P_MAX_INDEX) {
		PStringArray ids = vendorId.Tokenise(",", FALSE);
		if (ids.GetSize() == 3) {
			vendor.m_vendor.m_t35CountryCode = ids[0].AsUnsigned();
			vendor.m_vendor.m_manufacturerCode = ids[1].AsUnsigned();
			vendor.m_vendor.m_t35Extension = ids[2].AsUnsigned();
		}
	}
}

bool GkClient::WaitForACF(H225_AdmissionRequest & arq, RasRequester & request, Routing::RoutingRequest *robj)
{
	request.SendRequest(m_gkaddr, m_gkport);
	if (request.WaitForResponse(5000)) {
		RasMsg * ras = request.GetReply();
		if (ras->GetTag() == H225_RasMessage::e_admissionConfirm) {
			if (robj) {
				H225_AdmissionConfirm & acf = (*ras)->m_recvRAS;
				Route route("parent", acf.m_destCallSignalAddress);
				route.m_flags |= Route::e_toParent;
				// check if destination has changed
				if (acf.HasOptionalField(H225_AdmissionConfirm::e_destinationInfo)) {
					// signal change of destination if caller supports canMapAlias
					if (arq.HasOptionalField(H225_AdmissionRequest::e_canMapAlias)
						&& arq.m_canMapAlias
						&& acf.m_destinationInfo.GetSize() > 0) {
						robj->SetFlag(Routing::RoutingRequest::e_aliasesChanged);
						Routing::AdmissionRequest * orig_request = dynamic_cast<Routing::AdmissionRequest *>(robj);
						if (orig_request) {
							orig_request->GetRequest().m_destinationInfo = acf.m_destinationInfo;
						}
					}
				}

				if (acf.HasOptionalField(H225_AdmissionConfirm::e_featureSet)) {
#ifdef HAS_H460
					H460_FeatureSet fs = H460_FeatureSet(acf.m_featureSet);
					// H.460.22
					if (fs.HasFeature(22)) {
						// check if response matches one of our security features
						if (acf.HasOptionalField(H225_AdmissionConfirm::e_featureSet)) {
							H460_FeatureSet arq_fs = H460_FeatureSet(arq.m_featureSet);
							if (arq_fs.HasFeature(22)) {
								H460_FeatureStd * arq_h46022 = (H460_FeatureStd *)arq_fs.GetFeature(22);
								H460_FeatureStd * acf_h46022 = (H460_FeatureStd *)fs.GetFeature(22);
								if (arq_h46022->Contains(Std22_TLS) && acf_h46022->Contains(Std22_TLS)) {
									// both support TLS, use it
									H460_FeatureParameter & tlsparam = acf_h46022->Value(Std22_TLS);
									H460_FeatureStd settings;
									settings.SetCurrentTable(tlsparam);
									if (settings.Contains(Std22_ConnectionAddress)) {
										H323TransportAddress tlsAddr = settings.Value(Std22_ConnectionAddress);
										route.m_destAddr = H323ToH225TransportAddress(tlsAddr);
										route.m_useTLS = true;
									} else {
										PTRACE(1, "TLS\tError: H.460.22 TLS address missing");
									}
								}
							}
						}
					}
#ifdef HAS_H46023
					if (m_registeredH46023 && fs.HasFeature(24)) {
						callptr call = arq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier) ?
							CallTable::Instance()->FindCallRec(arq.m_callIdentifier) : CallTable::Instance()->FindCallRec(arq.m_callReferenceValue);
							H46023_ACF(call, (H460_FeatureStd *)fs.GetFeature(24));
					}
#endif
#endif
				}
				robj->AddRoute(route);
			}
			return true;
		}
		if (ras->GetTag() == H225_RasMessage::e_admissionReject)
			OnARJ(ras);
	}
	return false;
}

H225_AdmissionRequest & GkClient::BuildARQ(H225_AdmissionRequest & arq)
{
	arq.m_callType.SetTag(H225_CallType::e_pointToPoint);

	arq.m_endpointIdentifier = m_endpointId;

	arq.IncludeOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress);
	// ok for call to parent, not ok for answer, will be overwritten later
	arq.m_srcCallSignalAddress = m_rasSrv->GetCallSignalAddress(m_loaddr);

	arq.IncludeOptionalField(H225_AdmissionRequest::e_canMapAlias);
	arq.m_canMapAlias = TRUE;

	arq.IncludeOptionalField(H225_AdmissionRequest::e_gatekeeperIdentifier);
	arq.m_gatekeeperIdentifier = m_gatekeeperId;

	SetPassword(arq);

	return arq;
}

void GkClient::OnRCF(RasMsg *ras)
{
	H225_RegistrationConfirm & rcf = (*ras)->m_recvRAS;
	if (!IsRegistered()) {
		PTRACE(2, "GKC\tRegister with " << AsString(m_gkaddr, m_gkport) << " successfully");
		m_registered = true;
		m_endpointId = rcf.m_endpointIdentifier;
		m_gatekeeperId = rcf.m_gatekeeperIdentifier;
		if (rcf.HasOptionalField(H225_RegistrationConfirm::e_alternateGatekeeper))
			m_gkList->Set(rcf.m_alternateGatekeeper);
        if (GkConfig()->GetBoolean(EndpointSection, "EnableAdditiveRegistration", false)) {
		    if (rcf.HasOptionalField(H225_RegistrationConfirm::e_supportsAdditiveRegistration))
				m_useAdditiveRegistration = true;
            else
                PTRACE(1, "GKC\tError:Parent doesn't support additive registrations");
        }

		if (m_useAdditiveRegistration)
			RegistrationTable::Instance()->UpdateTable();

		for_each(m_handlers, m_handlers + 4, bind1st(mem_fun(&RasServer::RegisterHandler), m_rasSrv));
	}

	// Not all RCF contain TTL, in that case keep old value
	if (rcf.HasOptionalField(H225_RegistrationConfirm::e_timeToLive)) {
		m_ttl = PMAX((long)(rcf.m_timeToLive - m_retry), (long)30);
		// Have it reregister at 3/4 of TimeToLive, otherwise the parent
		// might go out of sync and ends up sending an URQ
		m_ttl = (m_ttl / 4) * 3;
	}

	m_timer = m_ttl * 1000;
	m_resend = m_retry;

	// NAT handling
	if (!m_enableH46018 && rcf.HasOptionalField(H225_RegistrationConfirm::e_nonStandardData)) {
		int iec = Toolkit::iecUnknown;
		if (rcf.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_h221NonStandard) {
			iec = Toolkit::Instance()->GetInternalExtensionCode((const H225_H221NonStandard&)rcf.m_nonStandardData.m_nonStandardIdentifier);
		} else if (rcf.m_nonStandardData.m_nonStandardIdentifier.GetTag() == H225_NonStandardIdentifier::e_object) {
			PASN_ObjectId &oid = rcf.m_nonStandardData.m_nonStandardIdentifier;
			if (oid.GetDataLength() == 0)
				iec = Toolkit::iecNATTraversal;
		}
		if (iec == Toolkit::iecNATTraversal) {
			if (rcf.m_nonStandardData.m_data.AsString().Find("NAT=") == 0)
				if (!m_natClient && rcf.m_callSignalAddress.GetSize() > 0)
					m_natClient = new NATClient(rcf.m_callSignalAddress[0], m_endpointId);
		}
	}

	if (rcf.HasOptionalField(H225_RegistrationConfirm::e_featureSet)) {
#if defined (HAS_H46018) || defined(HAS_H46023)
		H460_FeatureSet fs = H460_FeatureSet(rcf.m_featureSet);
#ifdef HAS_H46018
		if (m_enableH46018 && fs.HasFeature(18))
			m_registeredH46018 = true;
#endif
#ifdef HAS_H46023
		if (m_enableH46023 && fs.HasFeature(23))
			H46023_RCF((H460_FeatureStd *)fs.GetFeature(23));
#endif
#endif
	}
}

#ifdef HAS_H46023
void GkClient::RunSTUNTest(const H323TransportAddress & addr)
{
	if (m_stunClient)
		return;

	m_stunClient = new STUNClient(this, addr);
}

void GkClient::H46023_RCF(H460_FeatureStd * feat)
{
	if (feat->Contains(Std23_DetRASAddr)) {
		H323TransportAddress addr = feat->Value(Std23_DetRASAddr);
		PIPSocket::Address ip;
		addr.GetIpAddress(ip);
		if (m_loaddr != ip) {
			PTRACE(4, "GKC\tH46024 ALG Detected local IP " << m_loaddr << " reported " << ip);
			m_algDetected = true;
			H46023_ForceReregistration();
			return;
		}
	}

	m_registeredH46023 = true;
	if (feat->Contains(Std23_STUNAddr)) {
		H323TransportAddress addr = feat->Value(Std23_STUNAddr);
		RunSTUNTest(addr);
	}
}

bool GkClient::H46023_TypeNotify(int & nattype)
{
	if (m_natnotify)
		nattype = m_nattype;

	return m_natnotify;
}

void GkClient::H46023_ACF(callptr m_call, H460_FeatureStd * feat)
{
    if (feat->Contains(Std24_NATInstruct)) {
		unsigned NATinst = feat->Value(Std24_NATInstruct);

        PTRACE(4, "GKC\tH46024 strategy for call set to " << NATinst);

		if (m_call)
			H46023_SetNATStategy(m_call->GetCallIdentifier(), NATinst);
	}
}

bool GkClient::H46023_CreateSocketPair(const H225_CallIdentifier & id, PINDEX callNo, WORD sessionID, UDPProxySocket * & rtp, UDPProxySocket * & rtcp, bool & nated)
{
	if (!m_registeredH46023)
		return false;

	CallRec::NatStrategy strategy = H46023_GetNATStategy(id);

	switch (strategy) {
		case CallRec::e_natUnknown:
		case CallRec::e_natNoassist:
		case CallRec::e_natLocalProxy:
		case CallRec::e_natRemoteProxy:
		case CallRec::e_natFullProxy:
			// All handled by the ProxySocket
			return false;
		case CallRec::e_natAnnexA:
		case CallRec::e_natAnnexB:
			nated = false;
			rtp = new H46024Socket(this, true, id, callNo, strategy, sessionID);
			rtcp = new H46024Socket(this, false, id, callNo, strategy, sessionID);
			H46023_SetSocketPair(id, sessionID, rtp, rtcp);
			return true;
		case CallRec::e_natLocalMaster:
			nated = true;
			return (m_stunClient &&
					m_stunClient->CreateSocketPair(callNo, rtp, rtcp));
		case CallRec::e_natRemoteMaster:
			nated = false;
			return (m_stunClient &&
					m_stunClient->CreateSocketPair(callNo, rtp, rtcp));
		case CallRec::e_natFailure:
			// TODO signal the call will fail!
			PTRACE(1, "H46023\tNAT failure: Call will fail");
		default:
			return false;
	}
}

void GkClient::H46023_SetNATStategy(const H225_CallIdentifier & id, unsigned nat)
{
	PWaitAndSignal m(m_strategyMutex);

	std::list<CallH46024Sockets> natSockets;
	natSockets.push_back(CallH46024Sockets(nat));
	m_natstrategy.insert(pair<H225_CallIdentifier, std::list<CallH46024Sockets> >(id, natSockets));
}

CallRec::NatStrategy GkClient::H46023_GetNATStategy(const H225_CallIdentifier & id)
{
	PWaitAndSignal m(m_strategyMutex);

	GkNATSocketMap::const_iterator i = m_natstrategy.find(id);
	return (CallRec::NatStrategy)((i != m_natstrategy.end()) ? i->second.front().GetNatStrategy() : 0);
}

void GkClient::H46023_SetSocketPair(const H225_CallIdentifier & id, WORD sessionID, UDPProxySocket * rtp, UDPProxySocket * rtcp)
{
	PWaitAndSignal m(m_strategyMutex);

	GkNATSocketMap::iterator i = m_natstrategy.find(id);
	if (i != m_natstrategy.end()) {
		i->second.push_back(CallH46024Sockets(sessionID,rtp,rtcp));
	}
}

void GkClient::H46023_LoadAlternates(const H225_CallIdentifier & id, WORD session, PString & cui, unsigned & muxID, H323TransportAddress & m_rtp, H323TransportAddress & m_rtcp)
{
	PWaitAndSignal m(m_strategyMutex);

	GkNATSocketMap::iterator i = m_natstrategy.find(id);
	if (i != m_natstrategy.end()) {
		std::list<CallH46024Sockets>::iterator k = i->second.begin();
		while (k != i->second.end()) {
			CallH46024Sockets & sockets = *k;
			if (sockets.GetSessionID() ==  session) {
				sockets.LoadAlternate(cui, muxID, m_rtp, m_rtcp);
				break;
			}
			++k;
		}
	}
}

void GkClient::H46023_SetAlternates(const H225_CallIdentifier & id, WORD session, PString cui, unsigned muxID, H323TransportAddress m_rtp, H323TransportAddress m_rtcp)
{
	PWaitAndSignal m(m_strategyMutex);

	GkNATSocketMap::iterator i = m_natstrategy.find(id);
	if (i != m_natstrategy.end()) {
		std::list<CallH46024Sockets>::iterator k = i->second.begin();
		while (k != i->second.end()) {
			CallH46024Sockets & sockets = *k;
			if (sockets.GetSessionID() ==  session) {
				sockets.SetAlternate(cui, muxID, m_rtp, m_rtcp);
				break;
			}
			++k;
		}
	}
}

void GkClient::H46023_SetAlternates(const H225_CallIdentifier & id, const H46024B_ArrayOf_AlternateAddress & alternates)
{
	PWaitAndSignal m(m_strategyMutex);

	GkNATSocketMap::iterator i = m_natstrategy.find(id);
	if (i != m_natstrategy.end()) {
		for (PINDEX j = 0; j < alternates.GetSize(); ++j) {
			unsigned session = alternates[j].m_sessionID;
			std::list<CallH46024Sockets>::iterator k = i->second.begin();
			while (k != i->second.end()) {
				CallH46024Sockets & sockets = *k;
				if (sockets.GetSessionID() == session) {
					sockets.SetAlternate(alternates[j]);
					break;
				}
				++k;
			}
		}
	}
}

void GkClient::H46023_ForceReregistration()
{
	m_registeredTime = PTime() - PTimeInterval(m_timer);
}

void GkClient::H46023_TypeDetected(int nattype)
{
	m_nattype = nattype;
	m_natnotify = true;

	H46023_ForceReregistration();

	if (m_nattype != 2) {
		PTRACE(4, "GKC\tSTUN client disabled: Not supported for NAT type: " << nattype);
		m_stunClient->Stop();
		m_stunClient = NULL;
	}
}

#endif

void GkClient::OnRRJ(RasMsg *ras)
{
	H225_RegistrationReject & rrj = (*ras)->m_recvRAS;
	m_rrjReason = "Reason: " + rrj.m_rejectReason.GetTagName();
	PTRACE(1, "GKC\tRegistration Rejected: " << rrj.m_rejectReason.GetTagName());

	if (rrj.HasOptionalField(H225_RegistrationReject::e_altGKInfo)) {
		m_gkList->Set(rrj.m_altGKInfo.m_alternateGatekeeper);
		m_useAltGKPermanent = rrj.m_altGKInfo.m_altGKisPermanent;
		GetAltGK();
	} else if (rrj.m_rejectReason.GetTag() == H225_RegistrationRejectReason::e_fullRegistrationRequired) {
		SendURQ();
		m_timer = 100;
		Toolkit::Instance()->GetRouteTable()->InitTable();
	}
}

void GkClient::OnARJ(RasMsg *ras)
{
	H225_AdmissionReject & arj = (*ras)->m_recvRAS;
	if (arj.HasOptionalField(H225_AdmissionReject::e_altGKInfo)) {
		m_gkList->Set(arj.m_altGKInfo.m_alternateGatekeeper);
		m_useAltGKPermanent = arj.m_altGKInfo.m_altGKisPermanent;
		GetAltGK();
	} else if (arj.m_rejectReason.GetTag() == H225_AdmissionRejectReason::e_callerNotRegistered) {
		Unregister();
		m_timer = 100; // re-register again
	}
}

bool GkClient::OnURQ(RasMsg *ras)
{
	Unregister();

	m_registeredTime = PTime();
	H225_UnregistrationRequest & urq = (*ras)->m_recvRAS;
	switch (urq.m_reason.GetTag())
	{
		case H225_UnregRequestReason::e_reregistrationRequired:
		case H225_UnregRequestReason::e_ttlExpired:
			m_timer = 500;
			break;

		default:
			m_timer = m_retry * 1000;
			if (urq.HasOptionalField(H225_UnregistrationRequest::e_alternateGatekeeper)) {
				m_gkList->Set(urq.m_alternateGatekeeper);
				GetAltGK();
			}
			break;
	}

	(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_unregistrationConfirm);
	H225_UnregistrationConfirm & ucf = (*ras)->m_replyRAS;
	ucf.m_requestSeqNum = urq.m_requestSeqNum;
	return true;
}

bool GkClient::OnDRQ(RasMsg * ras)
{
	H225_DisengageRequest & drq = (*ras)->m_recvRAS;
	if (callptr call = drq.HasOptionalField(H225_DisengageRequest::e_callIdentifier) ? CallTable::Instance()->FindCallRec(drq.m_callIdentifier) : CallTable::Instance()->FindCallRec(drq.m_callReferenceValue))
		call->Disconnect(true);

	(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_disengageConfirm);
	H225_DisengageConfirm & dcf = (*ras)->m_replyRAS;
	dcf.m_requestSeqNum = drq.m_requestSeqNum;
	return true;
}

bool GkClient::OnBRQ(RasMsg *ras)
{
	// lazy implementation, just reply confirm
	// TODO: integrate into bandwidth management
	H225_BandwidthRequest & brq = (*ras)->m_recvRAS;
	(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_bandwidthConfirm);
	H225_BandwidthConfirm & bcf = (*ras)->m_replyRAS;
	bcf.m_requestSeqNum = brq.m_requestSeqNum;
	bcf.m_bandWidth = brq.m_bandWidth;
	return true;
}

bool GkClient::OnIRQ(RasMsg * ras)
{
	H225_InfoRequest & irq = (*ras)->m_recvRAS;
	(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_infoRequestResponse);
	H225_InfoRequestResponse & irr = (*ras)->m_replyRAS;
	irr.m_requestSeqNum = irq.m_requestSeqNum;
    irr.m_endpointIdentifier = m_endpointId;
	if (!Toolkit::AsBool(GkConfig()->GetInteger(EndpointSection, "HideGk", 0)))
		irr.m_endpointType.IncludeOptionalField(H225_EndpointType::e_gatekeeper);
	if (m_endpointType == EndpointType_Terminal) {
		irr.m_endpointType.IncludeOptionalField(H225_EndpointType::e_terminal);
	} else {
		irr.m_endpointType.IncludeOptionalField(H225_EndpointType::e_gateway);
	}
	SetRasAddress(irr.m_rasAddress);
	SetCallSignalAddress(irr.m_callSignalAddress);
	return true;
}

bool GkClient::RewriteString(PString & alias, bool fromInternal) const
{
	if (!m_rewriteInfo)
		return false;
	for (PINDEX i = 0; i < m_rewriteInfo->Size(); ++i) {
		PString prefix, insert;
		if (fromInternal) {
			insert = m_rewriteInfo->Key(i);
			prefix = m_rewriteInfo->Value(i);
		} else {
			prefix = m_rewriteInfo->Key(i);
			insert = m_rewriteInfo->Value(i);
		}
		int len = prefix.GetLength();
		if (len == 0 || strncmp(prefix, alias, len) == 0){
			PString result = insert + alias.Mid(len);
			PTRACE(2, "GKC\tRewriteString: " << alias << " to " << result);
			alias = result;
			return true;
		}
	}
	return false;
}

void GkClient::SetClearTokens(H225_ArrayOf_ClearToken & clearTokens, const PString & id)
{
    if (m_authAlgo == OID_H235_CAT) {
        clearTokens.RemoveAll();
        H235AuthCAT auth;
        // avoid copying for thread-safety
        auth.SetLocalId((const char *)id);
        auth.SetPassword((const char *)m_password);
        H225_ArrayOf_CryptoH323Token dumbTokens;
        auth.PrepareTokens(clearTokens, dumbTokens);
    }
}

void GkClient::SetCryptoTokens(H225_ArrayOf_CryptoH323Token & cryptoTokens, const PString & id)
{
    if (m_authAlgo == OID_H235_MD5) {
        cryptoTokens.RemoveAll();
        H235AuthSimpleMD5 auth;
        // avoid copying for thread-safety
        auth.SetLocalId((const char *)id);
        auth.SetPassword((const char *)m_password);
        H225_ArrayOf_ClearToken dumbTokens;
        auth.PrepareTokens(dumbTokens, cryptoTokens);
    }
}

void GkClient::SetRasAddress(H225_ArrayOf_TransportAddress & addr)
{
	addr.SetSize(1);
	addr[0] = m_rasSrv->GetRasAddress(m_loaddr);
}

void GkClient::SetRasAddress(H225_TransportAddress & addr)
{
	addr = m_rasSrv->GetRasAddress(m_loaddr);
}

void GkClient::SetCallSignalAddress(H225_ArrayOf_TransportAddress & addr)
{
	addr.SetSize(1);
	addr[0] = m_rasSrv->GetCallSignalAddress(m_loaddr);
}

void GkClient::SetCallSignalAddress(H225_TransportAddress & addr)
{
	addr = m_rasSrv->GetCallSignalAddress(m_loaddr);
}

void GkClient::SetNBPassword(
	H225_LocationRequest & lrq, /// LRQ message to be filled with tokens
	const PString & id // login name
	)
{
	if (!m_password) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_cryptoTokens), SetCryptoTokens(lrq.m_cryptoTokens, id);
		lrq.IncludeOptionalField(H225_LocationRequest::e_tokens), SetClearTokens(lrq.m_tokens, id);
	}
}

bool GkClient::UsesAdditiveRegistration() const
{
	return m_useAdditiveRegistration;
}

bool GkClient::AdditiveRegister(H225_ArrayOf_AliasAddress & aliases, int & rejectReason, H225_ArrayOf_ClearToken * tokens, H225_ArrayOf_CryptoH323Token * cryptotokens)
{
	PWaitAndSignal lock(m_rrqMutex);

	m_rrjReason = "no response";
	if (!m_useAdditiveRegistration || !IsRegistered()) {
		rejectReason = H225_RegistrationRejectReason::e_undefinedReason;
		return false;
	}

	H225_RasMessage rrq_ras;
	Requester<H225_RegistrationRequest> request(rrq_ras, m_loaddr);
	BuildRRQ(rrq_ras);

	H225_RegistrationRequest & rrq = rrq_ras;
	rrq.IncludeOptionalField(H225_RegistrationRequest::e_additiveRegistration);

	rrq.IncludeOptionalField(H225_RegistrationRequest::e_terminalAlias);
	rrq.m_terminalAlias = aliases;

	if (tokens) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_tokens);
		rrq.m_tokens = *tokens;
	}

	if (cryptotokens) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_cryptoTokens);
		rrq.m_cryptoTokens = *cryptotokens;
	}

	OnSendingRRQ(rrq_ras);
	request.SendRequest(m_gkaddr, m_gkport);
	m_registeredTime = PTime();
	if (request.WaitForResponse(m_retry * 1000)) {
		RasMsg *ras = request.GetReply();
		switch (ras->GetTag())
		{
			case H225_RasMessage::e_registrationConfirm:
			{
				H225_RegistrationConfirm & rcf = (*ras)->m_recvRAS;
				AppendLocalAlias(rcf.m_terminalAlias);  // this relies on the fact that the parent will only include the added alias in the RCF
				aliases = rcf.m_terminalAlias;
				return true;
			}
			case H225_RasMessage::e_registrationReject:
			{
				H225_RegistrationReject & rrj = (*ras)->m_recvRAS;
				rejectReason = rrj.m_rejectReason.GetTag();
				return false;
			}
		}
	}
	rejectReason = H225_RegistrationRejectReason::e_undefinedReason;
	return false;
}

bool GkClient::AdditiveUnRegister(const H225_ArrayOf_AliasAddress & aliases)
{
	RemoveLocalAlias(aliases);

	H225_RasMessage urq_ras;
	urq_ras.SetTag(H225_RasMessage::e_unregistrationRequest);
	H225_UnregistrationRequest & urq = urq_ras;
	urq.m_requestSeqNum = m_rasSrv->GetRequestSeqNum();
	urq.IncludeOptionalField(H225_UnregistrationRequest::e_gatekeeperIdentifier);
	urq.m_gatekeeperIdentifier = m_gatekeeperId;
	urq.IncludeOptionalField(H225_UnregistrationRequest::e_endpointIdentifier);
	urq.m_endpointIdentifier = m_endpointId;
	SetCallSignalAddress(urq.m_callSignalAddress);

	urq.IncludeOptionalField(H225_UnregistrationRequest::e_endpointAlias);
	urq.m_endpointAlias = aliases;

	m_rasSrv->SendRas(urq_ras, m_gkaddr, m_gkport, m_loaddr, NULL); // TODO235
	return true;
}

void GkClient::AppendLocalAlias(const H225_ArrayOf_AliasAddress & aliases)
{
	for (PINDEX i = 0; i < aliases.GetSize(); ++i)
		m_h323Id.AppendString(AsString(aliases[i], false));
}

void GkClient::RemoveLocalAlias(const H225_ArrayOf_AliasAddress & aliases)
{
	PStringArray newAliasList;
	for (PINDEX j = 0; j < m_h323Id.GetSize(); ++j) {
		int found = false;
		for (PINDEX i = 0; i < aliases.GetSize(); ++i) {
			if (AsString(aliases[i], false) == m_h323Id[j]) {
				found = true;
				break;
			}
		}
		if (!found) {
			newAliasList.AppendString(m_h323Id[j]);
        }
	}
	m_h323Id = newAliasList;
}

bool GkClient::HandleSetup(SetupMsg & setup, bool fromInternal)
{
	RewriteE164(setup, fromInternal);

	H225_Setup_UUIE & setupBody = setup.GetUUIEBody();
	if (!fromInternal) {
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)) {
#ifdef HAS_H46023
			H225_ArrayOf_FeatureDescriptor & fs = setupBody.m_supportedFeatures;
			unsigned location = 0;
			if (m_registeredH46023 && FindH460Descriptor(24, fs, location)) {
				H460_Feature feat = H460_Feature(fs[location]);
				H460_FeatureStd & std24 = (H460_FeatureStd &)feat;
				if (std24.Contains(Std24_NATInstruct)) {
					unsigned natstat = std24.Value(Std24_NATInstruct);
					H46023_SetNATStategy(setup.GetUUIEBody().m_callIdentifier, natstat);
				}
				RemoveH460Descriptor(24, fs);
			}
#endif
		}
	} else {
#ifdef HAS_H46023
		unsigned nonce = 0;
		if (setupBody.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures)
			&& FindH460Descriptor(24, setupBody.m_supportedFeatures, nonce))
			RemoveH460Descriptor(24, setupBody.m_supportedFeatures);

		if (m_registeredH46023) {
			CallRec::NatStrategy natoffload = H46023_GetNATStategy(setupBody.m_callIdentifier);
			H460_FeatureStd feat = H460_FeatureStd(24);
			feat.Add(Std24_NATInstruct, H460_FeatureContent((unsigned)natoffload, 8));
			H225_ArrayOf_FeatureDescriptor & desc = setupBody.m_supportedFeatures;
			int sz = desc.GetSize();
			desc.SetSize(sz + 1);
			desc[sz] = feat;
		}
#endif
		if (setupBody.m_supportedFeatures.GetSize() > 0)
			setupBody.IncludeOptionalField(H225_Setup_UUIE::e_supportedFeatures);
	}
	return true;
}
