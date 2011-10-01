//////////////////////////////////////////////////////////////////
//
// GkClient.cxx
//
// Copyright (c) Citron Network Inc. 2001-2003
// Copyright (c) 2002-2011, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

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

#ifdef HAS_H46023
  #include <h460/h4601.h>
  #include <ptclib/pstun.h>
  #include <ptclib/random.h>
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

class AlternateGKs {
public:
	AlternateGKs(const PIPSocket::Address &, WORD);
	void Set(const H225_ArrayOf_AlternateGK &);
	void Set(const PString &);
	bool Get(PIPSocket::Address &, WORD &);

private:
	typedef multimap<int, H225_TransportAddress> GKList;
	GKList AltGKs;
	GKList::iterator index;
	PIPSocket::Address pgkaddr, pgkport;
};

AlternateGKs::AlternateGKs(const PIPSocket::Address & gkaddr, WORD gkport)
{
	pgkaddr = gkaddr, pgkport = gkport;
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
		PTRACE(3, "GKC\tInvalid AlternateGK Address!" );
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
	CallSignalSocket *socket;
};

NATClient::NATClient(const H225_TransportAddress & addr, const H225_EndpointIdentifier & id)
{
	GetIPAndPortFromTransportAddr(addr, gkip, gkport);
	endpointId = id.GetValue();
	socket = 0;
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
	
	socket = new CallSignalSocket;
	socket->SetPort(gkport);
	if (socket->Connect(gkip)) {
		PTRACE(2, "GKC\t" << socket->GetName() << " connected, waiting for incoming call");
		if (DetectIncomingCall()) {
			PTRACE(3, "GKC\tIncoming call detected");
			CreateJob(socket, &CallSignalSocket::Dispatch, "NAT call");
			socket = 0;
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
		long retry = GkConfig()->GetInteger(
			EndpointSection, "NATKeepaliveInterval", 20
			); // keep alive interval must be less than 30 sec (from testing 20 sec seems fine)
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
  
  STUNchangeRequest() { }

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
  
  STUNmessage()
  { }
  
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

  STUNattribute * GetFirstAttribute() { 

    int length = ((STUNmessageHeader *)theArray)->msgLength;
    if (theArray == NULL || length < (int) sizeof(STUNmessageHeader))
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

class STUNsocket  : public UDPSocket
{
public:
    STUNsocket();
	virtual PBoolean GetLocalAddress(PIPSocket::Address &);
	virtual PBoolean GetLocalAddress(PIPSocket::Address &, WORD &);

	PIPSocket::Address externalIP;
};

STUNsocket::STUNsocket()
  : externalIP(0)
{
}


PBoolean STUNsocket::GetLocalAddress(PIPSocket::Address & addr)
{
  if (!externalIP.IsValid())
    return UDPSocket::GetLocalAddress(addr);

  addr = externalIP;
  return true;
}


PBoolean STUNsocket::GetLocalAddress(PIPSocket::Address & addr, WORD & port)
{
  if (!externalIP.IsValid())
     return UDPSocket::GetLocalAddress(addr, port);

  addr = externalIP;
  port = GetPort();
  return true;
}

//////

struct STUNportRange {

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

class STUNClient   :  public  Job,
	                          public PSTUNClient
{
 public:
	STUNClient(GkClient * _client, const H323TransportAddress &);
	virtual ~STUNClient();

	virtual void Stop();

	virtual void Run();

    virtual bool CreateSocketPair(
			UDPSocket * & rtp,
			UDPSocket * & rtcp,
			const PIPSocket::Address & binding = PIPSocket::GetDefaultIpAny()
    );

protected:
	bool OpenSocketA(UDPSocket & socket, PortInfo & portInfo, const PIPSocket::Address & binding);

private:
	// override from class Task
	virtual void Exec();
	// Callback
   void OnDetectedNAT(int m_nattype);

    GkClient *                    m_client;
	NatTypes                      m_nattype;
	bool                          m_shutdown;
	PMutex                        m_portCreateMutex;
    int                           m_socketsForPairing;
    int                           m_pollRetries;

};

STUNClient::STUNClient(GkClient * _client, const H323TransportAddress & addr)
:  m_client(_client), m_nattype(UnknownNat), m_shutdown(false),
   m_socketsForPairing(4), m_pollRetries(3)
{

	PIPSocket::Address ip;
	WORD port;
	addr.GetIpAndPort(ip,port);
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

        PTimedMutex mute;

		// Wait 500 ms until the RCF has been processed before running tests 
		// to prevent blocking.
		mute.Wait(500);
	
		// Get a valid NAT type....
	    // We do the test 3 times as often the first test gives odd results
	    // if after 3 attempts it gives odd results well it must be an odd NAT :)  S.H.
		PINDEX i = 0;
		do  {
			m_nattype = GetNatType(TRUE);
			i++;
		} while ((i <= 3) && (m_nattype == RestrictedNat ||
			     m_nattype == PortRestrictedNat ||
			     m_nattype == BlockedNat ||
			     m_nattype== PartialBlockedNat
			));

		OnDetectedNAT(m_nattype);

		// Keep this job (thread) open so that creating STUN ports does not hold up 
		// the processing of other calls
		while (!m_shutdown) {
			PThread::Sleep(100);
		}

	ReadUnlock unlockConfig(ConfigReloadMutex);
}

void STUNClient::OnDetectedNAT(int nattype)
{
	PTRACE(3,"STUN\tDetected NAT as type " << nattype << " " << GetNatTypeString((NatTypes)nattype));

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
  }  
  else {
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
  return false;
}
#endif

bool STUNClient::CreateSocketPair(UDPSocket * & rtp, UDPSocket * & rtcp, const PIPSocket::Address & binding)
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
    PINDEX idx = stunSocket.Append(new STUNsocket);
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

#endif

/////////////////////////////////////////////////////////////////////

class GRQRequester : public RasRequester {
public:
	GRQRequester(const PString & gkid, H225_EndpointType & type);
	virtual ~GRQRequester();

	// override from class RasRequester
	virtual bool SendRequest(const Address &, WORD, int = 2);

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
	grq.m_endpointType.IncludeOptionalField(H225_EndpointType::e_gatekeeper);
	if (type.HasOptionalField(H225_EndpointType::e_terminal))
		grq.m_endpointType.IncludeOptionalField(H225_EndpointType::e_terminal);
	if (type.HasOptionalField(H225_EndpointType::e_gateway))
		grq.m_endpointType.IncludeOptionalField(H225_EndpointType::e_gateway);
	grq.IncludeOptionalField(H225_GatekeeperRequest::e_supportsAltGK);
	if (!gkid) {
		grq.IncludeOptionalField(H225_GatekeeperRequest::e_gatekeeperIdentifier);
		grq.m_gatekeeperIdentifier = gkid;
	}
	grq.IncludeOptionalField(H225_GatekeeperRequest::e_authenticationCapability);
	grq.IncludeOptionalField(H225_GatekeeperRequest::e_algorithmOIDs);
	H235AuthSimpleMD5 md5auth;
	md5auth.SetPassword("dummy"); // activate it
	md5auth.SetCapability(grq.m_authenticationCapability, grq.m_algorithmOIDs);
	H235AuthCAT catauth;
	catauth.SetPassword("dummy"); // activate it
	catauth.SetCapability(grq.m_authenticationCapability, grq.m_algorithmOIDs);
	m_rasSrv->RegisterHandler(this);
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
		socket->SendRas(grq_ras, addr, pt);
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

bool GkClientHandler::IsExpected(const RasMsg *ras) const
{
	return (ras->GetTag() == tag) && client->CheckFrom(ras);
}

void GkClientHandler::Process(RasMsg *ras)
{
	CreateJob(this, &GkClientHandler::OnRequest, ras, ras->GetTagName());
}

void GkClientHandler::OnRequest(RasMsg *ras)
{
	ReadLock lockConfig(ConfigReloadMutex);
	if ((client->*handlePDU)(ras))
		ras->Reply();
	delete ras;
	ras = NULL;
}

namespace {
const long DEFAULT_TTL = 60;
const long DEFAULT_RRQ_RETRY = 3;
}

// class GkClient
GkClient::GkClient() 
	: m_rasSrv(RasServer::Instance()), m_registered(false), m_discoveryComplete(false),
	m_ttl(GkConfig()->GetInteger(EndpointSection, "TimeToLive", DEFAULT_TTL)),
	m_timer(0),
	m_retry(GkConfig()->GetInteger(EndpointSection, "RRQRetryInterval", DEFAULT_RRQ_RETRY)),
	m_authMode(-1), m_rewriteInfo(NULL), m_natClient(NULL),
	m_parentVendor(ParentVendor_GnuGk), m_endpointType(EndpointType_Gateway),
	m_discoverParent(true)
#ifdef HAS_H46023
	, m_nattype(0), m_natnotify(false), gk_H460_23(false),  m_stunClient(NULL)
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

#ifdef OpenH323Factory
	m_password = PString::Empty();
    m_h235Authenticators = new H235Authenticators();
    PFactory<H235Authenticator>::KeyList_T keyList = PFactory<H235Authenticator>::GetKeyList();
    PFactory<H235Authenticator>::KeyList_T::const_iterator r;
    for (r = keyList.begin(); r != keyList.end(); ++r) {
       H235Authenticator * Auth = PFactory<H235Authenticator>::CreateInstance(*r);
       m_h235Authenticators->Append(Auth);
	}
#endif

}

GkClient::~GkClient()
{
#ifdef OpenH323Factory
    delete m_h235Authenticators;
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
	m_authMode = -1;

	PCaselessString s = GkConfig()->GetString(EndpointSection, "Vendor", "GnuGk");
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

	m_h323Id = cfg->GetString(
		EndpointSection, "H323ID", (const char *)Toolkit::GKName()
		).Tokenise(" ,;\t", FALSE);
	m_e164 = cfg->GetString(EndpointSection, "E164", "").Tokenise(" ,;\t", FALSE);
	
	PIPSocket::Address gkaddr = m_gkaddr;
	WORD gkport = m_gkport;
	PCaselessString gk(cfg->GetString(EndpointSection, "Gatekeeper", "no"));

	PStringList gkHost;
#if P_DNS
	PStringList str;
    if (gk != "no" && PDNS::LookupSRV(gk, "_h323rs._udp.", str)) {
		PTRACE(5, "EP\t" << str.GetSize() << " h323rs SRV Records found" );
		  for (PINDEX i = 0; i < str.GetSize(); i++) {
			PCaselessString newhost = str[i].Right(str[i].GetLength()-5);
			PTRACE(4, "EP\th323rs SRV record " << newhost );
			if (i == 0) 
				gk = newhost;
			else 
				m_gkList->Set(newhost);
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

PString GkClient::GetParent() const
{
	return IsRegistered() ?
		AsString(m_gkaddr, m_gkport) + '\t' + m_endpointId.GetValue() :
		"not registered\t" + m_rrjReason;
}

bool GkClient::OnSendingRRQ(H225_RegistrationRequest &rrq)
{
	if (m_parentVendor == ParentVendor_GnuGk) {
		PIPSocket::Address sigip;
		if (rrq.m_callSignalAddress.GetSize() > 0
				&& GetIPFromTransportAddr(rrq.m_callSignalAddress[0], sigip)) {
			rrq.IncludeOptionalField(H225_RegistrationRequest::e_nonStandardData);
			rrq.m_nonStandardData.m_nonStandardIdentifier.SetTag(H225_NonStandardIdentifier::e_h221NonStandard);
			H225_H221NonStandard &t35 = rrq.m_nonStandardData.m_nonStandardIdentifier;
			t35.m_t35CountryCode = Toolkit::t35cPoland;
			t35.m_manufacturerCode = Toolkit::t35mGnuGk;
			t35.m_t35Extension = Toolkit::t35eNATTraversal;
			rrq.m_nonStandardData.m_data = "IP=" + sigip.AsString();
		}
	}

#ifdef HAS_H46023
		// H.460.23 Feature
		if (Toolkit::Instance()->IsH46023Enabled()) {
			bool contents = false;
			rrq.IncludeOptionalField(H225_RegistrationRequest::e_featureSet);
			H460_FeatureStd feat = H460_FeatureStd(23); 

			if (!IsRegistered()) {
					feat.Add(Std23_RemoteNAT,H460_FeatureContent(true));
					contents = true;
			} else {
					int natType = 0;
					if (H46023_TypeNotify(natType)) {
						feat.Add(Std23_NATdet,H460_FeatureContent(natType,8)); 
						contents = true;
					}
			}
			if (contents) {
				rrq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
				H225_ArrayOf_FeatureDescriptor & desc = rrq.m_featureSet.m_supportedFeatures;
				desc.SetSize(1);
				desc[0] = feat;
			}
		}
#endif

	return true;
}

bool GkClient::OnSendingARQ(H225_AdmissionRequest &arq, Routing::AdmissionRequest & /* req */)
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

bool GkClient::OnSendingLRQ(H225_LocationRequest &lrq, Routing::LocationRequest &/*req*/)
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

bool GkClient::OnSendingARQ(H225_AdmissionRequest &arq, Routing::SetupRequest &req, bool /*answer*/)
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

bool GkClient::OnSendingARQ(H225_AdmissionRequest &arq, Routing::FacilityRequest &/*req*/)
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

bool GkClient::OnSendingDRQ(H225_DisengageRequest &/*drq*/, const callptr &/*call*/)
{
	return true;
}

bool GkClient::OnSendingURQ(H225_UnregistrationRequest &/*urq*/)
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

#ifdef HAS_H46023
	if (gk_H460_23) {
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
	SetNBPassword(lrq);

	if (!OnSendingLRQ(lrq, lrq_obj))
		return false;
		
	request.SendRequest(m_gkaddr, m_gkport);
	if (request.WaitForResponse(5000)) {
		RasMsg *ras = request.GetReply();
		unsigned tag = ras->GetTag();
		if (tag == H225_RasMessage::e_locationConfirm) {
			H225_LocationConfirm & lcf = (*ras)->m_recvRAS;
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

bool GkClient::SendARQ(Routing::SetupRequest & setup_obj, bool answer, int natoffload)
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
	if (setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_destinationInfo);
		arq.m_destinationInfo = setup.m_destinationAddress;
		if (answer)
			RewriteE164(arq.m_destinationInfo, true);
	}
	arq.m_answerCall = answer;
	// workaround for bandwidth
	arq.m_bandWidth = 1280;

#ifdef HAS_H46023
	if (gk_H460_23) {
		arq.IncludeOptionalField(H225_AdmissionRequest::e_featureSet);
		H460_FeatureStd feat = H460_FeatureStd(24); 

		if (answer  && natoffload > 0) 
			feat.Add(Std24_NATInstruct,H460_FeatureContent((unsigned)natoffload,8));

		arq.m_featureSet.IncludeOptionalField(H225_FeatureSet::e_supportedFeatures);
		H225_ArrayOf_FeatureDescriptor & desc = arq.m_featureSet.m_supportedFeatures;
		desc.SetSize(1);
		desc[0] = feat;
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
	arq.m_bandWidth = 1280;

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
	drq.m_answeredCall = !call->GetCallingParty();
	SetPassword(drq);

	if (OnSendingDRQ(drq, call)) {
		request.SendRequest(m_gkaddr, m_gkport);
		request.WaitForResponse(3000);
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
		m_rasSrv->SendRas(urq_ras, m_gkaddr, m_gkport, m_loaddr);
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

bool GkClient::RewriteE164(
	SetupMsg &setup, 
	bool fromInternal
	)
{
	Q931 &q931 = setup.GetQ931();
	H225_Setup_UUIE &setupBody = setup.GetUUIEBody();
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
			if (gcf.HasOptionalField(H225_GatekeeperConfirm::e_authenticationMode))
				m_authMode = gcf.m_authenticationMode.GetTag();
			PTRACE(2, "GKC\tDiscover GK " << AsString(m_gkaddr, m_gkport) << " at " << m_loaddr);
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
			// TODO: not thread-safe ?
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
//		rrq.IncludeOptionalField(H225_RegistrationRequest::e_multipleCalls);
//		rrq.m_multipleCalls = FALSE;
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

	int ttl = GkConfig()->GetInteger(EndpointSection, "TimeToLive", DEFAULT_TTL);
	if (ttl > 0) {
		rrq.IncludeOptionalField(H225_RegistrationRequest::e_timeToLive);
		rrq.m_timeToLive = ttl;
	}

	H225_VendorIdentifier & vendor = rrq.m_endpointVendor;
	vendor.IncludeOptionalField(H225_VendorIdentifier::e_productId);
	vendor.m_productId = PString(PString::Printf, "GNU Gatekeeper on %s %s %s, %s %s", (const unsigned char*)(PProcess::GetOSName()), (const unsigned char*)(PProcess::GetOSHardware()), (const unsigned char*)(PProcess::GetOSVersion()) ,__DATE__, __TIME__);
	vendor.IncludeOptionalField(H225_VendorIdentifier::e_versionId);
	vendor.m_versionId = "Version " + PProcess::Current().GetVersion();

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
	rrq.m_keepAlive = TRUE;
}

bool GkClient::WaitForACF(H225_AdmissionRequest &arq, RasRequester & request, Routing::RoutingRequest *robj)
{
	request.SendRequest(m_gkaddr, m_gkport);
	if (request.WaitForResponse(5000)) {
		RasMsg *ras = request.GetReply();
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
						&& acf.m_destinationInfo.GetSize() > 0 ) {
						robj->SetFlag(Routing::RoutingRequest::e_aliasesChanged);
						Routing::AdmissionRequest * orig_request = dynamic_cast<Routing::AdmissionRequest *>(robj);
						if (orig_request) {
							orig_request->GetRequest().m_destinationInfo = acf.m_destinationInfo;
						}
					}
				}
				robj->AddRoute(route);
#ifdef HAS_H46023
			  if (Toolkit::Instance()->IsH46023Enabled()) {
				if (acf.HasOptionalField(H225_AdmissionConfirm::e_featureSet)) {
					callptr call = arq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier) ?
						CallTable::Instance()->FindCallRec(arq.m_callIdentifier) : CallTable::Instance()->FindCallRec(arq.m_callReferenceValue);
					H460_FeatureSet fs = H460_FeatureSet(acf.m_featureSet);
					if (fs.HasFeature(24)) 
						HandleP2P_ACF(call, (H460_FeatureStd *)fs.GetFeature(24));
				 }
			  }
#endif
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
		for_each(m_handlers, m_handlers + 4, bind1st(mem_fun(&RasServer::RegisterHandler), m_rasSrv));
	}
	
	// Not all RCF contain TTL, in that case keep old value
	if (rcf.HasOptionalField(H225_RegistrationConfirm::e_timeToLive)) {
		m_ttl = PMAX(rcf.m_timeToLive - m_retry, 30);
		// Have it reregister at 3/4 of TimeToLive, otherwise the parent
		// might go out of sync and ends up sending an URQ
		m_ttl = (m_ttl / 4) * 3;
	}
	
	m_timer = m_ttl * 1000;
	m_resend = m_retry;

	// NAT handling
	if (rcf.HasOptionalField(H225_RegistrationConfirm::e_nonStandardData)) {
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

#ifdef HAS_H46023
    if (Toolkit::Instance()->IsH46023Enabled()) {
		if (rcf.HasOptionalField(H225_RegistrationConfirm::e_genericData)) {
			H460_FeatureSet fs = H460_FeatureSet(rcf.m_genericData);
			if (fs.HasFeature(23)) 
				HandleP2P_RCF((H460_FeatureStd *)fs.GetFeature(23));
		}
	}
#endif
}

#ifdef HAS_H46023
void GkClient::HandleP2P_RCF(H460_FeatureStd * feat)
{
//   PBoolean proxy = FALSE;
   PBoolean NATdetect = FALSE;

   gk_H460_23 = true;

//   if (feat->Contains(Std24_ProxyNAT)) 
//       proxy = feat->Value(Std24_ProxyNAT);

   if (feat->Contains(Std23_IsNAT))
       NATdetect = feat->Value(Std23_IsNAT);

   if (feat->Contains(Std23_DetRASAddr)) {
       H323TransportAddress addr = feat->Value(Std23_DetRASAddr);
	   if (!NATdetect) {
		   PIPSocket::Address ip;
		   addr.GetIpAddress(ip);
	 //      EP->OnDetectRASAddress(ip);
	   }
   }

   if (NATdetect && feat->Contains(Std23_STUNAddr)) {
           H323TransportAddress addr = feat->Value(Std23_STUNAddr);
		   m_stunClient = new STUNClient(this,addr);
   }
}

bool GkClient::H46023_TypeNotify(int & nattype)
{
	if (m_natnotify) 
		nattype = m_nattype;

	return m_natnotify;
}

void GkClient::HandleP2P_ACF(callptr m_call, H460_FeatureStd * feat)
{
    if (feat->Contains(Std24_NATInstruct)) {
		unsigned NATinst = feat->Value(Std24_NATInstruct);

        PTRACE(4,"GKC\tH46024 strategy for call set to " << NATinst);

		if (m_call) 
			m_call->SetNATStrategy((CallRec::NatStrategy)NATinst);

	}
}

bool GkClient::H46023_CreateSocketPair(const H225_CallIdentifier & id, UDPProxySocket * & rtp, UDPProxySocket * & rtcp, bool & nated)
{

  if (!m_stunClient) 
	  return false;

   callptr call = CallTable::Instance()->FindCallRec(id);
   if (call && call->GetNATStrategy() == CallRec::e_natLocalMaster) {   // Local media master need to use STUN to open RTP ports
			nated = true;
			return m_stunClient->CreateSocketPair((UDPSocket * &)rtp,(UDPSocket * &)rtcp);
	}

	return false;
}

void GkClient::H46023_TypeDetected(int nattype)
{
	m_nattype = nattype;
	m_natnotify = true;
	// This will cause the client to reregister
	// We just advance the timer to force reregister
	m_registeredTime = PTime() - PTimeInterval(m_timer);

	if (m_nattype != 2) {
		PTRACE(4,"GKC\tSTUN client disabled: Not supported for NAT type: " << nattype);
		m_stunClient->Stop();
		m_stunClient = NULL;
	}
}

#endif

void GkClient::OnRRJ(RasMsg *ras)
{
	H225_RegistrationReject & rrj = (*ras)->m_recvRAS;
	m_rrjReason =  "Reason: " + rrj.m_rejectReason.GetTagName();
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

bool GkClient::OnDRQ(RasMsg *ras)
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
	H225_BandwidthRequest & brq = (*ras)->m_recvRAS;
	(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_bandwidthConfirm);
	H225_BandwidthConfirm & bcf = (*ras)->m_replyRAS;
	bcf.m_requestSeqNum = brq.m_requestSeqNum;
	bcf.m_bandWidth = brq.m_bandWidth;
	return true;
}

bool GkClient::OnIRQ(RasMsg *ras)
{
	H225_InfoRequest & irq = (*ras)->m_recvRAS;
	(*ras)->m_replyRAS.SetTag(H225_RasMessage::e_infoRequestResponse);
	H225_InfoRequestResponse & irr = (*ras)->m_replyRAS;
	irr.m_requestSeqNum = irq.m_requestSeqNum;
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
			PTRACE(2, "GKC\tRewritePString: " << alias << " to " << result);
			alias = result;
			return true;
		}
	}
	return false;
}

void GkClient::SetClearTokens(H225_ArrayOf_ClearToken & clearTokens, const PString & id)
{
	clearTokens.RemoveAll();
	H235AuthCAT auth;
	// avoid copying for thread-safely
	auth.SetLocalId((const char *)id);
	auth.SetPassword((const char *)m_password);
	H225_ArrayOf_CryptoH323Token dumbTokens;
	auth.PrepareTokens(clearTokens, dumbTokens);
}

void GkClient::SetCryptoTokens(H225_ArrayOf_CryptoH323Token & cryptoTokens, const PString & id)
{
	cryptoTokens.RemoveAll();
	H235AuthSimpleMD5 auth;
	// avoid copying for thread-safely
	auth.SetLocalId((const char *)id);
	auth.SetPassword((const char *)m_password);
	H225_ArrayOf_ClearToken dumbTokens;
	auth.PrepareTokens(dumbTokens, cryptoTokens);
}

void GkClient::SetRasAddress(H225_ArrayOf_TransportAddress & addr)
{
	addr.SetSize(1);
	addr[0] = m_rasSrv->GetRasAddress(m_loaddr);
}

void GkClient::SetCallSignalAddress(H225_ArrayOf_TransportAddress & addr)
{
	addr.SetSize(1);
	addr[0] = m_rasSrv->GetCallSignalAddress(m_loaddr);
}

void GkClient::SetNBPassword(
	H225_LocationRequest& lrq, /// LRQ message to be filled with tokens
	const PString& id // login name
	)
{
	if (!m_password) {
		lrq.IncludeOptionalField(H225_LocationRequest::e_cryptoTokens), SetCryptoTokens(lrq.m_cryptoTokens, id);
		lrq.IncludeOptionalField(H225_LocationRequest::e_tokens), SetClearTokens(lrq.m_tokens, id);
	}
}
