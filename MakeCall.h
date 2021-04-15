//////////////////////////////////////////////////////////////////
//
// MakeCall.h
//
// Copyright (c) 2007-2017, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef _MakeCall_H
#define _MakeCall_H

#include <ptlib.h>
#include <h323.h>
#include "singleton.h"
#include "config.h"
#include <map>

class MakeCallEndPoint : public Singleton<MakeCallEndPoint>, public H323EndPoint
{
public:
    MakeCallEndPoint();
    virtual ~MakeCallEndPoint();

    // overrides from H323EndPoint
    virtual H323Connection * CreateConnection(unsigned callReference);

    virtual PBoolean OnIncomingCall(H323Connection &, const H323SignalPDU &, H323SignalPDU &);
    virtual PBoolean OnConnectionForwarded(H323Connection &, const PString &, const H323SignalPDU &);
    virtual void OnConnectionEstablished(H323Connection & connection, const PString & token);
#ifdef H323_AUDIO_CODECS
    virtual PBoolean OpenAudioChannel(H323Connection &, PBoolean, unsigned, H323AudioCodec &);
#endif
	virtual void OnRegistrationConfirm(const H323TransportAddress & rasAddress);
	virtual void OnRegistrationReject();

	virtual void ThirdPartyMakeCall(const PString & user1, const PString & user2, const PString & transferMethod);
	virtual PBoolean IsRegisteredWithGk() const;

	// get destination from list
    PString GetDestination(const PString & token);
    BYTE GetRateMultiplier() const { return m_rateMultiplier; }

protected:
    void AddDestination(const PString & token, const PString & alias, const PString & transferMethod);
	// get and remove destination from list
    PString GetRemoveDestination(const PString & token);
    PString GetRemoveTransferMethod(const PString & token);

    // call destinations
    PMutex destinationMutex;
    std::map<PString, PString> destinations;
    // per call transfer methods
    PMutex methodMutex;
    std::map<PString, PString> methods;

	PCaselessString globalTransferMethod;
	PBoolean isRegistered;
	PString m_gkAddress;
	long m_bandwidth;
	BYTE m_rateMultiplier;
};


class MakeCallConnection : public H323Connection
{
public:
    MakeCallConnection(MakeCallEndPoint & ep, unsigned _callReference, unsigned _options);
    virtual ~MakeCallConnection() { }

    PBoolean OnSendSignalSetup(H323SignalPDU & setupPDU);
#ifdef H323_AUDIO_CODECS
    PBoolean OpenAudioChannel(PBoolean isEncoding, unsigned bufferSize, H323AudioCodec & codec);
#endif

protected:
    MakeCallEndPoint & m_ep;
};


class SilentChannel : public PIndirectChannel
{
    PCLASSINFO(SilentChannel, PIndirectChannel);
  public:
    SilentChannel() { }
    virtual ~SilentChannel() { }
    virtual PBoolean Read(void * buf, PINDEX len);
    virtual PBoolean Write(const void *, PINDEX);
    virtual PBoolean Close();
  protected:
    PAdaptiveDelay readDelay;
    PAdaptiveDelay writeDelay;
};

#endif  // _MakeCall_H

