//////////////////////////////////////////////////////////////////
//
// MakeCall.h
//
// Copyright (c) 2007-2011, Jan Willamowius
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

    // overrides from H323EndPoint
    virtual PBoolean OnIncomingCall(H323Connection &, const H323SignalPDU &, H323SignalPDU &);
    virtual PBoolean OnConnectionForwarded(H323Connection &, const PString &, const H323SignalPDU &);
    virtual void OnConnectionEstablished(H323Connection & connection, const PString & token);
    virtual PBoolean OpenAudioChannel(H323Connection &, PBoolean, unsigned, H323AudioCodec &);
	virtual void OnRegistrationConfirm(const H323TransportAddress & rasAddress);
	virtual void OnRegistrationReject();

	virtual void ThirdPartyMakeCall(const PString & user1, const PString & user2);
	virtual PBoolean IsRegisteredWithGk() const;

protected:    
    void AddDestination(PString token, PString alias);
	// get and remove destination from list
    PString GetDestination(PString token);

    PMutex destinationMutex;
    std::map<PString, PString> destinations;

	PCaselessString transferMethod;
	PBoolean isRegistered;
};

#endif  // _MakeCall_H

