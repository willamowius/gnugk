//////////////////////////////////////////////////////////////////
//
// MakeCall.h
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Jan Willamowius
//
//////////////////////////////////////////////////////////////////

#ifndef _MakeCall_H
#define _MakeCall_H

#include <ptlib.h>
#include <h323.h>
#include "singleton.h"
#include <map>
using namespace std;

class MakeCallEndPoint : public Singleton<MakeCallEndPoint>, public H323EndPoint
{
  PCLASSINFO(MakeCallEndPoint, H323EndPoint);

public:
    MakeCallEndPoint();

    // overrides from H323EndPoint
    virtual BOOL OnIncomingCall(H323Connection &, const H323SignalPDU &, H323SignalPDU &);
    virtual BOOL OnConnectionForwarded(H323Connection &, const PString &, const H323SignalPDU &);
    virtual void OnConnectionEstablished(H323Connection & connection, const PString & token);
    virtual BOOL OpenAudioChannel(H323Connection &, BOOL, unsigned, H323AudioCodec &);
	virtual void OnRegistrationConfirm();
	virtual void OnRegistrationReject();

    // New functions
    BOOL SetSoundDevice(PArgList &, const char *, PSoundChannel::Directions);

	virtual void ThirdPartyMakeCall(PString & user1, PString & user2);
	virtual BOOL GatekeeperIsRegistered(void);

protected:    
    void AddDestination(PString token, PString alias);
	// get and remove destination from list
    PString GetDestination(PString token);

    PMutex destinationMutex;
    map<PString, PString> destinations; 

	BOOL useH450Transfer;
	BOOL isRegistered;
};

#endif  // _MakeCall_H

