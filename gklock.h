// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// Lock.h
//
// Copyright (c) Nils Bokermann <nils.bokermann@mediaways.net>
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//
//////////////////////////////////////////////////////////////////

// This class shall prevent deletion of objects used (bogus pointers)
// The user is responsible to Lock/Unlock objects.

#ifndef GKLOCK_H
#define GKLOCK_H "@(#) $Id$"

class GKCondMutex : public PCondMutex {
public:
	GKCondMutex() :  access_count(0) {};
	virtual BOOL Condition();
	virtual void Lock();
	virtual void Unlock();
protected:
	PINDEX access_count;
};

class ProxyCondMutex : public GKCondMutex {
public:
	ProxyCondMutex() {};
	virtual BOOL Condition();
	virtual void Lock(const PString &name);
	virtual void Unlock(const PString &name);
private:
	PStringList locker;
};

#endif /* _GKLOCK_H */
