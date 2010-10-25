//////////////////////////////////////////////////////////////////
//
// rwlock.h
//
// Utilities for PReadWriteMutex usage
//
// Copyright (c) Citron Network Inc. 2002
// Copyright (c) 2006-2010, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef RWLOCK_H
#define RWLOCK_H "@(#) $Id$"

class ReadLock {
	PReadWriteMutex & mutex;
  public:
	ReadLock(PReadWriteMutex & m) : mutex(m) { mutex.StartRead(); }
	~ReadLock() { mutex.EndRead(); }
};

class WriteLock {
	PReadWriteMutex & mutex;
  public:
	WriteLock(PReadWriteMutex & m) : mutex(m) { mutex.StartWrite(); }
	~WriteLock() { mutex.EndWrite(); }
};

class ReadUnlock {
	PReadWriteMutex & mutex;
  public:
	ReadUnlock(PReadWriteMutex & m) : mutex(m) { mutex.EndRead(); }
	~ReadUnlock() { mutex.StartRead(); }
};

class WriteUnlock {
	PReadWriteMutex & mutex;
  public:
	WriteUnlock(PReadWriteMutex & m) : mutex(m) { mutex.EndWrite(); }
	~WriteUnlock() { mutex.StartWrite(); }
};

extern PReadWriteMutex ConfigReloadMutex;

#endif // RWLOCK_H
