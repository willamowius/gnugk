// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// Classes for locking
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

#include <ptlib.h>
#include "Toolkit.h"
#include "gklock.h"


#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = GKLOCK_H;
#endif /* lint */


// GKCondMutex
void
GKCondMutex::Lock()
{
	Wait();
	access_count +=1;
	Signal();
}

void
GKCondMutex::Unlock()
{
	Wait();
 	if(access_count >0) {
		access_count -=1;
	}
//	PTRACE(5, "GKCondMutex: " << access_count);
	Signal();
}

BOOL
GKCondMutex::Condition()
{
//	PTRACE(5, "access_count is: " << access_count);
	return access_count==0;
}

// ProxyCondMutex

void
ProxyCondMutex::Lock(const PString & name)
{
	Wait();
	locker.AppendString(name);
	access_count +=1;
//	PTRACE(5, "ProxyCondMutex: " << access_count << " from " << name );
	Signal();
}

void
ProxyCondMutex::Unlock(const PString &name)
{
	Wait();
 	if(access_count >0) {
//		PTRACE(5, "deleting Lock of:" << name << " with place " << locker.GetStringsIndex(name));
		access_count -=1;
		if (locker.GetStringsIndex(name)!=P_MAX_INDEX)
			locker.RemoveAt(locker.GetStringsIndex(name));
	}
//	PTRACE(5, "ProxyCondMutex: " << access_count);
	Signal();
}

BOOL
ProxyCondMutex::Condition()
{
	PTRACE(5, "access_count is: " << access_count);
	PTRACE(5, "locks of: " << locker);
	return access_count==0;
}
