// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2002 Nils Bokermann <Nils.Bokermann@mediaWays.net>
//
// PURPOSE OF THIS FILE: This class shall prevent deletion of objects
// used (bogus pointers) The user is responsible to Lock/Unlock
// objects.
//
// - Automatic Version Information via RCS:
//   $Id$
//   $Source$
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//


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
	virtual void OnWait();
	virtual void WaitCondition();
private:
	PStringList locker;
};

#endif /* _GKLOCK_H */
