// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2002 Nils Bokermann <Nils.Bokermann@mediaWays.net>
//
// PURPOSE OF THIS FILE: Listen to Multicast packages
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

#ifndef MULTICASTGRQ_H
#define MULTICASTGRQ_H "@(#) $Id$"

#include "ptlib.h"
#include "ptlib/sockets.h"
#include "h225.h"
#include "RasListener.h"

class MulticastGRQ : public GK_RASListener
{
	  PCLASSINFO(MulticastGRQ, PThread)
public:
	MulticastGRQ(PIPSocket::Address GKHome);
	virtual ~MulticastGRQ();

	void Close(void);
	virtual void Main(void);
protected:
	H225_TransportAddress GKRasAddress;
};

#endif // MULTICASTGRQ_H
