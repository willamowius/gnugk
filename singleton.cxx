// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// singleton.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//      2001/07/11      initial version (Chih-Wei Huang)
//
//////////////////////////////////////////////////////////////////

#include "singleton.h"

#ifndef lint
// mark object with version info in such a way that it is retreivable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = SINGLETON_H;
#endif /* lint */

#ifdef PTRACING
static int singleton_cnt=0;
#endif

listptr<SingletonBase> SingletonBase::_instance_list;

SingletonBase::SingletonBase()
{
	PTRACE(5, "Create instance: " << ++singleton_cnt << endl);
        _instance_list.push_back(this);
}

SingletonBase::~SingletonBase()
{
	PTRACE(5, "Delete instance: " << --singleton_cnt << endl);
	if (!_instance_list.clear_list)
		_instance_list.remove(this);
}
