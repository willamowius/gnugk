//////////////////////////////////////////////////////////////////
//
// singleton.cxx
//
// Copyright (c) 2001-2010, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include "singleton.h"

#if PTRACING
static int singleton_cnt=0;
#endif

listptr<SingletonBase> SingletonBase::_instance_list;

SingletonBase::SingletonBase(const char *n) : m_name(n)
{
#if PTRACING
	++singleton_cnt;
	PTRACE(2,"Create instance: "<<m_name<<'('<<singleton_cnt<<')');
#endif
	_instance_list.push_back(this);
}

SingletonBase::~SingletonBase()
{
#if PTRACING
	--singleton_cnt;
	PTRACE(2,"Delete instance: "<<m_name<<'('<<singleton_cnt<<" objects left)");
#endif
	if (!_instance_list.clear_list)
		_instance_list.remove(this);
}
