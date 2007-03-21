//////////////////////////////////////////////////////////////////
//
// singleton.cxx
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////

#if defined(_WIN32) && (_MSC_VER <= 1200)
#pragma warning(disable:4284)
#endif

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
