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

#ifdef PTRACING
static int singleton_cnt=0;
#endif

listptr<SingletonBase> SingletonBase::_instance_list;

SingletonBase::SingletonBase()
{
	PTRACE(5, "Create instance: " << ++singleton_cnt);
        _instance_list.push_back(this);
}

SingletonBase::~SingletonBase()
{
	PTRACE(5, "Delete instance: " << --singleton_cnt);
	if (!_instance_list.clear_list)
		_instance_list.remove(this);
}
