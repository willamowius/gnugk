//////////////////////////////////////////////////////////////////
//
// slist.h
//
// A Single Linked List Template   *** LEGACY - use STL for new code ***
// only used as parent for Policy class
//
// Copyright (c) Citron Network Inc. 2003
// Copyright (c) 2006-2010, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef SLIST_H
#define SLIST_H "@(#) $Id$"

#include "factory.h"
#include <ptlib.h>

template<class T>
class SList {
public:
	typedef T Base;	// for SimpleCreator template 

	SList() : m_next(0) {}
	virtual ~SList() = 0;

	static T *Create(const PStringArray &);
	
protected:
	T *m_next;
};

template<class T>
SList<T>::~SList()
{
	delete m_next;  // delete whole list recursively
}


// ignore overflow warning when comparing size
#pragma GCC diagnostic ignored "-Wstrict-overflow"

template<class T>
T *SList<T>::Create(const PStringArray & rules)
{
	T *next = 0;
	for (int i = rules.GetSize(); --i >= 0; )
		if (T *current = Factory<T>::Create(rules[i])) {
			current->m_next = next;
			next = current;
		}
	return next;
}

#endif // SLIST_H
