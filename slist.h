//////////////////////////////////////////////////////////////////
//
// slist.h
//
// A Single Linked List Template
//
// Copyright (c) Citron Network Inc. 2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 07/16/2003
//
//////////////////////////////////////////////////////////////////

#ifndef SLIST_H
#define SLIST_H "@(#) $Id$"

#include "factory.h"

template<class T>
class SList {
public:
	typedef T Base;	// for SimpleCreator template 

	SList() : m_next(0) {}
	virtual ~SList() = 0;

	T* GetNext() { return m_next; }
	const T* GetNext() const { return m_next; }

	static T *Create(const PStringArray &);
	
protected:
	T *m_next;
};

template<class T>
SList<T>::~SList()
{
	delete m_next;  // delete whole list recursively
}

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
