//////////////////////////////////////////////////////////////////
//
// name.h
//
// Template for a named object
// We don't use PObject since it is too large
//
// Copyright (c) Citron Network Inc. 2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chin-Wei Huang <cwhuang@linux.org.tw>
// initial version: 07/15/2003
//
//////////////////////////////////////////////////////////////////

#ifndef NAME_H
#define NAME_H "@(#) $Id$"

#if PTRACING

#ifndef _PTLIB_H
#include <ptlib.h>
#endif

class NamedObject {
public:
	void SetName(const char *n) { m_name = n; }
	const PString & GetName() const { return m_name; }

private:
	PString m_name;
};

class CNamedObject {
public:
	void SetName(const char *n) { m_name = n; }
	const char *GetName() const { return m_name; }

private:
	const char *m_name;
};

#else

struct NamedObject {
	void SetName(const char *) {}
};

struct CNamedObject {
	void SetName(const char *) {}
};

#endif

#endif // NAME_H
