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

template<typename N>
class NamedObj {
public:
#if PTRACING
        N GetName() const { return m_name; }
        void SetName(const N & n) { m_name = n; }

private:
        N m_name;
#else
        void SetName(const N &) {}
#endif
};

class PString;
typedef NamedObj<PString> NamedObject;
typedef NamedObj<const char *> CNamedObject;

#endif // NAME_H
