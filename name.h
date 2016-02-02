//////////////////////////////////////////////////////////////////
//
// name.h
//
// Template for a named object
// We don't use PObject since it is too large
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

#ifndef NAME_H
#define NAME_H "@(#) $Id$"


class NamedObject
{
public:
	/// build a named with the given name (or with an empty name)
	NamedObject(
		/// name to set for the object
		const char* name = NULL
		) : m_name(name) { }

	/// copy constructor for proper PString copying
	NamedObject(
		const NamedObject& obj
		) : m_name((const char*)(obj.m_name)) { }

	virtual ~NamedObject() { }

	/// assignment operator for proper PString assignment
	NamedObject & operator=(const NamedObject & obj)
	{
		m_name = (const char*)(obj.m_name);
		return *this;
	}

	/** Set new name for the object.
		Not really thread safe (another thread may call GetName in the same time),
		so it should be used with care.
	*/
	void SetName(
		/// name to set for the object
		const char* name
		)
	{
		m_name = name;
	}

	/** @return
		Name for this object.
	*/
	const PString & GetName() const { return m_name; }

private:
	/// object name
	PString m_name;
};

#endif // NAME_H
