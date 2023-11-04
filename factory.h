//////////////////////////////////////////////////////////////////
//
// Object factory for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2003
// Copyright (c) 2006-2023, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef FACTORY_H
#define FACTORY_H "@(#) $Id$"

/*****************************************************************
//
// An example how to use the factory template
//

// a base class for polymorphic objects

class SampleBase {
public:
	SampleBase() { }
	SampleBase(const char *n) { cerr << "This is a " << n << "\n"; }
	virtual ~SampleBase() { }

	template<class Derived>
	struct Init : public Factory<SampleBase>::Creator0 {
		Init(const char *n) : Factory<SampleBase>::Creator0(n), n_(n) { }
		virtual SampleBase *operator()() const { return new Derived(n_); }

		const char *n_;
	};
};

class SampleA : public SampleBase {
public:
	SampleA(const char *n) : SampleBase(n) { }
};

class SampleB : public SampleBase {
public:
	SampleB(const char *n) : SampleBase(n) { }
};

class SampleC : public SampleBase {
public:
	SampleC(const char *n) : SampleBase(n) { }
	SampleC(int i) { cerr << "This is a SampleC " << i << "\n"; }

	// how to create object for a class with different constructors
	struct InitC : public SampleBase::Init<SampleC>, public Factory<SampleBase>::Creator1<int> {
		InitC(const char *n) : SampleBase::Init<SampleC>(n), Factory<SampleBase>::Creator1<int>(n) { }
		virtual SampleBase *operator()(int i) const { return new SampleC(i); }
	};
};

// register the derived classes with the factory

SampleA::Init<SampleA> SampleAInit("SampleA");
SampleB::Init<SampleB> SampleBInit("SampleB");
SampleC::InitC SampleCInit("SampleC");


void CreateSamples()
{
	SampleBase *pa, *pb, *pc1, *pc2, *pc3;
	pa = Factory<SampleBase>::Create("SampleA");
	pb = Factory<SampleBase>::Create("SampleB");
	pc1 = Factory<SampleBase>::Create("SampleC");
	pc2 = Factory<SampleBase>::Create("SampleC", 2);
	pc3 = Factory<SampleBase>::Create("SampleC", 1, 2, 3); // runtime error
}

The output

This is a SampleA
This is a SampleB
This is a SampleC
This is a SampleC 2

and an error message in trace

factory.h(135)   Init    Can't create SampleC with 3 parameter(s)

*****************************************************************/

#if defined(_WIN32) && (_MSC_VER >= 1200)
#pragma warning( disable : 4355 ) // warning about using 'this' in initializer
#endif

#include <map>
#include <cstring>
#include <functional>

namespace std {

// gcc 3.x said specialization can't be put in different namespace
template<> struct less<const char *> : public binary_function<const char *, const char *, bool> {
	bool operator()(const char *s1, const char *s2) const { return (strcmp(s1, s2) < 0); }
};

}


// a function object template with returned value R
template<typename R>
struct Functor {
	typedef R result_type;
	virtual ~Functor() { }
};

// function objects with different parameters
// currently at most 3 parameters are supported

// since VC6 didn't support partial specialization,
// we have to define Functor with different parameters to
// different names
template<typename R>
struct Functor0 : public Functor<R> {
	virtual R operator()() const = 0;
};

template<typename R, typename T1>
struct Functor1 : public Functor<R> {
	typedef T1 argument_type;
	virtual R operator()(T1) const = 0;
};

template<typename R, typename T1, typename T2>
struct Functor2 : public Functor<R> {
	typedef T1 first_argument_type;
	typedef T2 second_argument_type;
	virtual R operator()(T1, T2) const = 0;
};

template<typename R, typename T1, typename T2, typename T3>
struct Functor3 : public Functor<R> {
	typedef T1 first_argument_type;
	typedef T2 second_argument_type;
	typedef T3 third_argument_type;
	virtual R operator()(T1, T2, T3) const = 0;
};


// object factory template
template<class Product, typename Identifier = const char *>
class Factory {
public:
	typedef Factory<Product, Identifier> Self;
	typedef Functor<Product *> *Creator;
	typedef std::map<Identifier, Creator> Associations;

	static Creator Register(Identifier n, Creator c);
	static void SetDefaultCreator(Creator c) { m_default = c; }

	// registrars
	class Registrar {
	protected:
		Identifier m_id;
		Creator m_old;
		Registrar(Identifier n, Creator c);
		~Registrar();
	};

	struct Creator0 : public Functor0<Product *>, Registrar {
		Creator0(Identifier n) : Registrar(n, this) { }
	};

	template<typename P1>
	struct Creator1 : public Functor1<Product *, P1>, Registrar {
		Creator1(Identifier n) : Registrar(n, this) { }
	};

	template<typename P1, typename P2>
	struct Creator2 : public Functor2<Product *, P1, P2>, Registrar {
		Creator2(Identifier n) : Registrar(n, this) { }
	};

	template<typename P1, typename P2, typename P3>
	struct Creator3 : public Functor3<Product *, P1, P2, P3>, Registrar {
		Creator3(Identifier n) : Registrar(n, this) { }
	};

	static Product *Create(Identifier n)
	{
		Functor0<Product *> *f0;
		return FindCreator(n, 0, f0) ? (*f0)() : NULL;
	}

	template<typename P1>
	static Product *Create(Identifier n, P1 p1)
	{
		Functor1<Product *, P1> *f1;
		return FindCreator(n, 1, f1) ? (*f1)(p1) : NULL;
	}

	template<typename P1, typename P2>
	static Product *Create(Identifier n, P1 p1, P2 p2)
	{
		Functor2<Product *, P1, P2> *f2;
		return FindCreator(n, 2, f2) ? (*f2)(p1, p2) : NULL;
	}

	template<typename P1, typename P2, typename P3>
	static Product *Create(Identifier n, P1 p1, P2 p2, P3 p3)
	{
		Functor3<Product *, P1, P2, P3> *f3;
		return FindCreator(n, 3, f3) ? (*f3)(p1, p2, p3) : NULL;
	}

private:
	static Creator FindCreator(Identifier);
	static bool ParmMismatch(Identifier, int);
	template<typename P>
	static bool FindCreator(Identifier n, int i, P & p)
	{
		Creator creator = FindCreator(n);
		p = dynamic_cast<P>(creator);
		return creator && (p || ParmMismatch(n, i));
	}

	static Associations *m_associations;
	static Creator m_default;
};

#if !defined(_WIN32) || (_MSC_VER > 1300)
// stupid VC can't instantiate these
template<class Product, typename Identifier>
Factory<Product, Identifier>::Registrar::Registrar(Identifier n, Creator c) : m_id(n)
{
// VS.NET fix
#if defined(_WIN32) && (_MSC_VER > 1300)
	m_old = Register(n, c);
#else
	m_old = Self::Register(n, c);
#endif
}

template<class Product, typename Identifier>
Factory<Product, Identifier>::Registrar::~Registrar()
{
	if (m_old)
// VS.NET fix
#if defined(_WIN32) && (_MSC_VER > 1300)
		Register(m_id, m_old);
#else
		Self::Register(m_id, m_old);
#endif
}
#endif

template<class Product, typename Identifier>
Functor<Product *> *Factory<Product, Identifier>::Register(Identifier n, Creator c)
{
	static Associations associations;
	m_associations = &associations;
	Creator & d = associations[n];
	Creator old = d;
	d = c;
	return old;
}

template<class Product, typename Identifier>
Functor<Product *> *Factory<Product, Identifier>::FindCreator(Identifier n)
{
	typename Associations::iterator i = m_associations->find(n);
	if (i != m_associations->end())
		return i->second;
	else if (m_default)
		return m_default;
	PTRACE(1, "Init\tError: Can't create unknown class " << n);
	return NULL;
}

template<class Product, typename Identifier>
bool Factory<Product, Identifier>::ParmMismatch(Identifier n, int i)
{
	PTRACE(1, "Init\tError: Can't create " << n << " with " << i << " parameter(s)");
	return false;
}

template<class Product, typename Identifier>
std::map<Identifier, Functor<Product *> *> *Factory<Product, Identifier>::m_associations;

template<class Product, typename Identifier>
Functor<Product *> *Factory<Product, Identifier>::m_default = NULL;


// a simple creator for classes having default constructor
// the ConcreteProduct must define its base class as a subtype Base
template<class ConcreteProduct, typename Identifier = const char *>
struct SimpleCreator : public Factory<typename ConcreteProduct::Base, Identifier>::Creator0 {
	typedef typename ConcreteProduct::Base AbstractProduct;
	SimpleCreator(Identifier n) : Factory<AbstractProduct, Identifier>::Creator0(n) { }
	virtual AbstractProduct *operator()() const { return new ConcreteProduct; }
};


#endif // FACTORY_H
