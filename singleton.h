//////////////////////////////////////////////////////////////////
//
// singleton.h
//
// All singleton objects are put into a list
// so that it would be delete when program exits.
//
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	2001/07/11	initial version (Chih-Wei Huang)
//
//////////////////////////////////////////////////////////////////

#ifndef SINGLETON_H
#define SINGLETON_H "@(#) $Id$"

// STL
#include <list>
#include <algorithm>
#include <stdexcept>

//
// a list of pointers that would delete all objects
// referred by the pointers in the list on destruction
//
template<class T> class listptr : public std::list<void *> {
  public:
	listptr() : clear_list(false) {}
	~listptr();
	bool clear_list;

  private:
	static void delete_obj(void *t) { delete static_cast<T *>(t); }
};

template<class T> listptr<T>::~listptr()
{
	clear_list=true;
	std::for_each(begin(), end(), delete_obj);
}


// Base class for all singletons
class SingletonBase {
  public:
	SingletonBase(const char *);
	virtual ~SingletonBase();

  private:
	const char *m_name;
	// Note the SingletonBase instance is not singleton itself :p
	// However, list of singletons *are* singleton
	// But we can't put the singleton into the list :(
	static listptr<SingletonBase> _instance_list;
};

//
// A singleton class should be derived from this template.
// class Ts : public Singleton<Ts> {
//     ...
// };
//
// If the class is instantiated more than once,
// a runtime error would be thrown
//
// I provide two ways to access the singleton:
// (since I'm not sure which is better)
// T::Instance()  or  InstanceOf<T>
//
template<class T> class Singleton : public SingletonBase {
  public:
	static T *Instance();
	template<class U> static T *Instance(const U &);

  protected:
	Singleton(const char *);
	~Singleton();

#ifdef WIN32
  public:
#else
  private:
	friend T *InstanceOf<T>();
#endif
	static T *m_Instance;
	static PMutex m_CreationLock;
};

template<class T> Singleton<T>::Singleton(const char *n) : SingletonBase(n)
{
	if (m_Instance != 0)
		throw std::runtime_error("Duplicate instances");
}

template<class T> Singleton<T>::~Singleton()
{
	PWaitAndSignal lock(m_CreationLock);
	m_Instance = 0;
}

// Function to access the singleton
template<class T> T *Singleton<T>::Instance()
{
	if (m_Instance == 0) {
		PWaitAndSignal lock(m_CreationLock);
		// We have to check it again after we got the lock
		if (m_Instance == 0)
			m_Instance = new T;
	}
	return m_Instance;
}

#ifndef WIN32  // VC++ doesn't support nested template?
template<class T> template <class U> T *Singleton<T>::Instance(const U &u)
{
	if (m_Instance == 0) {
		PWaitAndSignal lock(m_CreationLock);
		// We have to check it again after we got the lock
		if (m_Instance == 0)
			m_Instance = new T(u);
	}
	return m_Instance;
}
#endif

// Function to access the singleton
template<class T> T *InstanceOf()
{
	if (Singleton<T>::m_Instance == 0) {
		PWaitAndSignal lock(Singleton<T>::m_CreationLock);
		// We have to check it again after we got the lock
		if (Singleton<T>::m_Instance == 0)
			Singleton<T>::m_Instance = new T;
	}
	return Singleton<T>::m_Instance;
}

// static members
template<class T> T *Singleton<T>::m_Instance=0;
template<class T> PMutex Singleton<T>::m_CreationLock;


#endif // SINGLETON_H
