/*
 * gktimer.h
 *
 * Generic support for time-based events.
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.2  2004/05/12 11:47:06  zvision
 * Generic support for time-based events
 *
 * Revision 1.1.2.2  2004/05/10 18:01:38  zvision
 * Fixed VC6 compilation errors regarding member templates
 *
 * Revision 1.1.2.1  2004/05/10 16:43:26  zvision
 * Generic support for time-based events
 *
 */
#ifndef GKTIMER_H
#define GKTIMER_H "@(#) $Id$"

#include <list>

/** A base class for timer objects. Currently two types of timer objects
    are implemented: a timer calling a regular function and a timer calling
    an object member function on timer expiration.
*/
class GkTimer
{
public:
	/** @return
	    True if the timer is periodic (timer function is called periodically).
	*/
	bool IsPeriodic() const { return m_periodic; }

	/** @return
	    Return time interval (seconds) between subsequent timer function calls
	    for periodic timers. For one-shot timer the return value is 0.
	*/
	long GetInterval() const { return m_interval; }
	
	/** @return
	    Get timer expiration time (time when a timer function will be called).
	*/
	const PTime& GetExpirationTime() const { return m_expirationTime; }
	
	/** @return
	    Set a new timer expiration time.
	*/
	void SetExpirationTime(
		const PTime& expirationTime /// the new expiration time
		) { m_expirationTime = expirationTime; }
		
	/** @return
	    True if the timer has expired (and the timer function should be called.
	*/
	bool IsExpired() const 
		{ return PTime() >= m_expirationTime && (m_periodic || !m_fired); }

	/// Set timer expiration state to fired or not fired
	void SetFired(
		bool fired /// new state
		) { m_fired = fired; }

	/** @return
	    True if the timer has already been fired (timer function has been
	    called at least once).
	*/
	bool IsFired() const { return m_fired; }
	
	/// destroy this timer object
	virtual ~GkTimer() {}
		
protected:
	/// build an one-shot timer object
	GkTimer(
		const PTime& expirationTime /// expiration time
		) : m_periodic(false), m_fired(false), m_interval(0), 
			m_expirationTime(expirationTime) {}

	/// build a periodic timer object
	GkTimer(
		const PTime& expirationTime, /// the first expiration time
		long interval /// timer interval (seconds)
		) : m_periodic(true), m_fired(false), m_interval(interval), 
			m_expirationTime(expirationTime) {}

	/// This function is called by GkTimerManager when the timer expires
	virtual void OnTimerExpired() = 0;

	friend class GkTimerManager;
	
private:
	GkTimer();
	
private:
	bool m_periodic; /// one-shot(false)/periodic(true) timer
	bool m_fired; /// true if the timer function has already been called
	long m_interval; /// timer interval (seconds) for periodic timers
	PTime m_expirationTime; /// next expiration time
};

/// A timer that calls an object member function on its expiration
template<class T>
class GkVoidMemberFuncTimer : public GkTimer
{
public:
	/// build an one-shot timer object
	GkVoidMemberFuncTimer(
		const PTime& expirationTime, /// timer expiration time
		T* classObj, /// object of class T
		void (T::*timerFunc)() /// object's member function to call
		) : GkTimer(expirationTime), m_classObj(classObj), m_timerFunc(timerFunc) {}

	/// build a periodic timer object
	GkVoidMemberFuncTimer(
		const PTime& expirationTime, /// the first timer expiration time
		long interval, /// timer interval (seconds)
		T* classObj, /// object of class T
		void (T::*timerFunc)() /// object's member function to call
		) : GkTimer(expirationTime, interval), m_classObj(classObj), m_timerFunc(timerFunc) {}

protected:
	/// This function is called by GkTimerManager when the timer expires
	virtual void OnTimerExpired() 
	{ 
		if (m_classObj && m_timerFunc)
			(m_classObj->*m_timerFunc)();
	}

private:
	GkVoidMemberFuncTimer();
	
private:
	T* m_classObj;
	void (T::*m_timerFunc)();
};

/// A timer that calls an object member function on its expiration
template<class T>
class GkOneArgMemberFuncTimer : public GkTimer
{
public:
	/// build an one-shot timer object
	GkOneArgMemberFuncTimer(
		const PTime& expirationTime, /// timer expiration time
		T* classObj, /// object of class T
		void (T::*timerFunc)(GkTimer*) /// object's member function to call
		) : GkTimer(expirationTime), m_classObj(classObj), m_timerFunc(timerFunc) {}

	/// build a periodic timer object
	GkOneArgMemberFuncTimer(
		const PTime& expirationTime, /// the first timer expiration time
		long interval, /// timer interval (seconds)
		T* classObj, /// object of class T
		void (T::*timerFunc)(GkTimer*) /// object's member function to call
		) : GkTimer(expirationTime, interval), m_classObj(classObj), m_timerFunc(timerFunc) {}

protected:
	/// This function is called by GkTimerManager when the timer expires
	virtual void OnTimerExpired() 
	{ 
		if (m_classObj && m_timerFunc)
			(m_classObj->*m_timerFunc)(this);
	}

private:
	GkOneArgMemberFuncTimer();
	
private:
	T* m_classObj;
	void (T::*m_timerFunc)(GkTimer*);
};


/** This class manages a list of running timers and calls a timer function
    when the given timer expires. It support various timer object types:
    simple timer functions (void and one arg), object member functions (void
    and one arg). To make this class working, CheckTimers function has to be
    called periodically. It checks the timers and calls timer functions 
    if it is necessary.
*/
class GkTimerManager
{
public:
	/// timer "handle" object
	typedef GkTimer* GkTimerHandle;
	/// value for an invalid timer handle
	const static GkTimerHandle INVALID_HANDLE;

	GkTimerManager();

	/** Register an one-shot timer that calls a simple void function
	    on timer expiration.

	    @return
	    A handle to the timer or INVALID_HANDLE, if something has failed.
	*/
	GkTimerHandle RegisterTimer(
		void (*timerFunc)(), /// timer function
		const PTime& tm /// timer expiration time
		);
	
	/** Register a periodic timer that calls a simple void function
	    on every timer expiration.

	    @return
	    A handle to the timer or INVALID_HANDLE, if something has failed.
	*/
	GkTimerHandle RegisterTimer(
		void (*timerFunc)(), /// timer function
		const PTime& tm, /// the first expiration time
		long interval /// timer interval (seconds)
		);
		
	/** Register an one-shot timer that calls an one arg function
	    on timer expiration. The argument to the function is a pointer
	    to this timer object.

	    @return
	    A handle to the timer or INVALID_HANDLE, if something has failed.
	*/
	GkTimerHandle RegisterTimer(
		void (*timerFunc)(GkTimer*), /// timer function
		const PTime& tm /// timer expiration time
		);

	/** Register a periodic timer that calls an one arg function
	    on every timer expiration. The argument to the function is a pointer
	    to this timer object.

	    @return
	    A handle to the timer or INVALID_HANDLE, if something has failed.
	*/
	GkTimerHandle RegisterTimer(
		void (*timerFunc)(GkTimer*), /// timer function
		const PTime& tm, /// the first timer expiration time
		long interval /// timer interval (seconds)
		);

	/** Register an one-shot timer that calls a simple object member void 
	    function on timer expiration.

	    @return
	    A handle to the timer or INVALID_HANDLE, if something has failed.
	*/
	template<class T>
	GkTimerHandle RegisterTimer(
		T* obj, /// object of the class T
		void (T::*timerFunc)(), /// timer function (a member of the class T)
		const PTime& tm /// expiration time
		)
	{ // it has to be here to compile with VC6
		GkTimer* const t = new GkVoidMemberFuncTimer<T>(tm, obj, timerFunc);
		PWaitAndSignal lock(m_timersMutex);
		m_timers.push_back(t);
		return t;
	}

	/** Register a periodic timer that calls a simple object member void 
	    function on every timer expiration.

	    @return
	    A handle to the timer or INVALID_HANDLE, if something has failed.
	*/
	template<class T>
	GkTimerHandle RegisterTimer(
		T* obj, /// object of the class T
		void (T::*timerFunc)(), /// timer function (a member of the class T)
		const PTime& tm, /// the first expiration time
		long interval /// timer interval (seconds)
		)
	{ // it has to be here to compile with VC6
		GkTimer* const t = new GkVoidMemberFuncTimer<T>(tm, interval, obj, timerFunc);
		PWaitAndSignal lock(m_timersMutex);
		m_timers.push_back(t);
		return t;
	}

	/** Register an one-shot timer that calls an object member function 
	    on timer expiration. The member function takes one parameter
	    which is a pointer to this timer object.

	    @return
	    A handle to the timer or INVALID_HANDLE, if something has failed.
	*/
	template<class T>
	GkTimerHandle RegisterTimer(
		T* obj, /// object of the class T
		void (T::*timerFunc)(GkTimer*), /// timer function (a member of the class T)
		const PTime& tm /// timer expiration time
		)
	{ // it has to be here to compile with VC6
		GkTimer* const t = new GkOneArgMemberFuncTimer<T>(tm, obj, timerFunc);
		PWaitAndSignal lock(m_timersMutex);
		m_timers.push_back(t);
		return t;
	}

	/** Register a periodic timer that calls an object member function 
	    on every timer expiration. The member function takes one parameter
	    which is a pointer to this timer object.

	    @return
	    A handle to the timer or INVALID_HANDLE, if something has failed.
	*/
	template<class T>
	GkTimerHandle RegisterTimer(
		T* obj, /// object of the class T
		void (T::*timerFunc)(GkTimer*), /// timer function (a member of the class T)
		const PTime& tm, /// the first timer expiration time
		long interval /// timer interval (seconds)
		)
	{ // it has to be here to compile with VC6
		GkTimer* const t = new GkOneArgMemberFuncTimer<T>(tm, interval, obj, timerFunc);
		PWaitAndSignal lock(m_timersMutex);
		m_timers.push_back(t);
		return t;
	}

	/** Unregisters (and stops) the timer. After this function completes
	    it is not valid to reference the timer handle.
		
	    @return
	    True if the timer has been found on the list, false otherwise.
	*/		
	bool UnregisterTimer(
		GkTimerHandle timer /// timer handle
		);
		
	/** Check timers and call timer functions for timers that have expired.
	    It is important that this function is called periodically, otherwise
	    timers will not work.
	*/
	void CheckTimers();

	~GkTimerManager();
		
private:
	GkTimerManager(const GkTimerManager&);
	GkTimerManager& operator=(const GkTimerManager&);
	
private:
	PMutex m_timersMutex; /// mutual access to the timers
	std::list<GkTimerHandle> m_timers; /// a list of registered timers
};

#endif /* GKTIMER_H */
